//! Which Seatbelt rights the per-session socket directory needs on macOS (#40).
//!
//! The session must bind and connect there. Nothing from a write tree may be renamed or
//! hard-linked in, or a socket of a server outside the session, sitting in a write tree, could be
//! moved into the one place connect is allowed. Each candidate rule set is checked for both, with
//! a control that the same rename and link succeed unconfined.
#![cfg(target_os = "macos")]

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

struct Dirs {
    root: PathBuf,
    w: PathBuf,
    d: PathBuf,
}
impl Drop for Dirs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn dirs() -> Dirs {
    static N: AtomicU32 = AtomicU32::new(0);
    let root = std::env::temp_dir().join(format!(
        "zws-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(root.join("w")).unwrap();
    std::fs::create_dir_all(root.join("d")).unwrap();
    let root = root.canonicalize().unwrap();
    Dirs {
        w: root.join("w"),
        d: root.join("d"),
        root,
    }
}

fn run(policy: Option<&str>, script: &str) -> bool {
    let mut c = match policy {
        Some(p) => {
            let mut c = Command::new("/usr/bin/sandbox-exec");
            c.args(["-p", p, "/bin/bash", "-c", script]);
            c
        }
        None => {
            let mut c = Command::new("/bin/bash");
            c.args(["-c", script]);
            c
        }
    };
    let o = c.output().unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!err.contains("sandbox-exec:"), "policy rejected: {err}");
    o.status.success()
}

/// Outcomes under zwinger's shape (writes only in `w`) plus `extra` for the socket directory.
fn outcomes(extra: &str) -> Vec<(&'static str, bool)> {
    let t = dirs();
    let (w, d) = (t.w.to_str().unwrap(), t.d.to_str().unwrap());
    let extra = extra.replace("@D", d);
    let p = format!(
        "(version 1)\n(allow default)\n(deny file-write*)\n\
         (allow file-write* (subpath \"{w}\") (literal \"/dev/null\"))\n{extra}"
    );
    // A server outside the session, listening in the write tree.
    let _srv = UnixListener::bind(t.w.join("srv")).unwrap();
    std::fs::write(t.w.join("f"), "x").unwrap();
    let bind = format!(
        "nc -lU {d}/s & p=$!; for i in 1 2 3 4 5 6 7 8 9 10; do test -S {d}/s && break; sleep 0.1; done; \
         test -S {d}/s; r=$?; kill $p 2>/dev/null; exit $r"
    );
    let unlink = format!("rm -f {d}/s");
    vec![
        ("bind in the socket directory", run(Some(&p), &bind)),
        ("unlink own socket", run(Some(&p), &unlink)),
        (
            "rename a write-tree socket in",
            run(Some(&p), &format!("mv {w}/srv {d}/m")),
        ),
        (
            "hard-link a write-tree file in",
            run(Some(&p), &format!("ln {w}/f {d}/l")),
        ),
        (
            "create a regular file",
            run(Some(&p), &format!("echo x > {d}/r")),
        ),
        ("mkdir", run(Some(&p), &format!("mkdir {d}/sub"))),
    ]
}

fn check(extra: &str, want: &[(&str, bool)]) {
    let got = outcomes(extra);
    let bad: Vec<_> = want
        .iter()
        .filter(|(k, v)| got.iter().any(|(g, o)| g == k && o != v))
        .collect();
    assert!(
        bad.is_empty(),
        "rules {extra:?}\n got {got:#?}\n wrong {bad:?}"
    );
}

#[test]
fn controls_rename_and_link_succeed_unconfined() {
    let t = dirs();
    let _srv = UnixListener::bind(t.w.join("srv")).unwrap();
    std::fs::write(t.w.join("f"), "x").unwrap();
    let (w, d) = (t.w.display(), t.d.display());
    assert!(run(None, &format!("mv {w}/srv {d}/m && ln {w}/f {d}/l")));
}

const WANT: &[(&str, bool)] = &[
    ("bind in the socket directory", true),
    ("rename a write-tree socket in", false),
    ("hard-link a write-tree file in", false),
];

#[test]
fn no_write_rights() {
    check("", WANT);
}

#[test]
fn create_only() {
    check("(allow file-write-create (subpath \"@D\"))\n", WANT);
}

#[test]
fn create_sockets_only() {
    check(
        "(allow file-write-create (require-all (subpath \"@D\") (vnode-type SOCKET)))\n",
        WANT,
    );
}

#[test]
fn create_and_unlink_sockets_only() {
    check(
        "(allow file-write-create file-write-unlink (require-all (subpath \"@D\") (vnode-type SOCKET)))\n",
        WANT,
    );
}
