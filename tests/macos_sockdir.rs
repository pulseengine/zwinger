//! The Seatbelt rules for the per-session socket directory (#40), measured. The session must
//! bind and connect there; nothing from a write tree should get in. bind() needs
//! file-write-create, and Seatbelt checks a rename's target as the same right, so a socket already
//! in a write tree can be renamed in: that residual is asserted, so a change is noticed.
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
    let unlink = format!("rm -f {d}/s && ! test -e {d}/s");
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

#[test]
fn controls_rename_and_link_succeed_unconfined() {
    let t = dirs();
    let _srv = UnixListener::bind(t.w.join("srv")).unwrap();
    std::fs::write(t.w.join("f"), "x").unwrap();
    let (w, d) = (t.w.display(), t.d.display());
    assert!(run(None, &format!("mv {w}/srv {d}/m && ln {w}/f {d}/l")));
}

#[test]
fn bind_needs_a_write_right() {
    // No write rights in the directory: bind() is refused, so some create right is needed.
    let got = outcomes("");
    assert!(
        got.contains(&("bind in the socket directory", false)),
        "{got:#?}"
    );
}

// rivet: verifies REQ-ZW-027
#[test]
fn the_session_socket_rules() {
    // The rules zwinger emits (src/macos.rs session_socket_rules).
    let got = outcomes(&zwinger::macos::session_socket_rules("\"@D\""));
    let want = [
        ("bind in the socket directory", true),
        ("unlink own socket", true),
        ("hard-link a write-tree file in", false),
        ("create a regular file", false),
        ("mkdir", false),
        // The residual, asserted so a change in Seatbelt is noticed: a rename's target is
        // checked as file-write-create, which sockets need for bind (docs/profile.md).
        ("rename a write-tree socket in", true),
    ];
    for w in want {
        assert!(got.contains(&w), "want {w:?}\n got {got:#?}");
    }
}
