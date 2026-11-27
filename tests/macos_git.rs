//! Seatbelt and a read-only `.git` inside a write tree (#14, macOS half): which operations a
//! policy of zwinger's shape refuses when `.git` is denied for writing directly under a write
//! root. The policy is applied with sandbox-exec, so this measures Seatbelt itself, ahead of
//! wiring the rule into zwinger.
//!
//! The root cannot be renamed (its parent is outside the grants), so nothing can be renamed
//! above `.git`. The open question is a hard link out of `.git`: Seatbelt matches paths, so a
//! write through a link elsewhere in the write tree would change the same inode. Each refusal
//! has a control: the same operation on a path outside `.git` succeeds.
#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

struct Repo(PathBuf);
impl Drop for Repo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn git(dir: &Path, args: &[&str]) {
    let o = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

/// A committed repository in a fresh directory, by its resolved path.
fn repo() -> Repo {
    static N: AtomicU32 = AtomicU32::new(0);
    let d = std::env::temp_dir().join(format!(
        "zwg-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    let d = d.canonicalize().unwrap();
    git(&d, &["init", "-q"]);
    std::fs::write(d.join("a.txt"), "one\n").unwrap();
    git(&d, &["add", "a.txt"]);
    git(&d, &["commit", "-q", "-m", "one"]);
    std::fs::write(d.join("a.txt"), "two\n").unwrap();
    Repo(d)
}

/// zwinger's shape: writes only in the write root (and /dev/null), then `.git` taken back.
/// `extra` is appended last (Seatbelt: the last matching rule wins).
fn policy(w: &Path, extra: &str) -> String {
    let w = w.to_str().unwrap();
    format!(
        "(version 1)\n(allow default)\n(deny file-write*)\n\
         (allow file-write* (subpath \"{w}\") (literal \"/dev/null\"))\n\
         (deny file-write* (subpath \"{w}/.git\"))\n{extra}"
    )
}

/// Run a bash script under the policy; Ok(true) when it exits 0, Err when sandbox-exec
/// rejects the policy itself.
fn sandboxed(policy: &str, w: &Path, script: &str) -> Result<bool, String> {
    let o = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", policy, "/bin/bash", "-c", script])
        .current_dir(w)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    if err.contains("sandbox-exec:") {
        return Err(err.into_owned());
    }
    eprintln!("  {script} -> {:?} {}", o.status.code(), err.trim());
    Ok(o.status.success())
}

fn config(w: &Path) -> String {
    std::fs::read_to_string(w.join(".git/config")).unwrap()
}

/// Checks every expectation under one policy and returns the failures.
fn check(extra: impl Fn(&Path) -> String) -> Result<Vec<String>, String> {
    let r = repo();
    let w = &r.0;
    let p = policy(w, &extra(w));
    let mut bad = Vec::new();
    let mut want = |what: &str, ok: bool, expected: bool| {
        if ok != expected {
            bad.push(format!("{what}: got {ok}, want {expected}"));
        }
    };
    // Controls: the write tree is writable, and git's read-only commands work.
    want(
        "write in the tree",
        sandboxed(&p, w, "echo x > b.txt")?,
        true,
    );
    want(
        "git status",
        sandboxed(&p, w, "git status --porcelain")?,
        true,
    );
    want(
        "git diff",
        sandboxed(&p, w, "git diff --quiet; test $? -eq 1")?,
        true,
    );
    want("git log", sandboxed(&p, w, "git log --oneline -1")?, true);
    // The rule.
    want(
        "write .git/hooks",
        sandboxed(&p, w, "echo x > .git/hooks/pre-commit")?,
        false,
    );
    want(
        "append .git/config",
        sandboxed(&p, w, "echo x >> .git/config")?,
        false,
    );
    want("rename .git", sandboxed(&p, w, "mv .git aside")?, false);
    want("remove .git", sandboxed(&p, w, "rm -rf .git")?, false);
    want(
        "commit directly",
        sandboxed(
            &p,
            w,
            "git -c user.name=t -c user.email=t@invalid commit -qam two",
        )?,
        false,
    );
    // Control: a hard link between two files outside .git succeeds, so a refused link below is
    // the rule and not ln failing for another reason.
    want(
        "hard link in the tree",
        sandboxed(&p, w, "ln b.txt b2.txt")?,
        true,
    );
    // A hard link out of .git, then a write through it.
    let before = config(w);
    let linked = sandboxed(&p, w, "ln .git/config cfg")?;
    // Stronger than the inode check below: the link itself must be refused, so no name for a
    // .git inode exists outside .git.
    want("hard link out of .git", linked, false);
    if linked {
        let _ = sandboxed(&p, w, "echo '[core] fsmonitor = x' >> cfg")?;
    }
    want("config unchanged through a link", config(w) == before, true);
    Ok(bad)
}

#[test]
fn readonly_git_with_path_rules_only() {
    match check(|_| String::new()) {
        Ok(bad) => assert!(bad.is_empty(), "{bad:#?}"),
        Err(e) => panic!("policy rejected: {e}"),
    }
}

#[test]
fn readonly_git_with_hard_links_denied() {
    // Seatbelt's file-link operation, if this macOS has it, on the link's source.
    match check(|w| format!("(deny file-link (subpath \"{}/.git\"))\n", w.display())) {
        Ok(bad) => assert!(bad.is_empty(), "{bad:#?}"),
        Err(e) => panic!("policy rejected (no file-link operation?): {e}"),
    }
}
