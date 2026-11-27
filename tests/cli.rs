use std::process::Command;

fn zwinger(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_zwinger"))
        .env("ZWINGER_EVENTS_DIR", "")
        .args(args)
        .output()
        .unwrap()
}

fn profile(text: &str) -> tempfile_path::Path {
    tempfile_path::write(text)
}

mod tempfile_path {
    pub struct Path(pub std::path::PathBuf);
    impl Drop for Path {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    pub fn write(text: &str) -> Path {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("zwinger-test-{}-{n}.yaml", std::process::id()));
        std::fs::write(&p, text).unwrap();
        Path(p)
    }
}

#[test]
fn check_accepts_a_valid_profile() {
    // A write tree that exists: on Linux, check plans the paths as run would. It is a
    // subdirectory, so the profile (in the temp dir) lies outside it (REQ-ZW-024).
    let dir = std::env::temp_dir().join(format!("zwinger-cli-w-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = profile(&format!("name: s\nwrite: [{:?}]\n", dir.to_str().unwrap()));
    let o = zwinger(&["check", p.0.to_str().unwrap()]);
    let _ = std::fs::remove_dir(&dir);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

// rivet: verifies REQ-ZW-001
#[test]
fn check_refuses_a_missing_profile() {
    let o = zwinger(&["check", "/nonexistent/zwinger.yaml"]);
    assert_eq!(o.status.code(), Some(78));
}

// rivet: verifies REQ-ZW-001
#[test]
fn run_never_starts_unconfined() {
    // A valid profile no backend can enforce (no backend filters by host name), a harmless
    // command: refused on every platform, with or without a backend (REQ-ZW-001).
    let marker = std::env::temp_dir().join(format!("zwinger-ran-{}", std::process::id()));
    let p = profile("name: \"s\"\nnetwork:\n  allow: [\"example.org\"]\n");
    let o = zwinger(&[
        "run",
        p.0.to_str().unwrap(),
        "--",
        "touch",
        marker.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(78));
    assert!(!marker.exists(), "the command ran unconfined");
}

#[test]
fn bad_usage_exits_2() {
    for args in [
        &[][..],
        &["--frobnicate"],
        &["frobnicate"],
        &["check"],
        &["run", "p.yaml", "x"],
    ] {
        let o = zwinger(args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8_lossy(&o.stderr).starts_with("usage: zwinger"),
            "{args:?}"
        );
    }
}

#[test]
fn version_and_help_exit_0() {
    for flag in ["--version", "-V"] {
        let o = zwinger(&[flag]);
        assert!(o.status.success());
        assert_eq!(
            String::from_utf8_lossy(&o.stdout),
            format!("zwinger {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
    assert!(zwinger(&["--help"]).status.success());
}

// rivet: verifies REQ-ZW-010
#[test]
fn explain_names_the_rule_for_a_path_and_a_port() {
    let dir = std::env::temp_dir().join(format!("zwinger-explain-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("w")).unwrap();
    let p = profile(&format!(
        "name: \"s\"\nwrite: [{:?}]\n",
        dir.join("w").to_str().unwrap()
    ));
    let f = dir.join("w/f");
    let o = zwinger(&["explain", p.0.to_str().unwrap(), f.to_str().unwrap()]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(out.contains("write: allowed (write "), "{out}");
    let o = zwinger(&["explain", p.0.to_str().unwrap(), "tcp:443"]);
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("tcp port 443: denied"));
    let o = zwinger(&["explain", "/nonexistent/z.yaml", "/x"]);
    assert_eq!(o.status.code(), Some(78));
    let _ = std::fs::remove_dir_all(&dir);
}

// rivet: verifies REQ-ZW-014
#[test]
fn run_with_an_unloadable_profile_writes_a_profile_refusal_event() {
    let dir = std::env::temp_dir().join(format!("zwinger-cli-events-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let o = Command::new(env!("CARGO_BIN_EXE_zwinger"))
        .args(["run", "/nonexistent/zwinger.yaml", "--", "/bin/true"])
        .env("ZWINGER_EVENTS_DIR", &dir)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(78));
    let files: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert_eq!(files.len(), 1);
    let text = std::fs::read_to_string(files[0].as_ref().unwrap().path()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["verdict"], "refused");
    assert_eq!(v["category"], "profile");
    assert_eq!(v["profile"], serde_json::Value::Null);
    assert_eq!(v["profile_sha256"], serde_json::Value::Null);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_empty_events_dir_turns_events_off() {
    let o = Command::new(env!("CARGO_BIN_EXE_zwinger"))
        .args(["run", "/nonexistent/zwinger.yaml", "--", "/bin/true"])
        .env("ZWINGER_EVENTS_DIR", "")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(78));
    assert!(!String::from_utf8_lossy(&o.stderr).contains("events:"));
}

// rivet: verifies REQ-ZW-024
#[test]
fn check_refuses_a_profile_inside_its_own_write_grant() {
    let root = std::env::temp_dir()
        .join(format!("zwinger-cli-selfgrant-{}", std::process::id()))
        .canonicalize()
        .unwrap_or_else(|_| {
            let d =
                std::env::temp_dir().join(format!("zwinger-cli-selfgrant-{}", std::process::id()));
            std::fs::create_dir_all(&d).unwrap();
            d.canonicalize().unwrap()
        });
    std::fs::create_dir_all(root.join("w")).unwrap();
    std::fs::create_dir_all(root.join("safe")).unwrap();
    let text = format!(
        "name: \"s\"\nread: [\"/usr\"]\nwrite: [{:?}]\n",
        root.join("w").to_str().unwrap()
    );
    let inside = root.join("w/profile.yaml");
    let outside = root.join("safe/profile.yaml");
    std::fs::write(&inside, &text).unwrap();
    std::fs::write(&outside, &text).unwrap();

    let o = zwinger(&["check", inside.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(78));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("lies inside write grant"), "{err}");

    // Control: the same profile outside the grant is not refused for this reason.
    let o = zwinger(&["check", outside.to_str().unwrap()]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!err.contains("lies inside write grant"), "{err}");
    let _ = std::fs::remove_dir_all(&root);
}

// rivet: verifies REQ-ZW-024
#[test]
fn check_refuses_zwinger_invoked_through_a_symlink_inside_a_write_grant() {
    let root = std::env::temp_dir().join(format!("zwinger-cli-arg0-{}", std::process::id()));
    std::fs::create_dir_all(root.join("w")).unwrap();
    std::fs::create_dir_all(root.join("safe")).unwrap();
    let root = root.canonicalize().unwrap();
    let link = root.join("w/zwinger");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_zwinger"), &link).unwrap();
    let profile = root.join("safe/profile.yaml");
    std::fs::write(
        &profile,
        format!(
            "name: \"a\"\nwrite: [{:?}]\n",
            root.join("w").to_str().unwrap()
        ),
    )
    .unwrap();
    let o = Command::new(&link)
        .env("ZWINGER_EVENTS_DIR", "")
        .args(["check", profile.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(78));
    let err = String::from_utf8_lossy(&o.stderr);
    // macOS reports the invoked symlink as the executable, Linux resolves it; either check
    // must refuse.
    assert!(
        err.contains("lies inside write grant")
            && (err.contains("zwinger invocation path") || err.contains("zwinger executable")),
        "{err}"
    );
    // Control: invoked by its own path, the same profile is not refused for this reason.
    let o = zwinger(&["check", profile.to_str().unwrap()]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!err.contains("lies inside write grant"), "{err}");
    let _ = std::fs::remove_dir_all(&root);
}
