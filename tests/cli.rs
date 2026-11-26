use std::process::Command;

fn zwinger(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_zwinger"))
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
        let p = std::env::temp_dir().join(format!("zwinger-test-{}-{n}.toml", std::process::id()));
        std::fs::write(&p, text).unwrap();
        Path(p)
    }
}

#[test]
fn check_accepts_a_valid_profile() {
    let p = profile("name = \"s\"\nwrite = [\"/tmp/s\"]\n");
    let o = zwinger(&["check", p.0.to_str().unwrap()]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

// rivet: verifies REQ-ZW-001
#[test]
fn check_refuses_a_missing_profile() {
    let o = zwinger(&["check", "/nonexistent/zwinger.toml"]);
    assert_eq!(o.status.code(), Some(78));
}

// rivet: verifies REQ-ZW-001
#[cfg(not(target_os = "linux"))]
#[test]
fn run_never_starts_unconfined() {
    // A valid profile, a harmless command: still refused, because no backend exists (REQ-ZW-001).
    let marker = std::env::temp_dir().join(format!("zwinger-ran-{}", std::process::id()));
    let p = profile("name = \"s\"\n");
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
        &["run", "p.toml", "x"],
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
        "name = \"s\"\nwrite = [{:?}]\n",
        dir.join("w").to_str().unwrap()
    ));
    let f = dir.join("w/f");
    let o = zwinger(&["explain", p.0.to_str().unwrap(), f.to_str().unwrap()]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(out.contains("write: allowed (write "), "{out}");
    let o = zwinger(&["explain", p.0.to_str().unwrap(), "tcp:443"]);
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("tcp port 443: denied"));
    let o = zwinger(&["explain", "/nonexistent/z.toml", "/x"]);
    assert_eq!(o.status.code(), Some(78));
    let _ = std::fs::remove_dir_all(&dir);
}
