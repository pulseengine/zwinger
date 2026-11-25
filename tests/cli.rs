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

#[test]
fn check_refuses_a_missing_profile() {
    let o = zwinger(&["check", "/nonexistent/zwinger.toml"]);
    assert_eq!(o.status.code(), Some(78));
}

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
fn bad_usage_is_64() {
    assert_eq!(zwinger(&[]).status.code(), Some(64));
}
