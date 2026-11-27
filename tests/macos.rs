//! End-to-end confinement on macOS: `zwinger run` applies a Seatbelt policy with sandbox_init
//! and execs the command, and the command meets Seatbelt's refusals (REQ-ZW-003, prototype).
//!
//! Every "refused" assertion has a negative control: the same probe run unconfined succeeds, so a
//! red probe means confinement, not a broken probe. sandbox_init cannot be nested, so these tests
//! fail inside another sandbox (zwinger exits 78); CI runs them on a hosted macOS runner.
#![cfg(target_os = "macos")]

use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const ZWINGER: &str = env!("CARGO_BIN_EXE_zwinger");
// Every spawn sets ZWINGER_EVENTS_DIR to "" (events off) unless a test sets its own: test runs must
// not drop confinement events where a real warte probe collects them.
/// What Seatbelt returns for a denied operation (sys/errno.h: EPERM = 1).
const EPERM: i32 = 1;

struct Dir(PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A scratch area: `w` (granted writable), `r` (granted read-only), `o` (outside the profile).
struct Scene {
    root: Dir,
    profile: PathBuf,
}

impl Scene {
    fn new(extra: &str) -> Scene {
        static N: AtomicU32 = AtomicU32::new(0);
        // Short names: a UNIX socket path must fit in 104 bytes.
        let root = std::env::temp_dir().join(format!(
            "zw-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        for d in ["w", "r/private", "o"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("r/public"), "public-data\n").unwrap();
        std::fs::write(root.join("r/private/key"), "private-key\n").unwrap();
        std::fs::write(root.join("r/private/pub"), "public-key\n").unwrap();
        std::fs::write(root.join("o/secret"), "secret-data\n").unwrap();
        let exe_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let read = [
            PathBuf::from("/usr"),
            PathBuf::from("/bin"),
            root.join("r"),
            exe_dir,
        ];
        let list = |v: &[PathBuf]| {
            v.iter()
                .map(|p| format!("{:?}", p.to_str().unwrap()))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let write = [root.join("w"), PathBuf::from("/dev/null")];
        let text = format!(
            "name: \"e2e\"\nread: [{}]\nwrite: [{}]\n{}",
            list(&read),
            list(&write),
            extra.replace('@', root.to_str().unwrap())
        );
        let profile = root.join("profile.yaml");
        std::fs::write(&profile, text).unwrap();
        Scene {
            root: Dir(root),
            profile,
        }
    }

    fn check(&self) -> Output {
        Command::new(ZWINGER)
            .env("ZWINGER_EVENTS_DIR", "")
            .arg("check")
            .arg(&self.profile)
            .output()
            .unwrap()
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.0.join(rel)
    }

    fn run(&self, cmd: &[&str]) -> Output {
        self.run_env(cmd, &[])
    }

    fn run_env(&self, cmd: &[&str], env: &[(&str, &str)]) -> Output {
        let o = Command::new(ZWINGER)
            .env("ZWINGER_EVENTS_DIR", "")
            .arg("run")
            .arg(&self.profile)
            .arg("--")
            .args(cmd)
            .envs(env.iter().copied())
            .output()
            .unwrap();
        assert_ne!(
            o.status.code(),
            Some(78),
            "zwinger refused to confine: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        o
    }
}

fn unconfined(cmd: &[&str]) -> Output {
    Command::new(cmd[0]).args(&cmd[1..]).output().unwrap()
}

fn bash(script: &str) -> [&str; 3] {
    ["/bin/bash", "-c", script]
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// Probe one operation from inside a confined process by re-running this test binary; the
/// exit status is 0 on success or the errno.
fn probe(sc: &Scene, what: &str, arg: &str) -> Option<i32> {
    let exe = std::env::current_exe().unwrap();
    let o = sc.run_env(
        &[
            s(&exe),
            "--exact",
            "probe_entry",
            "--test-threads=1",
            "--nocapture",
        ],
        &[("ZWINGER_PROBE", what), ("ZWINGER_PROBE_ARG", arg)],
    );
    o.status.code()
}

fn probe_unconfined(what: &str, arg: &str) -> Option<i32> {
    let exe = std::env::current_exe().unwrap();
    Command::new(exe)
        .args(["--exact", "probe_entry", "--test-threads=1", "--nocapture"])
        .env("ZWINGER_PROBE", what)
        .env("ZWINGER_PROBE_ARG", arg)
        .output()
        .unwrap()
        .status
        .code()
}

/// Not a test of its own: when ZWINGER_PROBE is set, perform one operation and exit with 0 on
/// success or the errno on failure.
#[test]
fn probe_entry() {
    let Ok(what) = std::env::var("ZWINGER_PROBE") else {
        return;
    };
    let arg = std::env::var("ZWINGER_PROBE_ARG").unwrap_or_default();
    let r: std::io::Result<()> = match what.as_str() {
        "read" => std::fs::read(&arg).map(|_| ()),
        "create" => std::fs::write(&arg, "x").map(|_| ()),
        "tcp_connect" => std::net::TcpStream::connect(&arg).map(|_| ()),
        "unix_connect" => std::os::unix::net::UnixStream::connect(&arg).map(|_| ()),
        "unix_bind" => UnixListener::bind(&arg).map(|_| ()),
        "mkdir" => std::fs::create_dir(&arg),
        other => panic!("unknown probe {other}"),
    };
    std::process::exit(r.map(|_| 0).unwrap_or_else(|e| {
        eprintln!("probe {what} {arg}: {e}");
        e.raw_os_error().unwrap_or(-1)
    }));
}

// rivet: verifies REQ-ZW-015
#[test]
fn writes_inside_the_write_tree() {
    let sc = Scene::new("");
    let f = sc.path("w/ok");
    let o = sc.run(&["/usr/bin/touch", s(&f)]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(f.exists());
}

// rivet: verifies REQ-ZW-015
#[test]
fn writes_outside_the_profile_are_refused_with_eperm() {
    let sc = Scene::new("");
    assert_eq!(
        probe_unconfined("create", s(&sc.path("o/control"))),
        Some(0),
        "control: the probe can write there unconfined"
    );
    let f = sc.path("o/new");
    assert_eq!(probe(&sc, "create", s(&f)), Some(EPERM));
    assert!(
        !f.exists(),
        "confined session wrote outside its write trees"
    );
    // and through a real tool
    assert!(!sc.run(&["/usr/bin/touch", s(&f)]).status.success());
    assert!(!f.exists());
}

// rivet: verifies REQ-ZW-015
#[test]
fn read_only_tree_is_readable_not_writable() {
    let sc = Scene::new("");
    let o = sc.run(&["/bin/cat", s(&sc.path("r/public"))]);
    assert_eq!(String::from_utf8_lossy(&o.stdout), "public-data\n");
    assert_eq!(probe(&sc, "create", s(&sc.path("r/public"))), Some(EPERM));
    let script = format!(": > {}", s(&sc.path("r/public")));
    assert!(
        !sc.run(&bash(&script)).status.success(),
        "truncate in a read-only tree"
    );
    assert_eq!(
        std::fs::read_to_string(sc.path("r/public")).unwrap(),
        "public-data\n"
    );
}

// rivet: verifies REQ-ZW-015
#[test]
fn reads_outside_the_profile_are_refused() {
    let sc = Scene::new("");
    let secret = sc.path("o/secret");
    assert!(unconfined(&["/bin/cat", s(&secret)]).status.success());
    assert_eq!(probe_unconfined("read", s(&secret)), Some(0));
    assert_eq!(probe(&sc, "read", s(&secret)), Some(EPERM));
    let o = sc.run(&["/bin/cat", s(&secret)]);
    assert!(!o.status.success());
    assert!(!String::from_utf8_lossy(&o.stdout).contains("secret-data"));
}

// rivet: verifies REQ-ZW-015
#[test]
fn deny_read_inside_a_grant_is_refused_and_a_stated_exception_is_not() {
    // What Landlock cannot express: a denied subtree inside a granted one.
    let sc = Scene::new("deny_read: [\"@/r/private\"]\nread_if_present: [\"@/r/private/pub\"]\n");
    let key = sc.path("r/private/key");
    assert_eq!(probe_unconfined("read", s(&key)), Some(0), "control");
    assert_eq!(probe(&sc, "read", s(&key)), Some(EPERM));
    let o = sc.run(&["/bin/cat", s(&key)]);
    assert!(!String::from_utf8_lossy(&o.stdout).contains("private-key"));
    // the rest of the grant, and the exception stated inside the denied tree, stay readable
    assert_eq!(probe(&sc, "read", s(&sc.path("r/public"))), Some(0));
    assert_eq!(probe(&sc, "read", s(&sc.path("r/private/pub"))), Some(0));
}

// rivet: verifies REQ-ZW-015
#[test]
fn carve_outs_inside_a_write_tree_are_refused() {
    // Seatbelt matches paths. Inside a write tree the session could rename a directory above a
    // carve-out, or hard-link a file out of it, and the rule would match nothing: refused, as
    // on Linux, for each kind. Show first that the rename really changes the path.
    let sc = Scene::new("");
    std::fs::create_dir_all(sc.path("w/a/locked")).unwrap();
    let o = sc.run(&bash(&format!(
        "mv {} {} && test -d {}",
        s(&sc.path("w/a")),
        s(&sc.path("w/b")),
        s(&sc.path("w/b/locked"))
    )));
    assert!(
        o.status.success(),
        "control: a write tree allows renaming a directory"
    );
    refused("deny_write: [\"@/w/a/locked\"]\n");
    refused("deny_read: [\"@/w/a/locked\"]\n");
    refused("noexec: [\"@/w/a\"]\n");
}

// rivet: verifies REQ-ZW-015
#[test]
fn tcp_connect_is_refused_under_mode_none() {
    let sc = Scene::new("");
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    assert_eq!(probe_unconfined("tcp_connect", &addr), Some(0), "control");
    assert_eq!(probe(&sc, "tcp_connect", &addr), Some(EPERM));
}

// rivet: verifies REQ-ZW-015
#[test]
fn unfiltered_network_allows_tcp_but_paths_stay_confined() {
    let sc = Scene::new("network:\n  mode: \"unfiltered\"\n");
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    assert_eq!(probe(&sc, "tcp_connect", &addr), Some(0));
    let f = sc.path("o/new");
    assert_eq!(probe(&sc, "create", s(&f)), Some(EPERM));
    assert!(
        !f.exists(),
        "unfiltered network must not open the filesystem"
    );
}

// rivet: verifies REQ-ZW-015
#[test]
fn unfiltered_network_keeps_unix_sockets_confined() {
    // mode = unfiltered opens IP networking, not UNIX sockets: unix_sockets stays confined.
    let sc = Scene::new("network:\n  mode: \"unfiltered\"\n");
    let outside = sc.path("o/s");
    let _lo = UnixListener::bind(&outside).unwrap();
    assert_eq!(
        probe_unconfined("unix_connect", s(&outside)),
        Some(0),
        "control"
    );
    assert_eq!(probe(&sc, "unix_connect", s(&outside)), Some(EPERM));
    assert_eq!(probe(&sc, "unix_bind", s(&sc.path("o/b"))), Some(EPERM));
    let inside = sc.path("w/s");
    let _li = UnixListener::bind(&inside).unwrap();
    assert_eq!(probe(&sc, "unix_connect", s(&inside)), Some(0));
}

// rivet: verifies REQ-ZW-015
#[test]
fn denials_hold_for_another_spelling_of_the_path() {
    // macOS volumes are usually case-insensitive; a denial must not be bypassed by spelling
    // the path in another case.
    let sc = Scene::new("deny_read: [\"@/r/private\"]\n");
    let upper = sc.path("r/PRIVATE/key");
    assert_eq!(
        probe_unconfined("read", s(&upper)),
        Some(0),
        "control: the volume is case-insensitive, so the other spelling reaches the file"
    );
    assert_eq!(
        probe(&sc, "read", s(&upper)),
        Some(EPERM),
        "existing deny_read"
    );
    // A denial stated in another case than the name on disk.
    let sc = Scene::new("deny_read: [\"@/r/PUBLIC\"]\n");
    assert_eq!(probe_unconfined("read", s(&sc.path("r/public"))), Some(0));
    assert_eq!(
        probe(&sc, "read", s(&sc.path("r/public"))),
        Some(EPERM),
        "deny_read stated in upper case"
    );
}

// rivet: verifies REQ-ZW-015
#[test]
fn unix_sockets_reach_only_write_trees() {
    let sc = Scene::new("");
    let outside = sc.path("o/s");
    let _lo = UnixListener::bind(&outside).unwrap();
    assert_eq!(
        probe_unconfined("unix_connect", s(&outside)),
        Some(0),
        "control"
    );
    assert_eq!(probe(&sc, "unix_connect", s(&outside)), Some(EPERM));
    let inside = sc.path("w/s");
    let _li = UnixListener::bind(&inside).unwrap();
    assert_eq!(probe(&sc, "unix_connect", s(&inside)), Some(0));
    assert_eq!(probe(&sc, "unix_bind", s(&sc.path("w/b"))), Some(0));
}

// rivet: verifies REQ-ZW-015
#[test]
fn unfiltered_unix_sockets_reach_outside_but_tcp_stays_refused() {
    let sc = Scene::new("network:\n  unix_sockets: \"unfiltered\"\n");
    let outside = sc.path("o/s");
    let _lo = UnixListener::bind(&outside).unwrap();
    assert_eq!(probe(&sc, "unix_connect", s(&outside)), Some(0));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    assert_eq!(probe_unconfined("tcp_connect", &addr), Some(0), "control");
    assert_eq!(probe(&sc, "tcp_connect", &addr), Some(EPERM));
}

// rivet: verifies REQ-ZW-015
#[test]
fn inherited_descriptors_do_not_leak_into_the_session() {
    let sc = Scene::new("");
    let log = sc.path("o/log");
    let control = sc.path("o/control-log");
    let script = |target: &Path, inner: &str| format!("exec 3>>{}; {inner}", s(target));
    // Control: without zwinger the inner shell writes through fd 3.
    let o = unconfined(&bash(&script(&control, "/bin/bash -c 'echo leaked >&3'")));
    assert!(o.status.success());
    assert_eq!(std::fs::read_to_string(&control).unwrap(), "leaked\n");
    let inner = format!(
        "{ZWINGER} run {} -- /bin/bash -c '/usr/bin/touch {}; echo leaked >&3'",
        s(&sc.profile),
        s(&sc.path("w/ran"))
    );
    let o = unconfined(&bash(&script(&log, &inner)));
    // The session ran (a refusal would leave the log empty too).
    assert!(
        sc.path("w/ran").exists(),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&log).unwrap_or_default(),
        "",
        "fd 3 leaked into the session"
    );
}

/// A copy of /usr/bin/true at `rel`, made outside the session.
fn copy_true(sc: &Scene, rel: &str) -> PathBuf {
    let t = sc.path(rel);
    std::fs::create_dir_all(t.parent().unwrap()).unwrap();
    assert!(
        Command::new("/bin/cp")
            .args(["/usr/bin/true", s(&t)])
            .status()
            .unwrap()
            .success()
    );
    t
}

// rivet: verifies REQ-ZW-013
// rivet: verifies REQ-ZW-015
#[test]
fn noexec_on_a_write_tree_refuses_exec_but_not_reading_or_writing() {
    let sc = Scene::new("noexec: [\"@/w\"]\n");
    let t = copy_true(&sc, "w/t");
    let ok = copy_true(&sc, "r/t");
    assert!(
        unconfined(&[s(&t)]).status.success(),
        "control: it runs unconfined"
    );
    let o = sc.run(&[s(&t)]);
    // The exec itself fails, so zwinger reports it as not executable (126).
    assert_eq!(
        o.status.code(),
        Some(126),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    // The same file in a read tree runs confined, and the noexec tree stays readable and
    // writable.
    assert!(sc.run(&[s(&ok)]).status.success());
    assert_eq!(probe(&sc, "read", s(&t)), Some(0));
    assert_eq!(probe(&sc, "create", s(&sc.path("w/f"))), Some(0));
}

// rivet: verifies REQ-ZW-015
#[test]
fn exit_status_passes_through_and_a_missing_command_is_127() {
    let sc = Scene::new("");
    let o = sc.run(&bash("exit 7"));
    assert_eq!(o.status.code(), Some(7));
    let o = Command::new(ZWINGER)
        .env("ZWINGER_EVENTS_DIR", "")
        .args(["run", s(&sc.profile), "--", "/nonexistent/cmd"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(127));
}

/// A profile the macOS backend cannot enforce is refused before the command runs, by run and
/// by check.
fn refused(extra: &str) {
    let sc = Scene::new(extra);
    let marker = sc.path("w/ran");
    let o = Command::new(ZWINGER)
        .env("ZWINGER_EVENTS_DIR", "")
        .arg("run")
        .arg(&sc.profile)
        .arg("--")
        .args(["/usr/bin/touch", s(&marker)])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(78),
        "{extra}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(!marker.exists(), "{extra}: the command ran");
    assert_eq!(
        sc.check().status.code(),
        Some(78),
        "check passed what run refuses: {extra}"
    );
}

// rivet: verifies REQ-ZW-015
#[test]
fn unenforceable_profiles_are_refused_end_to_end() {
    refused("network:\n  allow: [\"github.com\"]\n");
    refused("network:\n  allow_local_binding: true\n");
    // a path the policy cannot quote safely
    refused("deny_read: [\"@/o/q\\\"uote\"]\n");
    refused("read: [\"@/absent\"]\n");
}

// rivet: verifies REQ-ZW-015
#[test]
fn session_sees_the_profile_and_the_startup_line_names_seatbelt() {
    let sc = Scene::new("write_if_present: [\"@/absent\"]\n");
    let o = sc.run(&bash("echo \"$ZWINGER_PROFILE\""));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(String::from_utf8_lossy(&o.stdout), "e2e\n");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.starts_with("zwinger: e2e confined: seatbelt; 4 read, 2 write grants"),
        "{err}"
    );
    assert!(err.contains("network: none"), "{err}");
    assert!(
        err.contains(&format!("absent, skipped: {}", s(&sc.path("absent")))),
        "{err}"
    );
}

// rivet: verifies REQ-ZW-015
#[test]
fn check_reports_what_run_would_enforce_without_running_anything() {
    let sc = Scene::new("");
    let c = sc.check();
    assert!(c.status.success(), "{}", String::from_utf8_lossy(&c.stderr));
    let out = String::from_utf8_lossy(&c.stdout);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "{out}");
    assert_eq!(lines[0], "zwinger: profile e2e ok");
    assert!(
        lines[1].starts_with("zwinger: e2e would be confined: seatbelt;"),
        "{out}"
    );
    std::fs::remove_dir(sc.path("w")).unwrap();
    let c = sc.check();
    assert_eq!(c.status.code(), Some(78));
    let err = String::from_utf8_lossy(&c.stderr);
    assert!(err.contains(s(&sc.path("w"))), "{err}");
    assert!(err.contains("No such file or directory"), "{err}");
}

// rivet: verifies REQ-ZW-015
#[test]
fn a_denial_inside_a_read_exception_stays_denied() {
    // deny_read r/private, read the exception r/private/pubdir, deny_read
    // r/private/pubdir/secret inside it: the exception must not re-open the inner secret.
    let sc = Scene::new(
        "deny_read: [\"@/r/private\", \"@/r/private/pubdir/secret\"]\n\
         read_if_present: [\"@/r/private/pubdir\"]\n",
    );
    std::fs::create_dir_all(sc.path("r/private/pubdir")).unwrap();
    std::fs::write(sc.path("r/private/pubdir/ok"), "ok\n").unwrap();
    std::fs::write(sc.path("r/private/pubdir/secret"), "inner-secret\n").unwrap();
    let secret = sc.path("r/private/pubdir/secret");
    assert_eq!(probe_unconfined("read", s(&secret)), Some(0), "control");
    assert_eq!(
        probe(&sc, "read", s(&sc.path("r/private/pubdir/ok"))),
        Some(0)
    );
    assert_eq!(probe(&sc, "read", s(&secret)), Some(EPERM));
}

// rivet: verifies REQ-ZW-015
#[test]
fn hard_links_cannot_give_an_unreadable_file_a_readable_path() {
    // A hard link needs no read access to its source, and the new name lies in a write tree.
    // If Seatbelt did not check the link's source, any unreadable file on the same volume
    // (outside every grant, or under a deny_read inside a read grant) could be linked into a
    // write tree and read there. Linux blocks this with Landlock's REFER right.
    let sc = Scene::new("deny_read: [\"@/r/private\"]\n");
    for (secret, name) in [
        (sc.path("o/secret"), "w/l1"),
        (sc.path("r/private/key"), "w/l2"),
    ] {
        let link = sc.path(name);
        let o = sc.run(&bash(&format!(
            "ln {} {} 2>/dev/null; cat {} 2>/dev/null",
            s(&secret),
            s(&link),
            s(&link)
        )));
        let out = String::from_utf8_lossy(&o.stdout);
        assert!(
            !out.contains("secret-data") && !out.contains("private-key"),
            "read {} through a hard link: {out}",
            secret.display()
        );
        assert!(
            !link.exists(),
            "the hard link to {} was created",
            secret.display()
        );
        // Control: unconfined, the same link works.
        let ok = sc.path(&format!("{name}-control"));
        assert!(
            Command::new("/bin/ln")
                .args([s(&secret), s(&ok)])
                .status()
                .unwrap()
                .success(),
            "control: ln works unconfined"
        );
    }
}

// rivet: verifies REQ-ZW-021
#[test]
fn the_session_receives_its_plan_in_zwinger_grants() {
    let sc = Scene::new("deny_read: [\"@/r/private\"]\nnoexec: [\"@/w\"]\n");
    let o = sc.run(&["/usr/bin/printenv", zwinger::grants::VAR]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).expect("ZWINGER_GRANTS is JSON");
    assert_eq!(v["schema"], zwinger::grants::SCHEMA);
    let has = |key: &str, p: PathBuf| {
        let p = p.canonicalize().unwrap();
        let list = v[key]
            .as_array()
            .unwrap_or_else(|| panic!("{key} is a list"));
        assert!(
            list.iter().any(|e| e.as_str() == p.to_str()),
            "{key} lacks {}: {v}",
            p.display()
        );
    };
    has("read", sc.path("r"));
    has("write", sc.path("w"));
    has("deny_read", sc.path("r/private"));
    has("noexec", sc.path("w"));
    assert_eq!(v["exec"], serde_json::json!([]));
}

// rivet: verifies REQ-ZW-024
#[test]
fn run_refuses_a_profile_inside_its_own_write_grant() {
    let sc = Scene::new("");
    let marker = sc.path("w/ran");
    let inside = sc.path("w/profile.yaml");
    std::fs::copy(&sc.profile, &inside).unwrap();
    let o = Command::new(ZWINGER)
        .env("ZWINGER_EVENTS_DIR", "")
        .args(["run", s(&inside), "--", "/usr/bin/touch", s(&marker)])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(78),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("lies inside write grant"));
    assert!(!marker.exists(), "the command must not have run");
    // Control: the same profile outside the grant runs the command.
    let o = sc.run(&["/usr/bin/touch", s(&marker)]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(marker.exists());
// rivet: verifies REQ-ZW-022
#[test]
fn code_injecting_variables_are_removed_unless_kept() {
    // Not DYLD_*: SIP strips those from /usr/bin binaries by itself, which would hide a failure.
    let sc = Scene::new("env_keep: [\"GIT_SSH_COMMAND\"]\n");
    let env = [
        ("BASH_ENV", "/nonexistent-zwinger-test/rc"),
        ("RUSTC_WRAPPER", "/nonexistent-zwinger-test/w"),
        ("GIT_SSH_COMMAND", "ssh -v"),
        ("ZWINGER_TEST_ORDINARY", "1"),
    ];
    let o = sc.run_env(&["/usr/bin/env"], &env);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out = String::from_utf8_lossy(&o.stdout);
    let lines: Vec<&str> = out.lines().collect();
    assert!(!lines.iter().any(|l| l.starts_with("BASH_ENV=")), "{out}");
    assert!(
        !lines.iter().any(|l| l.starts_with("RUSTC_WRAPPER=")),
        "{out}"
    );
    assert!(
        lines.contains(&"GIT_SSH_COMMAND=ssh -v"),
        "kept by env_keep: {out}"
    );
    assert!(
        lines.contains(&"ZWINGER_TEST_ORDINARY=1"),
        "not on the list: {out}"
    );
    let err = String::from_utf8_lossy(&o.stderr);
    // Every planted scrubbed variable is named; cargo sets DYLD_FALLBACK_LIBRARY_PATH for tests
    // on macOS, which is removed too.
    let removed = err.split("; environment removed: ").nth(1).unwrap_or("");
    for v in ["BASH_ENV", "RUSTC_WRAPPER"] {
        assert!(
            removed.split(", ").any(|r| r.trim() == v),
            "{v} not named: {err}"
        );
    }
    assert!(
        !removed.contains("GIT_SSH_COMMAND"),
        "kept by env_keep: {err}"
    );
}
