//! End-to-end confinement on a real Linux kernel: `zwinger run` applies Landlock and seccomp and
//! execs the command, and the command meets the kernel's refusals (REQ-ZW-004..006).
//!
//! Every "refused" assertion has a negative control: the same probe run unconfined succeeds, so a
//! red probe means confinement, not a broken probe. These tests need Landlock ABI >= 3; on a
//! kernel without it they fail (zwinger exits 78), which is the point.
#![cfg(target_os = "linux")]

use std::io::Write;
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const ZWINGER: &str = env!("CARGO_BIN_EXE_zwinger");
// Every spawn sets ZWINGER_EVENTS_DIR to "" (events off) unless a test sets its own: test runs must
// not drop confinement events where a real warte probe collects them.

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
        let root = std::env::temp_dir().join(format!(
            "zwinger-e2e-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        for d in ["w", "r", "o"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("r/public"), "public-data\n").unwrap();
        std::fs::write(root.join("o/secret"), "secret-data\n").unwrap();
        let exe_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let mut read: Vec<PathBuf> = ["/usr", "/bin", "/lib", "/lib64", "/etc"]
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect();
        read.push(root.join("r"));
        read.push(exe_dir);
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

fn sh(script: &str) -> Vec<String> {
    vec!["/bin/sh".into(), "-c".into(), script.into()]
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

// rivet: verifies REQ-ZW-004
#[test]
fn writes_inside_the_write_tree() {
    let sc = Scene::new("");
    let f = sc.path("w/ok");
    let o = sc.run(&["/usr/bin/touch", s(&f)]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(f.exists());
}

// rivet: verifies REQ-ZW-004
#[test]
fn writes_outside_the_profile_are_refused() {
    let sc = Scene::new("");
    let f = sc.path("o/new");
    assert!(
        unconfined(&["/usr/bin/touch", s(&sc.path("o/control"))])
            .status
            .success()
    );
    let o = sc.run(&["/usr/bin/touch", s(&f)]);
    assert!(!o.status.success());
    assert!(
        !f.exists(),
        "confined session wrote outside its write trees"
    );
}

// rivet: verifies REQ-ZW-004
#[test]
fn read_only_tree_is_readable_not_writable() {
    let sc = Scene::new("");
    let o = sc.run(&["/bin/cat", s(&sc.path("r/public"))]);
    assert_eq!(String::from_utf8_lossy(&o.stdout), "public-data\n");
    let script = format!("echo x >> {}", s(&sc.path("r/public")));
    let o = sc.run(&bash(&script));
    assert!(!o.status.success());
    assert_eq!(
        std::fs::read_to_string(sc.path("r/public")).unwrap(),
        "public-data\n"
    );
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

// rivet: verifies REQ-ZW-004
#[test]
fn reads_outside_the_profile_are_refused() {
    let sc = Scene::new("");
    let secret = sc.path("o/secret");
    assert!(unconfined(&["/bin/cat", s(&secret)]).status.success());
    let o = sc.run(&["/bin/cat", s(&secret)]);
    assert!(!o.status.success());
    assert!(!String::from_utf8_lossy(&o.stdout).contains("secret-data"));
}

// rivet: verifies REQ-ZW-004
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
        "{ZWINGER} run {} -- /bin/bash -c 'echo leaked >&3'",
        s(&sc.profile)
    );
    let o = unconfined(&bash(&script(&log, &inner)));
    assert!(!o.status.success());
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        "",
        "fd 3 leaked into the session"
    );
}

// rivet: verifies REQ-ZW-005
#[test]
fn tcp_egress_is_refused() {
    let sc = Scene::new("");
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let script = format!(
        "echo hi > /dev/tcp/127.0.0.1/{}",
        l.local_addr().unwrap().port()
    );
    assert!(
        unconfined(&bash(&script)).status.success(),
        "control: probe can connect"
    );
    let o = sc.run(&bash(&script));
    assert!(
        !o.status.success(),
        "confined session opened a TCP connection"
    );
}

// rivet: verifies REQ-ZW-005
#[test]
fn udp_egress_is_refused() {
    let sc = Scene::new("");
    let script = "echo hi > /dev/udp/127.0.0.1/9";
    assert!(
        unconfined(&bash(script)).status.success(),
        "control: probe can send"
    );
    let o = sc.run(&bash(script));
    assert!(!o.status.success(), "confined session sent a UDP datagram");
}

/// Probe syscalls from inside a confined process by re-running this test binary.
fn probe(sc: &Scene, what: &str, arg: &str) -> Output {
    let exe = std::env::current_exe().unwrap();
    sc.run_env(
        &[
            s(&exe),
            "--exact",
            "probe_entry",
            "--test-threads=1",
            "--nocapture",
        ],
        &[("ZWINGER_PROBE", what), ("ZWINGER_PROBE_ARG", arg)],
    )
}

fn probe_unconfined(what: &str, arg: &str) -> Output {
    let exe = std::env::current_exe().unwrap();
    Command::new(exe)
        .args(["--exact", "probe_entry", "--test-threads=1", "--nocapture"])
        .env("ZWINGER_PROBE", what)
        .env("ZWINGER_PROBE_ARG", arg)
        .output()
        .unwrap()
}

/// Not a test of its own: when ZWINGER_PROBE is set, perform one syscall and exit with 0 on
/// success or the errno on failure. `socket` uses SOCK_DGRAM, which every probed family
/// (INET, INET6, UNIX, NETLINK) supports; netlink has no SOCK_STREAM.
#[test]
fn probe_entry() {
    let Ok(what) = std::env::var("ZWINGER_PROBE") else {
        return;
    };
    let arg = std::env::var("ZWINGER_PROBE_ARG").unwrap_or_default();
    // SAFETY: plain syscalls with valid arguments.
    let rc = unsafe {
        match what.as_str() {
            "socket" => libc::socket(arg.parse().unwrap(), libc::SOCK_DGRAM, 0),
            "socketpair" => {
                let mut fds = [0i32; 2];
                libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr())
            }
            "io_uring" => {
                let mut params = [0u8; 120];
                libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) as i32
            }
            "unix_connect" => {
                let r = std::os::unix::net::UnixStream::connect(&arg);
                std::process::exit(
                    r.map(|_| 0)
                        .unwrap_or_else(|e| e.raw_os_error().unwrap_or(1)),
                )
            }
            other => panic!("unknown probe {other}"),
        }
    };
    let code = if rc >= 0 {
        0
    } else {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    };
    std::io::stdout().flush().unwrap();
    std::process::exit(code);
}

fn kernel_abi() -> i32 {
    // SAFETY: LANDLOCK_CREATE_RULESET_VERSION query.
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            1u32,
        )
    };
    v as i32
}

// rivet: verifies REQ-ZW-005
#[test]
fn inet_and_packet_sockets_are_refused() {
    let sc = Scene::new("");
    for fam in [libc::AF_INET, libc::AF_INET6, libc::AF_NETLINK] {
        let fam = fam.to_string();
        assert_eq!(
            probe_unconfined("socket", &fam).status.code(),
            Some(0),
            "control {fam}"
        );
        assert_eq!(
            probe(&sc, "socket", &fam).status.code(),
            Some(libc::EACCES),
            "family {fam}"
        );
    }
}

// rivet: verifies REQ-ZW-005
#[test]
fn io_uring_is_refused() {
    let sc = Scene::new("");
    assert_eq!(probe(&sc, "io_uring", "").status.code(), Some(libc::EPERM));
}

// rivet: verifies REQ-ZW-006
#[test]
fn unix_sockets_follow_the_kernel_abi() {
    let sc = Scene::new("");
    let pair = probe(&sc, "socketpair", "");
    assert_eq!(
        pair.status.code(),
        Some(0),
        "socketpair cannot reach another process"
    );
    let expect = if kernel_abi() >= zwinger::linux::UNIX_SOCKET_ABI {
        0
    } else {
        libc::EACCES
    };
    let fam = libc::AF_UNIX.to_string();
    assert_eq!(probe(&sc, "socket", &fam).status.code(), Some(expect));
}

// rivet: verifies REQ-ZW-006
#[test]
fn unix_socket_outside_the_profile_is_unreachable() {
    let sc = Scene::new("");
    let path = sc.path("o/agent.sock");
    let _l = UnixListener::bind(&path).unwrap();
    assert_eq!(
        probe_unconfined("unix_connect", s(&path)).status.code(),
        Some(0),
        "control"
    );
    let o = probe(&sc, "unix_connect", s(&path));
    assert_ne!(
        o.status.code(),
        Some(0),
        "confined session reached a socket outside its profile"
    );
}

#[test]
fn exit_status_passes_through() {
    let sc = Scene::new("");
    assert_eq!(sc.run(&bash("exit 7")).status.code(), Some(7));
    let o = Command::new(ZWINGER)
        .env("ZWINGER_EVENTS_DIR", "")
        .args(["run", s(&sc.profile), "--", "/nonexistent/cmd"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(127));
}

/// A profile the Linux backend cannot enforce is refused before the command runs.
fn refused(extra: &str) {
    let sc = Scene::new(extra);
    let marker = sc.path("w/ran");
    let o = Command::new(ZWINGER)
        .env("ZWINGER_EVENTS_DIR", "")
        .arg("run")
        .arg(&sc.profile)
        .arg("--")
        .args(sh(&format!("touch {}", s(&marker))))
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(78),
        "{extra}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(!marker.exists(), "{extra}: the command ran");
    let c = sc.check();
    assert_eq!(
        c.status.code(),
        Some(78),
        "check passed what run refuses: {extra}"
    );
}

// rivet: verifies REQ-ZW-005
#[test]
fn host_allow_list_is_refused_end_to_end() {
    refused("network:\n  allow: [\"github.com\"]\n");
    refused("network:\n  allow_local_binding: true\n");
}

// rivet: verifies REQ-ZW-008
#[test]
fn unenforceable_carve_outs_are_refused_end_to_end() {
    refused("deny_read: [\"@/r/public\"]\n");
    refused("deny_write: [\"@/w/settings.json\"]\n");
}

// rivet: verifies REQ-ZW-009
#[test]
fn unfiltered_network_allows_egress_but_paths_stay_confined() {
    let sc = Scene::new("network:\n  mode: \"unfiltered\"\n");
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let script = format!(
        "echo hi > /dev/tcp/127.0.0.1/{}",
        l.local_addr().unwrap().port()
    );
    let o = sc.run(&bash(&script));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stderr).contains("network: unfiltered"));
    let f = sc.path("o/new");
    assert!(!sc.run(&["/usr/bin/touch", s(&f)]).status.success());
    assert!(
        !f.exists(),
        "unfiltered network must not open the filesystem"
    );
    let expect = if kernel_abi() >= zwinger::linux::UNIX_SOCKET_ABI {
        0
    } else {
        libc::EACCES
    };
    let fam = libc::AF_UNIX.to_string();
    assert_eq!(
        probe(&sc, "socket", &fam).status.code(),
        Some(expect),
        "unix stays confined"
    );
}

// rivet: verifies REQ-ZW-009
#[test]
fn unfiltered_unix_sockets_reach_sockets_outside_the_profile() {
    // The opt-in does what it says: this is the documented hole, not a leak.
    let sc = Scene::new("network:\n  unix_sockets: \"unfiltered\"\n");
    let path = sc.path("o/agent.sock");
    let _l = UnixListener::bind(&path).unwrap();
    let o = probe(&sc, "unix_connect", s(&path));
    assert_eq!(o.status.code(), Some(0));
    let fam = libc::AF_INET.to_string();
    assert_eq!(probe(&sc, "socket", &fam).status.code(), Some(libc::EACCES));
}

// rivet: verifies REQ-ZW-010
#[test]
fn session_sees_profile_and_abi_and_the_journal_line_names_them() {
    let sc = Scene::new("write_if_present: [\"@/absent\"]\n");
    let o = sc.run(&bash("echo \"$ZWINGER_PROFILE $ZWINGER_ABI\""));
    assert!(o.status.success());
    let abi = kernel_abi().min(zwinger::linux::MAX_KNOWN_ABI);
    assert_eq!(String::from_utf8_lossy(&o.stdout), format!("e2e {abi}\n"));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.starts_with(&format!("zwinger: e2e confined: landlock abi {abi};")),
        "{err}"
    );
    assert!(err.contains("network: none"), "{err}");
    assert!(
        err.contains(&format!("absent, skipped: {}", s(&sc.path("absent")))),
        "{err}"
    );
}

// rivet: verifies REQ-ZW-001
#[test]
fn check_refuses_a_granted_path_that_does_not_exist_yet() {
    // A runner's _work before registration: run refuses it, so check must too.
    let sc = Scene::new("");
    let c = sc.check();
    assert!(c.status.success(), "{}", String::from_utf8_lossy(&c.stderr));
    std::fs::remove_dir(sc.path("w")).unwrap();
    let c = sc.check();
    assert_eq!(c.status.code(), Some(78));
    let err = String::from_utf8_lossy(&c.stderr);
    assert!(
        err.contains(s(&sc.path("w"))),
        "the refusal names the path: {err}"
    );
    assert!(
        err.contains("No such file or directory"),
        "the refusal says why: {err}"
    );
}

// rivet: verifies REQ-ZW-010
#[test]
fn check_reports_what_run_would_enforce_without_running_anything() {
    let sc = Scene::new("");
    let c = sc.check();
    assert!(c.status.success(), "{}", String::from_utf8_lossy(&c.stderr));
    let out = String::from_utf8_lossy(&c.stdout);
    let lines: Vec<&str> = out.lines().collect();
    let abi = kernel_abi().min(zwinger::linux::MAX_KNOWN_ABI);
    assert_eq!(lines.len(), 2, "{out}");
    assert_eq!(lines[0], "zwinger: profile e2e ok");
    assert!(
        lines[1].starts_with(&format!(
            "zwinger: e2e would be confined: landlock abi {abi};"
        )),
        "{out}"
    );
    assert!(lines[1].contains("network: none"), "{out}");
}

/// A copy of /bin/true in the scene's write tree, executable. Copied by a child `cp`, not
/// in this process: a write descriptor held here would be inherited by another test thread's
/// fork, and exec of the file would then fail with ETXTBSY until that child execs.
fn copy_true(sc: &Scene) -> PathBuf {
    let t = sc.path("w/t");
    let src = Path::new("/bin/true").canonicalize().unwrap();
    let ok = Command::new("cp").arg(&src).arg(&t).status().unwrap();
    assert!(ok.success(), "cp {} {}", src.display(), t.display());
    let ok = Command::new("chmod").arg("755").arg(&t).status().unwrap();
    assert!(ok.success());
    t
}

// rivet: verifies REQ-ZW-013
#[test]
fn noexec_refuses_execve_in_a_write_tree_but_not_reading_or_writing_it() {
    let sc = Scene::new("noexec: [\"@/w\"]\n");
    let t = copy_true(&sc);
    assert!(
        unconfined(&[s(&t)]).status.success(),
        "control: it runs unconfined"
    );
    let o = sc.run(&[s(&t)]);
    assert!(!o.status.success(), "execve under noexec succeeded");
    // The exec itself fails, with EACCES, so zwinger reports it as not executable (126).
    assert_eq!(
        o.status.code(),
        Some(126),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let o = sc.run(&bash(&format!(
        "cat {} > /dev/null && echo x > {}",
        s(&t),
        s(&sc.path("w/f"))
    )));
    assert!(
        o.status.success(),
        "read and write still work: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    // Programs from read trees still run (bash itself, from /usr).
    assert!(sc.run(&bash("true")).status.success());
}

// rivet: verifies REQ-ZW-013
#[test]
fn without_noexec_the_same_file_runs_confined() {
    let sc = Scene::new("");
    let t = copy_true(&sc);
    assert!(sc.run(&[s(&t)]).status.success());
}

// rivet: verifies REQ-ZW-013
#[test]
fn noexec_inside_a_write_grant_is_refused_end_to_end() {
    refused("noexec: [\"@/w/sub\"]\n");
}

/// Every event file in `dir`, parsed.
fn events_in(dir: &Path) -> Vec<serde_json::Value> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.map(|e| {
        let text = std::fs::read_to_string(e.unwrap().path()).unwrap();
        serde_json::from_str(&text).unwrap()
    })
    .collect()
}

// rivet: verifies REQ-ZW-014
#[test]
fn run_writes_one_confined_event_to_a_dir_the_session_cannot_reach() {
    let sc = Scene::new("");
    // Outside every grant: the event still arrives (opened before confining), the session
    // itself cannot write there.
    let dir = sc.path("o/events");
    let env = [("ZWINGER_EVENTS_DIR", s(&dir))];
    let o = sc.run_env(&bash(&format!("touch {}/x", s(&dir))), &env);
    assert!(!o.status.success(), "the session wrote into the events dir");
    let evs = events_in(&dir);
    assert_eq!(evs.len(), 1, "{evs:?}");
    let e = &evs[0];
    let abi = kernel_abi().min(zwinger::linux::MAX_KNOWN_ABI);
    assert_eq!(e["schema"], "zwinger.event.v1");
    assert_eq!(e["verdict"], "confined");
    assert_eq!(e["profile"], "e2e");
    assert_eq!(e["landlock_abi"], abi);
    assert_eq!(e["network"], "none");
    assert_eq!(e["write_grants"], 2);
    assert_eq!(
        e["profile_sha256"],
        zwinger::events::sha256_file(&sc.profile).unwrap()
    );
    let text = e.to_string();
    assert!(
        !text.contains(s(&sc.root.0)),
        "a path left the machine: {text}"
    );
}

// rivet: verifies REQ-ZW-014
#[test]
fn a_refused_run_writes_its_category_and_no_reason_text() {
    let sc = Scene::new("deny_read: [\"@/r/public\"]\n");
    let dir = sc.path("o/events");
    let o = Command::new(ZWINGER)
        .env("ZWINGER_EVENTS_DIR", "")
        .arg("run")
        .arg(&sc.profile)
        .arg("--")
        .arg("/bin/true")
        .env("ZWINGER_EVENTS_DIR", &dir)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(78));
    let evs = events_in(&dir);
    assert_eq!(evs.len(), 1, "{evs:?}");
    assert_eq!(evs[0]["verdict"], "refused");
    assert_eq!(evs[0]["category"], "carve-out");
    assert_eq!(evs[0]["landlock_abi"], serde_json::Value::Null);
    assert!(!evs[0].to_string().contains(s(&sc.root.0)));
}

// rivet: verifies REQ-ZW-014
#[test]
fn no_event_is_written_where_the_session_could_forge_it() {
    let sc = Scene::new("");
    let dir = sc.path("w/events");
    let o = sc.run_env(&bash("true"), &[("ZWINGER_EVENTS_DIR", s(&dir))]);
    assert!(o.status.success(), "the session still runs");
    assert!(events_in(&dir).is_empty());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("lies inside the write grant"), "{err}");
}

// rivet: verifies REQ-ZW-021
#[test]
fn the_session_receives_its_plan_in_zwinger_grants() {
    let sc = Scene::new("deny_read: [\"@/o/secret\"]\nnoexec: [\"@/w\"]\n");
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
    has("deny_read", sc.path("o/secret"));
    has("noexec", sc.path("w"));
    assert_eq!(v["exec"], serde_json::json!([]));
    // Every path in the plan is absolute.
    for key in ["read", "write", "deny_read", "deny_write", "noexec"] {
        for e in v[key].as_array().unwrap() {
            assert!(e.as_str().unwrap().starts_with('/'), "{key}: {e}");
        }
    }
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
    let sc = Scene::new("env_keep: [\"GIT_SSH_COMMAND\"]\n");
    let env = [
        ("LD_LIBRARY_PATH", "/nonexistent-zwinger-test"),
        ("BASH_ENV", "/nonexistent-zwinger-test/rc"),
        ("GIT_SSH_COMMAND", "ssh -v"),
        ("ZWINGER_TEST_ORDINARY", "1"),
    ];
    let o = sc.run_env(&["/usr/bin/env"], &env);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out = String::from_utf8_lossy(&o.stdout);
    let lines: Vec<&str> = out.lines().collect();
    assert!(
        !lines.iter().any(|l| l.starts_with("LD_LIBRARY_PATH=")),
        "{out}"
    );
    assert!(!lines.iter().any(|l| l.starts_with("BASH_ENV=")), "{out}");
    assert!(
        lines.contains(&"GIT_SSH_COMMAND=ssh -v"),
        "kept by env_keep: {out}"
    );
    assert!(
        lines.contains(&"ZWINGER_TEST_ORDINARY=1"),
        "not on the list: {out}"
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("; environment removed: BASH_ENV, LD_LIBRARY_PATH"),
        "{err}"
    );
}
