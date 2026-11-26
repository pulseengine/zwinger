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
            "name = \"e2e\"\nread = [{}]\nwrite = [{}]\n{}",
            list(&read),
            list(&write),
            extra.replace('@', root.to_str().unwrap())
        );
        let profile = root.join("profile.toml");
        std::fs::write(&profile, text).unwrap();
        Scene {
            root: Dir(root),
            profile,
        }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.0.join(rel)
    }

    fn run(&self, cmd: &[&str]) -> Output {
        self.run_env(cmd, &[])
    }

    fn run_env(&self, cmd: &[&str], env: &[(&str, &str)]) -> Output {
        let o = Command::new(ZWINGER)
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
}

// rivet: verifies REQ-ZW-005
#[test]
fn host_allow_list_is_refused_end_to_end() {
    refused("[network]\nallow = [\"github.com\"]\n");
    refused("[network]\nallow_local_binding = true\n");
}

// rivet: verifies REQ-ZW-008
#[test]
fn unenforceable_carve_outs_are_refused_end_to_end() {
    refused("deny_read = [\"@/r/public\"]\n");
    refused("deny_write = [\"@/w/settings.json\"]\n");
}
