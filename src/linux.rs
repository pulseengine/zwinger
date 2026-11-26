//! Linux backend: Landlock for the filesystem (and TCP/UDP where the kernel ABI has them), plus a
//! seccomp filter for what Landlock cannot see on older kernels (REQ-ZW-004..006).
//!
//! The planning half (`plan`, `enforcement`, `seccomp_program`) is plain Rust and compiles on
//! every platform, so its refusals are unit- and mutation-tested anywhere. Only `confine`, which
//! calls the kernel, is Linux-only.
//!
//! What fails closed, and why:
//! - Landlock below ABI 3 (Linux 6.2) cannot stop `truncate(2)` outside the write trees: refuse.
//! - Landlock is an allow list. It cannot take a subtree back out of a granted tree, so a
//!   `deny_read` or `deny_write` inside a granted tree is refused, never silently dropped.
//! - Landlock filters ports, not hosts: a non-empty `network.allow` or `allow_local_binding`
//!   needs a filtering proxy the backend does not have, so it is refused.
//! - No egress is enforced by seccomp: `socket(2)` for every family except `AF_UNIX` fails with
//!   EACCES, and io_uring (whose socket opcodes bypass a `socket(2)` filter) fails with EPERM.
//! - `AF_UNIX` is allowed only when Landlock can confine it (ABI 9: pathname sockets via
//!   `ResolveUnix`, ABI 6: abstract sockets via scoping). On older kernels `socket(AF_UNIX)` is
//!   refused too; `socketpair(2)` stays available because it cannot reach another process.
//! - Inherited file descriptors above 2 are marked close-on-exec, so an fd opened outside the
//!   profile does not leak into the session.

use crate::profile::{Profile, within};
use std::path::{Path, PathBuf};

/// Lowest Landlock ABI the backend accepts: ABI 3 adds `Truncate`.
pub const MIN_ABI: i32 = 3;
/// Landlock ABI that confines `AF_UNIX`: `ResolveUnix` (ABI 9) on top of scoping (ABI 6).
pub const UNIX_SOCKET_ABI: i32 = 9;
/// Highest ABI the landlock crate in use knows; newer kernels are driven at this level.
pub const MAX_KNOWN_ABI: i32 = 10;

/// The resolved paths Landlock is given.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub read: Vec<PathBuf>,
    pub write: Vec<PathBuf>,
}

/// What the running kernel lets the backend enforce, decided from its Landlock ABI.
#[derive(Debug, PartialEq, Eq)]
pub struct Enforcement {
    /// The ABI the ruleset is built for (the kernel's, capped at `MAX_KNOWN_ABI`).
    pub abi: i32,
    /// Landlock denies TCP bind/connect too (ABI 4), behind the seccomp socket filter.
    pub tcp: bool,
    /// Landlock denies UDP bind/send too (ABI 10).
    pub udp: bool,
    /// Landlock scopes signals and abstract UNIX sockets to the session (ABI 6).
    pub scoped: bool,
    /// `socket(AF_UNIX)` is allowed because Landlock confines where it can connect (ABI 9).
    pub unix_sockets: bool,
}

/// Decide what to enforce for a kernel reporting Landlock ABI `abi` (<= 0: unavailable).
pub fn enforcement(abi: i32) -> Result<Enforcement, String> {
    if abi <= 0 {
        return Err(
            "Landlock is not available on this kernel (not built in or not enabled \
                    in the lsm= list); refusing to run unconfined"
                .into(),
        );
    }
    if abi < MIN_ABI {
        return Err(format!(
            "Landlock ABI {abi} cannot restrict truncate(2); ABI {MIN_ABI} (Linux 6.2) is the \
             minimum; refusing to run partially confined"
        ));
    }
    let abi = abi.min(MAX_KNOWN_ABI);
    Ok(Enforcement {
        abi,
        tcp: abi >= 4,
        udp: abi >= 10,
        scoped: abi >= 6,
        unix_sockets: abi >= UNIX_SOCKET_ABI,
    })
}

/// Canonicalize the longest existing prefix of `p` and append the rest, so a symlink anywhere
/// above a not-yet-existing path is still seen.
fn resolve(p: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut cur = p;
    loop {
        if let Ok(c) = cur.canonicalize() {
            return rest.iter().rev().fold(c, |acc: PathBuf, n| acc.join(n));
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_owned());
                cur = parent;
            }
            _ => return p.to_path_buf(),
        }
    }
}

/// Resolve the profile's paths and refuse anything Landlock cannot enforce as written.
pub fn plan(p: &Profile) -> Result<Plan, String> {
    if !p.network.allow.is_empty() {
        return Err(format!(
            "network.allow lists {} host(s); Landlock filters ports, not hosts, and the Linux \
             backend has no filtering proxy; refusing rather than allowing all egress",
            p.network.allow.len()
        ));
    }
    if p.network.allow_local_binding {
        return Err(
            "network.allow_local_binding: Landlock cannot tell loopback from other \
                    addresses; refusing rather than allowing all binds"
                .into(),
        );
    }
    let existing = |field: &str, paths: &[PathBuf]| -> Result<Vec<PathBuf>, String> {
        paths
            .iter()
            .map(|x| {
                x.canonicalize()
                    .map_err(|e| format!("{field}: {}: {e}; refusing", x.display()))
            })
            .collect()
    };
    let read = existing("read", &p.read)?;
    let write = existing("write", &p.write)?;
    let deny_read: Vec<PathBuf> = p.deny_read.iter().map(|d| resolve(d)).collect();
    let deny_write: Vec<PathBuf> = p.deny_write.iter().map(|d| resolve(d)).collect();

    for (d, dl) in deny_read.iter().zip(&p.deny_read) {
        for (a, al, field) in read
            .iter()
            .zip(&p.read)
            .map(|(a, al)| (a, al, "read"))
            .chain(write.iter().zip(&p.write).map(|(a, al)| (a, al, "write")))
        {
            if within(d, a) {
                return Err(format!(
                    "deny_read: {} lies inside {field} {} (resolved: {} in {}); Landlock \
                     cannot carve a denied path out of a granted tree; refusing",
                    dl.display(),
                    al.display(),
                    d.display(),
                    a.display()
                ));
            }
            // A read inside deny_read is an exception only where the profile wrote it so.
            let stated = field == "read" && within(al, dl) && al != dl;
            if within(a, d) && !stated {
                return Err(format!(
                    "{field}: {} resolves to {}, inside deny_read {}; refusing",
                    al.display(),
                    a.display(),
                    dl.display()
                ));
            }
        }
    }
    for (d, dl) in deny_write.iter().zip(&p.deny_write) {
        for (a, al) in write.iter().zip(&p.write) {
            if within(d, a) {
                return Err(format!(
                    "deny_write: {} lies inside write {}; Landlock cannot carve a read-only \
                     path out of a writable tree; refusing",
                    dl.display(),
                    al.display()
                ));
            }
            if within(a, d) {
                return Err(format!(
                    "write: {} resolves to {}, inside deny_write {}; refusing",
                    al.display(),
                    a.display(),
                    dl.display()
                ));
            }
        }
    }
    Ok(Plan { read, write })
}

/// One classic-BPF instruction, laid out as `struct sock_filter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

pub const BPF_LD_W_ABS: u16 = 0x20;
pub const BPF_JEQ_K: u16 = 0x15;
pub const BPF_JGE_K: u16 = 0x35;
pub const BPF_RET_K: u16 = 0x06;
pub const RET_ALLOW: u32 = 0x7fff_0000;
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_ERRNO: u32 = 0x0005_0000;
pub const EPERM: u32 = 1;
pub const EACCES: u32 = 13;
pub const AF_UNIX: u32 = 1;
/// `struct seccomp_data` offsets: nr, arch, args[0] (low half on little-endian).
pub const OFF_NR: u32 = 0;
pub const OFF_ARCH: u32 = 4;
pub const OFF_ARG0: u32 = 16;

/// The syscall table for one architecture.
#[derive(Debug, Clone, Copy)]
pub struct Arch {
    pub audit_arch: u32,
    pub socket: u32,
    pub io_uring: [u32; 3],
    /// Syscall numbers at or above this belong to a second ABI on the same audit arch (x32).
    pub foreign_from: Option<u32>,
}

pub const X86_64: Arch = Arch {
    audit_arch: 0xC000_003E,
    socket: 41,
    io_uring: [425, 426, 427],
    foreign_from: Some(0x4000_0000),
};

pub const AARCH64: Arch = Arch {
    audit_arch: 0xC000_00B7,
    socket: 198,
    io_uring: [425, 426, 427],
    foreign_from: None,
};

/// The table for the architecture zwinger was built for, if it has one.
pub fn native_arch() -> Option<Arch> {
    if cfg!(target_arch = "x86_64") {
        Some(X86_64)
    } else if cfg!(target_arch = "aarch64") {
        Some(AARCH64)
    } else {
        None
    }
}

/// The seccomp program: kill a foreign architecture, refuse x32, refuse io_uring with EPERM,
/// refuse `socket(2)` with EACCES unless the family is `AF_UNIX` and `unix_sockets` holds.
pub fn seccomp_program(arch: Arch, unix_sockets: bool) -> Vec<Insn> {
    let ret = |k| Insn {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k,
    };
    let ld = |k| Insn {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k,
    };
    // Instruction counts, so forward jump offsets can be computed in place.
    let n_foreign = usize::from(arch.foreign_from.is_some());
    let n_checks = n_foreign + 1 + arch.io_uring.len(); // jumps after `ld nr`
    let mut p = vec![
        ld(OFF_ARCH),
        Insn {
            code: BPF_JEQ_K,
            jt: 1,
            jf: 0,
            k: arch.audit_arch,
        },
        ret(RET_KILL_PROCESS),
        ld(OFF_NR),
    ];
    // Layout after the checks: ALLOW, SOCK (ld arg0), [jeq AF_UNIX], ret EACCES, [ALLOW], DENY.
    let sock_len = if unix_sockets { 4 } else { 2 };
    let deny_at = n_checks + 1 + sock_len; // relative to the first check
    let sock_at = n_checks + 1;
    let mut i = 0usize;
    let mut jump = |code, k, target: usize| {
        let jt = u8::try_from(target - i - 1).expect("short program");
        i += 1;
        Insn { code, jt, jf: 0, k }
    };
    if let Some(from) = arch.foreign_from {
        p.push(jump(BPF_JGE_K, from, deny_at));
    }
    p.push(jump(BPF_JEQ_K, arch.socket, sock_at));
    for nr in arch.io_uring {
        p.push(jump(BPF_JEQ_K, nr, deny_at));
    }
    p.push(ret(RET_ALLOW));
    p.push(ld(OFF_ARG0));
    if unix_sockets {
        p.push(Insn {
            code: BPF_JEQ_K,
            jt: 1,
            jf: 0,
            k: AF_UNIX,
        });
    }
    p.push(ret(RET_ERRNO | EACCES));
    if unix_sockets {
        p.push(ret(RET_ALLOW));
    }
    p.push(ret(RET_ERRNO | EPERM));
    p
}

/// Confine the calling process to `profile`. On success every later `exec` runs confined.
#[cfg(target_os = "linux")]
pub fn confine(profile: &Profile) -> Result<Enforcement, String> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
        RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
    };

    let plan = plan(profile)?;
    let arch = native_arch().ok_or("no seccomp syscall table for this architecture; refusing")?;
    let enf = enforcement(kernel_abi())?;
    let abi = ABI::from(enf.abi);
    let err = |e: landlock::RulesetError| format!("Landlock: {e}; refusing");

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(err)?;
    if enf.tcp {
        ruleset = ruleset
            .handle_access(AccessNet::from_all(abi))
            .map_err(err)?;
    }
    if enf.scoped {
        ruleset = ruleset.scope(Scope::from_all(abi)).map_err(err)?;
    }
    let mut created = ruleset.create().map_err(err)?;
    for (paths, access) in [
        (&plan.read, AccessFs::from_read(abi)),
        (&plan.write, AccessFs::from_all(abi)),
    ] {
        for path in paths {
            let fd = PathFd::new(path).map_err(|e| format!("{}: {e}; refusing", path.display()))?;
            let access = if path.is_dir() {
                access
            } else {
                access & AccessFs::from_file(abi)
            };
            created = created
                .add_rule(PathBeneath::new(fd, access))
                .map_err(err)?;
        }
    }
    let status = created.restrict_self().map_err(err)?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(format!(
            "Landlock not fully enforced ({status:?}); refusing"
        ));
    }

    // SAFETY: plain syscalls on integer arguments and a pointer to a live, correctly laid out
    // sock_fprog.
    unsafe {
        if libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        ) != 0
        {
            return Err(format!(
                "close_range: {}; refusing to leak inherited descriptors",
                std::io::Error::last_os_error()
            ));
        }
        let mut filter: Vec<libc::sock_filter> = seccomp_program(arch, enf.unix_sockets)
            .into_iter()
            .map(|i| libc::sock_filter {
                code: i.code,
                jt: i.jt,
                jf: i.jf,
                k: i.k,
            })
            .collect();
        let prog = libc::sock_fprog {
            len: u16::try_from(filter.len()).expect("short program"),
            filter: filter.as_mut_ptr(),
        };
        if libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0u32,
            &prog as *const libc::sock_fprog,
        ) != 0
        {
            return Err(format!(
                "seccomp: {}; refusing",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(enf)
}

/// The kernel's Landlock ABI version, or 0 when Landlock is unavailable.
#[cfg(target_os = "linux")]
fn kernel_abi() -> i32 {
    // SAFETY: LANDLOCK_CREATE_RULESET_VERSION with a null attr and size 0 only queries.
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            1u32,
        )
    };
    i32::try_from(v).unwrap_or(0).max(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // ---- enforcement(abi) ----

    // rivet: verifies REQ-ZW-004
    #[test]
    fn abi_below_minimum_refuses() {
        for abi in [-1, 0, 1, 2] {
            assert!(enforcement(abi).is_err(), "abi {abi}");
        }
        assert!(enforcement(MIN_ABI).is_ok());
    }

    #[test]
    fn abi_features_switch_on_at_their_versions() {
        let e = |abi| enforcement(abi).unwrap();
        assert_eq!(
            e(3),
            Enforcement {
                abi: 3,
                tcp: false,
                udp: false,
                scoped: false,
                unix_sockets: false
            }
        );
        assert!(e(4).tcp && !e(4).scoped);
        assert!(e(6).scoped && !e(6).unix_sockets);
        assert!(!e(8).unix_sockets);
        assert!(e(9).unix_sockets && !e(9).udp);
        assert!(e(10).udp);
        assert_eq!(
            e(42).abi,
            MAX_KNOWN_ABI,
            "newer kernels run at the known ABI"
        );
    }

    // ---- plan(profile) ----

    struct Tree(PathBuf);
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tree() -> Tree {
        static N: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "zwinger-plan-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        for d in ["home/.ssh", "home/repo/.claude", "usr"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("home/.ssh/k.pub"), "k").unwrap();
        Tree(root)
    }
    fn profile(t: &Tree, body: &str) -> Profile {
        let text = format!("name = \"t\"\n{}", body.replace("@", t.0.to_str().unwrap()));
        Profile::parse(Path::new("t.toml"), &text).unwrap()
    }

    // rivet: verifies REQ-ZW-004
    #[test]
    fn plan_resolves_granted_paths() {
        let t = tree();
        let p = plan(&profile(
            &t,
            "read = [\"@/usr\"]\nwrite = [\"@/home/repo\"]\n",
        ))
        .unwrap();
        assert_eq!(p.read, vec![t.0.join("usr").canonicalize().unwrap()]);
        assert_eq!(p.write, vec![t.0.join("home/repo").canonicalize().unwrap()]);
    }

    // rivet: verifies REQ-ZW-008
    #[test]
    fn missing_granted_path_refuses() {
        let t = tree();
        assert!(plan(&profile(&t, "read = [\"@/nope\"]\n")).is_err());
        assert!(plan(&profile(&t, "write = [\"@/nope\"]\n")).is_err());
    }

    // rivet: verifies REQ-ZW-008
    #[test]
    fn deny_read_inside_a_granted_tree_refuses() {
        let t = tree();
        assert!(
            plan(&profile(
                &t,
                "read = [\"@/home\"]\ndeny_read = [\"@/home/.ssh\"]\n"
            ))
            .is_err()
        );
        assert!(
            plan(&profile(
                &t,
                "write = [\"@/home\"]\ndeny_read = [\"@/home/.ssh\"]\n"
            ))
            .is_err()
        );
        // Not-yet-existing denied paths are checked too.
        assert!(
            plan(&profile(
                &t,
                "read = [\"@/home\"]\ndeny_read = [\"@/home/later\"]\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn deny_read_outside_granted_trees_is_enforced_by_omission() {
        let t = tree();
        assert!(
            plan(&profile(
                &t,
                "read = [\"@/usr\"]\ndeny_read = [\"@/home/.ssh\"]\n"
            ))
            .is_ok()
        );
    }

    #[test]
    fn stated_read_exception_inside_deny_read_is_allowed() {
        let t = tree();
        let p = "read = [\"@/home/.ssh/k.pub\"]\ndeny_read = [\"@/home/.ssh\"]\n";
        assert!(plan(&profile(&t, p)).is_ok());
    }

    // rivet: verifies REQ-ZW-008
    #[cfg(unix)]
    #[test]
    fn read_through_a_symlink_into_deny_read_refuses() {
        let t = tree();
        std::os::unix::fs::symlink(t.0.join("home/.ssh"), t.0.join("usr/keys")).unwrap();
        std::os::unix::fs::symlink(t.0.join("home/.ssh/k.pub"), t.0.join("usr/k")).unwrap();
        for read in ["@/usr/keys", "@/usr/k"] {
            let body = format!("read = [\"{read}\"]\ndeny_read = [\"@/home/.ssh\"]\n");
            assert!(plan(&profile(&t, &body)).is_err(), "{read}");
        }
    }

    // rivet: verifies REQ-ZW-008
    #[cfg(unix)]
    #[test]
    fn deny_read_under_a_symlinked_grant_refuses() {
        let t = tree();
        std::os::unix::fs::symlink(t.0.join("home"), t.0.join("h")).unwrap();
        let body = "read = [\"@/h\"]\ndeny_read = [\"@/home/.ssh\"]\n";
        assert!(plan(&profile(&t, body)).is_err());
        let body = "read = [\"@/home\"]\ndeny_read = [\"@/h/.ssh\"]\n";
        assert!(plan(&profile(&t, body)).is_err());
    }

    // rivet: verifies REQ-ZW-008
    #[cfg(unix)]
    #[test]
    fn write_through_a_symlink_into_a_denied_tree_refuses() {
        let t = tree();
        std::os::unix::fs::symlink(t.0.join("home/.ssh"), t.0.join("usr/keys")).unwrap();
        let body = "write = [\"@/usr/keys\"]\ndeny_read = [\"@/home/.ssh\"]\n";
        assert!(plan(&profile(&t, body)).is_err());
        let body = "write = [\"@/usr/keys\"]\ndeny_write = [\"@/home/.ssh\"]\n";
        assert!(plan(&profile(&t, body)).is_err());
    }

    // rivet: verifies REQ-ZW-008
    #[test]
    fn deny_write_inside_write_refuses() {
        let t = tree();
        let body = "write = [\"@/home/repo\"]\ndeny_write = [\"@/home/repo/.claude\"]\n";
        assert!(plan(&profile(&t, body)).is_err());
    }

    #[test]
    fn deny_write_inside_read_only_tree_is_enforced_by_omission() {
        let t = tree();
        let body = "read = [\"@/home/repo\"]\ndeny_write = [\"@/home/repo/.claude\"]\n";
        assert!(plan(&profile(&t, body)).is_ok());
    }

    // rivet: verifies REQ-ZW-005
    #[test]
    fn host_allow_list_refuses_on_linux() {
        let t = tree();
        assert!(plan(&profile(&t, "[network]\nallow = [\"github.com\"]\n")).is_err());
    }

    // rivet: verifies REQ-ZW-005
    #[test]
    fn local_binding_refuses_on_linux() {
        let t = tree();
        assert!(plan(&profile(&t, "[network]\nallow_local_binding = true\n")).is_err());
    }

    #[test]
    fn resolve_keeps_the_missing_tail() {
        let t = tree();
        let r = resolve(&t.0.join("home/a/b"));
        assert_eq!(r, t.0.canonicalize().unwrap().join("home/a/b"));
        assert_eq!(resolve(Path::new("/")), PathBuf::from("/"));
    }

    // ---- seccomp_program: run it in a classic-BPF interpreter ----

    /// Execute `prog` against one `seccomp_data`; panics on a malformed program.
    fn run(prog: &[Insn], arch: u32, nr: u32, arg0: u32) -> u32 {
        let (mut pc, mut acc) = (0usize, 0u32);
        loop {
            let i = prog[pc];
            pc += 1;
            match i.code {
                BPF_LD_W_ABS => {
                    acc = match i.k {
                        OFF_NR => nr,
                        OFF_ARCH => arch,
                        OFF_ARG0 => arg0,
                        k => panic!("load from {k}"),
                    }
                }
                BPF_JEQ_K => pc += usize::from(if acc == i.k { i.jt } else { i.jf }),
                BPF_JGE_K => pc += usize::from(if acc >= i.k { i.jt } else { i.jf }),
                BPF_RET_K => return i.k,
                c => panic!("opcode {c:#x}"),
            }
        }
    }

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 10;
    const AF_NETLINK: u32 = 16;
    const AF_PACKET: u32 = 17;

    fn every_case(arch: Arch) {
        for unix in [false, true] {
            let prog = seccomp_program(arch, unix);
            let r = |nr, a0| run(&prog, arch.audit_arch, nr, a0);
            for fam in [AF_INET, AF_INET6, AF_NETLINK, AF_PACKET, 0, 0xffff_ffff] {
                assert_eq!(r(arch.socket, fam), RET_ERRNO | EACCES, "family {fam}");
            }
            let unix_expect = if unix { RET_ALLOW } else { RET_ERRNO | EACCES };
            assert_eq!(r(arch.socket, AF_UNIX), unix_expect);
            for nr in arch.io_uring {
                assert_eq!(r(nr, 0), RET_ERRNO | EPERM, "io_uring {nr}");
            }
            for nr in [0, 1, 59, 221, 424, 428] {
                assert_eq!(r(nr, AF_INET), RET_ALLOW, "nr {nr}");
            }
            if let Some(from) = arch.foreign_from {
                assert_eq!(r(from + arch.socket, AF_INET), RET_ERRNO | EPERM);
                assert_eq!(r(from, 0), RET_ERRNO | EPERM);
                assert_eq!(r(from - 1, 0), RET_ALLOW);
            }
            assert_eq!(
                run(&prog, 0x4000_0003, 0, 0),
                RET_KILL_PROCESS,
                "i386 on x86_64"
            );
            assert_eq!(
                run(&prog, arch.audit_arch ^ 1, arch.socket, AF_UNIX),
                RET_KILL_PROCESS
            );
        }
    }

    // rivet: verifies REQ-ZW-005
    #[test]
    fn seccomp_program_x86_64() {
        every_case(X86_64);
    }

    // rivet: verifies REQ-ZW-005
    #[test]
    fn seccomp_program_aarch64() {
        every_case(AARCH64);
    }

    #[test]
    fn native_arch_has_a_table_on_supported_targets() {
        assert_eq!(
            native_arch().is_some(),
            cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
        );
    }
}
