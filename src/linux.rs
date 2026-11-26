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
//!   profile does not leak into the session. Fds 0-2 stay, and may be the caller's terminal, so
//!   `ioctl` with TIOCSTI or TIOCLINUX (injecting input an unconfined shell would read) fails.
//! - Paths are resolved and checked, then opened for Landlock in a second step. A process that
//!   could swap a symlink between the two already runs unconfined as the same user; the session
//!   it would target does not exist until the exec.

use crate::profile::{Network, NetworkMode, Profile, UnixSockets, within};
use std::path::{Path, PathBuf};

/// Lowest Landlock ABI the backend accepts: ABI 3 adds `Truncate`.
pub const MIN_ABI: i32 = 3;
/// Landlock ABI that confines `AF_UNIX`: `ResolveUnix` (ABI 9) on top of scoping (ABI 6).
pub const UNIX_SOCKET_ABI: i32 = 9;
/// Highest ABI the landlock crate in use knows; newer kernels are driven at this level.
pub const MAX_KNOWN_ABI: i32 = 10;

/// One granted path: as the profile stated it, and as Landlock will see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub field: &'static str,
    pub stated: PathBuf,
    pub resolved: PathBuf,
}

/// The resolved paths Landlock is given, and the optional ones that were absent.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub read: Vec<Grant>,
    pub write: Vec<Grant>,
    pub skipped: Vec<PathBuf>,
}

/// What the backend enforces for one profile on one kernel.
#[derive(Debug, PartialEq, Eq)]
pub struct Enforcement {
    /// The ABI the ruleset is built for (the kernel's, capped at `MAX_KNOWN_ABI`).
    pub abi: i32,
    /// The profile's network mode.
    pub network: NetworkMode,
    /// `socket(2)` for families other than `AF_UNIX` is allowed (mode `unfiltered`).
    pub inet_sockets: bool,
    /// Landlock denies TCP bind/connect too (mode `none`, ABI 4), behind the socket filter.
    pub tcp: bool,
    /// Landlock denies UDP bind/send too (mode `none`, ABI 10).
    pub udp: bool,
    /// `socket(AF_UNIX)` is allowed.
    pub unix_sockets: bool,
    /// Landlock confines pathname `connect(2)` to write trees (ABI 9, sockets not unfiltered).
    pub resolve_unix: bool,
    /// Landlock scopes abstract UNIX sockets to the session (ABI 6, sockets not unfiltered).
    pub scope_abstract_unix: bool,
    /// Landlock scopes signals to the session (ABI 6).
    pub scope_signals: bool,
    /// Landlock restricts ioctls on device files opened in the session (ABI 5).
    pub ioctl_dev: bool,
    /// Landlock logs denials in the session to the audit log (ABI 7).
    pub audit_log: bool,
}

impl Enforcement {
    /// What this profile leaves unconfined on this kernel, for the startup line.
    pub fn not_enforced(&self) -> Vec<&'static str> {
        let mut gaps = Vec::new();
        if self.network == NetworkMode::Unfiltered {
            gaps.push("network (mode = unfiltered)");
        }
        if self.unix_sockets && !self.resolve_unix {
            gaps.push("unix socket connections (unix_sockets = unfiltered)");
        }
        if !self.ioctl_dev {
            gaps.push("device ioctls (abi 5)");
        }
        if !self.scope_signals {
            gaps.push("signal scoping (abi 6)");
        }
        gaps
    }

    /// The single startup line written to stderr (the journal, under systemd).
    pub fn summary(&self, name: &str, plan: &Plan) -> String {
        let unix = match (self.unix_sockets, self.resolve_unix) {
            (false, _) => "refused",
            (true, true) => "confined to write trees",
            (true, false) => "unfiltered",
        };
        let network = match self.network {
            NetworkMode::None => "none",
            NetworkMode::Unfiltered => "unfiltered",
        };
        let mut s = format!(
            "zwinger: {name} confined: landlock abi {}; {} read, {} write grants",
            self.abi,
            plan.read.len(),
            plan.write.len()
        );
        if !plan.skipped.is_empty() {
            let names: Vec<String> = plan
                .skipped
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            s += &format!(" (absent, skipped: {})", names.join(", "));
        }
        s += &format!("; network: {network}; unix sockets: {unix}");
        s += &format!(
            "; denial audit log: {}",
            if self.audit_log { "on" } else { "off (abi 7)" }
        );
        let gaps = self.not_enforced();
        if !gaps.is_empty() {
            s += &format!("; not enforced: {}", gaps.join(", "));
        }
        s
    }
}

/// Decide what to enforce for `network` on a kernel reporting Landlock ABI `abi` (<= 0:
/// unavailable).
pub fn enforcement(abi: i32, network: &Network) -> Result<Enforcement, String> {
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
    let none = network.mode == NetworkMode::None;
    let unix_unfiltered = network.unix_sockets == UnixSockets::Unfiltered;
    Ok(Enforcement {
        abi,
        network: network.mode,
        inet_sockets: !none,
        tcp: none && abi >= 4,
        udp: none && abi >= 10,
        unix_sockets: unix_unfiltered || abi >= UNIX_SOCKET_ABI,
        resolve_unix: !unix_unfiltered && abi >= UNIX_SOCKET_ABI,
        scope_abstract_unix: !unix_unfiltered && abi >= 6,
        scope_signals: abi >= 6,
        ioctl_dev: abi >= 5,
        audit_log: abi >= 7,
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

/// Resolve the granted paths: a missing `read`/`write` path refuses, a missing `*_if_present`
/// path is recorded in `skipped`.
fn grants<'a>(
    paths: impl Iterator<Item = (&'static str, &'a PathBuf)>,
    skipped: &mut Vec<PathBuf>,
) -> Result<Vec<Grant>, String> {
    let mut out = Vec::new();
    for (field, stated) in paths {
        match stated.canonicalize() {
            Ok(resolved) => out.push(Grant {
                field,
                stated: stated.clone(),
                resolved,
            }),
            Err(e)
                if field.ends_with("_if_present") && e.kind() == std::io::ErrorKind::NotFound =>
            {
                skipped.push(stated.clone())
            }
            Err(e) => return Err(format!("{field}: {}: {e}; refusing", stated.display())),
        }
    }
    Ok(out)
}

/// Resolve the profile's paths and refuse anything Landlock cannot enforce as written.
pub fn plan(p: &Profile) -> Result<Plan, String> {
    if !p.network.allow.is_empty() {
        return Err(format!(
            "network.allow lists {} host(s); Landlock filters ports, not hosts, and the Linux \
             backend has no filtering proxy; refusing rather than allowing all egress (mode = \
             \"unfiltered\" says so explicitly)",
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
    let mut skipped = Vec::new();
    let read = grants(p.reads(), &mut skipped)?;
    let write = grants(p.writes(), &mut skipped)?;
    let deny_read: Vec<PathBuf> = p.deny_read.iter().map(|d| resolve(d)).collect();
    let deny_write: Vec<PathBuf> = p.deny_write.iter().map(|d| resolve(d)).collect();

    for (d, dl) in deny_read.iter().zip(&p.deny_read) {
        for g in read.iter().chain(&write) {
            if within(d, &g.resolved) {
                return Err(format!(
                    "deny_read: {} lies inside {} {} (resolved: {} in {}); Landlock cannot \
                     carve a denied path out of a granted tree; refusing",
                    dl.display(),
                    g.field,
                    g.stated.display(),
                    d.display(),
                    g.resolved.display()
                ));
            }
            // A read inside deny_read is an exception only where the profile wrote it so.
            let stated = g.field.starts_with("read") && within(&g.stated, dl) && g.stated != *dl;
            if within(&g.resolved, d) && !stated {
                return Err(format!(
                    "{}: {} resolves to {}, inside deny_read {}; refusing",
                    g.field,
                    g.stated.display(),
                    g.resolved.display(),
                    dl.display()
                ));
            }
        }
    }
    for (d, dl) in deny_write.iter().zip(&p.deny_write) {
        for g in &write {
            if within(d, &g.resolved) {
                return Err(format!(
                    "deny_write: {} lies inside {} {}; Landlock cannot carve a read-only path \
                     out of a writable tree; refusing",
                    dl.display(),
                    g.field,
                    g.stated.display()
                ));
            }
            if within(&g.resolved, d) {
                return Err(format!(
                    "{}: {} resolves to {}, inside deny_write {}; refusing",
                    g.field,
                    g.stated.display(),
                    g.resolved.display(),
                    dl.display()
                ));
            }
        }
    }
    Ok(Plan {
        read,
        write,
        skipped,
    })
}

/// Answer what the Linux backend would decide for one access, and which rule decides it.
/// `what` is a path or `tcp:PORT` / `udp:PORT`.
pub fn explain(p: &Profile, plan: &Plan, what: &str) -> Vec<String> {
    if let Some((proto, port)) = what
        .split_once(':')
        .filter(|(k, _)| *k == "tcp" || *k == "udp")
    {
        let verdict = match p.network.mode {
            NetworkMode::None => format!(
                "{proto} port {port}: denied (network.mode = none: socket(2) fails with EACCES)"
            ),
            NetworkMode::Unfiltered => {
                format!("{proto} port {port}: allowed (network.mode = unfiltered)")
            }
        };
        return vec![verdict];
    }
    let path = resolve(Path::new(what));
    let best = |gs: &[Grant]| {
        gs.iter()
            .filter(|g| within(&path, &g.resolved))
            .max_by_key(|g| g.resolved.components().count())
            .map(|g| format!("{} {}", g.field, g.stated.display()))
    };
    let mut out = vec![format!("path {what} (resolved: {})", path.display())];
    match best(&plan.write) {
        Some(rule) => {
            out.push(format!("read: allowed ({rule})"));
            out.push(format!("write: allowed ({rule})"));
        }
        None => {
            match best(&plan.read) {
                Some(rule) => out.push(format!("read: allowed ({rule})")),
                None => out.push(
                    "read: denied (no read or write grant covers it; open fails with EACCES)"
                        .into(),
                ),
            }
            out.push(
                "write: denied (no write grant covers it; open/create/unlink fail with EACCES, \
                 cross-directory rename or link with EXDEV)"
                    .into(),
            );
        }
    }
    out
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
/// Terminal ioctls that act on a terminal on another process's behalf: TIOCSTI pushes bytes
/// into the input queue (which an unconfined parent shell then reads), TIOCLINUX can paste the
/// console selection. Refused because the session inherits the caller's terminal on fds 0-2,
/// opened before confinement and so outside Landlock's IoctlDev right.
pub const TIOCSTI: u32 = 0x5412;
pub const TIOCLINUX: u32 = 0x541C;
/// `struct seccomp_data` offsets: nr, arch, args[0] and args[1] (low halves on little-endian).
pub const OFF_NR: u32 = 0;
pub const OFF_ARCH: u32 = 4;
pub const OFF_ARG0: u32 = 16;
pub const OFF_ARG1: u32 = 24;

/// The syscall table for one architecture.
#[derive(Debug, Clone, Copy)]
pub struct Arch {
    pub audit_arch: u32,
    pub socket: u32,
    pub ioctl: u32,
    pub io_uring: [u32; 3],
    /// Syscall numbers at or above this belong to a second ABI on the same audit arch (x32).
    pub foreign_from: Option<u32>,
}

pub const X86_64: Arch = Arch {
    audit_arch: 0xC000_003E,
    socket: 41,
    ioctl: 16,
    io_uring: [425, 426, 427],
    foreign_from: Some(0x4000_0000),
};

pub const AARCH64: Arch = Arch {
    audit_arch: 0xC000_00B7,
    socket: 198,
    ioctl: 29,
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

/// Jump targets in `seccomp_program`; resolved to forward offsets once the layout is known.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Label {
    Deny,
    Socket,
    Ioctl,
}

/// The seccomp program: kill a foreign architecture, refuse x32, io_uring and the terminal
/// ioctls TIOCSTI and TIOCLINUX with EPERM. `socket(2)` with family `AF_UNIX` is allowed when
/// `unix_sockets` holds, any other family when `inet_sockets` holds; the rest fail with EACCES.
pub fn seccomp_program(arch: Arch, unix_sockets: bool, inet_sockets: bool) -> Vec<Insn> {
    enum Op {
        Ld(u32),
        Ret(u32),
        Jump(u16, u32, Label),
        Mark(Label),
        /// Jump over the next `n` instructions when the condition holds.
        Skip(u16, u32, u8),
    }
    use Label::*;
    let mut ops = vec![
        Op::Ld(OFF_ARCH),
        Op::Skip(BPF_JEQ_K, arch.audit_arch, 1),
        Op::Ret(RET_KILL_PROCESS),
        Op::Ld(OFF_NR),
    ];
    if let Some(from) = arch.foreign_from {
        ops.push(Op::Jump(BPF_JGE_K, from, Deny));
    }
    ops.push(Op::Jump(BPF_JEQ_K, arch.socket, Socket));
    ops.push(Op::Jump(BPF_JEQ_K, arch.ioctl, Ioctl));
    for nr in arch.io_uring {
        ops.push(Op::Jump(BPF_JEQ_K, nr, Deny));
    }
    ops.push(Op::Ret(RET_ALLOW));
    ops.push(Op::Mark(Socket));
    match (unix_sockets, inet_sockets) {
        (true, true) => ops.push(Op::Ret(RET_ALLOW)),
        (false, false) => ops.push(Op::Ret(RET_ERRNO | EACCES)),
        (true, false) => {
            ops.push(Op::Ld(OFF_ARG0));
            ops.push(Op::Skip(BPF_JEQ_K, AF_UNIX, 1));
            ops.push(Op::Ret(RET_ERRNO | EACCES));
            ops.push(Op::Ret(RET_ALLOW));
        }
        (false, true) => {
            ops.push(Op::Ld(OFF_ARG0));
            ops.push(Op::Skip(BPF_JEQ_K, AF_UNIX, 1));
            ops.push(Op::Ret(RET_ALLOW));
            ops.push(Op::Ret(RET_ERRNO | EACCES));
        }
    }
    ops.push(Op::Mark(Ioctl));
    ops.push(Op::Ld(OFF_ARG1));
    ops.push(Op::Jump(BPF_JEQ_K, TIOCSTI, Deny));
    ops.push(Op::Jump(BPF_JEQ_K, TIOCLINUX, Deny));
    ops.push(Op::Ret(RET_ALLOW));
    ops.push(Op::Mark(Deny));
    ops.push(Op::Ret(RET_ERRNO | EPERM));

    // Resolve labels. BPF jumps only go forward, so a label may be marked more than once and a
    // jump goes to the nearest mark after it.
    let mut at = Vec::new();
    let mut n = 0usize;
    for op in &ops {
        match op {
            Op::Mark(l) => at.push((*l, n)),
            _ => n += 1,
        }
    }
    let index = |l: Label, from: usize| -> usize {
        at.iter()
            .filter(|(m, i)| *m == l && *i > from)
            .map(|&(_, i)| i)
            .min()
            .expect("forward label")
    };
    let mut prog = Vec::with_capacity(n);
    for op in &ops {
        let i = prog.len();
        let insn = match *op {
            Op::Mark(_) => continue,
            Op::Skip(code, k, n) => Insn {
                code,
                jt: n,
                jf: 0,
                k,
            },
            Op::Ld(k) => Insn {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k,
            },
            Op::Ret(k) => Insn {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k,
            },
            Op::Jump(code, k, l) => {
                let jt = u8::try_from(index(l, i) - i - 1).expect("short program");
                Insn { code, jt, jf: 0, k }
            }
        };
        prog.push(insn);
    }
    prog
}

/// Confine the calling process to `profile`. On success every later `exec` runs confined.
#[cfg(target_os = "linux")]
pub fn confine(profile: &Profile) -> Result<(Enforcement, Plan), String> {
    use landlock::BitFlags;
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
        RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
    };

    let plan = plan(profile)?;
    let arch = native_arch().ok_or("no seccomp syscall table for this architecture; refusing")?;
    let enf = enforcement(kernel_abi(), &profile.network)?;
    let abi = ABI::from(enf.abi);
    let err = |e: landlock::RulesetError| format!("Landlock: {e}; refusing");

    let mut fs_all = AccessFs::from_all(abi);
    if !enf.resolve_unix {
        fs_all.remove(AccessFs::ResolveUnix);
    }
    let mut scopes: BitFlags<Scope> = BitFlags::EMPTY;
    if enf.scope_signals {
        scopes |= Scope::Signal;
    }
    if enf.scope_abstract_unix {
        scopes |= Scope::AbstractUnixSocket;
    }
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(fs_all)
        .map_err(err)?;
    if enf.tcp {
        ruleset = ruleset
            .handle_access(AccessNet::from_all(abi))
            .map_err(err)?;
    }
    if !scopes.is_empty() {
        ruleset = ruleset.scope(scopes).map_err(err)?;
    }
    let mut created = ruleset.create().map_err(err)?;
    if enf.audit_log {
        // Log denials after the exec too: the session is a new program.
        created = created.log_new_exec(true).map_err(err)?;
    }
    for (paths, access) in [
        (&plan.read, AccessFs::from_read(abi)),
        (&plan.write, fs_all),
    ] {
        for path in paths.iter().map(|g| &g.resolved) {
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
        let mut filter: Vec<libc::sock_filter> =
            seccomp_program(arch, enf.unix_sockets, enf.inet_sockets)
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
    Ok((enf, plan))
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

    // ---- enforcement(abi, network) ----

    fn net(mode: NetworkMode, unix: UnixSockets) -> Network {
        Network {
            mode,
            unix_sockets: unix,
            ..Network::default()
        }
    }

    // rivet: verifies REQ-ZW-004
    #[test]
    fn abi_below_minimum_refuses() {
        for abi in [-1, 0, 1, 2] {
            assert!(enforcement(abi, &Network::default()).is_err(), "abi {abi}");
        }
        assert!(enforcement(MIN_ABI, &Network::default()).is_ok());
    }

    #[test]
    fn abi_features_switch_on_at_their_versions() {
        let e = |abi| enforcement(abi, &Network::default()).unwrap();
        assert_eq!(
            e(3),
            Enforcement {
                abi: 3,
                network: NetworkMode::None,
                inet_sockets: false,
                tcp: false,
                udp: false,
                unix_sockets: false,
                resolve_unix: false,
                scope_abstract_unix: false,
                scope_signals: false,
                ioctl_dev: false,
                audit_log: false,
            }
        );
        assert!(e(4).tcp && !e(4).ioctl_dev);
        assert!(e(5).ioctl_dev && !e(5).scope_signals);
        assert!(e(6).scope_signals && e(6).scope_abstract_unix && !e(6).audit_log);
        assert!(e(7).audit_log && !e(8).unix_sockets);
        assert!(e(9).unix_sockets && e(9).resolve_unix && !e(9).udp);
        assert!(e(10).udp);
        assert_eq!(
            e(42).abi,
            MAX_KNOWN_ABI,
            "newer kernels run at the known ABI"
        );
    }

    // rivet: verifies REQ-ZW-009
    #[test]
    fn unfiltered_network_drops_every_network_rule() {
        for abi in [3, 4, 10] {
            let e = enforcement(abi, &net(NetworkMode::Unfiltered, UnixSockets::Confined)).unwrap();
            assert!(e.inet_sockets && !e.tcp && !e.udp, "abi {abi}");
            assert_eq!(e.unix_sockets, abi >= UNIX_SOCKET_ABI, "abi {abi}");
        }
    }

    // rivet: verifies REQ-ZW-009
    #[test]
    fn unfiltered_unix_sockets_drop_landlock_unix_confinement() {
        for abi in [3, 6, 9, 10] {
            let e = enforcement(abi, &net(NetworkMode::None, UnixSockets::Unfiltered)).unwrap();
            assert!(
                e.unix_sockets && !e.resolve_unix && !e.scope_abstract_unix,
                "abi {abi}"
            );
            assert!(!e.inet_sockets);
            assert_eq!(e.scope_signals, abi >= 6, "signals stay scoped, abi {abi}");
        }
    }

    // rivet: verifies REQ-ZW-010
    #[test]
    fn summary_names_the_abi_mode_and_gaps() {
        let plan = Plan {
            read: vec![],
            write: vec![],
            skipped: vec![PathBuf::from("/opt/x")],
        };
        let e = enforcement(4, &net(NetworkMode::Unfiltered, UnixSockets::Confined)).unwrap();
        assert_eq!(
            e.summary("runner19", &plan),
            "zwinger: runner19 confined: landlock abi 4; 0 read, 0 write grants (absent, \
             skipped: /opt/x); network: unfiltered; unix sockets: refused; denial audit log: off \
             (abi 7); not enforced: network (mode = unfiltered), device ioctls (abi 5), signal \
             scoping (abi 6)"
        );
        let plan = Plan {
            read: vec![],
            write: vec![],
            skipped: vec![],
        };
        let e = enforcement(10, &Network::default()).unwrap();
        assert_eq!(
            e.summary("agent", &plan),
            "zwinger: agent confined: landlock abi 10; 0 read, 0 write grants; network: none; \
             unix sockets: confined to write trees; denial audit log: on"
        );
        let e = enforcement(10, &net(NetworkMode::None, UnixSockets::Unfiltered)).unwrap();
        assert!(e.summary("a", &plan).ends_with(
            "unix sockets: unfiltered; denial audit log: on; not enforced: unix socket \
             connections (unix_sockets = unfiltered)"
        ));
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
        let resolved = |gs: &[Grant]| gs.iter().map(|g| g.resolved.clone()).collect::<Vec<_>>();
        assert_eq!(
            resolved(&p.read),
            vec![t.0.join("usr").canonicalize().unwrap()]
        );
        assert_eq!(
            resolved(&p.write),
            vec![t.0.join("home/repo").canonicalize().unwrap()]
        );
        assert!(p.skipped.is_empty());
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

    // rivet: verifies REQ-ZW-009
    #[test]
    fn missing_if_present_grants_are_skipped_not_refused() {
        let t = tree();
        let body = "read_if_present = [\"@/nope\", \"@/usr\"]\nwrite_if_present = [\"@/gone\"]\n";
        let p = plan(&profile(&t, body)).unwrap();
        assert_eq!(p.read.len(), 1);
        assert_eq!(p.read[0].field, "read_if_present");
        assert!(p.write.is_empty());
        assert_eq!(p.skipped, vec![t.0.join("nope"), t.0.join("gone")]);
    }

    // rivet: verifies REQ-ZW-009
    #[test]
    fn if_present_grants_obey_the_carve_out_rules() {
        let t = tree();
        let body = "write_if_present = [\"@/home\"]\ndeny_read = [\"@/home/.ssh\"]\n";
        assert!(plan(&profile(&t, body)).is_err());
        let body = "write_if_present = [\"@/home/repo\"]\ndeny_write = [\"@/home/repo/.claude\"]\n";
        assert!(plan(&profile(&t, body)).is_err());
        let body = "read_if_present = [\"@/home/.ssh/k.pub\"]\ndeny_read = [\"@/home/.ssh\"]\n";
        assert!(plan(&profile(&t, body)).is_ok(), "a stated read exception");
    }

    // rivet: verifies REQ-ZW-010
    #[test]
    fn explain_names_the_deciding_grant() {
        let t = tree();
        let pr = profile(&t, "read = [\"@/home\"]\nwrite = [\"@/home/repo\"]\n");
        let pl = plan(&pr).unwrap();
        let home = t.0.join("home");
        let ex = |p: &Path| explain(&pr, &pl, p.to_str().unwrap());
        let w = ex(&home.join("repo/src/x.rs"));
        assert_eq!(
            w[1],
            format!("read: allowed (write {})", home.join("repo").display())
        );
        assert_eq!(
            w[2],
            format!("write: allowed (write {})", home.join("repo").display())
        );
        let r = ex(&home.join(".ssh/k.pub"));
        assert_eq!(r[1], format!("read: allowed (read {})", home.display()));
        assert!(r[2].starts_with("write: denied"), "{r:?}");
        let o = ex(&t.0.join("usr/bin"));
        assert!(
            o[1].starts_with("read: denied") && o[2].starts_with("write: denied"),
            "{o:?}"
        );
        assert_eq!(o.len(), 3);
    }

    #[test]
    fn explain_picks_the_most_specific_read_grant() {
        let t = tree();
        let pr = profile(&t, "read = [\"@/home\", \"@/home/repo\"]\n");
        let pl = plan(&pr).unwrap();
        let x = explain(&pr, &pl, t.0.join("home/repo/a").to_str().unwrap());
        assert_eq!(
            x[1],
            format!("read: allowed (read {})", t.0.join("home/repo").display())
        );
        let pr = profile(&t, "read = [\"@/home/repo\", \"@/home\"]\n");
        let pl = plan(&pr).unwrap();
        let x = explain(&pr, &pl, t.0.join("home/repo/a").to_str().unwrap());
        assert_eq!(
            x[1],
            format!("read: allowed (read {})", t.0.join("home/repo").display())
        );
    }

    // rivet: verifies REQ-ZW-010
    #[test]
    fn explain_answers_ports_by_mode() {
        let t = tree();
        let none = profile(&t, "");
        let pl = plan(&none).unwrap();
        assert!(explain(&none, &pl, "tcp:443")[0].starts_with("tcp port 443: denied"));
        assert!(explain(&none, &pl, "udp:53")[0].starts_with("udp port 53: denied"));
        let open = profile(&t, "[network]\nmode = \"unfiltered\"\n");
        let pl = plan(&open).unwrap();
        assert!(explain(&open, &pl, "tcp:443")[0].starts_with("tcp port 443: allowed"));
        // Only tcp: and udp: are ports; anything else is a path.
        assert!(explain(&open, &pl, "http:x")[0].starts_with("path http:x"));
    }

    // rivet: verifies REQ-ZW-011
    #[test]
    fn runner_template_refuses_until_substituted_then_plans() {
        let template = include_str!("../profiles/github-runner.toml");
        assert!(matches!(
            Profile::parse(Path::new("github-runner.toml"), template),
            Err(crate::profile::ProfileError::Invalid(..))
        ));
        let t = tree();
        for d in [
            "runner/_work",
            "runner/_tmp",
            "runner/_diag",
            "runner/.cache",
        ] {
            std::fs::create_dir_all(t.0.join(d)).unwrap();
        }
        let home = t.0.join("runner");
        let text = template.replace("{{home}}", home.to_str().unwrap());
        assert!(!text.contains("{{"), "the only placeholder is {{home}}");
        let p = Profile::parse(Path::new("runner.toml"), &text).unwrap();
        assert_eq!(p.network.mode, NetworkMode::Unfiltered);
        assert!(
            p.write
                .iter()
                .all(|w| w.starts_with(&home) || w.starts_with("/tmp") || w.starts_with("/dev"))
        );
        assert!(!p.write.contains(&home), "the home itself stays read-only");
        // The system trees exist on Linux runners, not on every test host; check the planner
        // on the runner's own part only.
        let mut own = p.clone();
        own.read.retain(|r| r.starts_with(&home));
        own.write.retain(|w| w.starts_with(&home));
        own.read_if_present.clear();
        let pl = plan(&own).unwrap();
        assert_eq!(
            pl.write.len(),
            3 + 1,
            "_work, _tmp, _diag and the one cache present"
        );
        assert_eq!(pl.skipped.len(), own.write_if_present.len() - 1);
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
    fn run(prog: &[Insn], arch: u32, nr: u32, arg0: u32, arg1: u32) -> u32 {
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
                        OFF_ARG1 => arg1,
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
        for (unix, inet) in [(false, false), (true, false), (false, true), (true, true)] {
            let prog = seccomp_program(arch, unix, inet);
            let r = |nr, a0| run(&prog, arch.audit_arch, nr, a0, 0);
            let inet_expect = if inet { RET_ALLOW } else { RET_ERRNO | EACCES };
            for fam in [AF_INET, AF_INET6, AF_NETLINK, AF_PACKET, 0, 0xffff_ffff] {
                assert_eq!(
                    r(arch.socket, fam),
                    inet_expect,
                    "family {fam}, inet {inet}"
                );
            }
            let unix_expect = if unix { RET_ALLOW } else { RET_ERRNO | EACCES };
            assert_eq!(r(arch.socket, AF_UNIX), unix_expect);
            for nr in arch.io_uring {
                assert_eq!(r(nr, 0), RET_ERRNO | EPERM, "io_uring {nr}");
            }
            for nr in [0, 1, 59, 221, 424, 428] {
                assert_eq!(r(nr, AF_INET), RET_ALLOW, "nr {nr}");
            }
            // ioctl: only the two terminal-injection requests are refused, on any fd.
            let io = |fd, req| run(&prog, arch.audit_arch, arch.ioctl, fd, req);
            for fd in [0, 1, 2, 7] {
                assert_eq!(io(fd, TIOCSTI), RET_ERRNO | EPERM, "TIOCSTI on fd {fd}");
                assert_eq!(io(fd, TIOCLINUX), RET_ERRNO | EPERM, "TIOCLINUX on fd {fd}");
            }
            for req in [0x5401, 0x5413, 0x541B, 0x5411, 0, TIOCSTI + 0x1_0000] {
                assert_eq!(io(0, req), RET_ALLOW, "ioctl {req:#x}");
            }
            if let Some(from) = arch.foreign_from {
                assert_eq!(r(from + arch.socket, AF_INET), RET_ERRNO | EPERM);
                assert_eq!(r(from, 0), RET_ERRNO | EPERM);
                assert_eq!(r(from - 1, 0), RET_ALLOW);
            }
            assert_eq!(
                run(&prog, 0x4000_0003, 0, 0, 0),
                RET_KILL_PROCESS,
                "i386 on x86_64"
            );
            assert_eq!(
                run(&prog, arch.audit_arch ^ 1, arch.socket, AF_UNIX, 0),
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
