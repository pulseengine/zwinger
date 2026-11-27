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

use crate::profile::{Network, NetworkMode, Profile, UnixSockets, normalize, within};
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
    /// The resolved `noexec` trees: no grant at or beneath one keeps the right to execute.
    pub noexec: Vec<PathBuf>,
}

fn bytes<'a>(paths: &[&'a Path]) -> Vec<&'a [u8]> {
    use std::os::unix::ffi::OsStrExt;
    paths.iter().map(|p| p.as_os_str().as_bytes()).collect()
}

/// Whether a grant keeps Landlock's execute right: not when it lies at or beneath a `noexec`
/// tree. `pathrules::may_exec_bytes` on the paths' bytes.
pub fn may_exec(grant: &Path, noexec: &[&Path]) -> bool {
    use std::os::unix::ffi::OsStrExt;
    crate::pathrules::may_exec_bytes(grant.as_os_str().as_bytes(), &bytes(noexec))
}

/// A `noexec` tree that lies strictly inside a grant, by index into each list. That grant's
/// execute right covers the tree, and Landlock, which adds rights along a path, cannot take it
/// away beneath the grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoexecViolation {
    pub noexec: usize,
    pub grant: usize,
}

/// The `noexec` rule on resolved paths: `pathrules::first_noexec_violation_bytes`, whose
/// soundness Verus proves for paths of any length, on the paths' bytes. A profile is
/// enforceable as written exactly when no grant strictly contains a `noexec` tree: then every
/// grant covering a path beneath the tree lies at or beneath it, and `may_exec` drops its
/// execute right.
pub fn first_noexec_violation(grants: &[&Path], noexec: &[&Path]) -> Option<NoexecViolation> {
    crate::pathrules::first_noexec_violation_bytes(&bytes(grants), &bytes(noexec))
        .map(|(noexec, grant)| NoexecViolation { noexec, grant })
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
        if !plan.noexec.is_empty() {
            let names: Vec<String> = plan
                .noexec
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            s += &format!(" (no execution under: {})", names.join(", "));
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

/// Why a kernel's Landlock cannot carry a profile. A plain enum, so the decision stays cheap to
/// reason about (the Kani proof covers every ABI); the text is rendered by `Display`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiRefusal {
    /// Landlock is not built in or not enabled.
    Unavailable,
    /// Landlock is there, below `MIN_ABI`.
    TooOld(i32),
}

impl std::fmt::Display for AbiRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbiRefusal::Unavailable => write!(
                f,
                "Landlock is not available on this kernel (not built in or not enabled in the \
                 lsm= list); refusing to run unconfined"
            ),
            AbiRefusal::TooOld(abi) => write!(
                f,
                "Landlock ABI {abi} cannot restrict truncate(2); ABI {MIN_ABI} (Linux 6.2) is the \
                 minimum; refusing to run partially confined"
            ),
        }
    }
}

/// Decide what to enforce for `network` on a kernel reporting Landlock ABI `abi` (<= 0:
/// unavailable).
pub fn enforcement(abi: i32, network: &Network) -> Result<Enforcement, AbiRefusal> {
    if abi <= 0 {
        return Err(AbiRefusal::Unavailable);
    }
    if abi < MIN_ABI {
        return Err(AbiRefusal::TooOld(abi));
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
            return normalize(&rest.iter().rev().fold(c, |acc: PathBuf, n| acc.join(n)));
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_owned());
                cur = parent;
            }
            _ => return normalize(p),
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

/// A denied path: as the profile stated it, and as Landlock would reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    pub stated: PathBuf,
    pub resolved: PathBuf,
}

/// Why Landlock cannot enforce a profile's denied paths as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarveRefusal {
    /// A denied path lies inside a granted tree; Landlock grants cannot be subtracted from.
    DenyInsideGrant {
        deny_field: &'static str,
        deny: Denied,
        grant: Grant,
    },
    /// A grant resolves into a denied tree and is not a read exception the profile stated.
    GrantInsideDeny {
        deny_field: &'static str,
        deny: Denied,
        grant: Grant,
    },
}

impl std::fmt::Display for CarveRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CarveRefusal::DenyInsideGrant {
                deny_field: "deny_read",
                deny,
                grant,
            } => write!(
                f,
                "deny_read: {} lies inside {} {} (resolved: {} in {}); Landlock cannot carve a \
                 denied path out of a granted tree; refusing",
                deny.stated.display(),
                grant.field,
                grant.stated.display(),
                deny.resolved.display(),
                grant.resolved.display()
            ),
            CarveRefusal::DenyInsideGrant {
                deny_field,
                deny,
                grant,
            } => write!(
                f,
                "{deny_field}: {} lies inside {} {}; Landlock cannot carve a read-only path out \
                 of a writable tree; refusing",
                deny.stated.display(),
                grant.field,
                grant.stated.display()
            ),
            CarveRefusal::GrantInsideDeny {
                deny_field,
                deny,
                grant,
            } => write!(
                f,
                "{}: {} resolves to {}, inside {deny_field} {}; refusing",
                grant.field,
                grant.stated.display(),
                grant.resolved.display(),
                deny.stated.display()
            ),
        }
    }
}

/// One path entry as the carve-out rules see it: its field, as stated, as resolved.
#[derive(Debug, Clone, Copy)]
pub struct PathView<'a> {
    pub field: &'static str,
    pub stated: &'a Path,
    pub resolved: &'a Path,
}

pub use crate::pathrules::Violation;

/// The carve-out rules on resolved paths: `pathrules::first_carve_violation_bytes`, whose
/// soundness Verus proves for paths of any length, on the paths' bytes. Landlock only grants,
/// so a profile is enforceable as written exactly when no granted tree covers a denied path,
/// and no grant reaches into a denied tree except a read the profile stated inside a deny_read
/// (one public key in a secrets directory).
pub fn first_carve_violation(
    read: &[PathView],
    write: &[PathView],
    deny_read: &[PathView],
    deny_write: &[PathView],
) -> Option<Violation> {
    use crate::pathrules::{Entry, first_carve_violation_bytes};
    use std::os::unix::ffi::OsStrExt;
    fn entries<'a>(views: &[PathView<'a>]) -> Vec<Entry<'a>> {
        views
            .iter()
            .map(|v| Entry {
                is_read: v.field.starts_with("read"),
                stated: v.stated.as_os_str().as_bytes(),
                resolved: v.resolved.as_os_str().as_bytes(),
            })
            .collect()
    }
    first_carve_violation_bytes(
        &entries(read),
        &entries(write),
        &entries(deny_read),
        &entries(deny_write),
    )
}

/// `first_carve_violation` over owned grants and denied paths, as a refusal naming the paths.
pub fn check_carve_outs(
    read: &[Grant],
    write: &[Grant],
    deny_read: &[Denied],
    deny_write: &[Denied],
) -> Result<(), Box<CarveRefusal>> {
    fn g(gs: &[Grant]) -> Vec<PathView<'_>> {
        gs.iter()
            .map(|g| PathView {
                field: g.field,
                stated: &g.stated,
                resolved: &g.resolved,
            })
            .collect()
    }
    fn d<'a>(field: &'static str, ds: &'a [Denied]) -> Vec<PathView<'a>> {
        ds.iter()
            .map(|d| PathView {
                field,
                stated: &d.stated,
                resolved: &d.resolved,
            })
            .collect()
    }
    let Some(v) = first_carve_violation(
        &g(read),
        &g(write),
        &d("deny_read", deny_read),
        &d("deny_write", deny_write),
    ) else {
        return Ok(());
    };
    let (deny_field, deny) = if v.deny_write {
        ("deny_write", deny_write[v.deny].clone())
    } else {
        ("deny_read", deny_read[v.deny].clone())
    };
    let grant = if v.write_grant {
        write[v.grant].clone()
    } else {
        read[v.grant].clone()
    };
    Err(Box::new(if v.deny_inside_grant {
        CarveRefusal::DenyInsideGrant {
            deny_field,
            deny,
            grant,
        }
    } else {
        CarveRefusal::GrantInsideDeny {
            deny_field,
            deny,
            grant,
        }
    }))
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
    let denied = |stated: &[PathBuf]| -> Vec<Denied> {
        stated
            .iter()
            .map(|d| Denied {
                stated: d.clone(),
                resolved: resolve(d),
            })
            .collect()
    };
    check_carve_outs(&read, &write, &denied(&p.deny_read), &denied(&p.deny_write))
        .map_err(|e| e.to_string())?;
    let noexec: Vec<PathBuf> = p.noexec.iter().map(|n| resolve(n)).collect();
    let all: Vec<&Grant> = read.iter().chain(write.iter()).collect();
    let paths: Vec<&Path> = all.iter().map(|g| g.resolved.as_path()).collect();
    let trees: Vec<&Path> = noexec.iter().map(PathBuf::as_path).collect();
    if let Some(v) = first_noexec_violation(&paths, &trees) {
        let g = all[v.grant];
        return Err(format!(
            "noexec: {} lies inside {} {}, which allows execution; Landlock cannot take that \
             right away beneath a grant; refusing",
            p.noexec[v.noexec].display(),
            g.field,
            g.stated.display()
        ));
    }
    Ok(Plan {
        read,
        write,
        skipped,
        noexec,
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
    let covering = best(&plan.write).or_else(|| best(&plan.read));
    out.push(
        match (covering, plan.noexec.iter().find(|n| within(&path, n))) {
            (None, _) => "execute: denied (no read or write grant covers it)".into(),
            (Some(_), Some(n)) => format!(
                "execute: denied (noexec {}: execve fails with EACCES)",
                n.display()
            ),
            (Some(rule), None) => format!("execute: allowed ({rule})"),
        },
    );
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

/// Upper bound on the program length (x86_64 with AF_UNIX allowed and the network refused).
pub const MAX_PROGRAM: usize = 20;

/// A seccomp program in a fixed array, so building it allocates nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Program {
    insns: [Insn; MAX_PROGRAM],
    len: usize,
}

impl Program {
    pub fn as_slice(&self) -> &[Insn] {
        &self.insns[..self.len]
    }

    /// For the planted-bug controls in the Kani proofs only.
    #[cfg(kani)]
    pub fn as_mut_slice(&mut self) -> &mut [Insn] {
        &mut self.insns[..self.len]
    }

    fn push(&mut self, insn: Insn) {
        self.insns[self.len] = insn;
        self.len += 1;
    }
}

const fn ld(k: u32) -> Insn {
    Insn {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn ret(k: u32) -> Insn {
    Insn {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k,
    }
}

/// The seccomp program: kill a foreign architecture, refuse x32, io_uring and the terminal
/// ioctls TIOCSTI and TIOCLINUX with EPERM. `socket(2)` with family `AF_UNIX` is allowed when
/// `unix_sockets` holds, any other family when `inet_sockets` holds; the rest fail with EACCES.
///
/// Layout, block by block (jumps only go forward, so every target is computed from it):
///
/// ```text
/// head    ld arch; jeq ARCH +1; ret KILL; ld nr
/// checks  [jge X32 -> deny]; jeq socket -> sock; jeq ioctl -> ioctl; jeq io_uring x3 -> deny
/// allow   ret ALLOW
/// sock    one ret (both or neither family allowed), or ld arg0; jeq AF_UNIX +1; ret; ret
/// ioctl   ld arg1; jeq TIOCSTI -> deny; jeq TIOCLINUX -> deny; ret ALLOW
/// deny    ret EPERM
/// ```
pub fn seccomp_program(arch: Arch, unix_sockets: bool, inet_sockets: bool) -> Program {
    let n_checks = usize::from(arch.foreign_from.is_some()) + 2 + arch.io_uring.len();
    let first_check = 4;
    let allow_at = first_check + n_checks;
    let sock_at = allow_at + 1;
    let sock_len = if unix_sockets == inet_sockets { 1 } else { 4 };
    let ioctl_at = sock_at + sock_len;
    let deny_at = ioctl_at + 4;

    let mut p = Program {
        insns: [ret(0); MAX_PROGRAM],
        len: 0,
    };
    let jump = |code, k, from: usize, to: usize| Insn {
        code,
        jt: u8::try_from(to - from - 1).expect("short program"),
        jf: 0,
        k,
    };
    p.push(ld(OFF_ARCH));
    p.push(Insn {
        code: BPF_JEQ_K,
        jt: 1,
        jf: 0,
        k: arch.audit_arch,
    });
    p.push(ret(RET_KILL_PROCESS));
    p.push(ld(OFF_NR));
    if let Some(from) = arch.foreign_from {
        p.push(jump(BPF_JGE_K, from, p.len, deny_at));
    }
    p.push(jump(BPF_JEQ_K, arch.socket, p.len, sock_at));
    p.push(jump(BPF_JEQ_K, arch.ioctl, p.len, ioctl_at));
    for nr in arch.io_uring {
        p.push(jump(BPF_JEQ_K, nr, p.len, deny_at));
    }
    p.push(ret(RET_ALLOW));
    match (unix_sockets, inet_sockets) {
        (true, true) => p.push(ret(RET_ALLOW)),
        (false, false) => p.push(ret(RET_ERRNO | EACCES)),
        (unix, _) => {
            // Exactly one family class is allowed: AF_UNIX falls through to the first `ret`.
            let (unix_ret, other_ret) = if unix {
                (RET_ALLOW, RET_ERRNO | EACCES)
            } else {
                (RET_ERRNO | EACCES, RET_ALLOW)
            };
            p.push(ld(OFF_ARG0));
            p.push(Insn {
                code: BPF_JEQ_K,
                jt: 0,
                jf: 1,
                k: AF_UNIX,
            });
            p.push(ret(unix_ret));
            p.push(ret(other_ret));
        }
    }
    p.push(ld(OFF_ARG1));
    p.push(jump(BPF_JEQ_K, TIOCSTI, p.len, deny_at));
    p.push(jump(BPF_JEQ_K, TIOCLINUX, p.len, deny_at));
    p.push(ret(RET_ALLOW));
    p.push(ret(RET_ERRNO | EPERM));
    debug_assert_eq!(p.len, deny_at + 1);
    p
}

/// A classic-BPF interpreter for the subset `seccomp_program` emits, over one `seccomp_data`.
/// It is the semantics the unit tests and the Kani proofs judge the program by; the kernel's own
/// interpreter is the external check (tests/linux.rs runs the program in real kernels). Panics on
/// an instruction outside the subset or a jump past the end, both of which the proofs rule out.
#[cfg(any(test, kani))]
pub(crate) fn bpf_run(prog: &[Insn], arch: u32, nr: u32, arg0: u32, arg1: u32) -> u32 {
    // Classic BPF only jumps forward (jt and jf are unsigned offsets), so walking the program in
    // order and executing only the instruction at `next` is the same semantics, with a concrete
    // loop index (which keeps the Kani proof tractable).
    let (mut next, mut acc) = (0usize, 0u32);
    for (pc, i) in prog.iter().enumerate() {
        if pc != next {
            continue;
        }
        next = pc + 1;
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
            BPF_JEQ_K => next += usize::from(if acc == i.k { i.jt } else { i.jf }),
            BPF_JGE_K => next += usize::from(if acc >= i.k { i.jt } else { i.jf }),
            BPF_RET_K => return i.k,
            c => panic!("opcode {c:#x}"),
        }
    }
    panic!("ran past the end of the program")
}

/// The filter's required verdict for one syscall, stated from REQ-ZW-005 and REQ-ZW-006 without
/// reference to how `seccomp_program` lays out its instructions:
/// - a foreign audit architecture is killed;
/// - a second syscall ABI on the same architecture (x32) fails with EPERM;
/// - io_uring_setup, io_uring_enter and io_uring_register fail with EPERM;
/// - ioctl with request TIOCSTI or TIOCLINUX (low 32 bits) fails with EPERM, any fd;
/// - socket(AF_UNIX, ..) is allowed iff `unix_sockets`, any other family iff `inet_sockets`,
///   otherwise it fails with EACCES;
/// - every other syscall is allowed (Landlock, not seccomp, governs it).
#[cfg(any(test, kani))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn seccomp_spec(
    arch: Arch,
    unix_sockets: bool,
    inet_sockets: bool,
    audit_arch: u32,
    nr: u32,
    arg0: u32,
    arg1: u32,
) -> u32 {
    if audit_arch != arch.audit_arch {
        return RET_KILL_PROCESS;
    }
    if arch.foreign_from.is_some_and(|from| nr >= from) {
        return RET_ERRNO | EPERM;
    }
    if arch.io_uring.contains(&nr) {
        return RET_ERRNO | EPERM;
    }
    if nr == arch.ioctl && (arg1 == TIOCSTI || arg1 == TIOCLINUX) {
        return RET_ERRNO | EPERM;
    }
    if nr == arch.socket {
        let allowed = if arg0 == AF_UNIX {
            unix_sockets
        } else {
            inet_sockets
        };
        return if allowed {
            RET_ALLOW
        } else {
            RET_ERRNO | EACCES
        };
    }
    RET_ALLOW
}

/// The plan as `ZWINGER_GRANTS` carries it. Linux refuses a denial inside a grant, so the
/// profile's denials lie outside every grant; they are passed resolved for the command's
/// information.
pub fn session_grants(profile: &Profile, plan: &Plan) -> crate::grants::Grants {
    use crate::grants::resolve_or_stated;
    crate::grants::Grants {
        read: plan.read.iter().map(|g| g.resolved.clone()).collect(),
        write: plan.write.iter().map(|g| g.resolved.clone()).collect(),
        deny_read: profile
            .deny_read
            .iter()
            .map(|p| resolve_or_stated(p))
            .collect(),
        deny_write: profile
            .deny_write
            .iter()
            .map(|p| resolve_or_stated(p))
            .collect(),
        noexec: plan.noexec.clone(),
        exec: Vec::new(),
    }
}

/// Everything `confine` decides before it changes the process: the path plan, the syscall table
/// and what this kernel can enforce. `zwinger check` runs it, so `check` refuses whatever `run`
/// would refuse, including a granted path that does not exist yet.
#[cfg(target_os = "linux")]
pub fn preflight(profile: &Profile) -> Result<(Enforcement, Plan), String> {
    let plan = plan(profile)?;
    native_arch().ok_or("no seccomp syscall table for this architecture; refusing")?;
    let enf = enforcement(kernel_abi(), &profile.network).map_err(|e| e.to_string())?;
    Ok((enf, plan))
}

/// Confine the calling process to `profile`. On success every later `exec` runs confined.
#[cfg(target_os = "linux")]
pub fn confine(profile: &Profile) -> Result<(Enforcement, Plan), String> {
    use landlock::BitFlags;
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
        RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
    };

    let (enf, plan) = preflight(profile)?;
    let arch = native_arch().ok_or("no seccomp syscall table for this architecture; refusing")?;
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
    let noexec: Vec<&Path> = plan.noexec.iter().map(PathBuf::as_path).collect();
    for (paths, access) in [
        (&plan.read, AccessFs::from_read(abi)),
        (&plan.write, fs_all),
    ] {
        for path in paths.iter().map(|g| &g.resolved) {
            let fd = PathFd::new(path).map_err(|e| format!("{}: {e}; refusing", path.display()))?;
            let mut access = if path.is_dir() {
                access
            } else {
                access & AccessFs::from_file(abi)
            };
            if !may_exec(path, &noexec) {
                access.remove(AccessFs::Execute);
            }
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

    sys::close_range_cloexec()
        .map_err(|e| format!("close_range: {e}; refusing to leak inherited descriptors"))?;
    let mut filter: Vec<libc::sock_filter> =
        seccomp_program(arch, enf.unix_sockets, enf.inet_sockets)
            .as_slice()
            .iter()
            .map(|i| libc::sock_filter {
                code: i.code,
                jt: i.jt,
                jf: i.jf,
                k: i.k,
            })
            .collect();
    sys::set_seccomp_filter(&mut filter).map_err(|e| format!("seccomp: {e}; refusing"))?;
    Ok((enf, plan))
}

/// The kernel's Landlock ABI version, or 0 when Landlock is unavailable.
#[cfg(target_os = "linux")]
fn kernel_abi() -> i32 {
    i32::try_from(sys::landlock_abi()).unwrap_or(0).max(0)
}

/// The only unsafe code in the Linux backend (docs/trusted-base.md): three raw syscalls the
/// landlock crate does not wrap. Everything they are given is computed and checked by the
/// safe code above.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod sys {
    /// Mark every inherited descriptor from 3 up close-on-exec.
    pub(super) fn close_range_cloexec() -> std::io::Result<()> {
        // SAFETY: a plain syscall on integer arguments.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Install `filter` as the seccomp filter. no_new_privs is already set by Landlock's
    /// restrict_self, which runs first.
    pub(super) fn set_seccomp_filter(filter: &mut [libc::sock_filter]) -> std::io::Result<()> {
        let len = u16::try_from(filter.len())
            .map_err(|_| std::io::Error::other("seccomp program longer than u16::MAX"))?;
        let prog = libc::sock_fprog {
            len,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: `prog` points at `filter`, which is live and correctly laid out for the whole
        // call; the kernel copies the program before returning.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0u32,
                &prog as *const libc::sock_fprog,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// LANDLOCK_CREATE_RULESET_VERSION: the ABI version, or a negative value without Landlock.
    pub(super) fn landlock_abi() -> libc::c_long {
        // SAFETY: a null attr with size 0 and the version flag only query the kernel.
        unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<u8>(),
                0usize,
                1u32,
            )
        }
    }
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
    fn abi_refusals_say_why() {
        let none = Network::default();
        assert_eq!(enforcement(0, &none), Err(AbiRefusal::Unavailable));
        assert_eq!(enforcement(-5, &none), Err(AbiRefusal::Unavailable));
        assert_eq!(enforcement(2, &none), Err(AbiRefusal::TooOld(2)));
        assert!(
            AbiRefusal::Unavailable
                .to_string()
                .starts_with("Landlock is not available")
        );
        assert!(
            AbiRefusal::TooOld(2)
                .to_string()
                .starts_with("Landlock ABI 2 cannot restrict")
        );
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
            noexec: vec![],
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
            noexec: vec![],
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
        let text = format!("name: \"t\"\n{}", body.replace("@", t.0.to_str().unwrap()));
        Profile::parse(Path::new("t.yaml"), &text).unwrap()
    }

    // rivet: verifies REQ-ZW-004
    #[test]
    fn plan_resolves_granted_paths() {
        let t = tree();
        let p = plan(&profile(
            &t,
            "read: [\"@/usr\"]\nwrite: [\"@/home/repo\"]\n",
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
        assert!(plan(&profile(&t, "read: [\"@/nope\"]\n")).is_err());
        assert!(plan(&profile(&t, "write: [\"@/nope\"]\n")).is_err());
    }

    // rivet: verifies REQ-ZW-008
    #[test]
    fn deny_read_inside_a_granted_tree_refuses() {
        let t = tree();
        assert!(
            plan(&profile(
                &t,
                "read: [\"@/home\"]\ndeny_read: [\"@/home/.ssh\"]\n"
            ))
            .is_err()
        );
        assert!(
            plan(&profile(
                &t,
                "write: [\"@/home\"]\ndeny_read: [\"@/home/.ssh\"]\n"
            ))
            .is_err()
        );
        // Not-yet-existing denied paths are checked too.
        assert!(
            plan(&profile(
                &t,
                "read: [\"@/home\"]\ndeny_read: [\"@/home/later\"]\n"
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
                "read: [\"@/usr\"]\ndeny_read: [\"@/home/.ssh\"]\n"
            ))
            .is_ok()
        );
    }

    #[test]
    fn stated_read_exception_inside_deny_read_is_allowed() {
        let t = tree();
        let p = "read: [\"@/home/.ssh/k.pub\"]\ndeny_read: [\"@/home/.ssh\"]\n";
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
            let body = format!("read: [\"{read}\"]\ndeny_read: [\"@/home/.ssh\"]\n");
            assert!(plan(&profile(&t, &body)).is_err(), "{read}");
        }
    }

    // rivet: verifies REQ-ZW-008
    #[cfg(unix)]
    #[test]
    fn deny_read_under_a_symlinked_grant_refuses() {
        let t = tree();
        std::os::unix::fs::symlink(t.0.join("home"), t.0.join("h")).unwrap();
        let body = "read: [\"@/h\"]\ndeny_read: [\"@/home/.ssh\"]\n";
        assert!(plan(&profile(&t, body)).is_err());
        let body = "read: [\"@/home\"]\ndeny_read: [\"@/h/.ssh\"]\n";
        assert!(plan(&profile(&t, body)).is_err());
    }

    // rivet: verifies REQ-ZW-008
    #[cfg(unix)]
    #[test]
    fn write_through_a_symlink_into_a_denied_tree_refuses() {
        let t = tree();
        std::os::unix::fs::symlink(t.0.join("home/.ssh"), t.0.join("usr/keys")).unwrap();
        let body = "write: [\"@/usr/keys\"]\ndeny_read: [\"@/home/.ssh\"]\n";
        assert!(plan(&profile(&t, body)).is_err());
        let body = "write: [\"@/usr/keys\"]\ndeny_write: [\"@/home/.ssh\"]\n";
        assert!(plan(&profile(&t, body)).is_err());
    }

    #[test]
    fn carve_refusals_name_the_paths() {
        let g = |field, s: &str, r: &str| Grant {
            field,
            stated: s.into(),
            resolved: r.into(),
        };
        let d = |s: &str, r: &str| Denied {
            stated: s.into(),
            resolved: r.into(),
        };
        let e = check_carve_outs(
            &[g("read", "/h", "/h")],
            &[],
            &[d("/h/.ssh", "/h/.ssh")],
            &[],
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            "deny_read: /h/.ssh lies inside read /h (resolved: /h/.ssh in /h); Landlock cannot \
             carve a denied path out of a granted tree; refusing"
        );
        let e = check_carve_outs(&[], &[g("write", "/r", "/r")], &[], &[d("/r/.c", "/r/.c")])
            .unwrap_err();
        assert_eq!(
            e.to_string(),
            "deny_write: /r/.c lies inside write /r; Landlock cannot carve a read-only path out \
             of a writable tree; refusing"
        );
        let e = check_carve_outs(
            &[g("read", "/u/k", "/h/.ssh/k")],
            &[],
            &[d("/h/.ssh", "/h/.ssh")],
            &[],
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            "read: /u/k resolves to /h/.ssh/k, inside deny_read /h/.ssh; refusing"
        );
        assert_eq!(check_carve_outs(&[], &[], &[], &[]), Ok(()));
        // With a read grant listed first, a violation by the write grant names the write grant.
        let e = check_carve_outs(
            &[g("read", "/u", "/u")],
            &[g("write", "/h", "/h")],
            &[d("/h/.ssh", "/h/.ssh")],
            &[],
        )
        .unwrap_err();
        assert!(e.to_string().contains("lies inside write /h "), "{e}");
    }

    // rivet: verifies REQ-ZW-008
    #[test]
    fn deny_write_inside_write_refuses() {
        let t = tree();
        let body = "write: [\"@/home/repo\"]\ndeny_write: [\"@/home/repo/.claude\"]\n";
        assert!(plan(&profile(&t, body)).is_err());
    }

    #[test]
    fn deny_write_inside_read_only_tree_is_enforced_by_omission() {
        let t = tree();
        let body = "read: [\"@/home/repo\"]\ndeny_write: [\"@/home/repo/.claude\"]\n";
        assert!(plan(&profile(&t, body)).is_ok());
    }

    // rivet: verifies REQ-ZW-009
    #[test]
    fn missing_if_present_grants_are_skipped_not_refused() {
        let t = tree();
        let body = "read_if_present: [\"@/nope\", \"@/usr\"]\nwrite_if_present: [\"@/gone\"]\n";
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
        let body = "write_if_present: [\"@/home\"]\ndeny_read: [\"@/home/.ssh\"]\n";
        assert!(plan(&profile(&t, body)).is_err());
        let body = "write_if_present: [\"@/home/repo\"]\ndeny_write: [\"@/home/repo/.claude\"]\n";
        assert!(plan(&profile(&t, body)).is_err());
        let body = "read_if_present: [\"@/home/.ssh/k.pub\"]\ndeny_read: [\"@/home/.ssh\"]\n";
        assert!(plan(&profile(&t, body)).is_ok(), "a stated read exception");
    }

    // rivet: verifies REQ-ZW-010
    #[test]
    fn explain_names_the_deciding_grant() {
        let t = tree();
        let pr = profile(&t, "read: [\"@/home\"]\nwrite: [\"@/home/repo\"]\n");
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
        assert_eq!(o.len(), 4);
        assert_eq!(o[3], "execute: denied (no read or write grant covers it)");
    }

    #[test]
    fn explain_picks_the_most_specific_read_grant() {
        let t = tree();
        let pr = profile(&t, "read: [\"@/home\", \"@/home/repo\"]\n");
        let pl = plan(&pr).unwrap();
        let x = explain(&pr, &pl, t.0.join("home/repo/a").to_str().unwrap());
        assert_eq!(
            x[1],
            format!("read: allowed (read {})", t.0.join("home/repo").display())
        );
        let pr = profile(&t, "read: [\"@/home/repo\", \"@/home\"]\n");
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
        let open = profile(&t, "network:\n  mode: \"unfiltered\"\n");
        let pl = plan(&open).unwrap();
        assert!(explain(&open, &pl, "tcp:443")[0].starts_with("tcp port 443: allowed"));
        // Only tcp: and udp: are ports; anything else is a path.
        assert!(explain(&open, &pl, "http:x")[0].starts_with("path http:x"));
    }

    // rivet: verifies REQ-ZW-011
    #[test]
    fn runner_template_refuses_until_substituted_then_plans() {
        let template = include_str!("../profiles/github-runner.yaml");
        assert!(matches!(
            Profile::parse(Path::new("github-runner.yaml"), template),
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
        let p = Profile::parse(Path::new("runner.yaml"), &text).unwrap();
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

    // rivet: verifies REQ-ZW-013
    #[test]
    fn noexec_drops_execute_at_and_beneath_the_tree_only() {
        let t = tree();
        let pr = profile(
            &t,
            "read: [\"@/usr\"]\nwrite: [\"@/home\", \"@/home/repo\"]\nnoexec: [\"@/home\"]\n",
        );
        let pl = plan(&pr).unwrap();
        let trees: Vec<&Path> = pl.noexec.iter().map(PathBuf::as_path).collect();
        assert!(may_exec(&pl.read[0].resolved, &trees), "/usr keeps execute");
        assert!(!may_exec(&pl.write[0].resolved, &trees), "the tree itself");
        assert!(
            !may_exec(&pl.write[1].resolved, &trees),
            "a grant beneath it"
        );
        let e = explain(&pr, &pl, &format!("{}/home/repo/x", t.0.display()));
        assert!(e[3].starts_with("execute: denied (noexec "), "{e:?}");
        let e = explain(&pr, &pl, &format!("{}/usr/bin/x", t.0.display()));
        assert!(e[3].starts_with("execute: allowed (read "), "{e:?}");
        let e = explain(&pr, &pl, &format!("{}/elsewhere", t.0.display()));
        assert_eq!(
            e.last().unwrap(),
            "execute: denied (no read or write grant covers it)"
        );
    }

    // rivet: verifies REQ-ZW-013
    #[test]
    fn noexec_inside_a_wider_grant_is_refused_and_names_both() {
        let t = tree();
        let e = plan(&profile(
            &t,
            "read: [\"@/usr\"]\nwrite: [\"@/home\"]\nnoexec: [\"@/home/repo\"]\n",
        ))
        .unwrap_err();
        let root = t.0.display();
        assert_eq!(
            e,
            format!(
                "noexec: {root}/home/repo lies inside write {root}/home, which allows \
                 execution; Landlock cannot take that right away beneath a grant; refusing"
            )
        );
        // Under a read grant too, and the index names the right grant when there are several.
        let e = plan(&profile(
            &t,
            "read: [\"@/home/.ssh\", \"@/usr\"]\nnoexec: [\"@/usr/bin\"]\n",
        ))
        .unwrap_err();
        assert!(e.contains(&format!("lies inside read {root}/usr,")), "{e}");
        // A noexec tree no grant reaches changes nothing and is accepted.
        assert!(plan(&profile(&t, "read: [\"@/usr\"]\nnoexec: [\"@/home\"]\n")).is_ok());
    }

    #[test]
    fn first_noexec_violation_reports_indices() {
        let g = [Path::new("/a"), Path::new("/b")];
        assert_eq!(first_noexec_violation(&g, &[Path::new("/a")]), None);
        assert_eq!(
            first_noexec_violation(&g, &[Path::new("/c"), Path::new("/b/x")]),
            Some(NoexecViolation {
                noexec: 1,
                grant: 1
            })
        );
        assert_eq!(first_noexec_violation(&g, &[Path::new("/")]), None);
    }

    // rivet: verifies REQ-ZW-005
    #[test]
    fn host_allow_list_refuses_on_linux() {
        let t = tree();
        assert!(plan(&profile(&t, "network:\n  allow: [\"github.com\"]\n")).is_err());
    }

    // rivet: verifies REQ-ZW-005
    #[test]
    fn local_binding_refuses_on_linux() {
        let t = tree();
        assert!(plan(&profile(&t, "network:\n  allow_local_binding: true\n")).is_err());
    }

    #[test]
    fn resolve_keeps_the_missing_tail() {
        let t = tree();
        let r = resolve(&t.0.join("home/a/b"));
        assert_eq!(r, t.0.canonicalize().unwrap().join("home/a/b"));
        assert_eq!(resolve(Path::new("/")), PathBuf::from("/"));
    }

    // ---- seccomp_program: run it in a classic-BPF interpreter ----

    use super::bpf_run as run;

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 10;
    const AF_NETLINK: u32 = 16;
    const AF_PACKET: u32 = 17;

    fn every_case(arch: Arch) {
        for (unix, inet) in [(false, false), (true, false), (false, true), (true, true)] {
            let program = seccomp_program(arch, unix, inet);
            let prog = program.as_slice();
            let r = |nr, a0| run(prog, arch.audit_arch, nr, a0, 0);
            let inet_expect = if inet { RET_ALLOW } else { RET_ERRNO | EACCES };
            // The program agrees with the independent spec on a grid of interesting inputs (the Kani
            // proof extends this to every input).
            let audits = [arch.audit_arch, arch.audit_arch ^ 1, 0x4000_0003];
            let nrs = [
                0,
                arch.socket,
                arch.ioctl,
                424,
                425,
                426,
                427,
                428,
                0x3fff_ffff,
                0x4000_0000,
            ];
            let vals = [0, AF_UNIX, AF_INET, TIOCSTI, TIOCLINUX, u32::MAX];
            for (&a, &nr) in audits.iter().flat_map(|a| nrs.iter().map(move |n| (a, n))) {
                for (&a0, &a1) in vals.iter().flat_map(|x| vals.iter().map(move |y| (x, y))) {
                    assert_eq!(
                        run(prog, a, nr, a0, a1),
                        seccomp_spec(arch, unix, inet, a, nr, a0, a1),
                        "audit {a:#x} nr {nr} a0 {a0} a1 {a1:#x}"
                    );
                }
            }
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
            let io = |fd, req| run(prog, arch.audit_arch, arch.ioctl, fd, req);
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
                run(prog, 0x4000_0003, 0, 0, 0),
                RET_KILL_PROCESS,
                "i386 on x86_64"
            );
            assert_eq!(
                run(prog, arch.audit_arch ^ 1, arch.socket, AF_UNIX, 0),
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

/// Kani proofs (`cargo kani`). They run over the shipped `seccomp_program` and `enforcement`,
/// not over a copy. Inputs are symbolic over their full range, so the only bound is loop
/// unwinding, and that is checked: `#[kani::unwind]` exceeds the longest program, and Kani
/// fails if a loop would need more.
///
/// Trusted base, named so it is not mistaken for coverage: `bpf_run` is this repository's model
/// of classic-BPF semantics, and Kani/CBMC itself. The kernel's interpreter is the external
/// check: tests/linux.rs runs the same program in real kernels.
#[cfg(kani)]
mod proofs {
    use super::*;

    // Unwind bound 30: the longest program (x86_64, AF_UNIX allowed, network refused) is 20
    // instructions and the builder walks at most 26 ops. Kani fails if a loop needs more.

    /// Structure (every instruction in the emitted subset, every jump inside the program, a `ret`
    /// last), then the spec for every (audit_arch, nr, arg0, arg1). One harness per architecture
    /// and socket mode, so each program is concrete and only the syscall is symbolic.
    fn meets_spec(arch: Arch, unix: bool, inet: bool) {
        let program = seccomp_program(arch, unix, inet);
        let prog = program.as_slice();
        assert!(!prog.is_empty() && prog.len() <= MAX_PROGRAM);
        assert_eq!(prog[prog.len() - 1].code, BPF_RET_K, "ends in a return");
        for (i, insn) in prog.iter().enumerate() {
            match insn.code {
                BPF_LD_W_ABS => {
                    assert!(matches!(insn.k, OFF_NR | OFF_ARCH | OFF_ARG0 | OFF_ARG1));
                }
                BPF_JEQ_K | BPF_JGE_K => {
                    assert!(i + 1 + usize::from(insn.jt) < prog.len());
                    assert!(i + 1 + usize::from(insn.jf) < prog.len());
                }
                BPF_RET_K => {}
                _ => panic!("instruction outside the emitted subset"),
            }
        }
        let (audit, nr, a0, a1): (u32, u32, u32, u32) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        let got = bpf_run(prog, audit, nr, a0, a1);
        assert_eq!(got, seccomp_spec(arch, unix, inet, audit, nr, a0, a1));
        // Non-vacuity: the verdicts this mode can produce are each reached.
        kani::cover!(got == RET_ALLOW, "allow");
        kani::cover!(got == RET_ERRNO | EPERM, "eperm");
        kani::cover!(got == RET_KILL_PROCESS, "kill");
        if !(unix && inet) {
            kani::cover!(got == RET_ERRNO | EACCES, "eacces");
        }
    }

    macro_rules! meets_spec_harness {
        ($name:ident, $arch:expr, $unix:expr, $inet:expr) => {
            #[kani::proof]
            #[kani::unwind(30)]
            fn $name() {
                meets_spec($arch, $unix, $inet);
            }
        };
    }

    meets_spec_harness!(seccomp_x86_64_no_unix_no_inet, X86_64, false, false);
    meets_spec_harness!(seccomp_x86_64_unix_no_inet, X86_64, true, false);
    meets_spec_harness!(seccomp_x86_64_no_unix_inet, X86_64, false, true);
    meets_spec_harness!(seccomp_x86_64_unix_inet, X86_64, true, true);
    meets_spec_harness!(seccomp_aarch64_no_unix_no_inet, AARCH64, false, false);
    meets_spec_harness!(seccomp_aarch64_unix_no_inet, AARCH64, true, false);
    meets_spec_harness!(seccomp_aarch64_no_unix_inet, AARCH64, false, true);
    meets_spec_harness!(seccomp_aarch64_unix_inet, AARCH64, true, true);

    /// Vacuity controls: the same check must reject a program with one planted bug. Each takes the
    /// real x86_64 program (no AF_UNIX, no network: every verdict occurs), breaks one thing, and
    /// asserts the spec; Kani must find the counterexample (`should_panic`). If the spec or the
    /// interpreter stopped looking, a control would pass and the proof job would fail.
    fn planted(mutate: fn(&mut [Insn])) {
        planted_in(false, false, mutate)
    }

    fn planted_in(unix: bool, inet: bool, mutate: fn(&mut [Insn])) {
        let mut program = seccomp_program(X86_64, unix, inet);
        mutate(program.as_mut_slice());
        let prog = program.as_slice();
        let (audit, nr, a0, a1): (u32, u32, u32, u32) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        assert_eq!(
            bpf_run(prog, audit, nr, a0, a1),
            seccomp_spec(X86_64, unix, inet, audit, nr, a0, a1)
        );
    }

    fn set_jeq(prog: &mut [Insn], code: u16, from: u32, to: u32) {
        for i in prog.iter_mut().filter(|i| i.code == code && i.k == from) {
            i.k = to;
        }
    }

    fn set_ret(prog: &mut [Insn], from: u32, to: u32) {
        for i in prog
            .iter_mut()
            .filter(|i| i.code == BPF_RET_K && i.k == from)
        {
            i.k = to;
        }
    }

    #[kani::proof]
    #[kani::unwind(30)]
    #[kani::should_panic]
    fn planted_tiocsti_not_checked() {
        planted(|p| {
            for i in p
                .iter_mut()
                .filter(|i| i.code == BPF_JEQ_K && i.k == TIOCSTI)
            {
                i.k = 0xffff_0000;
            }
        });
    }

    #[kani::proof]
    #[kani::unwind(30)]
    #[kani::should_panic]
    fn planted_eperm_becomes_allow() {
        planted(|p| set_ret(p, RET_ERRNO | EPERM, RET_ALLOW));
    }

    #[kani::proof]
    #[kani::unwind(30)]
    #[kani::should_panic]
    fn planted_eacces_becomes_allow() {
        planted(|p| set_ret(p, RET_ERRNO | EACCES, RET_ALLOW));
    }

    #[kani::proof]
    #[kani::unwind(30)]
    #[kani::should_panic]
    fn planted_arch_check_skipped() {
        planted(|p| p[1].jf = p[1].jt);
    }

    #[kani::proof]
    #[kani::unwind(30)]
    #[kani::should_panic]
    fn planted_tioclinux_not_checked() {
        planted(|p| set_jeq(p, BPF_JEQ_K, TIOCLINUX, 0xffff_0000));
    }

    #[kani::proof]
    #[kani::unwind(30)]
    #[kani::should_panic]
    fn planted_x32_not_refused() {
        planted(|p| set_jeq(p, BPF_JGE_K, 0x4000_0000, u32::MAX));
    }

    #[kani::proof]
    #[kani::unwind(30)]
    #[kani::should_panic]
    fn planted_io_uring_register_not_refused() {
        planted(|p| set_jeq(p, BPF_JEQ_K, 427, 0xffff_ffff));
    }

    #[kani::proof]
    #[kani::unwind(30)]
    #[kani::should_panic]
    fn planted_af_unix_check_tests_af_inet() {
        // The mode where only AF_UNIX is allowed: the family test is the whole decision.
        planted_in(true, false, |p| set_jeq(p, BPF_JEQ_K, AF_UNIX, 2));
    }

    /// REQ-ZW-005, REQ-ZW-006, REQ-ZW-009 end to end, from the profile and the kernel ABI to the
    /// filter's verdict on socket(2), stated from the requirement text rather than from the
    /// booleans `enforcement` hands the builder: AF_UNIX is allowed iff the profile says
    /// unix_sockets = "unfiltered" or Landlock confines it (ABI 9); any other family iff the
    /// profile says mode = "unfiltered".
    fn socket_verdict_follows_the_profile(arch: Arch) {
        let abi: i32 = kani::any();
        kani::assume(abi >= MIN_ABI);
        let network = Network {
            mode: if kani::any() {
                NetworkMode::Unfiltered
            } else {
                NetworkMode::None
            },
            unix_sockets: if kani::any() {
                UnixSockets::Unfiltered
            } else {
                UnixSockets::Confined
            },
            allow: Vec::new(),
            allow_local_binding: false,
        };
        let e = enforcement(abi, &network).expect("abi >= MIN_ABI is accepted");
        let program = seccomp_program(arch, e.unix_sockets, e.inet_sockets);
        let family: u32 = kani::any();
        let got = bpf_run(
            program.as_slice(),
            arch.audit_arch,
            arch.socket,
            family,
            kani::any(),
        );
        let allowed = if family == AF_UNIX {
            network.unix_sockets == UnixSockets::Unfiltered || abi >= UNIX_SOCKET_ABI
        } else {
            network.mode == NetworkMode::Unfiltered
        };
        assert_eq!(
            got,
            if allowed {
                RET_ALLOW
            } else {
                RET_ERRNO | EACCES
            }
        );
        kani::cover!(family == AF_UNIX && allowed && network.unix_sockets == UnixSockets::Confined);
        kani::cover!(family == AF_UNIX && !allowed);
        kani::cover!(family != AF_UNIX && allowed);
        kani::cover!(family != AF_UNIX && !allowed);
    }

    #[kani::proof]
    #[kani::unwind(30)]
    fn socket_verdict_follows_the_profile_x86_64() {
        socket_verdict_follows_the_profile(X86_64);
    }

    #[kani::proof]
    #[kani::unwind(30)]
    fn socket_verdict_follows_the_profile_aarch64() {
        socket_verdict_follows_the_profile(AARCH64);
    }

    /// A short absolute path in normal form over {'/', 'a', 'b'}: "/", "/a", "/ab", "/a/b", ...
    /// (no repeated or trailing separator, as `normalize` and `canonicalize` produce). Enough for
    /// equal paths, nesting, and siblings sharing a byte prefix ("/a" vs "/ab", which must not
    /// count as nested). Kept on the stack: no allocation for CBMC to model.
    fn any_normal_path() -> ([u8; 4], usize) {
        let len: usize = kani::any();
        kani::assume((1..=4).contains(&len));
        let mut bytes = [b'/'; 4];
        for b in bytes.iter_mut().skip(1) {
            let c: u8 = kani::any();
            kani::assume(c == b'/' || c == b'a' || c == b'b');
            *b = c;
        }
        for i in 1..len {
            kani::assume(!(bytes[i] == b'/' && bytes[i - 1] == b'/'));
        }
        kani::assume(len == 1 || bytes[len - 1] != b'/');
        (bytes, len)
    }

    fn as_path(p: &([u8; 4], usize)) -> &Path {
        use std::os::unix::ffi::OsStrExt;
        Path::new(std::ffi::OsStr::from_bytes(&p.0[..p.1]))
    }

    /// Lemma: two ancestors of the same path are nested one in the other. This is what lets
    /// the carve-out rules, which only compare grants with denied paths, speak for every path
    /// beneath them.
    #[kani::proof]
    #[kani::unwind(6)]
    fn ancestors_of_a_path_are_nested() {
        let (x, a, b) = (any_normal_path(), any_normal_path(), any_normal_path());
        let (x, a, b) = (as_path(&x), as_path(&a), as_path(&b));
        if within(x, a) && within(x, b) {
            assert!(within(a, b) || within(b, a));
        }
        kani::cover!(within(x, a) && within(x, b) && a != b);
    }

    /// REQ-ZW-008, end to end: if the carve-out rules accept the profile, then for every path x
    /// beneath a denied path, no write grant covers x, and a read grant covers x only as a read
    /// exception the profile stated inside that deny_read. Landlock, which only grants, then
    /// denies x. Stated and resolved paths vary independently (symlink aliasing).
    #[kani::proof]
    #[kani::unwind(6)]
    fn accepted_profiles_leave_every_denied_path_denied() {
        let raw: [([u8; 4], usize); 9] = [
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
        ];
        let view = |field, i: usize| PathView {
            field,
            stated: as_path(&raw[i]),
            resolved: as_path(&raw[i + 1]),
        };
        let (r, w) = (view("read", 0), view("write", 2));
        let (dr, dw) = (view("deny_read", 4), view("deny_write", 6));
        let x = as_path(&raw[8]);
        let accepted = first_carve_violation(&[r], &[w], &[dr], &[dw]).is_none();
        if accepted && within(x, dr.resolved) {
            assert!(
                !within(x, w.resolved),
                "a write grant covers a deny_read path"
            );
            assert!(
                !within(x, r.resolved)
                    || (within(r.stated, dr.stated) && !within(dr.stated, r.stated)),
                "a read grant covers a deny_read path without a stated exception"
            );
        }
        if accepted && within(x, dw.resolved) {
            assert!(
                !within(x, w.resolved),
                "a write grant covers a deny_write path"
            );
        }
        kani::cover!(
            accepted && within(x, dr.resolved),
            "a denied path under an accepted profile"
        );
        kani::cover!(
            accepted && within(x, dr.resolved) && within(x, r.resolved),
            "the stated read exception"
        );
        kani::cover!(!accepted, "refused");
    }

    /// Vacuity control: a checker without the deny_write rules must be caught.
    #[kani::proof]
    #[kani::unwind(6)]
    #[kani::should_panic]
    fn planted_deny_write_rules_dropped() {
        let (a, b, c, d, e) = (
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
        );
        let w = PathView {
            field: "write",
            stated: as_path(&a),
            resolved: as_path(&b),
        };
        let dw = PathView {
            field: "deny_write",
            stated: as_path(&c),
            resolved: as_path(&d),
        };
        let x = as_path(&e);
        // The real rules with the deny_write list withheld: a checker that forgot them.
        if first_carve_violation(&[], &[w], &[], &[]).is_none() && within(x, dw.resolved) {
            assert!(!within(x, w.resolved));
        }
    }

    /// Vacuity control: a checker that accepts any read inside a deny_read (the "stated" test
    /// skipped, by naming the grant so the real rule treats it as a write would be stricter;
    /// the lax rule is spelled out instead) must be caught.
    #[kani::proof]
    #[kani::unwind(6)]
    #[kani::should_panic]
    fn planted_read_exception_unconditional() {
        let (a, b, c, d, e) = (
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
        );
        let r = PathView {
            field: "read",
            stated: as_path(&a),
            resolved: as_path(&b),
        };
        let dr = PathView {
            field: "deny_read",
            stated: as_path(&c),
            resolved: as_path(&d),
        };
        let x = as_path(&e);
        let lax_accepts = !within(dr.resolved, r.resolved);
        if lax_accepts && within(x, dr.resolved) {
            assert!(
                !within(x, r.resolved)
                    || (within(r.stated, dr.stated) && !within(dr.stated, r.stated))
            );
        }
    }

    /// Vacuity control: dropping the "deny under a grant" rule must be caught.
    #[kani::proof]
    #[kani::unwind(6)]
    #[kani::should_panic]
    fn planted_deny_under_grant_unchecked() {
        let (a, b, c, d, e) = (
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
        );
        let w = PathView {
            field: "write",
            stated: as_path(&a),
            resolved: as_path(&b),
        };
        let dr = PathView {
            field: "deny_read",
            stated: as_path(&c),
            resolved: as_path(&d),
        };
        let x = as_path(&e);
        let lax_accepts = !within(w.resolved, dr.resolved);
        if lax_accepts && within(x, dr.resolved) {
            assert!(!within(x, w.resolved));
        }
    }

    /// DD-ZW-003, REQ-ZW-005/006/009: for every kernel ABI and every network mode, a channel the
    /// backend leaves open is either confined by Landlock at that ABI or explicitly opted into by
    /// the profile; nothing is enforced that the ABI does not have; and ABIs below the minimum
    /// are refused.
    #[kani::proof]
    #[kani::unwind(4)]
    fn enforcement_never_opens_an_unstated_channel() {
        let abi: i32 = kani::any();
        let network = Network {
            mode: if kani::any() {
                NetworkMode::Unfiltered
            } else {
                NetworkMode::None
            },
            unix_sockets: if kani::any() {
                UnixSockets::Unfiltered
            } else {
                UnixSockets::Confined
            },
            allow: Vec::new(),
            allow_local_binding: false,
        };
        match enforcement(abi, &network) {
            Err(_) => {
                assert!(abi < MIN_ABI);
            }
            Ok(e) => {
                assert!(abi >= MIN_ABI);
                assert!(e.abi >= MIN_ABI && e.abi <= MAX_KNOWN_ABI && e.abi <= abi);
                // Network sockets only when the profile says unfiltered.
                assert_eq!(e.inet_sockets, network.mode == NetworkMode::Unfiltered);
                // AF_UNIX only when Landlock confines it, or the profile says unfiltered.
                assert!(
                    !e.unix_sockets
                        || (e.resolve_unix && e.scope_abstract_unix)
                        || network.unix_sockets == UnixSockets::Unfiltered
                );
                // Landlock is never asked for a right its ABI lacks.
                assert!(!e.tcp || e.abi >= 4);
                assert!(!e.udp || e.abi >= 10);
                assert!(!e.ioctl_dev || e.abi >= 5);
                assert!(!(e.scope_signals || e.scope_abstract_unix) || e.abi >= 6);
                assert!(!e.audit_log || e.abi >= 7);
                assert!(!e.resolve_unix || e.abi >= UNIX_SOCKET_ABI);
                // ...and is asked for every right it has that the profile did not opt out of.
                assert_eq!(e.tcp, network.mode == NetworkMode::None && e.abi >= 4);
                assert_eq!(e.scope_signals, e.abi >= 6);
                kani::cover!(e.unix_sockets && network.unix_sockets == UnixSockets::Confined);
                kani::cover!(!e.unix_sockets);
            }
        }
    }

    /// REQ-ZW-013: if the noexec rule accepts the profile, then for every path x beneath a
    /// noexec tree, every grant that covers x has lost the execute right. Landlock allows execve
    /// only through a rule on an ancestor of x that carries it, so execve beneath the tree fails.
    #[kani::proof]
    #[kani::unwind(6)]
    fn accepted_profiles_execute_nothing_under_noexec() {
        let (a, b, n, x) = (
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
            any_normal_path(),
        );
        let grants = [as_path(&a), as_path(&b)];
        let noexec = [as_path(&n)];
        let x = as_path(&x);
        let accepted = first_noexec_violation(&grants, &noexec).is_none();
        if accepted && within(x, noexec[0]) {
            for g in grants {
                if within(x, g) {
                    assert!(!may_exec(g, &noexec), "a grant keeps execute under noexec");
                }
            }
        }
        kani::cover!(
            accepted && within(x, noexec[0]) && within(x, grants[0]),
            "a granted path under an accepted noexec tree"
        );
        kani::cover!(!accepted, "refused");
    }

    /// Vacuity control: accepting every profile (the inside-grant rule dropped) must be caught,
    /// because a wider grant then keeps execute beneath the noexec tree.
    #[kani::proof]
    #[kani::unwind(6)]
    #[kani::should_panic]
    fn planted_noexec_inside_grant_unchecked() {
        let (a, n, x) = (any_normal_path(), any_normal_path(), any_normal_path());
        let grants = [as_path(&a)];
        let noexec = [as_path(&n)];
        let x = as_path(&x);
        if within(x, noexec[0]) && within(x, grants[0]) {
            assert!(!may_exec(grants[0], &noexec));
        }
    }
}
