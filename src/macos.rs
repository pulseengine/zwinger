//! macOS backend, prototype: Seatbelt (`sandbox_init` with an SBPL policy), REQ-ZW-003.
//!
//! The target is an Endpoint Security descendants client (`bridge/`, DD-ZW-002); Seatbelt is the
//! stepping stone (DD-ZW-007). `sandbox_init` is deprecated and Apple calls SBPL "not API", but
//! it needs no entitlement and every process zwinger execs inherits the policy.
//!
//! The planning half (`plan`, `policy`, `summary`) is plain Rust and compiles on every platform,
//! so it is unit- and mutation-tested on Linux CI too. Only `confine`, which calls
//! `sandbox_init`, is macOS-only. An Endpoint Security client can reuse `plan` as it is.
//!
//! How the profile maps, and what fails closed:
//! - The policy starts from `(deny default)` plus `BASE`, the minimum a process needs to start
//!   (each entry says why).
//! - `read` trees get `file-read*`, `process-exec` and `file-map-executable` (read trees are
//!   executable, as on Linux); `write` trees get those plus `file-write*`.
//! - Seatbelt applies the last matching rule, so unlike Landlock it can take a subtree back out
//!   of a read-only grant: `deny_read` and `deny_write` are emitted after the grants. Inside a
//!   write grant a carve-out is refused, as on Linux: Seatbelt matches paths, and the session
//!   could rename a directory above the carve-out or hard-link a file out of it. A `read` the profile
//!   states inside a `deny_read` (one public key in a secrets directory) is re-allowed after the
//!   denials. A grant that *resolves* into a denied tree without being stated there is refused.
//! - A `noexec` tree denies `process-exec` and `file-map-executable` after every grant and
//!   exception, so it is enforced inside a wider read-only grant (Linux refuses that profile).
//! - Seatbelt matches resolved paths, so every grant and denial is written as resolved
//!   (`canonicalize`, or the longest existing prefix for a denied path that does not exist yet).
//! - Seatbelt filters sockets by address and port, not host name: a non-empty `network.allow`
//!   or `allow_local_binding` is refused, as on Linux.
//! - `network.mode = none`: only `AF_UNIX` sockets, which connect and bind only inside write
//!   trees (`unix_sockets = confined`) or anywhere (`unfiltered`). `network.mode = unfiltered`
//!   opens IP sockets only; `unix_sockets` alone decides UNIX sockets in either mode.
//! - Denials are plain `subpath` rules. On a case-insensitive volume Seatbelt holds them for any
//!   spelling of the path, including a denied path that does not exist yet (measured end to end
//!   in tests/macos.rs), so no case-folding is needed here.
//! - A path or Mach name containing `"`, `\` or a control character is refused rather than
//!   escaped: SBPL is not API, so its string syntax is not something to rely on.
//! - Inherited file descriptors above 2 are marked close-on-exec before the policy is applied,
//!   because Seatbelt does not revoke descriptors opened before it.
//! - `ioctl(TIOCSTI)` is denied, so the session cannot push input into the caller's terminal.

use crate::linux::{Denied, Grant};
use crate::profile::{NetworkMode, Profile, UnixSockets, normalize, within};

use std::path::{Path, PathBuf};

/// The resolved grants and denials the policy is written from, and the optional grants that
/// were absent.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub read: Vec<Grant>,
    pub write: Vec<Grant>,
    pub skipped: Vec<PathBuf>,
    pub deny_read: Vec<Denied>,
    pub deny_write: Vec<Denied>,
    /// Trees nothing may be executed or mapped executable from, resolved like the denials.
    pub noexec: Vec<Denied>,
}

/// What every confined process gets, whatever the profile says. Each entry is the minimum for
/// a process to start and use libSystem; the profile grants everything else.
pub const BASE: &str = r#";; ---- base: what a process needs to start ----
;; Children inherit the policy, so forking cannot escape it; shells and build tools fork.
(allow process-fork)
;; Signals and process info only within the confined tree (the caller is outside it).
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
;; libSystem, the Rust and Go runtimes and most tools read sysctls (hw.ncpu, kern.osversion).
;; Reading is not confined; writing is.
(allow sysctl-read)
;; dyld: system libraries and frameworks, the shared cache (in the OS cryptex on macOS 13 and
;; later, under /System/Library/dyld before), read and mapped executable.
(allow file-read* file-map-executable
  (subpath "/usr/lib")
  (subpath "/System/Library")
  (subpath "/System/Cryptexes/OS")
  (subpath "/System/Volumes/Preboot/Cryptexes/OS"))
;; Path resolution: dyld, realpath and getcwd stat and readlink every component of a path.
;; Metadata only (no content, no directory listing), as on Linux, where Landlock does not
;; restrict stat either. A deny_read takes it back for its tree.
(allow file-read-metadata file-test-existence)
;; dyld opens "/" as the root for its openat() calls and aborts the process without it
;; (Apple's dyld-support.sb allows the same). Lists the root directory, nothing beneath it.
(allow file-read* (literal "/"))
;; Local time: /etc/localtime links into the timezone database; without it time is UTC.
(allow file-read* (subpath "/private/var/db/timezone"))
;; Standard special files.
(allow file-read* file-write-data
  (literal "/dev/null")
  (literal "/dev/zero"))
(allow file-read*
  (literal "/dev/random")
  (literal "/dev/urandom"))
;; /dev/fd/N and /dev/stdin re-open descriptors the process already holds.
(allow file-read-data file-write-data (subpath "/dev/fd"))
;; The controlling terminal, and terminal ioctls (window size, raw mode) on the terminal the
;; session inherited. TIOCSTI is denied at the end of the policy.
(allow file-read* file-write-data file-ioctl (literal "/dev/tty"))
(allow file-ioctl (regex #"^/dev/ttys[0-9]+$"))
;; libnotify's shared page (time zone and other change notifications).
(allow ipc-posix-shm-read* (ipc-posix-name "apple.shm.notification_center"))
;; getpwuid/getgrgid and group membership (shells, git, ssh look up the user), notify(3).
(allow mach-lookup
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.system.opendirectoryd.membership")
  (global-name "com.apple.system.notification_center"))
"#;

/// Mach services the resolver needs, added when `network.mode = unfiltered`: getaddrinfo asks
/// mDNSResponder and reads the DNS configuration from configd.
pub const DNS_SERVICES: [&str; 3] = [
    "com.apple.dnssd.service",
    "com.apple.SystemConfiguration.DNSConfiguration",
    "com.apple.SystemConfiguration.configd",
];

/// `network.mode = unfiltered`: any socket may be created, and IP sockets may connect, accept
/// and bind anywhere. UNIX-socket connect and bind are not in these rules: `unix_sockets` alone
/// decides them, so `unfiltered` network does not unconfine them.
pub const UNFILTERED_IP: [&str; 4] = [
    "(allow system-socket)",
    "(allow network-outbound (remote ip))",
    "(allow network-inbound (local ip))",
    "(allow network-bind (local ip))",
];

const READ_OPS: &str = "file-read* file-test-existence process-exec file-map-executable";
const WRITE_OPS: &str =
    "file-read* file-test-existence file-write* process-exec file-map-executable";
/// A `deny_read` takes everything back: reading, executing, writing, and reaching or creating
/// a UNIX socket there (an agent socket in a secrets directory).
const DENY_READ_OPS: &str = "file-read* file-test-existence file-write* process-exec file-map-executable network-outbound network-bind";
/// A `deny_write` takes writing back, including creating a UNIX socket there.
const DENY_WRITE_OPS: &str = "file-write* network-bind";
/// A `noexec` tree: nothing executes from it, and no library or plugin there is mapped
/// executable.
const NOEXEC_OPS: &str = "process-exec file-map-executable";

/// Canonicalize the longest existing prefix of `p` and append the rest, so a symlink anywhere
/// above a not-yet-existing denied path is still seen (as `linux::plan` does).
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

/// Resolve granted paths: a missing `read`/`write` path refuses, a missing `*_if_present` path
/// is recorded in `skipped`.
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

/// A grant that resolves into a denied tree, unless it is a read the profile stated inside that
/// `deny_read`. A denied path inside a read-only grant is fine here: Seatbelt carves it out
/// (`carve_inside_write` refuses one inside a write grant).
fn grant_inside_deny(plan: &Plan) -> Option<String> {
    let refuse = |g: &Grant, field: &str, d: &Denied| {
        format!(
            "{}: {} resolves to {}, inside {field} {}; refusing",
            g.field,
            g.stated.display(),
            g.resolved.display(),
            d.stated.display()
        )
    };
    for d in &plan.deny_read {
        for g in plan.read.iter().chain(&plan.write) {
            let stated = g.field.starts_with("read")
                && within(&g.stated, &d.stated)
                && !within(&d.stated, &g.stated);
            if within(&g.resolved, &d.resolved) && !stated {
                return Some(refuse(g, "deny_read", d));
            }
        }
    }
    for d in &plan.deny_write {
        for g in &plan.write {
            if within(&g.resolved, &d.resolved) {
                return Some(refuse(g, "deny_write", d));
            }
        }
    }
    None
}

/// A carve-out (deny_read, deny_write, noexec) strictly inside a write grant. Seatbelt matches
/// paths, and the session can change which path a file has there: rename a directory above the
/// carve-out, or hard-link a file out of it, and the rule no longer matches. Refused, as on
/// Linux. Inside a read-only grant the session can do neither, so carve-outs stay enforceable.
fn carve_inside_write(plan: &Plan) -> Option<String> {
    for (field, denied) in [
        ("deny_read", &plan.deny_read),
        ("deny_write", &plan.deny_write),
        ("noexec", &plan.noexec),
    ] {
        for d in denied {
            for g in &plan.write {
                if within(&d.resolved, &g.resolved) && !within(&g.resolved, &d.resolved) {
                    return Some(format!(
                        "{field}: {} lies inside {} {}, which the session can write: it could \
                         rename a directory above it or hard-link a file out of it, and Seatbelt \
                         matches paths; refusing",
                        d.stated.display(),
                        g.field,
                        g.stated.display()
                    ));
                }
            }
        }
    }
    None
}

/// Resolve the profile's paths and refuse what Seatbelt cannot enforce as written.
pub fn plan(p: &Profile) -> Result<Plan, String> {
    if !p.network.allow.is_empty() {
        return Err(format!(
            "network.allow lists {} host(s); Seatbelt filters by address and port, not host \
             name, and the macOS backend has no filtering proxy; refusing rather than allowing \
             all egress (mode = \"unfiltered\" says so explicitly)",
            p.network.allow.len()
        ));
    }
    if p.network.allow_local_binding {
        return Err(
            "network.allow_local_binding: the macOS backend does not confine binds to \
             loopback yet; refusing rather than allowing all binds"
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
    let plan = Plan {
        read,
        write,
        skipped,
        deny_read: denied(&p.deny_read),
        deny_write: denied(&p.deny_write),
        noexec: denied(&p.noexec),
    };
    match grant_inside_deny(&plan).or_else(|| carve_inside_write(&plan)) {
        Some(e) => Err(e),
        None => Ok(plan),
    }
}

/// `s` as an SBPL string literal. A `"`, a `\` or a control character is refused, not escaped.
pub fn quote(field: &str, s: &str) -> Result<String, String> {
    if s.contains(['"', '\\']) || s.contains(char::is_control) {
        return Err(format!(
            "{field}: {s:?} contains '\"', '\\' or a control character, which the macOS backend \
             does not write into a Seatbelt policy; refusing"
        ));
    }
    Ok(format!("\"{s}\""))
}

fn quote_path(field: &str, p: &Path) -> Result<String, String> {
    let s = p
        .to_str()
        .ok_or_else(|| format!("{field}: {} is not valid UTF-8; refusing", p.display()))?;
    quote(field, s)
}

/// The SBPL policy for `p` as planned: `(deny default)`, the base, the grants, the network,
/// then the carve-outs (Seatbelt applies the last matching rule).
pub fn policy(p: &Profile, plan: &Plan) -> Result<String, String> {
    let mut s = String::from("(version 1)\n(deny default)\n");
    s += BASE;

    s += ";; ---- grants ----\n";
    for (grants, ops) in [(&plan.read, READ_OPS), (&plan.write, WRITE_OPS)] {
        for g in grants {
            let q = quote_path(g.field, &g.resolved)?;
            s += &format!(
                "(allow {ops} (subpath {q})) ; {} {}\n",
                g.field,
                quote_path(g.field, &g.stated)?
            );
        }
    }

    for m in &p.mach_lookup {
        s += &format!(
            "(allow mach-lookup (global-name {})) ; mach_lookup\n",
            quote("mach_lookup", m)?
        );
    }

    s += ";; ---- network ----\n";
    match p.network.mode {
        NetworkMode::None => s += "(allow system-socket (socket-domain AF_UNIX))\n",
        NetworkMode::Unfiltered => {
            // IP only: a UNIX socket's connect and bind stay governed by unix_sockets below.
            s += &UNFILTERED_IP.join("\n");
            s += "\n";
            for m in DNS_SERVICES {
                s += &format!("(allow mach-lookup (global-name {m:?})) ; resolver\n");
            }
        }
    }
    match p.network.unix_sockets {
        UnixSockets::Confined => {
            for g in &plan.write {
                let q = quote_path(g.field, &g.resolved)?;
                s += &format!(
                    "(allow network-outbound network-bind (subpath {q})) ; unix sockets\n"
                );
            }
        }
        UnixSockets::Unfiltered => {
            s += "(allow network-outbound network-bind (subpath \"/\")) ; unix_sockets = unfiltered\n";
        }
    }

    s += ";; ---- carve-outs (after the grants: the last matching rule applies) ----\n";
    for (denied, field, ops) in [
        (&plan.deny_read, "deny_read", DENY_READ_OPS),
        (&plan.deny_write, "deny_write", DENY_WRITE_OPS),
    ] {
        for d in denied {
            let q = quote_path(field, &d.resolved)?;
            s += &format!(
                "(deny {ops} (subpath {q})) ; {field} {}\n",
                quote_path(field, &d.stated)?
            );
        }
    }
    // A read stated inside a deny_read is an exception to it (one public key in a secrets
    // directory): allowed again, after the denial. `plan` refused any other grant in there.
    for g in &plan.read {
        if plan
            .deny_read
            .iter()
            .any(|d| within(&g.resolved, &d.resolved))
        {
            let q = quote_path(g.field, &g.resolved)?;
            s += &format!(
                "(allow {READ_OPS} (subpath {q})) ; exception: {} {}\n",
                g.field,
                quote_path(g.field, &g.stated)?
            );
        }
    }
    // A denial inside a read exception (deny_read /h/.ssh, read /h/.ssh/keys, deny_read
    // /h/.ssh/keys/secret) is emitted again after the exceptions: otherwise the exception, the
    // later rule, would re-open the inner denied tree.
    let exceptions: Vec<&Grant> = plan
        .read
        .iter()
        .filter(|g| {
            plan.deny_read
                .iter()
                .any(|d| within(&g.resolved, &d.resolved))
        })
        .collect();
    for (denied, field, ops) in [
        (&plan.deny_read, "deny_read", DENY_READ_OPS),
        (&plan.deny_write, "deny_write", DENY_WRITE_OPS),
    ] {
        for d in denied {
            if exceptions.iter().any(|g| within(&d.resolved, &g.resolved)) {
                let q = quote_path(field, &d.resolved)?;
                s += &format!(
                    "(deny {ops} (subpath {q})) ; {field} {}, inside a read exception\n",
                    quote_path(field, &d.stated)?
                );
            }
        }
    }
    // noexec after every grant and exception, so nothing re-allows exec there. Seatbelt can
    // take exec out of a granted tree, so unlike Landlock nothing needs refusing.
    for d in &plan.noexec {
        let q = quote_path("noexec", &d.resolved)?;
        s += &format!(
            "(deny {NOEXEC_OPS} (subpath {q})) ; noexec {}\n",
            quote_path("noexec", &d.stated)?
        );
    }
    // Last, so no grant re-allows it: pushing input into the inherited terminal would run
    // commands in the caller's unconfined shell after the session exits.
    s += "(deny file-ioctl (ioctl-command TIOCSTI))\n";
    Ok(s)
}

/// Everything `confine` decides before it changes the process: the plan and the policy.
/// `zwinger check` runs it, so `check` refuses whatever `run` would refuse.
pub fn preflight(p: &Profile) -> Result<(Plan, String), String> {
    let plan = plan(p)?;
    let policy = policy(p, &plan)?;
    Ok((plan, policy))
}

/// What the profile leaves unconfined, for the startup line.
pub fn not_enforced(p: &Profile) -> Vec<&'static str> {
    let mut gaps = Vec::new();
    if p.network.mode == NetworkMode::Unfiltered {
        gaps.push("network (mode = unfiltered)");
    }
    if p.network.unix_sockets == UnixSockets::Unfiltered {
        gaps.push("unix socket connections (unix_sockets = unfiltered)");
    }
    gaps
}

/// The single startup line written to stderr.
pub fn summary(p: &Profile, plan: &Plan) -> String {
    let network = match p.network.mode {
        NetworkMode::None => "none",
        NetworkMode::Unfiltered => "unfiltered",
    };
    let unix = match p.network.unix_sockets {
        UnixSockets::Confined => "confined to write trees",
        UnixSockets::Unfiltered => "unfiltered",
    };
    let mut s = format!(
        "zwinger: {} confined: seatbelt; {} read, {} write grants",
        p.name,
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
    s += &format!(
        "; {} deny_read, {} deny_write",
        plan.deny_read.len(),
        plan.deny_write.len()
    );
    if !plan.noexec.is_empty() {
        s += &format!(", {} noexec", plan.noexec.len());
    }
    s += &format!("; network: {network}; unix sockets: {unix}");
    let gaps = not_enforced(p);
    if !gaps.is_empty() {
        s += &format!("; not enforced: {}", gaps.join(", "));
    }
    s
}

/// Confine the calling process to `p`. On success every later `exec` runs confined.
#[cfg(target_os = "macos")]
pub fn confine(p: &Profile) -> Result<Plan, String> {
    let (plan, policy) = preflight(p)?;
    enforce::close_inherited_on_exec()?;
    enforce::apply(&policy)?;
    Ok(plan)
}

/// The macOS-only half: the calls into libSystem.
#[cfg(target_os = "macos")]
mod enforce {
    use std::ffi::{CStr, CString, c_char};

    // libsandbox, re-exported by libSystem (sandbox.h). Deprecated since macOS 10.8, still
    // shipped and used by sandbox-exec.
    unsafe extern "C" {
        fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> i32;
        fn sandbox_free_error(errorbuf: *mut c_char);
    }

    /// Apply `policy` (SBPL source: flags 0, not a named profile) to this process.
    pub fn apply(policy: &str) -> Result<(), String> {
        let src = CString::new(policy).map_err(|_| "policy contains NUL; refusing".to_string())?;
        let mut err: *mut c_char = std::ptr::null_mut();
        // SAFETY: src is a live NUL-terminated string; err is a valid out pointer, and an error
        // string sandbox_init returns is read once and freed with sandbox_free_error.
        let rc = unsafe { sandbox_init(src.as_ptr(), 0, &mut err) };
        if rc == 0 {
            return Ok(());
        }
        let why = if err.is_null() {
            std::io::Error::last_os_error().to_string()
        } else {
            // SAFETY: non-null err is a NUL-terminated string owned by libsandbox.
            let s = unsafe { CStr::from_ptr(err) }
                .to_string_lossy()
                .into_owned();
            unsafe { sandbox_free_error(err) };
            s
        };
        Err(format!("sandbox_init: {}; refusing", why.trim_end()))
    }

    /// Mark every inherited descriptor above 2 close-on-exec: Seatbelt checks opens, not
    /// descriptors the process already holds.
    pub fn close_inherited_on_exec() -> Result<(), String> {
        let fail =
            |e: std::io::Error| format!("/dev/fd: {e}; refusing to leak inherited descriptors");
        let fds: Vec<i32> = std::fs::read_dir("/dev/fd")
            .map_err(fail)?
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .filter(|fd| *fd > 2)
            .collect();
        for fd in fds {
            // SAFETY: fcntl on an integer descriptor; F_GETFD/F_SETFD take no pointers.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 {
                // The directory handle read_dir used, closed since.
                continue;
            }
            if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0 {
                return Err(fail(std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Tree(PathBuf);
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    /// A scratch tree, canonical (macOS temp dirs live behind the /var symlink).
    fn tree() -> Tree {
        static N: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "zwinger-macos-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        for d in ["home/.ssh", "home/repo/.claude", "usr"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("home/.ssh/k.pub"), "k").unwrap();
        Tree(root.canonicalize().unwrap())
    }
    fn profile(t: &Tree, body: &str) -> Profile {
        let text = format!("name: \"t\"\n{}", body.replace('@', t.0.to_str().unwrap()));
        Profile::parse(Path::new("t.yaml"), &text).unwrap()
    }
    fn at(t: &Tree, rel: &str) -> String {
        t.0.join(rel).to_str().unwrap().to_string()
    }
    fn generate(t: &Tree, body: &str) -> String {
        let p = profile(t, body);
        policy(&p, &plan(&p).unwrap()).unwrap()
    }
    /// The policy's rule lines after the base, without comments.
    fn rules(policy: &str) -> Vec<String> {
        let tail = policy.split_once(BASE).expect("base included").1;
        tail.lines()
            .filter(|l| !l.starts_with(";;"))
            .map(|l| l.split(" ; ").next().unwrap().to_string())
            .collect()
    }

    // ---- plan ----

    // rivet: verifies REQ-ZW-015
    #[test]
    fn plan_resolves_grants_and_denials() {
        let t = tree();
        std::os::unix::fs::symlink(t.0.join("home/repo"), t.0.join("link")).unwrap();
        let p = plan(&profile(
            &t,
            "read: [\"@/usr\", \"@/link\"]\ndeny_read: [\"@/link/.claude/new/x\"]\n\
             deny_write: [\"@/home/repo/.claude\"]\n",
        ))
        .unwrap();
        assert_eq!(p.read[0].resolved, t.0.join("usr"));
        assert_eq!(p.read[0].field, "read");
        assert_eq!(p.read[1].resolved, t.0.join("home/repo"));
        assert_eq!(p.read[1].stated, t.0.join("link"));
        // A denied path that does not exist yet resolves through the symlink above it.
        assert_eq!(p.deny_read[0].resolved, t.0.join("home/repo/.claude/new/x"));
        assert_eq!(p.deny_read[0].stated, t.0.join("link/.claude/new/x"));
        assert_eq!(p.deny_write[0].resolved, t.0.join("home/repo/.claude"));
        assert!(p.skipped.is_empty());
    }

    #[test]
    fn resolve_keeps_a_path_with_no_existing_prefix() {
        assert_eq!(resolve(Path::new("nowhere/a")), PathBuf::from("nowhere/a"));
    }

    // rivet: verifies REQ-ZW-015
    #[test]
    fn plan_refuses_a_missing_grant_and_skips_a_missing_optional_one() {
        let t = tree();
        for field in ["read", "write"] {
            let e = plan(&profile(&t, &format!("{field}: [\"@/absent\"]\n"))).unwrap_err();
            assert!(
                e.starts_with(&format!("{field}: {}: ", at(&t, "absent"))),
                "{e}"
            );
            assert!(e.ends_with("; refusing"), "{e}");
        }
        let p = plan(&profile(
            &t,
            "read_if_present: [\"@/absent\", \"@/usr\"]\nwrite_if_present: [\"@/gone\"]\n",
        ))
        .unwrap();
        assert_eq!(p.skipped, vec![t.0.join("absent"), t.0.join("gone")]);
        assert_eq!(p.read.len(), 1);
        assert_eq!(p.read[0].field, "read_if_present");
        assert!(p.write.is_empty());
    }

    #[test]
    fn plan_refuses_an_optional_grant_that_exists_but_cannot_be_resolved() {
        // Not NotFound: a path through a regular file (ENOTDIR) is refused, not skipped.
        let t = tree();
        let e = plan(&profile(&t, "read_if_present: [\"@/home/.ssh/k.pub/x\"]\n")).unwrap_err();
        assert!(e.starts_with("read_if_present: "), "{e}");
    }

    // rivet: verifies REQ-ZW-015
    #[test]
    fn plan_refuses_host_lists_and_loopback_binding() {
        let t = tree();
        let e = plan(&profile(
            &t,
            "network:\n  allow: [\"github.com\", \"x.org\"]\n",
        ))
        .unwrap_err();
        assert!(
            e.starts_with("network.allow lists 2 host(s); Seatbelt filters"),
            "{e}"
        );
        let e = plan(&profile(&t, "network:\n  allow_local_binding: true\n")).unwrap_err();
        assert!(e.starts_with("network.allow_local_binding: "), "{e}");
    }

    // rivet: verifies REQ-ZW-015
    #[test]
    fn carve_outs_inside_read_grants_are_enforced_and_inside_write_grants_refused() {
        // Inside a read-only grant the session cannot rename or hard-link, so Seatbelt's path
        // rules hold: accepted (Landlock would refuse).
        let t = tree();
        let ok = |body: &str| plan(&profile(&t, body)).is_ok();
        assert!(ok("read: [\"@/home\"]\ndeny_read: [\"@/home/.ssh\"]\n"));
        assert!(ok("read: [\"@/home\"]\nnoexec: [\"@/home/repo\"]\n"));
        // A noexec tree equal to a write grant: its root cannot be renamed.
        assert!(ok("write: [\"@/home/repo\"]\nnoexec: [\"@/home/repo\"]\n"));
        // Strictly inside a write grant: renaming a directory above it, or hard-linking a file
        // out of it, would leave the rule matching nothing. Refused, each kind.
        for body in [
            "write: [\"@/home\"]\ndeny_read: [\"@/home/.ssh\"]\n",
            "write: [\"@/home/repo\"]\ndeny_write: [\"@/home/repo/.claude\"]\n",
            "write: [\"@/home\"]\nnoexec: [\"@/home/repo\"]\n",
        ] {
            let e = plan(&profile(&t, body)).unwrap_err();
            assert!(e.contains("which the session can write"), "{body}: {e}");
        }
        let e = plan(&profile(
            &t,
            "write: [\"@/home/repo\"]\ndeny_write: [\"@/home/repo/.claude\"]\n",
        ))
        .unwrap_err();
        assert_eq!(
            e,
            format!(
                "deny_write: {} lies inside write {}, which the session can write: it could \
                 rename a directory above it or hard-link a file out of it, and Seatbelt \
                 matches paths; refusing",
                at(&t, "home/repo/.claude"),
                at(&t, "home/repo")
            )
        );
    }

    // rivet: verifies REQ-ZW-015
    #[test]
    fn plan_refuses_a_grant_that_resolves_into_a_denied_tree() {
        let t = tree();
        std::os::unix::fs::symlink(t.0.join("home/.ssh"), t.0.join("keys")).unwrap();
        std::os::unix::fs::symlink(t.0.join("home/repo/.claude"), t.0.join("cfg")).unwrap();
        // read through a symlink into deny_read
        let e = plan(&profile(
            &t,
            "read: [\"@/keys\"]\ndeny_read: [\"@/home/.ssh\"]\n",
        ))
        .unwrap_err();
        assert_eq!(
            e,
            format!(
                "read: {} resolves to {}, inside deny_read {}; refusing",
                at(&t, "keys"),
                at(&t, "home/.ssh"),
                at(&t, "home/.ssh")
            )
        );
        // write through a symlink into deny_read
        let e = plan(&profile(
            &t,
            "write: [\"@/keys\"]\ndeny_read: [\"@/home/.ssh\"]\n",
        ))
        .unwrap_err();
        assert!(e.starts_with("write: "), "{e}");
        // write through a symlink into deny_write
        let e = plan(&profile(
            &t,
            "write: [\"@/cfg\"]\ndeny_write: [\"@/home/repo/.claude\"]\n",
        ))
        .unwrap_err();
        assert!(e.contains("inside deny_write"), "{e}");
        // a read into a deny_write tree is fine: deny_write only takes writing back
        assert!(
            plan(&profile(
                &t,
                "read: [\"@/cfg\"]\ndeny_write: [\"@/home/repo/.claude\"]\n"
            ))
            .is_ok()
        );
    }

    // rivet: verifies REQ-ZW-015
    #[test]
    fn plan_accepts_a_read_stated_inside_a_deny_read() {
        let t = tree();
        let p = profile(
            &t,
            "read: [\"@/home/.ssh/k.pub\"]\ndeny_read: [\"@/home/.ssh\"]\n",
        );
        assert!(plan(&p).is_ok());
        // The same file reached through a symlink stated outside the denied tree is not an
        // exception the profile stated.
        std::os::unix::fs::symlink(t.0.join("home/.ssh/k.pub"), t.0.join("pub")).unwrap();
        let p = profile(&t, "read: [\"@/pub\"]\ndeny_read: [\"@/home/.ssh\"]\n");
        assert!(plan(&p).is_err());
    }

    #[test]
    fn a_read_exception_must_lie_strictly_inside_the_deny() {
        // stated read == stated deny can only arise through normalization; build it directly.
        let t = tree();
        let g = Grant {
            field: "read",
            stated: t.0.join("home/.ssh"),
            resolved: t.0.join("home/.ssh"),
        };
        let d = Denied {
            stated: t.0.join("home/.ssh"),
            resolved: t.0.join("home/.ssh"),
        };
        let mk = |field| Plan {
            read: vec![Grant { field, ..g.clone() }],
            write: vec![],
            skipped: vec![],
            deny_read: vec![d.clone()],
            deny_write: vec![],
            noexec: vec![],
        };
        assert!(grant_inside_deny(&mk("read")).is_some());
        // inside, stated inside: an exception, for read grants only
        let inner = Grant {
            field: "read_if_present",
            stated: t.0.join("home/.ssh/k.pub"),
            resolved: t.0.join("home/.ssh/k.pub"),
        };
        let mut p = mk("read");
        p.read = vec![inner.clone()];
        assert!(grant_inside_deny(&p).is_none());
        p.read = vec![];
        p.write = vec![Grant {
            field: "write",
            ..inner
        }];
        assert!(grant_inside_deny(&p).is_some());
    }

    // ---- quoting ----

    // rivet: verifies REQ-ZW-015
    #[test]
    fn quote_refuses_what_it_cannot_write_safely() {
        assert_eq!(quote("read", "/a b/c").unwrap(), "\"/a b/c\"");
        for bad in ["/a\"b", "/a\\b", "/a\nb", "/a\tb", "/a\u{7f}b"] {
            let e = quote("read", bad).unwrap_err();
            assert!(e.starts_with("read: "), "{e}");
            assert!(e.ends_with("; refusing"), "{e}");
        }
    }

    // rivet: verifies REQ-ZW-015
    #[test]
    fn policy_refuses_a_quote_in_a_resolved_path_or_mach_name() {
        let t = tree();
        std::fs::create_dir_all(t.0.join("we\"ird")).unwrap();
        std::fs::create_dir_all(t.0.join("back\\slash")).unwrap();
        for (body, field) in [
            ("read: [\"@/we\\\"ird\"]\n", "read:"),
            ("write: [\"@/back\\\\slash\"]\n", "write:"),
            ("deny_read: [\"@/we\\\"ird/x\"]\n", "deny_read:"),
            ("deny_write: [\"@/we\\\"ird/x\"]\n", "deny_write:"),
            ("noexec: [\"@/we\\\"ird/x\"]\n", "noexec:"),
            ("mach_lookup: [\"com.x\\\"y\"]\n", "mach_lookup:"),
        ] {
            let p = profile(&t, body);
            let e = policy(&p, &plan(&p).unwrap()).unwrap_err();
            assert!(e.starts_with(field), "{body}: {e}");
            assert!(preflight(&p).is_err(), "{body}");
        }
    }

    // rivet: verifies REQ-ZW-015
    #[test]
    fn policy_refuses_a_stated_path_that_would_break_out_of_a_comment() {
        // The policy names each grant as stated in a comment. A stated path with a newline
        // that resolves (through a symlink) to a clean path must not end the comment and
        // start a rule of its own.
        let t = tree();
        let evil = t.0.join("x\n(allow default)");
        std::os::unix::fs::symlink(t.0.join("usr"), &evil).unwrap();
        std::os::unix::fs::symlink(t.0.join("home/.ssh"), t.0.join("k\nk")).unwrap();
        let q = |rel: &str| at(&t, rel).replace('\n', "\\n");
        for (body, field) in [
            (
                format!("read: [\"{}\"]\n", q("x\n(allow default)")),
                "read: ",
            ),
            (
                format!("write: [\"{}\"]\n", q("x\n(allow default)")),
                "write: ",
            ),
            (
                format!("deny_read: [\"{}\"]\n", q("x\n(allow default)")),
                "deny_read: ",
            ),
            (
                format!("deny_write: [\"{}\"]\n", q("x\n(allow default)")),
                "deny_write: ",
            ),
        ] {
            let p = profile(&t, &body);
            let pl = plan(&p).unwrap();
            let e = policy(&p, &pl).unwrap_err();
            assert!(e.starts_with(field), "{body}: {e}");
        }
        // A read exception stated through such a path: refused too.
        let mut pl = plan(&profile(
            &t,
            "read: [\"@/home/.ssh/k.pub\"]\ndeny_read: [\"@/home/.ssh\"]\n",
        ))
        .unwrap();
        pl.read[0].stated = t.0.join("k\nk/k.pub");
        let e = policy(&profile(&t, ""), &pl).unwrap_err();
        assert!(e.starts_with("read: "), "{e}");
    }

    #[test]
    fn policy_refuses_a_non_utf8_path() {
        use std::os::unix::ffi::OsStrExt;
        let e =
            quote_path("write", Path::new(std::ffi::OsStr::from_bytes(b"/a\xffb"))).unwrap_err();
        assert!(e.starts_with("write: "), "{e}");
        assert!(e.contains("not valid UTF-8"), "{e}");
    }

    // ---- policy ----

    // rivet: verifies REQ-ZW-015
    #[test]
    fn policy_starts_closed_and_includes_the_base() {
        let t = tree();
        let s = generate(&t, "");
        assert!(s.starts_with("(version 1)\n(deny default)\n"), "{s}");
        assert!(s.contains(BASE));
        assert_eq!(
            rules(&s),
            vec![
                "(allow system-socket (socket-domain AF_UNIX))",
                "(deny file-ioctl (ioctl-command TIOCSTI))",
            ]
        );
    }

    // rivet: verifies REQ-ZW-015
    #[test]
    fn grants_map_to_read_and_write_rules() {
        let t = tree();
        let s = generate(
            &t,
            "read: [\"@/usr\"]\nread_if_present: [\"@/home/.ssh/k.pub\"]\nwrite: [\"@/home/repo\"]\n",
        );
        let r = rules(&s);
        let mut expect = vec![
            format!("(allow {READ_OPS} (subpath \"{}\"))", at(&t, "usr")),
            format!(
                "(allow {READ_OPS} (subpath \"{}\"))",
                at(&t, "home/.ssh/k.pub")
            ),
            format!("(allow {WRITE_OPS} (subpath \"{}\"))", at(&t, "home/repo")),
        ];
        expect.push("(allow system-socket (socket-domain AF_UNIX))".into());
        expect.push(format!(
            "(allow network-outbound network-bind (subpath \"{}\"))",
            at(&t, "home/repo")
        ));
        expect.push("(deny file-ioctl (ioctl-command TIOCSTI))".into());
        assert_eq!(r, expect, "{s}");
        // the comment names the field and the path as stated
        assert!(s.contains(&format!(
            "; read_if_present \"{}\"\n",
            at(&t, "home/.ssh/k.pub")
        )));
        assert!(READ_OPS.contains("process-exec") && READ_OPS.contains("file-map-executable"));
        assert!(!READ_OPS.contains("file-write"));
        assert!(WRITE_OPS.contains("file-write*") && WRITE_OPS.contains("process-exec"));
    }

    // rivet: verifies REQ-ZW-015
    #[test]
    fn denials_follow_the_grants_and_read_exceptions_follow_the_denials() {
        let t = tree();
        let s = generate(
            &t,
            "read: [\"@/home\", \"@/home/.ssh/k.pub\", \"@/usr\"]\nwrite: [\"@/home/repo\"]\n\
             deny_read: [\"@/home/.ssh\"]\ndeny_write: [\"@/home/usr-cache\"]\n",
        );
        let r = rules(&s);
        let pos = |needle: &str| {
            r.iter()
                .position(|l| l == needle)
                .unwrap_or_else(|| panic!("missing {needle}\n{s}"))
        };
        let home = pos(&format!(
            "(allow {READ_OPS} (subpath \"{}\"))",
            at(&t, "home")
        ));
        let repo = pos(&format!(
            "(allow {WRITE_OPS} (subpath \"{}\"))",
            at(&t, "home/repo")
        ));
        let deny_r = pos(&format!(
            "(deny {DENY_READ_OPS} (subpath \"{}\"))",
            at(&t, "home/.ssh")
        ));
        let deny_w = pos(&format!(
            "(deny {DENY_WRITE_OPS} (subpath \"{}\"))",
            at(&t, "home/usr-cache")
        ));
        let key = format!(
            "(allow {READ_OPS} (subpath \"{}\"))",
            at(&t, "home/.ssh/k.pub")
        );
        let first_key = pos(&key);
        let last_key = r.iter().rposition(|l| *l == key).unwrap();
        let tiocsti = pos("(deny file-ioctl (ioctl-command TIOCSTI))");
        assert!(home < deny_r && repo < deny_w && first_key < deny_r, "{s}");
        assert!(
            deny_r < deny_w && deny_w < last_key && last_key < tiocsti,
            "{s}"
        );
        assert_eq!(tiocsti, r.len() - 1);
        // only the exception is re-allowed after the denials: /home and /usr are not
        let exceptions: Vec<_> = r[deny_w + 1..tiocsti].to_vec();
        assert_eq!(exceptions, vec![key], "{s}");
        assert!(s.contains(&format!(
            "; exception: read \"{}\"\n",
            at(&t, "home/.ssh/k.pub")
        )));
        assert!(s.contains(&format!("; deny_read \"{}\"\n", at(&t, "home/.ssh"))));
        // a deny_read takes reading, writing, exec and sockets back; a deny_write only writes
        for op in [
            "file-read*",
            "file-write*",
            "process-exec",
            "network-outbound",
            "network-bind",
        ] {
            assert!(DENY_READ_OPS.contains(op), "{op}");
        }
        assert!(!DENY_WRITE_OPS.contains("file-read"));
    }

    // rivet: verifies REQ-ZW-015
    #[test]
    fn a_denial_inside_a_read_exception_comes_after_the_exception() {
        let t = tree();
        std::fs::create_dir_all(t.0.join("home/.ssh/keys/secret")).unwrap();
        let s = generate(
            &t,
            "read: [\"@/home/.ssh/keys\"]\n\
             deny_read: [\"@/home/.ssh\", \"@/home/.ssh/keys/secret\"]\n",
        );
        let r = rules(&s);
        let allow = format!(
            "(allow {READ_OPS} (subpath \"{}\"))",
            at(&t, "home/.ssh/keys")
        );
        let deny = format!(
            "(deny {DENY_READ_OPS} (subpath \"{}\"))",
            at(&t, "home/.ssh/keys/secret")
        );
        let last_allow = r.iter().rposition(|l| *l == allow).unwrap();
        let last_deny = r.iter().rposition(|l| *l == deny).unwrap();
        assert!(
            last_deny > last_allow,
            "the exception re-opens the inner denial\n{s}"
        );
        // Without an exception around it, a denial is not repeated.
        let s = generate(&t, "read: [\"@/usr\"]\ndeny_read: [\"@/home/.ssh\"]\n");
        assert!(!s.contains("inside a read exception"), "{s}");
    }

    #[test]
    fn denials_are_written_resolved() {
        let t = tree();
        std::os::unix::fs::symlink(t.0.join("home"), t.0.join("h")).unwrap();
        let s = generate(&t, "read: [\"@/usr\"]\ndeny_read: [\"@/h/.ssh\"]\n");
        assert!(
            rules(&s).contains(&format!(
                "(deny {DENY_READ_OPS} (subpath \"{}\"))",
                at(&t, "home/.ssh")
            )),
            "{s}"
        );
    }

    // rivet: verifies REQ-ZW-013
    #[test]
    fn noexec_takes_exec_back_after_every_grant_and_exception() {
        // Seatbelt can take exec out of a read-only grant, so a noexec inside one is enforced
        // rather than refused (Linux refuses it); one equal to a write grant is enforced too. Written resolved, last but TIOCSTI.
        let t = tree();
        std::os::unix::fs::symlink(t.0.join("home"), t.0.join("h")).unwrap();
        let p = profile(
            &t,
            "read: [\"@/home\", \"@/home/.ssh/k.pub\"]\nwrite: [\"@/home/repo\"]\n\
             deny_read: [\"@/home/.ssh\"]\nnoexec: [\"@/h/repo\", \"@/home/.ssh/k.pub\", \"@/gone\"]\n",
        );
        let pl = plan(&p).unwrap();
        assert_eq!(pl.noexec[0].resolved, t.0.join("home/repo"));
        assert_eq!(pl.noexec[0].stated, t.0.join("h/repo"));
        assert_eq!(pl.noexec[2].resolved, t.0.join("gone"));
        let s = policy(&p, &pl).unwrap();
        let r = rules(&s);
        let n = r.len();
        assert_eq!(
            r[n - 4..],
            [
                format!("(deny {NOEXEC_OPS} (subpath \"{}\"))", at(&t, "home/repo")),
                format!(
                    "(deny {NOEXEC_OPS} (subpath \"{}\"))",
                    at(&t, "home/.ssh/k.pub")
                ),
                format!("(deny {NOEXEC_OPS} (subpath \"{}\"))", at(&t, "gone")),
                "(deny file-ioctl (ioctl-command TIOCSTI))".to_string(),
            ],
            "{s}"
        );
        // after the read exception that re-allows exec for k.pub
        let exception = r
            .iter()
            .rposition(|l| {
                *l == format!(
                    "(allow {READ_OPS} (subpath \"{}\"))",
                    at(&t, "home/.ssh/k.pub")
                )
            })
            .unwrap();
        assert!(exception < n - 4, "{s}");
        assert!(s.contains(&format!("; noexec \"{}\"\n", at(&t, "h/repo"))));
        assert!(NOEXEC_OPS.contains("process-exec") && NOEXEC_OPS.contains("file-map-executable"));
        assert!(summary(&p, &pl).contains("; 1 deny_read, 0 deny_write, 3 noexec; network:"));
        // no noexec, no rule and no count
        let p = profile(&t, "read: [\"@/usr\"]\n");
        let pl = plan(&p).unwrap();
        assert!(!policy(&p, &pl).unwrap().contains("(deny process-exec"));
        assert!(summary(&p, &pl).contains("0 deny_write; network:"));
    }

    // rivet: verifies REQ-ZW-015
    #[test]
    fn mach_lookup_adds_exactly_the_named_services() {
        let t = tree();
        let s = generate(
            &t,
            "mach_lookup: [\"com.apple.server.bluetooth\", \"com.x.y\"]\n",
        );
        assert_eq!(
            rules(&s)[..2],
            [
                "(allow mach-lookup (global-name \"com.apple.server.bluetooth\"))".to_string(),
                "(allow mach-lookup (global-name \"com.x.y\"))".to_string(),
            ]
        );
        // the base set stays small and fixed
        assert_eq!(BASE.matches("(global-name ").count(), 3);
    }

    // rivet: verifies REQ-ZW-015
    #[test]
    fn network_none_allows_only_unix_sockets_in_write_trees() {
        let t = tree();
        let s = generate(&t, "write: [\"@/home/repo\", \"@/usr\"]\n");
        let r = rules(&s);
        assert!(!s.contains("network*") && !s.contains("DNSConfiguration"));
        let net: Vec<_> = r.iter().filter(|l| l.contains("network")).collect();
        assert_eq!(
            net,
            vec![
                &format!(
                    "(allow network-outbound network-bind (subpath \"{}\"))",
                    at(&t, "home/repo")
                ),
                &format!(
                    "(allow network-outbound network-bind (subpath \"{}\"))",
                    at(&t, "usr")
                ),
            ]
        );
        assert!(r.contains(&"(allow system-socket (socket-domain AF_UNIX))".to_string()));
    }

    // rivet: verifies REQ-ZW-015
    #[test]
    fn unfiltered_modes_open_what_they_name() {
        let t = tree();
        let s = generate(
            &t,
            "write: [\"@/home/repo\"]\nnetwork:\n  mode: \"unfiltered\"\n",
        );
        let r = rules(&s);
        for rule in UNFILTERED_IP {
            assert!(r.contains(&rule.to_string()), "{rule}\n{s}");
        }
        assert!(!r.contains(&"(allow system-socket (socket-domain AF_UNIX))".to_string()));
        // Unfiltered network opens IP only: no rule reaches a UNIX socket path except the
        // write-tree rules unix_sockets = confined gives, and no wildcard operation.
        assert!(!s.contains("network*"), "{s}");
        for l in r.iter().filter(|l| l.contains("network-")) {
            assert!(
                l.contains("(remote ip)")
                    || l.contains("(local ip)")
                    || l.ends_with(&format!("(subpath \"{}\"))", at(&t, "home/repo"))),
                "{l}"
            );
        }
        for m in DNS_SERVICES {
            assert!(
                r.contains(&format!("(allow mach-lookup (global-name \"{m}\"))")),
                "{m}"
            );
        }
        // unix sockets stay confined unless they are unfiltered too
        assert!(r.contains(&format!(
            "(allow network-outbound network-bind (subpath \"{}\"))",
            at(&t, "home/repo")
        )));
        let s = generate(
            &t,
            "write: [\"@/home/repo\"]\nnetwork:\n  unix_sockets: \"unfiltered\"\n",
        );
        let r = rules(&s);
        let net: Vec<_> = r.iter().filter(|l| l.contains("network")).collect();
        assert_eq!(
            net,
            vec!["(allow network-outbound network-bind (subpath \"/\"))"]
        );
        assert!(r.contains(&"(allow system-socket (socket-domain AF_UNIX))".to_string()));
    }

    // ---- summary ----

    // rivet: verifies REQ-ZW-015
    #[test]
    fn summary_names_seatbelt_counts_modes_and_gaps() {
        let t = tree();
        let p = profile(
            &t,
            "read: [\"@/usr\"]\nwrite: [\"@/home/repo\"]\nwrite_if_present: [\"@/gone\", \"@/no\"]\n\
             deny_read: [\"@/home/.ssh\"]\n",
        );
        let pl = plan(&p).unwrap();
        assert_eq!(
            summary(&p, &pl),
            format!(
                "zwinger: t confined: seatbelt; 1 read, 1 write grants (absent, skipped: {}, {}); \
                 1 deny_read, 0 deny_write; network: none; unix sockets: confined to write trees",
                at(&t, "gone"),
                at(&t, "no")
            )
        );
        let p = profile(
            &t,
            "deny_write: [\"@/x\"]\nnetwork:\n  mode: \"unfiltered\"\n  unix_sockets: \"unfiltered\"\n",
        );
        assert_eq!(
            summary(&p, &plan(&p).unwrap()),
            "zwinger: t confined: seatbelt; 0 read, 0 write grants; 0 deny_read, 1 deny_write; \
             network: unfiltered; unix sockets: unfiltered; not enforced: network (mode = \
             unfiltered), unix socket connections (unix_sockets = unfiltered)"
        );
        let p = profile(&t, "network:\n  unix_sockets: \"unfiltered\"\n");
        assert_eq!(
            not_enforced(&p),
            vec!["unix socket connections (unix_sockets = unfiltered)"]
        );
    }

    #[test]
    fn preflight_is_plan_then_policy() {
        let t = tree();
        let p = profile(&t, "read: [\"@/usr\"]\n");
        let (pl, pol) = preflight(&p).unwrap();
        assert_eq!(pl, plan(&p).unwrap());
        assert_eq!(pol, policy(&p, &pl).unwrap());
        assert!(preflight(&profile(&t, "read: [\"@/absent\"]\n")).is_err());
    }
}
