//! The per-session profile: what a confined session may read, write, reach and look up.
//!
//! Profiles are YAML, read by rivet-yaml, the parser every pulseengine artifact file goes through.
//! Loading fails closed (REQ-ZW-001): a missing or unreadable file, malformed YAML, an unknown or
//! duplicate key, a YAML tag, a second document, an empty or null name, a relative or `..` path, a contradictory pair of entries, a host that is
//! not an exact name or a malformed Mach service name is an error, never a default.
//!
//! Path semantics are an allow list with carve-outs: `read` and `write` grant trees, `deny_read`
//! and `deny_write` take subtrees back out, and an entry inside a denied tree is an exception to
//! it only where that is safe to state (a `read` inside a `deny_read`, e.g. one public key in a
//! secrets directory). A backend that cannot enforce a carve-out refuses the profile
//! (REQ-ZW-008); see `linux::plan` for Landlock's limits.

use serde::Deserialize;
use std::fmt;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// The session's name (e.g. the agent session it confines).
    pub name: String,
    /// Trees the session may read and execute. Nothing else is readable except `write` trees.
    #[serde(default)]
    pub read: Vec<PathBuf>,
    /// Trees the session may write (and read). Everything else is read-only or denied.
    #[serde(default)]
    pub write: Vec<PathBuf>,
    /// Like `read`, but a path that does not exist is skipped instead of refused (per-host
    /// directories such as `/lib32` or a tool cache only some machines have).
    #[serde(default)]
    pub read_if_present: Vec<PathBuf>,
    /// Directories the session may list (names only), and every directory beneath them; no
    /// file in them becomes readable. For programs that check they can list each ancestor of
    /// their root (REQ-ZW-046).
    #[serde(default)]
    pub list: Vec<PathBuf>,
    /// Like `write`, but a path that does not exist is skipped instead of refused.
    #[serde(default)]
    pub write_if_present: Vec<PathBuf>,
    /// Paths the session may not read at all (secrets, other sessions' tokens).
    #[serde(default)]
    pub deny_read: Vec<PathBuf>,
    /// Paths the session may not write even inside a `write` tree (its own launcher settings).
    #[serde(default)]
    pub deny_write: Vec<PathBuf>,
    /// Trees nothing may be executed from, even where `read` or `write` grants them (a scratch
    /// or download directory the session writes to). Every grant at or beneath one loses the
    /// right to execute. On Linux a `noexec` tree inside a wider grant is refused, because that
    /// grant's execute right would still cover it.
    #[serde(default)]
    pub noexec: Vec<PathBuf>,
    /// Directories whose UNIX sockets the session may connect to, besides the per-session socket
    /// directory zwinger creates (ZWINGER_SOCKET_DIR). Sockets elsewhere, including in write
    /// trees, cannot be connected to while UNIX sockets are confined (REQ-ZW-027).
    #[serde(default)]
    pub unix_socket_dirs: Vec<PathBuf>,
    /// Outbound network.
    #[serde(default)]
    pub network: Network,
    /// macOS Mach services the session may look up beyond the base set. Ignored on Linux, where
    /// there is nothing for it to allow.
    #[serde(default)]
    pub mach_lookup: Vec<String>,
    /// Variables on zwinger's scrub list (src/env.rs) that the session keeps. Every other
    /// scrubbed variable is removed before exec.
    #[serde(default)]
    pub env_keep: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// `none` (default): no egress except the hosts in `allow`. `unfiltered`: the network is not
    /// confined at all; only paths are. A profile has to say `unfiltered` to get it.
    #[serde(default)]
    pub mode: NetworkMode,
    /// Exact host names the session may connect to. Empty means no egress.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Whether the session may bind and listen on loopback ports.
    #[serde(default)]
    pub allow_local_binding: bool,
    /// Loopback TCP ports the session may connect to while `mode` is `none`, for example a
    /// network proxy outside the session. macOS only: Landlock filters ports, not addresses.
    #[serde(default)]
    pub allow_loopback_ports: Vec<u16>,
    /// `confined` (default): UNIX sockets only where the backend can confine where they connect.
    /// `unfiltered`: `socket(AF_UNIX)` is allowed and its connections are not confined.
    #[serde(default)]
    pub unix_sockets: UnixSockets,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    #[default]
    None,
    Unfiltered,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnixSockets {
    #[default]
    Confined,
    Unfiltered,
}

#[derive(Debug)]
pub enum ProfileError {
    Read(PathBuf, std::io::Error),
    Parse(PathBuf, String),
    Invalid(PathBuf, String),
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileError::Read(p, e) => write!(f, "{}: cannot read profile: {e}", p.display()),
            ProfileError::Parse(p, e) => write!(f, "{}: not a valid profile: {e}", p.display()),
            ProfileError::Invalid(p, e) => write!(f, "{}: {e}", p.display()),
        }
    }
}

impl std::error::Error for ProfileError {}

/// `p` in normal form: its components collected back into a path. Repeated separators collapse,
/// `.` segments vanish (except a leading `.` of a relative path), a trailing separator goes,
/// `..` stays. Profile paths are normalized when the profile is parsed, and resolved paths are
/// normal already, so every path the rules compare is in this form.
pub fn normalize(p: &Path) -> PathBuf {
    p.components().collect()
}

/// `inner` equals `outer` or lies beneath it, for paths in normal form (`normalize`): `outer`
/// is a byte prefix of `inner` that ends at a component boundary, or `outer` is the root (which
/// contains every absolute path) or empty (no components, so a prefix of everything). On normal
/// paths this is exactly `Path::starts_with`; a unit test checks `within(normalize(a),
/// normalize(b)) == a.starts_with(b)` for every pair of paths up to 5 bytes over
/// {'/', 'a', 'b', '.'}. It is a single comparison so the Kani proofs can reason about it.
pub fn within(inner: &Path, outer: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    crate::pathrules::within_bytes(inner.as_os_str().as_bytes(), outer.as_os_str().as_bytes())
}

/// `~/rest` becomes the invoking user's home joined with `rest`. A bare `~` is YAML's null and
/// stays as written, so it is refused as not absolute. Nothing else is expanded.
fn expand_home(p: &Path) -> Result<PathBuf, String> {
    match p.strip_prefix("~") {
        Ok(rest) if p.as_os_str().len() > 1 => Ok(home_dir()?.join(rest)),
        _ => Ok(p.to_path_buf()),
    }
}

/// Whether getpwuid_r found the user and a home directory: a zero return, an entry, and a
/// directory string. The backends' `home_dir` collects the three facts in unsafe code; the
/// decision is here, where it can be tested.
pub(crate) fn passwd_found(rc: i32, entry: bool, dir: bool) -> bool {
    rc == 0 && entry && dir
}

#[cfg(target_os = "linux")]
use crate::linux::home_dir;
#[cfg(target_os = "macos")]
use crate::macos::home_dir;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn home_dir() -> Result<PathBuf, String> {
    Err("~: no home directory lookup on this platform".into())
}

impl Profile {
    pub fn load(path: &Path) -> Result<Self, ProfileError> {
        let text = std::fs::read_to_string(path).map_err(|e| ProfileError::Read(path.into(), e))?;
        Self::parse(path, &text)
    }

    pub fn parse(path: &Path, text: &str) -> Result<Self, ProfileError> {
        let mut p: Profile = rivet_yaml::from_str(text)
            .map_err(|e| ProfileError::Parse(path.into(), e.to_string()))?;
        // Normal form at the boundary: every later comparison (`within`) relies on it.
        for list in [
            &mut p.read,
            &mut p.write,
            &mut p.read_if_present,
            &mut p.write_if_present,
            &mut p.deny_read,
            &mut p.deny_write,
            &mut p.noexec,
            &mut p.unix_socket_dirs,
            &mut p.list,
        ] {
            for entry in list.iter_mut() {
                let expanded =
                    expand_home(entry).map_err(|e| ProfileError::Invalid(path.into(), e))?;
                *entry = normalize(&expanded);
            }
        }
        p.validate()
            .map_err(|e| ProfileError::Invalid(path.into(), e))?;
        Ok(p)
    }

    /// The path lists by field name, in a fixed order.
    pub fn path_fields(&self) -> [(&'static str, &[PathBuf]); 9] {
        [
            ("read", &self.read),
            ("write", &self.write),
            ("read_if_present", &self.read_if_present),
            ("write_if_present", &self.write_if_present),
            ("deny_read", &self.deny_read),
            ("deny_write", &self.deny_write),
            ("noexec", &self.noexec),
            ("unix_socket_dirs", &self.unix_socket_dirs),
            ("list", &self.list),
        ]
    }

    /// Every read grant with its field name: `read`, then `read_if_present`.
    pub fn reads(&self) -> impl Iterator<Item = (&'static str, &PathBuf)> {
        let r = self.read.iter().map(|p| ("read", p));
        r.chain(self.read_if_present.iter().map(|p| ("read_if_present", p)))
    }

    /// Every write grant with its field name: `write`, then `write_if_present`.
    pub fn writes(&self) -> impl Iterator<Item = (&'static str, &PathBuf)> {
        let w = self.write.iter().map(|p| ("write", p));
        w.chain(
            self.write_if_present
                .iter()
                .map(|p| ("write_if_present", p)),
        )
    }

    fn validate(&self) -> Result<(), String> {
        // rivet-yaml reads a plain `~` or `null` as that text when the field is a string
        // (rivet#1354), so a name left null would otherwise load as the name "~".
        let name = self.name.trim();
        if name.is_empty() || matches!(name, "~" | "null" | "Null" | "NULL") {
            return Err("name is empty".into());
        }
        for (field, paths) in self.path_fields() {
            for p in paths {
                if !p.is_absolute() {
                    return Err(format!("{field}: {} is not absolute", p.display()));
                }
                if p.components().any(|c| matches!(c, Component::ParentDir)) {
                    return Err(format!("{field}: {} contains ..", p.display()));
                }
            }
        }
        // A writable tree inside a denied one would re-open the denied tree for writing.
        for (field, w) in self.writes() {
            if let Some(d) = self.deny_read.iter().find(|d| within(w, d)) {
                return Err(format!(
                    "{field}: {} lies inside deny_read {}",
                    w.display(),
                    d.display()
                ));
            }
            if let Some(d) = self.deny_write.iter().find(|d| within(w, d)) {
                return Err(format!(
                    "{field}: {} lies inside deny_write {}",
                    w.display(),
                    d.display()
                ));
            }
        }
        // The same path allowed and denied says nothing; refuse it rather than pick a winner.
        for (field, r) in self.reads() {
            if self.deny_read.contains(r) {
                return Err(format!(
                    "{field}: {} is also listed in deny_read",
                    r.display()
                ));
            }
        }
        let mut ports = self.network.allow_loopback_ports.clone();
        ports.sort_unstable();
        if ports.contains(&0) {
            return Err("network.allow_loopback_ports: port 0 is not a port; remove it".into());
        }
        if let Some(w) = ports.windows(2).find(|w| w[0] == w[1]) {
            return Err(format!(
                "network.allow_loopback_ports lists {} twice; remove one",
                w[0]
            ));
        }
        if self.network.mode == NetworkMode::Unfiltered {
            if !self.network.allow_loopback_ports.is_empty() {
                return Err(
                    "network.allow_loopback_ports is implied by mode = \"unfiltered\"; \
                            remove one of them"
                        .into(),
                );
            }
            if !self.network.allow.is_empty() {
                return Err(
                    "network.allow lists hosts, but mode = \"unfiltered\" allows every \
                            host; remove one of them"
                        .into(),
                );
            }
            if self.network.allow_local_binding {
                return Err(
                    "network.allow_local_binding is implied by mode = \"unfiltered\"; \
                            remove one of them"
                        .into(),
                );
            }
        }
        for h in &self.network.allow {
            if h.is_empty() || h.contains(['*', '/', ':']) || h.contains(char::is_whitespace) {
                return Err(format!("network.allow: {h:?} is not an exact host name"));
            }
        }
        for m in &self.mach_lookup {
            if m.is_empty() || m.contains('*') || m.contains(char::is_whitespace) {
                return Err(format!("mach_lookup: {m:?} is not an exact service name"));
            }
        }
        crate::env::validate_keep(&self.env_keep)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(t: &str) -> Result<Profile, ProfileError> {
        Profile::parse(Path::new("t.yaml"), t)
    }

    fn invalid(t: &str) -> bool {
        matches!(parse(t), Err(ProfileError::Invalid(..)))
    }

    const OK: &str = r#"
name: demo
read: [/usr, /Users/me/.ssh/id_ed25519.pub]
write:
  - /Users/me/git/demo
  - /tmp/demo
deny_read: [/Users/me/.ssh]
deny_write: [/Users/me/git/demo/.claude/settings.json]
mach_lookup: [com.apple.server.bluetooth]
network:
  allow: [api.anthropic.com, github.com]
  allow_local_binding: true
"#;

    // rivet: verifies REQ-ZW-002
    #[test]
    fn valid_profile_loads() {
        let p = parse(OK).unwrap();
        assert_eq!(p.name, "demo");
        assert_eq!(p.read.len(), 2);
        assert_eq!(p.write.len(), 2);
        assert_eq!(p.deny_read.len(), 1);
        assert_eq!(p.deny_write.len(), 1);
        assert_eq!(p.network.allow.len(), 2);
        assert!(p.network.allow_local_binding);
        assert_eq!(p.mach_lookup.len(), 1);
    }

    #[test]
    fn defaults_are_the_closed_ones() {
        let p = parse("name: \"x\"\n").unwrap();
        assert!(p.read.is_empty() && p.write.is_empty());
        assert!(p.network.allow.is_empty(), "empty allow means no egress");
        assert!(!p.network.allow_local_binding);
    }

    #[test]
    fn missing_file_fails_closed() {
        assert!(matches!(
            Profile::load(Path::new("/nonexistent/zwinger.yaml")),
            Err(ProfileError::Read(..))
        ));
    }

    #[test]
    fn unknown_key_fails_closed() {
        assert!(matches!(
            parse("name: \"x\"\nallow_all: true\n"),
            Err(ProfileError::Parse(..))
        ));
        assert!(matches!(
            parse("name: \"x\"\nnetwork:\n  allow: []\n  open: true\n"),
            Err(ProfileError::Parse(..))
        ));
    }

    // rivet: verifies REQ-ZW-001
    #[test]
    fn yaml_constructs_that_could_change_meaning_fail_closed() {
        for (why, t) in [
            ("duplicate key", "name: x\nname: y\n"),
            (
                "duplicate nested key",
                "name: x\nnetwork:\n  mode: none\n  mode: unfiltered\n",
            ),
            (
                "YAML 1.1 yes is not a boolean",
                "name: x\nnetwork:\n  allow_local_binding: yes\n",
            ),
            (
                "YAML 1.1 on is not a boolean",
                "name: x\nnetwork:\n  allow_local_binding: on\n",
            ),
            ("tag", "name: !!str x\n"),
            ("second document", "name: x\n---\nname: y\nread: [/]\n"),
            ("merge key", "name: x\n<<: {read: [/usr]}\n"),
            ("empty document", ""),
            ("scalar where a list belongs", "name: x\nread: /usr\n"),
        ] {
            assert!(
                matches!(parse(t), Err(ProfileError::Parse(..))),
                "{why}: {t:?}"
            );
        }
    }

    #[test]
    fn null_name_fails_closed() {
        for t in ["name:\n", "name: ~\n", "name: null\n", "name: NULL\n"] {
            assert!(invalid(t), "{t:?}");
        }
    }

    #[test]
    fn a_password_lookup_needs_every_part() {
        assert!(passwd_found(0, true, true));
        assert!(!passwd_found(34, true, true), "ERANGE");
        assert!(!passwd_found(0, false, true), "no entry");
        assert!(!passwd_found(0, true, false), "no directory");
    }

    // rivet: verifies REQ-ZW-031
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_leading_tilde_is_the_users_home_from_the_password_database() {
        let home = home_dir().unwrap();
        assert!(home.is_absolute(), "{}", home.display());
        let p = parse("name: x\nwrite: [\"~/repo\"]\ndeny_read: [\"~/.ssh\"]\n").unwrap();
        assert_eq!(p.write, vec![home.join("repo")]);
        assert_eq!(p.deny_read, vec![home.join(".ssh")]);
        // Not expanded: another user's home, the environment, a tilde later in the path.
        assert!(invalid("name: x\nread: [\"~root/x\"]\n"));
        assert!(invalid("name: x\nread: [\"$HOME/x\"]\n"));
        let p = parse("name: x\nread: [\"/a/~/b\"]\n").unwrap();
        assert_eq!(p.read, vec![PathBuf::from("/a/~/b")]);
    }

    #[test]
    fn null_paths_fail_closed() {
        // `~` reads as the text "~", which is not absolute.
        assert!(invalid("name: x\nread: [~]\n"));
        assert!(invalid("name: x\nwrite: [null]\n"));
    }

    #[test]
    fn wrong_type_fails_closed() {
        assert!(matches!(
            parse("name: \"x\"\nread: \"/usr\"\n"),
            Err(ProfileError::Parse(..))
        ));
        assert!(matches!(
            parse("name: \"x\"\nnetwork:\n  allow_local_binding: \"yes\"\n"),
            Err(ProfileError::Parse(..))
        ));
    }

    #[test]
    fn missing_name_fails_closed() {
        assert!(matches!(parse("write: []\n"), Err(ProfileError::Parse(..))));
        assert!(invalid("name: \" \"\n"));
    }

    #[test]
    fn relative_paths_fail_closed_in_every_path_field() {
        for field in [
            "read",
            "write",
            "read_if_present",
            "write_if_present",
            "deny_read",
            "deny_write",
            "noexec",
        ] {
            assert!(
                invalid(&format!("name: \"x\"\n{field}: [\"repo\"]\n")),
                "{field}"
            );
        }
    }

    #[test]
    fn dotdot_paths_fail_closed_in_every_path_field() {
        for field in [
            "read",
            "write",
            "read_if_present",
            "write_if_present",
            "deny_read",
            "deny_write",
            "noexec",
        ] {
            assert!(
                invalid(&format!("name: \"x\"\n{field}: [\"/repo/../etc\"]\n")),
                "{field}"
            );
        }
    }

    #[test]
    fn write_inside_deny_read_fails_closed() {
        assert!(invalid(
            "name: \"x\"\nwrite: [\"/Users/me/.ssh/x\"]\ndeny_read: [\"/Users/me/.ssh\"]\n"
        ));
        assert!(invalid(
            "name: \"x\"\nwrite: [\"/Users/me/.ssh\"]\ndeny_read: [\"/Users/me/.ssh\"]\n"
        ));
    }

    #[test]
    fn write_inside_deny_write_fails_closed() {
        assert!(invalid(
            "name: \"x\"\nwrite: [\"/r/.claude/x\"]\ndeny_write: [\"/r/.claude\"]\n"
        ));
    }

    #[test]
    fn deny_write_inside_write_is_a_carve_out() {
        assert!(parse("name: \"x\"\nwrite: [\"/r\"]\ndeny_write: [\"/r/.claude\"]\n").is_ok());
    }

    #[test]
    fn read_equal_to_deny_read_fails_closed() {
        assert!(invalid(
            "name: \"x\"\nread: [\"/Users/me/.ssh\"]\ndeny_read: [\"/Users/me/.ssh\"]\n"
        ));
    }

    #[test]
    fn read_inside_deny_read_is_an_exception() {
        assert!(
            parse(
                "name: \"x\"\nread: [\"/Users/me/.ssh/k.pub\"]\ndeny_read: [\"/Users/me/.ssh\"]\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn non_exact_hosts_fail_closed() {
        for h in [
            "*.github.com",
            "",
            "github.com/x",
            "github.com:443",
            "git hub.com",
        ] {
            assert!(
                invalid(&format!("name: \"x\"\nnetwork:\n  allow: [{h:?}]\n")),
                "{h:?}"
            );
        }
    }

    #[test]
    fn non_exact_mach_services_fail_closed() {
        for m in ["", "com.apple.*", "com.apple. x"] {
            assert!(
                invalid(&format!("name: \"x\"\nmach_lookup: [{m:?}]\n")),
                "{m:?}"
            );
        }
    }

    #[test]
    fn refusals_name_the_file_and_the_reason() {
        let read = Profile::load(Path::new("/nonexistent/z.yaml"))
            .unwrap_err()
            .to_string();
        assert!(
            read.starts_with("/nonexistent/z.yaml: cannot read profile: "),
            "{read}"
        );
        let p = parse("name: x\nread: /usr\n").unwrap_err().to_string();
        assert!(p.starts_with("t.yaml: not a valid profile: "), "{p}");
        let i = parse("name: \"x\"\nwrite: [\"repo\"]\n")
            .unwrap_err()
            .to_string();
        assert_eq!(i, "t.yaml: write: repo is not absolute");
    }
    // rivet: verifies REQ-ZW-009
    #[test]
    fn network_modes_parse_and_default_to_none() {
        let p = parse("name: \"x\"\n").unwrap();
        assert_eq!(p.network.mode, NetworkMode::None);
        assert_eq!(p.network.unix_sockets, UnixSockets::Confined);
        let p = parse(
            "name: \"x\"\nnetwork:\n  mode: \"unfiltered\"\n  unix_sockets: \"unfiltered\"\n",
        )
        .unwrap();
        assert_eq!(p.network.mode, NetworkMode::Unfiltered);
        assert_eq!(p.network.unix_sockets, UnixSockets::Unfiltered);
    }

    // rivet: verifies REQ-ZW-009
    #[test]
    fn unknown_network_values_fail_closed() {
        for body in [
            "mode: \"ports\"",
            "mode: \"all\"",
            "mode: \"Unfiltered\"",
            "unix_sockets: \"any\"",
            "mode: true",
        ] {
            assert!(
                matches!(
                    parse(&format!("name: \"x\"\nnetwork:\n  {body}\n")),
                    Err(ProfileError::Parse(..))
                ),
                "{body}"
            );
        }
    }

    // rivet: verifies REQ-ZW-009
    #[test]
    fn unfiltered_with_host_or_binding_allowances_fails_closed() {
        assert!(invalid(
            "name: \"x\"\nnetwork:\n  mode: \"unfiltered\"\n  allow: [\"github.com\"]\n"
        ));
        assert!(invalid(
            "name: \"x\"\nnetwork:\n  mode: \"unfiltered\"\n  allow_local_binding: true\n"
        ));
    }

    // rivet: verifies REQ-ZW-044
    #[test]
    fn loopback_ports_are_checked() {
        assert!(parse("name: \"x\"\nnetwork:\n  allow_loopback_ports: [3128, 18480]\n").is_ok());
        assert!(invalid(
            "name: \"x\"\nnetwork:\n  allow_loopback_ports: [0]\n"
        ));
        assert!(invalid(
            "name: \"x\"\nnetwork:\n  allow_loopback_ports: [3128, 3128]\n"
        ));
        // Not a u16: a parse error.
        assert!(parse("name: \"x\"\nnetwork:\n  allow_loopback_ports: [70000]\n").is_err());
        assert!(invalid(
            "name: \"x\"\nnetwork:\n  mode: \"unfiltered\"\n  allow_loopback_ports: [3128]\n"
        ));
    }

    #[test]
    fn if_present_grants_follow_the_same_contradiction_rules() {
        assert!(invalid(
            "name: \"x\"\nwrite_if_present: [\"/s/x\"]\ndeny_read: [\"/s\"]\n"
        ));
        assert!(invalid(
            "name: \"x\"\nwrite_if_present: [\"/r/.c/x\"]\ndeny_write: [\"/r/.c\"]\n"
        ));
        assert!(invalid(
            "name: \"x\"\nread_if_present: [\"/s\"]\ndeny_read: [\"/s\"]\n"
        ));
        let e = parse("name: \"x\"\nwrite_if_present: [\"/s/x\"]\ndeny_read: [\"/s\"]\n")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("write_if_present: /s/x lies inside deny_read /s"),
            "{e}"
        );
    }
}

#[cfg(test)]
mod within_tests {
    use super::{normalize, within};
    use std::path::Path;

    /// Every string up to `max` bytes over the alphabet.
    fn all_paths(max: usize) -> Vec<String> {
        let mut out = vec![String::new()];
        let mut frontier = vec![String::new()];
        for _ in 0..max {
            let mut next = Vec::new();
            for p in &frontier {
                for c in ['/', 'a', 'b', '.'] {
                    next.push(format!("{p}{c}"));
                }
            }
            out.extend(next.iter().cloned());
            frontier = next;
        }
        out
    }

    /// The Kani proofs rely on `within` of normal forms meaning `Path::starts_with` of the raw
    /// paths: checked exhaustively for
    /// every pair of paths up to 5 bytes over {'/', 'a', 'b', '.'} (1365 paths, ~1.9M pairs).
    #[test]
    fn within_agrees_with_path_starts_with() {
        let paths = all_paths(5);
        let mut checked = 0usize;
        for a in &paths {
            for b in &paths {
                let (pa, pb) = (Path::new(a), Path::new(b));
                assert_eq!(
                    within(&normalize(pa), &normalize(pb)),
                    pa.starts_with(pb),
                    "within({a:?}, {b:?})"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, paths.len() * paths.len());
        assert_eq!(paths.len(), 1365);
    }
}
