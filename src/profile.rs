//! The per-session profile: what a confined session may read, write, reach and look up.
//!
//! Loading fails closed (REQ-ZW-001): a missing or unreadable file, malformed TOML, an unknown
//! key, an empty name, a relative or `..` path, a contradictory pair of entries, a host that is
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
    /// Paths the session may not read at all (secrets, other sessions' tokens).
    #[serde(default)]
    pub deny_read: Vec<PathBuf>,
    /// Paths the session may not write even inside a `write` tree (its own launcher settings).
    #[serde(default)]
    pub deny_write: Vec<PathBuf>,
    /// Outbound network.
    #[serde(default)]
    pub network: Network,
    /// macOS Mach services the session may look up beyond the base set. Ignored on Linux, where
    /// there is nothing for it to allow.
    #[serde(default)]
    pub mach_lookup: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Exact host names the session may connect to. Empty means no egress.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Whether the session may bind and listen on loopback ports.
    #[serde(default)]
    pub allow_local_binding: bool,
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

/// `inner` equals `outer` or lies beneath it, compared by path components.
pub fn within(inner: &Path, outer: &Path) -> bool {
    inner.starts_with(outer)
}

impl Profile {
    pub fn load(path: &Path) -> Result<Self, ProfileError> {
        let text = std::fs::read_to_string(path).map_err(|e| ProfileError::Read(path.into(), e))?;
        Self::parse(path, &text)
    }

    pub fn parse(path: &Path, text: &str) -> Result<Self, ProfileError> {
        let p: Profile =
            toml::from_str(text).map_err(|e| ProfileError::Parse(path.into(), e.to_string()))?;
        p.validate()
            .map_err(|e| ProfileError::Invalid(path.into(), e))?;
        Ok(p)
    }

    /// The path lists by field name, in a fixed order.
    pub fn path_fields(&self) -> [(&'static str, &[PathBuf]); 4] {
        [
            ("read", &self.read),
            ("write", &self.write),
            ("deny_read", &self.deny_read),
            ("deny_write", &self.deny_write),
        ]
    }

    fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
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
        for w in &self.write {
            if let Some(d) = self.deny_read.iter().find(|d| within(w, d)) {
                return Err(format!(
                    "write: {} lies inside deny_read {}",
                    w.display(),
                    d.display()
                ));
            }
            if let Some(d) = self.deny_write.iter().find(|d| within(w, d)) {
                return Err(format!(
                    "write: {} lies inside deny_write {}",
                    w.display(),
                    d.display()
                ));
            }
        }
        // The same path allowed and denied says nothing; refuse it rather than pick a winner.
        for r in &self.read {
            if self.deny_read.contains(r) {
                return Err(format!("read: {} is also listed in deny_read", r.display()));
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(t: &str) -> Result<Profile, ProfileError> {
        Profile::parse(Path::new("t.toml"), t)
    }

    fn invalid(t: &str) -> bool {
        matches!(parse(t), Err(ProfileError::Invalid(..)))
    }

    const OK: &str = r#"
name = "demo"
read = ["/usr", "/Users/me/.ssh/id_ed25519.pub"]
write = ["/Users/me/git/demo", "/tmp/demo"]
deny_read = ["/Users/me/.ssh"]
deny_write = ["/Users/me/git/demo/.claude/settings.json"]
mach_lookup = ["com.apple.server.bluetooth"]
[network]
allow = ["api.anthropic.com", "github.com"]
allow_local_binding = true
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
        let p = parse("name = \"x\"\n").unwrap();
        assert!(p.read.is_empty() && p.write.is_empty());
        assert!(p.network.allow.is_empty(), "empty allow means no egress");
        assert!(!p.network.allow_local_binding);
    }

    #[test]
    fn missing_file_fails_closed() {
        assert!(matches!(
            Profile::load(Path::new("/nonexistent/zwinger.toml")),
            Err(ProfileError::Read(..))
        ));
    }

    #[test]
    fn unknown_key_fails_closed() {
        assert!(matches!(
            parse("name = \"x\"\nallow_all = true\n"),
            Err(ProfileError::Parse(..))
        ));
        assert!(matches!(
            parse("name = \"x\"\n[network]\nallow = []\nopen = true\n"),
            Err(ProfileError::Parse(..))
        ));
    }

    #[test]
    fn wrong_type_fails_closed() {
        assert!(matches!(
            parse("name = \"x\"\nread = \"/usr\"\n"),
            Err(ProfileError::Parse(..))
        ));
        assert!(matches!(
            parse("name = \"x\"\n[network]\nallow_local_binding = \"yes\"\n"),
            Err(ProfileError::Parse(..))
        ));
    }

    #[test]
    fn missing_name_fails_closed() {
        assert!(matches!(
            parse("write = []\n"),
            Err(ProfileError::Parse(..))
        ));
        assert!(invalid("name = \" \"\n"));
    }

    #[test]
    fn relative_paths_fail_closed_in_every_path_field() {
        for field in ["read", "write", "deny_read", "deny_write"] {
            assert!(
                invalid(&format!("name = \"x\"\n{field} = [\"repo\"]\n")),
                "{field}"
            );
        }
    }

    #[test]
    fn dotdot_paths_fail_closed_in_every_path_field() {
        for field in ["read", "write", "deny_read", "deny_write"] {
            assert!(
                invalid(&format!("name = \"x\"\n{field} = [\"/repo/../etc\"]\n")),
                "{field}"
            );
        }
    }

    #[test]
    fn write_inside_deny_read_fails_closed() {
        assert!(invalid(
            "name = \"x\"\nwrite = [\"/Users/me/.ssh/x\"]\ndeny_read = [\"/Users/me/.ssh\"]\n"
        ));
        assert!(invalid(
            "name = \"x\"\nwrite = [\"/Users/me/.ssh\"]\ndeny_read = [\"/Users/me/.ssh\"]\n"
        ));
    }

    #[test]
    fn write_inside_deny_write_fails_closed() {
        assert!(invalid(
            "name = \"x\"\nwrite = [\"/r/.claude/x\"]\ndeny_write = [\"/r/.claude\"]\n"
        ));
    }

    #[test]
    fn deny_write_inside_write_is_a_carve_out() {
        assert!(parse("name = \"x\"\nwrite = [\"/r\"]\ndeny_write = [\"/r/.claude\"]\n").is_ok());
    }

    #[test]
    fn read_equal_to_deny_read_fails_closed() {
        assert!(invalid(
            "name = \"x\"\nread = [\"/Users/me/.ssh\"]\ndeny_read = [\"/Users/me/.ssh\"]\n"
        ));
    }

    #[test]
    fn read_inside_deny_read_is_an_exception() {
        assert!(parse(
            "name = \"x\"\nread = [\"/Users/me/.ssh/k.pub\"]\ndeny_read = [\"/Users/me/.ssh\"]\n"
        )
        .is_ok());
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
                invalid(&format!("name = \"x\"\n[network]\nallow = [{h:?}]\n")),
                "{h:?}"
            );
        }
    }

    #[test]
    fn non_exact_mach_services_fail_closed() {
        for m in ["", "com.apple.*", "com.apple. x"] {
            assert!(
                invalid(&format!("name = \"x\"\nmach_lookup = [{m:?}]\n")),
                "{m:?}"
            );
        }
    }

    #[test]
    fn refusals_name_the_file_and_the_reason() {
        let read = Profile::load(Path::new("/nonexistent/z.toml"))
            .unwrap_err()
            .to_string();
        assert!(
            read.starts_with("/nonexistent/z.toml: cannot read profile: "),
            "{read}"
        );
        let p = parse("name = 1\n").unwrap_err().to_string();
        assert!(p.starts_with("t.toml: not a valid profile: "), "{p}");
        let i = parse("name = \"x\"\nwrite = [\"repo\"]\n")
            .unwrap_err()
            .to_string();
        assert_eq!(i, "t.toml: write: repo is not absolute");
    }
}
