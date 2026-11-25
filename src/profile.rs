//! The per-session profile: what a confined session may write, read, reach and look up.
//!
//! Loading fails closed (REQ-ZW-001): a missing or unreadable file, malformed TOML, an unknown
//! key, an empty name, a relative path or a wildcard domain is an error, never a default.

use serde::Deserialize;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// The session's name (e.g. the agent session it confines).
    pub name: String,
    /// Directories the session may write. Everything else is read-only or denied.
    #[serde(default)]
    pub write: Vec<PathBuf>,
    /// Paths the session may not read at all (secrets, other sessions' tokens).
    #[serde(default)]
    pub deny_read: Vec<PathBuf>,
    /// Outbound network.
    #[serde(default)]
    pub network: Network,
    /// macOS Mach services the session may look up beyond the base set.
    #[serde(default)]
    pub mach_lookup: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Exact host names the session may connect to. Empty means no egress.
    #[serde(default)]
    pub allow: Vec<String>,
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

    fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("name is empty".into());
        }
        for (field, paths) in [("write", &self.write), ("deny_read", &self.deny_read)] {
            for p in paths {
                if !p.is_absolute() {
                    return Err(format!("{field}: {} is not absolute", p.display()));
                }
                if p.components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    return Err(format!("{field}: {} contains ..", p.display()));
                }
            }
        }
        for w in &self.write {
            if self.deny_read.iter().any(|d| w.starts_with(d)) {
                return Err(format!(
                    "write: {} lies inside a deny_read path",
                    w.display()
                ));
            }
        }
        for h in &self.network.allow {
            if h.is_empty() || h.contains('*') || h.contains('/') || h.contains(char::is_whitespace)
            {
                return Err(format!("network.allow: {h:?} is not an exact host name"));
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

    const OK: &str = r#"
name = "demo"
write = ["/Users/me/git/demo", "/tmp/demo"]
deny_read = ["/Users/me/.ssh"]
mach_lookup = ["com.apple.server.bluetooth"]
[network]
allow = ["api.anthropic.com", "github.com"]
"#;

    #[test]
    fn valid_profile_loads() {
        let p = parse(OK).unwrap();
        assert_eq!(p.name, "demo");
        assert_eq!(p.network.allow.len(), 2);
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
    fn missing_name_fails_closed() {
        assert!(matches!(
            parse("write = []\n"),
            Err(ProfileError::Parse(..))
        ));
        assert!(matches!(
            parse("name = \" \"\n"),
            Err(ProfileError::Invalid(..))
        ));
    }

    #[test]
    fn relative_or_dotdot_paths_fail_closed() {
        assert!(matches!(
            parse("name = \"x\"\nwrite = [\"repo\"]\n"),
            Err(ProfileError::Invalid(..))
        ));
        assert!(matches!(
            parse("name = \"x\"\nwrite = [\"/repo/../etc\"]\n"),
            Err(ProfileError::Invalid(..))
        ));
    }

    #[test]
    fn write_inside_deny_read_fails_closed() {
        assert!(matches!(
            parse("name = \"x\"\nwrite = [\"/Users/me/.ssh/x\"]\ndeny_read = [\"/Users/me/.ssh\"]\n"),
            Err(ProfileError::Invalid(..))
        ));
    }

    #[test]
    fn wildcard_domain_fails_closed() {
        assert!(matches!(
            parse("name = \"x\"\n[network]\nallow = [\"*.github.com\"]\n"),
            Err(ProfileError::Invalid(..))
        ));
    }

    #[test]
    fn empty_allow_means_no_egress() {
        let p = parse("name = \"x\"\n").unwrap();
        assert!(p.network.allow.is_empty());
    }
}
