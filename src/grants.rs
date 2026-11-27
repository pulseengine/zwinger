//! The plan zwinger enforces, handed to the confined command as `ZWINGER_GRANTS` (REQ-ZW-021).
//!
//! A shell or agent inside the session reads it to know what it may touch: kapsel maps `read`
//! to read-only and `write` to read-write WASI preopens at the same paths (seam
//! pulseengine/kapsel#140), and any agent can use it to explain a denial. It
//! is information, not enforcement: the kernel sandbox enforces the same plan whether or not
//! the command reads this.
//!
//! Every path is absolute and resolved the way the backend resolved it. A path that is not
//! valid UTF-8 cannot be carried in JSON, so `to_json` refuses rather than write a lossy plan.

use serde::Serialize;
use std::path::{Path, PathBuf};

/// The environment variable the confined command receives.
pub const VAR: &str = "ZWINGER_GRANTS";
/// The schema of its value.
pub const SCHEMA: &str = "zwinger.grants.v1";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Grants {
    pub read: Vec<PathBuf>,
    pub write: Vec<PathBuf>,
    pub deny_read: Vec<PathBuf>,
    pub deny_write: Vec<PathBuf>,
    pub noexec: Vec<PathBuf>,
    /// Native executables the session may run. Empty until the profile has an exec allowlist
    /// (REQ-ZW-020); until then `read` trees are executable as before.
    pub exec: Vec<PathBuf>,
}

#[derive(Serialize)]
struct Wire<'a> {
    schema: &'static str,
    read: Vec<&'a str>,
    write: Vec<&'a str>,
    deny_read: Vec<&'a str>,
    deny_write: Vec<&'a str>,
    noexec: Vec<&'a str>,
    exec: Vec<&'a str>,
}

fn strs(v: &[PathBuf]) -> Result<Vec<&str>, String> {
    v.iter()
        .map(|p| {
            p.to_str().ok_or_else(|| {
                format!(
                    "{} is not valid UTF-8 and cannot be passed in {VAR}",
                    p.display()
                )
            })
        })
        .collect()
}

impl Grants {
    /// The JSON value of `ZWINGER_GRANTS`.
    pub fn to_json(&self) -> Result<String, String> {
        let wire = Wire {
            schema: SCHEMA,
            read: strs(&self.read)?,
            write: strs(&self.write)?,
            deny_read: strs(&self.deny_read)?,
            deny_write: strs(&self.deny_write)?,
            noexec: strs(&self.noexec)?,
            exec: strs(&self.exec)?,
        };
        serde_json::to_string(&wire).map_err(|e| format!("{VAR}: {e}"))
    }
}

/// A profile path as the session will meet it: resolved when it exists, as stated (already
/// absolute and normalized by the profile loader) when it does not.
pub fn resolve_or_stated(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_carries_every_list_and_the_schema() {
        let g = Grants {
            read: vec!["/usr".into(), "/home/me/repo".into()],
            write: vec!["/tmp/s".into()],
            deny_read: vec!["/home/me/repo/.env".into()],
            deny_write: vec![],
            noexec: vec!["/tmp/s".into()],
            exec: vec![],
        };
        let v: serde_json::Value = serde_json::from_str(&g.to_json().unwrap()).unwrap();
        assert_eq!(v["schema"], SCHEMA);
        assert_eq!(v["read"], serde_json::json!(["/usr", "/home/me/repo"]));
        assert_eq!(v["write"], serde_json::json!(["/tmp/s"]));
        assert_eq!(v["deny_read"], serde_json::json!(["/home/me/repo/.env"]));
        assert_eq!(v["deny_write"], serde_json::json!([]));
        assert_eq!(v["noexec"], serde_json::json!(["/tmp/s"]));
        assert_eq!(v["exec"], serde_json::json!([]));
        assert_eq!(v.as_object().unwrap().len(), 7, "no unexpected keys");
    }

    #[test]
    fn a_path_that_is_not_utf8_is_refused() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let g = Grants {
            write: vec![PathBuf::from(OsStr::from_bytes(b"/tmp/\xff"))],
            ..Grants::default()
        };
        let e = g.to_json().unwrap_err();
        assert!(e.contains("not valid UTF-8"), "{e}");
    }

    #[test]
    fn absent_paths_stay_as_stated_and_present_ones_resolve() {
        let absent = Path::new("/nonexistent-zwinger-test/x");
        assert_eq!(resolve_or_stated(absent), absent);
        let tmp = std::env::temp_dir();
        assert_eq!(resolve_or_stated(&tmp), tmp.canonicalize().unwrap());
    }
}
