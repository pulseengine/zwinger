//! Confinement events for warte's probe (pulseengine/warte#223, option A, owner decision
//! 2026-11-27): one JSON file per `zwinger run`, in the state dir the probe collects from.
//!
//! Only the fields agreed in warte#223 leave the machine: the profile's name and sha256, the
//! verdict, a refusal category, the Landlock ABI, the network mode, the not-enforced list and
//! grant counts. No path, argument or command line is written, because refusal texts and
//! grants name paths; a refusal is reduced to its category.
//!
//! Events never decide confinement. A directory that cannot be created or a file that cannot
//! be written is reported on stderr and the session proceeds (or is refused) exactly as it
//! would without events.

use serde::Serialize;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The schema name in every event. A new field or a changed meaning bumps it.
pub const SCHEMA: &str = "zwinger.event.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Confined,
    Refused,
}

/// One session's outcome, as the probe receives it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Event {
    pub schema: &'static str,
    pub zwinger_version: &'static str,
    /// Unix seconds when zwinger decided.
    pub time: u64,
    /// The zwinger process, which becomes the session's process after exec.
    pub pid: u32,
    /// `None` when the profile could not be loaded.
    pub profile: Option<String>,
    /// sha256 of the profile file's bytes, `None` when it could not be read.
    pub profile_sha256: Option<String>,
    pub verdict: Verdict,
    /// Why a session was refused, as one of [`CATEGORIES`]; `None` when confined.
    pub category: Option<&'static str>,
    pub landlock_abi: Option<i32>,
    pub network: Option<&'static str>,
    pub not_enforced: Vec<String>,
    pub read_grants: usize,
    pub write_grants: usize,
    pub skipped_grants: usize,
}

/// Every refusal category an event can carry.
pub const CATEGORIES: [&str; 7] = [
    "profile",
    "path",
    "carve-out",
    "noexec",
    "network",
    "kernel",
    "backend",
];

impl Event {
    fn base(profile: Option<String>, profile_sha256: Option<String>, verdict: Verdict) -> Event {
        Event {
            schema: SCHEMA,
            zwinger_version: env!("CARGO_PKG_VERSION"),
            time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            pid: std::process::id(),
            profile,
            profile_sha256,
            verdict,
            category: None,
            landlock_abi: None,
            network: None,
            not_enforced: Vec::new(),
            read_grants: 0,
            write_grants: 0,
            skipped_grants: 0,
        }
    }

    /// A refused session: the category only, never the refusal text.
    pub fn refused(
        profile: Option<String>,
        profile_sha256: Option<String>,
        category: &'static str,
    ) -> Event {
        Event {
            category: Some(category),
            ..Event::base(profile, profile_sha256, Verdict::Refused)
        }
    }

    /// A confined session.
    #[allow(clippy::too_many_arguments)]
    pub fn confined(
        profile: String,
        profile_sha256: Option<String>,
        landlock_abi: i32,
        network: &'static str,
        not_enforced: Vec<String>,
        read_grants: usize,
        write_grants: usize,
        skipped_grants: usize,
    ) -> Event {
        Event {
            landlock_abi: Some(landlock_abi),
            network: Some(network),
            not_enforced,
            read_grants,
            write_grants,
            skipped_grants,
            ..Event::base(Some(profile), profile_sha256, Verdict::Confined)
        }
    }

    pub fn to_json(&self) -> String {
        // Serializing a struct of strings, numbers and options cannot fail.
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// The directory events go to. `ZWINGER_EVENTS_DIR` wins (an empty value turns events off),
/// then `$XDG_STATE_HOME/warte/zwinger`, then `$HOME/.local/state/warte/zwinger`. A relative
/// value is ignored, as the XDG spec says.
pub fn resolve_dir(
    events_dir: Option<OsString>,
    xdg_state_home: Option<OsString>,
    home: Option<OsString>,
) -> Option<PathBuf> {
    let absolute = |v: OsString| Some(PathBuf::from(v)).filter(|p| p.is_absolute());
    if let Some(v) = events_dir {
        return absolute(v);
    }
    if let Some(p) = xdg_state_home.and_then(absolute) {
        return Some(p.join("warte/zwinger"));
    }
    home.and_then(absolute)
        .map(|h| h.join(".local/state/warte/zwinger"))
}

/// `resolve_dir` from this process's environment.
pub fn default_dir() -> Option<PathBuf> {
    resolve_dir(
        std::env::var_os("ZWINGER_EVENTS_DIR"),
        std::env::var_os("XDG_STATE_HOME"),
        std::env::var_os("HOME"),
    )
}

/// The category of a refusal text from `linux::preflight` (or `confine`, which runs it). The
/// texts are this crate's own; tests derive them from the planner, not from copies.
pub fn category(refusal: &str) -> &'static str {
    if refusal.starts_with("network.") {
        "network"
    } else if refusal.starts_with("noexec:") {
        "noexec"
    } else if refusal.contains("deny_read") || refusal.contains("deny_write") {
        "carve-out"
    } else if refusal.contains("Landlock") || refusal.contains("seccomp") {
        "kernel"
    } else if refusal.starts_with("read") || refusal.starts_with("write") {
        "path"
    } else {
        "backend"
    }
}

/// sha256 of a file's bytes, as lowercase hex.
pub fn sha256_file(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).ok()?;
    Some(
        Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

/// An event file, created before the session is confined so that writing it afterwards needs
/// no grant: Landlock checks a file when it is opened, not when an open descriptor is written.
pub struct Pending {
    file: std::fs::File,
}

impl Pending {
    /// Create `<dir>/<unix-nanos>-<pid>.json` (mode 0600, the directory 0700 when created).
    pub fn create(dir: &Path) -> std::io::Result<Pending> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(format!("{nanos}-{}.json", std::process::id())))?;
        Ok(Pending { file })
    }

    /// Write the event as one line, in one write.
    pub fn finish(mut self, event: &Event) -> std::io::Result<()> {
        let mut line = event.to_json();
        line.push('\n');
        self.file.write_all(line.as_bytes())
    }
}

/// `Pending::create` in the default dir, reporting (not failing on) any error.
pub fn begin() -> Option<Pending> {
    let dir = default_dir()?;
    match Pending::create(&dir) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!(
                "zwinger: events: cannot create an event file in {}: {e}; continuing without",
                dir.display()
            );
            None
        }
    }
}

/// Write `event` to `pending` if there is one, reporting (not failing on) any error.
pub fn end(pending: Option<Pending>, event: &Event) {
    if let Some(p) = pending
        && let Err(e) = p.finish(event)
    {
        eprintln!("zwinger: events: cannot write the event: {e}; continuing without");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> Option<OsString> {
        Some(OsString::from(s))
    }

    // rivet: verifies REQ-ZW-014
    #[test]
    fn dir_precedence_and_off_switch() {
        let d = |e, x, h| resolve_dir(e, x, h);
        assert_eq!(d(os("/ev"), os("/x"), os("/h")), Some(PathBuf::from("/ev")));
        assert_eq!(
            d(os(""), os("/x"), os("/h")),
            None,
            "empty turns events off"
        );
        assert_eq!(
            d(os("rel"), os("/x"), os("/h")),
            None,
            "relative is ignored"
        );
        assert_eq!(
            d(None, os("/x"), os("/h")),
            Some(PathBuf::from("/x/warte/zwinger"))
        );
        assert_eq!(
            d(None, os("rel"), os("/h")),
            Some(PathBuf::from("/h/.local/state/warte/zwinger"))
        );
        assert_eq!(
            d(None, None, os("/h")),
            Some(PathBuf::from("/h/.local/state/warte/zwinger"))
        );
        assert_eq!(d(None, None, os("h")), None);
        assert_eq!(d(None, None, None), None);
    }

    // rivet: verifies REQ-ZW-014
    #[test]
    fn events_carry_exactly_the_agreed_fields() {
        let c = Event::confined(
            "agent".into(),
            Some("ab".into()),
            6,
            "none",
            vec!["denial audit log (abi 7)".into()],
            3,
            2,
            1,
        );
        let v: serde_json::Value = serde_json::from_str(&c.to_json()).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "category",
                "landlock_abi",
                "network",
                "not_enforced",
                "pid",
                "profile",
                "profile_sha256",
                "read_grants",
                "schema",
                "skipped_grants",
                "time",
                "verdict",
                "write_grants",
                "zwinger_version"
            ]
        );
        assert_eq!(v["schema"], "zwinger.event.v1");
        assert_eq!(v["verdict"], "confined");
        assert_eq!(v["landlock_abi"], 6);
        assert_eq!(v["network"], "none");
        assert_eq!(
            v["not_enforced"],
            serde_json::json!(["denial audit log (abi 7)"])
        );
        assert_eq!(v["category"], serde_json::Value::Null);
        assert_eq!(v["read_grants"], 3);
        assert_eq!(v["write_grants"], 2);
        assert_eq!(v["skipped_grants"], 1);
        assert_eq!(v["pid"], std::process::id());
        assert!(v["time"].as_u64().unwrap() > 1_700_000_000);
        let r = Event::refused(None, None, "profile");
        let v: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(v["verdict"], "refused");
        assert_eq!(v["category"], "profile");
        assert_eq!(v["landlock_abi"], serde_json::Value::Null);
        assert_eq!(v["profile"], serde_json::Value::Null);
    }

    /// The categories come from the planner's real refusal texts, not from copies of them.
    // rivet: verifies REQ-ZW-014
    #[test]
    fn refusal_categories_follow_the_planner() {
        use crate::linux::plan;
        use crate::profile::Profile;
        let root = std::env::temp_dir().join(format!("zwinger-events-{}", std::process::id()));
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        let r = root.display();
        let refusal = |body: String| {
            let p = Profile::parse(Path::new("t.yaml"), &format!("name: t\n{body}")).unwrap();
            plan(&p).unwrap_err()
        };
        assert_eq!(
            category(&refusal("network:\n  allow: [github.com]\n".into())),
            "network"
        );
        assert_eq!(
            category(&refusal("network:\n  allow_local_binding: true\n".into())),
            "network"
        );
        assert_eq!(category(&refusal(format!("read: [{r}/missing]\n"))), "path");
        assert_eq!(
            category(&refusal(format!("write: [{r}/missing]\n"))),
            "path"
        );
        assert_eq!(
            category(&refusal(format!("read: [{r}/a]\ndeny_read: [{r}/a/b]\n"))),
            "carve-out"
        );
        assert_eq!(
            category(&refusal(format!("write: [{r}/a]\ndeny_write: [{r}/a/b]\n"))),
            "carve-out"
        );
        assert_eq!(
            category(&crate::linux::AbiRefusal::Unavailable.to_string()),
            "kernel"
        );
        assert_eq!(
            category(&crate::linux::AbiRefusal::TooOld(2).to_string()),
            "kernel"
        );
        assert_eq!(category("seccomp: Invalid argument; refusing"), "kernel");
        assert_eq!(category("noexec: /x lies inside write /"), "noexec");
        assert_eq!(
            category("no enforcement backend on this platform"),
            "backend"
        );
        let _ = std::fs::remove_dir_all(&root);
        for c in [
            "network",
            "noexec",
            "carve-out",
            "kernel",
            "path",
            "backend",
        ] {
            assert!(CATEGORIES.contains(&c), "{c}");
        }
    }

    // rivet: verifies REQ-ZW-014
    #[test]
    fn pending_writes_one_line_with_private_modes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("zwinger-ev-{}/x", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = Pending::create(&dir).unwrap();
        p.finish(&Event::refused(Some("t".into()), None, "path"))
            .unwrap();
        let files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1);
        let text = std::fs::read_to_string(&files[0]).unwrap();
        assert!(
            text.ends_with('\n') && text.lines().count() == 1,
            "{text:?}"
        );
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&files[0]), 0o600);
        assert_eq!(mode(&dir), 0o700);
        assert!(
            files[0]
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with(".json")
        );
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn sha256_matches_a_known_digest() {
        let f = std::env::temp_dir().join(format!("zwinger-sha-{}", std::process::id()));
        std::fs::write(&f, "abc").unwrap();
        assert_eq!(
            sha256_file(&f).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_file(&f);
        assert_eq!(sha256_file(Path::new("/nonexistent/zwinger")), None);
    }
}
