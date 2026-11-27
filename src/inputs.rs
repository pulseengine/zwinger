//! Files a later run trusts must lie outside the session's write grants (REQ-ZW-024).
//!
//! The next `zwinger run` reads the profile again and runs the zwinger executable again, both
//! with the operator's full authority. If the session could change either, it could choose the
//! grants or the code of the run after it. So `check` and `run` refuse a profile or an
//! executable that lies inside a write grant, compared both as stated and as resolved (a
//! symlink must not hide it), and refuse one with more than one hard link, since another link
//! could sit inside a write grant where no path check would see it.

use crate::profile::{normalize, within};
use std::path::{Path, PathBuf};

/// The absolute, lexically normalized form of `p` (relative paths join the current directory).
fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        normalize(p)
    } else {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        normalize(&cwd.join(p))
    }
}

/// Refuse when `file` (the profile, or the zwinger executable, as `what` names it) lies inside
/// one of `grants` (stated and resolved write grants), or, when `single_link`, has more than one
/// hard link.
pub fn outside_write_grants(
    what: &str,
    file: &Path,
    grants: &[PathBuf],
    single_link: bool,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let stated = absolute(file);
    let resolved = file
        .canonicalize()
        .map_err(|e| format!("{what} {}: {e}; refusing", file.display()))?;
    for g in grants {
        let g = normalize(g);
        for p in [&stated, &resolved] {
            if within(p, &g) {
                return Err(format!(
                    "{what} {} lies inside write grant {}, so the session could change what the \
                     next run trusts; move it outside every write grant; refusing",
                    p.display(),
                    g.display()
                ));
            }
        }
    }
    if !single_link {
        return Ok(());
    }
    let links = std::fs::metadata(&resolved)
        .map_err(|e| format!("{what} {}: {e}; refusing", resolved.display()))?
        .nlink();
    if links > 1 {
        return Err(format!(
            "{what} {} has {links} hard links, and another link could lie inside a write grant; \
             give it a single link; refusing",
            resolved.display()
        ));
    }
    Ok(())
}

/// The write grants to compare against: each entry as stated and, where it exists, resolved.
pub fn write_grants(profile: &crate::profile::Profile) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for (_, w) in profile.writes() {
        out.push(w.clone());
        if let Ok(r) = w.canonicalize() {
            out.push(r);
        }
    }
    out
}

/// Both checks `check` and `run` make: the profile file and the running executable.
pub fn check(profile: &crate::profile::Profile, profile_path: &Path) -> Result<(), String> {
    let grants = write_grants(profile);
    outside_write_grants("profile", profile_path, &grants, true)?;
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot locate the zwinger executable: {e}; refusing"))?;
    // No hard-link rule for the executable: Cargo hard-links build outputs, and the session
    // cannot create a cross-directory link (Landlock withholds REFER; Seatbelt refuses links to
    // files it cannot read), so a second link could only be the operator's own.
    outside_write_grants("zwinger executable", &exe, &grants, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tmp(tag: &str) -> Tmp {
        let d = std::env::temp_dir()
            .join(format!("zw-inputs-{tag}-{}", std::process::id()))
            .canonicalize()
            .unwrap_or_else(|_| {
                let d =
                    std::env::temp_dir().join(format!("zw-inputs-{tag}-{}", std::process::id()));
                std::fs::create_dir_all(&d).unwrap();
                d.canonicalize().unwrap()
            });
        std::fs::create_dir_all(d.join("w")).unwrap();
        std::fs::create_dir_all(d.join("safe")).unwrap();
        Tmp(d)
    }

    // rivet: verifies REQ-ZW-024
    #[test]
    fn a_file_inside_a_write_grant_is_refused_and_one_outside_is_not() {
        let t = tmp("in");
        let inside = t.0.join("w/profile.yaml");
        let outside = t.0.join("safe/profile.yaml");
        std::fs::write(&inside, "x").unwrap();
        std::fs::write(&outside, "x").unwrap();
        let grants = [t.0.join("w")];
        let e = outside_write_grants("profile", &inside, &grants, true).unwrap_err();
        assert!(e.contains("inside write grant"), "{e}");
        assert!(outside_write_grants("profile", &outside, &grants, true).is_ok());
    }

    // rivet: verifies REQ-ZW-024
    #[test]
    fn a_symlink_cannot_hide_a_file_inside_a_write_grant() {
        let t = tmp("link");
        let real = t.0.join("w/profile.yaml");
        std::fs::write(&real, "x").unwrap();
        let link = t.0.join("safe/profile.yaml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let grants = [t.0.join("w")];
        assert!(
            outside_write_grants("profile", &link, &grants, true).is_err(),
            "resolved inside"
        );
        // and a symlink inside the grant pointing outside is refused by its stated path
        let target = t.0.join("safe/real.yaml");
        std::fs::write(&target, "x").unwrap();
        let in_link = t.0.join("w/p.yaml");
        std::os::unix::fs::symlink(&target, &in_link).unwrap();
        assert!(
            outside_write_grants("profile", &in_link, &grants, true).is_err(),
            "stated inside"
        );
    }

    // rivet: verifies REQ-ZW-024
    #[test]
    fn a_file_with_a_second_hard_link_is_refused() {
        let t = tmp("hard");
        let f = t.0.join("safe/profile.yaml");
        std::fs::write(&f, "x").unwrap();
        assert!(outside_write_grants("profile", &f, &[t.0.join("w")], true).is_ok());
        std::fs::hard_link(&f, t.0.join("w/alias.yaml")).unwrap();
        let e = outside_write_grants("profile", &f, &[t.0.join("w")], true).unwrap_err();
        assert!(e.contains("2 hard links"), "{e}");
    }

    #[test]
    fn a_relative_path_is_compared_from_the_current_directory() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(absolute(Path::new("a/b")), normalize(&cwd.join("a/b")));
        assert_eq!(absolute(Path::new("/x/./y")), PathBuf::from("/x/y"));
    }
}
