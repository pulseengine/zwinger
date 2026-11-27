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

fn inside(what: &str, p: &Path, grants: &[PathBuf]) -> Result<(), String> {
    for g in grants {
        let g = normalize(g);
        if within(p, &g) {
            return Err(format!(
                "{what} {} lies inside write grant {}, so the session could change what the \
                 next run trusts; move it outside every write grant; refusing",
                p.display(),
                g.display()
            ));
        }
    }
    Ok(())
}

/// Refuse when `file` (named `what`) lies inside one of `grants` (stated and resolved write
/// grants), by its stated path or its resolved one. Returns the resolved path.
pub fn outside_write_grants(
    what: &str,
    file: &Path,
    grants: &[PathBuf],
) -> Result<PathBuf, String> {
    inside(what, &absolute(file), grants)?;
    let resolved = file
        .canonicalize()
        .map_err(|e| format!("{what} {}: {e}; refusing", file.display()))?;
    inside(what, &resolved, grants)?;
    Ok(resolved)
}

/// A profile read once: the parsed profile, the sha256 of exactly the bytes parsed, and the
/// identity of the file they came from.
pub struct Opened {
    pub profile: crate::profile::Profile,
    pub sha256: String,
    dev: u64,
    ino: u64,
    nlink: u64,
}

/// Open the profile once and parse, hash and identify that one file, so the file checked is the
/// file parsed even if the path is swapped meanwhile.
pub fn open_profile(path: &Path) -> Result<Opened, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let mut f = std::fs::File::open(path)
        .map_err(|e| crate::profile::ProfileError::Read(path.into(), e).to_string())?;
    let meta = f
        .metadata()
        .map_err(|e| format!("profile {}: {e}; refusing", path.display()))?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)
        .map_err(|e| crate::profile::ProfileError::Read(path.into(), e).to_string())?;
    let text = String::from_utf8(bytes.clone())
        .map_err(|_| format!("profile {} is not UTF-8; refusing", path.display()))?;
    let profile = crate::profile::Profile::parse(path, &text).map_err(|e| e.to_string())?;
    let sha256 = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(Opened {
        profile,
        sha256,
        dev: meta.dev(),
        ino: meta.ino(),
        nlink: meta.nlink(),
    })
}

/// `p` with every symlink along it resolved as far as the path exists, and the rest kept
/// lexically: a dangling symlink resolves to its target, so a directory that does not exist yet
/// is compared where it would be created.
fn resolve_lenient(p: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    let mut rest: Vec<std::ffi::OsString> = absolute(p)
        .components()
        .skip(1)
        .map(|c| c.as_os_str().to_owned())
        .collect();
    rest.reverse();
    let mut hops = 0;
    while let Some(c) = rest.pop() {
        if c == ".." {
            out.pop();
            continue;
        }
        if c == "." {
            continue;
        }
        let next = out.join(&c);
        match std::fs::read_link(&next) {
            Ok(target) if hops < 40 => {
                hops += 1;
                let target = if target.is_absolute() {
                    target
                } else {
                    out.join(target)
                };
                let mut parts: Vec<std::ffi::OsString> = normalize(&target)
                    .components()
                    .skip(1)
                    .map(|c| c.as_os_str().to_owned())
                    .collect();
                parts.reverse();
                rest.extend(parts);
                out = PathBuf::from("/");
            }
            _ => out = next,
        }
    }
    normalize(&out)
}

/// The invocation path: argv[0] as given, or, without a slash, the PATH directories searched up
/// to the one that holds it. A symlink or an earlier PATH entry inside a write grant would let
/// the session choose what the next invocation runs.
fn invocation_outside_write_grants(grants: &[PathBuf]) -> Result<(), String> {
    let Some(arg0) = std::env::args_os().next() else {
        return Ok(());
    };
    let arg0 = PathBuf::from(arg0);
    if arg0.as_os_str().is_empty() {
        return Ok(());
    }
    if arg0.components().count() > 1 {
        outside_write_grants("zwinger invocation path", &arg0, grants)?;
        return Ok(());
    }
    let Some(path) = std::env::var_os("PATH") else {
        return Ok(());
    };
    for dir in std::env::split_paths(&path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        // Each directory searched, by its stated and its resolved path.
        inside(
            "PATH directory searched for zwinger",
            &absolute(&dir),
            grants,
        )?;
        // Resolved leniently: a directory, or a symlink to one, that does not exist yet could be
        // created later inside a grant, so a missing tail is kept and checked too.
        inside(
            "PATH directory searched for zwinger",
            &resolve_lenient(&dir),
            grants,
        )?;
        // The shell's search: the first regular file with an execute bit, as execvp takes it.
        // (execvp asks access(X_OK); the mode bits differ only for ACLs or an exec bit for
        // others alone, and every directory up to the one holding zwinger is checked either way.)
        let candidate = dir.join(&arg0);
        let executable = std::fs::metadata(&candidate).is_ok_and(|m| {
            use std::os::unix::fs::PermissionsExt;
            m.is_file() && m.permissions().mode() & 0o111 != 0
        });
        if executable {
            outside_write_grants("zwinger invocation path", &candidate, grants)?;
            break;
        }
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

/// The checks `check` and `run` make before anything is confined: the profile file (the one
/// `opened` read, by identity, with a single link), the running executable and the path it was
/// invoked by.
pub fn check(opened: &Opened, profile_path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let grants = write_grants(&opened.profile);
    let resolved = outside_write_grants("profile", profile_path, &grants)?;
    let now = std::fs::metadata(&resolved)
        .map_err(|e| format!("profile {}: {e}; refusing", resolved.display()))?;
    if (now.dev(), now.ino()) != (opened.dev, opened.ino) {
        return Err(format!(
            "profile {} changed while zwinger read it; refusing",
            resolved.display()
        ));
    }
    if opened.nlink > 1 {
        return Err(format!(
            "profile {} has {} hard links, and another link could lie inside a write grant; \
             give it a single link; refusing",
            resolved.display(),
            opened.nlink
        ));
    }
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot locate the zwinger executable: {e}; refusing"))?;
    // No hard-link rule for the executable: Cargo hard-links build outputs, and the session
    // cannot create a cross-directory link (Landlock withholds REFER; Seatbelt refuses links to
    // files it cannot read), so a second link could only be the operator's own.
    outside_write_grants("zwinger executable", &exe, &grants)?;
    invocation_outside_write_grants(&grants)
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
        let e = outside_write_grants("profile", &inside, &grants).unwrap_err();
        assert!(e.contains("inside write grant"), "{e}");
        assert!(outside_write_grants("profile", &outside, &grants).is_ok());
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
            outside_write_grants("profile", &link, &grants).is_err(),
            "resolved inside"
        );
        // and a symlink inside the grant pointing outside is refused by its stated path
        let target = t.0.join("safe/real.yaml");
        std::fs::write(&target, "x").unwrap();
        let in_link = t.0.join("w/p.yaml");
        std::os::unix::fs::symlink(&target, &in_link).unwrap();
        assert!(
            outside_write_grants("profile", &in_link, &grants).is_err(),
            "stated inside"
        );
    }

    // rivet: verifies REQ-ZW-024
    #[test]
    fn a_profile_with_a_second_hard_link_is_refused() {
        let t = tmp("hard");
        let f = t.0.join("safe/profile.yaml");
        let text = format!(
            "name: \"h\"\nwrite: [{:?}]\n",
            t.0.join("w").to_str().unwrap()
        );
        std::fs::write(&f, &text).unwrap();
        let opened = open_profile(&f).unwrap();
        assert!(check(&opened, &f).is_ok(), "{:?}", check(&opened, &f));
        std::fs::hard_link(&f, t.0.join("w/alias.yaml")).unwrap();
        let opened = open_profile(&f).unwrap();
        let e = check(&opened, &f).unwrap_err();
        assert!(e.contains("2 hard links"), "{e}");
    }

    // rivet: verifies REQ-ZW-024
    #[test]
    fn a_profile_swapped_after_it_was_read_is_refused() {
        let t = tmp("swap");
        let f = t.0.join("safe/profile.yaml");
        let text = format!(
            "name: \"s\"\nwrite: [{:?}]\n",
            t.0.join("w").to_str().unwrap()
        );
        std::fs::write(&f, &text).unwrap();
        let opened = open_profile(&f).unwrap();
        // Replace the file at the path with a different one before the check.
        let other = t.0.join("safe/other.yaml");
        std::fs::write(&other, &text).unwrap();
        std::fs::rename(&other, &f).unwrap();
        let e = check(&opened, &f).unwrap_err();
        assert!(e.contains("changed while zwinger read it"), "{e}");
    }

    #[test]
    fn the_hash_is_of_the_bytes_parsed() {
        use sha2::{Digest, Sha256};
        let t = tmp("hash");
        let f = t.0.join("safe/profile.yaml");
        std::fs::write(&f, "name: \"x\"\n").unwrap();
        let opened = open_profile(&f).unwrap();
        let want: String = Sha256::digest(b"name: \"x\"\n")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(opened.sha256, want);
        assert_eq!(opened.profile.name, "x");
    }

    // rivet: verifies REQ-ZW-024
    #[test]
    fn a_dangling_symlink_resolves_to_where_its_target_would_be() {
        let t = tmp("dangle");
        let link = t.0.join("safe/bin");
        std::os::unix::fs::symlink(t.0.join("w/later/bin"), &link).unwrap();
        assert_eq!(resolve_lenient(&link), t.0.join("w/later/bin"));
        assert!(inside("PATH directory", &resolve_lenient(&link), &[t.0.join("w")]).is_err());
        // relative targets and .. resolve against the link's directory
        let rel = t.0.join("safe/rel");
        std::os::unix::fs::symlink("../w/x", &rel).unwrap();
        assert_eq!(resolve_lenient(&rel), t.0.join("w/x"));
        // an existing path resolves like canonicalize
        assert_eq!(
            resolve_lenient(&t.0.join("safe")),
            t.0.join("safe").canonicalize().unwrap()
        );
    }

    #[test]
    fn a_relative_path_is_compared_from_the_current_directory() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(absolute(Path::new("a/b")), normalize(&cwd.join("a/b")));
        assert_eq!(absolute(Path::new("/x/./y")), PathBuf::from("/x/y"));
    }
}
