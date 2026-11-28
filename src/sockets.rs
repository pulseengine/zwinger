//! The per-session socket directory (REQ-ZW-027).
//!
//! While UNIX sockets are confined, the session may connect only to sockets in this directory
//! and in the profile's `unix_socket_dirs`, not to sockets elsewhere in its write trees, which
//! could belong to servers outside the session. `run` creates the directory before confining
//! and passes it to the command as ZWINGER_SOCKET_DIR, so the session's own processes have a
//! place to meet.

use std::path::PathBuf;

/// The environment variable that names the directory for the command.
pub const VAR: &str = "ZWINGER_SOCKET_DIR";

/// Create a fresh, private (0700) directory and return its resolved path. It lies outside every
/// write grant in `write_grants` (resolved): inside one, the grant's rights would let the session
/// move or hard-link a foreign socket from a write tree into the directory and connect to it
/// there. The first base outside every write grant is used: $XDG_RUNTIME_DIR, the temp
/// directory, /tmp, /var/tmp. The name is short because a UNIX socket path must fit in 104 bytes
/// on macOS.
pub fn session_dir(write_grants: &[PathBuf]) -> Result<PathBuf, String> {
    fresh_dir(write_grants, "zw", "socket directory")
}

/// The variable that names the per-session temporary directory for the command.
pub const TMP_VAR: &str = "TMPDIR";

/// The per-session temporary directory (REQ-ZW-045): created like the socket directory, outside
/// every write grant, and then granted to the session as its TMPDIR. Outside every other grant,
/// it is a place no unconfined process of the user looks for files.
pub fn session_tmp_dir(write_grants: &[PathBuf]) -> Result<PathBuf, String> {
    fresh_dir(write_grants, "zwt", "session temporary directory")
}

fn fresh_dir(write_grants: &[PathBuf], prefix: &str, what: &str) -> Result<PathBuf, String> {
    let mut bases: Vec<PathBuf> = Vec::new();
    if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR") {
        bases.push(PathBuf::from(x));
    }
    bases.push(std::env::temp_dir());
    bases.push(PathBuf::from("/tmp"));
    bases.push(PathBuf::from("/var/tmp"));
    let granted = |p: &std::path::Path| write_grants.iter().any(|g| crate::profile::within(p, g));
    let mut failures = Vec::new();
    // Each base by its resolved path, and the directory created there checked again, so a
    // symlink swapped in between cannot place it inside a grant.
    for base in bases.iter().filter_map(|b| b.canonicalize().ok()) {
        if granted(&base) {
            continue;
        }
        match create_in(&base, prefix, what) {
            Ok(d) if !granted(&d) => return Ok(d),
            Ok(d) => {
                let _ = std::fs::remove_dir(&d);
                failures.push(format!(
                    "{what} {} resolved inside a write grant; refusing",
                    d.display()
                ));
            }
            Err(e) => failures.push(e),
        }
    }
    Err(if failures.is_empty() {
        format!(
            "no place for the {what} outside every write grant ($XDG_RUNTIME_DIR, the temp \
             directory, /tmp and /var/tmp are all granted or missing); refusing"
        )
    } else {
        failures.join("; ")
    })
}

fn create_in(base: &std::path::Path, prefix: &str, what: &str) -> Result<PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt;
    let base = base.to_path_buf();
    let pid = std::process::id();
    for n in 0..64u32 {
        let d = base.join(format!("{prefix}-{pid}-{n}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&d) {
            Ok(()) => {
                return d
                    .canonicalize()
                    .map_err(|e| format!("{what} {}: {e}; refusing", d.display()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "cannot create a {what} in {}: {e}; refusing",
                    base.display()
                ));
            }
        }
    }
    Err(format!(
        "cannot create a {what} in {}: 64 names taken; refusing",
        base.display()
    ))
}

/// UNIX sockets that already exist in `trees`, for `zwinger check` to warn about: they belong to
/// servers outside the session, which a session could not connect to once confined, but which a
/// profile author may not expect inside a write grant. Bounded: at most `max_depth` levels and
/// `max_entries` directory entries in all, so a large tree does not stall `check`.
pub fn existing_sockets(
    trees: &[std::path::PathBuf],
    max_depth: usize,
    max_entries: usize,
) -> Vec<std::path::PathBuf> {
    use std::os::unix::fs::FileTypeExt;
    let mut out = Vec::new();
    let mut seen = 0usize;
    let mut stack: Vec<(std::path::PathBuf, usize)> =
        trees.iter().map(|t| (t.clone(), 0)).collect();
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            seen += 1;
            if seen > max_entries {
                return out;
            }
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_socket() {
                out.push(e.path());
            } else if ft.is_dir() && depth + 1 < max_depth {
                stack.push((e.path(), depth + 1));
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_sockets_are_listed_within_the_bounds() {
        let d = session_dir(&[]).unwrap();
        std::fs::create_dir_all(d.join("a/b/c")).unwrap();
        let _s1 = std::os::unix::net::UnixListener::bind(d.join("a/s1")).unwrap();
        let _s2 = std::os::unix::net::UnixListener::bind(d.join("a/b/c/s2")).unwrap();
        std::fs::write(d.join("a/f"), "x").unwrap();
        assert_eq!(
            existing_sockets(std::slice::from_ref(&d), 2, 1000),
            vec![d.join("a/s1")]
        );
        assert_eq!(
            existing_sockets(std::slice::from_ref(&d), 4, 1000),
            vec![d.join("a/b/c/s2"), d.join("a/s1")]
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_directory_is_never_inside_a_write_grant() {
        let tmp = std::env::temp_dir().canonicalize().unwrap();
        let d = session_dir(std::slice::from_ref(&tmp)).unwrap();
        assert!(
            !crate::profile::within(&d, &tmp),
            "{} inside the granted {}",
            d.display(),
            tmp.display()
        );
        let _ = std::fs::remove_dir(&d);
        let all = [PathBuf::from("/")];
        assert!(
            session_dir(&all)
                .unwrap_err()
                .contains("outside every write grant")
        );
    }

    #[test]
    fn the_directory_is_fresh_private_and_resolved() {
        use std::os::unix::fs::PermissionsExt;
        let a = session_dir(&[]).unwrap();
        let b = session_dir(&[]).unwrap();
        assert_ne!(a, b, "each call makes a new directory");
        assert_eq!(a, a.canonicalize().unwrap());
        assert_eq!(
            std::fs::metadata(&a).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let _ = std::fs::remove_dir(&a);
        let _ = std::fs::remove_dir(&b);
    }
}
