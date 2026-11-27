//! Environment variables zwinger removes before it execs the command (REQ-ZW-022).
//!
//! Each one makes a program load or run code it was not asked to: a dynamic-loader injection,
//! a shell startup file, or a wrapper a build or VCS tool runs. Removing them means the session
//! starts without settings inherited from the shell that launched zwinger. A profile keeps one
//! by naming it in `env_keep`.
//!
//! What this does not do: the agent can still set any of them for the processes it starts.
//! Those children stay confined by the kernel sandbox; a capability shell such as kapsel
//! applies its own allowlist to what it passes to native tools.

/// Removed by exact name.
pub const SCRUB: &[&str] = &[
    // glibc and musl dynamic loader
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    // shell startup files and hooks
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
    "PROMPT_COMMAND",
    // build and VCS wrappers that run another program
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_EXEC_PATH",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
];

/// Removed by prefix: every macOS dyld variable (DYLD_INSERT_LIBRARIES, DYLD_LIBRARY_PATH, ...).
pub const SCRUB_PREFIXES: &[&str] = &["DYLD_"];

/// Whether `name` is on the scrub list.
pub fn scrubbed(name: &str) -> bool {
    SCRUB.contains(&name) || SCRUB_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// The variables to remove from `present`, in sorted order: scrubbed and not kept.
pub fn to_remove<'a>(present: impl IntoIterator<Item = &'a str>, keep: &[String]) -> Vec<String> {
    let mut out: Vec<String> = present
        .into_iter()
        .filter(|n| scrubbed(n) && !keep.iter().any(|k| k == n))
        .map(String::from)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// An `env_keep` entry must name a variable on the scrub list. Anything else would keep nothing,
/// so it is refused as the likely typo it is.
pub fn validate_keep(keep: &[String]) -> Result<(), String> {
    for k in keep {
        if !scrubbed(k) {
            return Err(format!(
                "env_keep: {k:?} is not a variable zwinger removes, so keeping it does nothing; \
                 the list is in docs/profile.md"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injection_variables_are_removed_and_ordinary_ones_kept() {
        let present = [
            "PATH",
            "HOME",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "BASH_ENV",
            "TERM",
        ];
        assert_eq!(
            to_remove(present, &[]),
            ["BASH_ENV", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD"]
        );
    }

    #[test]
    fn env_keep_keeps_a_named_variable() {
        let present = ["LD_LIBRARY_PATH", "LD_PRELOAD"];
        assert_eq!(
            to_remove(present, &["LD_LIBRARY_PATH".to_string()]),
            ["LD_PRELOAD"]
        );
    }

    #[test]
    fn a_dyld_prefix_matches_every_dyld_variable_but_not_a_lookalike() {
        assert!(scrubbed("DYLD_LIBRARY_PATH"));
        assert!(scrubbed("DYLD_FRAMEWORK_PATH"));
        assert!(!scrubbed("XDYLD_X"));
        assert!(!scrubbed("LD_PRELOADX"));
        assert!(
            !scrubbed("ld_preload"),
            "names are case-sensitive, as the loader reads them"
        );
    }

    #[test]
    fn env_keep_refuses_a_name_that_is_not_scrubbed() {
        assert!(validate_keep(&["LD_PRELOAD".into(), "DYLD_X".into()]).is_ok());
        let e = validate_keep(&["PATH".into()]).unwrap_err();
        assert!(e.contains("PATH"), "{e}");
        assert!(validate_keep(&["LD_PRELOADX".into()]).is_err());
    }
}
