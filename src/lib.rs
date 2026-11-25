//! zwinger: confine an AI coding-agent session with supported OS mechanisms.
//!
//! Status: bootstrap. The profile and its fail-closed loading exist; no enforcement backend does
//! yet, so `run` refuses (REQ-ZW-001). Planned backends: macOS Endpoint Security descendant clients
//! (REQ-ZW-003, `bridge/`), Linux Landlock + seccomp (REQ-ZW-004).

pub mod profile;

/// Exit status when zwinger refuses to start a session (EX_CONFIG).
pub const EXIT_REFUSED: i32 = 78;
