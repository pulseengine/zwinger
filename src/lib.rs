//! zwinger: confine an AI coding-agent session with supported OS mechanisms.
//!
//! The profile and its fail-closed loading are in `profile` (REQ-ZW-001, REQ-ZW-002). The Linux
//! backend (Landlock plus a seccomp socket filter) is in `linux` (REQ-ZW-004..006, REQ-ZW-008).
//! The macOS backend is a Seatbelt prototype in `macos` (REQ-ZW-003, DD-ZW-007); the target is
//! an Endpoint Security descendants client (`bridge/`). Elsewhere `run` refuses.
//!
//! `events` writes one confinement event per `run` for warte's probe (REQ-ZW-014).

pub mod events;
pub mod linux;
pub mod macos;
pub mod pathrules;
pub mod profile;

/// Exit status when zwinger refuses to start a session (EX_CONFIG).
pub const EXIT_REFUSED: i32 = 78;
