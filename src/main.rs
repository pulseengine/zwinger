use std::path::Path;
use std::process::ExitCode;
use zwinger::events::{self, Event};
use zwinger::{EXIT_REFUSED, profile::Profile};

const USAGE: &str = "usage: zwinger check PROFILE\n       zwinger explain PROFILE PATH|tcp:PORT|udp:PORT\n       zwinger run PROFILE -- COMMAND [ARG...]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("check") if args.len() == 2 => {
            match zwinger::inputs::open_profile(Path::new(&args[1])) {
                Ok(o) => match zwinger::inputs::check(&o, Path::new(&args[1])) {
                    Ok(()) => check(&o.profile),
                    Err(e) => refuse(&e),
                },
                Err(e) => refuse(&e),
            }
        }
        Some("explain") if args.len() == 3 => match Profile::load(Path::new(&args[1])) {
            Ok(p) => match zwinger::linux::plan(&p) {
                Ok(plan) => {
                    for line in zwinger::linux::explain(&p, &plan, &args[2]) {
                        println!("{line}");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => refuse(&e),
            },
            Err(e) => refuse(&e.to_string()),
        },
        Some("run") if args.len() >= 4 && args[2] == "--" => {
            let path = Path::new(&args[1]);
            match zwinger::inputs::open_profile(path) {
                Ok(o) => run(&o, path, &args[3], &args[4..]),
                Err(e) => {
                    let sha = events::sha256_file(path);
                    events::end(events::begin(&[]), &Event::refused(None, sha, "profile"));
                    refuse(&e)
                }
            }
        }
        Some("--version" | "-V") => {
            println!("zwinger {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            // pulseengine CLI convention: an unknown flag or command exits 2, usage on stderr.
            ExitCode::from(2)
        }
    }
}

#[cfg(target_os = "linux")]
fn run(opened: &zwinger::inputs::Opened, path: &Path, cmd: &str, args: &[String]) -> ExitCode {
    let p = &opened.profile;
    use std::os::unix::process::CommandExt;
    use zwinger::profile::NetworkMode;
    // Open the event file and hash the profile before confining: afterwards neither path is
    // reachable, while the open descriptor stays writable.
    // No event where the session could forge it: a write grant covering the events dir.
    let grants: Vec<std::path::PathBuf> = p
        .writes()
        .filter_map(|(_, w)| w.canonicalize().ok())
        .collect();
    let pending = events::begin(&grants);
    let sha = Some(opened.sha256.clone());
    // The profile and this executable are what the next run trusts: refuse them inside a
    // write grant (REQ-ZW-024).
    if let Err(e) = zwinger::inputs::check(opened, path) {
        events::end(
            pending,
            &Event::refused(Some(p.name.clone()), sha, "profile"),
        );
        return refuse(&e);
    }
    let socket_dir = match zwinger::sockets::session_dir() {
        Ok(d) => d,
        Err(e) => {
            events::end(pending, &Event::refused(Some(p.name.clone()), sha, "path"));
            return refuse(&e);
        }
    };
    let (enf, plan) = match zwinger::linux::confine(p, &socket_dir) {
        Ok(c) => c,
        Err(e) => {
            let ev = Event::refused(Some(p.name.clone()), sha, events::category(&e));
            events::end(pending, &ev);
            return refuse(&e);
        }
    };
    // The plan for the command (ZWINGER_GRANTS). A plan JSON cannot carry is refused, before
    // anything is exec'd.
    let grants_json = match zwinger::linux::session_grants(p, &plan).to_json() {
        Ok(g) => g,
        Err(e) => {
            events::end(pending, &Event::refused(Some(p.name.clone()), sha, "path"));
            return refuse(&e);
        }
    };
    let network = match enf.network {
        NetworkMode::None => "none",
        NetworkMode::Unfiltered => "unfiltered",
    };
    let ev = Event::confined(
        p.name.clone(),
        sha,
        Some(enf.abi),
        network,
        enf.not_enforced().into_iter().map(String::from).collect(),
        plan.read.len(),
        plan.write.len(),
        plan.skipped.len(),
    );
    events::end(pending, &ev);
    let mut command = std::process::Command::new(cmd);
    let removed = scrub_env(&mut command, &p.env_keep);
    eprintln!("{}{removed}", enf.summary(&p.name, &plan));
    // Only returns on failure; the session is already confined either way.
    let err = command
        .args(args)
        .env("ZWINGER_PROFILE", &p.name)
        .env("ZWINGER_ABI", enf.abi.to_string())
        .env(zwinger::grants::VAR, &grants_json)
        .env(zwinger::sockets::VAR, &socket_dir)
        .exec();
    eprintln!("zwinger: cannot exec {cmd}: {err}");
    ExitCode::from(if err.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn run(_: &zwinger::inputs::Opened, _: &Path, _: &str, _: &[String]) -> ExitCode {
    // Fail closed: never run a command unconfined because no backend exists yet.
    refuse("no enforcement backend on this platform yet; refusing to run unconfined")
}

/// `check` on Linux is `run` without confining or exec: the same plan, the same kernel ABI
/// test, the same refusals. A pre-flight check that passes means `run` will confine.
#[cfg(target_os = "linux")]
fn check(p: &Profile) -> ExitCode {
    match zwinger::linux::preflight(p) {
        Ok((enf, plan)) => {
            println!("zwinger: profile {} ok", p.name);
            println!(
                "{}",
                enf.summary(&p.name, &plan)
                    .replacen(" confined:", " would be confined:", 1)
            );
            warn_existing_sockets(plan.write.iter().map(|g| g.resolved.clone()).collect());
            ExitCode::SUCCESS
        }
        Err(e) => refuse(&e),
    }
}

/// Without a backend only the profile itself can be checked; say that paths were not.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn check(p: &Profile) -> ExitCode {
    println!(
        "zwinger: profile {} ok: {} readable, {} writable, {} read-denied, {} write-denied, \
         {} hosts, {} mach services; paths not checked (no enforcement backend on this platform)",
        p.name,
        p.read.len(),
        p.write.len(),
        p.deny_read.len(),
        p.deny_write.len(),
        p.network.allow.len(),
        p.mach_lookup.len()
    );
    ExitCode::SUCCESS
}

/// macOS (Seatbelt prototype): apply the policy, then exec, as on Linux.
#[cfg(target_os = "macos")]
fn run(opened: &zwinger::inputs::Opened, path: &Path, cmd: &str, args: &[String]) -> ExitCode {
    let p = &opened.profile;
    use std::os::unix::process::CommandExt;
    use zwinger::profile::NetworkMode;
    // As on Linux: open the event file and hash the profile before confining.
    let grants: Vec<std::path::PathBuf> = p
        .writes()
        .filter_map(|(_, w)| w.canonicalize().ok())
        .collect();
    let pending = events::begin(&grants);
    let sha = Some(opened.sha256.clone());
    // The profile and this executable are what the next run trusts: refuse them inside a
    // write grant (REQ-ZW-024).
    if let Err(e) = zwinger::inputs::check(opened, path) {
        events::end(
            pending,
            &Event::refused(Some(p.name.clone()), sha, "profile"),
        );
        return refuse(&e);
    }
    let socket_dir = match zwinger::sockets::session_dir() {
        Ok(d) => d,
        Err(e) => {
            events::end(pending, &Event::refused(Some(p.name.clone()), sha, "path"));
            return refuse(&e);
        }
    };
    let plan = match zwinger::macos::confine(p, &socket_dir) {
        Ok(plan) => plan,
        Err(e) => {
            let ev = Event::refused(Some(p.name.clone()), sha, events::category(&e));
            events::end(pending, &ev);
            return refuse(&e);
        }
    };
    let grants_json = match zwinger::macos::session_grants(&plan).to_json() {
        Ok(g) => g,
        Err(e) => {
            events::end(pending, &Event::refused(Some(p.name.clone()), sha, "path"));
            return refuse(&e);
        }
    };
    let network = match p.network.mode {
        NetworkMode::None => "none",
        NetworkMode::Unfiltered => "unfiltered",
    };
    let ev = Event::confined(
        p.name.clone(),
        sha,
        None,
        network,
        zwinger::macos::not_enforced(p)
            .into_iter()
            .map(String::from)
            .collect(),
        plan.read.len(),
        plan.write.len(),
        plan.skipped.len(),
    );
    events::end(pending, &ev);
    let mut command = std::process::Command::new(cmd);
    let removed = scrub_env(&mut command, &p.env_keep);
    eprintln!("{}{removed}", zwinger::macos::summary(p, &plan));
    // Only returns on failure; the session is already confined either way.
    let err = command
        .args(args)
        .env("ZWINGER_PROFILE", &p.name)
        .env(zwinger::grants::VAR, &grants_json)
        .env(zwinger::sockets::VAR, &socket_dir)
        .exec();
    eprintln!("zwinger: cannot exec {cmd}: {err}");
    ExitCode::from(if err.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    })
}

/// `check` on macOS is `run` without `sandbox_init` or exec: the same plan and policy.
#[cfg(target_os = "macos")]
fn check(p: &Profile) -> ExitCode {
    match zwinger::macos::preflight(p) {
        Ok((plan, _)) => {
            println!("zwinger: profile {} ok", p.name);
            println!(
                "{}",
                zwinger::macos::summary(p, &plan).replacen(" confined:", " would be confined:", 1)
            );
            warn_existing_sockets(plan.write.iter().map(|g| g.resolved.clone()).collect());
            ExitCode::SUCCESS
        }
        Err(e) => refuse(&e),
    }
}

/// Remove the scrubbed variables (src/env.rs) that are set and not kept by the profile, and
/// return the startup line's note naming them ("" when nothing was removed).
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn scrub_env(command: &mut std::process::Command, keep: &[String]) -> String {
    let names: Vec<String> = std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .collect();
    let removed = zwinger::env::to_remove(names.iter().map(String::as_str), keep);
    for name in &removed {
        command.env_remove(name);
    }
    if removed.is_empty() {
        String::new()
    } else {
        format!("; environment removed: {}", removed.join(", "))
    }
}

/// `check` only: UNIX sockets already present in write trees. Once confined, the session cannot
/// connect to them unless their directory is listed in `unix_socket_dirs` (REQ-ZW-027).
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn warn_existing_sockets(write_trees: Vec<std::path::PathBuf>) {
    for s in zwinger::sockets::existing_sockets(&write_trees, 3, 10_000) {
        println!(
            "zwinger: warning: unix socket {} lies in a write tree; the session cannot connect to it \
             unless its directory is in unix_socket_dirs",
            s.display()
        );
    }
}

fn refuse(why: &str) -> ExitCode {
    eprintln!("zwinger: refused: {why}");
    ExitCode::from(EXIT_REFUSED as u8)
}
