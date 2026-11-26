use std::path::Path;
use std::process::ExitCode;
use zwinger::{EXIT_REFUSED, profile::Profile};

const USAGE: &str = "usage: zwinger check PROFILE\n       zwinger explain PROFILE PATH|tcp:PORT|udp:PORT\n       zwinger run PROFILE -- COMMAND [ARG...]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("check") if args.len() == 2 => match Profile::load(Path::new(&args[1])) {
            Ok(p) => {
                println!(
                    "zwinger: profile {} ok: {} readable, {} writable, {} read-denied, \
                     {} write-denied, {} hosts, {} mach services",
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
            Err(e) => refuse(&e.to_string()),
        },
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
            match Profile::load(Path::new(&args[1])) {
                Ok(p) => run(&p, &args[3], &args[4..]),
                Err(e) => refuse(&e.to_string()),
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
fn run(p: &Profile, cmd: &str, args: &[String]) -> ExitCode {
    use std::os::unix::process::CommandExt;
    let (enf, plan) = match zwinger::linux::confine(p) {
        Ok(c) => c,
        Err(e) => return refuse(&e),
    };
    eprintln!("{}", enf.summary(&p.name, &plan));
    // Only returns on failure; the session is already confined either way.
    let err = std::process::Command::new(cmd)
        .args(args)
        .env("ZWINGER_PROFILE", &p.name)
        .env("ZWINGER_ABI", enf.abi.to_string())
        .exec();
    eprintln!("zwinger: cannot exec {cmd}: {err}");
    ExitCode::from(if err.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    })
}

#[cfg(not(target_os = "linux"))]
fn run(_: &Profile, _: &str, _: &[String]) -> ExitCode {
    // Fail closed: never run a command unconfined because no backend exists yet.
    refuse("no enforcement backend on this platform yet; refusing to run unconfined")
}

fn refuse(why: &str) -> ExitCode {
    eprintln!("zwinger: refused: {why}");
    ExitCode::from(EXIT_REFUSED as u8)
}
