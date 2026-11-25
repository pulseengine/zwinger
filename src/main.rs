use std::path::Path;
use std::process::ExitCode;
use zwinger::{EXIT_REFUSED, profile::Profile};

const USAGE: &str = "usage: zwinger check PROFILE\n       zwinger run PROFILE -- COMMAND [ARG...]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("check") if args.len() == 2 => match Profile::load(Path::new(&args[1])) {
            Ok(p) => {
                println!(
                    "zwinger: profile {} ok: {} writable, {} denied, {} hosts, {} mach services",
                    p.name,
                    p.write.len(),
                    p.deny_read.len(),
                    p.network.allow.len(),
                    p.mach_lookup.len()
                );
                ExitCode::SUCCESS
            }
            Err(e) => refuse(&e.to_string()),
        },
        Some("run") if args.len() >= 4 && args[2] == "--" => {
            if let Err(e) = Profile::load(Path::new(&args[1])) {
                return refuse(&e.to_string());
            }
            // Fail closed: never run a command unconfined because no backend exists yet.
            refuse("no enforcement backend on this platform yet; refusing to run unconfined")
        }
        Some("--version") => {
            println!("zwinger {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(64)
        }
    }
}

fn refuse(why: &str) -> ExitCode {
    eprintln!("zwinger: refused: {why}");
    ExitCode::from(EXIT_REFUSED as u8)
}
