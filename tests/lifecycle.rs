//! The binary follows the lifecycle the architecture model states (REQ-ZW-023).
//!
//! architecture/expected/lifecycle.smv is spar's export of the session's mode transitions
//! (`spar modes --format smv`); CI's architecture job regenerates it from the model and fails on
//! a diff. This test runs real sessions, reads what each one did from its event and its exit
//! status, maps that onto modes, and requires every step to be a transition in that relation:
//!
//! - an event `refused` with category `profile`: loading -> refused;
//! - any other refusal: loading -> preflight -> refused;
//! - an event `confined`: loading -> preflight -> confined -> exited (a child exit, or exec
//!   failing with 126 or 127 after confinement).
//!
//! The exit status must agree with the event: a refused session exits 78, and a confined one
//! never does. A disagreement becomes a step the model forbids (refused -> confined, or
//! confined -> refused), so a binary that runs a command it reported as refused fails here.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

const ZWINGER: &str = env!("CARGO_BIN_EXE_zwinger");
const REFUSED: i32 = 78;

/// The model's transition relation: (from, to) pairs, plus the initial mode.
struct Relation {
    initial: String,
    steps: BTreeSet<(String, String)>,
}

/// Parse the session module of spar's NuSMV export: `INIT state = X` and the `TRANS case` lines
/// `state = A : next(state) = B;` or `state = A : next(state) in {B, C};`. The catch-all
/// `TRUE : next(state) = state;` is the stuttering step, not a transition.
fn relation(smv: &str) -> Relation {
    let mut initial = None;
    let mut steps = BTreeSet::new();
    let mut in_trans = false;
    for line in smv.lines().map(str::trim) {
        if let Some(rest) = line
            .strip_prefix("state = ")
            .filter(|_| initial.is_none() && !in_trans)
        {
            initial = Some(rest.trim().to_string());
            continue;
        }
        if line == "TRANS" {
            in_trans = true;
            continue;
        }
        if line == "esac" {
            in_trans = false;
            continue;
        }
        if !in_trans || line.starts_with("TRUE") {
            continue;
        }
        let Some((from, to)) = line
            .strip_prefix("state = ")
            .and_then(|l| l.split_once(" : next(state) "))
        else {
            continue;
        };
        let to = to.trim_end_matches(';').trim();
        let targets: Vec<&str> = if let Some(set) = to.strip_prefix("in {") {
            set.trim_end_matches('}')
                .split(',')
                .map(str::trim)
                .collect()
        } else {
            vec![to.trim_start_matches("= ").trim()]
        };
        for t in targets {
            steps.insert((from.trim().to_string(), t.to_string()));
        }
    }
    Relation {
        initial: initial.expect("INIT state = ... in the export"),
        steps,
    }
}

fn model() -> Relation {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("architecture/expected/lifecycle.smv");
    let r = relation(&std::fs::read_to_string(&path).unwrap());
    assert!(
        !r.steps.is_empty(),
        "no transitions read from {}",
        path.display()
    );
    r
}

/// The modes a session went through, from its event and exit status.
fn observed(verdict: &str, category: Option<&str>, exit: Option<i32>) -> Vec<&'static str> {
    let mut path = vec!["loading"];
    match verdict {
        "refused" => {
            if category != Some("profile") {
                path.push("preflight");
            }
            path.push("refused");
            if exit != Some(REFUSED) {
                path.push("confined"); // it ran something after refusing
            }
        }
        "confined" => {
            path.extend(["preflight", "confined"]);
            if exit == Some(REFUSED) {
                path.push("refused"); // it refused after confining
            } else {
                path.push("exited");
            }
        }
        other => panic!("unknown verdict {other:?}"),
    }
    path
}

fn conforms(r: &Relation, path: &[&str]) -> Result<(), String> {
    if path.first() != Some(&r.initial.as_str()) {
        return Err(format!(
            "starts in {:?}, the model starts in {}",
            path.first(),
            r.initial
        ));
    }
    for w in path.windows(2) {
        if !r.steps.contains(&(w[0].to_string(), w[1].to_string())) {
            return Err(format!(
                "{} -> {} is not a transition of the model",
                w[0], w[1]
            ));
        }
    }
    Ok(())
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> Scratch {
    static N: AtomicU32 = AtomicU32::new(0);
    let d = std::env::temp_dir().join(format!(
        "zw-life-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(d.join("events")).unwrap();
    std::fs::create_dir_all(d.join("w")).unwrap();
    Scratch(d)
}

/// Run `zwinger run` on `profile` and return (verdict, category, exit status) from its event.
fn session(profile: &str, cmd: &[&str]) -> (String, Option<String>, Option<i32>) {
    let s = scratch();
    let text = profile.replace('@', s.0.to_str().unwrap());
    let p = s.0.join("profile.yaml");
    std::fs::write(&p, text).unwrap();
    let o = Command::new(ZWINGER)
        .env("ZWINGER_EVENTS_DIR", s.0.join("events"))
        .arg("run")
        .arg(&p)
        .arg("--")
        .args(cmd)
        .output()
        .unwrap();
    let events: Vec<PathBuf> = std::fs::read_dir(s.0.join("events"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(
        events.len(),
        1,
        "one event per run; stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let v: serde_json::Value =
        rivet_yaml::from_str(&std::fs::read_to_string(&events[0]).unwrap()).unwrap();
    (
        v["verdict"].as_str().unwrap().to_string(),
        v["category"].as_str().map(String::from),
        o.status.code(),
    )
}

/// A profile both backends confine: system trees readable, one scratch tree writable.
const GOOD: &str = "name: \"life\"\nread: [\"/usr\", \"/bin\"]\n\
    read_if_present: [\"/lib\", \"/lib64\", \"/etc\", \"/System\", \"/Library\", \"/private/etc\"]\n\
    write: [\"@/w\"]\n";

fn check(name: &str, profile: &str, cmd: &[&str], want: &[&str]) {
    let (verdict, category, exit) = session(profile, cmd);
    let path = observed(&verdict, category.as_deref(), exit);
    assert_eq!(
        path, want,
        "{name}: verdict {verdict}, category {category:?}, exit {exit:?}"
    );
    conforms(&model(), &path).unwrap_or_else(|e| panic!("{name}: {e}"));
}

// rivet: verifies REQ-ZW-023
#[test]
fn a_malformed_profile_is_refused_while_loading() {
    check(
        "unknown key",
        "name: \"life\"\nallow_all: true\n",
        &["/usr/bin/true"],
        &["loading", "refused"],
    );
}

// rivet: verifies REQ-ZW-023
#[test]
fn a_missing_grant_is_refused_in_preflight() {
    check(
        "missing write grant",
        "name: \"life\"\nread: [\"/usr\"]\nwrite: [\"@/absent\"]\n",
        &["/usr/bin/true"],
        &["loading", "preflight", "refused"],
    );
}

// rivet: verifies REQ-ZW-023
#[test]
fn a_confined_command_runs_and_exits() {
    check(
        "true",
        GOOD,
        &["/usr/bin/true"],
        &["loading", "preflight", "confined", "exited"],
    );
    check(
        "false",
        GOOD,
        &["/usr/bin/false"],
        &["loading", "preflight", "confined", "exited"],
    );
}

// rivet: verifies REQ-ZW-023
#[test]
fn exec_failure_happens_after_confinement() {
    let (verdict, _, exit) = session(GOOD, &["/nonexistent-zwinger-command"]);
    assert_eq!((verdict.as_str(), exit), ("confined", Some(127)));
    conforms(&model(), &observed(&verdict, None, exit)).unwrap();
}

// The mapping and the parser themselves.

#[test]
fn the_export_parses_to_the_models_transitions() {
    let r = model();
    assert_eq!(r.initial, "loading");
    let want: BTreeSet<(String, String)> = [
        ("loading", "preflight"),
        ("loading", "refused"),
        ("preflight", "confined"),
        ("preflight", "refused"),
        ("confined", "exited"),
    ]
    .iter()
    .map(|(a, b)| (a.to_string(), b.to_string()))
    .collect();
    assert_eq!(r.steps, want);
}

#[test]
fn a_session_that_runs_after_refusing_does_not_conform() {
    let r = model();
    let ran = observed("refused", Some("path"), Some(0));
    assert_eq!(
        conforms(&r, &ran).unwrap_err(),
        "refused -> confined is not a transition of the model"
    );
    let refused_late = observed("confined", None, Some(REFUSED));
    assert!(conforms(&r, &refused_late).is_err());
}
