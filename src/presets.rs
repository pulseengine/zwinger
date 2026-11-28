//! Built-in profile presets (REQ-ZW-030). `zwinger init --preset NAME --var key=value ...`
//! fills a preset's `{{key}}` placeholders and writes a profile; the rendered text must parse
//! as a profile before anything is written. Presets are compiled in, so a deployment renders
//! from zwinger's own source rather than a hand-copied template.

use std::collections::BTreeSet;
use std::path::Path;

/// Name and text of each preset.
pub const PRESETS: [(&str, &str); 3] = [
    ("agent-linux", include_str!("../profiles/agent-linux.yaml")),
    ("agent-macos", include_str!("../profiles/agent-macos.yaml")),
    (
        "github-runner",
        include_str!("../profiles/github-runner.yaml"),
    ),
];

/// The preset's text, or a refusal that lists the presets.
pub fn get(name: &str) -> Result<&'static str, String> {
    PRESETS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, t)| *t)
        .ok_or_else(|| format!("no preset {name:?}; presets: {}", names().join(", ")))
}

pub fn names() -> Vec<&'static str> {
    PRESETS.iter().map(|(n, _)| *n).collect()
}

/// The `{{name}}` placeholders in `text`, sorted.
pub fn placeholders(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = text;
    while let Some(i) = rest.find("{{") {
        rest = &rest[i + 2..];
        match rest.find("}}") {
            Some(j) => {
                out.insert(rest[..j].to_string());
                rest = &rest[j + 2..];
            }
            None => break,
        }
    }
    out
}

/// A value may hold only characters that cannot end a quoted YAML string or start new
/// structure: letters, digits, space and `. _ - / ~ + @ :`. A value such as `x", "/` would
/// otherwise add a grant.
fn check_value(key: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("--var {key}= is empty; give a value"));
    }
    match value
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || " ._-/~+@:".contains(*c)))
    {
        Some(c) => Err(format!(
            "--var {key}: {c:?} is not allowed in a value (letters, digits, space and . _ - / ~ + @ : are)"
        )),
        None => Ok(()),
    }
}

/// Fill every placeholder of preset `name` from `vars` and check the result parses as a
/// profile. A missing, unknown or repeated variable is refused.
pub fn render(name: &str, vars: &[(String, String)]) -> Result<String, String> {
    let text = get(name)?;
    let needed = placeholders(text);
    let mut seen = BTreeSet::new();
    for (k, v) in vars {
        if !needed.contains(k) {
            return Err(format!(
                "preset {name} has no variable {k:?}; its variables: {}",
                needed.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
        if !seen.insert(k.clone()) {
            return Err(format!("--var {k} is given twice; keep one"));
        }
        check_value(k, v)?;
    }
    let missing: Vec<&String> = needed.iter().filter(|k| !seen.contains(*k)).collect();
    if !missing.is_empty() {
        let list: Vec<String> = missing.iter().map(|k| format!("--var {k}=...")).collect();
        return Err(format!("preset {name} needs {}", list.join(" ")));
    }
    let mut out = text.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }
    crate::profile::Profile::parse(Path::new(name), &out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Parse `key=value` arguments of `--var`.
pub fn parse_var(arg: &str) -> Result<(String, String), String> {
    match arg.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_string(), v.to_string())),
        _ => Err(format!("--var {arg:?}: expected key=value")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(k: &str, val: &str) -> (String, String) {
        (k.into(), val.into())
    }

    // rivet: verifies REQ-ZW-030
    #[test]
    fn every_preset_names_its_variables_and_refuses_until_filled() {
        assert_eq!(names(), ["agent-linux", "agent-macos", "github-runner"]);
        for (name, text) in PRESETS {
            let needed = placeholders(text);
            assert!(!needed.is_empty(), "{name}");
            let e = render(name, &[]).unwrap_err();
            assert!(e.starts_with(&format!("preset {name} needs --var ")), "{e}");
        }
        assert_eq!(
            placeholders(get("agent-macos").unwrap()),
            ["proxy_port", "repo", "state"].map(String::from).into()
        );
        assert_eq!(
            placeholders(get("github-runner").unwrap()),
            ["home"].map(String::from).into()
        );
    }

    // rivet: verifies REQ-ZW-030
    #[test]
    fn rendering_fills_every_placeholder_and_parses() {
        let out = render(
            "agent-linux",
            &[
                v("repo", "/home/me/git/demo"),
                v("state", "/home/me/.agent"),
            ],
        )
        .unwrap();
        assert!(!out.contains("{{"), "{out}");
        assert!(out.contains("\"/home/me/git/demo\""), "{out}");
        let out = render("github-runner", &[v("home", "/var/lib/runners/r1")]).unwrap();
        assert!(out.contains("\"/var/lib/runners/r1/_work\""), "{out}");
        let out = render(
            "agent-macos",
            &[
                v("repo", "/Users/me/git/demo"),
                v("state", "/Users/me/.agent"),
                v("proxy_port", "3128"),
            ],
        )
        .unwrap();
        assert!(out.contains("allow_loopback_ports: [3128]"), "{out}");
    }

    // rivet: verifies REQ-ZW-030
    #[test]
    fn bad_variables_are_refused() {
        let r = |vars: &[(String, String)]| render("github-runner", vars).unwrap_err();
        assert!(r(&[v("hom", "/x")]).starts_with("preset github-runner has no variable \"hom\""));
        assert!(r(&[v("home", "/x"), v("home", "/y")]).contains("given twice"));
        assert!(r(&[v("home", "")]).contains("is empty"));
        // Breaking out of the quoted string would add a grant.
        assert!(r(&[v("home", "/x\", \"/")]).contains("'\"' is not allowed"));
        assert!(r(&[v("home", "/x\n")]).contains("is not allowed"));
        // A value that renders but does not make a valid profile.
        assert!(r(&[v("home", "relative")]).contains("is not absolute"));
        let e = render(
            "agent-macos",
            &[v("repo", "/r"), v("state", "/s"), v("proxy_port", "http")],
        )
        .unwrap_err();
        assert!(e.contains("not a valid profile"), "{e}");
        assert!(
            get("nope")
                .unwrap_err()
                .contains("presets: agent-linux, agent-macos")
        );
        assert!(parse_var("noequals").is_err());
        assert!(parse_var("=x").is_err());
        assert_eq!(parse_var("k=a=b").unwrap(), v("k", "a=b"));
    }
}
