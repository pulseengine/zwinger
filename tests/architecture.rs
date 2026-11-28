//! The expected profile fragments for the reference mesh (zwinger#17) are profiles zwinger
//! accepts, with the hosts the model's egress connections reach. spar's emitter must reproduce
//! them; once it ships, CI also diffs its output against these files.

use std::path::Path;
use zwinger::profile::{NetworkMode, Profile, UnixSockets};

fn fragment(name: &str) -> Profile {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("architecture/expected")
        .join(format!("{name}.yaml"));
    Profile::load(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn agent_fragment_allows_exactly_the_hosts_its_egress_reaches() {
    let p = fragment("agent");
    assert_eq!(p.name, "agent");
    assert_eq!(p.network.mode, NetworkMode::None);
    assert_eq!(p.network.allow, ["model-api.example", "git.example"]);
    assert!(!p.network.allow_local_binding);
    assert_eq!(p.network.unix_sockets, UnixSockets::Confined);
    // A fragment grants no path: only the network section is generated.
    assert_eq!(
        p.path_fields().iter().map(|(_, v)| v.len()).sum::<usize>(),
        0
    );
}

#[test]
fn devices_fragment_has_no_egress() {
    let p = fragment("devices");
    assert_eq!(p.name, "devices");
    assert_eq!(p.network.mode, NetworkMode::None);
    assert!(p.network.allow.is_empty());
    assert_eq!(
        p.path_fields().iter().map(|(_, v)| v.len()).sum::<usize>(),
        0
    );
}

#[test]
fn every_host_in_the_reference_mesh_is_in_some_fragment() {
    // The hosts come from the model; a Host added there without a fragment change fails here.
    let model = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("architecture/reference_mesh.aadl"),
    )
    .unwrap();
    let mut hosts: Vec<&str> = model
        .lines()
        .filter_map(|l| l.trim().strip_prefix("Zwinger_Profile::Host => \""))
        .filter_map(|r| r.split('"').next())
        .collect();
    hosts.sort_unstable();
    assert!(!hosts.is_empty(), "no Zwinger_Profile::Host in the model");
    let mut allowed: Vec<String> = ["agent", "devices"]
        .iter()
        .flat_map(|n| fragment(n).network.allow)
        .collect();
    allowed.sort_unstable();
    assert_eq!(allowed, hosts);
}
