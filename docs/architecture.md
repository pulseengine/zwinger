# Architecture model

[`architecture/zwinger.aadl`](../architecture/zwinger.aadl) is the AADL component type for one confined node: the session, its kernel, its profiles, the host resources the command touches, and the warte probe, each with an EMV2 error model. Any deployment imports package `Zwinger` and binds nodes to its own hosts. [`architecture/reference_mesh.aadl`](../architecture/reference_mesh.aadl) is the public template: an agent node on a Mac and a device node on a Pi, with warte on the agent's host.

`architecture/check.sh` runs [spar](https://github.com/pulseengine/spar) 0.49.0 on both models (CI job "Architecture model (spar)"). It fails when:

- spar reports an error;
- any fault propagates as access the profile did not grant (`ItemCommission`);
- the known telemetry gap changes: a run that wrote no event still reaches warte as a silent omission;
- the Pi's event stream to warte has no worst-case traversal time bound, or one above 1 ms.
- the session lifecycle (modes `loading`, `preflight`, `confined`, `refused`, `exited`) has a dead transition, leaves `refused` or `exited`, or enters `confined` from anything but `preflight`.

Five planted models must each fail the gate. `architecture/zwinger_profile.aadl` is the property set spar reads to generate a session's network section (`spar emit --format zwinger-profile`, seam #17); `architecture/expected/` holds the fragments the reference mesh must produce. The WCTT bound, 34.144 µs over one switch hop, rests on the rates and latencies written in the model as assumptions. It is not a delivery guarantee. The plan is for profiles to take their network peers from a fragment generated from the model (REQ-ZW-017), once the egress design (#14) is decided; zwinger itself will not parse AADL.

## The binary follows the model

`tests/lifecycle.rs` holds the real binary to the lifecycle in the model. It runs sessions that refuse while loading (a malformed profile), refuse in preflight (a missing grant), run and exit, and fail to exec after confinement. It reads each session's event and exit status, maps them onto the modes, and requires every step to be a transition in `architecture/expected/lifecycle.smv`, spar's export of the model. A session that runs a command after reporting a refusal maps to refused → confined, which the model forbids, so the test fails. The architecture job fails if the committed export differs from what spar derives from `zwinger.aadl`.
