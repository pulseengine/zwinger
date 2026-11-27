# Confinement pack

Planted controls that show a CI runner confined by zwinger actually refuses what its profile doesn't grant. The format is plant's (`ci-controls.toml`). The CI rollout was approved by the owner on 2026-11-27.

| manifest | runs on | every control must |
|---|---|---|
| `ci-controls.confined.toml` | the confined runner (`runs-on: [self-hosted, linux, confined]`) | PASS |
| `ci-controls.confined.stand-in.toml` | a disposable hosted runner, aimed at decoys in `/tmp/zwinger-decoy` | report FAIL-OPEN |

The baseline, `confinement/probe/job.sh`, fails unless `ZWINGER_PROFILE` and `ZWINGER_GRANTS` are set. So on an unconfined runner every real control goes red-baseline instead of passing. The stand-in turns that requirement off with `ZW_REQUIRE_CONFINED=0`.

| control | planted attack | refused on the confined runner because |
|---|---|---|
| `confined-write-decoy` | create `/var/lib/zwinger-probe/write-target` | the decoy directory is outside every write grant (EACCES) |
| `confined-read-decoy` | read `/var/lib/zwinger-probe/secret` | the file is outside every grant (EACCES) |
| `confined-replace-runner-file` | append to the runner's `run.sh` | the runner home is read-only under the profile (EACCES; also read-only under systemd) |

The decoy directory is created by the runner deploy (smithy), owned by the runner user, mode 0755, with `secret` at mode 0644, so that file permissions alone would allow both attacks. jig's baseline probe (`jig confined`) uses the same two paths.

A run counts when it is on the default branch, on the deployed runner with the label pinned, exits 0, and every control passes, and when the stand-in has shown every control FAIL-OPEN at least once since the profile last changed. The workflow runs on every push to main, nightly, and by hand. The confined job never runs on pull requests, and stays off until the repository variable `CONFINED_RUNNER_ONLINE` is `true`, set when a confined runner is registered.

Not claimed:
- **egress:** the runner profile leaves the network unfiltered until host filtering (#14) lands; then egress becomes a control;
- **the runner's own credentials:** `.runner` and `.credentials` stay readable to jobs, because Runner.Listener reads them and jobs inherit its confinement;
- **TIOCSTI:** CI jobs have no controlling terminal, so the ioctl fails there whether confined or not. It is covered by Kani and will be covered by an end-to-end test on a pty (#35);
- **noexec:** the runner profile sets no noexec tree;
- **device-ioctl and signal scoping:** the CI host's kernel is at Landlock ABI 4, which lacks both (ABI 5 and 6). zwinger names them on the startup line.
