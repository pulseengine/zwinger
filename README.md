# zwinger

zwinger confines an AI agent, whichever one you run, and every process it starts to what one typed profile allows.

## Vision

The goal is one profile that confines an agent the same way on a developer's Mac, a CI runner and a Raspberry Pi. Each run reports to [warte](https://github.com/pulseengine/warte) what was confined and what was not. An architecture model checked by [spar](https://github.com/pulseengine/spar) describes how confined nodes connect, and generates each session's network peers, so a fleet of agents can be checked against what was declared.

## Why use it

- **On Linux, the syscall filter and the path rules are machine-checked on the code that ships.** Kani proves the seccomp filter equals its specification for every syscall number and argument, and Verus proves the carve-out and noexec path checks for paths of any length. Planted bugs must make the proofs fail on every CI run. We found no other agent sandbox whose syscall filter and path rules are machine-checked proofs on the shipped code. [How the proofs work](docs/proofs.md)
- **It refuses rather than half-confines.** If the kernel or the backend cannot enforce something the profile states, `zwinger run` exits 78 with the reason and starts nothing. The startup line lists what this kernel cannot enforce and what the profile turned off. [What Linux refuses](docs/linux.md)
- **The profile is strict, and every decision can be explained.** Unknown or duplicate keys, relative paths and contradictory grants are refused before anything runs, and `zwinger explain` names the rule that decides a path. [Profile reference](docs/profile.md)

## Quick start

```sh
cargo install --locked --git https://github.com/pulseengine/zwinger zwinger
```

```yaml
# demo.yaml
name: demo
read: [/usr, /bin]
read_if_present: [/lib, /lib64, /etc, /System, /Library, /private/etc]
write: [/tmp]
```

```sh
zwinger check demo.yaml               # everything run checks, without running it
zwinger explain demo.yaml ~/.ssh      # which rule allows or denies a path
zwinger run demo.yaml -- my-agent     # any agent, and everything it starts, confined
```

The demo grants only system directories. A real agent also needs its own binary, its configuration in your home directory and its API host, so add those to `read` and `write`, and set `network.mode: unfiltered` until filtering by host name lands. Linux release archives are listed in a cosign-signed `SHA256SUMS.txt` and carry SLSA provenance; see [verifying a release](docs/releases.md).

## Status

| Part | State |
|---|---|
| Linux backend (Landlock and seccomp, x86_64 and aarch64, kernel 6.2 or later with Landlock enabled) | works |
| Self-hosted CI runner profile | works ([template](profiles/github-runner.yaml)) |
| One event per run for warte | works; collection by warte's probe is in progress |
| macOS backend on Seatbelt | prototype: Apple has deprecated Seatbelt, and it cannot start inside another sandbox |
| macOS backend on Endpoint Security | planned; needs Apple's entitlement |
| Egress filtering by host name | planned ([#14](https://github.com/pulseengine/zwinger/issues/14)); today a profile that names hosts is refused |
| Architecture model and generated network peers | the model is checked in CI; generation waits for spar's emitter release and the egress design (#14) |
| Proofs for the macOS policy | not yet: macOS is covered by tests only |
| Raspberry Pi kernels | not yet tested |
| Other Unix platforms | `run` refuses, so nothing starts unconfined; not tested in CI. Windows does not build |

`zwinger explain` answers with the Linux rules on every platform it builds on.

## Where to find more

- [Profiles and commands](docs/profile.md)
- [Linux backend](docs/linux.md) and [macOS prototype](docs/macos.md)
- [Proofs](docs/proofs.md) and the [trusted base](docs/trusted-base.md)
- [Architecture model](docs/architecture.md)
- [Reporting to warte](docs/telemetry.md)
- [Verifying a release](docs/releases.md)
- [Plan](docs/plan.md) and the requirements in [`artifacts/`](artifacts/) (rivet)

## Licence

MIT. Issues and pull requests are welcome.
