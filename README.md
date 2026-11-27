# zwinger

zwinger confines an AI coding-agent session (Claude Code and the processes it starts) to what a typed per-session profile allows. It uses Landlock plus seccomp on Linux. On macOS a Seatbelt prototype confines sessions today; the target there is an Endpoint Security descendants client (not built yet).

**Status:** the Linux backend enforces profiles. On macOS, `run` confines with Seatbelt (`sandbox_init`), a prototype. On any other platform `run` refuses: without an enforcement backend it will not start anything unconfined.

```sh
zwinger check profile.yaml           # everything run checks, without running; 78 with the reason
zwinger explain profile.yaml PATH    # which grant allows PATH (or tcp:PORT), and why not
zwinger run profile.yaml -- claude   # Linux, macOS: confined exec; elsewhere: refused (exit 78)
```

```yaml
name: demo
read: [/usr, /etc, /lib, /lib64]        # read + execute
read_if_present: [/opt]                # skipped when absent
write: [/home/me/git/demo, /tmp/demo, /dev/null]
deny_read: [/home/me/.ssh]             # carve-outs
deny_write: []
noexec: [/tmp/demo]                 # nothing executes from here
mach_lookup: [com.apple.server.bluetooth]  # macOS only

network:
  mode: none                 # none (default) or unfiltered (paths confined, network not)
  allow: []                  # exact host names; empty = no egress
  allow_local_binding: false
  unix_sockets: confined     # or unfiltered: AF_UNIX allowed and not confined
```

Profiles are read by [rivet-yaml](https://github.com/pulseengine/rivet/tree/main/rivet-yaml), the YAML parser rivet uses for every artifact file. It refuses duplicate keys, tags and multi-document files, and reads `yes`/`on` as strings, so a YAML 1.1 boolean is refused rather than guessed.

Nothing outside `read` and `write` is accessible. A `read` entry inside a `deny_read` tree is a stated exception (one public key in a secrets directory). A `write` inside a denied tree, the same path both allowed and denied, a relative or `..` path, an unknown or duplicate key, a null name or a wildcard host is refused when the profile loads.

## Linux

`zwinger run` restricts itself with Landlock and seccomp, marks inherited descriptors close-on-exec, then execs the command, so every descendant inherits the confinement. It refuses (exit 78) when:

- the kernel's Landlock ABI is below 3 (Linux 6.2), which cannot restrict `truncate(2)`;
- a granted path does not exist, or resolves through a symlink into a denied tree;
- a `deny_read` lies inside a granted tree, or a `deny_write` inside a write tree, because Landlock is an allow list and cannot carve a subtree out of a granted one;
- a `noexec` tree lies inside a wider grant, whose execute right would still cover it;
- `network.allow` names hosts or `allow_local_binding` is set, because Landlock filters ports, not hosts or addresses, and there is no filtering proxy yet.

No egress is enforced by seccomp (every socket family except `AF_UNIX`, and io_uring) and by Landlock's TCP (ABI 4) and UDP (ABI 10) rules where the kernel has them. `AF_UNIX` sockets are allowed only when Landlock confines them (ABI 9); on older kernels `socket(AF_UNIX)` is refused and `socketpair(2)` still works. `ioctl` with `TIOCSTI` or `TIOCLINUX` is refused, so the session cannot push input into the caller's terminal for the unconfined shell to run.

`network.mode = "unfiltered"` and `unix_sockets = "unfiltered"` turn those off explicitly; the startup line then lists them as not enforced.

### What a denial looks like

zwinger writes one line to stderr (the journal under systemd) before it execs, e.g.

```
zwinger: runner19 confined: landlock abi 4; 7 read, 9 write grants (absent, skipped: /lib32, /libx32); network: unfiltered; unix sockets: refused; denial audit log: off (abi 7); not enforced: network (mode = unfiltered), device ioctls (abi 5), signal scoping (abi 6)
```

The session gets `ZWINGER_PROFILE` and `ZWINGER_ABI` in its environment. Below Landlock ABI 7 (Linux 6.15) the kernel logs nothing, so a denial is only its errno: `EACCES` from open, creat, mkdir, unlink or truncate on a path; `EXDEV` from a rename or link across directories; `EACCES` from `socket(2)` for a refused family; `EPERM` for io_uring, `TIOCSTI` and `TIOCLINUX`. From ABI 7 on, Landlock writes denials to the audit log. `zwinger explain PROFILE PATH` names the grant that decides a path.

### Self-hosted CI runners

[`profiles/github-runner.yaml`](profiles/github-runner.yaml) confines one runner: substitute `{{home}}`, configure the runner with `--disableupdate`, and prefix the unit's command with `zwinger run PROFILE --`. Paths are confined; the network is not, because loopback build servers on ephemeral ports cannot be told from remote ports by Landlock (DD-ZW-004). The runner's own credentials stay readable to jobs.

Not covered, by Landlock's design: `chmod`, `chown`, `utime` and xattr changes outside the granted trees; signals to other processes below ABI 6; device ioctls below ABI 5.

## macOS (Seatbelt prototype)

`zwinger run` writes the profile as a Seatbelt (SBPL) policy, applies it to itself with `sandbox_init`, marks inherited descriptors close-on-exec, then execs the command; every descendant inherits the policy (DD-ZW-007). `sandbox_init` is deprecated and its profile language is not API. It is a stepping stone to the Endpoint Security client (REQ-ZW-003), not the end state.

The policy starts from `(deny default)` and a small base, every entry documented in `src/macos.rs` (`BASE`): fork, signals and process info within the session, reading sysctls, file metadata (stat, readlink: Landlock does not restrict it either), listing `/` (dyld opens it and aborts the process without it), the system libraries and dyld shared cache, `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`, `/dev/fd`, `/dev/tty`, terminal ioctls on the inherited terminal, the time zone database, and three Mach services (user and group lookup, notifications). `read` trees are readable and executable, `write` trees writable too. Seatbelt applies the last matching rule, so unlike Landlock it enforces a `deny_read` or `deny_write` inside a granted tree. `ioctl(TIOCSTI)` is denied. A `noexec` tree denies exec and executable mapping after every grant, so unlike Linux it is enforced inside a wider grant too. `network.mode: none` allows only UNIX sockets, and those connect and bind only inside write trees unless `unix_sockets: unfiltered`. `network.mode: unfiltered` allows IP sockets (connect, accept, bind) and the DNS resolver's Mach services; it does not open UNIX sockets, which `unix_sockets` alone decides. It refuses (exit 78) when:

- a granted path does not exist, or resolves through a symlink into a denied tree (a `read` stated inside a `deny_read` is the one exception);
- a `deny_read`, `deny_write` or `noexec` lies strictly inside a write grant: Seatbelt matches paths, and the session could rename a directory above it or hard-link a file out of it (inside a read-only grant they are enforced);
- `network.allow` names hosts or `allow_local_binding` is set, because Seatbelt filters by address and port, not host name;
- a resolved path or Mach name contains `"`, `\` or a control character, which the backend does not write into a policy;
- `sandbox_init` fails, for example inside another sandbox, where it cannot be nested.

A denied operation fails with `EPERM` (measured on the macOS 15 runner for open, create, connect and bind). On a case-insensitive volume a denial also holds for the path spelled in another case, including a denied path that does not exist yet (measured end to end; tests/macos.rs). The startup line says `seatbelt` where Linux names the Landlock ABI; the session gets `ZWINGER_PROFILE`. `zwinger explain` still answers with the Linux backend's rules.

Not covered: reading sysctls; the hard-link and policy-syntax caveats in DD-ZW-007; the network test runs on loopback only.

## Reporting to warte

Every `zwinger run` writes one JSON event (schema `zwinger.event.v1`) for warte's probe to collect and ship (pulseengine/warte#223). The event holds:
- the profile name and sha256;
- `confined` or `refused`, and for a refusal its category (`profile`, `path`, `carve-out`, `noexec`, `network`, `kernel`, `backend`);
- the Landlock ABI, network mode and not-enforced list;
- grant counts.

Paths, arguments and command lines are not written. zwinger opens the file before confining, so the session needs no grant for the events directory. When a write grant covers the events directory, zwinger writes no event and says so on stderr, because the session could forge or delete events there. A failure to write an event is reported on stderr and changes nothing else.

The directory is `ZWINGER_EVENTS_DIR` if set (empty turns events off), else `$XDG_STATE_HOME/warte/zwinger`, else `~/.local/state/warte/zwinger`. A systemd unit that runs as a service user sets `ZWINGER_EVENTS_DIR` to the directory the probe reads.

## Proofs

`cargo kani` checks the seccomp filter and the backend's decisions on the shipped code (`src/linux.rs`, `mod proofs`, CI job "Kani proofs"):

- for x86_64 and aarch64 in every socket mode, the filter's verdict equals its specification for every syscall number and argument, and the program is well formed;
- from any kernel ABI and network mode, `socket(2)` is allowed exactly as REQ-ZW-005, REQ-ZW-006 and REQ-ZW-009 state;
- for every ABI, the backend never opens a channel the profile did not state and never asks Landlock for a right the kernel lacks.
- if the carve-out rules accept a profile, every path beneath a `deny_read` or `deny_write` stays uncovered by the grants Landlock receives, except a read exception stated inside that `deny_read` (stated and resolved paths vary independently, so symlink aliasing is included).
- if the noexec rule accepts a profile, no grant covering a path beneath a `noexec` tree keeps the execute right.

Twelve planted bugs must each be rejected, so a proof that stopped looking fails the job. The trusted base is the classic-BPF model in `bpf_run`, the shared syscall constants, `within` (checked exhaustively against `Path::starts_with` by unit test) and Kani/CBMC; `tests/linux.rs` runs the same filter in real kernels.

`cargo verus verify` proves the path rules for paths of **any length** (`src/pathrules.rs`, CI job "Verus proofs"). Kani's carve-out and noexec harnesses cover paths of up to 4 bytes. The code inside `verus!` is the shipped code: a normal build erases the proofs, and `within` and the linux checkers call it. Verus proves:

- `within` computes its specification for all byte strings;
- two ancestors of a path are nested, and `within` is transitive;
- if the carve-out checker accepts a profile, every path beneath a `deny_read` or `deny_write` stays uncovered except by a stated read exception;
- if the noexec checker accepts, every grant covering a path beneath a `noexec` tree has lost execute.

Three planted bugs must each fail verification. Kani (CBMC) and Verus (Z3) check the same functions, so a gap in one solver is not shared by the other.

## Architecture model

[`architecture/zwinger.aadl`](architecture/zwinger.aadl) is the AADL component type for one confined node: the session, its kernel, its profiles, the host resources the command touches, and the warte probe, each with an EMV2 error model. Any deployment imports package `Zwinger` and binds nodes to its own hosts. [`architecture/reference_mesh.aadl`](architecture/reference_mesh.aadl) is the public template: an agent node on a Mac and a device node on a Pi, with warte on the agent's host.

`architecture/check.sh` runs [spar](https://github.com/pulseengine/spar) 0.49.0 on both models (CI job "Architecture model (spar)"). It fails when:

- spar reports an error;
- any fault propagates as access the profile did not grant (`ItemCommission`);
- the known telemetry gap changes: a run that wrote no event still reaches warte as a silent omission;
- the Pi's event stream to warte has no worst-case traversal time bound, or one above 1 ms.

Three planted models must each fail the gate. The WCTT bound, 34.144 µs over one switch hop, rests on the rates and latencies written in the model as assumptions. It is not a delivery guarantee. The plan is for profiles to take their network peers from a fragment generated from the model (REQ-ZW-017), once the egress design (#14) is decided; zwinger itself will not parse AADL.

## Releases

Tagged releases publish static Linux binaries (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`), a CycloneDX SBOM and a docs archive. All of them are listed in `SHA256SUMS.txt`, which is signed with cosign keyless; the archives also carry SLSA build provenance. To verify a download and pin it by sha256:

```sh
cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/pulseengine/zwinger/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --bundle SHA256SUMS.txt.cosign.bundle SHA256SUMS.txt
sha256sum --check --ignore-missing SHA256SUMS.txt
gh attestation verify zwinger-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz --repo pulseengine/zwinger
```

## Why

Today's agent sandboxes depend on `sandbox-exec`/Seatbelt, which Apple has deprecated; its profile language "is not considered API". They are also usually started by shell scripts, where a fail-open path is easy to miss. zwinger is a single binary that refuses whenever it isn't sure. Its own macOS prototype uses Seatbelt too, until the Endpoint Security client exists.

## Plan

- **REQ-ZW-001, REQ-ZW-002, done:** fail closed; one typed profile with every field refusable.
- **REQ-ZW-004..006, REQ-ZW-008, done:** the Linux backend (filesystem, network, UNIX sockets, unenforceable profiles refused), tested end to end on CI kernels.
- **REQ-ZW-009..011, done:** explicit unfiltered modes and optional grants, traceable denials, and the CI runner template.
- **REQ-ZW-003, prototype:** a Seatbelt backend confines `run` on macOS (DD-ZW-007), tested end to end on a hosted macOS runner.
- **REQ-ZW-003:** the macOS backend via `es_new_descendants_client` (macOS 27). [`bridge/`](bridge/) holds the C interface and the five spike checks. It needs Apple's Endpoint Security entitlement.
- **REQ-ZW-007:** check the Linux backend on a Raspberry Pi 5 kernel.

Traceability lives in [`artifacts/`](artifacts/) (rivet; `rivet validate` passes).

## Licence

MIT.
