# zwinger

zwinger confines an AI coding-agent session (Claude Code and the processes it starts) to what a typed per-session profile allows. It uses supported OS mechanisms: Landlock plus seccomp on Linux, and Endpoint Security descendant clients on macOS (not built yet).

**Status:** the Linux backend enforces profiles. On macOS, `run` still refuses: without an enforcement backend it will not start anything unconfined.

```sh
zwinger check profile.toml           # exit 0, or 78 with the reason
zwinger explain profile.toml PATH    # which grant allows PATH (or tcp:PORT), and why not
zwinger run profile.toml -- claude   # Linux: confined exec; elsewhere: refused (exit 78)
```

```toml
name = "demo"
read = ["/usr", "/etc", "/lib", "/lib64"]   # read + execute
read_if_present = ["/opt"]                 # skipped when absent
write = ["/home/me/git/demo", "/tmp/demo", "/dev/null"]
deny_read = ["/home/me/.ssh"]                # carve-outs
deny_write = []
mach_lookup = ["com.apple.server.bluetooth"] # macOS only

[network]
mode = "none"                 # "none" (default) or "unfiltered" (paths confined, network not)
allow = []                    # exact host names; empty = no egress
allow_local_binding = false
unix_sockets = "confined"     # or "unfiltered": AF_UNIX allowed and not confined
```

Nothing outside `read` and `write` is accessible. A `read` entry inside a `deny_read` tree is a stated exception (one public key in a secrets directory). A `write` inside a denied tree, the same path both allowed and denied, a relative or `..` path, an unknown key or a wildcard host is refused when the profile loads.

## Linux

`zwinger run` restricts itself with Landlock and seccomp, marks inherited descriptors close-on-exec, then execs the command, so every descendant inherits the confinement. It refuses (exit 78) when:

- the kernel's Landlock ABI is below 3 (Linux 6.2), which cannot restrict `truncate(2)`;
- a granted path does not exist, or resolves through a symlink into a denied tree;
- a `deny_read` lies inside a granted tree, or a `deny_write` inside a write tree, because Landlock is an allow list and cannot carve a subtree out of a granted one;
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

[`profiles/github-runner.toml`](profiles/github-runner.toml) confines one runner: substitute `{{home}}`, configure the runner with `--disableupdate`, and prefix the unit's command with `zwinger run PROFILE --`. Paths are confined; the network is not, because loopback build servers on ephemeral ports cannot be told from remote ports by Landlock (DD-ZW-004). The runner's own credentials stay readable to jobs.

Not covered, by Landlock's design: `chmod`, `chown`, `utime` and xattr changes outside the granted trees; signals to other processes below ABI 6; device ioctls below ABI 5.

## Proofs

`cargo kani` checks the seccomp filter and the backend's decisions on the shipped code (`src/linux.rs`, `mod proofs`, CI job "Kani proofs"):

- for x86_64 and aarch64 in every socket mode, the filter's verdict equals its specification for every syscall number and argument, and the program is well formed;
- from any kernel ABI and network mode, `socket(2)` is allowed exactly as REQ-ZW-005, REQ-ZW-006 and REQ-ZW-009 state;
- for every ABI, the backend never opens a channel the profile did not state and never asks Landlock for a right the kernel lacks.
- if the carve-out rules accept a profile, every path beneath a `deny_read` or `deny_write` stays uncovered by the grants Landlock receives, except a read exception stated inside that `deny_read` (stated and resolved paths vary independently, so symlink aliasing is included).

Eleven planted bugs must each be rejected, so a proof that stopped looking fails the job. The trusted base is the classic-BPF model in `bpf_run`, the shared syscall constants, `within` (checked exhaustively against `Path::starts_with` by unit test) and Kani/CBMC; `tests/linux.rs` runs the same filter in real kernels.

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

Today's agent sandboxes depend on `sandbox-exec`/Seatbelt, which Apple has deprecated; its profile language "is not considered API". They are also usually started by shell scripts, where a fail-open path is easy to miss. zwinger is a single binary that refuses whenever it isn't sure.

## Plan

- **REQ-ZW-001, REQ-ZW-002, done:** fail closed; one typed profile with every field refusable.
- **REQ-ZW-004..006, REQ-ZW-008, done:** the Linux backend (filesystem, network, UNIX sockets, unenforceable profiles refused), tested end to end on CI kernels.
- **REQ-ZW-009..011, done:** explicit unfiltered modes and optional grants, traceable denials, and the CI runner template.
- **REQ-ZW-003:** the macOS backend via `es_new_descendants_client` (macOS 27). [`bridge/`](bridge/) holds the C interface and the five spike checks. It needs Apple's Endpoint Security entitlement.
- **REQ-ZW-007:** check the Linux backend on a Raspberry Pi 5 kernel.

Traceability lives in [`artifacts/`](artifacts/) (rivet; `rivet validate` passes).

## Licence

MIT.
