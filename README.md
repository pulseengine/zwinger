# zwinger

zwinger confines an AI coding-agent session (Claude Code and the processes it starts) to what a typed per-session profile allows. It uses supported OS mechanisms: Landlock plus seccomp on Linux, and Endpoint Security descendant clients on macOS (not built yet).

**Status:** the Linux backend enforces profiles. On macOS, `run` still refuses: without an enforcement backend it will not start anything unconfined.

```sh
zwinger check profile.toml           # exit 0, or 78 with the reason
zwinger run profile.toml -- claude   # Linux: confined exec; elsewhere: refused (exit 78)
```

```toml
name = "demo"
read = ["/usr", "/etc", "/lib", "/lib64"]   # read + execute
write = ["/home/me/git/demo", "/tmp/demo", "/dev/null"]
deny_read = ["/home/me/.ssh"]                # carve-outs
deny_write = []
mach_lookup = ["com.apple.server.bluetooth"] # macOS only

[network]
allow = []                    # exact host names; empty = no egress
allow_local_binding = false
```

Nothing outside `read` and `write` is accessible. A `read` entry inside a `deny_read` tree is a stated exception (one public key in a secrets directory). A `write` inside a denied tree, the same path both allowed and denied, a relative or `..` path, an unknown key or a wildcard host is refused when the profile loads.

## Linux

`zwinger run` restricts itself with Landlock and seccomp, marks inherited descriptors close-on-exec, then execs the command, so every descendant inherits the confinement. It refuses (exit 78) when:

- the kernel's Landlock ABI is below 3 (Linux 6.2), which cannot restrict `truncate(2)`;
- a granted path does not exist, or resolves through a symlink into a denied tree;
- a `deny_read` lies inside a granted tree, or a `deny_write` inside a write tree, because Landlock is an allow list and cannot carve a subtree out of a granted one;
- `network.allow` names hosts or `allow_local_binding` is set, because Landlock filters ports, not hosts or addresses, and there is no filtering proxy yet.

No egress is enforced by seccomp (every socket family except `AF_UNIX`, and io_uring) and by Landlock's TCP (ABI 4) and UDP (ABI 10) rules where the kernel has them. `AF_UNIX` sockets are allowed only when Landlock confines them (ABI 9); on older kernels `socket(AF_UNIX)` is refused and `socketpair(2)` still works.

Not covered, by Landlock's design: `chmod`, `chown`, `utime` and xattr changes outside the granted trees; signals to other processes below ABI 6; device ioctls below ABI 5.

## Why

Today's agent sandboxes depend on `sandbox-exec`/Seatbelt, which Apple has deprecated; its profile language "is not considered API". They are also usually started by shell scripts, where a fail-open path is easy to miss. zwinger is a single binary that refuses whenever it isn't sure.

## Plan

- **REQ-ZW-001, REQ-ZW-002, done:** fail closed; one typed profile with every field refusable.
- **REQ-ZW-004..006, REQ-ZW-008, done:** the Linux backend (filesystem, network, UNIX sockets, unenforceable profiles refused), tested end to end on CI kernels.
- **REQ-ZW-003:** the macOS backend via `es_new_descendants_client` (macOS 27). [`bridge/`](bridge/) holds the C interface and the five spike checks. It needs Apple's Endpoint Security entitlement.
- **REQ-ZW-007:** check the Linux backend on a Raspberry Pi 5 kernel.

Traceability lives in [`artifacts/`](artifacts/) (rivet; `rivet validate` passes).

## Licence

MIT.
