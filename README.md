# zwinger

zwinger confines an AI coding-agent session (Claude Code and the processes it starts) to what a typed per-session profile allows. It uses supported OS mechanisms: Endpoint Security descendant clients on macOS, and Landlock plus seccomp on Linux.

**Status: bootstrap, nothing is enforced yet.** zwinger parses and checks profiles, and `run` refuses: without an enforcement backend it will not start anything unconfined.

```sh
zwinger check profile.toml           # exit 0, or 78 with the reason
zwinger run profile.toml -- claude   # today: always refused (exit 78)
```

```toml
name = "demo"
write = ["/Users/me/git/demo"]
deny_read = ["/Users/me/.ssh"]
mach_lookup = ["com.apple.server.bluetooth"]

[network]
allow = ["api.anthropic.com", "github.com"]   # exact host names; empty = no egress
```

## Why

Today's agent sandboxes depend on `sandbox-exec`/Seatbelt, which Apple has deprecated; its profile language "is not considered API". They are also usually started by shell scripts, where a fail-open path is easy to miss. zwinger is a single binary that refuses whenever it isn't sure.

## Plan

- **REQ-ZW-001, done:** fail closed, with tests that break when the guards are removed.
- **REQ-ZW-002, done:** one typed profile for every platform.
- **REQ-ZW-003:** the macOS backend via `es_new_descendants_client` (macOS 27). [`bridge/`](bridge/) holds the C interface and the five spike checks. It needs Apple's Endpoint Security entitlement.
- **REQ-ZW-004:** the Linux and Raspberry Pi backend via Landlock and seccomp.

Traceability lives in [`artifacts/`](artifacts/) (rivet; `rivet validate` passes).

## Licence

MIT.
