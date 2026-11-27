# Profiles and commands

## Commands

```sh
zwinger check profile.yaml           # everything run checks, without running; 78 with the reason
zwinger explain profile.yaml PATH    # which grant allows PATH (or tcp:PORT), and why not
zwinger run profile.yaml -- AGENT    # Linux, macOS: confined exec; elsewhere: refused (exit 78)
```

## Profile

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
