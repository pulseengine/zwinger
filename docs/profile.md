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

Nothing outside `read` and `write` is accessible. A `read` entry inside a `deny_read` tree is a stated exception (one public key in a secrets directory). A path may start with `~/`, the home directory of the user running zwinger, taken from the password database, not from `$HOME`. No other expansion happens: `$HOME`, `~user` and a bare `~`, which is YAML's null, are refused as not absolute. A `write` inside a denied tree, the same path both allowed and denied, a relative or `..` path, an unknown or duplicate key, a null name or a wildcard host is refused when the profile loads.

## What the session receives

The command zwinger runs gets three environment variables:

- `ZWINGER_PROFILE`: the profile's name;
- `ZWINGER_ABI`: the Landlock ABI in use (Linux only);
- `ZWINGER_GRANTS`: the plan zwinger enforces, as JSON with schema `zwinger.grants.v1`. It holds the resolved `read` and `write` grants, `deny_read`, `deny_write` and `noexec`, and `exec`, which stays empty until profiles get an exec allowlist. Every path is absolute.

```json
{"schema":"zwinger.grants.v1","read":["/usr","/home/me/repo"],"write":["/home/me/repo/target"],
 "deny_read":["/home/me/repo/.env"],"deny_write":[],"noexec":[],"exec":[]}
```

`ZWINGER_GRANTS` is information for the command. A capability shell such as kapsel maps it to its preopened directories, and an agent can use it to explain a denial. The kernel sandbox enforces the same plan whether or not the command reads it. If a resolved path is not valid UTF-8, JSON can't carry it, so zwinger refuses to run (exit 78).

## Where the profile and zwinger may live

`check` and `run` refuse (exit 78) when the profile file or the zwinger executable lies inside a write grant, whether by its path or through a symlink. They also refuse zwinger started through a symlink or a PATH directory inside a write grant, and a profile file with more than one hard link. The profile is read once, so the file checked is the file parsed. The next run reads both again with your full authority, so the session must not be able to change them. Keep profiles in a directory the session can only read, for example `/etc/zwinger`, and install zwinger outside every write grant, for example `/usr/local/bin`. A runner's `.cargo/bin` is not such a place if the runner grants write on its `.cargo`.

## Environment variables zwinger removes

Before it execs the command, zwinger removes variables that make a program load or run code it wasn't asked to. A profile keeps any of them by naming it:

```yaml
env_keep: [GIT_SSH_COMMAND]
```

- Dynamic loader: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, and every `DYLD_*` variable.
- Shell startup files and hooks: `BASH_ENV`, `ENV`, `ZDOTDIR`, `PROMPT_COMMAND`.
- Build and VCS wrappers: `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `CARGO_BUILD_RUSTC_WRAPPER`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_EXEC_PATH`, `GIT_ASKPASS`, `SSH_ASKPASS`.

The startup line names what was removed (`; environment removed: BASH_ENV, LD_PRELOAD`). An `env_keep` entry that isn't on the list keeps nothing, so it's refused as a likely typo.

This keeps the session from inheriting these settings from the shell that started zwinger. It does not stop the agent from setting them for the processes it starts. Those processes stay confined by the kernel sandbox, and a capability shell such as kapsel applies its own allowlist to the native tools it runs.

## UNIX sockets

While `unix_sockets` is `confined`, the session may create sockets in its write trees but connect only to sockets in two places:
- the per-session socket directory zwinger creates before confining, passed as `ZWINGER_SOCKET_DIR`, where the session's own processes can meet;
- the directories the profile lists:

  ```yaml
  unix_socket_dirs: [/home/me/.cache/bazel]   # e.g. a build server's own socket directory
  ```

A socket elsewhere, including one inside a write tree, may belong to a server outside the session, so connecting to it fails. On Linux this uses Landlock's UNIX-connect right (ABI 9); below ABI 9, `socket(AF_UNIX)` is refused under mode `none`. On macOS it uses Seatbelt's outbound rules. `zwinger check` lists sockets that already exist in write trees, searching three levels deep.

Verification status: the macOS end-to-end tests cover this rule fully. On Linux it needs Landlock ABI 9, and no CI kernel is at ABI 9 yet, so the Linux connect restriction is verified only on macOS until a CI job on an ABI 9 kernel runs its test (#41). On a kernel at ABI 9 or later the restriction is enforced; below ABI 9, `socket(AF_UNIX)` is refused under mode `none`.

The per-session directory is created outside every write grant, the first of `$XDG_RUNTIME_DIR`, the temp directory, `/tmp` and `/var/tmp` that no write grant covers, and nothing can be hard-linked into it. On Linux nothing can be renamed into it either, so the only sockets in it are ones the session bound there, not a foreign socket moved in from a write tree. On macOS the session can create only sockets there, but Seatbelt treats renaming a socket in like creating one, so a socket already in a write tree can be moved in and connected to. On macOS, keep other servers' sockets out of write trees; `zwinger check` lists the ones it finds. A directory you list in `unix_socket_dirs` that lies inside a write tree doesn't have that protection: the session could move another socket into it. List only directories that hold the sockets you mean, and prefer ones outside write trees.
