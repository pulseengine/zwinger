# Linux

`zwinger run` restricts itself with Landlock and seccomp, marks inherited descriptors close-on-exec, then execs the command, so every descendant inherits the confinement. It refuses (exit 78) when:

- the kernel's Landlock ABI is below 3 (Linux 6.2), which cannot restrict `truncate(2)`;
- a granted path does not exist, or resolves through a symlink into a denied tree, or no longer names the object the plan checked when its rule is installed;
- a `deny_read` lies inside a granted tree, or a `deny_write` inside a write tree, because Landlock is an allow list and cannot carve a subtree out of a granted one;
- a `noexec` tree lies inside a wider grant, whose execute right would still cover it;
- `network.allow` names hosts, or `allow_local_binding` or `allow_loopback_ports` is set, because Landlock filters ports, not hosts or addresses, and there is no filtering proxy yet.

No egress is enforced by seccomp (every socket family except `AF_UNIX`, and io_uring) and by Landlock's TCP (ABI 4) and UDP (ABI 10) rules where the kernel has them. `AF_UNIX` sockets are allowed only when Landlock confines them (ABI 9); on older kernels `socket(AF_UNIX)` is refused and `socketpair(2)` still works. `ioctl` with `TIOCSTI` or `TIOCLINUX` is refused, so the session cannot push input into the caller's terminal for the unconfined shell to run. `add_key`, `request_key` and `keyctl` are refused, so the session cannot use the kernel keyrings, which hold secrets no path rule covers.

`network.mode = "unfiltered"` and `unix_sockets = "unfiltered"` turn those off explicitly; the startup line then lists them as not enforced.

## What a denial looks like

zwinger writes one line to stderr (the journal under systemd) before it execs, e.g.

```
zwinger: runner19 confined: landlock abi 4; 7 read, 9 write grants (absent, skipped: /lib32, /libx32); network: unfiltered; unix sockets: refused; denial audit log: off (abi 7); not enforced: network (mode = unfiltered), device ioctls (abi 5), signal scoping (abi 6)
```

The session gets `ZWINGER_PROFILE` and `ZWINGER_ABI` in its environment. Below Landlock ABI 7 (Linux 6.15) the kernel logs nothing, so a denial is only its errno: `EACCES` from open, creat, mkdir, unlink or truncate on a path; `EXDEV` from a rename or link across directories; `EACCES` from `socket(2)` for a refused family; `EPERM` for io_uring, the keyring syscalls, `TIOCSTI` and `TIOCLINUX`. From ABI 7 on, Landlock writes denials to the audit log. `zwinger explain PROFILE PATH` names the grant that decides a path.

## Self-hosted CI runners

[`profiles/github-runner.yaml`](../profiles/github-runner.yaml) confines one runner: substitute `{{home}}`, configure the runner with `--disableupdate`, and prefix the unit's command with `zwinger run PROFILE --`. Paths are confined; the network is not, because loopback build servers on ephemeral ports cannot be told from remote ports by Landlock (DD-ZW-004). The runner's own credentials stay readable to jobs.

Not covered, by Landlock's design: `chmod`, `chown`, `utime` and xattr changes outside the granted trees; signals to other processes below ABI 6; device ioctls below ABI 5.
