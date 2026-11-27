# macOS (Seatbelt prototype)

`zwinger run` writes the profile as a Seatbelt (SBPL) policy, applies it to itself with `sandbox_init`, marks inherited descriptors close-on-exec, then execs the command; every descendant inherits the policy (DD-ZW-007). `sandbox_init` is deprecated and its profile language is not API. It is a stepping stone to the Endpoint Security client (REQ-ZW-003), not the end state.

The policy starts from `(deny default)` and a small base, every entry documented in `src/macos.rs` (`BASE`): fork, signals and process info within the session, reading sysctls, file metadata (stat, readlink: Landlock does not restrict it either), listing `/` (dyld opens it and aborts the process without it), the system libraries and dyld shared cache, `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`, `/dev/fd`, `/dev/tty`, terminal ioctls on the inherited terminal, the time zone database, and three Mach services (user and group lookup, notifications). `read` trees are readable and executable, `write` trees writable too. Seatbelt applies the last matching rule, so unlike Landlock it enforces a `deny_read` or `deny_write` inside a granted tree. `ioctl(TIOCSTI)` is denied. A `noexec` tree denies exec and executable mapping after every grant, so unlike Linux it is enforced inside a wider grant too. `network.mode: none` allows only UNIX sockets, and those connect and bind only inside write trees unless `unix_sockets: unfiltered`. `network.mode: unfiltered` allows IP sockets (connect, accept, bind) and the DNS resolver's Mach services; it does not open UNIX sockets, which `unix_sockets` alone decides. It refuses (exit 78) when:

- a granted path does not exist, or resolves through a symlink into a denied tree (a `read` stated inside a `deny_read` is the one exception);
- a `deny_read`, `deny_write` or `noexec` lies strictly inside a write grant: Seatbelt matches paths, and the session could rename a directory above it or hard-link a file out of it (inside a read-only grant they are enforced);
- `network.allow` names hosts or `allow_local_binding` is set, because Seatbelt filters by address and port, not host name;
- a resolved path or Mach name contains `"`, `\` or a control character, which the backend does not write into a policy;
- `sandbox_init` fails, for example inside another sandbox, where it cannot be nested.

A denied operation fails with `EPERM` (measured on the macOS 15 runner for open, create, connect and bind). On a case-insensitive volume a denial also holds for the path spelled in another case, including a denied path that does not exist yet (measured end to end; tests/macos.rs). The startup line says `seatbelt` where Linux names the Landlock ABI; the session gets `ZWINGER_PROFILE`. `zwinger explain` still answers with the Linux backend's rules.

Not covered: reading sysctls; the hard-link and policy-syntax caveats in DD-ZW-007; the network test runs on loopback only.
