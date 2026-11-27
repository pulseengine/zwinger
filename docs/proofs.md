# Proofs

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
