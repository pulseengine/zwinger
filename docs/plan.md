# Plan

- **REQ-ZW-001, REQ-ZW-002, done:** fail closed; one typed profile with every field refusable.
- **REQ-ZW-004..006, REQ-ZW-008, done:** the Linux backend (filesystem, network, UNIX sockets, unenforceable profiles refused), tested end to end on CI kernels.
- **REQ-ZW-009..011, done:** explicit unfiltered modes and optional grants, traceable denials, and the CI runner template.
- **REQ-ZW-003, prototype:** a Seatbelt backend confines `run` on macOS (DD-ZW-007), tested end to end on a hosted macOS runner.
- **REQ-ZW-003:** the macOS backend via `es_new_descendants_client` (macOS 27). [`bridge/`](../bridge/) holds the C interface and the five spike checks. It needs Apple's Endpoint Security entitlement.
- **REQ-ZW-007:** check the Linux backend on a Raspberry Pi 5 kernel.

Traceability lives in [`artifacts/`](../artifacts/) (rivet; `rivet validate` passes).
