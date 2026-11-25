# bridge/

The C side of the macOS backend. It is only a header today; `build.rs` does not compile it. The spike runs on a SIP-disabled macOS 27 VM and decides whether it gets built:

1. `es_new_descendants_client` confines one process tree, and a child process cannot escape it.
2. Claude Code's Keychain login still works inside the tree.
3. Remote Control still connects.
4. CoreBluetooth works where the profile allows it (a session that needs Bluetooth).
5. A denied write, read or connect is refused and logged, and the session keeps running.
