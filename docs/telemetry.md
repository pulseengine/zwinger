# Reporting to warte

Every `zwinger run` writes one YAML event (schema `zwinger.event.v1`, file `<nanos>-<pid>.yaml`) for warte's probe to collect and ship (pulseengine/warte#223). zwinger writes it with rivet-yaml, which quotes any string that would read as another type; readers should parse YAML 1.2. The event holds:
- the profile name and sha256;
- `confined` or `refused`, and for a refusal its category (`profile`, `path`, `carve-out`, `noexec`, `network`, `kernel`, `backend`);
- the Landlock ABI, network mode and not-enforced list;
- grant counts.

Paths, arguments and command lines are not written. zwinger opens the file before confining, so the session needs no grant for the events directory. When a write grant covers the events directory, zwinger writes no event and says so on stderr, because the session could forge or delete events there. A failure to write an event is reported on stderr and changes nothing else.

The directory is `ZWINGER_EVENTS_DIR` if set (empty turns events off), else `$XDG_STATE_HOME/warte/zwinger`, else `~/.local/state/warte/zwinger`. A systemd unit that runs as a service user sets `ZWINGER_EVENTS_DIR` to the directory the probe reads.
