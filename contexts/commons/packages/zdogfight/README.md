# zdogfight

Deterministic headless 2-team aerial dogfight match core, in strict
C23 — the authoritative simulation for cross-node, byte-identical
replays.

Fixed planes (up to 4 per team, red vs blue) fly a toroidal 2 km
world with bank-to-turn controls, guns, kills, respawns, and a match
that ends at 10 kills or 10 minutes. Per-tick controls in, one tick
advanced per call.

**Determinism contract:** same seed + same per-tick controls produce
byte-identical state on any machine and compiler. Integer arithmetic
only (no floating point — trig is a 256-entry int16 Q1.15
quarter-wave table), no heap, no clock, no `rand()`, no I/O; all
state lives in the caller-provided `zdog_match`, and the only entropy
is the embedded zprng xoshiro256**, drawn solely by respawns in
ascending plane index order.

- `zdog_match_init` / `zdog_tick` — fixed-seed match setup and the
  60 Hz tick
- `zdog_observe` / `zdog_obs` — pilot ABI observation (nearest-enemy
  sighting, toroidal-aware)
- `zdog_state_encode` — canonical little-endian field-by-field state
  serialization (always exactly `ZDOG_STATE_WIRE_MAX` = 2163 bytes);
  hash those bytes for the caller's state root
- `zdog_state_checksum` — built-in FNV-1a/64 over the canonical
  encoding for cheap in-test checks
- `zdog_obs_encode/decode`, `zdog_ctl_encode/decode` — exact-size
  wire codec for the process pilot ABI (82 and 7 bytes)

`zdogfight play [--seed N] [--planes N]` runs a match between two
built-in trivial pilots (straight vs weave) and prints the score,
winner, tick count, and FNV-1a/64 state checksum. Default seed is 7
and default planes-per-team is 2. `zdogfight selftest` is the same
loop with seed 42 and 2 planes — keep that as the package's smoke
command. Same seed + same pilots is a byte-identical match.

## Provenance

Gameplay concepts (aircraft movement, guns, collisions, health,
teams, scoring, match completion) derive from
`RhettCreighton/full-node-firewall-fly-over` at commit
`221b5410dd63a5467735bc4232e7292fb55ce62b`. That repository's README
declares Apache-2.0, but no LICENSE file exists at that commit; its
dependencies are raylib (rendering) plus a large specification/proof
apparatus. No code was imported: this package is a clean strict-C23
reimplementation of the headless simulation only, with no raylib
dependency.

The upstream "no-crash guarantee", signal-recovery, abort-override,
GDB-proof and philosophical-proof machinery are treated as historical
claims, not evidence. This package's determinism rests solely on its
own born-red selftests and the cross-node acceptance proof in
`tools/dev/arena_acceptance.sh`.

Depends only on zprng. Apache-2.0 licensed.
