# 09 — Seed Replay: Determinism as a Debugging Tool

## What this demonstrates

`docs/examples/09_seed_replay.c` opens a `seed_tape_t` (engine/modules/sim/include/sim/seed_tape.h)
with a fixed 64-bit seed, drives a tiny recording — a handful of RNG draws, clock
advances, and injected peer-message events — then snapshots the live tape two
ways at the same instant: a plain `.bin` file via `seed_tape_save()`, and a
postmortem capsule via `postmortem_capture_write()` (the same call a live node's
crash handler makes). It then reloads both snapshots in REPLAY mode and proves
each one reproduces the exact RNG continuation and event order the original
recording produced — the mechanism behind "every bug becomes a 64-bit seed."

## Build and run

```bash
make -C examples && ./examples/bin/09_seed_replay
```

(The examples tree links against the same `engine/modules/sim`, `platform/modules/platform`, etc.
objects the main build produces; run `make -j$(nproc)` first if this is a
clean checkout.)

## Expected output sketch

```
=== 09_seed_replay: record a seed tape, snapshot it two ways, prove bit-identical replay ===

[1/5] opening a fresh seed tape (seed=0x5eed7a9e00000042)...
[2/5] driving a small 'sim run': 4 RNG draws (nonce stand-ins) + 3 clock
      advances (150s simulated block interval) + 3 injected peer-message
      events...
      sample nonce draws: 0x... 0x... ...
[3/5] snapshotting the LIVE tape two ways at this exact instant: a plain
      .bin file and a postmortem capsule (as if a crash happened right
      here)...
      tape file:   /tmp/.../tape.bin
      capsule dir: /tmp/.../capsules/<timestamp>-<pid>.cap
[4/5] continuing the ORIGINAL tape 5 more RNG draws — this is the ground
      truth both reloaded snapshots must reproduce...
[5/5] reloading BOTH snapshots in REPLAY mode and proving bit-identical
      RNG continuation + identical event order...
      -- from plain .bin file --
      RNG continuation matches ground truth: yes
      replay tape rejects new writes (-EROFS): yes
      injected event queue replays in order: yes
      -- from postmortem capsule --
      RNG continuation matches ground truth: yes
      replay tape rejects new writes (-EROFS): yes
      injected event queue replays in order: yes

=== SUCCESS: both the plain .bin file and the postmortem capsule replayed the exact
RNG stream and event order the original process produced — a crash capsule
is a complete, replayable postmortem, no live process needed ===
```

Exit code 0 on success; nonzero with an `stderr` reason on any mismatch.

## Key APIs used

- `engine/modules/sim/include/sim/seed_tape.h` — `seed_tape_open`, `seed_tape_install`,
  `seed_tape_advance`, `seed_tape_inject`, `seed_tape_save`, `seed_tape_load`,
  `seed_tape_next_event`, `seed_tape_uninstall`, `seed_tape_close`
- `engine/modules/sim/include/sim/postmortem.h` — `postmortem_capture_write`,
  `postmortem_capsule_load_tape`
- `platform/modules/platform/include/platform/rng.h` — `rng_u64` (reads through the
  installed tape while a tape is installed)

## Production counterpart

Production never opens a seed tape by hand — a live node's boot path
(`engine/composition/src/boot.c`) wires a real tape plus `postmortem_install()` at process
start, so a `SIGSEGV`/`SIGABRT` handler calls `postmortem_capture_write()`
automatically, with no operator action needed. An operator (or Claude, via the
native command surface) inspects capsules with `z23 ops postmortem list`
and replays them through the corresponding RPC fallback, which are thin wrappers over
the same `postmortem_capsule_list()` / `postmortem_capsule_load_tape()` calls
this example drives directly.
