# In-memory simulation network — deterministic testing reference

The RAM-network simulation harness is built on `engine/modules/sim/src/seed_tape.c`
(`sim/seed_tape.h`): an xoshiro256++ RNG plus a virtual mono/wall clock, both
derived from one `uint64` seed, installed into `platform_rng`/`platform_clock`.
**Every seed is a pure function of that one scalar** — record/replay and the
`.cap` capsule format (`tools/scripts/simnet_replay_capsule.sh`) depend on
this: replaying a capsule only needs the seed, never wall-clock or host
entropy.

## Components

- `engine/modules/sim/src/simnet.c` — single-node RAM harness over real
  `connect_block(..., expensive_checks=false)`.
- `engine/modules/sim/src/simnet_cluster.c` — multi-node cluster with deterministic
  per-link latency/reorder from the seed_tape RNG, fork-choice by
  `nChainWork`, real `disconnect_block`/`connect_block` reorg. Test group
  `simnet_cluster` (`test_simnet_cluster.c`, `test_simnet_cluster_reorg.c`).
- `engine/modules/sim/src/simnet_byzantine.c` — adversarial peers and typed-blocker
  assertions: each rejection class rejects, names a typed blocker, does not
  advance the tip, and still accepts the next honest block. Test group
  `simnet_byzantine`.
- `engine/modules/sim/src/simnet_wire.c` — in-memory wire-frame transport (see
  [`io-harness-design.md`](./io-harness-design.md)). Test group
  `simnet_wire`.
- Deterministic seed fuzzing over the cluster: `test_simnet_fuzz.c`
  (`ZCL_SIMNET_FUZZ_ITERS` iterations, derived sub-seeds); on failure it
  prints `SIMNET REPRO SEED=0x...` and writes a replayable capsule via
  `postmortem_capture_write`.
- `engine/modules/sim/src/simnet_mempool.c` + `simnet_contract.c` — RAM mempool and
  P2SH HTLC/escrow contract-state projection testing (`PENDING → FUNDED →
  REDEEMED/REFUNDED/EXPIRED`). Test group `simnet_contract`.
- `tools/sim/chaos.c` — chaos binary driving the cluster via a `.scenario`
  DSL; `make simnet-repro SEED=0x...` replays a specific seed.

Consensus stays untouched throughout — `expensive_checks=false` is the
existing escape hatch every harness above uses; it never bypasses PoW,
signature, or shielded-proof checks, only the expensive verification passes
already skippable on a trusted local mint path.

## CI gating

Fast/hermetic in `make ci` via `test_parallel` (each lane ≲2s): `simnet_cluster`,
`simnet_byzantine`, `simnet_fuzz` (`ZCL_SIMNET_FUZZ_ITERS≈128`), `simnet_contract`.
Nightly (not in `make ci`): `make simnet-fuzz-sweep` (10k–100k seeds, deep-reorg
depth sweeps, larger clusters) aggregated as `make simnet-nightly`. Both tiers
print `SIMNET REPRO SEED` on failure and replay exact tapes from capsules.
