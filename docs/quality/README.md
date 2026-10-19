<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Quality and measurement

Simulators, chaos harnesses, benchmarks, acceptance gates and transaction laboratories that measure Z23 reliability and speed.

| Document | Purpose |
|---|---|
| [CHAOS_HARNESS.md](./CHAOS_HARNESS.md) | the two chaos and kill harnesses |
| [SIMULATOR.md](./SIMULATOR.md) | deterministic simulator surface and action coverage |
| [SIMULATOR_TXNS.md](./SIMULATOR_TXNS.md) | transparent-transaction toolkit for simnet tests |
| [SIMNET_PERF.md](./SIMNET_PERF.md) | deterministic simulation performance |
| [sim-phase2-plan.md](./sim-phase2-plan.md) | in-memory simulation network reference |
| [io-harness-design.md](./io-harness-design.md) | simnet_wire adversarial network-IO harness |
| [USER_BENCHMARKS.md](./USER_BENCHMARKS.md) | user-facing measurement specification |
| [BENCHMARKS_LOG.md](./BENCHMARKS_LOG.md) | append-only measured benchmark ledger |
| [NEON_CRYPTO_MATRIX.md](./NEON_CRYPTO_MATRIX.md) | per-crypto-family x86-64 and arm64 tier matrix |
| [GROTH16-SPEND-PARITY.md](./GROTH16-SPEND-PARITY.md) | Sapling spend-circuit differential parity scoreboard |
| [stopwatch-gates.md](./stopwatch-gates.md) | wall-clock stopwatch gates |
| [mvp-ci-map.md](./mvp-ci-map.md) | each MVP criterion mapped to its CI check |
| [mvp-live-gate.md](./mvp-live-gate.md) | read-only live-node MVP probe |
| [TRANSACTION_LAB.md](./TRANSACTION_LAB.md) | transaction laboratory notebook |
| [TRANSACTION_MICRO_LAB.md](./TRANSACTION_MICRO_LAB.md) | owner-gated 100-transaction demonstration runbook |
| [LIVE_TRANSACTION_DEMONSTRATIONS.md](./LIVE_TRANSACTION_DEMONSTRATIONS.md) | which transaction shapes are demonstrated live |
| [transaction-lab-events.jsonl](./transaction-lab-events.jsonl) | event ledger backing TRANSACTION_LAB |
| [transaction-micro-lab-events.jsonl](./transaction-micro-lab-events.jsonl) | event ledger backing TRANSACTION_MICRO_LAB |
| [CODE_FEARLESSLY.md](./CODE_FEARLESSLY.md) | why safe change depends on the environment |

## Also in this directory

- [`MVP.md`](./MVP.md): z23 — MVP target
