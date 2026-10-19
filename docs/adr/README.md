<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Architecture decision records

Each record states one architectural decision, the context that forced it,
and its consequences, numbered in the order it was accepted. Every record
opens with a Status line; a superseded record keeps its text and names what
replaced it.

Commands: `discover.wiki`, `discover.read`

- List the records with summaries: `z23 wiki adr`.
- Read one record: `z23 discover read adr/0002-sealed-consensus-core.md`.
- Current priorities and acceptance live in [`../../AGENTS.md`](../../AGENTS.md)
  and [`../quality/MVP.md`](../quality/MVP.md); a record explains why, not what is next.

## Also in this directory

- [`0001-personal-sovereignty-stack.md`](./0001-personal-sovereignty-stack.md): ADR-0001: Adopt the AI-Integrated Personal Sovereignty Stack vision
- [`0003-os-substrate-verdict.md`](./0003-os-substrate-verdict.md): ADR-0003: No operating system, no central scheduler — build the missing organs in-tree
- [`0004-capability-service-fabric-and-app-checkpoints.md`](./0004-capability-service-fabric-and-app-checkpoints.md): ADR-0004: Capability service fabric and cartridge-style App checkpoints
- [`0005-offchain-signed-contract-channels.md`](./0005-offchain-signed-contract-channels.md): ADR-0005: Off-chain signed-contract channels over deterministic node programs
- [`0006-always-sync-spine-file-size-raises.md`](./0006-always-sync-spine-file-size-raises.md): ADR-0006: File-size baseline raises for the always-sync spine core
- [`0007-property-settlement-and-trust-roots.md`](./0007-property-settlement-and-trust-roots.md): ADR-0007: Every metaverse property declares what settles it
- [`0008-seed-floor-declaration-file-size-raises.md`](./0008-seed-floor-declaration-file-size-raises.md): ADR-0008: File-size baseline raises for the external-seed floor declaration
- [`0009-swap-money-shape-guard-file-size-raise.md`](./0009-swap-money-shape-guard-file-size-raise.md): ADR-0009: File-size baseline raise for the atomic-swap money-shape guard
- [`0010-snapshot-io-file-size-raises.md`](./0010-snapshot-io-file-size-raises.md): ADR-0010: File-size raises for the consensus snapshot export/install IO
- [`0011-native-first-execution-with-emulator-failsafe.md`](./0011-native-first-execution-with-emulator-failsafe.md): ADR-0011: Native-first execution with an emulator failsafe
