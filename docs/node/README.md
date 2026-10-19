<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Node references

How the node boots, syncs, stores state, holds keys and recovers: operator and maintainer references for the chain-facing runtime.

| Document | Purpose |
|---|---|
| [HOW_THE_NODE_WORKS.md](./HOW_THE_NODE_WORKS.md) | follow a block through the node and find the stage that is waiting |
| [SYNC.md](./SYNC.md) | sync guide: methods, state offers, recovery |
| [BOOTSTRAPPING.md](./BOOTSTRAPPING.md) | legacy transparent-only starter pack |
| [CONSENSUS-STATE-BUNDLE.md](./CONSENSUS-STATE-BUNDLE.md) | naming and ownership authority for bootstrap artifacts |
| [sovereign-cutover-runbook.md](./sovereign-cutover-runbook.md) | owner-gated live cutover and revert procedure |
| [shielded-history-importer.md](./shielded-history-importer.md) | the shipped shielded-history import cure |
| [fresh-start-seam.md](./fresh-start-seam.md) | why a bare boot reaches no state source |
| [coldstart-remote-peer-proof.md](./coldstart-remote-peer-proof.md) | C3 stopwatch run against a remote peer |
| [tip-durability-collapse.md](./tip-durability-collapse.md) | rationale of record for coins_kv as sole live UTXO author |
| [concurrency-hazards-consensus-gated.md](./concurrency-hazards-consensus-gated.md) | cross-thread hazards on the chain-advance path |
| [canonical-unit-reconciliation.md](./canonical-unit-reconciliation.md) | systemd drop-in reconciliation runbook |
| [CANONICAL_LIFECYCLE.md](./CANONICAL_LIFECYCLE.md) | the single landing lifecycle |
| [LEGACY_LIFECYCLE.md](./LEGACY_LIFECYCLE.md) | legacy import and drift detection against a sibling zclassicd |
| [EQUIHASH_PARAMS.md](./EQUIHASH_PARAMS.md) | generated Equihash parameters by height |
| [JOIN.md](./JOIN.md) | joining the blockchain network and joining the package commons |
| [TELEMETRY_CONTRACT.md](./TELEMETRY_CONTRACT.md) | stable shape of ops.telemetry |
| [WINDOWS.md](./WINDOWS.md) | native Windows and WSL2 development |
| [MACOS_GUI_QUICKSTART.md](./MACOS_GUI_QUICKSTART.md) | scaffold, run and ship a macOS application |
| [ROM.md](./ROM.md) | compiled checkpoint and verification layers |
| [WALLET_PERSISTENCE_RECOVERY.md](./WALLET_PERSISTENCE_RECOVERY.md) | recovery when wallet keys on disk cannot be loaded |
| [CUSTODY_MODEL.md](./CUSTODY_MODEL.md) | wallet ownership and spend authority |
| [CHAIN_AUTHORITY.md](./CHAIN_AUTHORITY.md) | current chain-mutation paths and target ownership |
| [RELEASE_CANDIDATE_PIN.md](./RELEASE_CANDIDATE_PIN.md) | the record naming the build under proof |
| [SECURITY_AND_INTEGRITY.md](./SECURITY_AND_INTEGRITY.md) | security boundaries and build-verification results |
| [SELL.md](./SELL.md) | pay ZCL and sell a 1/1 collectible |
