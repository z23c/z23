<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Chain authority: current proof boundary and target ownership

This page answers one narrow question: **which code may turn validated chain
inputs into durable runtime chain truth?** It records what the checkout proves,
what it only intends, and the boundary a future refactor must enforce. It is not
a claim that wallet, peer, Commons, or other product state is a projection of
the chain kernel; those domains retain their own authorities.

## Verdict

The post-flip node has one physical SQLite transaction domain for reducer chain
state: `consensus.db`, opened by `progress_store`. Its seven fingerprinted
tables are `coins`, `sprout_anchors`, `sapling_anchors`, `anchor_state`,
`nullifiers`, `progress_meta`, and `stage_cursor`. Other tables co-located in
the file include stage verdict journals, inverse UTXO deltas,
`created_outputs`, repair rows, state-producer session/receipt rows, and the
two consensus-state proof-prefix tables; they are used or cleared by kernel
transactions and install cutovers. Co-location does not make `created_outputs` consensus
truth: it is a replayable prevout-resolution cache written by `body_persist`.
`progress.kv` is a separate projection file whose
executable migration STAY set is exactly `address_index`,
`address_index_state`, `txindex`, and `txindex_state`.

That proves a physical store boundary. It does **not** prove one code-level
writer or one owner for every durable chain fact. The mutable
`progress_store_db()` handle and several stage/storage APIs expose raw
`sqlite3 *`; source files in normal fold, bulk-fold flush, boot reconciliation,
repair, import, and install lifecycles can all mutate kernel tables. SQLite and
`progress_store_tx_lock()` serialize cooperating callers, but serialization is
not ownership.

## Mutation roles found in the current tree

| Role | Current path | What it may mutate | Authority reading |
|---|---|---|---|
| Normal live reducer | `stage_run_once()` and the eight stage jobs | Stage cursor + verdict row; `body_persist` writes the replayable `created_outputs` cache; `utxo_apply` also changes coins, anchors, nullifiers, delta rows, and frontier metadata | Intended live chain actor; transactions are centralized, but the capability is an untyped database handle. |
| Bulk-fold persistence | `coins_ram_flush()`, triggered automatically by `coins_ram_note_applied()`, after a batch by `coins_ram_flush_due()`, or at clean stop/export by `coins_ram_flush_final()` | Durable coins overlay, `utxo_apply` cursor, applied height, and flush watermark in a fresh kernel transaction | A routine writer in enabled bulk-fold mode, not merely recovery. It is a second implementation of frontier mutation guarded by a reducer witness. |
| Boot reconciliation | `coins_ram_reconcile_boot()` and boot/install gates | Rewinds cursor/frontier metadata to the last durable overlay watermark or installs a state generation accepted under bounded copy, receipt, and chain-binding evidence | Recovery or activation authority; it must never be counted as ordinary forward progress. Snapshot evidence does not prove derivation of the asserted UTXO/shielded state. |
| Supervised repair/reorg | reducer frontier replay, stage repair, seal rewind, chain restore | Deletes stale verdict ranges, replays inverse deltas, rewinds coins and cursors, records repair evidence | Necessary mutation authority with different preconditions from live advance. Raw access currently prevents a type-level proof that it cannot advance arbitrary facts. |
| Migration/candidate production | `consensus_db` migration and consensus-state producer/candidate code | Copies or constructs a contained kernel image and proof receipts | Produces or relocates bytes. A candidate is inert until the activation protocol accepts it; a copied database is not live authority merely because its tables look valid. |
| Projection folds | `projection_store` users | Address and transaction indexes in `progress.kv` | Rebuildable views. They have a different handle, mutex, and WAL and must not decide consensus. |

The source census exposed by `z23 code provenance facts` is useful for finding
named-literal writes to `progress_meta`, `stage_cursor`, and `node_state`. Its
own output correctly marks source completeness, runtime reachability, database
identity, and authority as unproven. The frontier-owner lint gate is likewise
limited to its manifest-declared regular expressions and scan roots. Neither is
a whole-program ownership proof.

## The ownership boundary

The durable design separates **meaning**, **execution**, and **capability**:

| Root | May own | Must not own |
|---|---|---|
| `core/` | Deterministic consensus predicates, parameters, cryptography, and pure state-transition meaning: whether an input and proposed transition are valid | Runtime scheduling, SQLite transactions, recovery policy, clocks, sockets, or authority to select and publish a live tip |
| `engine/reducer/` + reducer jobs | The live ordered actor that applies validated transitions, commits the kernel transaction, and publishes the served frontier | New consensus predicates or an alternate persistent chain ledger |
| `engine/modules/storage/` | Opaque persistence primitives, exact schemas, transaction mechanics, commitments, and file migration | Deciding which chain transition is valid or independently advancing a frontier |
| `contexts/` | Wallet custody and feature-owned durable facts; rebuildable product projections where declared | Direct mutation of consensus kernel truth outside an explicit engine capability |
| `cognition/` | Read-only code/evidence analysis and inert proposals | Runtime chain, wallet, deployment, or acceptance authority |
| `platform/` | Portable OS, file, time, entropy, network, and process capabilities behind narrow interfaces | Domain truth or policy decisions derived from those capabilities |

This is the target contract, not a statement that the physical tree already
conforms. In particular, the effective byte seal covers all tracked `core/`
content (except its manifest), including `core/modules/sync` and
`core/modules/net`; the pure include-boundary gate covers only four smaller
contexts. `core/modules/sync/src/stage.c` currently implements SQLite
transaction and cursor mechanics. Moving that runtime primitive to the engine,
or ratifying it as sealed runtime infrastructure, is an owner decision because
it crosses the sealed boundary.

## Capability needed to prove one writer

The clean end state is an opaque capability, not another pathname allowlist:

1. Storage constructs a private kernel handle; ordinary code cannot obtain a
   mutable `sqlite3 *`.
2. The reducer owns a `chain_kernel_tx` capability that can apply one validated
   transition and atomically write its state, verdict, and cursor.
3. Bulk-fold persistence uses that same owner operation instead of writing the
   frontier independently.
4. Recovery receives a narrower `chain_recovery_tx` capability. It can only
   rewind or install after typed preconditions and copy-first evidence; it
   cannot masquerade as normal advance.
5. Projection code receives only a projection handle. Observers receive
   snapshots or read-only connections.
6. Fault tests kill the process at every commit boundary and independently
   verify that restart exposes either the complete prior state or the complete
   next state, never a mixed frontier.

Until those constraints are type-visible and exercised through runtime and
crash evidence, the defensible statement is:

> The chain kernel is physically centralized and cooperating transactions are
> serialized. Exactly one live code writer and one owner for every durable
> chain fact remain **UNPROVEN**.

## Owner-gated decision

The next irreversible architectural choice is whether the full `core/` byte
seal intentionally includes runtime sync/network machinery. If not, authorize
an unseal/reseal slice that moves stage transaction mechanics into the engine
and introduces the opaque mutation capability above. If yes, update the core
doctrine to name the broader sealed runtime boundary and enforce its different
purity rules. Do not silently preserve the current mismatch between the seal's
effective scope and the documented semantic core.
