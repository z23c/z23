# Chain-Tip-Durability Collapse — the wedge-class kill

The corrected mechanism (move the coins set INTO progress.kv as a `coins` table)
has **landed** (`engine/modules/storage/src/coins_kv.c`); `coins_kv` is now the **sole live
UTXO author and read source** (the event_log / `utxo_projection.db` is seed-only).
This doc is the rationale of record for the `coins_kv` subsystem — the WHY/invariant
anchor cited by the source.

## The disease (resolved by the rip-out below)

The served chain tip / "coins applied through N" **was** recorded
**redundantly** in multiple stores with **no atomic cross-commit**, so any
crash/recovery drifted them apart and boot *guessed* which was right. The
guessing was the bug factory.

### Root cause, code-confirmed (the single tear window)

The reducer's 8 stage logs + their cursors all commit atomically inside
`stage_run_once`'s `BEGIN IMMEDIATE` on **progress.kv** (`stage.c:316-356`) — they
never tear. **The coins set was the one exception.** The old `utxo_apply` step:
1. `emit_delta()` (in `utxo_apply_stage.c`) appended `EV_UTXO_ADD/SPEND` to the
   **event_log** (a separate file) via `event_log_append()` — **two fsyncs
   OUTSIDE** the stage txn (`utxo_projection.c:430,450`).
2. The inverse-delta + `utxo_apply_log` row + the stage cursor committed **later**,
   inside `stage_run_once`'s txn on **progress.kv**.
3. `utxo_projection_catch_up()` then folded the event_log into the coins table in
   **utxo_projection.db** — a **third** file, its **own** txn, advancing
   `last_consumed_offset` (`utxo_projection.c:362-396`).

So the coins (event_log + utxo_projection.db) and the cursor (progress.kv) lived
in different WAL databases with **no atomic cross-commit**. A kill-9 anywhere in
that window left the cursor ahead of/behind the coins it claimed to have
applied. Worse, `last_consumed_offset` was **height-blind** and was **never
rewound** when a reorg rewound the stage cursor — so `catch_up` resumed from a
stale offset and **no forward path could rebuild a torn projection**
(`script_validate` then logged `prevout_unresolved` on perfectly valid blocks; this
hit exactly height 3134571, which the oracle confirms is a **valid** main-chain
block — so torn LOCAL state, not a consensus bug). The old in-code comment in
`utxo_apply_stage.c` ("crash-safe … independent of the stage cursor txn") stated
the bug as a feature; the fix removed it (the file was rewritten — `apply_coins_kv`
now writes coins inside the stage's `BEGIN IMMEDIATE`).

## The single source of truth (verified)

**`tip_finalize`'s contiguous finalized frontier** — the row + the stage cursor
commit in ONE `stage_run_once` txn. It is the consensus gate (reorg detect →
chainwork-greater → UTXO conservation → MMB/FlyClient + wallet/Sapling), not a
redundant durability stage. Once the coins set commits in the **same** txn, the
finalized frontier and the coins are atomic by construction.

Rejected authorities (both NO-GO, code-confirmed): `coins_best_block` HASH is
**dead-legacy** (`process_block` has zero live callers) and not atomic; the old
`utxo_apply` cursor advanced PAST failed blocks (in `utxo_apply_stage.c`).

## The structural rip-out (corrected mechanism)

**Move the coins/UTXO set INTO progress.kv as a `coins` table, written inside
`stage_run_once`'s `BEGIN IMMEDIATE`** — exactly the proven-correct pattern of
`created_outputs_index` (a progress.kv table written in the body_persist txn,
which never tears). Then every effect of block N — coin add/delete, inverse-delta,
`utxo_apply_log` row, stage cursor — commits or rolls back as **one atomic unit**
in **one database / one WAL**. By construction there is nothing left to drift and
nothing for boot to guess between.

**Why NOT `ATTACH`:** SQLite gives atomic multi-database commit (master journal)
ONLY in rollback-journal mode. **progress.kv and utxo_projection.db are both WAL**
(`progress_store.c:59`, `utxo_projection.c` checkpoints) — in WAL there is no
master journal, so a cross-attached-db transaction is **NOT atomic**. ATTACH
would reintroduce the exact tear.

**Why NOT collapse onto a separate-db `applied_height`:** the inverse-delta (for
reorg unwind) lives in progress.kv and MUST be atomic with the coin mutation;
keeping coins in a separate db forces a second non-atomic boundary. One db is the
only clean answer.

## Boot invariant + standing regression contract

**Boot invariant:** served tip == tip_finalize contiguous ok=1 frontier == coins
MAX height; FAIL LOUD on divergence (silent-halt doctrine).

**MANDATORY acceptance gate:** kill-9 mid-climb ≥10×, restart each time — coins
MAX height == `utxo_apply` cursor-1 == tip_finalize frontier on EVERY restart (no
drift). ADVANCE_DEADLINE ≥300s. This is the proof the class is dead.

No must-never-fork gate is weakened: reorg detect, chainwork-greater, UTXO
conservation, PoW/Equihash, MMB/FlyClient, script/proof validation, crypto,
sapling all stay exactly where they are on the tip_finalize publish path. The
change only moves the *durability boundary* of the coins fold (now atomic),
which can only make consensus state more consistent. No `tip_finalize_log` row is
ever deleted (anti-rewind preserved); the public tip can never drop below the
contiguous ok=1 frontier. (Boot keeps a back-compat replay of pre-migration
event_log into the new progress.kv `coins` table.)

**Standing caution — `cold-import` is NOT safe against the always-running oracle**
(refuted, 2026-06-07): `ldb_snapshot_make` hardlinks the oracle's LevelDB SSTs — a
race with the oracle's compaction can ENOENT mid-copy and fall back to unlinking
the oracle's LOCK (`ldb_snapshot.c:99-109`, no SST-deletion retry). Do not run it
against the live oracle. (This is a caution about reading the oracle's files, not a
claim that the live datadir is currently torn.)
