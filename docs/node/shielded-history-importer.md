# Shielded history importer — complete anchor + nullifier import from `zclassicd` chainstate

> This is a reference doc for **shipped** code — `-import-complete-shielded`,
> `shielded_history_import_service.c`, and the `anchor_kv`/`nullifier_kv`
> cursor-flip primitive. It is the *operational* (`release_assisted`) cure —
> a separate `sovereign` cure (from-genesis self-mint + bundle install) is
> the mechanism that actually passed the wedge live; see
> `docs/agent/HANDOFF.md` §0-LATEST for current trust-mode status and
> `sovereign-cutover-runbook.md` for that path. File:line references below
> rot — re-verify against HEAD before relying on them.

## What this closes

The reducer requires the **complete historical anchor + nullifier set** for
each shielded pool (Sprout, Sapling), not just the current frontier, because a
shielded spend can reference any prior root. `anchor_kv`/`nullifier_kv` track
this via a per-pool `activation_cursor`: **0 means from-genesis history is
present**; a positive cursor means "history below this height is not
guaranteed complete," and a fold that needs a root below the cursor holds
(`HISTORY_INCOMPLETE`) rather than silently accepting or forging one. This
importer is a fast, atomic way to fill both histories from an operator's own
`zclassicd` chainstate — an alternative to the from-genesis fold, not a
replacement for the sovereign (self-derived) cure.

## Data model

**`anchor_kv`** (`engine/modules/storage/src/anchor_kv.c`):
`sprout_anchors(anchor BLOB PK, height INTEGER, tree BLOB)` and
`sapling_anchors(...)` — the value is the **complete incremental frontier**,
not just the root (`anchor_kv.h`) — plus `anchor_state(pool PK,
activation_cursor)`. Sole per-root writer: `anchor_kv_add_tree(db, pool, tree,
height)` — `INSERT OR IGNORE`, idempotent, empty-root no-op. Lookup
`anchor_kv_get` returns `ANCHOR_KV_FOUND` / `ANCHOR_KV_HISTORY_INCOMPLETE`
(missing **and** `activation_cursor > 0`) — never a silent forge. The blocker
`utxo_apply_anchor_gap_blocker_refresh` (`engine/jobs/src/utxo_apply_anchors.c`)
reads `anchor_kv_activation_cursor` for both pools and raises the permanent
blocker `utxo_apply.anchor_backfill_gap` on `incomplete`, clearing only when
both pools report `activation_cursor == 0`.

**`nullifier_kv`** (`engine/modules/storage/src/nullifier_kv.c`):
`nullifiers(nf BLOB, pool INTEGER, height INTEGER, PRIMARY KEY(nf,pool))` +
`idx_nullifiers_height`. Sole writer: `nullifier_kv_add(db, nf, pool,
height)` — `INSERT OR REPLACE`. `nullifier_kv_get` fails **closed** on any
bind error. A separate permanent blocker `utxo_apply.nullifier_backfill_gap`
mirrors the anchor gap, keyed on its own `progress_meta` cursor
`nullifier_kv.activation_cursor`.

**Cursor-flip primitive:** `anchor_kv_publish_full_replay_complete_in_tx`
flips `activation_cursor` to 0 **without clearing rows** — the operation the
importer uses after a complete bulk insert.
`nullifier_kv_publish_full_replay_complete_in_tx` mirrors it for the
nullifier side.

## Verification asymmetry: Sapling is header-bound, Sprout is not

ZClassic headers commit `hashFinalSaplingRoot` (Heartwood was never activated
on this chain, so the field was never repurposed) — `struct block_header`
(`core/modules/primitives/include/primitives/block.h`), mirrored in
`struct block_index`. An imported **Sapling** frontier's root is therefore
byte-verifiable against `block_index.hashFinalSaplingRoot` at any height. The
**Sprout** frontier has no header commitment; its verification bottoms out at the
`zclassicd` chainstate's own byte content plus the reader's fail-closed root
re-hash check. This asymmetry is recorded in the importer's provenance and is
why this path is `release_assisted`, not `sovereign`.

## The `zclassicd` chainstate source (LevelDB key prefixes)

| Prefix | Const | Record |
|---|---|---|
| `'A'` | `DB_SPROUT_ANCHOR` | Sprout anchor: key `'A'‖root(32)`, value = serialized `SproutMerkleTree` |
| `'Z'` | `DB_SAPLING_ANCHOR` | Sapling anchor: key `'Z'‖root(32)`, value = serialized `SaplingMerkleTree` |
| `'s'` | `DB_NULLIFIER` | Sprout nullifier: key `'s'‖nf(32)`, value = presence bool |
| `'S'` | `DB_SAPLING_NULLIFIER` | Sapling nullifier: key `'S'‖nf(32)`, value = presence bool |
| `'a'` / `'z'` | `DB_BEST_SPROUT_ANCHOR` / `DB_BEST_SAPLING_ANCHOR` | bare-prefix key → current root pointer |
| `'B'` | `DB_BEST_BLOCK` | tip block hash |

Anchors are erased only on reorg disconnect, so under linear forward sync
`zclassicd`'s tip chainstate holds every historical root a live block could
spend against — the completeness property the importer relies on.

## The importer

Reused foundation: `engine/modules/storage/src/chainstate_legacy_reader.c` (clean-room
C23 reader over the `zclassicd` chainstate LevelDB), the wire-compatible tree
codec `incremental_tree_serialize/deserialize`
(`core/modules/sapling/include/sapling/incremental_merkle_tree.h`), and the
WAL-inclusive stable copy `utxo_recovery_copy_chainstate_stable`
(`engine/services/src/utxo_recovery_service.c`) — a full `cp -a` of the
chainstate (SSTs + the `.log` WAL) proven point-in-time by a dir signature.
The SST-only `ldb_snapshot_make` is NOT usable here: it drops the `.log`
WAL, so the `'B'`/`'z'` pointers read the last compacted state while coin
records sit tens of thousands of blocks fresher.

Reader entry points (`chainstate_legacy_reader.c/.h`):
`chainstate_legacy_iter_sapling_anchors` / `_sprout_anchors` (seek `'Z'`/`'A'`,
fail-closed root re-hash check per row), `chainstate_legacy_iter_sapling_nullifiers`
/ `_sprout_nullifiers` (seek `'S'`/`'s'`), `chainstate_legacy_get_sapling_anchor`
(by-root lookup, `FOUND`/not-found), `chainstate_legacy_get_best_sapling_anchor`
/ `_best_sprout_anchor` (`'z'`/`'a'` pointers — provenance only, never the bind).

Service: `engine/services/src/shielded_history_import_service.c` —
`shielded_history_import_from_chainstate(progress_db, chainstate_src_path,
height, block_hash, sapling_root, out)`. Algorithm: point-in-time copy the
chainstate → require its `'B'` best block to equal the target resume block
exactly (nullifiers are additive and carry no source heights, so importing a
newer set makes valid forward spends look spent) → verify the EXPECTED TIP
ANCHOR BY ROOT up front:
`chainstate_legacy_get_sapling_anchor(reader, expected_tip_sapling_root,
&tip_tree)` must return FOUND and an explicit `incremental_tree_root` Pedersen
re-verify of the returned tree must equal the expected root — a stale `'z'`
pointer (WAL/compaction lag) therefore cannot refuse a good import, while a
forged tree still fails closed → `BEGIN IMMEDIATE` → bulk-insert every Sapling
anchor → bulk-insert every Sprout anchor → bulk-insert every nullifier for
both pools → sanity-floor checks → flip both activation cursors to 0 via the
cursor-flip primitives → stamp a `shielded_import.provenance` row → `COMMIT`.
Any anomaly (torn record, root mismatch, count below floor) rolls back and
writes nothing — the blocker stays in place rather than flipping on an
incomplete set.

The expected tip (`tip_height`, block hash, Sapling root) is derived
TARGET-side: the reducer seed floor
(`REDUCER_SEED_FLOOR_HEIGHT_KEY`) when declared — a cold-import-seeded
datadir owes shielded history only up to its seed, and the fold's own rows
cover above it (the shielded preflight guarantees the folded span consumed
no spends) — else `coins_best`; the root comes from the target's own header
INDEX flat file at that height (`block_index_flat_header_at`). The source's
`'B'` pointer must match the target hash exactly before the transaction opens.
A fresh
never-booted datadir has neither boundary and is refused with "boot it once
first" (the importer opens the target's `node.db` itself, so the node must
also be STOPPED — GRACEFULLY: the shutdown flat save is what freshens
block_index.bin past the header-sync tip).

The root source is block_index.bin, NOT node.db `blocks.sapling_root`
(blocks rows are only written on body fold / lean sync / block import, and
a seeded boot's fold-resume anchor is a header-only height — canary FAIL#6)
and NOT the event-log block_index projection (a bulk P2P header sync emits
no EV_BLOCK_HEADER events, so the projection is empty on a fresh
cold-import datadir — canary FAIL#7). The point reader
(`block_index_flat_header_at`, engine/services/src/block_index_loader.c)
mmaps the flat, verifies the embedded BIIE SHA3 (legacy sidecar-only files
are refused — a bind this load-bearing does not read unverified bytes), and
binary-searches the height-sorted 172-byte rows; its format math is proven
byte-exact against the zd oracle (hash AND `finalsaplingroot` at
h=3202041). A stale-branch sibling at the same height fails CLOSED at the
service's by-root source lookup (a sibling never connected has no anchor
record), never a misbind.

Entry point: boot flag `-import-complete-shielded=ZCLASSICD-DATADIR`
(`engine/entry/main.c`, `import_complete_shielded_mode`) — not a native command.
`import_shielded_is_live_datadir()` refuses `~/.zclassic-c23` and
`~/.zclassic-c23-mint` by construction, so it only runs against an operator
`-datadir=<COPY>`. On success it prints `IMPORT COMPLETE (committed=1):
sapling_anchors=... sprout_anchors=... sapling_nf=... sprout_nf=...` (matched
by `tools/scripts/import-copy-prove.sh`) and exits 0.

## Operational vs sovereign verification split

The distinction lives in two independent `coins_kv` bits:

- `coins_kv_is_proven_authority(db, &applied)` — true once the transparent
  coin set is migrated and self-consistent (true for borrowed/seeded state
  too). This is the **operational** "can serve" signal.
- `coins_kv_contains_refold_marker(db)` (reads `COINS_KV_SELF_FOLDED_KEY`) —
  the **sovereign** bit: the coin set is self-derived (checkpoint-verified or
  from-genesis refold). Set by `coins_kv_mark_self_folded`.
- Composite: `coins_kv_tip_is_self_derived(db, hstar, reason, cap)`.

This importer fills the two shielded histories and flips both activation
cursors — it does **not** touch `COINS_KV_SELF_FOLDED_KEY`. After a successful
import: `coins_kv_is_proven_authority` stays true (serves tip: explorer,
REST/onion API, P2P relay, wallet viewing, reducer forward-fold), and
`coins_kv_contains_refold_marker` stays false (honest `release_assisted`
verification state — borrowed shielded history, Sapling chain-bound, Sprout
`zclassicd`-bound). `bundle_exporter.c`, `consensus_state_snapshot_export_proof.c`,
`boot_snapshot_offer.c`, and `consensus_state_snapshot_candidate_validate.c`
all gate export/re-serve/advertise on the sovereign bit, so a
`release_assisted` node can serve tip but cannot publish or re-seed the
network with borrowed shielded state.

`z23 dumpstate sovereignty` surfaces the live posture
(`coins_kv_proven_authority`, `self_folded_marker`, `trust_mode`:
`sovereign` | `release_assisted` | `bare`, `authority_posture`). Expected
value right after an import: `release_assisted` /
`proven_but_not_self_folded`.

## 5. Phone spend rule (`-spend-after-checkpoint`)

`sovereignty_guard_allow("wallet_spend")` refuses every spend while the tip is
`release_assisted`, which is what a phone started from a snapshot is. The one
exception is an explicit, default-off startup option, `-spend-after-checkpoint`,
meant for the phone build. The Android app does not pass it yet; until it
does, no shipped caller turns the rule on. It changes `z_sendmany` only (the
registered RPC handler, and `core.wallet.shielded.send`, which calls it).
`sendtoaddress`, `sendmany`, `zslp`, market, vault, multisig and the wallet view
(send and shield forms) keep the strict guard and stay refused, as do in-process callers of `rpc_z_sendmany` and
`z_sendmany_prepare`. Mining, bundle export and seeding are not touched, and
the capability table in `services/sync_trust_policy.h` is unchanged.

Nothing is read from a stored "approved" flag. At every send
`wallet_spend_gate_check` (`contexts/wallet/controllers/src/wallet_spend_gate.c`)
re-verifies, in order, and refuses with the first failing token:

| Token | Check |
|---|---|
| `option_off` | the process was not started with the option |
| `tip_not_validated` | no validated tip block (reducer tip), or its header Sapling root is unset |
| `behind_tip` | the validated tip trails the best header by more than 2 blocks |
| `checkpoint_missing` | no baked checkpoint at or below the tip, or the header chain does not reach it |
| `tip_not_descended` | the tip's ancestor at a baked checkpoint height has another hash |
| `checkpoint_mismatch` | the header `hashFinalSaplingRoot` at the baked frontier height differs from the baked frontier root |
| `anchor_root_mismatch` | the header Sapling root at the tip is absent from the reducer's per-block Sapling anchor ledger; or, before proving, a selected note's witness root differs from the header root at its witness height |
| `seed_floor_unrecorded` | the strict guard refused (borrowed history) and neither an assisted-install seam nor a reducer seed floor is recorded, so the floor would be the keystone height alone |
| `floor_unknown` | the Sapling anchor or nullifier activation cursor is absent, or the assisted-install seam, the reducer seed floor or the anchor ledger cannot be read, or the progress lock was not obtained within the bounded wait (5 s) |

An assisted bundle install resets both cursors to 0 and records its seam height. A cold import declares the reducer seed floor, and `-import-complete-shielded` then sets both cursors to 0 with no seam. The floor includes the seam height when one is recorded and the seed floor when one is declared, so funds from before the seeded state stay out in every install mode (keystone seed, assisted bundle, cold import). An unreadable seam or seed floor gives `floor_unknown`. When the strict guard refused and neither a seam nor a seed floor is recorded, the spend is refused with `seed_floor_unrecorded`; the floor is never left to the keystone height alone. A failed seed-floor write at cold import is logged and leaves spends refused this way.

With the option on, the strict guard alone never removes the floor. It counts a
failed authority read as "not borrowed", so no floor is applied only when the
durable self-folded marker reads true; otherwise the rule and floor apply.

Every baked checkpoint (the keystone and each rung) at or below the tip must
pass the two header checks. Header roots are proof-of-work committed.

**Funds floor.** The floor is `max(compiled keystone height, Sapling anchor
activation cursor, nullifier activation cursor, assisted-install seam height, reducer seed floor)`. A cursor of 0 does not prove the pre-seed history was replayed independently (a snapshot can carry a nullifier section), so the keystone height keeps older funds out. A shielded note or transparent coin received at or below the floor,
or with an unknown height, is never selected, change included (change is a new
output above the floor). A send that needs more than the post-floor funds
refuses with `insufficient_post_checkpoint_funds` and the shortfall, and never
spends partly; the reply says funds at or before the floor are not usable yet, not that they are absent. When the send's `minconf` excluded the notes instead, the reply names `insufficient_confirmed_funds` and says the notes have fewer confirmations than `minconf`; when both excluded notes, it names both. The shortfall goes to the caller only and is not logged.
The native send command is keyed, so a refusal of this rule frees the key and
answers with `SEND_REFUSED_KEY_RELEASED`: the refusal came before anything was
built, so nothing was sent and the caller may retry (any other
`WALLET_RPC_ERROR` may mean the send went out). Its log line carries a fixed
text, never the reply text.

**What the rule does not do.** It does not compare the snapshot's transparent
coin set with the checkpoint, and that cannot be done after the node has folded
forward: the set at the checkpoint height no longer exists to recompute. It
does not prove the snapshot was honest. It spends only funds created in blocks
this node validated after the floor, and binds the shielded state to
proof-of-work-committed roots (the two header checks and the witness check), so
a wrong snapshot makes a send refuse or fail on the device, not spend wrongly.
The ledger check reads the reducer's anchor table, not the persisted
`node_state["sapling_tree"]` copy, which is written only on rebuild, rescan and
install and may lag the tip.

Both cursor reads and the ledger read wait for the progress-store lock for at
most 5 s instead of trying it once; status reads use a try-lock and report
`unknown_progress_busy` while a walk holds the lock, and a send must not be
refused for that. Only a read failure or the timeout gives `floor_unknown`.

**One spent note below the floor blocks every shielded send.** The send path
reconciles the wallet's shielded notes against the chain before selecting, and
reconciling a spent note needs the body of the block that holds it. Blocks
below the seeded state have no body on a phone, so a note at or below the floor
that the chain shows as spent makes the send refuse with "Canonical shielded
note state is unavailable". The rule does not change that reconciliation.

**Nodes with a positive cursor.** On a node whose anchor or nullifier
activation cursor is positive, the apply stage holds every block that contains
a Sapling spend or JoinSplit (`shielded_history_incomplete`) and does not
advance past it. The tip then stops, `behind_tip` follows, and sends are
refused. The rule is therefore for nodes whose cursors are 0; it does not
change that hold.

`z23 dumpstate sovereignty` reports the rule in a separate
`gated`-sibling object, `spend_after_checkpoint` (`enabled`, `last_send_check`),
and does not change the meaning of the existing fields.

## Copy-prove harness

`tools/scripts/import-copy-prove.sh` covers this path (its verdict does
not require `self_folded`, unlike the sovereign harness). Contract (see the
script's own header comment for the authoritative, current detail):

1. Safety: requires the `--copy-dir` marker, refuses to alias a live datadir.
2. Header refresh: `--importblockindex` against the copy to refresh its
   header chain before the importer runs (a stale copy header chain makes
   the tip-frontier bind refuse with a zero `hashFinalSaplingRoot`).
3. Runs the importer against the copy — no separate manual chainstate copy
   step; the importer makes its own point-in-time snapshot internally.
4. Normal isolated boot of the copy.
5. Gate: H\* climbs past the wedge height and keeps rising, both anchor/
   nullifier backfill-gap blockers absent, `coins_applied_height == hstar+1`,
   and exact same-height tip-hash parity vs `zclassicd` at the pre-wedge,
   wedge+1, and current-tip heights.
6. Expected posture: `dumpstate sovereignty` reports `release_assisted` /
   `proven_but_not_self_folded` — a PASS-with-assisted-posture, not a failure.
7. Warm-restart + kill-9 mid-boot: H\* must not regress, blocker must not
   reappear.

Only on green does the operator run the same importer against the live
canonical datadir.

## Open items

- **Mining/spend are not bit-gated on `self_folded` anywhere in the tree.**
  Per `docs/SOVEREIGN-NETWORK-ROADMAP.md` Phase 1 ("mining, snapshot
  re-serving, and wallet spending off until background full-history
  verification promotes"), the mint entry and the `z_sendmany`/spend entry
  need an explicit `coins_kv_tip_is_self_derived` guard so borrowed shielded
  history can never be used to mint or spend. Small, safety-tightening,
  should land with any live use of this path.
- **`coins_kv_mark_self_folded` wiring gap.** As of the last check it is
  called only from test code and the producer bundle's install path, not
  from a live in-process refold — verify the promotion path actually stamps
  it before relying on `self_folded` flipping automatically.
- **C23's default Sapling-root enforcement is off** (`-enforce-sapling-root`
  defaults false; full-equality check is gated pending a 0-false-reject
  full-history replay). The importer's tip-anchor bind and the copy-prove
  hash-parity check cover the *import*, but ongoing forward validation does
  not re-check every block's Sapling root by default.
- **Sprout verification bottoms at the operator's own `zclassicd` chainstate** (no
  header commitment) — acceptable for a pre-Sapling, effectively-drained
  pool, but the sovereign install is the only path that replaces it with a
  self-derived Sprout history.

The importer writes the same `anchor_kv`/`nullifier_kv`/`coins_kv` tables the
sovereign install replaces wholesale, so a later sovereign promotion never
has to reconcile with an import done via this path — it overwrites it in one
transaction.
