# Boot Invariants

`engine/composition/src/boot.c` is the sequential, ordering-sensitive entry point
that initializes every long-lived global the node depends on.

This file is the source of truth for the boot ordering and what
each stage guarantees. The state machine that enforces the
ordering lives in `platform/modules/util/include/util/boot_phase.h` (`enum boot_stage`)
and `platform/modules/util/src/boot_phase.c` (`boot_stage_advance_to()`).

Cross-references: `CLAUDE.md` (top-level architecture),
`DEFENSIVE_CODING.md` (rules that boot steps must follow),
`LEGACY_LIFECYCLE.md` (legacy import / drift detection — the
cold-start path is now the `--importblockindex` + a normal boot
two-step).

---

## Boot stages

Stages are strictly **monotonic**. The advance API enforces:

- Equal-to-current: idempotent no-op.
- Successor stage: normal forward step. Logged to stderr.
- Forward skip (jump): logged as `WARN forward-jump` — gap to fill.
- Backward move: `abort()` with diagnostic. Never recoverable.
- `SHUTDOWN_REQUESTED` is reachable from any forward stage (operator
  may halt mid-boot).

| Stage | What it guarantees |
|------|--------------------|
| `INIT` | Process is up. Signal handlers installed. Event log open. Nothing else is set up. |
| `DATADIR_LOCKED` | Chain params selected (main/test/regtest). Datadir exists and is owned by this process (lockfile held). Unclean-shutdown marker checked. |
| `CRYPTO_READY` | ECC initialized. SHA-256 + field-arithmetic self-tests passed. `main_state_init` complete. `g_state.chain_active` initialized. Activation controller registered. |
| `DB_OPEN` | `node.db` opened. Schema migrations applied. DB worker thread started (or fallback to direct SQLite). |
| `WALLET_LOADED` | `wallet_keys` read (STATE C invariant). Canary self-test OK. STATE D/E/F abort paths not triggered. |
| `BLOCK_INDEX_LOADED` | `block_index` loaded from LevelDB. `g_state.chain_active` populated with stored tip. |
| `CHAIN_TIP_RESOLVED` | Reducer activation complete. CSR consistent. Coins.db tip equals or trails block_index tip per the [coins-before-block-index ordering invariant](#coins-vs-block-index-ordering). |
| `NETWORK_READY` | Connman initialized. Peer manager ready. Listeners not yet bound. |
| `SERVICES_RUNNING` | Background services started: disk_monitor, ibd_throttle, db_maintenance, wallet_backup, sync_watchdog. |
| `READY` | HTTPS + RPC + (optional) Tor onion listening. The node accepts external requests. |
| `SHUTDOWN_REQUESTED` | `app_shutdown` entered. New requests refused. |
| `SHUTDOWN_COMPLETE` | Clean shutdown marker written. Datadir lock released. All services stopped. Safe to exit. |

---

## Currently wired

All twelve boundaries are wired. The five middle boundaries (WALLET_LOADED …
SERVICES_RUNNING) are advanced through the **SYSINIT** declarative table
(`util/sysinit.h`, `engine/composition/src/boot.c:k_boot_sysinit_records[]`): each is a
`struct sysinit_record` whose init runs at its true boundary, and
`sysinit_run_stage(stage, ctx)` advances the state machine only if the records
succeed (fail-closed — a failed boundary returns a typed `zcl_result` and boot
exits, instead of a silent forward-jump WARN). The deterministic
(stage, order, name) run order is pinned by
`tools/lint/check_sysinit_ordering.sh` against a golden file.

- `BOOT_STAGE_DATADIR_LOCKED` — `boot_step_select_chain_and_datadir` (direct)
- `BOOT_STAGE_CRYPTO_READY` — `boot_step_init_crypto_and_state` (direct)
- `BOOT_STAGE_DB_OPEN` — `app_init` after `node_db_sync_init` succeeds (direct)
- `BOOT_STAGE_WALLET_LOADED` — SYSINIT `wallet_loaded`, after the wallet
  load/create block (STATE C/D/E/F resolved)
- `BOOT_STAGE_BLOCK_INDEX_LOADED` — SYSINIT `block_index_loaded`, after the
  block-index loaders + repair + the sidecar integrity gate
- `BOOT_STAGE_CHAIN_TIP_RESOLVED` — SYSINIT `chain_tip_resolved`, whose init
  runs `boot_step_finalize_chain_state` (after coins/block-index reconcile)
- `BOOT_STAGE_NETWORK_READY` — SYSINIT `network_ready`, in `app_init_services`
  after `connman_init` + `connman_load_addrman`, before listeners bind
- `BOOT_STAGE_SERVICES_RUNNING` — SYSINIT `services_running`, whose init runs
  `boot_step_start_maintenance_services`, before READY is advertised
- `BOOT_STAGE_READY` — end of `app_init` on `svc_ok` (direct)
- `BOOT_STAGE_SHUTDOWN_REQUESTED` — start of `app_shutdown` (direct)
- `BOOT_STAGE_SHUTDOWN_COMPLETE` — end of `app_shutdown` (direct)

The offline `-mint-anchor` path legitimately forward-jumps
`CHAIN_TIP_RESOLVED → READY` (no network/services), which the state machine
logs as a WARN forward-jump — expected for that one-shot producer.

---

## Coins vs block-index ordering

> coins.db must commit before LevelDB block_index fsync

The chain advance path is ordered so a kill -9 between (7) coins commit
and (8) block_index fsync leaves the system forward-recoverable:

- coins.db at N+1, block_index at N → boot detects drift, replays
  block_index forward.
- block_index at N+1, coins.db at N → unreachable by construction.

`utxo_recovery_service` runs at boot to forward-step coins.db if it
trails block_index. `chain_state_validator` cross-checks the two and
auto-rewinds when feasible.

When wiring `BOOT_STAGE_BLOCK_INDEX_LOADED` and
`BOOT_STAGE_CHAIN_TIP_RESOLVED`, the advance must happen
**after** the coins/block-index reconciliation, never before.

---

## Coins integrity gate and the stale-anchor self-heal

`coins_view_sqlite_open` runs `coins_view_sqlite_check_tip_consistency`
during `DB_OPEN`. It catches the dangerous class "UTXO writes landed but
the tip pointer didn't" (crash mid-flush), which could double-spend on
restart. Its verdict (`true` = consistent/healed, `false` = halt) gates
boot at `engine/composition/src/boot.c` — a `false` is FATAL.

The gate's branches, in order, when `max_utxo_height > resolved_tip`:

1. **`max == tip+1`, ≤32 rows above tip** → bounded auto-rewind
   (`coins_rewind_above_tip`): delete the overshoot rows. The
   crash-mid-flush shape.
2. **`tip > 1,000,000` and gap > 1000** → continue (historical
   coins-lag-headers; the node serves degraded and reconciles forward).
   Load-bearing for normal boots — do not narrow it without proving no
   legitimate lag boot regresses.
3. **Stale-anchor self-heal** (`coins_reconcile_stale_anchor`, the §3
   wedge: anchor pointer reset far below the real frontier, e.g. height
   200 while `utxos` holds millions of rows). This heals **only under
   cryptographic proof** — a stored height-stamped SHA3 commitment
   (`utxo_sha3`) recomputed over the live `utxos` table must match
   (hash+count) before the anchor is re-pointed. A blind "advance the
   anchor to the highest cursor" heal is consensus-**unsafe**: the tip
   cursors are non-independent promotion stamps, `MAX(utxos.height)`
   cannot see a dropped spend, and `height→hash` can name an orphan
   sibling. So every unproven shape (no commitment, count/hash mismatch,
   commitment below the live frontier, unresolvable anchor) **returns
   false → the strict FATAL is preserved**. No UTXO is ever deleted here.
4. Otherwise → strict FATAL (`DB_ERR_TIP_MISMATCH`).

The self-heal needs a stored `utxo_sha3` commitment to fire. A datadir
that carries none (the commitment is currently written only at
snapshot-import) correctly cannot self-heal and FATALs with a clear
`reconcile refused: no stored utxo_sha3 commitment` reason; recovery is
then operator-driven: re-derive the coins set (`-reindex-chainstate`,
which wipes `utxos` and replays every block) or restore the datadir.

> Follow-ups for full auto-heal: (a) persist `utxo_sha3` at finalized-tip
> checkpoints so a recurring wedge self-heals; (b) `-reindex-chainstate`
> currently runs *after* this gate, so a torn anchor FATALs before the
> rebuild can run.

---

## Adding a new stage

Don't reorder existing stages unless you understand every other
boot path that depends on them. If you need a new boundary:

1. Add it to `enum boot_stage` in
   `platform/modules/util/include/util/boot_phase.h`. Pick a position that
   reflects when the guarantee becomes true — every prior stage must
   already hold.
2. Add its name to `k_boot_stage_names` in
   `platform/modules/util/src/boot_phase.c`.
3. Call `boot_stage_advance_to(BOOT_STAGE_<NAME>)` at the point in
   `engine/composition/src/boot.c` (or `boot_services.c`) where the guarantee is
   established.
4. Document the guarantee in the table above.

The forward-jump warning is your friend during adoption — every
unfilled boundary surfaces in node.log on every boot until it is
wired or removed.

---

## How to debug a boot misorder abort

The advance API aborts on backward moves with:

```
[boot-stage] FATAL misorder: cannot move BACKWARD <from> -> <to>. See BOOT_INVARIANTS.md.
```

Steps to investigate:

1. Look at the most recent `[boot-stage]` lines preceding the abort
   in node.log. They show the linear path.
2. Search `engine/composition/src/boot.c` (and `boot_services.c`) for calls to
   `boot_stage_advance_to(BOOT_STAGE_<from>)` and
   `boot_stage_advance_to(BOOT_STAGE_<to>)`.
3. Identify which code path reached the second call while the
   global state was still in the first stage. Usually this is a
   re-entry (function called twice) or a path that bypasses an
   intermediate stage's wiring.
4. Fix the actual ordering bug. **Do not** "fix" it by lowering the
   abort to a warning — that defeats the purpose of the invariant.
