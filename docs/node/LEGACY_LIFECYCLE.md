# Legacy Lifecycle

Modules and CLI flags prefixed `legacy_` interact with a sibling
`zclassicd` (C++ ZClassic) install on the same host. They exist for two
distinct reasons that must not be confused:

1. **Bootstrap** — cold-start a fresh `z23` faster than full IBD
   by reading headers / block-index / chainstate / block bodies from a
   sibling `zclassicd` datadir.
2. **Drift detection** — at runtime, periodically compare our chain
   state against `zclassicd` so divergence is caught early.

This file is the source of truth for which paths exist and what each
one is for. Every `legacy_`-named module in the tree is listed below and
every one is **load-bearing** — none is cruft, and none is scheduled for
removal. A "purge legacy" grep that treats the word "legacy" as "dead
code" is wrong here; confirm against this table and the call sites first.

Cross-references: `CLAUDE.md` (top-level architecture),
`DEFENSIVE_CODING.md` (the rules `legacy_*` modules must follow).

---

## CLI flag map

The cold-start path is `build/bin/z23 --importblockindex <datadir>`
(headers from a sibling `zclassicd` datadir) followed by a normal boot,
which auto-reads/links `~/.zclassic` unless `-nolegacyimport` is passed.

| Flag | Module | Status | What it does |
|------|--------|--------|--------------|
| `-nolegacyimport` | (no module — disables) | **Active** | Disable auto-detection of a sibling `~/.zclassic` on boot. Use when you explicitly do not want legacy interaction. Default is to auto-detect. |
| `-load-snapshot-at-own-height=PATH` | `engine/composition/src/boot_refold_staged.c` (`boot_load_snapshot_at_own_height_reset`) | **Deprecated — guarded** | Seed coins_kv from a body-digest-verified USS snapshot at its own header height and fold forward. **Superseded by `-install-consensus-bundle`** for complete (transparent + shielded) state. A **v1 transparent-only** snapshot (no Sapling frontier/anchors/nullifiers) seeded on a chain past Sapling activation (mainnet h=476969) is now **refused UP FRONT** (`boot_seed_is_shieldless_past_sapling`): folding it forward is a guaranteed delayed wedge (`utxo_apply.{anchor,nullifier}_backfill_gap`). Use the consensus bundle or a v2/v3 (shielded) snapshot. Still referenced by the live/dev-lane units (v2 seeds) and the cold-start driver's SEED stage, so it is guarded, not deleted. |
| `-coldstart-seed-oneshot` | `engine/composition/src/args.c`, `engine/composition/src/boot.c`, `engine/composition/src/boot_cold_start.c` | **Deprecated — guarded** | Internal cold-start driver handshake: apply the `-load-snapshot-at-own-height` seed then exit cleanly before services. Requires the header chain already imported to ≥ the snapshot height; the prerequisite is now checked **early** (`boot_seed_oneshot_headers_ready`) — right after the block index loads — and a shortfall fails fast with a named prerequisite instead of burning a full boot. Never set on an operator-driven boot. |

There is no `-cold-import`, `-fastimport`, `-legacy-attach`,
`-importfromlegacy`, `-legacy-auto-import`, or `-bodypull-from-legacy`
CLI flag in the tree. `-nolegacyimport` is parsed because boot may
auto-detect a sibling `~/.zclassic` through the legacy anchor path
unless disabled.

**Invariant — no boot-time body-pull.** No path pre-populates
`block_index` with `BLOCK_HAVE_DATA` from a sibling node without
activating those blocks. Such a path wedges `find_most_work_chain` (it
finds have-data blocks it never advances) and must not be reintroduced.
Bodies enter only through normal activation or the explicit import
readers below.

---

## Module map

Every file below is **Active / load-bearing** and has live callers
outside its own tests. The "Callers" column names the non-legacy code
that reaches each module.

### Bootstrap — header / index / chainstate / body import

| File | Role | Callers |
|------|------|---------|
| `engine/composition/src/boot_legacy_import.c` | Pure boot-heuristic predicates (`boot_need_legacy_header_pull`, `boot_need_blocks_table_hydrate`, `boot_dispatch_blocks_table_hydrate`) for the automatic `zclassicd`-LevelDB header pull. Split out of `boot.c` to hold the E1 file-size seam. | `engine/composition/src/boot.c`, `engine/composition/src/boot_blkidx_ladder.c` |
| `engine/composition/src/boot_legacy_blocks.c` + `.h` | Boot-time detection / linking of a sibling `zclassicd`'s on-disk block files. | `engine/composition/src/boot.c` |
| `engine/modules/storage/src/blocks_index_legacy_reader.c` + `.h` | Reads `zclassicd`'s `block_index` LevelDB into our schema. Backbone of the `--importblockindex` cold-start path. | `engine/entry/main.c` path, `block_log_legacy.c`, `tools/rebuild_recent.c` |
| `engine/modules/storage/src/chainstate_legacy_reader.c` + `.h` | Reads `zclassicd`'s chainstate LevelDB (compressed UTXOs) into our `coins_db`. | `engine/entry/main.c`, `engine/services/src/shielded_history_import_service.c`, `engine/conditions/src/sapling_anchor_frontier_unavailable.c` |
| `platform/adapters/outbound/persistence/src/block_log_legacy.c` + `.h` | Legacy block-body reader adapter (over `blocks_index_legacy_reader` + the mmap reader) that serves raw block bytes from a sibling datadir. | `engine/services/src/replay_verify_service.c` |
| `engine/controllers/src/legacy_import.c` + `include/controllers/legacy_import.h` | RPC/controller surface for legacy import operations. Not wired to a dedicated CLI flag; reached by boot and the wallet diagnostic controllers. | `engine/composition/src/boot.c`, `engine/controllers/src/wallet_diagnostic_*.c`, `engine/controllers/src/snapshot_controller_import.c` |
| `engine/controllers/src/legacy_import_scan.c` + `.h` | Raw blk-file scanner and Sapling decrypt workers for legacy wallet import. | `engine/services/src/legacy_import_service.c` |
| `engine/services/src/legacy_import_service.c` + `include/services/legacy_import_service.h` | Service-grade orchestration for importing wallet data from a legacy node's raw block files. | `engine/controllers/src/legacy_import.c` |

### Drift detection (observe-only)

The mirror observer never applies blocks — it only compares our tip
against a sibling `zclassicd` and surfaces lag / divergence via
`EV_MIRROR_*` events. It powers `z23 ops mirror` and
`z23 dumpstate legacy_mirror`, and its lag/parity SLOs feed live
monitoring; do not remove it.

| File | Role | Callers |
|------|------|---------|
| `engine/services/src/legacy_mirror_sync_service.c` + `include/services/legacy_mirror_sync_service.h` | Background drift-detector: catch-up tick, lag/parity comparison, event emission. | boot sync wiring, health/event controllers, `parity_slo_breach`, `block_source_policy_runtime`, `chain_supervisor`, diagnostics registry |
| `engine/services/src/legacy_mirror_sync_state.c` | Runtime state snapshots, lifecycle wiring, and test hooks for the observer. | `legacy_mirror_sync_service.c` |
| `engine/services/src/legacy_mirror_sync_json.c` | Operator-facing JSON snapshot (the `dumpstate legacy_mirror` predicate). | `legacy_mirror_sync_service.c` |
| `engine/services/src/legacy_mirror_sync_parity_trend.c` | Bounded trend-history write for the mirror's consensus-parity comparisons. | `legacy_mirror_sync_service.c` |
| `engine/services/src/legacy_mirror_sync_internal.h` | Shared internal header for the four `.c` files above. | mirror-sync `.c` files |
| `engine/supervisors/src/legacy_mirror_supervisor.c` + `.h` | Supervisor contract for the mirror observer (registers it on the liveness tree). | `legacy_mirror_sync_service.c`, `legacy_mirror_sync_state.c` |

### RPC clients (`engine/modules/rpc/src/`)

| File | Role | Callers |
|------|------|---------|
| `legacy_rpc_client.c` + `.h` | HTTP/JSON-RPC client for talking to `zclassicd:8232`. | `zclassicd_oracle_service`, `utxo_parity_service`, `utxo_reference_source_zclassicd`, `header_probe` |
| `legacy_chain_oracle.c` + `.h` | Treats `zclassicd` as an external chain oracle (hash-at-height, getblockcount) for quorum / drift checks. | `fast_sync`, `boot_services`, `tip_stall_oracle_rebuild`, `snapshot_verify`, `repair_controller_rebuild` |
| `legacy_header_client.c` + `.h` | Header-fetch client used to pull headers over RPC. | `engine/services/src/header_probe.c` |

### Seed and status (operator tooling)

| File | Role |
|------|------|
| `tools/command/legacy_seed.c`, `legacy_seed_walk.c`, `legacy_seed_copy.c` | Two-phase seed of a new legacy datadir from the oracle. Behind `ops host legacy seed`. |
| `tools/command/legacy_status.c` | Binary identity, port conflicts, catch-up rate and mirror-credential comparison. Behind `ops host legacy status`. |

### Tests

| File | Covers |
|------|--------|
| `tests/harness/src/test_block_log_legacy.c` | `block_log_legacy` |
| `tests/harness/src/test_boot_legacy_blocks.c` | `boot_legacy_blocks` |
| `tests/harness/src/test_chainstate_legacy_reader.c` | `chainstate_legacy_reader` |
| `tests/harness/src/test_legacy_seed.c` | `legacy_seed`, `legacy_status` |

Boot-heuristic predicates from `boot_legacy_import.c` are additionally
exercised by `test_boot_phase.c` and
`test_importblockindex_cli_dispatch.c`; the RPC clients and mirror
observer by `test_rpc.c`, `test_zclassicd_oracle.c`, `test_lag_slo.c`,
`test_parity_slo.c`, and `test_block_source_policy.c`.

---

## Seed a legacy node from the parity oracle

Use this when a second legacy `zclassicd` datadir (the bootstrap server, or a
replacement for a corrupt one) is needed. Never `-reindex` a datadir that
crashed on reindex: copy the synced oracle's `blocks/` and `chainstate/`
(`txindex` lives in `blocks/index`) into a NEW datadir. Everything below is
native; `<oracle datadir>`, `<bootstrap datadir>` and the instance values are
placeholders.

| Leaf | Reads or writes |
|------|-----------------|
| `ops host legacy status` (alias `ops legacy status`) | read only |
| `ops host legacy seed` (alias `ops legacy seed`) | writes only `<target>.tmp`, then renames it to `<target>` |

Oracle and node must share the credential source. The node's legacy mirror
reads `rpcuser`/`rpcpassword` from `$HOME/.zclassic/zclassic.conf`; an oracle
in its own datadir has different ones and the mirror stays silently
unreachable (`consensus.parity_slo_breach`, `oracle_unreachable`). Point the
node at the oracle's conf with `ZCL_LEGACY_ORACLE_CONF=<oracle datadir>/zclassic.conf`
(unset keeps the default). `status` compares the file the node reads (`node_conf` if you pass what the running
node uses, else this process's `ZCL_LEGACY_ORACLE_CONF`, else the default) with each
instance's own `<datadir>/zclassic.conf`, and reports `status` reports `mirror_creds` per instance
(`match`, `mismatch`, `unknown`) and `mirror_creds_mismatch: true` when the
mirror would not authenticate; credentials are compared by SHA3 digest and
never printed.

1. Check identities, ports and progress (pass the previous height and unix
   time as `prev_height`/`prev_unix` to get `blocks_per_min` and
   `eta_seconds`):

   ```
   z23 ops host legacy status --input='{"instances":[
     {"name":"oracle","datadir":"<oracle datadir>","port":8034,"rpcport":8232,
      "binary":"<zclassicd>","sha256":"<pin>"},
     {"name":"bootstrap","datadir":"<bootstrap datadir>","port":8035,"rpcport":8233}],
     "z23_datadir":"<z23 datadir>","z23_rpcport":18232}'
   ```

2. Plan (runs every refusal; returns `plan_id`). Pass `source_height` and
   `z23_height` (from step 1) so a source more than `max_gap` (default 2)
   blocks behind is refused:

   ```
   z23 ops host legacy seed --input='{"source":"<oracle datadir>","target":"<bootstrap datadir>","source_height":<h>,"z23_height":<tip>}'
   ```

3. Stage while the oracle keeps running (resumable; copies every file of
   `blocks/` and `chainstate/`, LevelDB trees included, into
   `<bootstrap datadir>.tmp`; rerun after an interruption and files whose size
   and mtime match are skipped):

   ```
   z23 ops host legacy seed --input='{"source":"<oracle datadir>","target":"<bootstrap datadir>","step":"stage","confirm":true,"plan_id":"<id>"}'
   ```

4. Stop the oracle (`systemctl --user stop zclassicd-oracle`), wait for it to
   exit, then finish. The leaf holds the datadir lock and copies only what
   changed since stage: files that are new or whose size or mtime differ, plus
   LevelDB `MANIFEST-*`, `CURRENT`, `LOG` and the newest table and log of each
   LevelDB directory, which are always recopied. Target files the source no
   longer has (compacted `.ldb` files) are deleted, confined to the target
   tree. It then fsyncs, hashes the manifest, writes `seed-receipt.json`
   (`phase_b_ms`, `phase_b_files`, `phase_b_bytes`) and renames atomically.
   `downtime_ms` is the copy window with the oracle down; `phase_b_files` and
   `phase_b_bytes` count what that window copied:

   ```
   z23 ops host legacy seed --input='{"source":"<oracle datadir>","target":"<bootstrap datadir>","step":"finish","confirm":true,"plan_id":"<id>"}'
   ```

5. Restart the oracle (`systemctl --user start zclassicd-oracle`), then start
   `zclassicd-bootstrap` (ports 8035/8233).

   A seeded datadir has no `peers.dat` (the seed copies only `blocks/` and
   `chainstate/`), so it needs a peer source or it sits at the seed height with
   0 connections: pass `-addnode=127.0.0.1:8033` (the local z23 node's P2P
   address; the bootstrap unit does) or a dnsseed. `status` reports
   `connections` per instance and `no_peers: true` when it has none while
   behind the z23 tip or not advancing. The `finish` reply repeats this as
   `peer_source`.

Refusals (stable codes `legacy_seed.<name>`): `target_exists`, `source_running`
(pid file or a flock/fcntl lock on `.lock`), `source_missing`,
`source_symlink`, `target_symlink`, `owner_mismatch`, `symlink_in_tree`,
`special_file`, `gap_exceeded`, `insufficient_space` (source size plus
`margin_mib`, default 1024), `tmp_mismatch` (a `.tmp` from another source),
`plan_mismatch` (the plan id binds source, target, `max_gap`, both heights, `workers`, `margin_mib` and the source directory identity: repeat the same inputs at every step), `source_lock_missing` (finish needs `<datadir>/.lock` to prove the source stopped), `copy_failed`. A failed copy leaves no target, only a
`<target>.tmp` that a rerun resumes or you may delete. `wallet*`, `key*`,
`*.key`, `*.pem` and `*.wallet` files are never copied, and the datadir root
is never read. The receipt holds source, target, file count, bytes, the
SHA3-256 over the sorted `(path, size, sha3)` manifest, both heights and the
creation time.

## Self-heal note (not `legacy_`-named, but adjacent)

The missing-UTXO / stuck-tip self-heal coordinator lives in
`core/modules/validation/src/`. Recovery routes through the reducer (cursor move
+ `reducer_kick`), the same reach the app-layer controllers
`process_block_revalidate.c` / `process_block_invalidate.c` use. There
is no block-disconnect-engine and no legacy-RPC repair path.

Three files are **load-bearing** and must survive any purge:

- `process_block_self_heal.c` — failure-tracking state (`s_utxo_*`),
  `process_block_is_missing_utxo_failure`, `process_block_note_utxo_failure`,
  `ZCL_TESTING` hooks. The surviving coordinator, not residue.
- `process_block_self_heal_hot_loop.c` — hot-loop retry helper.
- `process_block_self_heal_scan_state.c` — scan-state bookkeeping.

Four out-of-band repair islands do **not** exist and must not be
re-added: `process_block_self_heal_chain_scan.c`,
`process_block_self_heal_sqlite_tx_index.c`,
`process_block_self_heal_legacy_rpc.c`,
`process_block_self_heal_inject.c`.

---

## Adding a new `legacy_` module

Don't, unless:

1. The behaviour is **strictly tied to interoperability with an
   external `zclassicd`** (bootstrap, drift detection, oracle). General
   "legacy because written earlier" modules belong in their own
   directory or get renamed.
2. The CLI flag goes through `app_context` and respects
   `-nolegacyimport`.
3. The new module has an entry in the tables above before merge.
