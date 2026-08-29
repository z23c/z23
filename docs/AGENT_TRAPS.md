# AGENT_TRAPS.md — guardrails for a future Claude agent

**Verify fresh before trusting any line here; this doc itself rots.** Line numbers
shift under refactors. Read 30-50 lines around any `file:line` before acting on it.
Every claim below was true at the time it was recorded; the live code is the only
authority.

This doc exists to stop a future agent from re-discovering things that are already
done, re-proposing optimizations that already ship, or "fixing" patterns that are
intentional consensus-parity decisions.

---

## (00) MANTRA — code fearlessly; immutable history is the oracle

ZClassic history is immutable. We cannot lose or rewrite canonical historic
data by breaking a local build, a throwaway datadir, a generated snapshot, or a
test fixture. Use that aggressively: make copies, replay real blocks, pin
historical fixtures, and delete/recreate derived artifacts when that is faster
than nursing them. Prefer real-chain canaries over imagined edge cases whenever
the chain already contains the answer.

The boundary is live-first surgery: do not mutate the operator's serving
datadir to test a repair. Copy it, reproduce there, prove H* climbs or the
historical fixture passes, then deploy/restart intentionally.

---

## (0) LIVE OPS TRAPS — public service vs private candidates

- **Public connected-node tables can lag or cache old peer identity.** Verify
  the live socket before trusting a crawler row — a node that switched
  services can still show the prior service string in a public peer table
  until the crawler reconnects and refreshes its cache.
- **Copied `block_index.bin` plus foreign `blocks/blk*.dat` is unsafe.** The
  block index contains source datadir file offsets. A non-empty block file with
  the same number is not enough proof that an indexed body is valid. In
  `-nolegacyimport` snapshot boots, existing block files must be untrusted
  unless the indexed block reads back and hashes to its block-index entry.
- **HODL/explorer wait regressions have a public smoke test.** Use
  `tools/scripts/public_explorer_smoke.sh`; it checks both `/api/v1/hodl` and
  `/explorer/hodl` without `jq` and fails on "refresh", "not processed",
  "retry", or "waiting" user-visible states.
- **Runtime-generation publication has one owner-gated native authority.**
  `z23-dev dev generation activate
  --input='{"idempotency_key":"<key>"}'` stages and
  preflights an immutable dev generation, then returns the exact
  `commit_input` required to activate it. The commit binds the candidate,
  source identity + ABA mutation + CAS root, resident generation, and expiry;
  the engine installs or updates the exact source-controlled dev unit before
  its first service action, verifies the exact running executable, and rolls
  back on failure. Fresh hosts do not need a contained legacy deploy command
  to install the unit first.
  All other broad paths remain contained: `dev.change.apply`, watcher modes,
  `make hotswap`, `deploy-dev*`, `agent-deploy-fast`, `agent-stage-dev`, and
  the direct deploy/hot-swap scripts all hard-refuse. Remote update/install/
  restart variables and `lane_recover --apply` also refuse before SSH, file,
  datadir, or service mutation. A source ID, environment switch, or direct
  script call does not bypass containment. Use build, simulation, read-only
  plans and verify/check watch. The two live dev runtime surfaces are that
  explicit owner plan/commit and the gated swappable-leaf hot-swap
  (`make hotswap-try` / `make hotswap-apply`) on the armed `zcl23-dev` lane.
- **Dev recovery is plan-only during containment.** `make agent-dev-recover`
  is read-only. `ARGS=--apply`, direct `recover-dev-lane.sh --apply`, and test
  environment variables cannot relink an existing generation or restart the
  service; only the isolated inherited-FD self-test reaches recovery machinery.
- **“Non-consensus” does not automatically mean hot-swappable.** The v2 loader
  admits only exact `config/hotswap_eligible.def` entries that export a
  stateless native-leaf manifest with the required ABI, capabilities, hashes,
  tests, probes, self-test, and no-quiescence contract. REST, diagnostics,
  services, models, storage, events, conditions, supervisors, networking,
  wallet/key/crypto state, reducers, and process ownership are
  `reload_required`. Never widen the allowlist to silence that blocker.
- **Do not interpret a contained hot-swap call as a transport failure.**
  `make hotswap` refuses before `dlopen` or resident RPC mutation. There is no
  automatic reload fallback and no successful committed generation to inspect
  during containment. This does
  NOT apply to the swappable-leaf module path: `dev.hotswap.probe`
  (verify-only, throwaway CLI process) works, and `dev.hotswap.apply`
  live-commits one allowlisted read-only leaf in the armed `zcl23-dev` node.
- **ZVCS revert is source-only.** `dev.vcs.revert` is available with
  `relink_generation=false`. Passing `true` refuses before the source revert;
  it never rebuilds, activates, or guesses a binary generation.
- **Do not infer latency SLOs from a safe/default benchmark run.**
  `make dev-loop-bench` skips hot-swap and process-reload activation cases by
  default; `ZCL_DEV_BENCH_ACTIVATE=1` opts into measuring the armed dev-lane
  activate path. Build/check timings alone cannot support hot-swap or
  reload SLO claims.
- **Module `.so`s must keep `-Wl,-Bsymbolic` — without it a "swapped" handler
  silently runs the OLD code.** ELF interposition lets the resident binary's
  definition win for intra-module calls; `-Bsymbolic` binds internal calls
  inside the module. Both module link lines in the Makefile carry it — never
  drop it from a new link path.
- **A flagless CLI invocation targets the CANONICAL datadir.** For dev-lane
  work pass `-datadir=$HOME/.zclassic-c23-dev -rpcport=18252`
  (`make hotswap-try` / `make hotswap-apply` do this for you). A bare
  `build/bin/z23-dev <cmd>` falls back to the canonical default
  datadir/ports and talks to the live node, not the dev lane.
- **`--importblockindex` ignores even an explicit `-datadir=` — it writes the
  DEFAULT datadir's `node.db` unless given the target as a positional.** The
  safe form for a side datadir is
  `build/bin/z23 --importblockindex <zclassicd-datadir> <side-datadir>/node.db`
  (exactly what the `-full-fold` FATAL prints). Proven 2026-08-02: a
  `-datadir=<producer> --importblockindex $HOME/.zclassic` invocation bulk-wrote
  3,192,879 headers into the CANONICAL `~/.zclassic-c23/node.db` while the live
  node was running (survived — the rows were additive duplicates the live node
  already had — but that is the live lane and the write was unintentional).
- **Do not hand-maintain `compile_commands.json`.** Run `make agent-index`.
  It derives commands from the real `DEV_OBJS` recipes, including generated
  headers and the target-specific `-Og`/hot-bucket `-O2` split, then records
  hash/freshness metadata. clangd is optional and its absence is not an index
  generation failure.
- **Do not restore blocking `PRAGMA quick_check(1)` on unclean WAL boots.**
  On a multi-GB production `node.db` that scan is hours of `folio_wait`
  D-state and holds `Type=notify` READY / P2P 8033 hostage. SQLite already
  recovered the WAL on open. Unverified/unclean existing files defer the
  same PRAGMA to `boot_fast_restart_start_bg_quick_check`, which fail-closes
  via `EV_OPERATOR_NEEDED`. Verified-clean skip still requires the v2
  marker binding; deferral must not set `quick_check_was_skipped` or
  fast-restart will trust an unproven node.db. Pinned by
  `test_shutdown_marker` (mutated header / WAL / no-marker existing file
  defer, missing file still runs the cheap blocking check).
- **FIXED 2026-08-10 (d032f1c36, integrated commit) — node_db newer-schema refusal used to
  fire only AFTER the open ceremony had already written to the datadir.**
  The old order ran quick_check (whose failure path quarantines/renames
  node.db and rebuilds it empty), create_schema() (re-creating baseline
  tables a newer schema may have deliberately dropped), and the
  schema_migrations bootstrap INSERT before `node_db_migrate`'s -2
  refusal — a "refused" open mutated the file it claimed to protect, and
  teardown of that half-opened `node_db` could print
  `double free or corruption (!prev)` (surfaced 2026-08-09 in
  test_file_market "restart reconstructs verified content reader"). The
  integrated first fix moved the refusal ahead of quick_check/schema/migration.
  The completed guard now runs `node_db_schema_preflight_existing()` before
  `db_open_raw` itself, so READWRITE|CREATE and `journal_mode=WAL` are still
  unreachable until the existing marker is proved readable and supported.
  It distinguishes absent/empty, supported, newer, and
  `SCHEMA_VERSION_UNKNOWN`; a malformed, missing, wrong-width, contradictory,
  unsupported, or unreadable marker fails closed. WAL selection matters:
  immutable inode-bound inspection is used only for a quiet WAL with no
  wal-index, while an existing WAL+SHM pair is read normally so committed
  uncheckpointed frames remain authoritative. Pinned by
  `test_db_migration_idempotent`: DELETE, clean-WAL and uncheckpointed-WAL
  refusals; malformed/missing/contradictory stores; 8 refused open/close
  rounds; and complete node.db/WAL/SHM/journal family SHA3, size, existence and
  metadata equality. `node_db_open_abort()` leaves the struct close-harmless
  (db NULL, open false, state destroyed), including double-close. Do not
  reintroduce any write-capable open before this preflight.
- **FIXED 2026-08-10 (82f94e65d) — a group that passes isolated but fails
  in the monolithic suite is not always a poisoned victim; check
  context-dependent OUTPUT SIZE first.** `test_test_group_selector`
  asserted on the tail of a `make -n t-fast-exact` dry run through a
  128 KiB head-truncating capture. The dry run's size depends on
  session-scoped build freshness: warm (isolated `make t-fast`) it is a
  few KB; cold (the parallel suite, a direct runner process, an expired
  session lease) every stale session/link/stamp recipe prints (~0.6 MB
  measured) and the tail evidence falls off the buffer. Deterministic
  cold repro: `test_parallel_fast --jobs=1
  --exact=test_test_group_selector --no-cache` directly, not via make.
  Fixed by sizing the capture past the all-stale bound (8 MiB static),
  not by touching any assertion. When bisecting "contamination", diff
  the victim's captured bytes between contexts before blaming another
  group.

---

## (1) STALE FACTS — old belief → current truth

- **getblockcount serves active_chain_height.** FALSE at HEAD. It serves `reducer_frontier_provable_tip_cached()` (H*, the provable frontier), commit `e75b5c62c`. Internal code still uses `active_chain_height` for lookahead, but only external/served RPCs use H*. → `app/controllers/src/blockchain_controller_blocks.c:50-66`.
- **P2P start_height advertises active_chain_height (or the sync-window tip).** FALSE. It advertises `reducer_frontier_provable_tip_cached()` (H*) — only the provable height, never the lookahead tip that can rewind under a reorg. → `lib/net/src/msg_version.c:155` (comment at `:149-154`).
- **getbestblockhash / getblockchaininfo serve active_chain_height and are inconsistent with getblockcount.** FALSE. All three serve H* and are internally consistent: `getblockchaininfo.blocks` returns `reducer_frontier_provable_tip_cached()` and resolves the tip hash at that same H* height. → `blockchain_controller_blocks.c:69-93` (getbestblockhash via `rpc_provable_tip` at H*); `app/controllers/src/blockchain_controller_chain.c:55-93` (getblockchaininfo: H* at `:84`, `active_chain_at(H*)` at `:85-86`).
- **Bare `build/bin/zclassic-cli` is always the z23 status target.** FALSE. It can follow local defaults, cookies, datadirs, or environment and answer from another RPC target. For z23 stability checks use the C-owned native agent commands first (`z23 status`, `z23 agent`, `z23 agentdiagnose`, `z23 getmirrorstatus`), or make direct RPC explicit with `build/bin/zcl-rpc getblockcount` / `build/bin/zclassic-cli -rpcport=18232 getblockcount`. A bare CLI height mismatch is an operator-interface ambiguity until the target lane is proven.
- **Heal/repair never deletes the upstream validation logs.** FALSE at HEAD. Heal deletes BOTH `script_validate_log` and `proof_validate_log` in the same transaction when repairing stale/retriable verdicts. → `app/jobs/src/stage_repair_reducer_frontier_coin.c:459-462` (`delete_log_range` for both logs inside `stale_script_replay_tx`, gated by `dry_run_stale_script_replay`). The "heal never clears upstream logs" framing is explicitly marked stale in `docs/work/self-verified-tip-plan.md`.
- **The boot `chain_restore.disk_rebuild_rows` counter is a "cold-seed-only / never-a-warm-boot" path.** FALSE. The disk-backed active-chain rebuild (`app/services/src/chain_restore_disk_repair.c` `_from_disk` at `:127`, `_from_block_files` at `:456`) walks tip→genesis reading one header per height — bounded by `tip->nHeight+1`, NOT by a delta above any durable cursor. Boot REACHES it on every **unclean** warm restart (crash / kill -9 / OOM), not just cold seeds: `config/src/boot.c:2743-2744` runs `utxo_recovery_restore_chain_tip` whenever the boot is not a `-reindex` AND `fast_restart` was not taken, and `fast_restart` requires a clean-shutdown marker (`config/src/boot_shutdown_marker.c` — a WAL present without the clean marker sets unclean=true). That restore calls `chain_restore_finalize` with the real datadir (`app/services/src/utxo_recovery_restore.c:737` → `chain_restore_repair.c:686` → `chain_restore_rebuild_active_chain`), which enters the O(chain) walk unless `chain_restore_trust_index_fastpath()` is engaged. The fastpath engages on a clean `fast_restart` (`config/src/boot_fast_restart.c`) and via `chain_restore_finalize_verified` when the index is verified (`config/src/boot.c:3785`), and — the fix — also around the unclean-restart restore branch (`config/src/boot.c`, the `else if (g_state.map_block_index.size > 1)` arm), which engages `chain_restore_set_trust_index_fastpath(true)` around `utxo_recovery_restore_chain_tip` whenever `chain_restore_index_verified_consistent(index_repaired, map_block_index.size)` holds (`index_repaired == 0 && size > 1000`), mirroring the `finalize_verified` guard — scoped + cleared, so the full disk walk stays the last-resort rung reached only when `index_repaired > 0`. The shared predicate lives in `chain_restore_executor.c` (`chain_restore_index_verified_consistent`). A genuine slow-boot defect otherwise — a kill -9 must resume in O(delta), not O(chain). Proven by `test_rebuild_active_chain_is_o_chain_not_delta` and `test_unclean_restart_recovery_is_o_delta` (`lib/test/src/test_chain_restore_service.c`): with the fastpath OFF the row counter scales with chain height (`rows == tip_h+1`); with it ON the fast path reads 0 disk rows regardless of height, and both differentially converge to the same tip (height + hash). The nBits backfill at `chain_restore_repair.c:688-689` is NOT an additional O(chain) disk cost (it skips entries whose nBits is already set, `:428`).

  **Copy-proven live** on a real multi-million-entry datadir across independent kill -9 samples mid-fold, confirmed via the `.shutdown_clean` marker absent before each reboot: the chain_restore-specific cost (`blkidx.restore_tip` + `chain_restore_finalize`) stays flat (order of ~1s total) as the index grows, nowhere near the O(chain) reference walk (tens of seconds) the same fixture class takes with the fastpath off, and `chain_restore.disk_rebuild_rows` never enters the O(chain) rung (`index_repaired == 0`). The remaining time-to-RPC-serving and time-to-first-cursor-advance is dominated by subsystems this fix does not touch and that do not scale with index size either: fixed per-boot DB integrity costs (`sqlite.quick_check`, `sqlite_open_migrate`, `prologue`) and the FlyClient MMB leaf-store catchup (proportional to the actual header-catchup delta accumulated while down, not an index-size regression).
- **`docs/work/sync-organism-map.md` "Wound 2" described current served heights.** DELETED — it was a stale doc that claimed "active_chain_height — what getblockcount and P2P start_height SERVE and ADVERTISE" with refs `blockchain_controller_blocks.c:39` and `msg_version.c:148`. Both line numbers and both claims were wrong: actual lines are 50 and 155, and BOTH serve H*. `never-stuck-plan.md` records FIX-1 (wire H* to served APIs) as DONE in `e75b5c62c`, but `sync-organism-map.md` was never updated before it was removed. Keep the corrected facts above (getblockcount/start_height serve H*) as the live truth; do not re-create the file or trust anything citing it. <!-- doc-path-ok: deleted stale doc, named so nobody re-creates it -->

---

## (2) ALREADY SHIPPED / DEAD — don't re-propose; don't assume it's live

### Already shipped — do NOT re-propose

- **Deferred ECDSA / proof verification below a checkpoint height.** Done. Two gates: `checkpoint_covers()` marks any height with a checkpoint entry as covered, and `g_deferred_proof_validation_below_height` gates expensive Sapling/JoinSplit proofs. When covered, `expensive_checks=false` skips PoW, script verification, and proof re-verification. → `lib/validation/src/connect_block.c:160-166`, `:182-186`; `contextual_check_tx.c:26`, `:77-78` (skip_proofs gates JoinSplit Ed25519 `:99`, Sapling Groth16 `:106-144`, Sprout `:147-172`); `chainparams.c:13-82` (63 checkpoints, every 50k blocks genesis→3,100,000).
- **Parallel ECDSA script verification in connect_block.** Done and live on the hot path. A lazy-initialized global workpool `g_script_pool` fans jobs to workers when `num_checks >= 4`, inline fallback below that. → `connect_block.c:66-82` (`get_script_pool()`), `:556-627` (Phase 1 collect), `:660-671` (Phase 2 dispatch), `:687` (telemetry `parallel=yes/no`).
- **Parallel-dispatch threshold for small batches.** Done. `num_checks >= 4` is the explicit heuristic to avoid scheduling overhead. → `connect_block.c:663`, `:687`.
- **Precompute per-tx sighash data before parallel dispatch.** Done. `struct precomputed_tx_data` is built once per tx and shared read-only across all parallel input verifications. → `connect_block.c:52` (struct, "shared per-tx, read-only"), `:414` (batch storage), `:571` (`precompute_tx_data` once per tx), `:621` (per-input pointer share); `sighash.h:25`.
- **Per-input MoneyRange validation.** Done. Every input value is range-checked at script-collection time, before script work is batched. → `connect_block.c:587-596` (rejects `bad-txns-inputvalues-outofrange`), listed as a new addition at `:18`.
- **BIP30 duplicate-coinbase skip below the deferred-proof height.** Done, intentional for snapshot re-connection / kill-9 recovery (coinbase outputs already exist in the imported UTXO set). → `connect_block.c:290-291` (`skip_bip30`), `:293` (gated loop), comment `:286-290`.

### Evaluated and REJECTED — the idea is fine, the implementation is not

- **A "boot cursor" that records how far the block-index scan got, so the next boot resumes instead of rescanning (`boot_cursor_scan_facts`, `BOOT_CUR_SCAN_UPTO`/`BOOT_CUR_SCAN_FACTS`).** Rejected on review; do not re-port it from history. It is described as an O(chain)→O(delta) boot conversion but is not one: the scan still runs `while (block_map_next(...))` over every block-index entry to clear `BLOCK_FAILED` and recompute hydration counters, and the cursor only skips ~3 ALU comparisons per entry inside the ~3.1M-entry pointer traversal that dominates the cost. The original harness (300K entries, min-of-7) could not distinguish a cold run from a warm one, so the speedup was never measured. It also predates the current `boot.c`. The GOAL is still right — don't redo work a previous boot finished — but a real fix has to eliminate the traversal itself, not annotate it, and must come with a measurement that separates cold from warm. Any replacement must preserve every `enum boot_stage` guarantee in `docs/BOOT_INVARIANTS.md`.

### Advisory scaffolding — do NOT wire into consensus thinking it authenticates state

- **The `xor_accumulator`-fed commitment MMR is advisory, sparse, and not consensus binding.** `boot_services.c` currently calls `rpc_blockchain_maybe_commit()` once to bootstrap an empty commitment history; no per-tip producer builds the history during ordinary runtime. The root is exposed by `getcommitmentmmr`/`auditchain`, but no consensus path reads it. Neither this XOR accumulator nor the MMB leaf's auxiliary `utxo_root` is committed by a ZClassic header, so neither can authenticate imported state or bind peer state to PoW. Treat `audit_passed` as internal-structure coverage only until this misleading compatibility surface is removed or renamed; keep snapshots assisted until local full-history promotion.

### Shipped but DEFAULT-OFF — present, not active (see also section 3 for why)

- **Sapling-root full-parity check.** Pure recompute predicate `sapling_root_matches()` is wired but gated on `g_enforce_sapling_root` (atomic, default false; only `-enforce-sapling-root` arms it). Default behavior is byte-identical to today (rejects only all-zeros root). → `connect_block.c:134-151` (predicate), `:725-735` (gate), `src/main.c`.
- **OP_CHECKDATASIG[VERIFY] sigop counting.** `SCRIPT_VERIFY_CHECKDATASIG_SIGOPS` is conditionally ORed only when `g_enforce_checkdatasig_sigops` is true (atomic, default false; `-enforce-checkdatasig-sigops`). Default flags omit it. → `connect_block.c:352` (default flags), `:359-361` (conditional OR), `src/main.c`.

---

## (3) NOT A BUG — INTENTIONAL — apparent bug → why → what breaks if "fixed"

- **Oversize tx at h=478544 (125,811 B) is not rejected at MAX_TX_SIZE_AFTER_SAPLING=102000.** Intentional: 413 canonical oversize post-Sapling txs (heights 478544..1968856, max 1922197 B) are grandfathered via a static sorted allowlist, checked ONLY in `DOMAIN_TX_CTX_BLOCK` context. Running zclassicd nodes ACCEPT these because validated blocks are never re-checked — this reproduces LIVE behavior, not the text. **Breaks if fixed:** forks the chain against every running zclassicd node. → `core/consensus/src/tx_structural.c` (the `ctx == DOMAIN_TX_CTX_BLOCK` gate → `domain_consensus_tx_oversize_grandfathered()` bsearch); `tools/data/oversize_grandfather_txids.txt` (413 entries); `docs/CONSENSUS_PARITY_DOCTRINE.md:76-130`. **`core/` is byte-sealed** — see §4. Also: don't "skip the lookup for perf" — cold path fires at most 413 times in a full reindex; cost is negligible vs fork risk.
- **`wallet_view_sync` Sapling placeholder crypto is a view-only marker, not spendable note material.** Intentional: zclassicd `z_listunspent` gives balance/output metadata, not the decrypted Sapling note fields required for a real spend. z23 stores deterministic placeholders as `wallet_sapling_notes.source='view'`; the fake `ivk` must not match a real keystore `ivk`, successful empty view results clear only `source='view'` rows, and a spend attempt against only those rows returns `view-only balance synced from zclassicd`. **Breaks if "fixed" by reusing real IVKs or deleting all notes on refresh:** external wallet-view data could enter spend selection or clobber durable local/catchup notes. → `app/controllers/src/wallet_view_sync.c`; `app/models/src/sapling_note.c`; `app/controllers/src/wallet_shielded_send_shielded.c`; `lib/test/src/test_wallet_funds_safety.c`.
- **`-enforce-coinbase-maturity` is DEFAULT-OFF.** Intentional. A tightening (reject) predicate must NOT ship until a full genesis→tip replay confirms ZERO false-rejects (the h=478544 lesson: you cannot assume what the canonical chain contains). Enabling before replay risks permanently wedging the node on old data. → `config/src/args.c:298-299` (flag ladder); `app/jobs/include/jobs/utxo_apply_delta.h:82-91`; `app/jobs/src/utxo_apply_delta.c:267-286`; `lib/test/src/test_utxo_apply_coinbase_maturity.c`.
- **`-enforce-checkdatasig-sigops` is DEFAULT-OFF.** Same reason: tightening predicate, gate on full-history replay. Default `connect_block` flags do not include the bit. **Breaks if defaulted on:** risk of false-rejecting old blocks → fork/wedge. → `connect_block.c:93-127`, `:352-361`; `core/consensus/src/check_block.c` (`DOMAIN_CONSENSUS_SIGOP_COUNT_FLAGS`); `config/src/args.c:310-311` (flag ladder); `lib/test/src/test_connect_block_checkdatasig_sigops.c`.
- **`-enforce-sapling-root` is DEFAULT-OFF.** Same doctrine. Must prove safe by full replay (0 false-rejects) before arming. **Breaks if defaulted on:** can permanently wedge on old blocks with now-detected shielded-commitment differences = a fork. → `config/src/args.c:286-287` (flag ladder); `connect_block.c:93-97`; `lib/test/src/test_connect_block_sapling_root.c`; `docs/CONSENSUS_PARITY_DOCTRINE.md:14-19`.
- **`contextual_check_block()` is skipped during IBD / historical replay.** Intentional: it IS wired on the connect path but fires ONLY near the live tip and ONLY when NOT in IBD, reproducing zclassicd's `ContextualCheckBlock`/`ContextualCheckTransaction` IBD short-circuit. A stage that halts honestly on `bad-cb-height`/`bad-txns-nonfinal` near tip is the CORRECT state, not a hang. **Breaks if the IBD gate is removed:** false-rejects old canonical blocks (non-final `nSequence`, past-height expiry, BIP34). → `app/jobs/src/script_validate_contextual.c:61-108` (proximity/IBD gate at `:85-92`, `is_initial_block_download` at `:95`); `contextual_check_block()` defined at `lib/validation/src/check_block.c:436`; `lib/test/src/test_script_validate_contextual_gate.c`.
- **JoinSplit Ed25519 sig verification on the connect path.** Intentional and load-bearing — runs BEFORE the per-joinsplit zk-SNARK loop and fails the whole block on an invalid `joinSplitSig` (`ok=0`, `first_failure_proof_type='joinsplit_sig'`), blocking the tip until a valid block replaces it. The SNARK binds `joinSplitPubKey` into `h_sig` but does NOT replace the Ed25519 sig, so this is required, not redundant. → `app/jobs/src/proof_validate_stage.c:141-147`; §2 item 3 of
`docs/work/consensus-parity-supplemental-audit-2026-06-08.md`.
- **`fCoinbaseMustBeProtected` is gated by chain params, not unconditional.** Intentional parity: fires on mainnet/testnet (`fCoinbaseMustBeProtected=true`), off on regtest (false), exactly as zclassicd gates it per-chain. **Breaks if the gate is removed:** breaks testnet/regtest compatibility. → `app/jobs/src/utxo_apply_delta.c:420-439`; `app/jobs/src/utxo_apply_stage.c:605-610`;
§2 item 5 of `docs/work/consensus-parity-supplemental-audit-2026-06-08.md`.
- **Upstream-hole (stale-replay artifact) returns JOB_IDLE, not JOB_BLOCKED.** Intentional. `JOB_BLOCKED` feeds the supervisor escalation/restart ladder, and a watchdog self-restart is what manufactures this hole class — re-blocking would re-trigger the watchdog that created it (a loop). The alarm is LOGGED+COUNTED, not escalated. **Breaks if changed to JOB_BLOCKED:** escalation loop. → `app/jobs/src/utxo_apply_stage.c:405-418` (`:409-414` comment, `:415` `upstream_hole_note()`). **Generalized:** the same JOB_IDLE-plus-typed-DEPENDENCY-blocker shape is shared via `stage_upstream_log_hole_note()`/`_clear()` (`app/jobs/include/jobs/stage_helpers.h`) and wired into ALL SEVEN downstream stages' `found==0` floor-violation sites — `body_fetch_stage.c`, `body_persist_stage.c`, `script_validate_stage.c`, `proof_validate_stage.c`, and `tip_finalize_stage.c` (its `utxo_apply_log` row-missing site; the sibling `validate_headers_stage.c` window-resolve-miss class below uses its own dedicated id, not this helper). Do not re-propose adding this; do check whether a NEW `found==0` site (a new stage, a new upstream log) has been wired to the same helper.
- **`stage_body_read_hold()`/`_clear()` (`stage_helpers.h`) name a typed TRANSIENT blocker `<stage>.body_read_failed` when `stage_read_block()` fails for a height body_persist already hash+merkle verified.** Wired into `script_validate_stage.c`, `proof_validate_stage.c`, and `utxo_apply_stage.c` (all three read the SAME already-verified body). `body_persist_stage.c`'s own read failure is a DIFFERENT case (`requeue_body_for_refetch`) — it owns the hash/merkle verification itself and clears `BLOCK_HAVE_DATA` to trigger a real network re-fetch; do not replace it with this helper.
- **`tip_finalize.uv_cursor_gap` typed DEPENDENCY blocker (`tip_finalize_stage_observe.c`) fires when `cursor_in > utxo_apply_cursor`.** This is an ANOMALY, not a normal wait — the pipeline order guarantees utxo_apply commits a height before tip_finalize consumes it, so this should be unreachable except via an out-of-band utxo_apply cursor repair. Folded into the existing `tip_finalize_observe_note_cursor_gap()` (previously WARN + counter only, no registry blocker) rather than added inline in `tip_finalize_stage.c`, to keep that file under its file-size-ceiling baseline.
- **`validate_headers.window_resolve_miss` is shared by TWO call sites via `vh_window_miss_note()` (`validate_headers_stage.c`): `step_validate`'s forward path AND `recheck_failed_rows`' repair path.** Both call `vh_resolve_bi()` and hit the identical unresolvable-height class; a resolve-miss stuck in the recheck loop pins H* exactly like a stuck forward step (an unrepaired `ok=0` `validate_headers_log` row caps `reducer_frontier_compute_hstar` regardless of how far the forward cursor climbed).
- **The "waiting for Sapling params to load" wait (there is NO enum named `JOB_WAIT_PARAMS` — do not invent one) instead of erroring.** Intentional and recoverable. Two distinct shapes: the contextual path returns `SV_CTX_WAIT_PARAMS` (`script_validate_contextual.c:101-103`, enum at `jobs/script_validate_contextual.h:29` documented as "recoverable, JOB_IDLE"), driven through `script_validate_stage.c:446` (the `SV_CTX_WAIT_PARAMS` case); the proof_validate path sets `internal_error=true` / `first_failure_proof_type="params_not_loaded"` (`proof_validate_stage.c:119-124`). Params load in a background boot thread; boot only WARNs on failure (`config/src/boot_services.c:836`). Returning a hard error would permanently reject valid canonical shielded blocks. A persistent wait looks like a hang but is correct when params fail to load — fix the params path (`-paramsdir=<dir>` pointing at a valid `sapling-spend.params`/`sapling-output.params` pair, or install the default `~/.zcash-params`). There is no `-nosaplingverify` flag — that string does not parse; the argv loop WARNs on any unrecognized `-flag` instead of silently no-op'ing. (The job-result enum is `JOB_BLOCKED`/`JOB_IDLE`/`JOB_FATAL` etc. in `jobs/job.h:36-37` — there is no `JOB_WAIT_PARAMS`.)
- **`-import-complete-shielded` REFUSING a bind whose chainstate best block != the target's fold-resume anchor (coins island root) is the bind guard, intentional.** A zclassicd whose on-disk chainstate lags its live tip (it had stopped flushing its block DB) used to import a frontier keyed BELOW the island root with both activation cursors flipped to 0 — the fold then hard-wedged at the first Sapling-commitment block above the island (`hashFinalSaplingRoot` mismatch, `utxo_apply.apply_failed`, H* pinned). The import now refuses pre-transaction (`shielded_history_import_bind_guard_probe` in `app/services/src/shielded_history_import_bind_guard.c`, called by both the verb in `src/main.c` and the service itself; nothing committed), and the boot-side refresh (`utxo_apply_anchor_gap_blocker_refresh_with_ndb` in `app/jobs/src/utxo_apply_anchors.c`) keeps the NAMED permanent blocker `utxo_apply.anchor_backfill_gap` raised on an ALREADY-manufactured mismatch (cursors 0 + latest Sapling frontier row below the island root + the header-committed root at the island root moved) — detection only, no auto-repair. The root comparison is what keeps the boot guard silent on healthy nodes (a folded node's latest anchor legitimately lags the coins tip over a commitment-free tail; the header root cannot have moved). **Do not "fix" the refusal by weakening the equality** — bind == island root is the only consistent bind. → `lib/test/src/test_shielded_bind_guard.c`.
- **Some `_v2`/`_v3`/`.v1` suffixes on names are load-bearing wire/ABI/format tags, not naming cruft.** A "canonicalize the names, drop version suffixes" sweep must NOT touch these — renaming breaks the dynamic-load ABI, silently drops a captured on-disk format section, or breaks wire/schema string matching against already-deployed consumers. Verified categories, with real symbols checked to exist at the time this was written:
  - **Hot-swap manifest symbol, resolved by exact string via `dlsym()`.** `struct zcl_hotswap_manifest_v2` (`lib/hotswap/include/hotswap/hotswap.h:87`) is exported as the data symbol literally named `zcl_hotswap_manifest_v2`, and `hotswap_loader.c:649` calls `dlsym(handle, "zcl_hotswap_manifest_v2")` — an exact byte-for-byte string lookup. `ZCL_HOTSWAP_MANIFEST_SCHEMA_V2` (`hotswap.h:49`) is a distinct schema-version constant checked against `manifest->schema_version` (`hotswap_loader.c:217-218`). Renaming the symbol (even to `_v3`) breaks every already-built `.so` module's dlsym resolution; bumping the constant without a real schema change breaks admission of existing modules. **Breaks if "cleaned up":** every hot-swap module fails to load with "missing zcl_hotswap_manifest_v2".
  - **The v3 shielded-snapshot format tag** (`config/src/boot_shielded_seed.c`, `config/include/config/boot_shielded_seed.h`; also referenced in this repo's root `CLAUDE.md` Tenacity section as "must not discard a captured v3 shielded section"). `shielded_v3` is not a stray variable suffix — it names a specific legacy USS snapshot format (Sapling+Sprout frontiers + nullifiers) that a v1/v2-oriented refold-reset path must not silently drop. Renaming or "flattening" the `v3` tag away from call sites (`boot_refold_staged.c:1081-1296`) makes it look like ordinary current-state code and invites a future edit to discard the captured section.
  - **Wire/schema string tags embedded as literal JSON values**, e.g. `"zcl.hotswap_module.v1"` (`hotswap_activate.c:236`), `"zcl.hotswap_generation.v2"` (`hotswap_loader.c:327`), `ZCL_SERVICE_MANIFEST_V1` (`config/services/catalog.def`), `"zcl.consensus_state_bundle.v1"` / `"zcl.consensus_state_install_verify_receipt.v1/record"` (`config/src/consensus_state_snapshot_install.c`, `config/src/consensus_state_install_verify_receipt.c:69`). These are the wire-format's own version discriminant, on the same footing as a protocol magic number — a consumer or diagnostic parser matches the literal string, so dropping the trailing `.v1`/`.v2` is a breaking schema change disguised as a rename, not a cleanup.
  - **The `test_hotswap_module_v2` test group — CHECKED 2026-07-25, load-bearing, do NOT rename.** It looks like the textbook "one canonical name, no `-v2` suffix" violation and has been proposed as one. It is not. The module ABI is versioned and the loader hard-refuses any module not carrying the CURRENT one — that constant has since moved to `ZCL_HOTSWAP_MODULE_ABI_V3` (the manifest gained the sealed-core sections a module compiled against), so read the current value out of `lib/hotswap/include/hotswap/hotswap_module.h` rather than trusting a number quoted here. The group tests the MULTI-LEAF ABI v2 admit/probe/batch-commit path specifically, and one of its six assertions is that an **old-ABI (v1) module is refused LOUDLY at `stage=abi`** (`test_hotswap_module_v2.c:263-275`). Its sibling `test_hotswap_module.c` is a DIFFERENT, co-existing group covering the single-leaf ABI plus the epoch/refcount dlclose drain — so `v2` is not a stale version marker on one canonical thing, it is the discriminator between two things that exist at the same time. Renaming it would both collide semantically with the sibling group and erase the ABI distinction that is the group's entire subject. **Breaks if "cleaned up":** the rename reads as cosmetic, the two groups become indistinguishable by name, and the next reader has no signal that v1-refusal coverage lives in the `_v2` file.
  - **What IS fair game:** a `_v2`/`_v3` suffix that is genuinely just an unused leftover local variable or file name with no dlsym/wire/format consumer anywhere in the tree — verify with `z23 code sym/refs` (or a scoped grep) that nothing resolves the literal string before touching it.
- **A "every `make <target>` named in docs must exist" gate was evaluated on 2026-07-25 and DECLINED — do not re-propose it without new evidence.** It sounds like an obvious sibling of `check-no-stale-pinned-facts`, and it is not worth its cost. Measured: 373 defined targets vs 166 doc-mentioned ones, and **zero** real violations. A naive scan reports ~34, and every one is a false positive of two kinds: (a) English prose — "make a", "make sure", "make it", "make progress", "make this", "make every" — because `make <word>` is an ordinary verb phrase; and (b) **macro-generated rules**, which no grep of `^target:` can see. `test_parallel_wpo` and `zclassic23-chaos` are both produced by `$(eval $(call BUILD_NODE_TOOL,...))` (`Makefile:1136,2477`) and look missing to a text scan while being perfectly real — confirm with `make -pn | grep -oE '^<target>:'`, which resolves macro-generated targets correctly. The only genuinely absent doc-mentioned target is `mvp-live`, and `docs/work/mvp-live-gate.md:99` already labels it "(suggested — not yet wired)", which is honest and would need an exemption anyway. **The adjacent class that WAS worth gating** — Makefile *tool rules that no longer build* — had six real violations and is now covered by `check-standalone-tools-link`; spend effort there, not here.
- **`.codeindex/` refusing to open when the directory is group- or world-writable is the security boundary, not a papercut — do NOT make it self-heal.** The check is `dir_st.st_mode & (S_IWGRP | S_IWOTH)` in `rebuild_lock_open()` (`lib/codeindex/src/codeindex_build.c`), and `lib/test/src/test_codeindex.c` pins it: it `chmod 0777`s the fixture and asserts `codeindex_open()` returns NULL ("Mode drift fails closed before SQLite can consume the canonical pathname"). The symptom is loud and looks like a regression — every group that reads the index fails with `rebuild failed`, and `test_code_capsule` goes red on a tree where nothing relevant changed. **The cause is environmental**: the C code creates the directory `0755`, but a shell `mkdir -p` under the common `umask 0002` leaves it `0775`, and `mkdir` then returns `EEXIST` on every later run so nothing ever tightens it. **Fix: `chmod g-w,o-w .codeindex`.** It is gitignored build state — deleting it is also fine. **Breaks if "fixed" with an auto-chmod:** tightening the mode afterwards does not undo anything an attacker already planted there, which is precisely why the refusal happens *before* the path reaches SQLite. (Bonus trap: `codeindex_build.c` is one of the files carried in `tools/lint/file_size_policy_baseline.txt`, so an auto-chmod patch that grows it past its recorded line count fails E1 too — a second, unrelated-looking failure with the same single cause.)
- ~~The compile-epoch object directory relocating on every edit is deliberate, and the whole-tree key it uses is load-bearing.~~ **RETIRED 2026-07-27 — the epoch is now toolchain+flags-keyed, and the guarantee was replaced, not dropped.** `zcl_compile_epoch` used to bind the whole-tree source id + mutation token, so any edit relocated all ~1,200 objects. It now binds only compiler/toolchain fingerprint, profile, effective compile/link flags, and `BUILD_SYSTEM_ID` (`build-epoch-key.sh build-system-id` = root Makefile, which holds every flag variable and per-object override, + the four epoch driver scripts), so a source edit recompiles only make's stale TUs inside the STABLE epoch while a Makefile/flags/toolchain edit still busts every epoch. The replacement guarantees: per-TU freshness rides make's timestamp+depfile graph; `clientversion.o` carries `ZCL_BUILD_SOURCE_ID` and depends on `$(BUILD_IDENTITY_STAMP)` in every profile, so any source-identity move rebuilds it and relinks every binary (all link rules take the stamp); every publish path still re-verifies the exact source record after compiling, and the per-TU compile driver still requires a session stamp naming the current source id/mutation. The known residual vs the old design: a compile that races an edit *in the same seconds window* can leave one object whose mtime postdates the reverted source — the publish-time verify-record still refuses the binary, but the old ABA quarantine-by-namespace is gone by design (accepted; the failed `perf/stable-objdir-and-gold-linker` branch had the same exposure and its review did not flag it). **Do not re-add a per-object attestation/verifier pass** — that was the branch's measured ~11% wall-time regression; the win comes from make's normal incrementality. The branch's other two defects are closed: a per-object CFLAGS edit moves `BUILD_SYSTEM_ID` (proven: dev epoch re-keys, full rebuild scheduled), and `check-build-epoch-integrity`'s cache key now includes the driver itself plus every script the probes read (proven: editing an input forces a real rerun). See `docs/BENCHMARKS_LOG.md`.
- **Onion gates self-SKIPing is SKIP-not-FAIL honesty, not a broken suite.** `test_onion_bootstrap` prints `SKIP (set ZCL_STRESS_TESTS=1 to run — ~30s + Tor network)` (`lib/test/src/test_onion_bootstrap.c:112`), and `mvp-onion-local` exits 0 with a named SKIP when the binary links the offline Tor stub or the host has no Tor-network egress (Makefile, the `mvp-onion-local` block). Both are deliberate: a timed real-network bootstrap on a sandboxed host would false-FAIL forever, and a stub-built binary answering the claim would be a lie. The Tor stack itself is hosted IN-PROCESS (vendored dynhost fork; `tor_run_main()` runs on our own thread — no external daemon is ever spawned), so the hermetic onion groups (`test_onion_stream`, `test_onion_persistence`, `test_onion_directory`, …) pass offline and there is nothing to "fix" about that either; wide-area rendezvous claims belong only to `make mvp-onion-local` on an egress-capable host. **Breaks if "fixed" by making them fail unconditionally:** every no-egress box (CI sandboxes included) turns permanently red for an environmental reason, which trains everyone to ignore red. → `docs/OVERLAY.md` "The onion lives inside this binary".

---

## (4) LOOKS DELETABLE — IS PINNED

A "repo hygiene / delete the dead directories" pass is a reasonable-sounding task
that detonates here. Seven top-level directories read as clutter and are pinned
by a test assert, a runtime string, a byte seal, or a lint gate's scan root.
Worse than a loud assert: **moving `domain/` hollows its gate to a silent
CLEAN**, and nothing fires for months.

| Directory | Looks like | What actually pins it |
|---|---|---|
| `core/` | ordinary source | **Byte-sealed.** `core/MANIFEST.sha3` + the `check-core-seal` gate hash every file. Any edit fails `make lint`. Unlock: `make core-unseal REASON="…"` (appends to `core/UNSEAL.md`, mints a one-commit `.core-unseal-token`) → edit → `make core-seal`. An agent cannot mint that token as a normal source edit. |
| `application/` | two `.gitkeep` files, no source | Hardcoded in the `roots[]` list of `run_check_build_commit_macro_contract()` in `lib/test/src/test_make_lint_gates.c`; each entry is `opendir()`ed. Delete the directory and the test aborts. |
| `apps/` | a second code layout next to `app/` | **Runtime data, not code.** `lib/framework/src/app_catalog.c` `snprintf`s `"%s/apps/%s/app.def"` against the datadir at run time, and a native command's reply is asserted equal to that exact string. |
| `domain/` | 8 files, mostly superseded by `core/` | `tools/scripts/check_domain_purity.sh` ends with `find domain -type f …`. Rename or move the directory and `find` matches nothing, `violations` stays empty, and the gate prints `clean` — **a hollowed gate that still passes**. |
| `ports/` | 12 headers, no `.c` | `tools/scripts/check_doc_counts.sh` hard-counts `ports/include/ports/*.h` against `port_interfaces` in the `DOC-COUNTS` block of `docs/CODEBASE_MAP.md`. |
| `adapters/` | thin sqlite wrappers | Same gate hard-counts `adapters/outbound/persistence/src/*.c` against `persistence_adapters`. |
| `src/` | four loose files at the root | The program entry point (`src/main.c`, `src/cli.c`, `src/main_cli_modes.{c,h}`) and the most content-asserted path outside `app/`. It is also in the same `roots[]` list as `application/`. |

- **The top-level directory set was mirrored in several hand-kept copies; most
  are now derived, one is not.** `tools/lint/repo_shape.sh` parses the
  Makefile and publishes `ZCL_REPO_TOPS[]`, and `check_no_orphan_placement.sh`
  now reads it rather than restating it. `MODULE_TOPS` in
  `tools/lint/check_doc_inline_paths.sh` is still a hand-kept literal, and
  deliberately a **different** set — it matches doc-citable paths, so it
  includes `docs`, `apps` and `src`, which are not build roots. Do not
  "unify" the two without reading both: they answer different questions.
  The historical failure this bullet recorded did happen — the Makefile
  carried an `application/` root that every hand copy omitted, so a file
  placed there would have been filed under the catch-all group while the gate
  meant to catch exactly that passed, because its own list was one of the
  copies missing the entry.
- **`ci_group_for_path()` in `lib/codeindex/src/codeindex_group.c` still owns
  the path→group rule** (the module *list* it uses is now pasted from
  `config/lib_module_order.def` as an X-macro, but the routing logic is its
  own). `ci_group_purpose()` — the string `z23 code map` prints — is
  still a hand-written table with one arm per group. A new group needs both.
- **`zslp_balances` is NOT a superseded copy of `zslp_ledger`. Do not delete
  it.** This one nearly shipped: `zslp_ledger.h`'s header says a credit-only
  ledger "cannot debit SEND inputs and would over-count holders" and that the
  chain-scan path leaves `zslp_balances` empty on purpose, which reads exactly
  like an abandoned duplicate awaiting cleanup. It is not. The two are
  different ledgers for different features, and their keys do not convert:
  `zslp_ledger` keys on a 32-byte genesis txid plus a 20-byte hash160, while
  the **store** (merchant checkout) writes `zslp_balances` keyed on permanent
  ticker strings — `"ZCL23ACCESS"`, `"ZCL23VPN"`, hardcoded in
  `store_controller_schema.c` — which `uint256_set_hex()` cannot parse at all.
  The store credits on a shielded ZCL payment reaching confirmations, before
  and independent of any SLP transaction, so nothing the store does can ever
  produce the rows `zslp_ledger` derives from. Live writer:
  `zslp_service_credit_balance` → `db_zslp_balance_credit`, driven from
  `app/services/src/zslp_command_service.c`. Readers include
  `store_controller.c` and `store_view.c` (token-gated access). Deleting it
  silently zeroes every store customer's balance. If it must go, that is a
  store-migration project, not a hygiene sweep.
- **Verify emptiness against the guard, not against `ls`.** Before deleting any
  top-level directory: `git grep -n '"<dirname>"' -- lib/test tools/lint tools/scripts lib/framework`
  and `git grep -n '<dirname>/' -- tools/lint tools/scripts`. A directory with
  no `.c` files can still be a scan root, a `roots[]` entry, or a runtime path.

---

## (5) BUILD & GATE TRAPS — a red that is not a test failure

Every trap in this section cost a real agent real time, and every one of them is
now **answered by a command or refused by a gate**. Read the table for the
command; do not memorize the prose. A row marked *refusal* cannot be committed
past — you will meet it whether or not you read this file, which is the point.

| # | The trap | What it is now | Where |
|---|---|---|---|
| 1 | A fresh `git worktree` does not inherit submodules, so `vendor/tor` is empty, the binary links a **stub** Tor, and nothing notices until the ship step ~25 minutes in | **command** | `make worktree-prime` initializes `vendor/tor` FIRST, then copies the four Tor archives and `vendor/lib/*.a`. `tools/ship.sh` preflights the same fact in seconds instead of at the finish line. |
| 2 | A submodule with files but no `.git` stops EVERY build with "exact source capture failed", having run no tests | **command** | Same `make worktree-prime` — the order matters and is enforced there: copying archives into an uninitialized gitlink is what produces that message, and the message itself now names the fix. |
| 3 | `make test_parallel ONLY=x` only **builds**; nothing runs and `ONLY=` is never read | **refusal** | `ONLY_IGNORING_GOALS` in `Makefile`. `ONLY=` on `test`, `test_parallel`, `test-parallel`, `test-asan`, `test-tsan` and friends is a parse-time `$(error)` naming `make t-fast ONLY=…` and `build/bin/test_parallel --only=…`. |
| 4 | `test_parallel` needs `ulimit -s unlimited`; deep wallet groups SIGSEGV without it and 64 MB is not enough | **refusal (self-healing)** | `raise_stack_limit()` in `lib/test/src/test_parallel.c` raises the soft limit to the hard limit before any group forks, so a direct `build/bin/test_parallel` run no longer depends on the caller remembering. The Makefile's `ulimit` stays as the second guard. |
| 5 | A `test_*.c` file that exists proves nothing runs — the group must be REGISTERED | **refusal** | `check-test-registration` (`tools/scripts/check_test_registration.sh`) fails the build for any `test_<name>.c` entry point dispatched by neither `tools/dev/test_group_catalog.def` nor the serial runner, and names both fixes. |
| 6 | `printf … \| grep -q` under `set -o pipefail` returns 141 on a **match**, inverting the decision | **refusal** | `check-pipefail-status-pipe`. Shrink-only baseline, no per-line escape hatch. Fix with `str_contains`/`str_lacks` from `tools/scripts/sh_str.sh`, a here-string, or by extracting the match into a variable. |
| 7 | `! cmd` does not fail a script under `set -e` — bash exempts an inverted command from errexit **and** from the ERR trap — so the assertion can never fire | **refusal** | `check-discarded-status` prong A. Fix with a `refute()` helper that exits for itself (`tools/ship.sh --selftest` is the reference spelling). `if ! cmd`, `while ! cmd`, `! cmd \|\| die` and `! cmd && …` all consume the status and are never counted. |
| 8 | An apostrophe inside `${var:-default}` or an `awk '…'` program swallows the rest of the file, and the error is reported at EOF | **refusal** | The push gate parses **every** tracked `*.sh` plus the extensionless entrypoints (`shell_parse_all` in `tools/agent_fast_ci.sh`) — 415 files, ~0.5 s. Build the default outside the expansion; do not escape inside it. |
| 9 | Piping `make` output to `tail` HIDES the exit code — without pipefail the pipeline reports `tail`'s 0 | **refusal** | `check-discarded-status` prong B, HARD with no baseline. Use `make <goal> > build.log 2>&1 \|\| { tail -20 build.log; exit 1; }`, or set pipefail, or read `${PIPESTATUS[0]}`. |
| 10 | A relative `-datadir=./foo` silently breaks the store/directory writers and the explorer cache while chain sync keeps working | **prose + a message that names the fix** | Not gated: see below. The failure now reads "cannot resolve the parent directory of '…' — pass an ABSOLUTE `-datadir=`" instead of "destination parent is not a safe real directory". |
| 11 | A lint gate needs wiring in **two** files; a missing `run_lint.sh` case makes `make lint` exit 2 with no gate results at all | **refusal** | `check-lint-gate-wiring` asserts exact parity between `LINT_GATES`/`LINT_FAST_GATES` and `gate_command()`, in both directions, plus a real Make target and a script that exists. |

### Why trap 10 is still prose

Two candidate refusals were measured and both rejected, so the reasoning is
recorded here rather than rediscovered:

- **A commit-time gate over documented commands has no signal.** Scanning every
  tracked `*.md` and `*.sh` for a relative `-datadir=` value returns 44 hits and
  **zero** real ones: they are argument-parser `case` patterns (`-datadir=*)`),
  usage-line placeholders (`--dev-datadir=ABSOLUTE_DIR`), and systemd `%h`
  specifiers. A gate whose entire yield is a hand-curated exemption list is
  noise, not a rail.
- **A runtime refusal is an owner decision, not a lane decision.** Refusing a
  relative `-datadir` at startup changes node semantics, and `test_cli_render.c`
  asserts the CLI's own guidance text renders a relative datadir. The choice
  between "canonicalize the datadir at boot" and "refuse it loudly" also has to
  settle the *separate* trigger with the same root cause — a relative
  destination passed as an RPC argument (`storebuy_collect 3 ./mybook.pdf`),
  which no datadir fix reaches.

What was in scope, and is done, is the third thing that memo asked for
regardless of which option wins: the failure names the next action.

### The rule this section is an instance of

**A trap that has to be read and remembered is not fixed.** When you lose an
hour to something here, the deliverable is not a paragraph — it is a command
that answers the question or a gate that refuses the mistake, and an error
message whose last line is a concrete next action rather than a symptom. Prose
is the fallback, and it owes the reader the measurement that ruled the other two
out.
