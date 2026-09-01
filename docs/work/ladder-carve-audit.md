# Ladder-carve deletion audit — the borrowed-state reconcile/recovery ladders

Scope: the ~8.3k LOC of recovery/reconcile/mirror machinery that the doctrine
(`docs/ARCHITECTURE_NORTH_STAR.md`, `docs/work/never-stuck-plan.md` §4) marks
for deletion once the node holds tip on self-derived state. This audit produces
the per-file consumer graph and the staged deletion plan so a future carve does
not repeat the prior failure (a delete that built green but broke content-assert
tests / lint baselines it never enumerated).

**Headline verdict: Phase A (provably dead TODAY) is EMPTY. Zero LOC are
deletable now.** Every target file has at least one live consumer, and every
`docs/work/never-stuck-plan.md` deletion (D1–D7) is gated on a B-item that is
**not done in code** (verified below). No code is deleted by this audit.

## 1. Method

For each file the graph enumerates six consumer surfaces. A file is deletable
only when **all six are empty of live (non-self, non-test-only-removable)
references** for that file *and* its precondition holds.

| Tag | Surface | How enumerated |
|-----|---------|----------------|
| (a) | direct callers | `grep` each exported symbol across `app/ lib/ config/ src/` |
| (b) | registration tables | `condition_registry.def`, `blocker_remedy_bindings.def`, `diagnostics_dumpers.def`, boot service specs |
| (c) | tests + **content asserts** | `tests/harness/include/test/**`, esp. `test_make_lint_gates.c` string asserts on FILE/SYMBOL |
| (d) | lint-gate greps + baselines | `tools/scripts/check_*.sh`, `tools/lint/*_baseline.txt` |
| (e) | doc contracts | `docs/**` that name the file/symbol as a contract |
| (f) | build refs | `Makefile`, include graph |

## 2. Precondition ledger — why every D-item is still gated

`never-stuck-plan.md` §4 gates each deletion on a B-item. Live-code check
(this worktree):

| Precondition | Meaning | State in code | Evidence |
|---|---|---|---|
| B3 / I2 — `seed_exempt` stamp removed | stage cursor may not be stamped forward without a real per-stage log row | **PRESENT / live** | `tip_finalize_anchor.c:295`, `stage_anchor.c:176,191,298` |
| B3 / I1 — row-count acceptance removed | no UTXO set accepted by row count | **PRESENT / live** | `utxo_recovery_restore.c:329,377` (ROW-COUNT heuristic) |
| I1/I2 lint gates | `check-no-rowcount-install`, `check-no-seed-exempt-stamp` enforce the above | **DO NOT EXIST** | no `tools/scripts/check_no_rowcount_install.sh` / `check_no_seed_exempt_stamp.sh` |
| B2/B6 — atomic complete-state installer + background sovereignty promotion replace the ladder | the replacement the deletes are gated on | **not landed** | `never-stuck-plan.md` top-note: "that sequence is still undone in code"; promotion rederive driver is a stub (MEMORY `project_cure_endgame_and_move2_shipped`) |
| B4 — 7 stage logs re-keyed `(height,block_hash)` | reorg-correct append-only logs | **not landed** | logs still single-keyed; `test_log_append_only_reorg` not present |
| B7 — sound re-derive/clear of a forward `ok=0` | the ONLY non-ladder escape from a forward false-reject | **not landed** | the reconcile/repair conditions ARE the only clearer today |

Because B2/B3/B4/B6/B7 are all unmet, **no D-item is unlocked**. This is the
structural reason Phase A is empty; it is not a failure to look hard enough.

## 3. Consumer graph — utxo_recovery_* cluster (2,749 LOC → all Phase B/C)

Live boot integration (surface a): `engine/composition/src/boot.c` calls
`utxo_recovery_restore_chain_tip` (`:2926`), `utxo_recovery_execute` (`:3133`),
`utxo_recovery_import_ldb` (`:2705`), `utxo_recovery_clean_above_tip` (`:3670`),
`utxo_recovery_backfill_shielded_if_needed` (`:482`),
`utxo_recovery_repair_stale_cursor_from_sync_projection` (`:2051`),
`utxo_recovery_heal_torn_legacy_coins_anchor` (`:2059`),
`utxo_recovery_prepare_reimport` (`:2155`); `boot_index.c:735,765,801` calls
`utxo_recovery_block_trust_rooted`; `boot_mint_anchor_reset.c` /
`boot_refold_staged.c` call `utxo_recovery_clear_cold_import_seed[_checked]`.

| File | LOC | live consumers (a,b,d,c) | Phase | Precondition to delete |
|---|---|---|---|---|
| utxo_recovery_restore.c | 800 | boot.c restore_chain_tip; content-assert `test_make_lint_gates.c:7794,7810,8047`; baseline `borrowed_seed_caller_baseline.txt:11` | **B** | B3 (row-count) + B6. CARVE-KEEP: `restore_chain_tip` authority splice if self-derived install reuses it |
| utxo_recovery_service.c | 702 | boot.c execute/wipe/prepare; content-assert `:8147,8151` | **B** | B3+B6 |
| utxo_recovery_frontier_gate.c | 790 | index-tip→authority promotion gate; baseline `file_purpose_baseline.txt:164` | **C KEEP** | survives cure — D4 explicit KEEP; self-derived path also promotes an index tip |
| utxo_recovery_backfill.c | 349 | boot.c shielded backfill; content-assert `:8159`; `repair_rung_baseline.txt:26` | **B** | B7 (shielded re-derive); parts may survive as a fold step |
| utxo_recovery_torn_anchor.c | 223 | boot.c heal_torn; `file_purpose_baseline.txt:168`; `silent_bool_errors_baseline.txt:55` | **B** | B3 — D1 preserve: fold torn-import verdict into a transition check (carve, not raw delete) |
| utxo_recovery_stale_cursor.c | 191 | boot.c repair_stale_cursor; `file_purpose_baseline.txt:167`; `silent_bool_errors_baseline.txt:54` | **B** | B3 (kill cursor-stamp lie) |
| utxo_recovery_cleanup.c | 196 | boot.c:3670 + condition `orphan_utxo_above_tip.c:132` (`clean_above_tip`) | **C KEEP** | reorg-residue bounded rewind; not borrowed-state cover — survives cure |
| utxo_recovery_ldb_copy.c | 109 | cold-import LevelDB cp; `file_purpose_baseline.txt` cluster | **B** | B2+B3+I6 (delete cp path once from-blocks fold is fast) |
| utxo_recovery_mirror_walk.c | 80 | zclassicd mirror walk; `file_purpose_baseline.txt:165` | **B** | I6 (no zclassicd runtime) |
| utxo_recovery_seed_provenance.c | 120 | cold-import seed provenance; `file_purpose_baseline.txt:166`; `silent_bool_errors_baseline.txt:53` | **B** | B3 |
| utxo_recovery_internal.h | 175 | src-private decls for the cluster | **B** | trim to surviving decls as the cluster carves |

Also-consuming headers (surface a, must be trimmed on carve):
`services/utxo_recovery_service.h`, `services/block_index_loader.h`,
`services/chain_tip.h`, `services/shielded_history_import_service.h`,
`conditions/orphan_utxo_above_tip.h`, `services/invariant_sentinel.h`,
`services/seed_integrity_gate.h`, `util/file_tree_ops.h`,
`storage/utxo_reimport_flag.h`, `config/boot.h`, `config/boot_internal.h`,
`test/test_helpers.h`.

## 4. Consumer graph — the 4 conditions (2,030 LOC → Phase B/C)

All four are **production-registered** via `condition_registry.def:33,34,42,58`
→ `condition_registry.c` (surface b). `test_make_lint_gates.c` and
`test_condition_engine.c` also `#include` that `.def` (surface c — content
coupling).

| File | LOC | live consumers | Phase | Precondition |
|---|---|---|---|---|
| reducer_frontier_reconcile_light.c | 794 | `blocker_remedy_bindings.def:113,115,116,134,137,138` (6 remedies); `recovery_coordinator.c:56` (ladder rung); `sticky_escalator.c:358`; `block_failed_mask_at_tip.c:410`; job stages (`body_fetch`, `script_validate`, `proof_validate`, `utxo_apply`) name it as healer; `agent_impact_rules.def:120,121`; `repair_rung_baseline.txt:5`; content-assert `test_make_lint_gates.c:3784,3842` | **B (carve)** | B3+B4+B7. Heals **live forward faults** (`prevout_unresolved`, `apply_failed`, `label_splice`, `apply_candidate_anomaly`, `upstream_log_hole`) that persist post-cure — only the borrowed-import reconcile arm is dead; the forward-fault healer MUST be preserved or re-homed (B7) |
| stale_validate_headers_repair.c | 663 | `blocker_remedy_bindings.def:88,169`; `service_state_driver.c:39`; `block_failed_mask_at_tip.c:412`; `header_probe.h:88`; `agent_impact_rules.def:120`; `repair_rung_baseline.txt:6`; content-assert `test_make_lint_gates.c:4999,5001,5004` | **B (carve)** | B7 — today the only escape (besides `reconsiderblock`) from a forward header false-reject; forward-fault healing survives the cure |
| checkpoint_header_solution_repair.c | 409 | `blocker_remedy_bindings.def:89`; `checkpoint_bundle_install_ready.c:22,94`; `shielded_selfheal_ladder.c:31,348` | **C KEEP** | peer-fetches the baked **checkpoint header's Equihash solution** — the cure's own checkpoint install depends on it; not borrowed-state cover |
| clock_skew_reconcile.c | 164 | `condition_registry.def:42`; `blocker_remedy_bindings.def` | **C KEEP** | wall-clock skew reconcile; independent of state provenance — survives cure |

Sibling files that follow `reducer_frontier_reconcile_light` on any carve (not
in the target list but part of the same condition): `reducer_frontier_light_observe.c`
/ `.h` (the observe half), and the job-side implementation
`engine/jobs/src/stage_repair_reducer_frontier*.c` (`silent_bool_errors_baseline.txt:14-24`
+ `stage_reducer_frontier_reconcile_light[_needed]` at
`stage_repair_reducer_frontier.c:825,833`). Deleting the condition without these
leaves dangling `stage_*` externs.

## 5. Consumer graph — mirror-sync services (2,584 LOC → Phase B/C)

Both services are **booted live** in `engine/composition/src/boot_runtime_sync_services.c`:
`legacy_mirror_sync_init/start/stop` (`:99,102,113`) and
`boot_utxo_mirror_sync_register/start` (`:238,273`).

| File | LOC | live consumers | Phase | Precondition |
|---|---|---|---|---|
| legacy_mirror_sync_service.c | 779 | boot_runtime_sync_services; `block_source_policy_runtime.c:317`; `boot_node_utilities.c:71`; `node_health_service.c:712`; `health_controller.c:64,71,73`; `operator_snapshot_service.c:71,129`; `agent_operator_contracts.c:19,20`; `event_operator_snapshot_controller.c:398`; `diagnostics_dumpers.def:124` (`ops state --subsystem=legacy_mirror`); `Makefile:4934` (lag-SLO); content-assert `test_make_lint_gates.c:4196,5807`; header consumers `prometheus_metrics.h`, `blocker.h`, `parity_sample.h`, `parity_slo_breach.h` | **B** | I6/B6 — D2: stub oracle reads; **KEEP `chain_linkage` fork-HOLD**; re-source lag-SLO + parity canary to peer quorum first |
| legacy_mirror_sync_state.c | 718 | state store for the above; `silent_bool_errors_baseline.txt:47,48` | **B** | I6 (with service) |
| legacy_mirror_sync_json.c | 157 | `legacy_mirror_sync_push_status_contract_json` (event controller); content-assert `test_make_lint_gates.c:5807` | **B** | I6 |
| legacy_mirror_sync_parity_trend.c | 61 | parity trend vs zclassicd (feeds parity SLO / `parity_slo_breach`) | **B** | I6/D3 — re-source C8 parity canary to peer quorum |
| legacy_mirror_sync_internal.h | 115 | private decls; `file_purpose_baseline.txt:157` | **B** | I6 |
| utxo_mirror_sync_service.c | 754 | boot register/start; `consensus_state_install_runtime.c:347,364,874`; `diagnostics_dumpers.def:568` (`ops state --subsystem=utxo_mirror_sync`); consumer headers `utxo_recovery_service.h`, `utxo_mirror_delta.h`, `refold_progress.h` | **C KEEP (pending)** | residual #4: KEEP until **proven a pure rebuildable node.db cache**. Precondition is a PROOF, not the cure — do not delete on tip-hold alone |

## 6. Phase classification + LOC totals

| Phase | Definition | Files | LOC |
|---|---|---|---|
| **A — deletable NOW** | zero live consumers today, precondition already holds | *(none)* | **0** |
| **B — dead once the cure holds tip** | borrowed-state / zclassicd-drift cover; delete after its precondition, some via carve | restore, service, backfill, torn_anchor, stale_cursor, ldb_copy, mirror_walk, seed_provenance, utxo_recovery_internal.h; reducer_frontier_reconcile_light, stale_validate_headers_repair; legacy_mirror_sync_service/state/json/parity_trend/internal.h | **6,036** |
| **C — load-bearing KEEP** | survives the cure (reorg/disk/peer/checkpoint machinery, or unproven cache) | utxo_recovery_frontier_gate, utxo_recovery_cleanup, checkpoint_header_solution_repair, clock_skew_reconcile, utxo_mirror_sync_service | **2,313** |
| | **Total audited** | | **8,349** |

**Deletable now: 0 LOC. Dead after cure (Phase B): ~6,036 LOC.
Kept (Phase C): ~2,313 LOC.**

Caveat on the 6,036: ~1,457 LOC (the two reconcile/repair conditions) +
223 LOC (`torn_anchor`) are **carves, not raw deletes** — a surviving
forward-fault healer / transition check must be extracted first (B7), so the
net raw-deletable-after-cure is meaningfully below 6,036.

## 7. Companion-edit catalog — the anti-miss checklist

Any Phase-B carve MUST edit every row below for the touched file, or the build
greens while a content-assert test or a lint baseline fails at runtime. This is
the surface the prior deletion missed.

| Surface | Location | Entries to remove/update on delete |
|---|---|---|
| Content asserts | `tests/harness/src/test_make_lint_gates.c` | `:4196` (legacy_mirror path), `:4999-5004` (stale_validate rules), `:5807` (legacy json contract), `:6805` (header-absence assert), `:7293` (utxo_recovery_service.h), `:7794-7814` (restore boot contract), `:8047,8147-8159` (file manifest array in `t_production_comments_do_not_carry_refactor_scaffold_labels`), `:3784,3842` (reducer_reconcile condition-name asserts) |
| Condition registry | `engine/conditions/include/conditions/condition_registry.def` | lines `33,34,42,58` for the four conditions |
| Blocker remedies | `engine/conditions/include/conditions/blocker_remedy_bindings.def` | `:88,89,113,115,116,134,137,138,169` — re-point each remedy to its B7 replacement first |
| Diagnostics dumpers | `engine/controllers/include/controllers/diagnostics_dumpers.def` | `:124` (legacy_mirror), `:568` (utxo_mirror_sync); update the diagnostics-registry test if it asserts the catalog |
| Lint baselines | `tools/lint/file_purpose_baseline.txt` (`13,22,35,46,53,157,164-168`), `tools/lint/borrowed_seed_caller_baseline.txt:11`, `tools/scripts/repair_rung_baseline.txt:5,6,26`, `tools/lint/silent_bool_errors_baseline.txt:14-24,47,48,53,54,55` | remove the row(s) for each deleted file/symbol |
| Lint scripts | `check_blocker_escape_registered.sh`, `check_condition_cooldown.sh`, `check_no_new_repair_rung.sh`, `check_lag_slo_observable.sh`, `check_honest_witness.sh`, `fresh-boot-proof.sh`, `sticky_fault_inject.sh` | confirm each still passes with the symbol gone (some grep for it) |
| Build / Makefile | `Makefile:4934` (lag-SLO observability on `legacy_mirror_sync_service`) | re-source before deleting the service |
| Consumer headers | §3/§4/§5 header lists | trim decls; delete dangling `stage_repair_reducer_frontier*` externs if the condition goes |
| Agent-impact map | `cognition/controllers/include/controllers/agent_impact_rules.def:120,121` | remove the reducer_frontier / stale_validate rows |
| Condition tests | `tests/harness/src/test_reducer_frontier_reconcile_light.c`, `test_reducer_reconcile_witness.c`, `test_stale_validate_headers_repair_condition.c`, `test_header_probe_p2p_fallback.c`, `test_sticky_conditions.c` | delete/rewrite; each calls `register_*` |

## 8. Ordering (from never-stuck-plan §4, unchanged)

Bottom-up, each gated on its replacement; D7 (purge verb) is LAST and strictly
after B4. Nothing in this list is startable until B2/B3 land the atomic
complete-state installer + background promotion that replace the row-count
heuristic and the `seed_exempt` stamp. Until then this audit is a map, not a
work order.
