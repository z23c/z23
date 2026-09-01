# Service-result convergence — shrinking-floor inventory + lane plan

The gate and its shrink-only baseline are live. This doc is the inventory
and lane partition for paying down the remaining baseline; it is not itself
a completion record — re-derive the live baseline count from
`tools/scripts/service_result_convergence_baseline.txt` before trusting any
number below.

## Why this exists

E2 (`check_one_result_type.sh`, `make check-one-result-type`) ratchets at
**file granularity**: an `engine/services/src/*.c` file is "clean" the moment it
references `struct zcl_result` **anywhere**, even if it still exports other
bare-`bool` top-level functions alongside that one converted surface. As of
this writing E2's own baseline (`tools/scripts/one_result_type_baseline.txt`)
is **empty** — every service file has adopted `zcl_result` somewhere or
carries a `// one-result-type-ok:<tag>` override. E2 is green, but that green
does not mean the framework-shape contract (services return `struct
zcl_result`, DEFENSIVE_CODING.md §2) is actually met file-wide: many files
are "mixed" — some functions converted, others still bare `bool` — and
nothing was forcing the mixed residue to shrink.

`check_service_result_convergence.sh` (`make
check-service-result-convergence`) is the sibling gate that closes that gap:
it counts **exported (non-static, top-level) bool-returning function
DEFINITIONS** per `engine/services/src/*.c` file and ratchets that count down to
zero, file by file, via `tools/scripts/service_result_convergence_baseline.txt`
(`<path> <count>`). See the script's header comment and
`docs/DEFENSIVE_CODING.md` for the exact fail conditions (grown count, new
unlisted file, stale/missing baseline entry, or a baseline entry left behind
for a file that is now clean or marker-exempt).

## Starting point vs. current baseline

`engine/services/src/*.c` files export legacy (non-static, top-level) bare-bool
functions; a file is exempt from this gate's baseline once it carries a
`// one-result-type-ok:<tag>` marker (the same marker E2 defines, reused here
exactly — file-level, no new syntax) judging its bool surface deliberate
(pure classifiers, watchdog/state-machine predicates, recovery-primitive
int/bool contracts, `*_dump_state_json` functions — see the CLAUDE.md
"Adding state introspection" convention, which mandates a `bool` return
there, not `struct zcl_result`). Re-run
`./tools/scripts/check_service_result_convergence.sh`, or read
`tools/scripts/service_result_convergence_baseline.txt` directly, for the
live file count and legacy-export count — both shrink as lanes land and
must not be pinned here.

### The `*_dump_state_json` pattern generalizes — read before converting

Five of the 19 remaining baselined files are **mixed**: they own one real
legacy-bool function AND a `*_dump_state_json` export that should almost
certainly get the same `one-result-type-ok` treatment, NOT a `zcl_result`
conversion:

| File | Real target(s) | dump_state_json (leave bool, don't convert) |
|------|-----------------|-----------------------------------------------|
| `disk_monitor.c` | `disk_monitor_is_critical` | `disk_monitor_dump_state_json` |
| `ibd_throttle.c` | `ibd_throttle_is_running`, `ibd_throttle_try_acquire`, `ibd_throttle_acquire` | `ibd_throttle_dump_state_json` |
| `legacy_mirror_sync_state.c` | `legacy_mirror_sync_blocker_should_surface` | `legacy_mirror_sync_dump_state_json` |
| `mempool_limits.c` | `mempool_limits_passes_min_relay` | `mempool_limits_dump_state_json` |
| `rolling_anchor_service.c` | `rolling_anchor_window_hash_ending_at` | `rolling_anchor_dump_state_json` |

**Important:** the `one-result-type-ok` marker is FILE-level (same as E2),
not function-level — adding it to one of these 5 files would also exempt the
REAL target function, silently removing it from the ratchet. Don't just
sprinkle the marker on these files. The correct fix (left to the lane that
picks up each file, not done in this pass, to keep this landing's diff to
comment-only additions with zero ambiguity) is either: (a) convert the real
function to `zcl_result` and ALSO add the marker citing the dump function
specifically (the marker's `<tag>` can and should name which function it
covers, e.g. `// one-result-type-ok:json-dump-bool-only:disk_monitor_dump_
state_json — disk_monitor_is_critical converted separately`), or (b) convert
both if the dump function's call site (always via the `g_dumpers` pointer
table in `engine/controllers/src/diagnostics_registry.c`) is judged safe to
change — it isn't, without also changing the dumper table's function-pointer
type for all ~50 registered subsystems, which is out of scope here.

## Per-file inventory (19 baselined files)

For each file: exported legacy bool functions, and every **production**
(non-test) call site found by `grep -rn` across `app/ config/ lib/ tools/
src/ domain/ core/ platform/ports/ platform/adapters/ engine/application/` (header declarations
excluded; test files under `tests/harness/src/` are covered by name only, not
line-by-line, to keep this table usable — every listed function is exercised
by `tests/harness/src/test_*.c`; use `grep -rn <name> tests/harness/src/` if that
detail matters for a specific migration).

### 1. `block_index_loader.c` (2 exports)
- `load_block_index_flat` — `engine/composition/src/boot.c:1836`, `engine/composition/src/boot_
  services.c:922`, `tools/mint_v2_snapshot.c:421,782` (+ comment mentions)
- `load_block_index_sqlite` — `engine/composition/src/boot.c:1839`
- Cluster: **boot-wiring**

### 2. `block_index_loader_rebuild.c` (2 exports)
- `load_block_index_from_projection` — referenced only in comments in
  `engine/composition/src/boot.c:1749`, `engine/composition/src/boot_projections.c:115` (no direct
  call site found outside its own TU/tests — verify before assuming dead)
- `boot_try_rebuild_block_index_from_projection` — `engine/composition/src/boot.c:1826,
  1854`
- Cluster: **boot-wiring** (shares `engine/composition/src/boot.c` with #1)

### 3. `block_source_policy_decisions.c` (3 exports)
- `block_source_policy_peer_floor_recovery_needed` — `engine/conditions/src/
  peer_floor_violated.c:90`
- `block_source_policy_snapshot_offer_allowed` — `engine/services/src/
  snapshot_offer.c:491,508,540,554,563`
- `block_source_policy_local_header_refill_needed` — `engine/conditions/src/
  local_header_refill_needed.c:92`
- Cluster: **snapshot-sync mesh** (shares `snapshot_offer.c` with #17)

### 4. `chain_evidence_persistence_service.c` (2 exports)
- `chain_evidence_state_set_retry` — `engine/services/src/chain_evidence_
  reconstruct.c:51,533,537`, `engine/services/src/chain_evidence_live_
  advance.c:231,235,339`
- `chain_evidence_state_set_int_retry` — `engine/services/src/chain_evidence_
  reconstruct.c:43`, `engine/services/src/chain_evidence_live_advance.c:247,
  343,347,350,354,358,362`
- Cluster: **chain-evidence**

### 5. `chain_restore_repair.c` (1 export)
- `chain_restore_trust_index_fastpath` — **no production call site found**
  outside its own TU (header declaration + tests only). Candidate for
  demotion to `static` as part of its conversion, or dead-code review.
- Cluster: **isolated / low-risk**

### 6. `chain_state_snapshot_service.c` (1 export)
- `csr_capture_frontiers` — `engine/services/src/chain_frontier_snapshot_
  service.c:137`
- Cluster: **chain-evidence** (no caller overlap with #4, but small enough to
  pair in the same lane)

### 7. `consensus_reject_index.c` (2 exports)
- `consensus_reject_index_running`, `consensus_reject_index_lookup` — **no
  production call site found** outside own TU (header + tests only).
- Cluster: **isolated / low-risk**

### 8. `disk_monitor.c` (2 exports)
- `disk_monitor_is_critical` (real target) — `engine/services/src/ibd_
  throttle.c:135`, `engine/models/src/db_txn.c:98`, `engine/conditions/src/disk_
  full_pause.c:44,99`
- `disk_monitor_dump_state_json` (leave bool — see table above) —
  `engine/controllers/src/diagnostics_registry.c:658` (pointer registration)
- Cluster: **disk/IBD-throttle** (shares `ibd_throttle.c` with #11)

### 9. `gap_fill_service.c` (3 exports)
- `gap_fill_compute_window`, `gap_fill_block_needs_queue`, `gap_fill_wake_
  dispatch_if_idle` — all three are called **only within `gap_fill_
  service.c` itself** (lines 313, 387, 410). Zero external production
  callers. Prime candidate to just go `static` + return `zcl_result`
  internally, or convert in place — either way, zero coordination risk.
- Cluster: **isolated / low-risk**

### 10. `header_sync_service.c` (17 exports — the largest single file)
- `syncsvc_should_begin_peer_sync`, `syncsvc_begin_peer_sync`,
  `syncsvc_should_mark_peer_caught_up`, `syncsvc_is_initial_block_download`,
  `syncsvc_should_disconnect_stale_header_peer`, `syncsvc_is_header_sync_
  stalled`, `syncsvc_should_request_headers_with_fallback` —
  `core/modules/net/src/msgprocessor.c:1801,1805,1808,1826,1889,1973`
- `syncsvc_should_restart_headers_from_tip`, `syncsvc_should_log_accepted_
  headers`, `syncsvc_should_release_snapshot_anchor` — `core/modules/net/src/msg_
  headers.c:664,713,886`
- `syncsvc_peer_is_behind` — `engine/services/src/block_sync_service.c:71`
- `syncsvc_should_request_headers`, `syncsvc_should_scan_block_files_after_
  headers`, `syncsvc_should_activate_after_block_file_scan`, `syncsvc_should_
  activate_after_header_processing`, `syncsvc_should_begin_blocks_download`,
  `syncsvc_headers_chain_from_tip` — **4 of these 6 ARE production-reachable;
  only 2 are genuinely unwired.** All are declared in `core/modules/sync/include/sync/
  sync_planner.h` and defined in `engine/services/src/header_sync_service.c`. The
  original "no production call site" reading counted *direct* callers only and
  missed one hop through the exported planners. Reachable, via a planner that
  live P2P message handling calls:
  - `syncsvc_should_request_headers` → `syncsvc_plan_periodic_getheaders` →
    `core/modules/net/src/msgprocessor.c:2142`
  - `syncsvc_should_scan_block_files_after_headers` →
    `syncsvc_plan_header_processing` → `core/modules/net/src/msg_headers.c:791`
  - `syncsvc_should_activate_after_block_file_scan` →
    `syncsvc_build_block_file_scan_activation` → `core/modules/net/src/msg_headers.c:950`
  - `syncsvc_should_activate_after_header_processing` →
    `syncsvc_build_header_processing_activation` → `core/modules/net/src/msg_headers.c:1018`

  Still unwired — their enclosing planners have no caller outside the defining
  TU and tests, so these two remain live candidates for deletion or wiring:
  `syncsvc_should_begin_blocks_download` (only reached by
  `syncsvc_plan_header_download`) and `syncsvc_headers_chain_from_tip` (only
  reached by `syncsvc_collect_needed_blocks`).
  <!-- claim: symbol-present syncsvc_plan_periodic_getheaders core/modules/net/src/msgprocessor.c # live P2P caller, one hop up -->
  <!-- claim: symbol-present syncsvc_plan_header_processing core/modules/net/src/msg_headers.c # live P2P caller, one hop up -->
  <!-- claim: symbol-absent syncsvc_plan_header_download core/modules/net # still no live caller: the 2 unwired ones stay unwired -->
- Cluster: **header-sync** — own lane (17 functions is a full lane by
  itself; its two production callers, `core/modules/net/src/msgprocessor.c` and
  `core/modules/net/src/msg_headers.c`, are not touched by any other baselined file).

### 11. `ibd_throttle.c` (4 exports)
- `ibd_throttle_is_running`, `ibd_throttle_try_acquire`, `ibd_throttle_
  acquire` — **no production call site found** (header + tests only; the
  header's own comment says "callers must `ibd_throttle_acquire()` one
  token per block" — this reads as a designed-but-not-yet-wired contract,
  not dead code — confirm with the IBD/block-download path owner before
  converting blind).
- `ibd_throttle_dump_state_json` (leave bool) — `engine/controllers/src/
  diagnostics_registry.c:605`
- Cluster: **disk/IBD-throttle** (shares `disk_monitor.c` — mutual: #8 calls
  into this file's `disk_monitor_is_critical`... no, correction: THIS file
  (`ibd_throttle.c`) calls `disk_monitor_is_critical()`, i.e. `ibd_
  throttle.c` is itself one of `disk_monitor.c`'s production callers. Converting
  `disk_monitor.c`'s signature requires touching `ibd_throttle.c` too — same
  lane.)

### 12. `legacy_mirror_sync_service.c` (4 exports)
- `lms_env_disabled` — `engine/services/src/legacy_mirror_sync_state.c:288`
- `lms_remote_hash_at` — `engine/services/src/mirror_divergence_locator.c:98`
- `lms_local_hash_at` — `engine/services/src/legacy_mirror_sync_state.c:394`,
  `engine/services/src/mirror_divergence_locator.c:59`
- `legacy_mirror_sync_request_catchup` — `engine/supervisors/src/legacy_
  mirror_supervisor.c:62`
- Cluster: **legacy-mirror** (shares `legacy_mirror_sync_state.c` with #13 —
  mutual: #13 also calls back into this file)

### 13. `legacy_mirror_sync_state.c` (2 exports)
- `legacy_mirror_sync_blocker_should_surface` — `engine/controllers/src/
  agent_operator_contracts.c:23`, `engine/controllers/src/health_
  controller.c:73`, `engine/controllers/src/event_healthcheck_controller.c:501`
- `legacy_mirror_sync_dump_state_json` (leave bool) — `engine/controllers/src/
  diagnostics_registry.c:509,551`
- Cluster: **legacy-mirror**

### 14. `mempool_limits.c` (2 exports)
- `mempool_limits_passes_min_relay` (real target) — **no production call
  site found** outside own TU/tests.
- `mempool_limits_dump_state_json` (leave bool) — `engine/controllers/src/
  diagnostics_registry.c:607`
- Cluster: **isolated / low-risk**

### 15. `rolling_anchor_service.c` (2 exports)
- `rolling_anchor_window_hash_ending_at` (real target) — `engine/services/src/
  seal_service.c:118`
- `rolling_anchor_dump_state_json` (leave bool) — `engine/controllers/src/
  diagnostics_registry.c:557`
- Cluster: **isolated / low-risk** (its one real caller, `seal_service.c`, is
  not touched by any other baselined file)

### 16. `snapshot_fetch.c` (2 exports)
- `snapsync_discard_staging_write_internal`, `snapsync_rollback_receive_
  write_internal` — both called from `engine/services/src/snapshot_sync_
  service.c:226,246` (passed as function pointers into `snapsync_run_write_
  internal`)
- Cluster: **snapshot-sync mesh** — mutual with #17 (`snapshot_sync_
  service.c` calls into `snapshot_fetch.c`'s `snapsync_run_write_internal`,
  and `snapshot_fetch.c`'s exports are consumed BY `snapshot_sync_
  service.c` — these two files must convert together or in lockstep)

### 17. `snapshot_sync_service.c` (8 exports — second-largest file)
- `snapsync_run_write_internal` — `engine/services/src/snapshot_fetch.c:203,
  435,447,455,510,513`, `engine/services/src/snapshot_verify.c:270`
- `snapsync_is_peer_blacklisted` — `engine/services/src/snapshot_offer.c:507`
- `snapsync_is_active` — `engine/composition/src/boot_msg_callbacks.c:92`, `core/modules/net/src/
  msgprocessor_snapshot.c:1075`
- `snapsync_awaiting_utxos` — `engine/services/src/chain_activation_
  service.c:363`
- `snapsync_check_negotiation_stall` — `engine/conditions/src/snapshot_
  negotiation_stalled.c:45`
- `snapsync_check_failed_reset` — `engine/conditions/src/snapshot_failed_
  reset.c:48`
- `snapsync_check_stall` — `engine/conditions/src/snapshot_receive_
  stalled.c:45`, `core/modules/net/src/msgprocessor_snapshot.c:1090`
- `snapsync_prepare_serve_step` — `core/modules/net/src/msgprocessor_
  snapshot.c:2233`
- Cluster: **snapshot-sync mesh** — the hub. Shares `snapshot_offer.c` with
  #3, `snapshot_fetch.c` mutually with #16, and `core/modules/net/src/msgprocessor_
  snapshot.c` / `engine/composition/src/boot_msg_callbacks.c` with no other baselined
  file. This is the single most fan-out file in the remaining baseline.

### 18. `utxo_recovery_service.c` (1 export)
- `utxo_recovery_xor_mismatch_is_corruption_candidate` — `engine/services/src/
  invariant_sentinel.c:593`
- Cluster: **isolated / low-risk**

### 19. `zslp_service.c` (5 exports)
- `zslp_service_is_alphanumeric`, `zslp_service_is_hex_string` — **no
  production call site found** outside own TU/tests (internal helpers used
  by the other 3 exports below, over-exposed via the header).
- `zslp_service_validate_token_key` — `engine/controllers/src/store_
  controller.c:196`, `contexts/market/controllers/src/zslp_controller.c:87,196,250,324`,
  `engine/controllers/src/api_controller_resources.c:192,231`
- `zslp_service_decode_transparent_destination` — `engine/services/src/zslp_
  command_service.c:161,181`
- `zslp_service_validate_recipient_addr` — `engine/controllers/src/zslp_
  controller.c:97,197`, `engine/controllers/src/store_controller.c:190`
- Cluster: **isolated / low-risk** (its callers — `store_controller.c`,
  `zslp_controller.c`, `api_controller_resources.c`, `zslp_command_
  service.c` — are not touched by any other baselined file)

## Lane partition

No two lanes below share a production caller file (the constraint the
orchestrator asked for). Lane 1 is the one exception called out explicitly —
`engine/composition/src/boot.c` is the single highest-fan-in wiring file in the whole
tree, so both files that touch it are folded into ONE serial lane rather
than split, exactly per the "concentrate boot/controller-wired services into
as few lanes as possible" guidance.

| Lane | Services | Shared caller file(s) | Risk / notes |
|------|----------|------------------------|---------------|
| **1. BOOT-WIRING** (serial, orchestrator-owned) | `block_index_loader.c`, `block_index_loader_rebuild.c` | `engine/composition/src/boot.c` (both), plus `boot_services.c` / `boot_projections.c` / `tools/mint_v2_snapshot.c` individually | Highest blast radius in the set — `boot.c` is the composition root. Land as ONE PR, hand-verified against a live boot, not parallelized with any other lane. |
| **2. SNAPSHOT-SYNC MESH** | `snapshot_sync_service.c`, `snapshot_fetch.c`, `block_source_policy_decisions.c` | `snapshot_offer.c` (2 & 17), mutual calls between 16 & 17 | The tightest internal coupling in the baseline (17's `snapsync_run_write_internal` takes 16's functions AS function pointers — their signatures must change together). Do NOT split 16/17 across lanes. Largest lane by export count (13). |
| **3. HEADER-SYNC** | `header_sync_service.c` | `core/modules/net/src/msgprocessor.c`, `core/modules/net/src/msg_headers.c` | Largest single file (17 exports). No caller overlap with any other lane — safe to run in parallel with everything except lane 1/2 IF `core/modules/net/src/msgprocessor.c` isn't independently touched by another in-flight branch (check live branch state, not just this table). 6 of its 17 functions have zero found production callers — confirm live-wiring status before converting those 6 (may be mid-refactor scaffolding). |
| **4. DISK / IBD-THROTTLE** | `disk_monitor.c`, `ibd_throttle.c` | Mutual: `ibd_throttle.c` calls `disk_monitor_is_critical()`; both also register a `*_dump_state_json` in `diagnostics_registry.c` (dump-only touch, see note below) | `ibd_throttle_is_running/try_acquire/acquire` (3 of 4 exports) have zero found production callers — the header comment implies a designed-but-unwired IBD block-download throttle; confirm before converting. |
| **5. LEGACY-MIRROR** | `legacy_mirror_sync_service.c`, `legacy_mirror_sync_state.c` | Mutual (13 calls back into 12); `diagnostics_registry.c` (dump-only) | `legacy_mirror_sync_state.c`'s real function is also called from 3 controllers (`agent_operator_contracts.c`, `health_controller.c`, `event_healthcheck_controller.c`) — none shared with any other lane. |
| **6. CHAIN-EVIDENCE** | `chain_evidence_persistence_service.c`, `chain_state_snapshot_service.c` | None shared between the two; grouped only because both are small (3 exports total) and unrelated to every other lane | Safe to split into 2 single-file lanes if more parallelism is wanted — no coupling. |
| **7. ISOLATED / LOW-RISK (batch)** | `chain_restore_repair.c`, `consensus_reject_index.c`, `gap_fill_service.c`, `mempool_limits.c`, `rolling_anchor_service.c`, `utxo_recovery_service.c`, `zslp_service.c` | None — verified zero caller-file overlap among these 7, and none with lanes 1-6 | Largest lane by file count (7) but each file is independent — freely splittable into as many parallel sub-lanes as desired. 3 files (`chain_restore_repair.c`, `consensus_reject_index.c`, `gap_fill_service.c`'s 3 exports) have **zero** found production callers at all — cheapest possible conversions (or `static` demotions), good first targets to prove the pattern. |

**Controller/registry touch note (all lanes):** `engine/controllers/src/
diagnostics_registry.c` appears as a caller for lanes 4, 5, and 7
(`mempool_limits.c`, `rolling_anchor_service.c`) purely via each file's
`*_dump_state_json` pointer registration. Per the "leave bool, don't
convert" guidance above, none of these should actually touch `diagnostics_
registry.c` — so despite appearing in multiple lanes' caller sets, this file
is not a real scheduling conflict. If a lane's implementer disagrees and
wants to convert a dump function anyway, that's the one case requiring
cross-lane coordination (it would mean changing the `g_dumpers` table's
function-pointer type, which fans out to ~50 registrations, not just the
lane's own file).
