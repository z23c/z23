/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Diagnostics registry: the `g_dumpers[]` table plus the `dumpstate` /
 * dumpstate dispatcher. Adding a subsystem is one descriptor row in
 * diagnostics_dumpers.def plus one dump function in the owning module.
 *
 * It also owns controller-level state (main_state + datadir) shared across
 * the diagnostics controller family.
 */

#include "platform/time_compat.h"
#include "platform/os_sandbox.h"
#include "util/thread_registry.h"
#include "controllers/agent_copy_prove_controller.h"
#include "controllers/agent_test_controller.h"
#include "controllers/shielded_gap_remedy_controller.h"
#include "controllers/block_intake_json.h"
#include "controllers/diagnostics_controller.h"
#include "controllers/diagnostics_internal.h"

#include "validation/main_state.h"
#include "validation/contextual_check_tx.h"
#include "validation/process_block.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "json/json.h"
#include "rpc/server.h"
#include "controllers/strong_params.h"
#include "services/chain_restore_boot_snapshot.h"
#include "services/block_source_policy.h"
#include "services/zclassicd_oracle_service.h"
#include "services/header_probe.h"
#include "services/utxo_parity_service.h"
#include "services/soak_attestation_service.h"
#include "services/canary_sentinel_watch.h"
#include "services/stopwatch_skip_watch.h"
#include "services/slo_ledger_summary.h"
#include "services/tip_agreement_watch.h"
#include "services/bg_validation_service.h"
#include "services/disk_monitor.h"
#include "services/network_monitor.h"
#include "services/network_crawler.h"
#include "services/sync_monitor.h"
#include "services/db_maintenance.h"
#include "services/legacy_mirror_sync_service.h"
#include "services/oracle_policy.h"
#include "services/quorum_oracle_service.h"
#include "services/rolling_anchor_service.h"
#include "services/seal_service.h"
#include "services/header_range_scheduler.h"
#include "services/block_pruning_service.h"
#include "services/segment_sealer_service.h"
#include "services/op_return_backfill_service.h"
#include "services/build_fabric_runtime.h"
#include "services/service_lifecycle.h"
#include "services/service_token_gate.h"
#include "services/zslp_ledger_backfill_service.h"
#include "services/market_moderation_service.h"
#include "services/vault_read.h"
#include "net/rom_seed.h"
#include "net/rom_fetch.h"
#include "net/fast_sync.h"
#include "net/file_service.h"
#include "zswap/zswap_yardsale.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_status.h"
#include "vcs/zcode_work_node.h"
#include "controllers/messaging_controller.h"
#include "controllers/observation_site_controller.h"
#include "services/chain_evidence_authority_service.h"
#include "services/gap_fill_service.h"
#include "services/wallet_backup_service.h"
#include "services/consensus_reject_index.h"
#include "services/blocker_history.h"
#include "services/block_index_integrity.h"
#include "services/storage_telemetry.h"
#include "services/telemetry_rollup.h"
#include "services/utxo_mirror_sync_service.h"
#include "services/mirror_divergence_locator.h"
#include "services/nullifier_backfill_service.h"
#include "services/consensus_state_publication_cas.h"
#include "services/recovery_coordinator.h"
#include "controllers/chain_segment_controller.h"
#include "jobs/header_admit_stage.h"
#include "jobs/reducer_frontier.h"
#include "jobs/validate_headers_stage.h"
#include "services/node_health_service.h"
#include "jobs/body_fetch_stage.h"
#include "jobs/body_persist_stage.h"
#include "jobs/script_validate_stage.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/utxo_apply_batch_commit.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/stage_repair_coin_backfill.h"
#include "jobs/refold_progress.h"
#include "jobs/pv_lookahead.h"
#include "storage/block_prefetch.h"
#include "jobs/rom_compile_status.h"
#include "jobs/psc_audit.h"
#include "services/chain_tip_watchdog.h"
#include "services/sticky_escalator.h"
#include "services/authority_projection_audit.h"
#include "services/state_auditor.h"
#include "services/address_index_service.h"
#include "services/txindex_projection_service.h"
#include "services/invariant_sentinel.h"
#include "framework/condition.h"
#include "conditions/catalog_lag_exceeded.h"
#include "conditions/blocker_handoff_registry.h"
#include "conditions/reducer_drive_watchdog.h"
#include "conditions/sync_rate_below_floor.h"
#include "storage/block_index_projection.h"
#include "storage/body_coverage.h"
#include "storage/body_history.h"
#include "storage/checkpoint_ladder.h"
#include "storage/mempool_projection.h"
#include "storage/peers_projection.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"
#include "config/boot.h"
#include "config/boot_blkidx_ladder.h"
#include "config/boot_endpoint_records.h"
#include "config/boot_bundle_fetch.h"
#include "config/boot_flight_recorder.h"
#include "config/boot_zcode_dht.h"
#include "config/boot_zcode_swarm_receipt.h"
#include "config/bundle_exporter.h"
#include "controllers/sovereignty_controller.h"
#include "controllers/status_frontdoor.h"
#include "services/sovereign_promotion_service.h"
#include "storage/small_projections.h"
#include "storage/topology_store.h"
#include "storage/znam_projection.h"
#include "storage/wallet_projection.h"
#include "crypto_registry/crypto_registry.h"
#include "hotswap/hotswap.h"
#include "services/ibd_throttle.h"
#include "services/mempool_limits.h"
#include "health/heartbeat.h"
#include "models/database.h"
#include "models/principal.h"
#include "models/agent_session.h"
#include "models/zid_identity.h"
#include "models/onion_directory.h"
#include "models/auth_challenge.h"
#include "models/zid_domain.h"
#include "config/runtime.h"
#include "net/peer_lifecycle.h"
#include "net/https_server.h"
#include "net/tor_integration.h"
#include "net/onion_ratelimit.h"
#include "net/rom_seed_policy.h"
#include "net/rom_seed_ledger.h"
#include "net/sync_shadow.h"
#include "util/log_macros.h"
#include "util/long_op.h"
#include "util/service_state.h"
#include "util/reducer_stage_profile.h"
#include "util/supervisor.h"
#include "util/telemetry_ontology.h"
#include "util/supervisor_backstop.h"
#include "util/blocker.h"
#include "util/db_txn_trace.h"
#include "util/self_backtrace.h"
#include "util/time_authority.h"
#include "util/cpu_topology.h"
#include "util/hw_bench.h"
#include "util/hw_profile.h"
#include "services/storage_housekeeping.h"
#include "util/storage_pacing.h"
#include "util/mem_pressure.h"
#include "util/thread_profile.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>
/* ── Controller-level state ─────────────────────────────────────────
 *
 * The boot-populated main_state + datadir (diagnostics_controller_set_state /
 * diag_datadir / diag_main_state) moved to the RESIDENT diagnostics_dispatch.c.
 * This TU is Tier-1 hot-swap eligible (engine/composition/hotswap_eligible.def), so it must
 * hold NO mutable file-scope statics: a recompiled generation .so would get its
 * own zero-initialized copy and lose the live boot state. The dumpers here reach
 * that state through the resident accessors declared in diagnostics_internal.h. */

/* ── explorer (clearnet HTTPS frontend) dump ───────────────────────
 *
 * One-call diagnosis of why the clearnet block-explorer is or isn't
 * serving. The HTTPS listener only binds when a TLS cert/key exist at
 * <datadir>/ssl/{fullchain,privkey}.pem at boot (see
 * boot_https_explorer_start in engine/composition/src/boot_frontend_services.c); a
 * missing cert silently leaves the node onion-only. This dumper surfaces
 * that condition without grepping node.log + ss + openssl by hand.
 *
 * Lives here because it needs diag_datadir; access()-only existence checks,
 * no sqlite and no cert parsing. */
static bool explorer_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    json_push_kv_bool(out, "https_started", https_server_is_running());
    json_push_kv_int(out, "https_port", (int64_t)https_server_port());
    json_push_kv_bool(out, "https_deferred", https_deferred_pending());

    const char *datadir = diag_datadir();
    char cert_path[1100], key_path[1100];
    snprintf(cert_path, sizeof(cert_path), "%s/ssl/fullchain.pem",
             datadir ? datadir : "");
    snprintf(key_path, sizeof(key_path), "%s/ssl/privkey.pem",
             datadir ? datadir : "");
    bool cert_present = (datadir && datadir[0] && access(cert_path, R_OK) == 0);
    bool key_present  = (datadir && datadir[0] && access(key_path, R_OK) == 0);
    json_push_kv_str(out, "cert_path", cert_path);
    json_push_kv_bool(out, "cert_present", cert_present);
    json_push_kv_bool(out, "key_present", key_present);

    json_push_kv_bool(out, "onion_enabled", tor_integration_is_enabled());
    const char *onion = tor_integration_get_onion_address();
    json_push_kv_str(out, "onion_address", onion ? onion : "");
    return true;
}

/* os_sandbox confinement state. A denied syscall KILLs the process (no
 * survivable "denied counter"), so the observable state is: whether a profile
 * entered, which one, the Landlock ABI, and the deny-set/seccomp posture. */
static bool sandbox_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);
    json_push_kv_bool(out, "active", os_sandbox_active());
    const char *prof = os_sandbox_active_profile_name();
    json_push_kv_str(out, "profile", prof ? prof : "");
    /* CACHED, never a fresh probe: os_sandbox_landlock_abi() issues
     * landlock_create_ruleset(2), which is absent from both -confine seccomp
     * allow-sets — probing it from inside a confined node is
     * SECCOMP_RET_KILL_PROCESS, so `ops state --subsystem=sandbox` would kill
     * the node it is diagnosing. Falls back to a live probe only while
     * unconfined (cached is -1 until a domain is built). */
    json_push_kv_int(out, "landlock_abi",
                     (int64_t)(os_sandbox_active()
                                   ? os_sandbox_landlock_abi_cached()
                                   : os_sandbox_landlock_abi()));
    json_push_kv_bool(out, "seccomp_supported", os_sandbox_seccomp_supported());
    json_push_kv_bool(out, "seccomp_active",
                      os_sandbox_active() && os_sandbox_seccomp_supported());
    size_t n_denied = 0;
    (void)os_sandbox_node_steady_denied_syscalls(&n_denied);
    json_push_kv_int(out, "node_denied_syscalls", (int64_t)n_denied);

    /* Thread-coverage witness — two independent dimensions, reported so the
     * witness proves ACTUAL coverage, not intent:
     *  - seccomp_tsync: the filter was installed via seccomp(2)+TSYNC, so it is
     *    on EVERY thread of the process atomically (pre-existing + future).
     *  - landlock_covered_threads: threads that have run landlock_restrict_self
     *    — either the entering boot thread itself, or an already-running
     *    thread that later joined via os_sandbox_landlock_apply_to_self()
     *    (the health-sweep/metrics loops do this on every tick; see
     *    engine/composition/src/boot.c:sr_sandbox_enter). Landlock has no TSYNC and is
     *    not retroactive, so any service thread NOT wired to that retrofit
     *    join is the documented residual (Landlock-unconfined but still
     *    seccomp-confined) — notably the supervisor dispatch thread
     *    (platform/modules/util/src/supervisor.c:supervisor_thread_main), which runs
     *    every registered supervisor child's on_tick synchronously and so
     *    cannot be confined without confining every dispatched callback. */
    json_push_kv_str(out, "seccomp_install_method",
                     os_sandbox_seccomp_install_method());
    json_push_kv_bool(out, "seccomp_tsync", os_sandbox_seccomp_tsync_active());
    json_push_kv_int(out, "threads_total",
                     (int64_t)thread_registry_live_count());
    json_push_kv_int(out, "landlock_covered_threads",
                     (int64_t)os_sandbox_landlock_restricted_count());
    return true;
}

/* bundle_scan_seed_height / bundle_classify / bundle_staleness_dump_state_json
 * live in diagnostics_registry_bundle.c, a separate translation unit sized
 * per check-file-size-ceiling; decl in diagnostics_internal.h. Same
 * precedent as sapling_checkpoint_dump_state_json in
 * diagnostics_sapling_checkpoint.c. */

/* ── RPC: getmirrorstatus ──────────────────────────────────────────
 *
 * Backs the native mirror-status command: the legacy_mirror
 * drift-detection introspection surface.
 */
bool diag_rpc_getmirrorstatus(const struct json_value *params, bool help,
                              struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "getmirrorstatus\n"
        "\nReturn legacy mirror sync status.\n"
        "\nResult: zclassic23_height/hash, zclassicd_height/hash, lag, "
        "reachable, mirror_running, last_catchup, last_error, "
        "headers_added, blocks_applied.");

    json_set_object(result);
    return legacy_mirror_sync_dump_state_json(result, NULL);
}

/* ── RPC: selfbacktrace ────────────────────────────────────────────
 *
 * Backs the `ops.debug.backtrace` native command. Dumps a live backtrace for
 * every registered thread of THIS running node into <datadir>/backtrace-<ts>.log
 * and returns { path, thread_count }. Works where perf/gdb/ptrace are blocked
 * (perf_event_paranoid, yama ptrace_scope).
 */
bool diag_rpc_selfbacktrace(const struct json_value *params, bool help,
                            struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "selfbacktrace\n"
        "\nDump a backtrace for every thread of the running node into "
        "<datadir>/backtrace-<unixts>.log.\n"
        "\nResult: { path, thread_count }.");

    json_set_object(result);
    char path[4300] = {0};
    int n = self_backtrace_dump_all(path, sizeof(path));
    if (n < 0) {
        json_push_kv_str(result, "error",
                         "self-backtrace dump failed (handler not installed or "
                         "log open failed)");
        return false;
    }
    json_push_kv_str(result, "path", path);
    json_push_kv_int(result, "thread_count", (int64_t)n);
    return true;
}

/* ── RPC: profile [seconds] [top_n] ────────────────────────────────
 *
 * Backs the `ops.profile` native command. Samples THIS running node's
 * /proc/self/task/<tid>/stat twice `seconds` apart and returns the busiest
 * threads (cpu_ms delta, name, wchan) plus a one-line verdict and a compact
 * reducer-stage step-EWMA snapshot. Read-only; in-process — the replacement
 * for the /proc sampling an operator does by hand to find a bottleneck.
 */
static void diag_profile_push_stage_ewma(struct json_value *result)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    struct stage_row {
        const char *name;
        int64_t (*ewma)(void);
        uint64_t cursor;
    } rows[] = {
        { "header_admit",     header_admit_stage_step_us_ewma,
          header_admit_stage_cursor() },
        { "validate_headers", validate_headers_stage_step_us_ewma,
          validate_headers_stage_cursor() },
        { "body_fetch",       body_fetch_stage_step_us_ewma,
          body_fetch_stage_cursor() },
        { "body_persist",     body_persist_stage_step_us_ewma,
          body_persist_stage_cursor() },
        { "script_validate",  script_validate_stage_step_us_ewma,
          script_validate_stage_cursor() },
        { "proof_validate",   proof_validate_stage_step_us_ewma,
          proof_validate_stage_cursor() },
        { "utxo_apply",       utxo_apply_stage_step_us_ewma,
          utxo_apply_stage_cursor() },
        { "tip_finalize",     tip_finalize_stage_step_us_ewma,
          tip_finalize_stage_cursor() },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        int64_t ewma_us = rows[i].ewma();
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_str(&item, "stage", rows[i].name);
        json_push_kv_int(&item, "cursor", (int64_t)rows[i].cursor);
        json_push_kv_int(&item, "step_us_ewma", ewma_us);
        json_push_kv_int(&item, "steps_per_sec",
                         ewma_us > 0 ? (int64_t)(1000000.0 / (double)ewma_us
                                                 + 0.5)
                                     : 0);
        json_push_back(&arr, &item);
        json_free(&item);
    }
    json_push_kv(result, "stage_ewma", &arr);
    json_free(&arr);
}

bool diag_rpc_profile(const struct json_value *params, bool help,
                      struct json_value *result)
{
    RPC_HELP(help, result,
        "profile [seconds] [top_n]\n"
        "\nSample this node's threads over `seconds` and report the busiest "
        "threads (cpu_ms, name, wchan), a one-line verdict, and the reducer "
        "stage step-EWMA snapshot.\n"
        "\nResult: { sample_ms, sampled_threads, verdict, busiest_thread, "
        "threads:[...], stage_ewma:[...] }.");

    int seconds = 3;
    const struct json_value *s0 = json_at(params, 0);
    if (s0 && s0->type == JSON_INT) {
        int64_t v = json_get_int(s0);
        if (v >= 1 && v <= 60) seconds = (int)v;
    }
    int top_n = 8;
    const struct json_value *s1 = json_at(params, 1);
    if (s1 && s1->type == JSON_INT) {
        int64_t v = json_get_int(s1);
        if (v >= 1 && v <= (int64_t)THREAD_PROFILE_TOP_MAX) top_n = (int)v;
    }

    struct thread_profile_opts opts = {
        .sample_ms = seconds * 1000,
        .top_n = top_n,
    };
    if (!thread_profile_sample(&opts, result)) {
        json_set_object(result);
        json_push_kv_str(result, "error", "thread profile sample failed "
                                          "(/proc/self/task unreadable)");
        return false;
    }
    diag_profile_push_stage_ewma(result);
    return true;
}

/* ── RPC: dumpstate <subsystem> [key] ────────────────────────────── */

#define DIAG_OWNER_LOCAL "engine/controllers/src/diagnostics_registry.c"
#define DIAG_TEST_DEFAULT "tests/harness/src/test_syncdiag_rpc.c"
/* Keep the legacy-oracle dependency contained in this allowlisted translation
 * unit.  The data-only manifest deliberately refers only to neutral aliases. */
#define DIAG_REFERENCE_ORACLE_DUMPER zclassicd_oracle_dump_state_json
#define DIAG_REFERENCE_ORACLE_OWNER \
    "engine/services/src/zclassicd_oracle_service.c"
#define DIAG_REFERENCE_ORACLE_DESC \
    "zclassicd oracle: drift-probe stats + RPC config"
#define DIAG_HEADER_PROBE_DESC \
    "header probe: bulk header pull from co-located zclassicd via JSON-RPC"
#define DIAG_LEGACY_MIRROR_DESC \
    "legacy mirror: always-on lockstep catch-up from co-located zclassicd"
#define DIAG_ENTRY(name_, fn_, desc_, state_, shape_, owner_, freshness_, \
                   cost_, key_, example_1_, example_2_, test_, drilldown_) \
    { .name = (name_), .fn = (fn_), .desc = (desc_), \
      .state_class = (state_), .owner_shape = (shape_), \
      .owner_file = (owner_), .freshness = (freshness_), .cost = (cost_), \
      .key_hint = (key_), .key_example_1 = (example_1_), \
      .key_example_2 = (example_2_), .primary_test = (test_), \
      .include_supervisor_drilldown = (drilldown_) }
#define DIAG_SERVICE(name_, fn_, desc_, owner_, test_) \
    DIAG_ENTRY(name_, fn_, desc_, "diagnostic", "service", owner_, \
               "in_process_snapshot", "cheap", NULL, NULL, NULL, test_, true)
#define DIAG_LOCAL(name_, fn_, desc_) \
    DIAG_SERVICE(name_, fn_, desc_, DIAG_OWNER_LOCAL, DIAG_TEST_DEFAULT)
#define DIAG_CHAIN(name_, fn_, desc_, owner_, test_) \
    DIAG_ENTRY(name_, fn_, desc_, "chain_or_network", "service", owner_, \
               "in_process_snapshot", "cheap", NULL, NULL, NULL, test_, true)
#define DIAG_CONDITION(name_, fn_, desc_, owner_, test_) \
    DIAG_ENTRY(name_, fn_, desc_, "condition_or_blocker", "condition", \
               owner_, "in_process_snapshot", "cheap", NULL, NULL, NULL, \
               test_, true)
#define DIAG_RUNTIME(name_, fn_, desc_, owner_, test_) \
    DIAG_ENTRY(name_, fn_, desc_, "runtime", "runtime", owner_, \
               "in_process_snapshot", "cheap", NULL, NULL, NULL, test_, true)
#define DIAG_JOB(name_, fn_, desc_, owner_, test_) \
    DIAG_ENTRY(name_, fn_, desc_, "diagnostic", "job", owner_, \
               "in_process_snapshot", "cheap", NULL, NULL, NULL, test_, true)
#define DIAG_STAGE(name_, fn_, desc_, owner_, test_) \
    DIAG_ENTRY(name_, fn_, desc_, "reducer_stage", "job", owner_, \
               "in_process_snapshot", "cheap", NULL, NULL, NULL, test_, true)
#define DIAG_PROJECTION(name_, fn_, desc_, owner_, test_) \
    DIAG_ENTRY(name_, fn_, desc_, "projection", "projection", owner_, \
               "persisted_projection_snapshot", "bounded_lookup", NULL, \
               NULL, NULL, test_, true)

/* One descriptor source drives dumpstate dispatch, the state catalog, native's
 * advisory subsystem enum, health rollup, and registry invariants. */
static const struct diagnostics_dump_entry g_dumpers[] = {
#include "controllers/diagnostics_dumpers.def"
};

#undef DIAG_PROJECTION
#undef DIAG_STAGE
#undef DIAG_JOB
#undef DIAG_RUNTIME
#undef DIAG_CONDITION
#undef DIAG_CHAIN
#undef DIAG_LOCAL
#undef DIAG_SERVICE
#undef DIAG_ENTRY
#undef DIAG_LEGACY_MIRROR_DESC
#undef DIAG_HEADER_PROBE_DESC
#undef DIAG_REFERENCE_ORACLE_DESC
#undef DIAG_REFERENCE_ORACLE_OWNER
#undef DIAG_REFERENCE_ORACLE_DUMPER
#undef DIAG_TEST_DEFAULT
#undef DIAG_OWNER_LOCAL

/* See diagnostics_internal.h: independent second derivation of this same
 * .def file's row count, via a dummy element type unrelated to struct
 * diagnostics_dump_entry. Re-including diagnostics_dumpers.def here builds a
 * second array using the file's own inter-row commas — exactly how
 * g_dumpers[] above is built — so this cannot silently agree with
 * g_dumpers[] by construction; it independently re-counts the same rows. */
size_t diagnostics_dumpers_def_row_count(void)
{
    struct diag_row_probe { char unused; };
#define DIAG_ENTRY(...) { 0 }
#define DIAG_SERVICE(...) { 0 }
#define DIAG_LOCAL(...) { 0 }
#define DIAG_CHAIN(...) { 0 }
#define DIAG_CONDITION(...) { 0 }
#define DIAG_RUNTIME(...) { 0 }
#define DIAG_JOB(...) { 0 }
#define DIAG_STAGE(...) { 0 }
#define DIAG_PROJECTION(...) { 0 }
    static const struct diag_row_probe rows[] = {
#include "controllers/diagnostics_dumpers.def"
    };
#undef DIAG_PROJECTION
#undef DIAG_STAGE
#undef DIAG_JOB
#undef DIAG_RUNTIME
#undef DIAG_CONDITION
#undef DIAG_CHAIN
#undef DIAG_LOCAL
#undef DIAG_SERVICE
#undef DIAG_ENTRY
    return sizeof(rows) / sizeof(rows[0]);
}

int diagnostics_subsystems_csv(char *out, size_t out_sz)
{
    if (!out || out_sz == 0) return 0;
    out[0] = '\0';
    size_t pos = 0;
    int unclamped = 0;
    for (size_t i = 0; i < sizeof(g_dumpers) / sizeof(g_dumpers[0]); i++) {
        int n = snprintf(out + pos, pos < out_sz ? out_sz - pos : 0,
                         "%s%s", i ? "," : "", g_dumpers[i].name);
        unclamped += n;
        if (n > 0 && (size_t)n < out_sz - pos) pos += (size_t)n;
        else pos = out_sz - 1;
    }
    return unclamped;
}

size_t diagnostics_dumper_count(void) { return sizeof(g_dumpers) / sizeof(g_dumpers[0]); }

const struct diagnostics_dump_entry *diagnostics_dumper_at(size_t idx)
{
    return idx < diagnostics_dumper_count() ? &g_dumpers[idx] : NULL;
}
static void diagnostics_dumpstate_help(struct json_value *result)
{
    char known[4096];
    diagnostics_subsystems_csv(known, sizeof(known));

    char text[8192];
    snprintf(text, sizeof(text),
             "dumpstate <subsystem> [key]\n"
             "\nDump in-process state for a subsystem. Known subsystems:\n"
             "  %s\n"
             "\nResult: { subsystem, description, captured_at, state: {...} }",
             known);
    json_set_str(result, text);
}

static bool diagnostics_dumpstate_unknown(struct json_value *result,
                                          const char *sub)
{
    char known[4096];
    diagnostics_subsystems_csv(known, sizeof(known));

    char msg[8192];
    snprintf(msg, sizeof(msg),
             "dumpstate: unknown subsystem '%s'; known_subsystems=%s",
             sub ? sub : "", known);
    json_set_str(result, msg);
    LOG_FAIL("diag", "%s", msg);
}

bool diag_rpc_dumpstate_builtin(const struct json_value *params, bool help,
                                struct json_value *result)
{
    if (help) {
        diagnostics_dumpstate_help(result);
        return true;
    }

    const char *sub = json_get_str(json_at(params, 0));
    const struct json_value *key_val = json_at(params, 1);
    /* Accept either string or int for the key; numeric height callers
     * often pass `3091000` rather than `"3091000"`. */
    char key_buf[64] = {0};
    const char *key = NULL;
    if (key_val) {
        if (key_val->type == JSON_INT) {
            snprintf(key_buf, sizeof(key_buf), "%lld",
                     (long long)json_get_int(key_val));
            key = key_buf;
        } else if (key_val->type == JSON_STR) {
            key = json_get_str(key_val);
        }
    }

    if (!sub || !sub[0]) {
        json_set_str(result, "dumpstate: missing subsystem");
        LOG_FAIL("diag", "dumpstate: missing subsystem");
    }

    const struct diagnostics_dump_entry *e = NULL;
    const char *domain_key = NULL;
    for (size_t i = 0; i < sizeof(g_dumpers) / sizeof(g_dumpers[0]); i++) {
        if (strcmp(g_dumpers[i].name, sub) == 0) {
            e = &g_dumpers[i];
            break;
        }
    }
    if (!e && strncmp(sub, "supervisor.", strlen("supervisor.")) == 0) {
        e = &g_dumpers[0];
        domain_key = sub + strlen("supervisor.");
    }
    if (!e) {
        return diagnostics_dumpstate_unknown(result, sub);
    }

    json_set_object(result);
    json_push_kv_str(result, "subsystem", domain_key ? sub : e->name);
    json_push_kv_str(result, "description", e->desc);
    json_push_kv_int(result, "captured_at", (int64_t)platform_time_wall_time_t());

    struct json_value state = {0};
    json_set_object(&state);
    bool ok = e->fn(&state, domain_key ? domain_key : key);
    if (!ok) {
        json_free(&state);
        json_set_str(result, "dumpstate: dump function returned false");
        LOG_FAIL("diag", "dumpstate: %s dump function returned false", sub);
    }
    json_push_kv(result, "state", &state);
    json_free(&state);
    return true;
}

/* ── Hot-swap generation entrypoint ─────────────────────────────────
 *
 * This TU (the g_dumpers[] table + the dumpers defined here) is Tier-1
 * hot-swap eligible (engine/composition/hotswap_eligible.def). Under a generation .so build
 * (-DZCL_HOTSWAP_GEN) the macro emits zcl_hotswap_gen_init, which re-points the
 * resident `dumpstate` provider at THIS TU's freshly-compiled
 * diag_rpc_dumpstate_builtin (and its recompiled g_dumpers[] + dumpers).
 * diag_dumpstate_replace lives in the resident diagnostics_dispatch.c, so it
 * binds to the executable's copy and mutates the provider the live read path
 * reads; the boot-populated main_state/datadir are reached through the resident
 * accessors, never a stale .so-local copy. In the node build and in release the
 * macro expands to nothing (no trailing semicolon by design). */
ZCL_HOTSWAP_EXPORT_PROVIDER(
    diag_dumpstate_replace(diag_rpc_dumpstate_builtin))
