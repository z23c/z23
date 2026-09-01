/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression tests for rolling_anchor_service supervisor ownership.
 * The service used to run from lib/health; it now owns a chain-domain
 * liveness contract and must stay idempotent across start/stop. */

#include "test/test_core.h"

#include "chain/sha3_windows.h"
#include "event/event.h"
#include "json/json.h"
#include "services/oracle_policy.h"
#include "services/rolling_anchor_service.h"
#include "platform/directory_compat.h"
#include "platform/private_file.h"
#include "util/supervisor.h"
#include "validation/main_state.h"

#ifdef _WIN32
#include <windows.h>
#endif

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* Row-8 page capture: count EV_OPERATOR_NEEDED events carrying the
 * rolling_anchor sealed-read-failure condition. */
static _Atomic int g_ra_pages = 0;
static void ra_page_observer(enum event_type type, uint32_t peer_id,
                             const void *payload, uint32_t payload_len,
                             void *ctx)
{
    (void)type; (void)peer_id; (void)ctx;
    if (payload && payload_len > 0 &&
        strstr((const char *)payload, "rolling_anchor_sealed_read_failure"))
        atomic_fetch_add(&g_ra_pages, 1);
}

/* B8: oracle divergence is evidence, never a gate. Counts
 * EV_SYNC_STATE_CHANGE payloads naming rolling_anchor's own divergence
 * observation (distinct from the sibling quorum-split payload). */
static _Atomic int g_ra_divergence_events = 0;
static void ra_divergence_observer(enum event_type type, uint32_t peer_id,
                                   const void *payload, uint32_t payload_len,
                                   void *ctx)
{
    (void)type; (void)peer_id; (void)ctx;
    if (payload && payload_len > 0 &&
        strstr((const char *)payload, "rolling_anchor oracle divergence"))
        atomic_fetch_add(&g_ra_divergence_events, 1);
}

#define RA_CHECK(name, expr) do { \
    printf("rolling_anchor: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static int64_t ra_dump_int(const char *field)
{
    struct json_value v;
    json_init(&v);
    int64_t got = -999999;
    if (rolling_anchor_dump_state_json(&v, NULL)) {
        const struct json_value *f = json_get(&v, field);
        if (f) got = json_get_int(f);
    }
    json_free(&v);
    return got;
}

static int find_rolling_anchor_snapshot(struct supervisor_snapshot *out,
                                        int *out_count)
{
    struct supervisor_snapshot snap[SUPERVISOR_CAP];
    int n = supervisor_snapshot_all(snap, SUPERVISOR_CAP);
    int matches = 0;
    int found = -1;
    for (int i = 0; i < n; i++) {
        if (strcmp(snap[i].name, "chain.rolling_anchor") == 0) {
            if (out) *out = snap[i];
            matches++;
            found = i;
        }
    }
    if (out_count) *out_count = matches;
    return found;
}

int test_rolling_anchor_service(void)
{
    printf("\n=== rolling_anchor_service tests ===\n");
    int failures = 0;

    supervisor_reset_for_testing();
    rolling_anchor_reset_for_test();

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rolling_anchor", "supervisor");

    struct main_state ms;
    main_state_init(&ms);

    struct zcl_result r = rolling_anchor_start(&ms, dir);
    RA_CHECK("start returns ZCL_OK", r.ok);

    struct supervisor_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    int count = 0;
    int idx = find_rolling_anchor_snapshot(&snap, &count);
    RA_CHECK("registered exactly one supervisor child", idx >= 0 && count == 1);
    RA_CHECK("period is 60 seconds", snap.period_secs == 60);
    RA_CHECK("deadline stall gate is disabled", snap.deadline_secs == 0);

    int64_t expected_marker =
        (g_sha3_windows_count == 0)
            ? -1
            : (int64_t)g_sha3_windows_count * SHA3_WINDOW_SIZE - 1;
    RA_CHECK("progress marker starts at effective prefix end",
             snap.progress_marker == expected_marker);

    rolling_anchor_stop();
    idx = find_rolling_anchor_snapshot(&snap, &count);
    RA_CHECK("stop keeps one registered child", idx >= 0 && count == 1);
    RA_CHECK("stop disables the supervisor period", snap.period_secs == 0);

    r = rolling_anchor_start(&ms, dir);
    RA_CHECK("restart returns ZCL_OK", r.ok);
    idx = find_rolling_anchor_snapshot(&snap, &count);
    RA_CHECK("restart does not duplicate child", idx >= 0 && count == 1);
    RA_CHECK("restart restores 60 second period", snap.period_secs == 60);

    rolling_anchor_reset_for_test();
    idx = find_rolling_anchor_snapshot(&snap, &count);
    RA_CHECK("test reset unregisters child", idx < 0 && count == 0);

    /* The narrow commit hook executes the production durable transaction;
     * reload and corruption checks therefore cover the actual wire and I/O
     * path without constructing one thousand historical block bodies. */
    {
        char persist_dir[256];
        test_make_tmpdir(persist_dir, sizeof(persist_dir), "rolling_anchor",
                         "persistence");
        struct zcl_result initialized =
            rolling_anchor_init(persist_dir, NULL);
        RA_CHECK("persistence: initial empty load succeeds", initialized.ok);

        int32_t start = (int32_t)(g_sha3_windows_count * SHA3_WINDOW_SIZE);
        int32_t end = start + (int32_t)SHA3_WINDOW_SIZE - 1;
        uint8_t committed[32];
        for (size_t i = 0; i < sizeof(committed); i++)
            committed[i] = (uint8_t)(0x40u + i);
        struct zcl_result saved =
            rolling_anchor_test_commit_window(start, committed);
        RA_CHECK("persistence: production durable commit succeeds", saved.ok);

        char state_path[512];
        (void)snprintf(state_path, sizeof(state_path),
                       "%s/sha3_windows_runtime.dat", persist_dir);
        RA_CHECK("persistence: committed state exists",
                 !platform_private_path_absent(state_path));
        struct platform_directory_list files = {0};
        bool listed = platform_directory_list_regular_sorted(persist_dir,
                                                              &files);
        bool staging_found = false;
        for (size_t i = 0; listed && i < files.count; i++)
            if (strstr(files.entries[i].name,
                       "sha3_windows_runtime.dat.tmp.") ==
                files.entries[i].name)
                staging_found = true;
        RA_CHECK("persistence: successful commit leaves no staging file",
                 listed && !staging_found);
        platform_directory_list_free(&files);

        rolling_anchor_reset_for_test();
        struct zcl_result reloaded = rolling_anchor_init(persist_dir, NULL);
        uint8_t loaded[32] = {0};
        struct zcl_result found =
            rolling_anchor_window_hash_ending_at(end, loaded);
        RA_CHECK("persistence: reset/reload succeeds", reloaded.ok);
        RA_CHECK("persistence: reloaded window is exposed exactly",
                 found.ok && memcmp(loaded, committed, 32) == 0 &&
                     rolling_anchor_effective_prefix_end() == end);

        struct platform_private_file corrupt;
        platform_private_file_init(&corrupt);
        uint8_t bad_magic = 0;
        bool corrupted = platform_private_file_open_locked(state_path,
                                                            &corrupt) &&
                         platform_private_file_write_at(&corrupt, &bad_magic,
                                                        1, 0) &&
                         platform_private_file_flush(&corrupt);
        platform_private_file_close(&corrupt);
        RA_CHECK("persistence: fixture corruption is durable", corrupted);

        rolling_anchor_reset_for_test();
        struct zcl_result refused = rolling_anchor_init(persist_dir, NULL);
        memset(loaded, 0, sizeof(loaded));
        found = rolling_anchor_window_hash_ending_at(end, loaded);
        int32_t compile_end = start - 1;
        RA_CHECK("persistence: corrupt state is refused", !refused.ok);
        RA_CHECK("persistence: corrupt runtime window is never exposed",
                 !found.ok &&
                     rolling_anchor_effective_prefix_end() == compile_end);
        RA_CHECK("persistence: corrupt private state is removed",
                 platform_private_path_absent(state_path));

        rolling_anchor_reset_for_test();
#ifdef _WIN32
        char outside_path[512];
        (void)snprintf(outside_path, sizeof(outside_path),
                       "%s/rolling-anchor-outside.dat", persist_dir);
        struct platform_private_file outside;
        platform_private_file_init(&outside);
        uint8_t outside_byte = 0x7a;
        bool outside_ready = platform_private_file_create(outside_path,
                                                          &outside) &&
                             platform_private_file_write_at(
                                 &outside, &outside_byte, 1, 0) &&
                             platform_private_file_flush(&outside);
        platform_private_file_close(&outside);
        bool link_created = outside_ready &&
            CreateSymbolicLinkA(state_path, outside_path, 0) != 0;
        if (link_created) {
            struct zcl_result reparse_refused =
                rolling_anchor_init(persist_dir, NULL);
            DWORD attrs = GetFileAttributesA(state_path);
            RA_CHECK("persistence: reparse state is refused",
                     !reparse_refused.ok);
            RA_CHECK("persistence: refusal does not follow or delete reparse",
                     attrs != INVALID_FILE_ATTRIBUTES &&
                         (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0);
            rolling_anchor_reset_for_test();
            (void)DeleteFileA(state_path);
        }
        (void)platform_private_file_unlink_missing_ok(outside_path);
#endif
        test_cleanup_tmpdir(persist_dir);
    }

    /* rolling_anchor_window_hash_ending_at — success + one failure envelope
     * (E2 migration to struct zcl_result; no prior direct coverage). */
    {
        uint8_t out[32];
        if (g_sha3_windows_count > 0) {
            int32_t end_h = (int32_t)SHA3_WINDOW_SIZE - 1;
            memset(out, 0, sizeof(out));
            struct zcl_result r2 = rolling_anchor_window_hash_ending_at(end_h,
                                                                        out);
            RA_CHECK("window_hash_ending_at: compile-time window is ZCL_OK",
                     r2.ok);
            RA_CHECK("window_hash_ending_at: hash matches table entry",
                     memcmp(out, g_sha3_windows[0].hash, 32) == 0);
        }
        /* end_h=5 does not end any 1000-block window. */
        struct zcl_result bad =
            rolling_anchor_window_hash_ending_at(5, out);
        RA_CHECK("window_hash_ending_at: non-window-boundary end_h fails",
                 !bad.ok && bad.message[0] != '\0');
        struct zcl_result null_out =
            rolling_anchor_window_hash_ending_at(
                (int32_t)SHA3_WINDOW_SIZE - 1, NULL);
        RA_CHECK("window_hash_ending_at: NULL out is a named failure",
                 !null_out.ok && null_out.message[0] != '\0');
    }

    /* ── §4d row-8: sealed-domain read failure PAGES after N consecutive,
     *    exactly once, re-arms on success; above-prefix never pages ── */
    {
        event_log_init();
        event_clear_all_observers();
        atomic_store(&g_ra_pages, 0);
        event_observe(EV_OPERATOR_NEEDED, ra_page_observer, NULL);

        rolling_anchor_reset_for_test();
        /* effective prefix end = compile-time prefix end. */
        int prefix_end = rolling_anchor_effective_prefix_end();

        /* The first block after the prefix is unsealed window territory.
         * A sparse/snapshot datadir may not have that old body; that must
         * defer extension without becoming a sealed-read failure. */
        rolling_anchor_test_reset_read_failures();
        rolling_anchor_test_note_window_read_failure(
            prefix_end, prefix_end + 1, prefix_end + 1);
        RA_CHECK("missing next-window body is a skip, not read failure",
                 rolling_anchor_test_total_read_failures() == 0 &&
                 rolling_anchor_test_total_skipped_missing_body() == 1 &&
                 rolling_anchor_test_consecutive_read_failures() == 0);
        rolling_anchor_test_run_stall_escalation();
        RA_CHECK("missing next-window body does not page",
                 atomic_load(&g_ra_pages) == 0);

        /* Below prefix, 4 consecutive failures: NOT enough (threshold is 5). */
        rolling_anchor_test_reset_read_failures();
        for (int i = 0; i < 4; i++)
            rolling_anchor_test_inject_read_failure(prefix_end - 100);
        rolling_anchor_test_run_stall_escalation();
        RA_CHECK("4 consecutive below-prefix failures do NOT page",
                 atomic_load(&g_ra_pages) == 0);

        /* 5th failure crosses the threshold: pages exactly once. */
        rolling_anchor_test_inject_read_failure(prefix_end - 100);
        rolling_anchor_test_run_stall_escalation();
        RA_CHECK("5th below-prefix failure pages once",
                 atomic_load(&g_ra_pages) == 1);

        /* A subsequent stall while still latched does NOT re-page. */
        rolling_anchor_test_run_stall_escalation();
        RA_CHECK("latched: repeated stall does not re-page",
                 atomic_load(&g_ra_pages) == 1);

        /* A success resets consecutive + re-arms the latch. */
        rolling_anchor_test_reset_read_failures();
        atomic_store(&g_ra_pages, 0);

        /* ABOVE prefix: even 6 consecutive failures never page (window
         * territory — re-fetch is normal). */
        for (int i = 0; i < 6; i++)
            rolling_anchor_test_inject_read_failure(prefix_end + 5000);
        rolling_anchor_test_run_stall_escalation();
        RA_CHECK("above-prefix failures never page",
                 atomic_load(&g_ra_pages) == 0);

        event_clear_all_observers();
        rolling_anchor_reset_for_test();
    }

    /* ── B8: oracle divergence is evidence, never a gate ─────────────
     * A HALTED oracle_policy state (a co-located zclassicd that is merely
     * wrong or behind) must not block rolling-anchor extension — it must
     * only be recorded on the service's own observability surface. */
    {
        struct zcl_result r2 = rolling_anchor_start(&ms, dir);
        RA_CHECK("oracle-divergence setup: (re)start returns ZCL_OK", r2.ok);

        oracle_policy_reset_for_test();
        struct oracle_policy_config cfg = {
            .window_secs = 86400,
            .halt_distinct_heights = 3,
            .evidence_prefix_end_height = 1,
        };
        oracle_policy_init(&cfg);
        oracle_policy_record_disagreement(1000001, "a", "b");
        oracle_policy_record_disagreement(1000002, "a", "b");
        oracle_policy_record_disagreement(1000003, "a", "b");
        RA_CHECK("oracle policy reaches HALTED",
                 oracle_policy_get_state() == OP_HALTED);

        event_log_init();
        event_clear_all_observers();
        atomic_store(&g_ra_divergence_events, 0);
        event_observe(EV_SYNC_STATE_CHANGE, ra_divergence_observer, NULL);

        int64_t before = ra_dump_int("total_oracle_divergence_observed");
        int extended = rolling_anchor_extend_if_due(&ms, dir);

        RA_CHECK("HALTED oracle policy does not block extend_if_due "
                 "(no early-return gate)",
                 extended >= 0);
        RA_CHECK("HALTED oracle policy increments the divergence counter",
                 ra_dump_int("total_oracle_divergence_observed") > before);
        RA_CHECK("HALTED oracle policy still records a divergence event",
                 atomic_load(&g_ra_divergence_events) > 0);
        RA_CHECK("oracle_policy state is untouched by rolling_anchor "
                 "(evidence-only; extension never clears it)",
                 oracle_policy_get_state() == OP_HALTED);

        event_clear_all_observers();
        oracle_policy_reset_for_test();
        rolling_anchor_reset_for_test();
    }

    main_state_free(&ms);
    test_cleanup_tmpdir(dir);
    supervisor_reset_for_testing();
    return failures;
}
