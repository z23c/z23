/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_rom_fetch_controller — proves the ONE documented, discoverable
 * command an operator reads zcl.sync_benchmark.v1 phase timings from:
 * `ops.debug.rom_fetch.status` (engine/controllers/src/rom_fetch_controller.c,
 * zcl_native_handle_rom_fetch_status). The command already returned the
 * ROM-fetch engine's own state (rom_fetch_dump_state_json); this lane merged
 * in the sync-benchmark receipt under a "sync_benchmark" key so the same
 * typed command answers "how long did sync actually take" without an
 * operator hand-parsing <datadir>/sync_benchmark.json.
 *
 * This test drives the instrument directly (sync_benchmark_init/
 * phase_begin/phase_end/write_receipt) against a test_mkdtemp scratch dir —
 * never a real datadir — to synthesize a receipt with SOME phases stamped
 * and others deliberately left unwired, then calls the command handler and
 * asserts the reply's "sync_benchmark" object carries exactly that shape:
 * every stamped phase's elapsed_ms present and non-negative, and the two
 * phases this lane's design explicitly leaves unwired on the automatic path
 * (peer_discovery, manifest) reported as null with a reason — never a
 * fabricated number, never a silently missing field. */

#include "test/test_core.h"

#include "kernel/command_registry.h"
#include "controllers/diagnostics_internal.h"
#include "json/json.h"
#include "services/sync_benchmark_service.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

extern void zcl_native_handle_rom_fetch_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

static int case_status_merges_sync_benchmark_receipt(void)
{
    int failures = 0;
    TEST("ops.debug.rom_fetch.status: reply carries a full sync_benchmark receipt") {
        char datadir[PATH_MAX];
        ASSERT(test_mkdtemp(datadir, sizeof(datadir), "rfc_bench") != NULL);

        sync_benchmark_reset_for_test();
        sync_benchmark_init(datadir);
        sync_benchmark_set_artifact(
            "5340df085eda2edaba3fb53f39bedb51bcab6c1f1484a0929c7bc3b25ab747d");

        /* Stamp a representative subset of the eight phases — exactly the
         * ones this lane's design wires on the automatic boot path — and
         * leave PEER_DISCOVERY / MANIFEST / ARTIFACT_DOWNLOAD untouched
         * (those stay manual-command-only per the lane's documented gap). */
        sync_benchmark_phase_begin(SYNC_BENCH_HEADERS);
        sync_benchmark_phase_end(SYNC_BENCH_HEADERS);
        sync_benchmark_phase_begin(SYNC_BENCH_ARTIFACT_VERIFY);
        sync_benchmark_phase_end(SYNC_BENCH_ARTIFACT_VERIFY);
        sync_benchmark_phase_begin(SYNC_BENCH_INSTALL);
        sync_benchmark_phase_end(SYNC_BENCH_INSTALL);
        sync_benchmark_mark_ready();
        sync_benchmark_phase_begin(SYNC_BENCH_TAIL_DOWNLOAD);
        sync_benchmark_phase_end(SYNC_BENCH_TAIL_DOWNLOAD);
        sync_benchmark_phase_begin(SYNC_BENCH_TAIL_FOLD);
        sync_benchmark_phase_end(SYNC_BENCH_TAIL_FOLD);
        sync_benchmark_mark_sovereign();
        ASSERT(sync_benchmark_write_receipt(true, NULL));

        struct zcl_command_request request;
        memset(&request, 0, sizeof(request));
        request.invoked_name = "ops.debug.rom_fetch.status";
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.rom_fetch_status.v1");

        zcl_native_handle_rom_fetch_status(&request, &reply);

        const struct json_value *bench = json_get(&reply.data, "sync_benchmark");
        ASSERT(bench != NULL);
        ASSERT(json_get_bool(json_get(bench, "complete")));
        const struct json_value *timings = json_get(bench, "timings_ms");
        ASSERT(timings != NULL);

        static const char *const stamped[] = {
            "headers", "artifact_verify", "install",
            "tail_download", "tail_fold",
        };
        for (size_t i = 0; i < sizeof(stamped) / sizeof(stamped[0]); i++) {
            const struct json_value *v = json_get(timings, stamped[i]);
            ASSERT(v != NULL);
            ASSERT(!json_is_null(v));
            ASSERT(json_get_int(v) >= 0);
        }

        static const char *const unwired[] = {
            "peer_discovery", "manifest", "artifact_download",
        };
        const struct json_value *reasons = json_get(bench, "null_reasons");
        ASSERT(reasons != NULL);
        for (size_t i = 0; i < sizeof(unwired) / sizeof(unwired[0]); i++) {
            const struct json_value *v = json_get(timings, unwired[i]);
            ASSERT(v != NULL);
            ASSERT(json_is_null(v));
            const struct json_value *reason = json_get(reasons, unwired[i]);
            ASSERT(reason != NULL);
            const char *reason_str = json_get_str(reason);
            ASSERT(reason_str && reason_str[0]);
        }

        const struct json_value *t_ready = json_get(timings, "t_ready");
        const struct json_value *t_sovereign = json_get(timings, "t_sovereign");
        ASSERT(t_ready && !json_is_null(t_ready) && json_get_int(t_ready) >= 0);
        ASSERT(t_sovereign && !json_is_null(t_sovereign) &&
              json_get_int(t_sovereign) >= 0);

        /* The receipt landed durably too — the round trip this scratch
         * fixture is proving, not just the in-process dump. */
        char receipt_path[PATH_MAX + 32];
        snprintf(receipt_path, sizeof(receipt_path), "%s/sync_benchmark.json",
                 datadir);
        FILE *rf = fopen(receipt_path, "rb");
        ASSERT(rf != NULL);
        if (rf) fclose(rf);

        zcl_command_reply_free(&reply);
        sync_benchmark_reset_for_test();
    } _test_next:;
    return failures;
}

/* The rom_fetch engine's own fields still sit alongside the merged receipt —
 * this command remains ONE reply, not a replacement of the existing
 * artifact-fetch surface. */
static int case_status_still_reports_rom_fetch_state(void)
{
    int failures = 0;
    TEST("ops.debug.rom_fetch.status: rom_fetch fields and sync_benchmark coexist") {
        char datadir[PATH_MAX];
        ASSERT(test_mkdtemp(datadir, sizeof(datadir), "rfc_bench_coexist") != NULL);
        sync_benchmark_reset_for_test();
        sync_benchmark_init(datadir);

        struct zcl_command_request request;
        memset(&request, 0, sizeof(request));
        request.invoked_name = "ops.debug.rom_fetch.status";
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.rom_fetch_status.v1");

        zcl_native_handle_rom_fetch_status(&request, &reply);

        /* Never asserts the exact rom_fetch schema (owned elsewhere) —
         * only that the reply is still an object carrying BOTH surfaces. */
        ASSERT(reply.data.type == JSON_OBJ);
        ASSERT(json_get(&reply.data, "sync_benchmark") != NULL);
        ASSERT(json_size(&reply.data) >= 2);

        zcl_command_reply_free(&reply);
        sync_benchmark_reset_for_test();
    } _test_next:;
    return failures;
}

int test_rom_fetch_controller(void)
{
    printf("\n=== rom_fetch_controller ===\n");
    int failures = 0;
    failures += case_status_merges_sync_benchmark_receipt();
    failures += case_status_still_reports_rom_fetch_state();
    printf("=== rom_fetch_controller: %d failure(s) ===\n", failures);
    return failures;
}
