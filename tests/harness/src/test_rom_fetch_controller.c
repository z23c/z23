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
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "net/rom_fetch.h"
#include "net/rom_seed.h"
#include "services/sync_benchmark_service.h"

#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern void zcl_native_handle_rom_fetch_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
extern void zcl_native_handle_rom_fetch_bundle(
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

/* Plant a one-chunk consensus bundle and register it so the serve-side
 * digests are the commitment the controller must reuse. */
static bool rfc_plant_bundle(const char *dir, const char *name, size_t size,
                             struct rom_artifact *art)
{
    uint8_t *content = malloc(size);
    if (!content)
        return false;
    static const uint8_t magic[16] = "SQLite format 3";
    for (size_t i = 0; i < size; i++)
        content[i] = (uint8_t)((i * 131u + 7u) & 0xffu);
    if (size >= 16)
        memcpy(content, magic, 16);
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        free(content);
        return false;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        free(content);
        return false;
    }
    size_t off = 0;
    bool ok = true;
    while (off < size) {
        ssize_t w = write(fd, content + off, size - off);
        if (w <= 0) {
            ok = false;
            break;
        }
        off += (size_t)w;
    }
    close(fd);
    free(content);
    if (!ok)
        return false;
    return rom_seed_register(dir, name, NULL, art) == ROM_REG_OK;
}

static void rfc_bundle_request(struct json_value *input,
                               const struct rom_artifact *art,
                               const char *peer, const char *out_dir)
{
    char root_hex[65], whole_hex[65], size_s[32];
    HexStr(art->chunk_root, 32, false, root_hex, sizeof(root_hex));
    HexStr(art->whole_sha3, 32, false, whole_hex, sizeof(whole_hex));
    snprintf(size_s, sizeof(size_s), "%llu",
             (unsigned long long)art->size_bytes);
    json_init(input);
    json_set_object(input);
    (void)json_push_kv_str(input, "peer", peer);
    (void)json_push_kv_str(input, "port", "1");
    (void)json_push_kv_str(input, "root", root_hex);
    (void)json_push_kv_str(input, "whole_sha3", whole_hex);
    (void)json_push_kv_str(input, "size", size_s);
    (void)json_push_kv_str(input, "filename", art->filename);
    (void)json_push_kv_str(input, "out_dir", out_dir);
}

/* Dead peers (port 1, nothing listening). Success is only possible when the
 * controller accepts the already-installed file and does not dial. */
static int case_warm_identical_moves_no_payload(void)
{
    int failures = 0;
    TEST("ops.debug.rom_fetch.bundle: an already-verified install is reused "
         "with zero downloaded bytes, even when every named peer is dead") {
        rom_seed_reset();
        sync_benchmark_reset_for_test();
        char dir[PATH_MAX];
        ASSERT(test_mkdtemp(dir, sizeof(dir), "rfc_warm") != NULL);
        struct rom_artifact art;
        memset(&art, 0, sizeof(art));
        ASSERT(rfc_plant_bundle(dir, "consensus-state-bundle-warm.sqlite",
                                8192, &art));
        ASSERT(art.num_chunks == 1);
        ASSERT(art.size_bytes == 8192);

        struct json_value input;
        rfc_bundle_request(&input, &art, "127.0.0.1,127.0.0.1", dir);
        struct zcl_command_request request;
        memset(&request, 0, sizeof(request));
        request.input = &input;
        request.invoked_name = "ops.debug.rom_fetch.bundle";
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.rom_fetch_bundle.v1");

        zcl_native_handle_rom_fetch_bundle(&request, &reply);

        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(&reply.data, "verified")));
        ASSERT(json_get_bool(json_get(&reply.data, "warm_identical")));
        ASSERT(!json_get_bool(json_get(&reply.data, "fallback_used")));
        ASSERT(json_get_int(json_get(&reply.data, "bytes_reused_from_journal"))
               == 8192);
        ASSERT(json_get_int(json_get(&reply.data, "chunks_reused_from_journal"))
               == 1);
        const char *installed = json_get_str(json_get(&reply.data, "installed"));
        ASSERT(installed && strcmp(installed, art.filename) == 0);

        struct zcl_command_reply status;
        zcl_command_reply_init(&status, "zcl.rom_fetch_status.v1");
        struct zcl_command_request status_req;
        memset(&status_req, 0, sizeof(status_req));
        status_req.invoked_name = "ops.debug.rom_fetch.status";
        zcl_native_handle_rom_fetch_status(&status_req, &status);
        const struct json_value *bench = json_get(&status.data, "sync_benchmark");
        ASSERT(bench != NULL);
        const struct json_value *res = json_get(bench, "resources");
        ASSERT(res != NULL);
        ASSERT(json_get_int(json_get(res, "bytes_downloaded")) == 0);
        ASSERT(json_get_int(json_get(res, "bytes_reused")) == 8192);
        const struct json_value *timings = json_get(bench, "timings_ms");
        ASSERT(timings != NULL);
        ASSERT(!json_is_null(json_get(timings, "manifest")));
        ASSERT(!json_is_null(json_get(timings, "artifact_download")));

        zcl_command_reply_free(&status);
        zcl_command_reply_free(&reply);
        json_free(&input);
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, art.filename);
        unlink(path);
        rmdir(dir);
        rom_seed_reset();
        sync_benchmark_reset_for_test();
    } _test_next:;
    return failures;
}

/* A file that is present but does not match the committed digest must not
 * be reported as a warm hit. The dead peer then fails the real download. */
static int case_mismatched_install_is_not_warm(void)
{
    int failures = 0;
    TEST("ops.debug.rom_fetch.bundle: a local file with the right name but "
         "the wrong bytes is not a warm hit") {
        rom_seed_reset();
        sync_benchmark_reset_for_test();
        char dir[PATH_MAX];
        ASSERT(test_mkdtemp(dir, sizeof(dir), "rfc_warm_bad") != NULL);
        struct rom_artifact art;
        memset(&art, 0, sizeof(art));
        const char *name = "consensus-state-bundle-warm-bad.sqlite";
        ASSERT(rfc_plant_bundle(dir, name, 8192, &art));

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, art.filename);
        int fd = open(path, O_RDWR);
        ASSERT(fd >= 0);
        ASSERT(lseek(fd, -1, SEEK_END) != (off_t)-1);
        uint8_t b = 0;
        ASSERT(read(fd, &b, 1) == 1);
        b ^= 0xff;
        ASSERT(lseek(fd, -1, SEEK_END) != (off_t)-1);
        ASSERT(write(fd, &b, 1) == 1);
        close(fd);

        struct json_value input;
        rfc_bundle_request(&input, &art, "127.0.0.1", dir);
        struct zcl_command_request request;
        memset(&request, 0, sizeof(request));
        request.input = &input;
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.rom_fetch_bundle.v1");

        zcl_native_handle_rom_fetch_bundle(&request, &reply);

        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(reply.error.code, "ROM_FETCH_FAILED") == 0);

        zcl_command_reply_free(&reply);
        json_free(&input);
        unlink(path);
        char part[PATH_MAX];
        snprintf(part, sizeof(part), "%s%s", path, ROM_FETCH_PART_SUFFIX);
        unlink(part);
        char jrnl[PATH_MAX];
        snprintf(jrnl, sizeof(jrnl), "%s.journal", part);
        unlink(jrnl);
        rmdir(dir);
        rom_seed_reset();
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
    failures += case_warm_identical_moves_no_payload();
    failures += case_mismatched_install_is_not_warm();
    printf("=== rom_fetch_controller: %d failure(s) ===\n", failures);
    return failures;
}
