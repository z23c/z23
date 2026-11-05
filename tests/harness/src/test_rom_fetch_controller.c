/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_rom_fetch_controller: proves `ops.debug.rom_fetch.status`
 * (engine/controllers/src/rom_fetch_controller.c,
 * zcl_native_handle_rom_fetch_status) returns the ROM-fetch engine state plus
 * the sync-benchmark receipt under a "sync_benchmark" key.
 *
 * Drives the instrument directly against a test_mkdtemp scratch dir with some
 * phases stamped and others unwired, then asserts every stamped phase has a
 * non-negative elapsed_ms and the unwired peer_discovery / manifest phases
 * are null with a reason, never a fabricated number. */

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
#include <stdio.h>
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

        /* Stamp a representative subset of the eight phases and leave
         * PEER_DISCOVERY / MANIFEST / ARTIFACT_DOWNLOAD untouched (manual-command-only). */
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


/* ── mutation-gap tests: every refusal's structured body, the accepted
 * boundaries, and the exact success / failure reply fields ──────────────── */

struct rfc_refusal {
    const char *peer, *port, *root, *whole, *size, *filename;
    const char *code;
};

#define RFC_HEX_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define RFC_HEX_63 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define RFC_HEX_65 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define RFC_HEX_BADTAIL \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag"

static void rfc_push_nonempty(struct json_value *in, const char *k,
                              const char *v)
{
    if (v && v[0])
        (void)json_push_kv_str(in, k, v);
}

/* Runs the bundle handler on one refusal row; the reply must be the exact
 * parse-phase INVALID refusal: not retryable, nothing mutated. */
static bool rfc_refusal_ok(const struct rfc_refusal *r, const char *dir)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    rfc_push_nonempty(&input, "peer", r->peer);
    rfc_push_nonempty(&input, "port", r->port);
    rfc_push_nonempty(&input, "root", r->root);
    rfc_push_nonempty(&input, "whole_sha3", r->whole);
    rfc_push_nonempty(&input, "size", r->size);
    rfc_push_nonempty(&input, "filename", r->filename);
    (void)json_push_kv_str(&input, "out_dir", dir);
    struct zcl_command_request request;
    memset(&request, 0, sizeof(request));
    request.input = &input;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.rom_fetch_bundle.v1");
    zcl_native_handle_rom_fetch_bundle(&request, &reply);
    bool ok = reply.status == ZCL_COMMAND_STATUS_FAILED &&
              reply.exit_code == ZCL_COMMAND_EXIT_INVALID &&
              strcmp(reply.error.code, r->code) == 0 &&
              strcmp(reply.error.phase, "parse") == 0 &&
              !reply.error.retryable && !reply.error.mutated &&
              reply.error.message[0] != '\0';
    if (!ok)
        printf("[refusal %s got %s] ", r->code, reply.error.code);
    zcl_command_reply_free(&reply);
    json_free(&input);
    return ok;
}

static int case_bundle_refusals_are_exact(void)
{
    int failures = 0;
    TEST("ops.debug.rom_fetch.bundle: every parse refusal returns its own "
         "code, phase, INVALID exit, not retryable, not mutated") {
        rom_seed_reset();
        sync_benchmark_reset_for_test();
        char dir[PATH_MAX];
        ASSERT(test_mkdtemp(dir, sizeof(dir), "rfc_refuse") != NULL);
        char longname[ROM_FETCH_NAME_MAX + 1];
        memset(longname, 'n', sizeof(longname) - 1);
        longname[ROM_FETCH_NAME_MAX] = '\0';
        char longpeer[300];
        snprintf(longpeer, sizeof(longpeer), "%0150d,%0150d", 1, 2);
        const char *H = RFC_HEX_A;
        const char *P = "127.0.0.1";
        const char *Z = "8192";
        const struct rfc_refusal rows[] = {
            { "", "1", H, H, Z, "", "MISSING_PEER" },
            { P, "0", H, H, Z, "", "BAD_PORT" },
            { P, "65536", H, H, Z, "", "BAD_PORT" },
            { P, "-1", H, H, Z, "", "BAD_PORT" },
            { P, "abc", H, H, Z, "", "BAD_PORT" },
            { P, "80x", H, H, Z, "", "BAD_PORT" },
            { P, "1a", H, H, Z, "", "BAD_PORT" },
            { P, "1", "", H, Z, "", "BAD_ROOT" },
            { P, "1", RFC_HEX_63, H, Z, "", "BAD_ROOT" },
            { P, "1", RFC_HEX_65, H, Z, "", "BAD_ROOT" },
            { P, "1", RFC_HEX_BADTAIL, H, Z, "", "BAD_ROOT" },
            { P, "1", H, "", Z, "", "BAD_WHOLE_SHA3" },
            { P, "1", H, RFC_HEX_63, Z, "", "BAD_WHOLE_SHA3" },
            { P, "1", H, RFC_HEX_65, Z, "", "BAD_WHOLE_SHA3" },
            { P, "1", H, RFC_HEX_BADTAIL, Z, "", "BAD_WHOLE_SHA3" },
            { P, "1", H, H, "", "", "MISSING_SIZE" },
            { P, "1", H, H, "0", "", "BAD_SIZE" },
            { P, "1", H, H, "12x", "", "BAD_SIZE" },
            { P, "1", H, H, "abc", "", "BAD_SIZE" },
            { P, "1", H, H, "999999999999", "", "MANIFEST_NOT_SANE" },
            { P, "1", H, H, "34359738369", "", "MANIFEST_NOT_SANE" },
            { P, "1", H, H, Z, longname, "BAD_FILENAME" },
            { P, "1", H, H, Z, "a/b", "MANIFEST_NOT_SANE" },
            { P, "1", H, H, Z, "..", "MANIFEST_NOT_SANE" },
            { ",", "1", H, H, Z, "", "BAD_PEER_LIST" },
            { " , ", "1", H, H, Z, "", "BAD_PEER_LIST" },
            { longpeer, "1", H, H, Z, "", "BAD_PEER_LIST" },
        };
        for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            printf("[row %zu] ", i);
            ASSERT(rfc_refusal_ok(&rows[i], dir));
        }
        sync_benchmark_reset_for_test();
        rmdir(dir);
    } _test_next:;
    return failures;
}

static bool rfc_streq(const struct json_value *v, const char *want)
{
    const char *s = v ? json_get_str(v) : NULL;
    return s && strcmp(s, want) == 0;
}

/* The warm success body, field by field, for one planted artifact. */
static bool rfc_warm_body_ok(const struct json_value *d, const char *dir,
                             const char *name, const struct rom_artifact *a)
{
    char want_path[PATH_MAX], root_hex[65], bench[PATH_MAX];
    snprintf(want_path, sizeof(want_path), "%s/%s", dir, name);
    snprintf(bench, sizeof(bench), "%s/sync_benchmark.json", dir);
    HexStr(a->chunk_root, 32, false, root_hex, sizeof(root_hex));
    const char *next = json_get_str(json_get(d, "next"));
    return rfc_streq(json_get(d, "installed"), name) &&
           rfc_streq(json_get(d, "path"), want_path) &&
           rfc_streq(json_get(d, "chunk_root"), root_hex) &&
           rfc_streq(json_get(d, "benchmark_receipt"), bench) &&
           next && strstr(next, "-install-consensus-bundle") != NULL &&
           json_get_int(json_get(d, "size_bytes")) == (int64_t)a->size_bytes &&
           json_get_int(json_get(d, "num_chunks")) == (int64_t)a->num_chunks &&
           json_get_int(json_get(d, "chunks_verified")) ==
               (int64_t)a->num_chunks &&
           json_get_int(json_get(d, "chunks_reused_from_journal")) ==
               (int64_t)a->num_chunks &&
           json_get_int(json_get(d, "bytes_reused_from_journal")) ==
               (int64_t)a->size_bytes &&
           json_get_bool(json_get(d, "verified")) &&
           json_get_bool(json_get(d, "used_manifest_path")) &&
           json_get_bool(json_get(d, "warm_identical")) &&
           !json_get_bool(json_get(d, "fallback_used"));
}


/* Plants `size` bytes under `name`, optionally renames to the digest-derived
 * name, then runs a warm bundle request with the given port/filename input. */
static bool rfc_warm_run(const char *name, size_t size, const char *port,
                         bool omit_filename, uint32_t want_chunks)
{
    char dir[PATH_MAX];
    struct rom_artifact art;
    memset(&art, 0, sizeof(art));
    if (!test_mkdtemp(dir, sizeof(dir), "rfc_warm_x") ||
        !rfc_plant_bundle(dir, name, size, &art) ||
        art.num_chunks != want_chunks)
        return false;
    char use_name[ROM_FETCH_NAME_MAX];
    snprintf(use_name, sizeof(use_name), "%s", art.filename);
    char from[PATH_MAX], to[PATH_MAX];
    if (omit_filename) {
        char hex[17];
        HexStr(art.chunk_root, 8, false, hex, sizeof(hex));
        snprintf(use_name, sizeof(use_name), "rom-artifact-%s", hex);
        snprintf(from, sizeof(from), "%s/%s", dir, art.filename);
        snprintf(to, sizeof(to), "%s/%s", dir, use_name);
        if (rename(from, to) != 0)
            return false;
    }
    struct json_value input;
    rfc_bundle_request(&input, &art, "127.0.0.1", dir);
    json_set_str((struct json_value *)json_get(&input, "port"), port);
    if (omit_filename)
        json_set_str((struct json_value *)json_get(&input, "filename"), "");
    struct zcl_command_request request;
    memset(&request, 0, sizeof(request));
    request.input = &input;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.rom_fetch_bundle.v1");
    sync_benchmark_reset_for_test();
    zcl_native_handle_rom_fetch_bundle(&request, &reply);
    bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED &&
              rfc_warm_body_ok(&reply.data, dir, use_name, &art);
    zcl_command_reply_free(&reply);
    json_free(&input);
    snprintf(to, sizeof(to), "%s/%s", dir, use_name);
    unlink(to);
    snprintf(to, sizeof(to), "%s/sync_benchmark.json", dir);
    unlink(to);
    rmdir(dir);
    return ok;
}

static int case_bundle_warm_reply_fields(void)
{
    int failures = 0;
    TEST("ops.debug.rom_fetch.bundle: warm reply carries exact path, "
         "chunk counts, ports and derived filenames") {
        rom_seed_reset();
        const size_t chunk = ROM_SEED_CHUNK_SIZE;
        ASSERT(rfc_warm_run("consensus-state-bundle-w1.sqlite", 8192, "1",
                            false, 1));
        ASSERT(rfc_warm_run("consensus-state-bundle-w2.sqlite", 8192, "65535",
                            false, 1));
        ASSERT(rfc_warm_run("consensus-state-bundle-w3.sqlite", 8192, "99",
                            false, 1));
        ASSERT(rfc_warm_run("consensus-state-bundle-w4.sqlite", 8192, "",
                            false, 1));
        ASSERT(rfc_warm_run("consensus-state-bundle-w5.sqlite", chunk, "1",
                            false, 1));
        ASSERT(rfc_warm_run("consensus-state-bundle-w6.sqlite", chunk + 1, "1",
                            false, 2));
        /* No input.filename: the digest-derived name is the installed one. */
        ASSERT(rfc_warm_run("consensus-state-bundle-w7.sqlite", 8192, "1",
                            true, 1));
        rom_seed_reset();
        sync_benchmark_reset_for_test();
    } _test_next:;
    return failures;
}

/* A dead single peer on a cold directory: the exact ROM_FETCH_FAILED body
 * and the abort receipt left behind. */
static int case_bundle_fetch_failure_body(void)
{
    int failures = 0;
    TEST("ops.debug.rom_fetch.bundle: a dead peer yields the retryable "
         "execute-phase ROM_FETCH_FAILED body and an abort receipt") {
        rom_seed_reset();
        sync_benchmark_reset_for_test();
        char dir[PATH_MAX];
        ASSERT(test_mkdtemp(dir, sizeof(dir), "rfc_dead") != NULL);
        struct rom_artifact art;
        memset(&art, 0, sizeof(art));
        ASSERT(rfc_plant_bundle(dir, "consensus-state-bundle-dead.sqlite",
                                8192, &art));
        char src[PATH_MAX], gone[PATH_MAX];
        snprintf(src, sizeof(src), "%s/%s", dir, art.filename);
        snprintf(gone, sizeof(gone), "%s/moved-away.bin", dir);
        ASSERT(rename(src, gone) == 0);

        struct json_value input;
        rfc_bundle_request(&input, &art, "127.0.0.1", dir);
        struct zcl_command_request request;
        memset(&request, 0, sizeof(request));
        request.input = &input;
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.rom_fetch_bundle.v1");
        zcl_native_handle_rom_fetch_bundle(&request, &reply);

        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_FAILED);
        ASSERT(strcmp(reply.error.code, "ROM_FETCH_FAILED") == 0);
        ASSERT(strcmp(reply.error.phase, "execute") == 0);
        ASSERT(reply.error.retryable);
        ASSERT(!reply.error.mutated);
        ASSERT(strncmp(reply.error.message, "fetch from 127.0.0.1:1 failed: ",
                       31) == 0);
        ASSERT(reply.next_count == 1);
        ASSERT(strcmp(reply.next[0].command,
                      "ops.debug.rom_fetch.status") == 0);
        ASSERT(strcmp(reply.next[0].input_json, "{}") == 0);

        char rec[PATH_MAX];
        snprintf(rec, sizeof(rec), "%s/sync_benchmark.json", dir);
        FILE *f = fopen(rec, "r");
        ASSERT(f != NULL);
        char buf[8192] = {0};
        size_t got = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        ASSERT(got > 0);
        ASSERT(strstr(buf, "artifact_download_failed") != NULL);

        zcl_command_reply_free(&reply);
        json_free(&input);
        unlink(rec);
        unlink(gone);
        {
            char part[PATH_MAX], jrnl[PATH_MAX];
            snprintf(part, sizeof(part), "%s%s", src, ROM_FETCH_PART_SUFFIX);
            snprintf(jrnl, sizeof(jrnl), "%s.journal", part);
            unlink(part);
            unlink(jrnl);
        }
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
    failures += case_bundle_refusals_are_exact();
    failures += case_bundle_warm_reply_fields();
    failures += case_bundle_fetch_failure_body();
    printf("=== rom_fetch_controller: %d failure(s) ===\n", failures);
    return failures;
}
