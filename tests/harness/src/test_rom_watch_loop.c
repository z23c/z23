/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Focused test for the ops.rom watch driver (tools/command/rom_watch_loop.c)
 * and the read-only offline composer (tools/command/rom_compile_offline.c):
 *   1. rom_watch_run with an INJECTED fetch — three synthetic bodies at
 *      max_iters=3 render three frames and exit 0; a fetch error renders one
 *      diagnostic line and the loop keeps going (does not abort).
 *   2. rom_compile_offline_compose against a hermetic fixture datadir — a
 *      well-formed mint-progress.log parses the eight stage EWMAs + bottleneck;
 *      a malformed/absent log yields zeroed EWMAs and never an error; an
 *      absent segments store renders sealed_history absent; node-only layers
 *      are absent with a note.
 *
 * Each case is its own static function (the shared ASSERT() macro hardcodes
 * `goto _test_next`, so one label per function). */

#include "test/test_core.h"

#include "command/rom_watch_loop.h"
#include "command/rom_compile_offline.h"
#include "command/rom_compile_render.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── watch loop: injected fetch ──────────────────────────────────────── */

struct fake_fetch_ctx {
    int calls;
    bool fail;
};

/* Build a minimal-but-valid zcl.rom_compile.v1 body so the renderer emits its
 * "ROM compile" header line on every successful frame. */
static bool fake_fetch_ok(void *vctx, struct json_value *out, char *err,
                          size_t errlen)
{
    (void)err;
    (void)errlen;
    struct fake_fetch_ctx *c = (struct fake_fetch_ctx *)vctx;
    c->calls++;
    json_set_object(out);
    json_push_kv_str(out, "schema", "zcl.rom_compile.v1");
    struct json_value fold;
    json_init(&fold);
    json_set_object(&fold);
    json_push_kv_bool(&fold, "active", true);
    json_push_kv_str(&fold, "mode", "from_genesis");
    json_push_kv_int(&fold, "height", 1000000 + c->calls);
    json_push_kv_int(&fold, "target", 3056758);
    json_push_kv_real(&fold, "percent", 32.5);
    json_push_kv_int(&fold, "remaining_blocks", 2000000);
    json_push_kv_real(&fold, "rate_blk_s", 10.0);
    json_push_kv_int(&fold, "eta_seconds", 100);
    json_push_kv_str(&fold, "eta_human", "0h01m40s");
    json_push_kv(out, "fold", &fold);
    json_free(&fold);
    return true;
}

static bool fake_fetch_fail(void *vctx, struct json_value *out, char *err,
                            size_t errlen)
{
    (void)out;
    struct fake_fetch_ctx *c = (struct fake_fetch_ctx *)vctx;
    c->calls++;
    (void)snprintf(err, errlen, "synthetic boom");
    return false;
}

/* Count non-overlapping occurrences of `needle` in `hay`. */
static int count_occurrences(const char *hay, const char *needle)
{
    int n = 0;
    size_t nl = strlen(needle);
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += nl)
        n++;
    return n;
}

/* Drain a rewindable FILE* into a heap buffer the caller frees. */
static char *slurp_stream(FILE *f)
{
    fflush(f);
    long sz = ftell(f);
    if (sz < 0)
        return NULL;
    rewind(f);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf)
        return NULL;
    size_t got = fread(buf, 1, (size_t)sz, f);
    buf[got] = '\0';
    return buf;
}

static int test_rom_watch_three_frames(void)
{
    int failures = 0;

    TEST("rom watch: max_iters=3 renders three frames and exits 0") {
        FILE *f = tmpfile();
        ASSERT(f != NULL);
        struct fake_fetch_ctx ctx = { 0, false };
        struct rom_watch_opts opts = {
            .interval_ms = 500, .max_iters = 3, .ansi = false, .stream = f };
        int rc = rom_watch_run(fake_fetch_ok, &ctx, &opts);
        ASSERT_EQ(rc, 0);
        ASSERT_EQ(ctx.calls, 3);
        char *out = slurp_stream(f);
        ASSERT(out != NULL);
        ASSERT_EQ(count_occurrences(out, "ROM compile"), 3);
        free(out);
        fclose(f);
        PASS();
    } _test_next:;

    return failures;
}

static int test_rom_watch_fetch_error_continues(void)
{
    int failures = 0;

    TEST("rom watch: a fetch error renders a diagnostic and does not abort") {
        FILE *f = tmpfile();
        ASSERT(f != NULL);
        struct fake_fetch_ctx ctx = { 0, true };
        struct rom_watch_opts opts = {
            .interval_ms = 500, .max_iters = 2, .ansi = false, .stream = f };
        int rc = rom_watch_run(fake_fetch_fail, &ctx, &opts);
        ASSERT_EQ(rc, 0);
        /* Both iterations ran (the error did not break the loop). */
        ASSERT_EQ(ctx.calls, 2);
        char *out = slurp_stream(f);
        ASSERT(out != NULL);
        ASSERT(strstr(out, "fetch failed: synthetic boom") != NULL);
        ASSERT_EQ(count_occurrences(out, "fetch failed"), 2);
        free(out);
        fclose(f);
        PASS();
    } _test_next:;

    return failures;
}

static int test_rom_watch_null_args(void)
{
    int failures = 0;

    TEST("rom watch: NULL fetch/opts is a non-zero invalid-usage return") {
        ASSERT(rom_watch_run(NULL, NULL, NULL) != 0);
        struct rom_watch_opts opts = { .max_iters = 1 };
        ASSERT(rom_watch_run(NULL, NULL, &opts) != 0);
        PASS();
    } _test_next:;

    return failures;
}

static bool stop_after_first_frame(void *opaque)
{
    int *polls = (int *)opaque;
    *polls += 1;
    return *polls >= 2;
}

static int test_rom_watch_stop_callback(void)
{
    int failures = 0;

    TEST("rom watch: headless stop callback exits after the current frame") {
        FILE *f = tmpfile();
        ASSERT(f != NULL);
        struct fake_fetch_ctx ctx = { 0, false };
        int stop_polls = 0;
        struct rom_watch_opts opts = {
            .interval_ms = 500,
            .stream = f,
            .stop = stop_after_first_frame,
            .stop_ctx = &stop_polls
        };
        int rc = rom_watch_run(fake_fetch_ok, &ctx, &opts);
        ASSERT_EQ(rc, 0);
        ASSERT_EQ(ctx.calls, 1);
        ASSERT_EQ(stop_polls, 2);
        fclose(f);
        PASS();
    } _test_next:;

    return failures;
}

/* ── offline composer ────────────────────────────────────────────────── */

static bool write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    fputs(content, f);
    fclose(f);
    return true;
}

static int test_rom_offline_wellformed_log(void)
{
    int failures = 0;

    TEST("rom offline: a well-formed mint-progress.log parses the eight "
         "stage EWMAs and the bottleneck") {
        char tmpl[] = "/tmp/zcl_romoff_XXXXXX";
        char *dir = mkdtemp(tmpl);
        ASSERT(dir != NULL);

        char logpath[512];
        (void)snprintf(logpath, sizeof(logpath), "%s/mint-progress.log", dir);
        ASSERT(write_file(
            logpath,
            "mint height=900000 / 3056758 rate=20.0 blk/s eta=1:00:00 "
            "elapsed=50s slow=sv:900us cm:1400us pvla=10/2 "
            "stages=[ha:5us vh:12us bf:40us bp:90us sv:900us pv:800us "
            "ua:150us tf:8us]\n"
            "mint height=1000000 / 3056758 rate=25.0 blk/s eta=0:45:00 "
            "elapsed=100s slow=sv:900us cm:1400us pvla=20/3 "
            "stages=[ha:6us vh:13us bf:41us bp:91us sv:901us pv:801us "
            "ua:151us tf:9us]\n"));

        struct json_value body;
        json_init(&body);
        char err[256];
        err[0] = '\0';
        bool ok = rom_compile_offline_compose(dir, &body, err, sizeof(err));
        ASSERT(ok);
        ASSERT(body.type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(&body, "schema")),
                     "zcl.rom_compile.v1");

        /* Stage EWMAs come from the LAST line. */
        const struct json_value *stages = json_get(&body, "stages");
        ASSERT(stages && stages->type == JSON_ARR);
        ASSERT_EQ(stages->num_children, (size_t)8);
        ASSERT_EQ(json_get_int(json_get(json_at(stages, 0), "step_us_ewma")),
                 (int64_t)6);
        ASSERT_EQ(json_get_int(json_get(json_at(stages, 4), "step_us_ewma")),
                 (int64_t)901);
        ASSERT_STR_EQ(json_get_str(json_get(&body, "bottleneck_stage")), "sv");
        ASSERT_EQ(json_get_int(json_get(&body, "commit_us_ewma")),
                 (int64_t)1400);

        /* No segments dir was created — sealed_history is absent, gracefully. */
        const struct json_value *layers = json_get(&body, "layers");
        ASSERT(layers && layers->type == JSON_OBJ);
        ASSERT(!json_get_bool(
            json_get(json_get(layers, "sealed_history"), "present")));
        /* ROM checkpoint is compiled in — present even offline. */
        ASSERT(json_get_bool(
            json_get(json_get(layers, "rom_checkpoint"), "present")));
        /* Node-only layers are absent with a note. */
        const struct json_value *bx = json_get(layers, "bundle_export");
        ASSERT(bx && !json_get_bool(json_get(bx, "present")));
        ASSERT(json_get_str(json_get(bx, "note")) != NULL);

        /* The renderer draws it without crashing. */
        char text[8192];
        rom_compile_render_ascii(&body, text, sizeof(text));
        ASSERT(strstr(text, "ROM pipeline") != NULL);

        json_free(&body);
        (void)unlink(logpath);
        (void)rmdir(dir);
        PASS();
    } _test_next:;

    return failures;
}

static int test_rom_offline_malformed_log(void)
{
    int failures = 0;

    TEST("rom offline: a malformed/absent log yields zeroed EWMAs, never an "
         "error") {
        char tmpl[] = "/tmp/zcl_romoff_XXXXXX";
        char *dir = mkdtemp(tmpl);
        ASSERT(dir != NULL);

        char logpath[512];
        (void)snprintf(logpath, sizeof(logpath), "%s/mint-progress.log", dir);
        ASSERT(write_file(logpath, "not a real progress line at all\n"));

        struct json_value body;
        json_init(&body);
        char err[256];
        err[0] = '\0';
        bool ok = rom_compile_offline_compose(dir, &body, err, sizeof(err));
        ASSERT(ok);
        const struct json_value *stages = json_get(&body, "stages");
        ASSERT(stages && stages->num_children == (size_t)8);
        for (size_t i = 0; i < 8; i++)
            ASSERT_EQ(json_get_int(json_get(json_at(stages, i),
                                            "step_us_ewma")), (int64_t)0);
        json_free(&body);
        (void)unlink(logpath);

        /* Absent log entirely — still a clean, complete body. */
        struct json_value body2;
        json_init(&body2);
        ok = rom_compile_offline_compose(dir, &body2, err, sizeof(err));
        ASSERT(ok);
        ASSERT(json_get(&body2, "fold") != NULL);
        json_free(&body2);

        (void)rmdir(dir);
        PASS();
    } _test_next:;

    return failures;
}

static int test_rom_offline_rejects_empty_datadir(void)
{
    int failures = 0;

    TEST("rom offline: empty datadir is a hard error with a reason") {
        struct json_value body;
        json_init(&body);
        char err[256];
        err[0] = '\0';
        bool ok = rom_compile_offline_compose("", &body, err, sizeof(err));
        ASSERT(!ok);
        ASSERT(err[0] != '\0');
        json_free(&body);
        PASS();
    } _test_next:;

    return failures;
}

int test_rom_watch_loop(void)
{
    int failures = 0;
    failures += test_rom_watch_three_frames();
    failures += test_rom_watch_fetch_error_continues();
    failures += test_rom_watch_null_args();
    failures += test_rom_watch_stop_callback();
    failures += test_rom_offline_wellformed_log();
    failures += test_rom_offline_malformed_log();
    failures += test_rom_offline_rejects_empty_datadir();
    return failures;
}
