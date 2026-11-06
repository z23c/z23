/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_app_playtest_session — the scripted playtest driver
 * (command/app_playtest_session.h) against the v=1 STUB CHILD
 * (tests/harness/fixtures/app_playtest_stub_child.c), so no raylib and no
 * display are needed.
 *
 *   1. Frames: observe, step 60, step 60 report frames 0, 60 and 120
 *      exactly, under the caller's labels, with the capture digest, a
 *      bounded trace, a display-only child environment and a reaped child.
 *   2. Hang: the child parks (with a helper in its group) on the first step:
 *      PLAYTEST_TIMEOUT, the child is reaped and its process group is empty.
 *   3. Huge: a 13 MiB reply frame is REPLY_TOO_LARGE, and the child reaped.
 *   4. Duplicate step ids are refused before spawn (the image path does not
 *      even exist, so any later stage would name a different refusal).
 *   5. An image edited in place, and a wrong digest, are IMAGE_HASH_MISMATCH
 *      with no process.
 *   6. The display environment builder passes the allowlist and nothing else.
 *
 * Fixture files live under ./test-tmp/. */

#include "test/test_core.h"

#include "base/hex.h"
#include "command/app_playtest_session.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/prctl.h>
#include <sys/wait.h>
#endif

#define APS_STUB "build/fixtures/aps_stub"
#define APS_STUB_HANG "build/fixtures/aps_stub_hang"
#define APS_STUB_HUGE "build/fixtures/aps_stub_huge"
#define APS_TMP "test-tmp/app_playtest_session"

static bool aps_file_sha3(const char *path, char hex[RESIDENT_LAUNCH_DIGEST_HEX + 1u])
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    unsigned char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha3_256_write(&sha, buf, n);
    bool ok = !ferror(f);
    if (fclose(f) != 0)
        ok = false;
    unsigned char digest[32];
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof(digest), hex);
    return ok;
}

static void aps_bytes_sha3(const void *bytes, size_t n,
                           char hex[RESIDENT_LAUNCH_DIGEST_HEX + 1u])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, bytes, n);
    unsigned char digest[32];
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof(digest), hex);
}

static struct app_playtest_step aps_step(uint32_t id, uint32_t frames, bool capture)
{
    struct app_playtest_step s = {.id = id, .capture = capture};
    s.op = frames ? APP_PLAYTEST_STEP : APP_PLAYTEST_OBSERVE;
    s.frames = frames;
    s.input.move_x = 0.5f;
    s.input.throttle = true;
    return s;
}

static struct app_playtest_result *aps_result(void)
{
    return calloc(1, sizeof(struct app_playtest_result));
}

#if defined(__linux__)
/* The child (and group leader) is gone: no longer our child, and no member
 * of its process group survives. A helper orphaned by the group kill is
 * reparented to a subreaper (us, if we are one) and reaped there. */
static bool aps_group_gone(uint64_t pid)
{
    if (!pid)
        return false;
    int status;
    if (waitpid((pid_t)pid, &status, WNOHANG) != -1 || errno != ECHILD)
        return false;
    int subreaper = 0;
    (void)prctl(PR_GET_CHILD_SUBREAPER, &subreaper);
    for (int i = 0; i < 300; i++) {
        if (subreaper)
            (void)waitpid(-(pid_t)pid, &status, WNOHANG);
        if (kill(-(pid_t)pid, 0) != 0 && errno == ESRCH)
            return true;
        struct timespec nap = {0, 10 * 1000 * 1000};
        nanosleep(&nap, NULL);
    }
    return false;
}

static bool aps_run(const char *image, const struct app_playtest_step *steps,
                    size_t n, uint32_t timeout_ms, struct app_playtest_result *out)
{
    char sha3[RESIDENT_LAUNCH_DIGEST_HEX + 1u];
    if (!aps_file_sha3(image, sha3))
        return false;
    struct app_playtest_request request = {
        .image_path = image, .image_sha3_hex = sha3, .steps = steps,
        .n_steps = n, .seed = 7, .step_timeout_ms = timeout_ms};
    (void)app_playtest_run(&request, out);
    return true;
}

static int test_aps_frames(void)
{
    int failures = 0;
    struct app_playtest_result *out = aps_result();
    TEST("app_playtest_session: frames 0, 60, 120 under the caller's labels") {
        ASSERT(out);
        struct app_playtest_step steps[] = {
            aps_step(10, 0, true), aps_step(20, 60, false), aps_step(30, 60, true)};
        /* A leaked environment makes the stub exit before READY. */
        ASSERT(setenv("APS_PLAYTEST_CANARY", "secret", 1) == 0);
        bool ran = aps_run(APS_STUB, steps, 3, 5000, out);
        (void)unsetenv("APS_PLAYTEST_CANARY");
        ASSERT(ran);
        if (out->code != APP_PLAYTEST_OK)
            printf("[%s: %s] ", app_playtest_code_name(out->code), out->error);
        ASSERT_EQ(out->code, APP_PLAYTEST_OK);
        ASSERT_STR_EQ(app_playtest_code_name(out->code), "OK");
        ASSERT(out->spawned);
        ASSERT(out->pid != 0);
        ASSERT_EQ(out->n_steps, (size_t)3);
        ASSERT_EQ(out->steps[0].frame, 0u);
        ASSERT_EQ(out->steps[1].frame, 60u);
        ASSERT_EQ(out->steps[2].frame, 120u);
        ASSERT_EQ(out->steps[0].id, 10u);
        ASSERT_EQ(out->steps[1].id, 20u);
        ASSERT_EQ(out->steps[2].id, 30u);
        ASSERT_EQ(out->steps[0].wire_id, 1u);
        ASSERT_EQ(out->steps[2].wire_id, 3u);
        ASSERT(out->steps[2].ok);
        ASSERT(out->steps[2].time == 2.0);
        ASSERT(out->steps[2].player_present);
        ASSERT(out->steps[2].y == 120.0);
        char abc[RESIDENT_LAUNCH_DIGEST_HEX + 1u];
        aps_bytes_sha3("abc", 3, abc);
        ASSERT(out->steps[0].capture.present);
        ASSERT_STR_EQ(out->steps[0].capture.sha3_hex, abc);
        ASSERT_EQ(out->steps[0].capture.bytes, (size_t)3);
        ASSERT(!out->steps[1].capture.present);
        ASSERT(out->steps[2].capture.present);
        ASSERT(out->trace_len > 0 && out->trace_len <= APP_PLAYTEST_TRACE_MAX);
        ASSERT_EQ(strlen(out->trace), out->trace_len);
        ASSERT(!out->trace_truncated);
        ASSERT(strstr(out->trace, "\"frame\":120") != NULL);
        ASSERT(strstr(out->trace, abc) != NULL);
        ASSERT(aps_group_gone(out->pid));
        PASS();
    } _test_next:;
    if (out)
        app_playtest_result_free(out);
    free(out);
    return failures;
}

static int test_aps_hang(void)
{
    int failures = 0;
    struct app_playtest_result *out = aps_result();
    struct app_playtest_step steps[] = {aps_step(1, 0, false), aps_step(2, 60, false)};
    TEST("app_playtest_session: a hung child is PLAYTEST_TIMEOUT, group reaped") {
        ASSERT(out);
        ASSERT(aps_run(APS_STUB_HANG, steps, 2, 400, out));
        ASSERT_STR_EQ(app_playtest_code_name(out->code), "PLAYTEST_TIMEOUT");
        ASSERT_EQ(out->n_steps, (size_t)1);
        ASSERT_EQ(out->steps[0].frame, 0u);
        ASSERT(out->spawned);
        ASSERT(aps_group_gone(out->pid));
        PASS();
    } _test_next:;
    if (out)
        app_playtest_result_free(out);
    free(out);
    return failures;
}

static int test_aps_huge(void)
{
    int failures = 0;
    struct app_playtest_result *out = aps_result();
    struct app_playtest_step steps[] = {aps_step(1, 0, false), aps_step(2, 60, false)};
    TEST("app_playtest_session: a 13 MiB reply is REPLY_TOO_LARGE") {
        ASSERT(out);
        ASSERT(aps_run(APS_STUB_HUGE, steps, 2, 5000, out));
        ASSERT_STR_EQ(app_playtest_code_name(out->code), "REPLY_TOO_LARGE");
        ASSERT_EQ(out->n_steps, (size_t)1);
        ASSERT(aps_group_gone(out->pid));
        PASS();
    } _test_next:;
    if (out)
        app_playtest_result_free(out);
    free(out);
    return failures;
}

static bool aps_copy(const char *from, const char *to)
{
    FILE *in = fopen(from, "rb"), *o = in ? fopen(to, "wb") : NULL;
    bool ok = in && o;
    unsigned char buf[65536];
    size_t n;
    while (ok && (n = fread(buf, 1, sizeof(buf), in)) > 0)
        ok = fwrite(buf, 1, n, o) == n;
    if (in && (ferror(in) || fclose(in) != 0))
        ok = false;
    if (o && fclose(o) != 0)
        ok = false;
    return ok && chmod(to, 0755) == 0;
}

/* Flip one byte in place: same inode, same size, different bytes. */
static bool aps_flip(const char *path)
{
    FILE *f = fopen(path, "r+b");
    if (!f)
        return false;
    bool ok = fseek(f, -1, SEEK_END) == 0;
    int c = ok ? fgetc(f) : EOF;
    ok = c != EOF && fseek(f, -1, SEEK_END) == 0 && fputc(c ^ 0x5a, f) != EOF;
    return fclose(f) == 0 && ok;
}

static int test_aps_image(void)
{
    int failures = 0;
    struct app_playtest_result *out = aps_result();
    struct app_playtest_step steps[] = {aps_step(1, 0, false)};
    char edited[] = APS_TMP "/edited";
    TEST("app_playtest_session: an edited image is IMAGE_HASH_MISMATCH, no spawn") {
        ASSERT(out);
        test_rm_rf(APS_TMP);
        ASSERT(mkdir("test-tmp", 0755) == 0 || errno == EEXIST);
        ASSERT(mkdir(APS_TMP, 0755) == 0);
        ASSERT(aps_copy(APS_STUB, edited));
        char sha3[RESIDENT_LAUNCH_DIGEST_HEX + 1u];
        ASSERT(aps_file_sha3(edited, sha3));
        ASSERT(aps_flip(edited));
        struct app_playtest_request request = {
            .image_path = edited, .image_sha3_hex = sha3, .steps = steps,
            .n_steps = 1, .step_timeout_ms = 2000};
        ASSERT(!app_playtest_run(&request, out));
        ASSERT_STR_EQ(app_playtest_code_name(out->code), "IMAGE_HASH_MISMATCH");
        ASSERT(!out->spawned);
        ASSERT_EQ(out->pid, (uint64_t)0);
        app_playtest_result_free(out);
        /* The unedited stub under a digest that is not its own. */
        sha3[0] = sha3[0] == '0' ? '1' : '0';
        request.image_path = APS_STUB;
        ASSERT(!app_playtest_run(&request, out));
        ASSERT_STR_EQ(app_playtest_code_name(out->code), "IMAGE_HASH_MISMATCH");
        ASSERT_EQ(out->pid, (uint64_t)0);
        PASS();
    } _test_next:;
    if (out)
        app_playtest_result_free(out);
    free(out);
    test_rm_rf(APS_TMP);
    return failures;
}
#endif

static int test_aps_duplicate(void)
{
    int failures = 0;
    struct app_playtest_result *out = aps_result();
    TEST("app_playtest_session: duplicate step ids are refused before spawn") {
        ASSERT(out);
        struct app_playtest_step steps[] = {
            aps_step(5, 0, false), aps_step(6, 60, false), aps_step(5, 60, false)};
        struct app_playtest_request request = {
            .image_path = APS_TMP "/does-not-exist",
            .image_sha3_hex =
                "0000000000000000000000000000000000000000000000000000000000000000",
            .steps = steps, .n_steps = 3};
        ASSERT(!app_playtest_run(&request, out));
        ASSERT_STR_EQ(app_playtest_code_name(out->code), "DUPLICATE_STEP_ID");
        ASSERT(!out->spawned);
        ASSERT_EQ(out->pid, (uint64_t)0);
        ASSERT_EQ(out->n_steps, (size_t)0);
        ASSERT(strstr(out->error, "5") != NULL);
        PASS();
    } _test_next:;
    if (out)
        app_playtest_result_free(out);
    free(out);
    return failures;
}

#if !defined(_WIN32)
static int test_aps_env(void)
{
    int failures = 0;
    TEST("app_playtest_session: the child environment is the display allowlist") {
        char *saved = getenv("DISPLAY");
        char keep[256] = {0};
        bool had = saved && strlen(saved) < sizeof(keep);
        if (had)
            (void)snprintf(keep, sizeof(keep), "%s", saved);
        ASSERT(setenv("DISPLAY", ":77", 1) == 0);
        ASSERT(setenv("APS_PLAYTEST_CANARY", "secret", 1) == 0);
        char *env[APP_PLAYTEST_ENV_MAX + 1u];
        size_t n = app_playtest_display_env(env);
        bool display = false, leaked = false;
        for (size_t i = 0; i < n; i++) {
            if (strcmp(env[i], "DISPLAY=:77") == 0)
                display = true;
            if (strncmp(env[i], "APS_PLAYTEST_CANARY=", 20) == 0 ||
                strncmp(env[i], "HOME=", 5) == 0 || strncmp(env[i], "PATH=", 5) == 0)
                leaked = true;
        }
        (void)unsetenv("APS_PLAYTEST_CANARY");
        if (had)
            (void)setenv("DISPLAY", keep, 1);
        else
            (void)unsetenv("DISPLAY");
        ASSERT(n >= 1 && n <= APP_PLAYTEST_ENV_MAX);
        ASSERT(env[n] == NULL);
        ASSERT(display);
        ASSERT(!leaked);
        PASS();
    } _test_next:;
    return failures;
}
#endif

int test_app_playtest_session(void)
{
    int failures = 0;
    failures += test_aps_duplicate();
#if !defined(_WIN32)
    failures += test_aps_env();
#endif
#if defined(__linux__)
    failures += test_aps_frames();
    failures += test_aps_hang();
    failures += test_aps_huge();
    failures += test_aps_image();
#endif
    return failures;
}
