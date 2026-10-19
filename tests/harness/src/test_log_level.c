/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the opt-in log-level filter (platform/modules/base/src/log_level.c,
 * consulted by ZCL_LOG_EMIT_AT) and the ERROR-rank origin= stamp added by
 * platform/modules/util/include/util/log_macros.h.
 *
 * Coverage:
 *   - level ordering: ALL/INFO < WARN < ERROR < FATAL < OFF
 *   - zcl_log_level_from_string(): all six recognized tokens round-trip;
 *     unrecognized input is rejected (false, *out untouched)
 *   - default level is ZCL_LOG_ALL (== ZCL_LOG_INFO): every LOG_* macro
 *     emits with zero configuration
 *   - a level below the floor is suppressed; a level at/above the floor
 *     emits — exercised through the real LOG_WARN/LOG_INFO macros (not a
 *     reimplementation), captured via the stderr-redirect pattern used by
 *     test_coinbase_subsidy_adversarial.c's csa_mint_capture().
 *   - setting OFF suppresses even the highest structural level exercised
 *     here (WARN).
 */

#include "test/test_core.h"
#include "util/log_level.h"
#include "util/log_macros.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define LVL_CHECK(name, expr) do { \
    printf("log_level: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Mirrors csa_mint_capture() in test_coinbase_subsidy_adversarial.c: redirect
 * stderr to a scratch file for the duration of `fn`, then hand back what
 * landed. On plumbing failure it still runs `fn` uncaptured; callers treat an
 * empty capture as a real FAIL. */
static bool log_level_capture(void (*fn)(void), char *out, size_t out_len)
{
    if (out && out_len > 0)
        out[0] = '\0';

    mkdir("./test-tmp", 0755);
    char path[256];
    snprintf(path, sizeof(path), "./test-tmp/log_level_test_stderr_%d.log",
              (int)getpid());

    fflush(stderr);
    int saved_fd = dup(STDERR_FILENO);
    FILE *capf = (saved_fd >= 0) ? fopen(path, "w+") : NULL;
    if (!capf) {
        if (saved_fd >= 0)
            close(saved_fd);
        return false;
    }
    dup2(fileno(capf), STDERR_FILENO);

    fn();

    fflush(stderr);
    dup2(saved_fd, STDERR_FILENO);
    close(saved_fd);

    if (out && out_len > 0) {
        long sz = ftell(capf);
        if (sz > 0) {
            rewind(capf);
            size_t want = (size_t)sz < out_len - 1 ? (size_t)sz : out_len - 1;
            size_t got = fread(out, 1, want, capf);
            out[got] = '\0';
        }
    }
    fclose(capf);
    unlink(path);
    return true;
}

static void emit_test_warn(void)
{
    LOG_WARN("test_log_level", "warn line marker=%s", "WMARK");
}

static void emit_test_info(void)
{
    LOG_INFO("test_log_level", "info line marker=%s", "IMARK");
}

/* The source line of the LOG_ERROR call below, kept in sync by hand; the
 * assertion re-derives it via __LINE__ so a moved call fails loudly. */
enum { kEmitTestErrorLine = __LINE__ + 3 };
static void emit_test_error(void)
{
    LOG_ERROR("test_log_level", "error line marker=%s", "EMARK");
}

/* A call site whose free-text message already contains the literal
 * substring "origin=" (e.g. logging a field named that) — the appended
 * stamp must still land once, at the true end of the line. Keep the macro
 * invocation on one line so its __LINE__ is independent of how the
 * preprocessor locates a multiline invocation. */
enum { kEmitTestEmbeddedOriginLine = __LINE__ + 3 };
static void emit_test_error_with_embedded_origin_text(void)
{
    LOG_ERROR("test_log_level", "existing origin=user-supplied-value in the message body");
}

static int test_log_level_origin_checks(void);

int test_log_level(void)
{
    int failures = 0;
    enum zcl_log_level prev = zcl_log_level_get();

    /* ── ordering (compile-time constants; process-state independent) ── */
    LVL_CHECK("ALL == INFO (aliased rank)", ZCL_LOG_ALL == ZCL_LOG_INFO);
    LVL_CHECK("ALL < WARN", ZCL_LOG_ALL < ZCL_LOG_WARN);
    LVL_CHECK("WARN < ERROR", ZCL_LOG_WARN < ZCL_LOG_ERROR);
    LVL_CHECK("ERROR < FATAL", ZCL_LOG_ERROR < ZCL_LOG_FATAL);
    LVL_CHECK("FATAL < OFF", ZCL_LOG_FATAL < ZCL_LOG_OFF);

    /* ── set/get round-trip ── */
    zcl_log_level_set(ZCL_LOG_ERROR);
    LVL_CHECK("set/get round-trips ERROR", zcl_log_level_get() == ZCL_LOG_ERROR);
    zcl_log_level_set(ZCL_LOG_ALL);
    LVL_CHECK("set/get round-trips ALL", zcl_log_level_get() == ZCL_LOG_ALL);

    /* ── zcl_log_level_from_string(): recognized tokens ── */
    {
        static const struct { const char *tok; enum zcl_log_level want; } cases[] = {
            {"all",   ZCL_LOG_ALL},
            {"info",  ZCL_LOG_INFO},
            {"warn",  ZCL_LOG_WARN},
            {"error", ZCL_LOG_ERROR},
            {"fatal", ZCL_LOG_FATAL},
            {"off",   ZCL_LOG_OFF},
        };
        bool all_ok = true;
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            enum zcl_log_level got = (enum zcl_log_level)-1;
            if (!zcl_log_level_from_string(cases[i].tok, &got) ||
                got != cases[i].want)
                all_ok = false;
        }
        LVL_CHECK("from_string: all six tokens parse correctly", all_ok);
    }

    /* ── zcl_log_level_from_string(): rejects unknown, leaves *out alone ── */
    {
        enum zcl_log_level sentinel = ZCL_LOG_ERROR;
        bool rejected_bad = !zcl_log_level_from_string("bogus", &sentinel);
        bool rejected_null = !zcl_log_level_from_string(NULL, &sentinel);
        LVL_CHECK("from_string: rejects unrecognized token",
                  rejected_bad && sentinel == ZCL_LOG_ERROR);
        LVL_CHECK("from_string: rejects NULL string", rejected_null);
        LVL_CHECK("from_string: NULL out pointer also rejected",
                  !zcl_log_level_from_string("warn", NULL));
    }

    /* ── default level is ALL: nothing configured, everything emits ── */
    {
        char buf[512];
        zcl_log_level_set(ZCL_LOG_ALL);
        bool captured = log_level_capture(emit_test_info, buf, sizeof(buf));
        LVL_CHECK("default ALL: LOG_INFO emits with no -loglevel set",
                  captured && strstr(buf, "IMARK") != NULL);
    }

    /* ── suppressed: floor above the macro's structural level ── */
    {
        char buf[512];
        zcl_log_level_set(ZCL_LOG_ERROR); /* WARN(1) < ERROR(2): suppressed */
        bool captured = log_level_capture(emit_test_warn, buf, sizeof(buf));
        LVL_CHECK("floor=ERROR suppresses LOG_WARN",
                  captured && strstr(buf, "WMARK") == NULL);
    }

    /* ── passing: floor at/below the macro's structural level ── */
    {
        char buf[512];
        zcl_log_level_set(ZCL_LOG_WARN); /* WARN(1) >= WARN(1): emits */
        bool captured = log_level_capture(emit_test_warn, buf, sizeof(buf));
        LVL_CHECK("floor=WARN passes LOG_WARN",
                  captured && strstr(buf, "WMARK") != NULL);
    }

    /* ── OFF suppresses everything, including the highest level exercised
     * here (WARN) ── */
    {
        char buf[512];
        zcl_log_level_set(ZCL_LOG_OFF);
        bool captured = log_level_capture(emit_test_warn, buf, sizeof(buf));
        LVL_CHECK("floor=OFF suppresses LOG_WARN",
                  captured && strstr(buf, "WMARK") == NULL);
    }

    /* ── emitted lines carry the ISO-8601 UTC timestamp + level token ──
     * Contract with nodelog_controller.c: "YYYY-MM-DDTHH:MM:SSZ LEVEL
     * [domain] ..." — timestamp at line start, token right after it. */
    {
        char buf[512];
        zcl_log_level_set(ZCL_LOG_ALL);
        bool captured = log_level_capture(emit_test_warn, buf, sizeof(buf));
        bool iso_prefix = strlen(buf) > 21 &&
            isdigit((unsigned char)buf[0]) &&
            isdigit((unsigned char)buf[1]) &&
            isdigit((unsigned char)buf[2]) &&
            isdigit((unsigned char)buf[3]) &&
            buf[4] == '-' && buf[7] == '-' && buf[10] == 'T' &&
            buf[13] == ':' && buf[16] == ':' && buf[19] == 'Z' &&
            buf[20] == ' ';
        LVL_CHECK("LOG_WARN line starts with ISO-8601 UTC timestamp",
                  captured && iso_prefix);
        LVL_CHECK("LOG_WARN line carries the WARN level token",
                  captured && strstr(buf, "Z WARN [test_log_level]") != NULL);
    }
    {
        char buf[512];
        zcl_log_level_set(ZCL_LOG_ALL);
        bool captured = log_level_capture(emit_test_info, buf, sizeof(buf));
        LVL_CHECK("LOG_INFO line carries the INFO level token",
                  captured && strstr(buf, "Z INFO [test_log_level]") != NULL);
    }

    failures += test_log_level_origin_checks();

    /* Restore the entry level for later groups in the same binary. */
    zcl_log_level_set(prev);

    return failures;
}

/* Split out of test_log_level() to keep it under the cyclomatic complexity
 * cap: the origin=<file>:<line> stamping checks live here. */
static int test_log_level_origin_checks(void)
{
    int failures = 0;

    /* ── ERROR-and-above lines carry a trailing origin=<basename>:<line> token
     * matching the call site. ── */
    {
        char buf[512];
        char want[64];
        snprintf(want, sizeof(want), "origin=test_log_level.c:%d\n",
                 (int)kEmitTestErrorLine);
        zcl_log_level_set(ZCL_LOG_ALL);
        bool captured = log_level_capture(emit_test_error, buf, sizeof(buf));
        size_t buf_len = strlen(buf);
        size_t want_len = strlen(want);
        bool ends_with_origin = captured && buf_len >= want_len &&
            !memcmp(buf + buf_len - want_len, want, want_len);
        LVL_CHECK("LOG_ERROR line ends with origin=<basename>:<line> "
                  "matching the call site", ends_with_origin);
    }

    /* ── INFO/WARN lines are byte-for-byte unchanged: no origin= token is
     * appended below ERROR rank ── */
    {
        char buf[512];
        zcl_log_level_set(ZCL_LOG_ALL);
        bool captured = log_level_capture(emit_test_info, buf, sizeof(buf));
        LVL_CHECK("LOG_INFO line carries no origin= token",
                  captured && strstr(buf, "origin=") == NULL);
    }
    {
        char buf[512];
        zcl_log_level_set(ZCL_LOG_ALL);
        bool captured = log_level_capture(emit_test_warn, buf, sizeof(buf));
        LVL_CHECK("LOG_WARN line carries no origin= token",
                  captured && strstr(buf, "origin=") == NULL);
    }

    /* ── a message that already contains the substring "origin=" is not
     * double-stamped, and the real origin= token (added once, at the true
     * end of the line) still parses correctly by anchoring on end-of-line
     * rather than on the first occurrence ── */
    {
        char buf[512];
        zcl_log_level_set(ZCL_LOG_ALL);
        bool captured = log_level_capture(
            emit_test_error_with_embedded_origin_text, buf, sizeof(buf));
        size_t buf_len = strlen(buf);
        int origin_occurrences = 0;
        const char *scan = buf;
        while ((scan = strstr(scan, "origin=")) != NULL) {
            origin_occurrences++;
            scan++;
        }
        char want_tail[64];
        snprintf(want_tail, sizeof(want_tail), "origin=test_log_level.c:%d\n",
                 (int)kEmitTestEmbeddedOriginLine);
        size_t want_len = strlen(want_tail);
        bool real_stamp_at_end = buf_len >= want_len &&
            !memcmp(buf + buf_len - want_len, want_tail, want_len);
        /* Exactly two textual occurrences (the embedded free-text one plus
         * our one real stamp) but only one is the structured end-of-line
         * token a parser anchored on "origin=<file>:<digits>$" would find. */
        LVL_CHECK("embedded 'origin=' text is not double-stamped and the "
                  "real stamp still anchors at end-of-line",
                  captured && origin_occurrences == 2 && real_stamp_at_end);
    }

    /* ── `grep -a -m1 'origin='` on a 200-INFO-line fixture log plus one ERROR
     * line finds the ERROR line (docs/dev/DEVELOPING.md). ── */
    {
        char path[PATH_MAX];
        int fd = test_mkstemp(path, sizeof(path), "log_level_origin_fixture");
        LVL_CHECK("fixture log file created", fd >= 0);
        if (fd >= 0) {
            FILE *f = fdopen(fd, "w");
            for (int i = 0; i < 200; i++)
                fprintf(f, "2026-09-08T00:00:00Z INFO [fixture] filler.c:%d "
                           "noise(): line %d\n", i, i);
            fprintf(f, "2026-09-08T00:00:00Z ERROR [fixture] "
                       "chain_restore_repair.c:802 "
                       "chain_restore_finalize_verified(): post-restore "
                       "integrity FAILED origin=chain_restore_repair.c:802\n");
            fclose(f);

            char cmd[PATH_MAX + 64];
            snprintf(cmd, sizeof(cmd), "grep -a -m1 'origin=' '%s'", path);
            FILE *p = popen(cmd, "r");
            char hit[256] = {0};
            if (p) {
                if (!fgets(hit, sizeof(hit), p))
                    hit[0] = '\0';
                pclose(p);
            }
            LVL_CHECK("grep -a -m1 'origin=' finds the ERROR line, not "
                      "any of the 200 INFO lines",
                      strstr(hit, "post-restore integrity FAILED") != NULL &&
                      strstr(hit, "ERROR") != NULL);
            unlink(path);
        }
    }

    return failures;
}
