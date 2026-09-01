/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_blocker_reason_truncation — a blocker reason that does not fit must say
 * so, in the field AND in the log.
 *
 * Why this test exists
 * ---------------------
 * The typed blocker is this project's honesty mechanism: a stall is always a
 * NAMED blocker, never a quiet stop. But `blocker_init` used to store the
 * reason with a bare
 *
 *     snprintf(out->reason, BLOCKER_REASON_MAX, "%s", reason);
 *
 * and discard the return value. snprintf returns the length it WOULD have
 * written, so that one discarded int was the only evidence the stored sentence
 * was partial. The operator then read a reason that stopped mid-word with
 * nothing saying anything was missing — a degraded diagnosis presented as a
 * complete one, delivered at the exact moment someone is trying to recover.
 * Note the asymmetry it replaced: an over-long `id` or `owner` was LOG_FAILed,
 * while the reason — the field a human actually reads — was silently mangled.
 *
 * This is not hypothetical. Four producers in this tree format 280-361 bytes
 * into their 256-byte reason buffers on live paths, and the clause a tail cut
 * eats first is always the "...and here is what clears it" half:
 *   engine/conditions/src/sync_rate_below_floor.c   282 min / 330 live / 361 max
 *   engine/jobs/src/utxo_root_ladder_tripwire.c     324 on the DEFAULT fail-closed
 *   engine/reducer/jobs/src/reducer_frontier_body_read_note.c 271 min / 297 live
 *   engine/services/src/directory_influence_policy.c  280 at a full 60-byte prefix
 *
 * What is asserted (the POSITIVE capability, not "it didn't crash")
 * -----------------------------------------------------------------
 *   1. An over-long reason lands in the record with a VISIBLE in-band marker
 *      (`...[cut <len>/<cap>]`) so a reader of `dumpstate blocker` can see the
 *      text is partial without consulting anything else.
 *   2. The truncation is REPORTED: one WARN line naming the field, the intended
 *      length, the capacity, the bytes lost, and the FULL untruncated reason,
 *      so nothing is actually lost.
 *   3. The success/failure contract did NOT change: blocker_init still returns
 *      true, the field is still NUL-terminated inside BLOCKER_REASON_MAX, and
 *      the reason still round-trips through blocker_set into the snapshot. A
 *      long sentence must never turn a recoverable stall into an error path.
 *   4. A reason that FITS is stored byte-exact with no marker and logs nothing
 *      — the guard must not tax the normal case or cry wolf.
 *
 * Both assertion 1 and assertion 2 fail on the parent commit.
 *
 * make t ONLY=blocker_reason_truncation
 */

#include "test/test_core.h"

#include "base/log_level.h"
#include "base/text_fit.h"
#include "util/blocker.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BRT_CHECK(name, expr) do { \
    printf("blocker_reason_truncation: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Captured stderr from the last brt_capture_init() run. */
static char g_brt_log[8192];
static bool g_brt_reason_ok;
static struct blocker_record g_brt_rec;
static const char *g_brt_reason_in;

/* Same stderr-capture shape as log_level_capture() in test_log_level.c:
 * redirect stderr into a scratch file for the duration of `fn`, then hand back
 * whatever landed in it. Returns false if the plumbing itself failed, which the
 * caller treats as a real FAIL because the captured text IS the thing under
 * test. */
static bool brt_capture(void (*fn)(void), char *out, size_t out_len)
{
    if (out && out_len > 0)
        out[0] = '\0';

    mkdir("./test-tmp", 0755);
    char path[256];
    snprintf(path, sizeof(path), "./test-tmp/blocker_reason_trunc_%d.log",
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

static void brt_init_under_capture(void)
{
    g_brt_reason_ok = blocker_init(&g_brt_rec, "test.reason_truncation",
                                   "test_blocker_reason_truncation",
                                   BLOCKER_TRANSIENT, g_brt_reason_in);
}

/* Build a reason whose distinguishing detail sits in a TRAILING clause, which
 * is precisely the shape a silent tail cut destroys. `len` bytes, all ASCII. */
static void brt_build_reason(char *out, size_t out_cap, size_t len,
                             const char *tail_marker)
{
    size_t tail = strlen(tail_marker);
    if (len + 1 > out_cap)
        len = out_cap - 1;
    if (tail > len)
        tail = len;
    memset(out, 'a', len - tail);
    memcpy(out + (len - tail), tail_marker, tail);
    out[len] = '\0';
}

int test_blocker_reason_truncation(void)
{
    int failures = 0;

    if (!blocker_module_init()) {
        printf("blocker_reason_truncation: blocker_module_init FAILED\n");
        return 1;
    }
    blocker_reset_for_testing();

    /* The truncation report is a WARN, so the level has to admit WARN for the
     * capture to see it. Don't inherit whatever a previous group left set. */
    enum zcl_log_level prev_level = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_ALL);

    /* ── (1) over-long reason: visible marker + a report ───────────────── */

    /* 600 bytes — comfortably past BLOCKER_REASON_MAX (256), and past any
     * plausible future raise of it, so this test keeps meaning if the cap
     * grows. The last clause names what clears the stall; a silent cut is
     * exactly the failure of eating it. */
    char long_reason[700];
    brt_build_reason(long_reason, sizeof(long_reason), 600,
                     " CLEARS_WHEN=the body re-downloads");
    size_t long_len = strlen(long_reason);

    g_brt_reason_in = long_reason;
    bool captured = brt_capture(brt_init_under_capture, g_brt_log,
                                sizeof(g_brt_log));
    BRT_CHECK("stderr capture plumbing worked", captured);

    /* Contract unchanged: naming a stall must not fail because the sentence
     * ran long. */
    BRT_CHECK("blocker_init still returns true on an over-long reason",
              g_brt_reason_ok);
    BRT_CHECK("stored reason stays inside BLOCKER_REASON_MAX",
              strlen(g_brt_rec.reason) < (size_t)BLOCKER_REASON_MAX);

    /* THE new positive capability, half one: the field SHOWS it was cut. */
    BRT_CHECK("stored reason carries the visible cut marker",
              strstr(g_brt_rec.reason, ZCL_TEXT_FIT_MARKER_TAG) != NULL);

    /* The marker is not decoration — it states the real numbers. */
    char want_marker[64];
    snprintf(want_marker, sizeof(want_marker),
             ZCL_TEXT_FIT_MARKER_TAG "%zu/%d]", long_len, BLOCKER_REASON_MAX);
    BRT_CHECK("marker states the intended length and the capacity",
              strstr(g_brt_rec.reason, want_marker) != NULL);

    /* The marker sits at the END, where a reader hits it after the text. */
    size_t stored_len = strlen(g_brt_rec.reason);
    size_t mlen = strlen(want_marker);
    BRT_CHECK("marker is the tail of the stored text",
              stored_len >= mlen &&
              strcmp(g_brt_rec.reason + (stored_len - mlen), want_marker) == 0);

    /* THE new positive capability, half two: the cut is REPORTED. */
    BRT_CHECK("truncation is logged at WARN",
              strstr(g_brt_log, "WARN") != NULL &&
              strstr(g_brt_log, "did not fit") != NULL);
    BRT_CHECK("log names the field that was cut",
              strstr(g_brt_log, "blocker_record.reason") != NULL);

    char want_len[64];
    snprintf(want_len, sizeof(want_len), "intended_len=%zu", long_len);
    BRT_CHECK("log states the original length", strstr(g_brt_log, want_len) != NULL);

    char want_cap[64];
    snprintf(want_cap, sizeof(want_cap), "capacity=%d", BLOCKER_REASON_MAX);
    BRT_CHECK("log states the field capacity", strstr(g_brt_log, want_cap) != NULL);

    char want_lost[64];
    snprintf(want_lost, sizeof(want_lost), "lost=%zu",
             long_len - (stored_len - mlen));
    BRT_CHECK("log states how many bytes of the reason were lost",
              strstr(g_brt_log, want_lost) != NULL);

    /* Nothing is actually lost: the trailing clause the field could not hold is
     * in the log line. This is the assertion that makes the fix worth having —
     * a marker alone would only tell the operator that the answer is gone. */
    BRT_CHECK("log carries the FULL reason, including the cut trailing clause",
              strstr(g_brt_log, long_reason) != NULL);
    BRT_CHECK("the cut clause is absent from the field but present in the log",
              strstr(g_brt_rec.reason, "CLEARS_WHEN=") == NULL &&
              strstr(g_brt_log, "CLEARS_WHEN=the body re-downloads") != NULL);

    /* (3) it survives the registry round-trip the operator actually reads. */
    BRT_CHECK("blocker_set accepts the record", blocker_set(&g_brt_rec) == 0);
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    const struct blocker_snapshot *found = NULL;
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, "test.reason_truncation") == 0) {
            found = &snaps[i];
            break;
        }
    }
    BRT_CHECK("the blocker is in the snapshot", found != NULL);
    BRT_CHECK("the snapshot reason still shows the cut marker",
              found && strstr(found->reason, ZCL_TEXT_FIT_MARKER_TAG) != NULL);

    /* ── (4) a reason that FITS is untouched and silent ────────────────── */

    blocker_reset_for_testing();

    char short_reason[BLOCKER_REASON_MAX];
    brt_build_reason(short_reason, sizeof(short_reason),
                     BLOCKER_REASON_MAX - 1, " CLEARS_WHEN=ok");
    g_brt_reason_in = short_reason;
    captured = brt_capture(brt_init_under_capture, g_brt_log, sizeof(g_brt_log));
    BRT_CHECK("stderr capture plumbing worked (exact-fit case)", captured);
    BRT_CHECK("an exactly-fitting reason is stored byte-exact",
              g_brt_reason_ok &&
              strcmp(g_brt_rec.reason, short_reason) == 0);
    BRT_CHECK("an exactly-fitting reason gets no marker",
              strstr(g_brt_rec.reason, ZCL_TEXT_FIT_MARKER_TAG) == NULL);
    BRT_CHECK("an exactly-fitting reason logs nothing (no crying wolf)",
              strstr(g_brt_log, "did not fit") == NULL);

    /* One byte over the exact fit is the boundary the old code got wrong
     * without saying so. */
    blocker_reset_for_testing();
    char boundary[BLOCKER_REASON_MAX + 8];
    brt_build_reason(boundary, sizeof(boundary), BLOCKER_REASON_MAX,
                     " CLEARS_WHEN=ok");
    g_brt_reason_in = boundary;
    captured = brt_capture(brt_init_under_capture, g_brt_log, sizeof(g_brt_log));
    BRT_CHECK("stderr capture plumbing worked (one-over case)", captured);
    BRT_CHECK("one byte over the cap is marked and reported",
              strstr(g_brt_rec.reason, ZCL_TEXT_FIT_MARKER_TAG) != NULL &&
              strstr(g_brt_log, "did not fit") != NULL);

    /* NULL reason stays empty and silent — blocker_init documents it as
     * optional. */
    blocker_reset_for_testing();
    g_brt_reason_in = NULL;
    captured = brt_capture(brt_init_under_capture, g_brt_log, sizeof(g_brt_log));
    BRT_CHECK("stderr capture plumbing worked (NULL case)", captured);
    BRT_CHECK("a NULL reason stays empty and logs nothing",
              g_brt_reason_ok && g_brt_rec.reason[0] == '\0' &&
              strstr(g_brt_log, "did not fit") == NULL);

    blocker_reset_for_testing();
    zcl_log_level_set(prev_level);
    printf("blocker_reason_truncation: %d failure(s)\n", failures);
    return failures;
}
