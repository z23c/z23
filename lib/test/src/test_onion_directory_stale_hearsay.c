/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sub-test of the `onion_directory` group (dispatched from
 * test_onion_directory.c, which owns that group's entry point). Two
 * contracts, both about ONE field: the hearsay stamp a peer relays
 * alongside a directory record.
 *
 *  1. THE FRESHNESS BOUNDARY IS EXACT, AND IT IS ONE RULE. A record is
 *     FRESH strictly inside ONION_DIR_STALE_SECS, STALE from that
 *     threshold up to ONION_DIR_EXPIRE_SECS, and EXPIRED at the expiry
 *     threshold itself — every comparison is `<`, so both thresholds
 *     belong to the OLDER bucket. A stamp in the future reads FRESH and
 *     reports age 0, never a negative age.
 *
 *     onion_service_directory_learn() is held to the same rule from the
 *     other side: a relayed stamp inside the expiry window is recorded,
 *     one at or past the threshold is refused outright and leaves NO row
 *     behind. Refused, deliberately NOT clamped up to the expiry floor: a
 *     clamped row would be served on by our own /directory.json as merely
 *     STALE, the next hop would clamp it to the floor again, and a host
 *     nobody has reached in weeks would ride the relay graph forever with
 *     its apparent age reset at every hop. The refusal terminates that
 *     chain.
 *
 *  2. THE REFUSAL IS BOUNDED IN THE LOG. Live evidence (devfleet node1,
 *     2026-08-23): the seeds it dials serve directories whose rows froze
 *     ~45 days ago, so every discovery pass re-offered the same expired
 *     records and the per-record ERROR line took 707 of the node's last
 *     3000 log lines — 23% of the log volume spent restating an EXPECTED
 *     condition, at a level that means this node is broken. A flood of
 *     stale records must now cost at most one line per report, the report
 *     must still happen (bounded is not silent), and the retired
 *     per-record wording must not come back.
 *
 * The negative assertions are the load-bearing ones: nothing here may
 * make an expired record usable, and nothing here may make the refusal
 * silent.
 */

#include "test/test_core.h"

#include "base/log_level.h"
#include "platform/time_compat.h"
#include "net/onion_service.h"
#include "util/path_check.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* A distinct host set: these rows must never be seen by the sibling
 * suites in the same group, which run against their own datadirs. Each is
 * 56 characters from the base32 alphabet plus ".onion". */
#define SH_HOST_KEEP \
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddd.onion"
#define SH_HOST_EDGE \
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.onion"
#define SH_HOST_GONE \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff.onion"
#define SH_HOST_FUTURE \
    "gggggggggggggggggggggggggggggggggggggggggggggggggggggggg.onion"

#define SH_CHECK(label, cond) do { \
    printf("onion_directory: %s... ", (label)); \
    if (cond) { printf("OK\n"); } \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── 1. The pure rule, at every boundary ──────────────────────────
 *
 * Exact, with no margin and no flake: onion_directory_freshness() takes
 * `now` as a parameter and never reads a clock. */
static int sh_freshness_boundary(void)
{
    int failures = 0;
    const int64_t now = 1800000000;

    SH_CHECK("one second inside the stale threshold is FRESH",
             onion_directory_freshness(now - (ONION_DIR_STALE_SECS - 1), now,
                                       false) == ONION_DIR_FRESH);
    SH_CHECK("the stale threshold itself is STALE, not FRESH",
             onion_directory_freshness(now - ONION_DIR_STALE_SECS, now,
                                       false) == ONION_DIR_STALE);
    SH_CHECK("one second inside the expiry threshold is still STALE",
             onion_directory_freshness(now - (ONION_DIR_EXPIRE_SECS - 1), now,
                                       false) == ONION_DIR_STALE);
    SH_CHECK("the expiry threshold itself is EXPIRED, not STALE",
             onion_directory_freshness(now - ONION_DIR_EXPIRE_SECS, now,
                                       false) == ONION_DIR_EXPIRED);
    SH_CHECK("a stamp past the expiry threshold is EXPIRED",
             onion_directory_freshness(now - ONION_DIR_EXPIRE_SECS - 1, now,
                                       false) == ONION_DIR_EXPIRED);

    /* A future stamp is peer clock skew, or hearsay reaching for
     * freshness it has not earned. It reads FRESH — never more than that,
     * because FRESH is already the top of the ladder — and its age clamps
     * at zero instead of going negative under the comparisons. */
    SH_CHECK("a stamp in the future reads FRESH, no better",
             onion_directory_freshness(now + 86400, now, false) ==
                 ONION_DIR_FRESH);
    SH_CHECK("a future stamp reports age 0, never a negative age",
             onion_directory_age_secs(now + 86400, now) == 0);
    SH_CHECK("age is measured, not guessed, for a stamp in the past",
             onion_directory_age_secs(now - 1234, now) == 1234);

    /* The two ends that carry no age at all. */
    SH_CHECK("a row with no stamp has no provenance and is EXPIRED",
             onion_directory_freshness(0, now, false) == ONION_DIR_EXPIRED);
    SH_CHECK("our own row is FRESH whatever its stamp says",
             onion_directory_freshness(0, now, true) == ONION_DIR_FRESH);
    return failures;
}

/* ── Local datadir helpers ────────────────────────────────────────
 * The sibling suite's equivalents are static to its own translation
 * unit. These read only; the ONE rule they are checking against still
 * lives in the library, so a second reader here cannot drift into
 * disagreeing with it. */
static sqlite3 *sh_open_db(const char *datadir)
{
    char path[1024];
    zcl_node_db_path(path, sizeof(path), datadir);
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db, 2000);
    return db;
}

/* last_seen for one host, or -1 when there is no row at all. */
static int64_t sh_row_last_seen(sqlite3 *db, const char *host)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT last_seen FROM peer_directory WHERE onion_address = ?",
            -1, &s, NULL) != SQLITE_OK || !s)
        return -1;
    sqlite3_bind_text(s, 1, host, -1, SQLITE_STATIC);
    int64_t v = -1;
    if (sqlite3_step(s) == SQLITE_ROW)
        v = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return v;
}

/* ── 2. learn() holds the same boundary ───────────────────────────
 *
 * learn() samples the wall clock itself, so the threshold cannot be
 * pinned to the second here the way the pure rule above is pinned. It is
 * approached from both sides with a margin larger than any plausible
 * tick: a stamp well inside the window must be RECORDED, one at or past
 * the threshold must be REFUSED. A clock that advances mid-test pushes
 * both cases further into the outcome already asserted, so neither
 * direction can flake. */
static int sh_learn_boundary(sqlite3 *db)
{
    int failures = 0;
    const int64_t now = (int64_t)platform_time_wall_time_t();
    const int64_t margin = 300;

    SH_CHECK("a relayed stamp well inside the expiry window is recorded",
             onion_service_directory_learn(
                 SH_HOST_KEEP, 8033, 5,
                 now - (ONION_DIR_EXPIRE_SECS - margin), NULL));
    SH_CHECK("the recorded row kept the relayed stamp, unaltered",
             sh_row_last_seen(db, SH_HOST_KEEP) ==
                 now - (ONION_DIR_EXPIRE_SECS - margin));
    SH_CHECK("a recorded relayed row reads STALE — hearsay buys no freshness",
             onion_directory_freshness(sh_row_last_seen(db, SH_HOST_KEEP),
                                       now, false) == ONION_DIR_STALE);

    SH_CHECK("a relayed stamp AT the expiry threshold is refused",
             !onion_service_directory_learn(SH_HOST_EDGE, 8033, 5,
                                            now - ONION_DIR_EXPIRE_SECS,
                                            NULL));
    SH_CHECK("the refused threshold stamp left no row behind",
             sh_row_last_seen(db, SH_HOST_EDGE) == -1);

    /* 3914217s is a real age off devfleet node1 on 2026-08-23 — a stamp
     * from 2026-07-09 that a live seed was still relaying as current. */
    SH_CHECK("a relayed stamp 45 days past expiry is refused",
             !onion_service_directory_learn(SH_HOST_GONE, 8033, 5,
                                            now - 3914217, NULL));
    SH_CHECK("the refused stale stamp left no row behind",
             sh_row_last_seen(db, SH_HOST_GONE) == -1);
    SH_CHECK("an expired record is never clamped up to the expiry floor",
             sh_row_last_seen(db, SH_HOST_GONE) !=
                 now - ONION_DIR_EXPIRE_SECS);

    /* Hearsay may age a row, never freshen it past OUR clock. */
    SH_CHECK("a relayed stamp in the future is accepted",
             onion_service_directory_learn(SH_HOST_FUTURE, 8033, 5,
                                           now + 86400, NULL));
    SH_CHECK("the future stamp was clamped, not stored as given",
             sh_row_last_seen(db, SH_HOST_FUTURE) < now + 86400);
    SH_CHECK("the clamped row is not stamped in the future at all",
             sh_row_last_seen(db, SH_HOST_FUTURE) <=
                 (int64_t)platform_time_wall_time_t());
    return failures;
}

/* ── 3. The refusal is bounded in the log ─────────────────────────
 *
 * Same stderr-capture shape as brt_capture() in
 * test_blocker_reason_truncation.c: redirect stderr into a scratch file
 * for the duration of `fn`, then hand back whatever landed in it.
 * Returns false if the plumbing itself failed, which the caller treats as
 * a real FAIL — the captured text IS the thing under test. */
static bool sh_capture(void (*fn)(void), char *out, size_t out_len)
{
    if (out && out_len > 0)
        out[0] = '\0';

    mkdir("./test-tmp", 0755);
    char path[256];
    snprintf(path, sizeof(path), "./test-tmp/onion_dir_stale_%d.log",
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

/* Distinct hosts, every one of them relaying a ~45-day-old stamp: the
 * shape node1 meets on every discovery pass against a seed whose
 * directory froze at first sighting, only compressed into one burst. */
#define SH_FLOOD_N 600
static int g_flood_accepted;

static void sh_flood_stale(void)
{
    const int64_t now = (int64_t)platform_time_wall_time_t();
    static const char B32[] = "abcdefghijklmnopqrstuvwxyz234567";

    g_flood_accepted = 0;
    for (int i = 0; i < SH_FLOOD_N; i++) {
        /* 56 base32 characters + ".onion". Built here rather than written
         * out so the length is exact by construction. */
        char host[64];
        memset(host, 'h', 54);
        host[54] = B32[(i / 32) % 32];
        host[55] = B32[i % 32];
        memcpy(host + 56, ".onion", 7);
        if (onion_service_directory_learn(host, 8033, 1,
                                          now - ONION_DIR_EXPIRE_SECS -
                                              3900000 - i,
                                          NULL))
            g_flood_accepted++;
    }
}

/* Non-overlapping occurrences of `needle` in `hay`. */
static int sh_count(const char *hay, const char *needle)
{
    int n = 0;
    size_t len = strlen(needle);
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += len)
        n++;
    return n;
}

static int sh_log_bounded(void)
{
    int failures = 0;
    static char log[262144];

    /* The captured text IS the thing under test, so the threshold that
     * decides whether it exists at all is set here rather than inherited
     * from whatever ran before. Restored immediately after. */
    enum zcl_log_level saved_level = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_ALL);
    bool captured = sh_capture(sh_flood_stale, log, sizeof(log));
    zcl_log_level_set(saved_level);

    SH_CHECK("stderr capture plumbing worked", captured);
    SH_CHECK("every stale record in the flood was refused",
             g_flood_accepted == 0);

    int lines = sh_count(log, "already past expiry");

    /* BOUNDED IS NOT SILENT. A burst this size must be reported: the
     * count bound in note_stale_hearsay() exists precisely so a flood
     * does not sit unmentioned until the window rolls. */
    SH_CHECK("a large stale burst is still reported at least once",
             lines >= 1);

    /* AND THE LOG DOES NOT SCALE WITH THE RECORDS. The pinned property is
     * the ratio, not the exact report cadence, so tuning the bound in
     * note_stale_hearsay() does not have to be mirrored here. Under the
     * per-record ERROR this replaced, `lines` would be SH_FLOOD_N. */
    SH_CHECK("the log grows by at most one line per 20 stale records",
             lines * 20 <= SH_FLOOD_N);

    /* The retired per-record wording must not creep back. It named no
     * host, so no reader could tell WHICH record was stale; the aggregate
     * names the oldest one it saw. */
    SH_CHECK("the retired per-record message is gone",
             sh_count(log, "relayed stamp is already past expiry") == 0);

    /* Whatever is emitted is an AGGREGATE: it carries a count and the
     * window it covers, never a bare single-record report. */
    SH_CHECK("the emitted line is an aggregate, with a count and a window",
             strstr(log, "ignored ") != NULL &&
                 strstr(log, "in the last ") != NULL);

    /* ERROR means "this node is broken". A peer relaying a directory it
     * never refreshes is expected input, and our handling of it is
     * correct and complete — so this domain says nothing at ERROR here. */
    SH_CHECK("the aggregate is not raised at ERROR level",
             sh_count(log, "ERROR [net.onion_directory]") == 0);
    return failures;
}

/* ── Sub-test entry point ─────────────────────────────────────────
 * Named for its subject, NOT for its file. A filename-matching name
 * would make this a test-registration entry point in its own right
 * (tools/scripts/check_test_registration.sh) and demand its own catalog
 * row; it is a sub-test of the registered `onion_directory` group and is
 * dispatched from that group's entry point in test_onion_directory.c. */
int od_stale_hearsay_bound(void);

int od_stale_hearsay_bound(void)
{
    int failures = 0;

    failures += sh_freshness_boundary();

    /* Static: onion_service_start() borrows this pointer for ctx->datadir,
     * which is where learn() then writes. */
    static char datadir[256];
    test_make_tmpdir(datadir, sizeof(datadir), "onion_dir", "stale_hearsay");
    onion_service_start(datadir);

    sqlite3 *db = sh_open_db(datadir);
    if (!db) {
        printf("onion_directory: could not open the stale-hearsay test db..."
               " FAIL\n");
        onion_service_stop();
        test_cleanup_tmpdir(datadir);
        return failures + 1;
    }

    failures += sh_learn_boundary(db);
    failures += sh_log_bounded();

    sqlite3_close(db);
    onion_service_stop();
    test_cleanup_tmpdir(datadir);
    return failures;
}
