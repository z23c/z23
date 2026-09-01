/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: prove the determinism measurement detects what it claims to detect
 * AND does not accuse what it should not — the direction that decides whether
 * anyone leaves it switched on.
 *
 * A determinism checker with false positives is switched off within a week, so
 * the false-accusation direction is proved explicitly here and not merely
 * assumed: the DETERMINISTIC fixture emits a transcript whose bytes GENUINELY
 * differ between runs — different durations, different temp paths, different
 * pointer values, a different environment around it — and the verdict-vector
 * digest must be bitwise identical anyway. A tool that hashed the transcript
 * would fail that case, which is exactly why this one does not. */

#include "test/test_core.h"

#include "determinism/classify.h"
#include "determinism/perturbation.h"
#include "determinism/receipt.h"
#include "determinism/verdict.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── transcript fixtures ──────────────────────────────────────────────────
 * Every fixture writes a REAL test_parallel replay section: the same header
 * shape and the same "<name>... <outcome>" lines the harness in
 * test/test_core.h prints. Nothing here is a mock of the format. */

#define FIXTURE_CAP 8192

struct fixture {
    char text[FIXTURE_CAP];
    size_t len;
};

static void fx_reset(struct fixture *f)
{
    f->len = 0;
    f->text[0] = '\0';
}

static void fx_add(struct fixture *f, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void fx_add(struct fixture *f, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(f->text + f->len, FIXTURE_CAP - f->len, fmt, ap);
    va_end(ap);
    if (n > 0 && (size_t)n < FIXTURE_CAP - f->len) f->len += (size_t)n;
}

/* Run a fixture's text through the real scanner and return the digest of the
 * ONE group it contains. */
struct one_group {
    bool found;
    struct zcl_det_group_digest g;
};

static bool one_group_sink(void *ctx, const struct zcl_det_group_digest *g)
{
    struct one_group *o = ctx;
    o->found = true;
    o->g = *g;
    return true;
}

static bool digest_of(const struct fixture *f, struct zcl_det_group_digest *out)
{
#if defined(_WIN32)
    /* MinGW's UCRT has no fmemopen().  Exercise the same scanner with the
     * exact fixture bytes through an anonymous test stream instead. */
    FILE *in = tmpfile();
    if (!in) return false;
    if (fwrite(f->text, 1, f->len, in) != f->len || fflush(in) != 0 ||
        fseek(in, 0, SEEK_SET) != 0) {
        fclose(in);
        return false;
    }
#else
    FILE *in = fmemopen((void *)f->text, f->len, "r");
    if (!in) return false;
#endif
    struct one_group o;
    memset(&o, 0, sizeof(o));
    struct zcl_det_scan_stats stats;
    bool ok = zcl_det_transcript_scan(in, one_group_sink, &o, &stats);
    fclose(in);
    if (!ok || !o.found) return false;
    *out = o.g;
    return true;
}

/* The DETERMINISTIC fixture. Its verdict vector is fixed; everything else
 * about its transcript — the wall-clock duration in the header, a temp path,
 * a pointer, a pid, an elapsed line — is made to vary on purpose. */
static void emit_deterministic(struct fixture *f, int nonce)
{
    fx_reset(f);
    fx_add(f, "==================== test_fixture_stable (PASS, %ds) "
              "====================\n", nonce * 7 + 1);
    fx_add(f, "fixture temp dir: /var/tmp/zcl-%d-%d/work\n", nonce, nonce * 31);
    fx_add(f, "opened arena at %p\n", (void *)(uintptr_t)(0x7ffd0000u + nonce));
    fx_add(f, "alpha check... OK\n");
    fx_add(f, "elapsed %d.%03d ms\n", nonce, nonce * 17 % 1000);
    fx_add(f, "bravo check... OK\n");
    fx_add(f, "charlie check... SKIP (needs ZCL_STRESS_TESTS=1 in %d)\n", nonce);
    fx_add(f, "delta check... OK\n");
    fx_add(f, "worker pid %d finished\n", 4000 + nonce);
}

/* The three failures a verdict vector must catch, each one mutation away from
 * emit_deterministic. */
static void emit_outcome_flipped(struct fixture *f)
{
    emit_deterministic(f, 0);
    char *p = strstr(f->text, "bravo check... OK");
    if (p) memcpy(p, "bravo check... FA", 17);
    /* Rebuild cleanly instead of patching a partial word. */
    fx_reset(f);
    fx_add(f, "==================== test_fixture_stable (PASS, 1s) "
              "====================\n");
    fx_add(f, "alpha check... OK\n");
    fx_add(f, "bravo check... FAIL at tests/harness/src/test_fixture.c:11 (x != y): 1 != 2\n");
    fx_add(f, "charlie check... SKIP (needs ZCL_STRESS_TESTS=1 in 0)\n");
    fx_add(f, "delta check... OK\n");
}

static void emit_order_swapped(struct fixture *f)
{
    fx_reset(f);
    fx_add(f, "==================== test_fixture_stable (PASS, 1s) "
              "====================\n");
    fx_add(f, "bravo check... OK\n");
    fx_add(f, "alpha check... OK\n");
    fx_add(f, "charlie check... SKIP (needs ZCL_STRESS_TESTS=1 in 0)\n");
    fx_add(f, "delta check... OK\n");
}

static void emit_check_dropped(struct fixture *f)
{
    fx_reset(f);
    fx_add(f, "==================== test_fixture_stable (PASS, 1s) "
              "====================\n");
    fx_add(f, "alpha check... OK\n");
    fx_add(f, "charlie check... SKIP (needs ZCL_STRESS_TESTS=1 in 0)\n");
    fx_add(f, "delta check... OK\n");
}

/* The NON-DETERMINISTIC fixture: it really reads the environment, the way the
 * defect that motivated this module did. Under CC_SET it asserts one thing;
 * with CC absent it asserts another. */
static void emit_env_sensitive(struct fixture *f)
{
    const char *cc = getenv("ZCL_DET_FIXTURE_CC");
    fx_reset(f);
    fx_add(f, "==================== test_fixture_env (PASS, 1s) "
              "====================\n");
    fx_add(f, "compiler probe... OK\n");
    if (cc && cc[0])
        fx_add(f, "compiler-cache two-token invocation... OK\n");
    fx_add(f, "teardown... OK\n");
}

/* ── 1. the digest detects the three failures ─────────────────────────────*/

static int test_vector_detects_the_three_failures(void)
{
    int failures = 0;
    TEST("verdict vector: outcome flip, reorder and dropped check all move the digest") {
        struct fixture f;
        struct zcl_det_group_digest base, flipped, reordered, dropped;

        emit_deterministic(&f, 0);
        ASSERT(digest_of(&f, &base));
        ASSERT_EQ(base.check_count, 4u);
        ASSERT_STR_EQ(base.group, "test_fixture_stable");

        emit_outcome_flipped(&f);
        ASSERT(digest_of(&f, &flipped));
        ASSERT(memcmp(base.digest, flipped.digest, ZCL_DET_DIGEST_LEN) != 0);

        emit_order_swapped(&f);
        ASSERT(digest_of(&f, &reordered));
        ASSERT(memcmp(base.digest, reordered.digest, ZCL_DET_DIGEST_LEN) != 0);
        /* Same multiset of (name, outcome) pairs, different order. A digest
         * that folded the pairs in unordered would miss this entirely. */
        ASSERT_EQ(reordered.check_count, base.check_count);

        emit_check_dropped(&f);
        ASSERT(digest_of(&f, &dropped));
        ASSERT(memcmp(base.digest, dropped.digest, ZCL_DET_DIGEST_LEN) != 0);
        ASSERT_EQ(dropped.check_count, 3u);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2. the false-accusation direction ────────────────────────────────────*/

static int test_no_false_accusation(void)
{
    int failures = 0;
    TEST("verdict vector: varying durations, paths, pointers and pids do NOT move the digest") {
        struct fixture a, b;
        struct zcl_det_group_digest da, db;
        emit_deterministic(&a, 1);
        emit_deterministic(&b, 9);
        /* The transcripts genuinely differ — if they did not, this would prove
         * nothing at all. */
        ASSERT(a.len != b.len || memcmp(a.text, b.text, a.len) != 0);
        ASSERT(digest_of(&a, &da));
        ASSERT(digest_of(&b, &db));
        ASSERT(memcmp(da.digest, db.digest, ZCL_DET_DIGEST_LEN) == 0);
        ASSERT_EQ(da.check_count, db.check_count);
        PASS();
    } _test_next:;
    return failures;
}

static int test_failure_values_are_excluded(void)
{
    int failures = 0;
    TEST("verdict vector: a FAIL keeps its file:line and discards the printed values") {
        struct fixture a, b;
        struct zcl_det_group_digest da, db, dc;
        fx_reset(&a);
        fx_add(&a, "==================== test_x (FAIL, 1s) ====================\n");
        fx_add(&a, "case... FAIL at tests/harness/src/test_x.c:42 (p != q): 0x7ffd1000 != 0x7ffd2000\n");
        fx_reset(&b);
        fx_add(&b, "==================== test_x (FAIL, 9s) ====================\n");
        fx_add(&b, "case... FAIL at tests/harness/src/test_x.c:42 (p != q): 0x5643aaaa != 0x5643bbbb\n");
        ASSERT(digest_of(&a, &da));
        ASSERT(digest_of(&b, &db));
        /* Two runs of the SAME failing assertion, printing two ASLR-dependent
         * addresses. Same assertion, same digest — otherwise every failing
         * pointer comparison in the tree would be reported non-deterministic. */
        ASSERT(memcmp(da.digest, db.digest, ZCL_DET_DIGEST_LEN) == 0);

        /* A DIFFERENT assertion in the same group must still move it. */
        struct fixture c;
        fx_reset(&c);
        fx_add(&c, "==================== test_x (FAIL, 1s) ====================\n");
        fx_add(&c, "case... FAIL at tests/harness/src/test_x.c:77 (p != q): 0x7ffd1000 != 0x7ffd2000\n");
        ASSERT(digest_of(&c, &dc));
        ASSERT(memcmp(da.digest, dc.digest, ZCL_DET_DIGEST_LEN) != 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2b. the split-across-lines convention ────────────────────────────────
 * TEST_CASE prints "<name>... " with no newline, so a case that logs while it
 * runs puts its own output between the name and the outcome word. Measured on
 * this tree, 91 of 1013 dispatched groups do exactly that; a reader that only
 * accepted "<name>... OK" reported every one of them as asserting nothing. */

static int test_outcome_on_a_later_line(void)
{
    int failures = 0;
    TEST("stream: a check whose outcome lands lines later is still captured") {
        struct fixture a, b;
        struct zcl_det_group_digest da, db;

        fx_reset(&a);
        fx_add(&a, "==================== test_late (PASS, 1s) ====================\n");
        fx_add(&a, "alpha... [boot]   sqlite.quick_check           0ms\n");
        fx_add(&a, "db: applied 78 migration(s), now at version 79\n");
        fx_add(&a, "OK\n");
        fx_add(&a, "bravo... OK\n");
        ASSERT(digest_of(&a, &da));
        ASSERT_EQ(da.check_count, 2u);

        /* The interleaved chatter is exactly where a duration or a temp path
         * lives, so changing it must not move the digest. */
        fx_reset(&b);
        fx_add(&b, "==================== test_late (PASS, 9s) ====================\n");
        fx_add(&b, "alpha... [boot]   sqlite.quick_check           7ms\n");
        fx_add(&b, "db: applied 78 migration(s), now at version 79\n");
        fx_add(&b, "tmp dir /var/tmp/zcl-99331/work\n");
        fx_add(&b, "OK\n");
        fx_add(&b, "bravo... OK\n");
        ASSERT(digest_of(&b, &db));
        ASSERT_EQ(db.check_count, 2u);
        ASSERT(memcmp(da.digest, db.digest, ZCL_DET_DIGEST_LEN) == 0);

        /* And the same two checks written the ordinary way agree with them:
         * the two conventions are one vector, not two. */
        struct fixture plain;
        struct zcl_det_group_digest dp;
        fx_reset(&plain);
        fx_add(&plain, "==================== test_late (PASS, 1s) ====================\n");
        fx_add(&plain, "alpha... OK\n");
        fx_add(&plain, "bravo... OK\n");
        ASSERT(digest_of(&plain, &dp));
        ASSERT(memcmp(da.digest, dp.digest, ZCL_DET_DIGEST_LEN) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_stream_refuses_to_guess(void)
{
    int failures = 0;
    TEST("stream: chatter cannot open, steal or close a check") {
        struct zcl_det_stream s;
        uint8_t digest[ZCL_DET_DIGEST_LEN];
        uint32_t count = 0;
        uint64_t dangling = 0;

        /* A chatter line containing the separator while a check is OPEN must
         * not re-open one and take its outcome. */
        zcl_det_stream_begin(&s);
        ASSERT(zcl_det_stream_line(&s, "alpha... starting\n"));
        ASSERT(zcl_det_stream_line(&s, "loading tables... please wait\n"));
        ASSERT(zcl_det_stream_line(&s, "OK\n"));
        ASSERT(zcl_det_stream_finish(&s, digest, &count, &dangling));
        ASSERT_EQ(count, 1u);
        ASSERT_EQ(dangling, 0llu);

        /* A bare outcome with nothing open is a summary line, not a check. */
        zcl_det_stream_begin(&s);
        ASSERT(zcl_det_stream_line(&s, "OK\n"));
        ASSERT(zcl_det_stream_line(&s, "FAIL\n"));
        ASSERT(zcl_det_stream_finish(&s, digest, &count, &dangling));
        ASSERT_EQ(count, 0u);
        ASSERT_EQ(dangling, 0llu);

        /* Prose that merely STARTS with an outcome word does not close one. */
        zcl_det_stream_begin(&s);
        ASSERT(zcl_det_stream_line(&s, "alpha... working\n"));
        ASSERT(zcl_det_stream_line(&s, "OK: 12 rows loaded\n"));
        ASSERT(zcl_det_stream_line(&s, "OKAY then\n"));
        ASSERT(zcl_det_stream_finish(&s, digest, &count, &dangling));
        ASSERT_EQ(count, 0u);
        /* Opened and never closed: DANGLING, counted, never invented. */
        ASSERT_EQ(dangling, 1llu);

        /* A group that only prints progress and never an outcome yields an
         * EMPTY vector — the honest no-vector exclusion, not a fabricated
         * verdict. */
        zcl_det_stream_begin(&s);
        ASSERT(zcl_det_stream_line(&s, "peer ingest + retention pruning...\n"));
        ASSERT(zcl_det_stream_line(&s, "consensus-view fold: modal tip...\n"));
        ASSERT(zcl_det_stream_finish(&s, digest, &count, &dangling));
        ASSERT_EQ(count, 0u);

        /* A complete line while a check is open drops the open one rather
         * than pairing it with the wrong result. */
        zcl_det_stream_begin(&s);
        ASSERT(zcl_det_stream_line(&s, "alpha... working\n"));
        ASSERT(zcl_det_stream_line(&s, "bravo... OK\n"));
        ASSERT(zcl_det_stream_finish(&s, digest, &count, &dangling));
        ASSERT_EQ(count, 1u);
        ASSERT_EQ(dangling, 1llu);

        ASSERT(!zcl_det_stream_line(NULL, "x"));
        ASSERT(!zcl_det_stream_line(&s, NULL));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. the line parser refuses to guess ──────────────────────────────────*/

static int test_parser_ignores_chatter(void)
{
    int failures = 0;
    TEST("check-line parser: only the four harness outcomes are verdicts") {
        struct zcl_det_check c;
        ASSERT(zcl_det_parse_check_line("thing... OK\n", &c));
        ASSERT_EQ((int)c.outcome, (int)ZCL_DET_OUTCOME_PASS);
        ASSERT_STR_EQ(c.name, "thing");

        ASSERT(zcl_det_parse_check_line("  indented... OK\n", &c));
        ASSERT_STR_EQ(c.name, "indented");

        ASSERT(zcl_det_parse_check_line(
            "t... FAIL at tests/harness/src/a.c:9 (x)\n", &c));
        ASSERT_EQ((int)c.outcome, (int)ZCL_DET_OUTCOME_FAIL);
        ASSERT_STR_EQ(c.locator, "tests/harness/src/a.c:9");

        ASSERT(zcl_det_parse_check_line("t... SKIP (needs a thing)\n", &c));
        ASSERT_EQ((int)c.outcome, (int)ZCL_DET_OUTCOME_SKIP);
        ASSERT(zcl_det_parse_check_line("t... UNOBSERVED (no mingw)\n", &c));
        ASSERT_EQ((int)c.outcome, (int)ZCL_DET_OUTCOME_UNOBSERVED);

        /* Chatter that must NOT be read as a verdict. Each of these appearing
         * in a vector would be a false accusation waiting to happen, because
         * the tail of each varies run to run. */
        ASSERT(!zcl_det_parse_check_line("elapsed... 12.4 ms\n", &c));
        ASSERT(!zcl_det_parse_check_line("loading... OKAY, moving on\n", &c));
        ASSERT(!zcl_det_parse_check_line("... OK\n", &c));
        ASSERT(!zcl_det_parse_check_line("no separator here OK\n", &c));
        ASSERT(!zcl_det_parse_check_line("dump\x01... OK\n", &c));
        ASSERT(!zcl_det_parse_check_line("", &c));

        /* A name that itself contains the separator keeps all of it. */
        ASSERT(zcl_det_parse_check_line("a... b... OK\n", &c));
        ASSERT_STR_EQ(c.name, "a... b");
        PASS();
    } _test_next:;
    return failures;
}

static int test_header_parser(void)
{
    int failures = 0;
    TEST("group-header parser: name and status, and nothing else accepted") {
        char g[ZCL_DET_GROUP_MAX];
        enum zcl_det_group_status st = ZCL_DET_GROUP_UNKNOWN;
        ASSERT(zcl_det_parse_group_header(
            "==================== test_foo (PASS, 3s) ====================\n",
            g, sizeof(g), &st));
        ASSERT_STR_EQ(g, "test_foo");
        ASSERT_EQ((int)st, (int)ZCL_DET_GROUP_PASS);
        ASSERT(zcl_det_parse_group_header(
            "==================== test_bar (FAIL, 2 SKIP, 3s) ====================\n",
            g, sizeof(g), &st));
        ASSERT_STR_EQ(g, "test_bar");
        ASSERT_EQ((int)st, (int)ZCL_DET_GROUP_FAIL);
        ASSERT(!zcl_det_parse_group_header("just some output\n", g, sizeof(g), &st));
        ASSERT(!zcl_det_parse_group_header("==================== nogap\n",
                                           g, sizeof(g), &st));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4. the buckets partition, exhaustively ───────────────────────────────*/

static int test_buckets_partition(void)
{
    int failures = 0;
    TEST("classification: exactly one bucket per group, over every observation shape") {
        const size_t n = 4;
        struct zcl_det_partition part = {0};
        size_t cases = 0;
        /* Slot 3 is the only SCHEDULING profile, so a split confined to it is
         * the one shape that may come back TIMING_SENSITIVE. Slots 1 and 2 are
         * REPEAT and ENVIRONMENT, and either of them in a split forces the
         * stronger NONDETERMINISTIC claim. */
        const enum zcl_det_perturbation order[4] = {
            ZCL_DET_P_BASE, ZCL_DET_P_BASE_REPEAT,
            ZCL_DET_P_CC_SET, ZCL_DET_P_LOAD_HIGH,
        };

        /* Every observed mask x every assignment of two distinct digests to
         * the observed slots x an empty/non-empty vector per slot. 2^4 masks
         * x 2^4 digest choices x 2^4 vector-presence choices = 4096 shapes. */
        for (unsigned mask = 0; mask < 16u; mask++) {
            for (unsigned dsel = 0; dsel < 16u; dsel++) {
                for (unsigned vsel = 0; vsel < 16u; vsel++) {
                    struct zcl_det_observation obs[4];
                    memset(obs, 0, sizeof(obs));
                    for (size_t i = 0; i < n; i++) {
                        obs[i].observed = (mask >> i) & 1u;
                        obs[i].check_count = ((vsel >> i) & 1u) ? 3u : 0u;
                        memset(obs[i].digest, ((dsel >> i) & 1u) ? 0xAA : 0x55,
                               ZCL_DET_DIGEST_LEN);
                    }
                    struct zcl_det_verdict v;
                    ASSERT(zcl_det_classify(obs, order, n, &v));
                    /* Exactly one bucket, always. */
                    int in_bucket =
                        (v.klass == ZCL_DET_CLASS_DETERMINISTIC) +
                        (v.klass == ZCL_DET_CLASS_NONDETERMINISTIC) +
                        (v.klass == ZCL_DET_CLASS_TIMING_SENSITIVE) +
                        (v.klass == ZCL_DET_CLASS_UNKNOWN);
                    ASSERT_EQ(in_bucket, 1);
                    /* UNKNOWN always carries a reason; the others never do. */
                    if (v.klass == ZCL_DET_CLASS_UNKNOWN)
                        ASSERT(v.reason != ZCL_DET_UNKNOWN_NONE);
                    else
                        ASSERT_EQ((int)v.reason, (int)ZCL_DET_UNKNOWN_NONE);
                    /* Exactly the two varying verdicts name a cause. */
                    const bool varies =
                        (v.klass == ZCL_DET_CLASS_NONDETERMINISTIC ||
                         v.klass == ZCL_DET_CLASS_TIMING_SENSITIVE);
                    if (varies)
                        ASSERT(v.split_mask != 0);
                    else
                        ASSERT_EQ(v.split_mask, 0u);
                    /* TIMING_SENSITIVE is earned ONLY when scheduling is the
                     * entire explanation. If any non-scheduling slot split,
                     * the verdict must be the stronger one. */
                    if (v.klass == ZCL_DET_CLASS_TIMING_SENSITIVE) {
                        for (size_t i = 1; i < n; i++) {
                            if (!(v.split_mask & ((uint32_t)1u << i))) continue;
                            ASSERT_EQ((int)zcl_det_perturbation_class(order[i]),
                                      (int)ZCL_DET_PC_SCHEDULING);
                        }
                    }
                    zcl_det_partition_add(&part, &v);
                    cases++;
                }
            }
        }
        ASSERT_EQ(cases, (size_t)4096);
        ASSERT_EQ(part.total, cases);
        ASSERT(zcl_det_partition_is_exact(&part));
        /* All four buckets are actually reachable, or the partition would be
         * trivially exact for the wrong reason. TIMING_SENSITIVE especially:
         * a rule that never fires would make the separation a comment. */
        ASSERT(part.deterministic > 0);
        ASSERT(part.nondeterministic > 0);
        ASSERT(part.timing_sensitive > 0);
        ASSERT(part.unknown_not_run > 0);
        ASSERT(part.unknown_partial > 0);
        ASSERT(part.unknown_no_vector > 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_unknown_is_never_folded(void)
{
    int failures = 0;
    TEST("classification: an unmeasured group is UNKNOWN, never DETERMINISTIC") {
        struct zcl_det_observation obs[3];
        struct zcl_det_verdict v;
        const enum zcl_det_perturbation ord[3] = {
            ZCL_DET_P_BASE, ZCL_DET_P_BASE_REPEAT, ZCL_DET_P_CC_SET,
        };

        memset(obs, 0, sizeof(obs));
        ASSERT(zcl_det_classify(obs, ord, 3, &v));
        ASSERT_EQ((int)v.klass, (int)ZCL_DET_CLASS_UNKNOWN);
        ASSERT_EQ((int)v.reason, (int)ZCL_DET_UNKNOWN_NOT_RUN);

        /* Ran everywhere, asserted nothing anywhere: an EXCLUSION that must be
         * named and counted, not quietly called clean. */
        memset(obs, 0, sizeof(obs));
        for (size_t i = 0; i < 3; i++) obs[i].observed = true;
        ASSERT(zcl_det_classify(obs, ord, 3, &v));
        ASSERT_EQ((int)v.klass, (int)ZCL_DET_CLASS_UNKNOWN);
        ASSERT_EQ((int)v.reason, (int)ZCL_DET_UNKNOWN_NO_VECTOR);

        /* Dispatched under some perturbations only. */
        memset(obs, 0, sizeof(obs));
        obs[0].observed = true; obs[0].check_count = 2;
        obs[2].observed = true; obs[2].check_count = 2;
        ASSERT(zcl_det_classify(obs, ord, 3, &v));
        ASSERT_EQ((int)v.klass, (int)ZCL_DET_CLASS_UNKNOWN);
        ASSERT_EQ((int)v.reason, (int)ZCL_DET_UNKNOWN_PARTIAL);

        /* Malformed calls are refused rather than answered. */
        ASSERT(!zcl_det_classify(NULL, ord, 3, &v));
        ASSERT(!zcl_det_classify(obs, NULL, 3, &v));
        ASSERT(!zcl_det_classify(obs, ord, 0, &v));
        ASSERT(!zcl_det_classify(obs, ord, 33, &v));

        /* Slot 0 must be BASE. Every split is stated as "differs from slot
         * 0", and if slot 0 is not the reference run that sentence is a
         * different claim, so this is refused rather than answered. */
        const enum zcl_det_perturbation bad[3] = {
            ZCL_DET_P_CC_SET, ZCL_DET_P_BASE, ZCL_DET_P_BASE_REPEAT,
        };
        ASSERT(!zcl_det_classify(obs, bad, 3, &v));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4b. TIMING_SENSITIVE is separated, not folded ────────────────────────
 *
 * The rule this pins down is the eligibility rule for carrying a receipt: a
 * group that only moves under load produces a different verdict vector on a
 * busier machine, so an honest re-runner REFUTES a receipt that was never
 * wrong. That population has to be visible on its own or the refutations look
 * like fraud. */
static int test_timing_sensitive_is_separated(void)
{
    int failures = 0;
    TEST("classification: load-only splits are TIMING_SENSITIVE, not NONDETERMINISTIC") {
        /* BASE, BASE_REPEAT, CC_SET, JOBS_LOW, LOAD_HIGH */
        const enum zcl_det_perturbation ord[5] = {
            ZCL_DET_P_BASE, ZCL_DET_P_BASE_REPEAT, ZCL_DET_P_CC_SET,
            ZCL_DET_P_JOBS_LOW, ZCL_DET_P_LOAD_HIGH,
        };
        struct zcl_det_observation obs[5];
        struct zcl_det_verdict v;

        /* Helper shape: everything observed, everything asserting, all
         * digests equal to BASE unless a slot is named below. */
        #define RESET_ALL_EQUAL()                                      \
            do {                                                       \
                memset(obs, 0, sizeof(obs));                           \
                for (size_t i = 0; i < 5; i++) {                       \
                    obs[i].observed = true;                            \
                    obs[i].check_count = 7;                            \
                    memset(obs[i].digest, 0x11, ZCL_DET_DIGEST_LEN);   \
                }                                                      \
            } while (0)

        /* Nothing moved. */
        RESET_ALL_EQUAL();
        ASSERT(zcl_det_classify(obs, ord, 5, &v));
        ASSERT_EQ((int)v.klass, (int)ZCL_DET_CLASS_DETERMINISTIC);
        ASSERT_EQ(v.split_mask, 0u);

        /* Only LOAD_HIGH moved: settled logic, clock-graded assertion. */
        RESET_ALL_EQUAL();
        memset(obs[4].digest, 0x22, ZCL_DET_DIGEST_LEN);
        ASSERT(zcl_det_classify(obs, ord, 5, &v));
        ASSERT_EQ((int)v.klass, (int)ZCL_DET_CLASS_TIMING_SENSITIVE);
        ASSERT_EQ(v.split_mask, 1u << 4);

        /* Both scheduling profiles moved: still scheduling alone. */
        RESET_ALL_EQUAL();
        memset(obs[3].digest, 0x22, ZCL_DET_DIGEST_LEN);
        memset(obs[4].digest, 0x33, ZCL_DET_DIGEST_LEN);
        ASSERT(zcl_det_classify(obs, ord, 5, &v));
        ASSERT_EQ((int)v.klass, (int)ZCL_DET_CLASS_TIMING_SENSITIVE);

        /* A plain re-run moved: internal, and no scheduling excuse. */
        RESET_ALL_EQUAL();
        memset(obs[1].digest, 0x22, ZCL_DET_DIGEST_LEN);
        ASSERT(zcl_det_classify(obs, ord, 5, &v));
        ASSERT_EQ((int)v.klass, (int)ZCL_DET_CLASS_NONDETERMINISTIC);

        /* The environment moved: internal. */
        RESET_ALL_EQUAL();
        memset(obs[2].digest, 0x22, ZCL_DET_DIGEST_LEN);
        ASSERT(zcl_det_classify(obs, ord, 5, &v));
        ASSERT_EQ((int)v.klass, (int)ZCL_DET_CLASS_NONDETERMINISTIC);

        /* THE ASYMMETRY. Scheduling AND something else both split. The weaker
         * TIMING_SENSITIVE verdict is an excuse ("your box was busy"), and a
         * group that also moves on a plain re-run has not earned it. One
         * non-scheduling slot outvotes any number of scheduling ones. */
        RESET_ALL_EQUAL();
        memset(obs[1].digest, 0x22, ZCL_DET_DIGEST_LEN);
        memset(obs[3].digest, 0x33, ZCL_DET_DIGEST_LEN);
        memset(obs[4].digest, 0x44, ZCL_DET_DIGEST_LEN);
        ASSERT(zcl_det_classify(obs, ord, 5, &v));
        ASSERT_EQ((int)v.klass, (int)ZCL_DET_CLASS_NONDETERMINISTIC);
        /* and the scheduling slots are still named in the cause */
        ASSERT(v.split_mask & (1u << 3));
        ASSERT(v.split_mask & (1u << 4));

        /* The two classes are distinct values with distinct names, so a
         * report cannot print one and mean the other. */
        ASSERT(ZCL_DET_CLASS_TIMING_SENSITIVE != ZCL_DET_CLASS_NONDETERMINISTIC);
        ASSERT(strcmp(zcl_det_class_name(ZCL_DET_CLASS_TIMING_SENSITIVE),
                      "TIMING_SENSITIVE") == 0);

        /* And the vocabulary itself: exactly the two scheduling profiles are
         * SCHEDULING, or the rule above would quietly change meaning. */
        ASSERT_EQ((int)zcl_det_perturbation_class(ZCL_DET_P_JOBS_LOW),
                  (int)ZCL_DET_PC_SCHEDULING);
        ASSERT_EQ((int)zcl_det_perturbation_class(ZCL_DET_P_LOAD_HIGH),
                  (int)ZCL_DET_PC_SCHEDULING);
        ASSERT_EQ((int)zcl_det_perturbation_class(ZCL_DET_P_BASE_REPEAT),
                  (int)ZCL_DET_PC_REPEAT);
        ASSERT_EQ((int)zcl_det_perturbation_class(ZCL_DET_P_BASE),
                  (int)ZCL_DET_PC_REFERENCE);
        for (int i = 0; i < ZCL_DET_P__COUNT; i++) {
            enum zcl_det_perturbation p = (enum zcl_det_perturbation)i;
            if (p == ZCL_DET_P_JOBS_LOW || p == ZCL_DET_P_LOAD_HIGH) continue;
            ASSERT(zcl_det_perturbation_class(p) != ZCL_DET_PC_SCHEDULING);
        }
        #undef RESET_ALL_EQUAL
        PASS();
    } _test_next:;
    return failures;
}

/* ── 5. end to end: caught, and not falsely accused ───────────────────────*/

static int test_end_to_end_env_sensitivity(void)
{
    int failures = 0;
    TEST("end to end: an env-reading fixture is caught and a stable one is not accused") {
        struct fixture f;
        struct zcl_det_observation nd[3];
        struct zcl_det_observation ok[3];
        struct zcl_det_group_digest g;
        memset(nd, 0, sizeof(nd));
        memset(ok, 0, sizeof(ok));

        /* Three genuinely different environments, applied for real. */
        static const char *const values[3] = { NULL, "/x/build/bin/zcc gcc",
                                               NULL };
        for (int i = 0; i < 3; i++) {
            if (values[i]) {
                ASSERT_EQ(setenv("ZCL_DET_FIXTURE_CC", values[i], 1), 0);
            } else {
                (void)unsetenv("ZCL_DET_FIXTURE_CC");
            }

            emit_env_sensitive(&f);
            ASSERT(digest_of(&f, &g));
            nd[i].observed = true;
            nd[i].check_count = g.check_count;
            memcpy(nd[i].digest, g.digest, ZCL_DET_DIGEST_LEN);

            emit_deterministic(&f, i + 1);
            ASSERT(digest_of(&f, &g));
            ok[i].observed = true;
            ok[i].check_count = g.check_count;
            memcpy(ok[i].digest, g.digest, ZCL_DET_DIGEST_LEN);
        }
        (void)unsetenv("ZCL_DET_FIXTURE_CC");

        struct zcl_det_verdict v_nd, v_ok;
        const enum zcl_det_perturbation e2e[3] = {
            ZCL_DET_P_BASE, ZCL_DET_P_CC_SET, ZCL_DET_P_CC_UNSET,
        };
        ASSERT(zcl_det_classify(nd, e2e, 3, &v_nd));
        ASSERT(zcl_det_classify(ok, e2e, 3, &v_ok));

        /* CAUGHT: slot 1 had CC set and asserted one more check. */
        ASSERT_EQ((int)v_nd.klass, (int)ZCL_DET_CLASS_NONDETERMINISTIC);
        ASSERT_EQ(v_nd.split_mask, 1u << 1);
        /* And slot 2, which restored the base environment, agrees with BASE —
         * so the tool blames the perturbation that actually split it and not
         * every profile after it. */
        ASSERT((v_nd.split_mask & (1u << 2)) == 0);

        /* NOT ACCUSED: the stable fixture, measured under the very same three
         * environments, with a transcript that differed in every run. */
        ASSERT_EQ((int)v_ok.klass, (int)ZCL_DET_CLASS_DETERMINISTIC);
        ASSERT_EQ(v_ok.split_mask, 0u);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6. the receipt ───────────────────────────────────────────────────────*/

static void fill_receipt(struct zcl_det_receipt *r)
{
    memset(r, 0, sizeof(*r));
    r->version = ZCL_DET_RECEIPT_VERSION;
    (void)zcl_det_receipt_set_commit(
        r, "0123456789abcdef0123456789abcdef01234567");
    snprintf(r->group, sizeof(r->group), "test_determinism");
    zcl_det_receipt_label_digest("gcc-13/glibc-2.39/x86_64", r->toolchain);
    zcl_det_receipt_label_digest("gate:jobs=8", r->env_class);
    r->verdict = ZCL_DET_CLASS_DETERMINISTIC;
    r->reason = ZCL_DET_UNKNOWN_NONE;
    r->perturbations = 8;
    r->split_mask = 0;
    r->check_count = 41;
    for (size_t i = 0; i < ZCL_DET_DIGEST_LEN; i++) {
        r->vector[i] = (uint8_t)(i * 7u + 3u);
        r->producer[i] = (uint8_t)(0xA0u ^ i);
    }
}

static int test_receipt_roundtrip(void)
{
    int failures = 0;
    TEST("receipt: fixed-layout encode/decode round-trips exactly") {
        struct zcl_det_receipt r, back;
        fill_receipt(&r);
        uint8_t wire[ZCL_DET_RECEIPT_SIZE];
        size_t len = 0;
        ASSERT(zcl_det_receipt_encode(&r, wire, sizeof(wire), &len));
        ASSERT_EQ(len, (size_t)ZCL_DET_RECEIPT_SIZE);
        ASSERT(zcl_det_receipt_decode(wire, len, &back));
        ASSERT_EQ(back.version, r.version);
        ASSERT_STR_EQ(back.group, r.group);
        ASSERT_EQ(back.verdict, r.verdict);
        ASSERT_EQ(back.reason, r.reason);
        ASSERT_EQ(back.perturbations, r.perturbations);
        ASSERT_EQ(back.split_mask, r.split_mask);
        ASSERT_EQ(back.check_count, r.check_count);
        ASSERT(memcmp(back.commit, r.commit, sizeof(r.commit)) == 0);
        ASSERT(memcmp(back.vector, r.vector, sizeof(r.vector)) == 0);
        ASSERT(memcmp(back.producer, r.producer, sizeof(r.producer)) == 0);
        ASSERT(memcmp(back.toolchain, r.toolchain, sizeof(r.toolchain)) == 0);
        ASSERT(memcmp(back.env_class, r.env_class, sizeof(r.env_class)) == 0);

        /* Re-encoding the decoded record must reproduce the same bytes: the
         * encoding is canonical, so no receipt has two spellings. */
        uint8_t again[ZCL_DET_RECEIPT_SIZE];
        size_t len2 = 0;
        ASSERT(zcl_det_receipt_encode(&back, again, sizeof(again), &len2));
        ASSERT_EQ(len2, len);
        ASSERT(memcmp(wire, again, len) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_receipt_golden_bytes(void)
{
    int failures = 0;
    TEST("receipt: the wire layout is pinned to a golden vector") {
        struct zcl_det_receipt r;
        fill_receipt(&r);
        uint8_t wire[ZCL_DET_RECEIPT_SIZE];
        size_t len = 0;
        ASSERT(zcl_det_receipt_encode(&r, wire, sizeof(wire), &len));
        /* The header the layout pins: magic, version, commit, group field. If
         * a field is added, moved or resized, this fails and the version must
         * be bumped — which is the point of pinning it. */
        static const uint8_t want_head[] = {
            'Z', 'D', 'R', '1', 0x01, 0x00,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        };
        ASSERT(memcmp(wire, want_head, sizeof(want_head)) == 0);
        ASSERT(memcmp(wire + 38, "test_determinism", 16) == 0);
        for (size_t i = 38 + 16; i < 38 + ZCL_DET_GROUP_MAX; i++)
            ASSERT_EQ(wire[i], 0);
        /* No padding byte anywhere: every byte of the record was written by an
         * explicit field, so the sum of the field widths IS the size. */
        ASSERT_EQ((size_t)ZCL_DET_RECEIPT_SIZE,
                  (size_t)(4 + 2 + ZCL_DET_RECEIPT_COMMIT_LEN +
                           ZCL_DET_GROUP_MAX + ZCL_DET_DIGEST_LEN +
                           ZCL_DET_DIGEST_LEN + 1 + 1 + 2 + 4 + 4 +
                           ZCL_DET_DIGEST_LEN + ZCL_DET_DIGEST_LEN));
        PASS();
    } _test_next:;
    return failures;
}

static int test_receipt_rejects(void)
{
    int failures = 0;
    TEST("receipt: a malformed record is refused, never half-read") {
        struct zcl_det_receipt r, back;
        fill_receipt(&r);
        uint8_t wire[ZCL_DET_RECEIPT_SIZE + 1];
        size_t len = 0;
        ASSERT(zcl_det_receipt_encode(&r, wire, ZCL_DET_RECEIPT_SIZE, &len));

        /* Truncation at every cut. */
        for (size_t cut = 0; cut < len; cut++)
            ASSERT(!zcl_det_receipt_decode(wire, cut, &back));
        /* A trailing byte. */
        wire[len] = 0x00;
        ASSERT(!zcl_det_receipt_decode(wire, len + 1, &back));

        uint8_t bad[ZCL_DET_RECEIPT_SIZE];
        memcpy(bad, wire, ZCL_DET_RECEIPT_SIZE);
        bad[0] = 'X';
        ASSERT(!zcl_det_receipt_decode(bad, ZCL_DET_RECEIPT_SIZE, &back));

        memcpy(bad, wire, ZCL_DET_RECEIPT_SIZE);
        bad[4] = 0x02; /* an unsupported version */
        ASSERT(!zcl_det_receipt_decode(bad, ZCL_DET_RECEIPT_SIZE, &back));

        memcpy(bad, wire, ZCL_DET_RECEIPT_SIZE);
        bad[38 + ZCL_DET_GROUP_MAX - 1] = 'z'; /* non-canonical group padding */
        ASSERT(!zcl_det_receipt_decode(bad, ZCL_DET_RECEIPT_SIZE, &back));

        memcpy(bad, wire, ZCL_DET_RECEIPT_SIZE);
        bad[38] = 0x00; /* an empty group id */
        ASSERT(!zcl_det_receipt_decode(bad, ZCL_DET_RECEIPT_SIZE, &back));

        memcpy(bad, wire, ZCL_DET_RECEIPT_SIZE);
        bad[198] = 9; /* a verdict outside the enum */
        ASSERT(!zcl_det_receipt_decode(bad, ZCL_DET_RECEIPT_SIZE, &back));

        /* A DETERMINISTIC record that also names a splitting perturbation says
         * two things at once, and is refused. */
        struct zcl_det_receipt contradictory = r;
        contradictory.split_mask = 4u;
        ASSERT(zcl_det_receipt_encode(&contradictory, bad, sizeof(bad), &len));
        ASSERT(!zcl_det_receipt_decode(bad, len, &back));

        /* A NONDETERMINISTIC record that names none is the "it varies" answer
         * this whole module refuses to accept. */
        struct zcl_det_receipt causeless = r;
        causeless.verdict = ZCL_DET_CLASS_NONDETERMINISTIC;
        causeless.split_mask = 0;
        ASSERT(zcl_det_receipt_encode(&causeless, bad, sizeof(bad), &len));
        ASSERT(!zcl_det_receipt_decode(bad, len, &back));

        /* TIMING_SENSITIVE is a real verdict and obeys the same rule in both
         * directions: it must name a cause, and it round-trips when it does.
         * A verdict the encoding refuses to carry could not be reported. */
        struct zcl_det_receipt ts_causeless = r;
        ts_causeless.verdict = ZCL_DET_CLASS_TIMING_SENSITIVE;
        ts_causeless.split_mask = 0;
        ASSERT(zcl_det_receipt_encode(&ts_causeless, bad, sizeof(bad), &len));
        ASSERT(!zcl_det_receipt_decode(bad, len, &back));

        struct zcl_det_receipt ts_ok = r;
        ts_ok.verdict = ZCL_DET_CLASS_TIMING_SENSITIVE;
        ts_ok.split_mask = 1u << ZCL_DET_P_LOAD_HIGH;
        ASSERT(zcl_det_receipt_encode(&ts_ok, bad, sizeof(bad), &len));
        ASSERT(zcl_det_receipt_decode(bad, len, &back));
        ASSERT_EQ((int)back.verdict, (int)ZCL_DET_CLASS_TIMING_SENSITIVE);
        ASSERT_EQ(back.split_mask, 1u << ZCL_DET_P_LOAD_HIGH);

        /* 5 is one past the widened range and must still be refused, so the
         * range check tracks the enum rather than being left permanently open. */
        memcpy(bad, wire, ZCL_DET_RECEIPT_SIZE);
        bad[198] = 5;
        ASSERT(!zcl_det_receipt_decode(bad, ZCL_DET_RECEIPT_SIZE, &back));

        /* An UNKNOWN record with no reason, and a measured record carrying
         * one, are both self-contradictory. */
        struct zcl_det_receipt reasonless = r;
        reasonless.verdict = ZCL_DET_CLASS_UNKNOWN;
        reasonless.reason = ZCL_DET_UNKNOWN_NONE;
        ASSERT(zcl_det_receipt_encode(&reasonless, bad, sizeof(bad), &len));
        ASSERT(!zcl_det_receipt_decode(bad, len, &back));

        struct zcl_det_receipt overexplained = r;
        overexplained.reason = ZCL_DET_UNKNOWN_NOT_RUN;
        ASSERT(zcl_det_receipt_encode(&overexplained, bad, sizeof(bad), &len));
        ASSERT(!zcl_det_receipt_decode(bad, len, &back));

        /* A commit id of the wrong width is refused rather than truncated. */
        struct zcl_det_receipt c;
        fill_receipt(&c);
        ASSERT(!zcl_det_receipt_set_commit(&c, "abc"));
        ASSERT(!zcl_det_receipt_set_commit(&c, ""));
        PASS();
    } _test_next:;
    return failures;
}

static int test_receipt_verification(void)
{
    int failures = 0;
    TEST("receipt check: CORROBORATED / REFUTED / UNKNOWN, and UNKNOWN is never a default") {
        struct zcl_det_receipt claim, fresh;
        char why[160];
        fill_receipt(&claim);

        fresh = claim;
        ASSERT_EQ((int)zcl_det_receipt_check(&claim, &fresh, why, sizeof(why)),
                  (int)ZCL_DET_CORROBORATED);

        /* Same commit and toolchain, a different verdict vector: refuted. */
        fresh = claim;
        fresh.vector[0] ^= 0xFF;
        ASSERT_EQ((int)zcl_det_receipt_check(&claim, &fresh, why, sizeof(why)),
                  (int)ZCL_DET_REFUTED);

        /* A different commit says nothing about the claim. It must NOT refute
         * it and must NOT confirm it. */
        fresh = claim;
        ASSERT(zcl_det_receipt_set_commit(
            &fresh, "ffffffffffffffffffffffffffffffffffffffff"));
        fresh.vector[0] ^= 0xFF;
        ASSERT_EQ((int)zcl_det_receipt_check(&claim, &fresh, why, sizeof(why)),
                  (int)ZCL_DET_INDETERMINATE);

        /* A different toolchain, likewise. */
        fresh = claim;
        zcl_det_receipt_label_digest("clang-18/musl/aarch64", fresh.toolchain);
        ASSERT_EQ((int)zcl_det_receipt_check(&claim, &fresh, why, sizeof(why)),
                  (int)ZCL_DET_INDETERMINATE);

        /* A different environment class, likewise. */
        fresh = claim;
        zcl_det_receipt_label_digest("gate:jobs=1", fresh.env_class);
        ASSERT_EQ((int)zcl_det_receipt_check(&claim, &fresh, why, sizeof(why)),
                  (int)ZCL_DET_INDETERMINATE);

        /* A fresh run that could not be measured neither confirms nor refutes. */
        fresh = claim;
        fresh.verdict = ZCL_DET_CLASS_UNKNOWN;
        fresh.reason = ZCL_DET_UNKNOWN_NOT_RUN;
        ASSERT_EQ((int)zcl_det_receipt_check(&claim, &fresh, why, sizeof(why)),
                  (int)ZCL_DET_INDETERMINATE);

        /* A DIFFERENCE THAT IS ALREADY EXPLAINED IS NOT EVIDENCE.
         *
         * This is the case the whole TIMING_SENSITIVE bucket exists for. The
         * group is known to answer differently when the machine's load
         * differs; load is a property of the moment, so neither side's
         * environment class can pin it. An honest node re-running on a busier
         * box therefore computes a different vector — and if that came back
         * REFUTED, the network would manufacture an accusation against a
         * producer who did nothing wrong and could offer nothing in reply.
         * Reserve REFUTED for a disagreement about something reproducible. */
        fresh = claim;
        fresh.verdict = ZCL_DET_CLASS_TIMING_SENSITIVE;
        fresh.split_mask = 1u << ZCL_DET_P_LOAD_HIGH;
        fresh.vector[0] ^= 0xFF;
        ASSERT_EQ((int)zcl_det_receipt_check(&claim, &fresh, why, sizeof(why)),
                  (int)ZCL_DET_INDETERMINATE);

        /* Symmetric: it holds whichever side carries the verdict. */
        struct zcl_det_receipt ts_claim = claim;
        ts_claim.verdict = ZCL_DET_CLASS_TIMING_SENSITIVE;
        ts_claim.split_mask = 1u << ZCL_DET_P_JOBS_LOW;
        fresh = ts_claim;
        fresh.vector[0] ^= 0xFF;
        ASSERT_EQ((int)zcl_det_receipt_check(&ts_claim, &fresh, why, sizeof(why)),
                  (int)ZCL_DET_INDETERMINATE);

        /* But two TIMING_SENSITIVE runs that DID agree still corroborate —
         * the rule above softens a disagreement, it does not discard an
         * agreement. */
        fresh = ts_claim;
        ASSERT_EQ((int)zcl_det_receipt_check(&ts_claim, &fresh, why, sizeof(why)),
                  (int)ZCL_DET_CORROBORATED);

        /* And the softening is SPECIFIC to that verdict: a plain
         * NONDETERMINISTIC disagreement is still a refutation, or the rule
         * would have quietly disabled refutation altogether. */
        struct zcl_det_receipt nd_claim = claim;
        nd_claim.verdict = ZCL_DET_CLASS_NONDETERMINISTIC;
        nd_claim.split_mask = 1u << ZCL_DET_P_CC_SET;
        fresh = nd_claim;
        fresh.vector[0] ^= 0xFF;
        ASSERT_EQ((int)zcl_det_receipt_check(&nd_claim, &fresh, why, sizeof(why)),
                  (int)ZCL_DET_REFUTED);

        /* Different groups are not comparable at all. */
        fresh = claim;
        snprintf(fresh.group, sizeof(fresh.group), "test_other");
        ASSERT_EQ((int)zcl_det_receipt_check(&claim, &fresh, why, sizeof(why)),
                  (int)ZCL_DET_INDETERMINATE);

        /* And an absent receipt is never silently treated as agreement. */
        ASSERT_EQ((int)zcl_det_receipt_check(&claim, NULL, why, sizeof(why)),
                  (int)ZCL_DET_INDETERMINATE);
        ASSERT_EQ((int)zcl_det_receipt_check(NULL, &claim, why, sizeof(why)),
                  (int)ZCL_DET_INDETERMINATE);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 7. the perturbation vocabulary is total ──────────────────────────────*/

static int test_perturbation_names(void)
{
    int failures = 0;
    TEST("perturbations: every id has a distinct name that round-trips") {
        for (int i = 0; i < ZCL_DET_P__COUNT; i++) {
            const char *name =
                zcl_det_perturbation_name((enum zcl_det_perturbation)i);
            ASSERT(name[0] != '\0');
            /* A split must name a CAUSE, not just a label. */
            ASSERT(strlen(zcl_det_perturbation_why(
                       (enum zcl_det_perturbation)i)) > 8);
            enum zcl_det_perturbation back = ZCL_DET_P__COUNT;
            ASSERT(zcl_det_perturbation_from_name(name, &back));
            ASSERT_EQ((int)back, i);
            for (int j = 0; j < i; j++)
                ASSERT(strcmp(name, zcl_det_perturbation_name(
                                        (enum zcl_det_perturbation)j)) != 0);
        }
        enum zcl_det_perturbation p;
        ASSERT(!zcl_det_perturbation_from_name("VIBES", &p));
        ASSERT(!zcl_det_perturbation_from_name(NULL, &p));

        /* A split mask is rendered through the CALLER's profile order, not the
         * enum's. A measurement over a subset would otherwise print the wrong
         * cause, and a wrong cause is worse than no cause. */
        static const enum zcl_det_perturbation order[3] = {
            ZCL_DET_P_BASE, ZCL_DET_P_ENV_PAD, ZCL_DET_P_CC_SET
        };
        char cause[64];
        zcl_det_split_mask_string(0x6u, order, 3, cause, sizeof(cause));
        ASSERT_STR_EQ(cause, "ENV_PAD+CC_SET");
        zcl_det_split_mask_string(0x4u, order, 3, cause, sizeof(cause));
        ASSERT_STR_EQ(cause, "CC_SET");
        zcl_det_split_mask_string(0u, order, 3, cause, sizeof(cause));
        ASSERT_STR_EQ(cause, "");
        /* Too small a buffer truncates rather than overruns. */
        char tiny[4];
        zcl_det_split_mask_string(0x6u, order, 3, tiny, sizeof(tiny));
        ASSERT_STR_EQ(tiny, "");

        /* BASE must be index 0: the classifier compares every other profile
         * against slot 0, and a renumbering would silently change what
         * "the reference run" means. */
        ASSERT_EQ((int)ZCL_DET_P_BASE, 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_determinism(void)
{
    return test_vector_detects_the_three_failures() +
           test_no_false_accusation() +
           test_outcome_on_a_later_line() +
           test_stream_refuses_to_guess() +
           test_failure_values_are_excluded() +
           test_parser_ignores_chatter() +
           test_header_parser() +
           test_buckets_partition() +
           test_timing_sensitive_is_separated() +
           test_unknown_is_never_folded() +
           test_end_to_end_env_sensitivity() +
           test_receipt_roundtrip() +
           test_receipt_golden_bytes() +
           test_receipt_rejects() +
           test_receipt_verification() +
           test_perturbation_names();
}
