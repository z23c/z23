/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_kpi — the cognition/modules/kpi gate.
 *
 * The module exists to make ONE claim that nothing else in this tree makes:
 * a number nobody could read and a number that honestly measured zero are
 * DIFFERENT FACTS, and the ledger keeps them apart all the way down to the
 * bytes on disk. Everything below is arranged around proving that, because a
 * test that only checked rendered strings would pass on an encoder that had
 * quietly collapsed the two.
 *
 *  1. CANONICAL MEANS BYTE-IDENTICAL. The same metric set encodes to the same
 *     bytes twice, and changing any single value changes them. If it did not,
 *     two frames could not be compared with a memcmp and the ledger's whole
 *     premise — that a frame is a fingerprint of a measurement — is gone.
 *
 *  2. UNAVAILABLE != 0, ON DISK. The same metric encoded UNAVAILABLE and
 *     encoded PRESENT-with-value-0 must produce different bytes, and must
 *     survive a decode still distinguishable. This is the assertion the whole
 *     module is built around, so it is checked directly rather than inferred
 *     from a rendered field.
 *
 *  3. A BASELINE IS THE PRIOR FRAME, NOT THIS ONE. Two appends to a temp
 *     ledger must leave the second run reading the FIRST run's values as
 *     `previous`. Reading after appending would make every run its own
 *     baseline and every delta zero — a ledger that reports a tree which
 *     never changes.
 *
 *  4. A FIRST RUN IS no_baseline, NEVER unchanged. "Equal to nothing" is not
 *     a measurement, and calling it unchanged would report a first run as a
 *     run in which nothing moved.
 *
 *  5. A MISSING ARTIFACT IS UNAVAILABLE, AND THE FRAME IS STILL WRITTEN. The
 *     unavailability is itself the fact being recorded; a run that refused to
 *     record it would leave a gap indistinguishable from a run nobody made.
 *
 *  6. DIRECTION IS RESPECTED. The same movement — a number going down — is
 *     `improved` for a LOWER_IS_BETTER metric and `regressed` for a
 *     HIGHER_IS_BETTER one. A verdict that ignored direction would grade
 *     deleting tests as progress.
 *
 * Every ledger here lives under this test's own temp directory. The real
 * .codeindex/kpi.chainlog is never opened: a gate that appended to the
 * developer's ledger would be writing the history it is supposed to audit.
 */

#include "test/test_core.h"

#include "kpi/kpi.h"

#include <stdio.h>
#include <string.h>

#define KPI_CHECK(name, expr)                                      \
    do {                                                           \
        const bool kpi_ok_ = (expr);                               \
        if (!kpi_ok_) failures++;                                  \
        printf("kpi: %s %s\n", kpi_ok_ ? "OK  " : "FAIL", (name)); \
    } while (0)

/* A frame built by hand, so the assertions below do not depend on any
 * artifact existing. */
static void frame_seed(struct kpi_frame *f)
{
    memset(f, 0, sizeof *f);
    for (int i = 0; i < 32; i++)
        f->source_root_sha3[i] = (uint8_t)(0x10 + i);
    f->count = 3;
    snprintf(f->metric[0].id, sizeof f->metric[0].id, "alpha");
    f->metric[0].state = KPI_STATE_PRESENT;
    f->metric[0].value = 7;
    snprintf(f->metric[1].id, sizeof f->metric[1].id, "beta");
    f->metric[1].state = KPI_STATE_PRESENT;
    f->metric[1].value = 0;
    snprintf(f->metric[2].id, sizeof f->metric[2].id, "gamma");
    f->metric[2].state = KPI_STATE_PRESENT;
    f->metric[2].value = 100;
}

static struct kpi_entry entry_of(const char *id, enum kpi_state s, uint64_t v)
{
    struct kpi_entry e;
    memset(&e, 0, sizeof e);
    snprintf(e.id, sizeof e.id, "%s", id);
    e.state = s;
    e.value = v;
    return e;
}

/* ── 1. the metric table is what the encoding assumes it is ────────── */

static int case_table(void)
{
    int failures = 0;
    size_t n = 0;
    const struct kpi_metric_def *d = kpi_metric_defs(&n);

    KPI_CHECK("the table is non-empty and fits a frame",
              d != NULL && n > 0 && n <= KPI_METRIC_MAX);

    /* The canonical payload's field order IS this order. A table that stopped
     * being sorted would change the bytes for unchanged values and break every
     * comparison against an older frame, silently. */
    bool sorted = true, named = true, drilled = true;
    for (size_t i = 0; i < n; i++) {
        if (i > 0 && strcmp(d[i - 1].id, d[i].id) >= 0) sorted = false;
        if (!d[i].id || !d[i].id[0] || strlen(d[i].id) >= KPI_ID_MAX)
            named = false;
        if (!d[i].drill || !d[i].drill[0]) drilled = false;
    }
    KPI_CHECK("every metric id is sorted and strictly unique", sorted);
    KPI_CHECK("every metric id is non-empty and fits the field", named);
    /* A number nobody can drill into is a number nobody can act on. */
    KPI_CHECK("every metric names a drill-down command", drilled);

    KPI_CHECK("ids resolve back to their definition",
              kpi_metric_def_by_id(d[0].id) == &d[0] &&
                  kpi_metric_def_by_id("no_such_metric") == NULL &&
                  kpi_metric_def_by_id(NULL) == NULL);

    KPI_CHECK("the whole table fits one payload",
              (size_t)(32 + 4) + n * (1 + KPI_ID_MAX + 1 + 8) <=
                  KPI_PAYLOAD_MAX);

    KPI_CHECK("every label names itself",
              strcmp(kpi_verdict_label(KPI_VERDICT_NO_BASELINE),
                     "no_baseline") == 0 &&
                  strcmp(kpi_state_label(KPI_STATE_UNAVAILABLE),
                         "unavailable") == 0 &&
                  strcmp(kpi_direction_label(KPI_DIRECTION_LOWER_IS_BETTER),
                         "LOWER_IS_BETTER") == 0 &&
                  strcmp(kpi_verdict_label((enum kpi_verdict)77),
                         "unknown_verdict") == 0);
    return failures;
}

/* ── 2. canonical bytes ────────────────────────────────────────────── */

static int case_canonical_bytes(void)
{
    int failures = 0;
    struct kpi_frame a, b;
    frame_seed(&a);
    frame_seed(&b);

    uint8_t ba[KPI_PAYLOAD_MAX], bb[KPI_PAYLOAD_MAX];
    size_t la = kpi_encode(&a, ba, sizeof ba);
    size_t lb = kpi_encode(&b, bb, sizeof bb);
    KPI_CHECK("an identical metric set encodes to identical bytes",
              la > 0 && la == lb && memcmp(ba, bb, la) == 0);

    /* The size is a pure function of the ids, so it is stated rather than
     * read back from the encoder it is supposed to check. */
    size_t want = 32 + 4 + (1 + 5 + 1 + 8) + (1 + 4 + 1 + 8) + (1 + 5 + 1 + 8);
    KPI_CHECK("the payload is exactly the declared layout", la == want);

    b.metric[1].value = 1;
    lb = kpi_encode(&b, bb, sizeof bb);
    KPI_CHECK("changing ONE value changes the bytes",
              lb == la && memcmp(ba, bb, la) != 0);

    /* The tree a frame measured is part of the frame. Two identical metric
     * sets over different trees are not the same measurement. */
    frame_seed(&b);
    b.source_root_sha3[0] ^= 0xFF;
    lb = kpi_encode(&b, bb, sizeof bb);
    KPI_CHECK("changing the source root changes the bytes",
              lb == la && memcmp(ba, bb, la) != 0);

    struct kpi_frame back;
    memset(&back, 0, sizeof back);
    KPI_CHECK("a frame decodes to itself",
              kpi_decode(ba, la, &back) && back.count == a.count &&
                  memcmp(back.source_root_sha3, a.source_root_sha3, 32) == 0 &&
                  strcmp(back.metric[2].id, "gamma") == 0 &&
                  back.metric[2].value == 100 &&
                  back.metric[1].state == KPI_STATE_PRESENT &&
                  back.metric[1].value == 0);

    KPI_CHECK("a truncated payload is refused, not half-read",
              !kpi_decode(ba, la - 1, &back));
    uint8_t longer[KPI_PAYLOAD_MAX];
    memcpy(longer, ba, la);
    longer[la] = 0;
    KPI_CHECK("trailing bytes are refused", !kpi_decode(longer, la + 1, &back));
    KPI_CHECK("a buffer too small yields no bytes rather than a short frame",
              kpi_encode(&a, ba, la - 1) == 0);

    /* An unavailable metric carries no number. A frame claiming both is
     * self-contradictory and must be refused rather than half-believed. */
    uint8_t bad[KPI_PAYLOAD_MAX];
    memcpy(bad, ba, la);
    bad[32 + 4 + 1 + 5] = (uint8_t)KPI_STATE_UNAVAILABLE; /* alpha -> unavail */
    KPI_CHECK("an unavailable metric carrying a value is refused",
              !kpi_decode(bad, la, &back));
    memcpy(bad, ba, la);
    bad[32 + 4 + 1 + 5] = 9; /* an unknown state byte */
    KPI_CHECK("an unknown state byte is refused", !kpi_decode(bad, la, &back));
    return failures;
}

/* ── 3. UNAVAILABLE is not zero, on disk ───────────────────────────── */

static int case_unavailable_is_not_zero(void)
{
    int failures = 0;
    struct kpi_frame zero, unavail;
    frame_seed(&zero);
    frame_seed(&unavail);

    /* metric[1] ("beta") already measured a genuine 0. Make the other frame's
     * beta UNAVAILABLE and nothing else. */
    unavail.metric[1].state = KPI_STATE_UNAVAILABLE;
    unavail.metric[1].value = 0;

    uint8_t bz[KPI_PAYLOAD_MAX], bu[KPI_PAYLOAD_MAX];
    size_t lz = kpi_encode(&zero, bz, sizeof bz);
    size_t lu = kpi_encode(&unavail, bu, sizeof bu);
    KPI_CHECK("both encode", lz > 0 && lu > 0 && lz == lu);
    /* THE assertion this module exists for. */
    KPI_CHECK("an unavailable metric encodes DIFFERENTLY from a measured 0",
              memcmp(bz, bu, lz) != 0);

    struct kpi_frame rz, ru;
    KPI_CHECK("both decode", kpi_decode(bz, lz, &rz) && kpi_decode(bu, lu, &ru));
    KPI_CHECK("and stay distinguishable after a round trip",
              rz.metric[1].state == KPI_STATE_PRESENT &&
                  ru.metric[1].state == KPI_STATE_UNAVAILABLE &&
                  rz.metric[1].value == 0 && ru.metric[1].value == 0);

    /* An unavailable metric must never carry a stale number into the log:
     * a value nobody read would decode as a measurement nobody took. */
    struct kpi_frame stale;
    frame_seed(&stale);
    stale.metric[0].state = KPI_STATE_UNAVAILABLE;
    stale.metric[0].value = 7; /* the value it HAD when it was readable */
    uint8_t bs[KPI_PAYLOAD_MAX];
    size_t ls = kpi_encode(&stale, bs, sizeof bs);
    struct kpi_frame rs;
    KPI_CHECK("an unavailable metric's stale value is zeroed by the encoder",
              ls == lz && kpi_decode(bs, ls, &rs) &&
                  rs.metric[0].state == KPI_STATE_UNAVAILABLE &&
                  rs.metric[0].value == 0);

    KPI_CHECK("an unavailable current reading is never given a verdict",
              kpi_verdict_of(KPI_DIRECTION_LOWER_IS_BETTER, NULL,
                             &ru.metric[1]) == KPI_VERDICT_UNAVAILABLE);

    /* A baseline nobody could read is not a baseline. Comparing against it
     * would invent a delta out of an absence. */
    struct kpi_entry prev = entry_of("beta", KPI_STATE_UNAVAILABLE, 0);
    struct kpi_entry cur = entry_of("beta", KPI_STATE_PRESENT, 5);
    KPI_CHECK("an unavailable BASELINE is no_baseline, not a delta from 0",
              kpi_verdict_of(KPI_DIRECTION_LOWER_IS_BETTER, &prev, &cur) ==
                  KPI_VERDICT_NO_BASELINE);
    return failures;
}

/* ── 4. direction decides the verdict ──────────────────────────────── */

static int case_direction(void)
{
    int failures = 0;
    struct kpi_entry was = entry_of("m", KPI_STATE_PRESENT, 10);
    struct kpi_entry down = entry_of("m", KPI_STATE_PRESENT, 4);
    struct kpi_entry up = entry_of("m", KPI_STATE_PRESENT, 11);
    struct kpi_entry same = entry_of("m", KPI_STATE_PRESENT, 10);

    KPI_CHECK("LOWER_IS_BETTER going down is improved",
              kpi_verdict_of(KPI_DIRECTION_LOWER_IS_BETTER, &was, &down) ==
                  KPI_VERDICT_IMPROVED);
    KPI_CHECK("LOWER_IS_BETTER going up is regressed",
              kpi_verdict_of(KPI_DIRECTION_LOWER_IS_BETTER, &was, &up) ==
                  KPI_VERDICT_REGRESSED);
    /* Deleting tests is not progress. */
    KPI_CHECK("HIGHER_IS_BETTER going down is regressed",
              kpi_verdict_of(KPI_DIRECTION_HIGHER_IS_BETTER, &was, &down) ==
                  KPI_VERDICT_REGRESSED);
    KPI_CHECK("HIGHER_IS_BETTER going up is improved",
              kpi_verdict_of(KPI_DIRECTION_HIGHER_IS_BETTER, &was, &up) ==
                  KPI_VERDICT_IMPROVED);
    /* A neutral metric that moved has changed, and that is all anyone can
     * honestly say; scoring it either way would manufacture a verdict. */
    KPI_CHECK("NEUTRAL is never graded either way",
              kpi_verdict_of(KPI_DIRECTION_NEUTRAL, &was, &down) ==
                      KPI_VERDICT_UNCHANGED &&
                  kpi_verdict_of(KPI_DIRECTION_NEUTRAL, &was, &up) ==
                      KPI_VERDICT_UNCHANGED);
    KPI_CHECK("an equal value is unchanged in every direction",
              kpi_verdict_of(KPI_DIRECTION_LOWER_IS_BETTER, &was, &same) ==
                      KPI_VERDICT_UNCHANGED &&
                  kpi_verdict_of(KPI_DIRECTION_HIGHER_IS_BETTER, &was, &same) ==
                      KPI_VERDICT_UNCHANGED);
    /* The first run of all: never unchanged. */
    KPI_CHECK("no prior entry is no_baseline, NOT unchanged",
              kpi_verdict_of(KPI_DIRECTION_HIGHER_IS_BETTER, NULL, &same) ==
                  KPI_VERDICT_NO_BASELINE);
    return failures;
}

/* ── 5. the ledger: the baseline is the PRIOR frame ────────────────── */

static int case_ledger_previous(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "kpi", "ledger");
    char path[640];
    snprintf(path, sizeof path, "%s/kpi.chainlog", dir);

    struct kpi_frame first;
    frame_seed(&first);

    struct kpi_ledger_result r1;
    memset(&r1, 0, sizeof r1);
    KPI_CHECK("the first append succeeds",
              kpi_ledger_record(path, &first, &r1) && r1.wrote && r1.seq == 1);
    /* A first run has no history to be measured against, and must say so. */
    KPI_CHECK("the first run has no previous frame",
              !r1.have_previous && r1.prior_records == 0);

    const struct kpi_entry *c0 = kpi_frame_find(&first, "alpha");
    KPI_CHECK("the first run's verdict is no_baseline, not unchanged",
              c0 != NULL &&
                  kpi_verdict_of(KPI_DIRECTION_HIGHER_IS_BETTER, NULL, c0) ==
                      KPI_VERDICT_NO_BASELINE);

    struct kpi_frame second;
    frame_seed(&second);
    second.metric[0].value = 9;   /* alpha 7 -> 9 */
    second.metric[2].value = 90;  /* gamma 100 -> 90 */

    struct kpi_ledger_result r2;
    memset(&r2, 0, sizeof r2);
    KPI_CHECK("the second append succeeds",
              kpi_ledger_record(path, &second, &r2) && r2.wrote && r2.seq == 2);
    /* The baseline must be the frame that already existed, never the one this
     * run just wrote — otherwise every delta is zero forever. */
    KPI_CHECK("the second run's previous IS the first run's frame",
              r2.have_previous && r2.prior_records == 1 &&
                  r2.previous.count == first.count &&
                  memcmp(r2.previous.source_root_sha3, first.source_root_sha3,
                         32) == 0);

    const struct kpi_entry *p_alpha = kpi_frame_find(&r2.previous, "alpha");
    const struct kpi_entry *p_gamma = kpi_frame_find(&r2.previous, "gamma");
    KPI_CHECK("previous carries the first run's values",
              p_alpha && p_alpha->value == 7 && p_gamma && p_gamma->value == 100);
    KPI_CHECK("a metric absent from the log is not invented",
              kpi_frame_find(&r2.previous, "delta") == NULL);

    const struct kpi_entry *c_alpha = kpi_frame_find(&second, "alpha");
    const struct kpi_entry *c_gamma = kpi_frame_find(&second, "gamma");
    KPI_CHECK("the deltas are graded against the prior frame",
              kpi_verdict_of(KPI_DIRECTION_HIGHER_IS_BETTER, p_alpha,
                             c_alpha) == KPI_VERDICT_IMPROVED &&
                  kpi_verdict_of(KPI_DIRECTION_LOWER_IS_BETTER, p_gamma,
                                 c_gamma) == KPI_VERDICT_IMPROVED);

    /* The log is a chainlog, so an auditor can walk it without touching it. */
    uint8_t stream[32];
    kpi_stream_id(stream);
    struct zcl_chainlog_report rep;
    memset(&rep, 0, sizeof rep);
    KPI_CHECK("the ledger verifies as an intact chain of two frames",
              zcl_chainlog_verify(path, stream, &rep) == ZCL_CHAINLOG_OK &&
                  rep.records == 2);

    /* A kpi frame may not be appended to somebody else's history. */
    uint8_t other[32];
    memset(other, 0x5A, sizeof other);
    memset(&rep, 0, sizeof rep);
    KPI_CHECK("the log is bound to the kpi stream",
              zcl_chainlog_verify(path, other, &rep) ==
                  ZCL_CHAINLOG_STREAM_MISMATCH);

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 6. a missing artifact is UNAVAILABLE, and still writes a frame ── */

static int case_missing_artifact(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "kpi", "missing");

    /* An empty directory is a checkout with none of the artifacts in it, which
     * is the honest shape of "I could not look" — not a tree measuring zero. */
    struct kpi_frame f;
    kpi_collect(dir, NULL, &f);

    size_t n = 0;
    (void)kpi_metric_defs(&n);
    KPI_CHECK("collection still fills the whole metric set",
              f.count == (uint32_t)n);

    bool all_unavailable = true, all_zero_valued = true;
    for (uint32_t i = 0; i < f.count; i++) {
        if (f.metric[i].state != KPI_STATE_UNAVAILABLE) all_unavailable = false;
        if (f.metric[i].value != 0) all_zero_valued = false;
    }
    KPI_CHECK("every metric with no artifact is UNAVAILABLE, not 0",
              all_unavailable && all_zero_valued);

    /* With no verified index handle the tree is UNKNOWN, and all-zero is the
     * unambiguous way to say so: codeindex never yields an all-zero root. */
    uint8_t zero_root[32] = { 0 };
    KPI_CHECK("an unmeasured tree leaves an all-zero source root",
              memcmp(f.source_root_sha3, zero_root, 32) == 0);

    /* The unavailability is itself the fact being recorded, so the run must
     * still write. A run that refused would leave a gap in the history that
     * is indistinguishable from a run nobody made. */
    char path[640];
    snprintf(path, sizeof path, "%s/kpi.chainlog", dir);
    struct kpi_ledger_result r;
    memset(&r, 0, sizeof r);
    KPI_CHECK("an all-unavailable run STILL writes its frame",
              kpi_ledger_record(path, &f, &r) && r.wrote && r.seq == 1);

    struct kpi_ledger_result r2;
    memset(&r2, 0, sizeof r2);
    KPI_CHECK("and the unavailable state survives into the next run's baseline",
              kpi_ledger_record(path, &f, &r2) && r2.have_previous &&
                  r2.previous.count == f.count &&
                  r2.previous.metric[0].state == KPI_STATE_UNAVAILABLE);

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 7. the parsers refuse rather than report zero ─────────────────── */

static bool spill(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

static int case_parsers(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "kpi", "parse");
    char path[640];
    uint64_t n = 0;

    KPI_CHECK("a missing file is never a zero",
              !kpi_count_jsonl_records("/nonexistent/kpi.jsonl", "capability",
                                       &n, NULL) &&
                  !kpi_count_test_groups("/nonexistent/kpi.def", &n) &&
                  !kpi_count_lint_gates("/nonexistent/Makefile", &n) &&
                  !kpi_count_baseline_rows("/nonexistent/base.txt", &n));

    /* JSONL: a file with records but none of the requested kind is an honest
     * 0; a file with no records at all is a shape we did not recognise. */
    snprintf(path, sizeof path, "%s/inv.jsonl", dir);
    KPI_CHECK("a jsonl fixture writes",
              spill(path, "{\"record\":\"inventory\",\"capabilities\":3}\n"
                          "{\"record\":\"capability\",\"a\":1}\n"
                          "{\"record\":\"duplicate\",\"a\":2}\n"
                          "{\"record\":\"capability\",\"a\":3}\n"));
    uint64_t total = 0;
    KPI_CHECK("records of one kind are counted",
              kpi_count_jsonl_records(path, "capability", &n, &total) &&
                  n == 2 && total == 4);
    KPI_CHECK("a kind with no rows in a real records file is an honest 0",
              kpi_count_jsonl_records(path, "untested_invariant", &n, NULL) &&
                  n == 0);
    KPI_CHECK("a file with no record fields at all is UNAVAILABLE, not 0",
              spill(path, "not a records file\n") &&
                  !kpi_count_jsonl_records(path, "capability", &n, NULL));

    /* The catalog: prose that names the macro is documentation, not a row.
     * Both registry macros count, because both are rows the drill-down command
     * (`test_parallel --list`) prints. */
    snprintf(path, sizeof path, "%s/catalog.def", dir);
    KPI_CHECK("a catalog fixture writes",
              spill(path, "/* Include with ZCL_TEST_GROUP(name) defined. */\n"
                          "ZCL_TEST_GROUP(one)\n"
                          "ZCL_SPEC_GROUP(spec_one)\n"
                          "not_a_row ZCL_TEST_GROUP(inline)\n"
                          "ZCL_TEST_GROUP(two)\n"));
    KPI_CHECK("only rows count, not prose that names the macro",
              kpi_count_test_groups(path, &n) && n == 3);
    KPI_CHECK("a catalog with no rows is UNAVAILABLE, not 0",
              spill(path, "/* nothing registered */\n") &&
                  !kpi_count_test_groups(path, &n));

    /* LINT_GATES: a backslash-continued list, and only at column zero. */
    snprintf(path, sizeof path, "%s/Makefile", dir);
    KPI_CHECK("a makefile fixture writes",
              spill(path, "# LINT_GATES is the source of truth\n"
                          "ZCL_LINT_GATES := decoy\n"
                          "LINT_GATES := \\\n"
                          "    check-one \\\n"
                          "    check-two check-three \\\n"
                          "    check-four\n"
                          "other: ;\n"));
    KPI_CHECK("the continued gate list is counted, decoys are not",
              kpi_count_lint_gates(path, &n) && n == 4);
    KPI_CHECK("a Makefile with no LINT_GATES is UNAVAILABLE, not 0",
              spill(path, "all: ;\n") && !kpi_count_lint_gates(path, &n));

    /* The ratchet baseline is the ONE source where 0 is a real answer. */
    snprintf(path, sizeof path, "%s/baseline.txt", dir);
    KPI_CHECK("a baseline fixture writes",
              spill(path, "# a comment\n\n  # an indented comment\n"
                          "group_a NONDETERMINISTIC BASE_REPEAT\n"
                          "group_b TIMING_SENSITIVE CC_SET\n"));
    KPI_CHECK("only non-comment rows count",
              kpi_count_baseline_rows(path, &n) && n == 2);
    KPI_CHECK("an EMPTY ratchet is an honest 0, not UNAVAILABLE",
              spill(path, "# nothing owed\n") &&
                  kpi_count_baseline_rows(path, &n) && n == 0);

    test_cleanup_tmpdir(dir);
    return failures;
}

int test_kpi(void);
int test_kpi(void)
{
    int failures = 0;
    failures += case_table();
    failures += case_canonical_bytes();
    failures += case_unavailable_is_not_zero();
    failures += case_direction();
    failures += case_ledger_previous();
    failures += case_missing_artifact();
    failures += case_parsers();
    printf("kpi: %d failure(s)\n", failures);
    return failures;
}
