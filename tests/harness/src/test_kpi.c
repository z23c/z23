/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_kpi — the cognition/modules/kpi gate.
 *
 * Proves the ledger keeps "unavailable" and "measured zero" distinct down to
 * the bytes on disk: canonical encoding is byte-identical, UNAVAILABLE != 0
 * after decode, the baseline is the prior frame (first run is no_baseline),
 * a missing artifact still writes a frame, and direction decides the verdict.
 * Ledgers live under this test's temp directory; the real .codeindex/kpi.chainlog
 * is never opened.
 */

#include "test/test_core.h"

#include "kpi/kpi.h"

#include <stdio.h>
#include <sys/stat.h>
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

/* One pass over the table rows, setting *sorted, *named and *drilled to
 * whether every id is sorted and strictly unique, non-empty and short
 * enough for its field, and backed by a drill-down command. */
static void scan_metric_table_rows(const struct kpi_metric_def *d, size_t n,
                                   bool *sorted, bool *named, bool *drilled)
{
    *sorted = true;
    *named = true;
    *drilled = true;
    for (size_t i = 0; i < n; i++) {
        if (i > 0 && strcmp(d[i - 1].id, d[i].id) >= 0) *sorted = false;
        if (!d[i].id || !d[i].id[0] || strlen(d[i].id) >= KPI_ID_MAX)
            *named = false;
        if (!d[i].drill || !d[i].drill[0]) *drilled = false;
    }
}

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
    bool sorted, named, drilled;
    scan_metric_table_rows(d, n, &sorted, &named, &drilled);
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

/* ── 8. groups ─────────────────────────────────────────────────────── */

static int case_group_names(void)
{
    int failures = 0;
    uint32_t m = 0;
    KPI_CHECK("no name and 'all' mean every group",
              kpi_group_parse(NULL, &m) && m == KPI_GROUP_ALL &&
                  kpi_group_parse("", &m) && m == KPI_GROUP_ALL &&
                  kpi_group_parse("all", &m) && m == KPI_GROUP_ALL);
    KPI_CHECK("each group name selects its own bit",
              kpi_group_parse("cmd", &m) && m == KPI_GROUP_CMD &&
                  kpi_group_parse("code", &m) && m == KPI_GROUP_CODE &&
                  kpi_group_parse("docs", &m) && m == KPI_GROUP_DOCS);
    KPI_CHECK("an unknown group is refused", !kpi_group_parse("nope", &m));
    return failures;
}

static int case_group_of_ids(void)
{
    int failures = 0;
    KPI_CHECK("dotted prefixes pick the group",
              kpi_metric_group("cmd.leaves") == KPI_GROUP_CMD &&
                  kpi_metric_group("docs.orphans") == KPI_GROUP_DOCS &&
                  kpi_metric_group("code.size_debt") == KPI_GROUP_CODE);
    KPI_CHECK("an id without a prefix belongs to code",
              kpi_metric_group("lint_gates") == KPI_GROUP_CODE);
    KPI_CHECK("percent math is whole hundredths and 0 over 0",
              kpi_pct_hundredths(4, 7) == 5714 &&
                  kpi_pct_hundredths(7, 7) == 10000 &&
                  kpi_pct_hundredths(3, 0) == 0);
    return failures;
}

/* The pre-existing ids are unchanged, so an older ledger still compares. */
static int case_legacy_ids(void)
{
    static const char *const k_ids[] = {
        "capabilities", "determinism_debt", "duplicate_candidates",
        "files_owned", "lint_gates", "territories", "test_groups",
        "untested_invariants" };
    bool all = true;
    for (size_t i = 0; i < sizeof k_ids / sizeof k_ids[0]; i++)
        if (!kpi_metric_def_by_id(k_ids[i]))
            all = false;
    int failures = 0;
    KPI_CHECK("the original metric ids are still defined", all);
    return failures;
}

/* ── 9. the command scoreboard, on a fixture catalog ───────────────── */

static bool fixture_put(const char *dir, const char *rel, const char *text)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, rel);
    for (char *p = path + strlen(dir) + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        (void)mkdir(path, 0700);
        *p = '/';
    }
    return spill(path, text);
}

/* The first 12 arguments every leaf macro shares, then filler up to `total`,
 * with `handler` at index `h` (-1: none). */
static void leaf_row(char *out, size_t cap, const char *macro, const char *path,
                     const char *summary, const char *example, int total, int h,
                     const char *handler)
{
    int n = snprintf(out, cap,
                     "%s(\n    \"%s\", \"x\", \"\",\n    \"%s\",\n    \"sem\", 0,"
                     " \"tag\", \"in\", \"out\", \"\", \"\",\n    \"%s\"",
                     macro, path, summary, example);
    for (int i = 12; i < total && (size_t)n < cap; i++)
        n += snprintf(out + n, cap - (size_t)n, ",%s%s", i % 4 == 0 ? "\n    " : " ",
                      i == h ? handler : "FILL");
    snprintf(out + n, cap - (size_t)n, ")\n");
}

static void fixture_defs(const char *dir)
{
    char row[1024], all[8192] = "";
    struct { const char *m, *p, *s, *e; int total, h; const char *hd; } r[] = {
        { "ZCL_COMMAND_READY_READ", "x.one", "S", "z23 x one", 22, 21, "h_one" },
        { "ZCL_COMMAND_READY_READ", "x.two", "", "z23 x two", 22, 21, "h_two" },
        { "ZCL_COMMAND_READY_READ", "x.nul", "S", "e", 22, 21, "NULL" },
        { "ZCL_COMMAND_PLANNED_READ", "x.plan", "S", "e", 20, -1, "" },
        { "ZCL_COMMAND_COMPAT_READ", "x.compat", "S", "", 21, -1, "" },
        { "ZCL_COMMAND_DEV_READ", "x.dev", "S", "e", 22, 19, "h_dev" },
        { "ZCL_COMMAND_READY_READ", "x.paren", "a (b, c)", "e", 22, 21, "h_p" },
    };
    strcat(all, "ZCL_COMMAND_BRANCH(\"x\", \"\", \"Branch\", LAYER)\n");
    strcat(all, "/* ZCL_COMMAND_READY_READ( inside a comment is skipped */\n");
    for (size_t i = 0; i < sizeof r / sizeof r[0]; i++) {
        leaf_row(row, sizeof row, r[i].m, r[i].p, r[i].s, r[i].e, r[i].total,
                 r[i].h, r[i].hd);
        strcat(all, row);
    }
    fixture_put(dir, "engine/composition/commands/catalog.def", "#include \"x.def\"\n");
    fixture_put(dir, "engine/composition/commands/x.def", all);
}

static void fixture_tests(const char *dir)
{
    fixture_put(dir, "tests/harness/src/t1.c",
        "// \"x.paren\" in a line comment is not a reference\n"
        "/* \"x.dev\" in a block comment is not one either */\n"
        "int x_dev = 1; /* x.dev as bare text */\n"
        "const char *a = \"x.one\";\n"
        "const char *b = \"z23 x two --flag\";\n"
        "const char *c = \"x.paren.sub\";\n"
        "const char *d = \"x.one.deeper\";\n");
}

static int case_cmd_scoreboard(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "kpi", "cmd");
    fixture_defs(dir);

    struct kpi_cmd_stats s;
    KPI_CHECK("a catalog without test sources still scans",
              kpi_cmd_scan(dir, &s) && !s.have_tested);
    KPI_CHECK("leaves are READY, PLANNED and COMPAT rows; branches and comments "
              "are not", s.leaves == 7);
    KPI_CHECK("ready needs a handler: NULL and PLANNED/COMPAT rows are not "
              "ready, a dev row with a handler is", s.ready == 4);
    KPI_CHECK("help needs both a summary and an example", s.help == 5);

    fixture_tests(dir);
    KPI_CHECK("tested counts dotted and spaced mentions in string literals "
              "only, never a longer path or a comment",
              kpi_cmd_scan(dir, &s) && s.have_tested && s.tested == 2);

    struct kpi_frame f;
    kpi_collect_files(dir, KPI_GROUP_CMD, &f);
    const struct kpi_entry *leaves = kpi_frame_find(&f, "cmd.leaves");
    const struct kpi_entry *ready = kpi_frame_find(&f, "cmd.ready_pct");
    const struct kpi_entry *help = kpi_frame_find(&f, "cmd.help_pct");
    const struct kpi_entry *tested = kpi_frame_find(&f, "cmd.tested");
    KPI_CHECK("the frame carries the four cmd metrics",
              leaves && leaves->state == KPI_STATE_PRESENT &&
                  leaves->value == 7 && ready && ready->value == 5714 &&
                  help && help->value == 7142 && tested && tested->value == 2);

    (void)test_rm_rf_recursive(dir);
    return failures;
}

/* ── 10. the file-backed metrics, groups and UNAVAILABLE ───────────── */

static int case_tree_metrics(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "kpi", "tree");
    fixture_defs(dir);
    fixture_put(dir, "tools/lint/bash_allowlist.txt", "# header\na.sh\nb.sh\nc.sh\n");
    fixture_put(dir, "tools/lint/file_size_policy_baseline.txt",
        "# header\nsrc/a.c 1600\nsrc/b.c 1700\n");
    fixture_put(dir, "tools/lint/orphan_placement_baseline.txt", "# nothing owed\n");

    struct kpi_frame f;
    kpi_collect_files(dir, KPI_GROUP_ALL, &f);
    const struct kpi_entry *bash = kpi_frame_find(&f, "code.shell_scripts");
    const struct kpi_entry *size = kpi_frame_find(&f, "code.size_debt");
    const struct kpi_entry *orph = kpi_frame_find(&f, "docs.orphans");
    KPI_CHECK("bash scripts and size debt count their rows",
              bash && bash->state == KPI_STATE_PRESENT && bash->value == 3 &&
                  size && size->state == KPI_STATE_PRESENT && size->value == 2);
    KPI_CHECK("an empty orphan baseline is an honest 0, not UNAVAILABLE",
              orph && orph->state == KPI_STATE_PRESENT && orph->value == 0);
    const struct kpi_entry *no_cmd_tests = kpi_frame_find(&f, "cmd.tested");
    KPI_CHECK("without test sources cmd.tested is UNAVAILABLE while the other "
              "cmd metrics are measured",
              no_cmd_tests && no_cmd_tests->state == KPI_STATE_UNAVAILABLE &&
                  kpi_frame_find(&f, "cmd.leaves")->state == KPI_STATE_PRESENT);
    KPI_CHECK("a metric whose artifact is absent stays UNAVAILABLE, value 0",
              kpi_frame_find(&f, "capabilities")->state ==
                      KPI_STATE_UNAVAILABLE &&
                  kpi_frame_find(&f, "capabilities")->value == 0);

    kpi_collect_files(dir, KPI_GROUP_DOCS, &f);
    KPI_CHECK("a group mask measures only that group",
              kpi_frame_find(&f, "docs.orphans")->state == KPI_STATE_PRESENT &&
                  kpi_frame_find(&f, "cmd.leaves")->state ==
                      KPI_STATE_UNAVAILABLE &&
                  kpi_frame_find(&f, "code.shell_scripts")->state ==
                      KPI_STATE_UNAVAILABLE);

    uint8_t buf[KPI_PAYLOAD_MAX];
    KPI_CHECK("a full frame of the grown table encodes within one payload",
              (kpi_collect_files(dir, KPI_GROUP_ALL, &f), true) &&
                  kpi_encode(&f, buf, sizeof buf) > 0);
    (void)test_rm_rf_recursive(dir);
    return failures;
}

/* ── 11. read-only mode appends nothing ────────────────────────────── */

static bool slurp_file(const char *path, char *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    *len = fread(buf, 1, cap, f);
    bool ok = ferror(f) == 0;
    fclose(f);
    return ok;
}

static int case_peek_missing(const char *dir)
{
    int failures = 0;
    char path[640];
    snprintf(path, sizeof path, "%s/absent.chainlog", dir);
    struct kpi_ledger_result r;
    struct stat st;
    KPI_CHECK("peeking a ledger that does not exist succeeds with no baseline",
              kpi_ledger_peek(path, &r) && !r.have_previous && !r.wrote &&
                  r.prior_records == 0);
    KPI_CHECK("and does not create it", stat(path, &st) != 0);
    return failures;
}

static int case_peek_existing(const char *dir)
{
    int failures = 0;
    char path[640];
    snprintf(path, sizeof path, "%s/kpi.chainlog", dir);
    struct kpi_frame a;
    frame_seed(&a);
    struct kpi_ledger_result r;
    KPI_CHECK("one frame is recorded",
              kpi_ledger_record(path, &a, &r) && r.seq == 1);

    static char before[1 << 16], after[1 << 16];
    size_t nb = 0, na = 0;
    KPI_CHECK("the ledger reads back for comparison",
              slurp_file(path, before, sizeof before, &nb) && nb > 0);
    KPI_CHECK("a peek returns the newest frame as the baseline",
              kpi_ledger_peek(path, &r) && r.have_previous && !r.wrote &&
                  r.seq == 0 && r.prior_records == 1);
    KPI_CHECK("the baseline carries the recorded values",
              kpi_frame_find(&r.previous, "gamma") &&
                  kpi_frame_find(&r.previous, "gamma")->value == 100);
    KPI_CHECK("peeking twice still leaves the ledger byte-identical",
              kpi_ledger_peek(path, &r) &&
                  slurp_file(path, after, sizeof after, &na) && na == nb &&
                  memcmp(before, after, nb) == 0);
    return failures;
}

static int case_peek_foreign(const char *dir)
{
    int failures = 0;
    char other[640];
    snprintf(other, sizeof other, "%s/other.chainlog", dir);
    struct kpi_ledger_result r;
    KPI_CHECK("a file that is not a chainlog is refused, not read as empty",
              spill(other, "not a chainlog at all, but long enough to read\n"
                           "0123456789012345678901234567890123456789012345\n") &&
                  !kpi_ledger_peek(other, &r));
    return failures;
}

static int case_read_only_ledger(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "kpi", "peek");
    failures += case_peek_missing(dir);
    failures += case_peek_existing(dir);
    failures += case_peek_foreign(dir);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 12. the floor: loading, and one step worse ────────────────────── */

static int case_floor_loads(const char *path)
{
    int failures = 0;
    unsigned bad = 0;
    struct kpi_floor fl;
    KPI_CHECK("comments, blanks and trailing comments load",
              spill(path, "# header\n\ncmd.tested 7\ncode.size_debt 2 # why\n") &&
                  kpi_floor_load(path, &fl, &bad) && fl.count == 2 &&
                  fl.value[0] == 7 && fl.value[1] == 2);
    KPI_CHECK("a missing floor file is refused",
              !kpi_floor_load("/nonexistent/kpi_floor.txt", &fl, &bad) &&
                  bad == 0);
    return failures;
}

static bool floor_refused(const char *path, const char *text, unsigned line)
{
    struct kpi_floor fl;
    unsigned bad = 0;
    return spill(path, text) && !kpi_floor_load(path, &fl, &bad) && bad == line;
}

static int case_floor_refusals(const char *path)
{
    int failures = 0;
    KPI_CHECK("an unknown metric is refused with its line",
              floor_refused(path, "# h\nno.such 1\n", 2));
    KPI_CHECK("a neutral metric cannot be floored",
              floor_refused(path, "capabilities 1\n", 1));
    KPI_CHECK("command, lint-gate and test-group counts are neutral and cannot be floored",
              floor_refused(path, "cmd.leaves 1\n", 1) &&
                  floor_refused(path, "lint_gates 1\n", 1) &&
                  floor_refused(path, "test_groups 1\n", 1));
    KPI_CHECK("a duplicate row is refused",
              floor_refused(path, "cmd.tested 1\ncmd.tested 2\n", 2));
    KPI_CHECK("a non-numeric value is refused",
              floor_refused(path, "cmd.tested x\n", 1));
    KPI_CHECK("a negative value is refused",
              floor_refused(path, "cmd.tested -1\n", 1));
    KPI_CHECK("a row without a value is refused",
              floor_refused(path, "cmd.tested\n", 1));
    return failures;
}

/* Equal passes; one step worse in the declared direction fails. */
static int case_floor_steps(const char *path)
{
    int failures = 0;
    struct kpi_floor fl;
    unsigned bad = 0;
    struct kpi_frame f;
    memset(&f, 0, sizeof f);
    f.count = 2;
    f.metric[0] = entry_of("cmd.tested", KPI_STATE_PRESENT, 7);       /* up */
    f.metric[1] = entry_of("code.size_debt", KPI_STATE_PRESENT, 2);   /* down */
    struct kpi_miss miss[4];
    KPI_CHECK("metrics exactly at their floor pass",
              spill(path, "cmd.tested 7\ncode.size_debt 2\n") &&
                  kpi_floor_load(path, &fl, &bad) &&
                  kpi_floor_check(&fl, &f, miss, 4) == 0);
    f.metric[0].value = 8;
    f.metric[1].value = 1;
    KPI_CHECK("better than the floor passes",
              kpi_floor_check(&fl, &f, miss, 4) == 0);
    f.metric[0].value = 6;
    size_t n = kpi_floor_check(&fl, &f, miss, 4);
    KPI_CHECK("a higher-is-better metric one step down fails, naming it",
              n == 1 && strcmp(miss[0].def->id, "cmd.tested") == 0 &&
                  miss[0].kind == KPI_MISS_WORSE && miss[0].floor == 7 &&
                  miss[0].current == 6);
    f.metric[0].value = 7;
    f.metric[1].value = 3;
    n = kpi_floor_check(&fl, &f, miss, 4);
    KPI_CHECK("a lower-is-better metric one step up fails, naming it",
              n == 1 && strcmp(miss[0].def->id, "code.size_debt") == 0 &&
                  miss[0].current == 3 && miss[0].floor == 2);
    return failures;
}

static int case_floor_unmeasured(const char *path)
{
    int failures = 0;
    struct kpi_floor fl;
    unsigned bad = 0;
    struct kpi_frame f;
    memset(&f, 0, sizeof f);
    f.count = 2;
    f.metric[0] = entry_of("cmd.tested", KPI_STATE_PRESENT, 7);
    f.metric[1] = entry_of("code.size_debt", KPI_STATE_UNAVAILABLE, 0);
    struct kpi_miss miss[4];
    KPI_CHECK("a floored metric that cannot be measured fails, not passes",
              spill(path, "cmd.tested 7\ncode.size_debt 2\n") &&
                  kpi_floor_load(path, &fl, &bad) &&
                  kpi_floor_check(&fl, &f, miss, 4) == 1 &&
                  miss[0].kind == KPI_MISS_UNAVAILABLE);
    f.count = 1;
    KPI_CHECK("a floored metric absent from the frame fails",
              kpi_floor_check(&fl, &f, miss, 4) == 1);
    return failures;
}

static int case_floor(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "kpi", "floor");
    char path[640];
    snprintf(path, sizeof path, "%s/kpi_floor.txt", dir);
    failures += case_floor_loads(path);
    failures += case_floor_refusals(path);
    failures += case_floor_steps(path);
    failures += case_floor_unmeasured(path);
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
    failures += case_group_names();
    failures += case_group_of_ids();
    failures += case_legacy_ids();
    failures += case_cmd_scoreboard();
    failures += case_tree_metrics();
    failures += case_read_only_ledger();
    failures += case_floor();
    printf("kpi: %d failure(s)\n", failures);
    return failures;
}
