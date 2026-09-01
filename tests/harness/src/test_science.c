/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_science — the cognition/modules/science gate.
 *
 * The module's whole value is a set of refusals and one derivation, so this
 * file is mostly attempts to get something dishonest into the register and
 * the named refusal that comes back.
 *
 *  1. A CLAIM WITHOUT A FALSIFIER DOES NOT GET IN. One case per missing
 *     field, each asserting the refusal NAMES the field. A refusal that said
 *     only "invalid" would leave a caller guessing, and a caller who guesses
 *     eventually deletes the check.
 *
 *  2. A ZERO FLOOR IS REFUSED, NOT ACCEPTED. effect_floor = 0 and
 *     sample_floor = 0 look rigorous and are not: with them the claim can
 *     never come back INCONCLUSIVE, so nothing could ever count against it.
 *
 *  3. THE METRIC SET IS CLOSED. "vibes", "" and a near-miss spelling are all
 *     refused by name; every enum member round-trips through its name. A
 *     free-text metric is how an impression enters a register dressed as a
 *     measurement.
 *
 *  4. THE SAMPLE FLOOR COMES BEFORE THE EFFECT. Three trials that look
 *     enormous are UNTESTED. This is the load-bearing check in the file: it
 *     is the one that stops the register becoming a rumour mill, and it is
 *     asserted with a deliberately lopsided fixture so that a bug which read
 *     the effect first would produce SUPPORTED here.
 *
 *  5. SUPPORTED, REFUTED AND INCONCLUSIVE ARE ALL REACHABLE. A register that
 *     has never refuted anything has not been shown to work, so REFUTED is
 *     driven in both directions (a claim that says "up" met by a fall, and a
 *     claim that says "down" met by a rise).
 *
 *  6. THERE IS NO WAY TO SET A STATUS. Asserted against the header text: no
 *     declared function takes an `enum science_status`, and no name in the
 *     public surface contains "set_status". Structural, so it stays true when
 *     someone adds an API in a hurry.
 *
 *  7. ONE PRODUCER IS VISIBLY NOT FIVE. Two claims with identical arithmetic
 *     and different producer sets must read as different facts.
 *
 *  8. CANONICAL BYTES ARE CANONICAL. Identical content gives identical bytes;
 *     changing ANY field changes them. Without that, "these trials survived a
 *     reopen" and "the chainlog head means something" are both empty.
 *
 *  9. IT SURVIVES A CLOSE AND REOPEN. Evidence a restart forgets is not
 *     evidence.
 *
 * 10. THE CORPUS REPORT REFUSES TO FLATTER. No inventory means "not
 *     measured", never "zero duplicates"; a stale inventory is announced
 *     rather than divided into a current line count.
 */

#include "test/test_core.h"

#include "base/safe_alloc.h"
#include "platform/directory_compat.h"
#include "science/science_claim.h"
#include "science/science_corpus.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SC_CHECK(name, expr)                                        \
    do {                                                            \
        const bool sc_ok_ = (expr);                                 \
        if (!sc_ok_) failures++;                                    \
        printf("science: %s %s\n", sc_ok_ ? "OK  " : "FAIL", (name)); \
    } while (0)

/* A claim that IS complete, used as the base every refusal case damages in
 * exactly one place. */
static struct science_claim_spec good_spec(void)
{
    return (struct science_claim_spec){
        .statement = "giving the model the territory brief raises the "
                     "first-try gate pass rate",
        .treatment = "territory brief pasted into the prompt preamble",
        .metric = SCIENCE_METRIC_VERDICT_PASS_RATE,
        .direction = SCIENCE_DIRECTION_UP,
        .effect_floor_milli = 100, /* ten percentage points */
        .sample_floor = 5,
    };
}

/* A complete reproduction block: what a stranger with only this repo needs.
 * Every field is required, so the fixture supplies every field. */
static struct science_repro repro(void)
{
    return (struct science_repro){
        .command = "build/bin/test_parallel --exact=test_science",
        .commit = "0000000000000000000000000000000000000000",
        .input = "fixture:test_science",
        .compiler = "fixture-cc 1.0.0",
        .optimisation = "-O2",
        .nproc = 32,
        .stress_tests = false,
    };
}

/* An observation with n and the order statistics, not a bare summary. */
static struct science_samples observed(uint32_t n)
{
    return (struct science_samples){
        .availability = SCIENCE_OBSERVED,
        .unit = "ms",
        .n = n,
        .min_milli = 6900,
        .median_milli = 7031,
        .p95_milli = 7400,
        .max_milli = 7900,
    };
}

static struct science_receipt receipt(const char *producer,
                                      enum science_arm arm,
                                      enum engine_verdict verdict)
{
    return (struct science_receipt){
        .producer = producer,
        .arm = arm,
        .engine = "fixture",
        .model = "fixture-model",
        .territory = "cognition/modules/science",
        .group = "science",
        .files_changed = 3,
        .groups_ran = 1,
        .groups_failed = verdict == ENGINE_VERDICT_PASS ? 0 : 1,
        .cached = false,
        .prompt_tokens = 1000,
        .completion_tokens = 2000,
        .verdict = verdict,
        .repro = repro(),
        .observed = observed(9),
    };
}

/* The same, with the two numbers the metrics actually read set explicitly. */
static struct science_receipt trial(const char *producer, enum science_arm arm,
                                    enum engine_verdict verdict,
                                    uint32_t files, int64_t completion)
{
    struct science_receipt r = receipt(producer, arm, verdict);
    r.files_changed = files;
    r.completion_tokens = completion;
    return r;
}

static struct science_register *open_fresh(char *dir, size_t dirn,
                                           const char *tag, char *path,
                                           size_t pathn)
{
    test_make_tmpdir(dir, dirn, "science", tag);
    (void)snprintf(path, pathn, "%s/claims.chainlog", dir);
    struct science_open_report rep;
    return science_open(path, &rep);
}

/* ── 1. a claim with no falsifier is refused, by name ─────────────────── */

static int case_falsifier_required(void)
{
    int failures = 0;
    char dir[512], path[640];
    struct science_register *reg = open_fresh(dir, sizeof dir, "falsifier",
                                              path, sizeof path);
    SC_CHECK("the register opens", reg != NULL);
    if (!reg) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    struct science_claim_spec s;

    s = good_spec();
    s.statement = "";
    SC_CHECK("a claim with no statement is refused as STATEMENT",
             science_claim_register(reg, &s, NULL) == SCIENCE_REFUSED_STATEMENT);

    s = good_spec();
    s.treatment = NULL;
    SC_CHECK("a claim naming no treatment is refused as TREATMENT",
             science_claim_register(reg, &s, NULL) == SCIENCE_REFUSED_TREATMENT);

    /* The metric is the field that turns an opinion into a claim. Out of the
     * closed enum is not a metric at all. */
    s = good_spec();
    s.metric = (enum science_metric)SCIENCE_METRIC_COUNT;
    SC_CHECK("a claim with no metric in the closed set is refused as METRIC",
             science_claim_register(reg, &s, NULL) == SCIENCE_REFUSED_METRIC);

    s = good_spec();
    s.direction = SCIENCE_DIRECTION_NONE;
    SC_CHECK("a claim that does not say which way the number must move is "
             "refused as DIRECTION",
             science_claim_register(reg, &s, NULL) == SCIENCE_REFUSED_DIRECTION);

    /* Zero is not a small floor. With it, noise alone eventually confirms the
     * claim in one direction or the other. */
    s = good_spec();
    s.effect_floor_milli = 0;
    SC_CHECK("a zero effect floor is refused as EFFECT_FLOOR",
             science_claim_register(reg, &s, NULL) ==
                 SCIENCE_REFUSED_EFFECT_FLOOR);

    s = good_spec();
    s.effect_floor_milli = -5;
    SC_CHECK("a negative effect floor is refused as EFFECT_FLOOR too",
             science_claim_register(reg, &s, NULL) ==
                 SCIENCE_REFUSED_EFFECT_FLOOR);

    s = good_spec();
    s.sample_floor = 0;
    SC_CHECK("a zero sample floor is refused as SAMPLE_FLOOR",
             science_claim_register(reg, &s, NULL) ==
                 SCIENCE_REFUSED_SAMPLE_FLOOR);

    SC_CHECK("no refused claim entered the register",
             science_claim_count(reg) == 0);

    s = good_spec();
    SC_CHECK("the complete claim is accepted",
             science_claim_register(reg, &s, NULL) == SCIENCE_OK);
    SC_CHECK("and it is the only claim there", science_claim_count(reg) == 1);
    SC_CHECK("registering the same claim twice is DUPLICATE, not a second row",
             science_claim_register(reg, &s, NULL) == SCIENCE_REFUSED_DUPLICATE);
    SC_CHECK("still one claim", science_claim_count(reg) == 1);

    science_close(reg);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 2. the metric set is closed ──────────────────────────────────────── */

static int case_metric_closed(void)
{
    int failures = 0;
    enum science_metric m = SCIENCE_METRIC_COUNT;

    SC_CHECK("a free-text metric is refused",
             !science_metric_from_name("vibes", &m));
    SC_CHECK("an empty metric name is refused",
             !science_metric_from_name("", &m));
    SC_CHECK("a NULL metric name is refused",
             !science_metric_from_name(NULL, &m));
    /* A near miss is the dangerous one: it reads as correct in a diff. */
    SC_CHECK("a near-miss spelling is refused, not fuzzy-matched",
             !science_metric_from_name("verdict_pass_rates", &m));
    SC_CHECK("a metric this tree does not measure is refused",
             !science_metric_from_name("developer_happiness", &m));

    bool round_trips = true;
    for (int i = 0; i < (int)SCIENCE_METRIC_COUNT; i++) {
        enum science_metric back = SCIENCE_METRIC_COUNT;
        const char *name = science_metric_name((enum science_metric)i);
        round_trips = round_trips && science_metric_from_name(name, &back) &&
                      back == (enum science_metric)i &&
                      strcmp(name, "unknown_metric") != 0;
    }
    SC_CHECK("every metric in the closed set round-trips through its name",
             round_trips);
    SC_CHECK("an out-of-range metric names itself as unknown",
             strcmp(science_metric_name((enum science_metric)99),
                    "unknown_metric") == 0);
    SC_CHECK("the closed set is the five documented metrics",
             (int)SCIENCE_METRIC_COUNT == 5);
    SC_CHECK("a metric depending on the model's self-report is not in it",
             !science_metric_from_name("model_reported_success", &m) &&
                 !science_metric_from_name("exit_code", &m));
    return failures;
}

/* ── 3. the sample floor comes before the effect ──────────────────────── */

static int case_sample_floor_first(void)
{
    int failures = 0;
    char dir[512], path[640];
    struct science_register *reg = open_fresh(dir, sizeof dir, "floor", path,
                                              sizeof path);
    if (!reg) {
        SC_CHECK("the register opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    struct science_claim_spec s = good_spec();
    s.sample_floor = 5;
    uint8_t id[32];
    SC_CHECK("a claim needing five trials per arm registers",
             science_claim_register(reg, &s, id) == SCIENCE_OK);

    /* As lopsided as it gets: control never passes, treatment always does.
     * The effect is 1000 milli against a floor of 100. It is still UNTESTED,
     * because three trials an arm is three trials an arm. */
    bool recorded = true;
    for (int i = 0; i < 3; i++) {
        struct science_receipt c = trial("alice", SCIENCE_ARM_CONTROL,
                                         ENGINE_VERDICT_FAIL, 2, 100);
        struct science_receipt t = trial("bob", SCIENCE_ARM_TREATMENT,
                                         ENGINE_VERDICT_PASS, 2, 100);
        recorded = recorded &&
                   science_trial_record(reg, id, &c) == SCIENCE_OK &&
                   science_trial_record(reg, id, &t) == SCIENCE_OK;
    }
    SC_CHECK("six trials record", recorded);

    struct science_reading r;
    SC_CHECK("the claim reads", science_claim_read(reg, id, &r) == SCIENCE_OK);
    SC_CHECK("an effect that looks enormous on three trials is still UNTESTED",
             r.status == SCIENCE_UNTESTED);
    SC_CHECK("and the reading says which floor it fell short of",
             r.trials == 6 && r.control.trials == 3 && r.treatment.trials == 3 &&
                 r.sample_floor == 5);
    SC_CHECK("no effect is offered while the claim is untested",
             r.effect_readable == false);

    /* Two more per arm reaches the floor and the verdict becomes readable. */
    bool more = true;
    for (int i = 0; i < 2; i++) {
        struct science_receipt c = trial("alice", SCIENCE_ARM_CONTROL,
                                         ENGINE_VERDICT_FAIL, 2, 100);
        struct science_receipt t = trial("bob", SCIENCE_ARM_TREATMENT,
                                         ENGINE_VERDICT_PASS, 2, 100);
        more = more && science_trial_record(reg, id, &c) == SCIENCE_OK &&
               science_trial_record(reg, id, &t) == SCIENCE_OK;
    }
    SC_CHECK("four more trials record", more);
    SC_CHECK("the claim reads again",
             science_claim_read(reg, id, &r) == SCIENCE_OK);
    SC_CHECK("at the sample floor the same evidence reads SUPPORTED",
             r.status == SCIENCE_SUPPORTED);
    SC_CHECK("the effect is the full swing in pass rate",
             r.effect_readable && r.effect_milli == 1000 &&
                 r.control.value_milli == 0 && r.treatment.value_milli == 1000);

    /* An arm below the floor is enough on its own: a lopsided sample is not
     * fixed by piling more trials into the arm that already has them. */
    struct science_claim_spec one_sided = good_spec();
    one_sided.statement = "one arm only";
    uint8_t id2[32];
    SC_CHECK("a second claim registers",
             science_claim_register(reg, &one_sided, id2) == SCIENCE_OK);
    bool many = true;
    for (int i = 0; i < 8; i++) {
        struct science_receipt t = trial("carol", SCIENCE_ARM_TREATMENT,
                                         ENGINE_VERDICT_PASS, 1, 10);
        many = many && science_trial_record(reg, id2, &t) == SCIENCE_OK;
    }
    SC_CHECK("eight treatment trials record", many);
    SC_CHECK("many trials in one arm and none in the other is UNTESTED",
             science_claim_read(reg, id2, &r) == SCIENCE_OK &&
                 r.status == SCIENCE_UNTESTED && r.trials == 8);

    science_close(reg);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 4. supported, refuted, inconclusive ──────────────────────────────── */

/* Record `n` trials into `arm` where `passes` of them pass. */
static bool fill(struct science_register *reg, const uint8_t id[32],
                 enum science_arm arm, const char *producer, int n, int passes)
{
    for (int i = 0; i < n; i++) {
        struct science_receipt rc =
            receipt(producer, arm,
                    i < passes ? ENGINE_VERDICT_PASS : ENGINE_VERDICT_FAIL);
        if (science_trial_record(reg, id, &rc) != SCIENCE_OK)
            return false;
    }
    return true;
}

static int case_three_verdicts(void)
{
    int failures = 0;
    char dir[512], path[640];
    struct science_register *reg = open_fresh(dir, sizeof dir, "verdicts",
                                              path, sizeof path);
    if (!reg) {
        SC_CHECK("the register opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }
    struct science_reading r;

    /* SUPPORTED: 8/10 treatment against 2/10 control, floor 100 milli. */
    struct science_claim_spec up = good_spec();
    up.sample_floor = 5;
    uint8_t up_id[32];
    SC_CHECK("the up claim registers",
             science_claim_register(reg, &up, up_id) == SCIENCE_OK);
    SC_CHECK("its trials record",
             fill(reg, up_id, SCIENCE_ARM_CONTROL, "alice", 5, 1) &&
                 fill(reg, up_id, SCIENCE_ARM_TREATMENT, "bob", 5, 4));
    SC_CHECK("a rise past the floor on an up claim is SUPPORTED",
             science_claim_read(reg, up_id, &r) == SCIENCE_OK &&
                 r.status == SCIENCE_SUPPORTED && r.effect_milli == 600);

    /* REFUTED: the same claim direction, met by a FALL past the floor. A
     * register that has never refuted anything has not been shown to work. */
    struct science_claim_spec up_bad = good_spec();
    up_bad.statement = "the brief raises the pass rate (it does not)";
    up_bad.sample_floor = 5;
    uint8_t bad_id[32];
    SC_CHECK("the refuted-to-be claim registers",
             science_claim_register(reg, &up_bad, bad_id) == SCIENCE_OK);
    SC_CHECK("its trials record",
             fill(reg, bad_id, SCIENCE_ARM_CONTROL, "alice", 5, 4) &&
                 fill(reg, bad_id, SCIENCE_ARM_TREATMENT, "bob", 5, 1));
    SC_CHECK("a fall past the floor on an up claim is REFUTED",
             science_claim_read(reg, bad_id, &r) == SCIENCE_OK &&
                 r.status == SCIENCE_REFUTED && r.effect_milli == -600);
    SC_CHECK("and the reading says the movement was the opposite way",
             r.reason != NULL && strstr(r.reason, "OPPOSITE") != NULL);

    /* A DOWN claim is refuted by a RISE — the mirror, so a sign error in one
     * branch cannot hide behind the other. */
    struct science_claim_spec down = {
        .statement = "the brief lowers completion tokens",
        .treatment = "territory brief pasted into the prompt preamble",
        .metric = SCIENCE_METRIC_COMPLETION_TOKENS,
        .direction = SCIENCE_DIRECTION_DOWN,
        .effect_floor_milli = 100 * SCIENCE_MILLI, /* 100 tokens */
        .sample_floor = 4,
    };
    uint8_t down_id[32];
    SC_CHECK("the down claim registers",
             science_claim_register(reg, &down, down_id) == SCIENCE_OK);
    bool ok = true;
    for (int i = 0; i < 4; i++) {
        struct science_receipt c = receipt("alice", SCIENCE_ARM_CONTROL,
                                           ENGINE_VERDICT_PASS);
        c.completion_tokens = 1000;
        struct science_receipt t = receipt("bob", SCIENCE_ARM_TREATMENT,
                                           ENGINE_VERDICT_PASS);
        t.completion_tokens = 4000; /* the treatment made it WORSE */
        ok = ok && science_trial_record(reg, down_id, &c) == SCIENCE_OK &&
             science_trial_record(reg, down_id, &t) == SCIENCE_OK;
    }
    SC_CHECK("the down claim's trials record", ok);
    SC_CHECK("a rise on a down claim is REFUTED",
             science_claim_read(reg, down_id, &r) == SCIENCE_OK &&
                 r.status == SCIENCE_REFUTED);

    /* INCONCLUSIVE: a real but small difference, inside the declared floor. */
    struct science_claim_spec small = good_spec();
    small.statement = "the brief raises the pass rate a little";
    small.sample_floor = 5;
    small.effect_floor_milli = 300;
    uint8_t small_id[32];
    SC_CHECK("the small-effect claim registers",
             science_claim_register(reg, &small, small_id) == SCIENCE_OK);
    SC_CHECK("its trials record",
             fill(reg, small_id, SCIENCE_ARM_CONTROL, "alice", 5, 2) &&
                 fill(reg, small_id, SCIENCE_ARM_TREATMENT, "bob", 5, 3));
    SC_CHECK("an effect inside the floor is INCONCLUSIVE, not SUPPORTED",
             science_claim_read(reg, small_id, &r) == SCIENCE_OK &&
                 r.status == SCIENCE_INCONCLUSIVE && r.effect_milli == 200);

    /* Exactly AT the floor counts: the floor is the smallest effect that
     * would COUNT, so it must be inclusive or the boundary is unstated. */
    struct science_claim_spec edge = good_spec();
    edge.statement = "the brief raises the pass rate by exactly the floor";
    edge.sample_floor = 5;
    edge.effect_floor_milli = 200;
    uint8_t edge_id[32];
    SC_CHECK("the edge claim registers",
             science_claim_register(reg, &edge, edge_id) == SCIENCE_OK);
    SC_CHECK("its trials record",
             fill(reg, edge_id, SCIENCE_ARM_CONTROL, "alice", 5, 2) &&
                 fill(reg, edge_id, SCIENCE_ARM_TREATMENT, "bob", 5, 3));
    SC_CHECK("an effect exactly at the floor is SUPPORTED",
             science_claim_read(reg, edge_id, &r) == SCIENCE_OK &&
                 r.status == SCIENCE_SUPPORTED && r.effect_milli == 200);

    science_close(reg);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 5. hollow, and tokens per landed file ────────────────────────────── */

static int case_hollow_and_ratio(void)
{
    int failures = 0;
    char dir[512], path[640];
    struct science_register *reg = open_fresh(dir, sizeof dir, "ratio", path,
                                              sizeof path);
    if (!reg) {
        SC_CHECK("the register opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }
    struct science_reading r;

    /* HOLLOW_RATE counts the runs that looked green while running nothing.
     * A treatment that raises it is making the evidence worse. */
    struct science_claim_spec hollow = {
        .statement = "skipping the group selector raises the hollow rate",
        .treatment = "dispatch with no group named",
        .metric = SCIENCE_METRIC_HOLLOW_RATE,
        .direction = SCIENCE_DIRECTION_UP,
        .effect_floor_milli = 200,
        .sample_floor = 4,
    };
    uint8_t hid[32];
    SC_CHECK("the hollow claim registers",
             science_claim_register(reg, &hollow, hid) == SCIENCE_OK);
    bool ok = true;
    for (int i = 0; i < 4; i++) {
        struct science_receipt c =
            receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);
        struct science_receipt t =
            receipt("bob", SCIENCE_ARM_TREATMENT, ENGINE_VERDICT_HOLLOW);
        ok = ok && science_trial_record(reg, hid, &c) == SCIENCE_OK &&
             science_trial_record(reg, hid, &t) == SCIENCE_OK;
    }
    SC_CHECK("the hollow claim's trials record", ok);
    SC_CHECK("every treatment run hollow and no control run hollow is "
             "SUPPORTED at 1000 milli",
             science_claim_read(reg, hid, &r) == SCIENCE_OK &&
                 r.status == SCIENCE_SUPPORTED && r.effect_milli == 1000);
    SC_CHECK("a HOLLOW verdict is not counted as a pass",
             r.treatment.value_milli == 1000);

    /* TOKENS_PER_LANDED_FILE over arm totals. Treatment spends 1000 tokens
     * for 10 files (100/file); control spends 1000 for 2 (500/file). */
    struct science_claim_spec eff = {
        .statement = "the brief lowers tokens spent per landed file",
        .treatment = "territory brief pasted into the prompt preamble",
        .metric = SCIENCE_METRIC_TOKENS_PER_LANDED_FILE,
        .direction = SCIENCE_DIRECTION_DOWN,
        .effect_floor_milli = 50 * SCIENCE_MILLI,
        .sample_floor = 2,
    };
    uint8_t eid[32];
    SC_CHECK("the efficiency claim registers",
             science_claim_register(reg, &eff, eid) == SCIENCE_OK);
    ok = true;
    for (int i = 0; i < 2; i++) {
        struct science_receipt c =
            receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);
        c.files_changed = 1;
        c.completion_tokens = 500;
        struct science_receipt t =
            receipt("bob", SCIENCE_ARM_TREATMENT, ENGINE_VERDICT_PASS);
        t.files_changed = 5;
        t.completion_tokens = 500;
        ok = ok && science_trial_record(reg, eid, &c) == SCIENCE_OK &&
             science_trial_record(reg, eid, &t) == SCIENCE_OK;
    }
    SC_CHECK("the efficiency claim's trials record", ok);
    SC_CHECK("the ratio is over arm TOTALS: 1000/2 vs 1000/10",
             science_claim_read(reg, eid, &r) == SCIENCE_OK &&
                 r.control.value_milli == 500 * SCIENCE_MILLI &&
                 r.treatment.value_milli == 100 * SCIENCE_MILLI);
    SC_CHECK("a fall past the floor on a down claim is SUPPORTED",
             r.status == SCIENCE_SUPPORTED);

    /* An arm that landed NOTHING has no tokens-per-landed-file. Dropping such
     * trials would make a treatment that writes nothing look infinitely
     * efficient, so the reading refuses instead of scoring it. */
    struct science_claim_spec none = eff;
    none.statement = "a treatment that lands nothing at all";
    uint8_t nid[32];
    SC_CHECK("the lands-nothing claim registers",
             science_claim_register(reg, &none, nid) == SCIENCE_OK);
    ok = true;
    for (int i = 0; i < 2; i++) {
        struct science_receipt c =
            receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);
        c.files_changed = 4;
        c.completion_tokens = 400;
        struct science_receipt t =
            receipt("bob", SCIENCE_ARM_TREATMENT, ENGINE_VERDICT_NO_CHANGE);
        t.files_changed = 0; /* spent tokens, landed nothing */
        t.completion_tokens = 9000;
        ok = ok && science_trial_record(reg, nid, &c) == SCIENCE_OK &&
             science_trial_record(reg, nid, &t) == SCIENCE_OK;
    }
    SC_CHECK("the lands-nothing trials record", ok);
    SC_CHECK("an arm that landed nothing is INCONCLUSIVE, never a great score",
             science_claim_read(reg, nid, &r) == SCIENCE_OK &&
                 r.status == SCIENCE_INCONCLUSIVE);
    SC_CHECK("and the reading says the effect could not be read at all",
             !r.effect_readable && r.effect_milli == 0 &&
                 !r.treatment.defined && r.control.defined);
    SC_CHECK("the reason names the zero-landed arm",
             r.reason != NULL && strstr(r.reason, "zero files") != NULL);

    science_close(reg);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 6. there is no setter for status ─────────────────────────────────── */

/* Read the public header so the claim is about the API SURFACE, not about
 * one call this test happened to think of. */
static char *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    const long n = ftell(f);
    if (n <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    char *buf = zcl_malloc((size_t)n + 1u, "test_science_slurp");
    if (!buf) {
        fclose(f);
        return NULL;
    }
    const size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[got] = '\0';
    if (len)
        *len = got;
    return buf;
}

static int case_no_status_setter(void)
{
    int failures = 0;
    size_t len = 0;
    char *hdr = slurp("cognition/modules/science/include/science/science_claim.h", &len);
    SC_CHECK("the public header is readable", hdr != NULL);
    if (!hdr)
        return failures;

    SC_CHECK("no function in the surface is named *_set_status",
             strstr(hdr, "set_status") == NULL);
    SC_CHECK("no function in the surface is named *_status_set",
             strstr(hdr, "status_set") == NULL);

    /* The decisive one, checked against every declaration rather than against
     * a call this test happened to imagine: no function may TAKE a status.
     * A status that can be passed in is a status that can be ASSERTED rather
     * than derived, and every other guarantee here rests on it being derived.
     * The single permitted exception is the pure name lookup, which stores
     * nothing. Comment lines are skipped so the prose above may discuss the
     * rule without breaking it. */
    int status_params = 0;
    bool only_name_lookup = true;
    for (const char *line = hdr; line && *line;) {
        const char *end = strchr(line, '\n');
        const size_t n = end ? (size_t)(end - line) : strlen(line);
        const char *p = line;
        while ((size_t)(p - line) < n && (*p == ' ' || *p == '\t'))
            p++;
        const bool comment = (size_t)(p - line) < n &&
                             (*p == '*' || (*p == '/' && p[1] == '*'));
        if (!comment) {
            char buf[512];
            const size_t take = n < sizeof buf - 1u ? n : sizeof buf - 1u;
            memcpy(buf, line, take);
            buf[take] = '\0';
            if (strstr(buf, "enum science_status") && strchr(buf, '(')) {
                status_params++;
                if (!strstr(buf, "science_status_name"))
                    only_name_lookup = false;
            }
        }
        line = end ? end + 1 : NULL;
    }
    SC_CHECK("exactly one declaration takes an `enum science_status`",
             status_params == 1);
    SC_CHECK("and it is the pure name lookup, which stores nothing",
             only_name_lookup);
    SC_CHECK("the spec a caller supplies carries no status field",
             strstr(hdr, "struct science_claim_spec {") != NULL);

    const char *spec = strstr(hdr, "struct science_claim_spec {");
    const char *spec_end = spec ? strstr(spec, "};") : NULL;
    bool spec_clean = spec && spec_end;
    if (spec_clean) {
        char *body = zcl_malloc((size_t)(spec_end - spec) + 1u,
                                "test_science_spec");
        if (body) {
            memcpy(body, spec, (size_t)(spec_end - spec));
            body[spec_end - spec] = '\0';
            spec_clean = strstr(body, "status") == NULL;
            free(body);
        } else {
            spec_clean = false;
        }
    }
    SC_CHECK("the caller-supplied spec has no status member anywhere in it",
             spec_clean);

    /* And the behavioural half of the same claim: the only thing that moved
     * the status was recording trials. */
    char dir[512], path[640];
    struct science_register *reg = open_fresh(dir, sizeof dir, "nosetter",
                                              path, sizeof path);
    if (reg) {
        struct science_claim_spec s = good_spec();
        s.sample_floor = 2;
        uint8_t id[32];
        struct science_reading r;
        (void)science_claim_register(reg, &s, id);
        SC_CHECK("a fresh claim is UNTESTED",
                 science_claim_read(reg, id, &r) == SCIENCE_OK &&
                     r.status == SCIENCE_UNTESTED);
        (void)fill(reg, id, SCIENCE_ARM_CONTROL, "alice", 2, 0);
        SC_CHECK("one arm is not enough to move it",
                 science_claim_read(reg, id, &r) == SCIENCE_OK &&
                     r.status == SCIENCE_UNTESTED);
        (void)fill(reg, id, SCIENCE_ARM_TREATMENT, "bob", 2, 2);
        SC_CHECK("recording trials is the only thing that moved it",
                 science_claim_read(reg, id, &r) == SCIENCE_OK &&
                     r.status == SCIENCE_SUPPORTED);
        SC_CHECK("reading twice does not change it",
                 science_claim_read(reg, id, &r) == SCIENCE_OK &&
                     r.status == SCIENCE_SUPPORTED);
        science_close(reg);
    } else {
        SC_CHECK("the register opens", false);
    }
    test_cleanup_tmpdir(dir);
    free(hdr);
    return failures;
}

/* ── 7. one producer is not five ──────────────────────────────────────── */

static int case_producers(void)
{
    int failures = 0;
    char dir[512], path[640];
    struct science_register *reg = open_fresh(dir, sizeof dir, "producers",
                                              path, sizeof path);
    if (!reg) {
        SC_CHECK("the register opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }
    struct science_reading solo, crowd;

    /* Identical arithmetic, different producer sets. */
    struct science_claim_spec a = good_spec();
    a.statement = "supported by its own author alone";
    a.sample_floor = 4;
    uint8_t aid[32];
    SC_CHECK("the single-producer claim registers",
             science_claim_register(reg, &a, aid) == SCIENCE_OK);
    SC_CHECK("its trials record",
             fill(reg, aid, SCIENCE_ARM_CONTROL, "dana", 4, 0) &&
                 fill(reg, aid, SCIENCE_ARM_TREATMENT, "dana", 4, 4));

    struct science_claim_spec b = good_spec();
    b.statement = "supported by five different producers";
    b.sample_floor = 4;
    uint8_t bid[32];
    SC_CHECK("the multi-producer claim registers",
             science_claim_register(reg, &b, bid) == SCIENCE_OK);
    static const char *const who[] = { "ann", "bo", "cy", "di", "ed" };
    bool ok = true;
    for (int i = 0; i < 4; i++) {
        struct science_receipt c =
            receipt(who[i], SCIENCE_ARM_CONTROL, ENGINE_VERDICT_FAIL);
        struct science_receipt t =
            receipt(who[i + 1], SCIENCE_ARM_TREATMENT, ENGINE_VERDICT_PASS);
        ok = ok && science_trial_record(reg, bid, &c) == SCIENCE_OK &&
             science_trial_record(reg, bid, &t) == SCIENCE_OK;
    }
    SC_CHECK("its trials record", ok);

    SC_CHECK("both claims read", science_claim_read(reg, aid, &solo) ==
                                         SCIENCE_OK &&
                                     science_claim_read(reg, bid, &crowd) ==
                                         SCIENCE_OK);
    SC_CHECK("both reach the same status on the same arithmetic",
             solo.status == SCIENCE_SUPPORTED &&
                 crowd.status == SCIENCE_SUPPORTED &&
                 solo.effect_milli == crowd.effect_milli);
    /* Same status, different fact. The register must never collapse them. */
    SC_CHECK("the self-confirmed claim reports one distinct producer",
             solo.producers == 1 && solo.single_producer);
    SC_CHECK("the corroborated claim reports five",
             crowd.producers == 5 && !crowd.single_producer);
    SC_CHECK("per-arm producer counts are reported too",
             solo.control.producers == 1 && solo.treatment.producers == 1 &&
                 crowd.control.producers == 4 &&
                 crowd.treatment.producers == 4);
    SC_CHECK("a repeated producer is counted once, not once per trial",
             solo.trials == 8 && solo.producers == 1);
    struct science_receipt bad = receipt("", SCIENCE_ARM_CONTROL,
                                         ENGINE_VERDICT_PASS);
    SC_CHECK("a trial with no producer is refused",
             science_trial_record(reg, aid, &bad) == SCIENCE_REFUSED_PRODUCER);
    bad = receipt("eve", SCIENCE_ARM_NONE, ENGINE_VERDICT_PASS);
    SC_CHECK("a trial in neither arm is refused",
             science_trial_record(reg, aid, &bad) == SCIENCE_REFUSED_ARM);

    science_close(reg);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 8. canonical bytes ───────────────────────────────────────────────── */

static int case_canonical(void)
{
    int failures = 0;
    uint8_t a[1024], b[1024];
    const struct science_claim_spec base = good_spec();

    const size_t na = science_claim_canonical(&base, a, sizeof a);
    const size_t nb = science_claim_canonical(&base, b, sizeof b);
    SC_CHECK("a valid claim encodes", na > 0);
    SC_CHECK("identical content gives byte-identical frames",
             na == nb && memcmp(a, b, na) == 0);

    /* Every field must be load-bearing: a field that does not change the
     * bytes is a field two different claims could share an id on. */
    struct science_claim_spec v;
    size_t n;
#define DIFFERS(what, mutate)                                             \
    do {                                                                  \
        v = base;                                                         \
        mutate;                                                           \
        n = science_claim_canonical(&v, b, sizeof b);                     \
        SC_CHECK("claim bytes change when " what,                         \
                 n > 0 && (n != na || memcmp(a, b, na) != 0));            \
    } while (0)
    DIFFERS("the statement changes", v.statement = "a different statement");
    DIFFERS("the treatment changes", v.treatment = "a different treatment");
    DIFFERS("the metric changes", v.metric = SCIENCE_METRIC_HOLLOW_RATE);
    DIFFERS("the direction changes", v.direction = SCIENCE_DIRECTION_DOWN);
    DIFFERS("the effect floor changes", v.effect_floor_milli = 101);
    DIFFERS("the sample floor changes", v.sample_floor = 6);
    DIFFERS("the source changes", v.source = "arXiv 0000.00000");
#undef DIFFERS

    /* A length prefix rather than NUL padding: no pair of strings can collide
     * by one being a prefix of the other. */
    v = base;
    v.statement = "abc";
    v.treatment = "de";
    const size_t n1 = science_claim_canonical(&v, a, sizeof a);
    v.statement = "ab";
    v.treatment = "cde";
    const size_t n2 = science_claim_canonical(&v, b, sizeof b);
    SC_CHECK("a shifted split between two strings gives different bytes",
             n1 > 0 && n2 > 0 && (n1 != n2 || memcmp(a, b, n1) != 0));

    /* No timestamp and no path: encoding the same claim later, elsewhere,
     * gives the same bytes and therefore the same id. */
    uint8_t id1[32], id2[32];
    SC_CHECK("a claim id is its content hash",
             science_claim_id(&base, id1) && science_claim_id(&base, id2) &&
                 memcmp(id1, id2, sizeof id1) == 0);

    /* A claim that would be refused has no canonical form at all. */
    v = base;
    v.effect_floor_milli = 0;
    SC_CHECK("an unfalsifiable claim has no canonical bytes",
             science_claim_canonical(&v, b, sizeof b) == 0);
    SC_CHECK("and no id", !science_claim_id(&v, id1));
    SC_CHECK("a buffer too small refuses rather than truncating",
             science_claim_canonical(&base, b, 4) == 0);

    /* Trials the same way. */
    const struct science_receipt r0 =
        receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);
    (void)science_claim_id(&base, id1);
    const size_t tn = science_trial_canonical(id1, &r0, a, sizeof a);
    SC_CHECK("a trial encodes", tn > 0);
    SC_CHECK("identical trials give identical bytes",
             science_trial_canonical(id1, &r0, b, sizeof b) == tn &&
                 memcmp(a, b, tn) == 0);
    struct science_receipt rv;
    size_t tm;
#define TDIFFERS(what, mutate)                                            \
    do {                                                                  \
        rv = r0;                                                          \
        mutate;                                                           \
        tm = science_trial_canonical(id1, &rv, b, sizeof b);              \
        SC_CHECK("trial bytes change when " what,                         \
                 tm > 0 && (tm != tn || memcmp(a, b, tn) != 0));          \
    } while (0)
    TDIFFERS("the producer changes", rv.producer = "bob");
    TDIFFERS("the arm changes", rv.arm = SCIENCE_ARM_TREATMENT);
    TDIFFERS("files_changed changes", rv.files_changed = 4);
    TDIFFERS("groups_ran changes", rv.groups_ran = 2);
    TDIFFERS("groups_failed changes", rv.groups_failed = 7);
    TDIFFERS("cached changes", rv.cached = true);
    TDIFFERS("prompt_tokens changes", rv.prompt_tokens = 1001);
    TDIFFERS("completion_tokens changes", rv.completion_tokens = 2001);
    TDIFFERS("the verdict changes", rv.verdict = ENGINE_VERDICT_HOLLOW);
    TDIFFERS("the engine changes", rv.engine = "other");
    TDIFFERS("the model changes", rv.model = "other-model");
    TDIFFERS("the territory changes", rv.territory = "engine/modules/chainlog");
    TDIFFERS("the group changes", rv.group = "chainlog");
#undef TDIFFERS
    /* The claim binding is in the bytes: the same receipt under a different
     * claim is a different frame. */
    (void)science_claim_id(&base, id1);
    struct science_claim_spec other = base;
    other.statement = "some other claim";
    SC_CHECK("the same receipt under another claim gives different bytes",
             science_claim_id(&other, id2) &&
                 science_trial_canonical(id2, &r0, b, sizeof b) == tn &&
                 memcmp(a, b, tn) != 0);
    return failures;
}

/* ── 9. it survives a close and reopen ────────────────────────────────── */

static int case_durability(void)
{
    int failures = 0;
    char dir[512], path[640];
    test_make_tmpdir(dir, sizeof dir, "science", "durable");
    (void)snprintf(path, sizeof path, "%s/claims.chainlog", dir);

    uint8_t id[32] = { 0 };
    int64_t effect_before = 0;
    {
        struct science_open_report rep;
        struct science_register *reg = science_open(path, &rep);
        SC_CHECK("a new register opens empty",
                 reg != NULL && rep.refusal == SCIENCE_OK && rep.claims == 0 &&
                     rep.trials == 0);
        if (!reg) {
            test_cleanup_tmpdir(dir);
            return failures;
        }
        struct science_claim_spec s = good_spec();
        s.sample_floor = 3;
        SC_CHECK("a claim registers",
                 science_claim_register(reg, &s, id) == SCIENCE_OK);
        SC_CHECK("trials record",
                 fill(reg, id, SCIENCE_ARM_CONTROL, "alice", 3, 0) &&
                     fill(reg, id, SCIENCE_ARM_TREATMENT, "bob", 3, 3));
        struct science_reading r;
        SC_CHECK("it reads SUPPORTED before the close",
                 science_claim_read(reg, id, &r) == SCIENCE_OK &&
                     r.status == SCIENCE_SUPPORTED);
        effect_before = r.effect_milli;
        science_close(reg);
    }
    {
        struct science_open_report rep;
        struct science_register *reg = science_open(path, &rep);
        SC_CHECK("the register reopens", reg != NULL);
        if (!reg) {
            test_cleanup_tmpdir(dir);
            return failures;
        }
        SC_CHECK("the replay found one claim and six trials",
                 rep.claims == 1 && rep.trials == 6 && rep.frames == 7);
        SC_CHECK("nothing was torn", rep.torn_bytes == 0);
        SC_CHECK("the claim is still there by its content id",
                 science_claim_count(reg) == 1);

        struct science_reading r;
        SC_CHECK("and reads the same status from the replayed trials",
                 science_claim_read(reg, id, &r) == SCIENCE_OK &&
                     r.status == SCIENCE_SUPPORTED &&
                     r.effect_milli == effect_before && r.trials == 6);
        SC_CHECK("the producers survived the round trip",
                 r.producers == 2 && !r.single_producer);

        /* The claim's spec survives verbatim: a falsifier that came back
         * different would mean the register replayed a different claim. */
        struct science_claim_spec back;
        char statement[SCIENCE_STATEMENT_MAX], treatment[SCIENCE_TREATMENT_MAX];
        char source[SCIENCE_SOURCE_MAX];
        SC_CHECK("the spec reads back",
                 science_claim_spec_at(reg, 0, &back, statement, treatment,
                                       source));
        const struct science_claim_spec want = good_spec();
        SC_CHECK("with the same statement and treatment",
                 strcmp(back.statement, want.statement) == 0 &&
                     strcmp(back.treatment, want.treatment) == 0);
        SC_CHECK("and the same falsifier",
                 back.metric == want.metric &&
                     back.direction == want.direction &&
                     back.effect_floor_milli == want.effect_floor_milli &&
                     back.sample_floor == 3);

        uint8_t id_at[32];
        SC_CHECK("the enumerated id matches the registered one",
                 science_claim_id_at(reg, 0, id_at) &&
                     memcmp(id_at, id, sizeof id) == 0);
        SC_CHECK("there is no claim at index 1",
                 !science_claim_id_at(reg, 1, id_at));

        /* Appending after a reopen continues the same history. */
        SC_CHECK("a further trial records after the reopen",
                 fill(reg, id, SCIENCE_ARM_CONTROL, "cara", 1, 0));
        SC_CHECK("and is counted",
                 science_claim_read(reg, id, &r) == SCIENCE_OK &&
                     r.trials == 7 && r.producers == 3);
        science_close(reg);
    }
    {
        struct science_open_report rep;
        struct science_register *reg = science_open(path, &rep);
        SC_CHECK("a third open sees all seven trials",
                 reg != NULL && rep.trials == 7 && rep.claims == 1);
        science_close(reg);
    }

    /* A trial for a claim nobody registered is refused, not filed under a
     * claim that happens to exist. */
    {
        struct science_open_report rep;
        struct science_register *reg = science_open(path, &rep);
        if (reg) {
            uint8_t bogus[32];
            memset(bogus, 0x5A, sizeof bogus);
            struct science_receipt rc =
                receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);
            SC_CHECK("a trial for an unregistered claim is refused",
                     science_trial_record(reg, bogus, &rc) ==
                         SCIENCE_REFUSED_UNKNOWN_CLAIM);
            struct science_reading r;
            SC_CHECK("and reading an unregistered claim is refused too",
                     science_claim_read(reg, bogus, &r) ==
                         SCIENCE_REFUSED_UNKNOWN_CLAIM);
            science_close(reg);
        } else {
            SC_CHECK("the register reopens for the unknown-claim case", false);
        }
    }

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 10. the corpus report refuses to flatter ─────────────────────────── */

static bool spill(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    const size_t n = strlen(text);
    const bool ok = fwrite(text, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

/* mkdir -p through the platform seam, one component at a time. */
static bool mkdir_p(const char *dir, const char *rel)
{
    char path[1024];
    int n = snprintf(path, sizeof path, "%s/", dir);
    if (n <= 0 || (size_t)n >= sizeof path)
        return false;
    size_t at = (size_t)n;
    for (const char *p = rel;; p++) {
        if (*p == '/' || *p == '\0') {
            if (at >= sizeof path)
                return false;
            path[at] = '\0';
            if (!platform_directory_ensure(path, 0755))
                return false;
            if (*p == '\0')
                return true;
        }
        if (at + 1 >= sizeof path)
            return false;
        path[at++] = *p;
    }
}

/* A fixture tree with two of the maintained roots and four source files, so
 * the walk's own arithmetic is checkable by hand. */
static bool build_fixture(const char *dir)
{
    char p[1024];
    if (!mkdir_p(dir, "lib/demo/src") || !mkdir_p(dir, "tools/demo") ||
        !mkdir_p(dir, "vendor/third_party") || !mkdir_p(dir, "docs"))
        return false;

    (void)snprintf(p, sizeof p, "%s/lib/demo/src/one.c", dir);
    if (!spill(p, "a\nb\nc\n"))
        return false;
    (void)snprintf(p, sizeof p, "%s/lib/demo/src/two.h", dir);
    if (!spill(p, "x\ny\n"))
        return false;
    /* No trailing newline: still a line. */
    (void)snprintf(p, sizeof p, "%s/tools/demo/three.c", dir);
    if (!spill(p, "one\ntwo"))
        return false;
    (void)snprintf(p, sizeof p, "%s/tools/demo/notes.md", dir);
    if (!spill(p, "not C23 and must not be counted\n"))
        return false;
    /* Vendored code is not this project's corpus. */
    (void)snprintf(p, sizeof p, "%s/vendor/third_party/huge.c", dir);
    if (!spill(p, "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n"))
        return false;
    return true;
}

static int case_corpus_honesty(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "science", "corpus");
    SC_CHECK("the fixture tree builds", build_fixture(dir));

    char inv[1024];
    (void)snprintf(inv, sizeof inv, "%s/docs/CAPABILITY_INVENTORY.jsonl", dir);

    /* (a) No inventory: proof is NOT MEASURED, and must never read as zero. */
    struct science_corpus_report r;
    SC_CHECK("the walk succeeds with no inventory present",
             science_corpus_measure(dir, inv, &r));
    SC_CHECK("only C23 files under maintained roots are counted",
             r.files_walked == 3);
    SC_CHECK("lines are counted, including a final line with no newline",
             r.lines == 3 + 2 + 2);
    SC_CHECK("vendored code is outside the corpus", r.bytes == 6 + 4 + 7);
    SC_CHECK("the inventory is reported absent, not empty",
             !r.inventory_present && !r.scope_agrees);
    SC_CHECK("the proven fraction is -1 (not measured), never 0 (nothing "
             "proven)",
             science_corpus_proven_symbols_milli(&r) == -1);
    char head[1024];
    SC_CHECK("the headline says proof was not measured",
             science_corpus_headline(&r, head, sizeof head) > 0 &&
                 strstr(head, "PROOF NOT MEASURED") != NULL);
    SC_CHECK("and does not claim zero duplicates",
             strstr(head, "0 duplicate") == NULL);

    /* (b) A fresh inventory that agrees on the file count. Three symbols: one
     * reached, two not. The honest headline leads with the two. */
    static const char *const k_inv =
        "{\"record\":\"inventory\",\"files_scanned\":3,"
        "\"production_files\":2,\"test_files\":1}\n"
        "{\"record\":\"capability\",\"symbols\":["
        "{\"test_evidence\":\"registered_test_reachable\"},"
        "{\"test_evidence\":\"none_UNPROVEN\"},"
        "{\"test_evidence\":\"test_source_reference_only_UNPROVEN\"}]}\n"
        "{\"record\":\"duplicate\",\"symbol_a\":\"x\"}\n"
        "{\"record\":\"duplicate\",\"symbol_a\":\"y\"}\n"
        "{\"record\":\"untested_invariant\",\"symbol\":\"z\"}\n";
    SC_CHECK("the fixture inventory writes", spill(inv, k_inv));
    SC_CHECK("the measure reads it",
             science_corpus_measure(dir, inv, &r) && r.inventory_present);
    SC_CHECK("symbols are counted from the records, not from a summary",
             r.symbols_exposed == 3 && r.symbols_test_reached == 1 &&
                 r.symbols_no_test == 1 && r.symbols_test_source_only == 1);
    SC_CHECK("duplicates and untested invariants are counted",
             r.duplicates == 2 && r.untested_invariants == 1 &&
                 r.capabilities == 1);
    SC_CHECK("the two halves agree on the tree",
             r.scope_agrees && r.inventory_files_scanned == 3);
    SC_CHECK("the proven fraction is over PUBLIC SYMBOLS: 1 of 3",
             science_corpus_proven_symbols_milli(&r) == 333);
    SC_CHECK("the headline leads with what is NOT proven",
             science_corpus_headline(&r, head, sizeof head) > 0 &&
                 strncmp(head, "2 of 3 public symbols", 21) == 0 &&
                 strstr(head, "NOT reached") != NULL);
    SC_CHECK("the goal fraction is a line count and is not rounded up",
             science_corpus_goal_milli(&r) == 0);
    SC_CHECK("a fresh inventory produces no staleness warning",
             strstr(head, "STALE") == NULL);

    /* (c) A stale inventory: the file counts disagree, so the proof figures
     * describe another tree and the report must say so rather than divide
     * one walk's numerator by another walk's denominator. */
    static const char *const k_stale =
        "{\"record\":\"inventory\",\"files_scanned\":9001,"
        "\"production_files\":9000,\"test_files\":1}\n"
        "{\"record\":\"capability\",\"symbols\":["
        "{\"test_evidence\":\"registered_test_reachable\"}]}\n";
    SC_CHECK("the stale inventory writes", spill(inv, k_stale));
    SC_CHECK("the measure reads it",
             science_corpus_measure(dir, inv, &r) && r.inventory_present);
    SC_CHECK("the scope check catches it",
             !r.scope_agrees && r.inventory_files_scanned == 9001 &&
                 r.files_walked == 3);
    SC_CHECK("and the headline announces the staleness rather than hiding it",
             science_corpus_headline(&r, head, sizeof head) > 0 &&
                 strstr(head, "STALE") != NULL &&
                 strstr(head, "docs-capability-inventory") != NULL);
    /* Even a 100%-reached inventory must not read as a finished corpus. */
    SC_CHECK("a fully-reached symbol set is still only that denominator",
             science_corpus_proven_symbols_milli(&r) == 1000 &&
                 science_corpus_goal_milli(&r) == 0);

    /* (d) A file with a record shape but no summary is not an inventory we
     * can scope-check, so it does not count as present. */
    SC_CHECK("a headerless inventory writes",
             spill(inv, "{\"record\":\"duplicate\",\"symbol_a\":\"x\"}\n"));
    SC_CHECK("an inventory with no summary record is not present",
             science_corpus_measure(dir, inv, &r) && !r.inventory_present &&
                 science_corpus_proven_symbols_milli(&r) == -1);

    (void)test_rm_rf_recursive(dir);
    return failures;
}

/* ── 11. the falsifier cannot be moved after the results arrive ───────── */

static int case_falsifier_immutable(void)
{
    int failures = 0;
    char dir[512], path[640];
    struct science_register *reg = open_fresh(dir, sizeof dir, "immutable",
                                              path, sizeof path);
    if (!reg) {
        SC_CHECK("the register opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    /* Register a prediction, then produce a result that misses it. */
    struct science_claim_spec s = good_spec();
    s.sample_floor = 4;
    s.effect_floor_milli = 500; /* predicted: fifty points */
    uint8_t id[32];
    SC_CHECK("a claim predicting a fifty-point rise registers",
             science_claim_register(reg, &s, id) == SCIENCE_OK);
    SC_CHECK("trials record",
             fill(reg, id, SCIENCE_ARM_CONTROL, "alice", 4, 2) &&
                 fill(reg, id, SCIENCE_ARM_TREATMENT, "bob", 4, 3));
    struct science_reading before;
    SC_CHECK("it comes back INCONCLUSIVE against its own floor",
             science_claim_read(reg, id, &before) == SCIENCE_OK &&
                 before.status == SCIENCE_INCONCLUSIVE &&
                 before.effect_milli == 250);

    /* Now the oldest trick: lower the floor until the result clears it. */
    struct science_claim_spec moved = s;
    moved.effect_floor_milli = 200;
    SC_CHECK("re-registering the same claim with a lowered floor is RESTATED",
             science_claim_register(reg, &moved, NULL) ==
                 SCIENCE_REFUSED_RESTATED);
    moved = s;
    moved.direction = SCIENCE_DIRECTION_DOWN;
    SC_CHECK("flipping the predicted direction is RESTATED too",
             science_claim_register(reg, &moved, NULL) ==
                 SCIENCE_REFUSED_RESTATED);
    moved = s;
    moved.sample_floor = 2;
    SC_CHECK("lowering the sample floor is RESTATED too",
             science_claim_register(reg, &moved, NULL) ==
                 SCIENCE_REFUSED_RESTATED);

    SC_CHECK("no restatement entered the register",
             science_claim_count(reg) == 1);
    struct science_reading after;
    SC_CHECK("and the original claim reads exactly as it did",
             science_claim_read(reg, id, &after) == SCIENCE_OK &&
                 after.status == before.status &&
                 after.effect_milli == before.effect_milli &&
                 after.effect_floor_milli == 500 && after.sample_floor == 4);

    /* The structural half of the same guarantee: the falsifier is inside the
     * claim id, so an edited floor is not an edit at all. */
    uint8_t id_moved[32];
    struct science_claim_spec lower = good_spec();
    lower.effect_floor_milli = 500;
    struct science_claim_spec lower2 = lower;
    lower2.effect_floor_milli = 200;
    SC_CHECK("a different floor hashes to a different claim id",
             science_claim_id(&lower, id) && science_claim_id(&lower2, id_moved) &&
                 memcmp(id, id_moved, sizeof id) != 0);

    /* A genuinely different claim on the same metric is NOT a restatement:
     * the check must not become a ban on studying the same treatment twice. */
    struct science_claim_spec other = s;
    other.statement = "a different question about the same treatment";
    other.effect_floor_milli = 200;
    SC_CHECK("a differently-worded claim with its own floor is allowed",
             science_claim_register(reg, &other, NULL) == SCIENCE_OK);
    struct science_claim_spec other_metric = s;
    other_metric.metric = SCIENCE_METRIC_COMPLETION_TOKENS;
    other_metric.effect_floor_milli = 200;
    SC_CHECK("the same words on a different metric are allowed",
             science_claim_register(reg, &other_metric, NULL) == SCIENCE_OK);
    SC_CHECK("three claims stand", science_claim_count(reg) == 3);

    science_close(reg);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 12. seeded claims start UNTESTED, citation and all ───────────────── */

static int case_seeds(void)
{
    int failures = 0;
    char dir[512], path[640];
    struct science_register *reg = open_fresh(dir, sizeof dir, "seeds", path,
                                              sizeof path);
    if (!reg) {
        SC_CHECK("the register opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    SC_CHECK("there are seeds to install", science_seed_count() >= 3);
    uint32_t added = 0, already = 0;
    SC_CHECK("they install",
             science_seed_install(reg, &added, &already) == SCIENCE_OK);
    SC_CHECK("every one of them was added",
             added == science_seed_count() && already == 0 &&
                 science_claim_count(reg) == science_seed_count());

    /* THE POINT: a citation is provenance, never evidence. A paper's result
     * is a fact about the tree the authors measured. */
    bool all_untested = true, all_cited = true, all_falsifiable = true;
    for (uint32_t i = 0; i < science_claim_count(reg); i++) {
        uint8_t id[32];
        struct science_reading r;
        if (!science_claim_id_at(reg, i, id) ||
            science_claim_read(reg, id, &r) != SCIENCE_OK) {
            all_untested = false;
            break;
        }
        all_untested = all_untested && r.status == SCIENCE_UNTESTED &&
                       r.trials == 0 && r.producers == 0 && !r.effect_readable;
        all_falsifiable = all_falsifiable && r.effect_floor_milli > 0 &&
                          r.sample_floor > 0 &&
                          (r.direction == SCIENCE_DIRECTION_UP ||
                           r.direction == SCIENCE_DIRECTION_DOWN);
        struct science_claim_spec spec;
        char st[SCIENCE_STATEMENT_MAX], tr[SCIENCE_TREATMENT_MAX];
        char src[SCIENCE_SOURCE_MAX];
        all_cited = all_cited &&
                    science_claim_spec_at(reg, i, &spec, st, tr, src) &&
                    src[0] != '\0';
    }
    SC_CHECK("every seeded claim starts UNTESTED, citation and all",
             all_untested);
    SC_CHECK("every seeded claim names where it came from", all_cited);
    SC_CHECK("every seeded claim carries a real falsifier", all_falsifiable);

    /* The claim that points away from where effort naturally goes is present
     * by name, so nobody can quietly drop it. */
    bool saw_prompt_claim = false, saw_structure_claim = false;
    for (uint32_t i = 0; i < science_claim_count(reg); i++) {
        struct science_claim_spec spec;
        char st[SCIENCE_STATEMENT_MAX], tr[SCIENCE_TREATMENT_MAX];
        char src[SCIENCE_SOURCE_MAX];
        if (!science_claim_spec_at(reg, i, &spec, st, tr, src))
            continue;
        if (strstr(st, "system prompt") != NULL)
            saw_prompt_claim = true;
        if (strstr(st, "retrieval tool") != NULL)
            saw_structure_claim = true;
    }
    SC_CHECK("the prompt-prose claim the ablation contradicts is seeded",
             saw_prompt_claim);
    SC_CHECK("and the harness-structure claim beside it", saw_structure_claim);

    /* Installing twice adds nothing and loses nothing. */
    added = already = 0;
    SC_CHECK("a second install is a no-op",
             science_seed_install(reg, &added, &already) == SCIENCE_OK &&
                 added == 0 && already == science_seed_count() &&
                 science_claim_count(reg) == science_seed_count());

    /* A citation buys a seed nothing on the way to a verdict: it still needs
     * its full sample floor in each arm. Driving one all the way to a status
     * is case_refutation_is_a_result()'s job — it takes a seeded claim to
     * REFUTED — so this only proves the floor is not shortened for a cited
     * claim. */
    uint8_t first[32];
    struct science_reading r;
    SC_CHECK("the first seed is readable",
             science_claim_id_at(reg, 0, first) &&
                 science_claim_read(reg, first, &r) == SCIENCE_OK &&
                 r.status == SCIENCE_UNTESTED && r.sample_floor == 20);
    SC_CHECK("a lopsided handful of trials leaves a cited claim UNTESTED",
             fill(reg, first, SCIENCE_ARM_CONTROL, "alice", 3, 0) &&
                 fill(reg, first, SCIENCE_ARM_TREATMENT, "bob", 3, 3) &&
                 science_claim_read(reg, first, &r) == SCIENCE_OK &&
                 r.status == SCIENCE_UNTESTED && r.trials == 6);

    /* And a seed reads back out of the register with its citation intact. */
    science_close(reg);
    struct science_open_report rep;
    reg = science_open(path, &rep);
    SC_CHECK("the seeded register reopens",
             reg != NULL && rep.claims == science_seed_count());
    if (reg) {
        struct science_claim_spec spec, seed;
        char st[SCIENCE_STATEMENT_MAX], tr[SCIENCE_TREATMENT_MAX];
        char src[SCIENCE_SOURCE_MAX];
        SC_CHECK("the first seed survives verbatim",
                 science_seed_at(0, &seed) &&
                     science_claim_spec_at(reg, 0, &spec, st, tr, src) &&
                     strcmp(spec.statement, seed.statement) == 0 &&
                     strcmp(spec.treatment, seed.treatment) == 0 &&
                     strcmp(spec.source, seed.source) == 0 &&
                     spec.effect_floor_milli == seed.effect_floor_milli);
        SC_CHECK("an out-of-range seed index refuses",
                 !science_seed_at(science_seed_count(), &seed));
        science_close(reg);
    }

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 13. a stranger has to be able to rerun it ────────────────────────── */

static int case_repeatable_by_a_stranger(void)
{
    int failures = 0;
    char dir[512], path[640];
    struct science_register *reg = open_fresh(dir, sizeof dir, "repro", path,
                                              sizeof path);
    if (!reg) {
        SC_CHECK("the register opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }
    struct science_claim_spec s = good_spec();
    uint8_t id[32];
    SC_CHECK("a claim registers",
             science_claim_register(reg, &s, id) == SCIENCE_OK);

    /* One case per field, each asserting the refusal NAMES the missing one.
     * A record is refused at record time rather than stored with a hole: a
     * hole is found later, by someone who already reasoned from the rows
     * around it. */
    struct science_receipt r;
#define MISSING(what, mutate, want)                                       \
    do {                                                                  \
        r = receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);   \
        mutate;                                                           \
        SC_CHECK("a trial with " what " is refused as " #want,            \
                 science_trial_record(reg, id, &r) == want);              \
    } while (0)
    MISSING("no command line", r.repro.command = NULL,
            SCIENCE_REFUSED_COMMAND);
    MISSING("an empty command line", r.repro.command = "",
            SCIENCE_REFUSED_COMMAND);
    MISSING("no commit sha", r.repro.commit = NULL, SCIENCE_REFUSED_COMMIT);
    MISSING("no input or seed", r.repro.input = NULL, SCIENCE_REFUSED_INPUT);
    MISSING("no compiler id", r.repro.compiler = NULL,
            SCIENCE_REFUSED_COMPILER);
    MISSING("no optimisation level", r.repro.optimisation = NULL,
            SCIENCE_REFUSED_OPTIMISATION);
    MISSING("zero cores", r.repro.nproc = 0, SCIENCE_REFUSED_NPROC);
#undef MISSING
    SC_CHECK("none of the unrepeatable trials were stored",
             science_claim_read(reg, id, &(struct science_reading){0}) ==
                     SCIENCE_OK &&
                 science_claim_count(reg) == 1);
    struct science_reading rd;
    SC_CHECK("the claim still has no trials at all",
             science_claim_read(reg, id, &rd) == SCIENCE_OK && rd.trials == 0);

    /* The complete one goes in, and comes back with every field intact — a
     * reproduction block that did not survive the round trip would be a
     * reproduction block a peer could not use. */
    r = receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);
    r.repro.stress_tests = true;
    SC_CHECK("a complete trial records",
             science_trial_record(reg, id, &r) == SCIENCE_OK);
    uint8_t frame[4096];
    const size_t n = science_trial_canonical(id, &r, frame, sizeof frame);
    SC_CHECK("and encodes", n > 0);
    uint8_t back_claim[32], back_trial[32];
    SC_CHECK("and verifies as a pure function of its own bytes",
             science_trial_verify(frame, n, back_claim, back_trial) &&
                 memcmp(back_claim, id, sizeof id) == 0);
    /* ZCL_STRESS_TESTS changes which groups run at all, so two runs that
     * disagree about it are not comparable. It is in the fingerprint. */
    struct science_receipt without = r;
    without.repro.stress_tests = false;
    uint8_t other[4096];
    const size_t m = science_trial_canonical(id, &without, other, sizeof other);
    SC_CHECK("flipping ZCL_STRESS_TESTS changes the record",
             m == n && memcmp(other, frame, n) != 0);
    SC_CHECK("and both halves of the flip still verify on their own bytes",
             science_trial_verify(other, m, NULL, NULL) &&
                 science_trial_verify(frame, n, NULL, NULL));

    science_close(reg);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 14. data, not a summary ──────────────────────────────────────────── */

static int case_data_not_summary(void)
{
    int failures = 0;
    char dir[512], path[640];
    struct science_register *reg = open_fresh(dir, sizeof dir, "data", path,
                                              sizeof path);
    if (!reg) {
        SC_CHECK("the register opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }
    struct science_claim_spec s = good_spec();
    uint8_t id[32];
    SC_CHECK("a claim registers",
             science_claim_register(reg, &s, id) == SCIENCE_OK);

    struct science_receipt r;
    /* "7031ms" with no n is a claim, not a measurement. */
    r = receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);
    r.observed.n = 0;
    SC_CHECK("an observation with no sample count is refused",
             science_trial_record(reg, id, &r) == SCIENCE_REFUSED_SAMPLES);
    r = receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);
    r.observed.unit = NULL;
    SC_CHECK("an observation with no unit is refused",
             science_trial_record(reg, id, &r) == SCIENCE_REFUSED_SAMPLES);
    r = receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);
    r.observed.median_milli = r.observed.min_milli - 1;
    SC_CHECK("order statistics out of order are refused",
             science_trial_record(reg, id, &r) == SCIENCE_REFUSED_SAMPLES);
    r = receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);
    r.observed.p95_milli = r.observed.max_milli + 1;
    SC_CHECK("a p95 above the max is refused",
             science_trial_record(reg, id, &r) == SCIENCE_REFUSED_SAMPLES);
    r = receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);
    r.observed.availability = SCIENCE_AVAILABILITY_NONE;
    SC_CHECK("an observation that does not say whether it exists is refused",
             science_trial_record(reg, id, &r) == SCIENCE_REFUSED_AVAILABILITY);

    /* UNAVAILABLE must say why, and must not carry numbers: a zero beside an
     * UNAVAILABLE flag is exactly the confusion the flag exists to prevent. */
    r = receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);
    r.observed = (struct science_samples){ .availability = SCIENCE_UNAVAILABLE };
    SC_CHECK("UNAVAILABLE with no reason is refused",
             science_trial_record(reg, id, &r) == SCIENCE_REFUSED_REASON);
    r.observed.reason = "the run was killed before the timer stopped";
    r.observed.n = 3;
    SC_CHECK("UNAVAILABLE carrying a sample count is refused",
             science_trial_record(reg, id, &r) == SCIENCE_REFUSED_SAMPLES);
    r.observed.n = 0;
    r.observed.median_milli = 7031;
    SC_CHECK("UNAVAILABLE carrying a number is refused",
             science_trial_record(reg, id, &r) == SCIENCE_REFUSED_SAMPLES);
    r.observed.median_milli = 0;
    SC_CHECK("UNAVAILABLE with a reason and no numbers is a valid record",
             science_trial_record(reg, id, &r) == SCIENCE_OK);

    /* THE DISTINCTION, in the bytes: "I could not measure" and "I measured
     * zero" must not encode the same way. */
    struct science_receipt zero =
        receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);
    zero.observed = (struct science_samples){
        .availability = SCIENCE_OBSERVED, .unit = "ms", .n = 1,
        .min_milli = 0, .median_milli = 0, .p95_milli = 0, .max_milli = 0 };
    SC_CHECK("a measured zero is a valid record too",
             science_trial_record(reg, id, &zero) == SCIENCE_OK);
    uint8_t a[4096], b[4096];
    const size_t na = science_trial_canonical(id, &r, a, sizeof a);
    const size_t nb = science_trial_canonical(id, &zero, b, sizeof b);
    SC_CHECK("both encode", na > 0 && nb > 0);
    SC_CHECK("and 'could not measure' is not the same bytes as 'measured "
             "zero'",
             na != nb || memcmp(a, b, na) != 0);
    uint8_t ida[32], idb[32];
    SC_CHECK("so they are not the same record",
             science_trial_id(id, &r, ida) && science_trial_id(id, &zero, idb) &&
                 memcmp(ida, idb, sizeof ida) != 0);
    SC_CHECK("every observation name is stable",
             strcmp(science_availability_name(SCIENCE_OBSERVED),
                    "observed") == 0 &&
                 strcmp(science_availability_name(SCIENCE_UNAVAILABLE),
                        "unavailable") == 0 &&
                 strcmp(science_availability_name(SCIENCE_AVAILABILITY_NONE),
                        "unknown_availability") == 0);

    science_close(reg);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 15. a peer checks the record, not the sender ─────────────────────── */

/* The encoding pinned against a fixed expectation. A single build cannot
 * observe another build, so it testifies about one instead: these bytes are
 * what the layout says they are, in big-endian, length-prefixed, padding-free
 * and float-free form. Any build at any optimisation level that produces
 * different bytes fails here, which is the only honest way one binary can
 * assert that -O0 and -O2 agree. */
static int case_peer_verifiable(void)
{
    int failures = 0;

    /* A tiny claim whose canonical form can be read off by hand. */
    const struct science_claim_spec tiny = {
        .statement = "ab",
        .treatment = "c",
        .metric = SCIENCE_METRIC_VERDICT_PASS_RATE, /* 0 */
        .direction = SCIENCE_DIRECTION_UP,          /* 1 */
        .effect_floor_milli = 100,
        .sample_floor = 2,
        .source = NULL,
    };
    static const uint8_t k_golden[] = {
        0x00, 0x00, 0x00, 0x01,                         /* version 1 */
        0x00, 0x00, 0x00, 0x00,                         /* metric 0 */
        0x00, 0x00, 0x00, 0x01,                         /* direction UP */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, /* floor 100 */
        0x00, 0x00, 0x00, 0x02,                         /* sample floor 2 */
        0x00, 0x00, 0x00, 0x02, 'a',  'b',              /* statement */
        0x00, 0x00, 0x00, 0x01, 'c',                    /* treatment */
        0x00, 0x00, 0x00, 0x00,                         /* source, empty */
    };
    uint8_t got[4096];
    const size_t n = science_claim_canonical(&tiny, got, sizeof got);
    SC_CHECK("the claim encoding matches the pinned golden vector",
             n == sizeof k_golden && memcmp(got, k_golden, n) == 0);
    SC_CHECK("no padding: the frame is exactly the fields' width",
             n == 4 + 4 + 4 + 8 + 4 + 4 + 2 + 4 + 1 + 4);

    /* A peer accepts it using only these bytes. */
    uint8_t id[32], id_direct[32];
    SC_CHECK("a peer verifies a claim from its bytes alone",
             science_claim_verify(got, n, id) && science_claim_id(&tiny, id_direct) &&
                 memcmp(id, id_direct, sizeof id) == 0);

    /* Mutate ANY byte and the record must stop verifying or change its id.
     * Every byte is load-bearing or it is a byte an attacker can use. */
    bool every_byte_matters = true;
    for (size_t i = 0; i < n && every_byte_matters; i++) {
        for (unsigned bit = 0; bit < 8 && every_byte_matters; bit++) {
            uint8_t mutant[4096];
            memcpy(mutant, got, n);
            mutant[i] ^= (uint8_t)(1u << bit);
            uint8_t mid[32];
            if (!science_claim_verify(mutant, n, mid))
                continue; /* refused outright: also a detection */
            every_byte_matters = memcmp(mid, id, sizeof id) != 0;
        }
    }
    SC_CHECK("every single bit of a claim frame is load-bearing",
             every_byte_matters);
    SC_CHECK("a truncated frame is refused, not read short",
             !science_claim_verify(got, n - 1, NULL));
    SC_CHECK("trailing bytes are refused, so one fact has one address",
             (memcpy(got + n, "\0", 1), !science_claim_verify(got, n + 1, NULL)));
    SC_CHECK("an empty frame is refused", !science_claim_verify(got, 0, NULL));

    /* THE HYPOTHESIS IS UPSTREAM OF THE RESULT IN THE BYTES. Two trials with
     * completely different outcomes under the same claim share their first 36
     * bytes exactly — version and the claim id — so a record cannot be re-cut
     * to make the prediction match the outcome after the fact. */
    uint8_t claim_id[32];
    SC_CHECK("the claim has an id", science_claim_id(&tiny, claim_id));
    struct science_receipt won =
        receipt("alice", SCIENCE_ARM_TREATMENT, ENGINE_VERDICT_PASS);
    struct science_receipt lost =
        receipt("alice", SCIENCE_ARM_TREATMENT, ENGINE_VERDICT_FAIL);
    uint8_t fa[4096], fb[4096];
    const size_t la = science_trial_canonical(claim_id, &won, fa, sizeof fa);
    const size_t lb = science_trial_canonical(claim_id, &lost, fb, sizeof fb);
    SC_CHECK("both trials encode", la > 0 && lb > 0);
    SC_CHECK("the hypothesis occupies the first 36 bytes of both",
             la >= 36 && lb >= 36 && memcmp(fa, fb, 36) == 0);
    SC_CHECK("and the outcomes differ after it",
             la != lb || (la > 36 && memcmp(fa + 36, fb + 36, la - 36) != 0));
    SC_CHECK("the claim id inside the frame is the real one",
             memcmp(fa + 4, claim_id, 32) == 0);

    /* And a trial frame is checkable the same way. */
    uint8_t tid[32], tid_direct[32], back_claim[32];
    SC_CHECK("a peer verifies a trial from its bytes alone",
             science_trial_verify(fa, la, back_claim, tid) &&
                 memcmp(back_claim, claim_id, 32) == 0 &&
                 science_trial_id(claim_id, &won, tid_direct) &&
                 memcmp(tid, tid_direct, sizeof tid) == 0);

    /* Mutating a trial's fields must move its id. Bit-sweeping a 1.4KB frame
     * is slower than it is worth; the fields are swept instead, which is the
     * same claim at the granularity a forger would work at. */
    struct science_receipt v;
    bool all_move = true;
#define MOVES(mutate)                                                     \
    do {                                                                  \
        v = won;                                                          \
        mutate;                                                           \
        uint8_t vid[32];                                                  \
        all_move = all_move && science_trial_id(claim_id, &v, vid) &&     \
                   memcmp(vid, tid, sizeof vid) != 0;                     \
    } while (0)
    MOVES(v.repro.command = "something else");
    MOVES(v.repro.commit = "1111111111111111111111111111111111111111");
    MOVES(v.repro.input = "another seed");
    MOVES(v.repro.compiler = "other-cc 2.0.0");
    MOVES(v.repro.optimisation = "-O0");
    MOVES(v.repro.nproc = 16);
    MOVES(v.repro.stress_tests = true);
    MOVES(v.observed.n = 10);
    MOVES(v.observed.unit = "us");
    MOVES(v.observed.min_milli = 1);
    MOVES(v.observed.median_milli = 7032);
    MOVES(v.observed.p95_milli = 7401);
    MOVES(v.observed.max_milli = 7901);
    MOVES(v.verdict = ENGINE_VERDICT_HOLLOW);
    MOVES(v.files_changed = 99);
#undef MOVES
    SC_CHECK("changing any recorded field changes the trial's content address",
             all_move);

    /* A record whose reproduction block is incomplete does not verify, no
     * matter who sent it. A peer applies the same bar we do. */
    struct science_receipt holed = won;
    holed.repro.commit = "";
    SC_CHECK("a trial with a hole cannot even be encoded",
             science_trial_canonical(claim_id, &holed, fb, sizeof fb) == 0);
    return failures;
}

/* ── 16. a refutation is a first-class record ─────────────────────────── */

static int case_refutation_is_a_result(void)
{
    int failures = 0;
    char dir[512], path[640];
    struct science_register *reg = open_fresh(dir, sizeof dir, "refuted", path,
                                              sizeof path);
    if (!reg) {
        SC_CHECK("the register opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    /* Seed the register, then REFUTE the seeded belief that rewriting the
     * system prompt raises the pass rate — the paper's own ablation says the
     * gain is not there. A register that could only store confirmations would
     * have nowhere to put this. */
    SC_CHECK("the seeds install",
             science_seed_install(reg, NULL, NULL) == SCIENCE_OK);
    uint32_t prompt_index = science_seed_count();
    for (uint32_t i = 0; i < science_claim_count(reg); i++) {
        struct science_claim_spec spec;
        char st[SCIENCE_STATEMENT_MAX], tr[SCIENCE_TREATMENT_MAX];
        char src[SCIENCE_SOURCE_MAX];
        if (science_claim_spec_at(reg, i, &spec, st, tr, src) &&
            strstr(st, "system prompt") != NULL)
            prompt_index = i;
    }
    SC_CHECK("the prompt-prose claim is in the register",
             prompt_index < science_claim_count(reg));
    if (prompt_index >= science_claim_count(reg)) {
        science_close(reg);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    uint8_t id[32];
    struct science_reading r;
    SC_CHECK("it starts UNTESTED",
             science_claim_id_at(reg, prompt_index, id) &&
                 science_claim_read(reg, id, &r) == SCIENCE_OK &&
                 r.status == SCIENCE_UNTESTED);
    SC_CHECK("twenty trials an arm arrive, and the prose made it WORSE",
             fill(reg, id, SCIENCE_ARM_CONTROL, "alice", 20, 16) &&
                 fill(reg, id, SCIENCE_ARM_TREATMENT, "bob", 20, 8));
    SC_CHECK("the seeded belief is REFUTED, and that is a stored result",
             science_claim_read(reg, id, &r) == SCIENCE_OK &&
                 r.status == SCIENCE_REFUTED && r.effect_milli == -400);
    SC_CHECK("a refutation is named, not hidden",
             strcmp(science_status_name(r.status), "REFUTED") == 0);
    SC_CHECK("and it survives the close and reopen like any other result",
             (science_close(reg), true));
    struct science_open_report rep;
    reg = science_open(path, &rep);
    SC_CHECK("the register reopens with the refutation intact",
             reg != NULL && science_claim_read(reg, id, &r) == SCIENCE_OK &&
                 r.status == SCIENCE_REFUTED && r.trials == 40);
    science_close(reg);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 17. the refusal and status vocabularies name themselves ──────────── */

static int case_surface(void)
{
    int failures = 0;
    SC_CHECK("every status names itself",
             strcmp(science_status_name(SCIENCE_UNTESTED), "UNTESTED") == 0 &&
                 strcmp(science_status_name(SCIENCE_SUPPORTED),
                        "SUPPORTED") == 0 &&
                 strcmp(science_status_name(SCIENCE_REFUTED), "REFUTED") == 0 &&
                 strcmp(science_status_name(SCIENCE_INCONCLUSIVE),
                        "INCONCLUSIVE") == 0 &&
                 strcmp(science_status_name((enum science_status)77),
                        "UNKNOWN_STATUS") == 0);
    SC_CHECK("every refusal names itself",
             strcmp(science_refusal_name(SCIENCE_OK), "OK") == 0 &&
                 strcmp(science_refusal_name(SCIENCE_REFUSED_EFFECT_FLOOR),
                        "EFFECT_FLOOR") == 0 &&
                 strcmp(science_refusal_name(SCIENCE_REFUSED_SAMPLE_FLOOR),
                        "SAMPLE_FLOOR") == 0 &&
                 strcmp(science_refusal_name((enum science_refusal)77),
                        "UNKNOWN_REFUSAL") == 0);
    SC_CHECK("directions and arms name themselves",
             strcmp(science_direction_name(SCIENCE_DIRECTION_UP), "up") == 0 &&
                 strcmp(science_direction_name(SCIENCE_DIRECTION_DOWN),
                        "down") == 0 &&
                 strcmp(science_direction_name(SCIENCE_DIRECTION_NONE),
                        "unknown_direction") == 0 &&
                 strcmp(science_arm_name(SCIENCE_ARM_CONTROL), "control") == 0 &&
                 strcmp(science_arm_name(SCIENCE_ARM_TREATMENT),
                        "treatment") == 0);

    /* A register needs a caller-supplied path. It never picks a directory of
     * its own, which is what keeps it out of a node datadir. */
    struct science_open_report rep;
    SC_CHECK("opening with no path refuses",
             science_open(NULL, &rep) == NULL &&
                 rep.refusal == SCIENCE_REFUSED_ARGUMENT);
    SC_CHECK("opening with an empty path refuses",
             science_open("", &rep) == NULL &&
                 rep.refusal == SCIENCE_REFUSED_ARGUMENT);
    SC_CHECK("closing NULL is safe", (science_close(NULL), true));
    SC_CHECK("counting a NULL register is zero",
             science_claim_count(NULL) == 0);

    /* Out-of-range receipt numbers are refused, never clamped: a clamped
     * value would be a measurement nobody took. */
    char dir[512], path[640];
    struct science_register *reg = open_fresh(dir, sizeof dir, "surface", path,
                                              sizeof path);
    if (reg) {
        struct science_claim_spec s = good_spec();
        uint8_t id[32];
        (void)science_claim_register(reg, &s, id);
        struct science_receipt rc =
            receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);
        rc.completion_tokens = -1;
        SC_CHECK("a negative token count is refused",
                 science_trial_record(reg, id, &rc) == SCIENCE_REFUSED_FIELD);
        rc.completion_tokens = SCIENCE_TOKENS_MAX + 1;
        SC_CHECK("an absurd token count is refused, not clamped",
                 science_trial_record(reg, id, &rc) == SCIENCE_REFUSED_FIELD);
        rc = receipt("alice", SCIENCE_ARM_CONTROL, ENGINE_VERDICT_PASS);
        rc.files_changed = SCIENCE_FILES_MAX + 1u;
        SC_CHECK("an absurd file count is refused",
                 science_trial_record(reg, id, &rc) == SCIENCE_REFUSED_FIELD);
        rc = receipt("alice", SCIENCE_ARM_CONTROL, (enum engine_verdict)42);
        SC_CHECK("a verdict outside the engine's enum is refused",
                 science_trial_record(reg, id, &rc) == SCIENCE_REFUSED_VERDICT);
        struct science_reading r;
        SC_CHECK("none of the refused receipts entered the register",
                 science_claim_read(reg, id, &r) == SCIENCE_OK &&
                     r.trials == 0 && r.status == SCIENCE_UNTESTED);
        science_close(reg);
    } else {
        SC_CHECK("the register opens", false);
    }
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_science(void);
int test_science(void)
{
    int failures = 0;
    failures += case_falsifier_required();
    failures += case_metric_closed();
    failures += case_sample_floor_first();
    failures += case_three_verdicts();
    failures += case_hollow_and_ratio();
    failures += case_no_status_setter();
    failures += case_producers();
    failures += case_canonical();
    failures += case_durability();
    failures += case_corpus_honesty();
    failures += case_falsifier_immutable();
    failures += case_seeds();
    failures += case_repeatable_by_a_stranger();
    failures += case_data_not_summary();
    failures += case_peer_verifiable();
    failures += case_refutation_is_a_result();
    failures += case_surface();
    printf("science: %d failure(s)\n", failures);
    return failures;
}
