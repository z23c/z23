/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: fleet_observe classifies at the exact named thresholds, refuses a
 *          malformed ledger row and an unknown enum by line number, detects
 *          a drifted committed .def, and the rows it emits answer dev.know.
 *
 * NOT proven here: that tools/lint/check_fleet_observations.sh's own
 * --selftest rejects a hand-edited committed file end to end — that gate
 * carries its own fixture-driven selftest, run before every scan by `make
 * check-fleet-observations`. This group proves the library the gate and the
 * CLI both call. */
#include "test/test_core.h"

#include "fleet_observe.h"
#include "fleetfacts/fleet_facts.h"

#include <string.h>

/* ── classification thresholds ────────────────────────────────────────── */

static struct fo_pair fo_pair(const char *ex, const char *tc, int64_t n,
                              int64_t land, int64_t fix_land)
{
    struct fo_pair p;

    memset(&p, 0, sizeof(p));
    (void)snprintf(p.executor, sizeof(p.executor), "%s", ex);
    (void)snprintf(p.task_class, sizeof(p.task_class), "%s", tc);
    p.n = n;
    p.land = land;
    p.fix_land = fix_land;
    return p;
}

static int test_fleet_observe_classify(void)
{
    int failures = 0;

    TEST("classify: n>=3 and p>=0.8 is routable_for") {
        struct fo_pair p = fo_pair("grok", "unit_c23_one_file", 3, 3, 0);
        struct fo_observation out[2];
        size_t k = fo_classify(&p, out);

        ASSERT_EQ((int)k, 1);
        ASSERT_STR_EQ(out[0].relation, "routable_for");
        ASSERT_EQ(out[0].num, (int64_t)3);
        ASSERT_EQ(out[0].den, (int64_t)3);
        PASS();
    }

    TEST("classify: 0 of n>=2 is refused_for, even though n<3") {
        struct fo_pair p = fo_pair("mac", "land_train", 2, 0, 0);
        struct fo_observation out[2];
        size_t k = fo_classify(&p, out);

        ASSERT_EQ((int)k, 1);
        ASSERT_STR_EQ(out[0].relation, "refused_for");
        PASS();
    }

    TEST("classify: n<3 and not all-zero is probe_for") {
        struct fo_pair p = fo_pair("grok", "unit_docs", 2, 2, 0);
        struct fo_observation out[2];
        size_t k = fo_classify(&p, out);

        ASSERT_EQ((int)k, 1);
        ASSERT_STR_EQ(out[0].relation, "probe_for");
        PASS();
    }

    TEST("classify: n==1 and 0 landed is probe_for, not refused_for "
              "(refused needs n>=2)") {
        struct fo_pair p = fo_pair("claude-haiku", "diagnose", 1, 0, 0);
        struct fo_observation out[2];
        size_t k = fo_classify(&p, out);

        ASSERT_EQ((int)k, 1);
        ASSERT_STR_EQ(out[0].relation, "probe_for");
        PASS();
    }

    TEST("classify: n=3, p=2/3 (0.67) clears neither routable nor probe nor "
              "refused, so it is observed_for") {
        struct fo_pair p = fo_pair("glm", "verify", 3, 2, 0);
        struct fo_observation out[2];
        size_t k = fo_classify(&p, out);

        ASSERT_EQ((int)k, 1);
        ASSERT_STR_EQ(out[0].relation, "observed_for");
        ASSERT_EQ(out[0].num, (int64_t)2);
        ASSERT_EQ(out[0].den, (int64_t)3);
        PASS();
    }

    TEST("classify: n=4, p=0.75 is also observed_for (below the 0.8 floor)") {
        struct fo_pair p = fo_pair("claude-sonnet", "rebase_land", 4, 3, 0);
        struct fo_observation out[2];
        size_t k = fo_classify(&p, out);

        ASSERT_EQ((int)k, 1);
        ASSERT_STR_EQ(out[0].relation, "observed_for");
        PASS();
    }

    TEST("classify: FIX_LAND at half of n or more adds a second "
              "handles_with_finisher row") {
        struct fo_pair p = fo_pair("grok", "unit_c23_one_file", 3, 3, 2);
        struct fo_observation out[2];
        size_t k = fo_classify(&p, out);

        ASSERT_EQ((int)k, 2);
        ASSERT_STR_EQ(out[0].relation, "routable_for");
        ASSERT_STR_EQ(out[1].relation, "handles_with_finisher");
        ASSERT_EQ(out[1].num, (int64_t)2);
        ASSERT_EQ(out[1].den, (int64_t)3);
        PASS();
    }

    TEST("classify: FIX_LAND below half of n adds no second row") {
        struct fo_pair p = fo_pair("claude-sonnet", "verify", 10, 10, 1);
        struct fo_observation out[2];
        size_t k = fo_classify(&p, out);

        ASSERT_EQ((int)k, 1);
        PASS();
    }

_test_next:;
    return failures;
}

/* ── ledger parsing: malformed rows and unknown enums ─────────────────── */

static int test_fleet_observe_parse(void)
{
    int failures = 0;

    TEST("parse: a well-formed result row parses clean") {
        struct fo_row row;
        char err[128];
        const char *line =
            "2026-09-01T09:00:00Z\tresult\tnode1\tt1\tverify\tstory\t"
            "claude-sonnet\tagent-tool\tsonnet\tmedium\t1\t1\t1\t0\t1\t1\t"
            "1\tLAND\t0\t0\t0\tnote";

        ASSERT(fo_parse_line(line, 7, &row, err, sizeof(err)));
        ASSERT_STR_EQ(row.executor, "claude-sonnet");
        ASSERT_STR_EQ(row.task_class, "verify");
        ASSERT_STR_EQ(row.outcome, "LAND");
        PASS();
    }

    TEST("parse: a row missing fields is refused and names its line") {
        struct fo_row row;
        char err[128];

        ASSERT(!fo_parse_line("2026-09-01T09:00:00Z\tresult\tnode1", 42, &row,
                              err, sizeof(err)));
        ASSERT(strstr(err, "42") != NULL);
        PASS();
    }

    TEST("parse: an unknown task_class is refused, named line included") {
        struct fo_row row;
        char err[128];
        const char *line =
            "2026-09-01T09:00:00Z\tresult\tnode1\tt1\tnot_a_class\tstory\t"
            "grok\tgrok-cli-queue\tgrok-4.6\thigh\t1\t1\t1\t0\t1\t1\t1\t"
            "LAND\t0\t0\t0\tnote";

        ASSERT(!fo_parse_line(line, 5, &row, err, sizeof(err)));
        ASSERT(strstr(err, "5") != NULL);
        ASSERT(strstr(err, "task_class") != NULL);
        PASS();
    }

    TEST("parse: an unknown executor is refused") {
        struct fo_row row;
        char err[128];
        const char *line =
            "2026-09-01T09:00:00Z\tresult\tnode1\tt1\tverify\tstory\t"
            "not_an_executor\tagent-tool\tsonnet\tmedium\t1\t1\t1\t0\t1\t1\t"
            "1\tLAND\t0\t0\t0\tnote";

        ASSERT(!fo_parse_line(line, 9, &row, err, sizeof(err)));
        ASSERT(strstr(err, "executor") != NULL);
        PASS();
    }

    TEST("parse: an unknown outcome is refused") {
        struct fo_row row;
        char err[128];
        const char *line =
            "2026-09-01T09:00:00Z\tresult\tnode1\tt1\tverify\tstory\t"
            "grok\tgrok-cli-queue\tgrok-4.6\thigh\t1\t1\t1\t0\t1\t1\t1\t"
            "MAYBE\t0\t0\t0\tnote";

        ASSERT(!fo_parse_line(line, 11, &row, err, sizeof(err)));
        ASSERT(strstr(err, "outcome") != NULL);
        PASS();
    }

    TEST("parse: a malformed ISO-8601 timestamp is refused") {
        struct fo_row row;
        char err[128];
        const char *line =
            "not-a-timestamp\tresult\tnode1\tt1\tverify\tstory\t"
            "grok\tgrok-cli-queue\tgrok-4.6\thigh\t1\t1\t1\t0\t1\t1\t1\t"
            "LAND\t0\t0\t0\tnote";

        ASSERT(!fo_parse_line(line, 3, &row, err, sizeof(err)));
        ASSERT(strstr(err, "3") != NULL);
        PASS();
    }

_test_next:;
    return failures;
}

/* ── --check drift detection ──────────────────────────────────────────── */

static int test_fleet_observe_check(void)
{
    int failures = 0;

    TEST("render: two generations from the same rows are byte-identical, "
              "and a mutated observation set renders differently") {
        struct fo_observation obs[2];
        char a[4096], b[4096];
        size_t la, lb;

        memset(obs, 0, sizeof(obs));
        (void)snprintf(obs[0].subject, sizeof(obs[0].subject), "grok");
        (void)snprintf(obs[0].relation, sizeof(obs[0].relation),
                       "routable_for");
        (void)snprintf(obs[0].object, sizeof(obs[0].object),
                       "unit_c23_one_file");
        obs[0].num = 3;
        obs[0].den = 3;

        la = fo_render_def(obs, 1, 7, 1788512400, "tests/fixtures/x", a,
                           sizeof(a));
        lb = fo_render_def(obs, 1, 7, 1788512400, "tests/fixtures/x", b,
                           sizeof(b));
        ASSERT_EQ((int)la, (int)lb);
        ASSERT(strcmp(a, b) == 0);

        obs[0].den = 4; /* a drifted committed file would look like this */
        lb = fo_render_def(obs, 1, 7, 1788512400, "tests/fixtures/x", b,
                           sizeof(b));
        (void)lb;
        ASSERT(strcmp(a, b) != 0);
        PASS();
    }

_test_next:;
    return failures;
}

/* ── dev.know answers from the generated table ────────────────────────── */

static int test_fleet_observe_dev_know(void)
{
    int failures = 0;

    TEST("dev.know: a routable_for ask answers with num/den/window in why") {
        struct zcl_fleet_facts_answer_v1 answer;
        bool found = false;

        ASSERT(zcl_fleet_facts_query("grok", "routable_for", NULL,
                                     ZCL_FLEET_FACTS_MAX_ROWS, &answer));
        ASSERT(!answer.unknown);
        for (size_t i = 0; i < answer.row_count; i++) {
            if (strcmp(answer.rows[i].object, "unit_c23_one_file") == 0) {
                found = true;
                ASSERT_EQ((int)answer.rows[i].confidence,
                          (int)ZCL_FLEET_CONFIDENCE_OBSERVED);
                ASSERT(strstr(answer.rows[i].why, "3/3") != NULL);
                ASSERT(strstr(answer.rows[i].why, "7 days") != NULL);
            }
        }
        ASSERT(found);
        PASS();
    }

    TEST("dev.know: a probe_for ask answers too, distinctly from routable") {
        struct zcl_fleet_facts_answer_v1 answer;
        bool found = false;

        ASSERT(zcl_fleet_facts_query("glm", "probe_for", NULL,
                                     ZCL_FLEET_FACTS_MAX_ROWS, &answer));
        ASSERT(!answer.unknown);
        for (size_t i = 0; i < answer.row_count; i++) {
            if (strcmp(answer.rows[i].object, "unit_c23_one_file") == 0)
                found = true;
        }
        ASSERT(found);
        PASS();
    }

    TEST("dev.know: an executor with no observed row for a relation "
              "answers unknown, same as the doctrine table") {
        struct zcl_fleet_facts_answer_v1 answer;

        ASSERT(zcl_fleet_facts_query("codex", "routable_for", NULL,
                                     ZCL_FLEET_FACTS_MAX_ROWS, &answer));
        ASSERT(answer.unknown);
        PASS();
    }

_test_next:;
    return failures;
}

int test_fleet_observe(void)
{
    int failures = 0;
    failures += test_fleet_observe_classify();
    failures += test_fleet_observe_parse();
    failures += test_fleet_observe_check();
    failures += test_fleet_observe_dev_know();
    return failures;
}
