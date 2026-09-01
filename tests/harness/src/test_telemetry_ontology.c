/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_telemetry_ontology — the field-level meaning table and its evaluator.
 *
 * The defect these checks exist to prevent is the one that cost real time:
 * `"pre_handshake_disconnects":27` on a healthy node and the same field at 8
 * on a node that could not start are IDENTICAL IN SHAPE, and nothing in the
 * output tells the reader that the second one is the whole story. So the
 * checks below are not "does the table parse" — they drive the two real dumps
 * through the evaluator and assert it calls the healthy one healthy and names
 * the broken one, critically, with a next step.
 */

#include "test/test_core.h"

#include "json/json.h"
#include "util/telemetry_ontology.h"

#include <stdio.h>
#include <string.h>

/* One label-free assertion per line. TEST/ASSERT mint a per-function
 * `_test_next` label, so they cannot be used many times inside one function;
 * these checks are numerous and independent, so they report individually and
 * keep going rather than jumping out on the first failure. */
#define TO_CHECK(name, cond) \
    do { \
        printf("%s... ", (name)); \
        if (cond) { printf("OK\n"); } \
        else { printf("FAIL (%s)\n", #cond); failures++; } \
    } while (0)

/* The healthy live node's peer_lifecycle summary, verbatim. */
static const char *k_healthy_dump =
    "{\"summary\":{\"attempted\":332,\"connected\":383,\"version_sent\":358,"
    "\"version_received\":356,\"verack_received\":246,"
    "\"handshake_complete\":356,\"active\":353,\"disconnected\":149,"
    "\"timeout\":213,\"rejected\":0,\"cache_skipped\":146,"
    "\"pre_handshake_disconnects\":27}}";

/* The node that could not start: 8 dials, 8 pre-handshake disconnects, zero
 * handshakes. Same shape, opposite meaning. */
static const char *k_broken_dump =
    "{\"summary\":{\"attempted\":8,\"connected\":8,\"version_sent\":8,"
    "\"version_received\":0,\"verack_received\":0,"
    "\"handshake_complete\":0,\"active\":0,\"disconnected\":8,"
    "\"timeout\":0,\"rejected\":0,\"cache_skipped\":0,"
    "\"pre_handshake_disconnects\":8}}";

static const struct json_value *find_finding(const struct json_value *out,
                                             const char *path)
{
    const struct json_value *f = json_get(out, "findings");
    if (!f)
        return NULL;
    for (size_t i = 0; i < json_size(f); i++) {
        const struct json_value *e = json_at(f, i);
        const char *p = json_get_str(json_get(e, "path"));
        if (p && strcmp(p, path) == 0)
            return e;
    }
    return NULL;
}

static int check_table_shape(void)
{
    int failures = 0;

    TO_CHECK("[ontology] the six question-answering subsystems are covered",
             telemetry_subsystem_covered("peer_lifecycle") &&
             telemetry_subsystem_covered("connman") &&
             telemetry_subsystem_covered("addrman") &&
             telemetry_subsystem_covered("network") &&
             telemetry_subsystem_covered("fast_sync") &&
             telemetry_subsystem_covered("sync_rate"));

    TO_CHECK("[ontology] an uncovered subsystem is reported as uncovered, "
             "never silently empty",
             !telemetry_subsystem_covered("no_such_subsystem") &&
             !telemetry_subsystem_covered(""));

    /* Every row states what it counts, and every JUDGED row also states what
     * an unhealthy value implies and where to look next. A row that carries a
     * rule but no consequence is exactly the hollow metadata this work
     * exists to remove. */
    int blank_means = 0, hollow_judged = 0, judged = 0;
    for (size_t i = 0; i < telemetry_field_count(); i++) {
        const struct telemetry_field *f = telemetry_field_at(i);
        if (!f->means || !f->means[0])
            blank_means++;
        if (f->rule == TFR_INFO)
            continue;
        judged++;
        if (!f->implies || !f->implies[0] || !f->next || !f->next[0])
            hollow_judged++;
    }
    TO_CHECK("[ontology] every row says what it counts", blank_means == 0);
    TO_CHECK("[ontology] every judged row says what a bad value implies and "
             "what to read next", hollow_judged == 0);
    TO_CHECK("[ontology] a meaningful number of rows carry a health rule",
             judged >= 20);

    /* A ratio rule with no operand cannot be evaluated by anything. */
    int bad_ratio = 0;
    for (size_t i = 0; i < telemetry_field_count(); i++) {
        const struct telemetry_field *f = telemetry_field_at(i);
        if ((f->rule == TFR_MIN_RATIO_OF || f->rule == TFR_MAX_RATIO_OF) &&
            (!f->operand || !f->operand[0] || f->threshold <= 0))
            bad_ratio++;
    }
    TO_CHECK("[ontology] every ratio rule names an operand and a threshold",
             bad_ratio == 0);

    return failures;
}

static int check_the_motivating_field(void)
{
    int failures = 0;
    const struct telemetry_field *f =
        telemetry_field_lookup("peer_lifecycle",
                               "summary.pre_handshake_disconnects");

    TO_CHECK("[ontology] pre_handshake_disconnects has a meaning row", f != NULL);
    if (!f)
        return failures;

    TO_CHECK("[ontology] it is judged as a RATIO of attempted, not as an "
             "absolute count (27 and 8 are the same absolute size of problem "
             "only if you ignore the denominator)",
             f->rule == TFR_MAX_RATIO_OF && f->operand &&
             strcmp(f->operand, "summary.attempted") == 0);
    TO_CHECK("[ontology] an unhealthy value is CRITICAL, not advisory",
             f->severity == TFS_CRITICAL);
    TO_CHECK("[ontology] its meaning names the zero-protocol-bytes fact",
             strstr(f->means, "before the VERSION") != NULL);
    TO_CHECK("[ontology] its implication names who is refusing whom",
             strstr(f->implies, "refusing us") != NULL);
    TO_CHECK("[ontology] its next step is the rejected/pre-handshake "
             "comparison that decides direction",
             strstr(f->next, "summary.rejected") != NULL);

    char range[192] = "";
    telemetry_field_healthy_range(f, range, sizeof(range));
    TO_CHECK("[ontology] the healthy range renders machine-readably",
             strcmp(range, "value <= 0.400 * summary.attempted") == 0);

    return failures;
}

static int check_evaluator(void)
{
    int failures = 0;
    struct json_value healthy = {0}, broken = {0}, out = {0};

    bool parsed = json_read(&healthy, k_healthy_dump, strlen(k_healthy_dump)) &&
                  json_read(&broken, k_broken_dump, strlen(k_broken_dump));
    TO_CHECK("[ontology] both fixture dumps parse", parsed);

    /* (a) The healthy live node: 27 of 332 pre-handshake disconnects and 356
     * handshakes must come back clean. A verdict that cries wolf on a healthy
     * node is worse than no verdict. */
    json_init(&out);
    bool ok = telemetry_ontology_annotate("peer_lifecycle", &healthy, &out);
    TO_CHECK("[ontology] annotate accepts a covered subsystem", ok);
    TO_CHECK("[ontology] healthy node: no unhealthy field",
             json_get_int(json_get(&out, "unhealthy_count")) == 0);
    TO_CHECK("[ontology] healthy node: rules actually ran (not a silent skip)",
             json_get_int(json_get(&out, "rules_evaluated")) >= 6);
    TO_CHECK("[ontology] healthy node: verdict is healthy",
             json_get_bool(json_get(&out, "healthy")));
    json_free(&out);

    /* (b) The node that could not start. Same JSON shape, and the evaluator
     * must name pre_handshake_disconnects AND handshake_complete, both
     * critical, and carry the next step on the finding itself. */
    json_init(&out);
    ok = telemetry_ontology_annotate("peer_lifecycle", &broken, &out);
    TO_CHECK("[ontology] broken node: annotate succeeds", ok);
    TO_CHECK("[ontology] broken node: verdict is unhealthy",
             !json_get_bool(json_get(&out, "healthy")));
    TO_CHECK("[ontology] broken node: at least one CRITICAL finding",
             json_get_int(json_get(&out, "critical_count")) >= 1);

    const struct json_value *phd =
        find_finding(&out, "summary.pre_handshake_disconnects");
    TO_CHECK("[ontology] broken node: 8-of-8 pre-handshake disconnects is a "
             "finding (the identical-shaped 27-of-332 was not)", phd != NULL);
    if (phd) {
        TO_CHECK("[ontology] the finding carries the offending value",
                 json_get_int(json_get(phd, "value")) == 8);
        TO_CHECK("[ontology] the finding is severity critical",
                 json_get_str(json_get(phd, "severity")) &&
                 strcmp(json_get_str(json_get(phd, "severity")),
                        "critical") == 0);
        TO_CHECK("[ontology] the finding carries a next command",
                 json_get_str(json_get(phd, "next")) &&
                 json_get_str(json_get(phd, "next"))[0] != '\0');
    }
    const struct json_value *hs = find_finding(&out, "summary.handshake_complete");
    TO_CHECK("[ontology] broken node: zero completed handshakes is named "
             "explicitly (question 3 answered by the evaluator itself)",
             hs != NULL);
    /* rejected is 0 in both dumps: we did not refuse anyone. The evaluator
     * must NOT report it, because that is what decides the direction of the
     * refusal. */
    TO_CHECK("[ontology] broken node: summary.rejected is NOT a finding, so "
             "the refusal is attributed to the peer and not to us",
             find_finding(&out, "summary.rejected") == NULL);
    json_free(&out);

    /* (c) An uncovered subsystem fails loud with a hint, never a silent pass. */
    json_init(&out);
    ok = telemetry_ontology_annotate("no_such_subsystem", &healthy, &out);
    TO_CHECK("[ontology] uncovered subsystem returns false",
             !ok && !json_get_bool(json_get(&out, "covered")));
    json_free(&out);

    json_free(&healthy);
    json_free(&broken);
    return failures;
}

static int check_discovery_index(void)
{
    int failures = 0;

    TO_CHECK("[ontology] the discovery index carries the questions that cost "
             "real time", telemetry_question_count() >= 8);

    /* Every question must route to a runnable command and say how to read the
     * answer; a question index that just names a subsystem is the same
     * guessing game it replaces. */
    int hollow = 0;
    bool saw_handshake = false, saw_direction = false, saw_root = false;
    for (size_t i = 0; i < telemetry_question_count(); i++) {
        const struct telemetry_question *q = telemetry_question_at(i);
        if (!q->question[0] || !q->command[0] || !q->how_to_read[0] ||
            !q->keywords[0])
            hollow++;
        if (strcmp(q->id, "any_handshake") == 0)
            saw_handshake = true;
        if (strcmp(q->id, "who_refused") == 0)
            saw_direction = true;
        if (strcmp(q->id, "which_blocker_is_root") == 0)
            saw_root = true;
    }
    TO_CHECK("[ontology] every question routes to a command and says how to "
             "read it", hollow == 0);
    TO_CHECK("[ontology] 'do I have any peer that completed a handshake' is "
             "indexed", saw_handshake);
    TO_CHECK("[ontology] 'is it them refusing me or me refusing them' is "
             "indexed", saw_direction);
    TO_CHECK("[ontology] 'which blocker is the root' is indexed", saw_root);

    return failures;
}

static int check_json_surface(void)
{
    int failures = 0;
    struct json_value out = {0};

    json_init(&out);
    bool ok = telemetry_ontology_json(&out, "peer_lifecycle");
    const struct json_value *fields = json_get(&out, "fields");
    TO_CHECK("[ontology] json by subsystem returns only that subsystem",
             ok && fields && json_size(fields) > 20);
    if (fields && json_size(fields) > 0) {
        const struct json_value *first = json_at(fields, 0);
        TO_CHECK("[ontology] a row carries unit, healthy_range, means, "
                 "implies and next",
                 json_get(first, "unit") && json_get(first, "healthy_range") &&
                 json_get(first, "means") && json_get(first, "implies") &&
                 json_get(first, "next"));
    }
    json_free(&out);

    /* A bare field name resolves without knowing which of 23 reports owns it
     * — that is the discovery half of the problem. */
    json_init(&out);
    ok = telemetry_ontology_json(&out, "pre_handshake_disconnects");
    fields = json_get(&out, "fields");
    TO_CHECK("[ontology] a bare field name resolves without naming a report",
             ok && fields && json_size(fields) >= 2);
    json_free(&out);

    json_init(&out);
    ok = telemetry_ontology_json(&out, "questions");
    TO_CHECK("[ontology] the questions key returns the discovery index",
             ok && json_get(&out, "questions") &&
             json_size(json_get(&out, "questions")) >= 8);
    json_free(&out);

    return failures;
}

int test_telemetry_ontology(void)
{
    int failures = 0;
    failures += check_table_shape();
    failures += check_the_motivating_field();
    failures += check_evaluator();
    failures += check_discovery_index();
    failures += check_json_surface();
    return failures;
}
