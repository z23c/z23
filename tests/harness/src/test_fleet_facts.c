/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: The fleet fact table answers every seeded row, and answers an ask
 *          it has no row for without guessing.
 *
 * Two surfaces, one group: cognition/modules/fleetfacts (the table and the
 * query) and dev.know (the leaf), called in process through the real registry
 * so an input key the .def never declared fails here rather than from a shell.
 *
 * NOT proven here, and deliberately: that the lint gate rejects a bad row.
 * tools/lint/check_fleet_facts.sh carries its own `--selftest` over a fixture
 * table — an undeclared object, an undeclared relation, an UNKNOWN
 * confidence, a duplicated row, an empty why and an unused term each have to
 * fail before the gate will report on the real table — and `make
 * check-fleet-facts` runs that selftest before the scan on every lint cycle.
 * Reimplementing it here would be a second oracle over the same fixture. */
#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "fleetfacts/fleet_facts.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <string.h>

#define FFT_PATH "dev.fleet.know"

/* ── one in-process invocation of the leaf ─────────────────────────────── */

struct fft_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void fft_begin(struct fft_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), FFT_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.dev_know.v1");
}

static bool fft_run(struct fft_call *c)
{
    char why[192];

    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_dev_know(&c->request, &c->reply);
    return true;
}

static void fft_end(struct fft_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static const struct json_value *fft_get(const struct fft_call *c,
                                        const char *key)
{
    return json_get(&c->reply.data, key);
}

static bool fft_bool(const struct fft_call *c, const char *key)
{
    const struct json_value *v = fft_get(c, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static int64_t fft_int(const struct fft_call *c, const char *key)
{
    const struct json_value *v = fft_get(c, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static const char *fft_row_str(const struct fft_call *c, size_t index,
                               const char *key)
{
    const struct json_value *rows = fft_get(c, "rows");
    const struct json_value *row = rows ? json_at(rows, index) : NULL;
    const struct json_value *v = row ? json_get(row, key) : NULL;
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

/* ── the table ─────────────────────────────────────────────────────────── */

static int test_fleet_facts_table(void)
{
    int failures = 0;

    TEST("fleet_facts: every seeded row resolves through its own subject") {
        size_t count = zcl_fleet_facts_row_count();
        ASSERT(count >= 20);
        for (size_t i = 0; i < count; i++) {
            struct zcl_fleet_fact_v1 row;
            struct zcl_fleet_facts_answer_v1 answer;
            bool found = false;

            ASSERT(zcl_fleet_facts_get(i, &row));
            /* Every stored row is asserted, never unknown, and carries a
             * root and a reason: a row that cannot say why it is here is
             * indistinguishable from a guess. */
            ASSERT(row.confidence == ZCL_FLEET_CONFIDENCE_DOCTRINE ||
                   row.confidence == ZCL_FLEET_CONFIDENCE_OBSERVED);
            ASSERT(strlen(row.provenance) == 64);
            ASSERT(row.why[0] != '\0');
            ASSERT(row.subject[0] != '\0' && row.object[0] != '\0');

            ASSERT(zcl_fleet_facts_query(row.subject, row.relation,
                                         row.context,
                                         ZCL_FLEET_FACTS_MAX_ROWS, &answer));
            ASSERT(!answer.unknown);
            for (size_t j = 0; j < answer.row_count; j++)
                if (strcmp(answer.rows[j].provenance, row.provenance) == 0)
                    found = true;
            ASSERT(found);
        }
        PASS();
    }

    TEST("fleet_facts: the row root is the row, not the position") {
        struct zcl_fleet_fact_v1 a, b;
        ASSERT(zcl_fleet_facts_get(0, &a));
        ASSERT(zcl_fleet_facts_get(1, &b));
        ASSERT(strcmp(a.provenance, b.provenance) != 0);
        PASS();
    }

    TEST("fleet_facts: an unknown subject answers one UNKNOWN row, never none") {
        struct zcl_fleet_facts_answer_v1 answer;
        ASSERT(zcl_fleet_facts_query("no-such-subject", NULL, NULL, 8,
                                     &answer));
        ASSERT(answer.unknown);
        ASSERT_EQ(answer.row_count, (size_t)1);
        ASSERT_EQ(answer.total, (size_t)1);
        ASSERT(!answer.truncated);
        ASSERT(answer.rows[0].confidence == ZCL_FLEET_CONFIDENCE_UNKNOWN);
        ASSERT_STR_EQ(answer.rows[0].subject, "no-such-subject");
        ASSERT_STR_EQ(answer.rows[0].object, "");
        ASSERT(answer.rows[0].why[0] != '\0');
        PASS();
    }

    TEST("fleet_facts: a malformed ask is refused, not answered") {
        struct zcl_fleet_facts_answer_v1 answer;
        ASSERT(!zcl_fleet_facts_query(NULL, NULL, NULL, 8, &answer));
        ASSERT(!zcl_fleet_facts_query("", NULL, NULL, 8, &answer));
        ASSERT(!zcl_fleet_facts_query("sonnet", NULL, NULL, 8, NULL));
        PASS();
    }

    TEST("fleet_facts: the relation filter narrows, and narrows exactly") {
        struct zcl_fleet_facts_answer_v1 all, well;
        ASSERT(zcl_fleet_facts_query("sonnet", NULL, NULL,
                                     ZCL_FLEET_FACTS_MAX_ROWS, &all));
        ASSERT(!all.unknown);
        ASSERT(all.total >= 2);
        ASSERT(zcl_fleet_facts_query("sonnet", "handles_well", NULL,
                                     ZCL_FLEET_FACTS_MAX_ROWS, &well));
        ASSERT(!well.unknown);
        ASSERT(well.total <= all.total);
        for (size_t i = 0; i < well.row_count; i++)
            ASSERT_STR_EQ(well.rows[i].relation, "handles_well");
        /* A relation the subject has no row for is UNKNOWN, not empty. */
        struct zcl_fleet_facts_answer_v1 none;
        ASSERT(zcl_fleet_facts_query("sonnet", "trap_signature", NULL,
                                     ZCL_FLEET_FACTS_MAX_ROWS, &none));
        ASSERT(none.unknown);
        ASSERT_EQ(none.row_count, (size_t)1);
        PASS();
    }

    TEST("fleet_facts: the context filter selects one microtheory") {
        struct zcl_fleet_facts_answer_v1 proof, doctrine;
        ASSERT(zcl_fleet_facts_query("test_boot_phase", NULL, "lane_state:proof",
                                     ZCL_FLEET_FACTS_MAX_ROWS, &proof));
        ASSERT(!proof.unknown);
        for (size_t i = 0; i < proof.row_count; i++)
            ASSERT_STR_EQ(proof.rows[i].context, "lane_state:proof");
        ASSERT(zcl_fleet_facts_query("test_boot_phase", NULL, "doctrine",
                                     ZCL_FLEET_FACTS_MAX_ROWS, &doctrine));
        ASSERT(doctrine.unknown);
        PASS();
    }

    TEST("fleet_facts: a row budget truncates loudly, never silently") {
        struct zcl_fleet_facts_answer_v1 full, cut;
        ASSERT(zcl_fleet_facts_query("sonnet", NULL, NULL,
                                     ZCL_FLEET_FACTS_MAX_ROWS, &full));
        ASSERT(full.total >= 2);
        ASSERT(!full.truncated);
        ASSERT(zcl_fleet_facts_query("sonnet", NULL, NULL, 1, &cut));
        ASSERT_EQ(cut.row_count, (size_t)1);
        ASSERT_EQ(cut.total, full.total);
        ASSERT(cut.truncated);
        PASS();
    }

    TEST("fleet_facts: the vocabularies are closed and non-empty") {
        ASSERT(zcl_fleet_facts_relation_count() >= 4);
        ASSERT(zcl_fleet_facts_context_count() >= 4);
        ASSERT(zcl_fleet_facts_term_count() >= 20);
        ASSERT(zcl_fleet_facts_relation_at(0) != NULL);
        ASSERT(zcl_fleet_facts_relation_at(
                   zcl_fleet_facts_relation_count()) == NULL);
        ASSERT(zcl_fleet_facts_context_at(
                   zcl_fleet_facts_context_count()) == NULL);
        ASSERT(zcl_fleet_facts_term_at(zcl_fleet_facts_term_count()) == NULL);
        ASSERT_STR_EQ(zcl_fleet_facts_confidence_name(
                          ZCL_FLEET_CONFIDENCE_DOCTRINE), "doctrine");
        ASSERT_STR_EQ(zcl_fleet_facts_confidence_name(
                          ZCL_FLEET_CONFIDENCE_UNKNOWN), "unknown");
        PASS();
    }

_test_next:;
    return failures;
}

/* ── the leaf ──────────────────────────────────────────────────────────── */

static int test_fleet_facts_leaf(void)
{
    int failures = 0;

    TEST("dev.know: registered read-only, dev-only, operator authority") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), FFT_PATH, NULL);
        ASSERT(spec != NULL);
        /* `z23 dev know` is the ask an agent is told to make, and it reaches
         * this leaf through the declared alias, not a second registration. */
        ASSERT(spec->aliases && strcmp(spec->aliases, "dev.know") == 0);
        ASSERT(spec->handler == zcl_native_handle_dev_know);
        ASSERT_EQ((int)spec->effect, (int)ZCL_COMMAND_EFFECT_READ);
        ASSERT_EQ((int)spec->authority, (int)ZCL_COMMAND_AUTH_OPERATOR);
        ASSERT((spec->traits & ZCL_COMMAND_TRAIT_DEV_ONLY) != 0);
        PASS();
    }

    TEST("dev.know: --subject sonnet answers what Sonnet handles well") {
        struct fft_call c;
        bool saw_handles_well = false;

        fft_begin(&c);
        (void)json_push_kv_str(&c.input, "subject", "sonnet");
        ASSERT(fft_run(&c));
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!fft_bool(&c, "unknown"));
        ASSERT(fft_int(&c, "row_count") >= 2);
        for (int64_t i = 0; i < fft_int(&c, "row_count"); i++) {
            ASSERT_STR_EQ(fft_row_str(&c, (size_t)i, "subject"), "sonnet");
            ASSERT_STR_EQ(fft_row_str(&c, (size_t)i, "confidence"), "doctrine");
            ASSERT(strlen(fft_row_str(&c, (size_t)i, "provenance")) == 64);
            ASSERT(fft_row_str(&c, (size_t)i, "why")[0] != '\0');
            if (strcmp(fft_row_str(&c, (size_t)i, "relation"),
                       "handles_well") == 0)
                saw_handles_well = true;
        }
        ASSERT(saw_handles_well);
        fft_end(&c);
        PASS();
    }

    TEST("dev.know: a trap signature names its trap") {
        struct fft_call c;

        fft_begin(&c);
        (void)json_push_kv_str(&c.input, "subject", "test_boot_phase");
        (void)json_push_kv_str(&c.input, "relation", "trap_signature");
        ASSERT(fft_run(&c));
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!fft_bool(&c, "unknown"));
        ASSERT_EQ(fft_int(&c, "row_count"), (int64_t)1);
        ASSERT_STR_EQ(fft_row_str(&c, 0, "object"), "ram-generation-root");
        fft_end(&c);
        PASS();
    }

    TEST("dev.know: an unanswered subject returns one unknown row") {
        struct fft_call c;

        fft_begin(&c);
        (void)json_push_kv_str(&c.input, "subject", "no-such-subject");
        ASSERT(fft_run(&c));
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_PASSED);
        ASSERT(fft_bool(&c, "unknown"));
        ASSERT_EQ(fft_int(&c, "row_count"), (int64_t)1);
        ASSERT_STR_EQ(fft_row_str(&c, 0, "confidence"), "unknown");
        ASSERT(!fft_bool(&c, "truncated"));
        fft_end(&c);
        PASS();
    }

    TEST("dev.know: no subject, and a relation outside the vocabulary, "
              "are both refused") {
        struct fft_call c;

        fft_begin(&c);
        ASSERT(fft_run(&c));
        ASSERT(c.reply.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(c.reply.error.code, "SUBJECT_REQUIRED");
        fft_end(&c);

        fft_begin(&c);
        (void)json_push_kv_str(&c.input, "subject", "sonnet");
        (void)json_push_kv_str(&c.input, "relation", "handles_wel");
        ASSERT(fft_run(&c));
        ASSERT(c.reply.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(c.reply.error.code, "UNKNOWN_VOCABULARY");
        /* The refusal teaches the whole closed set rather than the miss. */
        ASSERT(strstr(c.reply.error.message, "handles_well") != NULL);
        fft_end(&c);
        PASS();
    }

    TEST("dev.know: a budget cut is typed, and still reports the total") {
        struct fft_call c;

        fft_begin(&c);
        (void)json_push_kv_str(&c.input, "subject", "sonnet");
        (void)json_push_kv_int(&c.input, "budget_bytes", 256);
        ASSERT(fft_run(&c));
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_PASSED);
        ASSERT(fft_bool(&c, "truncated"));
        ASSERT_EQ(fft_int(&c, "row_count"), (int64_t)1);
        ASSERT(fft_int(&c, "total") > fft_int(&c, "row_count"));
        ASSERT_EQ(fft_int(&c, "budget_bytes"), (int64_t)256);
        fft_end(&c);
        PASS();
    }

_test_next:;
    return failures;
}

int test_fleet_facts(void)
{
    int failures = 0;
    failures += test_fleet_facts_table();
    failures += test_fleet_facts_leaf();
    return failures;
}
