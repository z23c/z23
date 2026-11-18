/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.loop.measure reads records the caller already has. The fixture
 * numbers below are the record fields; the assertions check the catalog
 * handler's reply, not a second classifier.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <string.h>

static const char lm_window[] =
    "["
    "{\"schema\":\"zcl.code_guide_brief.v1\",\"question\":\"factory\","
    "\"tree\":\"t1\",\"prior_question\":\"factory\",\"prior_tree\":\"t1\","
    "\"prompt_tokens\":100,\"completion_tokens\":0,\"elapsed_ms\":2000},"
    "{\"schema\":\"zcl.hotswap_build_receipt.v1\",\"artifact_cache_key\":\"k1\","
    "\"artifact_cache_hit\":true,\"prompt_tokens\":40,\"completion_tokens\":0,"
    "\"build_total_us\":8000000},"
    "{\"schema\":\"zcl.agent_fast_plan.v1\",\"test_groups\":\"dev_factory\","
    "\"prior_test_groups\":\"dev_factory\",\"prompt_tokens\":10,"
    "\"completion_tokens\":0,\"elapsed_ms\":1500},"
    "{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"failed\","
    "\"stage_detail\":\"undefined-ref\",\"prior_stage_detail\":\"undefined-ref\","
    "\"elapsed_ms\":3000},"
    "{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
    "\"proof_scope\":\"source_wide_compile_tests_lint_fast\","
    "\"proof_inputs_sha3\":\"aa\",\"stale\":true,\"prompt_tokens\":50,"
    "\"completion_tokens\":0,\"elapsed_ms\":20000},"
    "{\"schema\":\"zcl.plugin_call.v1\",\"name\":\"upper\",\"elapsed_ms\":500,"
    "\"prompt_tokens\":20,\"completion_tokens\":0},"
    "{\"commit\":\"0123456789abcdef0123456789abcdef01234567\"}"
    "]";

struct lm_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
    const struct zcl_command_spec *spec;
};

static void lm_end(struct lm_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool lm_begin(struct lm_call *c, const char *records)
{
    memset(c, 0, sizeof(*c));
    json_init(&c->input);
    json_set_object(&c->input);
    c->spec = zcl_command_registry_find(zcl_command_catalog(),
                                        "dev.loop.measure", NULL);
    if (!c->spec)
        return false;
    c->request.spec = c->spec;
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, c->spec->output_schema);
    if (records && !json_push_kv_str(&c->input, "records", records))
        return false;
    if (c->spec->handler)
        c->spec->handler(&c->request, &c->reply);
    else
        zcl_native_handle_dev_loop_measure(&c->request, &c->reply);
    return true;
}

static const struct json_value *lm_at(const struct lm_call *c, const char *path)
{
    const struct json_value *v = &c->reply.data;
    const char *p = path;
    while (v && *p) {
        char key[64];
        size_t n = 0;
        while (*p && *p != '.' && n + 1 < sizeof(key))
            key[n++] = *p++;
        key[n] = '\0';
        if (*p == '.')
            p++;
        v = json_get(v, key);
    }
    return v;
}

static int64_t lm_int(const struct lm_call *c, const char *path)
{
    const struct json_value *v = lm_at(c, path);
    if (!v || v->type != JSON_INT)
        return -12345;
    return json_get_int(v);
}

static bool lm_null(const struct lm_call *c, const char *path)
{
    const struct json_value *v = lm_at(c, path);
    return v && v->type == JSON_NULL;
}

static bool lm_bool(const struct lm_call *c, const char *path, bool want)
{
    const struct json_value *v = lm_at(c, path);
    return v && v->type == JSON_BOOL && json_get_bool(v) == want;
}

static bool lm_str(const struct lm_call *c, const char *path, const char *want)
{
    const struct json_value *v = lm_at(c, path);
    return v && v->type == JSON_STR && strcmp(json_get_str(v), want) == 0;
}

static bool lm_list_has(const struct lm_call *c, const char *path,
                        const char *want)
{
    const struct json_value *arr = lm_at(c, path);
    if (!arr || arr->type != JSON_ARR)
        return false;
    for (size_t i = 0; i < arr->num_children; i++)
        if (arr->children[i].type == JSON_STR &&
            strcmp(json_get_str(&arr->children[i]), want) == 0)
            return true;
    return false;
}

static const struct json_value *lm_work(const struct lm_call *c,
                                        const char *work)
{
    const struct json_value *arr = lm_at(c, "decisions");
    if (!arr || arr->type != JSON_ARR)
        return NULL;
    for (size_t i = 0; i < arr->num_children; i++) {
        const struct json_value *one = &arr->children[i];
        if (strcmp(json_get_str(json_get(one, "work")), work) == 0)
            return one;
    }
    return NULL;
}

static bool lm_action(const struct lm_call *c, const char *work,
                      const char *action, bool start)
{
    const struct json_value *d = lm_work(c, work);
    const struct json_value *got = d ? json_get(d, "action") : NULL;
    const struct json_value *flag = d ? json_get(d, "start") : NULL;
    return got && got->type == JSON_STR && strcmp(json_get_str(got), action) == 0 &&
           flag && flag->type == JSON_BOOL && json_get_bool(flag) == start;
}

static int lm_test_catalog(void)
{
    int failures = 0;
    struct lm_call c;
    TEST("loop measure: catalog binds the shipped handler") {
        ASSERT(lm_begin(&c, lm_window));
        ASSERT(strcmp(c.spec->path, "dev.loop.measure") == 0);
        ASSERT(strcmp(c.spec->output_schema, "zcl.dev_loop_measure.v1") == 0);
        ASSERT(c.spec->handler == NULL ||
               c.spec->handler == zcl_native_handle_dev_loop_measure);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(lm_str(&c, "schema", "zcl.dev_loop_measure.v1"));
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_waste_a(void)
{
    int failures = 0;
    struct lm_call c;
    TEST("loop measure: discovery and build totals") {
        ASSERT(lm_begin(&c, lm_window));
        ASSERT_EQ(lm_int(&c, "classes.repeated_discovery.n"), (int64_t)1);
        ASSERT_EQ(lm_int(&c, "classes.repeated_discovery.tokens"), (int64_t)100);
        ASSERT_EQ(lm_int(&c, "classes.repeated_discovery.seconds_ms"),
                  (int64_t)2000);
        ASSERT(lm_bool(&c, "classes.repeated_discovery.eliminable", true));
        ASSERT_EQ(lm_int(&c, "classes.redundant_builds.n"), (int64_t)1);
        ASSERT_EQ(lm_int(&c, "classes.redundant_builds.tokens"), (int64_t)40);
        ASSERT_EQ(lm_int(&c, "classes.redundant_builds.seconds_ms"),
                  (int64_t)8000);
        ASSERT(lm_bool(&c, "classes.redundant_builds.eliminable", true));
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_waste_b(void)
{
    int failures = 0;
    struct lm_call c;
    TEST("loop measure: test, repair, and safety totals") {
        ASSERT(lm_begin(&c, lm_window));
        ASSERT_EQ(lm_int(&c, "classes.unnecessary_tests.n"), (int64_t)1);
        ASSERT_EQ(lm_int(&c, "classes.unnecessary_tests.tokens"), (int64_t)10);
        ASSERT_EQ(lm_int(&c, "classes.unnecessary_tests.seconds_ms"),
                  (int64_t)1500);
        ASSERT(lm_bool(&c, "classes.unnecessary_tests.eliminable", true));
        ASSERT_EQ(lm_int(&c, "classes.repair_rounds.n"), (int64_t)1);
        ASSERT(lm_null(&c, "classes.repair_rounds.tokens"));
        ASSERT_EQ(lm_int(&c, "classes.repair_rounds.seconds_ms"), (int64_t)3000);
        ASSERT(lm_bool(&c, "classes.repair_rounds.eliminable", true));
        ASSERT_EQ(lm_int(&c, "classes.safety_proof.tokens"), (int64_t)50);
        ASSERT_EQ(lm_int(&c, "classes.safety_proof.seconds_ms"), (int64_t)20000);
        ASSERT(lm_bool(&c, "classes.safety_proof.eliminable", false));
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_names(void)
{
    int failures = 0;
    struct lm_call c;
    TEST("loop measure: safety proof is outside the eliminable names") {
        ASSERT(lm_begin(&c, lm_window));
        ASSERT(lm_list_has(&c, "unknown_tokens", "repair_rounds.tokens"));
        ASSERT(!lm_list_has(&c, "eliminable", "safety_proof"));
        ASSERT(lm_list_has(&c, "eliminable", "repeated_discovery"));
        ASSERT(lm_list_has(&c, "eliminable", "redundant_builds"));
        ASSERT(lm_list_has(&c, "eliminable", "unnecessary_tests"));
        ASSERT(lm_list_has(&c, "eliminable", "repair_rounds"));
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_ratio(void)
{
    int failures = 0;
    struct lm_call c;
    TEST("loop measure: one run per known token, not the commit") {
        ASSERT(lm_begin(&c, lm_window));
        ASSERT_EQ(lm_int(&c, "running_software.capabilities"), (int64_t)1);
        ASSERT_EQ(lm_int(&c, "running_software.commits"), (int64_t)1);
        ASSERT_EQ(lm_int(&c, "running_software.tokens"), (int64_t)220);
        ASSERT_EQ(lm_int(&c, "running_software.per_token_num"), (int64_t)1);
        ASSERT_EQ(lm_int(&c, "running_software.per_token_den"), (int64_t)220);
        ASSERT(lm_bool(&c, "running_software.unknown_omitted", true));
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_reuse(void)
{
    int failures = 0;
    struct lm_call c;
    TEST("loop measure: reuse and required safety proof") {
        const struct json_value *safety;
        ASSERT(lm_begin(&c, lm_window));
        ASSERT(lm_action(&c, "discovery", "reused", false));
        ASSERT(lm_action(&c, "build", "reused", false));
        ASSERT(lm_action(&c, "test", "reused", false));
        ASSERT(lm_action(&c, "failure", "reused", false));
        ASSERT(lm_action(&c, "safety_proof", "required", true));
        safety = lm_work(&c, "safety_proof");
        ASSERT(safety != NULL);
        ASSERT(strcmp(json_get_str(json_get(safety, "reason")), "stale") == 0);
        ASSERT(strcmp(json_get_str(json_get(safety, "id")), "aa") == 0);
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_empty(void)
{
    int failures = 0;
    struct lm_call c;
    TEST("loop measure: an empty window does not invent zeroes") {
        ASSERT(lm_begin(&c, "[]"));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(lm_int(&c, "classes.repeated_discovery.n"), (int64_t)0);
        ASSERT(lm_null(&c, "classes.repeated_discovery.tokens"));
        ASSERT(lm_null(&c, "classes.repeated_discovery.seconds"));
        ASSERT(lm_null(&c, "classes.safety_proof.tokens"));
        ASSERT_EQ(lm_int(&c, "running_software.capabilities"), (int64_t)0);
        ASSERT(lm_null(&c, "running_software.tokens"));
        ASSERT(lm_null(&c, "running_software.per_token_num"));
        ASSERT(lm_action(&c, "safety_proof", "required", true));
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_not_repeat(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"schema\":\"zcl.code_guide_brief.v1\",\"question\":\"factory\","
        "\"tree\":\"t1\",\"prompt_tokens\":7,\"completion_tokens\":1,"
        "\"elapsed_ms\":10}]";
    TEST("loop measure: a first discovery stays required") {
        ASSERT(lm_begin(&c, records));
        ASSERT_EQ(lm_int(&c, "classes.repeated_discovery.n"), (int64_t)0);
        ASSERT(lm_null(&c, "classes.repeated_discovery.tokens"));
        ASSERT(lm_action(&c, "discovery", "required", true));
        ASSERT_EQ(lm_int(&c, "running_software.tokens"), (int64_t)8);
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_have(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"query\":\"validation\",\"tree\":\"t9\",\"prior_query\":\"validation\","
        "\"prior_tree\":\"t9\",\"searched\":{\"matching_symbol_rows\":1},"
        "\"prompt_tokens\":3,\"completion_tokens\":1,\"elapsed_ms\":100}]";
    TEST("loop measure: a repeated code-have query is reused") {
        ASSERT(lm_begin(&c, records));
        ASSERT_EQ(lm_int(&c, "classes.repeated_discovery.n"), (int64_t)1);
        ASSERT_EQ(lm_int(&c, "classes.repeated_discovery.tokens"), (int64_t)4);
        ASSERT_EQ(lm_int(&c, "classes.repeated_discovery.seconds_ms"),
                  (int64_t)100);
        ASSERT(lm_action(&c, "discovery", "reused", false));
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_release(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"schema\":\"zcl.hotswap_build_receipt.v1\","
        "\"artifact_cache_key\":\"rel\",\"artifact_cache_hit\":true,"
        "\"release\":true,\"prompt_tokens\":9,\"completion_tokens\":0,"
        "\"build_total_us\":1000}]";
    TEST("loop measure: a release cache hit is not an eliminable rebuild") {
        ASSERT(lm_begin(&c, records));
        ASSERT_EQ(lm_int(&c, "classes.redundant_builds.n"), (int64_t)0);
        ASSERT(lm_action(&c, "build", "required", true));
        ASSERT_EQ(lm_int(&c, "running_software.capabilities"), (int64_t)0);
        ASSERT_EQ(lm_int(&c, "running_software.tokens"), (int64_t)9);
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_safety_flag(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"proof_scope\":\"source_wide_compile_tests_lint_fast\","
        "\"proof_inputs_sha3\":\"aa\",\"prior_proof_inputs_sha3\":\"aa\","
        "\"admitted\":true,\"prompt_tokens\":1,\"completion_tokens\":0,"
        "\"elapsed_ms\":1}]";
    TEST("loop measure: an admitted flag is not a receipt") {
        const struct json_value *safety;
        ASSERT(lm_begin(&c, records));
        ASSERT(lm_bool(&c, "classes.safety_proof.eliminable", false));
        ASSERT(lm_action(&c, "safety_proof", "required", true));
        safety = lm_work(&c, "safety_proof");
        ASSERT(safety != NULL);
        ASSERT(strcmp(json_get_str(json_get(safety, "reason")), "missing") == 0);
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_different(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"proof_scope\":\"source_wide_compile_tests_lint_fast\","
        "\"proof_inputs_sha3\":\"aa\",\"prior_proof_inputs_sha3\":\"bb\","
        "\"receipt_hex\":\"00\",\"prompt_tokens\":1,\"completion_tokens\":0,"
        "\"elapsed_ms\":1}]";
    TEST("loop measure: a different proof input stays required") {
        const struct json_value *safety;
        ASSERT(lm_begin(&c, records));
        ASSERT(lm_action(&c, "safety_proof", "required", true));
        safety = lm_work(&c, "safety_proof");
        ASSERT(safety != NULL);
        ASSERT(strcmp(json_get_str(json_get(safety, "reason")),
                      "different_input") == 0);
        ASSERT(lm_bool(&c, "classes.safety_proof.eliminable", false));
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_receipt(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"proof_scope\":\"source_wide_compile_tests_lint_fast\","
        "\"proof_inputs_sha3\":\"aa\",\"prior_proof_inputs_sha3\":\"aa\","
        "\"local_commit\":\"aa\",\"remote_base\":\"bb\",\"receipt_hex\":\"00\","
        "\"prompt_tokens\":2,\"completion_tokens\":0,\"elapsed_ms\":4}]";
    TEST("loop measure: a bad receipt does not satisfy a safety proof") {
        const struct json_value *safety;
        ASSERT(lm_begin(&c, records));
        ASSERT(lm_action(&c, "safety_proof", "required", true));
        safety = lm_work(&c, "safety_proof");
        ASSERT(safety != NULL);
        ASSERT(strcmp(json_get_str(json_get(safety, "reason")),
                      "receipt_rejected") == 0);
        ASSERT_EQ(lm_int(&c, "running_software.capabilities"), (int64_t)0);
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_runs(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"schema\":\"zcl.hotswap_build_receipt.v1\","
        "\"artifact_cache_key\":\"k\",\"artifact_cache_hit\":true,"
        "\"candidate_bytes_executed\":true,\"prompt_tokens\":1,"
        "\"completion_tokens\":0,\"build_total_us\":0},"
        "{\"schema\":\"zcl.plugin_call.v1\",\"name\":\"upper\",\"queued\":true,"
        "\"elapsed_ms\":9,\"prompt_tokens\":4,\"completion_tokens\":0},"
        "{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"proof_scope\":\"dev_factory\",\"prompt_tokens\":3,"
        "\"completion_tokens\":0,\"elapsed_ms\":8},"
        "{\"commit\":\"abcdef\"}]";
    TEST("loop measure: a leaf and a focused proof run; a queue does not") {
        ASSERT(lm_begin(&c, records));
        ASSERT_EQ(lm_int(&c, "running_software.capabilities"), (int64_t)2);
        ASSERT_EQ(lm_int(&c, "running_software.commits"), (int64_t)1);
        ASSERT_EQ(lm_int(&c, "classes.redundant_builds.n"), (int64_t)1);
        ASSERT_EQ(lm_int(&c, "classes.safety_proof.n"), (int64_t)0);
        ASSERT_EQ(lm_int(&c, "running_software.tokens"), (int64_t)8);
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_unknown_flag(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"schema\":\"zcl.code_guide_brief.v1\",\"question\":\"factory\","
        "\"tree\":\"t1\",\"prior_question\":\"factory\",\"prior_tree\":\"t1\","
        "\"prompt_tokens\":0,\"prompt_tokens_known\":false,"
        "\"completion_tokens\":5,\"completion_tokens_known\":true,"
        "\"elapsed_ms\":10}]";
    TEST("loop measure: a known-false token is unknown, not zero") {
        ASSERT(lm_begin(&c, records));
        ASSERT(lm_null(&c, "classes.repeated_discovery.tokens"));
        ASSERT(lm_list_has(&c, "unknown_tokens", "repeated_discovery.tokens"));
        ASSERT(lm_null(&c, "running_software.tokens"));
        ASSERT(lm_null(&c, "running_software.per_token_num"));
        ASSERT_EQ(lm_int(&c, "classes.repeated_discovery.seconds_ms"),
                  (int64_t)10);
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_scope_none(void)
{
    int failures = 0;
    struct lm_call c;
    const char *both =
        "[{\"schema\":\"zcl.hotswap_build_receipt.v1\","
        "\"artifact_cache_key\":\"k\",\"artifact_cache_hit\":true,"
        "\"candidate_bytes_executed\":true,\"prompt_tokens\":1,"
        "\"completion_tokens\":0,\"build_total_us\":0},"
        "{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"proof_scope\":\"none\",\"elapsed_ms\":5,\"prompt_tokens\":0,"
        "\"completion_tokens\":0}]";
    const char *only =
        "[{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"proof_scope\":\"none\",\"elapsed_ms\":5}]";
    TEST("loop measure: proof_scope none is not a running capability") {
        ASSERT(lm_begin(&c, both));
        ASSERT_EQ(lm_int(&c, "running_software.capabilities"), (int64_t)1);
        lm_end(&c);
        ASSERT(lm_begin(&c, only));
        ASSERT_EQ(lm_int(&c, "running_software.capabilities"), (int64_t)0);
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_scope_blank(void)
{
    int failures = 0;
    struct lm_call c;
    const char *missing =
        "[{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"elapsed_ms\":5}]";
    const char *empty =
        "[{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"proof_scope\":\"\",\"elapsed_ms\":5}]";
    TEST("loop measure: a blank proof scope is not a focused proof") {
        ASSERT(lm_begin(&c, missing));
        ASSERT_EQ(lm_int(&c, "running_software.capabilities"), (int64_t)0);
        lm_end(&c);
        ASSERT(lm_begin(&c, empty));
        ASSERT_EQ(lm_int(&c, "running_software.capabilities"), (int64_t)0);
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_consensus(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"schema\":\"zcl.agent_fast_plan.v1\","
        "\"test_groups\":\"consensus_parity\","
        "\"prior_test_groups\":\"consensus_parity\","
        "\"proof_scope\":\"full_source_inventory\","
        "\"prompt_tokens\":6,\"completion_tokens\":1,\"elapsed_ms\":9}]";
    TEST("loop measure: consensus parity stays required") {
        ASSERT(lm_begin(&c, records));
        ASSERT_EQ(lm_int(&c, "classes.unnecessary_tests.n"), (int64_t)0);
        ASSERT_EQ(lm_int(&c, "classes.safety_proof.n"), (int64_t)1);
        ASSERT(lm_bool(&c, "classes.safety_proof.eliminable", false));
        ASSERT(lm_action(&c, "safety_proof", "required", true));
        ASSERT(!lm_action(&c, "test", "reused", false));
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_custody_seal(void)
{
    int failures = 0;
    struct lm_call c;
    const char *custody =
        "[{\"schema\":\"zcl.agent_fast_plan.v1\",\"test_groups\":\"custody\","
        "\"prior_test_groups\":\"custody\",\"prompt_tokens\":1,"
        "\"completion_tokens\":0,\"elapsed_ms\":1}]";
    const char *sealed =
        "[{\"schema\":\"zcl.agent_fast_plan.v1\","
        "\"test_groups\":\"sealed-core\",\"prior_test_groups\":\"sealed-core\","
        "\"prompt_tokens\":1,\"completion_tokens\":0,\"elapsed_ms\":1}]";
    TEST("loop measure: custody and sealed-core stay required") {
        ASSERT(lm_begin(&c, custody));
        ASSERT_EQ(lm_int(&c, "classes.unnecessary_tests.n"), (int64_t)0);
        ASSERT(lm_action(&c, "safety_proof", "required", true));
        lm_end(&c);
        ASSERT(lm_begin(&c, sealed));
        ASSERT_EQ(lm_int(&c, "classes.unnecessary_tests.n"), (int64_t)0);
        ASSERT(lm_bool(&c, "classes.safety_proof.eliminable", false));
        ASSERT(lm_action(&c, "safety_proof", "required", true));
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_story_green(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"story_green\","
        "\"candidate_bytes_executed\":true}]";
    TEST("loop measure: an executed hot-swap story counts") {
        ASSERT(lm_begin(&c, records));
        ASSERT_EQ(lm_int(&c, "running_software.capabilities"), (int64_t)1);
        ASSERT_EQ(lm_int(&c, "running_software.commits"), (int64_t)0);
        ASSERT_EQ(lm_int(&c, "classes.safety_proof.n"), (int64_t)0);
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_story_ratio(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"story_green\","
        "\"candidate_bytes_executed\":true,\"prompt_tokens\":10,"
        "\"completion_tokens\":0}]";
    TEST("loop measure: an executed story keeps its token ratio") {
        ASSERT(lm_begin(&c, records));
        ASSERT_EQ(lm_int(&c, "running_software.capabilities"), (int64_t)1);
        ASSERT_EQ(lm_int(&c, "running_software.tokens"), (int64_t)10);
        ASSERT_EQ(lm_int(&c, "running_software.per_token_num"), (int64_t)1);
        ASSERT_EQ(lm_int(&c, "running_software.per_token_den"), (int64_t)10);
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_none_ratio(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"proof_scope\":\"none\",\"candidate_bytes_executed\":true,"
        "\"prompt_tokens\":4,\"completion_tokens\":0}]";
    TEST("loop measure: an executed none-scope proof keeps its tokens") {
        ASSERT(lm_begin(&c, records));
        ASSERT_EQ(lm_int(&c, "running_software.capabilities"), (int64_t)1);
        ASSERT_EQ(lm_int(&c, "running_software.per_token_num"), (int64_t)1);
        ASSERT_EQ(lm_int(&c, "running_software.per_token_den"), (int64_t)4);
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_repair_match(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"rejected\","
        "\"stage_detail\":\"compile\",\"prior_stage_detail\":\"compile\","
        "\"failure_capsule\":\"missing-symbol\","
        "\"prior_failure_capsule\":\"missing-symbol\",\"elapsed_ms\":4}]";
    TEST("loop measure: a repeated rejected compile is reused") {
        ASSERT(lm_begin(&c, records));
        ASSERT_EQ(lm_int(&c, "classes.repair_rounds.n"), (int64_t)1);
        ASSERT(lm_bool(&c, "classes.repair_rounds.eliminable", true));
        ASSERT(lm_action(&c, "failure", "reused", false));
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_repair_identity(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"story_red\","
        "\"stage_detail\":\"service_story\","
        "\"prior_stage_detail\":\"service_story\","
        "\"failure_id\":\"aa\",\"prior_failure_id\":\"bb\","
        "\"failure_capsule\":\"capsule-a\","
        "\"prior_failure_capsule\":\"capsule-b\","
        "\"first_error\":\"e1\",\"prior_first_error\":\"e2\"}]";
    TEST("loop measure: a different failure identity stays required") {
        ASSERT(lm_begin(&c, records));
        ASSERT_EQ(lm_int(&c, "classes.repair_rounds.n"), (int64_t)0);
        ASSERT(lm_action(&c, "failure", "required", true));
        ASSERT(!lm_action(&c, "failure", "reused", false));
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_repair_phase(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"schema\":\"zcl.dev_cycle.v1\",\"producer\":\"native\","
        "\"status\":\"failed\",\"proof_scope\":\"none\","
        "\"phase\":\"compile\",\"prior_phase\":\"compile\","
        "\"failure_phase\":\"compile\",\"prior_failure_phase\":\"compile\","
        "\"failure_id\":\"f1\",\"prior_failure_id\":\"f1\","
        "\"failure_capsule\":\"missing-symbol\","
        "\"prior_failure_capsule\":\"missing-symbol\","
        "\"first_error\":\"undefined-ref\","
        "\"prior_first_error\":\"undefined-ref\"}]";
    TEST("loop measure: a native phase with the same failure is reused") {
        ASSERT(lm_begin(&c, records));
        ASSERT_EQ(lm_int(&c, "classes.repair_rounds.n"), (int64_t)1);
        ASSERT(lm_bool(&c, "classes.repair_rounds.eliminable", true));
        ASSERT(lm_action(&c, "failure", "reused", false));
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_repair_phase_differs(void)
{
    int failures = 0;
    struct lm_call c;
    const char *records =
        "[{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"failed\","
        "\"phase\":\"link\",\"prior_phase\":\"compile\","
        "\"stage_detail\":\"compile\",\"prior_stage_detail\":\"compile\","
        "\"failure_id\":\"f1\",\"prior_failure_id\":\"f1\","
        "\"failure_capsule\":\"missing-symbol\","
        "\"prior_failure_capsule\":\"missing-symbol\","
        "\"first_error\":\"undefined-ref\","
        "\"prior_first_error\":\"undefined-ref\"}]";
    TEST("loop measure: a different phase stays required") {
        ASSERT(lm_begin(&c, records));
        ASSERT_EQ(lm_int(&c, "classes.repair_rounds.n"), (int64_t)0);
        ASSERT(lm_action(&c, "failure", "required", true));
        ASSERT(!lm_action(&c, "failure", "reused", false));
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_repair_failure_phase(void)
{
    int failures = 0;
    struct lm_call c;
    const char *same =
        "[{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"failed\","
        "\"failure_phase\":\"compile\",\"prior_failure_phase\":\"compile\","
        "\"failure_id\":\"f1\",\"prior_failure_id\":\"f1\"}]";
    const char *differs =
        "[{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"rejected\","
        "\"failure_phase\":\"link\",\"prior_failure_phase\":\"compile\","
        "\"stage_detail\":\"compile\",\"prior_stage_detail\":\"compile\","
        "\"failure_capsule\":\"missing-symbol\","
        "\"prior_failure_capsule\":\"missing-symbol\"}]";
    TEST("loop measure: failure_phase is part of the failure identity") {
        ASSERT(lm_begin(&c, same));
        ASSERT_EQ(lm_int(&c, "classes.repair_rounds.n"), (int64_t)1);
        ASSERT(lm_action(&c, "failure", "reused", false));
        lm_end(&c);
        ASSERT(lm_begin(&c, differs));
        ASSERT_EQ(lm_int(&c, "classes.repair_rounds.n"), (int64_t)0);
        ASSERT(lm_action(&c, "failure", "required", true));
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

static int lm_test_reject(void)
{
    int failures = 0;
    struct lm_call c;
    TEST("loop measure: a missing records array is refused") {
        ASSERT(lm_begin(&c, NULL));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(c.reply.exit_code == ZCL_COMMAND_EXIT_INVALID);
        lm_end(&c);
        PASS();
    }
_test_next:;
    return failures;
}

int test_dev_loop_measure(void);
int test_dev_loop_measure(void)
{
    int failures = 0;
    failures += lm_test_catalog();
    failures += lm_test_waste_a();
    failures += lm_test_waste_b();
    failures += lm_test_names();
    failures += lm_test_ratio();
    failures += lm_test_reuse();
    failures += lm_test_empty();
    failures += lm_test_not_repeat();
    failures += lm_test_have();
    failures += lm_test_release();
    failures += lm_test_safety_flag();
    failures += lm_test_different();
    failures += lm_test_receipt();
    failures += lm_test_runs();
    failures += lm_test_unknown_flag();
    failures += lm_test_scope_none();
    failures += lm_test_scope_blank();
    failures += lm_test_consensus();
    failures += lm_test_custody_seal();
    failures += lm_test_story_green();
    failures += lm_test_story_ratio();
    failures += lm_test_none_ratio();
    failures += lm_test_repair_match();
    failures += lm_test_repair_identity();
    failures += lm_test_repair_phase();
    failures += lm_test_repair_phase_differs();
    failures += lm_test_repair_failure_phase();
    failures += lm_test_reject();
    if (failures == 0)
        printf("test_dev_loop_measure: all passed\n");
    else
        printf("test_dev_loop_measure: %d FAILED\n", failures);
    return failures;
}
