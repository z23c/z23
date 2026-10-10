/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Parity for dev.test.fast_plan (tools/command/native_dev_fast_plan.c) against the
 * shell oracle `tools/agent_fast_ci.sh plan-json`. Each fixture fixes the
 * changed set through the same env knobs the shell reads
 * (ZCL_FAST_CHANGED_FILES_ONLY=1 with ZCL_FAST_CHANGED_FILES or
 * ZCL_FAST_CHANGED_FILES_FILE), so no git state participates. The oracle is
 * run as a child process with the same environment; its JSON is parsed and
 * the changed files, selected groups, unmapped changes, compile plan target
 * and recommended command are compared element for element. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FP_OUT_CAP 65536
#define FP_ORACLE_TIMEOUT_MS 120000

struct fp_case {
    const char *name;
    const char *changed; /* ZCL_FAST_CHANGED_FILES, or "" */
    bool via_file;       /* hint file holding an empty list instead */
};

static const struct fp_case fp_cases[] = {
    {"c_file_with_rule", "engine/composition/src/args.c", false},
    {"doc_file", "docs/ARENA.md", false},
    {"makefile", "Makefile", false},
    {"code_without_rule", "contexts/commons/modules/vcs/src/zcode_work_output.c", false},
    {"deleted_source", "tests/harness/src/no_such_dev_fast_plan_fixture.c", false},
    {"mixed",
     "engine/composition/src/args.c,Makefile,docs/ARENA.md,"
     "contexts/commons/modules/vcs/src/zcode_work_output.c,"
     "tests/harness/src/no_such_dev_fast_plan_fixture.c",
     false},
    {"empty_set", "", true},
};

static const char *fp_unset_knobs[] = {
    "ZCL_FAST_CHANGED_FILES", "ZCL_FAST_CHANGED_FILES_FILE", "ZCL_FAST_BASE",
    "ZCL_FAST_TESTS", "ZCL_FAST_COMPILE_SCOPE_PROOF",
    "ZCL_FAST_IMPACT_RULES_FILE", "ZCL_FAST_CACHE_DIR", "ZCL_FAST_COMPILE",
    "ZCL_FAST_LIVE", "ZCL_FAST_STRICT_TESTS", "ZCL_FAST_BUILD_SOURCE_RECORD",
};

/* The knobs both sides read, pinned so the parity is hermetic. */
static void fp_pin_env(void)
{
    size_t n = sizeof(fp_unset_knobs) / sizeof(fp_unset_knobs[0]);
    for (size_t i = 0; i < n; i++)
        (void)unsetenv(fp_unset_knobs[i]);
    (void)setenv("LC_ALL", "C", 1);
    (void)setenv("ZCL_FAST_CHANGED_FILES_ONLY", "1", 1);
    (void)setenv("ZCL_FAST_CC", "cc", 1);
    (void)setenv("ZCL_FAST_JOBS", "4", 1);
    (void)setenv("ZCL_FAST_CACHE", "0", 1);
}

static void fp_set_hints(const char *changed, const char *file)
{
    if (changed[0])
        (void)setenv("ZCL_FAST_CHANGED_FILES", changed, 1);
    else
        (void)unsetenv("ZCL_FAST_CHANGED_FILES");
    if (file && file[0])
        (void)setenv("ZCL_FAST_CHANGED_FILES_FILE", file, 1);
    else
        (void)unsetenv("ZCL_FAST_CHANGED_FILES_FILE");
}

/* Null-safe views over the parsed JSON, so a missing key compares as "". */
static const struct json_value *fp_child(const struct json_value *o,
                                         const char *key)
{
    return o ? json_get(o, key) : NULL;
}

static const char *fp_str(const struct json_value *o, const char *key)
{
    const struct json_value *v = fp_child(o, key);
    const char *s = v ? json_get_str(v) : NULL;
    return s ? s : "";
}

static bool fp_same_list(const struct json_value *a, const struct json_value *b)
{
    size_t n;
    if (!a || !b || a->type != JSON_ARR || b->type != JSON_ARR)
        return false;
    n = json_size(a);
    if (n != json_size(b))
        return false;
    for (size_t i = 0; i < n; i++) {
        const char *x = json_get_str(json_at(a, i));
        const char *y = json_get_str(json_at(b, i));
        if (!x || !y || strcmp(x, y) != 0)
            return false;
    }
    return true;
}

static int fp_check_list(const char *name, const char *key,
                         const struct json_value *want,
                         const struct json_value *got)
{
    if (fp_same_list(fp_child(want, key), fp_child(got, key)))
        return 0;
    printf("\n  %s: %s differs from plan-json\n", name, key);
    return 1;
}

static int fp_check_str(const char *name, const char *key,
                        const struct json_value *want,
                        const struct json_value *got)
{
    if (strcmp(fp_str(want, key), fp_str(got, key)) == 0)
        return 0;
    printf("\n  %s: %s is '%s' in plan-json, '%s' natively\n", name, key,
           fp_str(want, key), fp_str(got, key));
    return 1;
}

static int fp_check_compile_target(const char *name,
                                   const struct json_value *want,
                                   const struct json_value *got)
{
    const char *a = fp_str(fp_child(want, "compile_plan"), "target");
    const char *b = fp_str(fp_child(got, "compile_plan"), "target");
    if (strcmp(a, b) == 0)
        return 0;
    printf("\n  %s: compile_plan.target is '%s' in plan-json, '%s' natively\n",
           name, a, b);
    return 1;
}

static bool fp_run_oracle(char *out)
{
    const char *argv[] = {"bash", "tools/agent_fast_ci.sh", "plan-json", NULL};
    out[0] = '\0';
    if (zcl_spawn_capture(argv, out, FP_OUT_CAP, FP_ORACLE_TIMEOUT_MS) != 0)
        return false;
    return out[0] == '{';
}

static void fp_run_leaf(struct zcl_command_reply *reply)
{
    struct zcl_command_request request;
    struct json_value input;
    memset(&request, 0, sizeof(request));
    json_init(&input);
    json_set_object(&input);
    request.input = &input;
    zcl_command_reply_init(reply, "zcl.agent_fast_plan.v1");
    zcl_native_handle_dev_fast_plan(&request, reply);
    json_free(&input);
}

static int fp_compare_case(const char *name, const struct json_value *want,
                           const struct json_value *got)
{
    int bad = 0;
    bad += fp_check_list(name, "changed_files", want, got);
    bad += fp_check_list(name, "test_groups", want, got);
    bad += fp_check_list(name, "unmapped_code_changes", want, got);
    bad += fp_check_str(name, "recommended_command", want, got);
    bad += fp_check_str(name, "compiler", want, got);
    bad += fp_check_str(name, "jobs", want, got);
    bad += fp_check_str(name, "schema", want, got);
    bad += fp_check_compile_target(name, want, got);
    if (fp_child(want, "changed_file_count") && fp_child(got, "changed_file_count")) {
        if (json_get_int(fp_child(want, "changed_file_count")) !=
            json_get_int(fp_child(got, "changed_file_count"))) {
            printf("\n  %s: changed_file_count differs\n", name);
            bad++;
        }
    } else {
        printf("\n  %s: changed_file_count missing\n", name);
        bad++;
    }
    return bad;
}

static int fp_run_case(const struct fp_case *c, const char *file_hint)
{
    char oracle_raw[FP_OUT_CAP];
    struct json_value want;
    struct zcl_command_reply reply;
    int bad = 0;

    fp_set_hints(c->via_file ? "" : c->changed,
                 c->via_file ? file_hint : "");
    printf("%s... ", c->name);
    if (!fp_run_oracle(oracle_raw)) {
        printf("FAIL oracle plan-json did not run\n");
        return 1;
    }
    json_init(&want);
    if (!json_read(&want, oracle_raw, strlen(oracle_raw))) {
        printf("FAIL oracle plan-json is not JSON\n");
        json_free(&want);
        return 1;
    }
    fp_run_leaf(&reply);
    bad = fp_compare_case(c->name, &want, &reply.data);
    if (reply.status != ZCL_COMMAND_STATUS_PASSED)
        bad++;
    zcl_command_reply_free(&reply);
    json_free(&want);
    printf("%s\n", bad ? "FAIL" : "OK");
    return bad;
}

/* Native refusals: the verdicts it does not derive must not be guessed. */
static int fp_refusal_case(const char *knob, const char *value)
{
    struct zcl_command_reply reply;
    int bad = 0;
    (void)setenv(knob, value, 1);
    fp_set_hints("engine/composition/src/args.c", "");
    fp_run_leaf(&reply);
    if (reply.status != ZCL_COMMAND_STATUS_BLOCKED) {
        printf("refusal %s=%s: expected BLOCKED, got status %d\n", knob, value,
               (int)reply.status);
        bad = 1;
    }
    zcl_command_reply_free(&reply);
    (void)unsetenv(knob);
    return bad;
}

static int fp_write_empty(const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return 0;
    (void)fclose(f);
    return 1;
}

int test_dev_fast_plan(void);
int test_dev_fast_plan(void)
{
    int failures = 0;
    char base[512];
    char empty_path[640];
    size_t n = sizeof(fp_cases) / sizeof(fp_cases[0]);

    printf("test_dev_fast_plan: parity with tools/agent_fast_ci.sh plan-json\n");
    test_make_tmpdir(base, sizeof(base), "dev_fast_plan", "t");
    (void)snprintf(empty_path, sizeof(empty_path), "%s/empty_changed.txt", base);
    if (!fp_write_empty(empty_path)) {
        printf("FAIL could not write the empty hint file\n");
        return 1;
    }
    fp_pin_env();
    for (size_t i = 0; i < n; i++)
        failures += fp_run_case(&fp_cases[i], empty_path) != 0;

    failures += fp_refusal_case("ZCL_FAST_CACHE", "1") != 0;
    failures += fp_refusal_case("ZCL_FAST_COMPILE_SCOPE_PROOF", empty_path) != 0;
    fp_pin_env();

    if (failures == 0)
        printf("test_dev_fast_plan: all passed\n");
    else
        printf("test_dev_fast_plan: %d FAILED\n", failures);
    return failures;
}
