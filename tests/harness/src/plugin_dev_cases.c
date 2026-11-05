/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: prove plugin.dev: a fresh directory becomes generation 1 and
 *          current, a changed executable becomes generation 2 and current,
 *          and a failed pack leaves generation 2 current with an error that
 *          names the failed step. Runs under a temporary HOME; the real
 *          ~/.z23 is never read. */

#include "test/plugin_dev_cases.h"
#include "test/test_core.h"

#include "command/native_command.h"
#include "json/json.h"
#include "plugin/plugin_store.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct pdc_env {
    char base[PATH_MAX], home[PATH_MAX], dir[PATH_MAX], exe[PATH_MAX], root[PATH_MAX];
    char input[PATH_MAX + 32];
};

static bool pdc_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    bool ok = f && fwrite(text, 1, strlen(text), f) == strlen(text);
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok;
}

static bool pdc_open(struct pdc_env *e)
{
    memset(e, 0, sizeof(*e));
    if (!test_mkdtemp(e->base, sizeof(e->base), "plugin_dev"))
        return false;
    int n = snprintf(e->home, sizeof(e->home), "%s/home", e->base);
    n += snprintf(e->dir, sizeof(e->dir), "%s/hello", e->base);
    n += snprintf(e->exe, sizeof(e->exe), "%s/hello/hello", e->base);
    n += snprintf(e->root, sizeof(e->root), "%s/home/.z23/plugins", e->base);
    n += snprintf(e->input, sizeof(e->input), "{\"dir\":\"%s\"}", e->dir);
    return n > 0 && mkdir(e->home, 0700) == 0 && mkdir(e->dir, 0700) == 0 &&
           setenv("HOME", e->home, 1) == 0;
}

static bool pdc_dev(const struct pdc_env *e, struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, e->input, strlen(e->input));
    struct zcl_command_request request = { .input = &input, .view = "normal" };
    zcl_command_reply_init(reply, "zcl.plugin_test.v1");
    if (ok)
        zcl_native_handle_plugin_dev(&request, reply);
    json_free(&input);
    return ok;
}

/* The stored state of hello: its generation count, and its current id. */
static bool pdc_state(const struct pdc_env *e, size_t *count, char *current)
{
    struct plugin_info *infos = NULL;
    size_t n = 0;
    if (plugin_store_list(e->root, &infos, &n) != PLUGIN_OK || n != 1)
        return false;
    *count = infos[0].generation_count;
    snprintf(current, PLUGIN_HEX_SHA3_512 + 1, "%s", infos[0].current);
    plugin_store_list_free(infos, n);
    return true;
}

static int pdc_case_fresh(struct pdc_env *e, char *first)
{
    int failures = 0;
    struct zcl_command_reply r;
    char current[PLUGIN_HEX_SHA3_512 + 1];
    size_t count = 0;
    TEST_CASE("plugin dev makes a fresh directory generation 1 and current") {
        ASSERT(pdc_write(e->exe, "version one"));
        ASSERT(pdc_dev(e, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&r.data, "sequence")), 1);
        ASSERT_EQ(json_size(json_get(&r.data, "steps")), 5u);
        snprintf(first, PLUGIN_HEX_SHA3_512 + 1, "%s", json_get_str(json_get(&r.data, "generation")));
        zcl_command_reply_free(&r);
        ASSERT(pdc_state(e, &count, current));
        ASSERT_EQ(count, 1u);
        ASSERT_STR_EQ(current, first);
    } TEST_END
    return failures;
}

static int pdc_case_second(struct pdc_env *e, char *first)
{
    int failures = 0;
    struct zcl_command_reply r;
    char current[PLUGIN_HEX_SHA3_512 + 1];
    size_t count = 0;
    TEST_CASE("plugin dev makes a changed executable generation 2 and current") {
        ASSERT(pdc_write(e->exe, "version two"));
        ASSERT(pdc_dev(e, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&r.data, "sequence")), 2);
        const struct json_value *step = json_at(json_get(&r.data, "steps"), 0);
        ASSERT_STR_EQ(json_get_str(json_get(step, "result")), "exists");
        ASSERT(strcmp(json_get_str(json_get(&r.data, "generation")), first) != 0);
        snprintf(first, PLUGIN_HEX_SHA3_512 + 1, "%s", json_get_str(json_get(&r.data, "generation")));
        zcl_command_reply_free(&r);
        ASSERT(pdc_state(e, &count, current));
        ASSERT_EQ(count, 2u);
        ASSERT_STR_EQ(current, first);
    } TEST_END
    return failures;
}

static int pdc_case_broken_pack(struct pdc_env *e)
{
    int failures = 0;
    struct zcl_command_reply r;
    char before[PLUGIN_HEX_SHA3_512 + 1], after[PLUGIN_HEX_SHA3_512 + 1];
    size_t count = 0;
    TEST_CASE("a broken pack leaves generation 2 current and names the step") {
        ASSERT(pdc_state(e, &count, before));
        ASSERT_EQ(unlink(e->exe), 0);
        ASSERT(pdc_dev(e, &r));
        ASSERT(r.exit_code != ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(r.error.message, "step pack") != NULL);
        ASSERT(strstr(r.error.evidence, "current generation is unchanged") != NULL);
        ASSERT(r.error.next_action[0] != '\0');
        zcl_command_reply_free(&r);
        ASSERT(pdc_state(e, &count, after));
        ASSERT_EQ(count, 2u);
        ASSERT_STR_EQ(after, before);
    } TEST_END
    return failures;
}

static bool pdc_copy_cat(const char *dst)
{
    FILE *in = fopen("/bin/cat", "rb"), *out = fopen(dst, "wb");
    char buf[4096];
    size_t n = 0;
    bool ok = in && out;
    while (ok && (n = fread(buf, 1, sizeof(buf), in)) > 0)
        ok = fwrite(buf, 1, n, out) == n;
    if (in)
        fclose(in);
    if (out)
        ok = fclose(out) == 0 && ok;
    return ok && chmod(dst, 0755) == 0;
}

/* Run plugin dev with the given cases JSON array text. */
static bool pdc_dev_cases(struct pdc_env *e, const char *cases, struct zcl_command_reply *r)
{
    int n = snprintf(e->input, sizeof(e->input), "{\"dir\":\"%s\",\"cases\":%s}", e->dir, cases);
    return n > 0 && (size_t)n < sizeof(e->input) && pdc_dev(e, r);
}

static int pdc_case_cases(struct pdc_env *e)
{
    int failures = 0;
    struct zcl_command_reply r;
    char before[PLUGIN_HEX_SHA3_512 + 1], after[PLUGIN_HEX_SHA3_512 + 1];
    size_t count = 0;
    TEST_CASE("plugin dev with cases: malformed and failing cases are refused before any step") {
        ASSERT(pdc_copy_cat(e->exe));
        ASSERT(pdc_state(e, &count, before));
        ASSERT_EQ(count, 2u);
        ASSERT(pdc_dev_cases(e, "\"not an array\"", &r));
#if !defined(__linux__)
        /* Off Linux the lab is unsupported, so the cases cannot run at all
         * and plugin dev refuses before any step; the case verdicts are
         * unobserved here. The refusal and the untouched state are checked. */
        ASSERT_STR_EQ(r.error.code, "PLUGIN_DEV_CASES_UNAVAILABLE");
        zcl_command_reply_free(&r);
        ASSERT(pdc_state(e, &count, after));
        ASSERT_EQ(count, 2u);
        ASSERT_STR_EQ(after, before);
        printf("UNOBSERVED (plugin_dev_cases: running cases needs the Linux lab)... ");
#else
        ASSERT_STR_EQ(r.error.code, "PLUGIN_DEV_BAD_CASES");
        zcl_command_reply_free(&r);
        ASSERT(pdc_dev_cases(e, "[{\"name\":\"upcase\",\"stdin\":\"abc\\n\",\"expect_stdout\":\"ABC\\n\"}]", &r));
        ASSERT(r.exit_code != ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_DEV_CASES_FAILED");
        ASSERT(strstr(r.error.message, "upcase") != NULL);
        ASSERT(strstr(r.error.evidence, "upcase: line 1: expected") != NULL);
        ASSERT(strstr(r.error.evidence, "ABC") != NULL && strstr(r.error.evidence, "abc") != NULL);
        zcl_command_reply_free(&r);
        ASSERT(pdc_state(e, &count, after));
        ASSERT_EQ(count, 2u);
        ASSERT_STR_EQ(after, before);
#endif
    } TEST_END
    return failures;
}

static int pdc_case_cases_pass(struct pdc_env *e)
{
    int failures = 0;
    struct zcl_command_reply r;
    char before[PLUGIN_HEX_SHA3_512 + 1], after[PLUGIN_HEX_SHA3_512 + 1];
    size_t count = 0;
    TEST_CASE("plugin dev with passing cases makes a new current generation") {
        ASSERT(pdc_dev_cases(e, "[{\"name\":\"echo\",\"stdin\":\"abc\\n\",\"expect_stdout\":\"abc\\n\",\"expect_exit\":0}]", &r));
#if !defined(__linux__)
        /* Off Linux the cases cannot run (the lab is unsupported), so no
         * generation is made: the refusal is the assertion, the pass is
         * unobserved. */
        ASSERT(r.exit_code != ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_DEV_CASES_UNAVAILABLE");
        zcl_command_reply_free(&r);
        ASSERT(pdc_state(e, &count, after));
        ASSERT_EQ(count, 2u);
        (void)before;
        printf("UNOBSERVED (plugin_dev_cases: running cases needs the Linux lab)... ");
#else
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&r.data, "sequence")), 3);
        snprintf(before, sizeof(before), "%s", json_get_str(json_get(&r.data, "generation")));
        zcl_command_reply_free(&r);
        ASSERT(pdc_state(e, &count, after));
        ASSERT_EQ(count, 3u);
        ASSERT_STR_EQ(after, before);
#endif
    } TEST_END
    return failures;
}

/* An argument refusal runs no step, so its message must not name one. */
static int pdc_case_refusals(struct pdc_env *e)
{
    int failures = 0;
    struct zcl_command_reply r;
    TEST_CASE("plugin dev refuses a missing dir without naming a step") {
        snprintf(e->input, sizeof(e->input), "{\"name\":\"hello\"}");
        ASSERT(pdc_dev(e, &r));
        ASSERT(r.exit_code != ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(r.error.message, "plugin dev refused: ") != NULL);
        ASSERT(strstr(r.error.message, "step") == NULL);
        ASSERT(strstr(r.error.evidence, "step key") == NULL);
        ASSERT(strstr(r.error.evidence, "0 of 5") == NULL);
        zcl_command_reply_free(&r);
    } TEST_END
    return failures;
}

static int pdc_case_key_step(struct pdc_env *e)
{
    int failures = 0;
    struct zcl_command_reply r;
    TEST_CASE("plugin dev still names the key step when the key cannot be written") {
        int n = snprintf(e->input, sizeof(e->input),
                         "{\"dir\":\"%s\",\"key\":\"%s/no-such-dir/plugin_dev.key\"}",
                         e->dir, e->base);
        ASSERT(n > 0 && (size_t)n < sizeof(e->input));
        ASSERT(pdc_dev(e, &r));
        ASSERT(r.exit_code != ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(r.error.message, "failed at step key") != NULL);
        ASSERT(strstr(r.error.evidence, "step key failed after 0 of 5 steps") != NULL);
        zcl_command_reply_free(&r);
    } TEST_END
    return failures;
}

int plugin_dev_cases(void)
{
    int failures = 0;
    struct pdc_env e;
    const char *old_home = getenv("HOME");
    char saved[PATH_MAX] = "";
    if (old_home)
        snprintf(saved, sizeof(saved), "%s", old_home);
    TEST_CASE("plugin dev fixture opens") {
        ASSERT(pdc_open(&e));
    } TEST_END
    if (failures == 0) {
        char first[PLUGIN_HEX_SHA3_512 + 1] = "";
        failures += pdc_case_fresh(&e, first);
        failures += pdc_case_second(&e, first);
        failures += pdc_case_broken_pack(&e);
        failures += pdc_case_cases(&e);
        failures += pdc_case_cases_pass(&e);
        failures += pdc_case_refusals(&e);
        failures += pdc_case_key_step(&e);
    }
    if (old_home)
        (void)setenv("HOME", saved, 1);
    else
        (void)unsetenv("HOME");
    if (e.base[0])
        (void)test_rm_rf_recursive(e.base);
    return failures;
}
