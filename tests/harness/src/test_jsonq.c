/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 *
 * test_jsonq — regressions for the jsonq stdin JSON path-query CLI
 * (tools/jsonq.c, built as build/bin/jsonq by `make jsonq`).
 *
 * Python is banned in this repository; nested command envelopes are
 * extracted with jsonq. These cases pin the exact stdout and exit codes of
 * the operators an agent shell actually relies on, including the container
 * shapes: count/keys must measure only the direct members of the selected
 * object or array — a nested container is one member, never a source of
 * extra counted keys. */

#include "test/test_core.h"
#include "util/spawn.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#include "test/jsonq_fixture_adapter.h"

static int test_jsonq_count_and_keys(void)
{
    int failures = 0;
    char buf[512] = {0};
    TEST("jsonq: count/keys measure direct members only") {
        ASSERT(jsonq_fixture_run("{\"a\":1,\"b\":{\"x\":1,\"y\":2},\"c\":[1,2]}",
                         (const char *const[]){JSONQ_FIXTURE_BIN, "count", "", NULL}, buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "3" JSONQ_FIXTURE_EOL "") == 0);

        ASSERT(jsonq_fixture_run("{\"a\":1,\"b\":{\"x\":1}}", (const char *const[]){JSONQ_FIXTURE_BIN, "keys", "", NULL},
                         buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "a" JSONQ_FIXTURE_EOL "b" JSONQ_FIXTURE_EOL "") == 0);

        /* A nested container under the queried path is one member; its own
         * keys must not leak into the parent count or key list. */
        ASSERT(jsonq_fixture_run("{\"b\":{\"x\":{\"deep\":1}}}", (const char *const[]){JSONQ_FIXTURE_BIN, "count", "b", NULL},
                         buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "1" JSONQ_FIXTURE_EOL "") == 0);
        ASSERT(jsonq_fixture_run("{\"b\":{\"x\":{\"deep\":1}}}", (const char *const[]){JSONQ_FIXTURE_BIN, "keys", "b", NULL},
                         buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "x" JSONQ_FIXTURE_EOL "") == 0);

        /* Arrays were already correct: nested containers count as one
         * element each. Pin it so both container kinds stay honest. */
        ASSERT(jsonq_fixture_run("[1,[2,3],{\"x\":1}]", (const char *const[]){JSONQ_FIXTURE_BIN, "count", "", NULL},
                         buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "3" JSONQ_FIXTURE_EOL "") == 0);

        /* An object member whose value is an array: still one member. */
        ASSERT(jsonq_fixture_run("{\"a\":[1,2,3],\"b\":{\"c\":{\"d\":1}}}",
                         (const char *const[]){JSONQ_FIXTURE_BIN, "count", "", NULL}, buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "2" JSONQ_FIXTURE_EOL "") == 0);

        /* Empty and mixed nested values stay direct members. */
        ASSERT(jsonq_fixture_run("{}", (const char *const[]){JSONQ_FIXTURE_BIN, "count", "", NULL}, buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "0" JSONQ_FIXTURE_EOL "") == 0);
        ASSERT(jsonq_fixture_run("{}", (const char *const[]){JSONQ_FIXTURE_BIN, "keys", "", NULL}, buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "") == 0);
        ASSERT(jsonq_fixture_run("[]", (const char *const[]){JSONQ_FIXTURE_BIN, "count", "", NULL}, buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "0" JSONQ_FIXTURE_EOL "") == 0);
        ASSERT(jsonq_fixture_run("{\"a\":[{\"hidden\":1}],\"b\":null,\"c\":[]}",
                         (const char *const[]){JSONQ_FIXTURE_BIN, "keys", "", NULL}, buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "a" JSONQ_FIXTURE_EOL "b" JSONQ_FIXTURE_EOL "c" JSONQ_FIXTURE_EOL "") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_jsonq_key_count(void)
{
    static const struct {
        const char *document, *path, *key, *output;
        int status;
    } cases[] = {
        {"{\"usage\":1,\"\\u0075sage\":2}", "", "usage", "2" JSONQ_FIXTURE_EOL, 0},
        {"{\"usage\":1,\"metadata\\nusage\":2}", "", "usage", "1" JSONQ_FIXTURE_EOL, 0},
        {"{\"usage\":{\"input_tokens\":1,\"\\u0069nput_tokens\":2,"
         "\"nested\":{\"input_tokens\":3},\"items\":[{\"input_tokens\":4}]}}",
         "usage", "input_tokens", "2" JSONQ_FIXTURE_EOL, 0},
        {"{\"usage\":{\"input_tokens\":1,\"note\\ninput_tokens\":2}}",
         "usage", "input_tokens", "1" JSONQ_FIXTURE_EOL, 0},
        {"{\"input\":1,\"input\\u0000\":2}", "", "input", "1" JSONQ_FIXTURE_EOL, 0},
        {"{\"a\\nb\":1,\"a\\u000ab\":2}", "", "a\nb", "2" JSONQ_FIXTURE_EOL, 0},
        {"{\"\":1,\"other\":2}", "", "", "1" JSONQ_FIXTURE_EOL, 0},
        {"{\"rows\":[{\"usage\":1},{\"usage\":2,\"usage\":3}]}",
         "rows[1]", "usage", "2" JSONQ_FIXTURE_EOL, 0},
        {"{}", "", "usage", "0" JSONQ_FIXTURE_EOL, 0},
        {"{\"nested\":{\"usage\":1}}", "", "usage", "0" JSONQ_FIXTURE_EOL, 0},
        {"{}", "missing", "usage", "", 1},
        {"[]", "", "usage", "", 1},
        {"{\"usage\":1}", "usage", "input_tokens", "", 1},
        {"{\"usage\":1} junk", "", "usage", "", 2},
        {"{\"usage\":1,", "", "usage", "", 2},
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char buf[512] = {0};
        TEST("jsonq: key-count preserves decoded identity and direct-member scope") {
            ASSERT_EQ(jsonq_fixture_run(cases[i].document,
                (const char *const[]){JSONQ_FIXTURE_BIN, "key-count",
                    cases[i].path, cases[i].key, NULL}, buf, sizeof(buf)), cases[i].status);
            ASSERT_STR_EQ(buf, cases[i].output);
            PASS();
        } _test_next:;
    }
    return failures;
}

static int test_jsonq_scalar_paths(void)
{
    int failures = 0;
    char buf[512] = {0};
    TEST("jsonq: get/has/eq/type address scalars inside nested shapes") {
        const char *doc = "{\"result\":{\"items\":[{\"id\":\"a\"},"
                          "{\"id\":\"b\"}],\"ok\":true},\"n\":7}";
        ASSERT(jsonq_fixture_run(doc, (const char *const[]){JSONQ_FIXTURE_BIN, "get", "result.items[1].id", NULL}, buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "b" JSONQ_FIXTURE_EOL "") == 0);
        ASSERT(jsonq_fixture_run(doc, (const char *const[]){JSONQ_FIXTURE_BIN, "has", "result.ok", NULL}, buf, sizeof(buf)) == 0);
        ASSERT(jsonq_fixture_run(doc, (const char *const[]){JSONQ_FIXTURE_BIN, "type", "result.items", NULL}, buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "array" JSONQ_FIXTURE_EOL "") == 0);
        ASSERT(jsonq_fixture_run(doc, (const char *const[]){JSONQ_FIXTURE_BIN, "eq", "result.ok", "true", NULL}, buf, sizeof(buf)) == 0);
        ASSERT(jsonq_fixture_run(doc, (const char *const[]){JSONQ_FIXTURE_BIN, "get", "n", NULL}, buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "7" JSONQ_FIXTURE_EOL "") == 0);
        /* Missing path exits 1; malformed document exits 2. */
        ASSERT(jsonq_fixture_run(doc, (const char *const[]){JSONQ_FIXTURE_BIN, "get", "result.absent", NULL}, buf, sizeof(buf)) == 1);
        ASSERT(jsonq_fixture_run("{not json}", (const char *const[]){JSONQ_FIXTURE_BIN, "get", "a", NULL}, buf, sizeof(buf)) == 2);
        /* CRT text stdin must not hide malformed suffix bytes on Windows. */
        ASSERT(jsonq_fixture_run("{}\x1a" "junk", (const char *const[]){JSONQ_FIXTURE_BIN, "count", "", NULL}, buf, sizeof(buf)) == 2);
        ASSERT(strcmp(buf, "") == 0);
        ASSERT(jsonq_fixture_run("{\r\n\"a\":1,\r\n\"b\":[]}\r\n", (const char *const[]){JSONQ_FIXTURE_BIN, "count", "", NULL}, buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "2" JSONQ_FIXTURE_EOL) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_jsonq_unwrap(void)
{
    int failures = 0;
    char buf[512] = {0};
    TEST("jsonq: unwrap prints a result envelope and refuses an error one") {
        ASSERT(jsonq_fixture_run("{\"result\":{\"ok\":true},\"error\":null}",
                         (const char *const[]){JSONQ_FIXTURE_BIN, "unwrap", NULL}, buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "{\"ok\":true}" JSONQ_FIXTURE_EOL "") == 0);
        ASSERT(jsonq_fixture_run("{\"result\":1,\"error\":{\"code\":-1}}",
                         (const char *const[]){JSONQ_FIXTURE_BIN, "unwrap", NULL}, buf, sizeof(buf)) == 2);
        ASSERT(jsonq_fixture_run("{\"result\":[1,2]}", (const char *const[]){JSONQ_FIXTURE_BIN, "unwrap", NULL}, buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "[1,2]" JSONQ_FIXTURE_EOL "") == 0);
        PASS();
    } _test_next:;
    return failures;
}

#if !defined(_WIN32)
/* One walker, three spellings: a link named jsonq in a temp dir (argv0
 * dispatch in z23), the build/bin/jsonq link, and `z23 jsonq` (argv+1).
 * All three must print the same direct-member count. */
static int test_jsonq_multicall_names(void)
{
    int failures = 0;
    char dir[4096], cwd[PATH_MAX], target[PATH_MAX + 32], alias[4608];
    char buf[512] = {0};
    const char *doc = "{\"a\":1,\"b\":{\"x\":1,\"y\":2},\"c\":[1,2]}";
    test_make_tmpdir(dir, sizeof(dir), "jsonq", "alias");
    TEST("jsonq: argv0 link and z23 jsonq run the same walker") {
        ASSERT(getcwd(cwd, sizeof(cwd)) != NULL);
        ASSERT(snprintf(target, sizeof(target), "%s/build/bin/z23", cwd) > 0);
        ASSERT(snprintf(alias, sizeof(alias), "%s/jsonq", dir) > 0);
        ASSERT(symlink(target, alias) == 0);
        ASSERT(jsonq_fixture_run_as(alias, doc,
                   (const char *const[]){alias, "count", "", NULL},
                   buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "3" JSONQ_FIXTURE_EOL) == 0);
        ASSERT(jsonq_fixture_run_as(JSONQ_FIXTURE_BIN, doc,
                   (const char *const[]){JSONQ_FIXTURE_BIN, "count", "", NULL},
                   buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "3" JSONQ_FIXTURE_EOL) == 0);
        ASSERT(jsonq_fixture_run_as("build/bin/z23", doc,
                   (const char *const[]){"build/bin/z23", "jsonq", "count", "", NULL},
                   buf, sizeof(buf)) == 0);
        ASSERT(strcmp(buf, "3" JSONQ_FIXTURE_EOL) == 0);
        /* A malformed document keeps exit 2 through the subcommand. */
        ASSERT(jsonq_fixture_run_as("build/bin/z23", "{not json}",
                   (const char *const[]){"build/bin/z23", "jsonq", "get", "a", NULL},
                   buf, sizeof(buf)) == 2);
        PASS();
    } _test_next:;
    (void)test_rm_rf_recursive(dir);
    return failures;
}
#endif

int test_jsonq(void)
{
    int failures = 0;
    struct stat st;
    bool available = stat(JSONQ_FIXTURE_BIN, &st) == 0;
#if defined(_WIN32)
    available = available && (st.st_mode & S_IFREG) != 0;
#else
    available = available && (st.st_mode & S_IXUSR) != 0;
#endif
    if (!available) {
        printf("jsonq: required build/bin/jsonq missing (run: make jsonq)" JSONQ_FIXTURE_EOL "");
        return 1;
    }
    failures += test_jsonq_count_and_keys();
    failures += test_jsonq_key_count();
    failures += test_jsonq_scalar_paths();
    failures += test_jsonq_unwrap();
#if !defined(_WIN32)
    failures += test_jsonq_multicall_names();
#endif
    return failures;
}
