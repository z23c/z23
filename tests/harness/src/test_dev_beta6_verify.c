/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.beta6.verify
 * (tools/command/native_dev_beta6_verify.c): the leaf half calls the bound
 * handler DIRECTLY after every input first crosses the REAL registry
 * validator, exactly like test_dev_orient.c, so an input key the .def never
 * declared fails here rather than only from a shell. Fixture trees live
 * under this test's own tmpdir and are torn down on every path, pass or
 * fail.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/beta6_bootstrap.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define DBV_PATH "dev.beta6.verify"

/* ── one in-process invocation ─────────────────────────────────────────── */

struct dbv_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dbv_begin(struct dbv_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), DBV_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.dev_beta6_verify.v1");
}

static bool dbv_run(struct dbv_call *c)
{
    char why[192];
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_dev_beta6_verify(&c->request, &c->reply);
    return true;
}

static void dbv_end(struct dbv_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool dbv_ok(const struct dbv_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *dbv_str(const struct dbv_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static long long dbv_int(const struct dbv_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v ? json_get_int(v) : -12345;
}

/* ── fixture: a beta6 serve tree on disk ─────────────────────────────────
 * Same shape and compiled-anchor line as
 * tests/harness/src/test_beta6_bootstrap.c's fixture_build(), reproduced
 * here rather than shared because that file's helpers are file-scope
 * static and this group owns a different translation unit. */

static bool dbv_write(const char *dir, const char *relative, size_t bytes)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, relative);
    char *slash = strrchr(path, '/');
    if (slash) {
        *slash = '\0';
        for (char *p = path + 1; *p; p++) {
            if (*p != '/')
                continue;
            *p = '\0';
            (void)mkdir(path, 0700);
            *p = '/';
        }
        (void)mkdir(path, 0700);
        *slash = '/';
    }
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    for (size_t i = 0; i < bytes; i++)
        fputc(0xAB, f);
    return fclose(f) == 0;
}

static bool dbv_anchor(const char *dir)
{
    char sidecar[300];
    snprintf(sidecar, sizeof(sidecar), "%s.anchor", dir);
    FILE *f = fopen(sidecar, "w");
    if (!f)
        return false;
    fprintf(f, "3126937 00000663e40f1fe0bc32a7e7282fac25de5fe8ec"
               "efd9c627e2fd948d388f7053\n");
    return fclose(f) == 0;
}

static bool dbv_build_curated(const char *dir)
{
    return dbv_write(dir, "blocks/blk00000.dat", 40) &&
           dbv_write(dir, "blocks/index/000005.ldb", 10) &&
           dbv_write(dir, "chainstate/000007.ldb", 20) && dbv_anchor(dir);
}

/* ── cases ────────────────────────────────────────────────────────────── */

static int test_dbv_curated_tree_verifies(void)
{
    int failures = 0;
    TEST("a curated serve tree verifies: height 3126937, file_count 3") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "dev_beta6_verify", "curated");
        ASSERT(dbv_build_curated(dir));

        struct dbv_call c;
        dbv_begin(&c);
        (void)json_push_kv_str(&c.input, "source_dir", dir);
        ASSERT(dbv_run(&c));
        ASSERT(dbv_ok(&c));
        ASSERT_EQ(dbv_int(&c, "height"), 3126937);
        ASSERT_EQ(dbv_int(&c, "file_count"), 3);
        ASSERT_STR_EQ(dbv_str(&c, "sidecar_used"), "anchor");
        ASSERT_STR_EQ(dbv_str(&c, "network"), "main");
        ASSERT_EQ(dbv_int(&c, "manifest_version"), 1);
        dbv_end(&c);

        /* Verifying does not leave the service armed for this process. */
        ASSERT(!beta6_bs_status().ok);

        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dbv_stray_entry_refused_by_name(void)
{
    int failures = 0;
    TEST("a wallet.dat beside blocks/chainstate is refused BEFORE arming") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "dev_beta6_verify", "datadir");
        ASSERT(dbv_build_curated(dir));
        ASSERT(dbv_write(dir, "wallet.dat", 4));

        struct dbv_call c;
        dbv_begin(&c);
        (void)json_push_kv_str(&c.input, "source_dir", dir);
        ASSERT(dbv_run(&c));
        ASSERT(!dbv_ok(&c));
        ASSERT(strstr(c.reply.error.message, "this is a datadir, not a "
                                             "serve tree") != NULL);
        ASSERT(strstr(c.reply.error.message, "wallet.dat") != NULL);
        dbv_end(&c);

        /* Refused before arming: nothing was ever armed to leak. */
        ASSERT(!beta6_bs_status().ok);

        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dbv_no_sidecar_exact_refusal(void)
{
    int failures = 0;
    TEST("no .anchor/.meta sidecar: the exact arm refusal text") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "dev_beta6_verify", "nosidecar");
        ASSERT(dbv_write(dir, "blocks/blk00000.dat", 40));
        ASSERT(dbv_write(dir, "blocks/index/000005.ldb", 10));
        ASSERT(dbv_write(dir, "chainstate/000007.ldb", 20));

        struct dbv_call c;
        dbv_begin(&c);
        (void)json_push_kv_str(&c.input, "source_dir", dir);
        ASSERT(dbv_run(&c));
        ASSERT(!dbv_ok(&c));
        ASSERT(strstr(c.reply.error.message,
                      "has no readable .anchor marker beside") != NULL);
        dbv_end(&c);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dbv_relative_path_refused(void)
{
    int failures = 0;
    TEST("a relative source_dir is refused") {
        struct dbv_call c;
        dbv_begin(&c);
        (void)json_push_kv_str(&c.input, "source_dir",
                               "relative/serve/tree/dir");
        ASSERT(dbv_run(&c));
        ASSERT(!dbv_ok(&c));
        ASSERT(c.reply.error.message[0] != '\0');
        dbv_end(&c);
        PASS();
    } _test_next:;
    return failures;
}

int test_dev_beta6_verify(void);
int test_dev_beta6_verify(void)
{
    int failures = test_dbv_curated_tree_verifies() +
                   test_dbv_stray_entry_refused_by_name() +
                   test_dbv_no_sidecar_exact_refusal() +
                   test_dbv_relative_path_refused();

    if (failures == 0) printf("test_dev_beta6_verify: all passed\n");
    else printf("test_dev_beta6_verify: %d FAILED\n", failures);
    return failures;
}
