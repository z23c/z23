/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.agent.ticketkey
 * (tools/command/native_devagent_ticketkey.c).
 *
 * The owning file->group map comes from the real tree, so no fixture
 * repository can stand in for it: this group runs against the real checkout
 * (cwd default) for group devagent_situation and pins the commuting-ticket
 * contract from docs/agent/COMMUTING_TICKETS.md — closure membership, key
 * shape, determinism, tip sensitivity, and the two refusal codes.
 *
 * It calls the bound handler DIRECTLY: dev.agent.ticketkey is a dev-lane
 * leaf and an in-process call is exactly what the CLI does after input
 * validation, so the input keys are additionally validated through the real
 * registry.
 */

#include "test/test_core.h"
#include "controllers/agent_impact_harness.h"
#include "base/safe_alloc.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DVT_PATH "dev.agent.ticketkey"
#define DVT_GROUP "devagent_situation"
#define DVT_TEST_FILE "tests/harness/src/test_devagent_situation.c"
#define DVT_IMPL_FILE "tools/command/native_devagent_situation.c"

/* ── one in-process invocation ─────────────────────────────────────────── */

struct dvt_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dvt_begin(struct dvt_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), DVT_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.agent_ticketkey.v1");
}

/* Validate through the REAL registry first, so a key the .def never declared
 * is caught here rather than passing in-process and failing from a shell. */
static bool dvt_run(struct dvt_call *c)
{
    char why[192];
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_dev_agent_ticketkey(&c->request, &c->reply);
    return true;
}

static void dvt_end(struct dvt_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool dvt_ok(const struct dvt_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static const char *dvt_str(const struct dvt_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static int64_t dvt_int(const struct dvt_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static bool dvt_hex64(const char *s)
{
    if (!s || strlen(s) != 64)
        return false;
    return strspn(s, "0123456789abcdef") == 64;
}

static bool dvt_hex40(const char *s)
{
    if (!s || strlen(s) != 40)
        return false;
    return strspn(s, "0123456789abcdef") == 40;
}

/* One git argv in the process checkout (which is the default cwd). Never a
 * shell: zcl_spawn_capture execs git itself. */
static bool dvt_git(const char *const args[], char *out, size_t cap)
{
    const char *argv[16];
    size_t n = 0;
    size_t i;
    argv[n++] = "git";
    for (i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0]))
            return false;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    if (zcl_spawn_capture(argv, out, cap, 30000) != 0)
        return false;
    {
        size_t len = strlen(out);
        while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r'))
            out[--len] = '\0';
    }
    return out[0] != '\0';
}

static bool dvt_files_contains(const struct dvt_call *c, const char *path)
{
    const struct json_value *v = json_get(&c->reply.data, "files");
    size_t i;
    if (!v || v->type != JSON_ARR)
        return false;
    for (i = 0; i < v->num_children; i++) {
        const char *s = json_get_str(&v->children[i]);
        if (s && strcmp(s, path) == 0)
            return true;
    }
    return false;
}

static bool dvt_files_sorted(const struct dvt_call *c)
{
    const struct json_value *v = json_get(&c->reply.data, "files");
    size_t i;
    if (!v || v->type != JSON_ARR || v->num_children == 0)
        return false;
    for (i = 1; i < v->num_children; i++) {
        const char *a = json_get_str(&v->children[i - 1]);
        const char *b = json_get_str(&v->children[i]);
        if (!a || !b || strcmp(a, b) >= 0)
            return false;
    }
    return true;
}

static bool dvt_fixture_write(const char *path, const char *text)
{
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    bool ok = fwrite(text, 1, strlen(text), file) == strlen(text);
    return fclose(file) == 0 && ok;
}

static bool dvt_snapshot_dirs(void)
{
    const char *dirs[] = {"tools", "tests", "tests/harness", "tests/harness/src",
        "tools/lint", "tools/lint/lintc", "platform", "platform/modules",
        "platform/modules/platform", "platform/modules/platform/tests"};
    for (size_t i = 0; i < sizeof(dirs)/sizeof(dirs[0]); i++)
        if (mkdir(dirs[i], 0700)) return false;
    return true;
}

static bool dvt_snapshot_fixture(void)
{
    if (!dvt_snapshot_dirs()) return false;
    if (!dvt_fixture_write("tools/ticket_snapshot_probe.c", "int probe(void){return 1;}\n") ||
        !dvt_fixture_write(DVT_TEST_FILE, "const char *probe = \"ticket_snapshot_probe\";\n") ||
        !dvt_fixture_write("platform/modules/platform/tests/windows_acceptance.mk", "# fixture\n"))
        return false;
    char output[2048];
    const char *init[] = {"git", "init", "-q", NULL};
    const char *add[] = {"git", "add", ".", NULL};
    const char *commit[] = {"git", "-c", "user.name=Fixture", "-c",
        "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
        "-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture", NULL};
    return zcl_spawn_capture(init, output, sizeof(output), 30000) == 0 &&
           zcl_spawn_capture(add, output, sizeof(output), 30000) == 0 &&
           zcl_spawn_capture(commit, output, sizeof(output), 30000) == 0;
}

static bool dvt_probe_membership(bool expected)
{
    struct dvt_call c;
    dvt_begin(&c);
    (void)json_push_kv_str(&c.input, "group", DVT_GROUP);
    bool ran = dvt_run(&c);
    bool actual = dvt_files_contains(&c, "tools/ticket_snapshot_probe.c");
    printf("[snapshot fixture expected=%d actual=%d handler_ok=%d] ",
           expected, actual, ran && dvt_ok(&c));
    bool ok = ran && dvt_ok(&c) && actual == expected;
    dvt_end(&c);
    return ok;
}

static bool dvt_snapshot_parity(const struct agent_impact_snapshot *snapshot)
{
    const char *paths[] = {DVT_TEST_FILE, "tools/ticket_snapshot_probe.c",
        "tools/plain.c", "tools/unknown.c", "core/unknown.c"};
    for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
        struct agent_impact_acc live = {0}, captured = {0};
        bool live_risk = false, captured_risk = false;
        const char *a = zcl_native_code_route_for_path(paths[i], &live, &live_risk);
        const char *b = zcl_native_code_route_snapshot(paths[i], &captured,
            &captured_risk, snapshot);
        if (strcmp(a, b) || live_risk != captured_risk ||
            live.groups_len != captured.groups_len ||
            live.shared_rule_hits != captured.shared_rule_hits ||
            live.groups_lost != captured.groups_lost) return false;
        for (size_t g = 0; g < live.groups_len; g++)
            if (strcmp(live.groups[g], captured.groups[g])) return false;
    }
    return true;
}

static bool dvt_snapshot_loss(const struct agent_impact_snapshot *snapshot)
{
    struct agent_impact_acc live = {0}, captured = {0};
    char group[32];
    for (size_t i = 0; i < ZCL_AGENT_IMPACT_MAX_GROUPS; i++) {
        (void)snprintf(group, sizeof(group), "fixture_%zu", i);
        agent_impact_add_group(&live, group);
        agent_impact_add_group(&captured, group);
    }
    bool a = agent_impact_apply_name_reference_routes("tools/ticket_snapshot_probe.c", &live);
    bool b = agent_impact_name_routes_snapshot("tools/ticket_snapshot_probe.c", &captured, snapshot);
    return a && b && live.groups_lost && captured.groups_lost &&
        live.groups_len == captured.groups_len &&
        live.shared_rule_hits == captured.shared_rule_hits;
}

static bool dvt_snapshot_row_cap(void)
{
    char path[128];
    bool ok = true;
    for (size_t i = 0; i < 4095; i++) {
        (void)snprintf(path, sizeof(path), "tools/lint/lintc/snapshot_%zu.c", i);
        if (!dvt_fixture_write(path, "")) { ok = false; break; }
    }
    struct agent_impact_snapshot *full = agent_impact_snapshot_create();
    ok = ok && full != NULL;
    agent_impact_snapshot_free(full);
    ok = ok && dvt_fixture_write("tools/lint/lintc/snapshot_extra.c", "");
    struct agent_impact_snapshot *over = agent_impact_snapshot_create();
    ok = ok && over == NULL;
    agent_impact_snapshot_free(over);
    for (size_t i = 0; i < 4095; i++) {
        (void)snprintf(path, sizeof(path), "tools/lint/lintc/snapshot_%zu.c", i);
        if (unlink(path)) ok = false;
    }
    if (unlink("tools/lint/lintc/snapshot_extra.c")) ok = false;
    return ok;
}

static bool dvt_snapshot_table_test(void)
{
    const char *table = "platform/modules/platform/tests/windows_acceptance.mk";
    const char *path = "tests/harness/src/fixture_snapshot_bridge.c";
    if (!dvt_fixture_write(table, "ZCL_WINDOWS_ACCEPTANCE_FIX_SOURCES := tests/harness/src/fixture_snapshot_bridge.c\n")) return false;
    struct agent_impact_snapshot *old = agent_impact_snapshot_create();
    if (!old) return false;
    bool ok = dvt_snapshot_parity(old) && dvt_fixture_write(table, "# changed\n");
    struct agent_impact_snapshot *fresh = agent_impact_snapshot_create();
    struct agent_impact_acc a = {0}, b = {0};
    ok = ok && fresh && memcmp(agent_impact_snapshot_digest(old),
        agent_impact_snapshot_digest(fresh), 32) != 0;
    ok = ok && agent_impact_harness_routes_snapshot(path, &a, old) &&
        !agent_impact_harness_routes_snapshot(path, &b, fresh);
    agent_impact_snapshot_free(old);
    agent_impact_snapshot_free(fresh);
    return ok;
}

static bool dvt_snapshot_fallback_test(void)
{
    zcl_alloc_fault_fail_next("agent_impact_snapshot");
    struct agent_impact_snapshot *failed = agent_impact_snapshot_create();
    bool ok = failed == NULL;
    agent_impact_snapshot_free(failed);
    const char *table = "platform/modules/platform/tests/windows_acceptance.mk";
    ok = ok && unlink(table) == 0;
    failed = agent_impact_snapshot_create();
    ok = ok && failed == NULL && dvt_probe_membership(false);
    agent_impact_snapshot_free(failed);
    return ok && dvt_fixture_write(table, "# restored\n");
}

static bool dvt_snapshot_root_test(void)
{
    char first[PATH_MAX], second[PATH_MAX];
    if (!getcwd(first, sizeof(first))) return false;
    test_make_tmpdir(second, sizeof(second), "ticket_snapshot", "other");
    struct agent_impact_snapshot *old = agent_impact_snapshot_create();
    bool ok = old && chdir(second) == 0 && dvt_snapshot_fixture();
    struct agent_impact_snapshot *fresh = agent_impact_snapshot_create();
    ok = ok && fresh && memcmp(agent_impact_snapshot_digest(old),
        agent_impact_snapshot_digest(fresh), 32) != 0 && dvt_probe_membership(true);
    bool restored = chdir(first) == 0;
    agent_impact_snapshot_free(old);
    agent_impact_snapshot_free(fresh);
    return restored && test_rm_rf_recursive(second) == 0 && ok &&
        dvt_probe_membership(false);
}

static int dvt_referrer_mutation_test(void)
{
    int failures = 0;
    TEST("ticketkey: referrer edits between calls invalidate ownership memo") {
        char saved[PATH_MAX], root[PATH_MAX];
        ASSERT(getcwd(saved, sizeof(saved)) != NULL);
        test_make_tmpdir(root, sizeof(root), "ticket_snapshot", "mutation");
        bool ok = chdir(root) == 0;
        ok = ok && dvt_snapshot_fixture();
        struct agent_impact_snapshot *captured = agent_impact_snapshot_create();
        ok = ok && captured != NULL;
        ok = ok && dvt_snapshot_parity(captured);
        ok = ok && dvt_snapshot_loss(captured);
        ok = ok && dvt_snapshot_row_cap();
        ok = ok && dvt_probe_membership(true);
        ok = ok && dvt_fixture_write(DVT_TEST_FILE, "const char *probe = \"different_name\";\n");
        ok = ok && dvt_probe_membership(false);
        agent_impact_snapshot_free(captured);
        ok = ok && dvt_snapshot_table_test();
        ok = ok && dvt_snapshot_fallback_test();
        ok = ok && dvt_snapshot_root_test();
        bool restored = chdir(saved) == 0;
        ASSERT(restored);
        ASSERT_EQ(test_rm_rf_recursive(root), 0);
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

int test_devagent_ticketkey(void);
int test_devagent_ticketkey(void)
{
    int failures = dvt_referrer_mutation_test();

    TEST("ticketkey: the leaf is registered with group,cwd,tip keys") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DVT_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "group") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "cwd") != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "tip") != NULL);
        PASS();
    }

    TEST("ticketkey: a missing group is BAD_INPUT") {
        struct dvt_call c;
        dvt_begin(&c);
        ASSERT(dvt_run(&c));
        ASSERT(!dvt_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "BAD_INPUT");
        dvt_end(&c);
        PASS();
    }

    TEST("ticketkey: an unknown group names UNKNOWN_GROUP") {
        struct dvt_call c;
        dvt_begin(&c);
        (void)json_push_kv_str(&c.input, "group", "no_such_group");
        ASSERT(dvt_run(&c));
        ASSERT(!dvt_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "UNKNOWN_GROUP");
        dvt_end(&c);
        PASS();
    }

    TEST("ticketkey: the real checkout keys devagent_situation") {
        struct dvt_call c;
        const struct json_value *files;
        char head[256];
        const char *tip_args[] = {"rev-parse", "HEAD", NULL};
        ASSERT(dvt_git(tip_args, head, sizeof(head)));
        ASSERT(dvt_hex40(head));
        dvt_begin(&c);
        (void)json_push_kv_str(&c.input, "group", DVT_GROUP);
        ASSERT(dvt_run(&c));
        ASSERT(dvt_ok(&c));
        ASSERT_STR_EQ(dvt_str(&c, "leaf"), DVT_PATH);
        ASSERT_STR_EQ(dvt_str(&c, "group"), DVT_GROUP);
        ASSERT_STR_EQ(dvt_str(&c, "tip"), head);
        ASSERT_STR_EQ(dvt_str(&c, "harness"), "ticketkey.v1");
        ASSERT(dvt_hex64(dvt_str(&c, "key")));
        ASSERT(dvt_hex64(dvt_str(&c, "epoch")));
        ASSERT(dvt_files_contains(&c, DVT_TEST_FILE));
        ASSERT(dvt_files_contains(&c, DVT_IMPL_FILE));
        ASSERT(dvt_files_sorted(&c));
        files = json_get(&c.reply.data, "files");
        ASSERT(files && files->type == JSON_ARR);
        ASSERT(dvt_int(&c, "files_count") == (int64_t)files->num_children);
        ASSERT(dvt_int(&c, "files_count") >= 2);
        ASSERT(dvt_int(&c, "elapsed_ms") >= 0);
        dvt_end(&c);
        PASS();
    }

    TEST("ticketkey: two calls give the same key") {
        struct dvt_call a;
        struct dvt_call b;
        char key_a[128];
        dvt_begin(&a);
        (void)json_push_kv_str(&a.input, "group", DVT_GROUP);
        ASSERT(dvt_run(&a));
        ASSERT(dvt_ok(&a));
        (void)snprintf(key_a, sizeof(key_a), "%s", dvt_str(&a, "key"));
        dvt_begin(&b);
        (void)json_push_kv_str(&b.input, "group", DVT_GROUP);
        ASSERT(dvt_run(&b));
        ASSERT(dvt_ok(&b));
        ASSERT_STR_EQ(dvt_str(&b, "key"), key_a);
        ASSERT_STR_EQ(dvt_str(&b, "epoch"), dvt_str(&a, "epoch"));
        dvt_end(&a);
        dvt_end(&b);
        PASS();
    }

    TEST("ticketkey: an older tip moves the key when the blob moved") {
        const char *prev_args[] = {"rev-parse", "HEAD~1", NULL};
        char prev[256];
        /* A shallow or single-commit checkout has no HEAD~1: that is a
         * property of the checkout, not of the leaf, so note and pass. */
        if (!dvt_git(prev_args, prev, sizeof(prev))) {
            printf("[note: no HEAD~1 in this checkout; tip comparison "
                   "skipped] ");
            PASS();
        } else {
            const char *blob_now_args[] = {"rev-parse",
                                           "HEAD:" DVT_IMPL_FILE, NULL};
            const char *blob_prev_args[] = {"rev-parse",
                                            "HEAD~1:" DVT_IMPL_FILE, NULL};
            char blob_now[256];
            char blob_prev[256];
            ASSERT(dvt_git(blob_now_args, blob_now, sizeof(blob_now)));
            if (!dvt_git(blob_prev_args, blob_prev, sizeof(blob_prev)) ||
                strcmp(blob_now, blob_prev) == 0) {
                printf("[note: " DVT_IMPL_FILE " unchanged at HEAD~1; "
                       "tip comparison skipped] ");
                PASS();
            } else {
                struct dvt_call now;
                struct dvt_call then;
                char key_now[128];
                dvt_begin(&now);
                (void)json_push_kv_str(&now.input, "group", DVT_GROUP);
                ASSERT(dvt_run(&now));
                ASSERT(dvt_ok(&now));
                (void)snprintf(key_now, sizeof(key_now), "%s",
                               dvt_str(&now, "key"));
                dvt_begin(&then);
                (void)json_push_kv_str(&then.input, "group", DVT_GROUP);
                (void)json_push_kv_str(&then.input, "tip", "HEAD~1");
                ASSERT(dvt_run(&then));
                ASSERT(dvt_ok(&then));
                ASSERT_STR_EQ(dvt_str(&then, "tip"), prev);
                if (strcmp(dvt_str(&then, "key"), key_now) == 0) {
                    printf("[note: key unchanged across a blob move — "
                           "FAIL] ");
                    ASSERT(0);
                }
                dvt_end(&now);
                dvt_end(&then);
                PASS();
            }
        }
    }

_test_next:;
    if (failures == 0)
        printf("test_devagent_ticketkey: all passed\n");
    else
        printf("test_devagent_ticketkey: %d FAILED\n", failures);
    return failures;
}
