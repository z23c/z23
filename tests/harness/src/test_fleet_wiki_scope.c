/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The scope option of the fleet wiki leaves: write, read, find, list and
 * history take `public` (default) or `fleet`. A fleet page is stored and
 * served only through the fleet-private board scope; a public read, find,
 * list or history never returns it; a review or revision stays in the scope
 * of the page it answers. Every case runs the real native handler against a
 * real `fleet_board` RPC table over an in-memory store. */
#include "test/test_core.h"
#include "config/boot_fleet_board.h"
#include "config/boot_internal.h"
#include "config/runtime.h"
#include "rpc/server.h"
#include "command/native_command.h"
#include "controllers/rpc_client.h"
#include "models/fleet_board_post.h"
#include "util/fleet_role_check.h"
#include "session/fleet_board_proto.h"

#include <stdlib.h>
#include <string.h>

typedef void (*fws_handler)(const struct zcl_command_request *,
                            struct zcl_command_reply *);

static struct rpc_table *fws_table;

static char *fws_rpc(const char *method, const char *params)
{
    struct json_value p, result, copy;
    char *out = NULL;
    (void)method;
    json_init(&p); json_init(&result); json_init(&copy);
    if (json_read(&p, params, strlen(params)) && json_at(&p, 0)) {
        struct json_value args;
        json_init(&args); json_set_array(&args);
        if (json_push_back(&args, json_at(&p, 0)) &&
            rpc_table_execute(fws_table, "fleet_board", &args, &result)) {
            size_t n = json_write(&result, NULL, 0);
            out = malloc(n + 1);
            if (out && json_write(&result, out, n + 1) == 0) { free(out); out = NULL; }
        }
        json_free(&args);
    }
    json_free(&p); json_free(&result); json_free(&copy);
    return out;
}

/* Run one handler with string fields: kv is key, value, key, value, NULL. */
static bool fws_run(fws_handler handler, const char *schema,
                    const char *const *kv, struct zcl_command_reply *reply)
{
    struct json_value in;
    json_init(&in); json_set_object(&in);
    bool ok = true;
    for (size_t i = 0; kv[i] && ok; i += 2)
        ok = json_push_kv_str(&in, kv[i], kv[i + 1]);
    struct zcl_command_request request = {.input = &in, .budget_bytes = 8192};
    zcl_command_reply_init(reply, schema);
    if (ok) handler(&request, reply);
    json_free(&in);
    return ok;
}

static bool fws_write(const char *slug, const char *scope, const char *text,
                      const char *supersedes, const char *format,
                      struct zcl_command_reply *reply)
{
    const char *kv[16];
    size_t n = 0;
    kv[n++] = "slug"; kv[n++] = slug;
    kv[n++] = "title"; kv[n++] = "Scoped page";
    kv[n++] = "text"; kv[n++] = text;
    if (scope) { kv[n++] = "scope"; kv[n++] = scope; }
    if (supersedes) { kv[n++] = "supersedes"; kv[n++] = supersedes; }
    if (format) { kv[n++] = "format"; kv[n++] = format; }
    kv[n] = NULL;
    return fws_run(zcl_native_handle_fleet_wiki_write, "zcl.fleet_board_post_id.v1", kv, reply);
}

/* One read by slug; scope may be NULL for the default. */
static bool fws_read(const char *slug, const char *scope, struct zcl_command_reply *reply)
{
    const char *kv[] = {"slug", slug, "scope", scope, NULL};
    if (!scope) kv[2] = NULL;
    return fws_run(zcl_native_handle_fleet_wiki_read, "zcl.fleet_wiki_read.v1", kv, reply);
}

static bool fws_names(const struct json_value *rows, const char *slug)
{
    for (size_t i = 0; i < json_size(rows); i++)
        if (!strcmp(json_get_str(json_get(json_at(rows, i), "slug")), slug)) return true;
    return false;
}

/* Does the page-index (list) or history reply name this slug? */
static bool fws_list_has(const char *scope, const char *slug)
{
    const char *kv[] = {"scope", scope, NULL};
    struct zcl_command_reply reply;
    if (!scope) kv[0] = NULL;
    bool ok = fws_run(zcl_native_handle_fleet_wiki_list, "zcl.fleet_board_list.v1", kv, &reply);
    bool has = ok && reply.status == ZCL_COMMAND_STATUS_PASSED &&
        fws_names(json_get(&reply.data, "posts"), slug);
    zcl_command_reply_free(&reply);
    return has;
}

static bool fws_history_has(const char *scope, const char *slug)
{
    const char *kv[] = {"slug", slug, "scope", scope, NULL};
    struct zcl_command_reply reply;
    if (!scope) kv[2] = NULL;
    bool ok = fws_run(zcl_native_handle_fleet_wiki_history, "zcl.fleet_board_list.v1", kv, &reply);
    bool has = ok && reply.status == ZCL_COMMAND_STATUS_PASSED &&
        fws_names(json_get(&reply.data, "posts"), slug);
    zcl_command_reply_free(&reply);
    return has;
}

/* Does a find for q show this slug among its entries? */
static bool fws_find_has(const char *scope, const char *q, const char *slug)
{
    const char *kv[] = {"q", q, "scope", scope, NULL};
    struct zcl_command_reply reply;
    if (!scope) kv[2] = NULL;
    bool ok = fws_run(zcl_native_handle_fleet_wiki_find, "zcl.fleet_wiki_find.v1", kv, &reply);
    bool has = ok && reply.status == ZCL_COMMAND_STATUS_PASSED &&
        fws_names(json_get(&reply.data, "entries"), slug);
    zcl_command_reply_free(&reply);
    return has;
}

static const char FWS_ENTRY[] =
    "{\"schema\":\"zcl.fleet_wiki_entry.v1\",\"topic\":\"scoped-topic\","
    "\"summary\":\"A lesson only the fleet may read.\","
    "\"lessons\":[{\"rule\":\"Keep it in the fleet.\",\"why\":\"It names a host.\",\"evidence\":\"docs/agent/WIKI.md\"}],"
    "\"applies_to\":[\"fleet\"],\"updated\":\"2026-11-03T09:00:00Z\"}";

static void fws_review_body(char *body, size_t cap, const char *target)
{
    (void)snprintf(body, cap,
        "{\"schema\":\"zcl.fleet_wiki_review.v1\",\"target\":\"%s\","
        "\"verdict\":\"approve\",\"rating\":5,\"rationale\":\"Checked these bytes.\"}",
        target);
}

static int fws_scope_cases(struct node_db *db)
{
    int failures = 0;
    struct zcl_command_reply pub, fleet, got;
    char pub_id[65], fleet_id[65];

    TEST("wiki scope: write and read in each scope; one slug names one page per scope") {
        ASSERT(fws_write("shared-slug", NULL, "public body", NULL, NULL, &pub));
        ASSERT_EQ(pub.status, ZCL_COMMAND_STATUS_PASSED);
        (void)snprintf(pub_id, sizeof(pub_id), "%s", json_get_str(json_get(&pub.data, "id")));
        ASSERT(fws_write("shared-slug", "fleet", "fleet body", NULL, NULL, &fleet));
        ASSERT_EQ(fleet.status, ZCL_COMMAND_STATUS_PASSED);
        (void)snprintf(fleet_id, sizeof(fleet_id), "%s", json_get_str(json_get(&fleet.data, "id")));
        uint8_t id[32];
        struct db_fleet_board_post row;
        ASSERT(fleet_board_id_from_hex(fleet_id, id) && db_fleet_board_post_find(db, id, &row));
        ASSERT_EQ(row.post.scope, FLEET_BOARD_SCOPE_FLEET);
        ASSERT_EQ(row.post.room[0], '\0');
        ASSERT(fleet_board_id_from_hex(pub_id, id) && db_fleet_board_post_find(db, id, &row));
        ASSERT_EQ(row.post.scope, FLEET_BOARD_SCOPE_PUBLIC);
        /* Default and explicit public read the public page, whichever
         * revision is newer; fleet reads the fleet page. */
        ASSERT(fws_read("shared-slug", NULL, &got));
        ASSERT_EQ(got.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!strcmp(json_get_str(json_get(&got.data, "text")), "public body"));
        zcl_command_reply_free(&got);
        ASSERT(fws_read("shared-slug", "public", &got));
        ASSERT(!strcmp(json_get_str(json_get(&got.data, "text")), "public body"));
        zcl_command_reply_free(&got);
        ASSERT(fws_read("shared-slug", "fleet", &got));
        ASSERT_EQ(got.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!strcmp(json_get_str(json_get(&got.data, "text")), "fleet body"));
        ASSERT(!strcmp(json_get_str(json_get(&got.data, "id")), fleet_id));
        zcl_command_reply_free(&got);
        /* A bad scope is refused by name. */
        ASSERT(fws_read("shared-slug", "everyone", &got));
        ASSERT_EQ(got.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strstr(got.error.message, "public or fleet") != NULL);
        zcl_command_reply_free(&got);
        zcl_command_reply_free(&pub);
        zcl_command_reply_free(&fleet);
        PASS();
    } _test_next:;
    return failures;
}

static int fws_hidden_cases(struct node_db *db)
{
    int failures = 0;
    struct zcl_command_reply fleet, got;
    TEST("wiki scope: a public read, find, list and history never return a fleet page") {
        ASSERT(fws_write("fleet-only", "fleet", FWS_ENTRY, NULL, "entry", &fleet));
        ASSERT_EQ(fleet.status, ZCL_COMMAND_STATUS_PASSED);
        const char *fleet_id = json_get_str(json_get(&fleet.data, "id"));
        ASSERT(fws_read("fleet-only", NULL, &got));
        ASSERT_EQ(got.status, ZCL_COMMAND_STATUS_FAILED);
        zcl_command_reply_free(&got);
        ASSERT(fws_read("fleet-only", "public", &got));
        ASSERT_EQ(got.status, ZCL_COMMAND_STATUS_FAILED);
        zcl_command_reply_free(&got);
        /* An exact id read with no scope is public and refuses it, as does
         * scope=public; only scope=fleet reads the revision. */
        const char *bare_id[] = {"id", fleet_id, NULL};
        ASSERT(fws_run(zcl_native_handle_fleet_wiki_read, "zcl.fleet_wiki_read.v1", bare_id, &got));
        ASSERT_EQ(got.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strstr(got.error.message, "scope=fleet") != NULL);
        zcl_command_reply_free(&got);
        const char *by_id[] = {"id", fleet_id, "scope", "public", NULL};
        ASSERT(fws_run(zcl_native_handle_fleet_wiki_read, "zcl.fleet_wiki_read.v1", by_id, &got));
        ASSERT_EQ(got.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strstr(got.error.message, "scope=fleet") != NULL);
        zcl_command_reply_free(&got);
        by_id[3] = "fleet";
        ASSERT(fws_run(zcl_native_handle_fleet_wiki_read, "zcl.fleet_wiki_read.v1", by_id, &got));
        ASSERT_EQ(got.status, ZCL_COMMAND_STATUS_PASSED);
        zcl_command_reply_free(&got);
        ASSERT(!fws_find_has(NULL, "scoped-topic", "fleet-only"));
        ASSERT(!fws_find_has("public", "", "fleet-only"));
        ASSERT(!fws_list_has(NULL, "fleet-only"));
        ASSERT(!fws_history_has(NULL, "fleet-only"));
        /* And the fleet view does show it. */
        ASSERT(fws_find_has("fleet", "scoped-topic", "fleet-only"));
        ASSERT(fws_list_has("fleet", "fleet-only"));
        ASSERT(fws_history_has("fleet", "fleet-only"));
        ASSERT(!fws_list_has("fleet", "shared-slug-absent"));
        /* The model agrees: the public view of the store skips the row. */
        struct db_fleet_board_post row;
        ASSERT(!db_fleet_board_wiki_read_in(db, FLEET_WIKI_VIEW_PUBLIC, "fleet-only", &row));
        ASSERT(db_fleet_board_wiki_read_in(db, FLEET_WIKI_VIEW_FLEET, "fleet-only", &row));
        zcl_command_reply_free(&fleet);
        PASS();
    } _test_next:;
    return failures;
}

static int fws_cross_cases(void)
{
    int failures = 0;
    struct zcl_command_reply pub, fleet, bad, good, seen;
    char body[512];
    TEST("wiki scope: a review or revision must match the scope of its target page") {
        ASSERT(fws_write("cross-page", NULL, "public page", NULL, NULL, &pub));
        ASSERT(fws_write("cross-fleet-page", "fleet", "fleet page", NULL, NULL, &fleet));
        const char *pub_id = json_get_str(json_get(&pub.data, "id"));
        const char *fleet_id = json_get_str(json_get(&fleet.data, "id"));
        /* A public review of a fleet page is refused, and says why. */
        fws_review_body(body, sizeof(body), fleet_id);
        ASSERT(fws_write("review-a", NULL, body, NULL, "review", &bad));
        ASSERT_EQ(bad.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(!strcmp(bad.error.code, "CROSS_SCOPE_REVIEW"));
        ASSERT(strstr(bad.error.message, "fleet scope") != NULL);
        ASSERT(strstr(bad.error.message, "scope=fleet") != NULL);
        zcl_command_reply_free(&bad);
        /* A fleet review of a public page likewise. */
        fws_review_body(body, sizeof(body), pub_id);
        ASSERT(fws_write("review-b", "fleet", body, NULL, "review", &bad));
        ASSERT_EQ(bad.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(!strcmp(bad.error.code, "CROSS_SCOPE_REVIEW"));
        zcl_command_reply_free(&bad);
        /* A revision names its predecessor across scopes: refused. */
        ASSERT(fws_write("cross-page", "fleet", "forked", pub_id, NULL, &bad));
        ASSERT_EQ(bad.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(!strcmp(bad.error.code, "CROSS_SCOPE_REVISION"));
        zcl_command_reply_free(&bad);
        ASSERT(fws_write("cross-fleet-page", NULL, "leaked", fleet_id, NULL, &bad));
        ASSERT(!strcmp(bad.error.code, "CROSS_SCOPE_REVISION"));
        zcl_command_reply_free(&bad);
        /* Same scope works: a fleet review of the fleet page, read back only
         * through the fleet view of the target's history. */
        fws_review_body(body, sizeof(body), fleet_id);
        ASSERT(fws_write("review-c", "fleet", body, NULL, "review", &good));
        ASSERT_EQ(good.status, ZCL_COMMAND_STATUS_PASSED);
        const char *seen_kv[] = {"target", fleet_id, "scope", "fleet", NULL};
        ASSERT(fws_run(zcl_native_handle_fleet_wiki_history, "zcl.fleet_board_list.v1", seen_kv, &seen));
        ASSERT_EQ(seen.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(json_size(json_get(&seen.data, "posts")), 1);
        zcl_command_reply_free(&seen);
        const char *pub_kv[] = {"target", fleet_id, NULL};
        ASSERT(fws_run(zcl_native_handle_fleet_wiki_history, "zcl.fleet_board_list.v1", pub_kv, &seen));
        ASSERT_EQ(json_size(json_get(&seen.data, "posts")), 0);
        zcl_command_reply_free(&seen);
        /* A same-scope revision of a fleet page supersedes it. */
        zcl_command_reply_free(&good);
        ASSERT(fws_write("cross-fleet-page", "fleet", "fleet page v2", fleet_id, NULL, &good));
        ASSERT_EQ(good.status, ZCL_COMMAND_STATUS_PASSED);
        zcl_command_reply_free(&good);
        zcl_command_reply_free(&pub);
        zcl_command_reply_free(&fleet);
        PASS();
    } _test_next:;
    return failures;
}

/* The wiki_write op signs public only: one call of it, expected NULL for absent. */
static char *fws_op_write(const char *slug, const char *expected, char marker)
{
    char params[640];
    (void)snprintf(params, sizeof(params),
        "[{\"op\":\"wiki_write\",\"expected\":\"%s\",\"text\":\"op body\","
        "\"slug\":\"%s\",\"title\":\"Op page\","
        "\"binding\":\"00000000000000000000000000000001\","
        "\"marker\":\"000000000000000000000000000000000000000000000000000000000000000%c\"}]",
        expected ? expected : "absent", slug, marker);
    return fws_rpc("fleet_board", params);
}

static int fws_write_op_cases(struct node_db *db)
{
    int failures = 0;
    struct zcl_command_reply fleet;
    struct fleet_board_status before, after;
    char *refused = NULL, *absent = NULL;
    TEST("wiki scope: the wiki_write op refuses a fleet parent and sees only its own scope") {
        ASSERT(fws_write("wo-fleet", "fleet", "fleet page", NULL, NULL, &fleet));
        const char *fleet_id = json_get_str(json_get(&fleet.data, "id"));
        ASSERT(db_fleet_board_status(db, 0, &before));
        refused = fws_op_write("wo-fleet", fleet_id, '1');
        ASSERT(refused && strstr(refused, "CROSS_SCOPE_REVISION") != NULL);
        ASSERT(db_fleet_board_status(db, 0, &after));
        ASSERT_EQ(after.posts, before.posts);
        ASSERT(!fws_list_has(NULL, "wo-fleet"));
        ASSERT(!fws_history_has(NULL, "wo-fleet"));
        /* No head in the public scope: a fleet page of the slug is no conflict. */
        absent = fws_op_write("wo-fleet", NULL, '2');
        ASSERT(absent && strstr(absent, "WIKI_CONFLICT") == NULL);
        ASSERT(fws_history_has(NULL, "wo-fleet"));
        ASSERT(db_fleet_board_status(db, 0, &after));
        ASSERT_EQ(after.posts, before.posts + 1);
        PASS();
    } _test_next:;
    free(refused);
    free(absent);
    zcl_command_reply_free(&fleet);
    return failures;
}

static int fws_plan_cases(void)
{
    int failures = 0;
    struct zcl_command_reply plan_pub, plan_fleet, bad;
    TEST("wiki scope: an MCP write plan is bound to its scope") {
        struct zcl_command_context mcp = {.plan_first = true};
        struct json_value in;
        struct zcl_command_request request = {.context = &mcp, .input = &in, .budget_bytes = 8192};
        json_init(&in); json_set_object(&in);
        ASSERT(json_push_kv_str(&in, "slug", "plan-scope") &&
               json_push_kv_str(&in, "title", "Plan") &&
               json_push_kv_str(&in, "text", "body"));
        zcl_command_reply_init(&plan_pub, "zcl.fleet_board_post_id.v1");
        zcl_native_handle_fleet_wiki_write(&request, &plan_pub);
        ASSERT(json_push_kv_str(&in, "scope", "fleet"));
        zcl_command_reply_init(&plan_fleet, "zcl.fleet_board_post_id.v1");
        zcl_native_handle_fleet_wiki_write(&request, &plan_fleet);
        ASSERT(!strcmp(json_get_str(json_get(&plan_pub.data, "scope")), "public"));
        ASSERT(!strcmp(json_get_str(json_get(&plan_fleet.data, "scope")), "fleet"));
        const char *public_plan = json_get_str(json_get(&plan_pub.data, "plan_id"));
        const char *fleet_plan = json_get_str(json_get(&plan_fleet.data, "plan_id"));
        ASSERT(public_plan[0] && strcmp(public_plan, fleet_plan) != 0);
        /* The public plan cannot be confirmed as a fleet write. */
        ASSERT(json_push_kv_str(&in, "plan_id", public_plan) &&
               json_push_kv_bool(&in, "confirm", true));
        zcl_command_reply_init(&bad, "zcl.fleet_board_post_id.v1");
        zcl_native_handle_fleet_wiki_write(&request, &bad);
        ASSERT_EQ(bad.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(!strcmp(bad.error.code, "PLAN_MISMATCH"));
        json_free(&in);
        zcl_command_reply_free(&plan_pub);
        zcl_command_reply_free(&plan_fleet);
        zcl_command_reply_free(&bad);
        PASS();
    } _test_next:;
    return failures;
}

int test_fleet_wiki_scope(void)
{
    int failures = 0;
    struct node_db db = {0};
    char dir[256] = {0}, warmup[256];
    bool was_warming = rpc_is_in_warmup(warmup, sizeof(warmup));
    zcl_fleet_role_checker_install_permissive_for_testing();
    bool opened = node_db_open(&db, ":memory:");
    struct db_service service = {.node_db = &db, .started = true};
    struct app_runtime_context runtime = {.db_service = &service};
    struct boot_svc_ctx svc = {.node_db = &db, .datadir = dir};
    struct rpc_table table;
    if (opened) {
        test_make_tmpdir(dir, sizeof(dir), "fleetboard", "wikiscope");
        boot_fleet_board_shutdown(); boot_fleet_board_wire(&svc);
        app_runtime_set_current(&runtime);
        rpc_table_init(&table); boot_fleet_board_register_rpc(&table);
        set_rpc_warmup_finished();
        fws_table = &table;
        node_rpc_client_set_test_hook(fws_rpc);
        failures += fws_scope_cases(&db) + fws_hidden_cases(&db) +
                    fws_cross_cases() + fws_write_op_cases(&db) + fws_plan_cases();
    } else {
        TEST("wiki scope: the in-memory store opens") { ASSERT(opened); PASS(); }
        _test_next:;
    }
    node_rpc_client_set_test_hook(NULL);
    app_runtime_set_current(NULL);
    if (was_warming) set_rpc_warmup_started(warmup);
    boot_fleet_board_shutdown();
    if (db.open) node_db_close(&db);
    if (dir[0]) test_rm_rf(dir);
    return failures;
}
