/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * code.guide lessons: the wiki entries that concern the paths, not the words
 * in their top-level directory. Ranking (exact applies_to, directory prefix,
 * file stem), trust (a public page from a key with no role is dropped),
 * staleness and the 1500-byte section cap are proven on the collector with
 * fixtures; the path match runs the real guide over a real board store. */
#include "test/test_core.h"
#include "config/boot_fleet_board.h"
#include "config/boot_internal.h"
#include "config/runtime.h"
#include "controllers/rpc_client.h"
#include "command/native_command.h"
#include "json/json.h"
#include "models/fleet_board_post.h"
#include "rpc/server.h"
#include "util/fleet_role_check.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

bool zcl_code_brief_test_collect_lessons(const struct json_value *entries,
                                          const char *prior_error, int64_t now,
                                          struct json_value *data);

#define CGL_NOW 1795392000 /* 2026-11-23T00:00:00Z */

static bool cgl_collect(const char *entries_json, int64_t now, struct json_value *data)
{
    struct json_value entries;
    json_init(&entries);
    bool ok = json_read(&entries, entries_json, strlen(entries_json));
    json_init(data);
    json_set_object(data);
    ok = ok && zcl_code_brief_test_collect_lessons(&entries, NULL, now, data);
    json_free(&entries);
    return ok;
}

static const char *cgl_slug(const struct json_value *data, size_t i)
{
    return json_get_str(json_get(json_at(json_get(data, "lessons"), i), "slug"));
}

static int cgl_ranking_cases(void)
{
    int failures = 0;
    struct json_value data;
    TEST("code.guide lessons rank exact, then prefix, then stem; at most 3") {
        ASSERT(cgl_collect("["
            "{\"slug\":\"d-stem\",\"summary\":\"S\",\"author_role\":true,\"test_rank\":2,\"updated\":\"2026-11-22T00:00:00Z\"},"
            "{\"slug\":\"c-prefix\",\"summary\":\"P\",\"author_role\":true,\"test_rank\":1,\"updated\":\"2026-11-22T00:00:00Z\"},"
            "{\"slug\":\"b-exact-old\",\"summary\":\"E\",\"author_role\":true,\"test_rank\":0,\"updated\":\"2026-11-01T00:00:00Z\"},"
            "{\"slug\":\"a-exact-new\",\"summary\":\"E\",\"author_role\":true,\"test_rank\":0,\"updated\":\"2026-11-22T00:00:00Z\"}]",
            CGL_NOW, &data));
        ASSERT_EQ(json_size(json_get(&data, "lessons")), 3u);
        ASSERT_STR_EQ(cgl_slug(&data, 0), "a-exact-new");
        ASSERT_STR_EQ(cgl_slug(&data, 1), "b-exact-old");
        ASSERT_STR_EQ(cgl_slug(&data, 2), "c-prefix");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(json_get(&data, "lessons"), 0), "match")), "exact");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(json_get(&data, "lessons"), 2), "match")), "prefix");
        ASSERT(json_get_bool(json_get(&data, "lessons_capped")));
        json_free(&data);
        /* A fleet page whose author holds no role is dropped like a public one. */
        ASSERT(cgl_collect("["
            "{\"slug\":\"norole\",\"summary\":\"N\",\"test_rank\":0,\"updated\":\"2026-11-22T00:00:00Z\"},"
            "{\"slug\":\"role\",\"summary\":\"R\",\"author_role\":true,\"test_rank\":0,\"updated\":\"2026-11-01T00:00:00Z\"}]",
            CGL_NOW, &data));
        ASSERT_EQ(json_size(json_get(&data, "lessons")), 1u);
        ASSERT_STR_EQ(cgl_slug(&data, 0), "role");
        ASSERT_EQ(json_get_int(json_get(&data, "lessons_untrusted_dropped")), 1);
        json_free(&data);
        PASS();
    } _test_next:;
    return failures;
}

static int cgl_trust_stale_cases(void)
{
    int failures = 0;
    struct json_value data;
    TEST("code.guide drops a public page from a key with no role and marks stale lessons") {
        ASSERT(cgl_collect("["
            "{\"slug\":\"public-norole\",\"summary\":\"Untrusted\",\"test_scope\":\"public\"},"
            "{\"slug\":\"public-role\",\"summary\":\"Trusted\",\"test_scope\":\"public\",\"author_role\":true,"
            "\"updated\":\"2026-11-21T00:00:00Z\"},"
            "{\"slug\":\"fleet-old\",\"author_role\":true,\"summary\":\"Old\",\"updated\":\"2026-01-01T00:00:00Z\"},"
            "{\"slug\":\"fleet-undated\",\"author_role\":true,\"summary\":\"Undated\",\"updated\":\"soon\"}]",
            CGL_NOW, &data));
        const struct json_value *l = json_get(&data, "lessons");
        ASSERT_EQ(json_size(l), 3u);
        ASSERT_EQ(json_get_int(json_get(&data, "lessons_untrusted_dropped")), 1);
        for (size_t i = 0; i < json_size(l); i++)
            ASSERT(strcmp(cgl_slug(&data, i), "public-norole") != 0);
        for (size_t i = 0; i < json_size(l); i++) {
            const struct json_value *e = json_at(l, i);
            const char *slug = json_get_str(json_get(e, "slug"));
            if (!strcmp(slug, "public-role")) {
                ASSERT(!json_get_bool(json_get(e, "stale")));
                ASSERT_EQ(json_get_int(json_get(e, "age_days")), 2);
                ASSERT_STR_EQ(json_get_str(json_get(e, "scope")), "public");
            } else if (!strcmp(slug, "fleet-old")) {
                ASSERT(json_get_bool(json_get(e, "stale")));
                ASSERT_STR_EQ(json_get_str(json_get(e, "stale_reason")), "age");
                ASSERT_EQ(json_get_int(json_get(e, "age_days")), 326);
            } else {
                ASSERT(json_get_bool(json_get(e, "stale")));
                ASSERT_STR_EQ(json_get_str(json_get(e, "stale_reason")), "undated");
            }
        }
        json_free(&data);
        PASS();
    } _test_next:;
    return failures;
}

static int cgl_drop_overflow_case(void)
{
    int failures = 0;
    char entries[16384];
    size_t len = 0;
    entries[len++] = '[';
    for (size_t i = 0; i < 66; i++) {
        size_t slug = i == 65 ? 64 : i;
        len += (size_t)snprintf(entries + len, sizeof(entries) - len,
            "%s{\"slug\":\"drop-%02zu\",\"summary\":\"X\",\"test_scope\":\"public\"}",
            i ? "," : "", slug);
    }
    entries[len++] = ']';
    entries[len] = '\0';
    struct json_value data;
    TEST("code.guide marks dropped-page counts incomplete past 64 without double counting") {
        ASSERT(cgl_collect(entries, CGL_NOW, &data));
        ASSERT_EQ(json_get_int(json_get(&data, "lessons_untrusted_dropped")), 64);
        ASSERT(json_get_bool(json_get(&data, "lessons_untrusted_incomplete")));
        json_free(&data);
        PASS();
    } _test_next:;
    return failures;
}

static int cgl_cap_cases(void)
{
    int failures = 0;
    struct json_value data;
    TEST("code.guide lessons section never exceeds 1500 bytes and says it was cut") {
        char rules[401], entries[4096];
        /* A quote escapes to two bytes, so three 200-byte rules overflow. */
        for (size_t i = 0; i < 200; i++)
            memcpy(rules + 2 * i, "\\\"", 2);
        rules[400] = '\0';
        const char *slugs[3] = {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"};
        size_t len = 0;
        entries[len++] = '[';
        for (size_t i = 0; i < 3; i++)
            len += (size_t)snprintf(entries + len, sizeof(entries) - len,
                "%s{\"slug\":\"%s\",\"rules\":[\"%s\"],\"author_role\":true,"
                "\"updated\":\"2026-11-2%zuT00:00:00Z\"}",
                i ? "," : "", slugs[i], rules, 2 - i);
        entries[len++] = ']';
        entries[len] = '\0';
        ASSERT(cgl_collect(entries, CGL_NOW, &data));
        size_t n = json_write(json_get(&data, "lessons"), NULL, 0);
        ASSERT(n <= 1500);
        ASSERT(json_size(json_get(&data, "lessons")) < 3u);
        ASSERT(json_get_bool(json_get(&data, "lessons_truncated")));
        json_free(&data);
        PASS();
    } _test_next:;
    return failures;
}

/* ── the real guide over a real board store ───────────────────────────── */

static struct rpc_table *cgl_table;
static bool cgl_role_ok;
static bool cgl_role_worker; /* a worker-only key: every kind but wiki */

static bool cgl_role(const uint8_t key[32], const char *leaf, const char *kind,
                     char *why, size_t why_cap, void *ctx)
{
    (void)key; (void)leaf; (void)ctx;
    bool allowed = cgl_role_ok && !(cgl_role_worker && kind && !strcmp(kind, "wiki"));
    if (!allowed && why && why_cap)
        (void)snprintf(why, why_cap, "no role in this fixture");
    return allowed;
}

static char *cgl_rpc(const char *method, const char *params)
{
    struct json_value p, result;
    char *out = NULL;
    (void)method;
    json_init(&p);
    json_init(&result);
    if (json_read(&p, params, strlen(params)) && json_at(&p, 0)) {
        struct json_value args;
        json_init(&args);
        json_set_array(&args);
        if (json_push_back(&args, json_at(&p, 0)) &&
            rpc_table_execute(cgl_table, "fleet_board", &args, &result)) {
            size_t n = json_write(&result, NULL, 0);
            out = malloc(n + 1);
            if (out && json_write(&result, out, n + 1) == 0) { free(out); out = NULL; }
        }
        json_free(&args);
    }
    json_free(&p);
    json_free(&result);
    return out;
}

static bool cgl_write(const char *slug, const char *scope, const char *applies,
                      const char *updated, const char *rule)
{
    char entry[1024];
    struct zcl_command_reply reply;
    struct json_value in;
    (void)snprintf(entry, sizeof(entry),
        "{\"schema\":\"zcl.fleet_wiki_entry.v1\",\"topic\":\"%s\","
        "\"summary\":\"%s\","
        "\"lessons\":[{\"rule\":\"%s\",\"why\":\"fixture\",\"evidence\":\"docs/agent/WIKI.md\"}],"
        "\"applies_to\":[\"%s\"],\"updated\":\"%s\"}", slug, rule, rule, applies, updated);
    json_init(&in);
    json_set_object(&in);
    bool ok = json_push_kv_str(&in, "slug", slug) && json_push_kv_str(&in, "title", "Lesson") &&
              json_push_kv_str(&in, "text", entry) && json_push_kv_str(&in, "format", "entry") &&
              json_push_kv_str(&in, "scope", scope);
    struct zcl_command_request request = {.input = &in, .budget_bytes = 8192};
    zcl_command_reply_init(&reply, "zcl.fleet_board_post_id.v1");
    if (ok)
        zcl_native_handle_fleet_wiki_write(&request, &reply);
    ok = ok && reply.status == ZCL_COMMAND_STATUS_PASSED;
    zcl_command_reply_free(&reply);
    json_free(&in);
    return ok;
}

/* The brief for one path in an isolated source root. */
static bool cgl_guide(const char *root, const char *path, struct zcl_command_reply *reply)
{
    struct json_value in;
    json_init(&in);
    json_set_object(&in);
    bool ok = json_push_kv_str(&in, "paths", path) && json_push_kv_int(&in, "budget", 8192);
    struct zcl_command_context ctx = {.source_root = root, .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    struct zcl_command_request request = {.input = &in, .context = &ctx};
    zcl_command_reply_init(reply, "zcl.test.code_guide.v1");
    if (ok)
        zcl_native_handle_code_guide(&request, reply);
    json_free(&in);
    return ok;
}

static bool cgl_has(const struct zcl_command_reply *reply, const char *slug, const char *match)
{
    const struct json_value *l = json_get(&reply->data, "lessons");
    for (size_t i = 0; i < json_size(l); i++) {
        const struct json_value *e = json_at(l, i);
        if (!strcmp(json_get_str(json_get(e, "slug")), slug))
            return !match || !strcmp(json_get_str(json_get(e, "match")), match);
    }
    return false;
}

/* Commit one file into a fresh repository at root. */
static bool cgl_commit_file(const char *root, const char *rel)
{
    char path[640], out[128];
    const char *init[] = {"git", "init", "-q", NULL};
    const char *add[] = {"git", "add", "-A", NULL};
    const char *commit[] = {"git", "-c", "user.email=t@example.com", "-c",
                            "user.name=t", "commit", "-q", "-m", "fixture", NULL};
    static const char *const dirs[] = {"engine", "engine/composition", "engine/composition/src"};
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        (void)snprintf(path, sizeof(path), "%s/%s", root, dirs[i]);
        (void)mkdir(path, 0700);
    }
    (void)snprintf(path, sizeof(path), "%s/%s", root, rel);
    FILE *f = fopen(path, "w");
    if (!f) return false;
    (void)fputs("int x;\n", f);
    (void)fclose(f);
    return zcl_spawn_capture_in_dir_observed(init, root, out, sizeof(out), 5000, NULL) == 0 &&
           zcl_spawn_capture_in_dir_observed(add, root, out, sizeof(out), 5000, NULL) == 0 &&
           zcl_spawn_capture_in_dir_observed(commit, root, out, sizeof(out), 5000, NULL) == 0;
}

static int cgl_guide_cases(void)
{
    int failures = 0;
    char root[512], fresh[32];
    struct zcl_command_reply r;
    time_t t = CGL_NOW - 2 * 86400;
    struct tm tmv;
    TEST("code.guide returns the lessons that apply to the path, by exact and prefix rank") {
        ASSERT(gmtime_r(&t, &tmv) != NULL);
        (void)strftime(fresh, sizeof(fresh), "%Y-%m-%dT%H:%M:%SZ", &tmv);
        ASSERT(test_mkdtemp(root, sizeof root, "guide_lessons"));
        cgl_role_ok = true;
        ASSERT(cgl_write("board-boot-lesson", "fleet", "engine/composition/src/boot_fleet_board.c",
                         fresh, "Gossip waits for the roster."));
        ASSERT(cgl_write("board-rpc-lesson", "fleet", "engine/composition/src/boot_fleet_board_rpc.c",
                         "2020-01-01T00:00:00Z", "The find op verifies at most 256 revisions."));
        ASSERT(cgl_write("wallet-lesson", "fleet", "contexts/wallet",
                         fresh, "Run custody-check."));
        ASSERT(cgl_write("public-board-lesson", "public", "engine/composition/src/boot_fleet_board.c",
                         fresh, "A public note about the board boot."));
        /* The exact path, and a sibling file by directory prefix. */
        ASSERT(cgl_guide(root, "engine/composition/src/boot_fleet_board.c", &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(cgl_has(&r, "board-boot-lesson", "exact"));
        ASSERT(cgl_has(&r, "board-rpc-lesson", "prefix"));
        ASSERT(cgl_has(&r, "public-board-lesson", "exact"));
        ASSERT(!cgl_has(&r, "wallet-lesson", NULL));
        ASSERT(json_get(&r.data, "lessons_unavailable") == NULL);
        zcl_command_reply_free(&r);
        ASSERT(cgl_guide(root, "engine/composition/src/boot_fleet_board_ingest.c", &r));
        ASSERT(cgl_has(&r, "board-boot-lesson", "prefix"));
        ASSERT(cgl_has(&r, "board-rpc-lesson", "prefix"));
        ASSERT(!cgl_has(&r, "wallet-lesson", NULL));
        zcl_command_reply_free(&r);
        /* An exact hit marks its own staleness. */
        ASSERT(cgl_guide(root, "engine/composition/src/boot_fleet_board_rpc.c", &r));
        ASSERT(cgl_has(&r, "board-rpc-lesson", "exact"));
        const struct json_value *l = json_get(&r.data, "lessons");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(l, 0), "slug")), "board-rpc-lesson");
        ASSERT(json_get_bool(json_get(json_at(l, 0), "stale")));
        ASSERT(json_size(l) <= 3u);
        zcl_command_reply_free(&r);
        /* The wallet path sees the wallet lesson and no board lesson. */
        ASSERT(cgl_guide(root, "contexts/wallet/src/wallet.c", &r));
        ASSERT(cgl_has(&r, "wallet-lesson", "prefix"));
        ASSERT(!cgl_has(&r, "board-boot-lesson", NULL));
        zcl_command_reply_free(&r);
        /* The node no longer vouches for any author (a revoked scribe): the
         * fleet and the public page both go, so no revoked key steers an agent. */
        cgl_role_ok = false;
        ASSERT(cgl_guide(root, "engine/composition/src/boot_fleet_board.c", &r));
        ASSERT(!cgl_has(&r, "board-boot-lesson", NULL));
        ASSERT(!cgl_has(&r, "public-board-lesson", NULL));
        ASSERT_EQ(json_get_int(json_get(&r.data, "lessons_untrusted_dropped")), 3);
        zcl_command_reply_free(&r);
        /* A worker-only key may post a note but never a wiki page: a wiki page
         * of its in either scope is dropped. */
        cgl_role_ok = true;
        cgl_role_worker = true;
        ASSERT(cgl_guide(root, "engine/composition/src/boot_fleet_board.c", &r));
        ASSERT(!cgl_has(&r, "public-board-lesson", NULL));
        ASSERT_EQ(json_get_int(json_get(&r.data, "lessons_untrusted_dropped")), 3);
        zcl_command_reply_free(&r);
        cgl_role_worker = false;
        ASSERT(cgl_guide(root, "engine/composition/src/boot_fleet_board.c", &r));
        ASSERT(cgl_has(&r, "public-board-lesson", "exact"));
        zcl_command_reply_free(&r);
        /* A file changed after the lesson was written marks it stale, even
         * when the lesson is only two days old. */
        ASSERT(cgl_commit_file(root, "engine/composition/src/boot_fleet_board.c"));
        ASSERT(cgl_guide(root, "engine/composition/src/boot_fleet_board.c", &r));
        l = json_get(&r.data, "lessons");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(l, 0), "slug")), "board-boot-lesson");
        ASSERT(json_get_bool(json_get(json_at(l, 0), "stale")));
        ASSERT_STR_EQ(json_get_str(json_get(json_at(l, 0), "stale_reason")), "applies_to_changed");
        zcl_command_reply_free(&r);
        /* The same lesson reached by directory prefix is checked against its own
         * applies_to, not reported fresh. */
        ASSERT(cgl_guide(root, "engine/composition/src/boot_fleet_board_ingest.c", &r));
        l = json_get(&r.data, "lessons");
        for (size_t i = 0; i < json_size(l); i++)
            if (!strcmp(json_get_str(json_get(json_at(l, i), "slug")), "board-boot-lesson")) {
                ASSERT_STR_EQ(json_get_str(json_get(json_at(l, i), "match")), "prefix");
                ASSERT_STR_EQ(json_get_str(json_get(json_at(l, i), "stale_reason")), "applies_to_changed");
            }
        ASSERT(cgl_has(&r, "board-boot-lesson", "prefix"));
        zcl_command_reply_free(&r);
        ASSERT_EQ(test_rm_rf_recursive(root), 0);
        PASS();
    } _test_next:;
    return failures;
}

int cgl_run_cases(void)
{
    int failures = cgl_ranking_cases() + cgl_trust_stale_cases() + cgl_drop_overflow_case() + cgl_cap_cases();
    struct node_db db = {0};
    char dir[256] = {0}, warmup[256];
    bool was_warming = rpc_is_in_warmup(warmup, sizeof(warmup));
    struct zcl_fleet_role_checker checker = {.allow = cgl_role, .name = "code_guide_lessons"};
    bool opened = node_db_open(&db, ":memory:");
    struct db_service service = {.node_db = &db, .started = true};
    struct app_runtime_context runtime = {.db_service = &service};
    struct boot_svc_ctx svc = {.node_db = &db, .datadir = dir};
    struct rpc_table table;
    zcl_fleet_role_checker_install(&checker);
    if (opened) {
        test_make_tmpdir(dir, sizeof(dir), "fleetboard", "guidelessons");
        boot_fleet_board_shutdown();
        boot_fleet_board_wire(&svc);
        app_runtime_set_current(&runtime);
        rpc_table_init(&table);
        boot_fleet_board_register_rpc(&table);
        set_rpc_warmup_finished();
        cgl_table = &table;
        node_rpc_client_set_test_hook(cgl_rpc);
        failures += cgl_guide_cases();
    } else {
        TEST("code.guide lessons: the in-memory store opens") { ASSERT(opened); PASS(); }
        _test_next:;
    }
    node_rpc_client_set_test_hook(NULL);
    app_runtime_set_current(NULL);
    if (was_warming) set_rpc_warmup_started(warmup);
    boot_fleet_board_shutdown();
    zcl_fleet_role_checker_install(NULL);
    if (db.open) node_db_close(&db);
    if (dir[0]) test_rm_rf(dir);
    return failures;
}
