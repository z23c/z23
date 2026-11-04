/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * lab.brief against fixture sub-leaf outputs: no node, land queue or
 * plan is read. The leaf runs through the real registry, so the 2048-byte
 * bound is measured on the whole envelope a caller receives.
 */

#include "test/test_core.h"

#include "command/native_devagent_brief.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <string.h>

#define DBX_PATH "lab.brief"
#define DBX_CAP 2048

enum dbx_mode { DBX_HEALTHY, DBX_HUGE, DBX_FAIL, DBX_EMPTY };
static enum dbx_mode g_mode;

static void dbx_push_outcome(struct json_value *arr, const char *state,
                             const char *tip, const char *ts, const char *detail)
{
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    (void)json_push_kv_str(&o, "state", state);
    (void)json_push_kv_str(&o, "tip", tip);
    (void)json_push_kv_str(&o, "ts", ts);
    (void)json_push_kv_str(&o, "detail", detail);
    (void)json_push_back(arr, &o);
    json_free(&o);
}

static void dbx_land(struct json_value *d, const char *detail)
{
    struct json_value q, outs, row;
    json_set_object(d);
    json_init(&q);
    json_set_array(&q);
    json_init(&row);
    json_set_str(&row, "row");
    (void)json_push_back(&q, &row);
    json_free(&row);
    (void)json_push_kv(d, "queued", &q);
    json_free(&q);
    json_init(&outs);
    json_set_array(&outs);
    dbx_push_outcome(&outs, "landed", "aaaaaaaaaaaaaaaaaaaa", "2026-11-04T01:00:00Z", "");
    dbx_push_outcome(&outs, "failed", "bbbbbbbbbbbbbbbbbbbb", "2026-11-04T02:00:00Z", detail);
    (void)json_push_kv(d, "outcomes", &outs);
    json_free(&outs);
}

static void dbx_plan(struct json_value *d, const char *title)
{
    struct json_value items, s;
    json_set_object(d);
    json_init(&items);
    json_set_array(&items);
    for (int i = 0; i < 5; i++) {
        json_init(&s);
        json_set_str(&s, title);
        (void)json_push_back(&items, &s);
        json_free(&s);
    }
    (void)json_push_kv(d, "items", &items);
    json_free(&items);
}

static void dbx_fill_source(enum zcl_devagent_brief_source src,
                            struct json_value *d, const char *big)
{
    json_set_object(d);
    switch (src) {
    case ZCL_BRIEF_NODE:
        (void)json_push_kv_int(d, "hstar", 3308054);
        (void)json_push_kv_int(d, "gap", 0);
        (void)json_push_kv_str(d, "sync", g_mode == DBX_HUGE ? big : "at_tip");
        (void)json_push_kv_int(d, "peers", 32);
        break;
    case ZCL_BRIEF_LAND:
        dbx_land(d, big);
        break;
    case ZCL_BRIEF_PLAN:
        dbx_plan(d, big);
        break;
    case ZCL_BRIEF_AGENTS: {
        struct json_value q;
        json_init(&q);
        json_set_array(&q);
        (void)json_push_kv(d, "queued", &q);
        (void)json_push_kv(d, "running", &q);
        json_free(&q);
        break;
    }
    default:
        (void)json_push_kv_int(d, "now", 1000);
        (void)json_push_kv_int(d, "soonest_expiry", 4600);
        (void)json_push_kv_int(d, "active_count", 1);
        (void)json_push_kv_bool(d, "renew_due", false);
        break;
    }
}

static bool dbx_fetch(const struct zcl_command_request *rq,
                      enum zcl_devagent_brief_source src, struct json_value *d,
                      char *code, size_t ccap, char *why, size_t wcap)
{
    static char big[4001];
    (void)rq;
    if (g_mode == DBX_FAIL) {
        (void)snprintf(code, ccap, "FIXTURE_DOWN");
        (void)snprintf(why, wcap, "fixture source %d is down", (int)src);
        return false;
    }
    if (g_mode == DBX_EMPTY) {
        json_set_object(d);
        return true;
    }
    for (size_t i = 0; i < sizeof(big) - 1; i++)
        big[i] = (i % 7 == 0) ? '"' : (i % 11 == 0 ? '\\' : 'x');
    big[sizeof(big) - 1] = '\0';
    dbx_fill_source(src, d, g_mode == DBX_HUGE ? big : "A fixture title");
    return true;
}

/* Run the real leaf through the registry; returns the envelope length. */
static size_t dbx_run(char *out, size_t cap, struct json_value *env)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(reg, DBX_PATH, NULL);
    struct zcl_command_context ctx = {
        .registry = reg, .operator_lane = "dev",
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER, .dev_build = true};
    struct json_value in;
    enum zcl_command_exit ec = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n;
    if (!spec)
        return 0;
    json_init(&in);
    json_set_object(&in);
    n = zcl_command_registry_execute_json(reg, spec, &ctx, &in, false, DBX_PATH,
                                          "full", 0, 0, NULL, out, cap, &ec);
    json_free(&in);
    json_init(env);
    if (n == 0 || !json_read(env, out, n))
        return 0;
    return n;
}

static const char *dbx_sec(const struct json_value *env, const char *sec,
                           const char *key)
{
    const struct json_value *s = json_get(json_get(env, "data"), sec);
    const struct json_value *v = json_get(s, key);
    return v && v->type == JSON_STR ? json_get_str(v) : "";
}

static const char *dbx_code(const struct json_value *env, const char *sec)
{
    const struct json_value *u =
        json_get(json_get(json_get(env, "data"), sec), "unavailable");
    const struct json_value *c = json_get(u, "code");
    return c && c->type == JSON_STR ? json_get_str(c) : "";
}

int test_devagent_brief(void);
int test_devagent_brief(void)
{
    int failures = 0;
    static char out[16384];
    struct json_value env;

    zcl_devagent_brief_set_fetch(dbx_fetch);

    TEST("brief: registered with a 2048-byte response budget") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), DBX_PATH, NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->budget_bytes == DBX_CAP);
        PASS();
    }

    TEST("brief: every section names the leaf it came from") {
        g_mode = DBX_HEALTHY;
        size_t n = dbx_run(out, sizeof(out), &env);
        ASSERT(n > 0 && n <= DBX_CAP);
        ASSERT(json_get_bool(json_get(&env, "ok")));
        ASSERT_STR_EQ(dbx_sec(&env, "node", "leaf"), "core.status.brief");
        ASSERT_STR_EQ(dbx_sec(&env, "land", "leaf"), "dev.land.status");
        ASSERT_STR_EQ(dbx_sec(&env, "plan", "source"), "docs/work/FORWARD_PLAN.md@HEAD");
        ASSERT_STR_EQ(dbx_sec(&env, "agents", "leaf"), "dev.agent.queue");
        ASSERT_STR_EQ(dbx_sec(&env, "deadlines", "leaf"), "ops.mesh.device.pair.status");
        {
            const struct json_value *d = json_get(&env, "data");
            const struct json_value *now = json_get(json_get(d, "plan"), "now");
            ASSERT(now != NULL && now->num_children == 3);
            ASSERT(json_get(json_get(d, "land"), "last_landed") != NULL);
            ASSERT_STR_EQ(dbx_sec(&env, "land", "unavailable"), "");
            ASSERT(json_get(json_get(d, "land"), "last_failure") != NULL);
        }
        /* The failure is newer than the last landing: next points at it. */
        ASSERT_STR_EQ(dbx_sec(&env, "next", "command"), "z23 dev land status");
        json_free(&env);
        PASS();
    }

    TEST("brief: the worst case stays within 2048 bytes and shows its cuts") {
        g_mode = DBX_HUGE;
        size_t n = dbx_run(out, sizeof(out), &env);
        ASSERT(n > 0 && n <= DBX_CAP);
        ASSERT(json_get_bool(json_get(&env, "ok")));
        {
            const struct json_value *now =
                json_get(json_get(json_get(&env, "data"), "plan"), "now");
            const char *first = now ? json_get_str(json_at(now, 0)) : "";
            size_t len = first ? strlen(first) : 0;
            ASSERT(len >= 4 && strcmp(first + len - 3, "...") == 0);
            ASSERT(strchr(first, '"') == NULL && strchr(first, '\\') == NULL);
        }
        json_free(&env);
        PASS();
    }

    TEST("brief: every failing source is a typed unavailable, not an error") {
        static const char *const sec[] = {"node", "land", "plan", "agents", "deadlines"};
        g_mode = DBX_FAIL;
        size_t n = dbx_run(out, sizeof(out), &env);
        ASSERT(n > 0 && n <= DBX_CAP);
        ASSERT(json_get_bool(json_get(&env, "ok")));
        for (size_t i = 0; i < 5; i++)
            ASSERT_STR_EQ(dbx_code(&env, sec[i]), "FIXTURE_DOWN");
        ASSERT_STR_EQ(dbx_sec(&env, "next", "command"), "z23 core status brief");
        json_free(&env);
        PASS();
    }

    TEST("brief: a source that answers without its fields is FIELDS_MISSING") {
        g_mode = DBX_EMPTY;
        size_t n = dbx_run(out, sizeof(out), &env);
        ASSERT(n > 0 && n <= DBX_CAP);
        ASSERT_STR_EQ(dbx_code(&env, "node"), "FIELDS_MISSING");
        ASSERT_STR_EQ(dbx_code(&env, "land"), "FIELDS_MISSING");
        ASSERT_STR_EQ(dbx_code(&env, "plan"), "FIELDS_MISSING");
        json_free(&env);
        PASS();
    }

_test_next:;
    zcl_devagent_brief_set_fetch(NULL);
    if (failures == 0) printf("test_devagent_brief: all passed\n");
    else printf("test_devagent_brief: %d FAILED\n", failures);
    return failures;
}
