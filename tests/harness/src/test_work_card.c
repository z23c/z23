/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Owner-signed public work cards: the zcl.work_card.v1 validator, the seed
 * card file, and `work list` / `work show` over a real board store reached
 * through the fleet_board RPC table. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/work_card.h"
#include "config/boot.h"
#include "config/boot_fleet_board.h"
#include "config/boot_internal.h"
#include "config/runtime.h"
#include "controllers/rpc_client.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/fleet_board_post.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "session/fleet_board_proto.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define WC_BASE "0123456789abcdef0123456789abcdef01234567"

static void wc_card_full(char *out, size_t cap, const char *name,
                         const char *level, const char *acceptance,
                         const char *owned, const char *base)
{
    (void)snprintf(out, cap,
        "{\"schema\":\"zcl.work_card.v1\",\"name\":\"%s\",\"level\":\"%s\","
        "\"outcome\":\"Make the thing true.\",\"base\":\"%s\","
        "\"owned\":%s,\"forbidden\":[\"core/\"],"
        "\"contract\":[\"keep it small\"],\"acceptance\":\"%s\","
        "\"stop_if\":[\"base moved\"],\"credit\":\"volunteer\"}",
        name, level, base, owned, acceptance);
}

static void wc_card(char *out, size_t cap, const char *name, const char *level,
                    const char *acceptance)
{
    wc_card_full(out, cap, name, level, acceptance, "[\"tools/x.c\"]", WC_BASE);
}

static enum work_card_reason wc_judge(const char *text)
{
    struct work_card card;
    return work_card_validate(text, strlen(text), &card);
}

static int test_work_card_validator_1(void)
{
    int failures = 0;
    TEST("work card: a complete card validates and exposes its fields") {
        char text[WORK_CARD_BYTES_MAX + 1];
        struct work_card card;
        wc_card(text, sizeof(text), "fix-thing-2", "haiku", "make t-fast ONLY=x");
        ASSERT_EQ(work_card_validate(text, strlen(text), &card), WORK_CARD_OK);
        ASSERT_STR_EQ(card.name, "fix-thing-2");
        ASSERT_EQ(card.level, WORK_CARD_LEVEL_HAIKU);
        ASSERT_STR_EQ(card.base, WC_BASE);
        ASSERT_STR_EQ(card.acceptance, "make t-fast ONLY=x");
        ASSERT_EQ(card.owned_count, 1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_work_card_validator_2(void)
{
    int failures = 0;
    TEST("work card: schema, size and level refusals carry their reason") {
        char text[WORK_CARD_BYTES_MAX + 8];
        wc_card(text, sizeof(text), "n", "gpt", "make x");
        ASSERT_EQ(wc_judge(text), WORK_CARD_LEVEL);
        wc_card(text, sizeof(text), "n", "opus", "make x");
        ASSERT_EQ(wc_judge(text), WORK_CARD_OK);
        {
            char dup[WORK_CARD_BYTES_MAX + 32];
            (void)snprintf(dup, sizeof(dup), "{\"name\":\"dup\",%s", text + 1);
            ASSERT_EQ(wc_judge(dup), WORK_CARD_SCHEMA);
        }
        ASSERT_EQ(wc_judge("not json"), WORK_CARD_SCHEMA);
        ASSERT_EQ(wc_judge("[]"), WORK_CARD_SCHEMA);
        ASSERT_EQ(wc_judge("{\"schema\":\"zcl.work_card.v2\"}"), WORK_CARD_SCHEMA);
        ASSERT_EQ(wc_judge("{\"schema\":\"zcl.work_card.v1\",\"level\":\"haiku\"}"),
                  WORK_CARD_SCHEMA);
        memset(text, 'x', WORK_CARD_BYTES_MAX + 1);
        text[WORK_CARD_BYTES_MAX + 1] = '\0';
        ASSERT_EQ(wc_judge(text), WORK_CARD_TOO_LARGE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_work_card_validator_3(void)
{
    int failures = 0;
    TEST("work card: base must be 40 lowercase hex characters") {
        static const char *const bad[] = {
            "0123456789abcdef0123456789abcdef0123456",
            "0123456789ABCDEF0123456789abcdef01234567",
            "0123456789abcdef0123456789abcdef012345678", "",
        };
        char text[WORK_CARD_BYTES_MAX + 1];
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            wc_card_full(text, sizeof(text), "n", "haiku", "make x",
                         "[\"a\"]", bad[i]);
            ASSERT_EQ(wc_judge(text), WORK_CARD_BASE);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_work_card_validator_4(void)
{
    int failures = 0;
    TEST("work card: acceptance refuses every shell metacharacter") {
        static const char *const bad[] = {
            "make x;ls", "make x|cat", "make x&", "make $HOME", "make `id`",
            "make <f", "make >f", "make x\\nls", "sh -c make", "bash -c make",
            "env make", "exec make", "make 'x'", "make \\\"x\\\"", "make *",
            "make ~", "make x\\ty", "make  x", " make", "make ", "make a\\\\b",
        };
        char text[WORK_CARD_BYTES_MAX + 1];
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            wc_card(text, sizeof(text), "n", "haiku", bad[i]);
            ASSERT_EQ(wc_judge(text), WORK_CARD_ACCEPTANCE_SHELL);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_work_card_validator_5(void)
{
    int failures = 0;
    TEST("work card: owned must be a non-empty list") {
        char text[WORK_CARD_BYTES_MAX + 1];
        wc_card_full(text, sizeof(text), "n", "haiku", "make x", "[]", WC_BASE);
        ASSERT_EQ(wc_judge(text), WORK_CARD_OWNED_EMPTY);
        wc_card_full(text, sizeof(text), "n", "haiku", "make x", "\"a.c\"", WC_BASE);
        ASSERT_EQ(wc_judge(text), WORK_CARD_SCHEMA);
        wc_card_full(text, sizeof(text), "n", "haiku", "make x", "[\"a.c\"]", WC_BASE);
        ASSERT_EQ(wc_judge(text), WORK_CARD_OK);
        PASS();
    } _test_next:;
    return failures;
}

static int test_work_card_validator_6(void)
{
    int failures = 0;
    TEST("work card: name must be a kebab-case identifier") {
        static const char *const bad[] = {
            "Bad_Name", "-lead", "trail-", "a--b", "", "has space",
            "this-name-is-far-too-long-for-a-card-identifier-xxxxxx",
        };
        char text[WORK_CARD_BYTES_MAX + 1];
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            wc_card(text, sizeof(text), bad[i], "haiku", "make x");
            ASSERT_EQ(wc_judge(text), WORK_CARD_NAME);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_work_card_validator_7(void)
{
    int failures = 0;
    TEST("work card: reason codes are the stable public vocabulary") {
        ASSERT_STR_EQ(work_card_reason_code(WORK_CARD_TOO_LARGE), "CARD_TOO_LARGE");
        ASSERT_STR_EQ(work_card_reason_code(WORK_CARD_SCHEMA), "CARD_SCHEMA");
        ASSERT_STR_EQ(work_card_reason_code(WORK_CARD_LEVEL), "CARD_LEVEL");
        ASSERT_STR_EQ(work_card_reason_code(WORK_CARD_BASE), "CARD_BASE");
        ASSERT_STR_EQ(work_card_reason_code(WORK_CARD_ACCEPTANCE_SHELL),
                      "CARD_ACCEPTANCE_SHELL");
        ASSERT_STR_EQ(work_card_reason_code(WORK_CARD_OWNED_EMPTY),
                      "CARD_OWNED_EMPTY");
        ASSERT_STR_EQ(work_card_reason_code(WORK_CARD_NAME), "CARD_NAME");
        PASS();
    } _test_next:;
    return failures;
}


static int test_work_card_owner_key(void)
{
    int failures = 0;
    TEST("work card: pinned owner key is 64 lowercase hex and resolution is ordered") {
        char out[WORK_KEY_HEX + 1], other[65];
        ASSERT_EQ(strlen(WORK_OWNER_BOARD_KEY), 64);
        for (size_t i = 0; i < 64; i++)
            ASSERT((WORK_OWNER_BOARD_KEY[i] >= '0' && WORK_OWNER_BOARD_KEY[i] <= '9') ||
                   (WORK_OWNER_BOARD_KEY[i] >= 'a' && WORK_OWNER_BOARD_KEY[i] <= 'f'));
        memset(other, 'b', 64);
        other[64] = '\0';
        ASSERT_EQ(work_owner_resolve(NULL, WORK_OWNER_BOARD_KEY, out), WORK_OWNER_OK);
        ASSERT_STR_EQ(out, WORK_OWNER_BOARD_KEY);
        ASSERT_EQ(work_owner_resolve(other, WORK_OWNER_BOARD_KEY, out), WORK_OWNER_OK);
        ASSERT_STR_EQ(out, other);
        ASSERT_EQ(work_owner_resolve("", WORK_OWNER_BOARD_KEY, out), WORK_OWNER_OK);
        ASSERT_EQ(work_owner_resolve("zz", WORK_OWNER_BOARD_KEY, out), WORK_OWNER_BAD);
        ASSERT_EQ(work_owner_resolve(NULL, "", out), WORK_OWNER_REQUIRED);
        ASSERT_EQ(work_owner_resolve(NULL, NULL, out), WORK_OWNER_REQUIRED);
        PASS();
    } _test_next:;
    return failures;
}

static int test_work_card_seed_file(void)
{
    int failures = 0;
    TEST("work card: every line of docs/work/cards.jsonl validates") {
        static char line[WORK_CARD_BYTES_MAX + 64];
        char names[32][WORK_CARD_NAME_MAX + 1];
        size_t count = 0;
        FILE *f = fopen("docs/work/cards.jsonl", "r");
        ASSERT(f != NULL);
        while (fgets(line, sizeof(line), f)) {
            struct work_card card;
            size_t n = strlen(line);
            if (n && line[n - 1] == '\n')
                line[--n] = '\0';
            if (n == 0)
                continue;
            ASSERT_EQ(work_card_validate(line, n, &card), WORK_CARD_OK);
            ASSERT(count < 32);
            for (size_t i = 0; i < count; i++)
                ASSERT(strcmp(names[i], card.name) != 0);
            (void)snprintf(names[count++], sizeof(names[0]), "%s", card.name);
        }
        (void)fclose(f);
        ASSERT(count >= 5);
        PASS();
    } _test_next:;
    return failures;
}

struct wc_fixture {
    struct node_db db;
    struct db_service service;
    struct app_runtime_context runtime;
    struct boot_svc_ctx svc;
    struct rpc_table table;
    char dir[256];
    char warmup_status[256];
    bool was_warming_up;
    char owner[65];
};

static const struct rpc_table *wc_table;

static char *wc_rpc(const char *method, const char *params)
{
    struct json_value input, output;
    char *wire = NULL;
    json_init(&input);
    json_init(&output);
    if (wc_table && json_read(&input, params, strlen(params)) &&
        rpc_table_execute(wc_table, method, &input, &output)) {
        size_t length = json_write(&output, NULL, 0);
        wire = malloc(length + 1);
        if (wire)
            (void)json_write(&output, wire, length + 1);
    }
    json_free(&input);
    json_free(&output);
    return wire;
}

static bool wc_open(struct wc_fixture *f, const char *tag)
{
    memset(f, 0, sizeof(*f));
    test_fmt_tmpdir(f->dir, sizeof(f->dir), "workcard", tag);
    if (!test_ensure_tmproot() ||
        (mkdir(f->dir, 0700) != 0 && errno != EEXIST))
        return false;
    f->service.node_db = &f->db;
    f->service.started = true;
    f->runtime.db_service = &f->service;
    f->svc.node_db = &f->db;
    f->svc.datadir = f->dir;
    if (!node_db_open(&f->db, ":memory:"))
        return false;
    boot_fleet_board_shutdown();
    boot_fleet_board_wire(&f->svc);
    app_runtime_set_current(&f->runtime);
    rpc_table_init(&f->table);
    boot_fleet_board_register_rpc(&f->table);
    f->was_warming_up =
        rpc_is_in_warmup(f->warmup_status, sizeof(f->warmup_status));
    set_rpc_warmup_finished();
    wc_table = &f->table;
    node_rpc_client_set_test_hook(wc_rpc);
    return true;
}

static void wc_close(struct wc_fixture *f)
{
    node_rpc_client_set_test_hook(NULL);
    wc_table = NULL;
    app_runtime_set_current(NULL);
    if (f->was_warming_up)
        set_rpc_warmup_started(f->warmup_status);
    boot_fleet_board_shutdown();
    node_db_close(&f->db);
    test_rm_rf(f->dir);
}

/* A post signed by this node's own board key, through the board RPC. */
static bool wc_node_post(struct wc_fixture *f, const char *kind,
                         const char *text, const char *ref, char id[65])
{
    struct json_value input, params, result;
    json_init(&input);
    json_set_object(&input);
    json_init(&params);
    json_set_array(&params);
    json_init(&result);
    bool ok = json_push_kv_str(&input, "op", "post") &&
              json_push_kv_str(&input, "kind", kind) &&
              json_push_kv_str(&input, "scope", "public") &&
              json_push_kv_str(&input, "room", "work") &&
              json_push_kv_str(&input, "text", text) &&
              (!ref || json_push_kv_str(&input, "ref", ref)) &&
              json_push_back(&params, &input) &&
              rpc_table_execute(&f->table, "fleet_board", &params, &result) &&
              json_get_bool(json_get(&result, "ok"));
    if (ok)
        (void)snprintf(id, 65, "%s", json_get_str(json_get(&result, "id")));
    json_free(&input);
    json_free(&params);
    json_free(&result);
    return ok;
}

/* A post signed by a second key, stored through the production ingest path. */
static bool wc_foreign_post(struct wc_fixture *f, uint8_t kind,
                            const char *text, const char *ref_hex,
                            const char *room, uint8_t key, char id[65])
{
    static struct fleet_board_post post;
    uint8_t seed[32], pk[32], sk[32];
    int64_t now = (int64_t)platform_time_wall_time_t();
    memset(seed, 0, sizeof(seed));
    seed[0] = key;
    ed25519_keypair(pk, sk, seed);
    memset(&post, 0, sizeof(post));
    post.kind = kind;
    post.scope = FLEET_BOARD_SCOPE_PUBLIC;
    post.created_at = (uint64_t)now;
    post.ttl = 3600;
    (void)snprintf(post.room, sizeof(post.room), "%s", room);
    (void)snprintf(post.agent, sizeof(post.agent), "volunteer");
    post.text_len = (uint32_t)strlen(text);
    memcpy(post.text, text, post.text_len + 1);
    if (ref_hex && !fleet_board_id_from_hex(ref_hex, post.ref))
        return false;
    if (fleet_board_post_sign(&post, sk, pk) != FLEET_BOARD_OK)
        return false;
    fleet_board_id_to_hex(post.id, id);
    return db_fleet_board_post_ingest(&f->db, &post, now, NULL) ==
           FLEET_BOARD_OK;
}

static bool wc_run(void (*handler)(const struct zcl_command_request *,
                                   struct zcl_command_reply *),
                   const char *input_json, const char *schema,
                   struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, input_json, strlen(input_json));
    struct zcl_command_request request = { .input = &input };
    zcl_command_reply_init(reply, schema);
    if (ok)
        handler(&request, reply);
    json_free(&input);
    return ok;
}

/* Like wc_run, with the fixture node key as owner unless the input names one. */
static bool wc_run_owned(const struct wc_fixture *f,
                         void (*handler)(const struct zcl_command_request *,
                                         struct zcl_command_reply *),
                         const char *input_json, const char *schema,
                         struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, input_json, strlen(input_json)) &&
              (json_get(&input, "owner") ||
               json_push_kv_str(&input, "owner", f->owner));
    struct zcl_command_request request = { .input = &input };
    zcl_command_reply_init(reply, schema);
    if (ok)
        handler(&request, reply);
    json_free(&input);
    return ok;
}

static const struct json_value *wc_row(const struct json_value *rows,
                                       const char *name)
{
    for (size_t i = 0; i < json_size(rows); i++)
        if (strcmp(json_get_str(json_get(json_at(rows, i), "name")), name) == 0)
            return json_at(rows, i);
    return NULL;
}

struct wc_ids {
    char open[65], claimed[65], done[65], submitted[65], bad[65], foreign[65];
};

static bool wc_seed_board(struct wc_fixture *f, struct wc_ids *ids)
{
    char text[WORK_CARD_BYTES_MAX + 1], claim[65], status_id[65];
    struct json_value in, params, status;
    bool ok;
    wc_card(text, sizeof(text), "card-open", "haiku", "make t-fast ONLY=a");
    ok = wc_node_post(f, "need", text, NULL, ids->open);
    wc_card(text, sizeof(text), "card-claimed", "sonnet", "make t-fast ONLY=b");
    ok = ok && wc_node_post(f, "need", text, NULL, ids->claimed);
    wc_card(text, sizeof(text), "card-done", "haiku", "make t-fast ONLY=c");
    ok = ok && wc_node_post(f, "need", text, NULL, ids->done);
    wc_card(text, sizeof(text), "card-submitted", "haiku", "make t-fast ONLY=e");
    ok = ok && wc_node_post(f, "need", text, NULL, ids->submitted);
    ok = ok && wc_foreign_post(f, FLEET_BOARD_KIND_RESULT, "stranger result",
                               ids->submitted, "work", 7, status_id);
    wc_card(text, sizeof(text), "card-bad", "haiku", "make x;rm -rf y");
    ok = ok && wc_node_post(f, "need", text, NULL, ids->bad);
    ok = ok && wc_node_post(f, "claim", "taking it", ids->claimed, claim);
    ok = ok && wc_node_post(f, "claim", "taking it", ids->done, claim);
    ok = ok && wc_node_post(f, "result", "finished", ids->done, status_id);
    wc_card(text, sizeof(text), "card-foreign", "haiku", "make t-fast ONLY=d");
    ok = ok && wc_foreign_post(f, FLEET_BOARD_KIND_NEED, text, NULL, "work", 7, ids->foreign);
    json_init(&in);
    json_set_object(&in);
    json_init(&params);
    json_set_array(&params);
    json_init(&status);
    ok = ok && json_push_kv_str(&in, "op", "status") &&
         json_push_back(&params, &in) &&
         rpc_table_execute(&f->table, "fleet_board", &params, &status);
    (void)snprintf(f->owner, sizeof(f->owner), "%s",
                   json_get_str(json_get(&status, "host")));
    json_free(&in);
    json_free(&params);
    json_free(&status);
    return ok && strlen(f->owner) == 64;
}

static bool wc_prepare(struct wc_fixture *f, struct wc_ids *ids, const char *tag)
{
    return wc_open(f, tag) && wc_seed_board(f, ids);
}

static int test_work_card_list(void)
{
    int failures = 0;
    struct wc_fixture fixture;
    struct wc_ids ids;
    bool opened = false;
    TEST("work list: owner cards only, state from the ref chain, bad cards rejected") {
        struct zcl_command_reply reply;
        const struct json_value *cards, *row, *rejected;
        opened = true;
        ASSERT(wc_prepare(&fixture, &ids, "list"));
        ASSERT(wc_run_owned(&fixture, zcl_native_handle_work_list, "{}", "zcl.work_list.v1", &reply));
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        cards = json_get(&reply.data, "cards");
        ASSERT_EQ(json_size(cards), 4);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "owner")), fixture.owner);
        row = wc_row(cards, "card-open");
        ASSERT(row != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(row, "state")), "open");
        ASSERT_STR_EQ(json_get_str(json_get(row, "id")), ids.open);
        ASSERT_STR_EQ(json_get_str(json_get(row, "level")), "haiku");
        row = wc_row(cards, "card-claimed");
        ASSERT(row != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(row, "state")), "claimed");
        row = wc_row(cards, "card-done");
        ASSERT(row != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(row, "state")), "done");
        row = wc_row(cards, "card-submitted");
        ASSERT(row != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(row, "state")), "submitted");
        ASSERT(wc_row(cards, "card-foreign") == NULL);
        ASSERT(wc_row(cards, "card-bad") == NULL);
        rejected = json_get(&reply.data, "rejected");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "rejected_count")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(rejected, 0), "reason")),
                      "CARD_ACCEPTANCE_SHELL");
        ASSERT_STR_EQ(json_get_str(json_get(json_at(rejected, 0), "id")), ids.bad);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    if (opened)
        wc_close(&fixture);
    return failures;
}

static int test_work_card_list_filters(void)
{
    int failures = 0;
    struct wc_fixture fixture;
    struct wc_ids ids;
    bool opened = false;
    TEST("work list: level filter, explicit owner and refusals") {
        struct zcl_command_reply reply;
        char input[160];
        opened = true;
        ASSERT(wc_prepare(&fixture, &ids, "filters"));
        ASSERT(wc_run_owned(&fixture, zcl_native_handle_work_list, "{\"level\":\"sonnet\"}",
                      "zcl.work_list.v1", &reply));
        ASSERT_EQ(json_size(json_get(&reply.data, "cards")), 1);
        zcl_command_reply_free(&reply);
        ASSERT(wc_run_owned(&fixture, zcl_native_handle_work_list, "{\"level\":\"gpt\"}",
                      "zcl.work_list.v1", &reply));
        ASSERT_STR_EQ(reply.error.code, "BAD_LEVEL");
        zcl_command_reply_free(&reply);
        ASSERT(wc_run_owned(&fixture, zcl_native_handle_work_list, "{\"owner\":\"zz\"}",
                      "zcl.work_list.v1", &reply));
        ASSERT_STR_EQ(reply.error.code, "BAD_OWNER");
        zcl_command_reply_free(&reply);
        (void)snprintf(input, sizeof(input), "{\"owner\":\"%064d\"}", 1);
        ASSERT(wc_run_owned(&fixture, zcl_native_handle_work_list, input, "zcl.work_list.v1", &reply));
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(json_size(json_get(&reply.data, "cards")), 0);
        zcl_command_reply_free(&reply);
        ASSERT(wc_run(zcl_native_handle_work_list, "{}", "zcl.work_list.v1", &reply));
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "owner")),
                      WORK_OWNER_BOARD_KEY);
        ASSERT_EQ(json_size(json_get(&reply.data, "cards")), 0);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    if (opened)
        wc_close(&fixture);
    return failures;
}

static int test_work_card_show(void)
{
    int failures = 0;
    struct wc_fixture fixture;
    struct wc_ids ids;
    bool opened = false;
    TEST("work show: full card, derived state, and the claim and result rows") {
        struct zcl_command_reply reply;
        const struct json_value *card;
        char input[160];
        opened = true;
        ASSERT(wc_prepare(&fixture, &ids, "show"));
        (void)snprintf(input, sizeof(input), "{\"id\":\"%s\"}", ids.done);
        ASSERT(wc_run_owned(&fixture, zcl_native_handle_work_show, input, "zcl.work_show.v1", &reply));
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        card = json_get(&reply.data, "card");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "state")), "done");
        ASSERT_STR_EQ(json_get_str(json_get(card, "name")), "card-done");
        ASSERT_STR_EQ(json_get_str(json_get(card, "acceptance")),
                      "make t-fast ONLY=c");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "claim_count")), 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "result_count")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(
            json_at(json_get(&reply.data, "results"), 0), "text")), "finished");
        zcl_command_reply_free(&reply);
        (void)snprintf(input, sizeof(input), "{\"id\":\"%s\"}", ids.submitted);
        ASSERT(wc_run_owned(&fixture, zcl_native_handle_work_show, input,
                            "zcl.work_show.v1", &reply));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "state")), "submitted");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "result_count")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(
            json_at(json_get(&reply.data, "results"), 0), "text")),
            "stranger result");
        zcl_command_reply_free(&reply);
        (void)snprintf(input, sizeof(input), "{\"id\":\"%s\"}", ids.open);
        ASSERT(wc_run_owned(&fixture, zcl_native_handle_work_show, input, "zcl.work_show.v1", &reply));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "state")), "open");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "claim_count")), 0);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    if (opened)
        wc_close(&fixture);
    return failures;
}

static int test_work_card_show_refusals(void)
{
    int failures = 0;
    struct wc_fixture fixture;
    struct wc_ids ids;
    bool opened = false;
    TEST("work show: refuses an invalid card, an untrusted author, a missing post and a bad id") {
        struct zcl_command_reply reply;
        char input[160];
        opened = true;
        ASSERT(wc_prepare(&fixture, &ids, "refusals"));
        (void)snprintf(input, sizeof(input), "{\"id\":\"%s\"}", ids.bad);
        ASSERT(wc_run_owned(&fixture, zcl_native_handle_work_show, input, "zcl.work_show.v1", &reply));
        ASSERT_STR_EQ(reply.error.code, "CARD_ACCEPTANCE_SHELL");
        zcl_command_reply_free(&reply);
        (void)snprintf(input, sizeof(input), "{\"id\":\"%s\"}", ids.foreign);
        ASSERT(wc_run_owned(&fixture, zcl_native_handle_work_show, input, "zcl.work_show.v1", &reply));
        ASSERT_STR_EQ(reply.error.code, "NOT_A_WORK_CARD");
        zcl_command_reply_free(&reply);
        (void)snprintf(input, sizeof(input), "{\"id\":\"%064d\"}", 2);
        ASSERT(wc_run_owned(&fixture, zcl_native_handle_work_show, input, "zcl.work_show.v1", &reply));
        ASSERT_STR_EQ(reply.error.code, "NOT_FOUND");
        zcl_command_reply_free(&reply);
        ASSERT(wc_run_owned(&fixture, zcl_native_handle_work_show, "{\"id\":\"xyz\"}",
                      "zcl.work_show.v1", &reply));
        ASSERT_STR_EQ(reply.error.code, "BAD_ID");
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    if (opened)
        wc_close(&fixture);
    return failures;
}

static int test_work_card_crowding(void)
{
    int failures = 0;
    struct wc_fixture fixture;
    struct wc_ids ids;
    bool opened = false;
    TEST("work list: 260 results in another room cannot hide the owner result") {
        struct zcl_command_reply reply;
        const struct json_value *cards, *row;
        char text[64], id[65];
        opened = true;
        ASSERT(wc_prepare(&fixture, &ids, "crowding"));
        for (int i = 0; i < 260; i++) {
            (void)snprintf(text, sizeof(text), "noise %d", i);
            ASSERT(wc_foreign_post(&fixture, FLEET_BOARD_KIND_RESULT, text,
                                   NULL, "other", (uint8_t)(8 + i / 52), id));
        }
        ASSERT(wc_run_owned(&fixture, zcl_native_handle_work_list, "{}",
                            "zcl.work_list.v1", &reply));
        cards = json_get(&reply.data, "cards");
        row = wc_row(cards, "card-done");
        ASSERT(row != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(row, "state")), "done");
        row = wc_row(cards, "card-submitted");
        ASSERT(row != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(row, "state")), "submitted");
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    if (opened)
        wc_close(&fixture);
    return failures;
}

int test_work_card(void)
{
    int failures = 0;
    failures += test_work_card_validator_1();
    failures += test_work_card_validator_2();
    failures += test_work_card_validator_3();
    failures += test_work_card_validator_4();
    failures += test_work_card_validator_5();
    failures += test_work_card_validator_6();
    failures += test_work_card_validator_7();
    failures += test_work_card_owner_key();
    failures += test_work_card_seed_file();
    failures += test_work_card_list();
    failures += test_work_card_list_filters();
    failures += test_work_card_show();
    failures += test_work_card_show_refusals();
    failures += test_work_card_crowding();
    return failures;
}
