/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The board's per-agent views: `inbox` (replies to an agent's posts and mail
 * addressed to it, after an arrival cursor), `inbox_wait` (the same, held
 * open until a row arrives, bounded in time and in concurrent callers), the
 * per-peer delivery record a push leaves, and the CLI leaves over them. The
 * stores are in-memory node databases driven through the real `fleet_board`
 * RPC table; nothing here posts to a live board. */

#include "test/test_core.h"

#include "config/boot.h"
#include "config/boot_fleet_board.h"
#include "config/boot_fleet_roster.h"
#include "config/boot_internal.h"
#include "config/command_catalog.h"
#include "config/runtime.h"
#include "base/hex.h"
#include "command/native_command.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "models/database.h"
#include "models/fleet_board_delivery.h"
#include "models/fleet_board_inbox.h"
#include "models/fleet_board_post.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "session/fleet_board_proto.h"
#include "test/fleet_board_two_node_fixture.h"
#include "util/fleet_role_check.h"
#include "util/fleet_roster_check.h"
#include "../../../engine/composition/src/boot_fleet_board_frame_internal.h"
#include "../../../engine/composition/src/boot_fleet_board_push_internal.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fbi_fixture {
    struct node_db db;
    struct db_service service;
    struct app_runtime_context runtime;
    struct boot_svc_ctx svc;
    struct rpc_table table;
    char dir[256];
    char warmup[256];
    bool was_warming;
    int64_t now;
};

static bool fbi_rpc(struct fbi_fixture *f, struct json_value *input,
                    struct json_value *out);

/* The signing times of the fixture posts must sit inside their TTL as the
 * node's own clock sees it, and no verdict below depends on elapsed time.
 * Take that anchor from the node itself: the created_at it signs one
 * unrelated note with (no ref, no mail receipt: never an inbox row). */
static bool fbi_anchor(struct fbi_fixture *f)
{
    struct json_value in, out;
    json_init(&in);
    json_set_object(&in);
    bool ok = json_push_kv_str(&in, "op", "post") &&
              json_push_kv_str(&in, "kind", "note") &&
              json_push_kv_str(&in, "text", "fixture anchor") &&
              json_push_kv_str(&in, "agent", "fixture") && fbi_rpc(f, &in, &out);
    const struct json_value *at = json_get(&out, "created_at");
    ok = ok && at && at->type == JSON_INT && json_get_int(at) > 0;
    if (ok)
        f->now = json_get_int(at);
    json_free(&out);
    json_free(&in);
    return ok;
}

static bool fbi_open(struct fbi_fixture *f, const char *tag)
{
    memset(f, 0, sizeof(*f));
    test_make_tmpdir(f->dir, sizeof(f->dir), "fleetboard-inbox", tag);
    f->service.node_db = &f->db;
    f->service.started = true;
    f->runtime.db_service = &f->service;
    f->svc.node_db = &f->db;
    f->svc.datadir = f->dir;
    if (!node_db_open(&f->db, ":memory:"))
        return false;
    zcl_fleet_role_checker_install_permissive_for_testing();
    boot_fleet_board_shutdown();
    boot_fleet_board_wire(&f->svc);
    app_runtime_set_current(&f->runtime);
    rpc_table_init(&f->table);
    boot_fleet_board_register_rpc(&f->table);
    f->was_warming = rpc_is_in_warmup(f->warmup, sizeof(f->warmup));
    set_rpc_warmup_finished();
    return fbi_anchor(f);
}

static void fbi_close(struct fbi_fixture *f)
{
    app_runtime_set_current(NULL);
    if (f->was_warming)
        set_rpc_warmup_started(f->warmup);
    boot_fleet_board_shutdown();
    node_db_close(&f->db);
    zcl_fleet_role_checker_install(NULL);
    (void)test_rm_rf_recursive(f->dir);
}

/* Sign and store one post by identity `who` under `agent`, received at
 * `received_at`. `ref` and `receipt` are optional. */
static bool fbi_post(struct fbi_fixture *f, uint8_t who, uint8_t kind,
                     uint8_t scope, const char *agent, const char *text,
                     const uint8_t *ref, const char *receipt,
                     int64_t created_at, int64_t received_at,
                     struct fleet_board_post *out)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(who, seed, pk);
    fb_test_compose(out, kind, agent, text, (uint64_t)created_at, 3600);
    fb_test_scope(out, scope, scope == FLEET_BOARD_SCOPE_PUBLIC ? "general" : "");
    if (ref)
        memcpy(out->ref, ref, 32);
    if (receipt)
        (void)snprintf(out->receipt, sizeof(out->receipt), "%s", receipt);
    return fleet_board_post_sign(out, seed, pk) == FLEET_BOARD_OK &&
           db_fleet_board_post_ingest(&f->db, out, received_at, NULL) ==
               FLEET_BOARD_OK;
}

static bool fbi_rpc(struct fbi_fixture *f, struct json_value *input,
                    struct json_value *out)
{
    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    json_init(out);
    bool ok = json_push_back(&params, input) &&
              rpc_table_execute(&f->table, "fleet_board", &params, out);
    json_free(&params);
    return ok;
}

/* One inbox (or inbox_wait) call. after < 0 sends none; limit 0 sends none. */
static bool fbi_inbox(struct fbi_fixture *f, const char *op, const char *agent,
                      int64_t after, int64_t limit, const uint8_t *ref,
                      int64_t timeout_ms, struct json_value *out)
{
    struct json_value in;
    json_init(&in);
    json_set_object(&in);
    char hex[65];
    if (ref)
        fleet_board_id_to_hex(ref, hex);
    bool ok = json_push_kv_str(&in, "op", op) &&
              (!agent || json_push_kv_str(&in, "agent", agent)) &&
              (after < 0 || json_push_kv_int(&in, "after", after)) &&
              (limit == 0 || json_push_kv_int(&in, "limit", limit)) &&
              (!ref || json_push_kv_str(&in, "ref", hex)) &&
              (timeout_ms < 0 || json_push_kv_int(&in, "timeout_ms", timeout_ms)) &&
              fbi_rpc(f, &in, out);
    json_free(&in);
    return ok;
}

static const char *fbi_row_id(const struct json_value *out, size_t i)
{
    return json_get_str(json_get(json_at(json_get(out, "rows"), i), "id"));
}

static const char *fbi_row_str(const struct json_value *out, size_t i,
                               const char *key)
{
    return json_get_str(json_get(json_at(json_get(out, "rows"), i), key));
}

static bool fbi_id_is(const char *hex, const struct fleet_board_post *post)
{
    char want[65];
    fleet_board_id_to_hex(post->id, want);
    return hex && strcmp(hex, want) == 0;
}

/* A board with one question by lane-a and every kind of row around it. */
struct fbi_board {
    struct fleet_board_post question, reply, own_reply, unrelated, mail_me,
        mail_other, fleet_reply;
};

static bool fbi_seed(struct fbi_fixture *f, struct fbi_board *b)
{
    int64_t t = f->now - 100;
    return fbi_post(f, 1, FLEET_BOARD_KIND_PROBLEM, FLEET_BOARD_SCOPE_PUBLIC,
                    "lane-a", "the regtest group wedges", NULL, NULL, t, t,
                    &b->question) &&
           fbi_post(f, 2, FLEET_BOARD_KIND_CLAIM, FLEET_BOARD_SCOPE_PUBLIC,
                    "lane-b", "taking it", b->question.id, NULL, t + 1, t + 1,
                    &b->reply) &&
           fbi_post(f, 1, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                    "lane-a", "thanks", b->question.id, NULL, t + 2, t + 2,
                    &b->own_reply) &&
           fbi_post(f, 3, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                    "lane-c", "unrelated chatter", NULL, NULL, t + 3, t + 3,
                    &b->unrelated) &&
           fbi_post(f, 3, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_FLEET,
                    "box-r1", "{\"to\":\"lane-a\",\"from\":\"lead\",\"body\":\"go\"}",
                    NULL, FLEET_BOARD_MAIL_RECEIPT, t + 4, t + 4, &b->mail_me) &&
           fbi_post(f, 3, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_FLEET,
                    "box-r1", "{\"to\":\"lane-z\",\"from\":\"lead\",\"body\":\"no\"}",
                    NULL, FLEET_BOARD_MAIL_RECEIPT, t + 5, t + 5, &b->mail_other) &&
           fbi_post(f, 2, FLEET_BOARD_KIND_RESULT, FLEET_BOARD_SCOPE_FLEET,
                    "lane-b", "fixed in abc123", b->question.id, NULL, t + 6,
                    t + 6 + 600, &b->fleet_reply);
}

static int test_fbi_inbox_rows(void)
{
    int failures = 0;
    TEST("board inbox: replies to my posts and mail to me, oldest first, nothing else") {
        struct fbi_fixture f;
        struct fbi_board b;
        struct json_value out;
        ASSERT(fbi_open(&f, "rows"));
        ASSERT(fbi_seed(&f, &b));
        ASSERT(fbi_inbox(&f, "inbox", "lane-a", 0, 0, NULL, -1, &out));
        ASSERT(json_get_bool(json_get(&out, "ok")));
        ASSERT_EQ(json_get_int(json_get(&out, "returned")), 3);
        ASSERT(fbi_id_is(fbi_row_id(&out, 0), &b.reply));
        ASSERT_STR_EQ(fbi_row_str(&out, 0, "why"), "reply");
        ASSERT(fbi_id_is(fbi_row_id(&out, 1), &b.mail_me));
        ASSERT_STR_EQ(fbi_row_str(&out, 1, "why"), "mail");
        ASSERT(fbi_id_is(fbi_row_id(&out, 2), &b.fleet_reply));
        /* It reached this store 600 s after it was signed: the row says so. */
        ASSERT(json_get_int(json_get(json_at(json_get(&out, "rows"), 2), "late_s")) >= 600);
        ASSERT(json_get(json_at(json_get(&out, "rows"), 0), "late_s") == NULL);
        ASSERT(!json_get_bool(json_get(&out, "has_more")));
        int64_t next = json_get_int(json_get(&out, "next_after"));
        ASSERT(next > 0);
        const char *cmd = json_get_str(json_get(&out, "next"));
        char want[128];
        (void)snprintf(want, sizeof(want),
                       "z23 fleet board wait --agent=lane-a --after=%lld",
                       (long long)next);
        ASSERT_STR_EQ(cmd, want);
        json_free(&out);
        /* From the cursor nothing repeats. */
        ASSERT(fbi_inbox(&f, "inbox", "lane-a", next, 0, NULL, -1, &out));
        ASSERT_EQ(json_get_int(json_get(&out, "returned")), 0);
        ASSERT_EQ(json_get_int(json_get(&out, "next_after")), next);
        json_free(&out);
        /* The mail addressed to lane-z is lane-z's, and lane-b sees the
         * question's thread only through its own posts' replies: none. */
        ASSERT(fbi_inbox(&f, "inbox", "lane-z", 0, 0, NULL, -1, &out));
        ASSERT_EQ(json_get_int(json_get(&out, "returned")), 1);
        ASSERT(fbi_id_is(fbi_row_id(&out, 0), &b.mail_other));
        json_free(&out);
        ASSERT(fbi_inbox(&f, "inbox", "lane-b", 0, 0, NULL, -1, &out));
        ASSERT_EQ(json_get_int(json_get(&out, "returned")), 0);
        json_free(&out);
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fbi_inbox_thread_and_paging(void)
{
    int failures = 0;
    TEST("board inbox: ref reads one thread; limit pages without skipping") {
        struct fbi_fixture f;
        struct fbi_board b;
        struct json_value out;
        ASSERT(fbi_open(&f, "thread"));
        ASSERT(fbi_seed(&f, &b));
        ASSERT(fbi_inbox(&f, "inbox", "lane-c", 0, 0, b.question.id, -1, &out));
        ASSERT_EQ(json_get_int(json_get(&out, "returned")), 3);
        ASSERT_STR_EQ(fbi_row_str(&out, 0, "why"), "thread");
        ASSERT(fbi_id_is(fbi_row_id(&out, 1), &b.own_reply));
        ASSERT(strstr(json_get_str(json_get(&out, "next")), " --ref=") != NULL);
        json_free(&out);
        /* lane-a's own reply never comes back to lane-a, even in its thread. */
        ASSERT(fbi_inbox(&f, "inbox", "lane-a", 0, 0, b.question.id, -1, &out));
        ASSERT_EQ(json_get_int(json_get(&out, "returned")), 2);
        json_free(&out);
        ASSERT(fbi_inbox(&f, "inbox", "lane-a", 0, 2, NULL, -1, &out));
        ASSERT_EQ(json_get_int(json_get(&out, "returned")), 2);
        ASSERT(json_get_bool(json_get(&out, "has_more")));
        int64_t next = json_get_int(json_get(&out, "next_after"));
        json_free(&out);
        ASSERT(fbi_inbox(&f, "inbox", "lane-a", next, 2, NULL, -1, &out));
        ASSERT_EQ(json_get_int(json_get(&out, "returned")), 1);
        ASSERT(fbi_id_is(fbi_row_id(&out, 0), &b.fleet_reply));
        json_free(&out);
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fbi_inbox_refusals(void)
{
    int failures = 0;
    TEST("board inbox: every bad input is refused with the limit and the fix") {
        struct fbi_fixture f;
        struct json_value out;
        ASSERT(fbi_open(&f, "refusals"));
        ASSERT(fbi_inbox(&f, "inbox", NULL, 0, 0, NULL, -1, &out));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "code")), "BAD_AGENT");
        ASSERT(strstr(json_get_str(json_get(&out, "message")), "1..64") != NULL);
        json_free(&out);
        ASSERT(fbi_inbox(&f, "inbox", "has space", 0, 0, NULL, -1, &out));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "code")), "BAD_AGENT");
        json_free(&out);
        ASSERT(fbi_inbox(&f, "inbox", "lane-a", 0, 65, NULL, -1, &out));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "code")), "BAD_INBOX_INPUT");
        ASSERT(strstr(json_get_str(json_get(&out, "message")), "1..64") != NULL);
        json_free(&out);
        ASSERT(fbi_inbox(&f, "inbox", "lane-a", -1, 0, NULL, -1, &out));
        ASSERT(json_get_bool(json_get(&out, "ok")));
        json_free(&out);
        struct json_value in;
        json_init(&in);
        json_set_object(&in);
        ASSERT(json_push_kv_str(&in, "op", "inbox") &&
               json_push_kv_str(&in, "agent", "lane-a") &&
               json_push_kv_str(&in, "ref", "not-a-post-id"));
        ASSERT(fbi_rpc(&f, &in, &out));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "code")), "BAD_REF");
        json_free(&out);
        json_free(&in);
        ASSERT(fbi_inbox(&f, "inbox_wait", "lane-a", 0, 0, NULL, 5001, &out));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "code")), "BAD_TIMEOUT");
        json_free(&out);
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

static bool fbi_count_row(const struct db_fleet_board_post *row, void *ctx)
{
    (void)row;
    (*(int *)ctx)++;
    return true;
}

/* Every inbox row is a row the list view already shows the same caller. */
static bool fbi_listed(struct fbi_fixture *f, const char *id)
{
    struct json_value in, out;
    json_init(&in);
    json_set_object(&in);
    bool ok = json_push_kv_str(&in, "op", "list") &&
              json_push_kv_int(&in, "limit", 256) && fbi_rpc(f, &in, &out);
    bool found = false;
    const struct json_value *posts = json_get(&out, "posts");
    for (size_t i = 0; ok && posts && i < json_size(posts); i++)
        found = found || !strcmp(json_get_str(json_get(json_at(posts, i), "id")), id);
    json_free(&out);
    json_free(&in);
    return found;
}

static int test_fbi_inbox_visibility(void)
{
    int failures = 0;
    TEST("board inbox: shows no row the list view would not, expired rows included") {
        struct fbi_fixture f;
        struct fbi_board b;
        struct fleet_board_post old;
        struct json_value out;
        ASSERT(fbi_open(&f, "visibility"));
        ASSERT(fbi_seed(&f, &b));
        /* A reply whose ttl ran out is gone from list, so from the inbox. */
        ASSERT(fbi_post(&f, 4, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-d", "stale reply", b.question.id, NULL,
                        f.now - 3500, f.now - 3500, &old));
        ASSERT(fbi_inbox(&f, "inbox", "lane-a", 0, 0, NULL, -1, &out));
        size_t n = json_size(json_get(&out, "rows"));
        ASSERT(n >= 3);
        for (size_t i = 0; i < n; i++)
            ASSERT(fbi_listed(&f, fbi_row_id(&out, i)));
        json_free(&out);
        /* Re-read at a time past that ttl through the store directly. */
        struct fleet_board_inbox_query q = {.agent = "lane-a", .after = 0,
                                            .limit = 64};
        int64_t scanned = 0;
        int seen = 0;
        ASSERT(db_fleet_board_inbox_scan(&f.db, f.now + 200, &q, fbi_count_row,
                                         &seen, &scanned, NULL) >= 0);
        /* reply, both mail candidates and the late fleet reply; the expired
         * reply and lane-a's own post are not candidates at all. */
        ASSERT_EQ(seen, 4);
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* ── who is speaking ──────────────────────────────────────────────────── */

/* A role store that vouches for every key but one: identity `*ctx`. */
static bool fbi_role_deny_one(const uint8_t key[32], const char *leaf,
                              const char *kind, char *why, size_t why_cap,
                              void *ctx)
{
    (void)leaf;
    (void)kind;
    uint8_t seed[32], pk[32];
    fb_test_identity(*(const uint8_t *)ctx, seed, pk);
    if (memcmp(key, pk, 32) != 0)
        return true;
    if (why && why_cap)
        (void)snprintf(why, why_cap, "no role");
    return false;
}

static void fbi_roles_deny(const uint8_t *who)
{
    struct zcl_fleet_role_checker c = {.allow = fbi_role_deny_one,
                                       .ctx = (void *)who,
                                       .name = "fbi-deny-one"};
    zcl_fleet_role_checker_install(&c);
}

static const struct json_value *fbi_row_of(const struct json_value *out,
                                           const struct fleet_board_post *post)
{
    const struct json_value *rows = json_get(out, "rows");
    for (size_t i = 0; i < json_size(rows); i++)
        if (fbi_id_is(json_get_str(json_get(json_at(rows, i), "id")), post))
            return json_at(rows, i);
    return NULL;
}

struct fbi_forgery {
    struct fleet_board_post question, forged_mail, forged_reply, stranger,
        mail_me;
};

/* Key 5 holds no role. Public scope needs none, so it can post there, and it
 * signs mail-shaped notes: one addressed to lane-a, one that also refs
 * lane-a's question, and a plain public reply. Key 3 holds the role and
 * sends lane-a real FLEET-scope mail. */
static bool fbi_seed_forgery(struct fbi_fixture *f, struct fbi_forgery *b)
{
    int64_t t = f->now - 50;
    static const char k_mail[] =
        "{\"to\":\"lane-a\",\"from\":\"lead\",\"body\":\"run X\"}";
    return fbi_post(f, 1, FLEET_BOARD_KIND_PROBLEM, FLEET_BOARD_SCOPE_PUBLIC,
                    "lane-a", "the regtest group wedges", NULL, NULL, t, t,
                    &b->question) &&
           fbi_post(f, 5, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                    "lead", k_mail, NULL, FLEET_BOARD_MAIL_RECEIPT, t + 1, t + 1,
                    &b->forged_mail) &&
           fbi_post(f, 5, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                    "lead", k_mail, b->question.id, FLEET_BOARD_MAIL_RECEIPT,
                    t + 2, t + 2, &b->forged_reply) &&
           fbi_post(f, 5, FLEET_BOARD_KIND_RESULT, FLEET_BOARD_SCOPE_PUBLIC,
                    "lane-b", "fixed, run X", b->question.id, NULL, t + 3,
                    t + 3, &b->stranger) &&
           fbi_post(f, 3, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_FLEET,
                    "box-r1", k_mail, NULL, FLEET_BOARD_MAIL_RECEIPT, t + 4,
                    t + 4, &b->mail_me);
}

static int test_fbi_inbox_forged_mail(void)
{
    int failures = 0;
    TEST("board inbox: mail only from a vouched FLEET note; forgeries are replies or nothing") {
        static const uint8_t k_unroled = 5, k_revoked = 3;
        struct fbi_fixture f;
        struct fbi_forgery b;
        struct json_value out;
        ASSERT(fbi_open(&f, "forged"));
        fbi_roles_deny(&k_unroled);
        ASSERT(fbi_seed_forgery(&f, &b));
        ASSERT(fbi_inbox(&f, "inbox", "lane-a", 0, 0, NULL, -1, &out));
        ASSERT(json_get_bool(json_get(&out, "ok")));
        /* The public mail-shaped note from an unroled key is not mail and
         * answers nothing of lane-a's: it is not a row at all. */
        ASSERT(fbi_row_of(&out, &b.forged_mail) == NULL);
        /* The one that refs lane-a's question is the reply it is. */
        const struct json_value *row = fbi_row_of(&out, &b.forged_reply);
        ASSERT(row != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(row, "why")), "reply");
        ASSERT_STR_EQ(json_get_str(json_get(row, "scope")), "public");
        ASSERT(!json_get_bool(json_get(row, "author_role")));
        row = fbi_row_of(&out, &b.stranger);
        ASSERT(row != NULL && !json_get_bool(json_get(row, "author_role")));
        /* Real FLEET mail from a vouched key is mail, and says who. */
        row = fbi_row_of(&out, &b.mail_me);
        ASSERT(row != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(row, "why")), "mail");
        ASSERT_STR_EQ(json_get_str(json_get(row, "scope")), "fleet");
        ASSERT(json_get_bool(json_get(row, "author_role")));
        char host[65];
        fleet_board_id_to_hex(b.mail_me.host_pubkey, host);
        host[FLEET_BOARD_INBOX_HOST_HEX] = '\0';
        ASSERT_STR_EQ(json_get_str(json_get(row, "host")), host);
        ASSERT_EQ(json_get_int(json_get(&out, "returned")), 3);
        ASSERT_EQ(json_get_int(json_get(&out, "unvouched")), 2);
        ASSERT(strstr(json_get_str(json_get(&out, "trust_note")), "untrusted") != NULL);
        json_free(&out);
        /* The role is revoked: the same stored note is no longer mail, and
         * it refs nothing of lane-a's, so it is no row. */
        fbi_roles_deny(&k_revoked);
        ASSERT(fbi_inbox(&f, "inbox", "lane-a", 0, 0, NULL, -1, &out));
        ASSERT(fbi_row_of(&out, &b.mail_me) == NULL);
        json_free(&out);
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* ── an armed roster ──────────────────────────────────────────────────── */

/* A roster provider that stands in for the operator seal: a roster row whose
 * text is "member:<id>" names test identity <id> as a member. The production
 * scan, cache and verdicts run on top of it. */
static bool fbi_roster_root(uint8_t root[32], bool *present, bool *manager,
                            void *ctx)
{
    (void)ctx;
    memset(root, 0x42, 32);
    *present = true;
    *manager = false;
    return true;
}

static bool fbi_roster_verify(const char *line, const uint8_t root[32],
                              enum zcl_fleet_root_state state, bool require,
                              uint8_t signer[32], uint8_t box[32], bool *sealed,
                              const char **why, void *ctx)
{
    (void)root;
    (void)state;
    (void)require;
    (void)ctx;
    uint8_t seed[32];
    *sealed = false;
    if (strncmp(line, "member:", 7) != 0) {
        *why = "fleetboard.roster_signature_invalid";
        return false;
    }
    fb_test_identity((uint8_t)atoi(line + 7), seed, signer);
    memcpy(box, signer, 32);
    *sealed = true;
    return true;
}

static bool fbi_roster_each(void (*visit)(const char *line, void *user),
                            void *user, void *ctx)
{
    (void)visit;
    (void)user;
    (void)ctx;
    return true;
}

static int test_fbi_inbox_roster_gates_mail(void)
{
    int failures = 0;
    TEST("board inbox: with an armed roster, mail from a role holder off the roster is not mail") {
        static const struct zcl_fleet_roster_provider k_provider = {
            .root = fbi_roster_root, .verify = fbi_roster_verify,
            .each_line = fbi_roster_each, .name = "fbi-roster"};
        static const char k_mail[] =
            "{\"to\":\"lane-a\",\"from\":\"lead\",\"body\":\"run X\"}";
        struct fbi_fixture f;
        struct fleet_board_post line, member_mail, stranger_mail;
        struct json_value out;
        ASSERT(fbi_open(&f, "roster"));
        int64_t t = f.now - 50;
        /* Keys 3 and 6 both hold the role (the fixture store is permissive);
         * only key 3 is on the roster. */
        ASSERT(fbi_post(&f, 1, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_FLEET,
                        "fleet-roster", "member:3", NULL, NULL, t, t, &line));
        ASSERT(fbi_post(&f, 3, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_FLEET,
                        "box-r1", k_mail, NULL, FLEET_BOARD_MAIL_RECEIPT,
                        t + 1, t + 1, &member_mail));
        ASSERT(fbi_post(&f, 6, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_FLEET,
                        "box-r1", k_mail, NULL, FLEET_BOARD_MAIL_RECEIPT,
                        t + 2, t + 2, &stranger_mail));
        /* Unarmed: both are vouched by the role alone. */
        boot_fleet_roster_test_reset();
        ASSERT(fbi_inbox(&f, "inbox", "lane-a", 0, 0, NULL, -1, &out));
        ASSERT(fbi_row_of(&out, &member_mail) != NULL);
        ASSERT(fbi_row_of(&out, &stranger_mail) != NULL);
        json_free(&out);
        /* Armed: the off-roster key is no row at all, the member is mail. */
        zcl_fleet_roster_provider_install(&k_provider);
        boot_fleet_roster_test_reset();
        ASSERT(fbi_inbox(&f, "inbox", "lane-a", 0, 0, NULL, -1, &out));
        const struct json_value *row = fbi_row_of(&out, &member_mail);
        ASSERT(row != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(row, "why")), "mail");
        ASSERT(fbi_row_of(&out, &stranger_mail) == NULL);
        json_free(&out);
        zcl_fleet_roster_provider_install(NULL);
        boot_fleet_roster_test_reset();
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* A page of rows that fail verification still counts toward has_more. */
static bool fbi_corrupt(struct fbi_fixture *f, const struct fleet_board_post *post)
{
    char hex[65], sql[160];
    fleet_board_id_to_hex(post->id, hex);
    (void)snprintf(sql, sizeof(sql),
                   "UPDATE fleet_board_posts SET text='tampered' WHERE id=X'%s'",
                   hex);
    return sqlite3_exec(f->db.db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static int test_fbi_inbox_read_counts_unverified(void)
{
    int failures = 0;
    TEST("board inbox: rows that fail verification still count as read") {
        struct fbi_fixture f;
        struct fbi_board b;
        ASSERT(fbi_open(&f, "unverified"));
        ASSERT(fbi_seed(&f, &b));
        ASSERT(fbi_corrupt(&f, &b.reply));
        struct fleet_board_inbox_query q = {.agent = "lane-a", .after = 0,
                                            .limit = 1};
        int64_t scanned = 0;
        unsigned read = 0;
        int seen = 0;
        ASSERT_EQ(db_fleet_board_inbox_scan(&f.db, f.now, &q, fbi_count_row,
                                            &seen, &scanned, &read), 0);
        ASSERT_EQ(seen, 0);
        ASSERT_EQ(read, 1u); /* read == limit: more may follow */
        ASSERT(scanned > 0); /* and the cursor moved past it */
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* ── the bounded wait ─────────────────────────────────────────────────── */

struct fbi_waiter {
    struct fbi_fixture *f;
    const char *agent;
    int64_t timeout_ms;
    int64_t after; /* the cursor the wait starts from */
    struct json_value out;
    bool ok;
};

static void *fbi_waiter_run(void *arg)
{
    struct fbi_waiter *w = arg;
    w->ok = fbi_inbox(w->f, "inbox_wait", w->agent, w->after, 0, NULL,
                      w->timeout_ms, &w->out);
    return NULL;
}

static int test_fbi_wait_returns_on_arrival(void)
{
    int failures = 0;
    TEST("board wait: returns as soon as a row for me lands, and times out bounded") {
        struct fbi_fixture f;
        struct fleet_board_post q, r;
        struct json_value out;
        ASSERT(fbi_open(&f, "wait"));
        ASSERT(fbi_post(&f, 1, FLEET_BOARD_KIND_NEED, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-a", "need a reviewer", NULL, NULL, f.now, f.now, &q));
        ASSERT(fbi_inbox(&f, "inbox_wait", "lane-a", 0, 0, NULL, 300, &out));
        ASSERT(json_get_bool(json_get(&out, "ok")));
        ASSERT(json_get_bool(json_get(&out, "timed_out")));
        ASSERT_EQ(json_get_int(json_get(&out, "returned")), 0);
        json_free(&out);

        /* The waiter returns through the arrival, not its timeout: the
         * reply carries the row and no timed_out. */
        struct fbi_waiter w = {.f = &f, .agent = "lane-a",
                               .timeout_ms = FLEET_BOARD_WAIT_SLICE_MS};
        pthread_t th;
        ASSERT(pthread_create(&th, NULL, fbi_waiter_run, &w) == 0);
        platform_sleep_ms(150);
        uint64_t gen = db_fleet_board_arrival_generation();
        ASSERT(fbi_post(&f, 2, FLEET_BOARD_KIND_OFFER, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-b", "I can review", q.id, NULL, f.now + 1, f.now + 1, &r));
        ASSERT(db_fleet_board_arrival_generation() != gen);
        ASSERT(pthread_join(th, NULL) == 0);
        ASSERT(w.ok);
        ASSERT_EQ(json_get_int(json_get(&w.out, "returned")), 1);
        ASSERT(fbi_id_is(fbi_row_id(&w.out, 0), &r));
        ASSERT(json_get(&w.out, "timed_out") == NULL);
        json_free(&w.out);
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* More candidates than one page reads (mail to another reader), then a reply
 * for lane-a: the wait reads on past the full page and returns the reply,
 * instead of sleeping on an arrival that already happened and timing out. */
static bool fbi_mail_burst(struct fbi_fixture *f, int n)
{
    bool ok = true;
    for (int i = 0; ok && i < n; i++) {
        char text[96];
        struct fleet_board_post m;
        (void)snprintf(text, sizeof(text),
                       "{\"to\":\"lane-z\",\"from\":\"lead\",\"body\":\"%d\"}", i);
        /* Spread over keys: one key may store 60 posts per window. */
        ok = fbi_post(f, (uint8_t)(10 + i % 8), FLEET_BOARD_KIND_NOTE,
                      FLEET_BOARD_SCOPE_FLEET, "box-r1", text, NULL,
                      FLEET_BOARD_MAIL_RECEIPT, f->now, f->now, &m);
    }
    return ok;
}

static int test_fbi_wait_reads_past_full_page(void)
{
    int failures = 0;
    TEST("board wait: a full page of other readers' mail does not hide a row already stored") {
        struct fbi_fixture f;
        struct fleet_board_post q, r;
        struct json_value out;
        ASSERT(fbi_open(&f, "burst"));
        ASSERT(fbi_post(&f, 1, FLEET_BOARD_KIND_NEED, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-a", "need a reviewer", NULL, NULL, f.now, f.now, &q));
        ASSERT(fbi_mail_burst(&f, (int)FLEET_BOARD_INBOX_SCAN_MAX + 44));
        ASSERT(fbi_post(&f, 2, FLEET_BOARD_KIND_OFFER, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-b", "I can review", q.id, NULL, f.now, f.now, &r));
        ASSERT(fbi_inbox(&f, "inbox_wait", "lane-a", 0, 0, NULL, 2000, &out));
        ASSERT(json_get_bool(json_get(&out, "ok")));
        ASSERT(json_get(&out, "timed_out") == NULL);
        ASSERT_EQ(json_get_int(json_get(&out, "returned")), 1);
        ASSERT(fbi_id_is(fbi_row_id(&out, 0), &r));
        json_free(&out);
        /* A zero-length wait that stops on a full page says has_more, never
         * that nothing came. */
        ASSERT(fbi_inbox(&f, "inbox_wait", "lane-a", 0, 0, NULL, 0, &out));
        ASSERT(json_get_bool(json_get(&out, "has_more")));
        ASSERT(json_get(&out, "timed_out") == NULL);
        json_free(&out);
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int fbi_cmp_i64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

/* The measurement the docs quote: store-to-waiter latency over 20 posts on
 * an isolated in-memory node (the node-side half; a cross-host post adds the
 * push), and the bytes "anything for me" costs as list versus inbox. It
 * asserts only that every wait returned through its arrival. */
static int test_fbi_wait_latency_and_bytes(void)
{
    int failures = 0;
    TEST("board wait: 20 post-to-waiter latencies and the list/inbox byte cost, measured") {
        enum { N = 20 };
        struct fbi_fixture f;
        struct fbi_board b;
        struct fleet_board_post r;
        int64_t lat[N];
        ASSERT(fbi_open(&f, "latency"));
        ASSERT(fbi_seed(&f, &b));
        for (int i = 0; i < 40; i++) {
            char text[64];
            (void)snprintf(text, sizeof(text), "unrelated chatter %d", i);
            ASSERT(fbi_post(&f, (uint8_t)(6 + i % 4), FLEET_BOARD_KIND_NOTE,
                            FLEET_BOARD_SCOPE_PUBLIC, "lane-x", text, NULL, NULL,
                            f.now, f.now, &r));
        }
        struct json_value in, out;
        json_init(&in);
        json_set_object(&in);
        ASSERT(json_push_kv_str(&in, "op", "list") && fbi_rpc(&f, &in, &out));
        size_t list_bytes = json_write(&out, NULL, 0);
        json_free(&out);
        json_free(&in);
        ASSERT(fbi_inbox(&f, "inbox", "lane-a", 0, 0, NULL, -1, &out));
        size_t inbox_bytes = json_write(&out, NULL, 0);
        int64_t after = json_get_int(json_get(&out, "next_after"));
        json_free(&out);
        for (int i = 0; i < N; i++) {
            struct fbi_waiter w = {.f = &f, .agent = "lane-a",
                                   .timeout_ms = FLEET_BOARD_WAIT_SLICE_MS,
                                   .after = after};
            pthread_t th;
            ASSERT(pthread_create(&th, NULL, fbi_waiter_run, &w) == 0);
            platform_sleep_ms(30); /* the waiter is asleep on the counter */
            char text[64];
            (void)snprintf(text, sizeof(text), "answer %d", i);
            int64_t t0 = platform_time_monotonic_ms();
            ASSERT(fbi_post(&f, 2, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                            "lane-b", text, b.question.id, NULL, f.now, f.now, &r));
            ASSERT(pthread_join(th, NULL) == 0);
            lat[i] = platform_time_monotonic_ms() - t0;
            ASSERT(w.ok && json_get(&w.out, "timed_out") == NULL);
            ASSERT(json_size(json_get(&w.out, "rows")) >= 1);
            after = json_get_int(json_get(&w.out, "next_after"));
            json_free(&w.out);
        }
        qsort(lat, N, sizeof(lat[0]), fbi_cmp_i64);
        printf("    board wait measured: post-to-waiter p50=%lld ms p95=%lld ms "
               "max=%lld ms over %d posts; anything-for-me: list %zu B, inbox "
               "%zu B\n", (long long)lat[N / 2], (long long)lat[N * 95 / 100],
               (long long)lat[N - 1], N, list_bytes, inbox_bytes);
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}


/* A waiter retries while a probe of the main thread holds its slot for a
 * moment, so the test waits on the event (the slot held), not the clock. A
 * refused wait is an ok reply: the plain inbox page, marked wait_busy. */
static bool fbi_busy(const struct json_value *out)
{
    return json_get_bool(json_get(out, "ok")) &&
           json_get_bool(json_get(out, "wait_busy"));
}

static void *fbi_slot_waiter_run(void *arg)
{
    struct fbi_waiter *w = arg;
    for (;;) { /* unbounded: a true wedge is the group watchdog's to catch */
        w->ok = fbi_inbox(w->f, "inbox_wait", w->agent, 0, 0, NULL, w->timeout_ms,
                          &w->out);
        if (!w->ok || !fbi_busy(&w->out) ||
            json_get_int(json_get(&w->out, "returned")) > 0)
            break;
        json_free(&w->out);
        platform_sleep_ms(2);
    }
    return NULL;
}

/* Probe with a zero-length wait until the node refuses `agent` a slot. */
static bool fbi_until_busy(struct fbi_fixture *f, const char *agent,
                           struct json_value *out)
{
    for (;;) { /* unbounded: a true wedge is the group watchdog's to catch */
        if (!fbi_inbox(f, "inbox_wait", agent, 0, 0, NULL, 0, out))
            return false;
        if (fbi_busy(out))
            return true;
        json_free(out);
        platform_sleep_ms(2);
    }
}

static int test_fbi_wait_slots(void)
{
    int failures = 0;
    TEST("board wait: at most 2 open waits in the node, one per agent; a refused wait answers the inbox page and when to retry") {
        struct fbi_fixture f;
        struct fleet_board_post qa, qb, qc, ra, rb, rc;
        struct json_value out;
        ASSERT(fbi_open(&f, "slots"));
        ASSERT(fbi_post(&f, 1, FLEET_BOARD_KIND_NEED, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-a", "a needs", NULL, NULL, f.now, f.now, &qa));
        ASSERT(fbi_post(&f, 2, FLEET_BOARD_KIND_NEED, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-b", "b needs", NULL, NULL, f.now, f.now, &qb));
        ASSERT(fbi_post(&f, 4, FLEET_BOARD_KIND_NEED, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-c", "c needs", NULL, NULL, f.now, f.now, &qc));
        ASSERT(fbi_post(&f, 5, FLEET_BOARD_KIND_OFFER, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-d", "for c", qc.id, NULL, f.now, f.now, &rc));
        struct fbi_waiter a = {.f = &f, .agent = "lane-a",
                               .timeout_ms = FLEET_BOARD_WAIT_SLICE_MS};
        struct fbi_waiter b = {.f = &f, .agent = "lane-b",
                               .timeout_ms = FLEET_BOARD_WAIT_SLICE_MS};
        pthread_t ta, tb;
        ASSERT(pthread_create(&ta, NULL, fbi_slot_waiter_run, &a) == 0);
        ASSERT(fbi_until_busy(&f, "lane-a", &out));
        ASSERT(strstr(json_get_str(json_get(&out, "wait_note")), "1 per agent") != NULL);
        json_free(&out);
        ASSERT(pthread_create(&tb, NULL, fbi_slot_waiter_run, &b) == 0);
        ASSERT(fbi_until_busy(&f, "lane-c", &out));
        ASSERT(strstr(json_get_str(json_get(&out, "wait_note")), "2 open waits") != NULL);
        ASSERT_EQ(json_get_int(json_get(&out, "retry_after_ms")), FLEET_BOARD_WAIT_RETRY_MS);
        /* The refusal is the inbox page itself: lane-c has its row in the
         * same call, with the cursor to wait from later. */
        ASSERT_EQ(json_get_int(json_get(&out, "returned")), 1);
        ASSERT(fbi_id_is(fbi_row_id(&out, 0), &rc));
        ASSERT(json_get_int(json_get(&out, "next_after")) > 0);
        json_free(&out);
        /* The plain read is never refused while waits hold their slots. */
        ASSERT(fbi_inbox(&f, "inbox", "lane-c", 0, 0, NULL, -1, &out));
        ASSERT(json_get_bool(json_get(&out, "ok")));
        json_free(&out);
        /* Release both waits through arrivals, not timeouts. */
        ASSERT(fbi_post(&f, 3, FLEET_BOARD_KIND_OFFER, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-c", "for a", qa.id, NULL, f.now, f.now, &ra));
        ASSERT(fbi_post(&f, 3, FLEET_BOARD_KIND_OFFER, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-c", "for b", qb.id, NULL, f.now, f.now, &rb));
        ASSERT(pthread_join(ta, NULL) == 0 && pthread_join(tb, NULL) == 0);
        ASSERT(a.ok && fbi_id_is(fbi_row_id(&a.out, 0), &ra));
        ASSERT(b.ok && fbi_id_is(fbi_row_id(&b.out, 0), &rb));
        json_free(&a.out);
        json_free(&b.out);
        /* The slots are free again. */
        ASSERT(fbi_inbox(&f, "inbox_wait", "lane-c", 0, 0, NULL, 0, &out));
        ASSERT(json_get_bool(json_get(&out, "ok")));
        json_free(&out);
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* ── delivery ─────────────────────────────────────────────────────────── */

static int test_fbi_delivery_model(void)
{
    int failures = 0;
    TEST("board delivery: one row per post and peer, replaced by the newest answer, bounded") {
        struct node_db db;
        memset(&db, 0, sizeof(db));
        ASSERT(node_db_open(&db, ":memory:"));
        struct db_fleet_board_delivery d = {.verdict = FLEET_BOARD_DELIVERY_DEFERRED,
                                            .at = 100};
        memset(d.post_id, 7, 32);
        memset(d.peer, 9, 32);
        (void)snprintf(d.reason, sizeof(d.reason), "no_receipt");
        ASSERT(db_fleet_board_delivery_save(&db, &d));
        d.verdict = FLEET_BOARD_DELIVERY_STORED;
        d.reason[0] = '\0';
        d.at = 101;
        ASSERT(db_fleet_board_delivery_save(&db, &d));
        struct db_fleet_board_delivery rows[4];
        ASSERT_EQ(db_fleet_board_delivery_for_post(&db, d.post_id, rows, 4), 1);
        ASSERT_EQ(rows[0].verdict, FLEET_BOARD_DELIVERY_STORED);
        ASSERT_EQ(rows[0].at, 101);
        /* Bad shapes never reach the table. */
        (void)snprintf(d.reason, sizeof(d.reason), "Has Space");
        ASSERT(!db_fleet_board_delivery_save(&db, &d));
        d.reason[0] = '\0';
        d.verdict = FLEET_BOARD_DELIVERY_VERDICTS;
        ASSERT(!db_fleet_board_delivery_save(&db, &d));
        /* Silence or "not now" never takes back a peer's "I have it". */
        d.verdict = FLEET_BOARD_DELIVERY_UNKNOWN;
        (void)snprintf(d.reason, sizeof(d.reason), "no_receipt");
        d.at = 102;
        ASSERT(db_fleet_board_delivery_save(&db, &d));
        d.verdict = FLEET_BOARD_DELIVERY_DEFERRED;
        (void)snprintf(d.reason, sizeof(d.reason), "busy");
        ASSERT(db_fleet_board_delivery_save(&db, &d));
        ASSERT_EQ(db_fleet_board_delivery_for_post(&db, d.post_id, rows, 4), 1);
        ASSERT_EQ(rows[0].verdict, FLEET_BOARD_DELIVERY_STORED);
        ASSERT_EQ(rows[0].at, 101);
        /* A real refusal is a new answer and replaces it. */
        d.verdict = FLEET_BOARD_DELIVERY_REFUSED;
        (void)snprintf(d.reason, sizeof(d.reason), "no_role");
        ASSERT(db_fleet_board_delivery_save(&db, &d));
        ASSERT_EQ(db_fleet_board_delivery_for_post(&db, d.post_id, rows, 4), 1);
        ASSERT_EQ(rows[0].verdict, FLEET_BOARD_DELIVERY_REFUSED);
        d.reason[0] = '\0';
        d.verdict = 0;
        for (int i = 0; i < 40; i++) {
            d.peer[0] = (uint8_t)(i + 10);
            d.at = 200 + i;
            ASSERT(db_fleet_board_delivery_save(&db, &d));
        }
        ASSERT(db_fleet_board_delivery_prune(&db, 16));
        ASSERT_EQ(db_fleet_board_delivery_count(&db), 16);
        ASSERT_EQ(db_fleet_board_delivery_for_post(&db, d.post_id, rows, 4), 4);
        ASSERT_EQ(rows[0].at, 239);
        node_db_close(&db);
        PASS();
    } _test_next:;
    return failures;
}

/* Whether one peer row carries this reason under this verdict. */
static bool fbi_peer_has(const struct json_value *peers, const char *reason,
                         const char *verdict)
{
    for (size_t i = 0; i < json_size(peers); i++) {
        const struct json_value *pr = json_at(peers, i);
        if (!strcmp(json_get_str(json_get(pr, "reason")), reason) &&
            !strcmp(json_get_str(json_get(pr, "verdict")), verdict))
            return true;
    }
    return false;
}

static int test_fbi_delivery_record(void)
{
    int failures = 0;
    TEST("board delivery: each peer's push answer is recorded with its reason and read back") {
        struct fbi_fixture f;
        struct fleet_board_post p;
        struct json_value in, out;
        ASSERT(fbi_open(&f, "delivery"));
        ASSERT(fbi_post(&f, 1, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_FLEET,
                        "lane-a", "for the fleet", NULL, NULL, f.now, f.now, &p));
        uint8_t ids[1][32], peer_a[32], peer_b[32], peer_c[32], peer_d[32];
        memcpy(ids[0], p.id, 32);
        memset(peer_a, 0xa1, 32);
        memset(peer_b, 0xb2, 32);
        memset(peer_c, 0xc3, 32);
        memset(peer_d, 0xd4, 32);
        board_delivery_forget();
        struct board_push_receipt rc;
        memset(&rc, 0, sizeof rc);
        rc.code = FLEET_BOARD_PUSH_CODE_COMMITTED;
        rc.n = 1;
        memcpy(rc.rec[0].id, p.id, 32);
        rc.rec[0].verdict = FLEET_BOARD_PUSH_RECORD_STORED;
        board_delivery_note_receipt(peer_a, ids, 1, &rc, f.now);
        rc.rec[0].verdict = FLEET_BOARD_PUSH_RECORD_REFUSED;
        rc.rec[0].result = FLEET_BOARD_ERR_ROLE;
        board_delivery_note_receipt(peer_b, ids, 1, &rc, f.now);
        rc.code = FLEET_BOARD_PUSH_CODE_INBOX_FULL;
        rc.n = 0;
        board_delivery_note_receipt(peer_c, ids, 1, &rc, f.now);
        board_delivery_note_unanswered(peer_d, ids, 1, "no_receipt", f.now);
        /* A committed receipt naming no record, and a refusal the receiver
         * gave about itself (no result code by design). */
        uint8_t peer_e[32], peer_g[32];
        memset(peer_e, 0xe5, 32);
        memset(peer_g, 0x67, 32);
        rc.code = FLEET_BOARD_PUSH_CODE_COMMITTED;
        rc.n = 0;
        board_delivery_note_receipt(peer_e, ids, 1, &rc, f.now);
        rc.n = 1;
        rc.rec[0].verdict = FLEET_BOARD_PUSH_RECORD_DEFERRED;
        rc.rec[0].result = FLEET_BOARD_OK;
        board_delivery_note_receipt(peer_g, ids, 1, &rc, f.now);
        /* peer_a stored it; a later push to it that got no receipt does not
         * take that back. */
        board_delivery_note_unanswered(peer_a, ids, 1, "no_receipt", f.now + 1);
        ASSERT_EQ(board_delivery_flush(&f.db), 7u);
        ASSERT_EQ(board_delivery_flush(&f.db), 0u);

        char hex[65];
        fleet_board_id_to_hex(p.id, hex);
        json_init(&in);
        json_set_object(&in);
        ASSERT(json_push_kv_str(&in, "op", "delivery") &&
               json_push_kv_str(&in, "id", hex));
        ASSERT(fbi_rpc(&f, &in, &out));
        json_free(&in);
        ASSERT(json_get_bool(json_get(&out, "ok")));
        ASSERT(json_get_bool(json_get(&out, "held_here")));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "scope")), "fleet");
        const struct json_value *counts = json_get(&out, "counts");
        ASSERT_EQ(json_get_int(json_get(counts, "stored")), 1);
        ASSERT_EQ(json_get_int(json_get(counts, "refused")), 1);
        /* push_inbox_full and receiver_state are "not now"; no receipt and
         * a receipt naming no record are unknown, never deferred. */
        ASSERT_EQ(json_get_int(json_get(counts, "deferred")), 2);
        ASSERT_EQ(json_get_int(json_get(counts, "unknown")), 2);
        ASSERT_EQ(json_get_int(json_get(&out, "notes_dropped")), 0);
        const struct json_value *peers = json_get(&out, "peers");
        ASSERT_EQ(json_size(peers), 6u);
        ASSERT(fbi_peer_has(peers, "no_role", "refused"));
        ASSERT(fbi_peer_has(peers, "push_inbox_full", "deferred"));
        ASSERT(fbi_peer_has(peers, "no_receipt", "unknown"));
        ASSERT(fbi_peer_has(peers, "no_record_verdict", "unknown"));
        ASSERT(fbi_peer_has(peers, "receiver_state", "deferred"));
        json_free(&out);

        /* An id nobody pushed: absent, said plainly. */
        json_init(&in);
        json_set_object(&in);
        ASSERT(json_push_kv_str(&in, "op", "delivery") &&
               json_push_kv_str(&in, "id", "zz"));
        ASSERT(fbi_rpc(&f, &in, &out));
        ASSERT_STR_EQ(json_get_str(json_get(&out, "code")), "BAD_ID");
        json_free(&out);
        json_free(&in);
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fbi_delivery_dropped(void)
{
    int failures = 0;
    TEST("board delivery: answers lost before they were recorded are counted and said") {
        struct fbi_fixture f;
        struct fleet_board_post p, p2;
        struct json_value in, out;
        ASSERT(fbi_open(&f, "dropped"));
        ASSERT(fbi_post(&f, 1, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_FLEET,
                        "lane-a", "for the fleet", NULL, NULL, f.now, f.now, &p));
        ASSERT(fbi_post(&f, 1, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_FLEET,
                        "lane-a", "second for the fleet", NULL, NULL, f.now,
                        f.now, &p2));
        uint8_t ids[1][32];
        memcpy(ids[0], p.id, 32);
        board_delivery_forget();
        /* One note more than the ring holds, before any lane tick. */
        for (unsigned i = 0; i <= FLEET_BOARD_DELIVERY_RING; i++) {
            uint8_t px[32];
            memset(px, 0x11, 32);
            px[0] = (uint8_t)(i + 1);
            board_delivery_note_unanswered(px, ids, 1, "no_receipt", f.now);
        }
        ASSERT_EQ(board_delivery_dropped(), 1u);
        (void)board_delivery_flush(&f.db);
        /* p2 has no recorded answer, and the node no longer claims that no
         * peer answered it. */
        char hex[65];
        fleet_board_id_to_hex(p2.id, hex);
        json_init(&in);
        json_set_object(&in);
        ASSERT(json_push_kv_str(&in, "op", "delivery") &&
               json_push_kv_str(&in, "id", hex));
        ASSERT(fbi_rpc(&f, &in, &out));
        json_free(&in);
        ASSERT_EQ(json_get_int(json_get(&out, "notes_dropped")), 1);
        ASSERT(strstr(json_get_str(json_get(&out, "note")), "may have answered") != NULL);
        json_free(&out);
        board_delivery_forget();
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

/* ── the CLI leaves ───────────────────────────────────────────────────── */

static struct rpc_table *g_fbi_table;

static char *fbi_hook(const char *method, const char *params)
{
    struct json_value input, output;
    json_init(&input);
    json_init(&output);
    char *wire = NULL;
    if (g_fbi_table && json_read(&input, params, strlen(params)) &&
        rpc_table_execute(g_fbi_table, method, &input, &output)) {
        size_t n = json_write(&output, NULL, 0);
        wire = malloc(n + 1);
        if (wire)
            (void)json_write(&output, wire, n + 1);
    }
    json_free(&input);
    json_free(&output);
    return wire;
}

static int test_fbi_cli(void)
{
    int failures = 0;
    TEST("board inbox CLI: rows and the next wait step; wait times out with the advanced cursor") {
        struct fbi_fixture f;
        struct fbi_board b;
        struct json_value input;
        struct zcl_command_reply reply;
        ASSERT(fbi_open(&f, "cli"));
        ASSERT(fbi_seed(&f, &b));
        g_fbi_table = &f.table;
        node_rpc_client_set_test_hook(fbi_hook);
        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "agent", "lane-a") &&
               json_push_kv_str(&input, "after", "0"));
        struct zcl_command_request request = {.input = &input};
        zcl_command_reply_init(&reply, "zcl.fleet_board_inbox.v1");
        zcl_native_handle_fleet_board_inbox(&request, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "returned")), 3);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "stopped_by")), "end");
        ASSERT(!json_get_bool(json_get(&reply.data, "truncated_by_budget")));
        ASSERT(!json_get(&reply.data, "notice"));
        ASSERT(reply.next_count >= 1);
        ASSERT_STR_EQ(reply.next[0].command, "fleet.board.wait");
        int64_t next = json_get_int(json_get(&reply.data, "next_after"));
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "agent", "lane-a") &&
               json_push_kv_int(&input, "after", next) &&
               json_push_kv_int(&input, "timeout_ms", 300));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.fleet_board_inbox.v1");
        zcl_native_handle_fleet_board_wait(&request, &reply);
        ASSERT_STR_EQ(reply.error.code, "WAIT_TIMEOUT");
        ASSERT(reply.next_count >= 1);
        ASSERT(strstr(reply.next[0].input_json, "\"after\":") != NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "agent", "lane-a") &&
               json_push_kv_int(&input, "timeout_ms", 60001));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.fleet_board_inbox.v1");
        zcl_native_handle_fleet_board_wait(&request, &reply);
        ASSERT_STR_EQ(reply.error.code, "BAD_TIMEOUT");
        zcl_command_reply_free(&reply);
        json_free(&input);

        node_rpc_client_set_test_hook(NULL);
        g_fbi_table = NULL;
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fbi_cli_budget(void)
{
    int failures = 0;
    TEST("board inbox CLI: default byte pages continue exactly once in arrival order") {
        struct fbi_fixture f;
        struct fleet_board_post parent, posts[20];
        struct json_value input;
        struct zcl_command_reply reply;
        char text[181];
        ASSERT(fbi_open(&f, "cli-budget"));
        ASSERT(fbi_post(&f, 1, FLEET_BOARD_KIND_PROBLEM, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-a", "question", NULL, NULL, f.now, f.now, &parent));
        for (unsigned i = 0; i < 20; i++) {
            memset(text, 'a' + (int)(i % 26), sizeof(text) - 1);
            text[sizeof(text) - 1] = '\0';
            ASSERT(fbi_post(&f, 2, FLEET_BOARD_KIND_NOTE, FLEET_BOARD_SCOPE_PUBLIC,
                            "lane-b", text, parent.id, NULL, f.now + i, f.now + i,
                            &posts[i]));
        }
        g_fbi_table = &f.table;
        node_rpc_client_set_test_hook(fbi_hook);
        int64_t after = 0;
        size_t seen = 0, pages = 0;
        bool more;
        do {
            json_init(&input);
            json_set_object(&input);
            ASSERT(json_push_kv_str(&input, "agent", "lane-a") &&
                   json_push_kv_int(&input, "after", after));
            struct zcl_command_request request = {.input = &input, .budget_bytes = 4096};
            zcl_command_reply_init(&reply, "zcl.fleet_board_inbox.v1");
            zcl_native_handle_fleet_board_inbox(&request, &reply);
            ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_PASSED);
            const struct json_value *rows = json_get(&reply.data, "rows");
            size_t count = json_size(rows);
            ASSERT(count > 0);
            ASSERT(json_write(&reply.data, NULL, 0) < 3072);
            if (pages == 0) {
                ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "stopped_by")), "byte_budget");
                ASSERT(json_get_bool(json_get(&reply.data, "truncated_by_budget")));
                ASSERT_EQ(json_get_int(json_get(&reply.data, "byte_budget")), 4096);
                const struct zcl_command_registry *reg = zcl_command_catalog();
                const struct zcl_command_spec *spec =
                    zcl_command_registry_find(reg, "fleet.board.inbox", NULL);
                struct zcl_command_context ctx = {.registry = reg,
                    .granted_capabilities = ~(uint64_t)0,
                    .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
                char wire[4097];
                enum zcl_command_exit rc;
                ASSERT(spec);
                size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input,
                    false, "fleet.board.inbox", "normal", 4096, 0, NULL,
                    wire, sizeof(wire), &rc);
                ASSERT(n > 0 && n <= 4096);
                ASSERT_EQ(rc, ZCL_COMMAND_EXIT_OK);
            }
            for (size_t i = 0; i < count; i++) {
                const struct json_value *row = json_at(rows, i);
                ASSERT(seen < 20 && fbi_id_is(json_get_str(json_get(row, "id")), &posts[seen]));
                int64_t arrival = json_get_int(json_get(row, "arrival"));
                ASSERT(arrival > after);
                after = arrival;
                seen++;
            }
            ASSERT_EQ(json_get_int(json_get(&reply.data, "next_after")), after);
            ASSERT_EQ(json_get_int(json_get(&reply.data, "returned")), (int64_t)count);
            more = json_get_bool(json_get(&reply.data, "has_more"));
            if (!more) {
                ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "stopped_by")), "end");
                ASSERT(!json_get_bool(json_get(&reply.data, "truncated_by_budget")));
                ASSERT(!json_get(&reply.data, "notice"));
            }
            pages++;
            ASSERT(pages <= 20);
            zcl_command_reply_free(&reply);
            json_free(&input);
        } while (more);
        ASSERT_EQ(seen, 20u);
        ASSERT(pages > 1);
        node_rpc_client_set_test_hook(NULL);
        g_fbi_table = NULL;
        fbi_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

int test_fleet_board_inbox(void)
{
    int failures = 0;
    failures += test_fbi_inbox_rows();
    failures += test_fbi_inbox_thread_and_paging();
    failures += test_fbi_inbox_refusals();
    failures += test_fbi_inbox_visibility();
    failures += test_fbi_inbox_forged_mail();
    failures += test_fbi_inbox_roster_gates_mail();
    failures += test_fbi_inbox_read_counts_unverified();
    failures += test_fbi_wait_returns_on_arrival();
    failures += test_fbi_wait_reads_past_full_page();
    failures += test_fbi_wait_slots();
    failures += test_fbi_wait_latency_and_bytes();
    failures += test_fbi_delivery_model();
    failures += test_fbi_delivery_record();
    failures += test_fbi_delivery_dropped();
    failures += test_fbi_cli();
    failures += test_fbi_cli_budget();
    return failures;
}
