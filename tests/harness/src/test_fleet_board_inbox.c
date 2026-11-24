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
#include "config/boot_internal.h"
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
#include "../../../engine/composition/src/boot_fleet_board_frame_internal.h"
#include "../../../engine/composition/src/boot_fleet_board_push_internal.h"

#include <pthread.h>
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
                                         &seen, &scanned) >= 0);
        /* reply, both mail candidates and the late fleet reply; the expired
         * reply and lane-a's own post are not candidates at all. */
        ASSERT_EQ(seen, 4);
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
    struct json_value out;
    bool ok;
};

static void *fbi_waiter_run(void *arg)
{
    struct fbi_waiter *w = arg;
    w->ok = fbi_inbox(w->f, "inbox_wait", w->agent, 0, 0, NULL, w->timeout_ms,
                      &w->out);
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


/* A waiter retries while a probe of the main thread holds its slot for a
 * moment, so the test waits on the event (the slot held), not the clock. */
static bool fbi_busy(const struct json_value *out)
{
    const char *code = json_get_str(json_get(out, "code"));
    return code && strcmp(code, "WAIT_BUSY") == 0;
}

static void *fbi_slot_waiter_run(void *arg)
{
    struct fbi_waiter *w = arg;
    for (;;) { /* unbounded: a true wedge is the group watchdog's to catch */
        w->ok = fbi_inbox(w->f, "inbox_wait", w->agent, 0, 0, NULL, w->timeout_ms,
                          &w->out);
        if (!w->ok || !fbi_busy(&w->out))
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
    TEST("board wait: at most 2 open waits in the node, one per agent; a refusal says when to retry") {
        struct fbi_fixture f;
        struct fleet_board_post qa, qb, ra, rb;
        struct json_value out;
        ASSERT(fbi_open(&f, "slots"));
        ASSERT(fbi_post(&f, 1, FLEET_BOARD_KIND_NEED, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-a", "a needs", NULL, NULL, f.now, f.now, &qa));
        ASSERT(fbi_post(&f, 2, FLEET_BOARD_KIND_NEED, FLEET_BOARD_SCOPE_PUBLIC,
                        "lane-b", "b needs", NULL, NULL, f.now, f.now, &qb));
        struct fbi_waiter a = {.f = &f, .agent = "lane-a",
                               .timeout_ms = FLEET_BOARD_WAIT_SLICE_MS};
        struct fbi_waiter b = {.f = &f, .agent = "lane-b",
                               .timeout_ms = FLEET_BOARD_WAIT_SLICE_MS};
        pthread_t ta, tb;
        ASSERT(pthread_create(&ta, NULL, fbi_slot_waiter_run, &a) == 0);
        ASSERT(fbi_until_busy(&f, "lane-a", &out));
        ASSERT(strstr(json_get_str(json_get(&out, "message")), "1 per agent") != NULL);
        json_free(&out);
        ASSERT(pthread_create(&tb, NULL, fbi_slot_waiter_run, &b) == 0);
        ASSERT(fbi_until_busy(&f, "lane-c", &out));
        ASSERT(strstr(json_get_str(json_get(&out, "message")), "2 open waits") != NULL);
        ASSERT_EQ(json_get_int(json_get(&out, "retry_after_ms")), FLEET_BOARD_WAIT_RETRY_MS);
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
        d.verdict = 4;
        ASSERT(!db_fleet_board_delivery_save(&db, &d));
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
        ASSERT_EQ(board_delivery_flush(&f.db), 4u);
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
        ASSERT_EQ(json_get_int(json_get(counts, "deferred")), 2);
        const struct json_value *peers = json_get(&out, "peers");
        ASSERT_EQ(json_size(peers), 4u);
        bool saw_role = false, saw_full = false, saw_receipt = false;
        for (size_t i = 0; i < json_size(peers); i++) {
            const char *reason = json_get_str(json_get(json_at(peers, i), "reason"));
            saw_role = saw_role || !strcmp(reason, "no_role");
            saw_full = saw_full || !strcmp(reason, "push_inbox_full");
            saw_receipt = saw_receipt || !strcmp(reason, "no_receipt");
        }
        ASSERT(saw_role && saw_full && saw_receipt);
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

int test_fleet_board_inbox(void)
{
    int failures = 0;
    failures += test_fbi_inbox_rows();
    failures += test_fbi_inbox_thread_and_paging();
    failures += test_fbi_inbox_refusals();
    failures += test_fbi_inbox_visibility();
    failures += test_fbi_wait_returns_on_arrival();
    failures += test_fbi_wait_slots();
    failures += test_fbi_delivery_model();
    failures += test_fbi_delivery_record();
    failures += test_fbi_cli();
    return failures;
}
