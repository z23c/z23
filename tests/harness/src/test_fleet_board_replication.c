/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fleet-board replication between two nodes under faults: the pull, the
 * cursor and the ingest, with the stage of every refusal named.
 *
 * Node A answers, node B pulls and commits, through the real "board" stream
 * service over the loopback wire (test/fleet_board_two_node_fixture.h). No
 * sleeps: the clock is the explicit `now` the authority is bound to, and a
 * pull is driven one call at a time, so nothing here depends on load. B's
 * store and its cursor file live on disk, so a restart is a real close and
 * reopen of both. The socket and the DHT delegation lookup are the only
 * stand-ins. */

#include "test/test_core.h"

#include "config/boot_fleet_board.h"
#include "config/mesh_stream.h"
#include "json/json.h"
#include "models/fleet_board_post.h"
#include "models/mesh_pairing.h"
#include "rpc/server.h"
#include "session/fleet_board_proto.h"
#include "test/fleet_board_two_node_fixture.h"
#include "test/mesh_stream_fixture.h"
#include "test/mesh_stream_loopback.h"
#include "util/fleet_role_check.h"
#include "../../../engine/composition/src/boot_fleet_board_rpc_internal.h"

#include <stdio.h>
#include <sqlite3.h>
#include <string.h>
#include <unistd.h>

#define REP_POSTS 40
#define REP_SOON INT64_C(3000) /* a pairing window that closes before REP_LATE */
#define REP_LATE INT64_C(3500)
#define REP_PAST_DELEGATION INT64_C(5000) /* after the fixture delegation ends */

struct rep {
    struct fbw w;
    char b_path[300];
    char cursor_path[300];
};

static struct rep g_rep;
static struct zcl_fleet_role_checker g_rep_checker = {
    .allow = fbw_role_check, .name = "fleet-board-replication-test" };

/* Open both nodes, B's store on disk beside its cursor file, the terminal
 * peer paired until `pairing_expires`, the clock at `now`. */
static bool rep_open(struct rep *r, int64_t pairing_expires, int64_t now)
{
    g_fbw_deny_read = false;
    g_fbw_deny_post = false;
    zcl_fleet_role_checker_install(&g_rep_checker);
    if (!fbw_open(&r->w))
        return false;
    (void)snprintf(r->b_path, sizeof r->b_path, "%s/b.db", r->w.dir);
    (void)snprintf(r->cursor_path, sizeof r->cursor_path,
                   "%s/fleet-board-cursors", r->w.dir);
    boot_fleet_board_fleet_test_cursor_dir(r->w.dir);
    node_db_close(&r->w.b);
    if (!node_db_open(&r->w.b, r->b_path) ||
        !mesh_term_pair_row(&r->w.f, &r->w.f.term_peer,
                            MESH_PAIRING_CAP_STATUS_READ, FBW_PAIRED_AT,
                            pairing_expires))
        return false;
    boot_fleet_board_fleet_test_bind_authority(&r->w.f.term_peer.delegation,
                                               r->w.f.genesis, now);
    boot_fleet_board_fleet_test_bind(&r->w.a);
    return true;
}

static void rep_close(struct rep *r)
{
    boot_fleet_board_fleet_test_cursor_dir(NULL);
    fbw_close(&r->w);
    g_fbw_deny_read = false;
    g_fbw_deny_post = false;
    zcl_fleet_role_checker_install_permissive_for_testing();
}

static void rep_clock(struct rep *r, int64_t now)
{
    boot_fleet_board_fleet_test_bind_authority(&r->w.f.term_peer.delegation,
                                               r->w.f.genesis, now);
}

static size_t rep_pull(struct rep *r)
{
    size_t frames = 0;
    return fbw_pull(&r->w, r->w.box_a, &r->w.b, &frames);
}

/* Up to `max` pulls; the posts stored in total. `first_after` (may be NULL)
 * receives the arrival the first of them asked from. */
static size_t rep_pull_until_quiet(struct rep *r, int max, int64_t *first_after)
{
    size_t total = 0;
    for (int i = 0; i < max; i++) {
        size_t got = rep_pull(r);
        if (got == SIZE_MAX)
            return SIZE_MAX;
        total += got;
        if (i == 0 && first_after)
            *first_after = boot_fleet_board_fleet_test_last_after();
    }
    return total;
}

static size_t rep_count(struct node_db *db)
{
    struct fleet_board_status st;
    return db_fleet_board_status(db, FBW_NOW, &st) ? (size_t)st.posts
                                                    : SIZE_MAX;
}

/* B as a new process: the store closed and reopened from its file, the
 * in-memory cursors dropped so the next pull reads the cursor file. */
static bool rep_restart_b(struct rep *r)
{
    node_db_close(&r->w.b);
    boot_fleet_board_fleet_test_restart_cursors();
    return node_db_open(&r->w.b, r->b_path);
}

static bool rep_post_n(struct rep *r, uint8_t who, int from, int n,
                       struct fleet_board_post *out)
{
    for (int i = 0; i < n; i++) {
        char text[48];
        (void)snprintf(text, sizeof text, "replicated note %d", from + i);
        if (!fbw_post(&r->w.a, who, FLEET_BOARD_SCOPE_FLEET, text,
                      2000 + from + i, 3600, 2100 + from + i, &out[i]))
            return false;
    }
    return true;
}

static bool rep_seq(struct node_db *db, const struct fleet_board_post *p,
                    int64_t *seq)
{
    struct db_fleet_board_post row;
    if (!db_fleet_board_post_find(db, p->id, &row))
        return false;
    *seq = row.seq;
    return true;
}

static void rep_observe(const uint8_t peer[32], const uint8_t post[32],
                        struct boot_fleet_board_observation *attempt,
                        struct boot_fleet_board_observation *ingest)
{
    boot_fleet_board_observe_query(peer, post, attempt, ingest);
}

/* Query the native status RPC against B, restoring the fixture's authority. */
static bool rep_status_rpc(struct rep *r, const uint8_t post[32], struct json_value *out)
{
    struct rpc_table table; struct json_value in, params;
    struct node_db *saved = r->w.dbsvc.node_db;
    char peer_hex[65], post_hex[65], warmup[256];
    bool was_warming = rpc_is_in_warmup(warmup, sizeof warmup);
    fleet_board_id_to_hex(r->w.box_a, peer_hex); fleet_board_id_to_hex(post, post_hex);
    json_init(&in); json_init(&params); json_set_object(&in); json_set_array(&params);
    rpc_table_init(&table); boot_fleet_board_register_rpc(&table);
    r->w.dbsvc.node_db = &r->w.b; set_rpc_warmup_finished();
    bool ok = json_push_kv_str(&in, "op", "status") &&
        json_push_kv_str(&in, "peer", peer_hex) && json_push_kv_str(&in, "post", post_hex) &&
        json_push_back(&params, &in) && rpc_table_execute(&table, "fleet_board", &params, out) &&
        json_get_bool(json_get(out, "ok"));
    r->w.dbsvc.node_db = saved;
    if (was_warming) set_rpc_warmup_started(warmup);
    json_free(&params); json_free(&in); return ok;
}

static bool rep_stage_is(const struct boot_fleet_board_observation *v,
                         const char *want)
{
    enum boot_fleet_board_stage s;
    return boot_fleet_board_observation_stage(v, &s) &&
           strcmp(boot_fleet_board_stage_name(s), want) == 0;
}

/* ── (a) the happy path ─────────────────────────────────────────────── */
static int test_rep_happy_path(void)
{
    int failures = 0;
    struct fleet_board_post p;
    size_t frames = 0;
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW);
    TEST("fleet board replication: A signs, B stores once, the cursor "
         "advances and a second pull transfers nothing") {
        ASSERT(opened);
        ASSERT(rep_post_n(&g_rep, 7, 0, 1, &p));
        ASSERT_EQ(rep_pull(&g_rep), (size_t)1);
        ASSERT(db_fleet_board_have(&g_rep.w.b, p.id));
        ASSERT_EQ(boot_fleet_board_fleet_test_last_after(), (int64_t)0);
        ASSERT_EQ(rep_count(&g_rep.w.b), (size_t)1);
        /* Nothing new: the answer is its head alone, then the close. */
        ASSERT_EQ(fbw_pull(&g_rep.w, g_rep.w.box_a, &g_rep.w.b, &frames),
                  (size_t)0);
        ASSERT_EQ(frames, (size_t)2);
        ASSERT(boot_fleet_board_fleet_test_last_after() > 0);
        ASSERT_EQ(rep_count(&g_rep.w.b), (size_t)1);
        ASSERT(access(g_rep.cursor_path, F_OK) == 0);
        PASS();
    } _test_next:;
    rep_close(&g_rep);
    return failures;
}

/* ── (b) restart in the middle of a transfer ────────────────────────── */
static int test_rep_restart_midway(void)
{
    int failures = 0;
    static struct fleet_board_post posts[REP_POSTS];
    int64_t first_after = -1;
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW);
    TEST("fleet board replication: a B restart mid-transfer resumes from "
         "the cursor with no loss and no duplicate") {
        ASSERT(opened);
        ASSERT(rep_post_n(&g_rep, 7, 0, REP_POSTS, posts));
        ASSERT_EQ(rep_pull(&g_rep), (size_t)FLEET_BOARD_FLEET_ANSWER_POSTS_MAX);
        ASSERT(rep_restart_b(&g_rep));
        ASSERT_EQ(rep_count(&g_rep.w.b),
                  (size_t)FLEET_BOARD_FLEET_ANSWER_POSTS_MAX);
        /* The restart also re-offers what B holds once; all of it is held,
         * so only the rest is stored. */
        ASSERT_EQ(rep_pull_until_quiet(&g_rep, 4, &first_after),
                  (size_t)(REP_POSTS - FLEET_BOARD_FLEET_ANSWER_POSTS_MAX));
        ASSERT(first_after > 0); /* resumed, did not start over */
        ASSERT(fbw_holds_all(&g_rep.w.b, posts, REP_POSTS));
        ASSERT_EQ(rep_count(&g_rep.w.b), (size_t)REP_POSTS);
        PASS();
    } _test_next:;
    rep_close(&g_rep);
    return failures;
}

/* ── (c) a partition, then healing ──────────────────────────────────── */
static int test_rep_partition(void)
{
    int failures = 0;
    struct fleet_board_post p[3];
    struct boot_fleet_board_observation attempt, ingest;
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW);
    TEST("fleet board replication: pulls fail across a partition and "
         "everything posted meanwhile arrives once, in order, on healing") {
        ASSERT(opened);
        g_rep.w.partitioned = true;
        for (int i = 0; i < 3; i++) {
            ASSERT(rep_post_n(&g_rep, 7, i, 1, &p[i]));
            ASSERT_EQ(rep_pull(&g_rep), SIZE_MAX); /* peer not connected */
        }
        ASSERT_EQ(rep_count(&g_rep.w.b), (size_t)0);
        ASSERT_EQ(boot_fleet_board_fleet_test_last_after(), (int64_t)0);
        rep_observe(g_rep.w.box_a, p[0].id, &attempt, &ingest);
        ASSERT(attempt.found);
        ASSERT_EQ(attempt.phase, FLEET_BOARD_OBS_OPEN_FAILURE);
        ASSERT_EQ(attempt.result, (int)MESH_STREAM_REFUSED_PEER_NOT_CONNECTED);
        ASSERT(rep_stage_is(&attempt, "stream"));
        g_rep.w.partitioned = false; /* healed */
        ASSERT_EQ(rep_pull(&g_rep), (size_t)3);
        ASSERT_EQ(rep_pull(&g_rep), (size_t)0);
        ASSERT_EQ(rep_count(&g_rep.w.b), (size_t)3);
        int64_t s0 = 0, s1 = 0, s2 = 0;
        ASSERT(rep_seq(&g_rep.w.b, &p[0], &s0));
        ASSERT(rep_seq(&g_rep.w.b, &p[1], &s1));
        ASSERT(rep_seq(&g_rep.w.b, &p[2], &s2));
        ASSERT(s0 < s1 && s1 < s2);
        PASS();
    } _test_next:;
    rep_close(&g_rep);
    return failures;
}

/* ── (d) a cursor that is missing, behind, or ahead ─────────────────── */

/* The cursor file's bytes, to put back later. */
static size_t rep_cursor_save(const struct rep *r, uint8_t *buf, size_t cap)
{
    FILE *f = fopen(r->cursor_path, "rb");
    size_t n = f ? fread(buf, 1, cap, f) : 0;
    if (f)
        (void)fclose(f);
    return n;
}

static bool rep_cursor_restore(const struct rep *r, const uint8_t *buf,
                               size_t n)
{
    FILE *f = fopen(r->cursor_path, "wb");
    bool ok = f && fwrite(buf, 1, n, f) == n;
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok;
}

static int test_rep_cursor_missing_or_behind(void)
{
    int failures = 0;
    struct fleet_board_post p[3];
    uint8_t saved[4096];
    int64_t first_after = -1;
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW);
    TEST("fleet board replication: a cursor that is missing or behind makes "
         "B pull again and keep one copy of each post") {
        ASSERT(opened);
        ASSERT(rep_post_n(&g_rep, 7, 0, 2, p));
        ASSERT_EQ(rep_pull(&g_rep), (size_t)2);
        size_t n = rep_cursor_save(&g_rep, saved, sizeof saved);
        ASSERT(n > 0);
        ASSERT(rep_post_n(&g_rep, 7, 2, 1, &p[2]));
        ASSERT_EQ(rep_pull(&g_rep), (size_t)1);
        ASSERT_EQ(rep_count(&g_rep.w.b), (size_t)3);
        /* Behind: the file says where B stood before the third post. */
        ASSERT(rep_cursor_restore(&g_rep, saved, n));
        ASSERT(rep_restart_b(&g_rep));
        ASSERT_EQ(rep_pull_until_quiet(&g_rep, 4, &first_after), (size_t)0);
        ASSERT(first_after > 0);
        ASSERT_EQ(rep_count(&g_rep.w.b), (size_t)3);
        /* Missing: no file at all, B starts from the beginning. */
        ASSERT(unlink(g_rep.cursor_path) == 0);
        ASSERT(rep_restart_b(&g_rep));
        ASSERT_EQ(rep_pull_until_quiet(&g_rep, 4, &first_after), (size_t)0);
        ASSERT_EQ(first_after, (int64_t)0);
        ASSERT_EQ(rep_count(&g_rep.w.b), (size_t)3);
        ASSERT(fbw_holds_all(&g_rep.w.b, p, 3));
        PASS();
    } _test_next:;
    rep_close(&g_rep);
    return failures;
}

static int test_rep_cursor_ahead(void)
{
    int failures = 0;
    struct fleet_board_post old[3], fresh;
    struct boot_fleet_board_observation attempt, ingest;
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW);
    TEST("fleet board replication: a cursor ahead of a reset peer is "
         "dropped, never wedged, and the new log is pulled") {
        ASSERT(opened);
        ASSERT(rep_post_n(&g_rep, 7, 0, 3, old));
        ASSERT_EQ(rep_pull(&g_rep), (size_t)3);
        ASSERT_EQ(rep_pull(&g_rep), (size_t)0);
        ASSERT(boot_fleet_board_fleet_test_last_after() >= 3);
        /* A comes back empty in a new process: fewer rows, a new epoch. */
        node_db_close(&g_rep.w.a);
        ASSERT(node_db_open(&g_rep.w.a, ":memory:"));
        boot_fleet_board_fleet_test_new_epoch();
        ASSERT(rep_post_n(&g_rep, 8, 100, 1, &fresh));
        ASSERT(rep_pull(&g_rep) != SIZE_MAX); /* answered, not wedged */
        rep_observe(g_rep.w.box_a, fresh.id, &attempt, &ingest);
        ASSERT_EQ(attempt.phase, FLEET_BOARD_OBS_CURSOR_RESET);
        ASSERT_EQ(attempt.result, (int)FLEET_BOARD_CURSOR_EPOCH_CHANGED);
        ASSERT_EQ(rep_pull(&g_rep), (size_t)1);
        ASSERT_EQ(boot_fleet_board_fleet_test_last_after(), (int64_t)0);
        ASSERT(db_fleet_board_have(&g_rep.w.b, fresh.id));
        ASSERT_EQ(rep_pull(&g_rep), (size_t)0);
        ASSERT_EQ(rep_count(&g_rep.w.b), (size_t)4); /* kept the old three */
        ASSERT(fbw_holds_all(&g_rep.w.b, old, 3));
        PASS();
    } _test_next:;
    rep_close(&g_rep);
    return failures;
}

/* ── (e) a post that expired ────────────────────────────────────────── */
static int test_rep_expired(void)
{
    int failures = 0;
    struct fleet_board_post gone, late;
    struct boot_fleet_board_observation attempt, ingest;
    struct boot_fleet_board_fleet_counts before, after;
    struct json_value out;
    size_t frames = 0;
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW);
    json_init(&out);
    json_set_object(&out);
    TEST("fleet board replication: an expired post is never delivered and "
         "is counted as expired, not as an error") {
        ASSERT(opened);
        /* Expired before anyone asks: never sent, never an observation. */
        ASSERT(fbw_post(&g_rep.w.a, 7, FLEET_BOARD_SCOPE_FLEET, "gone", 1000,
                        60, 1000, &gone));
        ASSERT_EQ(rep_pull(&g_rep), (size_t)0);
        ASSERT(!db_fleet_board_have(&g_rep.w.b, gone.id));
        rep_observe(g_rep.w.box_a, gone.id, &attempt, &ingest);
        ASSERT(!ingest.found);
        /* Live when A answers (now 2500, expires 2600), expired when B
         * commits it (now 2700): stale, not wrong. */
        ASSERT(fbw_post(&g_rep.w.a, 7, FLEET_BOARD_SCOPE_FLEET, "late", 2400,
                        200, 2450, &late));
        ASSERT(fbw_pull_answer(&g_rep.w, g_rep.w.box_a, &frames));
        rep_clock(&g_rep, 2700);
        boot_fleet_board_fleet_counts(&before);
        ASSERT_EQ(boot_fleet_board_fleet_test_drain_into(&g_rep.w.b), (size_t)0);
        boot_fleet_board_fleet_counts(&after);
        ASSERT(!db_fleet_board_have(&g_rep.w.b, late.id));
        rep_observe(g_rep.w.box_a, late.id, &attempt, &ingest);
        ASSERT(ingest.found);
        ASSERT_EQ(ingest.result, (int)FLEET_BOARD_ERR_EXPIRED);
        ASSERT(!ingest.stored && !ingest.retryable);
        ASSERT(!rep_stage_is(&ingest, "ingest-limit"));
        ASSERT(!rep_stage_is(&ingest, "decode"));
        ASSERT(!rep_stage_is(&ingest, "ingest-role"));
        ASSERT_EQ(after.deferred, before.deferred);
        ASSERT_EQ(after.answer_refused, before.answer_refused);
        ASSERT_EQ(after.role_refused, before.role_refused);
        ASSERT_EQ(after.delegation_refused, before.delegation_refused);
        ASSERT(fb_status_observation(&out, "post_ingest", &ingest));
        const struct json_value *o = json_get(&out, "post_ingest");
        ASSERT_STR_EQ(json_get_str(json_get(o, "disposition")), "expired");
        ASSERT(!json_get(o, "stage"));
        PASS();
    } _test_next:;
    json_free(&out);
    rep_close(&g_rep);
    return failures;
}

/* ── (f) the same post offered twice ────────────────────────────────── */
static int test_rep_duplicate_delivery(void)
{
    int failures = 0;
    struct fleet_board_post p;
    size_t frames = 0;
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW);
    TEST("fleet board replication: a replayed answer stores the post once") {
        ASSERT(opened);
        ASSERT(rep_post_n(&g_rep, 7, 0, 1, &p));
        /* Two answers to the same question reach B before it commits. */
        ASSERT(fbw_pull_answer(&g_rep.w, g_rep.w.box_a, &frames));
        ASSERT(fbw_pull_answer(&g_rep.w, g_rep.w.box_a, &frames));
        ASSERT_EQ(boot_fleet_board_fleet_test_drain_into(&g_rep.w.b), (size_t)1);
        ASSERT_EQ(rep_count(&g_rep.w.b), (size_t)1);
        ASSERT_EQ(rep_pull(&g_rep), (size_t)0);
        ASSERT_EQ(rep_count(&g_rep.w.b), (size_t)1);
        PASS();
    } _test_next:;
    rep_close(&g_rep);
    return failures;
}

/* ── (g) every refusal names its stage and a command ────────────────── */

static int test_rep_stage_text(void)
{
    int failures = 0;
    static const struct {
        enum boot_fleet_board_stage s;
        const char *name, *command;
    } want[] = {
        { BOARD_STAGE_PAIRING, "pairing", "z23 ops mesh pair list" },
        { BOARD_STAGE_DELEGATION, "delegation", "z23 fleet doctor" },
        { BOARD_STAGE_STREAM, "stream", "z23 ops mesh pair list" },
        { BOARD_STAGE_ANSWER_ROLE, "answer-role", "z23 fleet roles list" },
        { BOARD_STAGE_INGEST_ROLE, "ingest-role", "z23 fleet roles list" },
        { BOARD_STAGE_INGEST_LIMIT, "ingest-limit", "z23 fleet board status" },
        { BOARD_STAGE_INGEST_STORAGE, "ingest-storage", "storage logs" },
        { BOARD_STAGE_DECODE, "decode", "z23 version" },
        { BOARD_STAGE_ROSTER, "roster", "z23 fleet doctor" },
    };
    TEST("fleet board replication: every stage line names the stage and "
         "one command") {
        for (size_t i = 0; i < sizeof want / sizeof want[0]; i++) {
            char line[512];
            (void)boot_fleet_board_stage_line(want[i].s, "why", line,
                                              sizeof line);
            ASSERT_STR_EQ(boot_fleet_board_stage_name(want[i].s), want[i].name);
            ASSERT(strstr(line, "stage=") && strstr(line, want[i].name));
            ASSERT(strstr(line, "why") && strstr(line, "next: "));
            ASSERT(strstr(line, want[i].command));
        }
        for (size_t i = 0; i < sizeof want / sizeof want[0]; i++) {
            const char *action = boot_fleet_board_stage_action(want[i].s);
            ASSERT(!strstr(action, "grant") && !strstr(action, "renew") &&
                   !strstr(action, "commit") && !strstr(action, "fleet join"));
        }
        /* Ingest results map to the stage that can clear them. */
        ASSERT_EQ(boot_fleet_board_ingest_stage(FLEET_BOARD_ERR_ROLE),
                  BOARD_STAGE_INGEST_ROLE);
        ASSERT_EQ(boot_fleet_board_ingest_stage(FLEET_BOARD_ERR_QUOTA),
                  BOARD_STAGE_INGEST_LIMIT);
        ASSERT_EQ(boot_fleet_board_ingest_stage(FLEET_BOARD_ERR_STORAGE),
                  BOARD_STAGE_INGEST_STORAGE);
        ASSERT_EQ(boot_fleet_board_ingest_stage(FLEET_BOARD_ERR_SIGNATURE),
                  BOARD_STAGE_DECODE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_rep_clock_and_roster_guidance(void)
{
    int failures = 0;
    struct boot_fleet_board_observation attempt, ingest;
    struct fleet_board_post post;
    struct json_value result;
    char line[512];
    json_init(&result); json_set_object(&result);
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW);
    TEST("fleet board replication: future timestamp and roster-only defer name their real stage") {
        ASSERT(opened);
        int64_t future = FBW_NOW + FLEET_BOARD_FUTURE_SKEW_MAX + 1;
        ASSERT(fbw_post(&g_rep.w.a, 7, FLEET_BOARD_SCOPE_FLEET, "future", future,
                        3600, future, &post));
        ASSERT_EQ(rep_pull(&g_rep), (size_t)0);
        ASSERT(!db_fleet_board_have(&g_rep.w.b, post.id));
        rep_observe(g_rep.w.box_a, post.id, &attempt, &ingest);
        ASSERT(ingest.found && ingest.retryable && !ingest.stored);
        ASSERT_EQ(ingest.result, (int)FLEET_BOARD_ERR_FUTURE);
        ASSERT(fb_status_observation(&result, "post_ingest", &ingest));
        const struct json_value *row = json_get(&result, "post_ingest");
        ASSERT_STR_EQ(json_get_str(json_get(row, "stage")), "clock");
        ASSERT_STR_EQ(json_get_str(json_get(row, "next_action")), "inspect_clock");
        ASSERT(strstr(json_get_str(json_get(row, "operator_action")), "clock"));
        ASSERT(strstr(boot_fleet_board_deferred_line(FLEET_BOARD_ERR_FUTURE, false,
                                                     line, sizeof line), "stage=clock"));
        ASSERT(strstr(line, "clock"));
        ASSERT(strstr(boot_fleet_board_deferred_line(FLEET_BOARD_ERR_ROLE, true,
                                                     line, sizeof line), "stage=roster"));
        ASSERT(strstr(line, "z23 fleet doctor"));
        PASS();
    } _test_next:;
    json_free(&result);
    rep_close(&g_rep);
    return failures;
}

static int test_rep_answer_role_refused(void)
{
    int failures = 0;
    struct boot_fleet_board_observation attempt, ingest;
    struct boot_fleet_board_fleet_counts before, after;
    struct fleet_board_post p;
    size_t frames = 0;
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW);
    TEST("fleet board replication: an asker without the read role is "
         "refused at the answering node and sees a named stream stage") {
        ASSERT(opened);
        ASSERT(rep_post_n(&g_rep, 7, 0, 1, &p));
        g_fbw_deny_read = true;
        boot_fleet_board_fleet_counts(&before);
        ASSERT_EQ(fbw_pull(&g_rep.w, g_rep.w.box_a, &g_rep.w.b, &frames),
                  (size_t)0);
        ASSERT_EQ(frames, (size_t)1);
        boot_fleet_board_fleet_counts(&after);
        ASSERT_EQ(after.role_refused, before.role_refused + 1);
        ASSERT(!db_fleet_board_have(&g_rep.w.b, p.id));
        rep_observe(g_rep.w.box_a, p.id, &attempt, &ingest);
        ASSERT_EQ(attempt.phase, FLEET_BOARD_OBS_CLOSE);
        ASSERT_EQ(attempt.result, (int)MESH_STREAM_REFUSED_PEER_UNPAIRED);
        ASSERT(rep_stage_is(&attempt, "stream"));
        /* Granting the role clears it: the next pull delivers. */
        g_fbw_deny_read = false;
        ASSERT_EQ(rep_pull(&g_rep), (size_t)1);
        PASS();
    } _test_next:;
    rep_close(&g_rep);
    return failures;
}

static int test_rep_ingest_role_refused(void)
{
    int failures = 0;
    struct boot_fleet_board_observation attempt, ingest;
    struct boot_fleet_board_fleet_counts before, after;
    struct fleet_board_post p;
    uint8_t seed[32];
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW);
    TEST("fleet board replication: a post whose signer has no role is "
         "deferred at ingest-role, then arrives once the role is granted") {
        ASSERT(opened);
        ASSERT(rep_post_n(&g_rep, 9, 0, 1, &p));
        fb_test_identity(9, seed, g_fbw_deny_post_key);
        g_fbw_deny_post = true;
        boot_fleet_board_fleet_counts(&before);
        ASSERT_EQ(rep_pull(&g_rep), (size_t)0);
        boot_fleet_board_fleet_counts(&after);
        ASSERT_EQ(after.deferred, before.deferred + 1);
        ASSERT(!db_fleet_board_have(&g_rep.w.b, p.id));
        rep_observe(g_rep.w.box_a, p.id, &attempt, &ingest);
        ASSERT(ingest.found && ingest.retryable && !ingest.stored);
        ASSERT_EQ(ingest.result, (int)FLEET_BOARD_ERR_ROLE);
        ASSERT(rep_stage_is(&ingest, "ingest-role"));
        g_fbw_deny_post = false; /* role granted */
        ASSERT_EQ(rep_pull_until_quiet(&g_rep, 4, NULL), (size_t)1);
        ASSERT_EQ(rep_count(&g_rep.w.b), (size_t)1);
        PASS();
    } _test_next:;
    rep_close(&g_rep);
    return failures;
}

static int test_rep_ingest_limit(void)
{
    int failures = 0;
    struct boot_fleet_board_observation attempt, ingest;
    struct fleet_board_post p, filler;
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW);
    TEST("fleet board replication: a signer past B's per-key ceiling is "
         "deferred at ingest-limit and nothing is stored over it") {
        ASSERT(opened);
        for (int i = 0; i < FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX; i++) {
            char text[48];
            (void)snprintf(text, sizeof text, "already held %d", i);
            ASSERT(fbw_post(&g_rep.w.b, 31, FLEET_BOARD_SCOPE_FLEET, text,
                            2000 + i, 3600, 2100, &filler));
        }
        ASSERT(fbw_post(&g_rep.w.a, 31, FLEET_BOARD_SCOPE_FLEET, "one more",
                        2300, 3600, 2300, &p));
        ASSERT_EQ(rep_pull(&g_rep), (size_t)0);
        ASSERT(!db_fleet_board_have(&g_rep.w.b, p.id));
        ASSERT_EQ(rep_count(&g_rep.w.b),
                  (size_t)FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX);
        rep_observe(g_rep.w.box_a, p.id, &attempt, &ingest);
        ASSERT(ingest.found && ingest.retryable);
        ASSERT_EQ(ingest.result, (int)FLEET_BOARD_ERR_QUOTA);
        ASSERT(rep_stage_is(&ingest, "ingest-limit"));
        PASS();
    } _test_next:;
    rep_close(&g_rep);
    return failures;
}

/* Deny only B's board insertion, leaving reads and the stream intact. */
static int rep_deny_board_insert(void *ctx, int op, const char *table,
                                 const char *arg, const char *db, const char *trigger)
{
    (void)arg; (void)db; (void)trigger;
    if (op == SQLITE_INSERT && table && !strcmp(table, "fleet_board_posts")) {
        *(bool *)ctx = true;
        return SQLITE_DENY;
    }
    return SQLITE_OK;
}

static int test_rep_ingest_storage(void)
{
    int failures = 0;
    bool denied = false, authorized = false;
    struct boot_fleet_board_observation attempt, ingest;
    struct fleet_board_post post;
    struct json_value out; json_init(&out); json_set_object(&out);
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW);
    TEST("fleet board replication: storage refusal names the receiving store") {
        ASSERT(opened && rep_post_n(&g_rep, 7, 0, 1, &post));
        ASSERT_EQ(sqlite3_set_authorizer(g_rep.w.b.db, rep_deny_board_insert, &denied), SQLITE_OK);
        authorized = true;
        ASSERT_EQ(rep_pull(&g_rep), (size_t)0);
        ASSERT_EQ(sqlite3_set_authorizer(g_rep.w.b.db, NULL, NULL), SQLITE_OK);
        authorized = false;
        ASSERT(denied && !db_fleet_board_have(&g_rep.w.b, post.id));
        rep_observe(g_rep.w.box_a, post.id, &attempt, &ingest);
        ASSERT(ingest.found && ingest.retryable && !ingest.stored);
        ASSERT_EQ(ingest.result, (int)FLEET_BOARD_ERR_STORAGE);
        ASSERT(rep_status_rpc(&g_rep, post.id, &out));
        const struct json_value *row = json_get(&out, "post_ingest");
        ASSERT_STR_EQ(json_get_str(json_get(row, "stage")), "ingest-storage");
        ASSERT_STR_EQ(json_get_str(json_get(row, "next_action")), "inspect_board_store");
        ASSERT(strstr(json_get_str(json_get(row, "operator_action")), "storage logs"));
        ASSERT(rep_restart_b(&g_rep));
        ASSERT(!db_fleet_board_have(&g_rep.w.b, post.id));
        PASS();
    } _test_next:;
    if (authorized) (void)sqlite3_set_authorizer(g_rep.w.b.db, NULL, NULL);
    db_fleet_board_test_clear_quarantine();
    json_free(&out); rep_close(&g_rep);
    return failures;
}

/* An answer cut one byte short, delivered on the real stream. */
static bool rep_truncated_pull(struct fbw *w)
{
    uint8_t frame[MESH_LOOP_WIRE_MAX], cut[MESH_LOOP_WIRE_MAX], kind = 0;
    uint64_t sid = 0;
    bool more = false;
    const size_t data_off = MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u + 2u;
    mesh_loop_discard(w->asker, w->ask_q, w->f.res_term);
    mesh_loop_discard(w->answerer, w->answer_q, w->f.term_peer.ini);
    mesh_stream_test_reset();
    if (!boot_fleet_board_fleet_test_pull(w->f.resp_noise_pub, w->box_a))
        return false;
    size_t len = mesh_loop_take(w->asker, w->ask_q, w->f.res_term, frame,
                                sizeof frame, &more);
    if (!more || !mesh_stream_test_read_header(frame, len, &kind, &sid) ||
        kind != MESH_STREAM_KIND_OPEN ||
        !mesh_stream_frame(&w->mp, w->answerer, frame, len, NULL))
        return false;
    boot_fleet_board_fleet_test_serve();
    boot_fleet_board_fleet_test_serve();
    len = mesh_loop_take(w->answerer, w->answer_q, w->f.term_peer.ini, frame,
                         sizeof frame, &more);
    if (!more || !mesh_stream_test_read_header(frame, len, &kind, NULL) ||
        kind != MESH_STREAM_KIND_DATA || len <= data_off + 1u)
        return false;
    size_t cut_len = mesh_stream_test_data_frame(
        sid, frame + data_off, len - data_off - 1u, cut, sizeof cut);
    return cut_len && mesh_stream_frame(&w->mp, w->asker, cut, cut_len, NULL) &&
           mesh_loop_pump(w->answerer, w->answer_q, w->f.term_peer.ini, &w->mp,
                          w->asker) == 1;
}

static int test_rep_decode_refused(void)
{
    int failures = 0;
    struct boot_fleet_board_observation attempt, ingest;
    struct boot_fleet_board_fleet_counts before, after;
    struct fleet_board_post p;
    struct json_value out;
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW);
    json_init(&out);
    json_set_object(&out);
    TEST("fleet board replication: a malformed answer is refused at decode "
         "with a stage and a command, and the cursor does not move") {
        ASSERT(opened);
        ASSERT(rep_post_n(&g_rep, 7, 0, 1, &p));
        boot_fleet_board_fleet_counts(&before);
        ASSERT(rep_truncated_pull(&g_rep.w));
        ASSERT_EQ(boot_fleet_board_fleet_test_drain_into(&g_rep.w.b), (size_t)0);
        boot_fleet_board_fleet_counts(&after);
        ASSERT_EQ(after.answer_refused, before.answer_refused + 1);
        ASSERT(!db_fleet_board_have(&g_rep.w.b, p.id));
        rep_observe(g_rep.w.box_a, p.id, &attempt, &ingest);
        ASSERT_EQ(attempt.phase, FLEET_BOARD_OBS_ANSWER_REFUSED);
        ASSERT(rep_stage_is(&attempt, "decode"));
        ASSERT(fb_status_observation(&out, "peer_attempt", &attempt));
        const struct json_value *o = json_get(&out, "peer_attempt");
        ASSERT_STR_EQ(json_get_str(json_get(o, "stage")), "decode");
        ASSERT(strstr(json_get_str(json_get(o, "operator_action")),
                      "z23 version"));
        /* An intact answer then delivers from where the cursor still is. */
        ASSERT_EQ(rep_pull(&g_rep), (size_t)1);
        PASS();
    } _test_next:;
    json_free(&out);
    rep_close(&g_rep);
    return failures;
}

/* The pairing and delegation gates, read off the recorded observation. */
static const uint8_t g_rep_none[32];

static int test_rep_gate_pairing(void)
{
    int failures = 0;
    struct boot_fleet_board_observation attempt, ingest;
    struct json_value out;
    json_init(&out);
    json_set_object(&out);
    bool opened = rep_open(&g_rep, REP_SOON, FBW_NOW);
    TEST("fleet board replication: a closed pairing window is refused at "
         "pairing before any stream opens") {
        ASSERT(opened);
        rep_clock(&g_rep, REP_LATE);
        boot_fleet_board_fleet_test_pull_paired(REP_LATE);
        rep_observe(g_rep.w.f.term_peer.delegation.doc.master_pubkey, g_rep_none,
                    &attempt, &ingest);
        ASSERT(attempt.found);
        ASSERT_EQ(attempt.phase, FLEET_BOARD_OBS_GATE);
        ASSERT_EQ(attempt.result, (int)FLEET_BOARD_GATE_PAIRING);
        ASSERT(rep_stage_is(&attempt, "pairing"));
        ASSERT(fb_status_observation(&out, "peer_attempt", &attempt));
        ASSERT(strstr(json_get_str(json_get(json_get(&out, "peer_attempt"),
                                            "operator_action")),
                      "ops mesh pair list"));
        PASS();
    } _test_next:;
    json_free(&out);
    rep_close(&g_rep);
    return failures;
}

static int test_rep_gate_delegation_expired(void)
{
    int failures = 0;
    struct boot_fleet_board_observation attempt, ingest;
    struct boot_fleet_board_fleet_counts before, after;
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW);
    TEST("fleet board replication: an expired delegation is refused at "
         "delegation and counted") {
        ASSERT(opened);
        rep_clock(&g_rep, REP_PAST_DELEGATION);
        boot_fleet_board_fleet_counts(&before);
        boot_fleet_board_fleet_test_pull_paired(REP_PAST_DELEGATION);
        boot_fleet_board_fleet_counts(&after);
        ASSERT_EQ(after.delegation_refused, before.delegation_refused + 1);
        rep_observe(g_rep.w.f.term_peer.delegation.doc.master_pubkey, g_rep_none,
                    &attempt, &ingest);
        ASSERT_EQ(attempt.phase, FLEET_BOARD_OBS_GATE);
        ASSERT_EQ(attempt.result, (int)FLEET_BOARD_GATE_DELEGATION_REFUSED);
        ASSERT(rep_stage_is(&attempt, "delegation"));
        PASS();
    } _test_next:;
    rep_close(&g_rep);
    return failures;
}

static int test_rep_gate_unresolved(void)
{
    int failures = 0;
    struct boot_fleet_board_observation attempt, ingest;
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW) &&
             mesh_term_pair_row(&g_rep.w.f, &g_rep.w.f.status_peer,
                                MESH_PAIRING_CAP_STATUS_READ, FBW_PAIRED_AT,
                                FBW_PAIRING_EXPIRES);
    TEST("fleet board replication: a paired peer whose delegation cannot be "
         "resolved is refused at delegation; a due, connected peer is not "
         "refused at any stage") {
        ASSERT(opened);
        boot_fleet_board_fleet_test_pull_paired(FBW_NOW);
        rep_observe(g_rep.w.f.status_peer.delegation.doc.master_pubkey, g_rep_none,
                    &attempt, &ingest);
        ASSERT_EQ(attempt.phase, FLEET_BOARD_OBS_GATE);
        ASSERT_EQ(attempt.result, (int)FLEET_BOARD_GATE_DELEGATION_UNRESOLVED);
        ASSERT(rep_stage_is(&attempt, "delegation"));
        rep_observe(g_rep.w.f.term_peer.delegation.doc.master_pubkey, g_rep_none,
                    &attempt, &ingest);
        ASSERT_EQ(attempt.phase, FLEET_BOARD_OBS_OPEN_ATTEMPT);
        ASSERT(!rep_stage_is(&attempt, "stream"));
        PASS();
    } _test_next:;
    rep_close(&g_rep);
    return failures;
}

int test_fleet_board_replication(void)
{
    return test_rep_happy_path() + test_rep_restart_midway() +
           test_rep_partition() + test_rep_cursor_missing_or_behind() +
           test_rep_cursor_ahead() + test_rep_expired() +
           test_rep_duplicate_delivery() + test_rep_stage_text() +
           test_rep_clock_and_roster_guidance() +
           test_rep_answer_role_refused() + test_rep_ingest_role_refused() +
           test_rep_ingest_limit() + test_rep_ingest_storage() + test_rep_decode_refused() +
           test_rep_gate_pairing() + test_rep_gate_delegation_expired() +
           test_rep_gate_unresolved();
}
