/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fleet-board replication between two nodes under faults: the pull, the
 * cursor and the ingest, with the stage of every refusal named. Then
 * push-first delivery across three: the public relay, and the fleet push's
 * fan-out with the pull as repair.
 *
 * Node A answers, node B pulls and commits, through the real "board" stream
 * service over the loopback wire (test/fleet_board_two_node_fixture.h). No
 * sleeps: the clock is the explicit `now` the authority is bound to, and a
 * pull is driven one call at a time, so nothing here depends on load. B's
 * store and its cursor file live on disk, so a restart is a real close and
 * reopen of both. The socket and the DHT delegation lookup are the only
 * stand-ins. */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "config/boot_fleet_board.h"
#include "config/mesh_stream.h"
#include "json/json.h"
#include "models/fleet_board_post.h"
#include "models/mesh_pairing.h"
#include "models/zid_identity.h"
#include "net/fast_sync.h"
#include "net/net.h"
#include "net/peer_scoring.h"
#include "net/protocol.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "validation/main_constants.h"
#include "vcs/zcode_dht_delegation.h"
#include "session/fleet_board_proto.h"
#include "test/fleet_board_two_node_fixture.h"
#include "test/mesh_stream_fixture.h"
#include "test/mesh_stream_loopback.h"
#include "util/fleet_role_check.h"
#include "dev/fleet_roles.h"
#include "../../../engine/composition/src/boot_fleet_board_rpc_internal.h"

#include <stdio.h>
#include <sqlite3.h>
#include <stdlib.h>
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

/* ── every fleet kind a CLI posts travels to a box that granted worker ── */

/* B's real catalog answer for a key it granted `worker`: the asker's read
 * and the author's posts are judged by roles.def, not by a stand-in. */
static bool rep_worker_role_check(const uint8_t key[32], const char *leaf,
                                  const char *kind, char *why, size_t why_cap,
                                  void *ctx)
{
    (void)key;
    (void)ctx;
    uint8_t worker = 0;
    bool ok = zcl_role_from_name("worker", &worker) &&
              zcl_role_leaf_allowed(worker, leaf, kind);
    if (!ok && why && why_cap)
        (void)snprintf(why, why_cap, "role_refused: worker lacks %s kind=%s",
                       leaf, kind ? kind : "-");
    return ok;
}

static bool rep_post_kind(struct rep *r, uint8_t kind, const char *text,
                          int64_t created_at, struct fleet_board_post *out)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(7, seed, pk);
    fb_test_compose(out, kind, "carrier", text, (uint64_t)created_at, 3600);
    fb_test_scope(out, FLEET_BOARD_SCOPE_FLEET, "");
    return fleet_board_post_sign(out, seed, pk) == FLEET_BOARD_OK &&
           db_fleet_board_post_ingest(&r->w.a, out, created_at + 100, NULL) ==
               FLEET_BOARD_OK;
}

static int test_rep_worker_carries_shared_kinds(void)
{
    int failures = 0;
    static const struct zcl_fleet_role_checker worker_checker = {
        .allow = rep_worker_role_check, .name = "fleet-board-worker-test" };
    struct fleet_board_post agents, offer;
    bool opened = rep_open(&g_rep, FBW_PAIRING_EXPIRES, FBW_NOW);
    TEST("fleet board replication: a fleet `agents` snapshot and a fleet "
         "offer reach a box that granted the author worker") {
        ASSERT(opened);
        /* A stores its own posts (its own key is operator there). */
        ASSERT(rep_post_kind(&g_rep, FLEET_BOARD_KIND_AGENTS,
                             "host r1: 3 running", 2000, &agents));
        ASSERT(rep_post_kind(&g_rep, FLEET_BOARD_KIND_OFFER,
                             "spare build capacity", 2001, &offer));
        /* B judges the author by the catalog's worker role. */
        zcl_fleet_role_checker_install(&worker_checker);
        ASSERT_EQ(rep_pull_until_quiet(&g_rep, 4, NULL), (size_t)2);
        ASSERT(db_fleet_board_have(&g_rep.w.b, agents.id));
        ASSERT(db_fleet_board_have(&g_rep.w.b, offer.id));
        PASS();
    } _test_next:;
    rep_close(&g_rep);
    return failures;
}

/* ── push-first, public scope: the relay across three nodes ─────────────
 * Three board stores, each with its own net manager and one plaintext P2P
 * node per neighbour, on the real public frame path (boot_fleet_board_frame)
 * with the real codec. The board is a process singleton, so each frame is
 * handled with the receiving node's store wired, as that node would; every
 * frame a node sends is read off its outbound queue and delivered in order.
 * No tick ever runs, so nothing waits for FLEET_BOARD_ANNOUNCE_PERIOD_SECONDS:
 * an id reaches a node only by the origin's announce or a relay. */

#define RPB_NODES 3
#define RPB_QUEUE 96
#define RPB_WIRE_MAX                                                           \
    (FLEET_BOARD_FRAME_MAGIC_BYTES + 1 + FLEET_BOARD_BODY_MAX +                \
     FLEET_BOARD_SIG_BYTES)

struct rpb_msg {
    unsigned to, from;
    size_t len;
    uint8_t bytes[RPB_WIRE_MAX];
};

struct rpb {
    struct node_db db[RPB_NODES];
    struct net_manager nm[RPB_NODES];
    struct msg_processor mp[RPB_NODES];
    struct boot_svc_ctx svc[RPB_NODES];
    struct p2p_node *link[RPB_NODES][RPB_NODES]; /* i's node for peer j */
    struct send_segment *q[RPB_NODES][RPB_NODES];
    struct p2p_node *table[RPB_NODES][RPB_NODES];
    unsigned inv[RPB_NODES][RPB_NODES]; /* INV frames i sent to j */
    unsigned delivered;                 /* frames handled */
    size_t bytes;                       /* payload bytes handled */
};

static struct rpb g_rpb;
static struct rpb_msg g_rpb_q[RPB_QUEUE];
static size_t g_rpb_head, g_rpb_len;
static uint8_t g_rpb_wire[RPB_WIRE_MAX];

static bool rpb_push(unsigned to, unsigned from, const uint8_t *bytes,
                     size_t len)
{
    if (g_rpb_len == RPB_QUEUE || len > RPB_WIRE_MAX)
        return false;
    struct rpb_msg *m = &g_rpb_q[(g_rpb_head + g_rpb_len++) % RPB_QUEUE];
    m->to = to;
    m->from = from;
    m->len = len;
    memcpy(m->bytes, bytes, len);
    return true;
}

/* One plaintext board payload off `n`'s outbound queue; `more` false when
 * the queue was empty. */
static size_t rpb_take(struct p2p_node *n, struct send_segment *sentinel,
                       uint8_t *out, size_t cap, bool *more)
{
    struct send_segment *seg = sentinel->next;
    *more = seg != NULL;
    if (!seg)
        return 0;
    sentinel->next = seg->next;
    if (n->send_tail == seg)
        n->send_tail = sentinel;
    n->send_size = n->send_size >= seg->size ? n->send_size - seg->size : 0;
    n->send_offset = 0;
    size_t moved = 0;
    if (seg->size > MSG_HEADER_SIZE && seg->size - MSG_HEADER_SIZE <= cap &&
        memcmp(seg->data + MESSAGE_START_SIZE, "zpkgswm", 7) == 0) {
        moved = seg->size - MSG_HEADER_SIZE;
        memcpy(out, seg->data + MSG_HEADER_SIZE, moved);
    }
    send_segment_free(seg);
    return moved;
}

/* Everything node `i` sent, queued for its neighbours; INVs counted. */
static bool rpb_collect(struct rpb *r, unsigned i)
{
    for (unsigned j = 0; j < RPB_NODES; j++) {
        bool more = r->link[i][j] != NULL;
        while (more) {
            size_t n = rpb_take(r->link[i][j], r->q[i][j], g_rpb_wire,
                                sizeof g_rpb_wire, &more);
            if (!n)
                continue;
            if (fleet_board_frame_type(g_rpb_wire, n) == FLEET_BOARD_FRAME_INV)
                r->inv[i][j]++;
            if (!rpb_push(j, i, g_rpb_wire, n))
                return false;
        }
    }
    return true;
}

static bool rpb_deliver(struct rpb *r, unsigned to, unsigned from,
                        const uint8_t *bytes, size_t len)
{
    boot_fleet_board_shutdown();
    boot_fleet_board_wire(&r->svc[to]);
    r->delivered++;
    r->bytes += len;
    return boot_fleet_board_frame(&r->mp[to], r->link[to][from], bytes, len,
                                  NULL) &&
           rpb_collect(r, to);
}

/* Deliver in order until nothing is in flight; false past `max` frames. */
static bool rpb_run(struct rpb *r, unsigned max)
{
    for (unsigned n = 0; g_rpb_len > 0; n++) {
        if (n == max)
            return false;
        struct rpb_msg *m = &g_rpb_q[g_rpb_head];
        g_rpb_head = (g_rpb_head + 1) % RPB_QUEUE;
        g_rpb_len--;
        if (!rpb_deliver(r, m->to, m->from, m->bytes, m->len))
            return false;
    }
    return true;
}

static bool rpb_node_link(struct rpb *r, unsigned i, unsigned j)
{
    struct net_address addr;
    memset(&addr, 0, sizeof addr);
    addr.svc.port = (uint16_t)(18100 + i * RPB_NODES + j);
    struct p2p_node *n = p2p_node_create(&r->nm[i], ZCL_INVALID_SOCKET, &addr,
                                         "board-relay", false);
    if (!n)
        return false;
    n->state = PEER_HANDSHAKE_COMPLETE;
    n->services = NODE_NETWORK | NODE_ZCL23;
    r->link[i][j] = n;
    r->q[i][j] = mesh_loop_sentinel(n);
    r->table[i][r->nm[i].num_nodes++] = n;
    return r->q[i][j] != NULL;
}

/* `ring`: every node neighbours both others; else node 0 sits between nodes
 * 1 and 2, which do not neighbour each other. */
static bool rpb_open(struct rpb *r, bool ring)
{
    memset(r, 0, sizeof *r);
    g_rpb_head = g_rpb_len = 0;
    peer_scoring_init();
    const struct chain_params *params = chain_params_get();
    bool ok = params != NULL;
    for (unsigned i = 0; ok && i < RPB_NODES; i++) {
        zcl_mutex_init(&r->nm[i].cs_nodes);
        zcl_mutex_init(&r->nm[i].cs_last_node_id);
        r->nm[i].nodes = r->table[i];
        r->mp[i].params = params;
        r->mp[i].net_mgr = &r->nm[i];
        r->svc[i].node_db = &r->db[i];
        r->svc[i].msg_processor = &r->mp[i];
        r->svc[i].params = params;
        ok = node_db_open(&r->db[i], ":memory:");
        for (unsigned j = 0; ok && j < RPB_NODES; j++)
            if (j != i && (ring || i == 0 || j == 0))
                ok = rpb_node_link(r, i, j);
    }
    return ok;
}

static void rpb_close(struct rpb *r)
{
    boot_fleet_board_shutdown();
    for (unsigned i = 0; i < RPB_NODES; i++) {
        for (unsigned j = 0; j < RPB_NODES; j++) {
            if (!r->link[i][j])
                continue;
            mesh_loop_free_queue(r->link[i][j], r->q[i][j]);
            p2p_node_free(r->link[i][j]);
            free(r->q[i][j]);
        }
        zcl_mutex_destroy(&r->nm[i].cs_nodes);
        zcl_mutex_destroy(&r->nm[i].cs_last_node_id);
        if (r->db[i].open)
            node_db_close(&r->db[i]);
    }
}

/* A post by `who` in `scope`, created now, stored at node `at` (NULL: not
 * stored anywhere). */
static bool rpb_post(struct node_db *at, uint8_t who, uint8_t scope, int n,
                     struct fleet_board_post *out)
{
    uint8_t seed[32], pk[32];
    char text[64];
    int64_t now = (int64_t)platform_time_wall_time_t();
    fb_test_identity(who, seed, pk);
    (void)snprintf(text, sizeof text, "relayed public note %d", n);
    fb_test_compose(out, FLEET_BOARD_KIND_NOTE, "relay", text, (uint64_t)now,
                    3600);
    fb_test_scope(out, scope,
                  scope == FLEET_BOARD_SCOPE_PUBLIC ? "general" : "");
    return fleet_board_post_sign(out, seed, pk) == FLEET_BOARD_OK &&
           (!at || db_fleet_board_post_ingest(at, out, now, NULL) ==
                       FLEET_BOARD_OK);
}

/* The origin's own announce of one id to each of its neighbours, as
 * boot_fleet_board_announce floods it after a local post. */
static bool rpb_announce(struct rpb *r, unsigned from, const uint8_t id[32])
{
    uint8_t ids[1][32], frame[FLEET_BOARD_FRAME_MAX];
    size_t len = 0;
    memcpy(ids[0], id, 32);
    if (fleet_board_frame_encode_ids(FLEET_BOARD_FRAME_INV, ids, 1, frame,
                                     sizeof frame, &len) != FLEET_BOARD_OK)
        return false;
    for (unsigned j = 0; j < RPB_NODES; j++) {
        if (!r->link[from][j])
            continue;
        if (!rpb_push(j, from, frame, len))
            return false;
        r->inv[from][j]++;
    }
    return true;
}

static int test_rep_public_relay_two_hops(void)
{
    int failures = 0;
    struct fleet_board_post p, fleet;
    bool opened = rpb_open(&g_rpb, false);
    TEST("fleet board relay: a public post B -> A -> C reaches C at once, "
         "never back to B, with no announce period waited") {
        ASSERT(opened);
        uint64_t relayed = boot_fleet_board_relayed_count();
        ASSERT(rpb_post(&g_rpb.db[1], 31, FLEET_BOARD_SCOPE_PUBLIC, 0, &p));
        ASSERT(rpb_announce(&g_rpb, 1, p.id));
        ASSERT(rpb_run(&g_rpb, 16));
        ASSERT(db_fleet_board_have(&g_rpb.db[0], p.id));
        ASSERT(db_fleet_board_have(&g_rpb.db[2], p.id));
        /* INV B->A, GET, POST, the relay INV A->C, GET, POST: six frames. */
        ASSERT_EQ(g_rpb.delivered, 6u);
        ASSERT_EQ(g_rpb.inv[0][2], 1u);
        ASSERT_EQ(g_rpb.inv[0][1], 0u);
        ASSERT_EQ(g_rpb.inv[2][0], 0u);
        ASSERT_EQ(boot_fleet_board_relayed_count(), relayed + 1);
        /* A fleet post is never put on the public inventory path. */
        zcl_fleet_role_checker_install(&g_rep_checker);
        ASSERT(rpb_post(NULL, 31, FLEET_BOARD_SCOPE_FLEET, 1, &fleet));
        size_t len = 0;
        ASSERT_EQ(fleet_board_frame_encode_post(&fleet, g_rpb_wire,
                                                sizeof g_rpb_wire, &len),
                  FLEET_BOARD_OK);
        ASSERT(rpb_deliver(&g_rpb, 0, 1, g_rpb_wire, len));
        ASSERT_EQ(g_rpb_len, (size_t)0);
        ASSERT_EQ(g_rpb.inv[0][2], 1u);
        ASSERT_EQ(boot_fleet_board_relayed_count(), relayed + 1);
        PASS();
    } _test_next:;
    zcl_fleet_role_checker_install_permissive_for_testing();
    rpb_close(&g_rpb);
    return failures;
}

static int test_rep_public_relay_cycle(void)
{
    int failures = 0;
    struct fleet_board_post p;
    bool opened = rpb_open(&g_rpb, true);
    TEST("fleet board relay: in a cycle of three each node names a post to "
         "each neighbour at most once, and a replay names it to nobody") {
        ASSERT(opened);
        uint64_t relayed = boot_fleet_board_relayed_count();
        ASSERT(rpb_post(&g_rpb.db[0], 32, FLEET_BOARD_SCOPE_PUBLIC, 0, &p));
        ASSERT(rpb_announce(&g_rpb, 0, p.id));
        ASSERT(rpb_run(&g_rpb, 32));
        for (unsigned i = 0; i < RPB_NODES; i++) {
            ASSERT(db_fleet_board_have(&g_rpb.db[i], p.id));
            for (unsigned j = 0; j < RPB_NODES; j++)
                ASSERT(g_rpb.inv[i][j] <= 1u);
        }
        /* Nobody names it back to the origin it came from. */
        ASSERT_EQ(g_rpb.inv[1][0] + g_rpb.inv[2][0], 0u);
        ASSERT_EQ(boot_fleet_board_relayed_count(), relayed + 2);
        /* The same post and the same id again: held, so silence. */
        size_t len = 0;
        ASSERT_EQ(fleet_board_frame_encode_post(&p, g_rpb_wire,
                                                sizeof g_rpb_wire, &len),
                  FLEET_BOARD_OK);
        unsigned seen = g_rpb.delivered;
        ASSERT(rpb_deliver(&g_rpb, 1, 2, g_rpb_wire, len));
        ASSERT(rpb_announce(&g_rpb, 2, p.id));
        ASSERT(rpb_run(&g_rpb, 8));
        ASSERT_EQ(g_rpb.delivered, seen + 3);
        ASSERT_EQ(boot_fleet_board_relayed_count(), relayed + 2);
        PASS();
    } _test_next:;
    rpb_close(&g_rpb);
    return failures;
}

static int test_rep_public_relay_flood_bound(void)
{
    int failures = 0;
    bool opened = rpb_open(&g_rpb, false);
    TEST("fleet board relay: a peer posting many valid posts causes at most "
         "its frame budget of relays per window") {
        ASSERT(opened);
        boot_fleet_board_shutdown();
        boot_fleet_board_wire(&g_rpb.svc[0]);
        /* Four authors, so the public per-author quota is not what stops it. */
        const int sent = FLEET_BOARD_PEER_FRAMES_PER_WINDOW + 16;
        for (int i = 0; i < sent; i++) {
            struct fleet_board_post p;
            size_t len = 0;
            ASSERT(rpb_post(NULL, (uint8_t)(40 + i % 4),
                            FLEET_BOARD_SCOPE_PUBLIC, i, &p));
            ASSERT_EQ(fleet_board_frame_encode_post(&p, g_rpb_wire,
                                                    sizeof g_rpb_wire, &len),
                      FLEET_BOARD_OK);
            ASSERT(boot_fleet_board_frame(&g_rpb.mp[0], g_rpb.link[0][1],
                                          g_rpb_wire, len, NULL));
        }
        unsigned to_c = 0, to_b = 0;
        bool more = true;
        while (more)
            to_c += rpb_take(g_rpb.link[0][2], g_rpb.q[0][2], g_rpb_wire,
                             sizeof g_rpb_wire, &more) > 0;
        more = true;
        while (more)
            to_b += rpb_take(g_rpb.link[0][1], g_rpb.q[0][1], g_rpb_wire,
                             sizeof g_rpb_wire, &more) > 0;
        ASSERT_EQ(to_c, (unsigned)FLEET_BOARD_PEER_FRAMES_PER_WINDOW);
        ASSERT_EQ(to_b, 0u);
        PASS();
    } _test_next:;
    rpb_close(&g_rpb);
    return failures;
}

/* ── push-first, fleet scope: the fan-out ───────────────────────────────
 * The two-node loopback plus a third session: the box that opens streams
 * (the terminal peer's Noise key, store `b`) signs as RFO_PUSHER; the box
 * answering on the responder's key (store `a`) is RFO_ADDRESSEE; the status
 * peer's session, reached through a third node, is RFO_THIRD. A post with
 * no ref and no hint is offered to every connected peer the pull would
 * serve, and the third is made ineligible one check at a time. */

#define RFO_PUSHER 7
#define RFO_THIRD 8
#define RFO_ADDRESSEE 9

enum rfo_third { RFO_ELIGIBLE, RFO_UNPAIRED, RFO_STALE, RFO_NO_ROLE };

struct rfo {
    struct fbw w;
    struct vcs_zcode_dht_delegation pusher, addressee, third;
    struct mesh_term_peer addr_peer;
    struct p2p_node *third_node;
    struct send_segment *third_q;
    struct p2p_node *nodes[3];
    struct boot_fleet_board_fleet_counts before;
};

static struct rfo g_rfo;
static uint8_t g_rfo_deny_key[32];
static bool g_rfo_deny;

static bool rfo_role_check(const uint8_t key[32], const char *leaf,
                           const char *kind, char *why, size_t why_cap,
                           void *ctx)
{
    if (g_rfo_deny && strcmp(leaf, FLEET_BOARD_FLEET_READ_LEAF) == 0 &&
        memcmp(key, g_rfo_deny_key, 32) == 0) {
        if (why && why_cap)
            (void)snprintf(why, why_cap, "role_refused: test denies %s", leaf);
        return false;
    }
    return fbw_role_check(key, leaf, kind, why, why_cap, ctx);
}

static struct zcl_fleet_role_checker g_rfo_checker = {
    .allow = rfo_role_check, .name = "fleet-board-fanout-test" };

/* `who`'s board key on `noise`, under the master the fixture anchors with
 * `master_fill`, valid over [1000, until]. */
static bool rfo_delegation(const struct mesh_term_fixture *f, uint8_t who,
                           const uint8_t noise[32], uint8_t master_fill,
                           uint64_t until,
                           struct vcs_zcode_dht_delegation *out)
{
    uint8_t seed[32], pk[32], beacon[32], master_seed[32];
    fb_test_identity(who, seed, pk);
    memset(beacon, 0x22, sizeof beacon);
    memset(master_seed, master_fill, sizeof master_seed);
    return vcs_zcode_dht_delegation_sign(out, f->genesis, pk, noise,
                                         ZCL_FINALITY_DEPTH, beacon, 1000,
                                         until, 7, master_seed) ==
           VCS_ZCODE_DHT_DELEGATION_OK;
}

static bool rfo_identity_active(struct node_db *ndb, const uint8_t master[32])
{
    struct zid_identity identity = {0};
    memcpy(identity.master_pubkey, master, 32);
    memset(identity.anchor_txid, 0x77, 32);
    (void)snprintf(identity.status, sizeof identity.status, "%s",
                   ZID_IDENTITY_STATUS_ACTIVE);
    (void)snprintf(identity.source, sizeof identity.source, "%s",
                   ZID_IDENTITY_SOURCE_ZID_OVERLAY);
    return db_zid_identity_save(ndb, &identity);
}

/* The status peer's session, connected through a third node. */
static bool rfo_third_node(struct rfo *o)
{
    struct net_address addr;
    memset(&addr, 0, sizeof addr);
    addr.svc.port = 18036;
    o->third_node = p2p_node_create(&o->w.nm, ZCL_INVALID_SOCKET, &addr,
                                    "board-third", false);
    if (!o->third_node)
        return false;
    o->third_node->transport = o->w.f.res_status;
    o->third_node->state = PEER_HANDSHAKE_COMPLETE;
    o->third_q = mesh_loop_sentinel(o->third_node);
    o->nodes[0] = o->w.asker;
    o->nodes[1] = o->w.answerer;
    o->nodes[2] = o->third_node;
    o->w.nm.nodes = o->nodes;
    o->w.nm.num_nodes = 3;
    return o->third_q != NULL;
}

static bool rfo_pair(struct rfo *o, struct mesh_term_peer *peer)
{
    return mesh_term_pair_row(&o->w.f, peer, MESH_PAIRING_CAP_STATUS_READ,
                              FBW_PAIRED_AT, FBW_PAIRING_EXPIRES);
}

static bool rfo_pairings(struct rfo *o, enum rfo_third mode)
{
    struct mesh_term_fixture *f = &o->w.f;
    uint64_t until = mode == RFO_STALE ? 2000u : 4000u; /* FBW_NOW is 2500 */
    if (!rfo_delegation(f, RFO_PUSHER, f->term_peer.noise_pub, 0x61, 4000u,
                        &o->pusher) ||
        !rfo_delegation(f, RFO_ADDRESSEE, f->resp_noise_pub, 0x88, 4000u,
                        &o->addressee) ||
        !rfo_delegation(f, RFO_THIRD, f->status_peer.noise_pub, 0x60, until,
                        &o->third) ||
        !rfo_identity_active(&f->ndb, o->addressee.doc.master_pubkey))
        return false;
    f->term_peer.delegation = o->pusher;
    o->addr_peer.delegation = o->addressee;
    f->status_peer.delegation = o->third;
    return rfo_pair(o, &f->term_peer) && rfo_pair(o, &o->addr_peer) &&
           (mode == RFO_UNPAIRED || rfo_pair(o, &f->status_peer));
}

static bool rfo_open(struct rfo *o, enum rfo_third mode)
{
    memset(o, 0, sizeof *o);
    g_rfo_deny = false;
    zcl_fleet_role_checker_install(&g_rfo_checker);
    if (!fbw_open(&o->w) || !rfo_pairings(o, mode) || !rfo_third_node(o))
        return false;
    uint8_t seed[32];
    fb_test_identity(RFO_THIRD, seed, g_rfo_deny_key);
    g_rfo_deny = mode == RFO_NO_ROLE;
    boot_fleet_board_fleet_test_bind(&o->w.a);
    boot_fleet_board_fleet_test_bind_authority(&o->pusher, o->w.f.genesis,
                                               FBW_NOW);
    boot_fleet_board_fleet_test_bind_second_peer(&o->addressee);
    boot_fleet_board_fleet_test_bind_third_peer(&o->third);
    boot_fleet_board_fleet_test_pre_push_dispatch(false);
    boot_fleet_board_fleet_counts(&o->before);
    return true;
}

static void rfo_close(struct rfo *o)
{
    mesh_stream_test_reset();
    if (o->third_node) {
        o->w.nm.nodes = o->w.nodes;
        o->w.nm.num_nodes = 2;
        mesh_loop_free_queue(o->third_node, o->third_q);
        p2p_node_free(o->third_node);
        free(o->third_q);
        o->third_node = NULL;
    }
    boot_fleet_board_fleet_test_pre_push_dispatch(false);
    g_rfo_deny = false;
    fbw_close(&o->w);
    zcl_fleet_role_checker_install_permissive_for_testing();
}

/* A FLEET note by the pushing box, no ref, offered as the local post path
 * offers it. */
static bool rfo_post_offered(struct rfo *o, const char *text,
                             struct fleet_board_post *out)
{
    uint8_t seed[32], pk[32];
    fb_test_identity(RFO_PUSHER, seed, pk);
    return fbw_post(&o->w.b, RFO_PUSHER, FLEET_BOARD_SCOPE_FLEET, text, 2001,
                    3600, 2100, out) &&
           boot_fleet_board_fleet_push_enqueue_all(out, pk, NULL) ==
               FLEET_BOARD_PUSH_HINT_NONE;
}

static bool rfo_has(const uint8_t *frame, size_t len, const uint8_t id[32])
{
    for (size_t i = 0; i + 32 <= len; i++)
        if (memcmp(frame + i, id, 32) == 0)
            return true;
    return false;
}

/* Frames the third node carried to the status peer, and how many held `id`
 * (each read, so the queue is empty after). */
static size_t rfo_third_frames(struct rfo *o, const uint8_t id[32],
                               size_t *carrying)
{
    size_t frames = 0;
    *carrying = 0;
    for (bool more = true; more;) {
        size_t n = mesh_loop_take(o->third_node, o->third_q,
                                  o->w.f.status_peer.ini, g_rpb_wire,
                                  sizeof g_rpb_wire, &more);
        if (!n)
            continue;
        frames++;
        *carrying += rfo_has(g_rpb_wire, n, id);
    }
    return frames;
}

static struct boot_fleet_board_fleet_counts rfo_counts(void)
{
    struct boot_fleet_board_fleet_counts c;
    boot_fleet_board_fleet_counts(&c);
    return c;
}

/* The addressee's half: the OPEN carried, committed into `a`, the receipt
 * carried back. The posts stored. */
static size_t rfo_addressee_commit(struct rfo *o)
{
    struct fbw *w = &o->w;
    if (mesh_loop_pump(w->asker, w->ask_q, w->f.res_term, &w->mp,
                       w->answerer) != 1)
        return SIZE_MAX;
    size_t stored = boot_fleet_board_fleet_test_push_commit(&w->a);
    (void)mesh_loop_pump(w->answerer, w->answer_q, w->f.term_peer.ini, &w->mp,
                         w->asker);
    return stored;
}

/* The addressee pulls what the pushing box holds: the repair path. */
static size_t rfo_pull_into_addressee(struct rfo *o)
{
    size_t frames = 0;
    boot_fleet_board_fleet_test_bind(&o->w.b);
    return fbw_pull(&o->w, o->w.box_a, &o->w.a, &frames);
}

static int test_rep_fanout_eligible(void)
{
    int failures = 0;
    struct fleet_board_post p;
    size_t carrying = 0;
    bool opened = rfo_open(&g_rfo, RFO_ELIGIBLE);
    TEST("fleet board fan-out: a new fleet post with no addressee is pushed "
         "once to each connected peer a pull would serve, not to its author") {
        ASSERT(opened);
        ASSERT(rfo_post_offered(&g_rfo, "fanned out", &p));
        ASSERT_EQ(boot_fleet_board_fleet_test_push_queued(), (size_t)1);
        ASSERT_EQ(boot_fleet_board_fleet_test_push_send(&g_rfo.w.svc,
                                                        &g_rfo.w.b),
                  (size_t)2);
        struct boot_fleet_board_fleet_counts c = rfo_counts();
        ASSERT_EQ(c.push_opened, g_rfo.before.push_opened + 2);
        ASSERT_EQ(c.push_fanout, g_rfo.before.push_fanout + 2);
        for (unsigned i = 0; i < FLEET_BOARD_PUSH_REFUSALS; i++)
            ASSERT_EQ(c.push_fanout_refused[i],
                      g_rfo.before.push_fanout_refused[i]);
        ASSERT_EQ(rfo_third_frames(&g_rfo, p.id, &carrying), (size_t)1);
        ASSERT_EQ(carrying, (size_t)1);
        /* The answering box stores it from the push, with no pull. */
        ASSERT_EQ(rfo_addressee_commit(&g_rfo), (size_t)1);
        ASSERT(db_fleet_board_have(&g_rfo.w.a, p.id));
        /* Offered once: the next round has nothing to send. */
        ASSERT_EQ(boot_fleet_board_fleet_test_push_send_at(
                      &g_rfo.w.svc, &g_rfo.w.b, FBW_NOW + 1),
                  (size_t)0);
        PASS();
    } _test_next:;
    rfo_close(&g_rfo);
    return failures;
}

/* The third peer is connected but fails `mode`'s check: one push, to the
 * answering box only; nothing on the third's wire; the refusal counted. */
static int rfo_ineligible_case(enum rfo_third mode, const char *name,
                               int refusal)
{
    int failures = 0;
    struct fleet_board_post p;
    size_t carrying = 0;
    bool opened = rfo_open(&g_rfo, mode);
    TEST(name) {
        ASSERT(opened);
        ASSERT(rfo_post_offered(&g_rfo, "not for the third box", &p));
        ASSERT_EQ(boot_fleet_board_fleet_test_push_send(&g_rfo.w.svc,
                                                        &g_rfo.w.b),
                  (size_t)1);
        struct boot_fleet_board_fleet_counts c = rfo_counts();
        ASSERT_EQ(c.push_opened, g_rfo.before.push_opened + 1);
        ASSERT_EQ(c.push_fanout, g_rfo.before.push_fanout + 1);
        for (int i = 0; i < (int)FLEET_BOARD_PUSH_REFUSALS; i++)
            ASSERT_EQ(c.push_fanout_refused[i],
                      g_rfo.before.push_fanout_refused[i] + (i == refusal));
        ASSERT_EQ(rfo_third_frames(&g_rfo, p.id, &carrying), (size_t)0);
        ASSERT_EQ(rfo_addressee_commit(&g_rfo), (size_t)1);
        ASSERT(db_fleet_board_have(&g_rfo.w.a, p.id));
        PASS();
    } _test_next:;
    rfo_close(&g_rfo);
    return failures;
}

static int test_rep_fanout_ineligible(void)
{
    /* No pairing row: never a candidate, so nothing is judged or counted. */
    return rfo_ineligible_case(RFO_UNPAIRED,
                               "fleet board fan-out: a connected peer with "
                               "no pairing is not pushed to", -1) +
           rfo_ineligible_case(RFO_STALE,
                               "fleet board fan-out: a connected peer whose "
                               "delegation is not current is not pushed to",
                               (int)FLEET_BOARD_PUSH_REFUSAL_DELEGATION) +
           rfo_ineligible_case(RFO_NO_ROLE,
                               "fleet board fan-out: a connected peer "
                               "without the read role is not pushed to",
                               (int)FLEET_BOARD_PUSH_REFUSAL_ROLE);
}

static int test_rep_fanout_pull_repairs(void)
{
    int failures = 0;
    struct fleet_board_post lost, refused;
    size_t carrying = 0;
    bool opened = rfo_open(&g_rfo, RFO_ELIGIBLE);
    TEST("fleet board fan-out: a push dropped on the wire, or refused by a "
         "node from before the push, is recorded and the pull delivers") {
        ASSERT(opened);
        /* Dropped: both OPENs lost in flight. */
        ASSERT(rfo_post_offered(&g_rfo, "lost in flight", &lost));
        ASSERT_EQ(boot_fleet_board_fleet_test_push_send(&g_rfo.w.svc,
                                                        &g_rfo.w.b),
                  (size_t)2);
        mesh_loop_discard(g_rfo.w.asker, g_rfo.w.ask_q, g_rfo.w.f.res_term);
        ASSERT_EQ(rfo_third_frames(&g_rfo, lost.id, &carrying), (size_t)1);
        ASSERT(!db_fleet_board_have(&g_rfo.w.a, lost.id));
        /* Refused: the answering box treats the push as a malformed pull. */
        mesh_stream_test_reset();
        boot_fleet_board_fleet_test_pre_push_dispatch(true);
        ASSERT(rfo_post_offered(&g_rfo, "refused by an older node", &refused));
        ASSERT_EQ(boot_fleet_board_fleet_test_push_send_at(
                      &g_rfo.w.svc, &g_rfo.w.b, FBW_NOW + 1),
                  (size_t)2);
        ASSERT_EQ(rfo_addressee_commit(&g_rfo), (size_t)0);
        boot_fleet_board_fleet_test_pre_push_dispatch(false);
        struct boot_fleet_board_fleet_counts c = rfo_counts();
        ASSERT_EQ(c.push_skipped[FLEET_BOARD_PUSH_SKIP_UNSUPPORTED],
                  g_rfo.before.push_skipped[FLEET_BOARD_PUSH_SKIP_UNSUPPORTED] +
                      1);
        ASSERT(!db_fleet_board_have(&g_rfo.w.a, refused.id));
        /* The 15 s pull is the repair: both arrive. */
        ASSERT_EQ(rfo_pull_into_addressee(&g_rfo), (size_t)2);
        ASSERT(db_fleet_board_have(&g_rfo.w.a, lost.id));
        ASSERT(db_fleet_board_have(&g_rfo.w.a, refused.id));
        PASS();
    } _test_next:;
    rfo_close(&g_rfo);
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
           test_rep_gate_unresolved() +
           test_rep_worker_carries_shared_kinds() +
           test_rep_public_relay_two_hops() + test_rep_public_relay_cycle() +
           test_rep_public_relay_flood_bound() + test_rep_fanout_eligible() +
           test_rep_fanout_ineligible() + test_rep_fanout_pull_repairs();
}
