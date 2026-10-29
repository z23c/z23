/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Receiver-local wiki mutation: exact CAS, retained replay, and rollback. */
#include "test/test_core.h"
#include "config/boot_fleet_board.h"
#include "config/boot_internal.h"
#include "config/runtime.h"
#include "rpc/server.h"
#include "base/safe_alloc.h"
#include "command/native_command.h"
#include "controllers/rpc_client.h"
#include "models/fleet_board_post.h"
#include "models/fleet_board_post_internal.h"
#include "crypto/ed25519.h"
#include "util/thread_registry.h"
#include "util/fleet_role_check.h"
#include "session/fleet_wiki_entry.h"
#include "platform/time_compat.h"

#include <stdatomic.h>
#include <pthread.h>
#include <string.h>

#define FWM_NOW INT64_C(1000000)

static bool fwm_post(struct fleet_board_post *post, unsigned author,
    const char *marker, const char *body, int64_t now, const uint8_t *parent)
{
    uint8_t seed[32] = {0}, sk[32], pk[32];
    seed[0] = (uint8_t)author; seed[31] = 71;
    ed25519_keypair(pk, sk, seed);
    memset(post, 0, sizeof(*post));
    post->kind = FLEET_BOARD_KIND_WIKI;
    post->scope = FLEET_BOARD_SCOPE_PUBLIC;
    post->created_at = (uint64_t)now; post->ttl = 60;
    (void)snprintf(post->room, sizeof(post->room), "general");
    (void)snprintf(post->agent, sizeof(post->agent), "grant-%u", author);
    (void)snprintf(post->slug, sizeof(post->slug), "mutation-page");
    (void)snprintf(post->title, sizeof(post->title), "Receiver-local page");
    (void)snprintf(post->receipt, sizeof(post->receipt), "%s", marker);
    post->text_len = (uint32_t)strlen(body);
    memcpy(post->text, body, post->text_len + 1);
    if (parent) memcpy(post->supersedes, parent, 32);
    return fleet_board_post_sign(post, sk, pk) == FLEET_BOARD_OK;
}

static enum fleet_board_wiki_write_status fwm_write(struct node_db *db,
    const struct fleet_board_post *post, const uint8_t *parent,
    struct db_fleet_board_post *out)
{
    enum fleet_board_result refusal;
    return db_fleet_board_wiki_write(db, post, parent,
        (int64_t)post->created_at, out, &refusal);
}

static int fwm_replay_cas(void)
{
    int failures = 0;
    struct node_db db = {0};
    TEST("wiki mutation: retained replay binds payload and strict newest head refuses fallback") {
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post first, second, retry;
        struct db_fleet_board_post out;
        ASSERT(fwm_post(&first, 19, "request-first", "original", FWM_NOW, NULL));
        ASSERT_EQ(fwm_write(&db, &first, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(memcmp(out.post.id, first.id, 32) == 0);
        ASSERT(fwm_post(&second, 20, "request-second", "replacement", FWM_NOW + 1, first.id));
        ASSERT_EQ(fwm_write(&db, &second, first.id, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_post(&retry, 19, "request-first", "original", FWM_NOW + 1000, NULL));
        ASSERT_EQ(fwm_write(&db, &retry, NULL, &out), FLEET_WIKI_WRITE_REPLAY);
        ASSERT(memcmp(out.post.id, first.id, 32) == 0);
        ASSERT_EQ(fleet_board_post_verify(&out.post), FLEET_BOARD_OK);
        ASSERT(fwm_post(&retry, 19, "request-first", "changed", FWM_NOW + 2, NULL));
        ASSERT_EQ(fwm_write(&db, &retry, NULL, &out), FLEET_WIKI_WRITE_COLLISION);
        ASSERT(fwm_post(&retry, 19, "request-stale", "third", FWM_NOW + 2, first.id));
        ASSERT_EQ(fwm_write(&db, &retry, first.id, &out), FLEET_WIKI_WRITE_CONFLICT);
        ASSERT(fwm_post(&retry, 19, "request-tie", "third", FWM_NOW + 1, second.id));
        ASSERT_EQ(fwm_write(&db, &retry, second.id, &out), FLEET_WIKI_WRITE_CLOCK);
        ASSERT(node_db_exec(&db, "UPDATE fleet_board_posts SET text='corrupted' WHERE receipt='request-second'"));
        ASSERT(fwm_post(&retry, 19, "request-corrupt", "third", FWM_NOW + 3, first.id));
        ASSERT_EQ(fwm_write(&db, &retry, first.id, &out), FLEET_WIKI_WRITE_CORRUPT);
        struct fleet_board_status status;
        ASSERT(db_fleet_board_status(&db, FWM_NOW, &status));
        ASSERT_EQ(status.posts, 2);
        PASS();
    } _test_next:;
    if (db.open) node_db_close(&db);
    return failures;
}

struct fwm_racer {
    struct node_db *db;
    struct fleet_board_post post;
    uint8_t parent[32];
    atomic_int *ready;
    atomic_bool *go;
    enum fleet_board_wiki_write_status status;
};
static void *fwm_race_main(void *arg)
{
    struct fwm_racer *r = arg;
    atomic_fetch_add_explicit(r->ready, 1, memory_order_release);
    while (!atomic_load_explicit(r->go, memory_order_acquire)) platform_sleep_ms(1);
    struct db_fleet_board_post out;
    r->status = fwm_write(r->db, &r->post, r->parent, &out);
    return NULL;
}

static bool fwm_race(struct node_db *db, const struct fleet_board_post *head)
{
    atomic_int ready = 0;
    atomic_bool go = false;
    struct fwm_racer racers[2] = {{.db = db, .ready = &ready, .go = &go},
        {.db = db, .ready = &ready, .go = &go}};
    if (!fwm_post(&racers[0].post, 19, "race-a", "a", FWM_NOW + 1, head->id) ||
        !fwm_post(&racers[1].post, 20, "race-b", "b", FWM_NOW + 1, head->id)) return false;
    pthread_t threads[2];
    unsigned spawned = 0;
    for (; spawned < 2; spawned++) {
        memcpy(racers[spawned].parent, head->id, 32);
        if (thread_registry_spawn("wiki-cas", fwm_race_main, &racers[spawned], &threads[spawned])) break;
    }
    while (atomic_load_explicit(&ready, memory_order_acquire) < (int)spawned) platform_sleep_ms(1);
    atomic_store_explicit(&go, true, memory_order_release);
    for (unsigned i = 0; i < spawned; i++) pthread_join(threads[i], NULL);
    if (spawned != 2) return false;
    unsigned winners = (racers[0].status == FLEET_WIKI_WRITE_OK) +
        (racers[1].status == FLEET_WIKI_WRITE_OK);
    struct db_fleet_board_post out;
    unsigned loser = racers[0].status == FLEET_WIKI_WRITE_OK ? 1 : 0;
    return winners == 1 && fwm_write(db, &racers[loser].post, head->id, &out) == FLEET_WIKI_WRITE_CONFLICT;
}

static int fwm_race_case(void)
{
    int failures = 0;
    struct node_db db = {0};
    TEST("wiki mutation: two authors racing one exact parent admit one append") {
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post head;
        struct db_fleet_board_post out;
        ASSERT(fwm_post(&head, 19, "race-parent", "head", FWM_NOW, NULL));
        ASSERT_EQ(fwm_write(&db, &head, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_race(&db, &head));
        int64_t checked;
        ASSERT(db_fleet_board_chain_verify(&db, &checked));
        ASSERT_EQ(checked, 2);
        PASS();
    } _test_next:;
    if (db.open) node_db_close(&db);
    return failures;
}

enum fwm_fault_kind { FWM_FAULT_CHAIN, FWM_FAULT_SEQ, FWM_FAULT_COMMIT, FWM_FAULT_INSERT };
struct fwm_fault { enum fwm_fault_kind kind; bool armed, prefix; unsigned reads, hits; };
static bool fwm_read_denied(struct fwm_fault *f, const char *column)
{
    static const char *const columns[] = {"id", "chain_prev", "chain_hash"};
    if (f->reads < 3) f->prefix = f->prefix && !strcmp(column, columns[f->reads]);
    bool deny = (f->kind == FWM_FAULT_CHAIN && f->reads == 2 && f->prefix) ||
        (f->kind == FWM_FAULT_SEQ && f->reads == 0 && !strcmp(column, "seq"));
    f->reads++;
    return deny;
}
static int fwm_authorizer(void *arg, int action, const char *a, const char *b,
    const char *database, const char *trigger)
{
    (void)database; (void)trigger;
    struct fwm_fault *f = arg;
    if (action == SQLITE_SELECT) { f->reads = 0; f->prefix = true; }
    bool deny = action == SQLITE_TRANSACTION && a && !strcmp(a, "COMMIT") && f->kind == FWM_FAULT_COMMIT;
    if (action == SQLITE_INSERT && a && !strcmp(a, "fleet_board_posts"))
        deny = f->kind == FWM_FAULT_INSERT;
    if (action == SQLITE_READ && a && b && !strcmp(a, "fleet_board_posts")) {
        deny = fwm_read_denied(f, b) || deny;
    }
    if (deny && f->armed) { f->armed = false; f->hits++; return SQLITE_DENY; }
    return SQLITE_OK;
}

static bool fwm_rollback_verified(struct node_db *db, int64_t high,
    bool populated, const struct fwm_fault *fault,
    enum fleet_board_wiki_write_status result)
{
    struct fleet_board_status status;
    return fault->hits == 1 && result == FLEET_WIKI_WRITE_STORAGE &&
        fleet_board_arrival_checkpoint() == high && db_fleet_board_status(db, FWM_NOW, &status) &&
        status.posts == (populated ? 1 : 0);
}

static bool fwm_retry_verified(struct node_db *db, const struct fleet_board_post *next,
    const uint8_t *parent, int64_t high, bool populated)
{
    struct db_fleet_board_post out;
    int64_t checked;
    return fwm_write(db, next, parent, &out) == FLEET_WIKI_WRITE_OK &&
        out.seq == (populated ? 2 : 1) && out.arrival == high + 1 &&
        db_fleet_board_chain_verify(db, &checked) && checked == (populated ? 2 : 1);
}

static bool fwm_fault_case(enum fwm_fault_kind kind, bool populated)
{
    struct node_db db = {0};
    if (!node_db_open(&db, ":memory:")) return false;
    struct fleet_board_post head, next;
    struct db_fleet_board_post out;
    bool ok = fwm_post(&head, 19, "fault-parent", "head", FWM_NOW, NULL);
    if (populated) ok = ok && fwm_write(&db, &head, NULL, &out) == FLEET_WIKI_WRITE_OK;
    ok = ok && fwm_post(&next, 19, "fault-next", "next", FWM_NOW + 1, populated ? head.id : NULL);
    int64_t high = fleet_board_arrival_checkpoint();
    struct fwm_fault fault = {.kind = kind, .armed = true};
    sqlite3_set_authorizer(db.db, fwm_authorizer, &fault);
    enum fleet_board_wiki_write_status result = fwm_write(&db, &next, populated ? head.id : NULL, &out);
    sqlite3_set_authorizer(db.db, NULL, NULL);
    ok = ok && fwm_rollback_verified(&db, high, populated, &fault, result);
    ok = ok && fwm_retry_verified(&db, &next, populated ? head.id : NULL, high, populated);
    node_db_close(&db);
    return ok;
}

static int fwm_storage_cases(void)
{
    int failures = 0;
    TEST("wiki mutation: one-shot head, sequence and commit failures roll back empty and nonempty stores") {
        for (unsigned kind = 0; kind < 3; kind++) {
            ASSERT(fwm_fault_case((enum fwm_fault_kind)kind, false));
            ASSERT(fwm_fault_case((enum fwm_fault_kind)kind, true));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int fwm_sequence_overflow(void)
{
    int failures = 0;
    struct node_db db = {0};
    TEST("wiki mutation: exhausted signed sequence refuses append without wrapping") {
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post head, next;
        struct db_fleet_board_post out;
        ASSERT(fwm_post(&head, 19, "overflow-head", "head", FWM_NOW, NULL));
        ASSERT_EQ(fwm_write(&db, &head, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(node_db_exec(&db, "UPDATE fleet_board_posts SET seq=9223372036854775807"));
        ASSERT(fwm_post(&next, 19, "overflow-next", "next", FWM_NOW + 1, head.id));
        int64_t high = fleet_board_arrival_checkpoint();
        ASSERT_EQ(fwm_write(&db, &next, head.id, &out), FLEET_WIKI_WRITE_STORAGE);
        ASSERT_EQ(fleet_board_arrival_checkpoint(), high);
        struct fleet_board_status status;
        ASSERT(db_fleet_board_status(&db, FWM_NOW, &status));
        ASSERT_EQ(status.posts, 1);
        ASSERT(node_db_exec(&db, "UPDATE fleet_board_posts SET seq=1"));
        ASSERT(fwm_retry_verified(&db, &next, head.id, high, true));
        PASS();
    } _test_next:;
    if (db.open) node_db_close(&db);
    return failures;
}

static bool fwm_eviction_refusal(struct node_db *db, const struct fleet_board_post *first,
    const struct fleet_board_post *second, const struct fleet_board_post *next,
    enum fwm_fault_kind kind)
{
    struct db_fleet_board_post before, after, out;
    if (!db_fleet_board_post_find(db, second->id, &before)) return false;
    int64_t high = fleet_board_arrival_checkpoint();
    struct fwm_fault fault = {.kind = kind, .armed = true};
    sqlite3_set_authorizer(db->db, fwm_authorizer, &fault);
    enum fleet_board_wiki_write_status result = fwm_write(db, next, second->id, &out);
    sqlite3_set_authorizer(db->db, NULL, NULL);
    int64_t checked;
    return fault.hits == 1 && result == FLEET_WIKI_WRITE_STORAGE &&
        fleet_board_arrival_checkpoint() == high && db_fleet_board_have(db, first->id) &&
        db_fleet_board_post_find(db, second->id, &after) &&
        !memcmp(before.chain_hash, after.chain_hash, 32) &&
        db_fleet_board_chain_verify(db, &checked) && checked == 2;
}

static int fwm_eviction_case(void)
{
    int failures = 0;
    struct node_db db = {0};
    TEST("wiki mutation: eviction rollback preserves victim and replay ends when revision evicts") {
        ASSERT(node_db_open(&db, ":memory:"));
        db_fleet_board_test_set_wiki_limits(1000, 2);
        db_fleet_board_test_reset_wiki_evictions();
        struct fleet_board_post first, second, next, replay;
        struct db_fleet_board_post out;
        ASSERT(fwm_post(&first, 19, "evict-first", "first", FWM_NOW, NULL));
        ASSERT_EQ(fwm_write(&db, &first, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_post(&second, 19, "evict-second", "second", FWM_NOW + 1, first.id));
        ASSERT_EQ(fwm_write(&db, &second, first.id, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_post(&next, 19, "evict-next", "next", FWM_NOW + 2, second.id));
        ASSERT(fwm_eviction_refusal(&db, &first, &second, &next, FWM_FAULT_INSERT));
        ASSERT(fwm_eviction_refusal(&db, &first, &second, &next, FWM_FAULT_COMMIT));
        ASSERT_EQ(fwm_write(&db, &next, second.id, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(!db_fleet_board_have(&db, first.id));
        int64_t checked;
        ASSERT(db_fleet_board_chain_verify(&db, &checked));
        ASSERT_EQ(checked, 2);
        ASSERT(fwm_post(&replay, 19, "evict-second", "second", FWM_NOW + 100, first.id));
        ASSERT_EQ(fwm_write(&db, &replay, first.id, &out), FLEET_WIKI_WRITE_REPLAY);
        ASSERT(fwm_post(&replay, 19, "evict-first", "first", FWM_NOW + 100, NULL));
        ASSERT_EQ(fwm_write(&db, &replay, NULL, &out), FLEET_WIKI_WRITE_CONFLICT);
        ASSERT(node_db_begin(&db));
        ASSERT_EQ(fwm_write(&db, &replay, NULL, &out), FLEET_WIKI_WRITE_BUSY);
        ASSERT(node_db_rollback(&db));
        PASS();
    } _test_next:;
    if (db.open) node_db_close(&db);
    db_fleet_board_test_set_wiki_limits(0, 0);
    db_fleet_board_test_reset_wiki_evictions();
    return failures;
}

struct fwm_step_fault { sqlite3_stmt *target; bool armed; unsigned hits; };
static int fwm_interrupt_step(void *arg)
{
    struct fwm_step_fault *fault = arg;
    if (!fault->armed || !sqlite3_stmt_busy(fault->target)) return 0;
    fault->armed = false;
    fault->hits++;
    return 1;
}

static int fwm_head_trace(unsigned event, void *arg, void *statement, void *detail)
{
    (void)detail;
    struct fwm_step_fault *fault = arg;
    if (event == SQLITE_TRACE_PROFILE) {
        if (fault->target == statement) { fault->target = NULL; fault->armed = false; }
        return 0;
    }
    const char *sql = sqlite3_sql(statement);
    if (sql && strstr(sql, "fleet_board_posts") && strstr(sql, "ORDER BY") &&
        strstr(sql, "created_at"))
        { fault->target = statement; fault->armed = true; }
    return 0;
}

static int fwm_head_step_case(void)
{
    int failures = 0;
    struct node_db db = {0};
    TEST("wiki mutation: interrupted strict newest query refuses apparent absence") {
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post post;
        struct db_fleet_board_post out;
        ASSERT(fwm_post(&post, 19, "step-request", "body", FWM_NOW, NULL));
        int64_t high = fleet_board_arrival_checkpoint();
        struct fwm_step_fault fault = {0};
        /* Install before stepping: changing the progress handler inside a
         * trace callback can defer its interval to a later statement. */
        sqlite3_progress_handler(db.db, 1, fwm_interrupt_step, &fault);
        ASSERT_EQ(sqlite3_trace_v2(db.db, SQLITE_TRACE_STMT | SQLITE_TRACE_PROFILE, fwm_head_trace, &fault), SQLITE_OK);
        enum fleet_board_wiki_write_status result = fwm_write(&db, &post, NULL, &out);
        sqlite3_progress_handler(db.db, 0, NULL, NULL);
        ASSERT_EQ(sqlite3_trace_v2(db.db, 0, NULL, NULL), SQLITE_OK);
        ASSERT_EQ(fault.hits, 1);
        ASSERT_EQ(result, FLEET_WIKI_WRITE_STORAGE);
        ASSERT_EQ(fleet_board_arrival_checkpoint(), high);
        struct fleet_board_status status;
        ASSERT(db_fleet_board_status(&db, FWM_NOW, &status));
        ASSERT_EQ(status.posts, 0);
        ASSERT(fwm_retry_verified(&db, &post, NULL, high, false));
        PASS();
    } _test_next:;
    if (db.open) {
        sqlite3_progress_handler(db.db, 0, NULL, NULL);
        (void)sqlite3_trace_v2(db.db, 0, NULL, NULL);
        node_db_close(&db);
    }
    return failures;
}

static bool fwm_review(struct fleet_board_post *post, unsigned author,
    const char *marker, const struct fleet_board_post *target, int64_t now,
    const uint8_t *parent)
{
    char hex[65], body[512];
    fleet_board_id_to_hex(target->id, hex);
    (void)snprintf(body, sizeof(body),
        "{\"schema\":\"zcl.fleet_wiki_review.v1\",\"target\":\"%s\","
        "\"verdict\":\"approve\",\"rating\":5,\"rationale\":\"Reviewed exact bytes\"}", hex);
    if (!fwm_post(post, author, marker, body, now, parent)) return false;
    memcpy(post->ref, target->id, 32);
    uint8_t seed[32] = {0}, sk[32], pk[32];
    seed[0] = (uint8_t)author; seed[31] = 71;
    ed25519_keypair(pk, sk, seed);
    return fleet_board_post_sign(post, sk, pk) == FLEET_BOARD_OK;
}

static int fwm_review_admission(void)
{
    int failures = 0;
    struct node_db db = {0};
    TEST("wiki review: exact targets, independent signers and guarded updates") {
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post target, other, review, second, update, retry;
        struct db_fleet_board_post out;
        ASSERT(fwm_post(&target, 18, "review-target", "exact target", FWM_NOW, NULL));
        ASSERT_EQ(fwm_write(&db, &target, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_review(&review, 19, "review-first", &target, FWM_NOW + 1, NULL));
        ASSERT_EQ(fwm_write(&db, &review, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_review(&second, 20, "review-second", &target, FWM_NOW + 2, NULL));
        ASSERT_EQ(fwm_write(&db, &second, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(db_fleet_board_wiki_read(&db, target.slug, &out));
        ASSERT(memcmp(out.post.id, target.id, 32) == 0);
        ASSERT(fwm_review(&update, 19, "review-update", &target, FWM_NOW + 3, review.id));
        ASSERT_EQ(fwm_write(&db, &update, review.id, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_review(&retry, 19, "review-stale", &target, FWM_NOW + 4, review.id));
        ASSERT_EQ(fwm_write(&db, &retry, review.id, &out), FLEET_WIKI_WRITE_CONFLICT);
        ASSERT(fwm_review(&retry, 19, "review-update", &target, FWM_NOW + 5, review.id));
        ASSERT_EQ(fwm_write(&db, &retry, review.id, &out), FLEET_WIKI_WRITE_REPLAY);
        ASSERT(memcmp(out.post.id, update.id, 32) == 0);
        ASSERT(fwm_post(&other, 18, "review-target-other", "another target", FWM_NOW + 6, target.id));
        /* Generic page behavior stays unchanged; use a distinct slug because
         * the review fixtures deliberately share the target slug. */
        (void)snprintf(other.slug, sizeof(other.slug), "other-target");
        uint8_t seed[32] = {0}, sk[32], pk[32];
        seed[0] = 18; seed[31] = 71;
        ed25519_keypair(pk, sk, seed);
        memset(other.supersedes, 0, 32);
        ASSERT_EQ(fleet_board_post_sign(&other, sk, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fwm_write(&db, &other, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_review(&retry, 19, "review-retarget", &other, FWM_NOW + 7, update.id));
        ASSERT_EQ(fwm_write(&db, &retry, update.id, &out), FLEET_WIKI_WRITE_REFUSED);
        ASSERT(fwm_review(&retry, 19, "review-room", &target, FWM_NOW + 8, update.id));
        (void)snprintf(retry.room, sizeof(retry.room), "other-room");
        seed[0] = 19; ed25519_keypair(pk, sk, seed);
        ASSERT_EQ(fleet_board_post_sign(&retry, sk, pk), FLEET_BOARD_OK);
        ASSERT_EQ(fwm_write(&db, &retry, update.id, &out), FLEET_WIKI_WRITE_REFUSED);
        review.text[review.text_len - 2] ^= 1;
        ASSERT_EQ(fwm_write(&db, &review, NULL, &out), FLEET_WIKI_WRITE_REFUSED);
        PASS();
    } _test_next:;
    if (db.open) node_db_close(&db);
    return failures;
}

static int fwm_review_peer_order(void)
{
    int failures = 0;
    struct node_db db = {0};
    TEST("wiki review: peer-before-target retention, duplicate import and corrupt target refusal") {
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post target, review, retry;
        struct db_fleet_board_post out;
        ASSERT(fwm_post(&target, 18, "peer-target", "target bytes", FWM_NOW, NULL));
        ASSERT(fwm_review(&review, 19, "peer-review", &target, FWM_NOW + 1, NULL));
        bool stored = false;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &review, FWM_NOW + 1, &stored), FLEET_BOARD_OK);
        ASSERT(stored);
        ASSERT(db_fleet_board_post_find(&db, review.id, &out));
        stored = true;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &review, FWM_NOW + 1, &stored), FLEET_BOARD_OK);
        ASSERT(!stored);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &target, FWM_NOW + 1, &stored), FLEET_BOARD_OK);
        ASSERT(stored);
        ASSERT(db_fleet_board_post_find(&db, target.id, &out));
        ASSERT(node_db_exec(&db, "UPDATE fleet_board_posts SET text='corrupt target' WHERE receipt='peer-target'"));
        ASSERT(fwm_review(&retry, 19, "corrupt-review", &target, FWM_NOW + 2, review.id));
        ASSERT_EQ(fwm_write(&db, &retry, review.id, &out), FLEET_WIKI_WRITE_REFUSED);
        ASSERT(fwm_review(&retry, 19, "peer-review", &target, FWM_NOW + 3, NULL));
        ASSERT_EQ(fwm_write(&db, &retry, NULL, &out), FLEET_WIKI_WRITE_REPLAY);
        ASSERT(memcmp(out.post.id, review.id, 32) == 0);
        PASS();
    } _test_next:;
    if (db.open) node_db_close(&db);
    return failures;
}


static bool fwm_review_resign(struct fleet_board_post *post, unsigned author)
{
    uint8_t seed[32] = {0}, sk[32], pk[32];
    seed[0] = (uint8_t)author; seed[31] = 71;
    ed25519_keypair(pk, sk, seed);
    return fleet_board_post_sign(post, sk, pk) == FLEET_BOARD_OK;
}

static int fwm_review_boundaries(void)
{
    int failures = 0;
    zcl_fleet_role_checker_install_permissive_for_testing();
    struct node_db db = {0};
    TEST("wiki review: signed ref, rating, private scope and reviewer lineage are bound") {
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post target, private_target, review, bad;
        struct db_fleet_board_post out;
        ASSERT(fwm_post(&target, 18, "boundary-target", "target", FWM_NOW, NULL));
        ASSERT_EQ(fwm_write(&db, &target, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_review(&review, 19, "boundary-review", &target, FWM_NOW + 1, NULL));
        ASSERT_EQ(fwm_write(&db, &review, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_review(&bad, 20, "forged-parent", &target, FWM_NOW + 2, review.id));
        ASSERT_EQ(fwm_write(&db, &bad, review.id, &out), FLEET_WIKI_WRITE_REFUSED);
        ASSERT(fwm_review(&bad, 19, "forged-ref", &target, FWM_NOW + 3, review.id));
        bad.ref[0] ^= 1;
        ASSERT(fwm_review_resign(&bad, 19));
        ASSERT_EQ(fwm_write(&db, &bad, review.id, &out), FLEET_WIKI_WRITE_REFUSED);
        bool stored = false;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &bad, FWM_NOW + 3, &stored), FLEET_BOARD_ERR_TEXT);
        ASSERT(!stored);
        ASSERT(fwm_review(&bad, 19, "bad-rating", &target, FWM_NOW + 4, review.id));
        char *rating = strstr(bad.text, "\"rating\":5");
        ASSERT(rating != NULL); rating[9] = '6';
        ASSERT(fwm_review_resign(&bad, 19));
        ASSERT_EQ(fwm_write(&db, &bad, review.id, &out), FLEET_WIKI_WRITE_REFUSED);
        ASSERT(fwm_post(&private_target, 18, "private-target", "private target", FWM_NOW + 5, NULL));
        private_target.scope = FLEET_BOARD_SCOPE_FLEET;
        private_target.room[0] = '\0';
        (void)snprintf(private_target.slug, sizeof(private_target.slug), "private-target");
        ASSERT(fwm_review_resign(&private_target, 18));
        ASSERT_EQ(fwm_write(&db, &private_target, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_review(&bad, 19, "private-leak", &private_target, FWM_NOW + 6, NULL));
        ASSERT_EQ(fwm_write(&db, &bad, NULL, &out), FLEET_WIKI_WRITE_REFUSED);
        PASS();
    } _test_next:;
    if (db.open) node_db_close(&db);
    return failures;
}


static int fwm_review_queries(void)
{
    int failures = 0;
    struct node_db db = {0};
    TEST("wiki review: unresolved arrival resolves, graph forks paginate and explicit leaves survive clock reversal") {
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post target, root, left, right, next, plain, orphan, child;
        struct db_fleet_board_post out;
        struct fleet_wiki_review_state state;
        bool stored = false;
        ASSERT(fwm_post(&target, 18, "query-target", "target", FWM_NOW, NULL));
        ASSERT(fwm_review(&root, 19, "query-root", &target, FWM_NOW + 1, NULL));
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &root, FWM_NOW + 1, &stored), FLEET_BOARD_OK);
        ASSERT(db_fleet_board_review_state(&db, &root, &state));
        ASSERT(!state.resolved);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &target, FWM_NOW + 1, &stored), FLEET_BOARD_OK);
        ASSERT(db_fleet_board_review_state(&db, &root, &state));
        ASSERT(state.resolved && state.lineage_valid && state.complete && state.current && !state.fork);
        struct fleet_board_post private_review;
        ASSERT(fwm_review(&private_review, 22, "query-private", &target, FWM_NOW + 1, NULL));
        private_review.scope = FLEET_BOARD_SCOPE_FLEET; private_review.room[0] = 0;
        ASSERT(fwm_review_resign(&private_review, 22));
        zcl_fleet_role_checker_install_permissive_for_testing();
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &private_review, FWM_NOW + 1, &stored), FLEET_BOARD_OK);
        private_review.scope = FLEET_BOARD_SCOPE_PUBLIC;
        (void)snprintf(private_review.room, sizeof(private_review.room), "other-room");
        ASSERT(fwm_review_resign(&private_review, 22));
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &private_review, FWM_NOW + 1, &stored), FLEET_BOARD_OK);
        ASSERT(fwm_review(&left, 19, "query-left", &target, FWM_NOW + 10, root.id));
        ASSERT(fwm_review(&right, 19, "query-right", &target, FWM_NOW + 2, root.id));
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &left, FWM_NOW + 10, &stored), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &right, FWM_NOW + 10, &stored), FLEET_BOARD_OK);
        ASSERT(db_fleet_board_review_state(&db, &right, &state));
        ASSERT(state.current && state.fork && state.complete);
        uint8_t cursor[32] = {0}, next_cursor[32];
        size_t seen = 0, count = 0;
        bool more = true;
        while (more && seen < 8) {
            struct db_fleet_board_post page[1];
            ASSERT(db_fleet_board_wiki_reviews(&db, target.id, cursor, page, 1, &count, next_cursor, &more));
            ASSERT_EQ(count, 1);
            ASSERT_EQ(page[0].post.scope, FLEET_BOARD_SCOPE_PUBLIC);
            ASSERT(strcmp(page[0].post.room, FLEET_BOARD_ROOM_DEFAULT) == 0);
            ASSERT(memcmp(next_cursor, page[0].post.id, 32) == 0);
            ASSERT(memcmp(page[0].post.id, cursor, 32) > 0);
            memcpy(cursor, next_cursor, 32);
            seen += count;
        }
        ASSERT_EQ(seen, 3); ASSERT(!more);
        ASSERT(fwm_post(&plain, 19, "query-plain-ref", "ordinary referenced page", FWM_NOW + 100, NULL));
        memcpy(plain.ref, target.id, 32);
        ASSERT(fwm_review_resign(&plain, 19));
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &plain, FWM_NOW + 100, &stored), FLEET_BOARD_OK);
        ASSERT(fwm_review(&next, 19, "query-next", &target, FWM_NOW + 11, right.id));
        ASSERT_EQ(fwm_write(&db, &next, right.id, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_review(&next, 19, "query-old-leaf", &target, FWM_NOW + 12, root.id));
        ASSERT_EQ(fwm_write(&db, &next, root.id, &out), FLEET_WIKI_WRITE_CONFLICT);
        uint8_t absent[32]; memset(absent, 0x77, 32);
        ASSERT(fwm_review(&orphan, 21, "query-orphan", &target, FWM_NOW + 3, absent));
        ASSERT(fwm_review(&child, 21, "query-child", &target, FWM_NOW + 4, orphan.id));
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &orphan, FWM_NOW + 4, &stored), FLEET_BOARD_OK);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &child, FWM_NOW + 4, &stored), FLEET_BOARD_OK);
        ASSERT(db_fleet_board_review_state(&db, &child, &state));
        ASSERT(state.resolved && !state.lineage_valid && !state.complete && !state.current);
        PASS();
    } _test_next:;
    if (db.open) node_db_close(&db);
    return failures;
}

static int fwm_review_parser(void)
{
    int failures = 0;
    TEST("wiki review: parser bounds, whitespace, literal escapes and decoded NUL") {
        struct fleet_board_post target, review;
        memset(&target, 0, sizeof(target)); memset(target.id, 0x11, 32);
        ASSERT(fwm_review(&review, 19, "parser", &target, FWM_NOW, NULL));
        struct json_value parsed;
        char raw[1024];
        raw[0] = ' '; raw[1] = '\n';
        memcpy(raw + 2, review.text, review.text_len);
        size_t len = review.text_len + 2;
        raw[len] = 'X'; /* Input is deliberately not NUL-terminated at len. */
        ASSERT_EQ(fleet_wiki_review_parse(raw, len, &parsed, NULL), FLEET_WIKI_REVIEW_VALID);
        json_free(&parsed);
        char hex[65]; fleet_board_id_to_hex(target.id, hex);
        (void)snprintf(raw, sizeof(raw),
            "{\"schema\":\"zcl.fleet_wiki_review.v1\",\"target\":\"%s\","
            "\"verdict\":\"comment\",\"rationale\":\"literal \\\\u0000\"}", hex);
        ASSERT_EQ(fleet_wiki_review_parse(raw, strlen(raw), &parsed, NULL), FLEET_WIKI_REVIEW_VALID);
        json_free(&parsed);
        (void)snprintf(raw, sizeof(raw),
            "{\"schema\":\"zcl.fleet_wiki_review.v1\",\"target\":\"%s\","
            "\"verdict\":\"comment\",\"rationale\":\"hidden \\u0000suffix\"}", hex);
        ASSERT_EQ(fleet_wiki_review_parse(raw, strlen(raw), &parsed, NULL), FLEET_WIKI_NOT_REVIEW);
        ASSERT(!json_valid(raw, strlen(raw)));
        json_free(&parsed);
        (void)snprintf(raw, sizeof(raw), "{\"note\":\"ordinary %cu0000suffix\"}", 0x5c);
        ASSERT_EQ(fleet_wiki_review_parse(raw, strlen(raw), &parsed, NULL), FLEET_WIKI_NOT_REVIEW);
        json_free(&parsed);
        PASS();
    } _test_next:;
    return failures;
}

static int fwm_review_quota(void)
{
    int failures = 0;
    struct node_db db = {0};
    db_fleet_board_test_set_wiki_limits(100, 2);
    db_fleet_board_test_reset_wiki_evictions();
    TEST("wiki review: quota cannot confuse a review fork with superseded page history") {
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post target, first, fork, update;
        struct db_fleet_board_post out;
        ASSERT(fwm_post(&target, 18, "quota-target", "target", FWM_NOW, NULL));
        ASSERT_EQ(fwm_write(&db, &target, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_review(&first, 18, "quota-review", &target, FWM_NOW + 1, NULL));
        ASSERT_EQ(fwm_write(&db, &first, NULL, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(fwm_review(&fork, 18, "quota-fork", &target, FWM_NOW + 2, NULL));
        bool stored = false;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &fork, FWM_NOW + 2, &stored), FLEET_BOARD_ERR_WIKI_FULL);
        ASSERT(!stored);
        ASSERT(db_fleet_board_post_find(&db, target.id, &out));
        ASSERT(fwm_review(&update, 18, "quota-update", &target, FWM_NOW + 3, first.id));
        ASSERT_EQ(fwm_write(&db, &update, first.id, &out), FLEET_WIKI_WRITE_REFUSED);
        ASSERT(db_fleet_board_post_find(&db, target.id, &out));
        ASSERT(db_fleet_board_post_find(&db, first.id, &out));
        struct fleet_wiki_review_state state;
        ASSERT(db_fleet_board_review_state(&db, &first, &state));
        ASSERT(state.resolved && state.complete && state.lineage_valid && state.current);
        db_fleet_board_test_set_wiki_limits(100, 3);
        ASSERT_EQ(fwm_write(&db, &update, first.id, &out), FLEET_WIKI_WRITE_OK);
        ASSERT(db_fleet_board_review_state(&db, &update, &state));
        ASSERT(state.resolved && state.complete && state.lineage_valid && state.current);
        PASS();
    } _test_next:;
    if (db.open) node_db_close(&db);
    db_fleet_board_test_set_wiki_limits(0, 0);
    db_fleet_board_test_reset_wiki_evictions();
    return failures;
}


static bool fwm_rpc_call(struct rpc_table *table, const struct json_value *input,
    struct json_value *result)
{
    struct json_value params;
    json_init(&params); json_set_array(&params);
    bool ok = json_push_back(&params, input) &&
        rpc_table_execute(table, "fleet_board", &params, result);
    json_free(&params);
    return ok;
}

static int fwm_review_rpc(void)
{
    int failures = 0;
    struct node_db db = {0};
    char dir[256] = {0}, warmup[256];
    bool was_warming = rpc_is_in_warmup(warmup, sizeof(warmup));
    TEST("wiki review: existing RPC publishes and retrieves signed exact-target statements") {
        ASSERT(node_db_open(&db, ":memory:"));
        test_make_tmpdir(dir, sizeof(dir), "fleetboard", "review");
        struct db_service service = {.node_db = &db, .started = true};
        struct app_runtime_context runtime = {.db_service = &service};
        struct boot_svc_ctx svc = {.node_db = &db, .datadir = dir};
        boot_fleet_board_shutdown(); boot_fleet_board_wire(&svc);
        app_runtime_set_current(&runtime);
        struct rpc_table table;
        rpc_table_init(&table); boot_fleet_board_register_rpc(&table);
        set_rpc_warmup_finished();
        struct fleet_board_post target, peer;
        ASSERT(fwm_post(&target, 18, "rpc-target", "target", FWM_NOW, NULL));
        ASSERT(fwm_review(&peer, 19, "rpc-peer-review", &target, FWM_NOW + 1, NULL));
        bool stored;
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &peer, FWM_NOW + 1, &stored), FLEET_BOARD_OK);
        char hex[65]; fleet_board_id_to_hex(target.id, hex);
        struct json_value in, result;
        json_init(&in); json_set_object(&in); json_init(&result);
        ASSERT(json_push_kv_str(&in, "op", "wiki_history"));
        ASSERT(json_push_kv_str(&in, "target", hex));
        ASSERT(fwm_rpc_call(&table, &in, &result));
        ASSERT(json_get_bool(json_get(&result, "ok")));
        ASSERT_EQ(json_size(json_get(&result, "posts")), 1);
        const struct json_value *item = json_at(json_get(&result, "posts"), 0);
        ASSERT(!json_get_bool(json_get(item, "target_resolved")));
        json_free(&result); json_init(&result);
        ASSERT_EQ(db_fleet_board_post_ingest(&db, &target, FWM_NOW + 1, &stored), FLEET_BOARD_OK);
        ASSERT(fwm_rpc_call(&table, &in, &result));
        item = json_at(json_get(&result, "posts"), 0);
        ASSERT(json_get_bool(json_get(item, "target_resolved")));
        ASSERT(strcmp(json_get_str(json_get(item, "reviewer")),
            json_get_str(json_get(item, "host"))) == 0);
        json_free(&in); json_free(&result);
        json_init(&in); json_set_object(&in); json_init(&result);
        ASSERT(json_push_kv_str(&in, "op", "post"));
        ASSERT(json_push_kv_str(&in, "kind", "wiki"));
        ASSERT(json_push_kv_str(&in, "slug", "rpc-review"));
        ASSERT(json_push_kv_str(&in, "title", "Exact revision review"));
        ASSERT(json_push_kv_str(&in, "text", peer.text));
        ASSERT(json_push_kv_str(&in, "format", "review"));
        ASSERT(fwm_rpc_call(&table, &in, &result));
        ASSERT(json_get_bool(json_get(&result, "ok")));
        uint8_t published[32];
        ASSERT(fleet_board_id_from_hex(json_get_str(json_get(&result, "id")), published));
        struct db_fleet_board_post retained;
        ASSERT(db_fleet_board_post_find(&db, published, &retained));
        ASSERT_EQ(fleet_board_post_verify(&retained.post), FLEET_BOARD_OK);
        ASSERT(memcmp(retained.post.ref, target.id, 32) == 0);
        json_free(&in); json_free(&result);
        json_init(&in); json_set_object(&in); json_init(&result);
        char malformed[512];
        (void)snprintf(malformed, sizeof(malformed),
            "{\"schema\":\"zcl.fleet_wiki_review.v1\",\"target\":\"%s\","
            "\"verdict\":\"comment\",\"rationale\":\"bad %cu0000suffix\"}", hex, 0x5c);
        ASSERT(json_push_kv_str(&in, "op", "post"));
        ASSERT(json_push_kv_str(&in, "kind", "wiki"));
        ASSERT(json_push_kv_str(&in, "slug", "malformed-review"));
        ASSERT(json_push_kv_str(&in, "title", "Malformed review"));
        ASSERT(json_push_kv_str(&in, "text", malformed));
        ASSERT(json_push_kv_str(&in, "format", "review"));
        ASSERT(fwm_rpc_call(&table, &in, &result));
        ASSERT(!json_get_bool(json_get(&result, "ok")));
        ASSERT(strcmp(json_get_str(json_get(&result, "code")), "BAD_REVIEW") == 0);
        json_free(&in); json_free(&result);
        PASS();
    } _test_next:;
    app_runtime_set_current(NULL);
    if (was_warming) set_rpc_warmup_started(warmup);
    boot_fleet_board_shutdown();
    if (db.open) node_db_close(&db);
    if (dir[0]) test_rm_rf(dir);
    return failures;
}


static unsigned fwm_native_calls;
static char *fwm_native_unexpected_rpc(const char *method, const char *params)
{
    (void)method; (void)params;
    fwm_native_calls++;
    return NULL;
}

static int fwm_review_native_faults(void)
{
    int failures = 0;
    TEST("wiki review: native request construction fails without losing target or continuation") {
        struct json_value input;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "target",
            "1111111111111111111111111111111111111111111111111111111111111111"));
        ASSERT(json_push_kv_str(&input, "after_id",
            "2222222222222222222222222222222222222222222222222222222222222222"));
        bool ok = true;
        node_rpc_client_set_test_hook(fwm_native_unexpected_rpc);
        const char *labels[] = {"json_set_str", "json_push_kv_key"};
        for (unsigned label = 0; label < 2; label++) for (unsigned nth = 1; nth <= (label ? 5u : 3u); nth++) {
            struct zcl_command_request request = {.input = &input, .budget_bytes = 8192,
                .success_data_budget_provided = true, .success_data_budget = 7000};
            struct zcl_command_reply reply;
            zcl_command_reply_init(&reply, "zcl.fleet_board_list.v1");
            size_t before = json_test_live_blocks();
            fwm_native_calls = 0;
            zcl_alloc_fault_fail_nth(labels[label], nth);
            zcl_native_handle_fleet_wiki_history(&request, &reply);
            bool hit = zcl_alloc_fault_armed_label() == NULL;
            zcl_alloc_fault_clear();
            ok = ok && hit && !fwm_native_calls &&
                reply.status != ZCL_COMMAND_STATUS_PASSED &&
                !strcmp(reply.error.code, "REVIEW_REQUEST_FAILED");
            zcl_command_reply_free(&reply);
            ok = ok && json_test_live_blocks() == before;
        }
        node_rpc_client_set_test_hook(NULL);
        json_free(&input);
        ASSERT(ok);
        PASS();
    } _test_next:;
    zcl_alloc_fault_clear();
    node_rpc_client_set_test_hook(NULL);
    return failures;
}


static int fwm_review_missing(void)
{
    int failures = 0;
    struct node_db db = {0};
    TEST("wiki review: local publication refuses a missing exact target") {
        ASSERT(node_db_open(&db, ":memory:"));
        struct fleet_board_post review;
        struct db_fleet_board_post out;
        struct fleet_board_post absent = {0};
        memset(absent.id, 0x11, 32);
        ASSERT(fwm_review(&review, 19, "review-missing", &absent, FWM_NOW, NULL));
        ASSERT_EQ(fwm_write(&db, &review, NULL, &out), FLEET_WIKI_WRITE_REFUSED);
        PASS();
    } _test_next:;
    if (db.open) node_db_close(&db);
    return failures;
}

/* MCP plan/confirm for fleet.wiki.write: the stub node forwards each RPC
 * call to a real fleet_board table so a confirmed write is really stored.
 * fwm_plan_calls counts the write calls; fwm_plan_find's own read restores it. */
static struct rpc_table *fwm_plan_table;
static unsigned fwm_plan_calls;
static char *fwm_plan_rpc(const char *method, const char *params)
{
    struct json_value p, result;
    char *out = NULL;
    (void)method;
    fwm_plan_calls++;
    json_init(&p); json_init(&result);
    if (json_read(&p, params, strlen(params)) && json_at(&p, 0) &&
        fwm_rpc_call(fwm_plan_table, json_at(&p, 0), &result)) {
        size_t n = json_write(&result, NULL, 0);
        out = malloc(n + 1);
        if (out && json_write(&result, out, n + 1) == 0) { free(out); out = NULL; }
    }
    json_free(&p); json_free(&result);
    return out;
}

static bool fwm_plan_call(const struct zcl_command_context *ctx, const char *slug,
    const char *text, const char *plan_id, bool confirm,
    struct zcl_command_reply *reply)
{
    struct json_value in;
    json_init(&in); json_set_object(&in);
    bool ok = json_push_kv_str(&in, "slug", slug) &&
        json_push_kv_str(&in, "title", "Plan write") &&
        json_push_kv_str(&in, "text", text) &&
        (!plan_id || json_push_kv_str(&in, "plan_id", plan_id)) &&
        (!confirm || json_push_kv_bool(&in, "confirm", true));
    struct zcl_command_request request = {.context = ctx, .input = &in,
        .budget_bytes = 8192};
    zcl_command_reply_init(reply, "zcl.fleet_board_post_id.v1");
    if (ok) zcl_native_handle_fleet_wiki_write(&request, reply);
    json_free(&in);
    return ok;
}

static bool fwm_plan_find(const char *slug)
{
    unsigned writes = fwm_plan_calls;
    struct json_value in;
    json_init(&in); json_set_object(&in);
    bool found = json_push_kv_str(&in, "q", slug);
    struct zcl_command_request request = {.input = &in, .budget_bytes = 8192,
        .success_data_budget_provided = true, .success_data_budget = 7000};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.fleet_wiki_find.v1");
    if (found) zcl_native_handle_fleet_wiki_find(&request, &reply);
    found = found && reply.status == ZCL_COMMAND_STATUS_PASSED &&
        json_size(json_get(&reply.data, "entries")) == 1 &&
        !strcmp(json_get_str(json_get(json_at(json_get(&reply.data, "entries"), 0),
            "slug")), slug);
    zcl_command_reply_free(&reply);
    json_free(&in);
    fwm_plan_calls = writes;
    return found;
}

static int fwm_plan_confirm(void)
{
    int failures = 0;
    struct node_db db = {0};
    char dir[256] = {0}, warmup[256];
    bool was_warming = rpc_is_in_warmup(warmup, sizeof(warmup));
    TEST("wiki write: MCP plans without writing, confirms with the plan_id, CLI writes at once") {
        ASSERT(node_db_open(&db, ":memory:"));
        test_make_tmpdir(dir, sizeof(dir), "fleetboard", "planwrite");
        struct db_service service = {.node_db = &db, .started = true};
        struct app_runtime_context runtime = {.db_service = &service};
        struct boot_svc_ctx svc = {.node_db = &db, .datadir = dir};
        boot_fleet_board_shutdown(); boot_fleet_board_wire(&svc);
        app_runtime_set_current(&runtime);
        struct rpc_table table;
        rpc_table_init(&table); boot_fleet_board_register_rpc(&table);
        set_rpc_warmup_finished();
        fwm_plan_table = &table; fwm_plan_calls = 0;
        node_rpc_client_set_test_hook(fwm_plan_rpc);
        struct zcl_command_context mcp = {.plan_first = true};
        struct zcl_command_reply plan, bad, done, cli;
        char id[65];
        ASSERT(fwm_plan_call(&mcp, "plan-write", "first body", NULL, false, &plan));
        ASSERT_EQ(plan.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(fwm_plan_calls, 0);
        ASSERT(!json_get_bool(json_get(&plan.data, "mutated")));
        ASSERT_EQ(json_get_int(json_get(&plan.data, "bytes")), 10);
        ASSERT(!strcmp(json_get_str(json_get(&plan.data, "slug")), "plan-write"));
        snprintf(id, sizeof(id), "%s", json_get_str(json_get(&plan.data, "plan_id")));
        ASSERT_EQ(strlen(id), 64);
        ASSERT(!fwm_plan_find("plan-write"));
        ASSERT(fwm_plan_call(&mcp, "plan-write", "other body", id, true, &bad));
        ASSERT_EQ(bad.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(!strcmp(bad.error.code, "PLAN_MISMATCH"));
        ASSERT_EQ(fwm_plan_calls, 0);
        zcl_command_reply_free(&bad);
        ASSERT(fwm_plan_call(&mcp, "plan-write", "first body", "wrong", true, &bad));
        ASSERT(!strcmp(bad.error.code, "PLAN_MISMATCH"));
        ASSERT_EQ(fwm_plan_calls, 0);
        zcl_command_reply_free(&bad);
        ASSERT(fwm_plan_call(&mcp, "plan-write", "first body", id, true, &done));
        ASSERT_EQ(done.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(fwm_plan_calls, 1);
        ASSERT(fwm_plan_find("plan-write"));
        ASSERT(fwm_plan_call(NULL, "cli-write", "cli body", NULL, false, &cli));
        ASSERT_EQ(cli.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(fwm_plan_calls, 2);
        ASSERT(fwm_plan_find("cli-write"));
        zcl_command_reply_free(&plan); zcl_command_reply_free(&done);
        zcl_command_reply_free(&cli);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    app_runtime_set_current(NULL);
    if (was_warming) set_rpc_warmup_started(warmup);
    boot_fleet_board_shutdown();
    if (db.open) node_db_close(&db);
    if (dir[0]) test_rm_rf(dir);
    return failures;
}

int test_fleet_wiki_mutation(void)
{
    return fwm_plan_confirm() +fwm_review_native_faults() + fwm_review_rpc() + fwm_review_parser() + fwm_review_queries() + fwm_review_quota() + fwm_review_boundaries() + fwm_review_peer_order() + fwm_review_admission() + fwm_review_missing() + fwm_replay_cas() + fwm_race_case() + fwm_storage_cases() +
        fwm_sequence_overflow() + fwm_eviction_case() + fwm_head_step_case();
}
