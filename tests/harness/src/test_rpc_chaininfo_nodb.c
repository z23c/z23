/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * getblockcount, getbestblockhash and getblockchaininfo must keep answering
 * while the node.db connection mutex (or cs_main) is held by a stuck thread.
 * A helper thread holds the lock behind a latch; each handler must return
 * within RCN_BOUND_MS with the correct height and hash from the fixture
 * chain, and any field that needs the held lock must be reported unavailable
 * (never a guessed value). Once the latch is released the full normal reply
 * comes back. Every helper thread is joined, including on failure paths. */

#include "test/test_core.h"

#include "controllers/blockchain_controller.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "models/block.h"
#include "models/database.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

bool rpc_getblockchaininfo(const struct json_value *params, bool help,
                           struct json_value *result);
bool rpc_getblockcount(const struct json_value *params, bool help,
                       struct json_value *result);
bool rpc_getbestblockhash(const struct json_value *params, bool help,
                          struct json_value *result);

#define RCN_BOUND_MS 2000
/* The helper gives up holding after this long so a regressed (blocking)
 * handler still terminates and the test reports FAIL instead of hanging. */
#define RCN_HOLD_CAP_MS 4000

#define RCN_CHECK(name, expr) do {                              \
    printf("rpc_chaininfo_nodb: %s... ", (name));               \
    if (expr) { printf("OK\n"); }                               \
    else { printf("FAIL\n"); failures++; }                      \
} while (0)

struct rcn_holder {
    sqlite3_mutex *db_mutex;       /* held when non-NULL */
    zcl_mutex_t *cs;               /* held when non-NULL */
    atomic_bool held;
    atomic_bool release;
    pthread_t th;
    bool started;
};

static int64_t rcn_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void rcn_sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void *rcn_holder_main(void *arg)
{
    struct rcn_holder *h = arg;
    if (h->db_mutex) sqlite3_mutex_enter(h->db_mutex);
    if (h->cs) zcl_mutex_lock(h->cs);
    atomic_store(&h->held, true);
    int64_t deadline = rcn_now_ms() + RCN_HOLD_CAP_MS;
    while (!atomic_load(&h->release) && rcn_now_ms() < deadline)
        rcn_sleep_ms(5);
    if (h->cs) zcl_mutex_unlock(h->cs);
    if (h->db_mutex) sqlite3_mutex_leave(h->db_mutex);
    return NULL;
}

static bool rcn_hold_start(struct rcn_holder *h)
{
    atomic_store(&h->held, false);
    atomic_store(&h->release, false);
    h->started = pthread_create(&h->th, NULL, rcn_holder_main, h) == 0;
    if (!h->started) return false;
    int64_t deadline = rcn_now_ms() + 2000;
    while (!atomic_load(&h->held) && rcn_now_ms() < deadline)
        rcn_sleep_ms(2);
    return atomic_load(&h->held);
}

static void rcn_hold_stop(struct rcn_holder *h)
{
    atomic_store(&h->release, true);
    if (h->started) pthread_join(h->th, NULL);
    h->started = false;
}

typedef bool (*rcn_fn)(const struct json_value *, bool, struct json_value *);

/* Call a handler; returns elapsed ms, *ok = handler return value. */
static int64_t rcn_call(rcn_fn fn, struct json_value *res, bool *ok)
{
    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    json_init(res);
    int64_t t0 = rcn_now_ms();
    *ok = fn(&params, false, res);
    int64_t dt = rcn_now_ms() - t0;
    json_free(&params);
    return dt;
}

static bool rcn_str_is(const struct json_value *v, const char *want)
{
    const char *s = v ? json_get_str(v) : NULL;
    return s && strcmp(s, want) == 0;
}

static bool rcn_unavailable_lists(const struct json_value *res, const char *name)
{
    const struct json_value *u = json_get(res, "unavailable");
    if (!u) return false;
    for (size_t i = 0; i < json_size(u); i++)
        if (rcn_str_is(json_at(u, i), name)) return true;
    return false;
}

/* Check all three handlers against the fixture tip. */
static int rcn_check_in_memory(const char *tag, int height, const char *hex)
{
    int failures = 0;
    char name[96];
    struct json_value res;
    bool ok;
    int64_t dt;

    dt = rcn_call(rpc_getblockcount, &res, &ok);
    snprintf(name, sizeof(name), "%s: getblockcount fast + correct", tag);
    RCN_CHECK(name, ok && dt < RCN_BOUND_MS && json_get_int(&res) == height);
    json_free(&res);

    dt = rcn_call(rpc_getbestblockhash, &res, &ok);
    snprintf(name, sizeof(name), "%s: getbestblockhash fast + correct", tag);
    RCN_CHECK(name, ok && dt < RCN_BOUND_MS && rcn_str_is(&res, hex));
    json_free(&res);

    dt = rcn_call(rpc_getblockchaininfo, &res, &ok);
    snprintf(name, sizeof(name), "%s: getblockchaininfo fast + correct", tag);
    RCN_CHECK(name, ok && dt < RCN_BOUND_MS &&
              json_get_int(json_get(&res, "blocks")) == height &&
              rcn_str_is(json_get(&res, "bestblockhash"), hex));
    json_free(&res);
    return failures;
}

int test_rpc_chaininfo_nodb(void);
int test_rpc_chaininfo_nodb(void)
{
    printf("\n=== chain-height RPCs without node.db / cs_main ===\n");
    int failures = 0;

    test_reset_shared_globals();

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool dbok = node_db_open(&ndb, ":memory:");
    RCN_CHECK("fixture: in-memory node_db opens", dbok);
    if (!dbok) return failures;

    struct main_state ms;
    main_state_init(&ms);

    /* Fixture chain 0..2 with real hashes; tip is height 2. */
    struct block_index b[3];
    char hex[3][65];
    for (int i = 0; i < 3; i++) {
        block_index_init(&b[i]);
        b[i].nHeight = i;
        b[i].pprev = i ? &b[i - 1] : NULL;
        b[i].nTime = 1700000000u + (uint32_t)i * 150u;
        b[i].nBits = 0x1f07ffffu;
        snprintf(hex[i], sizeof(hex[i]),
                 "%064x", 0xabc000u + (unsigned)i);
        uint256_set_hex(&b[i].hashBlock, hex[i]);
        b[i].phashBlock = &b[i].hashBlock;
    }
    active_chain_move_window_tip(&ms.chain_active, &b[2]);
    ms.pindex_best_header = &b[2];
    reducer_frontier_provable_tip_set(2);
    rpc_blockchain_set_state(&ms, NULL, NULL);

    /* node.db row at the tip height, for the DB-fallback phase. */
    struct db_block row;
    memset(&row, 0, sizeof(row));
    uint256_get_hex(&b[2].hashBlock, hex[2]);
    {
        struct uint256 h2 = b[2].hashBlock;
        memcpy(row.hash, h2.data, 32);
        row.height = 2;
        row.prev_hash[0] = 1;
        row.merkle_root[0] = 1;
        row.time = b[2].nTime;
        row.bits = b[2].nBits;
        row.status = 3;
        static uint8_t sol[1] = { 1 };
        row.solution = sol;
        row.solution_len = sizeof(sol);
    }
    bool saved = db_block_save(&ndb, &row);
    RCN_CHECK("fixture: node.db block row saved", saved);

    struct rcn_holder h;
    memset(&h, 0, sizeof(h));
    struct json_value res;
    bool ok;
    int64_t dt;

    /* ── Phase 1: node.db mutex held, chain in memory ─────────────── */
    rpc_blockchain_set_state(&ms, NULL, NULL);
    rpc_blockchain_set_node_db(&ndb);
    h.db_mutex = sqlite3_db_mutex(ndb.db);
    h.cs = NULL;
    if (rcn_hold_start(&h)) {
        failures += rcn_check_in_memory("db held", 2, hex[2]);
        dt = rcn_call(rpc_getblockchaininfo, &res, &ok);
        RCN_CHECK("db held: getblockchaininfo needs no node.db field",
                  ok && !json_get(&res, "unavailable") &&
                  json_get(&res, "initialblockdownload") != NULL);
        json_free(&res);
    } else {
        RCN_CHECK("db held: helper acquired node.db mutex", false);
    }
    rcn_hold_stop(&h);

    /* ── Phase 2: tip hash only in node.db, mutex held ────────────── */
    b[2].phashBlock = NULL;
    if (rcn_hold_start(&h)) {
        dt = rcn_call(rpc_getbestblockhash, &res, &ok);
        RCN_CHECK("db-only hash, db held: getbestblockhash returns fast",
                  dt < RCN_BOUND_MS);
        RCN_CHECK("db-only hash, db held: unavailable, never a wrong hash",
                  !ok && !rcn_str_is(&res, "") &&
                  json_get_str(&res) != NULL &&
                  strcmp(json_get_str(&res), hex[2]) != 0);
        json_free(&res);
    } else {
        RCN_CHECK("db-only hash: helper acquired node.db mutex", false);
    }
    rcn_hold_stop(&h);
    dt = rcn_call(rpc_getbestblockhash, &res, &ok);
    RCN_CHECK("db-only hash, released: full normal reply from node.db",
              ok && rcn_str_is(&res, hex[2]));
    json_free(&res);
    b[2].phashBlock = &b[2].hashBlock;

    /* ── Phase 3: cs_main held (IBD latch not yet set) ────────────── */
    h.db_mutex = NULL;
    h.cs = &ms.cs_main;
    if (rcn_hold_start(&h)) {
        dt = rcn_call(rpc_getblockchaininfo, &res, &ok);
        RCN_CHECK("cs_main held: getblockchaininfo returns fast, tip correct",
                  ok && dt < RCN_BOUND_MS &&
                  json_get_int(json_get(&res, "blocks")) == 2 &&
                  rcn_str_is(json_get(&res, "bestblockhash"), hex[2]));
        RCN_CHECK("cs_main held: initialblockdownload marked unavailable",
                  json_get(&res, "initialblockdownload") == NULL &&
                  rcn_unavailable_lists(&res, "initialblockdownload"));
        json_free(&res);
        failures += rcn_check_in_memory("cs_main held", 2, hex[2]);
    } else {
        RCN_CHECK("cs_main held: helper acquired cs_main", false);
    }
    rcn_hold_stop(&h);
    dt = rcn_call(rpc_getblockchaininfo, &res, &ok);
    RCN_CHECK("released: full normal getblockchaininfo",
              ok && json_get(&res, "initialblockdownload") != NULL &&
              !json_get(&res, "unavailable") &&
              json_get(&res, "chainwork") != NULL &&
              json_get(&res, "verificationprogress") != NULL);
    json_free(&res);

    rpc_blockchain_set_node_db(NULL);
    node_db_close(&ndb);
    return failures;
}
