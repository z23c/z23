/* Unit tests for the address_index script-appearance projection — the backbone
 * that answers "everything script S ever did" without a full-chain scan. Keyed
 * by sha3_256(scriptPubKey) so it catalogs every output type (P2PKH, P2SH,
 * OP_RETURN/ZNAM/ZSLP, nonstandard) uniformly. */

#include "test/test_core.h"
#include "encoding/utilstrencodings.h"

#include "core/uint256.h"
#include "crypto/sha3.h"
#include "jobs/address_index.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "services/address_index_service.h"
#include "services/index_fold_guard.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/util.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AI_CHECK(name, expr) do {                                    \
    if (expr) { printf("  address_index: %s... OK\n", (name)); }     \
    else { printf("  address_index: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* Set tx->hash to a deterministic 32-byte value from `tag`. */
static void ai_set_txid(struct transaction *tx, uint8_t tag)
{
    memset(tx->hash.data, 0, 32);
    tx->hash.data[0] = tag;
    tx->hash.data[31] = 0xEE;
}

/* Give `tx` `nout` outputs; output i carries value[i] and script sc[i]. */
static void ai_set_vouts(struct transaction *tx, size_t nout,
                         const int64_t *values,
                         const unsigned char *const *scripts,
                         const size_t *slens)
{
    tx->num_vout = nout;
    tx->vout = zcl_calloc(nout, sizeof(struct tx_out), "ai_vout");
    for (size_t i = 0; i < nout; i++) {
        tx->vout[i].value = values[i];
        script_set(&tx->vout[i].script_pub_key, scripts[i], slens[i]);
    }
}

/* Give `tx` one input spending (prev_txid, prev_vout). NULL prev_txid => a
 * coinbase-shaped null prevout. */
static void ai_set_spend(struct transaction *tx, const struct uint256 *prev,
                         uint32_t prev_n)
{
    tx->num_vin = 1;
    tx->vin = zcl_calloc(1, sizeof(struct tx_in), "ai_vin");
    tx_in_init(&tx->vin[0]);
    if (prev) {
        tx->vin[0].prevout.hash = *prev;
        tx->vin[0].prevout.n = prev_n;
    }
}

/* Query one scripthash and return count + balance + (optional) first row. */
static int ai_query(sqlite3 *db, const uint8_t sh[32], int64_t *balance,
                    struct json_value *first_row_out)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    int n = address_index_query_appearances(db, sh, 0,
                                             ADDRESS_INDEX_QUERY_MAX_ROWS,
                                             &arr, balance);
    if (n > 0 && first_row_out) {
        const struct json_value *r0 = json_at(&arr, 0);
        json_init(first_row_out);
        if (r0)
            json_copy(first_row_out, r0);
    }
    json_free(&arr);
    return n;
}

/* Holds the progress-store lock on a NON-test thread. The mutex is RECURSIVE,
 * so a same-thread hold would let the guard's trylock succeed and prove
 * nothing. Announces acquisition, then waits to be told to release. */
struct ai_seed_lock_helper {
    pthread_mutex_t m;
    pthread_cond_t  cv;
    int             held;          /* 0 = not yet, 1 = held, 2 = please release */
};

static void *ai_seed_lock_holder(void *arg)
{
    struct ai_seed_lock_helper *h = (struct ai_seed_lock_helper *)arg;
    progress_store_tx_lock();
    pthread_mutex_lock(&h->m);
    h->held = 1;
    pthread_cond_signal(&h->cv);
    while (h->held != 2)
        pthread_cond_wait(&h->cv, &h->m);
    pthread_mutex_unlock(&h->m);
    progress_store_tx_unlock();
    return NULL;
}

int test_address_index(void);
int test_address_index(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "address_index", "main");

    AI_CHECK("progress_store opens", progress_store_open(dir));
    /* Wave A2 split: the address_index fold + keyed dumper query run on the
     * projection handle. Open it (same physical file) so the dumper assertions
     * below observe the rows the raw primitives commit. */
    AI_CHECK("projection_store opens", projection_store_open(dir));
    /* A4/A3 physical split: address_index is a projection table written and read
     * through the projection handle (progress.kv), a DIFFERENT file from the
     * consensus.db kernel. Fold + dump on that handle so they see the same rows. */
    sqlite3 *db = projection_store_db();
    AI_CHECK("db handle", db != NULL);

    /* OMNISCIENCE default: with no -addressindex arg the projection is ON so a
     * plain boot builds the script-appearance catalog. */
    {
        const char *noargs[] = { "test" };
        ParseParameters(1, noargs);
        address_index_enabled_reset_for_test();
        AI_CHECK("enabled by default (omniscience)", address_index_enabled());
    }
    /* Off-switch: -addressindex=0 fully disables; boot registration is then a
     * clean no-op — pays zero cost. */
    {
        const char *offargs[] = { "test", "-addressindex=0" };
        ParseParameters(2, offargs);
        address_index_enabled_reset_for_test();
        AI_CHECK("-addressindex=0 disables", !address_index_enabled());
        AI_CHECK("register no-op when disabled",
                 !address_index_service_register() &&
                 !address_index_service_registered());
    }
    /* Restore default-on (arg cleared) for the observable-gate assertions below;
     * the raw DB primitives don't depend on the gate. */
    {
        const char *noargs[] = { "test" };
        ParseParameters(1, noargs);
        address_index_enabled_reset_for_test();
    }

    /* Cursor read before schema exists is a clean cursor=-1 (not an error). */
    {
        int64_t c = 999;
        AI_CHECK("cursor before schema -> -1",
                 address_index_get_cursor(db, &c) && c == -1);
    }

    AI_CHECK("ensure_schema", address_index_ensure_schema(db));
    AI_CHECK("ensure_schema idempotent", address_index_ensure_schema(db));

    /* ── scripts (exercise every classification branch) ──────────── */
    unsigned char scA[25]; /* P2PKH */
    scA[0] = 0x76; scA[1] = 0xa9; scA[2] = 20;
    for (int i = 0; i < 20; i++) scA[3 + i] = (unsigned char)(0x10 + i);
    scA[23] = 0x88; scA[24] = 0xac;

    unsigned char scB[8] = { 0x6a, 'Z','N','A','M', 0x01, 0x02, 0x03 }; /* OP_RETURN */
    unsigned char scC[5] = { 0x51, 0x52, 0x53, 0x54, 0x55 };            /* nonstandard */
    unsigned char scD[25]; /* another P2PKH */
    scD[0] = 0x76; scD[1] = 0xa9; scD[2] = 20;
    for (int i = 0; i < 20; i++) scD[3 + i] = (unsigned char)(0xA0 + i);
    scD[23] = 0x88; scD[24] = 0xac;

    uint8_t shA[32], shB[32], shC[32], shD[32];
    address_index_scripthash(scA, sizeof(scA), shA);
    address_index_scripthash(scB, sizeof(scB), shB);
    address_index_scripthash(scC, sizeof(scC), shC);
    address_index_scripthash(scD, sizeof(scD), shD);

    /* scripthash is exactly sha3_256(scriptPubKey), and distinct per script. */
    {
        uint8_t ref[32];
        sha3_256(scA, sizeof(scA), ref);
        AI_CHECK("scripthash == sha3_256(script)", memcmp(shA, ref, 32) == 0);
        AI_CHECK("distinct scripthashes",
                 memcmp(shA, shB, 32) && memcmp(shA, shC, 32) &&
                 memcmp(shA, shD, 32) && memcmp(shB, shC, 32));
    }

    /* ── block 100: coinbase(A) + tx_p(B,C) ──────────────────────── */
    struct block blk100; block_init(&blk100);
    blk100.num_vtx = 2;
    blk100.vtx = zcl_calloc(2, sizeof(struct transaction), "b100");
    transaction_init(&blk100.vtx[0]);
    transaction_init(&blk100.vtx[1]);
    ai_set_txid(&blk100.vtx[0], 0xC0); /* coinbase, txid CB */
    ai_set_txid(&blk100.vtx[1], 0x50); /* txid P */
    ai_set_spend(&blk100.vtx[0], NULL, 0);            /* coinbase null prevout */
    {
        struct uint256 dummy; uint256_set_null(&dummy); dummy.data[0] = 0x77;
        ai_set_spend(&blk100.vtx[1], &dummy, 0);      /* spends a non-indexed prevout */
    }
    {
        int64_t vA[1] = { 1000 };
        const unsigned char *sA[1] = { scA }; size_t lA[1] = { sizeof(scA) };
        ai_set_vouts(&blk100.vtx[0], 1, vA, sA, lA);
        int64_t vBC[2] = { 0, 2000 };
        const unsigned char *sBC[2] = { scB, scC };
        size_t lBC[2] = { sizeof(scB), sizeof(scC) };
        ai_set_vouts(&blk100.vtx[1], 2, vBC, sBC, lBC);
    }

    /* ── block 101: tx_s spends (CB,0) -> creates D ───────────────── */
    struct block blk101; block_init(&blk101);
    blk101.num_vtx = 1;
    blk101.vtx = zcl_calloc(1, sizeof(struct transaction), "b101");
    transaction_init(&blk101.vtx[0]);
    ai_set_txid(&blk101.vtx[0], 0x51); /* txid S */
    ai_set_spend(&blk101.vtx[0], &blk100.vtx[0].hash, 0); /* spends A's output */
    {
        int64_t vD[1] = { 900 };
        const unsigned char *sD[1] = { scD }; size_t lD[1] = { sizeof(scD) };
        ai_set_vouts(&blk101.vtx[0], 1, vD, sD, lD);
    }

    /* Fold ascending, maintaining the running digest. */
    uint8_t digest[32]; memset(digest, 0, 32);
    int added100 = 0, added101 = 0;
    AI_CHECK("put block 100",
             address_index_put_block(db, &blk100, 100, digest, &added100));
    AI_CHECK("block 100 added 3 rows", added100 == 3);
    uint8_t digest_after_100[32]; memcpy(digest_after_100, digest, 32);
    AI_CHECK("digest advanced after block 100",
             memcmp(digest_after_100, (uint8_t[32]){0}, 32) != 0);
    AI_CHECK("put block 101",
             address_index_put_block(db, &blk101, 101, digest, &added101));
    AI_CHECK("block 101 added 1 row", added101 == 1);
    AI_CHECK("digest advanced after block 101",
             memcmp(digest, digest_after_100, 32) != 0);
    uint8_t digest_full[32]; memcpy(digest_full, digest, 32);

    /* ── appearance + spent-link correctness ─────────────────────── */
    {
        int64_t bal = -1;
        struct json_value row;
        int n = ai_query(db, shA, &bal, &row);
        AI_CHECK("A: one appearance", n == 1);
        bool spent = n == 1 && json_get_bool(json_get(&row, "spent"));
        AI_CHECK("A: spent", spent);
        AI_CHECK("A: value 1000",
                 n == 1 && json_get_int(json_get(&row, "value")) == 1000);
        AI_CHECK("A: height 100",
                 n == 1 && json_get_int(json_get(&row, "height")) == 100);
        AI_CHECK("A: spent_height 101",
                 n == 1 && json_get_int(json_get(&row, "spent_height")) == 101);
        /* spent_by_txid must equal S (block101 tx0). */
        char shex[65];
        HexStr(blk101.vtx[0].hash.data, 32, false, shex, sizeof(shex));
        AI_CHECK("A: spent_by == S",
                 n == 1 &&
                 strcmp(json_get_str(json_get(&row, "spent_by_txid")), shex) == 0);
        AI_CHECK("A: balance 0 (spent)", bal == 0);
        if (n == 1) json_free(&row);
    }
    {
        int64_t bal = -1;
        struct json_value row;
        int n = ai_query(db, shB, &bal, &row); /* OP_RETURN indexed */
        AI_CHECK("B: OP_RETURN indexed (one appearance)", n == 1);
        AI_CHECK("B: script_type OP_RETURN(2)",
                 n == 1 && json_get_int(json_get(&row, "script_type")) == 2);
        if (n == 1) json_free(&row);
    }
    {
        int64_t bal = -1;
        struct json_value row;
        int n = ai_query(db, shC, &bal, &row);
        AI_CHECK("C: unspent, balance 2000", n == 1 && bal == 2000);
        AI_CHECK("C: not spent",
                 n == 1 && !json_get_bool(json_get(&row, "spent")));
        if (n == 1) json_free(&row);
    }
    {
        int64_t bal = -1;
        int n = ai_query(db, shD, &bal, NULL);
        AI_CHECK("D: unspent at h101, balance 900", n == 1 && bal == 900);
    }
    {
        uint8_t shX[32];
        unsigned char noscript[3] = { 0xde, 0xad, 0xbe };
        address_index_scripthash(noscript, 3, shX);
        int64_t bal = -1;
        AI_CHECK("absent scripthash -> 0 rows",
                 ai_query(db, shX, &bal, NULL) == 0 && bal == 0);
    }

    /* Row count reflects the 4 outputs across both blocks. */
    AI_CHECK("row_count == 4", address_index_row_count(db) == 4);

    /* ── idempotent re-fold PRESERVES rows + spent links ─────────── */
    /* Row writes are INSERT OR IGNORE, so re-folding a block adds no rows and
     * never clobbers a spent link recorded by a later block (the digest is a
     * forward-only running chain and is NOT expected to be idempotent — a full
     * rebuild's determinism is asserted separately below). */
    {
        uint8_t d2[32]; memcpy(d2, digest, 32);
        int added = -1;
        AI_CHECK("re-put block 100 idempotent (rows)",
                 address_index_put_block(db, &blk100, 100, d2, &added));
        AI_CHECK("re-put added 0 rows (IGNORE)", added == 0);
        int64_t bal = -1;
        struct json_value row;
        int n = ai_query(db, shA, &bal, &row);
        AI_CHECK("A still spent after re-put",
                 n == 1 && json_get_bool(json_get(&row, "spent")));
        AI_CHECK("A balance still 0 after re-put", bal == 0);
        if (n == 1) json_free(&row);
    }

    /* ── cursor + digest persist round-trip ──────────────────────── */
    AI_CHECK("set_cursor", address_index_set_cursor(db, 101, digest_full));
    {
        int64_t c = -1;
        AI_CHECK("get_cursor == 101",
                 address_index_get_cursor(db, &c) && c == 101);
        uint8_t dg[32]; bool found = false;
        AI_CHECK("get_digest matches",
                 address_index_get_digest(db, dg, &found) && found &&
                 memcmp(dg, digest_full, 32) == 0);
    }

    /* ── drop-and-rederive is deterministic (rebuildable) ────────── */
    AI_CHECK("drop", address_index_drop(db));
    AI_CHECK("row_count 0 after drop", address_index_row_count(db) == 0);
    {
        int64_t c = 999;
        AI_CHECK("cursor -1 after drop",
                 address_index_get_cursor(db, &c) && c == -1);
    }
    AI_CHECK("re-ensure_schema", address_index_ensure_schema(db));
    {
        uint8_t d[32]; memset(d, 0, 32);
        int a1 = 0, a2 = 0;
        AI_CHECK("refold block 100",
                 address_index_put_block(db, &blk100, 100, d, &a1));
        AI_CHECK("refold block 101",
                 address_index_put_block(db, &blk101, 101, d, &a2));
        AI_CHECK("rederived digest identical",
                 memcmp(d, digest_full, 32) == 0);
        AI_CHECK("rederived row_count == 4",
                 address_index_row_count(db) == 4);
    }

    /* ── dumpstate keyed query smoke test ────────────────────────── */
    {
        char hex[65];
        HexStr(shC, 32, false, hex, sizeof(hex));
        struct json_value out;
        json_init(&out);
        AI_CHECK("dump keyed query returns true",
                 address_index_dump_state_json(&out, hex));
        AI_CHECK("dump: enabled true (omniscience default)",
                 json_get_bool(json_get(&out, "enabled")));
        AI_CHECK("dump: count 1 for C",
                 json_get_int(json_get(&out, "count")) == 1);
        AI_CHECK("dump: balance 2000 for C",
                 json_get_int(json_get(&out, "balance")) == 2000);
        json_free(&out);

        json_init(&out);
        AI_CHECK("dump status (no key) returns true",
                 address_index_dump_state_json(&out, NULL));
        AI_CHECK("dump status has rows key",
                 json_get(&out, "rows") != NULL);
        json_free(&out);

        json_init(&out);
        AI_CHECK("dump bad key -> error, no crash",
                 address_index_dump_state_json(&out, "not-a-scripthash") &&
                 json_get(&out, "error") != NULL);
        json_free(&out);
    }

    /* ── throughput measurement on a synthetic fixture ───────────── */
    {
        AI_CHECK("drop for perf fixture", address_index_drop(db));
        AI_CHECK("schema for perf fixture", address_index_ensure_schema(db));
        const int N = 400;          /* blocks */
        /* enum, not `const int`: a const-qualified object is not a constant
         * expression in C, so `int64_t vals[OUTS]` below would be a VLA. */
        enum { OUTS = 4 };          /* outputs per block */
        uint8_t d[32]; memset(d, 0, 32);
        sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
        int64_t t0 = platform_time_monotonic_us();
        int total_rows = 0;
        for (int h = 0; h < N; h++) {
            struct block b; block_init(&b);
            b.num_vtx = 1;
            b.vtx = zcl_calloc(1, sizeof(struct transaction), "perf_vtx");
            transaction_init(&b.vtx[0]);
            b.vtx[0].hash.data[0] = (uint8_t)(h & 0xff);
            b.vtx[0].hash.data[1] = (uint8_t)((h >> 8) & 0xff);
            b.vtx[0].hash.data[2] = 0x9a;
            ai_set_spend(&b.vtx[0], NULL, 0);
            int64_t vals[OUTS];
            unsigned char bufs[OUTS][12];
            const unsigned char *sp[OUTS];
            size_t sl[OUTS];
            for (int k = 0; k < OUTS; k++) {
                vals[k] = 100 + h * 10 + k;
                for (int j = 0; j < 12; j++)
                    bufs[k][j] = (unsigned char)(h + k + j);
                sp[k] = bufs[k];
                sl[k] = 12;
            }
            ai_set_vouts(&b.vtx[0], OUTS, vals, sp, sl);
            int add = 0;
            if (address_index_put_block(db, &b, 200 + h, d, &add))
                total_rows += add;
            transaction_free(&b.vtx[0]);
            free(b.vtx);
        }
        int64_t elapsed_us = platform_time_monotonic_us() - t0;
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
        AI_CHECK("perf fixture folded all rows", total_rows == N * OUTS);
        double secs = (double)elapsed_us / 1e6;
        double rps = secs > 0 ? (double)total_rows / secs : 0;
        double bps = secs > 0 ? (double)N / secs : 0;
        printf("  address_index: THROUGHPUT %d rows across %d blocks in "
               "%.3f ms => %.0f rows/s, %.0f blocks/s\n",
               total_rows, N, (double)elapsed_us / 1000.0, rps, bps);
        AI_CHECK("perf: nonzero throughput", rps > 0);
    }

    /* ── backfill safety rails (index_fold_guard) ────────────────
     * These are the always-on hardening: never fill the disk, never spin below
     * a snapshot-seed floor — both surface a NAMED typed blocker. */
    {
        blocker_reset_for_testing();

        /* Disk precheck OK when the free-space floor is 0. */
        index_fold_set_min_free_for_test(0);
        AI_CHECK("disk_ok true with 0-byte floor",
                 index_fold_disk_ok("address_index", "address_index", dir));
        AI_CHECK("no disk_low blocker when healthy",
                 !blocker_exists("address_index.disk_low"));

        /* Force LOW: an impossibly high floor makes any real FS "too low". */
        index_fold_set_min_free_for_test(INT64_MAX);
        AI_CHECK("disk_ok false when below floor",
                 !index_fold_disk_ok("address_index", "address_index", dir));
        AI_CHECK("address_index.disk_low blocker raised",
                 blocker_exists("address_index.disk_low"));
        AI_CHECK("disk_low blocker is RESOURCE class",
                 blocker_class_for("address_index.disk_low") == BLOCKER_RESOURCE);

        /* Recover: floor back to 0 clears the blocker. */
        index_fold_set_min_free_for_test(0);
        AI_CHECK("disk_ok true after recovery",
                 index_fold_disk_ok("address_index", "address_index", dir));
        AI_CHECK("disk_low blocker cleared after recovery",
                 !blocker_exists("address_index.disk_low"));
        index_fold_set_min_free_for_test(-1);   /* restore default */

        /* Seed floor: with NO trusted-base-height key, an absent body is a
         * transient gap, not a below-seed floor — no seed blocker. */
        index_fold_note_absent_body("address_index", "address_index", db, 0);
        AI_CHECK("no seed blocker without a snapshot seed",
                 !blocker_exists("address_index.below_snapshot_seed"));

        /* Install a snapshot-seed floor at height 1000. */
        {
            int64_t base = 1000;
            uint8_t blob[8];
            for (int i = 0; i < 8; i++)
                blob[i] = (uint8_t)((uint64_t)base >> (8 * i));
            /* A4: the seed floor is a kernel fact — write it to the kernel
             * store (progress_store_db), where the guard now reads it. */
            AI_CHECK("write trusted_base_height=1000",
                     progress_meta_set(progress_store_db(),
                                       REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                                       blob, sizeof(blob)));
        }
        /* An absent body BELOW the seed floor raises the named DEPENDENCY. */
        index_fold_note_absent_body("address_index", "address_index", db, 500);
        AI_CHECK("below-seed absent body raises below_snapshot_seed",
                 blocker_exists("address_index.below_snapshot_seed"));
        AI_CHECK("below_snapshot_seed is DEPENDENCY class",
                 blocker_class_for("address_index.below_snapshot_seed") ==
                 BLOCKER_DEPENDENCY);
        /* An absent body ABOVE the seed floor is transient — clears it. */
        index_fold_note_absent_body("address_index", "address_index", db, 1500);
        AI_CHECK("above-seed absent body clears below_snapshot_seed",
                 !blocker_exists("address_index.below_snapshot_seed"));
        /* Explicit clear is idempotent. */
        index_fold_note_absent_body("address_index", "address_index", db, 500);
        index_fold_clear_seed_blocker("address_index");
        AI_CHECK("clear_seed_blocker removes it",
                 !blocker_exists("address_index.below_snapshot_seed"));

        /* ── LOCK-ORDER LAW: the seed-floor read must YIELD, never block ──
         *
         * Regression for the 2026-07-27 crash loop. This read runs on the
         * supervisor tick-runner thread, which dispatches every child
         * synchronously and stamps its heartbeat only between rounds. When it
         * took a BLOCKING progress-store lock it parked behind the reducer
         * drive's fold commit (120-330 s at tip), the runner heartbeat froze,
         * the systemd keepalive was withheld, and the node was SIGABRT'd at the
         * 120 s limit — seven kills in forty minutes on a node that was folding
         * blocks correctly the whole time.
         *
         * Completing at all proves non-blocking: against the pre-fix code this
         * case DEADLOCKS (measured: killed at 300 s, signal 9). The yield
         * counter proves the trylock path is the reason, with no timing
         * assertion to go flaky under load. */
        {
            struct ai_seed_lock_helper h = {
                PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0
            };
            pthread_t tid;
            int rc = pthread_create(&tid, NULL, ai_seed_lock_holder, &h);
            AI_CHECK("seed-yield: helper thread spawned", rc == 0);

            if (rc == 0) {
                pthread_mutex_lock(&h.m);
                while (h.held == 0)
                    pthread_cond_wait(&h.cv, &h.m);
                pthread_mutex_unlock(&h.m);

                /* The "reducer" (helper) owns the lock. This call MUST return. */
                uint64_t y0 = index_fold_seed_floor_yields();
                index_fold_note_absent_body("address_index", "address_index",
                                            db, 500);
                uint64_t y1 = index_fold_seed_floor_yields();

                AI_CHECK("seed-yield: read yielded instead of blocking",
                         y1 == y0 + 1);
                /* A yield must be a NO-OP: it may not invent or clear state
                 * from a floor it could not read. */
                AI_CHECK("seed-yield: blocker state untouched by a yield",
                         !blocker_exists("address_index.below_snapshot_seed"));

                int64_t f = 0;
                AI_CHECK("seed-yield: snapshot_seed_floor reports unknown",
                         !index_fold_snapshot_seed_floor(&f) && f == -1);

                pthread_mutex_lock(&h.m);
                h.held = 2;
                pthread_cond_signal(&h.cv);
                pthread_mutex_unlock(&h.m);
                pthread_join(tid, NULL);

                /* Lock free again: the very same call now reads the floor and
                 * raises the blocker — proving the yield was the lock, not a
                 * broken read path. */
                index_fold_note_absent_body("address_index", "address_index",
                                            db, 500);
                AI_CHECK("seed-yield: same call works once the lock is free",
                         blocker_exists("address_index.below_snapshot_seed"));
                index_fold_clear_seed_blocker("address_index");
            }
        }

        blocker_reset_for_testing();
    }

    /* cleanup */
    for (size_t i = 0; i < blk100.num_vtx; i++)
        transaction_free(&blk100.vtx[i]);
    free(blk100.vtx);
    transaction_free(&blk101.vtx[0]);
    free(blk101.vtx);
    projection_store_close();
    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}
