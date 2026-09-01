/* Unit tests for coins_ram — the flag-gated in-RAM UTXO hot store for the bulk
 * fold (storage/coins_ram.h).
 *
 * THE load-bearing assertion: the SHA3 commitment over the EFFECTIVE set
 * (coins_ram_commitment, RAM overlay merged over the durable coins_kv) is
 * BYTE-IDENTICAL to coins_kv_commitment over the same logical set folded
 * straight into SQLite. That identity is what keeps the from-genesis fold
 * SELF-VERIFYING against the compiled checkpoint when the in-RAM store is on.
 *
 * Also covers: read-through (a cold miss reads the durable set), tombstone
 * shadowing (a spend of a durable coin reads ABSENT before flush), flush
 * durability (after flush the overlay is empty and coins_kv holds the truth),
 * and the crash-replay watermark (coins_ram_reconcile_boot rewinds an ahead
 * cursor to the last durable flush).
 *
 * The flag is read once from ZCL_FOLD_INRAM and cached, so this whole group
 * runs in the flag-ON process (test_parallel forks per group).
 *
 * THE identity proof is self-contained: the commitment over the FULL overlay
 * (nothing durable yet) must equal the commitment AFTER a flush (everything
 * durable, overlay empty — i.e. the pure SQLite coins_kv_commitment path). If
 * the overlay-merge encoder and the SQLite encoder ever diverged a byte, these
 * two roots would differ. */

#include "test/test_core.h"

#include "coins/coins.h"
#include "core/uint256.h"
#include "script/script.h"
#include "storage/coins_kv.h"
#include "storage/coins_ram.h"
#include "storage/progress_store.h"
#include "util/stage.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#define CR_CHECK(name, expr) do {                                       \
    if (expr) { printf("  coins_ram: %s... OK\n", (name)); }            \
    else { printf("  coins_ram: %s... FAIL\n", (name)); failures++; }   \
} while (0)

static struct uint256 cr_txid(uint8_t tag)
{
    struct uint256 t; uint256_set_null(&t);
    t.data[0] = tag; t.data[1] = 0x5A; t.data[31] = 0xA5;
    return t;
}

static int64_t cr_scalar_i64(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *s = NULL;
    int64_t out = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW)
            out = sqlite3_column_int64(s, 0);
        sqlite3_finalize(s);
    }
    return out;
}

/* One logical mutation in a deterministic fold script. */
struct fold_op { bool spend; uint8_t tag; uint32_t vout; int64_t value;
                 int32_t height; bool cb; uint8_t script[8]; size_t slen; };

/* A from-"genesis" fold script that creates several coins, then spends some,
 * including a create-then-spend within the same window (must NOT survive). */
static const struct fold_op SCRIPT[] = {
    { false, 0x01, 0, 5000, 10, true,  {0xA0,0xA1},      2 },
    { false, 0x01, 1, 6000, 10, true,  {0xB0,0xB1,0xB2}, 3 },
    { false, 0x02, 0, 7000, 11, false, {0xC0},           1 },
    { false, 0x03, 0, 8000, 12, false, {0},              0 },  /* empty script */
    { false, 0x04, 0, 9000, 13, false, {0xD0,0xD1},      2 },
    { true,  0x02, 0, 0,    0,  false, {0},              0 },  /* spend a live coin */
    { false, 0x05, 0, 1234, 14, false, {0xE0},           1 },
    { true,  0x05, 0, 0,    0,  false, {0},              0 },  /* create-then-spend */
    { false, 0x04, 1, 4321, 15, false, {0xF0,0xF1,0xF2}, 3 },
    { true,  0x01, 0, 0,    0,  false, {0},              0 },  /* spend coinbase out */
};
#define SCRIPT_N (sizeof(SCRIPT) / sizeof(SCRIPT[0]))

/* Apply the script through the PUBLIC coins_kv API (overlay-routed when the
 * flag is on, raw SQLite when off). */
static void apply_script_public(sqlite3 *db)
{
    for (size_t i = 0; i < SCRIPT_N; i++) {
        const struct fold_op *o = &SCRIPT[i];
        struct uint256 t = cr_txid(o->tag);
        if (o->spend)
            coins_kv_spend(db, t.data, o->vout);
        else
            coins_kv_add(db, t.data, o->vout, o->value, o->height, o->cb,
                         o->slen ? o->script : NULL, o->slen);
    }
}

/* ── A/B + multi-flush extension scaffolding ───────────────────────────────
 *
 * The original test above proves the overlay-vs-flushed IDENTITY within ONE
 * overlay leg. The two sections that follow close the gaps the task names:
 *  (a) a TRUE flag-OFF (pure-SQLite, overlay never initialised) leg vs a
 *      flag-ON overlay leg, asserting coins_kv_commitment() is byte-identical.
 *  (b) MULTI-FLUSH: overlay merged over an already-populated durable set, with
 *      cross-flush tombstones (spend of a coin that was flushed in a PRIOR
 *      flush) and a re-add over a durably-flushed key.
 *
 * Both reuse a wider op type than `struct fold_op`: a full 32-byte txid is
 * derived from a u32 tag so we can mint many distinct coins, and `flush==true`
 * marks a flush boundary (a no-op on the pure-SQLite leg, a real
 * coins_ram_flush on the overlay leg). */
struct ab_op {
    enum { AB_ADD, AB_SPEND, AB_FLUSH } kind;
    uint32_t tag;        /* seeds the txid */
    uint32_t vout;
    int64_t  value;
    int32_t  height;     /* also used as the flush watermark for OP_FLUSH */
    bool     cb;
    uint8_t  script[12];
    size_t   slen;
};

/* Deterministic 32-byte txid from a u32 tag — spreads bytes so the open-
 * addressed probe and the SQLite WITHOUT ROWID B-tree both see well-mixed
 * keys (and so distinct tags never collide). */
static struct uint256 ab_txid(uint32_t tag)
{
    struct uint256 t; uint256_set_null(&t);
    t.data[0]  = (uint8_t)(tag);
    t.data[1]  = (uint8_t)(tag >> 8);
    t.data[2]  = (uint8_t)(tag >> 16);
    t.data[3]  = (uint8_t)(tag >> 24);
    t.data[7]  = 0x5A;
    t.data[15] = (uint8_t)(tag * 2654435761u);          /* knuth mix */
    t.data[23] = (uint8_t)((tag * 2654435761u) >> 8);
    t.data[31] = 0xA5;
    return t;
}

/* Apply ONE op through the public coins_kv API. On the overlay leg the caller
 * passes overlay=true so OP_FLUSH drains the overlay; on the pure-SQLite leg
 * overlay=false and OP_FLUSH is a no-op (rows are already durable). Returns
 * false on any failed mutation/flush. */
static bool ab_apply_one(sqlite3 *db, const struct ab_op *o, bool overlay)
{
    struct uint256 t = ab_txid(o->tag);
    switch (o->kind) {
    case AB_ADD:
        return coins_kv_add(db, t.data, o->vout, o->value, o->height, o->cb,
                            o->slen ? o->script : NULL, o->slen);
    case AB_SPEND:
        return coins_kv_spend(db, t.data, o->vout);
    case AB_FLUSH:
        if (overlay) return coins_ram_flush(o->height);
        return true;  /* pure-SQLite: nothing buffered, already durable */
    }
    return false;
}

/* Run the whole op list. `overlay` chooses the leg. Returns the number of
 * failed ops (0 == clean). */
static int ab_apply_all(sqlite3 *db, const struct ab_op *ops, size_t n,
                        bool overlay)
{
    int fails = 0;
    for (size_t i = 0; i < n; i++)
        if (!ab_apply_one(db, &ops[i], overlay)) fails++;
    return fails;
}

/* Cross-thread reader for the UAF-guard test (section d): spawns a fresh
 * pthread, reads coins_ram_writer_thread() on THAT thread (whose _Thread_local
 * counter is 0 because the new thread never called _enter), and reports the
 * result back. Models the bg-validation / RPC-pool reader that must take the
 * SQLite path, not the lock-free overlay. */
struct cr_reader_arg { bool is_writer; };

static void *cr_reader_thread(void *p)
{
    struct cr_reader_arg *a = p;
    a->is_writer = coins_ram_writer_thread();
    return NULL;
}

/* Mint-drive marker gate: an UNMARKED reader thread (no writer bracket, no mint
 * drive marker) must take the durable SQLite path — coins_kv_get returns what
 * lives in coins_kv, invisible to any overlay tombstone. Used to prove the
 * marker gates overlay visibility per-thread. */
struct cr_md_arg { sqlite3 *db; const uint8_t *txid; bool present; bool drive; };
static void *cr_md_reader_thread(void *p)
{
    struct cr_md_arg *a = p;
    int64_t v = 0; size_t sl = 0; uint8_t sb[8];
    a->drive = coins_ram_mint_drive_thread();  /* expect false: fresh thread */
    a->present = coins_kv_get(a->db, a->txid, 0, &v, sb, sizeof(sb), &sl);
    return NULL;
}

int test_coins_ram(void);
int test_coins_ram(void)
{
    int failures = 0;

    /* Force the flag ON before the first coins_ram_enabled() (cached once). */
    setenv("ZCL_FOLD_INRAM", "1", 1);
    CR_CHECK("flag enabled", coins_ram_enabled());

    /* ── overlay fold: bind the overlay to a coins_kv handle and apply via the
     *    PUBLIC API (routed into the overlay) ── */
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "coins_ram_main", "main");
    CR_CHECK("ov: progress_store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    CR_CHECK("ov: db handle", db != NULL);
    CR_CHECK("ov: schema", coins_kv_ensure_schema(db));
    CR_CHECK("ov: init", coins_ram_init(
                 db, 1000000, coins_kv_set_applied_height_in_tx));
    CR_CHECK("ov: active", coins_ram_active());

    /* This test thread is the SINGLE WRITER driving the overlay (it mirrors the
     * reducer's fold). Bracket the overlay-driving region so the coins_kv_*
     * READ shims route to the overlay (the UAF guard's contract — a non-writer
     * thread transparently takes the SQLite path). */
    coins_ram_writer_enter();
    apply_script_public(db);

    /* The overlay is the effective set. Compute its commitment. */
    uint8_t ov_root[32] = {0};
    CR_CHECK("ov: commitment ok", coins_kv_commitment(db, ov_root) == 0);

    /* Determinism / stability: a second commitment over the unchanged overlay
     * must be identical. */
    uint8_t ov_root2[32] = {0};
    CR_CHECK("ov: commitment stable", coins_kv_commitment(db, ov_root2) == 0 &&
             memcmp(ov_root, ov_root2, 32) == 0);

    /* Read semantics over the effective set (before any flush): */
    int64_t v = 0; size_t sl = 0; uint8_t sbuf[16] = {0};
    struct uint256 t1 = cr_txid(0x01), t2 = cr_txid(0x02), t4 = cr_txid(0x04),
                   t5 = cr_txid(0x05);
    CR_CHECK("read: t1.0 spent -> absent",
             !coins_kv_get(db, t1.data, 0, &v, sbuf, sizeof(sbuf), &sl));
    CR_CHECK("read: t1.1 live",
             coins_kv_get(db, t1.data, 1, &v, sbuf, sizeof(sbuf), &sl) &&
             v == 6000 && sl == 3);
    CR_CHECK("read: t2.0 spent -> absent",
             !coins_kv_exists(db, t2.data, 0));
    CR_CHECK("read: t4.0 live", coins_kv_exists(db, t4.data, 0));
    CR_CHECK("read: t4.1 live", coins_kv_exists(db, t4.data, 1));
    CR_CHECK("read: t5.0 create-then-spend -> absent",
             !coins_kv_exists(db, t5.data, 0));

    /* Effective live count: created 7 outputs (t1.0,t1.1,t2.0,t3.0,t4.0,t5.0,
     * t4.1), spent t2.0,t5.0,t1.0 -> 4 live. */
    CR_CHECK("count: 4 live before flush", coins_kv_count(db) == 4);

    /* get_coins reconstruction for t4 (two live vouts 0 and 1). */
    struct coins c4; coins_init(&c4);
    bool g4 = coins_kv_get_coins(db, t4.data, &c4);
    CR_CHECK("get_coins: t4 has >=2 vouts", g4 && c4.num_vout >= 2 &&
             coins_is_available(&c4, 0) && coins_is_available(&c4, 1));
    coins_free(&c4);

    /* ── coins_ram_get_prevout: O(1) point resolver must return the SAME four
     *    fields (value/script/height/is_coinbase) as the get_coins
     *    reconstruction for a LIVE overlay coin, ABSENT for a spent/tombstoned
     *    coin, and ABSENT for a never-created vout. This is the fast path
     *    projection_live_lookup now routes through; it must be byte-identical
     *    to the reconstruction path it replaces. ── */
    {
        int64_t  pv = 0; size_t pl = 0; int32_t ph = -1; bool pcb = true;
        uint8_t  pbuf[16] = {0};
        /* t4.1 is LIVE in the overlay: value=4321, height=15, cb=false,
         * script {0xF0,0xF1,0xF2} (3 bytes) — from SCRIPT[8]. */
        bool h41 = coins_ram_get_prevout(t4.data, 1, &pv, pbuf, sizeof(pbuf),
                                         &pl, &ph, &pcb);
        CR_CHECK("prevout: t4.1 live hit", h41);
        CR_CHECK("prevout: t4.1 value==4321", h41 && pv == 4321);
        CR_CHECK("prevout: t4.1 script_len==3", h41 && pl == 3);
        CR_CHECK("prevout: t4.1 script bytes",
                 h41 && pbuf[0] == 0xF0 && pbuf[1] == 0xF1 && pbuf[2] == 0xF2);
        CR_CHECK("prevout: t4.1 height==15", h41 && ph == 15);
        CR_CHECK("prevout: t4.1 is_coinbase==false", h41 && !pcb);

        /* t4.0 is LIVE: value=9000, height=13, cb=false, script {0xD0,0xD1}. */
        int64_t  pv0 = 0; size_t pl0 = 0; int32_t ph0 = -1; bool pcb0 = true;
        uint8_t  pbuf0[16] = {0};
        bool h40 = coins_ram_get_prevout(t4.data, 0, &pv0, pbuf0, sizeof(pbuf0),
                                         &pl0, &ph0, &pcb0);
        CR_CHECK("prevout: t4.0 live hit", h40 && pv0 == 9000 && ph0 == 13 &&
                 !pcb0 && pl0 == 2 && pbuf0[0] == 0xD0 && pbuf0[1] == 0xD1);

        /* t1.0 was SPENT (tombstoned) -> ABSENT. */
        int32_t junk_h = 7; bool junk_cb = true;
        bool h10 = coins_ram_get_prevout(t1.data, 0, NULL, NULL, 0, NULL,
                                         &junk_h, &junk_cb);
        CR_CHECK("prevout: t1.0 spent -> absent", !h10);

        /* t5.0 create-then-spend -> ABSENT. */
        bool h50 = coins_ram_get_prevout(t5.data, 0, NULL, NULL, 0, NULL,
                                         NULL, NULL);
        CR_CHECK("prevout: t5.0 create-then-spend -> absent", !h50);

        /* never-created vout on a live txid -> ABSENT. */
        bool h4x = coins_ram_get_prevout(t4.data, 99, NULL, NULL, 0, NULL,
                                         NULL, NULL);
        CR_CHECK("prevout: t4.99 never-created -> absent", !h4x);
    }

    /* ── FLUSH: drain the overlay into coins_kv, then the overlay is empty and
     *    reads fall through to the (now-complete) durable set. ── */
    uint8_t pre_flush_root[32];
    memcpy(pre_flush_root, ov_root, 32);
    CR_CHECK("flush: ok", coins_ram_flush(20));

    /* After the flush the overlay holds nothing; coins_kv_count now reads the
     * durable set directly (overlay still active but empty). */
    CR_CHECK("count: 4 live after flush", coins_kv_count(db) == 4);

    /* Commitment IDENTITY: the post-flush effective commitment (overlay empty,
     * all rows durable) must equal the pre-flush effective commitment (overlay
     * full, nothing durable). This is the from-genesis self-verify guarantee:
     * the SHA3 is independent of WHEN the overlay was flushed. */
    uint8_t post_flush_root[32] = {0};
    CR_CHECK("commitment ok post-flush",
             coins_kv_commitment(db, post_flush_root) == 0);
    CR_CHECK("IDENTITY: pre-flush root == post-flush root",
             memcmp(pre_flush_root, post_flush_root, 32) == 0);

    /* The durable cursor + watermark moved to the flushed height. */
    int32_t applied = -1; bool found = false;
    CR_CHECK("applied frontier read",
             coins_kv_get_applied_height(db, &applied, &found));
    CR_CHECK("applied frontier == flushed+1", found && applied == 21);
    CR_CHECK("stale flush after newer commit is a no-op", coins_ram_flush(19));
    applied = -1; found = false;
    CR_CHECK("stale flush cannot rewind applied frontier",
             coins_kv_get_applied_height(db, &applied, &found) &&
             found && applied == 21 && coins_kv_count(db) == 4);

    /* ── coins_applied_height bound check (Wave N hardening, FORWARD_PLAN.md
     * item 7): the stored width is int64 but every reader treats the value
     * as int32_t. A corrupted blob decoding outside int32_t range must be a
     * hard read error, never a silently-truncated in-range-looking height. */
    {
        uint8_t out_of_range[8];
        int64_t huge = (int64_t)INT32_MAX + 1;  /* one past the valid range */
        for (int i = 0; i < 8; i++)
            out_of_range[i] = (uint8_t)(((uint64_t)huge) >> (8 * i));
        CR_CHECK("applied_height bound: corrupt blob written",
                 progress_meta_set(db, COINS_APPLIED_HEIGHT_KEY,
                                   out_of_range, sizeof(out_of_range)));
        int32_t bad_applied = -1; bool bad_found = true;
        CR_CHECK("applied_height bound: out-of-range value REFUSED",
                 !coins_kv_get_applied_height(db, &bad_applied, &bad_found));
        CR_CHECK("applied_height bound: found not stamped true on refusal",
                 !bad_found);

        /* Restore the real (in-range) value so the rest of this test group
         * keeps reading a valid applied frontier. */
        uint8_t restore[8];
        int64_t good = 21;
        for (int i = 0; i < 8; i++)
            restore[i] = (uint8_t)(((uint64_t)good) >> (8 * i));
        CR_CHECK("applied_height bound: restored valid blob",
                 progress_meta_set(db, COINS_APPLIED_HEIGHT_KEY,
                                   restore, sizeof(restore)));
        int32_t restored = -1; bool restored_found = false;
        CR_CHECK("applied_height bound: restored value reads back ok",
                 coins_kv_get_applied_height(db, &restored, &restored_found) &&
                 restored_found && restored == 21);
    }

    /* ── crash-replay reconcile: simulate the cursor advancing PAST the last
     *    flush (a crash between flushes), then reconcile must rewind it. ── */
    {
        progress_store_tx_lock();
        sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
        sqlite3_stmt *s = NULL;
        sqlite3_prepare_v2(db,
            "INSERT INTO stage_cursor(name,cursor,updated_at) "
            "VALUES('utxo_apply', 99, 0) "
            "ON CONFLICT(name) DO UPDATE SET cursor=99", -1, &s, NULL);
        sqlite3_step(s); sqlite3_finalize(s);
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
        progress_store_tx_unlock();
    }
    CR_CHECK("reconcile: ok", coins_ram_reconcile_boot(
                 db, coins_kv_set_applied_height_in_tx));
    {
        progress_store_tx_lock();
        sqlite3_stmt *s = NULL;
        int64_t cur = -1;
        if (sqlite3_prepare_v2(db,
                "SELECT cursor FROM stage_cursor WHERE name='utxo_apply'",
                -1, &s, NULL) == SQLITE_OK) {
            if (sqlite3_step(s) == SQLITE_ROW) cur = sqlite3_column_int64(s, 0);
            sqlite3_finalize(s);
        }
        progress_store_tx_unlock();
        /* watermark was 20 -> cursor rewound to 21 (watermark+1). */
        CR_CHECK("reconcile: cursor rewound to watermark+1 (21)", cur == 21);
    }
    /* If the process stopped cleanly enough to flush the first replay height,
     * cursor can already equal watermark+1 while stale replay-domain rows above
     * it remain from the pre-flush RAM tail. A mint/refold marker means those
     * downstream rows must still be purged before resuming. */
    {
        progress_store_tx_lock();
        sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
        sqlite3_exec(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) "
            "VALUES('refold_in_progress',x'01');"
            "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
            "height INTEGER PRIMARY KEY, status TEXT NOT NULL, "
            "ok INTEGER NOT NULL, spent_count INTEGER NOT NULL, "
            "added_count INTEGER NOT NULL, "
            "total_value_delta INTEGER NOT NULL, "
            "first_failure_kind TEXT, first_failure_detail BLOB, "
            "applied_at INTEGER NOT NULL);"
            "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
            "height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL, "
            "spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL);"
            "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
            "height INTEGER PRIMARY KEY, status TEXT NOT NULL, "
            "ok INTEGER NOT NULL, work_delta_high INTEGER NOT NULL, "
            "work_delta_low INTEGER NOT NULL, "
            "utxo_size_after INTEGER NOT NULL, "
            "reorg_depth INTEGER NOT NULL, finalized_at INTEGER NOT NULL, "
            "tip_hash BLOB);"
            "CREATE TABLE IF NOT EXISTS nullifiers ("
            "nf BLOB NOT NULL, pool INTEGER NOT NULL, "
            "height INTEGER NOT NULL, PRIMARY KEY(nf,pool)) "
            "WITHOUT ROWID;"
            "CREATE TABLE IF NOT EXISTS sprout_anchors ("
            "anchor BLOB PRIMARY KEY NOT NULL, "
            "height INTEGER NOT NULL, tree BLOB NOT NULL) "
            "WITHOUT ROWID;"
            "CREATE TABLE IF NOT EXISTS sapling_anchors ("
            "anchor BLOB PRIMARY KEY NOT NULL, "
            "height INTEGER NOT NULL, tree BLOB NOT NULL) "
            "WITHOUT ROWID;"
            "CREATE TABLE IF NOT EXISTS anchor_state ("
            "pool INTEGER PRIMARY KEY NOT NULL, "
            "activation_cursor INTEGER NOT NULL) WITHOUT ROWID;"
            "INSERT OR REPLACE INTO utxo_apply_log"
            "(height,status,ok,spent_count,added_count,"
            "total_value_delta,applied_at) "
            "VALUES(20,'verified',1,0,1,1,1),"
            "(21,'verified',1,0,1,1,1),"
            "(42,'verified',1,0,1,1,1);"
            "INSERT OR REPLACE INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) "
            "VALUES(20,zeroblob(32),x'',x'00'),"
            "(21,zeroblob(32),x'',x'00'),"
            "(42,zeroblob(32),x'',x'00');"
            "INSERT OR REPLACE INTO tip_finalize_log"
            "(height,status,ok,work_delta_high,work_delta_low,"
            "utxo_size_after,reorg_depth,finalized_at,tip_hash) "
            "VALUES(20,'finalized',1,0,0,0,0,1,zeroblob(32)),"
            "(42,'finalized',1,0,0,0,0,1,zeroblob(32));"
            "INSERT INTO stage_cursor(name,cursor,updated_at) "
            "VALUES('tip_finalize', 42, 0) "
            "ON CONFLICT(name) DO UPDATE SET cursor=42;"
            "INSERT OR REPLACE INTO nullifiers(nf,pool,height) "
            "VALUES(zeroblob(32),0,42);"
            "INSERT OR REPLACE INTO sprout_anchors(anchor,height,tree) "
            "VALUES(x'14',20,x'00'),(x'15',21,x'00'),"
            "(x'2A',42,x'00');"
            "INSERT OR REPLACE INTO sapling_anchors(anchor,height,tree) "
            "VALUES(x'14',20,x'00'),(x'15',21,x'00'),"
            "(x'2A',42,x'00');"
            "INSERT OR REPLACE INTO anchor_state(pool,activation_cursor) "
            "VALUES(0,7),(1,8);"
            "INSERT OR REPLACE INTO coins"
            "(txid,vout,value,height,is_coinbase,script) "
            "VALUES(zeroblob(32),20,20,20,0,x'51'),"
            "(zeroblob(32),21,21,21,0,x'51'),"
            "(zeroblob(32),42,42,42,0,x'51')",
            NULL, NULL, NULL);
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
        progress_store_tx_unlock();
        CR_CHECK("reconcile: equal-cursor stale tail ok",
                 coins_ram_reconcile_boot(
                     db, coins_kv_set_applied_height_in_tx));
        CR_CHECK("reconcile: equal-cursor keeps durable coin below tail",
                 cr_scalar_i64(db,
                     "SELECT COUNT(*) FROM coins "
                     "WHERE height=20 AND vout=20") == 1);
        CR_CHECK("reconcile: equal-cursor purges durable coin tail",
                 cr_scalar_i64(db,
                     "SELECT COUNT(*) FROM coins "
                     "WHERE height>=21") == 0);
        CR_CHECK("reconcile: equal-cursor keeps applied row",
                 cr_scalar_i64(db,
                     "SELECT COUNT(*) FROM utxo_apply_log "
                     "WHERE height=20") == 1);
        CR_CHECK("reconcile: equal-cursor purges utxo tail",
                 cr_scalar_i64(db,
                     "SELECT COUNT(*) FROM utxo_apply_log "
                     "WHERE height>=21") == 0);
        CR_CHECK("reconcile: equal-cursor purges delta tail",
                 cr_scalar_i64(db,
                     "SELECT COUNT(*) FROM utxo_apply_delta "
                     "WHERE height>=21") == 0);
        CR_CHECK("reconcile: equal-cursor purges tip tail",
                 cr_scalar_i64(db,
                     "SELECT COUNT(*) FROM tip_finalize_log "
                     "WHERE height>=20") == 0);
        CR_CHECK("reconcile: equal-cursor purges nullifier tail",
                 cr_scalar_i64(db,
                     "SELECT COUNT(*) FROM nullifiers "
                     "WHERE height>=21") == 0);
        CR_CHECK("reconcile: equal-cursor keeps Sprout anchor below tail",
                 cr_scalar_i64(db,
                     "SELECT COUNT(*) FROM sprout_anchors "
                     "WHERE height=20") == 1);
        CR_CHECK("reconcile: equal-cursor purges Sprout anchor tail",
                 cr_scalar_i64(db,
                     "SELECT COUNT(*) FROM sprout_anchors "
                     "WHERE height>=21") == 0);
        CR_CHECK("reconcile: equal-cursor keeps Sapling anchor below tail",
                 cr_scalar_i64(db,
                     "SELECT COUNT(*) FROM sapling_anchors "
                     "WHERE height=20") == 1);
        CR_CHECK("reconcile: equal-cursor purges Sapling anchor tail",
                 cr_scalar_i64(db,
                     "SELECT COUNT(*) FROM sapling_anchors "
                     "WHERE height>=21") == 0);
        CR_CHECK("reconcile: anchor coverage state preserved",
                 cr_scalar_i64(db,
                     "SELECT COUNT(*) FROM anchor_state WHERE "
                     "(pool=0 AND activation_cursor=7) OR "
                     "(pool=1 AND activation_cursor=8)") == 2);
        CR_CHECK("reconcile: equal-cursor tip cursor clamped",
                 cr_scalar_i64(db,
                     "SELECT cursor FROM stage_cursor "
                     "WHERE name='tip_finalize'") == 20);
    }
    /* If a mint/refold run crashes before the first RAM flush, no watermark
     * exists yet. The boot replay point must be genesis, not the stale cursor. */
    {
        progress_store_tx_lock();
        sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
        sqlite3_exec(db,
            "DELETE FROM progress_meta "
            "WHERE key='coins_ram_flushed_height';"
            "INSERT OR REPLACE INTO progress_meta(key,value) "
            "VALUES('refold_in_progress',x'01');"
            "INSERT INTO stage_cursor(name,cursor,updated_at) "
            "VALUES('utxo_apply', 99, 0) "
            "ON CONFLICT(name) DO UPDATE SET cursor=99;"
            "INSERT INTO stage_cursor(name,cursor,updated_at) "
            "VALUES('tip_finalize', 99, 0) "
            "ON CONFLICT(name) DO UPDATE SET cursor=99;"
            "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
            "height INTEGER PRIMARY KEY, status TEXT NOT NULL, "
            "ok INTEGER NOT NULL, spent_count INTEGER NOT NULL, "
            "added_count INTEGER NOT NULL, "
            "total_value_delta INTEGER NOT NULL, "
            "first_failure_kind TEXT, first_failure_detail BLOB, "
            "applied_at INTEGER NOT NULL);"
            "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
            "height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL, "
            "spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL);"
            "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
            "height INTEGER PRIMARY KEY, status TEXT NOT NULL, "
            "ok INTEGER NOT NULL, work_delta_high INTEGER NOT NULL, "
            "work_delta_low INTEGER NOT NULL, "
            "utxo_size_after INTEGER NOT NULL, "
            "reorg_depth INTEGER NOT NULL, finalized_at INTEGER NOT NULL, "
            "tip_hash BLOB);"
            "CREATE TABLE IF NOT EXISTS nullifiers ("
            "nf BLOB NOT NULL, pool INTEGER NOT NULL, "
            "height INTEGER NOT NULL, PRIMARY KEY(nf,pool)) "
            "WITHOUT ROWID;"
            "CREATE TABLE IF NOT EXISTS created_outputs ("
            "txid BLOB NOT NULL, vout INTEGER NOT NULL, "
            "value INTEGER NOT NULL, script BLOB NOT NULL, "
            "height INTEGER NOT NULL, PRIMARY KEY(txid,vout)) "
            "WITHOUT ROWID;"
            "INSERT OR REPLACE INTO utxo_apply_log"
            "(height,status,ok,spent_count,added_count,"
            "total_value_delta,applied_at) "
            "VALUES(0,'verified',1,0,0,0,1),"
            "(1,'verified',1,0,1,1,1),"
            "(42,'verified',1,0,1,1,1);"
            "INSERT OR REPLACE INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) "
            "VALUES(0,zeroblob(32),x'',x''),"
            "(1,zeroblob(32),x'',x'00'),"
            "(42,zeroblob(32),x'',x'00');"
            "INSERT OR REPLACE INTO tip_finalize_log"
            "(height,status,ok,work_delta_high,work_delta_low,"
            "utxo_size_after,reorg_depth,finalized_at,tip_hash) "
            "VALUES(0,'finalized',1,0,0,0,0,1,zeroblob(32)),"
            "(42,'finalized',1,0,0,0,0,1,zeroblob(32));"
            "INSERT OR REPLACE INTO nullifiers(nf,pool,height) "
            "VALUES(zeroblob(32),0,42);"
            "INSERT OR REPLACE INTO coins"
            "(txid,vout,value,height,is_coinbase,script) "
            "VALUES(zeroblob(32),1,1,1,0,x'51'),"
            "(zeroblob(32),42,42,42,0,x'51');"
            "INSERT OR REPLACE INTO created_outputs"
            "(txid,vout,value,script,height) "
            "VALUES(zeroblob(32),0,1,x'51',42)",
            NULL, NULL, NULL);
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
        progress_store_tx_unlock();
        CR_CHECK("reconcile: absent watermark + refold marker ok",
                 coins_ram_reconcile_boot(
                     db, coins_kv_set_applied_height_in_tx));
        progress_store_tx_lock();
        sqlite3_stmt *s = NULL;
        int64_t cur = -1;
        if (sqlite3_prepare_v2(db,
                "SELECT cursor FROM stage_cursor WHERE name='utxo_apply'",
                -1, &s, NULL) == SQLITE_OK) {
            if (sqlite3_step(s) == SQLITE_ROW) cur = sqlite3_column_int64(s, 0);
            sqlite3_finalize(s);
        }
        progress_store_tx_unlock();
        CR_CHECK("reconcile: absent watermark rewinds mint/refold to 0",
                 cur == 0);
        int32_t zero_applied = -1; bool zero_found = false;
        CR_CHECK("reconcile: absent watermark applied read",
                 coins_kv_get_applied_height(db, &zero_applied, &zero_found));
        CR_CHECK("reconcile: absent watermark applied == 0",
                 zero_found && zero_applied == 0);
        CR_CHECK("reconcile: stale utxo log purged",
                 cr_scalar_i64(db, "SELECT COUNT(*) FROM utxo_apply_log") == 0);
        CR_CHECK("reconcile: stale utxo delta purged",
                 cr_scalar_i64(db, "SELECT COUNT(*) FROM utxo_apply_delta") == 0);
        CR_CHECK("reconcile: stale tip finalize purged",
                 cr_scalar_i64(db, "SELECT COUNT(*) FROM tip_finalize_log") == 0);
        CR_CHECK("reconcile: stale nullifiers purged",
                 cr_scalar_i64(db, "SELECT COUNT(*) FROM nullifiers") == 0);
        CR_CHECK("reconcile: stale Sprout anchors purged",
                 cr_scalar_i64(db,
                     "SELECT COUNT(*) FROM sprout_anchors") == 0);
        CR_CHECK("reconcile: stale Sapling anchors purged",
                 cr_scalar_i64(db,
                     "SELECT COUNT(*) FROM sapling_anchors") == 0);
        CR_CHECK("reconcile: genesis replay preserves anchor coverage state",
                 cr_scalar_i64(db,
                     "SELECT COUNT(*) FROM anchor_state WHERE "
                     "(pool=0 AND activation_cursor=7) OR "
                     "(pool=1 AND activation_cursor=8)") == 2);
        CR_CHECK("reconcile: stale durable coins purged",
                 cr_scalar_i64(db, "SELECT COUNT(*) FROM coins") == 0);
        CR_CHECK("reconcile: upstream created_outputs preserved",
                 cr_scalar_i64(db, "SELECT COUNT(*) FROM created_outputs") == 1);
        CR_CHECK("reconcile: tip cursor clamped to replay point",
                 cr_scalar_i64(db,
                     "SELECT cursor FROM stage_cursor "
                     "WHERE name='tip_finalize'") == 0);
    }

    coins_ram_writer_exit();
    coins_ram_shutdown();
    progress_store_close();
    test_rm_rf_recursive(dir);

    /* ── stage-batch deferred flush: the live mint drains utxo_apply under an
     *    outer stage batch. Crossing the flush cadence inside that batch must
     *    NOT try a nested BEGIN; it should defer until after stage_batch_end. */
    {
        char dirD[256];
        test_make_tmpdir(dirD, sizeof(dirD), "coins_ram_deferred", "d");
        CR_CHECK("defer: open", progress_store_open(dirD));
        sqlite3 *dbD = progress_store_db();
        CR_CHECK("defer: schema", coins_kv_ensure_schema(dbD));
        CR_CHECK("defer: stage schema", stage_table_ensure(dbD));
        CR_CHECK("defer: init flush_every=1", coins_ram_init(
                     dbD, 1, coins_kv_set_applied_height_in_tx));
        coins_ram_writer_enter();

        struct uint256 dt = cr_txid(0x77);
        CR_CHECK("defer: add overlay coin",
                 coins_kv_add(dbD, dt.data, 0, 7777, 40, false,
                              (const uint8_t *)"d", 1));

        progress_store_tx_lock();
        CR_CHECK("defer: batch begin", stage_batch_begin(dbD));
        CR_CHECK("defer: note_applied defers inside batch",
                 coins_ram_note_applied(40));
        CR_CHECK("defer: batch still active", stage_batch_active());
        CR_CHECK("defer: batch end", stage_batch_end(dbD, true));
        progress_store_tx_unlock();

        CR_CHECK("defer: flush due after batch", coins_ram_flush_due());
        CR_CHECK("defer: durable count after flush", coins_kv_count(dbD) == 1);
        int32_t dapplied = -1; bool dfound = false;
        CR_CHECK("defer: applied frontier read",
                 coins_kv_get_applied_height(dbD, &dapplied, &dfound));
        CR_CHECK("defer: applied frontier == 41",
                 dfound && dapplied == 41);

        struct uint256 dt2 = cr_txid(0x78);
        CR_CHECK("stale-dirty: add next-height overlay coin",
                 coins_kv_add(dbD, dt2.data, 0, 8888, 41, false,
                              (const uint8_t *)"e", 1));
        progress_store_tx_lock();
        CR_CHECK("stale-dirty: batch begin", stage_batch_begin(dbD));
        CR_CHECK("stale-dirty: note next height", coins_ram_note_applied(41));
        CR_CHECK("stale-dirty: batch end", stage_batch_end(dbD, true));
        progress_store_tx_unlock();
        CR_CHECK("stale-dirty: old waiter promotes to dirty height",
                 coins_ram_flush(40));
        dapplied = -1; dfound = false;
        CR_CHECK("stale-dirty: promoted flush lands overlay without rewind",
                 cr_scalar_i64(dbD, "SELECT COUNT(*) FROM coins") == 2 &&
                 coins_kv_get_applied_height(dbD, &dapplied, &dfound) &&
                 dfound && dapplied == 42);

        coins_ram_writer_exit();
        coins_ram_shutdown();
        progress_store_close();
        test_rm_rf_recursive(dirD);
    }

    /* ── flush witness guard: when reducer witness tables exist, a RAM flush
     *    may not stamp the durable cursor/frontier unless the same height has
     *    an ok=1 utxo_apply_log row and an inverse-delta row. This is the
     *    guard against a rowless coins_applied_height span. ── */
    {
        char dirW[256];
        test_make_tmpdir(dirW, sizeof(dirW), "coins_ram_witness", "w");
        CR_CHECK("witness: open", progress_store_open(dirW));
        sqlite3 *dbW = progress_store_db();
        CR_CHECK("witness: schema", coins_kv_ensure_schema(dbW));
        CR_CHECK("witness: init", coins_ram_init(
                     dbW, 1000000, coins_kv_set_applied_height_in_tx));
        coins_ram_writer_enter();

        struct uint256 wt = cr_txid(0x88);
        CR_CHECK("witness: add overlay coin",
                 coins_kv_add(dbW, wt.data, 0, 8888, 30, false,
                              (const uint8_t *)"w", 1));
        CR_CHECK("witness: create reducer tables",
                 sqlite3_exec(dbW,
                     "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
                     "height INTEGER PRIMARY KEY, status TEXT NOT NULL, "
                     "ok INTEGER NOT NULL, spent_count INTEGER NOT NULL, "
                     "added_count INTEGER NOT NULL, "
                     "total_value_delta INTEGER NOT NULL, "
                     "first_failure_kind TEXT, first_failure_detail BLOB, "
                     "applied_at INTEGER NOT NULL);"
                     "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
                     "height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL, "
                     "spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL);",
                     NULL, NULL, NULL) == SQLITE_OK);
        CR_CHECK("witness: missing log refuses flush",
                 !coins_ram_flush(30));
        CR_CHECK("witness: insert log only",
                 sqlite3_exec(dbW,
                     "INSERT OR REPLACE INTO utxo_apply_log"
                     "(height,status,ok,spent_count,added_count,"
                     "total_value_delta,applied_at) "
                     "VALUES(30,'verified',1,0,1,8888,1)",
                     NULL, NULL, NULL) == SQLITE_OK);
        CR_CHECK("witness: missing delta refuses flush",
                 !coins_ram_flush(30));
        CR_CHECK("witness: insert delta",
                 sqlite3_exec(dbW,
                     "INSERT OR REPLACE INTO utxo_apply_delta"
                     "(height,branch_hash,spent_blob,added_blob) "
                     "VALUES(30,zeroblob(32),x'',x'')",
                     NULL, NULL, NULL) == SQLITE_OK);
        CR_CHECK("witness: complete witness permits flush",
                 coins_ram_flush(30));
        int32_t wapplied = -1; bool wfound = false;
        CR_CHECK("witness: applied frontier read",
                 coins_kv_get_applied_height(dbW, &wapplied, &wfound));
        CR_CHECK("witness: applied frontier == 31",
                 wfound && wapplied == 31);

        coins_ram_writer_exit();
        coins_ram_shutdown();
        progress_store_close();
        test_rm_rf_recursive(dirW);
    }

    /* ──────────────────────────────────────────────────────────────────────
     * (a) TRUE A/B: identical op script, pure-SQLite leg vs overlay leg.
     *
     * The cached flag (ZCL_FOLD_INRAM, read once by coins_ram_enabled) does NOT
     * gate the routing — coins_kv.c routes on coins_ram_active(), which is
     * (G.active && G.slots). So a leg that NEVER calls coins_ram_init runs the
     * byte-for-byte original SQLite path even with the env flag set. That gives
     * a genuine cross-encoder A/B inside this one (flag-ON) process:
     *   leg A: no coins_ram_init  -> coins_kv_* all hit pure SQLite, and
     *          coins_kv_commitment iterates the durable B-tree directly.
     *   leg B: coins_ram_init     -> coins_kv_* route through the overlay, and
     *          coins_kv_commitment iterates the EFFECTIVE (overlay+durable) set.
     * The op script includes spends, a create-then-spend, an empty script, and
     * an INSERT-OR-REPLACE over a live key — all the encoder corner cases.
     * ────────────────────────────────────────────────────────────────────── */
    {
        static const struct ab_op AB[] = {
            { AB_ADD,100, 0, 5000, 10, true,  {0xA0,0xA1},      2, },
            { AB_ADD,100, 1, 6000, 10, true,  {0xB0,0xB1,0xB2}, 3, },
            { AB_ADD,101, 0, 7000, 11, false, {0xC0},           1, },
            { AB_ADD,102, 0, 8000, 12, false, {0},              0, }, /* empty */
            { AB_ADD,103, 0, 9000, 13, false, {0xD0,0xD1},      2, },
            { AB_SPEND,101, 0, 0,    0,  false, {0},              0, },
            { AB_ADD,104, 0, 1234, 14, false, {0xE0},           1, },
            { AB_SPEND,104, 0, 0,    0,  false, {0},              0, }, /* create+spend */
            { AB_ADD,103, 1, 4321, 15, false, {0xF0,0xF1,0xF2}, 3, },
            { AB_ADD,100, 0, 5555, 16, false, {0x11},           1, }, /* REPLACE live */
            { AB_SPEND,100, 1, 0,    0,  false, {0},              0, },
            { AB_ADD,105, 7, 222,  17, false, {0x22,0x33},      2, },
        };
        const size_t AB_N = sizeof(AB) / sizeof(AB[0]);

        /* leg A — pure SQLite (overlay never initialised). */
        char dirA[256];
        test_make_tmpdir(dirA, sizeof(dirA), "coins_ram_ab_a", "a");
        CR_CHECK("ab.A: open", progress_store_open(dirA));
        sqlite3 *dbA = progress_store_db();
        CR_CHECK("ab.A: schema", coins_kv_ensure_schema(dbA));
        CR_CHECK("ab.A: overlay NOT active (pure sqlite)", !coins_ram_active());
        CR_CHECK("ab.A: apply clean", ab_apply_all(dbA, AB, AB_N, false) == 0);
        uint8_t rootA[32] = {0};
        CR_CHECK("ab.A: commitment ok", coins_kv_commitment(dbA, rootA) == 0);
        int64_t cntA = coins_kv_count(dbA);
        progress_store_close();
        test_rm_rf_recursive(dirA);

        /* leg B — overlay. Same ops, with a flush in the middle and at the end
         * so the commitment is taken once with rows split overlay/durable and
         * once fully drained. Both must equal leg A. */
        char dirB[256];
        test_make_tmpdir(dirB, sizeof(dirB), "coins_ram_ab_b", "b");
        CR_CHECK("ab.B: open", progress_store_open(dirB));
        sqlite3 *dbB = progress_store_db();
        CR_CHECK("ab.B: schema", coins_kv_ensure_schema(dbB));
        CR_CHECK("ab.B: init", coins_ram_init(
                     dbB, 1000000, coins_kv_set_applied_height_in_tx));
        CR_CHECK("ab.B: overlay active", coins_ram_active());
        /* This thread is the single writer driving the overlay leg (mirrors the
         * reducer). Bracket so the coins_kv_* READ shims route to the overlay. */
        coins_ram_writer_enter();
        CR_CHECK("ab.B: apply clean", ab_apply_all(dbB, AB, AB_N, true) == 0);

        /* Commitment with the overlay STILL holding everything (nothing
         * durable yet) — the cross-encoder path. */
        uint8_t rootB_overlay[32] = {0};
        CR_CHECK("ab.B: commitment (overlay-full) ok",
                 coins_kv_commitment(dbB, rootB_overlay) == 0);
        int64_t cntB_overlay = coins_kv_count(dbB);

        /* Now flush and re-take: rows fully durable, overlay empty. */
        CR_CHECK("ab.B: flush ok", coins_ram_flush(20));
        uint8_t rootB_flushed[32] = {0};
        CR_CHECK("ab.B: commitment (flushed) ok",
                 coins_kv_commitment(dbB, rootB_flushed) == 0);
        int64_t cntB_flushed = coins_kv_count(dbB);
        coins_ram_writer_exit();

        coins_ram_shutdown();
        progress_store_close();
        test_rm_rf_recursive(dirB);

        /* THE cross-encoder proofs. */
        CR_CHECK("AB: count A == B(overlay) == B(flushed)",
                 cntA == cntB_overlay && cntA == cntB_flushed);
        CR_CHECK("AB: root A == B(overlay)  [pure-sqlite == overlay-effective]",
                 memcmp(rootA, rootB_overlay, 32) == 0);
        CR_CHECK("AB: root A == B(flushed)  [pure-sqlite == drained-overlay]",
                 memcmp(rootA, rootB_flushed, 32) == 0);
    }

    /* ──────────────────────────────────────────────────────────────────────
     * (b) MULTI-FLUSH: the dominant real case the original test never hit —
     *     the overlay merged over an ALREADY-POPULATED durable set across many
     *     flush rounds, with cross-flush tombstones (spend of a coin durable
     *     since a PRIOR flush) and a re-add over a durably-flushed key.
     *
     * We fold the SAME op stream two ways and compare the FINAL commitment +
     * per-coin reads:
     *   golden  : pure SQLite (overlay off) — flushes are no-ops.
     *   overlay : flushes are real coins_ram_flush calls interleaved through
     *             the stream, so later ops mutate over a populated durable set.
     * ────────────────────────────────────────────────────────────────────── */
    {
        /* Round 1: mint a base set.            (tags 200..205)
         * flush.
         * Round 2: spend two NOW-DURABLE coins (cross-flush tombstone),
         *          spend a coin minted+spent in THIS round (overlay-only),
         *          re-add (REPLACE) a durably-flushed key,
         *          mint fresh coins.
         * flush.
         * Round 3: spend a coin minted in round 2 (durable now),
         *          spend a coin that was re-added in round 2 (durable now),
         *          mint more.
         * flush.
         * Round 4: spend across all prior rounds + mint, NO trailing flush so
         *          the final commitment is taken with a non-empty overlay over
         *          a populated durable set (the live mint's actual posture). */
        static const struct ab_op MF[] = {
            /* round 1 */
            { AB_ADD,200, 0, 1000, 1, true,  {0x01},           1, },
            { AB_ADD,200, 1, 1100, 1, true,  {0x02,0x03},      2, },
            { AB_ADD,201, 0, 1200, 2, false, {0x04},           1, },
            { AB_ADD,202, 0, 1300, 3, false, {0},              0, },
            { AB_ADD,203, 0, 1400, 4, false, {0x05,0x06,0x07}, 3, },
            { AB_ADD,204, 0, 1500, 5, false, {0x08},           1, },
            { AB_ADD,205, 0, 1600, 6, false, {0x09},           1, },
            { AB_FLUSH,0,   0, 0,    6, false, {0},              0, },
            /* round 2 */
            { AB_SPEND,201, 0, 0,    0, false, {0},              0, }, /* cross-flush tomb */
            { AB_SPEND,200, 1, 0,    0, false, {0},              0, }, /* cross-flush tomb */
            { AB_ADD,206, 0, 1700, 7, false, {0x0A},           1, },
            { AB_SPEND,206, 0, 0,    0, false, {0},              0, }, /* overlay-only c+s */
            { AB_ADD,202, 0, 9999, 8, false, {0x0B,0x0C},      2, }, /* REPLACE durable key */
            { AB_ADD,207, 0, 1800, 8, false, {0x0D},           1, },
            { AB_ADD,207, 1, 1850, 8, false, {0x0E},           1, },
            { AB_FLUSH,0,   0, 0,    8, false, {0},              0, },
            /* round 3 */
            { AB_SPEND,207, 0, 0,    0, false, {0},              0, }, /* round-2 coin now durable */
            { AB_SPEND,202, 0, 0,    0, false, {0},              0, }, /* the REPLACEd coin, now durable */
            { AB_ADD,208, 0, 1900, 9, false, {0x0F},           1, },
            { AB_ADD,208, 1, 1950, 9, false, {0x10,0x11},      2, },
            { AB_FLUSH,0,   0, 0,    9, false, {0},              0, },
            /* round 4 — NO trailing flush */
            { AB_SPEND,200, 0, 0,    0, false, {0},              0, }, /* round-1 coinbase, durable */
            { AB_SPEND,208, 1, 0,    0, false, {0},              0, }, /* round-3 coin, durable */
            { AB_ADD,209, 0, 2000, 10,false, {0x12},          1, },
            { AB_ADD,205, 0, 7777, 11,false, {0x13,0x14},     2, }, /* REPLACE round-1 durable */
        };
        const size_t MF_N = sizeof(MF) / sizeof(MF[0]);

        /* golden: pure SQLite. */
        char dirG[256];
        test_make_tmpdir(dirG, sizeof(dirG), "coins_ram_mf_g", "g");
        CR_CHECK("mf.G: open", progress_store_open(dirG));
        sqlite3 *dbG = progress_store_db();
        CR_CHECK("mf.G: schema", coins_kv_ensure_schema(dbG));
        CR_CHECK("mf.G: pure sqlite", !coins_ram_active());
        CR_CHECK("mf.G: apply clean", ab_apply_all(dbG, MF, MF_N, false) == 0);
        uint8_t rootG[32] = {0};
        CR_CHECK("mf.G: commitment ok", coins_kv_commitment(dbG, rootG) == 0);
        int64_t cntG = coins_kv_count(dbG);
        /* Capture a few golden point reads to compare against the overlay leg. */
        struct uint256 q_live  = ab_txid(209);  /* minted round 4, vout 0 */
        struct uint256 q_repl  = ab_txid(205);  /* re-added round 4, vout 0 */
        struct uint256 q_spent = ab_txid(202);  /* spent round 3, vout 0 */
        struct uint256 q_xtomb = ab_txid(201);  /* cross-flush tomb, vout 0 */
        int64_t gv_live = 0, gv_repl = 0;
        bool gex_live  = coins_kv_get(dbG, q_live.data,  0, &gv_live, NULL, 0, NULL);
        bool gex_repl  = coins_kv_get(dbG, q_repl.data,  0, &gv_repl, NULL, 0, NULL);
        bool gex_spent = coins_kv_exists(dbG, q_spent.data, 0);
        bool gex_xtomb = coins_kv_exists(dbG, q_xtomb.data, 0);
        progress_store_close();
        test_rm_rf_recursive(dirG);

        /* overlay: real flushes interleaved. */
        char dirO[256];
        test_make_tmpdir(dirO, sizeof(dirO), "coins_ram_mf_o", "o");
        CR_CHECK("mf.O: open", progress_store_open(dirO));
        sqlite3 *dbO = progress_store_db();
        CR_CHECK("mf.O: schema", coins_kv_ensure_schema(dbO));
        CR_CHECK("mf.O: init", coins_ram_init(
                     dbO, 1000000, coins_kv_set_applied_height_in_tx));
        CR_CHECK("mf.O: overlay active", coins_ram_active());
        /* Single writer driving the overlay leg (mirrors the reducer). */
        coins_ram_writer_enter();
        CR_CHECK("mf.O: apply clean", ab_apply_all(dbO, MF, MF_N, true) == 0);

        /* Final commitment taken with a NON-EMPTY overlay over a populated
         * durable set (round 4 has no trailing flush). */
        uint8_t rootO[32] = {0};
        CR_CHECK("mf.O: commitment ok", coins_kv_commitment(dbO, rootO) == 0);
        int64_t cntO = coins_kv_count(dbO);
        int64_t ov_live = 0, ov_repl = 0;
        bool oex_live  = coins_kv_get(dbO, q_live.data,  0, &ov_live, NULL, 0, NULL);
        bool oex_repl  = coins_kv_get(dbO, q_repl.data,  0, &ov_repl, NULL, 0, NULL);
        bool oex_spent = coins_kv_exists(dbO, q_spent.data, 0);
        bool oex_xtomb = coins_kv_exists(dbO, q_xtomb.data, 0);
        coins_ram_writer_exit();

        coins_ram_shutdown();
        progress_store_close();
        test_rm_rf_recursive(dirO);

        CR_CHECK("MULTIFLUSH: count golden == overlay", cntG == cntO);
        CR_CHECK("MULTIFLUSH: final root golden == overlay",
                 memcmp(rootG, rootO, 32) == 0);
        CR_CHECK("MULTIFLUSH: live read matches (val + presence)",
                 gex_live == oex_live && gex_live && gv_live == ov_live);
        CR_CHECK("MULTIFLUSH: replaced-key read matches",
                 gex_repl == oex_repl && gex_repl && gv_repl == ov_repl);
        CR_CHECK("MULTIFLUSH: spent-after-flush reads ABSENT both legs",
                 gex_spent == oex_spent && !gex_spent);
        CR_CHECK("MULTIFLUSH: cross-flush tombstone reads ABSENT both legs",
                 gex_xtomb == oex_xtomb && !gex_xtomb);
    }

    /* ──────────────────────────────────────────────────────────────────────
     * (c) MICRO-BENCHMARK: per-op cost of an in-RAM overlay probe vs a SQLite
     *     coins_kv B-tree get at a large populated N. Diagnostic only (printed,
     *     not asserted) — gives the real speedup the accelerator must earn
     *     before the ~35h mint is committed. N is sized down automatically if
     *     the build can't afford the larger fill cheaply. */
    {
        /* Default N is small: this block is a MEASUREMENT, not an assertion —
         * the only thing checked below is "both legs actually hit", which is
         * true at any N. At the full 1,000,000 it fills a million SQLite rows
         * and does 400k probes, roughly 4.6s of pure CPU and IO that every
         * `make test-parallel` was paying, on one of 32 workers, adding load
         * that pushed OTHER groups' timing-sensitive assertions over their
         * ceilings. The real speedup number is still one env var away.
         *
         * Set ZCL_TEST_PERF_ASSERTS=1 to run the full-size measurement. */
        const int N = getenv("ZCL_TEST_PERF_ASSERTS") ? 1000000 : 20000;
        char dirP[256];
        test_make_tmpdir(dirP, sizeof(dirP), "coins_ram_bench", "p");
        if (progress_store_open(dirP)) {
            sqlite3 *dbP = progress_store_db();
            coins_kv_ensure_schema(dbP);

            /* ── populate the durable SQLite B-tree (overlay OFF) ── */
            struct timespec t0, t1;
            clock_gettime(CLOCK_MONOTONIC, &t0);  // platform-ok:coins-ram-benchmark-realtime
            progress_store_tx_lock();
            sqlite3_exec(dbP, "BEGIN IMMEDIATE", NULL, NULL, NULL);
            int filled = 0;
            for (int i = 0; i < N; i++) {
                struct uint256 t = ab_txid((uint32_t)i + 1000000u);
                uint8_t scr[24];
                for (int k = 0; k < 24; k++) scr[k] = (uint8_t)(i + k);
                if (!coins_kv_add(dbP, t.data, 0, 1000 + i, i % 1000, false,
                                  scr, sizeof(scr)))
                    break;
                filled++;
            }
            sqlite3_exec(dbP, "COMMIT", NULL, NULL, NULL);
            progress_store_tx_unlock();
            clock_gettime(CLOCK_MONOTONIC, &t1);  // platform-ok:coins-ram-benchmark-realtime
            double fill_s = (t1.tv_sec - t0.tv_sec)
                          + (t1.tv_nsec - t0.tv_nsec) / 1e9;
            printf("  coins_ram: BENCH filled %d durable coins in %.2fs\n",
                   filled, fill_s);

            /* ── SQLite B-tree get cost (overlay OFF) ── */
            const int PROBES = getenv("ZCL_TEST_PERF_ASSERTS") ? 200000 : 5000;
            clock_gettime(CLOCK_MONOTONIC, &t0);  // platform-ok:coins-ram-benchmark-realtime
            volatile int64_t sink = 0; int hit = 0;
            for (int p = 0; p < PROBES; p++) {
                uint32_t idx = (uint32_t)(((uint64_t)p * 2654435761u) % (uint32_t)filled);
                struct uint256 t = ab_txid(idx + 1000000u);
                int64_t v = 0;
                if (coins_kv_get_sqlite(dbP, t.data, 0, &v, NULL, 0, NULL)) {
                    sink += v; hit++;
                }
            }
            clock_gettime(CLOCK_MONOTONIC, &t1);  // platform-ok:coins-ram-benchmark-realtime
            double sqlite_ns = ((t1.tv_sec - t0.tv_sec) * 1e9
                              + (t1.tv_nsec - t0.tv_nsec)) / PROBES;

            /* ── overlay probe cost: bind the overlay to the SAME db and read
             *    the SAME keys. The keys live ONLY in durable coins_kv, so each
             *    overlay get is a probe (miss) + read-through; to isolate the
             *    in-RAM probe cost we ALSO pre-load the keys into the overlay
             *    (LIVE slots) and read those (overlay hit, no SQLite). ── */
            coins_ram_init(dbP, 1000000,
                           coins_kv_set_applied_height_in_tx);
            /* warm the overlay with the probed keys as LIVE slots */
            for (int p = 0; p < PROBES; p++) {
                uint32_t idx = (uint32_t)(((uint64_t)p * 2654435761u) % (uint32_t)filled);
                struct uint256 t = ab_txid(idx + 1000000u);
                uint8_t scr[24];
                for (int k = 0; k < 24; k++) scr[k] = (uint8_t)(idx + k);
                coins_ram_add(t.data, 0, 1000 + idx, (int32_t)(idx % 1000), false,
                              scr, sizeof(scr));
            }
            clock_gettime(CLOCK_MONOTONIC, &t0);  // platform-ok:coins-ram-benchmark-realtime
            int hit2 = 0;
            for (int p = 0; p < PROBES; p++) {
                uint32_t idx = (uint32_t)(((uint64_t)p * 2654435761u) % (uint32_t)filled);
                struct uint256 t = ab_txid(idx + 1000000u);
                int64_t v = 0;
                if (coins_ram_get(t.data, 0, &v, NULL, 0, NULL)) { sink += v; hit2++; }
            }
            clock_gettime(CLOCK_MONOTONIC, &t1);  // platform-ok:coins-ram-benchmark-realtime
            double ram_ns = ((t1.tv_sec - t0.tv_sec) * 1e9
                           + (t1.tv_nsec - t0.tv_nsec)) / PROBES;

            printf("  coins_ram: BENCH N=%d  sqlite_get=%.0f ns/op  "
                   "ram_probe=%.0f ns/op  speedup=%.1fx  (sqlite_hits=%d "
                   "ram_hits=%d sink=%lld)\n",
                   filled, sqlite_ns, ram_ns,
                   ram_ns > 0 ? sqlite_ns / ram_ns : 0.0, hit, hit2,
                   (long long)sink);
            /* Sanity: both legs must have actually hit, else the numbers lie. */
            CR_CHECK("bench: both legs hit", hit > 0 && hit2 > 0);

            coins_ram_shutdown();
            progress_store_close();
        }
        test_rm_rf_recursive(dirP);
    }

    /* ──────────────────────────────────────────────────────────────────────
     * (e) MINT-DRIVE READ MARKER gate: coins_ram_mint_drive_thread() is the
     *     read-visibility marker the FULL -mint-anchor serial fold brackets its
     *     whole drive with, so script_validate's prevout resolver (a DIFFERENT
     *     stage step than utxo_apply's writer bracket, but the SAME single drive
     *     thread) sees the un-flushed overlay via coins_kv_overlay_safe(). This
     *     pins: (1) the per-thread marker contract (false by default, true only
     *     inside the bracket, counter-balanced, isolated per thread); and (2)
     *     the OBSERVABLE effect — an overlay tombstone shadowing a durable coin
     *     is ABSENT to a marked (drive) thread but PRESENT to an unmarked thread
     *     (which safely takes the durable SQLite path). Item (2) is the exact
     *     read-visibility the FULL-fold in-RAM cure turns on.
     * ────────────────────────────────────────────────────────────────────── */
    {
        char dirM[256];
        test_make_tmpdir(dirM, sizeof(dirM), "coins_ram_mintdrive", "md");
        CR_CHECK("md: open", progress_store_open(dirM));
        sqlite3 *dbM = progress_store_db();
        CR_CHECK("md: schema", coins_kv_ensure_schema(dbM));
        CR_CHECK("md: init", coins_ram_init(
                     dbM, 1000000, coins_kv_set_applied_height_in_tx));
        CR_CHECK("md: active", coins_ram_active());

        /* A durable coin the overlay will SHADOW as spent. Write it straight to
         * SQLite (the overlay-bypassing raw variant) so the two layers disagree:
         * durable=present, overlay=tombstone. */
        struct uint256 md = cr_txid(0x7D);
        uint8_t mdscript[2] = { 0xAB, 0xCD };
        struct coins_kv_add_row row = {
            .txid = md.data, .vout = 0, .value = 12345, .height = 9,
            .is_coinbase = false, .script = mdscript, .script_len = 2 };
        CR_CHECK("md: durable add (raw sqlite)",
                 coins_kv_add_many_sqlite(dbM, &row, 1));

        /* Overlay tombstone (a spend of a durable coin) — the mutation needs the
         * writer bracket, exactly as the fold holds it around utxo_apply. */
        coins_ram_writer_enter();
        CR_CHECK("md: overlay tombstone", coins_ram_spend(md.data, 0));
        coins_ram_writer_exit();

        /* (1) marker contract — mirrors the writer-bracket contract. */
        CR_CHECK("md: main not drive-thread yet", !coins_ram_mint_drive_thread());
        coins_ram_mint_drive_enter();
        CR_CHECK("md: enter -> drive thread", coins_ram_mint_drive_thread());
        coins_ram_mint_drive_enter();      /* nested */
        coins_ram_mint_drive_exit();
        CR_CHECK("md: nested -> still drive (counter)",
                 coins_ram_mint_drive_thread());

        /* (2a) On the MARKED thread coins_kv_get routes to the overlay → the
         *      tombstone shadows the durable row → ABSENT. This is the coin the
         *      old FULL-fold refusal existed to avoid; it now resolves via the
         *      overlay on the drive thread. */
        int64_t mv = 0; size_t ml = 0; uint8_t mb[8];
        CR_CHECK("md: marked thread sees overlay tombstone (absent)",
                 !coins_kv_get(dbM, md.data, 0, &mv, mb, sizeof(mb), &ml));

        coins_ram_mint_drive_exit();
        CR_CHECK("md: final exit -> not drive thread",
                 !coins_ram_mint_drive_thread());

        /* (2b) On an UNMARKED thread (no writer, no mint-drive) coins_kv_get
         *      takes the durable SQLite path → the tombstone is invisible → the
         *      coin is PRESENT. Confirms the marker is _Thread_local and gates
         *      overlay visibility per-thread (the UAF guard for a live node). */
        struct cr_md_arg ma = { .db = dbM, .txid = md.data,
                                .present = false, .drive = true };
        pthread_t mt;
        int mpc = pthread_create(&mt, NULL, cr_md_reader_thread, &ma);
        CR_CHECK("md: unmarked reader spawned", mpc == 0);
        if (mpc == 0) {
            pthread_join(mt, NULL);
            CR_CHECK("md: unmarked thread is NOT a drive thread", !ma.drive);
            CR_CHECK("md: unmarked thread sees durable coin (present)",
                     ma.present);
        }

        coins_ram_shutdown();
        progress_store_close();
        test_rm_rf_recursive(dirM);
    }

    /* ──────────────────────────────────────────────────────────────────────
     * (f) HIGH-WATER flush: when the live overlay slot count crosses
     *     ZCL_FOLD_INRAM_MAX_SLOTS, coins_ram_note_applied flushes MID-window
     *     even though the block cadence (flush_every) is nowhere near due — the
     *     OOM guard for a dense window that mints many coins between cadence
     *     boundaries. We set the cap to 4 and prove the 4th applied height
     *     drains the overlay to durable coins_kv. flush_every is huge so ONLY
     *     the high water can trigger the flush.
     * ────────────────────────────────────────────────────────────────────── */
    {
        setenv("ZCL_FOLD_INRAM_MAX_SLOTS", "4", 1);
        char dirH[256];
        test_make_tmpdir(dirH, sizeof(dirH), "coins_ram_hiwater", "h");
        CR_CHECK("hw: open", progress_store_open(dirH));
        sqlite3 *dbH = progress_store_db();
        CR_CHECK("hw: schema", coins_kv_ensure_schema(dbH));
        CR_CHECK("hw: init (flush_every huge)", coins_ram_init(
                     dbH, 1000000, coins_kv_set_applied_height_in_tx));
        CR_CHECK("hw: active", coins_ram_active());
        coins_ram_writer_enter();

        /* Add 4 live coins, noting each applied height. live_count reaches the
         * cap (4) on the 4th note_applied → that call flushes. */
        bool durable_empty_before = coins_kv_count_sqlite(dbH) == 0;
        CR_CHECK("hw: durable empty before", durable_empty_before);
        for (int k = 0; k < 4; k++) {
            struct uint256 hk = cr_txid((uint8_t)(0x90 + k));
            uint8_t sc[1] = { (uint8_t)k };
            CR_CHECK("hw: add",
                     coins_kv_add(dbH, hk.data, 0, 1000 + k, 100 + k,
                                  false, sc, 1));
            CR_CHECK("hw: note_applied", coins_ram_note_applied(100 + k));
        }

        /* The high-water flush drained the overlay into durable coins_kv: read
         * the durable set directly (overlay-bypassing) to prove the 4 rows
         * landed WITHOUT hitting the block cadence. */
        CR_CHECK("hw: durable count == 4 after high-water flush",
                 coins_kv_count_sqlite(dbH) == 4);
        /* And the effective count is unchanged (overlay now empty, rows durable). */
        CR_CHECK("hw: effective count == 4", coins_kv_count(dbH) == 4);

        coins_ram_writer_exit();
        coins_ram_shutdown();
        progress_store_close();
        test_rm_rf_recursive(dirH);
        unsetenv("ZCL_FOLD_INRAM_MAX_SLOTS");
    }

    /* ──────────────────────────────────────────────────────────────────────
     * (d) UAF GUARD contract: coins_ram_writer_thread() is the per-thread
     *     "am-the-writer" flag the coins_kv.c READ shims gate overlay use on.
     *     It MUST be false on ANY thread that did not bracket with
     *     coins_ram_writer_enter (the cross-thread reader case: bg-validation
     *     pthreads, RPC pool, seal_service), true only inside the bracket, and
     *     balanced on exit. This pins the exact contract the shim gating relies
     *     on — if this ever regresses, a cross-thread reader would touch the
     *     lock-free overlay concurrently with the writer's free()+repoint. */
    {
        /* (1) The main test thread never entered the bracket → false. */
        CR_CHECK("uaf: main thread not a writer", !coins_ram_writer_thread());

        /* (2) A FRESH pthread that never called _enter is also NOT a writer —
         *    this is the precise cross-thread-reader scenario (a bg-validation
         *    worker pthread). The guard is _Thread_local, so the new thread's
         *    counter is 0 regardless of overlay activity or what the main
         *    thread did. */
        struct cr_reader_arg ra = { .is_writer = true /* expect false */ };
        pthread_t rt;
        int pc = pthread_create(&rt, NULL, cr_reader_thread, &ra);
        CR_CHECK("uaf: reader pthread spawned", pc == 0);
        if (pc == 0) {
            pthread_join(rt, NULL);
            CR_CHECK("uaf: fresh pthread is NOT a writer", !ra.is_writer);
        }

        /* (3) After _enter, the CALLING (main) thread IS the writer. */
        coins_ram_writer_enter();
        CR_CHECK("uaf: enter -> is writer", coins_ram_writer_thread());

        /* (4) A nested _enter keeps it true (counter form, re-entrancy-safe). */
        coins_ram_writer_enter();
        CR_CHECK("uaf: nested enter -> still writer",
                 coins_ram_writer_thread());
        coins_ram_writer_exit();
        CR_CHECK("uaf: one exit -> still writer (counter)",
                 coins_ram_writer_thread());

        /* (5) After the matching final _exit, it is false again. */
        coins_ram_writer_exit();
        CR_CHECK("uaf: final exit -> not writer", !coins_ram_writer_thread());

        /* (6) While the main thread is the writer, a fresh pthread is STILL NOT
         *    — the flag is _Thread_local, so the writer's bracket does not leak
         *    into another thread. This is the crux: the guard isolates the
         *    writer from concurrent readers. */
        coins_ram_writer_enter();
        struct cr_reader_arg ra2 = { .is_writer = false /* expect false */ };
        pthread_t rt2;
        pc = pthread_create(&rt2, NULL, cr_reader_thread, &ra2);
        CR_CHECK("uaf: 2nd reader pthread spawned", pc == 0);
        if (pc == 0) {
            pthread_join(rt2, NULL);
            CR_CHECK("uaf: pthread NOT writer while main is writer",
                     !ra2.is_writer);
        }
        CR_CHECK("uaf: main still writer after pthread join",
                 coins_ram_writer_thread());
        coins_ram_writer_exit();
        CR_CHECK("uaf: main exits cleanly", !coins_ram_writer_thread());
    }

    printf("test_coins_ram: %d failures\n", failures);
    return failures;
}
