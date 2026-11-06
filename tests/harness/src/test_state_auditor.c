/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for state_auditor (engine/services/src/state_auditor.c) and its
 * condition-engine wiring (engine/conditions/src/state_auditor_mismatch.c):
 *
 *  1. op_return_index leg, on real on-disk blocks (mirrors test_op_return_
 *     index.c's backfill e2e fixture, sized to exactly
 *     STATE_AUDITOR_OPRET_WINDOW_BLOCKS heights so the window is pinned to
 *     [0, W-1] deterministically): a clean catalog produces zero mismatches
 *     over many ticks; corrupting one stored row's payload_sha3 gets
 *     flagged (right leg name, right height range) after
 *     STATE_AUDITOR_CONFIRM_STREAK confirming ticks; restoring the row
 *     clears the latch on the next tick (real witness, not a coincidence).
 *  2. coins_commitment leg, on a minimal fixture (coins_kv_ensure_schema'd
 *     progress.kv stand-in + a node_db with a matching `utxos` row set,
 *     txids placed deterministically in the forced test-seed's keyspace
 *     window): a clean cross-check produces zero mismatches; corrupting one
 *     utxos row's value gets flagged after confirmation; restoring clears.
 *  3. state_auditor_mismatch condition wiring (force-latch test hooks,
 *     no fixture needed): detect/remedy raise the typed
 *     "state_auditor.<leg>.mismatch" blocker; witness clears it once
 *     state_auditor's own latch clears.
 */

#include "test/test_core.h"
#include "validation/main_state.h"

#include "conditions/state_auditor_mismatch.h"
#include "coins/utxo_commitment.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "framework/condition.h"
#include "json/json.h"
#include "jobs/reducer_frontier.h"
#include "models/database.h"
#include "models/op_return_index.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "chain/chain.h"
#include "script/op_return_push.h"
#include "services/op_return_backfill_service.h"
#include "services/state_auditor.h"
#include "services/utxo_mirror_sync_service.h"
#include "storage/coins_kv.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "util/blocker.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SA_CHECK(name, expr) do { \
    printf("  state_auditor: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── shared small helpers ────────────────────────────────────────────── */

static size_t sa_build_opret(uint8_t *out, const uint8_t *tag, size_t tag_len,
                             const uint8_t *rest, size_t rest_len)
{
    size_t off = 0;
    out[off++] = 0x6a;
    off += push_data(out + off, tag, tag_len);
    if (rest_len) {
        memcpy(out + off, rest, rest_len);
        off += rest_len;
    }
    return off;
}

/* ── (1) op_return_index leg on real on-disk blocks ─────────────────── */

#define SA_OPRET_DIR_FMT "./test-tmp/%d_state_auditor_opret"
#define SA_OPRET_HEIGHTS STATE_AUDITOR_OPRET_WINDOW_BLOCKS /* exactly one
    possible window [0,W-1] — no seed-controlled placement needed */

struct sa_opret_fixture {
    char datadir[256];
    struct block_index blocks[SA_OPRET_HEIGHTS];
    struct uint256 hashes[SA_OPRET_HEIGHTS];
    struct main_state ms;
    struct node_db ndb;
};

/* Every 5th height carries one ZNAM-tagged OP_RETURN output + one plain
 * output; the rest are sole-output blocks (no OP_RETURN at all), so the
 * fixture exercises both "nothing to catalog" and "something to catalog"
 * heights within the one pinned window. */
/* True when detail ends with "digest_extracted=" plus all 64 hex characters:
 * a short buffer cuts the tail of the message, not its head. */
static bool sa_detail_has_full_extracted_digest(const char *detail)
{
    const char *tag = strstr(detail, "digest_extracted=");
    if (!tag)
        return false;
    const char *hex = tag + strlen("digest_extracted=");
    if (strlen(hex) != 64)
        return false;
    for (int i = 0; i < 64; i++)
        if (!((hex[i] >= '0' && hex[i] <= '9') ||
              (hex[i] >= 'a' && hex[i] <= 'f')))
            return false;
    return true;
}

static bool sa_opret_build_block(struct block *b, int height)
{
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = 1700000000u + (uint32_t)height;
    b->header.nBits = 0x2000ffff;
    b->header.nNonce.data[0] = (uint8_t)height;

    b->num_vtx = 1;
    b->vtx = calloc(1, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
    if (!b->vtx) return false;
    struct transaction *tx = &b->vtx[0];
    transaction_init(tx);

    if (height % 5 == 0) {
        transaction_alloc(tx, 1, 2);
        uint8_t tag[4] = {'Z', 'N', 'A', 'M'};
        /* The height-varying "rest" bytes are load-bearing: without them
         * every ZNAM height would build an IDENTICAL transaction (same tag,
         * same amounts, same zeroed vin) and so an IDENTICAL txid — the
         * op_return_index PK is (txid,vout_n), so every height after the
         * first would silently INSERT OR IGNORE itself away, making the
         * fixture never actually store more than one ZNAM row. */
        uint8_t rest[4] = {(uint8_t)(height >> 24), (uint8_t)(height >> 16),
                           (uint8_t)(height >> 8), (uint8_t)height};
        size_t l = sa_build_opret(tx->vout[0].script_pub_key.data, tag, 4,
                                  rest, sizeof(rest));
        tx->vout[0].script_pub_key.size = l;
        tx->vout[0].value = 0;
        tx->vout[1].value = 1;
    } else {
        transaction_alloc(tx, 1, 1);
        tx->vout[0].value = 50 + height; /* height-varying — avoid a spurious
                                          * txid collision across non-OP_RETURN
                                          * heights too (harmless to this
                                          * test, but keeps the fixture honest). */
    }
    tx->vin[0].sequence = 0xffffffff;
    transaction_compute_hash(tx);
    return true;
}

static bool sa_opret_fixture_init(struct sa_opret_fixture *f)
{
    memset(f, 0, sizeof(*f));
    snprintf(f->datadir, sizeof(f->datadir), SA_OPRET_DIR_FMT, (int)getpid());
    mkdir("./test-tmp", 0755);
    mkdir(f->datadir, 0755);
    char blocks_dir[300];
    snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", f->datadir);
    mkdir(blocks_dir, 0755);

    unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
    for (int h = 0; h < SA_OPRET_HEIGHTS; h++) {
        struct block b;
        if (!sa_opret_build_block(&b, h)) return false;

        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        bool wrote = write_block_to_disk(&b, &pos, f->datadir, msg_start);

        struct uint256 hash;
        block_get_hash(&b, &hash);
        block_free(&b);
        if (!wrote) return false;

        f->hashes[h] = hash;
        block_index_init(&f->blocks[h]);
        f->blocks[h].nHeight = h;
        f->blocks[h].phashBlock = &f->hashes[h];
        f->blocks[h].nFile = pos.nFile;
        f->blocks[h].nDataPos = pos.nPos;
        f->blocks[h].nStatus |= BLOCK_HAVE_DATA;
        if (h > 0) f->blocks[h].pprev = &f->blocks[h - 1];
    }

    main_state_init(&f->ms);
    active_chain_move_window_tip(&f->ms.chain_active,
                                 &f->blocks[SA_OPRET_HEIGHTS - 1]);

    if (!node_db_open(&f->ndb, ":memory:") || !f->ndb.open) return false;
    return true;
}

static void sa_opret_fixture_free(struct sa_opret_fixture *f)
{
    main_state_free(&f->ms);
    node_db_close(&f->ndb);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", f->datadir);
     TEST_DISCARD(system(cmd));
}

static int test_state_auditor_opret_leg(void)
{
    int failures = 0;
    struct sa_opret_fixture f;

    printf("state_auditor opret: fixture (%d on-disk blocks)... ",
          SA_OPRET_HEIGHTS);
    if (sa_opret_fixture_init(&f)) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    /* Populate the REAL catalog via the REAL backfill service first. */
    g_op_return_backfill_test_ndb = &f.ndb;
    g_op_return_backfill_test_ms = &f.ms;
    g_op_return_backfill_test_datadir = f.datadir;
    op_return_backfill_reset_for_test();
    reducer_frontier_provable_tip_set(SA_OPRET_HEIGHTS - 1);
    int folded = op_return_backfill_run_once();
    SA_CHECK("backfill populates the full window", folded == SA_OPRET_HEIGHTS);

    g_state_auditor_test_ndb = &f.ndb;
    g_state_auditor_test_ms = &f.ms;
    g_state_auditor_test_datadir = f.datadir;
    g_state_auditor_test_pdb = NULL; /* op_return leg does not touch pdb */
    state_auditor_reset_for_test();
    state_auditor_set_test_seed(0); /* only one window exists anyway */

    printf("state_auditor opret: clean catalog — zero mismatches over 10 "
          "ticks... ");
    {
        bool ok = true;
        for (int i = 0; i < 10; i++) {
            state_auditor_tick_once();
            struct state_auditor_mismatch_info info;
            state_auditor_get_mismatch(STATE_AUDITOR_LEG_OP_RETURN_INDEX,
                                       &info);
            if (info.latched) { ok = false; break; }
        }
        ok = ok && state_auditor_test_op_return_ticks() >= 10;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* Corrupt one stored row's payload_sha3 at a ZNAM height (h=5). */
    {
        uint8_t bad[32];
        memset(bad, 0xEE, 32);
        sqlite3_stmt *s = NULL;
        const char *sql =
            "UPDATE op_return_index SET payload_sha3=? WHERE height=5";
        SA_CHECK("prepare corruption UPDATE",
                sqlite3_prepare_v2(f.ndb.db, sql, -1, &s, NULL) == SQLITE_OK);
        sqlite3_bind_blob(s, 1, bad, 32, SQLITE_STATIC);
        int rc = sqlite3_step(s); // raw-sql-ok:test-fixture-corruption
        sqlite3_finalize(s);
        SA_CHECK("corruption UPDATE affected exactly 1 row",
                rc == SQLITE_DONE &&
                    sqlite3_changes(f.ndb.db) == 1);
    }

    printf("state_auditor opret: corrupted row flagged after %d confirming "
          "ticks... ", STATE_AUDITOR_CONFIRM_STREAK);
    {
        bool latched = false;
        struct state_auditor_mismatch_info info;
        memset(&info, 0, sizeof(info));
        for (int i = 0; i < STATE_AUDITOR_CONFIRM_STREAK; i++) {
            state_auditor_tick_once();
            state_auditor_get_mismatch(STATE_AUDITOR_LEG_OP_RETURN_INDEX,
                                       &info);
            latched = info.latched;
        }
        bool ok = latched && info.h_start == 0 && info.h_end == SA_OPRET_HEIGHTS - 1
                  && strstr(info.detail, "height=5") != NULL
                  && sa_detail_has_full_extracted_digest(info.detail);
        if (ok) printf("OK\n");
        else {
            printf("FAIL (latched=%d h=[%d,%d] detail=%s)\n", latched,
                   info.h_start, info.h_end, info.detail);
            failures++;
        }
    }

    printf("state_auditor opret: still latched — never a false CLEAR while "
          "corrupted... ");
    {
        state_auditor_tick_once();
        struct state_auditor_mismatch_info info;
        state_auditor_get_mismatch(STATE_AUDITOR_LEG_OP_RETURN_INDEX, &info);
        if (info.latched) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* Restore — a real external fix: truncate + re-derive the catalog from
     * the (unchanged, immutable) on-disk block bodies, exactly the recovery
     * an operator/backfill rebuild would perform. */
    {
        op_return_index_truncate(&f.ndb);
        op_return_backfill_run_once();
    }

    printf("state_auditor opret: restoring the row clears the latch (real "
          "witness)... ");
    {
        state_auditor_tick_once();
        struct state_auditor_mismatch_info info;
        state_auditor_get_mismatch(STATE_AUDITOR_LEG_OP_RETURN_INDEX, &info);
        if (!info.latched) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    g_op_return_backfill_test_ndb = NULL;
    g_op_return_backfill_test_ms = NULL;
    g_op_return_backfill_test_datadir = NULL;
    reducer_frontier_provable_tip_reset();
    g_state_auditor_test_ndb = NULL;
    g_state_auditor_test_ms = NULL;
    g_state_auditor_test_datadir = NULL;
    state_auditor_reset_for_test();
    sa_opret_fixture_free(&f);
    return failures;
}

/* ── (2) coins_commitment leg on a minimal fixture ──────────────────── */

/* Duplicates state_auditor.c's internal seed_hash() derivation (disambiguator
 * 1 == the coins leg) so the test can compute, in advance, the exact
 * txid_lo a forced test seed will select and place its fixture rows inside
 * that window deterministically — see services/state_auditor.h
 * state_auditor_set_test_seed. */
static void sa_derive_coins_txid_lo(uint64_t seed, uint8_t out[32])
{
    uint8_t buf[9];
    for (int i = 0; i < 8; i++) buf[i] = (uint8_t)(seed >> (8 * i));
    buf[8] = 1;
    zcl_sha3_256(buf, sizeof(buf), out);
}

/* base + delta as a 256-bit big-endian integer (byte[0] most significant,
 * matching SQLite BLOB memcmp ordering) — always > base for delta>0 short of
 * an all-0xFF overflow, astronomically unlikely for a SHA3 output. */
static void sa_txid_add(const uint8_t base[32], int delta, uint8_t out[32])
{
    memcpy(out, base, 32);
    int carry = delta;
    for (int i = 31; i >= 0 && carry != 0; i--) {
        int v = out[i] + carry;
        out[i] = (uint8_t)(v & 0xFF);
        carry = v >> 8;
    }
}

static bool sa_insert_utxo_row(struct node_db *ndb, const uint8_t txid[32],
                               uint32_t vout, int64_t value, int32_t height)
{
    sqlite3_stmt *s = NULL;
    const char *sql =
        "INSERT INTO utxos(txid,vout,value,script,script_type,address_hash,"
        "height,is_coinbase) VALUES(?,?,?,?,0,NULL,?,0)";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, (int)vout);
    sqlite3_bind_int64(s, 3, (sqlite3_int64)value);
    sqlite3_bind_blob(s, 4, "", 0, SQLITE_STATIC);
    sqlite3_bind_int(s, 5, height);
    int rc = sqlite3_step(s); // raw-sql-ok:test-fixture-insert
    sqlite3_finalize(s);
    return rc == SQLITE_DONE;
}

static bool sa_set_applied_height(sqlite3 *pdb, int32_t height)
{
    char *err = NULL;
    bool ok = sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, &err) ==
                  SQLITE_OK &&
              coins_kv_set_applied_height_in_tx(pdb, height) &&
              sqlite3_exec(pdb, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    return ok;
}

/* Install the three fixture rows in both stores plus the applied-height
 * markers, short-circuiting in the same order the inline chain did. */
static bool sa_install_coins_fixture_rows(sqlite3 *pdb, struct node_db *ndb,
                                          const uint8_t txid_a[32],
                                          const uint8_t txid_b[32],
                                          const uint8_t txid_c[32],
                                          int32_t height)
{
    return coins_kv_add(pdb, txid_a, 0, 5000, height, false, NULL, 0) &&
           coins_kv_add(pdb, txid_b, 0, 6000, height, false, NULL, 0) &&
           coins_kv_add(pdb, txid_c, 1, 7000, height, false, NULL, 0) &&
           sa_insert_utxo_row(ndb, txid_a, 0, 5000, height) &&
           sa_insert_utxo_row(ndb, txid_b, 0, 6000, height) &&
           sa_insert_utxo_row(ndb, txid_c, 1, 7000, height) &&
           sa_set_applied_height(pdb, height) &&
           node_db_state_set_int(ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, height);
}

/* Drive state_auditor_tick_once() the given number of times. */
static void sa_auditor_tick_n_times(int ticks)
{
    for (int i = 0; i < ticks; i++) state_auditor_tick_once();
}

/* Clean-fixture cross-check: 10 ticks with no coins-leg latch, and the
 * leg really ran (its tick counter reached 10). */
static bool sa_coins_clean_crosscheck_ok(void)
{
    bool ok = true;
    for (int i = 0; i < 10; i++) {
        state_auditor_tick_once();
        struct state_auditor_mismatch_info info;
        state_auditor_get_mismatch(STATE_AUDITOR_LEG_COINS_COMMITMENT,
                                   &info);
        if (info.latched) { ok = false; break; }
    }
    return ok && state_auditor_test_coins_ticks() >= 10;
}

/* Run STATE_AUDITOR_CONFIRM_STREAK confirming ticks on the coins leg,
 * leaving the last tick's mismatch info in *info; returns its latched flag
 * (the loop's final assignment). */
static bool sa_coins_run_confirm_streak(struct state_auditor_mismatch_info *info)
{
    memset(info, 0, sizeof(*info));
    bool latched = false;
    for (int i = 0; i < STATE_AUDITOR_CONFIRM_STREAK; i++) {
        state_auditor_tick_once();
        state_auditor_get_mismatch(STATE_AUDITOR_LEG_COINS_COMMITMENT, info);
        latched = info->latched;
    }
    return latched;
}

static int test_state_auditor_coins_leg(void)
{
    int failures = 0;

    sqlite3 *pdb = NULL;
    SA_CHECK("open in-memory progress.kv stand-in",
            sqlite3_open(":memory:", &pdb) == SQLITE_OK);
    SA_CHECK("coins_kv_ensure_schema", coins_kv_ensure_schema(pdb));
    SA_CHECK("progress_meta_table_ensure (applied-height marker storage)",
            progress_meta_table_ensure(pdb));

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    SA_CHECK("open in-memory node.db",
            node_db_open(&ndb, ":memory:") && ndb.open);

    uint8_t txid_lo[32], txid_a[32], txid_b[32], txid_c[32];
    sa_derive_coins_txid_lo(0, txid_lo);
    memcpy(txid_a, txid_lo, 32);
    sa_txid_add(txid_lo, 1, txid_b);
    sa_txid_add(txid_lo, 2, txid_c);

    const int32_t H = 100;
    bool inserted =
        sa_install_coins_fixture_rows(pdb, &ndb, txid_a, txid_b, txid_c, H);
    SA_CHECK("fixture rows + applied-height markers installed", inserted);

    g_state_auditor_test_pdb = pdb;
    g_state_auditor_test_ndb = &ndb;
    g_state_auditor_test_ms = NULL;     /* coins leg never touches ms */
    g_state_auditor_test_datadir = NULL;
    state_auditor_reset_for_test();
    state_auditor_set_test_seed(0);

    struct utxo_mirror_sync_service mirror_guard;
    memset(&mirror_guard, 0, sizeof(mirror_guard));
    g_utxo_mirror_sync = &mirror_guard;
    {
        uint64_t generation = UINT64_MAX;
        SA_CHECK("mirror audit snapshot is idle at generation zero",
                 utxo_mirror_sync_audit_snapshot(&generation) &&
                 generation == 0);
        atomic_store(&mirror_guard.updates_active, 1u);
        SA_CHECK("mirror audit snapshot refuses an active rebuild",
                 !utxo_mirror_sync_audit_snapshot(&generation));
        atomic_fetch_add(&mirror_guard.update_generation, 2u);
        atomic_store(&mirror_guard.updates_active, 0u);
        SA_CHECK("mirror audit snapshot observes completed update generation",
                 utxo_mirror_sync_audit_snapshot(&generation) &&
                 generation == 2);
    }

    printf("state_auditor coins: clean cross-check — zero mismatches over "
          "10 ticks... ");
    {
        bool ok = sa_coins_clean_crosscheck_ok();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* Corrupt row B's value in the utxos PROJECTION only. */
    {
        sqlite3_stmt *s = NULL;
        const char *sql = "UPDATE utxos SET value=value+1 WHERE txid=?";
        sqlite3_prepare_v2(ndb.db, sql, -1, &s, NULL);
        sqlite3_bind_blob(s, 1, txid_b, 32, SQLITE_STATIC);
        int rc = sqlite3_step(s); // raw-sql-ok:test-fixture-corruption
        sqlite3_finalize(s);
        SA_CHECK("corruption UPDATE affected exactly 1 row",
                rc == SQLITE_DONE && sqlite3_changes(ndb.db) == 1);
    }

    printf("state_auditor coins: active mirror rebuild is skipped, never "
          "confirmed as corruption... ");
    {
        atomic_store(&mirror_guard.updates_active, 1u);
        sa_auditor_tick_n_times(STATE_AUDITOR_CONFIRM_STREAK + 1);
        struct state_auditor_mismatch_info info;
        state_auditor_get_mismatch(STATE_AUDITOR_LEG_COINS_COMMITMENT, &info);
        atomic_fetch_add(&mirror_guard.update_generation, 2u);
        atomic_store(&mirror_guard.updates_active, 0u);
        if (!info.latched) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("state_auditor coins: corrupted row flagged after %d confirming "
          "ticks... ", STATE_AUDITOR_CONFIRM_STREAK);
    {
        struct state_auditor_mismatch_info info;
        bool latched = sa_coins_run_confirm_streak(&info);
        bool ok = latched && strstr(info.detail, "keyspace_window") != NULL;
        if (ok) printf("OK\n");
        else {
            printf("FAIL (latched=%d detail=%s)\n", latched, info.detail);
            failures++;
        }
    }

    /* Restore — a real external fix (checkpoint/projection resync). */
    {
        sqlite3_stmt *s = NULL;
        const char *sql = "UPDATE utxos SET value=value-1 WHERE txid=?";
        sqlite3_prepare_v2(ndb.db, sql, -1, &s, NULL);
        sqlite3_bind_blob(s, 1, txid_b, 32, SQLITE_STATIC);
        sqlite3_step(s); // raw-sql-ok:test-fixture-restore
        sqlite3_finalize(s);
    }

    printf("state_auditor coins: restoring the row clears the latch (real "
          "witness)... ");
    {
        state_auditor_tick_once();
        struct state_auditor_mismatch_info info;
        state_auditor_get_mismatch(STATE_AUDITOR_LEG_COINS_COMMITMENT, &info);
        if (!info.latched) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    g_state_auditor_test_pdb = NULL;
    g_state_auditor_test_ndb = NULL;
    g_utxo_mirror_sync = NULL;
    state_auditor_reset_for_test();
    node_db_close(&ndb);
    sqlite3_close(pdb);
    return failures;
}

/* ── (3) condition wiring (force-latch hooks, no fixture) ───────────── */

static int test_state_auditor_condition(void)
{
    int failures = 0;

    blocker_module_init();
    blocker_reset_for_testing();
    state_auditor_reset_for_test();

    printf("state_auditor_mismatch: detect() false when nothing latched... ");
    if (!state_auditor_mismatch_test_detect()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    state_auditor_force_latch_for_test(STATE_AUDITOR_LEG_OP_RETURN_INDEX,
                                       10, 41, "height=20 digest mismatch");

    printf("state_auditor_mismatch: detect() true once a leg is latched... ");
    if (state_auditor_mismatch_test_detect()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("state_auditor_mismatch: remedy raises "
          "state_auditor.op_return_index.mismatch... ");
    {
        int r = state_auditor_mismatch_test_remedy();
        bool exists = blocker_exists("state_auditor.op_return_index.mismatch");
        bool ok = r == COND_REMEDY_OK && exists;
        if (ok) printf("OK\n"); else { printf("FAIL (r=%d)\n", r); failures++; }
    }

    printf("state_auditor_mismatch: blocker reason names the range + "
          "detail... ");
    {
        struct blocker_snapshot snaps[BLOCKER_CAP];
        int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
        bool found = false, ok = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].id, "state_auditor.op_return_index.mismatch")
                    == 0) {
                found = true;
                ok = strstr(snaps[i].reason, "[10,41]") != NULL &&
                     strstr(snaps[i].reason, "height=20") != NULL;
            }
        }
        if (found && ok) printf("OK\n");
        else { printf("FAIL (found=%d)\n", found); failures++; }
    }

    printf("state_auditor_mismatch: witness does NOT clear while still "
          "latched... ");
    {
        bool cleared = state_auditor_mismatch_test_witness();
        bool still_exists =
            blocker_exists("state_auditor.op_return_index.mismatch");
        if (!cleared && still_exists) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    state_auditor_force_clear_for_test(STATE_AUDITOR_LEG_OP_RETURN_INDEX);

    printf("state_auditor_mismatch: witness clears the blocker once "
          "state_auditor's own latch clears... ");
    {
        bool cleared = state_auditor_mismatch_test_witness();
        bool gone = !blocker_exists("state_auditor.op_return_index.mismatch");
        if (cleared && gone) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    state_auditor_mismatch_test_reset();
    state_auditor_reset_for_test();
    blocker_reset_for_testing();
    return failures;
}

/* ── (4) exact-counter and boundary tests (mutation-gap closers) ────── */

#define SA_OPRET sa_leg_opret()
static enum state_auditor_leg sa_leg_opret(void)
{
    return STATE_AUDITOR_LEG_OP_RETURN_INDEX;
}

static void sa_ck(int *failures, const char *name, bool ok)
{
    printf("  state_auditor: %s... %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) (*failures)++;
}

static int64_t sa_dump_int(const char *key)
{
    struct json_value v;
    json_init(&v);
    int64_t r = INT64_MIN;
    if (state_auditor_dump_state_json(&v, NULL))
        r = json_get_int(json_get(&v, key));
    json_free(&v);
    return r;
}

static struct state_auditor_mismatch_info sa_tick_info(enum state_auditor_leg leg)
{
    struct state_auditor_mismatch_info info;
    state_auditor_tick_once();
    state_auditor_get_mismatch(leg, &info);
    return info;
}

/* reset_for_test also drops the forced seed; every case re-arms seed 0. */
static void sa_reset_seed0(void)
{
    state_auditor_reset_for_test();
    state_auditor_set_test_seed(0);
}

/* True when `label` is present in `detail` and is followed by at least `n`
 * lowercase hex digits. */
static bool sa_hex_field(const char *detail, const char *label, int n)
{
    const char *p = strstr(detail, label);
    if (!p) return false;
    p += strlen(label);
    for (int i = 0; i < n; i++) {
        bool hex = (p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f');
        if (!hex) return false;
    }
    return true;
}

static bool sa_opret_attach(struct sa_opret_fixture *f)
{
    g_op_return_backfill_test_ndb = &f->ndb;
    g_op_return_backfill_test_ms = &f->ms;
    g_op_return_backfill_test_datadir = f->datadir;
    op_return_backfill_reset_for_test();
    reducer_frontier_provable_tip_set(SA_OPRET_HEIGHTS - 1);
    int folded = op_return_backfill_run_once();
    g_state_auditor_test_ndb = &f->ndb;
    g_state_auditor_test_ms = &f->ms;
    g_state_auditor_test_datadir = f->datadir;
    g_state_auditor_test_pdb = NULL;
    sa_reset_seed0();
    return folded == SA_OPRET_HEIGHTS;
}

static void sa_opret_detach(struct sa_opret_fixture *f)
{
    g_op_return_backfill_test_ndb = NULL;
    g_op_return_backfill_test_ms = NULL;
    g_op_return_backfill_test_datadir = NULL;
    reducer_frontier_provable_tip_reset();
    g_state_auditor_test_ndb = NULL;
    g_state_auditor_test_ms = NULL;
    g_state_auditor_test_datadir = NULL;
    state_auditor_reset_for_test();
    sa_opret_fixture_free(f);
}

static bool sa_opret_corrupt(struct node_db *ndb, int height)
{
    uint8_t bad[32];
    memset(bad, 0xEE, sizeof(bad));
    sqlite3_stmt *s = NULL;
    const char *sql = "UPDATE op_return_index SET payload_sha3=? WHERE height=?";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(s, 1, bad, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, height);
    int rc = sqlite3_step(s); // raw-sql-ok:test-fixture-corruption
    sqlite3_finalize(s);
    return rc == SQLITE_DONE && sqlite3_changes(ndb->db) == 1;
}

static bool sa_opret_restore(struct node_db *ndb)
{
    op_return_index_truncate(ndb);
    return op_return_backfill_run_once() == SA_OPRET_HEIGHTS;
}

/* Corrupt -> candidate -> latch -> hold -> restore -> clear, with every
 * counter checked at each step. */
static void sa_opret_lifecycle(struct sa_opret_fixture *f, int *failures)
{
    struct state_auditor_mismatch_info in;
    state_auditor_tick_once();
    state_auditor_tick_once();
    state_auditor_tick_once();
    sa_ck(failures, "opret clean ticks: exact counters",
          sa_dump_int("opret_ticks_total") == 3 &&
          sa_dump_int("opret_skipped_total") == 0 &&
          sa_dump_int("opret_mismatches_total") == 0 &&
          sa_dump_int("opret_clears_total") == 0);

    sa_ck(failures, "opret corrupt h=5", sa_opret_corrupt(&f->ndb, 5));
    in = sa_tick_info(SA_OPRET);
    sa_ck(failures, "opret first mismatch is a candidate, window pinned",
          !in.latched && in.h_start == 0 && in.h_end == SA_OPRET_HEIGHTS - 1 &&
          sa_dump_int("opret_mismatches_total") == 0 &&
          sa_dump_int("opret_skipped_total") == 0);
    sa_ck(failures, "opret detail names height and row counts",
          strstr(in.detail, "height=5 stored_rows=1 extracted_rows=1 ") != NULL);
    sa_ck(failures, "opret detail carries both digests",
          sa_hex_field(in.detail, "digest_stored=", 64) &&
          sa_hex_field(in.detail, "digest_extracted=", 32));

    in = sa_tick_info(SA_OPRET);
    sa_ck(failures, "opret second mismatch latches once",
          in.latched && sa_dump_int("opret_mismatches_total") == 1);
    in = sa_tick_info(SA_OPRET);
    sa_ck(failures, "opret held latch does not recount",
          in.latched && sa_dump_int("opret_mismatches_total") == 1);

    sa_ck(failures, "opret restore", sa_opret_restore(&f->ndb));
    in = sa_tick_info(SA_OPRET);
    sa_ck(failures, "opret clean tick clears latch and counts one clear",
          !in.latched && sa_dump_int("opret_clears_total") == 1 &&
          sa_dump_int("opret_mismatches_total") == 1);
    state_auditor_tick_once();
    sa_ck(failures, "opret second clean tick adds no clear",
          sa_dump_int("opret_clears_total") == 1);

    sa_ck(failures, "opret re-corrupt h=5", sa_opret_corrupt(&f->ndb, 5));
    in = sa_tick_info(SA_OPRET);
    sa_ck(failures, "opret clear reset the streak: one mismatch is no latch",
          !in.latched && sa_dump_int("opret_mismatches_total") == 1);
    sa_ck(failures, "opret restore again", sa_opret_restore(&f->ndb));
    state_auditor_tick_once();
}

/* Pinned-window handling, driven through force_latch so the pinned range is
 * chosen by the test. The catalog is clean on entry. */
static void sa_opret_pinned(struct sa_opret_fixture *f, int *failures)
{
    struct state_auditor_mismatch_info in;

    /* inverted pin: dropped without a verdict, then a fresh window clears */
    state_auditor_force_latch_for_test(SA_OPRET, 20, 10, "forced");
    int64_t sk = sa_dump_int("opret_skipped_total");
    int64_t cl = sa_dump_int("opret_clears_total");
    in = sa_tick_info(SA_OPRET);
    sa_ck(failures, "opret inverted pin is skipped, latch untouched",
          in.latched && sa_dump_int("opret_skipped_total") == sk + 1 &&
          sa_dump_int("opret_clears_total") == cl);
    in = sa_tick_info(SA_OPRET);
    sa_ck(failures, "opret dropped pin: next tick re-checks a fresh window",
          !in.latched && sa_dump_int("opret_clears_total") == cl + 1);

    /* a one-block pin on a corrupt height is still checked */
    sa_ck(failures, "opret corrupt h=5 for one-block pin",
          sa_opret_corrupt(&f->ndb, 5));
    state_auditor_force_latch_for_test(SA_OPRET, 5, 5, "forced");
    sk = sa_dump_int("opret_skipped_total");
    in = sa_tick_info(SA_OPRET);
    sa_ck(failures, "opret one-block pin [5,5] is checked, mismatch held",
          in.latched && in.h_start == 5 && in.h_end == 5 &&
          strstr(in.detail, "height=5") != NULL &&
          sa_dump_int("opret_skipped_total") == sk);
    sa_ck(failures, "opret restore after one-block pin", sa_opret_restore(&f->ndb));
    in = sa_tick_info(SA_OPRET);
    sa_ck(failures, "opret clean one-block pin clears", !in.latched);

    /* the clear released the pin: a corrupt height outside [5,5] is seen */
    sa_ck(failures, "opret corrupt h=0 outside the old pin",
          sa_opret_corrupt(&f->ndb, 0));
    in = sa_tick_info(SA_OPRET);
    sa_ck(failures, "opret clear dropped investigating: fresh window sees h=0",
          strstr(in.detail, "height=0") != NULL && in.h_start == 0 &&
          in.h_end == SA_OPRET_HEIGHTS - 1);
    sa_ck(failures, "opret restore after h=0", sa_opret_restore(&f->ndb));
    state_auditor_tick_once();
}

/* An unreadable body is a skip, never a clear and never a mismatch. */
static void sa_opret_unreadable(struct sa_opret_fixture *f, int *failures)
{
    struct state_auditor_mismatch_info in;
    unsigned int saved = f->blocks[5].nStatus;
    int saved_file = f->blocks[5].nFile;

    f->blocks[5].nStatus = saved & ~(unsigned int)BLOCK_HAVE_DATA;
    state_auditor_force_latch_for_test(SA_OPRET, 5, 5, "forced");
    int64_t sk = sa_dump_int("opret_skipped_total");
    in = sa_tick_info(SA_OPRET);
    sa_ck(failures, "opret block without data: skipped, latch kept",
          in.latched && sa_dump_int("opret_skipped_total") == sk + 1);
    f->blocks[5].nStatus = saved;

    f->blocks[5].nFile = 99;
    state_auditor_force_latch_for_test(SA_OPRET, 5, 5, "forced");
    sk = sa_dump_int("opret_skipped_total");
    in = sa_tick_info(SA_OPRET);
    sa_ck(failures, "opret unreadable body: skipped, latch kept",
          in.latched && sa_dump_int("opret_skipped_total") == sk + 1);
    f->blocks[5].nFile = saved_file;
    state_auditor_force_clear_for_test(SA_OPRET);
}

/* Inputs that make the opret leg skip before or inside window choice. */
static void sa_opret_skip_inputs(struct sa_opret_fixture *f, int *failures)
{
    struct node_db closed;
    memset(&closed, 0, sizeof(closed));
    g_state_auditor_test_ndb = &closed;
    sa_reset_seed0();
    sa_auditor_tick_n_times(3);
    sa_ck(failures, "opret closed node_db: 3 skips, no tick counted",
          sa_dump_int("opret_ticks_total") == 0 &&
          sa_dump_int("opret_skipped_total") == 3);
    g_state_auditor_test_ndb = &f->ndb;

    g_state_auditor_test_datadir = "/";
    sa_reset_seed0();
    state_auditor_tick_once();
    sa_ck(failures, "opret one-char datadir is accepted (tick counted), body unreadable",
          sa_dump_int("opret_ticks_total") == 1 &&
          sa_dump_int("opret_skipped_total") == 1);
    g_state_auditor_test_datadir = f->datadir;

    struct node_db fresh;
    memset(&fresh, 0, sizeof(fresh));
    bool opened = node_db_open(&fresh, ":memory:") && fresh.open;
    sa_ck(failures, "opret open empty node_db", opened);
    if (opened) {
        g_state_auditor_test_ndb = &fresh;
        sa_reset_seed0();
        state_auditor_tick_once();
        sa_ck(failures, "opret empty catalog: tick counted, then skipped",
              sa_dump_int("opret_ticks_total") == 1 &&
              sa_dump_int("opret_skipped_total") == 1);
        g_state_auditor_test_ndb = &f->ndb;
    }
    node_db_close(&fresh);
}

/* History one block short of a window is skipped, whatever the base. */
static void sa_opret_short_history(struct sa_opret_fixture *f, int *failures)
{
    struct op_return_index_cursor saved, cur;
    sa_ck(failures, "opret read cursor", op_return_index_get_cursor(&f->ndb, &saved));
    cur = saved;
    cur.height = saved.height - 1;
    sa_ck(failures, "opret cursor one short", op_return_index_set_cursor(&f->ndb, &cur));
    sa_reset_seed0();
    state_auditor_tick_once();
    sa_ck(failures, "opret 31 folded blocks: skipped, no window checked",
          sa_dump_int("opret_ticks_total") == 1 &&
          sa_dump_int("opret_skipped_total") == 1);

    cur = saved;
    cur.base_height = 1;
    sa_ck(failures, "opret cursor base 1", op_return_index_set_cursor(&f->ndb, &cur));
    sa_reset_seed0();
    state_auditor_tick_once();
    sa_ck(failures, "opret base 1 leaves 31 blocks: skipped",
          sa_dump_int("opret_skipped_total") == 1);
    sa_ck(failures, "opret cursor restored", op_return_index_set_cursor(&f->ndb, &saved));
    sa_reset_seed0();
    state_auditor_tick_once();
    sa_ck(failures, "opret full window at base 0 is audited, not skipped",
          sa_dump_int("opret_ticks_total") == 1 &&
          sa_dump_int("opret_skipped_total") == 0);
}

static int sa_opret_counter_tests(void)
{
    int failures = 0;
    struct sa_opret_fixture f;
    if (!sa_opret_fixture_init(&f)) {
        printf("  state_auditor: counter fixture... FAIL\n");
        sa_opret_fixture_free(&f);
        return 1;
    }
    bool attached = sa_opret_attach(&f);
    sa_ck(&failures, "opret counter fixture backfilled", attached);
    if (attached) {
        sa_opret_lifecycle(&f, &failures);
        sa_opret_pinned(&f, &failures);
        sa_opret_unreadable(&f, &failures);
        sa_opret_skip_inputs(&f, &failures);
        sa_opret_short_history(&f, &failures);
    }
    sa_opret_detach(&f);
    return failures;
}

/* ── coins leg: exact-counter fixture ────────────────────────────────── */

struct sa_cfx {
    sqlite3 *pdb;
    struct node_db ndb;
    struct utxo_mirror_sync_service guard;
    uint8_t lo[32];
};

static bool sa_cfx_init(struct sa_cfx *c)
{
    memset(c, 0, sizeof(*c));
    if (sqlite3_open(":memory:", &c->pdb) != SQLITE_OK) return false;
    if (!coins_kv_ensure_schema(c->pdb) || !progress_meta_table_ensure(c->pdb))
        return false;
    if (!node_db_open(&c->ndb, ":memory:") || !c->ndb.open) return false;
    sa_derive_coins_txid_lo(0, c->lo);
    return true;
}

static void sa_cfx_attach(struct sa_cfx *c)
{
    g_state_auditor_test_pdb = c->pdb;
    g_state_auditor_test_ndb = &c->ndb;
    g_state_auditor_test_ms = NULL;
    g_state_auditor_test_datadir = NULL;
    g_utxo_mirror_sync = &c->guard;
    sa_reset_seed0();
}

static void sa_cfx_free(struct sa_cfx *c)
{
    g_state_auditor_test_pdb = NULL;
    g_state_auditor_test_ndb = NULL;
    g_utxo_mirror_sync = NULL;
    state_auditor_reset_for_test();
    node_db_close(&c->ndb);
    sqlite3_close(c->pdb);
}

static bool sa_cfx_put(struct sa_cfx *c, int delta, uint32_t vout, int64_t value,
                       int32_t height, bool in_auth, bool in_proj)
{
    uint8_t txid[32];
    sa_txid_add(c->lo, delta, txid);
    if (in_auth &&
        !coins_kv_add(c->pdb, txid, vout, value, height, false, NULL, 0))
        return false;
    return !in_proj || sa_insert_utxo_row(&c->ndb, txid, vout, value, height);
}

static bool sa_cfx_markers(struct sa_cfx *c, int32_t h)
{
    return sa_set_applied_height(c->pdb, h) &&
           node_db_state_set_int(&c->ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, h);
}

static bool sa_cfx_update_b(struct sa_cfx *c, const char *sql)
{
    uint8_t txid_b[32];
    sa_txid_add(c->lo, 1, txid_b);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(c->ndb.db, sql, -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(s, 1, txid_b, 32, SQLITE_STATIC);
    int rc = sqlite3_step(s); // raw-sql-ok:test-fixture-corruption
    sqlite3_finalize(s);
    return rc == SQLITE_DONE && sqlite3_changes(c->ndb.db) == 1;
}

/* First seed >= 1 whose keyspace window starts above every fixture row, so a
 * window drawn from it holds none of them. */
static int64_t sa_far_seed(const uint8_t rows_max[32])
{
    uint8_t lo[32];
    for (uint64_t s = 1; s < 4096; s++) {
        sa_derive_coins_txid_lo(s, lo);
        if (memcmp(lo, rows_max, 32) > 0) return (int64_t)s;
    }
    return -1;
}

static bool sa_detail_has_window(const char *detail, const uint8_t lo[32],
                                 const char *rows)
{
    char hex[65] = {0};
    char want[96];
    HexStr(lo, 32, false, hex, sizeof(hex));
    snprintf(want, sizeof(want), "txid_lo=%s", hex);
    return strstr(detail, want) != NULL && strstr(detail, rows) != NULL;
}

/* Install A(h100) B(h90) C(h110) in both stores, markers at 100. */
static bool sa_cfx_standard_rows(struct sa_cfx *c)
{
    return sa_cfx_put(c, 0, 0, 5000, 100, true, true) &&
           sa_cfx_put(c, 1, 0, 6000, 90, true, true) &&
           sa_cfx_put(c, 2, 1, 7000, 110, true, true) &&
           sa_cfx_markers(c, 100);
}

static void sa_coins_lifecycle_first(struct sa_cfx *c, int *failures)
{
    sa_ck(failures, "coins corrupt B (value and height) in the projection",
          sa_cfx_update_b(c, "UPDATE utxos SET value=value+1, height=120 "
                             "WHERE txid=?"));
    struct state_auditor_mismatch_info in = sa_tick_info(STATE_AUDITOR_LEG_COINS_COMMITMENT);
    sa_ck(failures, "coins first mismatch is a candidate with exact counters",
          !in.latched && sa_dump_int("coins_ticks_total") == 1 &&
          sa_dump_int("coins_skipped_total") == 0 &&
          sa_dump_int("coins_mismatches_total") == 0);
    sa_ck(failures, "coins detail: window, row counts, merged heights",
          sa_detail_has_window(in.detail, c->lo, "rows(auth=3 proj=3) heights=[90,120]"));
    sa_ck(failures, "coins last height span stored on the first mismatch",
          in.h_start == 90 && in.h_end == 120 &&
          sa_dump_int("coins_h_min") == 90 && sa_dump_int("coins_h_max") == 120);
}

static void sa_coins_lifecycle_pinned(struct sa_cfx *c, int64_t far, int *failures)
{
    state_auditor_set_test_seed(far);
    struct state_auditor_mismatch_info in = sa_tick_info(STATE_AUDITOR_LEG_COINS_COMMITMENT);
    sa_ck(failures, "coins second tick re-checks the PINNED window and latches",
          in.latched && sa_dump_int("coins_mismatches_total") == 1);
    sa_ck(failures, "coins pinned window kept in the detail",
          sa_detail_has_window(in.detail, c->lo, "rows(auth=3 proj=3)"));
    in = sa_tick_info(STATE_AUDITOR_LEG_COINS_COMMITMENT);
    sa_ck(failures, "coins held latch does not recount",
          in.latched && sa_dump_int("coins_mismatches_total") == 1);
    sa_ck(failures, "coins restore B",
          sa_cfx_update_b(c, "UPDATE utxos SET value=value-1, height=90 "
                             "WHERE txid=?"));
    in = sa_tick_info(STATE_AUDITOR_LEG_COINS_COMMITMENT);
    sa_ck(failures, "coins clean tick clears: one clear, no extra skip",
          !in.latched && sa_dump_int("coins_clears_total") == 1 &&
          sa_dump_int("coins_skipped_total") == 0);
}

static void sa_coins_lifecycle_after_clear(struct sa_cfx *c, int *failures)
{
    struct state_auditor_mismatch_info in;
    sa_ck(failures, "coins re-corrupt B",
          sa_cfx_update_b(c, "UPDATE utxos SET value=value+1, height=120 "
                             "WHERE txid=?"));
    /* far seed still set: a released pin means a fresh, empty window */
    state_auditor_tick_once();
    in = sa_tick_info(STATE_AUDITOR_LEG_COINS_COMMITMENT);
    sa_ck(failures, "coins clear released the pin: far window sees nothing",
          !in.latched && sa_dump_int("coins_mismatches_total") == 1 &&
          sa_dump_int("coins_clears_total") == 1);
    state_auditor_set_test_seed(0);
    in = sa_tick_info(STATE_AUDITOR_LEG_COINS_COMMITMENT);
    sa_ck(failures, "coins clear reset the streak: one mismatch is no latch",
          !in.latched && sa_dump_int("coins_mismatches_total") == 1);
    sa_ck(failures, "coins restore B again",
          sa_cfx_update_b(c, "UPDATE utxos SET value=value-1, height=90 "
                             "WHERE txid=?"));
    state_auditor_tick_once();
}

static int sa_coins_lifecycle_tests(void)
{
    int failures = 0;
    struct sa_cfx c;
    bool ok = sa_cfx_init(&c) && sa_cfx_standard_rows(&c);
    sa_ck(&failures, "coins lifecycle fixture", ok);
    if (ok) {
        sa_cfx_attach(&c);
        uint8_t row_c[32];
        sa_txid_add(c.lo, 2, row_c);
        int64_t far = sa_far_seed(row_c);
        sa_ck(&failures, "coins found a seed whose window misses the rows", far > 0);
        sa_coins_lifecycle_first(&c, &failures);
        if (far > 0) {
            sa_coins_lifecycle_pinned(&c, far, &failures);
            sa_coins_lifecycle_after_clear(&c, &failures);
        }
    }
    sa_cfx_free(&c);
    return failures;
}

/* Merged height span for each combination of populated/empty sides. Auth
 * rows use txid lo+i, projection rows lo+10+i, so every case mismatches. */
struct sa_merge_case {
    int n_auth;
    int32_t auth_h[3];
    int n_proj;
    int32_t proj_h[3];
    int32_t want_min, want_max;
    const char *rows;
};

static bool sa_merge_fill(struct sa_cfx *c, const struct sa_merge_case *m)
{
    for (int i = 0; i < m->n_auth; i++)
        if (!sa_cfx_put(c, i, 0, 1000 + i, m->auth_h[i], true, false))
            return false;
    for (int i = 0; i < m->n_proj; i++)
        if (!sa_cfx_put(c, 10 + i, 0, 2000 + i, m->proj_h[i], false, true))
            return false;
    return sa_cfx_markers(c, 100);
}

static void sa_merge_run(const struct sa_merge_case *m, int *failures)
{
    struct sa_cfx c;
    bool ok = sa_cfx_init(&c) && sa_merge_fill(&c, m);
    sa_ck(failures, "coins merge fixture", ok);
    if (ok) {
        sa_cfx_attach(&c);
        struct state_auditor_mismatch_info in = sa_tick_info(STATE_AUDITOR_LEG_COINS_COMMITMENT);
        char want[64];
        snprintf(want, sizeof(want), "heights=[%d,%d]", (int)m->want_min,
                 (int)m->want_max);
        sa_ck(failures, m->rows,
              sa_detail_has_window(in.detail, c.lo, m->rows) &&
              strstr(in.detail, want) != NULL && !in.latched &&
              in.h_start == m->want_min && in.h_end == m->want_max);
    }
    sa_cfx_free(&c);
}

static int sa_coins_merge_tests(void)
{
    static const struct sa_merge_case k_cases[] = {
        { 1, {50}, 1, {40}, 40, 50, "rows(auth=1 proj=1)" },
        { 0, {0}, 2, {7, 9}, 7, 9, "rows(auth=0 proj=2)" },
        { 2, {5, 8}, 0, {0}, 5, 8, "rows(auth=2 proj=0)" },
        { 3, {100, 90, 110}, 3, {100, 120, 110}, 90, 120, "rows(auth=3 proj=3)" },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(k_cases) / sizeof(k_cases[0]); i++)
        sa_merge_run(&k_cases[i], &failures);
    return failures;
}

/* ── coins leg: states that must be skipped, never cleared ───────────── */

static void sa_coins_expect_skip(const char *label, int *failures)
{
    state_auditor_force_latch_for_test(STATE_AUDITOR_LEG_COINS_COMMITMENT, 1, 2,
                                       "forced");
    int64_t sk = sa_dump_int("coins_skipped_total");
    int64_t cl = sa_dump_int("coins_clears_total");
    struct state_auditor_mismatch_info in = sa_tick_info(STATE_AUDITOR_LEG_COINS_COMMITMENT);
    sa_ck(failures, label,
          in.latched && sa_dump_int("coins_skipped_total") == sk + 1 &&
          sa_dump_int("coins_clears_total") == cl);
    state_auditor_force_clear_for_test(STATE_AUDITOR_LEG_COINS_COMMITMENT);
}

struct sa_lock_holder {
    pthread_mutex_t m;
    pthread_cond_t cv;
    bool held;
    bool release;
};

static void *sa_lock_holder_main(void *arg)
{
    struct sa_lock_holder *h = arg;
    progress_store_tx_lock();
    pthread_mutex_lock(&h->m);
    h->held = true;
    pthread_cond_broadcast(&h->cv);
    while (!h->release) pthread_cond_wait(&h->cv, &h->m);
    pthread_mutex_unlock(&h->m);
    progress_store_tx_unlock();
    return NULL;
}

/* The reducer holds the progress-store transaction lock: skip. */
static void sa_coins_busy_lock(int *failures)
{
    struct sa_lock_holder h = { PTHREAD_MUTEX_INITIALIZER,
                                PTHREAD_COND_INITIALIZER, false, false };
    pthread_t t;
    if (pthread_create(&t, NULL, sa_lock_holder_main, &h) != 0) {
        sa_ck(failures, "coins lock holder thread", false);
        return;
    }
    pthread_mutex_lock(&h.m);
    while (!h.held) pthread_cond_wait(&h.cv, &h.m);
    pthread_mutex_unlock(&h.m);
    sa_coins_expect_skip("coins busy progress-store lock: skipped", failures);
    pthread_mutex_lock(&h.m);
    h.release = true;
    pthread_cond_broadcast(&h.cv);
    pthread_mutex_unlock(&h.m);
    pthread_join(t, NULL);
}

/* Applied height absent while the cursor reads -1: -1 == -1 must not make the
 * pair comparable. */
static void sa_coins_missing_marker(struct sa_cfx *c, int *failures)
{
    sqlite3 *empty = NULL;
    bool ok = sqlite3_open(":memory:", &empty) == SQLITE_OK &&
              coins_kv_ensure_schema(empty) && progress_meta_table_ensure(empty) &&
              node_db_state_set_int(&c->ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, -1);
    sa_ck(failures, "coins missing-marker fixture", ok);
    if (ok) {
        g_state_auditor_test_pdb = empty;
        sa_coins_expect_skip("coins applied height absent, cursor -1: skipped",
                             failures);
        g_state_auditor_test_pdb = c->pdb;
    }
    sqlite3_close(empty);
    node_db_state_set_int(&c->ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, 100);
}

static int sa_coins_skip_tests(void)
{
    int failures = 0;
    struct sa_cfx c;
    bool ok = sa_cfx_init(&c) && sa_cfx_standard_rows(&c);
    sa_ck(&failures, "coins skip fixture", ok);
    if (ok) {
        sa_cfx_attach(&c);
        sa_ck(&failures, "coins skip fixture sets cursor off by one",
              node_db_state_set_int(&c.ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, 101));
        sa_coins_expect_skip("coins projection cursor ahead of authority: skipped",
                             &failures);
        node_db_state_set_int(&c.ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, 100);

        atomic_store(&c.guard.updates_active, 1u);
        sa_coins_expect_skip("coins active mirror rebuild: skipped", &failures);
        atomic_store(&c.guard.updates_active, 0u);

        struct node_db closed;
        memset(&closed, 0, sizeof(closed));
        g_state_auditor_test_ndb = &closed;
        sa_coins_expect_skip("coins closed node_db: skipped", &failures);
        g_state_auditor_test_ndb = &c.ndb;

        sa_coins_missing_marker(&c, &failures);
        sa_coins_busy_lock(&failures);
    }
    sa_cfx_free(&c);
    return failures;
}

static int sa_coins_counter_tests(void)
{
    return sa_coins_lifecycle_tests() + sa_coins_merge_tests() +
           sa_coins_skip_tests();
}

/* ── leg names ──────────────────────────────────────────────────────── */

static int sa_leg_name_tests(void)
{
    int failures = 0;
    sa_ck(&failures, "leg name op_return_index",
          strcmp(state_auditor_leg_name(STATE_AUDITOR_LEG_OP_RETURN_INDEX),
                 "op_return_index") == 0);
    sa_ck(&failures, "leg name coins_commitment",
          strcmp(state_auditor_leg_name(STATE_AUDITOR_LEG_COINS_COMMITMENT),
                 "coins_commitment") == 0);
    sa_ck(&failures, "leg name unknown",
          strcmp(state_auditor_leg_name(STATE_AUDITOR_LEG_COUNT), "unknown") == 0);
    return failures;
}

/* ── entry point ──────────────────────────────────────────────────── */

int test_state_auditor(void)
{
    printf("\n=== state_auditor tests ===\n");
    int failures = 0;
    failures += test_state_auditor_opret_leg();
    failures += test_state_auditor_coins_leg();
    failures += test_state_auditor_condition();
    failures += sa_opret_counter_tests();
    failures += sa_coins_counter_tests();
    failures += sa_leg_name_tests();
    return failures;
}
