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
#include "framework/condition.h"
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

#include <sqlite3.h>
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

    active_chain_init(&f->ms.chain_active);
    active_chain_move_window_tip(&f->ms.chain_active,
                                 &f->blocks[SA_OPRET_HEIGHTS - 1]);

    if (!node_db_open(&f->ndb, ":memory:") || !f->ndb.open) return false;
    return true;
}

static void sa_opret_fixture_free(struct sa_opret_fixture *f)
{
    active_chain_free(&f->ms.chain_active);
    node_db_close(&f->ndb);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", f->datadir);
    (void)system(cmd);
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
                  && strstr(info.detail, "height=5") != NULL;
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
        coins_kv_add(pdb, txid_a, 0, 5000, H, false, NULL, 0) &&
        coins_kv_add(pdb, txid_b, 0, 6000, H, false, NULL, 0) &&
        coins_kv_add(pdb, txid_c, 1, 7000, H, false, NULL, 0) &&
        sa_insert_utxo_row(&ndb, txid_a, 0, 5000, H) &&
        sa_insert_utxo_row(&ndb, txid_b, 0, 6000, H) &&
        sa_insert_utxo_row(&ndb, txid_c, 1, 7000, H) &&
        sa_set_applied_height(pdb, H) &&
        node_db_state_set_int(&ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, H);
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
        bool ok = true;
        for (int i = 0; i < 10; i++) {
            state_auditor_tick_once();
            struct state_auditor_mismatch_info info;
            state_auditor_get_mismatch(STATE_AUDITOR_LEG_COINS_COMMITMENT,
                                       &info);
            if (info.latched) { ok = false; break; }
        }
        ok = ok && state_auditor_test_coins_ticks() >= 10;
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
        for (int i = 0; i < STATE_AUDITOR_CONFIRM_STREAK + 1; i++)
            state_auditor_tick_once();
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
        bool latched = false;
        struct state_auditor_mismatch_info info;
        memset(&info, 0, sizeof(info));
        for (int i = 0; i < STATE_AUDITOR_CONFIRM_STREAK; i++) {
            state_auditor_tick_once();
            state_auditor_get_mismatch(STATE_AUDITOR_LEG_COINS_COMMITMENT,
                                       &info);
            latched = info.latched;
        }
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

/* ── entry point ──────────────────────────────────────────────────── */

int test_state_auditor(void)
{
    printf("\n=== state_auditor tests ===\n");
    int failures = 0;
    failures += test_state_auditor_opret_leg();
    failures += test_state_auditor_coins_leg();
    failures += test_state_auditor_condition();
    return failures;
}
