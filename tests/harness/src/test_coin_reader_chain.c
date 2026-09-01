/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_coin_reader_chain — the explorer/wallet coin read chain, end to end,
 * with only ONE UTXO ledger behind it.
 *
 * The kernel coins store (`coins` in progress.kv) is the single canonical UTXO
 * set. Everything an operator actually looks at is a read model derived from
 * it, in exactly one direction:
 *
 *     coins_kv (progress.kv `coins`)
 *        -> utxo_mirror_sync_service
 *        -> node.db `utxos`
 *        -> db_utxo_rebuild_wallet_and_address_caches
 *        -> node.db `wallet_utxos` + `addresses`
 *        -> wallet balance (db_wallet_utxo_balance) and the explorer's
 *           supply/hodl readouts (hodl_wave_scan_current_utxos, the
 *           count/SUM(value) that explorer_factoids_view.c serves)
 *
 * This test pins that chain against three failure modes that would each read as
 * "the explorer/wallet is empty" rather than as a crash:
 *
 *  (A) The canonical ledger stops round-tripping coin CONTENT (value + script),
 *      so every downstream number is wrong but nothing errors.
 *
 *  (B) The boot migration marks an EMPTY coins_kv as "migration complete".
 *      This is the sharp edge: coins_kv_seed_from_node_db() — the surviving
 *      seed used by reindex_epilogue, utxo_recovery_restore and
 *      boot_refold_staged — short-circuits on that stamp. A false stamp on an
 *      empty store therefore makes the seed a permanent no-op, coins_kv stays
 *      empty, the mirror mirrors nothing, and the wallet/explorer report a
 *      zero balance forever with no error anywhere.
 *
 *  (C) The node.db read models stop deriving from `utxos` (wallet_utxos would
 *      silently drop real coins; the address cache would under-report).
 *
 * The read chain is also asserted to be projection-free: no `utxo` /
 * `projection_meta` table is created in either database and no
 * utxo_projection.db file appears, so the numbers below are produced with the
 * demoted third UTXO copy provably absent rather than merely unused.
 */

#include "test/test_core.h"

#include "core/uint256.h"
#include "jobs/utxo_apply_stage.h"
#include "models/database.h"
#include "models/hodl_wave.h"
#include "models/utxo.h"
#include "models/wallet_tx.h"
#include "script/standard.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CRC_CHECK(name, expr) do {                                          \
    if (expr) { printf("  coin_reader_chain: %s... OK\n", (name)); }        \
    else { printf("  coin_reader_chain: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* ── tiny sqlite helpers (exec-only: no raw sqlite3_step in this file) ── */

static int crc_i64_cb(void *ctx, int ncol, char **vals, char **names)
{
    (void)names;
    if (ncol >= 1 && vals && vals[0])
        *(int64_t *)ctx = (int64_t)strtoll(vals[0], NULL, 10);
    return 0;
}

/* Run a single-value SELECT and return it, or `def` when the query yields
 * nothing (or fails). */
static int64_t crc_q_i64(sqlite3 *db, const char *sql, int64_t def)
{
    int64_t v = def;
    if (!db || sqlite3_exec(db, sql, crc_i64_cb, &v, NULL) != SQLITE_OK)
        return def;
    return v;
}

static bool crc_exec(sqlite3 *db, const char *sql)
{
    return db && sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static bool crc_table_exists(sqlite3 *db, const char *name)
{
    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='%s'",
             name);
    return crc_q_i64(db, sql, 0) > 0;
}

static struct uint256 crc_txid(uint8_t tag)
{
    struct uint256 t;
    uint256_set_null(&t);
    t.data[0] = tag;
    t.data[1] = 0x5A;
    t.data[31] = 0xC1;
    return t;
}

static bool crc_stamp_present(sqlite3 *db)
{
    uint8_t v = 0;
    size_t n = 0;
    bool found = false;
    return progress_meta_get(db, COINS_KV_MIGRATION_COMPLETE_KEY, &v, sizeof(v),
                             &n, &found) && found && n == 1 && v == 1;
}

/* The three fixture coins. Two pay a wallet-owned address_hash, one pays a
 * stranger; every value differs so a mis-joined row is visible in the sums. */
#define CRC_H_A 100
#define CRC_H_B 140
#define CRC_H_C 180
#define CRC_V_A 4000LL   /* wallet-owned */
#define CRC_V_B 5500LL   /* wallet-owned */
#define CRC_V_C 6250LL   /* stranger     */
#define CRC_V_WALLET (CRC_V_A + CRC_V_B)
#define CRC_V_ALL    (CRC_V_A + CRC_V_B + CRC_V_C)

/* ── Part A/B: the canonical ledger + the boot-migration stamp ─────────── */

/* Build a source database FILE holding the node.db-shaped `utxos` table that
 * coins_kv_seed_from_node_db() copies from. Heights stay far below any baked
 * SHA3 checkpoint height so the seed's checkpoint-content gate is invisible
 * (COINS_KV_CHECKPOINT_NOT_CHECKED) and cannot _exit the test process. */
static bool crc_write_seed_source(const char *path)
{
    sqlite3 *src = NULL;
    if (sqlite3_open(path, &src) != SQLITE_OK) {
        if (src) sqlite3_close(src);
        return false;
    }
    struct uint256 a = crc_txid(0xA1), b = crc_txid(0xB2), c = crc_txid(0xC3);
    uint8_t script[3] = {0x76, 0xA9, 0x14};
    bool ok = coins_kv_ensure_schema(src) &&
              coins_kv_add(src, a.data, 0, CRC_V_A, CRC_H_A, false,
                           script, sizeof(script)) &&
              coins_kv_add(src, b.data, 0, CRC_V_B, CRC_H_B, false,
                           script, sizeof(script)) &&
              coins_kv_add(src, c.data, 1, CRC_V_C, CRC_H_C, true,
                           script, sizeof(script));
    /* coins_kv_seed_from_node_db reads coinssrc.utxos. */
    ok = ok && crc_exec(src, "ALTER TABLE coins RENAME TO utxos");
    sqlite3_close(src);
    return ok;
}

static int crc_case_canonical_ledger(const char *dir)
{
    int failures = 0;
    char kv_path[512];
    char src_path[512];
    sqlite3 *kv = NULL;

    snprintf(kv_path, sizeof(kv_path), "%s/progress_kv.db", dir);
    snprintf(src_path, sizeof(src_path), "%s/seed_src.db", dir);
    (void)unlink(kv_path);
    (void)unlink(src_path);

    CRC_CHECK("seed source built", crc_write_seed_source(src_path));

    if (sqlite3_open(kv_path, &kv) != SQLITE_OK) {
        printf("  coin_reader_chain: open progress_kv... FAIL\n");
        if (kv) sqlite3_close(kv);
        return failures + 1;
    }
    CRC_CHECK("coins schema + meta table",
              coins_kv_ensure_schema(kv) && progress_meta_table_ensure(kv));

    /* (B) An EMPTY coins_kv must survive the boot migration WITHOUT a
     * completion stamp. A stamp here would make the surviving seed path a
     * permanent no-op and strand every downstream reader at zero. */
    CRC_CHECK("boot rebuild on empty coins_kv succeeds",
              coins_kv_boot_rebuild_if_needed(kv));
    CRC_CHECK("boot rebuild left coins_kv empty", coins_kv_count(kv) == 0);
    CRC_CHECK("boot rebuild did NOT stamp migration-complete on an empty store",
              !crc_stamp_present(kv));

    /* The seed the boot path no longer performs is still reachable. */
    CRC_CHECK("seed_from_node_db copies the borrowed set",
              coins_kv_seed_from_node_db(kv, src_path));
    CRC_CHECK("coins_kv holds all three coins", coins_kv_count(kv) == 3);
    CRC_CHECK("seed stamped migration-complete", crc_stamp_present(kv));

    /* (A) Coin CONTENT round-trips, not just row count. */
    {
        struct uint256 b = crc_txid(0xB2);
        int64_t value = -1;
        uint8_t script[8] = {0};
        size_t script_len = 0;
        bool live = coins_kv_get(kv, b.data, 0, &value, script, sizeof(script),
                                 &script_len);
        CRC_CHECK("canonical read returns the live coin", live);
        CRC_CHECK("canonical read returns the exact value", value == CRC_V_B);
        CRC_CHECK("canonical read returns the exact script",
                  script_len == 3 && script[0] == 0x76 && script[1] == 0xA9 &&
                  script[2] == 0x14);
    }

    /* A second boot over a POPULATED store is the idempotent stamp-only path. */
    CRC_CHECK("re-running boot rebuild is a no-op",
              coins_kv_boot_rebuild_if_needed(kv) && coins_kv_count(kv) == 3);

    /* Projection-free: the demoted copy's tables are nowhere in this store. */
    CRC_CHECK("no `utxo` table in progress.kv", !crc_table_exists(kv, "utxo"));
    CRC_CHECK("no `projection_meta` table in progress.kv",
              !crc_table_exists(kv, "projection_meta"));

    sqlite3_close(kv);
    return failures;
}

/* ── Part C: the node.db read models the explorer and wallet actually read ── */

static bool crc_save_utxo(struct node_db *ndb, uint8_t tag, uint32_t vout,
                          int64_t value, int height, bool coinbase,
                          const uint8_t addr[20])
{
    struct db_utxo u;
    uint8_t script[3] = {0x76, 0xA9, 0x14};
    struct uint256 t = crc_txid(tag);

    memset(&u, 0, sizeof(u));
    memcpy(u.txid, t.data, 32);
    u.vout = vout;
    u.value = value;
    u.script = script;
    u.script_len = sizeof(script);
    u.script_type = SCRIPT_P2PKH;
    memcpy(u.address_hash, addr, 20);
    u.has_address = true;
    u.height = height;
    u.is_coinbase = coinbase;
    return db_utxo_save(ndb, &u);
}

static int crc_case_read_models(const char *dir)
{
    int failures = 0;
    char db_path[512];
    struct node_db ndb;
    uint8_t mine[20];
    uint8_t theirs[20];

    memset(mine, 0x11, sizeof(mine));
    memset(theirs, 0x22, sizeof(theirs));

    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
    (void)unlink(db_path);
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, db_path)) {
        printf("  coin_reader_chain: open node.db... FAIL\n");
        return failures + 1;
    }

    /* The mirror's output: node.db `utxos`, two wallet-owned + one stranger. */
    CRC_CHECK("mirror rows saved",
              crc_save_utxo(&ndb, 0xA1, 0, CRC_V_A, CRC_H_A, false, mine) &&
              crc_save_utxo(&ndb, 0xB2, 0, CRC_V_B, CRC_H_B, false, mine) &&
              crc_save_utxo(&ndb, 0xC3, 1, CRC_V_C, CRC_H_C, true, theirs));
    CRC_CHECK("utxo count", db_utxo_count(&ndb) == 3);
    CRC_CHECK("utxo total value", db_utxo_total_value(&ndb) == CRC_V_ALL);
    CRC_CHECK("utxo max height", db_utxo_max_height(&ndb) == CRC_H_C);

    /* One wallet key owns the first two coins. wallet_keys has no model save
     * (the secret column's single writer is wallet_sqlite), so seed the
     * lookup column directly. */
    CRC_CHECK("wallet key seeded",
              crc_exec(ndb.db,
                       "INSERT INTO wallet_keys(pubkey_hash,pubkey,privkey) "
                       "VALUES (x'1111111111111111111111111111111111111111',"
                       "        x'02', x'01')"));

    /* The wallet read path: wallet_utxos is derived from `utxos` JOIN
     * wallet_keys — it must pick up exactly the owned coins, no more, no
     * less. A read model that silently lost its source reports zero here. */
    CRC_CHECK("wallet/address caches rebuilt",
              db_utxo_rebuild_wallet_and_address_caches(&ndb));
    {
        int count = -1;
        int64_t bal = db_wallet_utxo_balance_with_count(&ndb, &count);
        CRC_CHECK("wallet balance is the owned coins only", bal == CRC_V_WALLET);
        CRC_CHECK("wallet utxo count is the owned coins only", count == 2);
    }
    CRC_CHECK("stranger coin excluded from wallet_utxos",
              crc_q_i64(ndb.db,
                        "SELECT COALESCE(SUM(value),0) FROM wallet_utxos "
                        "WHERE address_hash = "
                        "x'2222222222222222222222222222222222222222'", -1) == 0);

    /* The address cache the explorer's address pages read. */
    CRC_CHECK("address cache balance (owned)",
              db_utxo_balance_for_address(&ndb, mine) == CRC_V_WALLET);
    CRC_CHECK("address cache balance (stranger)",
              db_utxo_balance_for_address(&ndb, theirs) == CRC_V_C);
    CRC_CHECK("addresses row aggregates the owned coins",
              crc_q_i64(ndb.db,
                        "SELECT balance FROM addresses WHERE address_hash = "
                        "x'1111111111111111111111111111111111111111'", -1)
                  == CRC_V_WALLET &&
              crc_q_i64(ndb.db,
                        "SELECT utxo_count FROM addresses WHERE address_hash = "
                        "x'1111111111111111111111111111111111111111'", -1) == 2);

    /* The explorer read path: supply totals + the hodl-wave scan. These are
     * the exact queries explorer_factoids_view.c / api_controller_compute.c
     * serve, so a broken source shows up as a wrong public number. */
    CRC_CHECK("explorer supply count/value",
              crc_q_i64(ndb.db, "SELECT count(*) FROM utxos", -1) == 3 &&
              crc_q_i64(ndb.db, "SELECT COALESCE(SUM(value),0) FROM utxos", -1)
                  == CRC_V_ALL);
    CRC_CHECK("explorer utxo tip height",
              crc_q_i64(ndb.db, "SELECT COALESCE(MAX(height),0) FROM utxos", -1)
                  == CRC_H_C);
    {
        struct hodl_wave_snapshot hodl;
        memset(&hodl, 0, sizeof(hodl));
        bool ok = hodl_wave_scan_current_utxos(ndb.db, CRC_H_C, &hodl);
        CRC_CHECK("hodl scan ok", ok);
        CRC_CHECK("hodl total count", hodl.total_count == 3);
        CRC_CHECK("hodl total value", hodl.total_value == CRC_V_ALL);
        CRC_CHECK("hodl skipped no rows", hodl.skipped_rows == 0);
    }

    /* Deleting a coin from the mirror propagates to both read models — the
     * derivation is live, not a one-time copy that would mask a stale source. */
    {
        struct uint256 a = crc_txid(0xA1);
        CRC_CHECK("mirror row deleted", db_utxo_delete(&ndb, a.data, 0));
        CRC_CHECK("caches rebuilt after delete",
                  db_utxo_rebuild_wallet_and_address_caches(&ndb));
        CRC_CHECK("wallet balance follows the mirror",
                  db_wallet_utxo_balance(&ndb) == CRC_V_B);
        CRC_CHECK("explorer supply follows the mirror",
                  crc_q_i64(ndb.db,
                            "SELECT COALESCE(SUM(value),0) FROM utxos", -1)
                      == CRC_V_ALL - CRC_V_A);
    }

    /* Projection-free: node.db never grows the demoted copy's tables. */
    CRC_CHECK("no `utxo` table in node.db", !crc_table_exists(ndb.db, "utxo"));
    CRC_CHECK("no `projection_meta` table in node.db",
              !crc_table_exists(ndb.db, "projection_meta"));

    node_db_close(&ndb);
    return failures;
}

/* ── Part D: the forward fold is self-derived on the boot that stamps it ──
 *
 * A from-genesis node's coins_kv is populated by its own utxo_apply fold with
 * NO migration stamp (every borrowed-state path — node.db import seed,
 * consensus-state bundle install, anchor refold — stamps migration-complete in
 * the same transaction that populates the set). The boot that recognises that
 * set (coins_kv_boot_rebuild_if_needed on a populated, unstamped store) must
 * stamp migration-complete AND the self-folded marker together: stamping only
 * the former flips the sovereignty gate to release_assisted
 * ("borrowed_seed_no_refold_marker") on the very boot that first makes the
 * money gate's proven-authority rung pass — a catch-22 that strands a fresh
 * self-folded node unable to mint or spend. */
static int crc_case_forward_fold_sovereign_stamp(const char *dir)
{
    int failures = 0;
    char kv_path[512];
    sqlite3 *kv = NULL;

    snprintf(kv_path, sizeof(kv_path), "%s/fold_progress_kv.db", dir);
    (void)unlink(kv_path);
    if (sqlite3_open(kv_path, &kv) != SQLITE_OK) {
        printf("  coin_reader_chain: open fold progress_kv... FAIL\n");
        if (kv) sqlite3_close(kv);
        return failures + 1;
    }
    CRC_CHECK("fold store schema + meta table",
              coins_kv_ensure_schema(kv) && progress_meta_table_ensure(kv));

    /* The node's own fold output: a coin present and the applied frontier
     * advanced, with NOT ONE stamp (borrowed paths always co-commit theirs). */
    {
        struct uint256 a = crc_txid(0xD4);
        uint8_t script[3] = {0x76, 0xA9, 0x14};
        CRC_CHECK("fold coin applied",
                  coins_kv_add(kv, a.data, 0, CRC_V_A, CRC_H_A, true,
                               script, sizeof(script)));
    }
    {
        bool frontier_ok = false;
        if (crc_exec(kv, "BEGIN IMMEDIATE")) {
            frontier_ok = coins_kv_set_applied_height_in_tx(kv, CRC_H_A + 1) &&
                          crc_exec(kv, "COMMIT");
        }
        CRC_CHECK("fold applied frontier advanced", frontier_ok);
    }
    CRC_CHECK("no migration stamp before boot", !crc_stamp_present(kv));
    CRC_CHECK("no self-folded marker before boot",
              !coins_kv_contains_refold_marker(kv));
    {
        char why[96] = {0};
        CRC_CHECK("unstamped fold is not treated as borrowed",
                  coins_kv_tip_is_self_derived(kv, CRC_H_A, why, sizeof(why)));
    }

    CRC_CHECK("boot recognises the populated fold",
              coins_kv_boot_rebuild_if_needed(kv));
    CRC_CHECK("boot stamped migration-complete", crc_stamp_present(kv));
    CRC_CHECK("boot stamped the self-folded marker",
              coins_kv_contains_refold_marker(kv));
    CRC_CHECK("boot-recognised fold is proven authority",
              coins_kv_is_proven_authority(kv, NULL));
    {
        char why[96] = {0};
        CRC_CHECK("stamped fold stays self-derived (no catch-22)",
                  coins_kv_tip_is_self_derived(kv, CRC_H_A, why, sizeof(why)));
    }

    sqlite3_close(kv);
    return failures;
}

/* ── Entry point ───────────────────────────────────────────────────────── */

int test_coin_reader_chain(void)
{
    int failures = 0;
    char dir[256];

    printf("Coin read chain (coins_kv -> node.db utxos -> wallet/explorer)\n");

    test_make_tmpdir(dir, sizeof(dir), "coin_reader_chain", "main");
    if (mkdir(dir, 0755) != 0 && access(dir, W_OK) != 0) {
        printf("  coin_reader_chain: fixture dir... FAIL\n");
        return 1;
    }

    failures += crc_case_canonical_ledger(dir);
    failures += crc_case_forward_fold_sovereign_stamp(dir);
    failures += crc_case_read_models(dir);

    /* The whole chain ran without any component creating the demoted copy's
     * database file. */
    {
        char proj[512];
        struct stat st;
        snprintf(proj, sizeof(proj), "%s/utxo_projection.db", dir);
        CRC_CHECK("no utxo_projection.db created", stat(proj, &st) != 0);
    }

    test_cleanup_tmpdir(dir);

    printf("Coin read chain: %d failure(s)\n", failures);
    return failures;
}
