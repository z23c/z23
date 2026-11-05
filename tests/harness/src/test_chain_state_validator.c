/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for chain_state_validator service — boot-time cross-check
 * between coins_best_block and active chain tip.
 */

#include "test/test_core.h"
#include "coins/coins_view.h"
#include "services/chain_state_validator.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "validation/chain_linkage_check.h"
#include "storage/progress_store.h"
#include "storage/coins_kv.h"
#include "jobs/tip_finalize_stage.h"
#include "services/utxo_recovery_service.h"
#include "services/chain_state_service.h"
#include "services/chain_activation_service.h"
#include "models/database.h"
#include "chain/chainparams.h"
#include "event/event.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define CSV_CHECK(name, expr) do {          \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Build a minimal chain of n blocks in main_state with matching
 * active_chain tip. */
static void csv_build_chain(struct main_state *ms, int n)
{
    struct uint256 hashes[256];
    int limit = n < 256 ? n : 256;

    for (int h = 0; h < limit; h++) {
        memset(&hashes[h], 0, sizeof(hashes[h]));
        hashes[h].data[0] = (uint8_t)(h & 0xFF);
        hashes[h].data[1] = (uint8_t)((h >> 8) & 0xFF);
        hashes[h].data[3] = 0xBB;

        struct block_index *pi = chainstate_insert_block_index(
            (struct chainstate *)ms, &hashes[h]);
        if (!pi) continue;

        pi->nHeight = h;
        pi->nBits = 0x1f07ffff;
        pi->nTime = 1000000 + (uint32_t)h * 150;
        pi->nVersion = 4;
        pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        pi->nTx = 1;
        pi->nChainTx = (uint32_t)(h + 1);
        arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(h + 1));

        if (h > 0) {
            struct block_index *prev = block_map_find(
                &ms->map_block_index, &hashes[h - 1]);
            if (prev) pi->pprev = prev;
        }
    }
    /* Set active chain tip to last block */
    if (limit > 0) {
        struct block_index *tip = block_map_find(
            &ms->map_block_index, &hashes[limit - 1]);
        if (tip) active_chain_move_window_tip(&ms->chain_active, tip);
    }
}

/* After-execute observations for the derived-agree verdict. */
struct csv_exec_out {
    bool ran;
    bool exec_ok;
    bool best_is_tip;
    bool recovered;
};

/* Run the validator's verdict through the real recovery executor on this
 * fixture (CSR over the same maps and coins view) and report the end state.
 * EV_BOOT_VALIDATION_FAILED is not observable from here: the verdict path
 * to it (case_legacy_coins_empty) is bypassed by construction, which the
 * action value asserts. */
static void csv_execute_verdict(struct main_state *ms,
                                struct coins_view_cache *cache,
                                const char *pdir,
                                struct boot_validation_result *vr,
                                struct csv_exec_out *out)
{
    char db_path[320];
    snprintf(db_path, sizeof(db_path), "%s/csv_node.db", pdir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, db_path))
        return;
    chain_params_select(CHAIN_MAIN);
    struct chain_state_repository *csr = csr_instance();
    csr_init(csr, &ms->map_block_index, &ms->chain_active,
             &ms->pindex_best_header, cache, &ndb, NULL);
    struct chain_activation_controller ctl;
    activation_controller_init(&ctl, ms, NULL, chain_params_get(), NULL);
    struct utxo_recovery_ctx uctx = {
        .state = ms, .coins_tip = cache, .ndb = &ndb,
        .datadir = "/nonexistent", .params = chain_params_get(),
        .activation_ctl = &ctl,
    };
    struct recovery_exec_result er = utxo_recovery_execute(&uctx, vr);
    struct uint256 best;
    memset(&best, 0, sizeof(best));
    coins_view_cache_get_best_block(cache, &best);
    struct block_index *tip = active_chain_tip(&ms->chain_active);
    out->ran = true;
    out->exec_ok = er.status.ok;
    out->recovered = er.recovered;
    out->best_is_tip = tip && tip->phashBlock &&
                       uint256_cmp(tip->phashBlock, &best) == 0;
    csr_free(csr);
    node_db_close(&ndb);
}

/* Null legacy coins best + a proven coins_kv whose DERIVED coins-best is
 * seeded (anchor row) at height `seed_h` with the hash of the block at
 * `seed_h` (hash_ok) or a hash absent from the index (!hash_ok). Chain tip
 * is h=49. Returns the validator verdict; *seeded reports fixture success. */
static enum boot_recovery_action csv_null_legacy_derived(int seed_h,
                                                         bool hash_ok,
                                                         bool *seeded,
                                                         struct csv_exec_out *out)
{
    char pdir[256];
    if (!test_mkdtemp(pdir, sizeof(pdir), "csv_der")) {
        *seeded = false;
        return BOOT_RECOVER_WIPE_WAIT;
    }
    char cmd[320];

    struct main_state ms;
    main_state_init(&ms);
    csv_build_chain(&ms, 50);

    *seeded = false;
    if (progress_store_open(pdir)) {
        sqlite3 *db = progress_store_db();
        uint8_t txid[32], one = 1;
        uint8_t hash[32] = {0};
        hash[0] = (uint8_t)seed_h;
        hash[3] = hash_ok ? 0xBB : 0xEE;
        uint8_t applied[8] = {0};
        applied[0] = (uint8_t)(seed_h + 1);
        memset(txid, 0x77, sizeof(txid));
        *seeded = db && coins_kv_ensure_schema(db) &&
                  coins_kv_add(db, txid, 0, 1000LL, 1, false, NULL, 0) &&
                  progress_meta_set(db, COINS_KV_MIGRATION_COMPLETE_KEY,
                                    &one, 1) &&
                  progress_meta_set(db, COINS_APPLIED_HEIGHT_KEY, applied,
                                    sizeof(applied)) &&
                  sqlite3_exec(db,
                      "CREATE TABLE IF NOT EXISTS validate_headers_log ("
                      " height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
                      " ok INTEGER NOT NULL, fail_reason TEXT,"
                      " validated_at INTEGER);", NULL, NULL, NULL)
                      == SQLITE_OK &&
                  tip_finalize_stage_seed_anchor(seed_h, hash, false);
    }

    struct coins_view_cache cache;
    struct coins_view nv;
    memset(&nv, 0, sizeof(nv));
    coins_view_cache_init(&cache, &nv); /* legacy best stays null */
    struct boot_validation_result r =
        validate_coins_chain_agreement(&ms, &cache, "/nonexistent");
    if (out && *seeded && r.action == BOOT_OK_COMMIT_DERIVED_BEST)
        csv_execute_verdict(&ms, &cache, pdir, &r, out);

    coins_view_cache_free(&cache);
    main_state_free(&ms);
    progress_store_close();
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", pdir);
    TEST_DISCARD(system(cmd));
    return r.action;
}

/* 2b/2c: null legacy best with a derived coins-best. Returns failures. */
static int csv_derived_cases(void)
{
    int failures = 0;
    /* ── 2b. Null legacy best, but the DERIVED coins-best IS the chain tip
     *        → BOOT_OK (healthy warm boot, coins are not empty) ── */
    {
        struct csv_exec_out ex = {0};
        bool seeded = false;
        enum boot_recovery_action a =
            csv_null_legacy_derived(49, true, &seeded, &ex);
        CSV_CHECK("csv: null legacy + derived best == chain tip → commit-derived verdict",
                  seeded && a == BOOT_OK_COMMIT_DERIVED_BEST);
        CSV_CHECK("csv: executing it leaves the coins view best == active tip",
                  ex.ran && ex.exec_ok && ex.recovered && ex.best_is_tip);
    }

    /* ── 2c. Null legacy best, derived best present but NOT the tip →
     *        today's verdict (WIPE_WAIT; no chainstate dir) ── */
    {
        bool s1 = false, s2 = false;
        enum boot_recovery_action wrong_hash =
            csv_null_legacy_derived(49, false, &s1, NULL);
        enum boot_recovery_action lagging =
            csv_null_legacy_derived(48, true, &s2, NULL);
        CSV_CHECK("csv: null legacy + derived hash != tip → WIPE_WAIT",
                  s1 && wrong_hash == BOOT_RECOVER_WIPE_WAIT);
        CSV_CHECK("csv: null legacy + derived best below tip → WIPE_WAIT",
                  s2 && lagging == BOOT_RECOVER_WIPE_WAIT);
    }
    return failures;
}

/* ── Mutation-sweep cases ──────────────────────────────────────────────
 * A table-driven fixture over the validator: every case names the chain, the
 * legacy coins best, an optional durable seed and an optional extra indexed
 * block, and the runner reports the verdict plus the events it emitted. */

struct csv_ev {
    int n;
    uint32_t peer;
    char text[EVENT_PAYLOAD_SIZE + 1];
};
static struct csv_ev g_csv_fail, g_csv_rec;

static void csv_observer(enum event_type type, uint32_t peer_id,
                         const void *payload, uint32_t len, void *ctx)
{
    (void)ctx;
    struct csv_ev *e = type == EV_BOOT_VALIDATION_FAILED ? &g_csv_fail
                                                         : &g_csv_rec;
    size_t n = len < EVENT_PAYLOAD_SIZE ? len : EVENT_PAYLOAD_SIZE;
    e->n++;
    e->peer = peer_id;
    if (payload) memcpy(e->text, payload, n);
    e->text[n] = '\0';
}

static bool csv_ev_is(const struct csv_ev *e, int n, const char *text)
{
    bool ok = e->n == n && (n == 0 || (e->peer == 0 &&
                                       strcmp(e->text, text) == 0));
    if (!ok) printf("[event n=%d peer=%u '%s'] ", e->n, e->peer, e->text);
    return ok;
}

enum { CSV_LEG_NULL = 0, CSV_LEG_H, CSV_LEG_UNKNOWN };
enum { CSV_SEED_NONE = 0, CSV_SEED_DERIVED, CSV_SEED_DERIVED_NOANCHOR,
       CSV_SEED_FINALIZED };
enum { CSV_DIR_NONE = 0, CSV_DIR_CHAINSTATE, CSV_DIR_CHAINSTATE_FILE };

struct csv_case {
    int chain_n;       /* csv_build_chain(n); 0 = no chain, tip NULL */
    int legacy;        /* CSV_LEG_* */
    int legacy_h;      /* CSV_LEG_H: hash of block pattern h */
    int seed;          /* CSV_SEED_* */
    int seed_h;        /* height of the seeded derived / finalized tip */
    int hash_h;        /* seeded hash is pattern hash_h; 0 = seed_h */
    int flip;          /* 1 + index of a seeded hash byte to corrupt */
    bool add;          /* extra indexed block with pattern hash add_h */
    int add_h;
    int add_nheight;
    bool add_fork;     /* extra block uses a marker distinct from the chain */
    bool add_parent;   /* extra block gets a pprev parent of height 0 */
    bool null_phash;   /* NULL the active tip's phashBlock during the call */
    int dir;           /* CSV_DIR_* */
};

static void csv_pattern_hash(struct uint256 *h, int id, uint8_t marker)
{
    memset(h, 0, sizeof(*h));
    h->data[0] = (uint8_t)id;
    h->data[3] = marker;
}

static struct block_index *csv_add_block(struct main_state *ms, int id,
                                         uint8_t marker, int nheight)
{
    struct uint256 h;
    csv_pattern_hash(&h, id, marker);
    struct block_index *pi =
        chainstate_insert_block_index((struct chainstate *)ms, &h);
    if (!pi) return NULL;
    pi->nHeight = nheight;
    pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    pi->nTx = 1;
    return pi;
}

static bool csv_seed_coins_kv(sqlite3 *db, const struct csv_case *c,
                              const uint8_t hash[32])
{
    uint8_t txid[32], one = 1, applied[8] = {0};
    memset(txid, 0x77, sizeof(txid));
    applied[0] = (uint8_t)(c->seed_h + 1);
    return db && coins_kv_ensure_schema(db) &&
           coins_kv_add(db, txid, 0, 1000LL, 1, false, NULL, 0) &&
           progress_meta_set(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1) &&
           progress_meta_set(db, COINS_APPLIED_HEIGHT_KEY, applied,
                             sizeof(applied)) &&
           sqlite3_exec(db,
               "CREATE TABLE IF NOT EXISTS validate_headers_log ("
               " height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
               " ok INTEGER NOT NULL, fail_reason TEXT,"
               " validated_at INTEGER);", NULL, NULL, NULL) == SQLITE_OK &&
           (c->seed != CSV_SEED_DERIVED ||
            tip_finalize_stage_seed_anchor(c->seed_h, hash, false));
}

static bool csv_seed_store(const struct csv_case *c)
{
    uint8_t hash[32] = {0};
    hash[0] = (uint8_t)(c->hash_h ? c->hash_h : c->seed_h);
    hash[3] = 0xBB;
    if (c->flip) hash[c->flip - 1] ^= 0x5A;
    if (c->seed != CSV_SEED_FINALIZED)
        return csv_seed_coins_kv(progress_store_db(), c, hash);
    char sql[160];
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at)"
             " VALUES('tip_finalize',%d,0)", c->seed_h + 1);
    return tip_finalize_stage_seed_anchor(c->seed_h, hash, false) &&
           sqlite3_exec(progress_store_db(), sql, NULL, NULL, NULL)
               == SQLITE_OK;
}

static bool csv_make_datadir(const struct csv_case *c, const char *pdir,
                             char *out, size_t n)
{
    snprintf(out, n, "%s", c->dir == CSV_DIR_NONE ? "/nonexistent" : pdir);
    char cs[400];
    snprintf(cs, sizeof(cs), "%s/chainstate", pdir);
    if (c->dir == CSV_DIR_CHAINSTATE) return mkdir(cs, 0700) == 0;
    if (c->dir == CSV_DIR_CHAINSTATE_FILE) {
        FILE *f = fopen(cs, "w");
        if (!f) return false;
        fclose(f);
    }
    return true;
}

static bool csv_add_extra(struct main_state *ms, const struct csv_case *c)
{
    if (!c->add) return true;
    struct block_index *x = csv_add_block(
        ms, c->add_h, c->add_fork ? 0xAF : 0xBB, c->add_nheight);
    if (!x) return false;
    if (!c->add_parent) return true;
    /* pprev_walk_depth requires strictly decreasing heights, so a parent of
     * an nHeight-0 block must sit below zero for the walk to resolve. */
    struct block_index *par = csv_add_block(ms, c->add_h + 100, 0xCC, -1);
    if (par) x->pprev = par;
    return par != NULL;
}

static void csv_set_legacy(struct coins_view_cache *cache,
                           const struct csv_case *c)
{
    struct uint256 leg;
    if (c->legacy == CSV_LEG_H) {
        bool fork = c->add && c->add_fork && c->legacy_h == c->add_h;
        csv_pattern_hash(&leg, c->legacy_h, fork ? 0xAF : 0xBB);
    } else if (c->legacy == CSV_LEG_UNKNOWN) {
        memset(&leg, 0xCD, sizeof(leg));
    } else {
        return;
    }
    coins_view_cache_set_best_block(cache, &leg);
}

static bool csv_build_fixture(struct main_state *ms,
                              struct coins_view_cache *cache,
                              struct coins_view *nv,
                              const struct csv_case *c, const char *pdir)
{
    if (c->chain_n > 0) csv_build_chain(ms, c->chain_n);
    bool ok = csv_add_extra(ms, c);
    if (c->seed != CSV_SEED_NONE)
        ok = ok && progress_store_open(pdir) && csv_seed_store(c);
    memset(nv, 0, sizeof(*nv));
    coins_view_cache_init(cache, nv);
    csv_set_legacy(cache, c);
    return ok;
}

/* Run one case. Returns false when the fixture could not be built (the
 * verdict is then not computed and *out is zero). */
static bool csv_run_case(const struct csv_case *c,
                         struct boot_validation_result *out)
{
    char pdir[256] = {0};
    char datadir[320] = {0};
    memset(out, 0, sizeof(*out));
    if (!test_mkdtemp(pdir, sizeof(pdir), "csv_case")) return false;

    struct main_state ms;
    main_state_init(&ms);
    struct coins_view_cache cache;
    struct coins_view nv;
    bool ok = csv_build_fixture(&ms, &cache, &nv, c, pdir) &&
              csv_make_datadir(c, pdir, datadir, sizeof(datadir));
    if (ok) {
        struct block_index *tip = active_chain_tip(&ms.chain_active);
        const struct uint256 *saved = tip ? tip->phashBlock : NULL;
        if (c->null_phash && tip) tip->phashBlock = NULL;
        memset(&g_csv_fail, 0, sizeof(g_csv_fail));
        memset(&g_csv_rec, 0, sizeof(g_csv_rec));
        *out = validate_coins_chain_agreement(&ms, &cache, datadir);
        if (c->null_phash && tip) tip->phashBlock = saved;
    }
    coins_view_cache_free(&cache);
    main_state_free(&ms);
    if (c->seed != CSV_SEED_NONE) progress_store_close();
    char cmd[320];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", pdir);
    TEST_DISCARD(system(cmd));
    return ok;
}

#define CSV_ANY (-1000000)

/* Verdict predicate: fixture ok, action, chain height and coins height
 * (CSV_ANY skips a height). */
static bool csv_v(bool ok, const struct boot_validation_result *r,
                  enum boot_recovery_action a, int chain_h, int coins_h)
{
    if (!ok || r->action != a) return false;
    if (chain_h != CSV_ANY && r->chain_height != chain_h) return false;
    return coins_h == CSV_ANY || r->coins_height == coins_h;
}

static bool csv_hash_is(const struct boot_validation_result *r, int b0, int b3)
{
    return r->coins_hash.data[0] == b0 && r->coins_hash.data[3] == b3;
}

static bool csv_quiet(void)
{
    return g_csv_fail.n == 0 && g_csv_rec.n == 0;
}

/* Case 2: legacy best null, chain has blocks. */
static int csv_null_legacy_cases(void)
{
    int failures = 0;
    struct boot_validation_result r;

    bool ok = csv_run_case(&(struct csv_case){ .chain_n = 50,
                  .dir = CSV_DIR_CHAINSTATE }, &r);
    CSV_CHECK("csv: null coins + chainstate dir -> REIMPORT",
              csv_v(ok, &r, BOOT_RECOVER_REIMPORT, 49, -1));
    CSV_CHECK("csv: reimport event names action and chain height",
              csv_ev_is(&g_csv_fail, 1, "coins_empty chain_h=49 action=reimport"));

    ok = csv_run_case(&(struct csv_case){ .chain_n = 50,
             .dir = CSV_DIR_CHAINSTATE_FILE }, &r);
    CSV_CHECK("csv: null coins + chainstate that is a FILE -> WIPE_WAIT",
              csv_v(ok, &r, BOOT_RECOVER_WIPE_WAIT, 49, -1));

    ok = csv_run_case(&(struct csv_case){ .chain_n = 50 }, &r);
    CSV_CHECK("csv: null coins verdict carries heights and a null hash",
              csv_v(ok, &r, BOOT_RECOVER_WIPE_WAIT, 49, -1) &&
              uint256_is_null(&r.coins_hash));
    CSV_CHECK("csv: wipe_wait event for null coins",
              csv_ev_is(&g_csv_fail, 1, "coins_empty chain_h=49 action=wipe_wait"));

    /* A tip at height 1 is above genesis: coins == tip hash is healthy. */
    ok = csv_run_case(&(struct csv_case){ .chain_n = 2,
             .legacy = CSV_LEG_H, .legacy_h = 1 }, &r);
    CSV_CHECK("csv: tip h=1 with coins == tip -> BOOT_OK (not at-genesis)",
              csv_v(ok, &r, BOOT_OK, 1, 1) && csv_quiet());
    return failures;
}

/* Case 2: the DERIVED coins-best against the active tip. */
static int csv_derived_tip_cases(void)
{
    int failures = 0;
    struct boot_validation_result r;

    /* Null legacy best, derived best at h=1 == tip at h=1. */
    bool ok = csv_run_case(&(struct csv_case){ .chain_n = 2,
                  .seed = CSV_SEED_DERIVED, .seed_h = 1 }, &r);
    CSV_CHECK("csv: null legacy + derived h=1 == tip h=1 -> commit derived",
              csv_v(ok, &r, BOOT_OK_COMMIT_DERIVED_BEST, 1, 1));
    CSV_CHECK("csv: commit-derived verdict carries the tip hash",
              csv_hash_is(&r, 1, 0xBB));

    /* A tip without a hash must never be treated as the derived best. */
    ok = csv_run_case(&(struct csv_case){ .chain_n = 50,
             .seed = CSV_SEED_DERIVED, .seed_h = 49, .null_phash = true }, &r);
    CSV_CHECK("csv: null legacy + derived best but tip has no hash -> WIPE_WAIT",
              csv_v(ok, &r, BOOT_RECOVER_WIPE_WAIT, CSV_ANY, CSV_ANY));
    return failures;
}

/* Case 3a: stale legacy best below a derived best that is the tip. */
static int csv_derived_agree_cases(void)
{
    int failures = 0;
    struct boot_validation_result r;
    struct csv_case base = { .chain_n = 50, .legacy = CSV_LEG_H,
                             .legacy_h = 20, .seed = CSV_SEED_DERIVED,
                             .seed_h = 49 };

    bool ok = csv_run_case(&base, &r);
    CSV_CHECK("csv: stale legacy + derived hash == tip -> BOOT_OK",
              csv_v(ok, &r, BOOT_OK, CSV_ANY, 49));

    struct csv_case c = base;
    c.flip = 1;     /* first byte differs */
    ok = csv_run_case(&c, &r);
    CSV_CHECK("csv: derived hash differs in byte 0 -> RESET_CHAIN",
              csv_v(ok, &r, BOOT_RECOVER_RESET_CHAIN, CSV_ANY, 20));

    c.flip = 32;    /* only the last byte differs */
    ok = csv_run_case(&c, &r);
    CSV_CHECK("csv: derived hash differs only in byte 31 -> RESET_CHAIN",
              csv_v(ok, &r, BOOT_RECOVER_RESET_CHAIN, CSV_ANY, 20));

    c = base;
    c.seed = CSV_SEED_DERIVED_NOANCHOR;     /* height-only witness */
    ok = csv_run_case(&c, &r);
    CSV_CHECK("csv: derived height == tip, no hash witness -> BOOT_OK",
              csv_v(ok, &r, BOOT_OK, CSV_ANY, 49));

    c.seed_h = 48;
    ok = csv_run_case(&c, &r);
    CSV_CHECK("csv: derived height 48 != tip 49, no hash witness -> RESET_CHAIN",
              csv_v(ok, &r, BOOT_RECOVER_RESET_CHAIN, CSV_ANY, 20));

    c = base;
    c.null_phash = true;
    ok = csv_run_case(&c, &r);
    CSV_CHECK("csv: stale legacy + derived best but tip has no hash -> RESET_CHAIN",
              csv_v(ok, &r, BOOT_RECOVER_RESET_CHAIN, CSV_ANY, 20));
    return failures;
}

/* Case 3b: the durable reducer-finalized tip against the active tip. */
static int csv_finalized_cases(void)
{
    int failures = 0;
    struct boot_validation_result r;
    struct csv_case base = { .chain_n = 100, .legacy = CSV_LEG_H,
                             .legacy_h = 50, .seed = CSV_SEED_FINALIZED,
                             .seed_h = 99 };

    bool ok = csv_run_case(&base, &r);
    CSV_CHECK("csv: finalized tip == active tip, coins behind -> BOOT_OK",
              csv_v(ok, &r, BOOT_OK, CSV_ANY, 99));

    struct csv_case c = base;
    c.flip = 32;    /* same height, hash differs only in the last byte */
    ok = csv_run_case(&c, &r);
    CSV_CHECK("csv: finalized hash differs only in byte 31 -> RESET_CHAIN",
              csv_v(ok, &r, BOOT_RECOVER_RESET_CHAIN, CSV_ANY, 50));

    c = base;
    c.seed_h = 98;
    c.hash_h = 99;  /* the tip's own hash, recorded at the wrong height */
    ok = csv_run_case(&c, &r);
    CSV_CHECK("csv: finalized height 98 != tip 99 with the tip's hash -> RESET_CHAIN",
              csv_v(ok, &r, BOOT_RECOVER_RESET_CHAIN, CSV_ANY, 50));

    /* coins_best not in the index: the finalized AGREE is denied. */
    c = base;
    c.legacy = CSV_LEG_UNKNOWN;
    ok = csv_run_case(&c, &r);
    CSV_CHECK("csv: finalized tip but coins_best not indexed -> WIPE_WAIT",
              csv_v(ok, &r, BOOT_RECOVER_WIPE_WAIT, CSV_ANY, -1));
    return failures;
}

/* coins_best indexed AT the tip's height on a fork: "at or behind". */
static int csv_fork_cases(void)
{
    int failures = 0;
    struct boot_validation_result r;
    struct csv_case c = { .chain_n = 100, .legacy = CSV_LEG_H,
                          .legacy_h = 0xAA, .seed = CSV_SEED_FINALIZED,
                          .seed_h = 99, .add = true, .add_h = 0xAA,
                          .add_nheight = 99, .add_fork = true };

    bool ok = csv_run_case(&c, &r);
    CSV_CHECK("csv: finalized tip, coins_best on a same-height fork -> BOOT_OK",
              csv_v(ok, &r, BOOT_OK, CSV_ANY, CSV_ANY));

    c.seed = CSV_SEED_NONE;     /* without the finalized witness it resets */
    ok = csv_run_case(&c, &r);
    CSV_CHECK("csv: same-height fork coins_best, no witness -> RESET_CHAIN",
              csv_v(ok, &r, BOOT_RECOVER_RESET_CHAIN, CSV_ANY, 99));
    return failures;
}

/* Case 4 event text and the coins-ahead verdict. */
static int csv_mismatch_cases(void)
{
    int failures = 0;
    struct boot_validation_result r;

    bool ok = csv_run_case(&(struct csv_case){ .chain_n = 100,
                  .legacy = CSV_LEG_H, .legacy_h = 50 }, &r);
    CSV_CHECK("csv: coins behind -> RESET_CHAIN",
              csv_v(ok, &r, BOOT_RECOVER_RESET_CHAIN, 99, 50));
    CSV_CHECK("csv: coins behind -> reset_chain event",
              csv_ev_is(&g_csv_fail, 1, "coins_chain_mismatch chain_h=99 "
                                        "coins_h=50 action=reset_chain"));

    ok = csv_run_case(&(struct csv_case){ .chain_n = 100,
             .legacy = CSV_LEG_UNKNOWN }, &r);
    CSV_CHECK("csv: coins unknown, short chain -> WIPE_WAIT keeps coins hash",
              csv_v(ok, &r, BOOT_RECOVER_WIPE_WAIT, 99, -1) &&
              csv_hash_is(&r, 0xCD, 0xCD));
    CSV_CHECK("csv: wipe_wait mismatch event",
              csv_ev_is(&g_csv_fail, 1, "coins_chain_mismatch chain_h=99 "
                                        "coins_h=-1 action=wipe_wait"));

    /* Coins ahead of the chain tip: wipe. */
    ok = csv_run_case(&(struct csv_case){ .chain_n = 100,
             .legacy = CSV_LEG_H, .legacy_h = 200, .add = true,
             .add_h = 200, .add_nheight = 150 }, &r);
    CSV_CHECK("csv: coins ahead of tip -> WIPE_WAIT with coins height",
              csv_v(ok, &r, BOOT_RECOVER_WIPE_WAIT, CSV_ANY, 150));
    return failures;
}

/* Case 4 with one tip block at an exact height and an unknown coins best. */
static enum boot_recovery_action csv_tall_tip(int tip_h, struct csv_ev *ev,
                                              struct boot_validation_result *r)
{
    memset(ev, 0, sizeof(*ev));
    struct main_state ms;
    main_state_init(&ms);
    struct block_index *tip = csv_add_block(&ms, 0xF1, 0xCC, tip_h);
    struct coins_view_cache cache;
    struct coins_view nv;
    memset(&nv, 0, sizeof(nv));
    coins_view_cache_init(&cache, &nv);
    struct uint256 unknown;
    memset(&unknown, 0xDE, sizeof(unknown));
    coins_view_cache_set_best_block(&cache, &unknown);
    enum boot_recovery_action a = BOOT_OK;
    memset(r, 0, sizeof(*r));
    if (tip) {
        tip->pprev = NULL;
        tip->nChainTx = (uint32_t)tip_h + 1;
        arith_uint256_set_u64(&tip->nChainWork, (uint64_t)tip_h + 1);
        active_chain_move_window_tip(&ms.chain_active, tip);
        memset(&g_csv_fail, 0, sizeof(g_csv_fail));
        *r = validate_coins_chain_agreement(&ms, &cache, "/nonexistent");
        a = r->action;
        *ev = g_csv_fail;
    }
    coins_view_cache_free(&cache);
    main_state_free(&ms);
    return a;
}

static int csv_tip_threshold_cases(void)
{
    int failures = 0;
    struct boot_validation_result r;
    struct csv_ev ev;

    enum boot_recovery_action a = csv_tall_tip(1000, &ev, &r);
    CSV_CHECK("csv: tip h=1000, coins unknown -> WIPE_WAIT (threshold is >1000)",
              a == BOOT_RECOVER_WIPE_WAIT);

    a = csv_tall_tip(1001, &ev, &r);
    CSV_CHECK("csv: tip h=1001, coins unknown -> RESET_COINS_TO_CHAIN_TIP",
              csv_v(a == BOOT_RECOVER_RESET_COINS_TO_CHAIN_TIP, &r,
                    BOOT_RECOVER_RESET_COINS_TO_CHAIN_TIP, 1001, 1001));
    CSV_CHECK("csv: reset-to-tip verdict carries the tip hash",
              csv_hash_is(&r, 0xF1, 0xCC));
    CSV_CHECK("csv: reset_coins_to_chain_tip event",
              csv_ev_is(&ev, 1, "coins_chain_mismatch chain_h=1001 "
                                "coins_h=1001 action=reset_coins_to_chain_tip"));
    return failures;
}

/* Case 1: chain empty, null or unknown coins. */
static int csv_empty_chain_cases(void)
{
    int failures = 0;
    struct boot_validation_result r;

    bool ok = csv_run_case(&(struct csv_case){ 0 }, &r);
    CSV_CHECK("csv: empty chain + null coins -> BOOT_OK with unset heights",
              csv_v(ok, &r, BOOT_OK, 0, -1) && csv_quiet());

    ok = csv_run_case(&(struct csv_case){ .legacy = CSV_LEG_UNKNOWN }, &r);
    CSV_CHECK("csv: empty chain + unknown coins -> reset cursor to genesis",
              csv_v(ok, &r, BOOT_RECOVER_RESET_COINS_TO_GENESIS, 0, 0) &&
              csv_hash_is(&r, 0xCD, 0xCD));
    CSV_CHECK("csv: reset_coins_to_genesis event reports chain height 0",
              csv_ev_is(&g_csv_rec, 1, "action=reset_coins_to_genesis "
                        "reason=coins_not_in_index chain_h=0"));
    return failures;
}

/* Case 1: chain empty, coins best indexed in the block map. */
static int csv_empty_chain_indexed_cases(void)
{
    int failures = 0;
    struct boot_validation_result r;

    /* Coins best indexed at height 1 while the chain is empty. */
    bool ok = csv_run_case(&(struct csv_case){ .legacy = CSV_LEG_H,
                  .legacy_h = 7, .add = true, .add_h = 7,
                  .add_nheight = 1 }, &r);
    CSV_CHECK("csv: empty chain + coins indexed at h=1 -> RESET_CHAIN to h=1",
              csv_v(ok, &r, BOOT_RECOVER_RESET_CHAIN, 0, 1) &&
              csv_hash_is(&r, 7, 0xBB));
    CSV_CHECK("csv: coins_ahead_of_chain event",
              csv_ev_is(&g_csv_rec, 1, "action=reset_chain "
                        "reason=coins_ahead_of_chain coins_h=1"));

    /* Indexed at nHeight 0 with no parent: unresolved, wait for P2P. */
    ok = csv_run_case(&(struct csv_case){ .legacy = CSV_LEG_H, .legacy_h = 7,
             .add = true, .add_h = 7, .add_nheight = 0 }, &r);
    CSV_CHECK("csv: coins indexed at h=0, no pprev -> BOOT_OK, no event",
              csv_v(ok, &r, BOOT_OK, 0, -1) && csv_quiet());

    /* Indexed at nHeight 0 with one parent: the pprev walk resolves h=1. */
    ok = csv_run_case(&(struct csv_case){ .legacy = CSV_LEG_H, .legacy_h = 7,
             .add = true, .add_h = 7, .add_nheight = 0,
             .add_parent = true }, &r);
    CSV_CHECK("csv: coins at nHeight 0 with one parent -> RESET_CHAIN to h=1",
              csv_v(ok, &r, BOOT_RECOVER_RESET_CHAIN, 0, 1) &&
              csv_hash_is(&r, 7, 0xBB));
    CSV_CHECK("csv: pprev-walk event",
              csv_ev_is(&g_csv_rec, 1, "action=reset_chain_pprev_walk "
                        "reason=post_import coins_h=1"));
    return failures;
}

/* Case 1 with a DERIVED coins-best (null tip, derived block in the index). */
static int csv_genesis_derived_cases(void)
{
    int failures = 0;
    struct boot_validation_result r;

    bool ok = csv_run_case(&(struct csv_case){ .seed = CSV_SEED_DERIVED,
                  .seed_h = 1, .add = true, .add_h = 1, .add_nheight = 1 }, &r);
    CSV_CHECK("csv: empty chain + derived best indexed at h=1 -> RESET_CHAIN",
              csv_v(ok, &r, BOOT_RECOVER_RESET_CHAIN, 0, 1) &&
              csv_hash_is(&r, 1, 0xBB));
    CSV_CHECK("csv: derived_coins_best event",
              csv_ev_is(&g_csv_rec, 1, "action=reset_chain "
                        "reason=derived_coins_best coins_h=1"));

    ok = csv_run_case(&(struct csv_case){ .seed = CSV_SEED_DERIVED,
             .seed_h = 1, .add = true, .add_h = 1, .add_nheight = 5 }, &r);
    CSV_CHECK("csv: derived block indexed at the wrong height -> BOOT_OK",
              csv_v(ok, &r, BOOT_OK, CSV_ANY, CSV_ANY) && csv_quiet());

    ok = csv_run_case(&(struct csv_case){ .seed = CSV_SEED_DERIVED,
             .seed_h = 1 }, &r);
    CSV_CHECK("csv: derived block absent from the index -> BOOT_OK",
              csv_v(ok, &r, BOOT_OK, CSV_ANY, CSV_ANY) && csv_quiet());

    ok = csv_run_case(&(struct csv_case){ .seed = CSV_SEED_DERIVED,
             .seed_h = 0, .add = true, .add_h = 0, .add_nheight = 0 }, &r);
    CSV_CHECK("csv: derived best at h=0 is not a restore target -> BOOT_OK",
              csv_v(ok, &r, BOOT_OK, CSV_ANY, CSV_ANY) && csv_quiet());
    return failures;
}

static int csv_mutant_cases(void)
{
    int failures = 0;
    bool obs = event_observe(EV_BOOT_VALIDATION_FAILED, csv_observer, NULL) &&
               event_observe(EV_RECOVERY_ACTION, csv_observer, NULL);
    CSV_CHECK("csv: event observers installed", obs);
    if (!obs) {
        event_clear_observers(EV_BOOT_VALIDATION_FAILED);
        event_clear_observers(EV_RECOVERY_ACTION);
        return failures;
    }
    failures += csv_null_legacy_cases();
    failures += csv_derived_tip_cases();
    failures += csv_derived_agree_cases();
    failures += csv_finalized_cases();
    failures += csv_mismatch_cases();
    failures += csv_tip_threshold_cases();
    failures += csv_fork_cases();
    failures += csv_empty_chain_cases();
    failures += csv_empty_chain_indexed_cases();
    failures += csv_genesis_derived_cases();
    event_clear_observers(EV_BOOT_VALIDATION_FAILED);
    event_clear_observers(EV_RECOVERY_ACTION);
    return failures;
}

int test_chain_state_validator(void)
{
    printf("\n=== chain state validator tests ===\n");
    int failures = 0;
    event_log_init();

    /* Test isolation: clear any chain-linkage HOLD left by a PRIOR group in
     * the shared-process monolith (test_zcl); the HOLD is process-global and
     * an inherited g_refuse_from makes csv_build_chain's advance refuse. */
    chain_linkage_reset_for_testing();

    /* Also disarm the active-chain authority
     * (active_chain_register_authority) and its block_map
     * (active_chain_register_block_map), which an earlier group leaves armed
     * with no unregister API; otherwise active_chain_tip() returns a dangling
     * block_index* from a freed block_map. Production never calls these with
     * a zeroed authority. */
    active_chain_register_authority(&(struct active_chain_authority){0});
    active_chain_register_block_map(NULL);

    /* ── 1. Coins and chain agree → BOOT_OK ──────────── */

    {
        struct main_state ms;
        main_state_init(&ms);
        csv_build_chain(&ms, 100);

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);

        /* Set coins_best_block to chain tip hash */
        struct block_index *tip = active_chain_tip(&ms.chain_active);
        coins_view_cache_set_best_block(&cache, tip->phashBlock);

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/tmp");

        CSV_CHECK("csv: coins == chain tip → BOOT_OK",
                  r.action == BOOT_OK && r.coins_height == 99);

        coins_view_cache_free(&cache);
        main_state_free(&ms);
    }

    /* ── 2. Empty coins, chain with blocks → reimport/wipe ── */

    {
        struct main_state ms;
        main_state_init(&ms);
        csv_build_chain(&ms, 50);

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);
        /* coins_best_block is null (default) */

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/nonexistent");

        CSV_CHECK("csv: null coins + chain at h=49 → WIPE_WAIT",
                  r.action == BOOT_RECOVER_WIPE_WAIT);

        coins_view_cache_free(&cache);
        main_state_free(&ms);
    }

    failures += csv_derived_cases();

    /* ── 3. Chain at genesis, null coins → BOOT_OK ─────── */

    {
        struct main_state ms;
        main_state_init(&ms);
        /* No chain built — tip is NULL */

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/tmp");

        CSV_CHECK("csv: genesis + null coins → BOOT_OK",
                  r.action == BOOT_OK);

        coins_view_cache_free(&cache);
        main_state_free(&ms);
    }

    /* ── 4. Chain at genesis, coins unknown → reset cursor via executor ── */

    {
        struct main_state ms;
        main_state_init(&ms);
        csv_build_chain(&ms, 1);

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);

        struct uint256 unknown;
        memset(&unknown, 0xAB, sizeof(unknown));
        coins_view_cache_set_best_block(&cache, &unknown);

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/tmp");

        struct uint256 after;
        coins_view_cache_get_best_block(&cache, &after);

        CSV_CHECK("csv: genesis + unknown coins → RESET_COINS_TO_GENESIS",
                  r.action == BOOT_RECOVER_RESET_COINS_TO_GENESIS &&
                  uint256_eq(&after, &unknown));

        coins_view_cache_free(&cache);
        main_state_free(&ms);
    }

    /* ── 5. Coins behind chain → RESET_CHAIN ─────────── */

    {
        struct main_state ms;
        main_state_init(&ms);
        csv_build_chain(&ms, 100);

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);

        /* Set coins_best_block to block at h=50 (behind tip at h=99) */
        struct uint256 h50;
        memset(&h50, 0, sizeof(h50));
        h50.data[0] = 50;
        h50.data[3] = 0xBB;
        coins_view_cache_set_best_block(&cache, &h50);

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/tmp");

        CSV_CHECK("csv: coins at h=50, chain at h=99 → RESET_CHAIN",
                  r.action == BOOT_RECOVER_RESET_CHAIN &&
                  r.coins_height == 50);

        coins_view_cache_free(&cache);
        main_state_free(&ms);
    }

    /* ── 5b. Coins behind chain BUT the chain tip IS the durable
     *        reducer-finalized tip → BOOT_OK (reducer tip is the authority) ──
     * Same shape as test 5 with a durable tip_finalize tip seeded at the
     * chain tip: the stale coins.db best is benign lagging materialization,
     * so the validator must AGREE. Test 5 (no progress store) still asserts
     * RESET_CHAIN. */
    {
        char pdir[96];
        snprintf(pdir, sizeof(pdir), "/tmp/zcl_csv_fin_%d", (int)getpid());
        char rmcmd[160];
        snprintf(rmcmd, sizeof(rmcmd), "rm -rf '%s'", pdir);
         TEST_DISCARD(system(rmcmd));
        char mkcmd[160];
        snprintf(mkcmd, sizeof(mkcmd), "mkdir -p '%s'", pdir);
         TEST_DISCARD(system(mkcmd));

        struct main_state ms;
        main_state_init(&ms);
        csv_build_chain(&ms, 100);
        struct block_index *tip = active_chain_tip(&ms.chain_active);

        bool seeded = false;
        if (tip && tip->phashBlock && progress_store_open(pdir)) {
            /* Seed the durable finalized-tip log row WITHOUT initialising the
             * stage (tip_finalize_stage_init registers an irreversible global
             * active_chain authority); stamp the 'tip_finalize' cursor
             * directly. */
            bool row = tip_finalize_stage_seed_anchor(tip->nHeight,
                                                      tip->phashBlock->data,
                                                      false);
            char sql[160];
            snprintf(sql, sizeof(sql),
                     "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at)"
                     " VALUES('tip_finalize',%d,0)", tip->nHeight + 1);
            seeded = row &&
                     sqlite3_exec(progress_store_db(), sql, NULL, NULL, NULL)
                         == SQLITE_OK;
        }

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);

        struct uint256 h50;
        memset(&h50, 0, sizeof(h50));
        h50.data[0] = 50;
        h50.data[3] = 0xBB;
        coins_view_cache_set_best_block(&cache, &h50);

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/tmp");

        CSV_CHECK("csv: coins behind + chain==reducer-finalized tip → BOOT_OK",
                  seeded && r.action == BOOT_OK && r.coins_height == 99);

        coins_view_cache_free(&cache);
        main_state_free(&ms);
        progress_store_close();
         TEST_DISCARD(system(rmcmd));
    }

    /* ── 6. Coins not in index, chain > 1000 → reset coins cursor ── */

    {
        struct main_state ms;
        main_state_init(&ms);

        /* Build a chain longer than 1000 using a compact range */
        struct uint256 hashes[2];
        /* Genesis */
        memset(&hashes[0], 0, sizeof(hashes[0]));
        hashes[0].data[0] = 0xF0;
        hashes[0].data[3] = 0xCC;
        struct block_index *genesis = chainstate_insert_block_index(
            (struct chainstate *)&ms, &hashes[0]);
        genesis->nHeight = 0;
        genesis->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        genesis->nTx = 1;
        genesis->nChainTx = 1;
        arith_uint256_set_u64(&genesis->nChainWork, 1);

        /* Tip at h=2000 */
        memset(&hashes[1], 0, sizeof(hashes[1]));
        hashes[1].data[0] = 0xF1;
        hashes[1].data[3] = 0xCC;
        struct block_index *tip = chainstate_insert_block_index(
            (struct chainstate *)&ms, &hashes[1]);
        tip->nHeight = 2000;
        /* pprev = NULL: a non-adjacent pprev is the splice shape the
         * linkage check refuses; this subtest only needs SOME tip at h=2000
         * with an unknown coins_best hash. */
        tip->pprev = NULL;
        tip->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        tip->nTx = 1;
        tip->nChainTx = 2001;
        arith_uint256_set_u64(&tip->nChainWork, 2001);
        active_chain_move_window_tip(&ms.chain_active, tip);

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);

        /* Set coins_best_block to hash NOT in block_map */
        struct uint256 unknown;
        memset(&unknown, 0xDE, sizeof(unknown));
        coins_view_cache_set_best_block(&cache, &unknown);

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/tmp");

        struct uint256 after;
        coins_view_cache_get_best_block(&cache, &after);

        CSV_CHECK("csv: coins hash not in index, chain > 1000 → reset cursor",
                  r.action == BOOT_RECOVER_RESET_COINS_TO_CHAIN_TIP &&
                  uint256_eq(&after, &unknown));

        coins_view_cache_free(&cache);
        main_state_free(&ms);
    }

    /* ── 7. Chain at genesis, coins set to known block → RESET ── */

    {
        struct main_state ms;
        main_state_init(&ms);

        /* Insert a block at h=500 but don't set it as active tip */
        struct uint256 hash;
        memset(&hash, 0, sizeof(hash));
        hash.data[0] = 0x42;
        hash.data[3] = 0xDD;
        struct block_index *bi = chainstate_insert_block_index(
            (struct chainstate *)&ms, &hash);
        bi->nHeight = 500;
        bi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        bi->nTx = 1;

        struct coins_view_cache cache;
        struct coins_view nv;
        memset(&nv, 0, sizeof(nv));
        coins_view_cache_init(&cache, &nv);
        coins_view_cache_set_best_block(&cache, &hash);

        struct boot_validation_result r =
            validate_coins_chain_agreement(&ms, &cache, "/tmp");

        CSV_CHECK("csv: genesis tip + coins at known h=500 → RESET_CHAIN",
                  r.action == BOOT_RECOVER_RESET_CHAIN &&
                  r.coins_height == 500);

        coins_view_cache_free(&cache);
        main_state_free(&ms);
    }

    failures += csv_mutant_cases();

    printf("=== chain state validator: %d failures ===\n", failures);
    return failures;
}
