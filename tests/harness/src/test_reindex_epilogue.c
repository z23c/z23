/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for reindex_epilogue_derive, the post-reindex derivation. A reindex
 * leaving coins_applied_height stale-HIGH over a rebuilt coin set produces the
 * `coins_applied > hstar` coin-tear; the epilogue must derive every durable
 * value from the replayed mirror:
 *   - reseed coins_kv from node.db `utxos` (+ migration stamp);
 *   - recompute + stamp the SHA3 commitment;
 *   - raise coins_applied_height to tip+1 FIRST, then clamp the tip_finalize
 *     anchor + 8 stage cursors to the replayed tip via the trusted seed;
 *   - self-check H* == replayed tip.
 *
 * In-process (no spawn): an isolated progress.kv + a real <dir>/node.db with a
 * known `utxos` set + a synthetic active chain to a known tip, STALE-HIGH
 * coins_applied as the precondition tear, then assert the post-state. */

#include "test/test_core.h"
#include "test/test_block_map.h"

#include "chain/chain.h"
#include "coins/utxo_commitment.h"
#include "core/uint256.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "jobs/reducer_frontier_schema.h"
#include "jobs/tip_finalize_stage.h"
#include "models/database.h"
#include "services/reindex_epilogue.h"
#include "services/seed_integrity_gate.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define RE_CHECK(name, expr) do {                              \
    printf("  reindex_epi: %s... ", (name));                   \
    if (expr) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                     \
} while (0)

struct re_chain {
    struct block_index tip;   /* one block at the high tip height */
    struct uint256     hash;
};

static void re_hash(struct uint256 *out, int h)
{
    uint256_set_null(out);
    out->data[0] = (uint8_t)(0xb0 + (h & 0x3F));
    out->data[1] = (uint8_t)(h & 0xFF);
    out->data[2] = (uint8_t)((h >> 8) & 0xFF);
    out->data[3] = (uint8_t)((h >> 16) & 0xFF);
}

/* Install a single synthetic block as the active tip at `tip_h`, above the
 * compiled SHA3 finality anchor so the H* hard-floor does not mask the
 * derivation. install_tip_slot sets the slot and publishes the height without
 * a pprev fill. */
static bool re_build_chain(struct re_chain *sc, struct main_state *ms, int tip_h)
{
    re_hash(&sc->hash, tip_h);
    block_index_init(&sc->tip);
    sc->tip.phashBlock = &sc->hash;
    sc->tip.nHeight = tip_h;
    sc->tip.nVersion = 4;
    sc->tip.nTime = 1700009000u;
    sc->tip.nBits = 0x1f07ffff;
    sc->tip.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
    arith_uint256_set_u64(&sc->tip.nChainWork, (uint64_t)tip_h + 1);
    if (!test_block_map_insert(&ms->map_block_index, sc->tip.phashBlock, &sc->tip))
        return false;
    return active_chain_install_tip_slot(&ms->chain_active, &sc->tip);
}

static void re_free_chain(struct re_chain *sc)
{
    memset(sc, 0, sizeof(*sc));
}

/* Insert one row into the node.db `utxos` mirror (the replayed authority). */
static bool re_insert_utxo(struct node_db *ndb, uint8_t tag, uint32_t vout,
                           int64_t value, int32_t height, int is_coinbase)
{
    uint8_t txid[32]; memset(txid, 0, 32);
    txid[0] = tag; txid[31] = 0x5a;
    uint8_t script[5] = {0x76, 0xa9, tag, 0x88, 0xac};
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT OR REPLACE INTO utxos"
            "(txid,vout,value,script,script_type,height,is_coinbase) "
            "VALUES(?,?,?,?,0,?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, (int)vout);
    sqlite3_bind_int64(st, 3, value);
    sqlite3_bind_blob(st, 4, script, sizeof(script), SQLITE_STATIC);
    sqlite3_bind_int(st, 5, height);
    sqlite3_bind_int(st, 6, is_coinbase);
    int rc = sqlite3_step(st);  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

/* Force one stage_cursor to a stale value (the pre-reindex torn precondition). */
static bool re_set_cursor(sqlite3 *db, const char *name, int64_t v)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES(?,?,1)", -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, v);
    int rc = sqlite3_step(st);  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static int64_t re_cursor(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int64_t out = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name=?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-fixture-verify
        out = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return out;
}

static int32_t re_trusted_base(sqlite3 *db)
{
    uint8_t blob[8] = {0}; size_t n = 0; bool found = false;
    if (!progress_meta_get(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                           blob, sizeof(blob), &n, &found) || !found || n != 8)
        return -1;
    int64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | blob[i];
    return (int32_t)v;
}

static bool re_shielded_markers_are(sqlite3 *db, int64_t want)
{
    int64_t sprout = -1, sapling = -1, nf = -1;
    bool sprout_found = false, sapling_found = false, nf_found = false;
    return anchor_kv_activation_cursor(
               db, ANCHOR_POOL_SPROUT, &sprout, &sprout_found) &&
           anchor_kv_activation_cursor(
               db, ANCHOR_POOL_SAPLING, &sapling, &sapling_found) &&
           nullifier_kv_activation_cursor(db, &nf, &nf_found) &&
           sprout_found && sapling_found && nf_found &&
           sprout == want && sapling == want && nf == want;
}

/* Seeds the replay completion witness directly (production advances this key
 * one height per block in the same transaction as anchors/nullifiers). */
static bool re_seed_completed_shielded_replay(sqlite3 *db, int64_t target)
{
    char next[24];
    int n = snprintf(next, sizeof(next), "%lld", (long long)(target + 1));
    return n > 0 && (size_t)n < sizeof(next) &&
           shielded_history_begin_full_replay(db, target) &&
           progress_meta_set(db, "shielded_history.full_replay.next",
                             next, (size_t)n);
}

static int mkdir_p_re(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    return (errno == EEXIST) ? 0 : -1;
}

#define ndb (*node_database)
#define expect_count (*expected_count)
#define TIP (*tip_height)
static int re_check_full_replay_post_state(
    int failures, sqlite3 *pdb, const int *tip_height,
    struct node_db *node_database, const uint8_t *replay_nf,
    const uint8_t *expect_root, const uint64_t *expected_count)
{
    /* ── POST-STATE assertions (the teeth). */

    /* coins_kv reseeded from the mirror + migration stamp. */
    RE_CHECK("post: coins_kv count == mirror count (4)",
             coins_kv_count(pdb) == 4);
    RE_CHECK("post: coins_kv proven-authority (migration stamp set)",
             coins_kv_is_proven_authority(pdb, NULL));
    {
        int64_t cursor = -1;
        bool found = false, row_found = false;
        RE_CHECK("post: full reindex publishes all shielded completeness last",
                 re_shielded_markers_are(pdb, 0) &&
                 nullifier_kv_activation_cursor(pdb, &cursor, &found) &&
                 found && cursor == 0);
        RE_CHECK("post: completion publication preserves replayed nullifiers",
                 nullifier_kv_get(pdb, replay_nf, NULLIFIER_POOL_SAPLING,
                                  &row_found, NULL) && row_found);
    }

    /* coins_applied_height == tip+1 (dropped from the stale-HIGH 99). */
    {
        int32_t ca = -1; bool found = false;
        bool ok = coins_kv_get_applied_height(pdb, &ca, &found);
        RE_CHECK("post: coins_applied_height == tip+1",
                 ok && found && ca == TIP + 1);
    }

    /* tip_finalize cursor == tip (#31, NEVER tip+1). */
    RE_CHECK("post: tip_finalize cursor == tip (NOT tip+1)",
             re_cursor(pdb, "tip_finalize") == TIP);

    /* 8 upstream cursors == tip+1 (the next-height convention). */
    RE_CHECK("post: utxo_apply cursor == tip+1",
             re_cursor(pdb, "utxo_apply") == TIP + 1);
    RE_CHECK("post: validate_headers cursor == tip+1",
             re_cursor(pdb, "validate_headers") == TIP + 1);
    RE_CHECK("post: header_admit cursor == tip+1",
             re_cursor(pdb, "header_admit") == TIP + 1);
    RE_CHECK("post: body_fetch cursor == tip+1",
             re_cursor(pdb, "body_fetch") == TIP + 1);
    RE_CHECK("post: body_persist cursor == tip+1",
             re_cursor(pdb, "body_persist") == TIP + 1);
    RE_CHECK("post: script_validate cursor == tip+1",
             re_cursor(pdb, "script_validate") == TIP + 1);
    RE_CHECK("post: proof_validate cursor == tip+1",
             re_cursor(pdb, "proof_validate") == TIP + 1);

    /* trusted_base_height == tip. */
    RE_CHECK("post: reducer_trusted_base_height == tip",
             re_trusted_base(pdb) == TIP);

    /* utxo_sha3 stamp == control compute over the mirror. */
    {
        uint8_t got[32]; int32_t gh = -1; uint64_t gc = 0;
        bool ld = utxo_commitment_sha3_load(ndb.db, got, &gh, &gc);
        RE_CHECK("post: utxo_sha3 stamp present", ld);
        RE_CHECK("post: utxo_sha3 == control compute",
                 ld && memcmp(got, expect_root, 32) == 0 &&
                 gc == expect_count && gh == TIP);
    }

    /* H* == replayed tip via reducer_frontier_compute_hstar (TIP is above the
     * compiled finality anchor, so MAX(tip,anchor) == tip). */
    {
        int32_t hs = 0, sf = 0;
        progress_store_tx_lock();
        bool ok = reducer_frontier_compute_hstar(pdb, &hs, &sf);
        progress_store_tx_unlock();
        RE_CHECK("post: H* == replayed tip", ok && hs == TIP);
    }

    /* TEAR GONE: coins_applied (tip+1) is NOT above the utxo_apply frontier. */
    {
        int32_t ca = 0; bool found = false;
        coins_kv_get_applied_height(pdb, &ca, &found);
        int32_t ua = 0;
        bool fok = reducer_frontier_log_frontier(pdb, "utxo_apply_log",
                                                 "utxo_apply", &ua);
        RE_CHECK("post: NO tear (coins_applied <= utxo_apply_frontier+1)",
                 found && fok && ca <= ua + 1);
    }
    return failures;
}
#undef ndb
#undef expect_count

static int re_check_imported_snapshot_authority(
    int failures, const int *tip_height)
{
    /* ── SNAPSHOT IMPORT: a verified snapshot import derives the same durable
     * authority surface as the full replay path. */
    test_reset_shared_globals();
    blocker_module_init();
    blocker_reset_for_testing();
    seed_integrity_gate_reset_for_testing();
    {
        char sdir[256];
        test_fmt_tmpdir(sdir, sizeof(sdir), "reindex_epi", "snapshot");
        mkdir_p_re(sdir);
        char snpath[600];
        snprintf(snpath, sizeof(snpath), "%s/node.db", sdir);

        struct node_db sndb;
        bool sok = node_db_open(&sndb, snpath);
        RE_CHECK("snapshot: node.db opens", sok);
        if (sok) {
            seed_integrity_gate_set_node_db_for_testing(&sndb);
            bool sutxos_ok = true;
            sutxos_ok &= re_insert_utxo(&sndb, 0x44, 0, 11000, 11, 1);
            sutxos_ok &= re_insert_utxo(&sndb, 0x55, 0, 12000, 12, 0);
            sutxos_ok &= re_insert_utxo(&sndb, 0x66, 0, 13000, 13, 0);
            RE_CHECK("snapshot: utxos seeded", sutxos_ok);

            uint8_t sexpect_root[32]; uint64_t sexpect_count = 0;
            utxo_commitment_sha3_compute(sndb.db, sexpect_root,
                                         &sexpect_count);
            RE_CHECK("snapshot: control utxo_count == 3",
                     sexpect_count == 3);

            RE_CHECK("snapshot: progress_store opens",
                     progress_store_open(sdir));
            sqlite3 *spdb = progress_store_db();
            RE_CHECK("snapshot: pdb handle", spdb != NULL);
            RE_CHECK("snapshot: shielded history starts assisted/incomplete",
                     shielded_history_reset_to_boundary(spdb, TIP));

            struct main_state sms;
            memset(&sms, 0, sizeof(sms));
            main_state_init(&sms);
            struct re_chain ssc; memset(&ssc, 0, sizeof(ssc));
            RE_CHECK("snapshot: synthetic chain to tip",
                     re_build_chain(&ssc, &sms, TIP));
            RE_CHECK("snapshot: tip_finalize stage init",
                     tip_finalize_stage_init(&sms));

            const int32_t SNAP_STALE_HIGH = TIP + 777;
            {
                char *err = NULL;
                bool seed_ok =
                    sqlite3_exec(spdb, "BEGIN IMMEDIATE", NULL, NULL, &err)
                        == SQLITE_OK &&
                    coins_kv_set_applied_height_in_tx(spdb, SNAP_STALE_HIGH) &&
                    sqlite3_exec(spdb, "COMMIT", NULL, NULL, &err)
                        == SQLITE_OK;
                if (err) sqlite3_free(err);
                RE_CHECK("snapshot: precond coins_applied stale-HIGH set",
                         seed_ok);
            }
            RE_CHECK("snapshot: precond stale tip_finalize cursor",
                     re_set_cursor(spdb, "tip_finalize", 3));
            RE_CHECK("snapshot: precond stale utxo_apply cursor",
                     re_set_cursor(spdb, "utxo_apply", 3));

            bool sderived = reindex_epilogue_derive_imported_snapshot(
                &sndb, snpath, TIP, ssc.hash.data);
            RE_CHECK("snapshot: imported epilogue returns true", sderived);

            RE_CHECK("snapshot: coins_kv count == mirror count (3)",
                     coins_kv_count(spdb) == 3);
            RE_CHECK("snapshot: coins_kv proven-authority",
                     coins_kv_is_proven_authority(spdb, NULL));
            {
                int64_t cursor = -1;
                bool found = false;
                RE_CHECK("snapshot: imported epilogue cannot publish shielded completeness",
                         re_shielded_markers_are(spdb, TIP) &&
                         nullifier_kv_activation_cursor(spdb, &cursor, &found) &&
                         found && cursor == TIP);
            }
            {
                int32_t ca = -1; bool found = false;
                bool ok = coins_kv_get_applied_height(spdb, &ca, &found);
                RE_CHECK("snapshot: coins_applied_height == tip+1",
                         ok && found && ca == TIP + 1);
            }
            RE_CHECK("snapshot: tip_finalize cursor == tip",
                     re_cursor(spdb, "tip_finalize") == TIP);
            RE_CHECK("snapshot: utxo_apply cursor == tip+1",
                     re_cursor(spdb, "utxo_apply") == TIP + 1);
            RE_CHECK("snapshot: validate_headers cursor == tip+1",
                     re_cursor(spdb, "validate_headers") == TIP + 1);
            RE_CHECK("snapshot: reducer_trusted_base_height == tip",
                     re_trusted_base(spdb) == TIP);
            {
                uint8_t got[32]; int32_t gh = -1; uint64_t gc = 0;
                bool ld = utxo_commitment_sha3_load(sndb.db, got, &gh, &gc);
                RE_CHECK("snapshot: utxo_sha3 stamp present", ld);
                RE_CHECK("snapshot: utxo_sha3 == control compute",
                         ld && memcmp(got, sexpect_root, 32) == 0 &&
                         gc == sexpect_count && gh == TIP);
            }
            {
                int32_t hs = 0, sf = 0;
                progress_store_tx_lock();
                bool ok = reducer_frontier_compute_hstar(spdb, &hs, &sf);
                progress_store_tx_unlock();
                RE_CHECK("snapshot: H* == imported tip", ok && hs == TIP);
            }

            tip_finalize_stage_shutdown();
            main_state_free(&sms);
            re_free_chain(&ssc);
            progress_store_close();
            seed_integrity_gate_reset_for_testing();
            node_db_close(&sndb);
        }
        test_cleanup_tmpdir(sdir);
    }
    return failures;
}

#undef TIP

/* ── Mutation-gap tests ────────────────────────────────────────────────
 * What the epilogue refuses, which typed reason it pages with, and what
 * state a refusal leaves behind. Every fixture is a throwaway datadir. */

struct re_ev {
    int pages;
    uint32_t peer;
    char last[256];
    int syncs;
    char sync[256];
};
static struct re_ev g_re_ev;

static void re_ev_obs(enum event_type type, uint32_t peer,
                      const void *payload, uint32_t len, void *ctx)
{
    (void)ctx;
    char *dst = g_re_ev.sync;
    if (type == EV_OPERATOR_NEEDED) {
        g_re_ev.pages++;
        g_re_ev.peer = peer;
        dst = g_re_ev.last;
    } else {
        g_re_ev.syncs++;
    }
    uint32_t n = !payload ? 0 : (len < 255 ? len : 255);
    if (n)
        memcpy(dst, payload, n);
    dst[n] = '\0';
}

static void re_ev_reset(void)
{
    memset(&g_re_ev, 0, sizeof(g_re_ev));
    event_log_init();
    event_clear_observers(EV_OPERATOR_NEEDED);
    event_clear_observers(EV_SYNC_STATE_CHANGE);
    event_observe(EV_OPERATOR_NEEDED, re_ev_obs, NULL);
    event_observe(EV_SYNC_STATE_CHANGE, re_ev_obs, NULL);
}

/* Exactly one page, to peer 0, with this typed reason at this height. */
static bool re_paged(const char *reason, int tip_h)
{
    char want[256];
    snprintf(want, sizeof(want),
             "check=reindex_epilogue tip_h=%d reason=%s", tip_h, reason);
    return g_re_ev.pages == 1 && g_re_ev.peer == 0 &&
           strcmp(g_re_ev.last, want) == 0;
}

/* Capture stdout+stderr through a pipe (output here is tiny). Where capture
 * is unavailable the text checks pass vacuously. */
static bool g_re_cap_live;

#ifndef _WIN32
#include <fcntl.h>

struct re_cap { int saved_out, saved_err, rd; };

static bool re_cap_begin(struct re_cap *c)
{
    int p[2];
    fflush(stdout);
    fflush(stderr);
    g_re_cap_live = pipe(p) == 0;
    if (!g_re_cap_live)
        return false;
    (void)fcntl(p[0], F_SETFL, O_NONBLOCK);
    c->saved_out = dup(1);
    c->saved_err = dup(2);
    (void)dup2(p[1], 1);
    (void)dup2(p[1], 2);
    close(p[1]);
    c->rd = p[0];
    return true;
}

static void re_cap_end(struct re_cap *c, char *buf, size_t cap)
{
    fflush(stdout);
    fflush(stderr);
    (void)dup2(c->saved_out, 1);
    (void)dup2(c->saved_err, 2);
    close(c->saved_out);
    close(c->saved_err);
    size_t n = 0;
    ssize_t r;
    while (n + 1 < cap && (r = read(c->rd, buf + n, cap - 1 - n)) > 0)
        n += (size_t)r;
    buf[n] = '\0';
    close(c->rd);
}
#else
struct re_cap { int unused; };
static bool re_cap_begin(struct re_cap *c)
{
    (void)c;
    g_re_cap_live = false;
    return false;
}
static void re_cap_end(struct re_cap *c, char *buf, size_t cap)
{
    (void)c; (void)cap;
    buf[0] = '\0';
}
#endif

enum { RE_OUT_CAP = 8192 };

static bool re_has(const char *out, const char *token)
{
    return !g_re_cap_live || strstr(out, token) != NULL;
}

static bool re_lacks(const char *out, const char *token)
{
    return !g_re_cap_live || strstr(out, token) == NULL;
}

/* The progress-store lock must be free once the epilogue returns. */
static bool re_lock_free(void)
{
    long tid = 0;
    int64_t held_us = 0;
    return !progress_store_tx_holder(&tid, &held_us);
}

static bool re_sql(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static int re_scalar(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int v = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-fixture-verify
        v = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return v;
}

static bool re_set_applied(sqlite3 *pdb, int32_t v)
{
    char *err = NULL;
    bool ok = sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, &err) == SQLITE_OK &&
              coins_kv_set_applied_height_in_tx(pdb, v) &&
              sqlite3_exec(pdb, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    return ok;
}

static int32_t re_applied(sqlite3 *pdb)
{
    int32_t v = -1;
    bool found = false;
    if (!coins_kv_get_applied_height(pdb, &v, &found) || !found)
        return -1;
    return v;
}

static uint64_t re_generation(sqlite3 *pdb)
{
    uint64_t v = UINT64_MAX;
    if (!coins_kv_get_authority_generation(pdb, &v))
        return UINT64_MAX;
    return v;
}

/* A throwaway datadir: node.db with a three-row utxos mirror, an optional
 * progress store, and a synthetic active chain to `tip`. */
struct re_gap {
    char dir[256];
    char path[600];
    struct node_db ndb;
    sqlite3 *pdb;
    struct main_state ms;
    struct re_chain sc;
    int tip;
};

static bool re_gap_seed_mirror(struct re_gap *g)
{
    return re_insert_utxo(&g->ndb, 0x44, 0, 11000, 11, 1) &&
           re_insert_utxo(&g->ndb, 0x55, 0, 12000, 12, 0) &&
           re_insert_utxo(&g->ndb, 0x66, 0, 13000, 13, 0);
}

static bool re_gap_open(struct re_gap *g, const char *tag, int tip,
                        bool store, bool full_logs)
{
    memset(g, 0, sizeof(*g));
    g->tip = tip;
    test_reset_shared_globals();
    blocker_module_init();
    blocker_reset_for_testing();
    seed_integrity_gate_reset_for_testing();
    test_fmt_tmpdir(g->dir, sizeof(g->dir), "reindex_epi", tag);
    mkdir_p_re("./test-tmp");
    mkdir_p_re(g->dir);
    snprintf(g->path, sizeof(g->path), "%s/node.db", g->dir);
    if (!node_db_open(&g->ndb, g->path))
        return false;
    seed_integrity_gate_set_node_db_for_testing(&g->ndb);
    main_state_init(&g->ms);
    bool ok = re_gap_seed_mirror(g) && re_build_chain(&g->sc, &g->ms, tip);
    if (store) {
        ok = ok && progress_store_open(g->dir);
        g->pdb = progress_store_db();
        ok = ok && g->pdb && tip_finalize_stage_init(&g->ms);
        ok = ok && (!full_logs || reducer_frontier_ensure_schema(g->pdb));
    }
    re_ev_reset();
    return ok;
}

static void re_gap_close(struct re_gap *g)
{
    if (g->pdb)
        tip_finalize_stage_shutdown();
    main_state_free(&g->ms);
    re_free_chain(&g->sc);
    if (g->pdb)
        progress_store_close();
    seed_integrity_gate_reset_for_testing();
    node_db_close(&g->ndb);
    test_cleanup_tmpdir(g->dir);
}

static bool re_snap(struct re_gap *g)
{
    return reindex_epilogue_derive_imported_snapshot(
        &g->ndb, g->path, g->tip, g->sc.hash.data);
}

static bool re_resume(struct re_gap *g, uint64_t gen, bool reset)
{
    return reindex_epilogue_resume_imported_snapshot(
        &g->ndb, g->path, g->tip, g->sc.hash.data, gen, reset);
}

#define RE_GAP_TIP ((int)REDUCER_FRONTIER_TRUSTED_ANCHOR + 5)

/* ── argument refusals ── */

struct re_arg_case {
    const char *label;
    struct node_db *ndb;
    const char *path;
    int height;
    const uint8_t *hash;
};

static int re_gap_arg_refusals(void)
{
    int failures = 0;
    struct re_gap g;
    uint8_t hash[32] = {1};
    struct node_db closed, nohandle;
    memset(&closed, 0, sizeof(closed));
    memset(&nohandle, 0, sizeof(nohandle));
    nohandle.open = true;
    RE_CHECK("gap/args: fixture", re_gap_open(&g, "args", 100, true, false));
    const struct re_arg_case cases[] = {
        { "NULL ndb", NULL, g.path, 100, hash },
        { "closed ndb", &closed, g.path, 100, hash },
        { "open ndb without a handle", &nohandle, g.path, 100, hash },
        { "NULL path", &g.ndb, NULL, 100, hash },
        { "empty path", &g.ndb, "", 100, hash },
        { "negative height", &g.ndb, g.path, -1, hash },
        { "NULL hash", &g.ndb, g.path, 100, NULL },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char label[96];
        re_ev_reset();
        bool r = reindex_epilogue_derive_imported_snapshot(
            cases[i].ndb, cases[i].path, cases[i].height, cases[i].hash);
        snprintf(label, sizeof(label), "gap/args: %s refused, paged at -1",
                 cases[i].label);
        RE_CHECK(label, !r && re_paged("null_or_closed_arg", -1));
    }
    /* A one-character path and height 0 are valid arguments: the refusal
     * comes later, at the reseed, not at the argument gate. */
    re_ev_reset();
    bool r = reindex_epilogue_derive_imported_snapshot(&g.ndb, "/", 0, hash);
    RE_CHECK("gap/args: one-char path at height 0 passes the arg gate",
             !r && re_paged("coins_kv_reseed_failed", 0));
    RE_CHECK("gap/args: lock released after the refusals", re_lock_free());
    re_gap_close(&g);

    RE_CHECK("gap/args: closed store fixture",
             re_gap_open(&g, "nostore", RE_GAP_TIP, false, false));
    r = re_snap(&g);
    RE_CHECK("gap/args: closed progress store refused and paged",
             !r && re_paged("progress_store_not_open", RE_GAP_TIP));
    re_gap_close(&g);
    return failures;
}

/* ── authority generation ── */

static bool re_gap_gen_triggers(sqlite3 *pdb, const char *action)
{
    char sql[512];
    snprintf(sql, sizeof(sql),
             "CREATE TRIGGER re_gen_ins BEFORE INSERT ON progress_meta "
             "WHEN NEW.key='%s' BEGIN SELECT RAISE(%s); END;"
             "CREATE TRIGGER re_gen_upd BEFORE UPDATE ON progress_meta "
             "WHEN NEW.key='%s' BEGIN SELECT RAISE(%s); END",
             COINS_KV_AUTHORITY_GENERATION_KEY, action,
             COINS_KV_AUTHORITY_GENERATION_KEY, action);
    return re_sql(pdb, sql);
}

static bool re_gap_drop_gen_triggers(sqlite3 *pdb)
{
    return re_sql(pdb, "DROP TRIGGER re_gen_ins;DROP TRIGGER re_gen_upd");
}

static int re_gap_generation_refusals(struct re_gap *g, uint64_t g0)
{
    int failures = 0;
    re_ev_reset();
    bool r = re_resume(g, g0 + 7, true);
    RE_CHECK("gap/gen: a changed generation is refused and paged",
             !r && re_paged("snapshot_generation_changed", g->tip));
    RE_CHECK("gap/gen: the refusal reset nothing",
             re_generation(g->pdb) == g0);

    RE_CHECK("gap/gen: reset-blocking trigger installs",
             re_gap_gen_triggers(g->pdb, "ABORT,'re'"));
    re_ev_reset();
    r = re_resume(g, g0, true);
    RE_CHECK("gap/gen: a failed reset is refused and paged",
             !r && re_paged("coins_kv_reset_failed", g->tip));
    RE_CHECK("gap/gen: the failed reset left the generation",
             re_generation(g->pdb) == g0);
    RE_CHECK("gap/gen: trigger drops", re_gap_drop_gen_triggers(g->pdb));

    RE_CHECK("gap/gen: bump-swallowing trigger installs",
             re_gap_gen_triggers(g->pdb, "IGNORE"));
    re_ev_reset();
    r = re_resume(g, g0, true);
    RE_CHECK("gap/gen: a reset that does not advance one generation is refused",
             !r && re_paged("snapshot_reset_generation_mismatch", g->tip));
    RE_CHECK("gap/gen: trigger drops again", re_gap_drop_gen_triggers(g->pdb));
    return failures;
}

static int re_gap_generation_resume(struct re_gap *g, uint64_t g0)
{
    int failures = 0;
    re_ev_reset();
    bool r = re_resume(g, g0, true);
    RE_CHECK("gap/gen: a matching generation with reset succeeds", r);
    RE_CHECK("gap/gen: the reset advanced exactly one generation",
             re_generation(g->pdb) == g0 + 1);
    RE_CHECK("gap/gen: reseed copied the mirror", coins_kv_count(g->pdb) == 3);
    RE_CHECK("gap/gen: success pages nothing", g_re_ev.pages == 0);

    uint64_t g1 = g0 + 1;
    re_ev_reset();
    r = re_resume(g, g1, false);
    RE_CHECK("gap/gen: resume without reset at the same generation succeeds", r);
    RE_CHECK("gap/gen: no reset, so the generation is unchanged",
             re_generation(g->pdb) == g1);
    RE_CHECK("gap/gen: lock released", re_lock_free());
    return failures;
}

static int re_gap_applied_clamp_directions(struct re_gap *g, uint64_t g1)
{
    int failures = 0;
    const int32_t t = g->tip;
    RE_CHECK("gap/clamp: precondition applied above tip+1",
             re_set_applied(g->pdb, t + 50));
    bool r = re_resume(g, g1, false);
    RE_CHECK("gap/clamp: an applied height above tip+1 is accepted", r);
    RE_CHECK("gap/clamp: and never lowered", re_applied(g->pdb) == t + 50);

    RE_CHECK("gap/clamp: precondition applied one below tip+1",
             re_set_applied(g->pdb, t));
    r = re_resume(g, g1, false);
    RE_CHECK("gap/clamp: an applied height below tip+1 is accepted", r);
    RE_CHECK("gap/clamp: and raised to tip+1", re_applied(g->pdb) == t + 1);

    r = re_resume(g, g1, false);
    RE_CHECK("gap/clamp: an applied height at tip+1 is accepted", r);
    RE_CHECK("gap/clamp: and left at tip+1", re_applied(g->pdb) == t + 1);
    return failures;
}

static int re_gap_generation(void)
{
    int failures = 0;
    struct re_gap g;
    RE_CHECK("gap/gen: fixture",
             re_gap_open(&g, "gen", RE_GAP_TIP, true, false));
    RE_CHECK("gap/gen: generation key exists after a bootstrap reset",
             coins_kv_reset_for_reseed(g.pdb));
    uint64_t g0 = re_generation(g.pdb);
    RE_CHECK("gap/gen: generation readable", g0 != UINT64_MAX);
    failures += re_gap_generation_refusals(&g, g0);
    failures += re_gap_generation_resume(&g, g0);
    failures += re_gap_applied_clamp_directions(&g, g0 + 1);
    re_gap_close(&g);
    return failures;
}

/* ── clamp failure leaves no open transaction ── */

#define RE_APPLIED_TRIGGERS(when_sql) \
    "CREATE TRIGGER re_ap_ins " when_sql " INSERT ON progress_meta " \
    "WHEN NEW.key='" COINS_APPLIED_HEIGHT_KEY "' BEGIN %s END;" \
    "CREATE TRIGGER re_ap_upd " when_sql " UPDATE ON progress_meta " \
    "WHEN NEW.key='" COINS_APPLIED_HEIGHT_KEY "' BEGIN %s END"

static bool re_gap_applied_trigger(sqlite3 *pdb, bool before, const char *body)
{
    char sql[768];
    snprintf(sql, sizeof(sql),
             before ? RE_APPLIED_TRIGGERS("BEFORE")
                    : RE_APPLIED_TRIGGERS("AFTER"), body, body);
    return re_sql(pdb, sql);
}

static int re_gap_check_clamp_refusal(struct re_gap *g, const char *label,
                                      bool r, const char *out)
{
    int failures = 0;
    char want[64];
    RE_CHECK(label, !r && re_paged("coins_applied_clamp_failed", g->tip));
    RE_CHECK("gap/clamp: no transaction left open on the progress store",
             sqlite3_get_autocommit(g->pdb) != 0);
    RE_CHECK("gap/clamp: progress-store lock released", re_lock_free());
    snprintf(want, sizeof(want), "clamp to %d failed", g->tip + 1);
    RE_CHECK("gap/clamp: log names the tip+1 target", re_has(out, want));
    RE_CHECK("gap/clamp: no tip_finalize anchor stamped on a refusal",
             re_cursor(g->pdb, "tip_finalize") != g->tip);
    RE_CHECK("gap/clamp: applied height not written",
             re_applied(g->pdb) == -1);
    return failures;
}

static int re_gap_clamp_write_fails(void)
{
    int failures = 0;
    struct re_gap g;
    char out[RE_OUT_CAP];
    struct re_cap c;
    RE_CHECK("gap/clamp: fixture",
             re_gap_open(&g, "clampw", RE_GAP_TIP, true, false));
    RE_CHECK("gap/clamp: write-blocking trigger installs",
             re_gap_applied_trigger(g.pdb, true,
                                    "SELECT RAISE(ABORT,'re');"));
    re_cap_begin(&c);
    bool r = re_snap(&g);
    if (g_re_cap_live) re_cap_end(&c, out, sizeof(out)); else out[0] = '\0';
    failures += re_gap_check_clamp_refusal(
        &g, "gap/clamp: a failed applied-height write is refused and paged",
        r, out);
    RE_CHECK("gap/clamp: trigger drops",
             re_sql(g.pdb, "DROP TRIGGER re_ap_ins;DROP TRIGGER re_ap_upd"));
    r = re_snap(&g);
    RE_CHECK("gap/clamp: a rerun after the refusal derives", r);
    RE_CHECK("gap/clamp: and lands the applied height at tip+1",
             re_applied(g.pdb) == g.tip + 1);
    re_gap_close(&g);
    return failures;
}

static int re_gap_clamp_commit_fails(void)
{
    int failures = 0;
    struct re_gap g;
    char out[RE_OUT_CAP];
    struct re_cap c;
    RE_CHECK("gap/clamp: fixture",
             re_gap_open(&g, "clampc", RE_GAP_TIP, true, false));
    RE_CHECK("gap/clamp: deferred-FK schema installs",
             re_sql(g.pdb,
                    "PRAGMA foreign_keys=ON;"
                    "CREATE TABLE re_fk_parent(id INTEGER PRIMARY KEY);"
                    "CREATE TABLE re_fk_child(pid INTEGER REFERENCES "
                    "re_fk_parent(id) DEFERRABLE INITIALLY DEFERRED)"));
    RE_CHECK("gap/clamp: orphan-inserting trigger installs",
             re_gap_applied_trigger(g.pdb, false,
                                    "INSERT INTO re_fk_child VALUES(9);"));
    re_cap_begin(&c);
    bool r = re_snap(&g);
    if (g_re_cap_live) re_cap_end(&c, out, sizeof(out)); else out[0] = '\0';
    failures += re_gap_check_clamp_refusal(
        &g, "gap/clamp: a failed COMMIT is refused and paged", r, out);
    RE_CHECK("gap/clamp: the failed transaction's rows were rolled back",
             re_scalar(g.pdb, "SELECT COUNT(*) FROM re_fk_child") == 0);
    re_gap_close(&g);
    return failures;
}

/* ── what a good run derives, and the non-fatal cache write ── */

static int re_gap_success_effects(void)
{
    int failures = 0;
    struct re_gap g;
    char out[RE_OUT_CAP], want[256];
    struct re_cap c;
    struct utxo_commitment stale, fresh, got;
    RE_CHECK("gap/ok: fixture",
             re_gap_open(&g, "ok", RE_GAP_TIP, true, false));
    memset(&stale, 0xee, sizeof(stale));
    stale.count = 99;
    RE_CHECK("gap/ok: stale XOR checkpoint planted",
             utxo_commitment_save_checkpoint(g.ndb.db, &stale));
    re_cap_begin(&c);
    bool r = re_snap(&g);
    if (g_re_cap_live) re_cap_end(&c, out, sizeof(out)); else out[0] = '\0';
    RE_CHECK("gap/ok: derives", r);
    utxo_commitment_compute_db(g.ndb.db, &fresh);
    RE_CHECK("gap/ok: XOR checkpoint recomputed over the mirror",
             utxo_commitment_load_checkpoint(g.ndb.db, &got) &&
             got.count == 3 && fresh.count == 3 &&
             memcmp(got.accumulator, fresh.accumulator, 32) == 0);
    uint8_t best[40] = {0};
    size_t blen = 0;
    RE_CHECK("gap/ok: coins_best_block cache holds the 32-byte tip hash",
             node_db_state_get(&g.ndb, "coins_best_block", best, sizeof(best),
                               &blen) &&
             blen == 32 && memcmp(best, g.sc.hash.data, 32) == 0);
    RE_CHECK("gap/ok: no cache-write warning on success",
             re_lacks(out, "cache write failed"));
    snprintf(want, sizeof(want),
             "UTXO authority epilogue derived: source=snapshot_import "
             "tip=%d coins_applied=%d utxo_count=3 H*=%d",
             g.tip, g.tip + 1, g.tip);
    RE_CHECK("gap/ok: summary log names source, tip, tip+1, count and H*",
             re_has(out, want));
    snprintf(want, sizeof(want),
             "utxo_authority_epilogue source=snapshot_import tip=%d count=3",
             g.tip);
    RE_CHECK("gap/ok: exactly one sync-state event with source, tip, count",
             g_re_ev.syncs == 1 && strcmp(g_re_ev.sync, want) == 0);
    RE_CHECK("gap/ok: success pages nothing", g_re_ev.pages == 0);
    RE_CHECK("gap/ok: lock released", re_lock_free());
    re_gap_close(&g);
    return failures;
}

static int re_gap_best_block_nonfatal(void)
{
    int failures = 0;
    struct re_gap g;
    char out[RE_OUT_CAP];
    struct re_cap c;
    uint8_t best[40];
    size_t blen = 0;
    RE_CHECK("gap/cache: fixture",
             re_gap_open(&g, "cache", RE_GAP_TIP, true, false));
    RE_CHECK("gap/cache: cache-blocking trigger installs",
             re_sql(g.ndb.db,
                    "CREATE TRIGGER re_bb BEFORE INSERT ON node_state "
                    "WHEN NEW.key='coins_best_block' "
                    "BEGIN SELECT RAISE(ABORT,'re'); END"));
    re_cap_begin(&c);
    bool r = re_snap(&g);
    if (g_re_cap_live) re_cap_end(&c, out, sizeof(out)); else out[0] = '\0';
    RE_CHECK("gap/cache: a failed cache write does not fail the epilogue", r);
    RE_CHECK("gap/cache: the failure is logged as a warning",
             re_has(out, "coins_best_block cache write failed"));
    RE_CHECK("gap/cache: no cache row was written",
             !node_db_state_get(&g.ndb, "coins_best_block", best,
                                sizeof(best), &blen));
    re_gap_close(&g);
    return failures;
}

/* ── ensure-schema and seed-anchor refusals ── */

static int re_deny_validate_headers_log(void *u, int act, const char *a,
                                        const char *b, const char *c,
                                        const char *d)
{
    (void)u; (void)b; (void)c; (void)d;
    bool hit = act == SQLITE_CREATE_TABLE && a &&
               strcmp(a, "validate_headers_log") == 0;
    return hit ? SQLITE_DENY : SQLITE_OK;
}

static int re_gap_schema_ensure_refused(void)
{
    int failures = 0;
    struct re_gap g;
    RE_CHECK("gap/schema: fixture",
             re_gap_open(&g, "schema", RE_GAP_TIP, true, false));
    RE_CHECK("gap/schema: the reducer log is absent",
             re_sql(g.pdb, "DROP TABLE IF EXISTS validate_headers_log"));
    sqlite3_set_authorizer(g.pdb, re_deny_validate_headers_log, NULL);
    bool r = re_snap(&g);
    RE_CHECK("gap/schema: an unavailable reducer log schema is refused, paged",
             !r && re_paged("reducer_log_schema_ensure_failed", g.tip));
    RE_CHECK("gap/schema: lock released", re_lock_free());
    sqlite3_set_authorizer(g.pdb, NULL, NULL);
    r = re_snap(&g);
    RE_CHECK("gap/schema: a rerun once the schema can be made derives", r);
    re_gap_close(&g);
    return failures;
}

static int re_gap_seed_anchor_refused(void)
{
    int failures = 0;
    struct re_gap g;
    RE_CHECK("gap/anchor: fixture",
             re_gap_open(&g, "anchor", RE_GAP_TIP, true, true));
    RE_CHECK("gap/anchor: anchor-blocking trigger installs",
             re_sql(g.pdb,
                    "CREATE TRIGGER re_tf BEFORE INSERT ON tip_finalize_log "
                    "BEGIN SELECT RAISE(ABORT,'re'); END"));
    bool r = re_snap(&g);
    RE_CHECK("gap/anchor: a failed seed anchor is refused and paged",
             !r && re_paged("seed_anchor_failed", g.tip));
    RE_CHECK("gap/anchor: lock released", re_lock_free());
    RE_CHECK("gap/anchor: no transaction left open on the progress store",
             sqlite3_get_autocommit(g.pdb) != 0);
    RE_CHECK("gap/anchor: trigger drops", re_sql(g.pdb, "DROP TRIGGER re_tf"));
    r = re_snap(&g);
    RE_CHECK("gap/anchor: a rerun after the refusal derives", r);
    re_gap_close(&g);
    return failures;
}

/* ── reindex_epilogue_derive: refusals ── */

static void re_gap_fill_dir(char *dst, size_t cap, size_t len)
{
    memset(dst, 'a', len);
    dst[0] = '/';
    dst[len < cap ? len : cap - 1] = '\0';
}

static int re_gap_derive_refusals(void)
{
    int failures = 0;
    struct re_gap g;
    char dd[700];
    RE_CHECK("gap/derive: fixture",
             re_gap_open(&g, "derive", RE_GAP_TIP, true, false));
    re_ev_reset();
    RE_CHECK("gap/derive: NULL datadir refused, paged at -1",
             !reindex_epilogue_derive(&g.ms, &g.ndb, NULL) &&
             re_paged("null_or_closed_arg", -1));
    re_ev_reset();
    RE_CHECK("gap/derive: NULL ms refused, paged at -1",
             !reindex_epilogue_derive(NULL, &g.ndb, g.dir) &&
             re_paged("null_or_closed_arg", -1));

    /* "<dir>/node.db" is 8 bytes longer than <dir>: 599 fits a 600-byte
     * buffer, 600 does not. */
    re_gap_fill_dir(dd, sizeof(dd), 591);
    re_ev_reset();
    (void)reindex_epilogue_derive(&g.ms, &g.ndb, dd);
    RE_CHECK("gap/derive: a 599-byte node.db path is not an overflow",
             strstr(g_re_ev.last, "node_db_path_overflow") == NULL);
    re_gap_fill_dir(dd, sizeof(dd), 592);
    re_ev_reset();
    RE_CHECK("gap/derive: a 600-byte node.db path overflows, refused and paged",
             !reindex_epilogue_derive(&g.ms, &g.ndb, dd) &&
             re_paged("node_db_path_overflow", g.tip));
    RE_CHECK("gap/derive: lock released", re_lock_free());
    re_gap_close(&g);
    return failures;
}

static int re_gap_derive_tip_cases(void)
{
    int failures = 0;
    struct re_gap g;
    char want[64];
    RE_CHECK("gap/tip: fixture",
             re_gap_open(&g, "notip", RE_GAP_TIP, true, false));
    struct main_state empty;
    memset(&empty, 0, sizeof(empty));
    main_state_init(&empty);
    re_ev_reset();
    bool r = reindex_epilogue_derive(&empty, &g.ndb, g.dir);
    snprintf(want, sizeof(want), "no_active_tip_after_replay");
    RE_CHECK("gap/tip: no active tip refused, paged with the typed reason",
             !r && g_re_ev.pages == 1 && g_re_ev.peer == 0 &&
             strstr(g_re_ev.last, want) != NULL);
    main_state_free(&empty);
    re_gap_close(&g);

    /* A chain at height 0 (genesis only) is a tip, not "no tip". */
    RE_CHECK("gap/tip: genesis fixture",
             re_gap_open(&g, "genesis", 0, true, false));
    re_ev_reset();
    (void)reindex_epilogue_derive(&g.ms, &g.ndb, g.dir);
    RE_CHECK("gap/tip: a height-0 tip is not refused as missing",
             strstr(g_re_ev.last, "no_active_tip_after_replay") == NULL);
    re_gap_close(&g);
    return failures;
}

static int re_mutation_gap_tests(void)
{
    int failures = 0;
    failures += re_gap_arg_refusals();
    failures += re_gap_generation();
    failures += re_gap_clamp_write_fails();
    failures += re_gap_clamp_commit_fails();
    failures += re_gap_success_effects();
    failures += re_gap_best_block_nonfatal();
    failures += re_gap_schema_ensure_refused();
    failures += re_gap_seed_anchor_refused();
    failures += re_gap_derive_refusals();
    failures += re_gap_derive_tip_cases();
    return failures;
}

int test_reindex_epilogue(void);
int test_reindex_epilogue(void)
{
    test_reset_shared_globals();   /* monolith isolation: see test_helpers.c */
    printf("\n=== reindex_epilogue tests ===\n");
    int failures = 0;
    /* Tip ABOVE the compiled SHA3 finality anchor so H* == tip is meaningful
     * (compute_hstar hard-floors H* at the anchor; a tip below it would pin
     * H* at the floor and mask the derivation under test). */
    const int TIP = (int)REDUCER_FRONTIER_TRUSTED_ANCHOR + 5;

    blocker_module_init();
    blocker_reset_for_testing();
    seed_integrity_gate_reset_for_testing();

    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "reindex_epi", "main");
    mkdir_p_re("./test-tmp");
    mkdir_p_re(dir);

    char ndb_path[600];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir);

    /* node.db with a known utxos set (the replayed mirror) + a matching
     * blocks projection ABSENT at the tip (the seed gate passes-with-warn). */
    struct node_db ndb;
    bool db_ok = node_db_open(&ndb, ndb_path);
    RE_CHECK("fixture: node.db opens", db_ok);
    if (!db_ok) return failures;
    /* Point the seed gate at our node.db so the trusted-seed commitment +
     * linkage checks run against the same handle the epilogue stamps. */
    seed_integrity_gate_set_node_db_for_testing(&ndb);

    bool utxos_ok = true;
    utxos_ok &= re_insert_utxo(&ndb, 0x11, 0, 5000, 2, 1);
    utxos_ok &= re_insert_utxo(&ndb, 0x11, 1, 6000, 2, 1);
    utxos_ok &= re_insert_utxo(&ndb, 0x22, 0, 7000, 5, 0);
    utxos_ok &= re_insert_utxo(&ndb, 0x33, 0, 8000, 7, 0);
    RE_CHECK("fixture: utxos seeded", utxos_ok);

    /* Independent control: the SHA3 the epilogue should stamp. */
    uint8_t expect_root[32]; uint64_t expect_count = 0;
    utxo_commitment_sha3_compute(ndb.db, expect_root, &expect_count);
    RE_CHECK("fixture: control utxo_count == 4", expect_count == 4);

    /* progress store + active chain + tip_finalize stage. */
    RE_CHECK("fixture: progress_store opens", progress_store_open(dir));
    sqlite3 *pdb = progress_store_db();
    RE_CHECK("fixture: pdb handle", pdb != NULL);
    uint8_t replay_nf[32] = {0x71};
    RE_CHECK("fixture: exact genesis-to-target shielded replay completed",
             re_seed_completed_shielded_replay(pdb, TIP));
    RE_CHECK("fixture: all shielded markers remain incomplete pre-epilogue",
             re_shielded_markers_are(pdb, (int64_t)TIP + 1));
    RE_CHECK("fixture: replay inserts a nullifier under positive marker",
             nullifier_kv_add(pdb, replay_nf, NULLIFIER_POOL_SAPLING, 9));

    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    main_state_init(&ms);
    struct re_chain sc; memset(&sc, 0, sizeof(sc));
    RE_CHECK("fixture: synthetic chain to tip", re_build_chain(&sc, &ms, TIP));
    RE_CHECK("fixture: active height == TIP",
             active_chain_height(&ms.chain_active) == TIP);

    RE_CHECK("fixture: tip_finalize stage init", tip_finalize_stage_init(&ms));
    RE_CHECK("fixture: reducer log schema complete",
             reducer_frontier_ensure_schema(pdb));

    /* ── PRECONDITION: torn state. coins_applied stale-HIGH above the rebuilt
     * tip and the finality anchor; upstream cursors stale-low. */
    const int32_t STALE_HIGH = TIP + 1000;
    {
        char *err = NULL;
        bool seed_ok = sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, &err) == SQLITE_OK
                       && coins_kv_set_applied_height_in_tx(pdb, STALE_HIGH)
                       && sqlite3_exec(pdb, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
        if (err) sqlite3_free(err);
        RE_CHECK("precond: coins_applied stale-HIGH set", seed_ok);
    }
    RE_CHECK("precond: stale tip_finalize cursor",
             re_set_cursor(pdb, "tip_finalize", 3));
    RE_CHECK("precond: stale utxo_apply cursor",
             re_set_cursor(pdb, "utxo_apply", 3));
    RE_CHECK("precond: stale validate_headers cursor",
             re_set_cursor(pdb, "validate_headers", 3));

    /* GATE-FIRES PROOF: before the epilogue, coins_applied is far above the
     * utxo_apply frontier (the tear shape the epilogue erases). */
    {
        int32_t ca = 0; bool found = false;
        coins_kv_get_applied_height(pdb, &ca, &found);
        int32_t ua = 0;
        bool fok = reducer_frontier_log_frontier(pdb, "utxo_apply_log",
                                                 "utxo_apply", &ua);
        RE_CHECK("precond: TEAR present (coins_applied > utxo_apply_frontier+1)",
                 found && fok && ca == STALE_HIGH && ca > ua + 1);
    }

    /* ── RUN THE EPILOGUE. Force the final NF marker write to fail after the
     * two anchor rows updated: the completion transaction must roll all three
     * back, then an un-faulted retry may accept. */
    RE_CHECK("fixture: completion interruption trigger installs",
             sqlite3_exec(
                 pdb,
                 "CREATE TRIGGER fail_reindex_completion BEFORE INSERT ON "
                 "progress_meta WHEN NEW.key='nullifier_kv.activation_cursor' "
                 "BEGIN SELECT RAISE(ABORT,'completion interrupted'); END",
                 NULL, NULL, NULL) == SQLITE_OK);
    re_ev_reset();
    bool interrupted = reindex_epilogue_derive(&ms, &ndb, dir);
    RE_CHECK("interrupted epilogue refuses",
             !interrupted);
    RE_CHECK("interrupted epilogue pages the typed completion reason",
             re_paged("shielded_completion_publish_failed", TIP));
    RE_CHECK("interrupted epilogue releases the progress-store lock",
             re_lock_free());
    RE_CHECK("interrupted epilogue keeps all shielded history incomplete",
             re_shielded_markers_are(pdb, (int64_t)TIP + 1));
    RE_CHECK("fixture: completion interruption trigger drops",
             sqlite3_exec(pdb, "DROP TRIGGER fail_reindex_completion",
                          NULL, NULL, NULL) == SQLITE_OK);
    re_ev_reset();
    bool derived = reindex_epilogue_derive(&ms, &ndb, dir);
    RE_CHECK("epilogue_derive returns true", derived);
    {
        char want[128];
        snprintf(want, sizeof(want),
                 "utxo_authority_epilogue source=reindex tip=%d count=4", TIP);
        RE_CHECK("reindex success emits one sync-state event, pages nothing",
                 g_re_ev.syncs == 1 && g_re_ev.pages == 0 &&
                 strcmp(g_re_ev.sync, want) == 0);
    }

    failures = re_check_full_replay_post_state(
        failures, pdb, &TIP, &ndb, replay_nf, expect_root, &expect_count);

    tip_finalize_stage_shutdown();
    main_state_free(&ms);
    re_free_chain(&sc);
    progress_store_close();
    seed_integrity_gate_reset_for_testing();
    node_db_close(&ndb);
    test_cleanup_tmpdir(dir);

    failures = re_check_imported_snapshot_authority(failures, &TIP);
    failures += re_mutation_gap_tests();

    /* ── NEGATIVE: empty/unreadable mirror + bad args -> false, no crash. */
    {
        /* NULL ms / ndb / datadir -> false (and the function pages + logs). */
        RE_CHECK("neg: NULL ms -> false",
                 !reindex_epilogue_derive(NULL, NULL, NULL));
        RE_CHECK("neg: imported snapshot bad args -> false",
                 !reindex_epilogue_derive_imported_snapshot(NULL, NULL, -1,
                                                            NULL));
    }
    {
        char ndir[256];
        test_fmt_tmpdir(ndir, sizeof(ndir), "reindex_epi", "neg");
        mkdir_p_re(ndir);
        char npath[600];
        snprintf(npath, sizeof(npath), "%s/node.db", ndir);
        struct node_db nndb;
        bool nok = node_db_open(&nndb, npath);
        RE_CHECK("neg: node.db opens", nok);
        if (nok) {
            seed_integrity_gate_reset_for_testing();
            seed_integrity_gate_set_node_db_for_testing(&nndb);
            progress_store_open(ndir);
            struct main_state nms; memset(&nms, 0, sizeof(nms));
            main_state_init(&nms);
            /* No active chain -> epilogue refuses cleanly (no partial clamp). */
            bool d = reindex_epilogue_derive(&nms, &nndb, ndir);
            RE_CHECK("neg: no-active-tip -> false (no partial clamp)", !d);
            int32_t nv = 0; bool nf = true;
            coins_kv_get_applied_height(progress_store_db(), &nv, &nf);
            RE_CHECK("neg: coins_applied still ABSENT (no partial write)", !nf);
            main_state_free(&nms);
            progress_store_close();
            seed_integrity_gate_reset_for_testing();
            node_db_close(&nndb);
        }
        test_cleanup_tmpdir(ndir);
    }

    blocker_reset_for_testing();
    return failures;
}
