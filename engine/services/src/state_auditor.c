// one-result-type-ok:fail-loud-background-scrubber
/* E2 override: this module's public surface is a bounded best-effort
 * background scrubber (state_auditor_tick_once) plus a pure snapshot read
 * (state_auditor_get_mismatch) and a JSON dump — the same fail-loud,
 * best-effort-batch shape as the sibling authority_projection_audit /
 * invariant_sentinel / op_return_backfill_service sweeps. A single skipped
 * tick (block not readable yet, reducer holds the trylock, markers moved
 * mid-scan) is an ordinary, expected outcome, not a failure to propagate via
 * a zcl_result; the confirmed-mismatch signal travels through
 * state_auditor_get_mismatch() to conditions/state_auditor_mismatch.c, which
 * owns the typed-blocker channel. */

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * state_auditor — see services/state_auditor.h for the design contract. */

#include "services/state_auditor.h"

#include "chain/chain.h"
#include "coins/utxo_commitment.h"
#include "config/runtime.h"
#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "models/op_return_index.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "services/utxo_mirror_sync_service.h" /* UTXO_MIRROR_SYNC_CURSOR_KEY */
#include "storage/coins_kv.h"
#include "storage/coins_ram.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/util.h"  /* GetDataDir */
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <inttypes.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Real chain blocks carry at most dozens of OP_RETURN outputs per block
 * (op_return_backfill_service's own cap is 65536, "real chain blocks carry
 * far fewer"). 128 is generous headroom while keeping both the extracted
 * and stored stack arrays small (~13 KB each). A block that genuinely
 * exceeds this is a pathological input, not a real block; the tick is
 * skipped rather than risk comparing truncated data as if it were complete
 * (see opret_check_window). */
#define STATE_AUDITOR_OPRET_ROW_CAP 128

enum audit_tick_result {
    AUDIT_TICK_SKIPPED = 0, /* benign: not enough history, unreadable body,
                             * reducer holds the trylock, or a torn scan —
                             * never a verdict, streak/latch untouched */
    AUDIT_TICK_CLEAN,
    AUDIT_TICK_MISMATCH,
};

/* ── leg state ────────────────────────────────────────────────────── */

struct opret_leg_state {
    _Atomic bool    latched;
    _Atomic bool    investigating; /* a pinned window is being confirmed or
                                    * is already latched — re-check it,
                                    * don't pick a fresh random one */
    _Atomic int     confirm_streak;
    _Atomic int32_t pinned_h_start;
    _Atomic int32_t pinned_h_end;
    pthread_mutex_t detail_lock;
    char            detail[192];
};

struct coins_leg_state {
    _Atomic bool    latched;
    _Atomic bool    investigating;
    _Atomic int     confirm_streak;
    _Atomic int32_t last_h_min; /* observed span of the pinned window's last
                                 * scan — reporting only, the pin itself is
                                 * pinned_txid_lo below */
    _Atomic int32_t last_h_max;
    pthread_mutex_t lock;       /* protects pinned_txid_lo + detail */
    uint8_t         pinned_txid_lo[32];
    char            detail[192];
};

static struct opret_leg_state g_opret_leg = {
    .detail_lock = PTHREAD_MUTEX_INITIALIZER,
};
static struct coins_leg_state g_coins_leg = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

/* ── counters (atomic; dumped via JSON) ─────────────────────────────── */
static _Atomic uint64_t g_opret_ticks      = 0;
static _Atomic uint64_t g_opret_skipped    = 0;
static _Atomic uint64_t g_opret_mismatches = 0; /* confirmed latch raises */
static _Atomic uint64_t g_opret_clears     = 0;
static _Atomic uint64_t g_coins_ticks      = 0;
static _Atomic uint64_t g_coins_skipped    = 0;
static _Atomic uint64_t g_coins_mismatches = 0;
static _Atomic uint64_t g_coins_clears     = 0;
static _Atomic int64_t  g_last_tick_unix   = 0;

static _Atomic uint64_t g_seed_counter = 0;

static const char *g_sa_datadir = NULL; /* process-lifetime string */

#ifdef ZCL_TESTING
struct node_db   *g_state_auditor_test_ndb;
struct main_state *g_state_auditor_test_ms;
sqlite3           *g_state_auditor_test_pdb;
const char        *g_state_auditor_test_datadir;
static _Atomic int64_t g_test_seed = -1;
#endif

/* ── handle resolution (test override, else the live runtime singletons) ── */

static struct node_db *auditor_ndb(void)
{
#ifdef ZCL_TESTING
    if (g_state_auditor_test_ndb) return g_state_auditor_test_ndb;
#endif
    return app_runtime_node_db();
}

static struct main_state *auditor_ms(void)
{
#ifdef ZCL_TESTING
    if (g_state_auditor_test_ms) return g_state_auditor_test_ms;
#endif
    return app_runtime_main_state();
}

static sqlite3 *auditor_pdb(void)
{
#ifdef ZCL_TESTING
    if (g_state_auditor_test_pdb) return g_state_auditor_test_pdb;
#endif
    return progress_store_db();
}

static const char *auditor_datadir(void)
{
#ifdef ZCL_TESTING
    if (g_state_auditor_test_datadir) return g_state_auditor_test_datadir;
#endif
    /* Bodies are written under the NET-SPECIFIC datadir (GetDataDir(true);
     * see reducer_ingest_service.c) — resolve the same directory for reads.
     * Byte-identical to g_sa_datadir on mainnet (base==net-specific). */
    static char net_dir[2048];
    GetDataDir(true, net_dir, sizeof(net_dir));
    return net_dir[0] ? net_dir : g_sa_datadir;
}

void state_auditor_set_datadir(const char *datadir)
{
    g_sa_datadir = datadir;
}

const char *state_auditor_leg_name(enum state_auditor_leg leg)
{
    switch (leg) {
    case STATE_AUDITOR_LEG_OP_RETURN_INDEX:  return "op_return_index";
    case STATE_AUDITOR_LEG_COINS_COMMITMENT: return "coins_commitment";
    default: return "unknown";
    }
}

/* ── deterministic per-tick seeding ──────────────────────────────────── */

static uint64_t next_seed(void)
{
#ifdef ZCL_TESTING
    int64_t forced = atomic_load(&g_test_seed);
    if (forced >= 0) return (uint64_t)forced;
#endif
    return atomic_fetch_add(&g_seed_counter, 1);
}

/* disambiguator lets both legs draw an independent-looking window from the
 * SAME per-tick seed without cross-correlating their picks. */
static void seed_hash(uint64_t seed, uint8_t disambiguator, uint8_t out[32])
{
    uint8_t buf[9];
    for (int i = 0; i < 8; i++) buf[i] = (uint8_t)(seed >> (8 * i));
    buf[8] = disambiguator;
    zcl_sha3_256(buf, sizeof(buf), out);
}

/* ── op_return_index leg: pure per-window check ─────────────────────── */

static int opret_row_cmp(const void *a, const void *b)
{
    const struct op_return_index_row *ra = a;
    const struct op_return_index_row *rb = b;
    int c = memcmp(ra->txid, rb->txid, 32);
    if (c != 0) return c;
    if (ra->vout_n < rb->vout_n) return -1; // raw-return-ok:qsort-comparator
    if (ra->vout_n > rb->vout_n) return 1;  // raw-return-ok:qsort-comparator
    return 0;
}

/* Re-extract every OP_RETURN output at each height in [h_start,h_end] from
 * the on-disk block body and compare a window-local (zero-IV) fold of that
 * fresh extraction against the SAME fold over the rows actually stored in
 * op_return_index for that height. Bounded to (h_end-h_start+1) block reads;
 * SKIPPED (never a false MISMATCH) on any unreadable body or a pathological
 * per-block row count. */
static enum audit_tick_result
opret_check_window(struct node_db *ndb, struct main_state *ms,
                   const char *datadir, int32_t h_start, int32_t h_end,
                   char *detail, size_t detail_cap)
{
    for (int32_t h = h_start; h <= h_end; h++) {
        struct block_index *bi = active_chain_at(&ms->chain_active, h);
        if (!bi || !bi->phashBlock ||
            !(block_index_status_load(bi) & BLOCK_HAVE_DATA))
            return AUDIT_TICK_SKIPPED;

        struct block blk;
        block_init(&blk);
        if (!read_block_from_disk_index_pread(&blk, bi, datadir)) {
            block_free(&blk);
            return AUDIT_TICK_SKIPPED;
        }

        struct op_return_index_row extracted[STATE_AUDITOR_OPRET_ROW_CAP];
        size_t n_extracted = 0;
        for (size_t ti = 0; ti < blk.num_vtx; ti++) {
            const struct transaction *tx = &blk.vtx[ti];
            for (size_t vo = 0; vo < tx->num_vout; vo++) {
                const struct tx_out *o = &tx->vout[vo];
                const uint8_t *script = o->script_pub_key.data;
                size_t slen = o->script_pub_key.size;
                if (slen == 0 || script[0] != 0x6a) continue;

                struct op_return_index_row row;
                if (!op_return_index_extract(script, slen, &row)) continue;
                memcpy(row.txid, tx->hash.data, 32);
                row.vout_n = (uint32_t)vo;
                row.height = h;
                if (n_extracted < STATE_AUDITOR_OPRET_ROW_CAP)
                    extracted[n_extracted] = row;
                n_extracted++;
            }
        }
        block_free(&blk);

        if (n_extracted > STATE_AUDITOR_OPRET_ROW_CAP)
            return AUDIT_TICK_SKIPPED; /* pathological block — never false-flag */

        qsort(extracted, n_extracted, sizeof(extracted[0]), opret_row_cmp);

        struct op_return_index_row stored[STATE_AUDITOR_OPRET_ROW_CAP];
        int n_stored = op_return_index_query(ndb, h, h, NULL, stored,
                                             STATE_AUDITOR_OPRET_ROW_CAP);
        if (n_stored < 0) return AUDIT_TICK_SKIPPED;

        /* Per-height A/B comparison, not a chain continuation: both sides use
         * the SAME zero base and zero prev, so the only thing that can differ
         * is the row set. The catalog's real declared base is irrelevant here
         * and deliberately not read. */
        uint8_t zero_iv[32] = {0};
        uint8_t digest_extracted[32], digest_stored[32];
        op_return_index_fold_block_digest(0, zero_iv, zero_iv, h,
                                          bi->phashBlock->data,
                                          extracted, n_extracted,
                                          digest_extracted);
        op_return_index_fold_block_digest(0, zero_iv, zero_iv, h,
                                          bi->phashBlock->data,
                                          stored, (size_t)n_stored,
                                          digest_stored);

        if (memcmp(digest_extracted, digest_stored, 32) != 0) {
            char dex[65] = {0}, dst[65] = {0};
            HexStr(digest_extracted, 32, false, dex, sizeof(dex));
            HexStr(digest_stored, 32, false, dst, sizeof(dst));
            snprintf(detail, detail_cap,
                     "height=%d stored_rows=%d extracted_rows=%zu "
                     "digest_stored=%s digest_extracted=%s",
                     h, n_stored, n_extracted, dst, dex);
            return AUDIT_TICK_MISMATCH;
        }
    }
    return AUDIT_TICK_CLEAN;
}

static void opret_leg_tick(struct node_db *ndb, struct main_state *ms,
                           const char *datadir, uint64_t seed)
{
    if (!ndb || !ndb->open || !ms || !datadir || !datadir[0]) {
        atomic_fetch_add(&g_opret_skipped, 1);
        return;
    }
    atomic_fetch_add(&g_opret_ticks, 1);

    struct op_return_index_cursor oc;
    if (!op_return_index_get_cursor(ndb, &oc)) {
        atomic_fetch_add(&g_opret_skipped, 1);
        return;
    }
    int32_t cursor = oc.height;
    /* The catalog covers [base, cursor], not [0, cursor], on a snapshot-seeded
     * datadir. Auditing a height below the declared base would compare stored
     * rows the catalog never claimed to hold against extracted rows and report
     * a false mismatch. */
    int32_t base = oc.base_height > 0 ? oc.base_height : 0;

    int32_t h_start, h_end;
    if (atomic_load(&g_opret_leg.investigating)) {
        h_start = atomic_load(&g_opret_leg.pinned_h_start);
        h_end = atomic_load(&g_opret_leg.pinned_h_end);
        if (h_end > cursor) h_end = cursor;
        if (h_start < base || h_start > h_end) {
            /* The folded prefix shrank under us (should not happen —
             * op_return_index_truncate resets to -1, not a partial rewind).
             * Drop the investigation defensively rather than check a
             * degenerate range. */
            atomic_store(&g_opret_leg.investigating, false);
            atomic_store(&g_opret_leg.confirm_streak, 0);
            atomic_fetch_add(&g_opret_skipped, 1);
            return;
        }
    } else {
        const int32_t w = STATE_AUDITOR_OPRET_WINDOW_BLOCKS;
        if (cursor - base + 1 < w) {
            atomic_fetch_add(&g_opret_skipped, 1);
            return; /* not enough folded history yet */
        }
        uint8_t sh[32];
        seed_hash(seed, 0, sh);
        uint64_t r;
        memcpy(&r, sh, sizeof(r));
        int32_t max_start = cursor - w + 1;
        h_start = base + (int32_t)(r % (uint64_t)((int64_t)max_start -
                                                  (int64_t)base + 1));
        h_end = h_start + w - 1;
    }

    char detail[192] = {0};
    enum audit_tick_result res =
        opret_check_window(ndb, ms, datadir, h_start, h_end, detail,
                           sizeof(detail));

    if (res == AUDIT_TICK_SKIPPED) {
        atomic_fetch_add(&g_opret_skipped, 1);
        return; /* leave any pinned investigation as-is for the next tick */
    }

    if (res == AUDIT_TICK_CLEAN) {
        bool was_latched = atomic_exchange(&g_opret_leg.latched, false);
        atomic_store(&g_opret_leg.confirm_streak, 0);
        atomic_store(&g_opret_leg.investigating, false);
        if (was_latched) {
            atomic_fetch_add(&g_opret_clears, 1);
            LOG_INFO("state_auditor",
                     "[state-auditor] op_return_index window [%d,%d] "
                     "cleared by a re-check", h_start, h_end);
        }
        return;
    }

    /* AUDIT_TICK_MISMATCH */
    atomic_store(&g_opret_leg.pinned_h_start, h_start);
    atomic_store(&g_opret_leg.pinned_h_end, h_end);
    atomic_store(&g_opret_leg.investigating, true);
    pthread_mutex_lock(&g_opret_leg.detail_lock);
    snprintf(g_opret_leg.detail, sizeof(g_opret_leg.detail), "%s", detail);
    pthread_mutex_unlock(&g_opret_leg.detail_lock);

    int streak = atomic_fetch_add(&g_opret_leg.confirm_streak, 1) + 1;
    if (streak >= STATE_AUDITOR_CONFIRM_STREAK) {
        bool was_latched = atomic_exchange(&g_opret_leg.latched, true);
        if (!was_latched) {
            atomic_fetch_add(&g_opret_mismatches, 1);
            LOG_WARN("state_auditor",
                     "[state-auditor] CONFIRMED op_return_index mismatch "
                     "[%d,%d]: %s", h_start, h_end, detail);
        }
    } else {
        LOG_WARN("state_auditor",
                 "[state-auditor] op_return_index candidate mismatch "
                 "[%d,%d] (streak=%d): %s — awaiting confirmation",
                 h_start, h_end, streak, detail);
    }
}

/* ── coins_commitment leg: pure per-window check ────────────────────── */

/* One keyspace-window cross-check between the coins_kv authority and the
 * utxos projection. SKIPPED (never a false MISMATCH) whenever the two
 * sources are not provably reflecting the same instant: bulk-fold mode
 * active, the reducer holds the trylock, the applied-height markers
 * disagree (legitimate catch-up lag/lead), or either marker moved between
 * the two independent scans (torn read). */
static enum audit_tick_result
coins_check_window(sqlite3 *pdb, struct node_db *ndb,
                   const uint8_t txid_lo[32],
                   int32_t *out_h_min, int32_t *out_h_max,
                   char *detail, size_t detail_cap)
{
    *out_h_min = -1;
    *out_h_max = -1;
    if (!pdb || !ndb || !ndb->open) return AUDIT_TICK_SKIPPED;

    uint64_t mirror_generation0 = 0;
    if (!utxo_mirror_sync_audit_snapshot(&mirror_generation0))
        return AUDIT_TICK_SKIPPED;

    /* Bulk-fold mode: the durable `coins` table legitimately lags the live
     * RAM overlay — a raw SQL read of it is stale by design, not evidence
     * of corruption. */
    if (coins_ram_active()) return AUDIT_TICK_SKIPPED;

    int32_t auth_h0 = -1;
    bool afound0 = false;
    if (!progress_store_tx_trylock()) return AUDIT_TICK_SKIPPED;
    (void)coins_kv_get_applied_height(pdb, &auth_h0, &afound0);
    progress_store_tx_unlock();
    int64_t proj_h0 = -1;
    bool pfound0 = node_db_state_get_int(ndb, UTXO_MIRROR_SYNC_CURSOR_KEY,
                                         &proj_h0);
    if (!afound0 || !pfound0 || (int64_t)auth_h0 != proj_h0)
        return AUDIT_TICK_SKIPPED; /* catch-up lag/lead — not comparable */

    struct utxo_commitment auth_uc, proj_uc;
    size_t auth_rows = 0, proj_rows = 0;
    int32_t auth_min = INT32_MAX, auth_max = INT32_MIN;
    int32_t proj_min = INT32_MAX, proj_max = INT32_MIN;
    uint8_t auth_last[32], proj_last[32];
    if (!utxo_commitment_compute_range(pdb, "coins", txid_lo,
                                       STATE_AUDITOR_COINS_WINDOW_ROWS,
                                       &auth_uc, &auth_rows, &auth_min,
                                       &auth_max, auth_last))
        return AUDIT_TICK_SKIPPED;
    if (!utxo_commitment_compute_range(ndb->db, "utxos", txid_lo,
                                       STATE_AUDITOR_COINS_WINDOW_ROWS,
                                       &proj_uc, &proj_rows, &proj_min,
                                       &proj_max, proj_last))
        return AUDIT_TICK_SKIPPED;

    int32_t auth_h1 = -1;
    bool afound1 = false;
    if (!progress_store_tx_trylock()) return AUDIT_TICK_SKIPPED;
    (void)coins_kv_get_applied_height(pdb, &auth_h1, &afound1);
    progress_store_tx_unlock();
    int64_t proj_h1 = -1;
    bool pfound1 = node_db_state_get_int(ndb, UTXO_MIRROR_SYNC_CURSOR_KEY,
                                         &proj_h1);
    if (!afound1 || !pfound1 || auth_h1 != auth_h0 || proj_h1 != proj_h0)
        return AUDIT_TICK_SKIPPED; /* the set moved mid-window — torn scan */

    uint64_t mirror_generation1 = 0;
    if (!utxo_mirror_sync_audit_snapshot(&mirror_generation1) ||
        mirror_generation1 != mirror_generation0)
        return AUDIT_TICK_SKIPPED; /* mirror transaction overlapped the scan */

    if (auth_rows > 0) { *out_h_min = auth_min; *out_h_max = auth_max; }
    if (proj_rows > 0) {
        if (*out_h_min < 0 || proj_min < *out_h_min) *out_h_min = proj_min;
        if (proj_max > *out_h_max) *out_h_max = proj_max;
    }

    if (utxo_commitment_equal(&auth_uc, &proj_uc))
        return AUDIT_TICK_CLEAN;

    char txid_hex[65] = {0};
    HexStr(txid_lo, 32, false, txid_hex, sizeof(txid_hex));
    snprintf(detail, detail_cap,
             "keyspace_window txid_lo=%s rows(auth=%zu proj=%zu) "
             "heights=[%d,%d]", txid_hex, auth_rows, proj_rows,
             *out_h_min, *out_h_max);
    return AUDIT_TICK_MISMATCH;
}

static void coins_leg_tick(sqlite3 *pdb, struct node_db *ndb, uint64_t seed)
{
    atomic_fetch_add(&g_coins_ticks, 1);

    uint8_t txid_lo[32];
    if (atomic_load(&g_coins_leg.investigating)) {
        pthread_mutex_lock(&g_coins_leg.lock);
        memcpy(txid_lo, g_coins_leg.pinned_txid_lo, 32);
        pthread_mutex_unlock(&g_coins_leg.lock);
    } else {
        seed_hash(seed, 1, txid_lo);
    }

    int32_t h_min = -1, h_max = -1;
    char detail[192] = {0};
    enum audit_tick_result res =
        coins_check_window(pdb, ndb, txid_lo, &h_min, &h_max, detail,
                           sizeof(detail));

    if (res == AUDIT_TICK_SKIPPED) {
        atomic_fetch_add(&g_coins_skipped, 1);
        return;
    }

    if (res == AUDIT_TICK_CLEAN) {
        bool was_latched = atomic_exchange(&g_coins_leg.latched, false);
        atomic_store(&g_coins_leg.confirm_streak, 0);
        atomic_store(&g_coins_leg.investigating, false);
        if (was_latched) {
            atomic_fetch_add(&g_coins_clears, 1);
            LOG_INFO("state_auditor",
                     "[state-auditor] coins_commitment window cleared by a "
                     "re-check");
        }
        return;
    }

    /* AUDIT_TICK_MISMATCH */
    pthread_mutex_lock(&g_coins_leg.lock);
    memcpy(g_coins_leg.pinned_txid_lo, txid_lo, 32);
    snprintf(g_coins_leg.detail, sizeof(g_coins_leg.detail), "%s", detail);
    pthread_mutex_unlock(&g_coins_leg.lock);
    atomic_store(&g_coins_leg.last_h_min, h_min);
    atomic_store(&g_coins_leg.last_h_max, h_max);
    atomic_store(&g_coins_leg.investigating, true);

    int streak = atomic_fetch_add(&g_coins_leg.confirm_streak, 1) + 1;
    if (streak >= STATE_AUDITOR_CONFIRM_STREAK) {
        bool was_latched = atomic_exchange(&g_coins_leg.latched, true);
        if (!was_latched) {
            atomic_fetch_add(&g_coins_mismatches, 1);
            LOG_WARN("state_auditor",
                     "[state-auditor] CONFIRMED coins_commitment mismatch: "
                     "%s", detail);
        }
    } else {
        LOG_WARN("state_auditor",
                 "[state-auditor] coins_commitment candidate mismatch "
                 "(streak=%d): %s — awaiting confirmation", streak, detail);
    }
}

/* ── public tick + snapshot API ──────────────────────────────────────── */

void state_auditor_tick_once(void)
{
    struct node_db *ndb = auditor_ndb();
    struct main_state *ms = auditor_ms();
    const char *datadir = auditor_datadir();
    sqlite3 *pdb = auditor_pdb();

    atomic_store(&g_last_tick_unix, platform_time_wall_unix());

    uint64_t seed = next_seed();
    opret_leg_tick(ndb, ms, datadir, seed);
    coins_leg_tick(pdb, ndb, seed);
}

bool state_auditor_get_mismatch(enum state_auditor_leg leg,
                                struct state_auditor_mismatch_info *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));

    if (leg == STATE_AUDITOR_LEG_OP_RETURN_INDEX) {
        out->latched = atomic_load(&g_opret_leg.latched);
        out->h_start = atomic_load(&g_opret_leg.pinned_h_start);
        out->h_end = atomic_load(&g_opret_leg.pinned_h_end);
        pthread_mutex_lock(&g_opret_leg.detail_lock);
        snprintf(out->detail, sizeof(out->detail), "%s", g_opret_leg.detail);
        pthread_mutex_unlock(&g_opret_leg.detail_lock);
        return true;
    }
    if (leg == STATE_AUDITOR_LEG_COINS_COMMITMENT) {
        out->latched = atomic_load(&g_coins_leg.latched);
        out->h_start = atomic_load(&g_coins_leg.last_h_min);
        out->h_end = atomic_load(&g_coins_leg.last_h_max);
        pthread_mutex_lock(&g_coins_leg.lock);
        snprintf(out->detail, sizeof(out->detail), "%s", g_coins_leg.detail);
        pthread_mutex_unlock(&g_coins_leg.lock);
        return true;
    }
    return false;
}

/* ── supervisor child ────────────────────────────────────────────────── */

static struct liveness_contract g_sa_contract;
static _Atomic supervisor_child_id g_sa_id = SUPERVISOR_INVALID_ID;
static _Atomic int64_t g_sa_ticks = 0;

static void sa_tick(struct liveness_contract *c)
{
    (void)c;
    state_auditor_tick_once();
    int64_t marker = atomic_fetch_add(&g_sa_ticks, 1) + 1;
    supervisor_progress(atomic_load(&g_sa_id), marker);
    supervisor_tick(atomic_load(&g_sa_id));
}

void state_auditor_register(void)
{
    supervisor_domains_init();
    if (atomic_load(&g_sa_id) != SUPERVISOR_INVALID_ID)
        return;
    liveness_contract_init(&g_sa_contract, "chain.state_auditor");
    atomic_store(&g_sa_contract.period_secs, (int64_t)STATE_AUDITOR_PERIOD_SECS);
    atomic_store(&g_sa_contract.deadline_secs, (int64_t)0);
    atomic_store(&g_sa_contract.progress_max_quiet_us, (int64_t)0);
    g_sa_contract.on_tick = sa_tick;
    g_sa_contract.on_stall = NULL;
    supervisor_child_id id =
        supervisor_register_in_domain(g_chain_sup, &g_sa_contract);
    atomic_store(&g_sa_id, id);
    if (id == SUPERVISOR_INVALID_ID)
        LOG_WARN("state_auditor", "[state-auditor] supervisor register failed");
}

/* ── diagnostics ─────────────────────────────────────────────────────── */

bool state_auditor_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    json_push_kv_int(out, "last_tick_unix",
                     (int64_t)atomic_load(&g_last_tick_unix));
    json_push_kv_int(out, "opret_ticks_total",
                     (int64_t)atomic_load(&g_opret_ticks));
    json_push_kv_int(out, "opret_skipped_total",
                     (int64_t)atomic_load(&g_opret_skipped));
    json_push_kv_int(out, "opret_mismatches_total",
                     (int64_t)atomic_load(&g_opret_mismatches));
    json_push_kv_int(out, "opret_clears_total",
                     (int64_t)atomic_load(&g_opret_clears));
    json_push_kv_bool(out, "opret_latched", atomic_load(&g_opret_leg.latched));
    json_push_kv_int(out, "opret_h_start",
                     (int64_t)atomic_load(&g_opret_leg.pinned_h_start));
    json_push_kv_int(out, "opret_h_end",
                     (int64_t)atomic_load(&g_opret_leg.pinned_h_end));

    json_push_kv_int(out, "coins_ticks_total",
                     (int64_t)atomic_load(&g_coins_ticks));
    json_push_kv_int(out, "coins_skipped_total",
                     (int64_t)atomic_load(&g_coins_skipped));
    json_push_kv_int(out, "coins_mismatches_total",
                     (int64_t)atomic_load(&g_coins_mismatches));
    json_push_kv_int(out, "coins_clears_total",
                     (int64_t)atomic_load(&g_coins_clears));
    json_push_kv_bool(out, "coins_latched", atomic_load(&g_coins_leg.latched));
    json_push_kv_int(out, "coins_h_min",
                     (int64_t)atomic_load(&g_coins_leg.last_h_min));
    json_push_kv_int(out, "coins_h_max",
                     (int64_t)atomic_load(&g_coins_leg.last_h_max));

    return true;
}

/* ── test hooks ──────────────────────────────────────────────────────── */

#ifdef ZCL_TESTING
void state_auditor_reset_for_test(void)
{
    atomic_store(&g_opret_ticks, 0);
    atomic_store(&g_opret_skipped, 0);
    atomic_store(&g_opret_mismatches, 0);
    atomic_store(&g_opret_clears, 0);
    atomic_store(&g_opret_leg.latched, false);
    atomic_store(&g_opret_leg.investigating, false);
    atomic_store(&g_opret_leg.confirm_streak, 0);
    atomic_store(&g_opret_leg.pinned_h_start, 0);
    atomic_store(&g_opret_leg.pinned_h_end, 0);
    pthread_mutex_lock(&g_opret_leg.detail_lock);
    g_opret_leg.detail[0] = '\0';
    pthread_mutex_unlock(&g_opret_leg.detail_lock);

    atomic_store(&g_coins_ticks, 0);
    atomic_store(&g_coins_skipped, 0);
    atomic_store(&g_coins_mismatches, 0);
    atomic_store(&g_coins_clears, 0);
    atomic_store(&g_coins_leg.latched, false);
    atomic_store(&g_coins_leg.investigating, false);
    atomic_store(&g_coins_leg.confirm_streak, 0);
    atomic_store(&g_coins_leg.last_h_min, -1);
    atomic_store(&g_coins_leg.last_h_max, -1);
    pthread_mutex_lock(&g_coins_leg.lock);
    memset(g_coins_leg.pinned_txid_lo, 0, 32);
    g_coins_leg.detail[0] = '\0';
    pthread_mutex_unlock(&g_coins_leg.lock);

    atomic_store(&g_seed_counter, 0);
    atomic_store(&g_test_seed, -1);
}

void state_auditor_set_test_seed(int64_t seed_or_negative_for_auto)
{
    atomic_store(&g_test_seed, seed_or_negative_for_auto);
}

void state_auditor_force_latch_for_test(enum state_auditor_leg leg,
                                        int32_t h_start, int32_t h_end,
                                        const char *detail)
{
    if (leg == STATE_AUDITOR_LEG_OP_RETURN_INDEX) {
        atomic_store(&g_opret_leg.pinned_h_start, h_start);
        atomic_store(&g_opret_leg.pinned_h_end, h_end);
        pthread_mutex_lock(&g_opret_leg.detail_lock);
        snprintf(g_opret_leg.detail, sizeof(g_opret_leg.detail), "%s",
                detail ? detail : "");
        pthread_mutex_unlock(&g_opret_leg.detail_lock);
        atomic_store(&g_opret_leg.investigating, true);
        atomic_store(&g_opret_leg.confirm_streak, STATE_AUDITOR_CONFIRM_STREAK);
        atomic_store(&g_opret_leg.latched, true);
    } else if (leg == STATE_AUDITOR_LEG_COINS_COMMITMENT) {
        atomic_store(&g_coins_leg.last_h_min, h_start);
        atomic_store(&g_coins_leg.last_h_max, h_end);
        pthread_mutex_lock(&g_coins_leg.lock);
        snprintf(g_coins_leg.detail, sizeof(g_coins_leg.detail), "%s",
                detail ? detail : "");
        pthread_mutex_unlock(&g_coins_leg.lock);
        atomic_store(&g_coins_leg.investigating, true);
        atomic_store(&g_coins_leg.confirm_streak, STATE_AUDITOR_CONFIRM_STREAK);
        atomic_store(&g_coins_leg.latched, true);
    }
}

void state_auditor_force_clear_for_test(enum state_auditor_leg leg)
{
    if (leg == STATE_AUDITOR_LEG_OP_RETURN_INDEX) {
        atomic_store(&g_opret_leg.latched, false);
        atomic_store(&g_opret_leg.investigating, false);
        atomic_store(&g_opret_leg.confirm_streak, 0);
    } else if (leg == STATE_AUDITOR_LEG_COINS_COMMITMENT) {
        atomic_store(&g_coins_leg.latched, false);
        atomic_store(&g_coins_leg.investigating, false);
        atomic_store(&g_coins_leg.confirm_streak, 0);
    }
}

uint64_t state_auditor_test_op_return_ticks(void)
{
    return atomic_load(&g_opret_ticks);
}

uint64_t state_auditor_test_coins_ticks(void)
{
    return atomic_load(&g_coins_ticks);
}
#endif
