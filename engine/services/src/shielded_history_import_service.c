/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * shielded_history_import_service — implementation. See the header for the
 * contract (completeness + atomicity are the whole point).
 *
 * The four chainstate iterators stream into anchor_kv / nullifier_kv inside ONE
 * BEGIN IMMEDIATE. Any anomaly aborts the whole transaction (rollback), so a
 * partial set can never flip a cursor to zero.
 *
 * one-result-type-ok:owner-gated-boot-import — this is a one-shot owner-gated
 * boot/import entry point (like the --importblockindex / node_db_import boot
 * modes), not a runtime saga step. Its public signature is deliberately
 * `bool + struct shielded_import_report` per the design spec
 * (docs/work/shielded-history-importer.md §4.4): the failure reason
 * travels with the failure via node.log [shielded_import] (every refusal path
 * LOG_FAIL/LOG_RETURNs the exact anomaly) AND via the per-pool report the
 * caller inspects; there is no zcl_result-returning runtime surface to thread. */
// one-result-type-ok:owner-gated-boot-import

#include "services/shielded_history_import_service.h"
#include "services/utxo_recovery_service.h"

#include "core/serialize.h"
#include "jobs/reducer_frontier.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/chainstate_legacy_reader.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include "utxo_recovery_internal.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SHI_SUBSYS "shielded_import"
#define SHI_PROVENANCE_KEY SHIELDED_IMPORT_PROVENANCE_KEY

/* Emit a node.log progress line every this-many rows. Chosen so a real import
 * (millions of records) logs a few times/second, turning the historically
 * silent multi-minute scan into a growing, named cursor. */
#define SHI_PROGRESS_LOG_INTERVAL 50000

/* ── never-silent progress (see the header) ──────────────────────────────────
 * Lock-free counters a concurrent dumpstate reader observes. Written only by
 * the single importer thread; read by any thread via the snapshot getter. */
static _Atomic bool         g_shi_active         = false;
static _Atomic int          g_shi_phase          = SHI_PHASE_IDLE;
static _Atomic int_least64_t g_shi_anchors       = 0;
static _Atomic int_least64_t g_shi_nullifiers    = 0;
static _Atomic int_least64_t g_shi_start_ms      = 0;
static _Atomic int_least64_t g_shi_last_elapsed  = 0;

bool shielded_history_import_progress_snapshot(struct shi_progress *out)
{
    if (!out)
        LOG_RETURN(false, SHI_SUBSYS, "progress_snapshot: NULL out");
    bool active = atomic_load_explicit(&g_shi_active, memory_order_acquire);
    out->active = active;
    out->phase = atomic_load_explicit(&g_shi_phase, memory_order_relaxed);
    out->anchors_done =
        atomic_load_explicit(&g_shi_anchors, memory_order_relaxed);
    out->nullifiers_done =
        atomic_load_explicit(&g_shi_nullifiers, memory_order_relaxed);
    if (active) {
        int64_t start =
            atomic_load_explicit(&g_shi_start_ms, memory_order_relaxed);
        out->elapsed_ms = start ? platform_time_monotonic_ms() - start : 0;
    } else {
        out->elapsed_ms =
            atomic_load_explicit(&g_shi_last_elapsed, memory_order_relaxed);
    }
    return true;
}

static int64_t shi_elapsed_ms(void)
{
    int64_t start = atomic_load_explicit(&g_shi_start_ms, memory_order_relaxed);
    return start ? platform_time_monotonic_ms() - start : 0;
}

static void shi_progress_begin(void)
{
    atomic_store_explicit(&g_shi_anchors, 0, memory_order_relaxed);
    atomic_store_explicit(&g_shi_nullifiers, 0, memory_order_relaxed);
    atomic_store_explicit(&g_shi_start_ms, platform_time_monotonic_ms(),
                          memory_order_relaxed);
    atomic_store_explicit(&g_shi_phase, SHI_PHASE_SNAPSHOT,
                          memory_order_relaxed);
    atomic_store_explicit(&g_shi_active, true, memory_order_release);
}

static void shi_progress_phase(int phase)
{
    atomic_store_explicit(&g_shi_phase, phase, memory_order_relaxed);
}

/* Mark the import over (success OR rollback). Freezes elapsed and clears active
 * so a reader stops treating stale counters as a live run. Idempotent. */
static void shi_progress_end(void)
{
    atomic_store_explicit(&g_shi_last_elapsed, shi_elapsed_ms(),
                          memory_order_relaxed);
    atomic_store_explicit(&g_shi_phase, SHI_PHASE_DONE, memory_order_relaxed);
    atomic_store_explicit(&g_shi_active, false, memory_order_release);
}

/* Streaming callback context — shared by the anchor + nullifier iterators. */
struct shi_ctx {
    sqlite3 *db;
    bool ok;                 /* set false on the first store failure */
    int pool;                /* ANCHOR_POOL_* / NULLIFIER_POOL_* for this pass */

    /* Height assignment: the best/tip anchor takes `tip_height` so
     * anchor_kv_latest_tree (ORDER BY height DESC) always returns the frontier
     * to append to; every other historical anchor takes a monotone
     * import-order height strictly below it (their exact block height is not
     * consensus-load-bearing — only presence + the tip frontier are). */
    int64_t tip_height;
    int64_t next_seq;        /* monotone import-order counter for non-tip rows */
    struct uint256 best_root;
    bool best_present;       /* is there a best-anchor pointer for this pool? */
    bool saw_best;           /* did we import a row equal to best_root? */

    int64_t nf_sentinel;     /* height stamped on imported nullifiers */
    int64_t count;

    /* Perf: the inlined reused-statement insert path. The canonical writer
     * anchor_kv_add_tree re-prepares a statement per row AND recomputes
     * incremental_tree_root — a full frontier Pedersen re-hash. Combined with the
     * bulk reader (which also no longer recomputes per anchor), the historical
     * scan pays ZERO per-anchor Pedersen work: each row is keyed on the anchor's
     * own key-root (leveldb block-CRC + a successful deserialize are the
     * byte-integrity floor), reusing ONE prepared statement + ONE serialize
     * buffer per pass. Historical anchor tree contents are not
     * consensus-load-bearing (ZClassic headers commit none of them); only
     * PRESENCE + the TIP FRONTIER are, and the tip frontier IS Pedersen-verified
     * once in shi_anchor_cb against the header-committed root. */
    sqlite3_stmt *ins;         /* reused INSERT stmt for this pass */
    struct byte_stream bs;     /* reused serialize buffer (anchor passes only) */
    struct uint256 empty_root; /* precomputed per-pool empty frontier root */
};

/* Count one streamed anchor toward the live progress + periodic node.log line. */
static void shi_count_anchor(const struct shi_ctx *c)
{
    int64_t n = atomic_fetch_add_explicit(&g_shi_anchors, 1,
                                          memory_order_relaxed) + 1;
    if (n % SHI_PROGRESS_LOG_INTERVAL == 0)
        LOG_INFO(SHI_SUBSYS,
                 "shielded import progress: phase=scan_anchors pool=%d "
                 "anchors=%lld nullifiers=%lld elapsed_ms=%lld",
                 c->pool, (long long)n,
                 (long long)atomic_load_explicit(&g_shi_nullifiers,
                                                 memory_order_relaxed),
                 (long long)shi_elapsed_ms());
}

static void shi_count_nullifier(const struct shi_ctx *c)
{
    int64_t m = atomic_fetch_add_explicit(&g_shi_nullifiers, 1,
                                          memory_order_relaxed) + 1;
    if (m % SHI_PROGRESS_LOG_INTERVAL == 0)
        LOG_INFO(SHI_SUBSYS,
                 "shielded import progress: phase=scan_nullifiers pool=%d "
                 "anchors=%lld nullifiers=%lld elapsed_ms=%lld",
                 c->pool,
                 (long long)atomic_load_explicit(&g_shi_anchors,
                                                 memory_order_relaxed),
                 (long long)m, (long long)shi_elapsed_ms());
}

static bool shi_anchor_cb(const struct uint256 *root,
                          const struct incremental_merkle_tree *tree,
                          void *vctx)
{
    struct shi_ctx *c = vctx;
    if (!c || !c->ok)
        return false;

    int64_t height = c->next_seq++;
    if (c->best_present && uint256_eq(root, &c->best_root)) {
        height = c->tip_height;
        c->saw_best = true;
        /* Tip-frontier consensus check — with the bulk reader path (no per-anchor
         * recompute), this is the ONE Pedersen root recompute the import keeps,
         * guarded to the best/tip anchor (O(1) per pool). The tip anchor's tree
         * MUST hash to best_root; for Sapling, best_root was already verified ==
         * the header-committed hashFinalSaplingRoot at the tip-bind, so this
         * binds the imported frontier tree to the header. A torn/forged frontier
         * is refused, rolling back the whole transaction. */
        struct uint256 tip_computed;
        incremental_tree_root(tree, &tip_computed);
        if (!uint256_eq(&tip_computed, &c->best_root)) {
            c->ok = false;
            LOG_RETURN(false, SHI_SUBSYS,
                       "tip frontier tree does not hash to committed root "
                       "pool=%d — refusing (torn/forged frontier)", c->pool);
        }
    }

    /* The protocol-implicit empty frontier is never persisted as a spendable
     * anchor row (anchor_kv_add_tree treats it as a no-op success, matching
     * zclassicd). A 32-byte compare against the precomputed empty root — NOT a
     * re-hash — reproduces that skip while still counting the record. */
    if (uint256_eq(root, &c->empty_root)) {
        c->count++;
        shi_count_anchor(c);
        return true;
    }

    /* Reuse the buffer: reset the cursor, keep the allocation (no per-row
     * malloc). */
    c->bs.size = 0;
    c->bs.read_pos = 0;
    c->bs.error = false;
    if (!incremental_tree_serialize(tree, &c->bs) || c->bs.error) {
        c->ok = false;
        LOG_RETURN(false, SHI_SUBSYS,
                   "anchor serialize failed pool=%d height=%lld",
                   c->pool, (long long)height);
    }

    sqlite3_stmt *s = c->ins;
    /* Key on the anchor's own key-root directly (see the shi_ctx comment): the
     * bulk reader delivers it byte-integrity-checked (leveldb block-CRC +
     * deserialize), and re-hashing every historical anchor here is the
     * intractable cost we are removing. The tip frontier was verified above. */
    bool bound =
        sqlite3_bind_blob(s, 1, root->data, 32, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_int64(s, 2, (sqlite3_int64)height) == SQLITE_OK &&
        sqlite3_bind_blob(s, 3, c->bs.data, (int)c->bs.size, SQLITE_STATIC)
            == SQLITE_OK;
    if (!bound) {
        c->ok = false;
        sqlite3_reset(s);
        LOG_RETURN(false, SHI_SUBSYS, "anchor bind failed pool=%d: %s",
                   c->pool, sqlite3_errmsg(c->db));
    }
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_reset(s);
    if (rc != SQLITE_DONE) {
        c->ok = false;
        LOG_RETURN(false, SHI_SUBSYS, "anchor step rc=%d pool=%d: %s",
                   rc, c->pool, sqlite3_errmsg(c->db));
    }
    c->count++;
    shi_count_anchor(c);
    return true;
}

static bool shi_nullifier_cb(const uint8_t nf[32], void *vctx)
{
    struct shi_ctx *c = vctx;
    if (!c || !c->ok)
        return false;
    sqlite3_stmt *s = c->ins;
    bool bound =
        sqlite3_bind_blob(s, 1, nf, 32, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_int(s, 2, c->pool) == SQLITE_OK &&
        sqlite3_bind_int64(s, 3, (sqlite3_int64)c->nf_sentinel) == SQLITE_OK;
    if (!bound) {
        c->ok = false;
        sqlite3_reset(s);
        LOG_RETURN(false, SHI_SUBSYS, "nullifier bind failed pool=%d: %s",
                   c->pool, sqlite3_errmsg(c->db));
    }
    int rc = sqlite3_step(s);  // raw-sql-ok:progress-kv-kernel-store
    sqlite3_reset(s);
    if (rc != SQLITE_DONE) {
        c->ok = false;
        LOG_RETURN(false, SHI_SUBSYS, "nullifier step rc=%d pool=%d: %s",
                   rc, c->pool, sqlite3_errmsg(c->db));
    }
    c->count++;
    shi_count_nullifier(c);
    return true;
}

/* Prepare the reused INSERT for `pool`'s anchor table. NULL on prepare error. */
static sqlite3_stmt *shi_prepare_anchor_insert(sqlite3 *db, int pool)
{
    const char *table =
        pool == ANCHOR_POOL_SPROUT ? "sprout_anchors" : "sapling_anchors";
    char sql[128];
    int n = snprintf(sql, sizeof(sql),
                     "INSERT OR IGNORE INTO %s(anchor,height,tree) "
                     "VALUES(?,?,?)", table);
    if (n <= 0 || (size_t)n >= sizeof(sql))
        return NULL;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN(SHI_SUBSYS, "anchor insert prepare failed pool=%d: %s",
                 pool, sqlite3_errmsg(db));
        return NULL;
    }
    return s;
}

static sqlite3_stmt *shi_prepare_nullifier_insert(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO nullifiers(nf,pool,height) VALUES(?,?,?)",
            -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN(SHI_SUBSYS, "nullifier insert prepare failed: %s",
                 sqlite3_errmsg(db));
        return NULL;
    }
    return s;
}

static void shi_pool_empty_root(int pool, struct uint256 *out)
{
    struct incremental_merkle_tree empty;
    if (pool == ANCHOR_POOL_SPROUT)
        sprout_tree_init(&empty);
    else
        sapling_tree_init(&empty);
    incremental_tree_root(&empty, out);
}

/* Run ONE complete anchor pass over `pool` with the inlined reused-statement
 * insert. On return the statement is finalized and the buffer freed. Returns
 * the delivered count (>=0) on success, -1 on ANY anomaly (a completeness
 * consumer must treat -1 as "roll back everything"). *count_out and
 * *saw_best_out are always set. */
static int64_t shi_run_anchor_pass(sqlite3 *db, void *h, int pool,
                                   bool best_present,
                                   const struct uint256 *best_root,
                                   int64_t tip_height, int64_t *count_out,
                                   bool *saw_best_out)
{
    struct shi_ctx c = {
        .db = db, .ok = true, .pool = pool, .tip_height = tip_height,
        .next_seq = 0, .best_present = best_present,
    };
    if (best_present)
        c.best_root = *best_root;
    shi_pool_empty_root(pool, &c.empty_root);
    c.ins = shi_prepare_anchor_insert(db, pool);
    if (!c.ins) {
        *count_out = 0;
        *saw_best_out = false;
        LOG_RETURN(-1, SHI_SUBSYS,
                   "anchor pass: insert prepare failed pool=%d", pool);
    }
    stream_init(&c.bs, 2048);

    /* Bulk iterators: byte-integrity floor (leveldb block-CRC + deserialize +
     * no trailing bytes) WITHOUT the per-anchor Pedersen root recompute — that
     * O(anchors × Pedersen) cost was the multi-minute silent scan. The tip
     * frontier is Pedersen-verified once in shi_anchor_cb against best_root. */
    int64_t n = (pool == ANCHOR_POOL_SPROUT)
        ? chainstate_legacy_iter_sprout_anchors_bulk(h, shi_anchor_cb, &c)
        : chainstate_legacy_iter_sapling_anchors_bulk(h, shi_anchor_cb, &c);

    sqlite3_finalize(c.ins);
    stream_free(&c.bs);
    *count_out = c.count;
    *saw_best_out = c.saw_best;
    return (n < 0 || !c.ok) ? -1 : n;
}

/* Run ONE complete nullifier pass over `pool`. Statement finalized on return.
 * Returns the delivered count (>=0), or -1 on any anomaly. */
static int64_t shi_run_nullifier_pass(sqlite3 *db, void *h, int pool,
                                      int64_t nf_sentinel, int64_t *count_out)
{
    struct shi_ctx c = {
        .db = db, .ok = true, .pool = pool, .nf_sentinel = nf_sentinel,
    };
    c.ins = shi_prepare_nullifier_insert(db);
    if (!c.ins) {
        *count_out = 0;
        LOG_RETURN(-1, SHI_SUBSYS,
                   "nullifier pass: insert prepare failed pool=%d", pool);
    }
    int64_t n = (pool == NULLIFIER_POOL_SPROUT)
        ? chainstate_legacy_iter_sprout_nullifiers(h, shi_nullifier_cb, &c)
        : chainstate_legacy_iter_sapling_nullifiers(h, shi_nullifier_cb, &c);
    sqlite3_finalize(c.ins);
    *count_out = c.count;
    return (n < 0 || !c.ok) ? -1 : n;
}

/* Read the three durable cursors, requiring both anchor pools share one
 * positive boundary and the nullifier marker be positive. Returns:
 *   1  -> proceed (anchor_boundary/nullifier_boundary filled, both positive)
 *   0  -> all three already zero (already complete; nothing to import)
 *  -1  -> anomaly (missing/negative/mixed) — caller must refuse */
static int shi_read_boundaries(sqlite3 *db, int64_t *anchor_boundary,
                               int64_t *nullifier_boundary)
{
    int64_t spr = -1, sap = -1, nf = -1;
    bool spr_f = false, sap_f = false, nf_f = false;
    if (!anchor_kv_activation_cursor(db, ANCHOR_POOL_SPROUT, &spr, &spr_f) ||
        !anchor_kv_activation_cursor(db, ANCHOR_POOL_SAPLING, &sap, &sap_f) ||
        !nullifier_kv_activation_cursor(db, &nf, &nf_f))
        LOG_RETURN(-1, SHI_SUBSYS, "cursor read failed");
    if (!spr_f || !sap_f || !nf_f)
        LOG_RETURN(-1, SHI_SUBSYS,
                   "cursor(s) absent spr=%d sap=%d nf=%d — history coverage "
                   "unknown; refusing", spr_f, sap_f, nf_f);
    if (spr == 0 && sap == 0 && nf == 0)
        return 0; /* already complete — not an error */
    if (spr <= 0 || sap <= 0 || nf <= 0)
        LOG_RETURN(-1, SHI_SUBSYS,
                   "cursor(s) not uniformly positive spr=%lld sap=%lld "
                   "nf=%lld — refusing (mixed/complete state)",
                   (long long)spr, (long long)sap, (long long)nf);
    if (spr != sap)
        LOG_RETURN(-1, SHI_SUBSYS,
                   "anchor pools disagree on boundary spr=%lld sap=%lld — "
                   "refusing", (long long)spr, (long long)sap);
    *anchor_boundary = sap;
    *nullifier_boundary = nf;
    return 1;
}

static void shi_rollback(sqlite3 *db)
{
    (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
    shi_progress_end();
}

static bool shi_write_provenance(sqlite3 *db, const struct uint256 *best_block,
                                 const struct shielded_import_report *r)
{
    char best_hex[65];
    uint256_get_hex(best_block, best_hex);
    char buf[320];
    int n = snprintf(buf, sizeof(buf),
                     "source=zclassicd_chainstate;best_block=%s;tip_h=%lld;"
                     "sapling_anchors=%lld;sprout_anchors=%lld;"
                     "sapling_nf=%lld;sprout_nf=%lld;tip_anchor_bound=%d;"
                     "self_folded=false",
                     best_hex, (long long)r->anchor_boundary - 1,
                     (long long)r->sapling_anchors,
                     (long long)r->sprout_anchors,
                     (long long)r->sapling_nullifiers,
                     (long long)r->sprout_nullifiers,
                     r->tip_anchor_bound ? 1 : 0);
    if (n <= 0 || (size_t)n >= sizeof(buf))
        LOG_FAIL(SHI_SUBSYS, "provenance format failed");
    if (!progress_meta_set_in_tx(db, SHI_PROVENANCE_KEY, buf, (size_t)n))
        LOG_FAIL(SHI_SUBSYS, "provenance write failed");
    return true;
}

bool shielded_history_import_from_chainstate(
    sqlite3 *progress_db, const char *chainstate_src_path,
    int64_t expected_tip_height, const struct uint256 *expected_tip_block_hash,
    const struct uint256 *expected_tip_sapling_root,
    struct shielded_import_report *out)
{
    struct shielded_import_report report = {0};
    if (out)
        *out = report;

    if (!progress_db || !chainstate_src_path || !expected_tip_block_hash ||
        !expected_tip_sapling_root || expected_tip_height < 0)
        LOG_FAIL(SHI_SUBSYS, "invalid args");

    /* Fork-safety, defense-in-depth: an all-zero expected root means the caller
     * failed to obtain the header-committed hashFinalSaplingRoot (e.g. reading a
     * blocks.sapling_root projection column that a header import left null). The
     * tip is far past Sapling activation, so its frontier root can never be
     * zero. Binding the imported frontier against zeros — then flipping the
     * activation cursors — would convert the SAFE wedge into an ACCEPT of an
     * unverified frontier. Refuse before touching the transaction. */
    if (uint256_is_null(expected_tip_sapling_root))
        LOG_FAIL(SHI_SUBSYS,
                 "expected tip Sapling root is all-zero — caller did not "
                 "obtain the header-committed hashFinalSaplingRoot; refusing to "
                 "bind the tip frontier against zeros (wedge left intact)");

    if (!anchor_kv_ensure_schema(progress_db) ||
        !nullifier_kv_ensure_schema(progress_db) ||
        !progress_meta_table_ensure(progress_db))
        LOG_FAIL(SHI_SUBSYS, "schema ensure failed");

    int64_t anchor_boundary = 0, nullifier_boundary = 0;
    int br = shi_read_boundaries(progress_db, &anchor_boundary,
                                 &nullifier_boundary);
    if (br < 0)
        return false;
    if (br == 0) {
        LOG_INFO(SHI_SUBSYS,
                 "cursors already zero — shielded history complete, nothing "
                 "to import");
        if (out) {
            out->committed = false;
            out->tip_anchor_bound = true;
        }
        return true;
    }
    report.anchor_boundary = anchor_boundary;
    report.nullifier_boundary = nullifier_boundary;

    /* Bind-height guard (fail-closed, pre-transaction): refuse to key the
     * frontier at a height that is not the target's fold-resume anchor. See
     * the header — a height-mismatched bind converts the safe wedge into a
     * deterministic consensus-time livelock. The predicate lives in
     * shielded_history_import_bind_guard.c, shared with the verb. */
    if (!shielded_history_import_bind_guard_probe(progress_db,
                                                  expected_tip_height, NULL))
        return false;  // raw-return-ok:refusal already logged inside the bind guard probe (height mismatch or derive error)

    /* Heavy work begins — arm the never-silent progress surface. Every failure
     * path below (pre-tx refusals AND in-tx rollbacks) calls shi_progress_end();
     * shi_rollback() does it for the transactional paths. */
    shi_progress_begin();

    /* Open the (already point-in-time / fixture) chainstate copy. */
    void *h = NULL;
    if (!chainstate_legacy_open(chainstate_src_path, &h) || !h) {
        shi_progress_end();
        LOG_FAIL(SHI_SUBSYS, "chainstate_legacy_open(%s) failed",
                 chainstate_src_path);
    }

    struct uint256 best_block;
    uint256_set_null(&best_block);
    if (!chainstate_legacy_get_best_block(h, &best_block)) {
        chainstate_legacy_close(h);
        shi_progress_end();
        LOG_FAIL(SHI_SUBSYS,
                 "source best-block bind FAILED: chainstate has no readable "
                 "best-block pointer; refusing before import");
    }
    if (!uint256_eq(&best_block, expected_tip_block_hash)) {
        char source_hex[65], target_hex[65];
        uint256_get_hex(&best_block, source_hex);
        uint256_get_hex(expected_tip_block_hash, target_hex);
        chainstate_legacy_close(h);
        shi_progress_end();
        LOG_FAIL(SHI_SUBSYS,
                 "source best-block bind FAILED: source=%s target=%s at "
                 "resume_h=%lld — importing an additive nullifier set from "
                 "above/below the target makes forward spends look already "
                 "spent; refusing before transaction",
                 source_hex, target_hex, (long long)expected_tip_height);
    }

    /* The chain-committed tip bind (§3), keyed on OUR expected root — never
     * the source's own 'z' best-anchor pointer. The pointer only reflects
     * what the source last flushed and races the WAL frontier on a live
     * daemon (a fresh flush between the target's UTXO seed and this import
     * moves it past the fold-resume anchor), so a pointer-derived bind can
     * key the frontier at a height the fold cannot use. The bind that is
     * actually load-bearing is: the anchor RECORD for the expected root
     * (the PoW-committed hashFinalSaplingRoot at the target's fold-resume
     * anchor, supplied by the caller) exists, and its tree Pedersen-hashes
     * to that root. A torn/forged frontier fails closed here, before the
     * import transaction opens. */
    struct incremental_merkle_tree tip_tree;
    enum chainstate_anchor_result tip_ar = chainstate_legacy_get_sapling_anchor(
        h, expected_tip_sapling_root, &tip_tree);
    if (tip_ar != CHAINSTATE_ANCHOR_FOUND) {
        chainstate_legacy_close(h);
        shi_progress_end();
        LOG_FAIL(SHI_SUBSYS,
                 "tip bind FAILED: chainstate has no Sapling anchor record "
                 "for the fold-resume root at h=%lld (result=%d) — the "
                 "source does not cover the target's resume point (stale "
                 "snapshot or reorg); refusing",
                 (long long)expected_tip_height, (int)tip_ar);
    }
    struct uint256 tip_recomputed;
    incremental_tree_root(&tip_tree, &tip_recomputed);
    if (!uint256_eq(&tip_recomputed, expected_tip_sapling_root)) {
        chainstate_legacy_close(h);
        shi_progress_end();
        LOG_FAIL(SHI_SUBSYS,
                 "tip bind FAILED: anchor tree for the fold-resume root at "
                 "h=%lld does not hash to the header-committed "
                 "hashFinalSaplingRoot — torn/forged frontier, refusing",
                 (long long)expected_tip_height);
    }
    /* The bulk pass keys the row matching best_root at tip_height and
     * Pedersen-verifies it a second time; feeding it the expected root keeps
     * the saw_best completeness assert on exactly the frontier we bound. */
    const struct uint256 best_sapling = *expected_tip_sapling_root;
    report.tip_anchor_bound = true;

    struct uint256 best_sprout;
    bool sprout_best_present =
        chainstate_legacy_get_best_sprout_anchor(h, &best_sprout);

    /* ── the ONE atomic transaction ── */
    progress_store_tx_lock();
    char *err = NULL;
    if (sqlite3_exec(progress_db, "BEGIN IMMEDIATE", NULL, NULL, &err)
            != SQLITE_OK) {
        LOG_WARN(SHI_SUBSYS, "BEGIN IMMEDIATE failed: %s",
                 err ? err : sqlite3_errmsg(progress_db));
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        chainstate_legacy_close(h);
        shi_progress_end();
        return false;
    }
    if (err) { sqlite3_free(err); err = NULL; }

    int64_t nf_sentinel = anchor_boundary - 1; /* highest historical height */

    /* ── anchors (Sapling then Sprout) ── */
    shi_progress_phase(SHI_PHASE_SCAN_ANCHORS);

    int64_t sap_count = 0;
    bool sap_saw_best = false;
    int64_t n = shi_run_anchor_pass(progress_db, h, ANCHOR_POOL_SAPLING, true,
                                    &best_sapling, expected_tip_height,
                                    &sap_count, &sap_saw_best);
    if (n < 0 || !sap_saw_best) {
        shi_rollback(progress_db);
        chainstate_legacy_close(h);
        LOG_FAIL(SHI_SUBSYS,
                 "Sapling anchor import incomplete n=%lld saw_tip=%d — "
                 "rolled back", (long long)n, sap_saw_best);
    }
    report.sapling_anchors = sap_count;

    /* Sprout anchors (best may be absent — a drained/empty pool). */
    int64_t spr_count = 0;
    bool spr_saw_best = false;
    n = shi_run_anchor_pass(progress_db, h, ANCHOR_POOL_SPROUT,
                            sprout_best_present, &best_sprout,
                            expected_tip_height, &spr_count, &spr_saw_best);
    if (n < 0 || (sprout_best_present && !spr_saw_best)) {
        shi_rollback(progress_db);
        chainstate_legacy_close(h);
        LOG_FAIL(SHI_SUBSYS,
                 "Sprout anchor import incomplete n=%lld best=%d saw_best=%d — "
                 "rolled back", (long long)n, sprout_best_present,
                 spr_saw_best);
    }
    report.sprout_anchors = spr_count;

    /* ── nullifiers (Sapling then Sprout) ── */
    shi_progress_phase(SHI_PHASE_SCAN_NULLIFIERS);

    int64_t snf_count = 0;
    n = shi_run_nullifier_pass(progress_db, h, NULLIFIER_POOL_SAPLING,
                               nf_sentinel, &snf_count);
    if (n < 0) {
        shi_rollback(progress_db);
        chainstate_legacy_close(h);
        LOG_FAIL(SHI_SUBSYS, "Sapling nullifier import failed n=%lld — "
                             "rolled back", (long long)n);
    }
    report.sapling_nullifiers = snf_count;

    int64_t pnf_count = 0;
    n = shi_run_nullifier_pass(progress_db, h, NULLIFIER_POOL_SPROUT,
                               nf_sentinel, &pnf_count);
    if (n < 0) {
        shi_rollback(progress_db);
        chainstate_legacy_close(h);
        LOG_FAIL(SHI_SUBSYS, "Sprout nullifier import failed n=%lld — "
                             "rolled back", (long long)n);
    }
    report.sprout_nullifiers = pnf_count;

    /* We are done reading the chainstate; close it before the flip so a torn
     * source cannot silently reopen. */
    chainstate_legacy_close(h);
    h = NULL;

    /* Flip BOTH activation cursors to zero — only now, after the COMPLETE set
     * is staged in this transaction and the tip was bound. */
    shi_progress_phase(SHI_PHASE_BIND);
    if (!anchor_kv_publish_full_replay_complete_in_tx(progress_db,
                                                      anchor_boundary) ||
        !nullifier_kv_publish_full_replay_complete_in_tx(progress_db,
                                                         nullifier_boundary) ||
        !shielded_history_cancel_full_replay_in_tx(progress_db)) {
        shi_rollback(progress_db);
        LOG_FAIL(SHI_SUBSYS, "cursor publish failed — rolled back");
    }

    if (!shi_write_provenance(progress_db, &best_block, &report)) {
        shi_rollback(progress_db);
        LOG_FAIL(SHI_SUBSYS, "provenance failed — rolled back");
    }

    shi_progress_phase(SHI_PHASE_COMMIT);
    if (sqlite3_exec(progress_db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN(SHI_SUBSYS, "COMMIT failed: %s",
                 err ? err : sqlite3_errmsg(progress_db));
        if (err) sqlite3_free(err);
        shi_rollback(progress_db);
        return false;
    }
    if (err) sqlite3_free(err);
    progress_store_tx_unlock();
    shi_progress_end();

    report.committed = true;

    /* Both cursors are now durably zero: refresh the two permanent blockers so
     * the reducer resumes folding from the wedge height + 1. */
    utxo_apply_anchor_gap_blocker_refresh(progress_db);
    utxo_apply_nullifier_gap_blocker_refresh(progress_db);

    LOG_INFO(SHI_SUBSYS,
             "IMPORT COMPLETE: sapling_anchors=%lld sprout_anchors=%lld "
             "sapling_nf=%lld sprout_nf=%lld boundary=%lld — both cursors flipped "
             "to 0, shielded history published",
             (long long)report.sapling_anchors,
             (long long)report.sprout_anchors,
             (long long)report.sapling_nullifiers,
             (long long)report.sprout_nullifiers,
             (long long)anchor_boundary);

    if (out)
        *out = report;
    return true;
}

bool shielded_history_import_register_cured_tip_trust_anchor(
    sqlite3 *progress_db, struct node_db *ndb)
{
    if (!progress_db || !ndb)
        LOG_RETURN(false, SHI_SUBSYS,
                   "cured-tip trust anchor: null args (progress_db=%p ndb=%p)",
                   (void *)progress_db, (void *)ndb);

    /* Derive the cured coins tip authoritatively from progress.kv's own
     * co-committed state: height = coins_applied_height - 1, hash = the
     * validate_headers_log own-hash at that height (the Invariant A trust
     * root). This is the import's OWN header-committed value, never a peer's. */
    int32_t h = -1;
    uint8_t hash[32];
    bool hash_found = false, found = false;
    if (!reducer_frontier_derive_coins_best(progress_db, &h, hash,
                                            &hash_found, &found))
        LOG_RETURN(false, SHI_SUBSYS,
                   "cured-tip trust anchor: coins-best derive failed "
                   "(progress.kv read error)");
    if (!found)
        LOG_RETURN(false, SHI_SUBSYS,
                   "cured-tip trust anchor: coins-best not derivable "
                   "(coins_applied_height absent / not proven-authority) — "
                   "leaving the coins tip un-anchored");
    if (h <= 0)
        LOG_RETURN(false, SHI_SUBSYS,
                   "cured-tip trust anchor: coins-best height non-positive "
                   "(h=%d)", h);
    if (!hash_found)
        LOG_RETURN(false, SHI_SUBSYS,
                   "cured-tip trust anchor: coins-best hash not resolvable "
                   "from validate_headers_log at h=%d — refusing to register a "
                   "heightless trust anchor", h);

    struct uint256 tip_hash;
    memcpy(tip_hash.data, hash, 32);

    /* In-memory: effective THIS process (the copy-prove harness / unit test
     * drive the Invariant A install without a reboot). */
    utxo_recovery_set_cold_import_trust_anchor(&tip_hash, h);

    /* Durable: the boot restore path (utxo_recovery_restore.c) re-reads these
     * node_db seed keys every boot and re-registers the anchor, so the coins
     * tip installs on the next NORMAL boot after the owner-gated import exits.
     * The count is the seed's cross-check PROVENANCE token — the coins_kv row
     * count the restore consumer verifies against the live store; the shielded
     * import never touches coins_kv, so it stays consistent. */
    int64_t utxo_count = coins_kv_count(progress_db);
    if (utxo_count <= 0)
        LOG_RETURN(false, SHI_SUBSYS,
                   "cured-tip trust anchor: coins_kv empty (count=%lld) — "
                   "cannot write the durable seed provenance token; the "
                   "in-memory anchor is registered for this process only",
                   (long long)utxo_count);
    utxo_recovery_write_cold_import_seed(ndb, (int)h, &tip_hash, utxo_count);

    char hex[65];
    uint256_get_hex(&tip_hash, hex);
    LOG_INFO(SHI_SUBSYS,
             "cured-tip trust anchor registered: h=%d hash=%s "
             "(in-memory + durable node_db seed, utxo_count=%lld) — Invariant A "
             "will install the coins tip into the active chain so getheaders is "
             "built from the real tip, not genesis",
             h, hex, (long long)utxo_count);
    return true;
}
