/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * shielded_history_promote_service — implementation. See the header for the
 * contract (the six gates + all-or-nothing atomicity are the whole point).
 *
 * Modeled on shielded_history_import_service.c (single BEGIN IMMEDIATE,
 * progress_store_tx_lock ordering, provenance write, gap-blocker refresh at the
 * end) but the SOURCE is a finished producer's progress.kv instead of a
 * zclassicd chainstate LevelDB: it is opened as a DEDICATED read-only SQLite
 * connection (SQLITE_OPEN_READONLY + PRAGMA query_only), which lets the existing
 * verified anchor_kv/nullifier_kv cursor readers run against it verbatim for G1
 * and is strictly stronger on read-only-ness than an ATTACH into the writable
 * target connection could be (query_only is connection-wide; the target must
 * write). The producer path is validated (-COPY- marker) by the verb before this
 * runs.
 *
 * one-result-type-ok:owner-gated-boot-import — this is a one-shot owner-gated
 * offline promote verb (like -ratify-mint-anchor / -import-complete-shielded),
 * not a runtime saga step. Its public signature is deliberately
 * `bool + struct shielded_promote_report`: the refusal reason travels via
 * node.log [shielded_promote] (every refusal path LOG_FAIL/LOG_RETURNs the exact
 * anomaly) AND via the report the caller inspects; there is no zcl_result runtime
 * surface to thread. */
// one-result-type-ok:owner-gated-boot-import

#include "services/shielded_history_promote_service.h"

#include "services/shielded_history_body_crosscheck.h"

#include "chain/chain.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/consensus_db.h"    /* consensus_db_kernel_store_path */
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <limits.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PROMOTE_SUBSYS "shielded_promote"

/* ── crosscheck test seam ──
 * Default (NULL) resolves to the REAL symbol linked in production. Only tests
 * set this; production never does. */
static shielded_promote_crosscheck_fn g_crosscheck_fn = NULL;

void shielded_history_promote_set_crosscheck_for_test(
    shielded_promote_crosscheck_fn fn)
{
    g_crosscheck_fn = fn;
}

void shielded_history_promote_reset_crosscheck_for_test(void)
{
    g_crosscheck_fn = NULL;
}

static bool promote_run_crosscheck(const char *copy_datadir,
                                   const char *producer_datadir,
                                   int64_t checkpoint_height,
                                   struct crosscheck_result *out)
{
    if (g_crosscheck_fn)
        return g_crosscheck_fn(copy_datadir, producer_datadir,
                               checkpoint_height, out);
    return shielded_history_body_crosscheck_run(copy_datadir, producer_datadir,
                                                checkpoint_height, out);
}

/* ── small helpers ── */

static void promote_rollback(struct sqlite3 *db)
{
    (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
}

/* Read the three target cursors, requiring both anchor pools share one positive
 * boundary and the nullifier marker be positive. Returns:
 *   1  -> proceed (anchor_boundary/nullifier_boundary filled, both positive)
 *   0  -> all three already zero (already complete; nothing to promote)
 *  -1  -> anomaly (missing/negative/mixed) — caller must refuse */
static int promote_read_target_boundaries(struct sqlite3 *db,
                                          int64_t *anchor_boundary,
                                          int64_t *nullifier_boundary)
{
    int64_t spr = -1, sap = -1, nf = -1;
    bool spr_f = false, sap_f = false, nf_f = false;
    if (!anchor_kv_activation_cursor(db, ANCHOR_POOL_SPROUT, &spr, &spr_f) ||
        !anchor_kv_activation_cursor(db, ANCHOR_POOL_SAPLING, &sap, &sap_f) ||
        !nullifier_kv_activation_cursor(db, &nf, &nf_f))
        LOG_RETURN(-1, PROMOTE_SUBSYS, "target cursor read failed");
    if (!spr_f || !sap_f || !nf_f)
        LOG_RETURN(-1, PROMOTE_SUBSYS,
                   "target cursor(s) absent spr=%d sap=%d nf=%d — coverage "
                   "unknown; refusing", spr_f, sap_f, nf_f);
    if (spr == 0 && sap == 0 && nf == 0)
        return 0; /* already complete — not an error */
    if (spr <= 0 || sap <= 0 || nf <= 0)
        LOG_RETURN(-1, PROMOTE_SUBSYS,
                   "target cursor(s) not uniformly positive spr=%lld sap=%lld "
                   "nf=%lld — refusing", (long long)spr, (long long)sap,
                   (long long)nf);
    if (spr != sap)
        LOG_RETURN(-1, PROMOTE_SUBSYS,
                   "target anchor pools disagree on boundary spr=%lld sap=%lld "
                   "— refusing", (long long)spr, (long long)sap);
    *anchor_boundary = sap;
    *nullifier_boundary = nf;
    return 1;
}

/* G1: a finished from-genesis producer has activation_cursor == 0 for both
 * anchor pools AND the nullifier marker == 0. */
static bool promote_check_producer_g1(struct sqlite3 *src)
{
    int64_t spr = -1, sap = -1, nf = -1;
    bool spr_f = false, sap_f = false, nf_f = false;
    if (!anchor_kv_activation_cursor(src, ANCHOR_POOL_SPROUT, &spr, &spr_f) ||
        !anchor_kv_activation_cursor(src, ANCHOR_POOL_SAPLING, &sap, &sap_f) ||
        !nullifier_kv_activation_cursor(src, &nf, &nf_f))
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "G1: producer cursor read failed — refusing");
    if (!spr_f || !sap_f || !nf_f || spr != 0 || sap != 0 || nf != 0)
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "G1: producer is NOT a finished from-genesis store "
                   "(spr=%lld/%d sap=%lld/%d nf=%lld/%d, want 0/1 each) — "
                   "refusing", (long long)spr, spr_f, (long long)sap, sap_f,
                   (long long)nf, nf_f);
    return true;
}

/* COUNT(*) over one producer table. Returns false on store error. */
static bool promote_count(struct sqlite3 *src, const char *sql, int64_t *out)
{
    *out = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(src, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_RETURN(false, PROMOTE_SUBSYS, "producer count prepare failed: %s",
                   sqlite3_errmsg(src));
    bool ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:read-only-probe
    if (rc == SQLITE_ROW)
        *out = sqlite3_column_int64(st, 0);
    else {
        ok = false;
        LOG_WARN(PROMOTE_SUBSYS, "producer count step rc=%d: %s", rc,
                 sqlite3_errmsg(src));
    }
    sqlite3_finalize(st);
    return ok;
}

/* G5 preflight: MAX(height) over one producer table must be <= checkpoint.
 * An empty table yields SQL NULL (max = -1 here), which passes. srcdb is a
 * static read-only file, so this bound holds for the whole install. */
static bool promote_g5_max_height_ok(struct sqlite3 *src, const char *table,
                                     int64_t checkpoint_height)
{
    char sql[96];
    int n = snprintf(sql, sizeof(sql), "SELECT MAX(height) FROM %s", table);
    if (n <= 0 || (size_t)n >= sizeof(sql))
        LOG_RETURN(false, PROMOTE_SUBSYS, "G5: sql overflow for %s", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(src, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_RETURN(false, PROMOTE_SUBSYS, "G5: prepare failed %s: %s", table,
                   sqlite3_errmsg(src));
    int64_t maxh = -1;
    bool ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:read-only-probe
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) != SQLITE_NULL)
            maxh = sqlite3_column_int64(st, 0);
    } else {
        ok = false;
        LOG_WARN(PROMOTE_SUBSYS, "G5: step rc=%d for %s", rc, table);
    }
    sqlite3_finalize(st);
    if (!ok)
        return false;
    if (maxh > checkpoint_height)
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "G5: producer %s has a row at height %lld > checkpoint %lld "
                   "— refusing (out-of-bound producer state)", table,
                   (long long)maxh, (long long)checkpoint_height);
    return true;
}

/* Checked deserialize of a stored frontier blob into a pool-typed tree. */
static bool promote_load_tree(int pool, const void *blob, int blob_len,
                              struct incremental_merkle_tree *out)
{
    if (!blob || blob_len <= 0)
        return false;
    if (pool == ANCHOR_POOL_SPROUT)
        sprout_tree_init(out);
    else
        sapling_tree_init(out);
    struct byte_stream bs;
    stream_init_from_data(&bs, (const unsigned char *)blob, (size_t)blob_len);
    bool ok = incremental_tree_deserialize(out, &bs) &&
              stream_remaining(&bs) == 0;
    return ok;
}

/* header-committed hashFinalSaplingRoot at `height` from the in-RAM block index
 * (NOT node.db blocks.sapling_root). false when the height is out of range or
 * the block index does not carry it. */
static bool promote_header_root_at(struct block_index *tip, int64_t height,
                                   struct uint256 *out)
{
    if (!tip || height < 0 || height > INT_MAX)
        return false;
    struct block_index *bi = block_index_get_ancestor(tip, (int)height);
    if (!bi || bi->nHeight != (int)height)
        return false;
    *out = bi->hashFinalSaplingRoot;
    return true;
}

/* G2: install every producer Sapling frontier, binding each row's recomputed
 * root to the header-committed hashFinalSaplingRoot at that height. */
static bool promote_install_sapling(struct sqlite3 *target, struct sqlite3 *src,
                                    struct block_index *header_tip,
                                    int64_t *installed_out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(src,
            "SELECT height,tree FROM sapling_anchors ORDER BY height",
            -1, &st, NULL) != SQLITE_OK)
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "G2: producer sapling select prepare failed: %s",
                   sqlite3_errmsg(src));
    int64_t installed = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {  // raw-sql-ok:read-only-probe
        int64_t height = sqlite3_column_int64(st, 0);
        const void *tblob = sqlite3_column_blob(st, 1);
        int tlen = sqlite3_column_bytes(st, 1);
        struct incremental_merkle_tree tree;
        struct uint256 expected;
        if (!promote_load_tree(ANCHOR_POOL_SAPLING, tblob, tlen, &tree)) {
            ok = false;
            LOG_WARN(PROMOTE_SUBSYS, "G2: sapling tree decode failed h=%lld",
                     (long long)height);
            break;
        }
        if (!promote_header_root_at(header_tip, height, &expected)) {
            ok = false;
            LOG_WARN(PROMOTE_SUBSYS,
                     "G2: no in-RAM header at h=%lld for sapling bind — refusing",
                     (long long)height);
            break;
        }
        if (uint256_is_null(&expected)) {
            ok = false;
            LOG_WARN(PROMOTE_SUBSYS,
                     "G2: header sapling root is null at h=%lld (above "
                     "activation) — corrupt/unimported header, refusing",
                     (long long)height);
            break;
        }
        /* seed_frontier_row recomputes the frontier root and REFUSES on any
         * mismatch vs the header-committed expected root (writes nothing). */
        if (!anchor_kv_seed_frontier_row(target, ANCHOR_POOL_SAPLING, &tree,
                                         height, &expected)) {
            ok = false;
            LOG_WARN(PROMOTE_SUBSYS,
                     "G2: sapling frontier bind FAILED h=%lld (recomputed root "
                     "!= header root) — refusing", (long long)height);
            break;
        }
        installed++;
    }
    if (ok && rc != SQLITE_DONE) {
        ok = false;
        LOG_WARN(PROMOTE_SUBSYS, "G2: sapling iteration rc=%d: %s", rc,
                 sqlite3_errmsg(src));
    }
    sqlite3_finalize(st);
    if (installed_out)
        *installed_out = installed;
    return ok;
}

/* G2b: every distinct header hashFinalSaplingRoot over [activation, boundary)
 * must have a present sapling_anchors row (installed above or pre-existing from
 * the target's own fold). A hole refuses — this is what makes the AC->0 flip
 * safe (anchor_kv.c: at AC>0 a missing root is soft HISTORY_INCOMPLETE; at AC=0
 * it becomes a hard MISSING consensus reject). */
static bool promote_g2b_sapling_complete(struct sqlite3 *target,
                                         struct block_index *header_tip,
                                         int64_t sapling_activation,
                                         int64_t anchor_boundary)
{
    struct incremental_merkle_tree empt;
    struct uint256 prev_root;
    sapling_tree_init(&empt);
    incremental_tree_root(&empt, &prev_root);  /* root below/at activation */
    for (int64_t h = sapling_activation; h < anchor_boundary; h++) {
        struct uint256 rh;
        if (!promote_header_root_at(header_tip, h, &rh))
            LOG_RETURN(false, PROMOTE_SUBSYS,
                       "G2b: no in-RAM header at h=%lld over [%lld,%lld) — "
                       "cannot prove completeness, refusing", (long long)h,
                       (long long)sapling_activation,
                       (long long)anchor_boundary);
        if (uint256_is_null(&rh))
            LOG_RETURN(false, PROMOTE_SUBSYS,
                       "G2b: header sapling root null at h=%lld (above "
                       "activation) — corrupt/unimported header, refusing",
                       (long long)h);
        if (uint256_eq(&rh, &prev_root))
            continue; /* root unchanged — already accounted for */
        enum anchor_kv_lookup_result r =
            anchor_kv_get(target, ANCHOR_POOL_SAPLING, &rh, NULL, NULL);
        if (r != ANCHOR_KV_FOUND)
            LOG_RETURN(false, PROMOTE_SUBSYS,
                       "G2b: HOLE — sapling frontier first appearing at h=%lld "
                       "is absent (lookup=%d) below the flip boundary %lld — "
                       "refusing (a missing below-cursor anchor would become a "
                       "hard consensus reject after the flip)", (long long)h,
                       (int)r, (long long)anchor_boundary);
        prev_root = rh;
    }
    return true;
}

/* G3: install every producer Sprout frontier (gated on a passing crosscheck).
 * Each stored tree is recomputed and must hash back to its stored anchor. */
static bool promote_install_sprout(struct sqlite3 *target, struct sqlite3 *src,
                                   int64_t *installed_out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(src,
            "SELECT anchor,height,tree FROM sprout_anchors ORDER BY height",
            -1, &st, NULL) != SQLITE_OK)
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "G3: producer sprout select prepare failed: %s",
                   sqlite3_errmsg(src));
    int64_t installed = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {  // raw-sql-ok:read-only-probe
        const void *ablob = sqlite3_column_blob(st, 0);
        int alen = sqlite3_column_bytes(st, 0);
        int64_t height = sqlite3_column_int64(st, 1);
        const void *tblob = sqlite3_column_blob(st, 2);
        int tlen = sqlite3_column_bytes(st, 2);
        struct incremental_merkle_tree tree;
        if (!ablob || alen != 32 ||
            !promote_load_tree(ANCHOR_POOL_SPROUT, tblob, tlen, &tree)) {
            ok = false;
            LOG_WARN(PROMOTE_SUBSYS, "G3: sprout row decode failed h=%lld",
                     (long long)height);
            break;
        }
        struct uint256 got, want;
        incremental_tree_root(&tree, &got);
        memcpy(want.data, ablob, 32);
        if (!uint256_eq(&got, &want)) {
            ok = false;
            LOG_WARN(PROMOTE_SUBSYS,
                     "G3: sprout tree/anchor mismatch h=%lld (corrupt producer "
                     "row) — refusing", (long long)height);
            break;
        }
        if (!anchor_kv_add_tree(target, ANCHOR_POOL_SPROUT, &tree, height)) {
            ok = false;
            LOG_WARN(PROMOTE_SUBSYS, "G3: sprout add_tree failed h=%lld",
                     (long long)height);
            break;
        }
        installed++;
    }
    if (ok && rc != SQLITE_DONE) {
        ok = false;
        LOG_WARN(PROMOTE_SUBSYS, "G3: sprout iteration rc=%d: %s", rc,
                 sqlite3_errmsg(src));
    }
    sqlite3_finalize(st);
    if (installed_out)
        *installed_out = installed;
    return ok;
}

/* G4: install every producer nullifier (gated on a passing crosscheck). */
static bool promote_install_nullifiers(struct sqlite3 *target,
                                       struct sqlite3 *src,
                                       int64_t *sapling_out, int64_t *sprout_out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(src, "SELECT nf,pool,height FROM nullifiers",
                           -1, &st, NULL) != SQLITE_OK)
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "G4: producer nullifier select prepare failed: %s",
                   sqlite3_errmsg(src));
    int64_t sap = 0, spr = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {  // raw-sql-ok:read-only-probe
        const void *nfb = sqlite3_column_blob(st, 0);
        int nflen = sqlite3_column_bytes(st, 0);
        int pool = sqlite3_column_int(st, 1);
        int64_t height = sqlite3_column_int64(st, 2);
        if (!nfb || nflen != 32 ||
            (pool != NULLIFIER_POOL_SPROUT && pool != NULLIFIER_POOL_SAPLING)) {
            ok = false;
            LOG_WARN(PROMOTE_SUBSYS,
                     "G4: malformed producer nullifier row (len=%d pool=%d) — "
                     "refusing", nflen, pool);
            break;
        }
        if (!nullifier_kv_add(target, (const uint8_t *)nfb, pool, height)) {
            ok = false;
            LOG_WARN(PROMOTE_SUBSYS, "G4: nullifier_kv_add failed pool=%d", pool);
            break;
        }
        if (pool == NULLIFIER_POOL_SAPLING) sap++; else spr++;
    }
    if (ok && rc != SQLITE_DONE) {
        ok = false;
        LOG_WARN(PROMOTE_SUBSYS, "G4: nullifier iteration rc=%d: %s", rc,
                 sqlite3_errmsg(src));
    }
    sqlite3_finalize(st);
    if (sapling_out) *sapling_out = sap;
    if (sprout_out) *sprout_out = spr;
    return ok;
}

/* G6: flip ALL THREE cursors to zero in the caller's open transaction, via the
 * direct-UPDATE publish primitives (never the delete-then-reset ones). */
static bool promote_flip_cursors(struct sqlite3 *db, int64_t anchor_boundary,
                                 int64_t nullifier_boundary)
{
    if (!anchor_kv_publish_full_replay_complete_in_tx(db, anchor_boundary))
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "G6: anchor cursor flip failed (boundary=%lld)",
                   (long long)anchor_boundary);
    if (!nullifier_kv_publish_full_replay_complete_in_tx(db, nullifier_boundary))
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "G6: nullifier cursor flip failed (boundary=%lld)",
                   (long long)nullifier_boundary);
    if (!shielded_history_cancel_full_replay_in_tx(db))
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "G6: cancel stale replay-session markers failed");
    return true;
}

static bool promote_write_provenance(struct sqlite3 *db,
                                     const char *producer_datadir,
                                     const struct shielded_promote_report *r,
                                     int64_t checkpoint_height)
{
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
                     "source=producer_progress_kv;producer=%s;"
                     "checkpoint_h=%lld;anchor_boundary=%lld;"
                     "sapling_anchors=%lld;sprout_anchors=%lld;"
                     "sapling_nf=%lld;sprout_nf=%lld;self_folded=false",
                     producer_datadir ? producer_datadir : "(null)",
                     (long long)checkpoint_height,
                     (long long)r->anchor_boundary,
                     (long long)r->sapling_anchors_installed,
                     (long long)r->sprout_anchors_installed,
                     (long long)r->sapling_nullifiers_installed,
                     (long long)r->sprout_nullifiers_installed);
    if (n <= 0 || (size_t)n >= sizeof(buf))
        LOG_FAIL(PROMOTE_SUBSYS, "provenance format failed/overflow");
    if (!progress_meta_set_in_tx(db, SHIELDED_PROMOTE_PROVENANCE_KEY, buf,
                                 (size_t)n))
        LOG_FAIL(PROMOTE_SUBSYS, "provenance write failed");
    return true;
}

/* Post-commit: assert all three cursors are durably zero. */
static bool promote_verify_cursors_zero(struct sqlite3 *db)
{
    int64_t spr = -1, sap = -1, nf = -1;
    bool spr_f = false, sap_f = false, nf_f = false;
    if (!anchor_kv_activation_cursor(db, ANCHOR_POOL_SPROUT, &spr, &spr_f) ||
        !anchor_kv_activation_cursor(db, ANCHOR_POOL_SAPLING, &sap, &sap_f) ||
        !nullifier_kv_activation_cursor(db, &nf, &nf_f))
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "post-commit cursor read-back failed");
    if (!spr_f || !sap_f || !nf_f || spr != 0 || sap != 0 || nf != 0)
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "post-commit cursors NOT all zero (spr=%lld sap=%lld "
                   "nf=%lld)", (long long)spr, (long long)sap, (long long)nf);
    return true;
}

bool shielded_history_promote_run(const struct shielded_promote_request *req,
                                  struct shielded_promote_report *out)
{
    struct shielded_promote_report report = {0};
    if (out)
        *out = report;

    if (!req || !req->target_progress_db || !req->producer_datadir ||
        !req->producer_datadir[0] || !req->header_tip ||
        req->sapling_activation_height < 0 || req->checkpoint_height < 0)
        LOG_FAIL(PROMOTE_SUBSYS, "invalid args");

    struct sqlite3 *target = req->target_progress_db;

    if (!anchor_kv_ensure_schema(target) ||
        !nullifier_kv_ensure_schema(target) ||
        !progress_meta_table_ensure(target))
        LOG_FAIL(PROMOTE_SUBSYS, "target schema ensure failed");

    int64_t anchor_boundary = 0, nullifier_boundary = 0;
    int br = promote_read_target_boundaries(target, &anchor_boundary,
                                            &nullifier_boundary);
    if (br < 0)
        return false;
    if (br == 0) {
        LOG_INFO(PROMOTE_SUBSYS,
                 "target cursors already zero — shielded history complete, "
                 "nothing to promote");
        if (out)
            out->committed = false;
        return true;
    }
    report.anchor_boundary = anchor_boundary;
    report.nullifier_boundary = nullifier_boundary;

    /* Open the producer kernel store as a DEDICATED read-only connection. The
     * anchors/nullifiers/stage cursors read below are kernel tables, so this is
     * consensus.db post-flip (or the legacy progress.kv on a pre-flip producer
     * datadir). */
    char src_path[PROGRESS_STORE_PATH_MAX];
    if (!consensus_db_kernel_store_path(req->producer_datadir, src_path,
                                        sizeof(src_path)))
        LOG_FAIL(PROMOTE_SUBSYS, "producer kernel store path overflow");
    struct sqlite3 *src = NULL;
    if (sqlite3_open_v2(src_path, &src,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL)
            != SQLITE_OK || !src) {
        if (src) sqlite3_close(src);
        LOG_FAIL(PROMOTE_SUBSYS, "cannot open producer %s read-only", src_path);
    }
    (void)sqlite3_exec(src, "PRAGMA query_only=ON", NULL, NULL, NULL);

    /* G1: producer must be a finished from-genesis store (all cursors 0). */
    if (!promote_check_producer_g1(src)) {
        sqlite3_close(src);
        return false;
    }

    /* Producer counts (report) + G5 preflight (no row above the checkpoint). */
    if (!promote_count(src, "SELECT COUNT(*) FROM sapling_anchors",
                       &report.producer_sapling_rows) ||
        !promote_count(src, "SELECT COUNT(*) FROM sprout_anchors",
                       &report.producer_sprout_rows) ||
        !promote_count(src,
                       "SELECT COUNT(*) FROM nullifiers WHERE pool=1",
                       &report.producer_sapling_nf) ||
        !promote_count(src,
                       "SELECT COUNT(*) FROM nullifiers WHERE pool=0",
                       &report.producer_sprout_nf)) {
        sqlite3_close(src);
        if (out) *out = report;
        return false;
    }
    if (!promote_g5_max_height_ok(src, "sapling_anchors",
                                  req->checkpoint_height) ||
        !promote_g5_max_height_ok(src, "sprout_anchors",
                                  req->checkpoint_height) ||
        !promote_g5_max_height_ok(src, "nullifiers", req->checkpoint_height)) {
        sqlite3_close(src);
        if (out) *out = report;
        return false;
    }

    /* G3/G4: the local-body cross-check is the trust root for the header-less
     * sprout frontiers + nullifier set. Run it BEFORE the transaction (a heavy
     * independent read of both datadirs); require a full PASS. */
    struct crosscheck_result cc = {0};
    bool cc_ret = promote_run_crosscheck(req->target_copy_datadir,
                                         req->producer_datadir,
                                         req->checkpoint_height, &cc);
    report.sprout_crosscheck_ok = cc_ret && cc.sprout_ok;
    report.nullifiers_crosscheck_ok = cc_ret && cc.nullifiers_ok;
    if (!cc_ret || !cc.sprout_ok || !cc.nullifiers_ok) {
        sqlite3_close(src);
        if (out) *out = report;
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "G3/G4: local-body cross-check did not fully pass "
                   "(ret=%d sprout_ok=%d nullifiers_ok=%d) — refusing sprout + "
                   "nullifier install (wedge intact)", cc_ret, cc.sprout_ok,
                   cc.nullifiers_ok);
    }

    /* ── the ONE atomic transaction ── */
    progress_store_tx_lock();
    char *err = NULL;
    if (sqlite3_exec(target, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN(PROMOTE_SUBSYS, "BEGIN IMMEDIATE failed: %s",
                 err ? err : sqlite3_errmsg(target));
        if (err) sqlite3_free(err);
        progress_store_tx_unlock();
        sqlite3_close(src);
        if (out) *out = report;
        return false;
    }
    if (err) { sqlite3_free(err); err = NULL; }

    /* G2: install + header-bind every producer Sapling frontier. */
    if (!promote_install_sapling(target, src, req->header_tip,
                                 &report.sapling_anchors_installed)) {
        promote_rollback(target);
        sqlite3_close(src);
        if (out) *out = report;
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "G2 sapling install refused — rolled back, wedge intact");
    }

    /* G2b: prove the below-boundary sapling history is now hole-free. */
    if (!promote_g2b_sapling_complete(target, req->header_tip,
                                      req->sapling_activation_height,
                                      anchor_boundary)) {
        promote_rollback(target);
        sqlite3_close(src);
        if (out) *out = report;
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "G2b sapling completeness FAILED — rolled back, wedge "
                   "intact");
    }
    report.sapling_header_complete = true;

    /* G3/G4: install sprout frontiers + nullifiers (crosscheck already passed). */
    if (!promote_install_sprout(target, src,
                                &report.sprout_anchors_installed)) {
        promote_rollback(target);
        sqlite3_close(src);
        if (out) *out = report;
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "G3 sprout install refused — rolled back, wedge intact");
    }
    if (!promote_install_nullifiers(target, src,
                                    &report.sapling_nullifiers_installed,
                                    &report.sprout_nullifiers_installed)) {
        promote_rollback(target);
        sqlite3_close(src);
        if (out) *out = report;
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "G4 nullifier install refused — rolled back, wedge intact");
    }

    /* We are done reading the producer; close it before the flip. */
    sqlite3_close(src);
    src = NULL;

    /* G6: flip ALL THREE cursors, then stamp provenance. */
    if (!promote_flip_cursors(target, anchor_boundary, nullifier_boundary) ||
        !promote_write_provenance(target, req->producer_datadir, &report,
                                  req->checkpoint_height)) {
        promote_rollback(target);
        if (out) *out = report;
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "cursor flip / provenance failed — rolled back, wedge "
                   "intact");
    }

    if (sqlite3_exec(target, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN(PROMOTE_SUBSYS, "COMMIT failed: %s",
                 err ? err : sqlite3_errmsg(target));
        if (err) sqlite3_free(err);
        promote_rollback(target);
        if (out) *out = report;
        return false;
    }
    if (err) sqlite3_free(err);
    progress_store_tx_unlock();

    /* Post-commit: verify the durable cursors are all zero, then refresh the two
     * permanent gap blockers so the reducer resumes folding. */
    if (!promote_verify_cursors_zero(target)) {
        if (out) *out = report;
        LOG_RETURN(false, PROMOTE_SUBSYS,
                   "post-commit cursor verification failed (committed rows "
                   "durable, but cursors not zero — see log)");
    }
    report.committed = true;
    utxo_apply_anchor_gap_blocker_refresh(target);
    utxo_apply_nullifier_gap_blocker_refresh(target);

    LOG_INFO(PROMOTE_SUBSYS,
             "PROMOTE COMPLETE: sapling_anchors=%lld sprout_anchors=%lld "
             "sapling_nf=%lld sprout_nf=%lld boundary=%lld — all three cursors "
             "flipped to 0, shielded history published from producer %s",
             (long long)report.sapling_anchors_installed,
             (long long)report.sprout_anchors_installed,
             (long long)report.sapling_nullifiers_installed,
             (long long)report.sprout_nullifiers_installed,
             (long long)anchor_boundary, req->producer_datadir);

    if (out)
        *out = report;
    return true;
}
