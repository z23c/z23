/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * shielded_history_body_crosscheck — the independent local-body trust root for
 * the shielded-history promote path. See shielded_history_body_crosscheck.h.
 *
 * Sprout frontiers and the nullifier set are NOT committed by any block header,
 * so a promoted producer table needs an independent trust root: the locally
 * held, PoW/merkle-verified block bodies. This verifier re-derives both from
 * bodies over [0, checkpoint_height] and compares against the producer's
 * sprout_anchors + nullifiers tables. It writes NOTHING: the producer
 * progress.kv is opened SQLITE_OPEN_READONLY + PRAGMA query_only, the copy
 * node.db is opened read-only, and bodies are read with pread().
 *
 * Shape of the walk:
 *  - Build the copy's SELECTED-chain block_index array [0..checkpoint] from its
 *    node.db `blocks` rows (status>=3, the same connected filter
 *    db_block_find_by_height uses), prev-linkage verified. This is the
 *    binding.target for nbf_chain_body_verify (block hash == selected-ancestor
 *    header hash + recomputed merkle == header) — the reused PoW/merkle bind.
 *  - Shard [0, checkpoint] at the producer's own sprout-frontier heights
 *    (SELECT height FROM sprout_anchors) grouped into <=32 contiguous ranges.
 *    Each shard resumes from the producer's serialized frontier at its
 *    range-start (deserialize + G3b root==anchor PK), folds every block's
 *    JoinSplit commitments in fold_sprout order (utxo_apply_anchors.c:133-139),
 *    and requires the running root == the producer anchor at every anchor height
 *    it crosses (its range-end is the last such check). Any mismatch =>
 *    sprout_ok=false (logged with the shard index).
 *  - Every shard collects nullifiers: each v_joinsplit[].nullifiers[0..1] as
 *    pool 0 (Sprout), each v_shielded_spend[].nullifier as pool 1 (Sapling).
 *  - G4: union(all shards' nf) is compared to the producer `nullifiers` rows at
 *    height<=checkpoint BOTH DIRECTIONS (set-equality). nullifiers_ok accordingly.
 *
 * Reentrant-safe; owns no global mutable state. Returns false ONLY on
 * infrastructure failure (unreadable/untrusted body, missing producer table,
 * malloc/deserialize/prepare failure); comparison verdicts land in *out.
 */
// one-result-type-ok:contract-bool-verdicts-in-out — the public entry point
// returns bool per the on-main contract header (comparison verdicts land in
// *out; false is reserved for infrastructure failure), so it does not converge
// on struct zcl_result.

#include "services/shielded_history_body_crosscheck.h"

#include "nullifier_backfill_chain.h"   /* nbf_chain_binding, nbf_chain_body_verify */

#include "chain/chain.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/constants.h"          /* ZC_NUM_JS_OUTPUTS */
#include "sapling/incremental_merkle_tree.h"
#include "storage/consensus_db.h"       /* consensus_db_kernel_store_path */
#include "storage/disk_block_io.h"
#include "storage/nullifier_kv.h"       /* NULLIFIER_POOL_SPROUT / _SAPLING */
#include "util/log_macros.h"
#include "util/result.h"
#include "util/safe_alloc.h"
#include "util/workpool.h"

#include <limits.h>
#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XCK_SUBSYS "shielded_crosscheck"
#define XCK_MAX_SHARDS 32u

struct xck_nf {
    uint8_t nf[32];
    int pool;
};

struct xck_shard {
    /* shared read-only inputs */
    const struct nbf_chain_binding *binding;
    const char *copy_datadir;
    const int64_t *anchor_h;          /* A[] sorted ascending */
    const struct uint256 *anchor_r;   /* R[] parallel roots      */
    size_t anchor_count;              /* m */
    int64_t lo;                       /* first block height (inclusive) */
    int64_t hi;                       /* last block height (inclusive)  */
    struct incremental_merkle_tree resume;  /* frontier after block lo-1 */
    int idx;
    /* outputs (each shard owns its own; no shared mutation) */
    bool sprout_ok;
    bool infra_ok;
    struct xck_nf *nf;
    size_t nf_count;
    size_t nf_cap;
};

/* ── read-only sqlite ───────────────────────────────────────────────── */

static sqlite3 *xck_open_ro(const char *datadir, const char *fname)
{
    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/%s", datadir, fname);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        LOG_WARN(XCK_SUBSYS, "open_ro: path too long %s/%s", datadir, fname);
        return NULL;
    }
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) {
        LOG_WARN(XCK_SUBSYS, "open_ro: open failed rc=%d path=%s: %s", rc, path,
                 db ? sqlite3_errmsg(db) : "(nil)");
        if (db)
            sqlite3_close(db);
        return NULL;
    }
    /* Belt-and-braces: refuse any accidental write on this handle. */
    (void)sqlite3_exec(db, "PRAGMA query_only=ON", NULL, NULL, NULL);
    return db;
}

/* ── in-memory selected-chain block_index from copy node.db ─────────── */

static bool xck_build_index(sqlite3 *cdb, int64_t checkpoint,
                            struct block_index **nodes_out, size_t *count_out)
{
    *nodes_out = NULL;
    *count_out = 0;
    size_t count = (size_t)checkpoint + 1u;
    struct block_index *nodes = zcl_calloc(count, sizeof(*nodes), "xck_index");
    if (!nodes)
        return false;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(cdb,
            "SELECT hash,prev_hash,merkle_root,file_num,data_pos "
            "FROM blocks WHERE height=? AND status>=3 LIMIT 1",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN(XCK_SUBSYS, "build_index prepare failed: %s",
                 sqlite3_errmsg(cdb));
        free(nodes);
        return false;
    }

    bool ok = true;
    for (int64_t h = 0; ok && h <= checkpoint; h++) {
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
        if (sqlite3_step(st) != SQLITE_ROW) { // raw-sql-ok:crosscheck-readonly
            LOG_WARN(XCK_SUBSYS, "build_index: missing connected block h=%lld",
                     (long long)h);
            ok = false;
            break;
        }
        const void *hash = sqlite3_column_blob(st, 0);
        const void *prev = sqlite3_column_blob(st, 1);
        const void *merkle = sqlite3_column_blob(st, 2);
        if (!hash || sqlite3_column_bytes(st, 0) != 32 ||
            !merkle || sqlite3_column_bytes(st, 2) != 32) {
            LOG_WARN(XCK_SUBSYS, "build_index: bad row width h=%lld",
                     (long long)h);
            ok = false;
            break;
        }
        struct block_index *bi = &nodes[h];
        block_index_init(bi);
        memcpy(bi->hashBlock.data, hash, 32);
        bi->phashBlock = &bi->hashBlock;
        memcpy(bi->hashMerkleRoot.data, merkle, 32);
        bi->nHeight = (int)h;
        bi->nFile = sqlite3_column_int(st, 3);
        bi->nDataPos = (unsigned int)sqlite3_column_int64(st, 4);
        bi->nStatus = (unsigned int)(BLOCK_VALID_TREE | BLOCK_HAVE_DATA);
        bi->pprev = (h > 0) ? &nodes[h - 1] : NULL;
        if (h > 0 &&
            (!prev || sqlite3_column_bytes(st, 1) != 32 ||
             memcmp(prev, nodes[h - 1].hashBlock.data, 32) != 0)) {
            LOG_WARN(XCK_SUBSYS, "build_index: prev-linkage break at h=%lld",
                     (long long)h);
            ok = false;
            break;
        }
        block_index_build_skip(bi);
    }
    sqlite3_finalize(st);
    if (!ok) {
        free(nodes);
        return false;
    }
    *nodes_out = nodes;
    *count_out = count;
    return true;
}

/* ── producer sprout-anchor heights + roots ─────────────────────────── */

static bool xck_load_anchor_heights(sqlite3 *pdb, int64_t checkpoint,
                                    int64_t **A_out, struct uint256 **R_out,
                                    size_t *m_out)
{
    *A_out = NULL;
    *R_out = NULL;
    *m_out = 0;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb,
            "SELECT height,anchor FROM sprout_anchors "
            "WHERE height<=? ORDER BY height ASC",
            -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN(XCK_SUBSYS, "load_anchor_heights prepare failed: %s",
                 sqlite3_errmsg(pdb));
        return false;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)checkpoint);

    size_t cap = 0, n = 0;
    int64_t *A = NULL;
    struct uint256 *R = NULL;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:crosscheck-readonly
        const void *anchor = sqlite3_column_blob(st, 1);
        if (!anchor || sqlite3_column_bytes(st, 1) != 32) {
            LOG_WARN(XCK_SUBSYS, "load_anchor_heights: bad anchor width");
            ok = false;
            break;
        }
        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 64;
            int64_t *nA = zcl_realloc(A, ncap * sizeof(*nA), "xck_A");
            struct uint256 *nR = zcl_realloc(R, ncap * sizeof(*nR), "xck_R");
            if (!nA || !nR) {
                free(nA ? nA : A);
                free(nR ? nR : R);
                sqlite3_finalize(st);
                return false;
            }
            A = nA;
            R = nR;
            cap = ncap;
        }
        A[n] = sqlite3_column_int64(st, 0);
        memcpy(R[n].data, anchor, 32);
        n++;
    }
    if (ok && rc != SQLITE_DONE) {
        LOG_WARN(XCK_SUBSYS, "load_anchor_heights step rc=%d: %s", rc,
                 sqlite3_errmsg(pdb));
        ok = false;
    }
    sqlite3_finalize(st);
    if (!ok) {
        free(A);
        free(R);
        return false;
    }
    *A_out = A;
    *R_out = R;
    *m_out = n;
    return true;
}

/* Load + G3b-verify the producer's serialized Sprout frontier at `height`
 * (its own root must equal the anchor PK). */
static bool xck_load_frontier_at(sqlite3 *pdb, int64_t height,
                                 const struct uint256 *expected_root,
                                 struct incremental_merkle_tree *tree_out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb, "SELECT tree FROM sprout_anchors WHERE height=?",
                           -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN(XCK_SUBSYS, "load_frontier prepare failed: %s",
                 sqlite3_errmsg(pdb));
        return false;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    if (sqlite3_step(st) != SQLITE_ROW) { // raw-sql-ok:crosscheck-readonly
        LOG_WARN(XCK_SUBSYS, "load_frontier: no producer frontier at h=%lld",
                 (long long)height);
        sqlite3_finalize(st);
        return false;
    }
    const void *blob = sqlite3_column_blob(st, 0);
    int blen = sqlite3_column_bytes(st, 0);
    bool ok = true;
    if (!blob || blen <= 0) {
        LOG_WARN(XCK_SUBSYS, "load_frontier: empty tree blob h=%lld",
                 (long long)height);
        ok = false;
    } else {
        sprout_tree_init(tree_out);
        struct byte_stream bs;
        stream_init_from_data(&bs, blob, (size_t)blen);
        if (!incremental_tree_deserialize(tree_out, &bs) ||
            stream_remaining(&bs) != 0) {
            LOG_WARN(XCK_SUBSYS, "load_frontier: deserialize failed h=%lld",
                     (long long)height);
            ok = false;
        } else {
            struct uint256 got;
            incremental_tree_root(tree_out, &got);
            if (!uint256_eq(&got, expected_root)) {
                LOG_WARN(XCK_SUBSYS,
                         "load_frontier: G3b root!=anchor PK at h=%lld",
                         (long long)height);
                ok = false;
            }
        }
    }
    sqlite3_finalize(st);
    return ok;
}

/* ── shard partition ────────────────────────────────────────────────── */

static bool xck_build_shards(sqlite3 *pdb,
                             const struct nbf_chain_binding *binding,
                             const char *copy_datadir, const int64_t *A,
                             const struct uint256 *R, size_t m,
                             int64_t checkpoint, struct xck_shard **shards_out,
                             size_t *S_out)
{
    *shards_out = NULL;
    *S_out = 0;
    size_t S = (m == 0) ? 1u
                        : (m < XCK_MAX_SHARDS ? m : (size_t)XCK_MAX_SHARDS);
    struct xck_shard *sh = zcl_calloc(S, sizeof(*sh), "xck_shards");
    if (!sh)
        return false;

    bool ok = true;
    for (size_t g = 0; g < S && ok; g++) {
        struct xck_shard *s = &sh[g];
        s->binding = binding;
        s->copy_datadir = copy_datadir;
        s->anchor_h = A;
        s->anchor_r = R;
        s->anchor_count = m;
        s->idx = (int)g;
        s->sprout_ok = true;
        s->infra_ok = true;

        if (m == 0) {
            s->lo = 0;
            s->hi = checkpoint;
            sprout_tree_init(&s->resume);
            continue;
        }
        size_t grp_start = g * m / S;         /* first anchor idx in group */
        size_t grp_end = (g + 1) * m / S - 1; /* last anchor idx in group  */
        s->hi = (g == S - 1) ? checkpoint : A[grp_end];
        if (g == 0) {
            s->lo = 0;
            sprout_tree_init(&s->resume);
        } else {
            size_t boundary = grp_start - 1; /* prev group's last anchor */
            s->lo = A[boundary] + 1;
            if (!xck_load_frontier_at(pdb, A[boundary], &R[boundary],
                                      &s->resume))
                ok = false;
        }
    }
    if (!ok) {
        free(sh);
        return false;
    }
    *shards_out = sh;
    *S_out = S;
    return true;
}

/* ── per-shard body walk (workpool_fn) ──────────────────────────────── */

/* fold_sprout append order, exactly utxo_apply_anchors.c:133-139:
 * vtx order i -> joinsplit order j -> output k in [0,ZC_NUM_JS_OUTPUTS). */
static void xck_append_jsplit(struct incremental_merkle_tree *tree,
                              const struct block *blk)
{
    for (size_t i = 0; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        for (size_t j = 0; j < tx->num_joinsplit; j++)
            for (size_t k = 0; k < ZC_NUM_JS_OUTPUTS; k++)
                incremental_tree_append(tree, &tx->v_joinsplit[j].commitments[k]);
    }
}

static bool xck_nf_push(struct xck_shard *s, const uint8_t nf[32], int pool)
{
    if (s->nf_count == s->nf_cap) {
        size_t ncap = s->nf_cap ? s->nf_cap * 2 : 64;
        struct xck_nf *n = zcl_realloc(s->nf, ncap * sizeof(*n), "xck_nf");
        if (!n)
            return false;
        s->nf = n;
        s->nf_cap = ncap;
    }
    memcpy(s->nf[s->nf_count].nf, nf, 32);
    s->nf[s->nf_count].pool = pool;
    s->nf_count++;
    return true;
}

/* Replicates the static nbf_collect_nullifiers pool mapping
 * (nullifier_backfill_service.c:72-86). */
static bool xck_collect_nf(struct xck_shard *s, const struct block *blk)
{
    for (size_t i = 0; i < blk->num_vtx; i++) {
        const struct transaction *tx = &blk->vtx[i];
        for (size_t j = 0; j < tx->num_joinsplit; j++)
            for (size_t k = 0; k < 2; k++)
                if (!xck_nf_push(s, tx->v_joinsplit[j].nullifiers[k].data,
                                 NULLIFIER_POOL_SPROUT))
                    return false;
        for (size_t j = 0; j < tx->num_shielded_spend; j++)
            if (!xck_nf_push(s, tx->v_shielded_spend[j].nullifier.data,
                             NULLIFIER_POOL_SAPLING))
                return false;
    }
    return true;
}

/* Is `h` a producer sprout-anchor height? Returns its index in A[] or -1. */
static int64_t xck_anchor_index(const int64_t *A, size_t m, int64_t h)
{
    size_t lo = 0, hi = m;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (A[mid] == h)
            return (int64_t)mid;
        if (A[mid] < h)
            lo = mid + 1;
        else
            hi = mid;
    }
    return -1; // raw-return-ok:sentinel h is not an anchor height (not an error)
}

static bool xck_shard_run(void *item)
{
    struct xck_shard *s = item;
    struct incremental_merkle_tree frontier = s->resume; /* value copy */

    for (int64_t h = s->lo; h <= s->hi; h++) {
        struct block_index *bi = block_index_get_ancestor(
            (struct block_index *)s->binding->target, (int)h);
        struct disk_block_pos pos;
        if (!bi || !block_index_disk_pos_snapshot(bi, &pos, NULL)) {
            s->infra_ok = false;
            LOG_RETURN(false, XCK_SUBSYS,
                       "shard %d: no disk position for h=%lld", s->idx,
                       (long long)h);
        }
        struct block blk;
        block_init(&blk);
        if (!read_block_from_disk_pread(&blk, &pos, s->copy_datadir)) {
            block_free(&blk);
            s->infra_ok = false;
            LOG_RETURN(false, XCK_SUBSYS, "shard %d: unreadable body h=%lld",
                       s->idx, (long long)h);
        }
        struct zcl_result vr = nbf_chain_body_verify(s->binding, &blk, h);
        if (!vr.ok) {
            block_free(&blk);
            s->infra_ok = false;
            LOG_RETURN(false, XCK_SUBSYS,
                       "shard %d: body not PoW/merkle-bound h=%lld: %s", s->idx,
                       (long long)h, vr.message);
        }
        xck_append_jsplit(&frontier, &blk);
        if (!xck_collect_nf(s, &blk)) {
            block_free(&blk);
            s->infra_ok = false;
            LOG_RETURN(false, XCK_SUBSYS, "shard %d: nf buffer alloc failed",
                       s->idx);
        }
        int64_t ai = xck_anchor_index(s->anchor_h, s->anchor_count, h);
        if (ai >= 0) {
            struct uint256 root;
            incremental_tree_root(&frontier, &root);
            if (!uint256_eq(&root, &s->anchor_r[ai])) {
                s->sprout_ok = false;
                LOG_WARN(XCK_SUBSYS,
                         "shard %d: Sprout frontier root mismatch at h=%lld",
                         s->idx, (long long)h);
            }
        }
        block_free(&blk);
    }
    return true;
}

/* ── nullifier set comparison (G4) ──────────────────────────────────── */

static int xck_nf_cmp(const void *a, const void *b)
{
    const struct xck_nf *x = a;
    const struct xck_nf *y = b;
    if (x->pool != y->pool)
        return x->pool < y->pool ? -1 : 1;
    return memcmp(x->nf, y->nf, 32);
}

static size_t xck_nf_sort_dedup(struct xck_nf *v, size_t n)
{
    if (n < 2) {
        qsort(v, n, sizeof(*v), xck_nf_cmp);
        return n;
    }
    qsort(v, n, sizeof(*v), xck_nf_cmp);
    size_t w = 1;
    for (size_t i = 1; i < n; i++)
        if (xck_nf_cmp(&v[w - 1], &v[i]) != 0)
            v[w++] = v[i];
    return w;
}

static bool xck_load_producer_nf(sqlite3 *pdb, int64_t checkpoint,
                                 struct xck_nf **P_out, size_t *n_out)
{
    *P_out = NULL;
    *n_out = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb,
            "SELECT nf,pool FROM nullifiers WHERE height<=?", -1, &st,
            NULL) != SQLITE_OK) {
        LOG_WARN(XCK_SUBSYS, "load_producer_nf prepare failed: %s",
                 sqlite3_errmsg(pdb));
        return false;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)checkpoint);

    size_t cap = 0, n = 0;
    struct xck_nf *P = NULL;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:crosscheck-readonly
        const void *nf = sqlite3_column_blob(st, 0);
        if (!nf || sqlite3_column_bytes(st, 0) != 32) {
            LOG_WARN(XCK_SUBSYS, "load_producer_nf: bad nf width");
            ok = false;
            break;
        }
        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 128;
            struct xck_nf *nP = zcl_realloc(P, ncap * sizeof(*nP), "xck_P");
            if (!nP) {
                free(P);
                sqlite3_finalize(st);
                return false;
            }
            P = nP;
            cap = ncap;
        }
        memcpy(P[n].nf, nf, 32);
        P[n].pool = sqlite3_column_int(st, 1);
        n++;
    }
    if (ok && rc != SQLITE_DONE) {
        LOG_WARN(XCK_SUBSYS, "load_producer_nf step rc=%d: %s", rc,
                 sqlite3_errmsg(pdb));
        ok = false;
    }
    sqlite3_finalize(st);
    if (!ok) {
        free(P);
        return false;
    }
    *P_out = P;
    *n_out = n;
    return true;
}

static bool xck_nf_sets_equal(const struct xck_nf *B, size_t nB,
                              const struct xck_nf *P, size_t nP)
{
    if (nB != nP) {
        LOG_WARN(XCK_SUBSYS, "nullifier set size differs: body=%zu producer=%zu",
                 nB, nP);
        return false;
    }
    for (size_t i = 0; i < nB; i++)
        if (xck_nf_cmp(&B[i], &P[i]) != 0) {
            LOG_WARN(XCK_SUBSYS, "nullifier set mismatch at sorted index %zu", i);
            return false;
        }
    return true;
}

/* ── entry point ────────────────────────────────────────────────────── */

bool shielded_history_body_crosscheck_run(const char *copy_datadir,
                                          const char *producer_datadir,
                                          int64_t checkpoint_height,
                                          struct crosscheck_result *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!copy_datadir || !producer_datadir || !out || checkpoint_height < 0 ||
        checkpoint_height > INT_MAX)
        LOG_RETURN(false, XCK_SUBSYS,
                   "crosscheck: invalid args checkpoint=%lld",
                   (long long)checkpoint_height);

    bool ret = false;
    sqlite3 *pdb = NULL, *cdb = NULL;
    struct block_index *nodes = NULL;
    size_t node_count = 0;
    int64_t *A = NULL;
    struct uint256 *R = NULL;
    size_t m = 0;
    struct xck_shard *shards = NULL;
    void **items = NULL;
    size_t S = 0;
    struct xck_nf *B = NULL, *P = NULL;
    size_t nB = 0, nP = 0;
    struct workpool wp;
    bool wp_init = false;

    /* A4: the producer's anchors/nullifiers live in the kernel store —
     * consensus.db post-flip, or the legacy progress.kv on a pre-flip datadir. */
    char kernel_path[PATH_MAX];
    const char *kernel_name = "progress.kv";
    if (consensus_db_kernel_store_path(producer_datadir, kernel_path,
                                       sizeof(kernel_path))) {
        const char *slash = strrchr(kernel_path, '/');
        kernel_name = slash ? slash + 1 : kernel_path;
    }
    pdb = xck_open_ro(producer_datadir, kernel_name);
    if (!pdb) {
        LOG_WARN(XCK_SUBSYS, "crosscheck: producer kernel store (%s) unavailable",
                 kernel_name);
        goto done;
    }
    cdb = xck_open_ro(copy_datadir, "node.db");
    if (!cdb) {
        LOG_WARN(XCK_SUBSYS, "crosscheck: copy node.db unavailable");
        goto done;
    }
    if (!xck_build_index(cdb, checkpoint_height, &nodes, &node_count))
        goto done;
    if (!xck_load_anchor_heights(pdb, checkpoint_height, &A, &R, &m))
        goto done;
    out->sprout_frontier_count = (uint64_t)m;

    struct nbf_chain_binding binding;
    memset(&binding, 0, sizeof(binding));
    binding.target = &nodes[node_count - 1];
    binding.tip = &nodes[node_count - 1];
    binding.target_height = (int)checkpoint_height;
    binding.tip_height = (int)checkpoint_height;
    binding.target_hash = nodes[node_count - 1].hashBlock;
    binding.tip_hash = nodes[node_count - 1].hashBlock;

    if (!xck_build_shards(pdb, &binding, copy_datadir, A, R, m,
                          checkpoint_height, &shards, &S))
        goto done;

    items = zcl_calloc(S, sizeof(*items), "xck_items");
    if (!items)
        goto done;
    for (size_t i = 0; i < S; i++)
        items[i] = &shards[i];
    if (!workpool_init(&wp, 0, S, xck_shard_run)) {
        LOG_WARN(XCK_SUBSYS, "crosscheck: workpool_init failed S=%zu", S);
        goto done;
    }
    wp_init = true;
    if (!workpool_run(&wp, items, S)) {
        LOG_WARN(XCK_SUBSYS, "crosscheck: a shard reported infra failure");
        goto done; /* ret stays false — infrastructure failure */
    }

    bool sprout_ok = true;
    size_t total_nf = 0;
    for (size_t i = 0; i < S; i++) {
        if (!shards[i].sprout_ok)
            sprout_ok = false;
        total_nf += shards[i].nf_count;
    }
    if (total_nf) {
        B = zcl_calloc(total_nf, sizeof(*B), "xck_B");
        if (!B)
            goto done;
        for (size_t i = 0, at = 0; i < S; i++) {
            if (shards[i].nf_count)
                memcpy(B + at, shards[i].nf, shards[i].nf_count * sizeof(*B));
            at += shards[i].nf_count;
        }
    }
    nB = xck_nf_sort_dedup(B, total_nf);

    if (!xck_load_producer_nf(pdb, checkpoint_height, &P, &nP))
        goto done;
    nP = xck_nf_sort_dedup(P, nP);

    out->sprout_ok = sprout_ok;
    out->nullifiers_ok = xck_nf_sets_equal(B, nB, P, nP);
    out->nf_count = (uint64_t)nB;
    out->max_height = checkpoint_height;
    ret = true;

done:
    if (wp_init)
        workpool_destroy(&wp);
    if (shards)
        for (size_t i = 0; i < S; i++)
            free(shards[i].nf);
    free(shards);
    free(items);
    free(nodes);
    free(A);
    free(R);
    free(B);
    free(P);
    if (pdb)
        sqlite3_close(pdb);
    if (cdb)
        sqlite3_close(cdb);
    return ret;
}
