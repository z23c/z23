/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * validate_headers_validator — default header validator for the
 * validate_headers Job. Reconstructs the block header from the in-memory or
 * persisted block index and checks PoW target plus Equihash solution. No
 * cursor logic lives here. */

#include "validate_headers_internal.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"              /* get_sha3_utxo_checkpoint */
#include "chain/equihash.h"
#include "chain/pow.h"
#include "config/runtime.h"
#include "core/uint256.h"
#include "jobs/stage_repair.h"
#include "models/block.h"
#include "primitives/block.h"
#include "storage/disk_block_io.h"
#include "storage/block_index_db.h"
#include "storage/progress_store.h"
#include "services/block_row_verify.h"
#include "validation/check_block.h"
#include "validation/chainstate.h"          /* active_chain_at */
#include "validation/main_state.h"          /* struct main_state */
#include "validate_headers_log_store.h"     /* validate_headers_log_insert */
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

extern struct block_tree_db *g_active_block_tree;

/* node.db handle for the SQLite solution fallback. Defaults to the live
 * runtime handle (NULL outside a booted node, e.g. unit tests); tests
 * inject a fixture handle via validate_headers_validator_set_node_db().
 * The bytes here are validated IDENTICALLY to the in-memory/persisted
 * paths — this is purely a different *source* for the same nSolution. */
static struct node_db *g_fallback_node_db = NULL;
static bool            g_fallback_node_db_set = false;

void validate_headers_validator_set_node_db(struct node_db *ndb);
void validate_headers_validator_set_node_db(struct node_db *ndb)
{
    g_fallback_node_db     = ndb;
    g_fallback_node_db_set = true;
}

static struct node_db *fallback_node_db(void)
{
    if (g_fallback_node_db_set)
        return g_fallback_node_db;
    return app_runtime_node_db();
}

/* Source the full header (incl. Equihash nSolution) from the progress.kv
 * header_solution_repair side-table. header_probe writes this row at
 * accept_block_header time for the LIVE frontier, so it covers heights
 * ABOVE the persisted node.db tip (which has no row there) and any
 * active-chain window position. This is the FIRST source in the ordered
 * resolver below.
 *
 * The bytes are validated IDENTICALLY to every other source — the
 * assembled header is handed to the SAME validate_header_fields
 * (CheckProofOfWork + check_equihash_solution). The loader independently
 * hash-binds the stored row to bi->phashBlock and recomputes the header
 * hash, so a forged / empty / wrong-height row can never be injected; but
 * hash-binding is NOT PoW — a hash-binding-yet-non-PoW solution still
 * fails check_equihash_solution. Returns false (distinct reason) when no
 * repair row exists, so the resolver falls through to the index/node.db
 * sources and ultimately keeps failing rather than passing unverified. */
static bool header_from_repair_table(const struct block_index *bi,
                                     struct block_header *out,
                                     char *out_reason,
                                     size_t out_reason_size)
{
    if (!bi || !bi->phashBlock || !out) {
        snprintf(out_reason, out_reason_size, "null-block-index");
        return false;
    }

    sqlite3 *db = progress_store_db();
    if (!db) {
        snprintf(out_reason, out_reason_size, "no-repair-store");
        return false;
    }

    struct block_header rh;
    if (!stage_repair_header_solution_load(db, bi->nHeight,
                                           bi->phashBlock, &rh)) {
        /* No hash-bound repair row at this height — fall through. */
        snprintf(out_reason, out_reason_size, "no-repair-header");
        return false;
    }
    if (rh.nSolutionSize == 0 ||
        rh.nSolutionSize > sizeof(out->nSolution)) {
        snprintf(out_reason, out_reason_size, "solution-too-large");
        return false;
    }

    /* The loaded header already hashes to bi->phashBlock (the loader's
     * round-trip proved it), so copy its stored fields exactly as stored —
     * including hashPrevBlock from the row, not bi->pprev. */
    block_header_init(out);
    out->nVersion = rh.nVersion;
    out->hashPrevBlock = rh.hashPrevBlock;
    out->hashMerkleRoot = rh.hashMerkleRoot;
    out->hashFinalSaplingRoot = rh.hashFinalSaplingRoot;
    out->nTime = rh.nTime;
    out->nBits = rh.nBits;
    out->nNonce = rh.nNonce;
    memcpy(out->nSolution, rh.nSolution, rh.nSolutionSize);
    out->nSolutionSize = rh.nSolutionSize;
    return true;
}

/* Source the Equihash solution from the node.db blocks.solution BLOB when
 * the in-memory and persisted block-index records have evicted it. Builds
 * the SAME struct block_header the index paths build, differing only in
 * where nSolution came from. Returns false (with a distinct reason) when
 * node.db has no real solution either — NEVER a synthesized/empty one, so
 * the caller keeps failing rather than passing without a verified PoW. */
static bool header_from_node_db_solution(const struct block_index *bi,
                                         struct block_header *out,
                                         char *out_reason,
                                         size_t out_reason_size)
{
    struct node_db *ndb = fallback_node_db();
    if (!ndb) {
        /* No node.db reachable (e.g. unbooted). The 675,755 rows whose
         * node.db solution is ALSO empty land here too via the loader's
         * false return below. */
        snprintf(out_reason, out_reason_size,
                 "no-header-solution-backfill-required");
        return false;
    }

    unsigned char sol[MAX_SOLUTION_SIZE];
    size_t sol_len = 0;
    if (!db_block_load_solution_by_height(ndb, bi->nHeight,
                                          sol, &sol_len, sizeof(sol))
        || sol_len == 0) {
        /* OWNER-GATED BACKFILL: ~675K of 3.13M node.db rows have an empty
         * solution column. They cannot be validated until a scoped
         * zclassicd LevelDB solution import is run (stop/import/restart) —
         * do NOT attempt that here. Until then this header has NO real,
         * verified solution and MUST fail; never a false pass. */
        snprintf(out_reason, out_reason_size,
                 "no-header-solution-backfill-required");
        return false;
    }
    if (sol_len > sizeof(out->nSolution)) {
        snprintf(out_reason, out_reason_size, "solution-too-large");
        return false;
    }
    if (bi->nHeight > 0 && (!bi->pprev || !bi->pprev->phashBlock)) {
        snprintf(out_reason, out_reason_size, "missing-parent-header");
        return false;
    }

    block_header_init(out);
    out->nVersion = bi->nVersion;
    if (bi->pprev && bi->pprev->phashBlock)
        out->hashPrevBlock = *bi->pprev->phashBlock;
    else
        memset(out->hashPrevBlock.data, 0, sizeof(out->hashPrevBlock.data));
    out->hashMerkleRoot = bi->hashMerkleRoot;
    out->hashFinalSaplingRoot = bi->hashFinalSaplingRoot;
    out->nTime = bi->nTime;
    out->nBits = bi->nBits;
    out->nNonce = bi->nNonce;
    memcpy(out->nSolution, sol, sol_len);
    out->nSolutionSize = sol_len;
    return true;
}

static bool header_from_node_db_block(const struct block_index *bi,
                                      struct block_header *out,
                                      char *out_reason,
                                      size_t out_reason_size)
{
    struct node_db *ndb = fallback_node_db();
    if (!ndb) {
        snprintf(out_reason, out_reason_size, "no-node-db-header");
        return false;
    }
    if (!bi || !bi->phashBlock || !out) {
        snprintf(out_reason, out_reason_size, "null-block-index");
        return false;
    }
    if (!db_block_load_header_by_hash_height(ndb, bi->nHeight,
                                             bi->phashBlock->data, out)) {
        snprintf(out_reason, out_reason_size, "no-node-db-header");
        return false;
    }
    return true;
}

static bool validate_header_fields(const struct block_header *header,
                                   const struct chain_params *cp,
                                   char *out_reason,
                                   size_t out_reason_size);

static bool header_hash_matches_index(const struct block_header *header,
                                      const struct block_index *bi);

static bool header_from_disk_block_file(const struct block_index *bi,
                                        const char *datadir,
                                        struct block_header *out,
                                        char *out_reason,
                                        size_t out_reason_size)
{
    if (!bi || !out || !datadir || datadir[0] == 0) {
        snprintf(out_reason, out_reason_size, "no-disk-block-header");
        return false;
    }
    if (!(bi->nStatus & BLOCK_HAVE_DATA) || bi->nFile < 0) {
        snprintf(out_reason, out_reason_size, "no-disk-block-header");
        return false;
    }

    struct block blk;
    block_init(&blk);
    if (!read_block_from_disk_index_pread(&blk, bi, datadir)) {
        block_free(&blk);
        snprintf(out_reason, out_reason_size, "no-disk-block-header");
        return false;
    }

    *out = blk.header;
    block_free(&blk);
    return true;
}


/* A wrong-epoch (but internally valid) Equihash solution must not ride
 * the forward path: the header-accept check rejects it, but the staged
 * validator must too — else a block whose header every peer-facing path
 * refuses could still be applied from a disk body (without this, blocks
 * were applied straight through under the wrong-epoch rules). Pin the
 * expected size whenever the header carries a full solution; sol_size==0
 * headers stay permissive (sparse fast-sync tails re-verify with full
 * context later). */
static bool header_solution_size_in_epoch(const struct block_header *h,
                                          int height,
                                          const struct chain_params *cp,
                                          char *out_reason,
                                          size_t out_reason_size)
{
    if (h->nSolutionSize == 0)
        return true;
    unsigned int en = chain_params_equihash_n(cp, height);
    unsigned int ek = chain_params_equihash_k(cp, height);
    size_t expected = (((size_t)1 << ek) * (en / (ek + 1) + 1)) / 8;
    if (h->nSolutionSize != expected) {
        snprintf(out_reason, out_reason_size, "bad-equihash-solution-size");
        return false;
    }
    return true;
}

static bool validate_from_disk_block_file(
    const struct block_index *bi,
    const char *datadir,
    const struct chain_params *cp,
    char *out_reason,
    size_t out_reason_size,
    bool *had_hash_bound_header)
{
    if (had_hash_bound_header)
        *had_hash_bound_header = false;

    struct block_header h;
    if (!header_from_disk_block_file(bi, datadir, &h, out_reason,
                                     out_reason_size))
        return false;

    if (!header_hash_matches_index(&h, bi)) {
        snprintf(out_reason, out_reason_size, "disk-block-hash-mismatch");
        return false;
    }

    if (had_hash_bound_header)
        *had_hash_bound_header = true;
    if (!header_solution_size_in_epoch(&h, bi->nHeight, cp, out_reason,
                                       out_reason_size))
        return false;
    return validate_header_fields(&h, cp, out_reason, out_reason_size);
}

/* ── Default validator: PoW target + Equihash ────────────────────── */

static bool header_from_block_index(const struct block_index *bi,
                                    struct block_header *out,
                                    char *out_reason,
                                    size_t out_reason_size)
{
    if (!bi || !out) {
        snprintf(out_reason, out_reason_size, "null-block-index");
        return false;
    }
    if (!bi->nSolution || bi->nSolutionSize == 0) {
        snprintf(out_reason, out_reason_size, "no-header-solution");
        return false;
    }
    if (bi->nSolutionSize > sizeof(out->nSolution)) {
        snprintf(out_reason, out_reason_size, "solution-too-large");
        return false;
    }
    if (bi->nHeight > 0 && (!bi->pprev || !bi->pprev->phashBlock)) {
        snprintf(out_reason, out_reason_size, "missing-parent-header");
        return false;
    }

    block_header_init(out);
    out->nVersion = bi->nVersion;
    if (bi->pprev && bi->pprev->phashBlock)
        out->hashPrevBlock = *bi->pprev->phashBlock;
    else
        memset(out->hashPrevBlock.data, 0, sizeof(out->hashPrevBlock.data));
    out->hashMerkleRoot = bi->hashMerkleRoot;
    out->hashFinalSaplingRoot = bi->hashFinalSaplingRoot;
    out->nTime = bi->nTime;
    out->nBits = bi->nBits;
    out->nNonce = bi->nNonce;
    memcpy(out->nSolution, bi->nSolution, bi->nSolutionSize);
    out->nSolutionSize = bi->nSolutionSize;
    return true;
}

static bool header_from_disk_block_index(const struct disk_block_index *dbi,
                                         struct block_header *out,
                                         char *out_reason,
                                         size_t out_reason_size)
{
    if (!dbi || !out) {
        snprintf(out_reason, out_reason_size, "null-disk-block-index");
        return false;
    }
    if (dbi->nSolutionSize == 0) {
        snprintf(out_reason, out_reason_size, "no-header-solution");
        return false;
    }
    if (dbi->nSolutionSize > sizeof(out->nSolution)) {
        snprintf(out_reason, out_reason_size, "solution-too-large");
        return false;
    }

    block_header_init(out);
    out->nVersion = dbi->nVersion;
    out->hashPrevBlock = dbi->hashPrev;
    out->hashMerkleRoot = dbi->hashMerkleRoot;
    out->hashFinalSaplingRoot = dbi->hashFinalSaplingRoot;
    out->nTime = dbi->nTime;
    out->nBits = dbi->nBits;
    out->nNonce = dbi->nNonce;
    memcpy(out->nSolution, dbi->nSolution, dbi->nSolutionSize);
    out->nSolutionSize = dbi->nSolutionSize;
    return true;
}

static bool header_from_persisted_block_index(const struct block_index *bi,
                                              struct block_header *out,
                                              char *out_reason,
                                              size_t out_reason_size)
{
    if (!g_active_block_tree || !bi || !bi->phashBlock) {
        snprintf(out_reason, out_reason_size, "no-header-solution");
        return false;
    }

    struct disk_block_index dbi;
    if (!block_tree_db_read_block_index(g_active_block_tree,
                                        bi->phashBlock, &dbi)) {
        snprintf(out_reason, out_reason_size, "no-header-solution");
        return false;
    }
    return header_from_disk_block_index(&dbi, out,
                                        out_reason, out_reason_size);
}

static bool validate_header_fields(const struct block_header *header,
                                   const struct chain_params *cp,
                                   char *out_reason,
                                   size_t out_reason_size)
{
    if (!header || !cp) {
        snprintf(out_reason, out_reason_size, "missing-header-context");
        return false;
    }

    /* PoW target + full Equihash solution check via the canonical
     * block_row_verify() primitive (services/block_row_verify.h) shared with
     * the import + blocks-hydrate loaders. The caller (validate_from_source)
     * has already hash-bound this header to bi->phashBlock, so the primitive's
     * hash-bind re-confirms it against the header's own recomputed hash (always
     * passes here); the load-bearing checks are the PoW target and the Equihash
     * solution. This path's reason tokens ("high-hash"/"invalid-solution") are
     * preserved by the mapping below. */
    struct uint256 hash;
    block_header_get_hash(header, &hash);
    switch (block_row_verify(hash.data, header->nBits, header, cp, true)) {
        case BLOCK_ROW_VERIFY_OK:
            return true;
        case BLOCK_ROW_VERIFY_HIGH_HASH:
            snprintf(out_reason, out_reason_size, "high-hash");
            return false;
        case BLOCK_ROW_VERIFY_BAD_EQUIHASH:
        case BLOCK_ROW_VERIFY_HASH_BIND_MISMATCH:
        case BLOCK_ROW_VERIFY_NO_PARAMS:
            snprintf(out_reason, out_reason_size, "invalid-solution");
            return false;
    }
    snprintf(out_reason, out_reason_size, "invalid-solution");
    return false;
}

static bool header_hash_matches_index(const struct block_header *header,
                                      const struct block_index *bi)
{
    if (!header || !bi || !bi->phashBlock)
        return false;
    struct uint256 hash;
    block_header_get_hash(header, &hash);
    return uint256_eq(&hash, bi->phashBlock);
}

typedef bool (*header_source_fn)(const struct block_index *bi,
                                 struct block_header *out,
                                 char *out_reason,
                                 size_t out_reason_size);

static bool validate_from_source(header_source_fn fn,
                                 const char *source_name,
                                 const struct block_index *bi,
                                 const struct chain_params *cp,
                                 char *out_reason,
                                 size_t out_reason_size,
                                 bool *had_hash_bound_header,
                                 bool *had_hash_mismatch)
{
    if (had_hash_bound_header)
        *had_hash_bound_header = false;

    struct block_header h;
    if (!fn(bi, &h, out_reason, out_reason_size))
        return false;

    if (!header_hash_matches_index(&h, bi)) {
        if (had_hash_mismatch)
            *had_hash_mismatch = true;
        snprintf(out_reason, out_reason_size,
                 "%s-hash-mismatch", source_name);
        return false;
    }

    if (had_hash_bound_header)
        *had_hash_bound_header = true;
    if (!header_solution_size_in_epoch(&h, bi->nHeight, cp, out_reason,
                                       out_reason_size))
        return false;
    return validate_header_fields(&h, cp, out_reason, out_reason_size);
}

bool validate_headers_default_validator(const struct block_index *bi,
                                        const char *datadir,
                                        char *out_reason,
                                        size_t out_reason_size,
                                        void *user)
{
    (void)user;
    (void)datadir;
    if (!bi || !bi->phashBlock) {
        snprintf(out_reason, out_reason_size, "null-block-index");
        return false;
    }

    /* (0) Genesis is exempt from contextual header checks — its validity is
     * pinned by consensus.hashGenesisBlock itself (same exemption as
     * check_block.c:301 and accept_block_header.c:221,319). Without this,
     * the loader's synthetic genesis entry (inserted on an empty index with
     * nVersion=0, engine/services/src/block_index_loader.c) terminal-fails the
     * version gate and the reducer dead-waits at H*=0 forever — the
     * 2026-07-27 wipe-to-tip stall's reducer-side wedge. */
    const struct chain_params *cp = chain_params_get();
    if (!cp) {
        snprintf(out_reason, out_reason_size, "no-chain-params");
        return false;
    }
    if (uint256_eq(bi->phashBlock, &cp->consensus.hashGenesisBlock))
        return true;

    /* (1) version. */
    if (bi->nVersion < MIN_BLOCK_VERSION) {
        snprintf(out_reason, out_reason_size, "version-too-low");
        return false;
    }

    /* (2) PoW target. Cheap — no disk. (cp resolved at (0) above.) */

    /* (3) Header source resolution — ONE ordered resolver, five sources.
     * A source can produce a terminal PoW/Equihash verdict only after its
     * assembled header hashes back to bi->phashBlock. A mismatch is treated
     * as a stale/corrupt source and falls through to the next candidate.
     *
     * FIRST source: the progress.kv header_solution_repair side-table.
     * header_probe writes this row at accept_block_header time for the
     * live frontier, so it is the authoritative source for heights ABOVE
     * the persisted node.db tip. When it holds a (hash-bound)
     * solution it hashes to bi->phashBlock identically to every other
     * source, so the PoW/Equihash verdict is source-independent. */
    bool had_hash_mismatch = false;
    bool had_hash_bound_header = false;
    if (validate_from_source(header_from_repair_table, "repair-header",
                             bi, cp, out_reason, out_reason_size,
                             &had_hash_bound_header,
                             &had_hash_mismatch))
        return true;
    if (had_hash_bound_header)
        return false;

    /* node.db blocks rows are keyed by the active-chain hash/height pair
     * and carry the full stored header. This source must precede the
     * in-memory index: after a stale block-index load, the index fields can
     * be inconsistent with phashBlock even though node.db has the canonical
     * connected header. */
    if (validate_from_source(header_from_node_db_block, "node-db-header",
                             bi, cp, out_reason, out_reason_size,
                             &had_hash_bound_header,
                             &had_hash_mismatch))
        return true;
    if (had_hash_bound_header)
        return false;

    /* Full block files are the next strongest source on a full datadir copy:
     * read the indexed block, hash-bind it to bi->phashBlock, then validate
     * the exact on-disk header. This covers node.db rows with missing/stale
     * solution bytes without trusting the body source blindly. */
    if (validate_from_disk_block_file(bi, datadir, cp, out_reason,
                                      out_reason_size,
                                      &had_hash_bound_header))
        return true;
    if (had_hash_bound_header)
        return false;

    /* The block index stores full header fields, including nonce and
     * Equihash solution, for headers admitted through normal P2P/RPC
     * paths. Validate from that header snapshot next. */
    if (validate_from_source(header_from_block_index, "block-index",
                             bi, cp, out_reason, out_reason_size,
                             &had_hash_bound_header,
                             &had_hash_mismatch))
        return true;
    if (had_hash_bound_header)
        return false;

    /* Restart/load paths deliberately keep the Equihash solution out
     * of the hot in-memory index to save RAM. The persisted block-index
     * record still owns it, so load that compact header record instead
     * of making header validation depend on readable block bodies. */
    if (validate_from_source(header_from_persisted_block_index,
                             "persisted-index", bi, cp,
                             out_reason, out_reason_size,
                             &had_hash_bound_header,
                             &had_hash_mismatch))
        return true;
    if (had_hash_bound_header)
        return false;

    /* Final source: the node.db blocks.solution BLOB. A cold-imported /
     * near-empty LevelDB leaves both index paths solution-less even though
     * the real, network-anchored Equihash solution lives in SQLite. We
     * validate it IDENTICALLY (same validate_header_fields → CheckProofOfWork
     * + check_equihash_solution). On a node.db that ALSO lacks the solution
     * this still FAILS with "no-header-solution-backfill-required" — never a
     * false pass. */
    if (validate_from_source(header_from_node_db_solution, "node-db-solution",
                             bi, cp, out_reason, out_reason_size,
                             &had_hash_bound_header,
                             &had_hash_mismatch))
        return true;
    if (had_hash_bound_header)
        return false;

    if (had_hash_mismatch)
        snprintf(out_reason, out_reason_size, "header-source-hash-mismatch");
    return false;
}

/* ── On-demand single-header pass record (the instant-on seam) ──────────────
 * See jobs/validate_headers_stage.h for the full contract. This is the
 * single-header form of the reducer stage's per-height validation, kept here in
 * the validator TU (a validation concern) so the Job file stays under its size
 * ceiling. It resolves the header index (active_chain_at, then the header-tip
 * ancestor walk — the same resolution the batched step uses), runs the FULL
 * canonical validator, and durably records a validate_headers_log PASS row on
 * success. Production ALWAYS uses validate_headers_default_validator (the real
 * PoW + Equihash pipeline); the ZCL_TESTING override below lets the focused unit
 * test drive the pass/fail branches without a mined Equihash header. */
#ifdef ZCL_TESTING
static vh_validator_fn g_ensure_validator_override = NULL;
static void           *g_ensure_validator_override_user = NULL;
void validate_headers_ensure_set_validator_for_test(vh_validator_fn fn,
                                                    void *user);
void validate_headers_ensure_set_validator_for_test(vh_validator_fn fn,
                                                    void *user)
{
    g_ensure_validator_override = fn;
    g_ensure_validator_override_user = user;
}
#endif

bool validate_headers_stage_ensure_pass_record(struct main_state *ms,
                                               int32_t height)
{
    if (!ms || height < 0)
        return false;
    sqlite3 *db = progress_store_db();
    if (!db)
        return false;

    /* Resolve the header at `height`: the connected chain first, then the
     * header-tip ancestor walk (read-only — chain_active is never mutated).
     * Works before validate_headers_stage_init: no Job state is touched. */
    struct block_index *bi = active_chain_at(&ms->chain_active, height);
    if (!bi && ms->pindex_best_header &&
        height <= ms->pindex_best_header->nHeight)
        bi = block_index_get_ancestor(ms->pindex_best_header, height);
    /* A headers-first substrate retains the checkpoint header in the block
     * map even if a subsequent fresh-genesis state reset lowers the published
     * header frontier. Resolve only the baked checkpoint by its baked hash;
     * the unchanged canonical validator below still rechecks full PoW. */
    if (!bi) {
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        if (cp && cp->height == height) {
            struct uint256 cp_hash;
            memcpy(cp_hash.data, cp->block_hash, 32);
            struct block_index *candidate =
                block_map_find(&ms->map_block_index, &cp_hash);
            if (candidate && candidate->nHeight == height)
                bi = candidate;
        }
    }
    if (!bi || !bi->phashBlock)
        return false;

    /* Idempotent: a P2P node's forward stage, or a prior call, already wrote it
     * — never re-run the Equihash work. */
    if (validate_headers_stage_has_pass_record(height, bi->phashBlock))
        return true;

    if (!validate_headers_log_ensure_schema(db))
        return false; // raw-return-ok:schema-ensure-logs-internally

    vh_validator_fn validator = validate_headers_default_validator;
    void *validator_user = NULL;
#ifdef ZCL_TESTING
    if (g_ensure_validator_override) {
        validator = g_ensure_validator_override;
        validator_user = g_ensure_validator_override_user;
    }
#endif
    /* FULL canonical validation: PoW target + Equihash solution. A wrong-block or
     * PoW-invalid header at `height` fails here → NO pass row is written → the
     * downstream header-bootstrap bind still refuses. */
    char reason[VH_MAX_REASON];
    reason[0] = '\0';
    if (!validator(bi, NULL, reason, sizeof(reason), validator_user)) {
        LOG_WARN("validate_headers",
                 "on-demand checkpoint-header validate FAILED h=%d reason=%s",
                 height, reason[0] ? reason : "(none)");
        return false;
    }

    progress_store_tx_lock();
    bool wrote =
        validate_headers_log_insert(db, height, bi->phashBlock, true, NULL);
    progress_store_tx_unlock();
    if (!wrote) {
        LOG_WARN("validate_headers",
                 "on-demand checkpoint-header pass-record insert failed h=%d",
                 height);
        return false;
    }
    LOG_INFO("validate_headers",
             "on-demand checkpoint-header PASS record written h=%d (full "
             "Equihash PoW verified)", height);
    return validate_headers_stage_has_pass_record(height, bi->phashBlock);
}
