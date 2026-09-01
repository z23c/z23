/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block Index Loader — node.db `blocks`-table hydrate rung (the
 * `--importblockindex` sink) with the J5 per-row quarantine. Split out of
 * block_index_loader.c along its natural seam; it shares the map post-load
 * helpers (block_index_forward_pass, promote_best_header_after_load) via
 * services/block_index_loader.h. */

#include "platform/time_compat.h"
#include "services/block_index_loader.h"
#include "services/block_row_verify.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "chain/pow.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "models/database.h"
#include "models/block.h"
#include "primitives/block.h"
#include "core/uint256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <sqlite3.h>

#include "util/ar_step_readonly.h"
#include "util/blocker.h"
#include "util/boot_phase.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "util/safe_alloc.h"

/* ── load_block_index_from_blocks_table ──────────────────── */

/* J5 per-row quarantine (blocks-hydrate). A poisoned `blocks` row no longer
 * refuses the WHOLE hydration; it is purged (db_block_delete) and skipped so
 * the remaining rows still load, its absence letting header sync + body_fetch
 * re-request that height. This counter is the dumpstate-visible tally of rows
 * purged this process — surfaced by diag_block_index_dump_state_json. */
static _Atomic int64_t g_blocks_hydrate_quarantined = 0;

int64_t block_index_blocks_hydrate_quarantined(void)
{
    return atomic_load_explicit(&g_blocks_hydrate_quarantined,
                                memory_order_relaxed);
}

/* De-storm the per-row quarantine WARN: a table with many poisoned rows must
 * not emit one WARN per row. Keyed on height so a genuinely-different row still
 * emits but a repeat collapses to first-fire + 60 s keepalive. */
static struct log_throttle g_blocks_hydrate_quarantine_log = LOG_THROTTLE_INIT;

/* Fixed typed-blocker id for the quarantine (height+hash+reason travel in the
 * reason string; fire_count + the counter above carry multiplicity, so a
 * per-height id is deliberately NOT used — it would exhaust the 128-slot
 * registry on a badly-shredded table). TRANSIENT: the purge is recoverable —
 * the height is re-fetched and the stages revalidate it. */
#define BLOCKS_HYDRATE_QUARANTINE_BLOCKER_ID "block_index.blocks_hydrate_quarantine"

/* Safety valve: localized corruption → per-row quarantine; a table with more
 * than this many poisoned rows is grossly shredded, so refuse the whole
 * hydration (the pre-J5 behavior) rather than seed a lace-riddled map.
 * BLOCKS_HYDRATE_MAX_QUARANTINE is shared with the flat loader via
 * services/block_index_loader.h (the common outer bound). */

/* Equihash budget knob mirroring the import path's IMPORT_ROW_POW_STRIDE: the
 * canonical block_row_verify() runs hash-bind + PoW target on EVERY row, but
 * the expensive full Equihash solution check only on every STRIDE-th height
 * plus every height above the ROM checkpoint (the unverified tail). Keeps the
 * ~3.1M-row boot hydrate affordable while still spot-checking solutions and
 * fully checking the above-checkpoint region. */
#define BLOCKS_HYDRATE_POW_STRIDE 10000

enum bhc_bad_reason {
    BHC_BAD_SHORT_HASH = 0,     /* hash PRIMARY KEY column missing/short */
    BHC_BAD_UNUSABLE_HEADER,    /* a fixed header field / solution unusable */
    BHC_BAD_HASH_MISMATCH,      /* header re-serializes to a different PoW hash */
    BHC_BAD_HIGH_HASH,          /* stored hash fails the PoW difficulty target */
    BHC_BAD_EQUIHASH,           /* Equihash solution check failed */
};

static const char *bhc_bad_reason_name(enum bhc_bad_reason r)
{
    switch (r) {
        case BHC_BAD_SHORT_HASH:      return "short-or-missing-hash";
        case BHC_BAD_UNUSABLE_HEADER: return "unusable-header";
        case BHC_BAD_HASH_MISMATCH:   return "hash-mismatch";
        case BHC_BAD_HIGH_HASH:       return "high-hash";
        case BHC_BAD_EQUIHASH:        return "invalid-equihash-solution";
    }
    return "unknown";
}

/* One poisoned row queued for deferred purge (we must not DELETE while the
 * validate SELECT is still stepping the same table). */
struct bhc_bad_row {
    int                 height;
    uint8_t             hash[32];
    bool                has_hash;
    enum bhc_bad_reason reason;
};

/* Purge one queued poisoned row: db_block_delete by hash when the hash column
 * is usable, else db_block_delete_by_height. Names the typed blocker with
 * height+hash+reason, bumps the dumpstate counter, and emits a throttled WARN.
 * Never aborts the caller — a failed DELETE is logged and the row is still
 * counted (it will be re-attempted on a later boot). */
static void bhc_quarantine_row(struct node_db *ndb, const struct bhc_bad_row *b)
{
    char hex[65] = "(no-hash)";
    if (b->has_hash) {
        struct uint256 hh;
        memcpy(hh.data, b->hash, 32);
        uint256_get_hex(&hh, hex);
    }

    bool purged = b->has_hash
        ? db_block_delete(ndb, b->hash)
        : db_block_delete_by_height(ndb, b->height);

    atomic_fetch_add_explicit(&g_blocks_hydrate_quarantined, 1,
                              memory_order_relaxed);

    struct blocker_record rec;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "blocks-hydrate poisoned row height=%d hash=%s reason=%s: purged "
             "from `blocks`%s; height re-fetched via header sync + body_fetch, "
             "stages revalidate", b->height, hex, bhc_bad_reason_name(b->reason),
             purged ? "" : " FAILED (retry next boot)");
    if (blocker_init(&rec, BLOCKS_HYDRATE_QUARANTINE_BLOCKER_ID, "block_index",
                     BLOCKER_TRANSIENT, reason))
        (void)blocker_set(&rec);

    uint64_t reps = 0;
    if (log_throttle_should_emit(&g_blocks_hydrate_quarantine_log,
                                 (uint64_t)(uint32_t)b->height,
                                 platform_time_wall_unix(), 60, &reps)) {
        if (purged)
            LOG_WARN("block_index",
                     "blocks-hydrate: quarantined poisoned row height=%d hash=%s "
                     "reason=%s — purged, load continues (repeats=%llu)",
                     b->height, hex, bhc_bad_reason_name(b->reason),
                     (unsigned long long)reps);
        else
            LOG_WARN("block_index",
                     "blocks-hydrate: poisoned row height=%d hash=%s reason=%s — "
                     "purge FAILED (row remains, retry next boot) (repeats=%llu)",
                     b->height, hex, bhc_bad_reason_name(b->reason),
                     (unsigned long long)reps);
    }
}

/* Column order shared by the validate + insert passes of the blocks-table
 * hydrator. Keep these in lock-step with the SELECT string BLOCKS_HYDRATE_SEL. */
enum {
    BHC_HASH = 0, BHC_PREV, BHC_VERSION, BHC_MERKLE, BHC_SAPLING,
    BHC_TIME, BHC_BITS, BHC_NONCE, BHC_SOLUTION, BHC_STATUS,
    BHC_NUMTX, BHC_HEIGHT
};

#define BLOCKS_HYDRATE_SEL \
    "SELECT hash,prev_hash,version,merkle_root,sapling_root,time,bits," \
    "nonce,solution,status,num_tx,height FROM blocks ORDER BY height"

/* Reconstruct the canonical block_header from a BLOCKS_HYDRATE_SEL row so its
 * PoW hash can be recomputed and compared to the stored `hash` column (the
 * same hash-bind test engine/models/src/block.c performs on a stored row). Returns
 * false when a fixed header field is missing/short or the Equihash solution is
 * empty/oversize — every such row makes the whole hydration refuse. */
static bool blocks_row_to_header(sqlite3_stmt *s, struct block_header *out)
{
    block_header_init(out);
    out->nVersion = (int32_t)sqlite3_column_int(s, BHC_VERSION);

    const void *prev = sqlite3_column_blob(s, BHC_PREV);
    if (!prev || sqlite3_column_bytes(s, BHC_PREV) < 32)
        return false;
    memcpy(out->hashPrevBlock.data, prev, 32);

    const void *mr = sqlite3_column_blob(s, BHC_MERKLE);
    if (!mr || sqlite3_column_bytes(s, BHC_MERKLE) < 32)
        return false;
    memcpy(out->hashMerkleRoot.data, mr, 32);

    /* sapling_root is a nullable projection column; a NULL/short value leaves
     * the header field at zero, which only hash-binds for a block whose real
     * hashFinalSaplingRoot is genuinely zero (pre-Sapling). A post-Sapling row
     * with a dropped root simply fails the hash-bind check below — refused,
     * never silently accepted. */
    const void *sr = sqlite3_column_blob(s, BHC_SAPLING);
    if (sr && sqlite3_column_bytes(s, BHC_SAPLING) >= 32)
        memcpy(out->hashFinalSaplingRoot.data, sr, 32);

    out->nTime = (uint32_t)sqlite3_column_int64(s, BHC_TIME);
    out->nBits = (uint32_t)sqlite3_column_int64(s, BHC_BITS);

    const void *nn = sqlite3_column_blob(s, BHC_NONCE);
    if (!nn || sqlite3_column_bytes(s, BHC_NONCE) < 32)
        return false;
    memcpy(out->nNonce.data, nn, 32);

    int sol_len = sqlite3_column_bytes(s, BHC_SOLUTION);
    const void *sol = sqlite3_column_blob(s, BHC_SOLUTION);
    if (!sol || sol_len <= 0 || sol_len > MAX_SOLUTION_SIZE)
        return false;
    memcpy(out->nSolution, sol, (size_t)sol_len);
    out->nSolutionSize = (size_t)sol_len;
    return true;
}

/* Hydrate the in-memory block_index map from the node.db `blocks` table.
 *
 * The `--importblockindex <src>` CLI bulk-loads ~3.1M header rows into `blocks`
 * (engine/controllers/src/snapshot_controller_import.c) but writes NO flat file,
 * NO block_index_cache, and NO datadir LevelDB. So every other loader rung
 * leaves a genesis-only map on a freshly-imported datadir and the node serves
 * H*=0 until the legacy pull rescues it. This rung closes that hole.
 *
 * Validation (matches what the sibling rungs trust vs re-check): every row's
 * header is re-serialized and its PoW hash recomputed. A row whose stored
 * `hash` does not equal that recomputed value (or whose hash column / header
 * fields are unusable) is QUARANTINED per-row (J5): db_block_delete purges it
 * from `blocks`, a typed blocker names height+hash+reason, the dumpstate
 * counter increments, and the load CONTINUES with the remaining rows — the
 * purged height re-fetches via header sync + body_fetch and the stages
 * revalidate it. Only a grossly-shredded table (> BLOCKS_HYDRATE_MAX_QUARANTINE
 * poisoned rows) still refuses whole (map untouched, boot falls through to the
 * LevelDB / legacy rungs). Parent linkage is asserted structurally via the
 * pprev link pass; a quarantined height leaves a gap the link pass honestly
 * declines to bridge (the segment above re-links once the height re-fetches).
 * NOTE the imported rows carry chain_work=0 (the importer never populates it),
 * so nChainWork is recomputed from the linked pprev chain by
 * block_index_forward_pass, exactly like the flat/LevelDB rungs.
 *
 * Validity is installed HONESTLY as header-only: the entry's BLOCK_VALID level
 * is clamped to at most BLOCK_VALID_TREE and NO HAVE_DATA/HAVE_UNDO bit is set
 * (we hold no block body — bodies are fetched lazily via P2P). Higher validity
 * is never fabricated from the stored status.
 *
 * Returns .ok=true on a non-empty hydrate (even if some rows were quarantined);
 * .ok=false on an empty table, a prepare error, all-rows-poisoned (0 usable),
 * or the gross-corruption refusal (map untouched by the refusal paths). */
struct zcl_result load_block_index_from_blocks_table(struct node_db *ndb,
                                                     struct main_state *ms)
{
    if (!ndb || !ndb->open)
        return ZCL_ERR(-1, "load_block_index_from_blocks_table: null/closed db");
    if (!ms)
        return ZCL_ERR(-1, "load_block_index_from_blocks_table: null main_state");

    int64_t row_count = 0;
    sqlite3_stmt *cnt = NULL;
    if (sqlite3_prepare_v2(ndb->db, "SELECT COUNT(*) FROM blocks", -1, &cnt,
                           NULL) == SQLITE_OK && cnt) {
        if (AR_STEP_ROW_READONLY(cnt) == SQLITE_ROW)
            row_count = sqlite3_column_int64(cnt, 0);
        sqlite3_finalize(cnt);
    }
    if (row_count <= 0)
        return ZCL_ERR(-2, "load_block_index_from_blocks_table: `blocks` "
                       "table empty — nothing to hydrate");

    int64_t t0 = (int64_t)platform_time_wall_time_t();
    LOG_INFO("block_index",
             "Hydrating block index from node.db `blocks` (%lld rows)...",
             (long long)row_count);

    /* Canonical admission context (shared with the import + flat loaders):
     * chain params for the PoW target + Equihash params, and the ROM
     * checkpoint height that opens the full-Equihash budget on the tail. */
    const struct chain_params *cp = chain_params_get();
    const struct rom_state_checkpoint *rom_cp = get_rom_state_checkpoint();
    int64_t rom_checkpoint_height = rom_cp ? (int64_t)rom_cp->height : -1;

    /* ── Pass A (J5): VALIDATE every row hash-binds BEFORE touching the map,
     *    but a poisoned row NO LONGER refuses the whole table. Each bad row is
     *    QUEUED for a deferred purge (we cannot DELETE while this SELECT is
     *    still stepping the same table) and skipped; the good rows still load.
     *    A grossly-shredded table (> BLOCKS_HYDRATE_MAX_QUARANTINE bad rows)
     *    still refuses whole — localized corruption heals per-row, gross
     *    corruption is not blindly seeded. */
    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(ndb->db, BLOCKS_HYDRATE_SEL, -1, &sel, NULL)
            != SQLITE_OK || !sel)
        return ZCL_ERR(-3, "load_block_index_from_blocks_table: failed to "
                       "prepare validate SELECT over `blocks`");

    struct bhc_bad_row *bad = NULL;   /* lazily allocated on first bad row */
    int64_t bad_count = 0;
    int64_t validated = 0;
    int64_t seen = 0;
    bool gross_corruption = false;
    while (AR_STEP_ROW_READONLY(sel) == SQLITE_ROW) {
        /* 3.1M-row validate pass (full Equihash on the strided/above-
         * checkpoint subset) outlives the 2-min systemd watchdog on a cold
         * boot — pump the boot-liveness marker (the flat loader convention)
         * so a progressing hydrate is never killed as a frozen boot. */
        if (((++seen) & 0xFFF) == 0)
            boot_progress_note("block_index.blocks_hydrate_validate",
                               (uint64_t)seen, (uint64_t)row_count);
        const void *hb = sqlite3_column_blob(sel, BHC_HASH);
        int h = sqlite3_column_int(sel, BHC_HEIGHT);
        bool has_hash = (hb && sqlite3_column_bytes(sel, BHC_HASH) >= 32);
        uint8_t stored_hash[32];
        if (has_hash)
            memcpy(stored_hash, hb, 32);

        enum bhc_bad_reason reason = BHC_BAD_UNUSABLE_HEADER;
        bool bad_row = true;
        struct block_header hdr;
        if (!has_hash) {
            reason = BHC_BAD_SHORT_HASH;
        } else if (!blocks_row_to_header(sel, &hdr)) {
            reason = BHC_BAD_UNUSABLE_HEADER;
        } else if (cp) {
            /* Canonical admission (J5 upgrade): hash-bind + PoW target on every
             * row, plus the full Equihash solution check on the strided /
             * above-checkpoint subset — the SAME strength the import + flat
             * loaders admit at, via the shared block_row_verify() primitive. */
            bool full_check =
                (h > 0 && (h % BLOCKS_HYDRATE_POW_STRIDE) == 0) ||
                (rom_checkpoint_height >= 0 && h > rom_checkpoint_height);
            switch (block_row_verify(stored_hash, hdr.nBits, &hdr, cp,
                                     full_check)) {
                case BLOCK_ROW_VERIFY_OK:
                    bad_row = false;
                    break;
                case BLOCK_ROW_VERIFY_HASH_BIND_MISMATCH:
                    reason = BHC_BAD_HASH_MISMATCH;
                    break;
                case BLOCK_ROW_VERIFY_HIGH_HASH:
                    reason = BHC_BAD_HIGH_HASH;
                    break;
                case BLOCK_ROW_VERIFY_BAD_EQUIHASH:
                    reason = BHC_BAD_EQUIHASH;
                    break;
                case BLOCK_ROW_VERIFY_NO_PARAMS:
                    reason = BHC_BAD_HASH_MISMATCH; /* unreachable: cp != NULL */
                    break;
            }
        } else {
            /* Chain params unavailable (not expected this late in boot): fall
             * back to the pre-J5 hash-bind-only admission so a missing params
             * table cannot quarantine the whole chain. */
            struct uint256 computed;
            block_header_get_hash(&hdr, &computed);
            if (memcmp(computed.data, stored_hash, 32) != 0)
                reason = BHC_BAD_HASH_MISMATCH;
            else
                bad_row = false;
        }

        if (!bad_row) {
            validated++;
            continue;
        }

        /* Queue the poisoned row for deferred purge. */
        if (!bad) {
            bad = zcl_malloc(
                (size_t)BLOCKS_HYDRATE_MAX_QUARANTINE * sizeof(*bad),
                "blocks_table quarantine list");
            if (!bad) {
                sqlite3_finalize(sel);
                return ZCL_ERR(-7, "load_block_index_from_blocks_table: OOM for "
                               "quarantine list");
            }
        }
        if (bad_count >= BLOCKS_HYDRATE_MAX_QUARANTINE) {
            gross_corruption = true;
            break;
        }
        bad[bad_count].height = h;
        bad[bad_count].has_hash = has_hash;
        if (has_hash)
            memcpy(bad[bad_count].hash, stored_hash, 32);
        bad[bad_count].reason = reason;
        bad_count++;
    }
    sqlite3_finalize(sel);
    sel = NULL;

    if (gross_corruption) {
        free(bad);
        LOG_WARN("block_index",
                 "blocks-hydrate: > %d poisoned rows — grossly-shredded "
                 "`blocks` table, refusing whole hydration (map untouched)",
                 BLOCKS_HYDRATE_MAX_QUARANTINE);
        struct blocker_record rec;
        char reason[BLOCKER_REASON_MAX];
        snprintf(reason, sizeof(reason),
                 "blocks-hydrate refused: > %d poisoned `blocks` rows "
                 "(grossly shredded); per-row quarantine declined, "
                 "operator/re-import needed", BLOCKS_HYDRATE_MAX_QUARANTINE);
        if (blocker_init(&rec, BLOCKS_HYDRATE_QUARANTINE_BLOCKER_ID,
                         "block_index", BLOCKER_PERMANENT, reason))
            (void)blocker_set(&rec);
        return ZCL_ERR(-8, "load_block_index_from_blocks_table: > %d poisoned "
                       "rows — refusing", BLOCKS_HYDRATE_MAX_QUARANTINE);
    }

    /* ── Quarantine phase: purge each queued poisoned row now that the
     *    validate SELECT is finalized. Purge before Pass B re-SELECTs so the
     *    poisoned rows are already gone from `blocks`. */
    for (int64_t i = 0; i < bad_count; i++)
        bhc_quarantine_row(ndb, &bad[i]);
    free(bad);
    bad = NULL;

    if (validated == 0)
        return ZCL_ERR(-6, "load_block_index_from_blocks_table: 0 usable rows "
                       "(quarantined %lld poisoned)", (long long)bad_count);

    /* ── Pass B: INSERT (rows are hash-bound now). ORDER BY height means the
     *    collected array is height-ASC, so pprev is always resolvable in the
     *    link pass and the forward pass sees each parent before its child. */
    struct block_index **sorted = zcl_malloc(
        (size_t)validated * sizeof(*sorted), "blocks_table hydrate sorted");
    if (!sorted)
        return ZCL_ERR(-7, "load_block_index_from_blocks_table: OOM for %lld "
                       "sorted pointers", (long long)validated);

    if (sqlite3_prepare_v2(ndb->db, BLOCKS_HYDRATE_SEL, -1, &sel, NULL)
            != SQLITE_OK || !sel) {
        free(sorted);
        return ZCL_ERR(-3, "load_block_index_from_blocks_table: failed to "
                       "prepare insert SELECT over `blocks`");
    }

    size_t n = 0;
    while (AR_STEP_ROW_READONLY(sel) == SQLITE_ROW && n < (size_t)validated) {
        const void *hb = sqlite3_column_blob(sel, BHC_HASH);
        if (!hb || sqlite3_column_bytes(sel, BHC_HASH) < 32)
            continue;   /* validated in pass A; defensive */
        struct uint256 hh;
        memcpy(hh.data, hb, 32);
        struct block_index *bi = chainstate_insert_block_index(
            (struct chainstate *)ms, &hh);
        if (!bi)
            continue;

        bi->nHeight  = sqlite3_column_int(sel, BHC_HEIGHT);
        bi->nVersion = (int32_t)sqlite3_column_int(sel, BHC_VERSION);
        bi->nTime    = (uint32_t)sqlite3_column_int64(sel, BHC_TIME);
        bi->nBits    = (uint32_t)sqlite3_column_int64(sel, BHC_BITS);
        {
            int nt = sqlite3_column_int(sel, BHC_NUMTX);
            if (nt > 0)
                bi->nTx = (unsigned int)nt;
        }

        const void *mr = sqlite3_column_blob(sel, BHC_MERKLE);
        if (mr && sqlite3_column_bytes(sel, BHC_MERKLE) >= 32)
            memcpy(bi->hashMerkleRoot.data, mr, 32);
        const void *sr = sqlite3_column_blob(sel, BHC_SAPLING);
        if (sr && sqlite3_column_bytes(sel, BHC_SAPLING) >= 32)
            memcpy(bi->hashFinalSaplingRoot.data, sr, 32);
        const void *nn = sqlite3_column_blob(sel, BHC_NONCE);
        if (nn && sqlite3_column_bytes(sel, BHC_NONCE) >= 32)
            memcpy(bi->nNonce.data, nn, 32);

        /* HONEST validity: we verified the header hash-binds (and the link
         * pass verifies parent linkage), but we hold NO block body and have
         * NOT checked tx/script/context validity. Clamp the BLOCK_VALID level
         * to at most BLOCK_VALID_TREE and assert NO HAVE_DATA/HAVE_UNDO — the
         * node fetches bodies lazily via P2P. Never fabricate a higher
         * validity than the stored row, and never above TREE. */
        unsigned int stored = (unsigned int)sqlite3_column_int(sel, BHC_STATUS);
        unsigned int level = stored & (unsigned int)BLOCK_VALID_MASK;
        if (level > (unsigned int)BLOCK_VALID_TREE)
            level = (unsigned int)BLOCK_VALID_TREE;
        bi->nStatus = level;   /* header-only: no HAVE bits, no FAILED bits */

        sorted[n++] = bi;
        if ((n & 0xFFF) == 0)
            boot_progress_note("block_index.blocks_hydrate_insert",
                               (uint64_t)n, (uint64_t)validated);
    }
    sqlite3_finalize(sel);
    sel = NULL;

    /* ── Pass C: link pprev by prev_hash (both endpoints now in the map). */
    if (sqlite3_prepare_v2(ndb->db, "SELECT hash,prev_hash FROM blocks",
                           -1, &sel, NULL) == SQLITE_OK && sel) {
        size_t linked = 0;
        while (AR_STEP_ROW_READONLY(sel) == SQLITE_ROW) {
            if (((++linked) & 0xFFF) == 0)
                boot_progress_note("block_index.blocks_hydrate_link",
                                   (uint64_t)linked, (uint64_t)row_count);
            const void *h = sqlite3_column_blob(sel, 0);
            const void *ph = sqlite3_column_blob(sel, 1);
            if (!h || !ph)
                continue;
            if (sqlite3_column_bytes(sel, 0) < 32 ||
                sqlite3_column_bytes(sel, 1) < 32)
                continue;
            struct uint256 hash, prev;
            memcpy(hash.data, h, 32);
            memcpy(prev.data, ph, 32);
            struct block_index *bi = block_map_find(&ms->map_block_index, &hash);
            struct block_index *pprev =
                block_map_find(&ms->map_block_index, &prev);
            if (bi && pprev)
                bi->pprev = pprev;
        }
        sqlite3_finalize(sel);
    }

    /* Post-load, identical to the LevelDB rung: recompute nChainWork/nChainTx/
     * skip from the linked pprev chain (the imported chain_work column is
     * zero), then promote the best header so active_chain_tip() is non-NULL
     * over the just-hydrated map and header sync anchors above genesis. */
    block_index_forward_pass(sorted, n);
    promote_best_header_after_load(ms, sorted, n);
    free(sorted);

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;
    LOG_INFO("block_index",
             "Block index `blocks` hydrate: %zu header-only entries in %llds",
             n, (long long)elapsed);

    if (n == 0)
        return ZCL_ERR(-6, "load_block_index_from_blocks_table: 0 entries "
                       "hydrated");
    return ZCL_OK;
}
