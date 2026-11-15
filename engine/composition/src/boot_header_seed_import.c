/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_header_seed_import.c — see config/boot_header_seed_import.h for the
 * contract. Consumes services/block_index_loader.h (the shared, verified flat
 * loader) + chain/checkpoints.h; defines no consensus predicate. */

#include "config/boot_header_seed_import.h"

#include "chain/chain.h"                        /* block_index, status helpers */
#include "chain/checkpoints.h"                  /* get_sha3_utxo_checkpoint */
#include "config/boot_consensus_bundle_marker.h" /* sovereign install marker */
#include "services/block_index_loader.h"        /* load_block_index_flat + promote */
#include "services/sync_benchmark_service.h"    /* SYNC_BENCH_HEADERS phase */
#include "validation/chainstate.h"              /* block_map_next / _count */
#include "validation/main_state.h"              /* struct main_state */
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/result.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HSI_SUBSYS "boot_header_seed"

/* Only seed a FRESH/near-empty header map. A populated index (a node that has
 * already synced or imported headers) must never be clobbered by a peer-served
 * artifact — above this many entries we no-op. A ladder-seeded fresh node holds
 * just genesis (map size 1). */
#define HSI_MAX_EXISTING_ENTRIES 1024u

/* The flat loader's process-lifetime arena scratch file (bil_arena_file_map,
 * engine/services/src/block_index_loader.c). It opens this path O_TRUNC and
 * maps it MAP_SHARED; the ladder's own flat load of a stub root file left the
 * stub's rows living in that mapping. */
#define HSI_LOADER_ARENA_NAME ".block_index.arena"

/* True when a row above genesis holds this node's own body or undo data. */
static bool hsi_index_has_local_body(const struct main_state *ms)
{
    size_t iter = 0;
    struct block_index *pi = NULL;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &pi)) {
        if (pi && pi->nHeight > 0 &&
            (block_index_status_load(pi) &
             (unsigned int)(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO)) != 0)
            return true;
    }
    return false;
}

/* True when the active chain tip is above genesis. */
static bool hsi_tip_above_genesis(const struct main_state *ms)
{
    const struct block_index *tip = active_chain_tip(&ms->chain_active);
    return tip && tip->nHeight > 0;
}

enum boot_header_seed_index_verdict
boot_header_seed_index_verdict(const struct main_state *ms, bool root_present)
{
    size_t rows = ms ? block_map_count(&ms->map_block_index) : 0;
    if (rows == 0)
        return root_present ? BOOT_HEADER_SEED_INDEX_NOT_LOADED
                            : BOOT_HEADER_SEED_INDEX_FRESH;
    if (rows > HSI_MAX_EXISTING_ENTRIES)
        return BOOT_HEADER_SEED_INDEX_POPULATED;
    if (hsi_index_has_local_body(ms))
        return BOOT_HEADER_SEED_INDEX_BODY_DATA;
    if (hsi_tip_above_genesis(ms))
        return BOOT_HEADER_SEED_INDEX_TIP_ABOVE_GENESIS;
    return root_present ? BOOT_HEADER_SEED_INDEX_STUB
                        : BOOT_HEADER_SEED_INDEX_FRESH;
}

bool boot_header_seed_index_verdict_allows(enum boot_header_seed_index_verdict v)
{
    return v == BOOT_HEADER_SEED_INDEX_FRESH || v == BOOT_HEADER_SEED_INDEX_STUB;
}

const char *
boot_header_seed_index_verdict_reason(enum boot_header_seed_index_verdict v)
{
    switch (v) {
    case BOOT_HEADER_SEED_INDEX_FRESH:
        return "fresh node: no local header index to keep";
    case BOOT_HEADER_SEED_INDEX_STUB:
        return "the local header index is a replaceable stub (at most 1024 "
               "header-only rows, tip at genesis or absent)";
    case BOOT_HEADER_SEED_INDEX_NOT_LOADED:
        return "the root block_index.bin loaded no rows, so nothing shows it "
               "is a stub";
    case BOOT_HEADER_SEED_INDEX_POPULATED:
        return "the header index is already populated (more than 1024 rows)";
    case BOOT_HEADER_SEED_INDEX_BODY_DATA:
        return "a row above genesis holds this node's own block body data";
    case BOOT_HEADER_SEED_INDEX_TIP_ABOVE_GENESIS:
        return "the active chain tip is above genesis";
    }
    return "unknown header index verdict";
}

/* Name a typed, retryable blocker (never a fatal abort — the header chain still
 * arrives via normal P2P; the artifact was an acceleration, not a dependency). */
static void hsi_name_blocker(const char *id, const char *reason)
{
    struct blocker_record b;
    /* blocker-id: header_seed.* */
    if (blocker_init(&b, id, HSI_SUBSYS, BLOCKER_TRANSIENT, reason))
        (void)blocker_set(&b);
}

/* True when the import request is unusable: no datadir, an empty datadir
 * string, or no main_state. */
static bool hsi_import_args_invalid(const char *datadir,
                                    const struct main_state *ms)
{
    return !datadir || !datadir[0] || !ms;
}

/* Probe outcome for the downloaded artifact under <datadir>/bundles. */
enum hsi_artifact_probe {
    HSI_ARTIFACT_PRESENT = 0, /* path built and the file exists */
    HSI_ARTIFACT_PATH_LONG,   /* path did not fit PATH_MAX */
    HSI_ARTIFACT_ABSENT       /* nothing downloaded — no-op */
};

/* Build the downloaded-artifact path and stat it; never logs — the caller
 * no-ops on any outcome other than HSI_ARTIFACT_PRESENT. */
static enum hsi_artifact_probe
hsi_locate_downloaded_artifact(const char *datadir, char *src, size_t src_size)
{
    int sn = snprintf(src, src_size, "%s/bundles/block_index.bin", datadir);
    if (sn < 0 || (size_t)sn >= src_size)
        return HSI_ARTIFACT_PATH_LONG;
    struct stat st;
    if (stat(src, &st) != 0)
        return HSI_ARTIFACT_ABSENT; /* nothing downloaded — no-op */
    return HSI_ARTIFACT_PRESENT;
}

/* Outcome of moving the downloaded artifact to the datadir root. */
enum hsi_stage_result {
    HSI_STAGE_MOVED = 0,     /* rename succeeded — the import may proceed */
    HSI_STAGE_REPLACED_STUB, /* rename atomically replaced a stub root file */
    HSI_STAGE_ARENA_BUSY,    /* the loader arena name could not be released */
    HSI_STAGE_RENAME_FAILED  /* rename failed; errno holds the reason */
};

/* Release the loader arena's NAME before a second in-process flat load. The
 * loader opens the arena path O_TRUNC and maps it MAP_SHARED, so loading the
 * artifact into a map that the ladder filled from a stub root file would
 * truncate the file still backing the stub's rows (zeroing them under the
 * live hash map) and alias the new arena over them. Unlinking the name leaves
 * the stub's mapping on its own inode (a mapping pins its inode) and gives the
 * new load a fresh file. Absent (ENOENT) is fine: no arena backs the stub. */
static bool hsi_release_loader_arena_name(const char *datadir)
{
    char arena[PATH_MAX];
    int n = snprintf(arena, sizeof(arena), "%s/" HSI_LOADER_ARENA_NAME, datadir);
    if (n < 0 || (size_t)n >= sizeof(arena))
        return false;
    return unlink(arena) == 0 || errno == ENOENT;
}

/* Move the artifact to the datadir root so (a) the flat loader finds it and
 * (b) the rom_seed scan re-serves it to the next fresh node. A present root
 * file reaches here only when it is a replaceable stub: rename(2) replaces it
 * atomically, so the root path always names either the stub or the whole
 * artifact. */
static enum hsi_stage_result
hsi_stage_artifact_at_root(const char *datadir, const char *src,
                           const char *dst, bool replace_stub)
{
    if (replace_stub && !hsi_release_loader_arena_name(datadir))
        return HSI_STAGE_ARENA_BUSY;
    if (rename(src, dst) != 0)
        return HSI_STAGE_RENAME_FAILED;
    return replace_stub ? HSI_STAGE_REPLACED_STUB : HSI_STAGE_MOVED;
}

/* Where the root block_index.bin lives and whether it is present; false when
 * the path does not fit. */
static bool hsi_root_probe(const char *datadir, char *dst, size_t dst_size,
                           bool *present)
{
    int dn = snprintf(dst, dst_size, "%s/block_index.bin", datadir);
    if (dn < 0 || (size_t)dn >= dst_size)
        return false;
    struct stat st;
    *present = stat(dst, &st) == 0;
    return true;
}

/* May the seed land on this datadir? Logs one INFO line naming the reason
 * whenever it may not. */
static bool hsi_seed_may_land(const char *datadir, const struct main_state *ms,
                              const char *dst, bool root_present)
{
    size_t existing = block_map_count(&ms->map_block_index);
    if (boot_consensus_bundle_marker_exists(datadir)) {
        LOG_INFO(HSI_SUBSYS,
                 "header-seed import skipped: the datadir holds the sovereign "
                 "install marker (%zu header entries) — installed state is "
                 "never re-seeded", existing);
        return false;
    }
    enum boot_header_seed_index_verdict v =
        boot_header_seed_index_verdict(ms, root_present);
    if (boot_header_seed_index_verdict_allows(v))
        return true;
    if (v == BOOT_HEADER_SEED_INDEX_POPULATED && !root_present) {
        LOG_INFO(HSI_SUBSYS,
                 "header-seed import skipped: header index already populated "
                 "(%zu entries) — the artifact is only for a fresh node",
                 existing);
        return false;
    }
    LOG_INFO(HSI_SUBSYS,
             "header-seed import skipped: %s %s (%zu header entries): %s",
             dst, root_present ? "is present" : "is absent", existing,
             boot_header_seed_index_verdict_reason(v));
    return false;
}

/* Name the staging failure; the downloaded artifact stays in bundles/. */
static void hsi_report_stage_failure(enum hsi_stage_result staged,
                                     const char *src, const char *dst)
{
    int err = errno; /* before the blocker write can disturb it */
    if (staged == HSI_STAGE_ARENA_BUSY) {
        hsi_name_blocker("header_seed.stage_failed",
                         "could not release the block-index loader arena name "
                         "before replacing the stub header index");
        LOG_WARN(HSI_SUBSYS, "header-seed import: cannot unlink the loader "
                 "arena beside %s (%s) — the stub header index is kept",
                 dst, strerror(err));
        return;
    }
    hsi_name_blocker("header_seed.stage_failed",
                     "could not move downloaded block_index.bin to datadir "
                     "root before import");
    LOG_WARN(HSI_SUBSYS, "header-seed import: rename %s -> %s failed: %s",
             src, dst, strerror(err));
}

/* Header-only clamp for the UNTRUSTED artifact: strip HAVE_DATA/HAVE_UNDO,
 * clear stale file positions, and clamp VALID level to <= BLOCK_VALID_TREE
 * on every non-genesis row. The seeder's persisted body/script validity and
 * data availability are NEVER trusted — every body is re-fetched and fully
 * re-validated (full Equihash) as the reducer folds forward. The flat
 * loader already reconciled the persisted FAILED bits; this closes the
 * remaining "trust n_status verbatim" gap for the artifact path. */
static size_t hsi_clamp_rows_header_only(struct main_state *ms)
{
    size_t iter = 0;
    struct block_index *pi;
    size_t clamped = 0;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &pi)) {
        if (!pi || pi->nHeight <= 0)
            continue; /* leave genesis exactly as the ladder seated it */
        block_index_status_clear_bits(pi, (unsigned int)(BLOCK_HAVE_DATA |
                                                         BLOCK_HAVE_UNDO));
        block_index_disk_pos_store(pi, -1, 0);
        unsigned int lvl = block_index_status_load(pi) & (unsigned int)BLOCK_VALID_MASK;
        if (lvl > (unsigned int)BLOCK_VALID_TREE)
            (void)block_index_status_set_valid_level(pi, BLOCK_VALID_TREE);
        clamped++;
    }
    return clamped;
}

/* Outcome of publishing the imported header frontier. */
enum hsi_promote_status {
    HSI_PROMOTE_PUBLISHED = 0, /* promote pass ran over the loaded rows */
    HSI_PROMOTE_ALLOC_FAILED   /* row-pointer array could not be allocated */
};

/* Publish the header frontier so the checkpoint-bundle install gate and the
 * getheaders locator see the imported chain (the whole point: no serial
 * header crawl before install). promote_best_header_after_load picks the
 * max-chainwork non-FAILED header regardless of array order. */
static enum hsi_promote_status
hsi_publish_loaded_frontier(struct main_state *ms, size_t count)
{
    struct block_index **sorted =
        zcl_malloc(count * sizeof(*sorted), "hdr_seed_promote");
    if (!sorted)
        return HSI_PROMOTE_ALLOC_FAILED;
    size_t idx = 0, it = 0;
    struct block_index *p;
    while (block_map_next(&ms->map_block_index, &it, NULL, &p))
        if (p && idx < count)
            sorted[idx++] = p;
    promote_best_header_after_load(ms, sorted, idx);
    free(sorted);
    return HSI_PROMOTE_PUBLISHED;
}

/* The blocker reason for a rejected flat load: the result's own message when
 * it has one, else the fixed fallback. */
static const char *hsi_flat_load_failure_reason(const struct zcl_result *r)
{
    return r->message[0]
        ? r->message
        : "load_block_index_flat rejected the header seed";
}

/* True when the imported chain holds the baked checkpoint block hash at the
 * checkpoint height; *height_out always receives cp->height, or -1 when
 * there is no checkpoint. */
static bool hsi_chain_owns_baked_checkpoint(const struct sha3_utxo_checkpoint *cp,
                                            struct main_state *ms,
                                            int *height_out)
{
    *height_out = cp ? cp->height : -1;
    bool owns_ckpt = false;
    if (cp && cp->height >= 0 && ms->pindex_best_header &&
        ms->pindex_best_header->nHeight >= cp->height) {
        struct block_index *at =
            block_index_get_ancestor(ms->pindex_best_header, (int)cp->height);
        owns_ckpt = at && at->phashBlock &&
                    memcmp(at->phashBlock->data, cp->block_hash, 32) == 0;
    }
    return owns_ckpt;
}

bool boot_header_seed_import_maybe(const char *datadir, struct main_state *ms)
{
    if (hsi_import_args_invalid(datadir, ms))
        return false;
    if (getenv("ZCL_NO_BUNDLE_FETCH"))
        return false;

    /* The downloaded, content-verified artifact. */
    char src[PATH_MAX];
    if (hsi_locate_downloaded_artifact(datadir, src, sizeof(src)) !=
        HSI_ARTIFACT_PRESENT)
        return false;

    /* zcl.sync_benchmark.v1: the artifact is present, so this boot is genuinely
     * attempting a header-seed import — arm the phase. A no-op boot (the
     * stat-miss case above) never begins it, so the receipt never claims a
     * headers phase for a boot that never tried one. */
    sync_benchmark_phase_begin(SYNC_BENCH_HEADERS);

    /* Never clobber a header index this node built (only a fresh node, or the
     * header-only stub an interrupted first boot left at the root, is seeded
     * from a peer artifact) and never re-seed sovereign installed state. */
    char dst[PATH_MAX];
    bool root_present = false;
    if (!hsi_root_probe(datadir, dst, sizeof(dst), &root_present))
        return false;
    if (!hsi_seed_may_land(datadir, ms, dst, root_present))
        return false;

    enum hsi_stage_result staged =
        hsi_stage_artifact_at_root(datadir, src, dst, root_present);
    if (staged == HSI_STAGE_RENAME_FAILED || staged == HSI_STAGE_ARENA_BUSY) {
        hsi_report_stage_failure(staged, src, dst);
        return false;
    }
    if (staged == HSI_STAGE_REPLACED_STUB)
        LOG_INFO(HSI_SUBSYS,
                 "header-seed import: replaced the stub header index at %s "
                 "(%zu header-only entries, tip at genesis or absent) with the "
                 "downloaded seed — importing it as on a fresh node",
                 dst, block_map_count(&ms->map_block_index));

    /* Load via the shared verified flat loader: embedded SHA3 re-verify,
     * per-row PoW-target admission (block_row_verify → CheckProofOfWork) with
     * per-row quarantine, persisted-FAILED-bit reconcile against the baked ROM
     * checkpoint, pprev link, and the canonical forward pass (nChainWork/skip).
     * Genesis (already in the ladder-seeded map) is deduped; header entries
     * link pprev to it by hash. */
    struct zcl_result r = load_block_index_flat(datadir, ms);
    if (!r.ok) {
        sync_benchmark_phase_end(SYNC_BENCH_HEADERS);
        hsi_name_blocker("header_seed.load_failed",
                         hsi_flat_load_failure_reason(&r));
        LOG_WARN(HSI_SUBSYS,
                 "header-seed import: flat load rejected the artifact (%s) — "
                 "falling back to P2P header sync", r.message);
        return false;
    }

    size_t clamped = hsi_clamp_rows_header_only(ms);

    size_t count = block_map_count(&ms->map_block_index);
    if (hsi_publish_loaded_frontier(ms, count) == HSI_PROMOTE_ALLOC_FAILED)
        LOG_WARN(HSI_SUBSYS, "header-seed import: promote alloc failed (%zu "
                 "entries) — pindex_best_header publish may lag", count);

    /* Persist the clamped map NOW. The on-disk artifact is otherwise still
     * the seeder's original bytes, and the NEXT boot's block-index ladder
     * (rung "flat") loads <datadir>/block_index.bin VERBATIM — the header-only
     * clamp above lives only in RAM on this import path. A self-respawn before
     * any shutdown save (the checkpoint_bundle_install_ready arm-and-respawn)
     * would then re-admit the seeder's HAVE_DATA + (nFile, nDataPos) as this
     * node's own warm cache, and every have-data-gated walker read-storms blk
     * files this node never wrote (measured: ~1.3M pread/s on an absent
     * blk00049.dat, wedging a supervised tick child). Saving here makes the
     * clamp durable before the artifact can serve as the next boot's flat
     * cache; the save re-encodes the hash-bound anchor header (the checkpoint
     * solution the install binds) from the in-memory map. */
    save_block_index_flat(datadir, ms);

    /* Checkpoint-ownership check: does the imported chain own the baked
     * checkpoint block hash? This is the exact precondition the bundle install
     * defers on (consensus_state_checkpoint_header_ready). If the artifact does
     * NOT bind it (a stale/forged seed), the below-checkpoint headers still seed
     * the locator, but the install must wait for the real checkpoint header via
     * P2P — name a typed blocker rather than let the install silently never
     * arm. */
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    int ckpt_height = -1;
    bool owns_ckpt = hsi_chain_owns_baked_checkpoint(cp, ms, &ckpt_height);
    int frontier = ms->pindex_best_header ? ms->pindex_best_header->nHeight : -1;
    if (owns_ckpt) {
        LOG_INFO(HSI_SUBSYS,
                 "header-seed import: %zu entries loaded, frontier h=%d, "
                 "%zu rows clamped header-only — chain OWNS the baked checkpoint "
                 "(h=%d): the checkpoint-bundle install can arm this boot",
                 count, frontier, clamped, cp->height);
    } else {
        hsi_name_blocker("header_seed.checkpoint_unbound",
                         "imported header seed does not own the baked checkpoint "
                         "block hash — bundle install waits on the checkpoint "
                         "header via P2P");
        LOG_WARN(HSI_SUBSYS,
                 "header-seed import: %zu entries loaded, frontier h=%d, but the "
                 "chain does NOT own the baked checkpoint (h=%d) — headers seed "
                 "the locator; install defers to the P2P-supplied checkpoint",
                 count, frontier, ckpt_height);
    }
    sync_benchmark_phase_end(SYNC_BENCH_HEADERS);
    return true;
}
