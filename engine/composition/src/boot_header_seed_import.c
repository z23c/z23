/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_header_seed_import.c — see config/boot_header_seed_import.h for the
 * contract. Consumes services/block_index_loader.h (the shared, verified flat
 * loader) + chain/checkpoints.h; defines no consensus predicate. */

#include "config/boot_header_seed_import.h"

#include "chain/chain.h"                        /* block_index, status helpers */
#include "chain/checkpoints.h"                  /* get_sha3_utxo_checkpoint */
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
    HSI_STAGE_DST_PATH_LONG, /* root path did not fit PATH_MAX */
    HSI_STAGE_ROOT_PRESENT,  /* root copy already ladder-owned — no-op */
    HSI_STAGE_RENAME_FAILED  /* rename failed; errno holds the reason */
};

/* Move the artifact to the datadir root so (a) the flat loader finds it and
 * (b) the rom_seed scan re-serves it to the next fresh node. If a root
 * block_index.bin already exists the boot ladder already consumed it — leave
 * both in place and no-op. */
static enum hsi_stage_result
hsi_stage_artifact_at_root(const char *datadir, const char *src, char *dst,
                           size_t dst_size)
{
    int dn = snprintf(dst, dst_size, "%s/block_index.bin", datadir);
    if (dn < 0 || (size_t)dn >= dst_size)
        return HSI_STAGE_DST_PATH_LONG;
    struct stat st;
    if (stat(dst, &st) == 0)
        return HSI_STAGE_ROOT_PRESENT;
    if (rename(src, dst) != 0)
        return HSI_STAGE_RENAME_FAILED;
    return HSI_STAGE_MOVED;
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

    /* Never clobber an already-populated header index (only the fresh
     * instant-on case seeds from a peer artifact). */
    size_t existing = block_map_count(&ms->map_block_index);
    if (existing > HSI_MAX_EXISTING_ENTRIES) {
        LOG_INFO(HSI_SUBSYS,
                 "header-seed import skipped: header index already populated "
                 "(%zu entries) — the artifact is only for a fresh node",
                 existing);
        return false;
    }

    char dst[PATH_MAX];
    enum hsi_stage_result staged =
        hsi_stage_artifact_at_root(datadir, src, dst, sizeof(dst));
    if (staged == HSI_STAGE_ROOT_PRESENT) {
        LOG_INFO(HSI_SUBSYS,
                 "header-seed import skipped: %s already present (ladder-owned)",
                 dst);
        return false;
    }
    if (staged == HSI_STAGE_RENAME_FAILED) {
        hsi_name_blocker("header_seed.stage_failed",
                         "could not move downloaded block_index.bin to datadir "
                         "root before import");
        LOG_WARN(HSI_SUBSYS, "header-seed import: rename %s -> %s failed: %s",
                 src, dst, strerror(errno));
        return false;
    }
    if (staged != HSI_STAGE_MOVED)
        return false;

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
