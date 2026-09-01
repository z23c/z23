/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_header_seed_import.c — see config/boot_header_seed_import.h for the
 * contract. Consumes services/block_index_loader.h (the shared, verified flat
 * loader) + chain/checkpoints.h; defines no consensus predicate. */

#include "config/boot_header_seed_import.h"

#include "chain/chain.h"                        /* block_index, status helpers */
#include "chain/checkpoints.h"                  /* get_sha3_utxo_checkpoint */
#include "services/block_index_loader.h"        /* load_block_index_flat + promote */
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

bool boot_header_seed_import_maybe(const char *datadir, struct main_state *ms)
{
    if (!datadir || !datadir[0] || !ms)
        return false;
    if (getenv("ZCL_NO_BUNDLE_FETCH"))
        return false;

    /* The downloaded, content-verified artifact. */
    char src[PATH_MAX];
    int sn = snprintf(src, sizeof(src), "%s/bundles/block_index.bin", datadir);
    if (sn < 0 || (size_t)sn >= sizeof(src))
        return false;
    struct stat st;
    if (stat(src, &st) != 0)
        return false; /* nothing downloaded — no-op */

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

    /* Move the artifact to the datadir root so (a) the flat loader finds it and
     * (b) the rom_seed scan re-serves it to the next fresh node. If a root
     * block_index.bin already exists the boot ladder already consumed it — leave
     * both in place and no-op. */
    char dst[PATH_MAX];
    int dn = snprintf(dst, sizeof(dst), "%s/block_index.bin", datadir);
    if (dn < 0 || (size_t)dn >= sizeof(dst))
        return false;
    if (stat(dst, &st) == 0) {
        LOG_INFO(HSI_SUBSYS,
                 "header-seed import skipped: %s already present (ladder-owned)",
                 dst);
        return false;
    }
    if (rename(src, dst) != 0) {
        hsi_name_blocker("header_seed.stage_failed",
                         "could not move downloaded block_index.bin to datadir "
                         "root before import");
        LOG_WARN(HSI_SUBSYS, "header-seed import: rename %s -> %s failed: %s",
                 src, dst, strerror(errno));
        return false;
    }

    /* Load via the shared verified flat loader: embedded SHA3 re-verify,
     * per-row PoW-target admission (block_row_verify → CheckProofOfWork) with
     * per-row quarantine, persisted-FAILED-bit reconcile against the baked ROM
     * checkpoint, pprev link, and the canonical forward pass (nChainWork/skip).
     * Genesis (already in the ladder-seeded map) is deduped; header entries
     * link pprev to it by hash. */
    struct zcl_result r = load_block_index_flat(datadir, ms);
    if (!r.ok) {
        hsi_name_blocker("header_seed.load_failed", r.message[0] ? r.message
                         : "load_block_index_flat rejected the header seed");
        LOG_WARN(HSI_SUBSYS,
                 "header-seed import: flat load rejected the artifact (%s) — "
                 "falling back to P2P header sync", r.message);
        return false;
    }

    /* Header-only clamp for the UNTRUSTED artifact: strip HAVE_DATA/HAVE_UNDO,
     * clear stale file positions, and clamp VALID level to <= BLOCK_VALID_TREE
     * on every non-genesis row. The seeder's persisted body/script validity and
     * data availability are NEVER trusted — every body is re-fetched and fully
     * re-validated (full Equihash) as the reducer folds forward. The flat
     * loader already reconciled the persisted FAILED bits; this closes the
     * remaining "trust n_status verbatim" gap for the artifact path. */
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

    /* Publish the header frontier so the checkpoint-bundle install gate and the
     * getheaders locator see the imported chain (the whole point: no serial
     * header crawl before install). promote_best_header_after_load picks the
     * max-chainwork non-FAILED header regardless of array order. */
    size_t count = block_map_count(&ms->map_block_index);
    struct block_index **sorted =
        zcl_malloc(count * sizeof(*sorted), "hdr_seed_promote");
    if (sorted) {
        size_t idx = 0, it = 0;
        struct block_index *p;
        while (block_map_next(&ms->map_block_index, &it, NULL, &p))
            if (p && idx < count)
                sorted[idx++] = p;
        promote_best_header_after_load(ms, sorted, idx);
        free(sorted);
    } else {
        LOG_WARN(HSI_SUBSYS, "header-seed import: promote alloc failed (%zu "
                 "entries) — pindex_best_header publish may lag", count);
    }

    /* Checkpoint-ownership check: does the imported chain own the baked
     * checkpoint block hash? This is the exact precondition the bundle install
     * defers on (consensus_state_checkpoint_header_ready). If the artifact does
     * NOT bind it (a stale/forged seed), the below-checkpoint headers still seed
     * the locator, but the install must wait for the real checkpoint header via
     * P2P — name a typed blocker rather than let the install silently never
     * arm. */
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    bool owns_ckpt = false;
    if (cp && cp->height >= 0 && ms->pindex_best_header &&
        ms->pindex_best_header->nHeight >= cp->height) {
        struct block_index *at =
            block_index_get_ancestor(ms->pindex_best_header, (int)cp->height);
        owns_ckpt = at && at->phashBlock &&
                    memcmp(at->phashBlock->data, cp->block_hash, 32) == 0;
    }

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
                 count, frontier, cp ? cp->height : -1);
    }
    return true;
}
