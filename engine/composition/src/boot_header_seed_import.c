/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_header_seed_import.c — see config/boot_header_seed_import.h for the
 * contract. Consumes services/block_index_loader.h (the shared, verified flat
 * loader) + chain/checkpoints.h; defines no consensus predicate. */

#include "config/boot_header_seed_import.h"

#include "chain/chain.h"                        /* block_index, status helpers */
#include "chain/checkpoints.h"                  /* get_sha3_utxo_checkpoint */
#include "core/arith_uint256.h"                 /* chainwork ranking */
#include "config/boot_consensus_bundle_marker.h" /* sovereign install marker */
#include "services/block_index_loader.h"        /* load_block_index_flat + promote */
#include "services/island_anchor.h"             /* compiled rung chainwork */
#include "services/sync_benchmark_service.h"    /* SYNC_BENCH_HEADERS phase */
#include "validation/chainstate.h"              /* block_map_next / _count */
#include "validation/main_state.h"              /* struct main_state */
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/result.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
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
 * engine/services/src/block_index_loader.c), created beside the file it
 * loads: the seed loads in place from <datadir>/bundles, so its arena is
 * <datadir>/bundles/.block_index.arena and never the one still backing the
 * rows the ladder loaded from a stub root. */
#define HSI_LOADER_ARENA_NAME ".block_index.arena"

/* The flat loader builds "<dir>/block_index.bin" in a 1024-byte buffer
 * (bil_flat_mapping_open); a longer seed path would open a truncated name. */
#define HSI_LOADER_PATH_MAX 1024u

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

/* Never-stuck failure memory for the seed, the same sibling "<name>.failed"
 * convention the bundle autodetect honours (boot_auto_install_bundle.c
 * icb_scan_best_bundle skips a bundle with that marker; its writer is
 * csir_write_failed_marker). An import that discards an unbound seed leaves
 * the seed in bundles/ — which keeps boot_bundle_fetch from fetching it again
 * (bbf_header_seed_needed) — and marks it here, so no later boot re-imports
 * it. Delete the marker to retry. A marker path that does not fit refuses the
 * import: a seed that could not be marked would be re-imported every boot. */
static bool hsi_failed_marker_path(const char *src, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s.failed", src);
    return n >= 0 && (size_t)n < cap;
}

static bool hsi_seed_marked_failed(const char *src)
{
    char failp[PATH_MAX];
    if (!hsi_failed_marker_path(src, failp, sizeof(failp))) {
        LOG_WARN(HSI_SUBSYS, "header-seed import skipped: the never-stuck "
                 "marker path for %s does not fit, so a discarded seed could "
                 "not be remembered", src);
        return true;
    }
    if (access(failp, F_OK) != 0)
        return false;
    LOG_INFO(HSI_SUBSYS,
             "header-seed import skipped: %s marks this seed as discarded by an "
             "earlier boot (its chain does not own the baked checkpoint) — "
             "headers arrive via P2P; delete the marker to retry", failp);
    return true;
}

static void hsi_mark_seed_failed(const char *src)
{
    char failp[PATH_MAX];
    if (!hsi_failed_marker_path(src, failp, sizeof(failp)))
        return; /* unreachable: hsi_seed_marked_failed refused this path */
    int fd = open(failp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        LOG_WARN(HSI_SUBSYS, "header-seed import: could not write the "
                 "never-stuck marker %s: %s", failp, strerror(errno));
        return;
    }
    if (close(fd) != 0)
        LOG_WARN(HSI_SUBSYS, "header-seed import: close of the never-stuck "
                 "marker %s failed: %s", failp, strerror(errno));
}

/* Release the NAME of the arena the seed's flat load mapped beside the seed.
 * The loader keeps a successful arena mapped for the process lifetime (the
 * rows live there; a mapping pins its inode), so the name is only scratch on
 * disk: unlinking it leaves no stray file in bundles/. Absent is fine. */
static void hsi_release_seed_arena_name(const char *dir)
{
    char arena[PATH_MAX];
    int n = snprintf(arena, sizeof(arena), "%s/" HSI_LOADER_ARENA_NAME, dir);
    if (n < 0 || (size_t)n >= sizeof(arena))
        return; /* unreachable: dir is shorter than the seed path */
    if (unlink(arena) != 0 && errno != ENOENT)
        LOG_WARN(HSI_SUBSYS, "header-seed import: could not unlink the loader "
                 "arena %s: %s", arena, strerror(errno));
}

/* An import by an earlier version kept a replaceable stub aside at
 * <datadir>/block_index.bin.pre-seed while the seed sat at the root. This
 * import never moves the root, so such a copy is a leftover of an interrupted
 * earlier import: remove it (the stub itself, if any, is still at the root). */
static void hsi_drop_stale_stub_backup(const char *datadir)
{
    char backup[PATH_MAX];
    int n = snprintf(backup, sizeof(backup), "%s/block_index.bin.pre-seed",
                     datadir);
    if (n < 0 || (size_t)n >= sizeof(backup))
        return;
    if (unlink(backup) == 0)
        LOG_INFO(HSI_SUBSYS, "header-seed import: removed the stale stub "
                 "backup %s an interrupted earlier import left", backup);
    else if (errno != ENOENT)
        LOG_WARN(HSI_SUBSYS, "header-seed import: could not remove the stale "
                 "stub backup %s: %s", backup, strerror(errno));
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

/* True when the chain ending at `best` holds the baked checkpoint block hash
 * at the checkpoint height; *height_out always receives cp->height, or -1
 * when there is no checkpoint. */
static bool hsi_chain_owns_baked_checkpoint(const struct sha3_utxo_checkpoint *cp,
                                            struct block_index *best,
                                            int *height_out)
{
    *height_out = cp ? cp->height : -1;
    bool owns_ckpt = false;
    if (cp && cp->height >= 0 && best && best->nHeight >= cp->height) {
        struct block_index *at =
            block_index_get_ancestor(best, (int)cp->height);
        owns_ckpt = at && at->phashBlock &&
                    memcmp(at->phashBlock->data, cp->block_hash, 32) == 0;
    }
    return owns_ckpt;
}

/* Work-then-height ranking, the rule promote_best_header_after_load applies
 * (header_ranks_above, engine/services/src/block_index_post_load.c). */
static bool hsi_header_ranks_above(const struct block_index *cand,
                                   const struct block_index *ref)
{
    bool have_work = !arith_uint256_is_zero(&cand->nChainWork) &&
                     !arith_uint256_is_zero(&ref->nChainWork);
    return have_work
        ? arith_uint256_compare(&cand->nChainWork, &ref->nChainWork) > 0
        : cand->nHeight > ref->nHeight;
}

/* The header hsi_publish_loaded_frontier WOULD leave in pindex_best_header,
 * computed without publishing anything: the first strongest row with a hash
 * outside BLOCK_FAILED_MASK in block_map_next order (the order the publish
 * array is built in; find_best_header_candidate's rule), and the current
 * frontier kept unless that row ranks strictly above it (promotion never
 * downgrades). Ownership is decided on this BEFORE the publish, because the
 * publish seats the served tip and emits events that cannot be withdrawn. */
static struct block_index *hsi_publish_candidate(struct main_state *ms)
{
    struct block_index *best = NULL;
    struct block_index *p = NULL;
    size_t it = 0;
    while (block_map_next(&ms->map_block_index, &it, NULL, &p)) {
        if (!p || !p->phashBlock ||
            (block_index_status_load(p) & (unsigned int)BLOCK_FAILED_MASK))
            continue;
        if (!best || hsi_header_ranks_above(p, best))
            best = p;
    }
    struct block_index *cur = ms->pindex_best_header;
    if (!best || (cur && cur != best && !hsi_header_ranks_above(best, cur)))
        return cur;
    return best;
}

/* The header rows this node held before the import (at most
 * HSI_MAX_EXISTING_ENTRIES — the verdict refuses more), sorted by address. */
struct hsi_resident {
    struct block_index **rows;
    size_t count;
};

static int hsi_row_addr_cmp(const void *a, const void *b)
{
    uintptr_t x = (uintptr_t)*(struct block_index *const *)a;
    uintptr_t y = (uintptr_t)*(struct block_index *const *)b;
    return (x > y) - (x < y);
}

static bool hsi_resident_capture(const struct main_state *ms,
                                 struct hsi_resident *res)
{
    if (!block_map_snapshot_indices(&ms->map_block_index, &res->rows,
                                    &res->count))
        return false;
    if (res->count > 1)
        qsort(res->rows, res->count, sizeof(*res->rows), hsi_row_addr_cmp);
    return true;
}

static bool hsi_is_resident(const struct hsi_resident *res,
                            const struct block_index *p)
{
    return res->count > 0 &&
           bsearch(&p, res->rows, res->count, sizeof(*res->rows),
                   hsi_row_addr_cmp) != NULL;
}

/* Take every row this import inserted back out of the header map, so it holds
 * exactly the resident rows again. Same reasoning as the loader's own refusal
 * rollback (bil_flat_rollback, engine/services/src/block_index_loader.c): the
 * map is linear-probed with no tombstones, every resident was placed before
 * any seed row (block_map_reserve re-places the old buckets first), so no
 * resident's probe path crosses a seed row's bucket and emptying those buckets
 * leaves every resident findable. Resident rows are never written by the load:
 * duplicates skip, the link pass sets only arena[i].pprev and the forward pass
 * walks arena rows only. Returns the number of rows removed. */
static size_t hsi_forget_seed_rows(struct main_state *ms,
                                   const struct hsi_resident *res)
{
    struct block_map *bm = &ms->map_block_index;
    int lk = pthread_rwlock_wrlock(&bm->rwlock);
    if (lk != 0)
        LOG_WARN(HSI_SUBSYS, "header-seed import: header map write lock "
                 "failed (%s) — removing the seed rows single-threaded, as the "
                 "boot loader inserted them", strerror(lk));
    size_t removed = 0;
    for (size_t slot = 0; slot < bm->capacity; slot++) {
        struct block_index *p = bm->buckets[slot].index;
        if (p && !hsi_is_resident(res, p)) {
            bm->buckets[slot].index = NULL;
            bm->size--;
            removed++;
        }
    }
    if (lk == 0)
        (void)pthread_rwlock_unlock(&bm->rwlock);
    return removed;
}

/* One import attempt's paths and the pre-import resident rows. */
struct hsi_import {
    char src[PATH_MAX];    /* <datadir>/bundles/block_index.bin */
    char dir[PATH_MAX];    /* <datadir>/bundles: the seed loads in place */
    char dst[PATH_MAX];    /* <datadir>/block_index.bin */
    bool root_present;
    struct hsi_resident resident;
};

/* All-or-nothing: the imported chain does not own the baked checkpoint, so
 * none of it stays. Called before bind, clamp, save and publish, so the
 * resident rows, pindex_best_header, the active-chain window, the served tip
 * and the root index were never touched; this removes the seed rows from the
 * map, keeps the seed in bundles/ (so the fetch does not download it again)
 * and marks it failed so no later boot re-imports it. */
static void hsi_discard_unbound_seed(struct main_state *ms,
                                     const struct hsi_import *imp,
                                     int ckpt_height)
{
    size_t loaded = block_map_count(&ms->map_block_index);
    size_t removed = hsi_forget_seed_rows(ms, &imp->resident);
    hsi_mark_seed_failed(imp->src);
    hsi_name_blocker("header_seed.checkpoint_unbound",
                     "header seed does not own the baked checkpoint block "
                     "hash — discarded; headers and the checkpoint arrive "
                     "via P2P");
    LOG_WARN(HSI_SUBSYS,
             "header-seed import: the seed's chain does NOT own the baked "
             "checkpoint (h=%d) — discarded all %zu seed rows (%zu header "
             "entries loaded, %zu kept from before); nothing of it stays in "
             "memory or at %s; falling back to P2P header sync",
             ckpt_height, removed, loaded, block_map_count(&ms->map_block_index),
             imp->dst);
    if (block_map_count(&ms->map_block_index) != imp->resident.count)
        LOG_WARN(HSI_SUBSYS, "header-seed import: %zu header entries after "
                 "the discard, %zu before the import",
                 block_map_count(&ms->map_block_index), imp->resident.count);
    sync_benchmark_phase_end(SYNC_BENCH_HEADERS);
}

/* True when the loaded seed may stay: there is no baked checkpoint, or the
 * header the publish would choose descends from it. A network with no baked
 * checkpoint (cp NULL) keeps the accept-and-name-blocker path below: there is
 * no hash to bind the seed to there. */
static bool hsi_seed_may_stay(struct main_state *ms, int *ckpt_height)
{
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp) {
        *ckpt_height = -1;
        return true;
    }
    return hsi_chain_owns_baked_checkpoint(cp, hsi_publish_candidate(ms),
                                           ckpt_height);
}

/* True when `p` is the anchor block's row or one of its ancestors. */
static bool hsi_bound_by(struct block_index *anchor,
                         const struct block_index *p)
{
    return p->nHeight <= anchor->nHeight &&
           block_index_get_ancestor(anchor, p->nHeight) == p;
}

/* True when the chain ending at `row` holds block hash `hash` at height h. */
static bool hsi_chain_holds(struct block_index *row, int32_t h,
                            const uint8_t hash[32])
{
    struct block_index *at =
        h >= 0 && row->nHeight >= h ? block_index_get_ancestor(row, (int)h)
                                    : NULL;
    return at && at->phashBlock && memcmp(at->phashBlock->data, hash, 32) == 0;
}

/* Why the seed row `row`, found by compiled rung r's block hash, may not
 * anchor the seed; NULL when it may. Its chain must hold the checkpoint row
 * itself and every lower compiled rung's block hash at that rung's height,
 * and its chainwork as the flat loader's forward pass derived it (parent work
 * plus the row's own proof, never the file's stored value) must equal the
 * compiled rung chainwork, the same test the rung install applies
 * (cbir_own_window, checkpoint_bundle_install_ready.c). Rows at or below a
 * compiled hash are linked by stored prev_hash only; the chainwork test is
 * what refuses a forged stretch between true checkpoint and rung rows. */
static const char *hsi_rung_refusal(struct block_index *row,
                                    const struct rom_state_rung *r,
                                    struct block_index *cp_row)
{
    if (row->nHeight != r->cp.height)
        return "the row is not at the rung height";
    if (block_index_status_load(row) & (unsigned int)BLOCK_FAILED_MASK)
        return "the row is marked failed";
    if (block_index_get_ancestor(row, cp_row->nHeight) != cp_row)
        return "its chain does not hold the baked checkpoint row";
    size_t n = get_rom_state_rung_count();
    for (size_t i = 0; i < n; i++) {
        const struct rom_state_rung *lo = get_rom_state_rung_at(i);
        if (lo && lo->cp.height < r->cp.height &&
            !hsi_chain_holds(row, lo->cp.height, lo->cp.block_hash))
            return "its chain does not hold a lower compiled rung's block hash";
    }
    struct arith_uint256 want;
    island_anchor_work_from_be(&want, r->chainwork);
    if (arith_uint256_compare(&row->nChainWork, &want) != 0)
        return "its derived chainwork is not the compiled rung chainwork";
    return NULL;
}

/* The highest compiled block hash the seed provably owns: a baked state rung
 * above the checkpoint (get_rom_state_rung_at) whose row, found by the rung's
 * own block hash and independent of which row carries the most work, passes
 * hsi_rung_refusal; else the baked checkpoint row `cp_row`. A rung row that
 * is present but refused is logged and the next lower anchor is tried. A
 * fresh node's install at a rung waits for its header chain to own the rung
 * (consensus_state_install_header_ready_for), so binding the seed only to the
 * checkpoint would leave every header between the two to P2P (measured live:
 * 264,402 headers, about 8.5 minutes, STALLED at 600 s). */
static struct block_index *hsi_bind_anchor(struct main_state *ms,
                                           struct block_index *cp_row)
{
    struct block_index *anchor = cp_row;
    size_t n = get_rom_state_rung_count();
    for (size_t i = 0; i < n; i++) {
        const struct rom_state_rung *r = get_rom_state_rung_at(i);
        if (!r || r->cp.height <= anchor->nHeight)
            continue;
        struct uint256 rung_hash;
        memcpy(rung_hash.data, r->cp.block_hash, sizeof(rung_hash.data));
        struct block_index *row = block_map_find(&ms->map_block_index,
                                                 &rung_hash);
        const char *why = row ? hsi_rung_refusal(row, r, cp_row) : NULL;
        if (row && !why)
            anchor = row;
        else if (why)
            LOG_WARN(HSI_SUBSYS, "header-seed import: the seed carries the "
                     "compiled state rung block hash h=%d but it may not "
                     "anchor the seed: %s — binding to a lower compiled hash",
                     (int)r->cp.height, why);
    }
    return anchor;
}

/* Rows of one bind: seed rows kept and removed. */
struct hsi_bind {
    size_t kept;
    size_t removed;
};

/* Collect into `rows` (in place over the snapshot) the seed rows the anchor
 * block binds; returns how many. */
static size_t hsi_collect_bound_rows(struct block_index **rows, size_t n,
                                     const struct hsi_resident *res,
                                     struct block_index *anchor)
{
    size_t keep = 0;
    for (size_t i = 0; i < n; i++) {
        struct block_index *p = rows[i];
        if (p && !hsi_is_resident(res, p) && hsi_bound_by(anchor, p))
            rows[keep++] = p;
    }
    return keep;
}

/* Keep from the seed only what a compiled block hash binds: the anchor block
 * (hsi_bind_anchor) and its ancestors. A seed row above the anchor, or one
 * not on the anchor block's chain, is bound by no compiled hash (the flat
 * seed carries no Equihash solutions and its stored hashes are checked only
 * against their own targets), so it leaves the map before anything is
 * clamped, saved or published; headers above the anchor arrive by P2P header
 * sync with full validation. Resident rows are never touched. Every seed row
 * is taken out (hsi_forget_seed_rows keeps resident lookups intact) and the
 * bound ones are inserted again, since emptying only some seed buckets could
 * cut the probe path of a kept one. False when the snapshot or a re-insert
 * fails; the caller then drops the seed whole. */
static bool hsi_bind_seed_to_anchor(struct main_state *ms,
                                    const struct hsi_resident *res,
                                    struct block_index *anchor,
                                    struct hsi_bind *out)
{
    out->kept = out->removed = 0;
    struct block_index **rows = NULL;
    size_t n = 0;
    if (!block_map_snapshot_indices(&ms->map_block_index, &rows, &n))
        return false;
    size_t keep = hsi_collect_bound_rows(rows, n, res, anchor);
    size_t seed_rows = hsi_forget_seed_rows(ms, res);
    bool ok = true;
    for (size_t i = 0; i < keep; i++)
        ok = block_map_insert(&ms->map_block_index, &rows[i]->hashBlock,
                              rows[i]) && ok;
    free(rows);
    out->kept = keep;
    out->removed = seed_rows - keep;
    return ok;
}

/* Bind the seed to the highest compiled block hash it owns and log what was
 * kept and removed; with no baked checkpoint there is nothing to bind to and
 * the seed stays whole. False (logged, blocker named, every seed row removed)
 * when the bind could not complete. */
static bool hsi_bind_or_drop(struct main_state *ms,
                             const struct hsi_import *imp)
{
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp)
        return true;
    struct uint256 cp_hash;
    memcpy(cp_hash.data, cp->block_hash, sizeof(cp_hash.data));
    struct block_index *cp_row = block_map_find(&ms->map_block_index, &cp_hash);
    struct block_index *anchor = cp_row ? hsi_bind_anchor(ms, cp_row) : NULL;
    struct hsi_bind b;
    if (anchor && hsi_bind_seed_to_anchor(ms, &imp->resident, anchor, &b)) {
        LOG_INFO(HSI_SUBSYS,
                 "header-seed import: kept %zu seed rows bound by the baked "
                 "%s block hash (h=%d: that block and its ancestors; "
                 "checkpoint h=%d), removed %zu (above it or off its chain), "
                 "%zu resident rows kept — header frontier h=%d; headers "
                 "above it arrive via P2P", b.kept,
                 anchor == cp_row ? "checkpoint" : "state-rung",
                 anchor->nHeight, cp->height, b.removed, imp->resident.count,
                 anchor->nHeight);
        return true;
    }
    size_t removed = hsi_forget_seed_rows(ms, &imp->resident);
    hsi_name_blocker("header_seed.stage_failed",
                     "could not bind the header seed to the baked checkpoint "
                     "block — dropped; headers arrive via P2P");
    LOG_WARN(HSI_SUBSYS, "header-seed import: binding the seed to the baked "
             "checkpoint (h=%d) failed — removed all %zu seed rows, kept the "
             "%zu resident rows, the seed stays at %s for the next boot",
             cp->height, removed, imp->resident.count, imp->src);
    sync_benchmark_phase_end(SYNC_BENCH_HEADERS);
    return false;
}

/* Build the seed directory path (it must fit the loader's path buffer) and
 * snapshot the resident rows; false (logged, blocker named) when either
 * fails, before anything is loaded. */
static bool hsi_import_prepare(const char *datadir, const struct main_state *ms,
                               struct hsi_import *imp)
{
    int n = snprintf(imp->dir, sizeof(imp->dir), "%s/bundles", datadir);
    if (n < 0 || (size_t)n >= sizeof(imp->dir) ||
        strlen(imp->src) >= HSI_LOADER_PATH_MAX) {
        LOG_WARN(HSI_SUBSYS, "header-seed import skipped: the seed path %s "
                 "does not fit the flat loader's %u-byte path", imp->src,
                 HSI_LOADER_PATH_MAX);
        return false;
    }
    if (!hsi_resident_capture(ms, &imp->resident)) {
        hsi_name_blocker("header_seed.stage_failed",
                         "could not record the resident header index before "
                         "importing the seed");
        LOG_WARN(HSI_SUBSYS, "header-seed import skipped: could not snapshot "
                 "the %zu resident header entries",
                 block_map_count(&ms->map_block_index));
        return false;
    }
    hsi_drop_stale_stub_backup(datadir);
    return true;
}

/* Run the shared verified flat loader over the seed IN PLACE in bundles/: the
 * root index is never replaced by peer bytes, so no kill at any later step
 * can leave an unchecked seed where the next boot's ladder loads this node's
 * own index. False (blocker named, logged) when the loader refuses; the
 * refused seed is removed from bundles/ (a later boot may fetch another) and
 * the root index, stub or absent, is left exactly as it was. */
static bool hsi_load_seed(struct main_state *ms, const struct hsi_import *imp)
{
    if (imp->root_present)
        LOG_INFO(HSI_SUBSYS,
                 "header-seed import: the root index %s is a replaceable stub "
                 "(%zu header-only entries, tip at genesis or absent) — "
                 "importing the downloaded seed over it as on a fresh node",
                 imp->dst, block_map_count(&ms->map_block_index));

    /* Embedded SHA3 re-verify, per-row PoW-target admission (block_row_verify
     * → CheckProofOfWork) with per-row quarantine, persisted-FAILED-bit
     * reconcile against the baked ROM checkpoint, pprev link, and the
     * canonical forward pass (nChainWork/skip). Rows already resident are
     * deduped; seed rows link pprev to them by hash. */
    struct zcl_result r = load_block_index_flat(imp->dir, ms);
    if (r.ok) {
        hsi_release_seed_arena_name(imp->dir);
        return true;
    }
    sync_benchmark_phase_end(SYNC_BENCH_HEADERS);
    hsi_name_blocker("header_seed.load_failed",
                     hsi_flat_load_failure_reason(&r));
    bool removed = unlink(imp->src) == 0;
    LOG_WARN(HSI_SUBSYS,
             "header-seed import: flat load rejected the artifact (%s) — %s %s; "
             "kept the %zu resident header entries and the root index %s "
             "untouched; falling back to P2P header sync", r.message,
             removed ? "removed" : "could not remove", imp->src,
             block_map_count(&ms->map_block_index), imp->dst);
    return false;
}

/* Never clobber a header index this node built (only a fresh node, or the
 * header-only stub an interrupted first boot left at the root, is seeded
 * from a peer artifact), never re-seed sovereign installed state, and never
 * re-import a seed an earlier boot discarded. */
static bool hsi_import_wanted(const char *datadir, struct main_state *ms,
                              struct hsi_import *imp)
{
    if (hsi_import_args_invalid(datadir, ms))
        return false;
    if (getenv("ZCL_NO_BUNDLE_FETCH"))
        return false;

    /* The downloaded, content-verified artifact. */
    if (hsi_locate_downloaded_artifact(datadir, imp->src, sizeof(imp->src)) !=
        HSI_ARTIFACT_PRESENT)
        return false;
    if (hsi_seed_marked_failed(imp->src))
        return false;

    /* zcl.sync_benchmark.v1: the artifact is present, so this boot is genuinely
     * attempting a header-seed import — arm the phase. A no-op boot (the
     * stat-miss case above) never begins it, so the receipt never claims a
     * headers phase for a boot that never tried one. */
    sync_benchmark_phase_begin(SYNC_BENCH_HEADERS);

    if (!hsi_root_probe(datadir, imp->dst, sizeof(imp->dst),
                        &imp->root_present))
        return false;
    return hsi_seed_may_land(datadir, ms, imp->dst, imp->root_present);
}

/* Report the published frontier's checkpoint ownership. hsi_seed_may_stay
 * already refused a seed whose chain does not own the baked checkpoint, so
 * the unbound branch is reached only with no baked checkpoint (cp NULL) or
 * when the publish did not seat the frontier hsi_publish_candidate expected:
 * then the install must wait for the real checkpoint header via P2P — name a
 * typed blocker rather than let the install silently never arm. */
static void hsi_report_published_frontier(struct main_state *ms, size_t count,
                                          size_t clamped)
{
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    int ckpt_height = -1;
    bool owns_ckpt = hsi_chain_owns_baked_checkpoint(cp, ms->pindex_best_header,
                                                     &ckpt_height);
    int frontier = ms->pindex_best_header ? ms->pindex_best_header->nHeight : -1;
    if (owns_ckpt) {
        LOG_INFO(HSI_SUBSYS,
                 "header-seed import: %zu entries loaded, frontier h=%d, "
                 "%zu rows clamped header-only — chain OWNS the baked checkpoint "
                 "(h=%d): the checkpoint-bundle install can arm this boot",
                 count, frontier, clamped, cp->height);
        return;
    }
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

#ifdef ZCL_TESTING
static enum boot_header_seed_kill_point g_hsi_kill_at;
void boot_header_seed_import_test_kill_at(enum boot_header_seed_kill_point p)
{
    g_hsi_kill_at = p;
}
static bool hsi_killed_at(enum boot_header_seed_kill_point p)
{
    if (g_hsi_kill_at != p)
        return false;
    g_hsi_kill_at = BOOT_HEADER_SEED_KILL_NONE;
    return true;
}
#define HSI_KILLED_AT(p) hsi_killed_at(p)
#else
#define HSI_KILLED_AT(p) false
#endif

/* Remove a stub root before the bound save. Over a present root the flat
 * writer first tries an IN-PLACE rewrite (flat_save_publish,
 * engine/services/src/block_index_flat_save.c; it takes it when at most a
 * quarter of the rows differ, so only over a stub almost as large as the
 * bound map): a kill in the middle of that leaves the stub's old header over
 * a half-new payload, a root that no longer loads, which the next boot's
 * verdict (NOT_LOADED) would refuse to re-seed on every later boot. With no
 * root the writer's only path is its full tmp+fsync+rename, so a kill leaves
 * either no root (the next boot is FRESH and decides the seed again) or the
 * complete bound root. The stub is header-only by the verdict (STUB): a kill
 * between this unlink and the rename loses only its rows, which P2P header
 * sync sends again. On Windows the in-place save is always declined, so the
 * stub is left for the full rewrite to replace. */
static struct zcl_result hsi_remove_stub_root(const struct hsi_import *imp)
{
#ifndef _WIN32
    if (imp->root_present && unlink(imp->dst) != 0 && errno != ENOENT)
        return ZCL_ERR(-1, "could not remove the stub root before the full "
                       "atomic save: %s", strerror(errno));
#else
    (void)imp;
#endif
    return ZCL_OK;
}

/* Write the bound, clamped map as the root index BEFORE anything of the seed
 * is published: the next boot's ladder (rung "flat") loads the root verbatim
 * as this node's own index, so it must already hold exactly what memory keeps
 * — no row above the anchor, no seeder HAVE_DATA or (nFile, nDataPos)
 * (a respawn before any shutdown save would otherwise re-admit them as its
 * own warm cache; measured: ~1.3M pread/s on an absent blk00049.dat). With
 * the stub root removed first (hsi_remove_stub_root) the write is the flat
 * writer's full tmp+fsync+rename, never an in-place rewrite, and it
 * re-encodes the hash-bound anchor header from the map. False (logged,
 * blocker named, every seed row removed, the seed left in bundles/ for the
 * next boot) when the stub cannot be removed or the write fails. */
static bool hsi_persist_bound_index(const char *datadir, struct main_state *ms,
                                    const struct hsi_import *imp)
{
    struct zcl_result w = hsi_remove_stub_root(imp);
    if (w.ok && HSI_KILLED_AT(BOOT_HEADER_SEED_KILL_AFTER_ROOT_UNLINK))
        return false;
    if (w.ok)
        w = save_block_index_flat_identity(datadir, ms, NULL);
    if (w.ok)
        return true;
    size_t removed = hsi_forget_seed_rows(ms, &imp->resident);
    hsi_name_blocker("header_seed.stage_failed",
                     "could not write the checkpoint-bound header index to "
                     "the datadir root — the seed stays in bundles/ for the "
                     "next boot; headers arrive via P2P");
    LOG_WARN(HSI_SUBSYS, "header-seed import: writing %s failed (%s) — "
             "removed all %zu seed rows from memory, kept the %zu resident "
             "rows; the root holds no seed row; the seed stays at %s for the "
             "next boot", imp->dst, w.message, removed, imp->resident.count,
             imp->src);
    sync_benchmark_phase_end(SYNC_BENCH_HEADERS);
    return false;
}

/* The root now holds the bound index: the downloaded seed is consumed. A
 * seed that cannot be removed is harmless — a later boot finds this node's
 * own root index and either refuses the seed by the verdict or re-runs the
 * same decision on it. */
static void hsi_consume_seed(const struct hsi_import *imp)
{
    if (unlink(imp->src) != 0 && errno != ENOENT)
        LOG_WARN(HSI_SUBSYS, "header-seed import: could not remove the "
                 "imported seed %s (%s); the root index %s already holds the "
                 "bound rows", imp->src, strerror(errno), imp->dst);
}

/* Load the seed and decide it: false when it was refused, discarded or the
 * bind failed (each path logged its outcome). */
static bool hsi_load_and_bind(const char *datadir, struct main_state *ms,
                              struct hsi_import *imp)
{
    if (!hsi_import_wanted(datadir, ms, imp) ||
        !hsi_import_prepare(datadir, ms, imp) || !hsi_load_seed(ms, imp))
        return false;
    if (HSI_KILLED_AT(BOOT_HEADER_SEED_KILL_AFTER_LOAD))
        return false;

    /* Checkpoint ownership BEFORE anything of the seed is bound, clamped,
     * saved or published: does the chain the publish would choose own the
     * baked checkpoint block hash — the exact precondition the bundle install
     * defers on (consensus_state_checkpoint_header_ready)? The flat seed
     * carries no Equihash solutions, so its rows passed only their own PoW
     * target; a seed that does not bind the checkpoint (stale or forged) is
     * discarded whole and the node falls back to P2P headers. */
    int ckpt_height = -1;
    if (!hsi_seed_may_stay(ms, &ckpt_height)) {
        hsi_discard_unbound_seed(ms, imp, ckpt_height);
        return false;
    }
    return hsi_bind_or_drop(ms, imp);
}

static bool hsi_import_run(const char *datadir, struct main_state *ms,
                           struct hsi_import *imp)
{
    if (!hsi_load_and_bind(datadir, ms, imp))
        return false;
    size_t clamped = hsi_clamp_rows_header_only(ms);
    if (HSI_KILLED_AT(BOOT_HEADER_SEED_KILL_AFTER_DECISION) ||
        !hsi_persist_bound_index(datadir, ms, imp) ||
        HSI_KILLED_AT(BOOT_HEADER_SEED_KILL_AFTER_SAVE))
        return false;
    hsi_consume_seed(imp);

    size_t count = block_map_count(&ms->map_block_index);
    if (hsi_publish_loaded_frontier(ms, count) == HSI_PROMOTE_ALLOC_FAILED)
        LOG_WARN(HSI_SUBSYS, "header-seed import: promote alloc failed (%zu "
                 "entries) — pindex_best_header publish may lag", count);
    hsi_report_published_frontier(ms, count, clamped);
    sync_benchmark_phase_end(SYNC_BENCH_HEADERS);
    return true;
}

bool boot_header_seed_import_maybe(const char *datadir, struct main_state *ms)
{
    struct hsi_import imp;
    memset(&imp, 0, sizeof(imp));
    bool imported = hsi_import_run(datadir, ms, &imp);
    free(imp.resident.rows);
    return imported;
}
