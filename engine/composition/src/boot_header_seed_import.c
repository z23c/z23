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

/* Never-stuck failure memory for the seed, the same sibling "<name>.failed"
 * convention the bundle autodetect honours (boot_auto_install_bundle.c
 * icb_scan_best_bundle skips a bundle with that marker; its writer is
 * csir_write_failed_marker). An import that discards an unbound seed returns
 * the seed to bundles/ — which keeps boot_bundle_fetch from fetching it again
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

/* Outcome of moving the downloaded artifact to the datadir root. */
enum hsi_stage_result {
    HSI_STAGE_MOVED = 0,     /* rename succeeded — the import may proceed */
    HSI_STAGE_REPLACED_STUB, /* rename atomically replaced a stub root file */
    HSI_STAGE_BACKUP_FAILED, /* the stub root could not be kept aside */
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

/* Drop this import's own stub backup, keeping errno for the caller. */
static void hsi_drop_stub_backup(const char *backup)
{
    int err = errno;
    if (backup && unlink(backup) != 0 && errno != ENOENT)
        LOG_WARN(HSI_SUBSYS, "header-seed import: could not remove the stub "
                 "backup link %s: %s", backup, strerror(errno));
    errno = err;
}

/* Copy every byte of `in` to `out`; false (errno set) on a read or write
 * error. */
static bool hsi_copy_stream(FILE *in, FILE *out)
{
    unsigned char buf[16384];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            if (errno == 0)
                errno = EIO;
            return false;
        }
    }
    if (!ferror(in))
        return true;
    if (errno == 0)
        errno = EIO;
    return false;
}

/* Copy `from` to the absent path `to` in binary mode; on failure the partial
 * copy is removed and errno names the first failure. */
static bool hsi_copy_file(const char *from, const char *to)
{
    FILE *in = fopen(from, "rb");
    if (!in)
        return false;
    FILE *out = fopen(to, "wb");
    if (!out) {
        int err = errno;
        (void)fclose(in);
        errno = err;
        return false;
    }
    errno = 0;
    bool ok = hsi_copy_stream(in, out);
    int err = errno;
    if (fclose(out) != 0 && ok) {
        ok = false;
        err = errno;
    }
    (void)fclose(in);
    if (!ok) {
        (void)unlink(to);
        errno = err;
    }
    return ok;
}

/* Keep the stub root aside at `backup` so a discarded import can put the same
 * bytes back. A `backup` already present is what an interrupted earlier import
 * left (often a hard link to this very stub): its name is unlinked first and
 * never opened for writing, so the stub itself is never truncated through it.
 * A hard link where the platform has one; a byte copy on Windows or when the
 * filesystem refuses the link (EXDEV, EPERM, ENOTSUP, EMLINK). */
static bool hsi_keep_stub_aside(const char *dst, const char *backup)
{
    if (unlink(backup) == 0)
        LOG_INFO(HSI_SUBSYS, "header-seed import: removed the stale stub "
                 "backup %s an interrupted earlier import left", backup);
    else if (errno != ENOENT)
        return false;
#if !defined(_WIN32)
    if (link(dst, backup) == 0)
        return true;
    LOG_INFO(HSI_SUBSYS, "header-seed import: cannot hard-link the stub %s "
             "aside (%s) — copying it", dst, strerror(errno));
#endif
    return hsi_copy_file(dst, backup);
}

/* Move the artifact to the datadir root so (a) the flat loader finds it and
 * (b) the rom_seed scan re-serves it to the next fresh node. A present root
 * file reaches here only when it is a replaceable stub: rename(2) replaces it
 * atomically, so the root path always names either the stub or the whole
 * artifact. The stub is first kept aside at `backup` (non-NULL exactly when a
 * stub is present) so a discarded import can put the same bytes back. */
static enum hsi_stage_result
hsi_stage_artifact_at_root(const char *datadir, const char *src,
                           const char *dst, const char *backup)
{
    if (backup && !hsi_keep_stub_aside(dst, backup))
        return HSI_STAGE_BACKUP_FAILED;
    if (backup && !hsi_release_loader_arena_name(datadir)) {
        hsi_drop_stub_backup(backup);
        return HSI_STAGE_ARENA_BUSY;
    }
    if (rename(src, dst) != 0) {
        hsi_drop_stub_backup(backup);
        return HSI_STAGE_RENAME_FAILED;
    }
    return backup ? HSI_STAGE_REPLACED_STUB : HSI_STAGE_MOVED;
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
    if (staged == HSI_STAGE_BACKUP_FAILED) {
        hsi_name_blocker("header_seed.stage_failed",
                         "could not keep the stub header index aside before "
                         "replacing it with the downloaded seed");
        LOG_WARN(HSI_SUBSYS, "header-seed import: cannot keep the stub %s "
                 "aside (%s) — the stub header index is kept", dst,
                 strerror(err));
        return;
    }
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
    char dst[PATH_MAX];    /* <datadir>/block_index.bin */
    char backup[PATH_MAX]; /* stub hard link; "" when no stub root */
    bool root_present;
    struct hsi_resident resident;
};

/* Put the files back the way this import found them: the seed returns to
 * bundles/ (so the fetch does not download it again) and a stub root is
 * restored from the copy kept aside (a hard link where the platform allows
 * one, so usually the very same file). The root never keeps the
 * seed: when it cannot move back, the seed copy this import made at the root
 * is removed. Never removes a file the node had before the import. */
static void hsi_unstage_seed(const struct hsi_import *imp)
{
    bool moved_back = rename(imp->dst, imp->src) == 0;
    if (!moved_back)
        LOG_WARN(HSI_SUBSYS, "header-seed import: could not return the "
                 "discarded seed %s to %s: %s", imp->dst, imp->src,
                 strerror(errno));
    if (imp->backup[0]) {
        if (rename(imp->backup, imp->dst) == 0)
            return;
        LOG_WARN(HSI_SUBSYS, "header-seed import: could not restore the stub "
                 "header index %s from %s: %s — the stub stays at %s",
                 imp->dst, imp->backup, strerror(errno), imp->backup);
    }
    if (!moved_back && unlink(imp->dst) != 0 && errno != ENOENT)
        LOG_WARN(HSI_SUBSYS, "header-seed import: could not remove the "
                 "discarded seed %s: %s", imp->dst, strerror(errno));
}

/* All-or-nothing: the imported chain does not own the baked checkpoint, so
 * none of it stays. Called before clamp, publish and save, so the resident
 * rows, pindex_best_header, the active-chain window and the served tip were
 * never touched; this removes the seed rows from the map and the seed from
 * the root. The loader keeps its arena mapped for the process lifetime (a
 * successful load never munmaps it, bil_arena_release), but after
 * hsi_forget_seed_rows no map bucket, frontier or tip points into it; the
 * marker keeps later boots from loading another, so it is one per boot. Its
 * file name is this load's own scratch (the stub's was released before
 * staging), so it is unlinked: the mapping pins the inode until exit. */
static void hsi_discard_unbound_seed(const char *datadir, struct main_state *ms,
                                     const struct hsi_import *imp,
                                     int ckpt_height)
{
    size_t loaded = block_map_count(&ms->map_block_index);
    size_t removed = hsi_forget_seed_rows(ms, &imp->resident);
    hsi_unstage_seed(imp);
    hsi_mark_seed_failed(imp->src);
    if (!hsi_release_loader_arena_name(datadir))
        LOG_WARN(HSI_SUBSYS, "header-seed import: could not unlink the loader "
                 "arena of the discarded seed beside %s", imp->dst);
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

/* Build the stub backup path (only when a stub root is present) and snapshot
 * the resident rows; false (logged, blocker named) when either fails, before
 * anything is moved. */
static bool hsi_import_prepare(const char *datadir, const struct main_state *ms,
                               struct hsi_import *imp)
{
    imp->backup[0] = '\0';
    if (imp->root_present) {
        int n = snprintf(imp->backup, sizeof(imp->backup),
                         "%s/block_index.bin.pre-seed", datadir);
        if (n < 0 || (size_t)n >= sizeof(imp->backup)) {
            LOG_WARN(HSI_SUBSYS, "header-seed import skipped: the stub backup "
                     "path under %s does not fit", datadir);
            return false;
        }
    }
    if (hsi_resident_capture(ms, &imp->resident))
        return true;
    hsi_name_blocker("header_seed.stage_failed",
                     "could not record the resident header index before "
                     "importing the seed");
    LOG_WARN(HSI_SUBSYS, "header-seed import skipped: could not snapshot the "
             "%zu resident header entries", block_map_count(&ms->map_block_index));
    return false;
}

/* Stage the seed at the root and run the shared verified flat loader; false
 * (blocker named, logged) when either step refuses. */
static bool hsi_stage_and_load(const char *datadir, struct main_state *ms,
                               const struct hsi_import *imp)
{
    enum hsi_stage_result staged = hsi_stage_artifact_at_root(
        datadir, imp->src, imp->dst, imp->root_present ? imp->backup : NULL);
    if (staged != HSI_STAGE_MOVED && staged != HSI_STAGE_REPLACED_STUB) {
        hsi_report_stage_failure(staged, imp->src, imp->dst);
        return false;
    }
    if (staged == HSI_STAGE_REPLACED_STUB)
        LOG_INFO(HSI_SUBSYS,
                 "header-seed import: replaced the stub header index at %s "
                 "(%zu header-only entries, tip at genesis or absent) with the "
                 "downloaded seed — importing it as on a fresh node",
                 imp->dst, block_map_count(&ms->map_block_index));

    /* Load via the shared verified flat loader: embedded SHA3 re-verify,
     * per-row PoW-target admission (block_row_verify → CheckProofOfWork) with
     * per-row quarantine, persisted-FAILED-bit reconcile against the baked ROM
     * checkpoint, pprev link, and the canonical forward pass (nChainWork/skip).
     * Genesis (already in the ladder-seeded map) is deduped; header entries
     * link pprev to it by hash. */
    struct zcl_result r = load_block_index_flat(datadir, ms);
    if (r.ok)
        return true;
    sync_benchmark_phase_end(SYNC_BENCH_HEADERS);
    hsi_name_blocker("header_seed.load_failed",
                     hsi_flat_load_failure_reason(&r));
    LOG_WARN(HSI_SUBSYS,
             "header-seed import: flat load rejected the artifact (%s) — "
             "falling back to P2P header sync", r.message);
    /* The loader removed its own rows; the stub (if any) was replaced. */
    hsi_drop_stub_backup(imp->root_present ? imp->backup : NULL);
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

static bool hsi_import_run(const char *datadir, struct main_state *ms,
                           struct hsi_import *imp)
{
    if (!hsi_import_wanted(datadir, ms, imp) ||
        !hsi_import_prepare(datadir, ms, imp) ||
        !hsi_stage_and_load(datadir, ms, imp))
        return false;

    /* Checkpoint ownership BEFORE anything of the seed is clamped, published
     * or saved: does the chain the publish would choose own the baked
     * checkpoint block hash — the exact precondition the bundle install defers
     * on (consensus_state_checkpoint_header_ready)? The flat seed carries no
     * Equihash solutions, so its rows passed only their own PoW target; a
     * seed that does not bind the checkpoint (stale or forged) is discarded
     * whole and the node falls back to P2P headers. */
    int ckpt_height = -1;
    if (!hsi_seed_may_stay(ms, &ckpt_height)) {
        hsi_discard_unbound_seed(datadir, ms, imp, ckpt_height);
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
    /* The stub was replaced for good; its hard link is no longer needed. */
    hsi_drop_stub_backup(imp->root_present ? imp->backup : NULL);
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
