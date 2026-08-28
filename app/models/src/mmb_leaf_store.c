/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * MMB Leaf Store — persistent flat file of MMB leaf hashes.
 * Memory-mapped for FlyClient proof building (mmb_prove).
 *
 * 3M blocks × 32 bytes = 96 MB on disk, mmap'd for O(1) access. */

#include "models/mmb_leaf_store.h"
#include "chain/mmr.h"                  /* MMR_COMMITMENT_INTERVAL boundary */
#include "storage/coins_kv.h"           /* boundary utxo_root read */
#include "storage/progress_store.h"     /* progress_store_db() handle */
#include "platform/time_compat.h"
#include "platform/file_sync.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

#if defined(_WIN32)
#include <io.h>
#define zcl_ftruncate(fd, length) _chsize_s((fd), (length))
#define ZCL_LEAF_STORE_OPEN_FLAGS (O_RDWR | O_CREAT | O_BINARY)
#else
#define zcl_ftruncate(fd, length) ftruncate((fd), (length))
#define ZCL_LEAF_STORE_OPEN_FLAGS (O_RDWR | O_CREAT)
#endif

static void mmb_leaf_store_unmap(struct mmb_leaf_store *store)
{
    platform_read_mapping_close(&store->mapping);
    store->map = NULL;
    store->capacity = 0;
}

static bool mmb_leaf_store_map(struct mmb_leaf_store *store, size_t size)
{
    if (!platform_read_mapping_open(&store->mapping, store->fd, size)) {
        store->map = NULL;
        store->capacity = 0;
        return false;
    }
    store->map = store->mapping.data;
    store->capacity = (uint64_t)(size / 32u);
    return true;
}

static bool mmb_leaf_store_sync(struct mmb_leaf_store *store)
{
    if (!store->dirty) return true;
    if (platform_data_sync(store->fd) != 0)
        LOG_FAIL("mmb_leaf_store", "fsync failed for %s", store->path);
    store->dirty = false;
    return true;
}

bool mmb_leaf_store_validate(struct mmb_leaf_store *store,
                             struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_string_present(errors, store->path, "path");
    if (ar_errors_any(errors))
        return false;

    struct stat st;
    if (stat(store->path, &st) == 0 && st.st_size > 0) {
        validates_custom(errors,
                         (st.st_size % 32) == 0,
                         "file_size",
                         "must be a multiple of 32 bytes (leaf hash size)");
    }
    return !ar_errors_any(errors);
}

bool mmb_leaf_store_open(struct mmb_leaf_store *store, const char *path)
{
    if (!store || !path || !path[0]) return false;
    memset(store, 0, sizeof(*store));
    store->fd = -1;
    platform_read_mapping_init(&store->mapping);
    int path_length = snprintf(store->path, sizeof(store->path), "%s", path);
    if (path_length < 0 || (size_t)path_length >= sizeof(store->path))
        return false;

    struct ar_errors errors;
    if (!mmb_leaf_store_validate(store, &errors)) {
        char msg[512];
        ar_errors_full_messages(&errors, msg, sizeof(msg));
        LOG_FAIL("mmb_leaf_store", "mmb_leaf_store: invalid: %s", msg);
    }

    store->fd = open(path, ZCL_LEAF_STORE_OPEN_FLAGS, 0644);
    if (store->fd < 0) {
        LOG_FAIL("mmb_leaf_store", "mmb_leaf_store: cannot open %s", path);
    }

    struct stat st;
    if (fstat(store->fd, &st) == 0 && st.st_size > 0) {
        store->num_leaves = (uint64_t)st.st_size / 32;
        if ((uintmax_t)st.st_size > SIZE_MAX ||
            !mmb_leaf_store_map(store, (size_t)st.st_size)) {
            LOG_WARN("mmb_leaf_store", "mmb_leaf_store: mmap failed for %s", path);
        }
    }

    store->open = true;
    return true;
}

void mmb_leaf_store_close(struct mmb_leaf_store *store)
{
    if (!store->open) return;
    mmb_leaf_store_unmap(store);
    if (store->fd >= 0) {
        (void)mmb_leaf_store_sync(store);
        close(store->fd);
        store->fd = -1;
    }
    store->open = false;
}

bool mmb_leaf_store_append(struct mmb_leaf_store *store,
                           const uint8_t hash[32])
{
    if (!store->open || store->fd < 0) return false;

    mmb_leaf_store_unmap(store);

    off_t original_size = lseek(store->fd, 0, SEEK_END);
    if (original_size < 0) return false;

    size_t written = 0;
    while (written < 32u) {
        ssize_t w = write(store->fd, hash + written, 32u - written);
        if (w <= 0) {
            (void)zcl_ftruncate(store->fd, original_size);
            (void)lseek(store->fd, original_size, SEEK_SET);
            return false;
        }
        written += (size_t)w;
    }

    store->num_leaves++;
    store->dirty = true;
    return true;
}

bool mmb_leaf_store_remap(struct mmb_leaf_store *store)
{
    if (!store || !store->open || store->fd < 0)
        return false;

    mmb_leaf_store_unmap(store);

    struct stat st;
    if (fstat(store->fd, &st) != 0 || st.st_size <= 0)
        return false;
    if ((st.st_size % 32) != 0)
        return false;
    if (!mmb_leaf_store_sync(store))
        LOG_FAIL("mmb_leaf_store", "sync before remap failed for %s",
                store->path);

    store->num_leaves = (uint64_t)st.st_size / 32;
    store->capacity = store->num_leaves;
    if ((uintmax_t)st.st_size > SIZE_MAX) return false;
    return mmb_leaf_store_map(store, (size_t)st.st_size);
}

const uint8_t *mmb_leaf_store_get(const struct mmb_leaf_store *store,
                                  uint64_t index)
{
    if (!store || !store->map || index >= store->num_leaves)
        return NULL;
    if (index > (uint64_t)(SIZE_MAX / 32u)) return NULL;
    size_t offset = (size_t)index * 32u;
    if (offset > store->mapping.size ||
        store->mapping.size - offset < 32u) return NULL;
    return store->map + offset;
}

const uint8_t (*mmb_leaf_store_all(const struct mmb_leaf_store *store))[32]
{
    if (!store || !store->map || store->num_leaves == 0 ||
        store->num_leaves > store->mapping.size / 32u)
        return NULL;
    return (const uint8_t (*)[32])store->map;
}

uint64_t mmb_leaf_store_rebuild(struct mmb_leaf_store *store,
                                const void *chain_active_ptr)
{
    if (!store || !store->open || !chain_active_ptr) return 0;

    const struct active_chain *chain =
        (const struct active_chain *)chain_active_ptr;
    int height = active_chain_height(chain);
    if (height < 0) return 0;

    /* Unmap existing data */
    mmb_leaf_store_unmap(store);

    /* Truncate and rewrite */
    if (zcl_ftruncate(store->fd, 0) != 0) return 0;
    lseek(store->fd, 0, SEEK_SET);
    store->num_leaves = 0;
    store->dirty = true;

    uint64_t count = 0;
    int64_t t0 = platform_time_monotonic_us();

    sqlite3 *pdb = progress_store_db();
    for (int h = 0; h <= height; h++) {
        const struct block_index *bi = active_chain_at(chain, h);
        if (!bi || !bi->phashBlock) continue;

        /* Reproduce the boundary utxo_root the live connect path recorded so a
         * rebuilt leaf hash is byte-identical to it (the store keeps only the
         * 32-byte hash, not the root). A missing boundary entry → zero
         * sentinel: that height's hash matches what the live path produced
         * before it had a root, never a forged binding. */
        uint8_t utxo_root[32] = {0};
        if (pdb && bi->nHeight > 0 &&
            bi->nHeight % MMR_COMMITMENT_INTERVAL == 0) {
            bool found = false;
            coins_kv_boundary_root_get(pdb, bi->nHeight, utxo_root, &found);
            if (!found) memset(utxo_root, 0, 32);
        }

        struct mmb_leaf leaf;
        mmb_leaf_from_block(&leaf,
            bi->phashBlock->data,
            bi->nHeight, bi->nTime, bi->nBits,
            bi->hashFinalSaplingRoot.data,
            (const uint8_t *)bi->nChainWork.pn,
            utxo_root);

        uint8_t hash[32];
        mmb_hash_leaf(&leaf, hash);

        if (!mmb_leaf_store_append(store, hash))
            break;
        count++;

        if (count % 500000 == 0)
            printf("[mmb_leaf_store] %llu/%d hashes written...\n",
                   (unsigned long long)count, height + 1);
    }

    int64_t elapsed = (platform_time_monotonic_us() - t0) / 1000000LL;

    printf("[mmb_leaf_store] Built %llu leaf hashes in %llds (%s)\n",
           (unsigned long long)count, (long long)elapsed, store->path);

    /* The remap boundary is also the durability boundary for the rebuild. */
    if (count > 0) (void)mmb_leaf_store_remap(store);

    return count;
}
