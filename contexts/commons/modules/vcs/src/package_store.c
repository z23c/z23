/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_store — public API and policy for the local ZCODE package
 * store: quota pools, deterministic eviction, admission (manifest /
 * chunk / release), pins, and state introspection. Filesystem layout and
 * crash recovery live in package_store_io.c; the frozen contract is in
 * vcs/package_store.h. Slice 2 is LOCAL STORE ONLY: no P2P, no RPC
 * spend, no reward credit. */

#include "package_store_priv.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "platform/positioned_file.h"
#include "platform/file_metadata.h"
#include "platform/rng.h"
#include "util/util.h"
#include "vcs/package_recipe.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <io.h>
#include <windows.h>
#else
#include <sys/file.h>
#endif
#include <unistd.h>

#define STORE_LOG "vcs.store"

bool store_process_lock(struct vcs_package_store *store)
{
#ifdef _WIN32
    if (!store || store->process_lock_fd < 0)
        return false;
    intptr_t raw = _get_osfhandle(store->process_lock_fd);
    if (raw == -1)
        return false;
    OVERLAPPED overlap = {0};
    return LockFileEx((HANDLE)raw, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0,
                      &overlap) != 0;
#else
    if (!store || store->process_lock_fd < 0)
        return false;
    int rc;
    do {
        rc = flock(store->process_lock_fd, LOCK_EX);
    } while (rc != 0 && errno == EINTR);
    return rc == 0;
#endif
}

void store_process_unlock(struct vcs_package_store *store)
{
#ifdef _WIN32
    if (store && store->process_lock_fd >= 0) {
        intptr_t raw = _get_osfhandle(store->process_lock_fd);
        OVERLAPPED overlap = {0};
        if (raw != -1)
            (void)UnlockFileEx((HANDLE)raw, 0, 1, 0, &overlap);
    }
#else
    if (store && store->process_lock_fd >= 0)
        (void)flock(store->process_lock_fd, LOCK_UN);
#endif
}

/* The process lock serializes this atomic change detector. It grants no
 * object authority: open still rebuilds from manifests and CAS, and final
 * publication validates those files. A damaged detector is replaced with a
 * fresh epoch; handles that saw the old epoch then refuse further mutation. */
static bool store_generation_path(struct vcs_package_store *store,
                                  char path[STORE_PATH_MAX])
{
    int n = snprintf(path, STORE_PATH_MAX, "%s/store-generation", store->root);
    return n > 0 && n < (int)STORE_PATH_MAX;
}

bool store_generation_read(struct vcs_package_store *store, uint64_t *value)
{
    char path[STORE_PATH_MAX];
    if (!store_generation_path(store, path)) return false;
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path)) return false;
    uint8_t bytes[9];
    int64_t n = platform_positioned_file_read(&file, bytes, sizeof(bytes), 0);
    platform_positioned_file_close(&file);
    if (n != 8) return false;
    *value = zcl_read_u64_le(bytes);
    return true;
}

static bool store_generation_write(struct vcs_package_store *store,
                                   uint64_t value)
{
    char path[STORE_PATH_MAX];
    if (!store_generation_path(store, path)) return false;
    uint8_t bytes[8];
    zcl_write_u64_le(bytes, value);
    return store_atomic_write(path, bytes, sizeof(bytes));
}

bool store_generation_check(struct vcs_package_store *store)
{
    uint64_t value = 0;
    return store_generation_read(store, &value) &&
           value == store->shared_generation;
}

bool store_generation_advance(struct vcs_package_store *store)
{
    if (!store_generation_check(store) ||
        store->shared_generation == UINT64_MAX) return false;
    uint64_t value = store->shared_generation + 1;
    if (!store_generation_write(store, value)) return false;
    store->shared_generation = value;
    return true;
}

static bool store_generation_initialize(struct vcs_package_store *store)
{
    if (store_generation_read(store, &store->shared_generation)) return true;
    uint64_t seed = 0;
    if (!rng_fill((uint8_t *)&seed, sizeof(seed)))
        LOG_FAIL(STORE_LOG, "random store generation seed");
    if (!seed) seed = 1;
    if (!store_generation_write(store, seed))
        LOG_FAIL(STORE_LOG, "write initial store generation");
    store->shared_generation = seed;
    return true;
}

void store_partial_catalog_free(struct vcs_package_store *store)
{
    for (size_t i = 0; i < store->pkg_count; i++) {
        store_package_release_hot(store, &store->pkgs[i]);
        free(store->pkgs[i].chunks);
    }
    free(store->pkgs);
    free(store->root_order);
    free(store->cas);
}

const char *vcs_package_store_result_string(
    enum vcs_package_store_result result)
{
    switch (result) {
    case VCS_PACKAGE_STORE_OK: return "ok";
    case VCS_PACKAGE_STORE_ERR_NULL: return "null-argument";
    case VCS_PACKAGE_STORE_ERR_IO: return "io-failure";
    case VCS_PACKAGE_STORE_ERR_MANIFEST: return "manifest-invalid";
    case VCS_PACKAGE_STORE_ERR_PACKAGE_CAP: return "package-over-64mib";
    case VCS_PACKAGE_STORE_ERR_CHUNK_HASH: return "chunk-hash-mismatch";
    case VCS_PACKAGE_STORE_ERR_CHUNK_COORD: return "chunk-coordinates-invalid";
    case VCS_PACKAGE_STORE_ERR_CHUNK_MISSING: return "chunk-missing";
    case VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE: return "unknown-package";
    case VCS_PACKAGE_STORE_ERR_QUOTA: return "pool-quota-exhausted";
    case VCS_PACKAGE_STORE_ERR_ACCEPT: return "release-acceptance-failed";
    case VCS_PACKAGE_STORE_ERR_ALLOC: return "allocation-failed";
    case VCS_PACKAGE_STORE_ERR_LIMIT: return "tracked-package-limit";
    case VCS_PACKAGE_STORE_ERR_RECIPE: return "recipe-invalid";
    }
    return "unknown-result";
}

const char *vcs_package_store_pool_string(enum vcs_package_store_pool pool)
{
    switch (pool) {
    case VCS_PACKAGE_STORE_POOL_PINS: return "pins";
    case VCS_PACKAGE_STORE_POOL_HOT: return "hot";
    case VCS_PACKAGE_STORE_POOL_RARE: return "rare";
    case VCS_PACKAGE_STORE_POOL_STAGING: return "staging";
    }
    return "unknown-pool";
}

bool vcs_package_store_hosting_enabled(void)
{
    return GetBoolArg("-packagehost", false);
}

uint64_t vcs_package_store_quota_bytes(void)
{
    int64_t v = GetArgInt("-packagequota",
                          (int64_t)VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    return v < 0 ? VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES : (uint64_t)v;
}

/* ── derived accounting ───────────────────────────────────────────── */
uint64_t store_pool_budget(const struct vcs_package_store *store,
                           enum vcs_package_store_pool pool)
{
    static const unsigned k_tenths[] = {
        VCS_PACKAGE_STORE_PINS_TENTHS, VCS_PACKAGE_STORE_HOT_TENTHS,
        VCS_PACKAGE_STORE_RARE_TENTHS, VCS_PACKAGE_STORE_STAGING_TENTHS,
    };
    unsigned tenths = k_tenths[pool];
    /* Overflow-safe quota*tenths/10. */
    return (store->quota / 10u) * tenths +
           ((store->quota % 10u) * tenths) / 10u;
}

struct store_package *store_find(struct vcs_package_store *store,
                                        const uint8_t root[32],
                                        size_t *index_out)
{
    size_t lo = 0, hi = store->pkg_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = memcmp(store->pkgs[store->root_order[mid]].root,
                         root, 32);
        if (cmp < 0) lo = mid + 1;
        else hi = mid;
    }
    if (lo < store->pkg_count) {
        size_t i = store->root_order[lo];
        if (memcmp(store->pkgs[i].root, root, 32) == 0) {
            if (!store_package_materialize(store, &store->pkgs[i])) {
                store->catalog_incomplete = true;
                return NULL;
            }
            if (index_out) *index_out = i;
            return &store->pkgs[i];
        }
    }
    return NULL;
}

static enum vcs_package_store_pool store_package_pool(
    struct vcs_package_store *store, const struct store_package *pkg)
{
    if (pkg->pinned)
        return VCS_PACKAGE_STORE_POOL_PINS;
    if (!store_package_complete(store, pkg))
        return VCS_PACKAGE_STORE_POOL_STAGING;
    return pkg->class_ == VCS_PACKAGE_STORE_CLASS_HOT
               ? VCS_PACKAGE_STORE_POOL_HOT
               : VCS_PACKAGE_STORE_POOL_RARE;
}

uint64_t store_pool_usage_locked(struct vcs_package_store *store,
                                  enum vcs_package_store_pool pool)
{
    uint64_t usage = 0;
    for (size_t i = 0; i < store->pkg_count; i++) {
        if (store_package_pool(store, &store->pkgs[i]) != pool)
            continue;
        uint64_t bytes = 0;
        store_package_present(store, &store->pkgs[i], NULL, &bytes);
        if (UINT64_MAX - usage < bytes)
            return UINT64_MAX;
        usage += bytes;
    }
    return usage;
}

void store_pool_usages_locked(struct vcs_package_store *store,
                              uint64_t usage[4])
{
    memset(usage, 0, 4u * sizeof(*usage));
    for (size_t i = 0; i < store->pkg_count; i++) {
        enum vcs_package_store_pool pool =
            store_package_pool(store, &store->pkgs[i]);
        uint64_t bytes = 0;
        store_package_present(store, &store->pkgs[i], NULL, &bytes);
        usage[pool] = UINT64_MAX - usage[pool] < bytes
                          ? UINT64_MAX : usage[pool] + bytes;
    }
}

uint64_t vcs_package_store_pool_usage(struct vcs_package_store *store,
                                      enum vcs_package_store_pool pool)
{
    if (!store)
        return 0;
    pthread_mutex_lock(&store->lock);
    uint64_t usage = store_pool_usage_locked(store, pool);
    pthread_mutex_unlock(&store->lock);
    return usage;
}

/* ── eviction ─────────────────────────────────────────────────────── */
/* Does any tracked package other than skip reference this chunk hash? */
static bool store_chunk_shared(const struct vcs_package_store *store,
                               const uint8_t hash[32], size_t skip)
{
    for (size_t i = 0; i < store->pkg_count; i++) {
        if (i == skip)
            continue;
        const struct store_package *pkg = &store->pkgs[i];
        for (size_t c = 0; c < pkg->chunk_count; c++)
            if (memcmp(pkg->chunks[c].hash, hash, 32) == 0)
                return true;
    }
    return false;
}

/* Remove a package from the table: delete its manifest (or staging dir),
 * any pin marker, and the CAS chunks no other package references. */
static bool store_drop_package(struct vcs_package_store *store, size_t index)
{
    struct store_package *pkg = &store->pkgs[index];
    char path[STORE_PATH_MAX];
    if (pkg->committed) {
        snprintf(path, sizeof(path), "%s/manifests/%s", store->root,
                 pkg->root_hex);
        if (!store_unlink(path))
            LOG_RETURN(false, STORE_LOG, "evict unlink %s: %s", path,
                       strerror(errno));
    } else {
        snprintf(path, sizeof(path), "%s/staging/%s", store->root,
                 pkg->root_hex);
        if (!store_rm_rf(path))
            LOG_RETURN(false, STORE_LOG, "evict staging cleanup %s", path);
    }
    snprintf(path, sizeof(path), "%s/pins/%s", store->root, pkg->root_hex);
    if (!store_unlink(path)) {
        store->catalog_incomplete = true;
        LOG_RETURN(false, STORE_LOG, "evict pin unlink %s: %s", path,
                   strerror(errno));
    }
    store->manifest_bytes_total -= pkg->total_bytes;
    store->next_mutation_generation++;
    if (!store->next_mutation_generation)
        store->next_mutation_generation++;
    for (size_t c = 0; c < pkg->chunk_count; c++) {
        if (store_chunk_shared(store, pkg->chunks[c].hash, index))
            continue;
        store_cas_path(store, pkg->chunks[c].hash, path, sizeof(path));
        if (!store_unlink(path)) {
            LOG_ERROR(STORE_LOG, "evict chunk unlink %s: %s", path,
                      strerror(errno));
            continue; /* leftover CAS bytes are harmless; retain presence */
        }
        store_cas_remove(store, pkg->chunks[c].hash);
    }
    store_package_release_hot(store, pkg);
    free(pkg->chunks);
    size_t removed = 0;
    while (removed < store->pkg_count && store->root_order[removed] != index)
        removed++;
    if (removed < store->pkg_count) {
        memmove(store->root_order + removed, store->root_order + removed + 1,
                (store->pkg_count - removed - 1) * sizeof(*store->root_order));
    }
    for (size_t i = 0; i + 1 < store->pkg_count; i++)
        if (store->root_order[i] == store->pkg_count - 1)
            store->root_order[i] = index;
    store->pkgs[index] = store->pkgs[store->pkg_count - 1];
    store->pkg_count--;
    return true;
}

/* Victim selection — deterministic, frozen (see package_store.h):
 * HOT evicts least-recently-requested first; RARE evicts
 * best-replicated-elsewhere first. The incoming package and pins are
 * never victims. Returns the table index or -1. */
static long store_pick_victim(struct vcs_package_store *store,
                              enum vcs_package_store_pool pool,
                              const uint8_t protect_root[32])
{
    long best = -1;
    for (size_t i = 0; i < store->pkg_count; i++) {
        const struct store_package *pkg = &store->pkgs[i];
        if (pkg->pinned || store_package_pool(store, pkg) != pool)
            continue;
        if (protect_root && memcmp(pkg->root, protect_root, 32) == 0)
            continue;
        if (best < 0) {
            best = (long)i;
            continue;
        }
        const struct store_package *cur = &store->pkgs[best];
        bool better;
        if (pool == VCS_PACKAGE_STORE_POOL_HOT) {
            better = pkg->access_count < cur->access_count ||
                (pkg->access_count == cur->access_count &&
                 (pkg->last_access < cur->last_access ||
                  (pkg->last_access == cur->last_access &&
                   memcmp(pkg->root, cur->root, 32) < 0)));
        } else {
            better = pkg->replicas > cur->replicas ||
                (pkg->replicas == cur->replicas &&
                 (pkg->access_count < cur->access_count ||
                  (pkg->access_count == cur->access_count &&
                   memcmp(pkg->root, cur->root, 32) < 0)));
        }
        if (better)
            best = (long)i;
    }
    return best;
}

/* A new manifest is refused when it can never fit the pool it will land
 * in. A pre-existing pin marker charges PINS, which never evicts, so the
 * package must fit the bytes still free in that budget. An unpinned
 * manifest must fit both its eventual class pool and the staging pool it
 * assembles in. */
static bool store_manifest_pool_fits(struct vcs_package_store *store,
                                     bool pre_pinned, uint64_t total_bytes,
                                     enum vcs_package_store_pool eventual)
{
    if (total_bytes > store_pool_budget(store, eventual))
        return false;
    if (!pre_pinned)
        return total_bytes <=
               store_pool_budget(store, VCS_PACKAGE_STORE_POOL_STAGING);
    uint64_t budget = store_pool_budget(store, VCS_PACKAGE_STORE_POOL_PINS);
    uint64_t used = store_pool_usage_locked(store, VCS_PACKAGE_STORE_POOL_PINS);
    if (used > budget)
        return false;
    return total_bytes <= budget - used;
}

/* Make room for incoming_bytes in pool, evicting (HOT/RARE only) until
 * it fits. STAGING and PINS never evict. False = no room and no victim. */
bool store_ensure_room(struct vcs_package_store *store,
                              enum vcs_package_store_pool pool,
                              uint64_t incoming,
                              const uint8_t protect_root[32])
{
    uint64_t budget = store_pool_budget(store, pool);
    uint64_t used;
    bool catalog_checked = false;
    while ((used = store_pool_usage_locked(store, pool)) > budget ||
           incoming > budget - used) {
        if (pool == VCS_PACKAGE_STORE_POOL_PINS ||
            pool == VCS_PACKAGE_STORE_POOL_STAGING)
            return false;
        long victim = store_pick_victim(store, pool, protect_root);
        if (victim < 0)
            return false;
        /* Eviction may remove CAS bytes. Recheck the authoritative manifest
         * catalog before deciding that no untracked package references them.
         * This cold scan happens only when eviction is actually needed. */
        if (!catalog_checked) {
            if (store_catalog_validate_disk(store) !=
                VCS_PACKAGE_STORE_PAGE_OK) {
                store->catalog_incomplete = true;
                LOG_ERROR(STORE_LOG,
                          "eviction refused: package catalog changed");
                return false;
            }
            catalog_checked = true;
        }
        LOG_INFO(STORE_LOG, "evicting %s package %s (pool %s over budget)",
                 vcs_package_store_pool_string(pool),
                 store->pkgs[victim].root_hex,
                 vcs_package_store_pool_string(pool));
        if (!store_drop_package(store, (size_t)victim)) {
            store->catalog_incomplete = true;
            return false;
        }
        store->evictions_total++;
    }
    return true;
}

/* Admission that cannot evict another package. Caller holds both store
 * locks, so this check and the following write observe one quota state. */
static bool store_room_available(struct vcs_package_store *store,
                                 enum vcs_package_store_pool pool,
                                 uint64_t incoming)
{
    uint64_t budget = store_pool_budget(store, pool);
    uint64_t used = store_pool_usage_locked(store, pool);
    return used <= budget && incoming <= budget - used;
}

/* ── open / close ─────────────────────────────────────────────────── */
static bool store_open_lock_ready(struct vcs_package_store *store)
{
    return store->process_lock_fd >= 0 && store_process_lock(store);
}

struct vcs_package_store *vcs_package_store_open(const char *datadir,
                                                 uint64_t quota_bytes)
{
    if (!datadir)
        LOG_NULL(STORE_LOG, "null datadir");
    struct vcs_package_store *store =
        zcl_malloc(sizeof(*store), "vcs_package_store");
    if (!store)
        LOG_NULL(STORE_LOG, "alloc store");
    memset(store, 0, sizeof(*store));
    store->process_lock_fd = -1;
    int n = snprintf(store->root, sizeof(store->root), "%s/zcode", datadir);
    if (n <= 0 || (size_t)n >= sizeof(store->root)) {
        free(store);
        LOG_NULL(STORE_LOG, "datadir too long");
    }
    store->preexisting_root = store_directory_exists(store->root);
    if (!store_mkdir_p(store->root)) {
        free(store);
        LOG_NULL(STORE_LOG, "create store root");
    }
    char lock_path[STORE_PATH_MAX];
    n = snprintf(lock_path, sizeof(lock_path), "%s/store-process.lock",
                 store->root);
    if (n <= 0 || (size_t)n >= sizeof(lock_path)) {
        free(store);
        LOG_NULL(STORE_LOG, "process lock path too long");
    }
#ifdef _WIN32
    int wide_count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                         lock_path, -1, NULL, 0);
    wchar_t wide_lock[STORE_PATH_MAX];
    HANDLE lock_handle = INVALID_HANDLE_VALUE;
    if (wide_count > 0 && wide_count <= (int)STORE_PATH_MAX &&
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, lock_path, -1,
                            wide_lock, wide_count) == wide_count) {
        lock_handle = CreateFileW(
            wide_lock, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            NULL);
    }
    if (lock_handle != INVALID_HANDLE_VALUE) {
        FILE_ATTRIBUTE_TAG_INFO tag;
        if (!GetFileInformationByHandleEx(lock_handle, FileAttributeTagInfo,
                                          &tag, sizeof(tag)) ||
            (tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
                                   FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
            CloseHandle(lock_handle);
            lock_handle = INVALID_HANDLE_VALUE;
        }
    }
    if (lock_handle != INVALID_HANDLE_VALUE) {
        store->process_lock_fd = _open_osfhandle(
            (intptr_t)lock_handle, _O_RDWR | _O_BINARY);
        if (store->process_lock_fd < 0)
            CloseHandle(lock_handle);
    }
#else
    store->process_lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC,
                                  0600);
#endif
    if (!store_open_lock_ready(store)) {
        if (store->process_lock_fd >= 0)
            close(store->process_lock_fd);
        free(store);
        LOG_NULL(STORE_LOG, "could not lock store recovery at %s", lock_path);
    }
    if (!store_generation_initialize(store)) {
        store_process_unlock(store);
        close(store->process_lock_fd);
        free(store);
        LOG_NULL(STORE_LOG, "initialize store generation at %s", lock_path);
    }
    store->quota = quota_bytes;
    pthread_mutex_init(&store->lock, NULL);
    store->accept = vcs_package_accept_new();
    if (!store->accept) {
        store_process_unlock(store);
        close(store->process_lock_fd);
        pthread_mutex_destroy(&store->lock);
        free(store);
        LOG_NULL(STORE_LOG, "alloc accept context");
    }
    if (!store_open_recover(store)) {
        char root_copy[STORE_PATH_MAX];
        snprintf(root_copy, sizeof(root_copy), "%s", store->root);
        store_partial_catalog_free(store);
        vcs_package_accept_free(store->accept);
        store_process_unlock(store);
        close(store->process_lock_fd);
        pthread_mutex_destroy(&store->lock);
        free(store);
        LOG_NULL(STORE_LOG, "recovery under %s", root_copy);
    }
    store_process_unlock(store);
    LOG_INFO(STORE_LOG,
             "package store open at %s (quota %llu bytes, %zu packages, "
             "%zu CAS chunks, %llu orphans GC'd)",
             store->root, (unsigned long long)store->quota,
             store->pkg_count, store->cas_count,
             (unsigned long long)store->gc_orphans_total);
    return store;
}

void vcs_package_store_close(struct vcs_package_store *store)
{
    if (!store)
        return;
    for (size_t i = 0; i < store->pkg_count; i++) {
        store_package_release_hot(store, &store->pkgs[i]);
        free(store->pkgs[i].chunks);
    }
    free(store->pkgs);
    free(store->root_order);
    free(store->cas);
    vcs_package_accept_free(store->accept);
    close(store->process_lock_fd);
    pthread_mutex_destroy(&store->lock);
    free(store);
}

bool vcs_package_store_pin_plan(
    struct vcs_package_store *store, const uint8_t root[32], bool pinned,
    struct vcs_package_store_status *status_out, uint8_t token_out[32])
{
    if (!store || !root || !status_out || !token_out)
        return false;
    memset(status_out, 0, sizeof(*status_out));
    if (!vcs_package_store_package_status(store, root, status_out))
        return false;
    struct sha3_256_ctx sha;
    uint8_t want = pinned ? 1u : 0u;
    uint8_t have = status_out->pinned ? 1u : 0u;
    uint8_t tracked = status_out->tracked ? 1u : 0u;
    uint8_t complete = status_out->complete ? 1u : 0u;
    uint8_t pool = (uint8_t)status_out->pool;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)"zcl.package.pin.plan.v2", 24);
    sha3_256_write(&sha, root, 32);
    sha3_256_write(&sha, &want, 1);
    sha3_256_write(&sha, &have, 1);
    sha3_256_write(&sha, &tracked, 1);
    sha3_256_write(&sha, &complete, 1);
    sha3_256_write(&sha, &pool, 1);
    sha3_256_finalize(&sha, token_out);
    return true;
}

static pthread_mutex_t g_global_lock = PTHREAD_MUTEX_INITIALIZER;
static struct vcs_package_store *g_global_store;

const char *vcs_package_store_root_dir(const struct vcs_package_store *store)
{
    return store ? store->root : NULL;
}

bool vcs_package_store_open_global(void)
{
    pthread_mutex_lock(&g_global_lock);
    if (g_global_store) {
        pthread_mutex_unlock(&g_global_lock);
        return true;
    }
    if (!vcs_package_store_hosting_enabled()) {
        pthread_mutex_unlock(&g_global_lock);
        return false;
    }
    char datadir[STORE_PATH_MAX];
    GetDataDir(false, datadir, sizeof(datadir));
    g_global_store =
        vcs_package_store_open(datadir, vcs_package_store_quota_bytes());
    if (g_global_store && !vcs_package_store_network_allowed(g_global_store)) {
        vcs_package_store_close(g_global_store);
        g_global_store = NULL;
        LOG_ERROR(STORE_LOG, "local-only package store cannot host network content");
    }
    bool ok = g_global_store != NULL;
    pthread_mutex_unlock(&g_global_lock);
    return ok;
}

bool vcs_package_store_network_allowed(const struct vcs_package_store *store)
{
    if (!store) return false;
    char marker[STORE_PATH_MAX];
    int n = snprintf(marker, sizeof(marker), "%s/local-only", store->root);
    if (n < 0 || (size_t)n >= sizeof(marker)) return false;
    struct platform_file_metadata metadata;
    return platform_file_metadata_read(marker, &metadata) == PLATFORM_FILE_METADATA_MISSING;
}

struct vcs_package_store *vcs_package_store_global(void)
{
    pthread_mutex_lock(&g_global_lock);
    struct vcs_package_store *store = g_global_store;
    pthread_mutex_unlock(&g_global_lock);
    return store;
}

void vcs_package_store_close_global(void)
{
    pthread_mutex_lock(&g_global_lock);
    struct vcs_package_store *store = g_global_store;
    g_global_store = NULL;
    pthread_mutex_unlock(&g_global_lock);
    vcs_package_store_close(store);
}

/* ── admission: manifests ─────────────────────────────────────────── */
/* Commit this package if it is staged and CAS-complete. */
static bool store_commit_if_complete(struct vcs_package_store *store,
                                     const uint8_t root[32])
{
    struct store_package *pkg = store_find(store, root, NULL);
    if (pkg && !pkg->committed && store_package_complete(store, pkg))
        return store_package_commit(store, pkg);
    return true;
}

static enum vcs_package_store_result store_finish_dedup_manifest(
    struct vcs_package_store *store, const uint8_t root[32], size_t index,
    bool no_evict)
{
    struct store_package *pkg = &store->pkgs[index];
    if (!store_package_complete(store, pkg)) return VCS_PACKAGE_STORE_OK;
    enum vcs_package_store_pool pool =
        pkg->pinned ? VCS_PACKAGE_STORE_POOL_PINS
                    : VCS_PACKAGE_STORE_POOL_RARE;
    /* The newly added complete package already contributes its bytes. */
    if (!(no_evict ? store_room_available(store, pool, 0)
                   : store_ensure_room(store, pool, 0, pkg->root))) {
        if (store->catalog_incomplete)
            LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                       "manifest admission stopped: catalog incomplete");
        if (!store_drop_package(store, index)) {
            store->catalog_incomplete = true;
            LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                       "manifest rollback failed");
        }
        store->quota_rejects_total++;
        return VCS_PACKAGE_STORE_ERR_QUOTA;
    }
    if (!store_commit_if_complete(store, root))
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "commit complete dedup manifest");
    return VCS_PACKAGE_STORE_OK;
}

static enum vcs_package_store_result store_manifest_preflight(
    struct vcs_package_store *store, const char *root_hex,
    uint64_t total_bytes, bool no_evict)
{
    if (total_bytes > VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES)
        return VCS_PACKAGE_STORE_ERR_PACKAGE_CAP;
    char pin[STORE_PATH_MAX];
    snprintf(pin, sizeof(pin), "%s/pins/%s", store->root, root_hex);
    bool pre_pinned = store_path_exists(pin);
    enum vcs_package_store_pool eventual =
        pre_pinned ? VCS_PACKAGE_STORE_POOL_PINS : VCS_PACKAGE_STORE_POOL_RARE;
    if (!store_manifest_pool_fits(store, pre_pinned, total_bytes, eventual) ||
        (no_evict && !store_room_available(store, eventual, total_bytes)) ||
        (no_evict && !pre_pinned &&
         !store_room_available(store, VCS_PACKAGE_STORE_POOL_STAGING,
                               total_bytes))) {
        store->quota_rejects_total++;
        return VCS_PACKAGE_STORE_ERR_QUOTA;
    }
    return VCS_PACKAGE_STORE_OK;
}

static enum vcs_package_store_result store_existing_manifest_noop(
    const struct vcs_package_store *store, const struct store_package *existing)
{
    if (store_catalog_validate_record_disk(store, existing) !=
        VCS_PACKAGE_STORE_PAGE_OK)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "manifest no-op refused: authoritative object missing");
    return VCS_PACKAGE_STORE_OK;
}

static enum vcs_package_store_result store_put_manifest_mode(
    struct vcs_package_store *store, const uint8_t *wire, size_t wire_len,
    uint8_t root_out[32], bool no_evict)
{
    if (!store || !wire)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_NULL, STORE_LOG,
                   "null store/wire");
    pthread_mutex_lock(&store->lock);
    if (store->catalog_incomplete) {
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "manifest admission refused: catalog incomplete");
    }

    uint8_t root[32];
    uint64_t total_bytes = 0;
    if (!store_manifest_identity(wire, wire_len, root, &total_bytes)) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_MANIFEST;
    }
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);

    if (root_out)
        memcpy(root_out, root, 32);
    if (!store_process_lock(store)) {
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "lock store for manifest admission");
    }
    if (!store_generation_check(store)) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "manifest admission refused: stale store handle");
    }
    struct store_package *existing = store_find(store, root, NULL);
    if (store->catalog_incomplete) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "manifest admission refused: catalog changed");
    }
    if (existing) {
        enum vcs_package_store_result result =
            store_existing_manifest_noop(store, existing);
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        return result; /* same root = same content: no-op if still present */
    }
    /* Early feasibility: the package must fit the pool it will end in.
     * A pin marker charges the pins budget, which never evicts, so a
     * package that does not fit the bytes still free is refused before
     * any manifest or chunk is admitted. */
    enum vcs_package_store_result preflight =
        store_manifest_preflight(store, root_hex, total_bytes, no_evict);
    if (preflight != VCS_PACKAGE_STORE_OK) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        return preflight;
    }

    char staging_dir[STORE_PATH_MAX];
    char staged[STORE_PATH_MAX];
    snprintf(staging_dir, sizeof(staging_dir), "%s/staging/%s", store->root,
             root_hex);
    snprintf(staged, sizeof(staged), "%s/manifest", staging_dir);
    if (!store_generation_advance(store) || !store_mkdir_p(staging_dir) ||
        !store_atomic_write(staged, wire, wire_len)) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_IO;
    }
    if (!store_record_add(store, wire, wire_len, root_hex, false)) {
        store_rm_rf(staging_dir);
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_ALLOC;
    }
    enum vcs_package_store_result result = store_finish_dedup_manifest(
        store, root, store->pkg_count - 1, no_evict);
    store_process_unlock(store);
    pthread_mutex_unlock(&store->lock);
    return result;
}

enum vcs_package_store_result vcs_package_store_put_manifest(
    struct vcs_package_store *store, const uint8_t *wire, size_t wire_len,
    uint8_t root_out[32])
{
    return store_put_manifest_mode(store, wire, wire_len, root_out, false);
}

enum vcs_package_store_result vcs_package_store_put_manifest_no_evict(
    struct vcs_package_store *store, const uint8_t *wire, size_t wire_len,
    uint8_t root_out[32])
{
    return store_put_manifest_mode(store, wire, wire_len, root_out, true);
}

/* ── admission: chunks ────────────────────────────────────────────── */
/* Model the new CAS hash under the admission lock. Other staged manifests
 * may share it and become complete, moving bytes between pools. Check the
 * whole derived state before making the hash durable. */
static enum vcs_package_store_result store_chunk_room_no_evict(
    struct vcs_package_store *store, const uint8_t hash[32])
{
    if (!store_cas_insert(store, hash))
        return VCS_PACKAGE_STORE_ERR_ALLOC;
    uint64_t usage[4];
    store_pool_usages_locked(store, usage);
    bool fits = true;
    for (int pool = VCS_PACKAGE_STORE_POOL_PINS;
         pool <= VCS_PACKAGE_STORE_POOL_STAGING; pool++) {
        if (usage[pool] > store_pool_budget(store, pool)) {
            fits = false;
            break;
        }
    }
    store_cas_remove(store, hash);
    if (fits) return VCS_PACKAGE_STORE_OK;
    store->quota_rejects_total++;
    return VCS_PACKAGE_STORE_ERR_QUOTA;
}

static bool store_chunk_persist(struct vcs_package_store *store,
                                const uint8_t hash[32],
                                const uint8_t *chunk, size_t chunk_len,
                                const uint8_t package_root[32],
                                bool will_complete)
{
    if (!store_chunk_write_verified(store, hash, chunk, chunk_len))
        return false;
    store_packages_touch_hash(store, hash);
    if (will_complete && !store_commit_if_complete(store, package_root))
        LOG_RETURN(false, STORE_LOG, "commit verified chunk package");
    return true;
}

static enum vcs_package_store_result store_chunk_admit(
    struct vcs_package_store *store, struct store_package *pkg,
    const uint8_t hash[32],
    const uint8_t package_root[32], bool no_evict, bool *will_complete)
{
    if (!no_evict && !store_generation_advance(store))
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "advance store generation for chunk admission");
    if (no_evict) {
        uint32_t present_before = 0;
        store_package_present(store, pkg, &present_before, NULL);
        *will_complete = (uint64_t)present_before + 1u == pkg->chunk_count;
    }
    enum vcs_package_store_result result = no_evict
        ? store_chunk_room_no_evict(store, hash)
        : store_chunk_room(store, pkg, hash, package_root, will_complete);
    if (result != VCS_PACKAGE_STORE_OK) return result;
    if (no_evict && !store_generation_advance(store))
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "advance store generation for no-evict chunk admission");
    return VCS_PACKAGE_STORE_OK;
}

static enum vcs_package_store_result store_put_chunk_mode(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *path, uint32_t chunk_index, const uint8_t *chunk,
    size_t chunk_len, bool no_evict)
{
    if (!store_chunk_inputs_valid(store, package_root, path, chunk))
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_NULL, STORE_LOG,
                   "null store/root/path/chunk");
    pthread_mutex_lock(&store->lock);

    if (!store_process_lock(store)) {
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "lock store for chunk admission");
    }
    if (!store_generation_check(store)) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "chunk admission refused: stale store handle");
    }

    struct store_package *pkg = store_find(store, package_root, NULL);
    if (store->catalog_incomplete) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "chunk admission refused: catalog incomplete");
    }
    if (!pkg) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE;
    }
    uint8_t hash[32];
    enum vcs_package_store_result checked = store_chunk_hash_checked(
        pkg, path, chunk_index, chunk, chunk_len, hash);
    if (checked != VCS_PACKAGE_STORE_OK) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        return checked;
    }

    /* Dedup: the content is already in the CAS, so it was already
     * present-for-this-package too — nothing changes. */
    if (store_cas_contains(store, hash)) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_OK;
    }
    bool will_complete = false;
    enum vcs_package_store_result result = store_chunk_admit(
        store, pkg, hash, package_root, no_evict,
        &will_complete);
    if (result != VCS_PACKAGE_STORE_OK) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        return result;
    }
    /* Verified above; store it. Temp + fsync + atomic rename beside the
     * final name, so a crash never leaves a partial chunk under a hash. */
    if (!store_chunk_persist(store, hash, chunk, chunk_len,
                             package_root, will_complete)) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_IO;
    }
    store_process_unlock(store);
    pthread_mutex_unlock(&store->lock);
    return VCS_PACKAGE_STORE_OK;
}

enum vcs_package_store_result vcs_package_store_put_chunk(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *path, uint32_t chunk_index, const uint8_t *chunk,
    size_t chunk_len)
{
    return store_put_chunk_mode(store, package_root, path, chunk_index,
                                chunk, chunk_len, false);
}

enum vcs_package_store_result vcs_package_store_put_chunk_no_evict(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *path, uint32_t chunk_index, const uint8_t *chunk,
    size_t chunk_len)
{
    return store_put_chunk_mode(store, package_root, path, chunk_index,
                                chunk, chunk_len, true);
}

/* ── admission: recipes ───────────────────────────────────── */

enum vcs_package_store_result vcs_package_store_put_recipe(
    struct vcs_package_store *store, const uint8_t *wire, size_t wire_len,
    uint8_t root_out[32])
{
    if (!store || !wire)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_NULL, STORE_LOG,
                   "null store/wire");
    pthread_mutex_lock(&store->lock);

    struct vcs_package_recipe recipe;
    enum vcs_package_recipe_error rerr =
        vcs_package_recipe_parse(wire, wire_len, &recipe);
    if (rerr != VCS_PACKAGE_RECIPE_OK) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_RECIPE;
    }
    uint8_t root[32];
    rerr = vcs_package_recipe_root(&recipe, root);
    vcs_package_recipe_free(&recipe);
    if (rerr != VCS_PACKAGE_RECIPE_OK) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_RECIPE;
    }
    if (root_out)
        memcpy(root_out, root, 32);
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    char path[STORE_PATH_MAX];
    snprintf(path, sizeof(path), "%s/recipes/%s", store->root, root_hex);
    bool ok = store_atomic_write(path, wire, wire_len);
    pthread_mutex_unlock(&store->lock);
    return ok ? VCS_PACKAGE_STORE_OK : VCS_PACKAGE_STORE_ERR_IO;
}

/* ── reads ────────────────────────────────────────────────────────── */

struct store_chunk_reader {
    struct platform_positioned_file handle;
    char path[STORE_PATH_MAX];
    uint64_t size;
};

#ifdef ZCL_TESTING
static _Thread_local struct vcs_package_store_read_stats store_read_stats;

struct vcs_package_store_read_stats vcs_package_store_read_stats_for_test(
    bool reset)
{
    struct vcs_package_store_read_stats result = store_read_stats;
    if (reset) memset(&store_read_stats, 0, sizeof(store_read_stats));
    return result;
}
#endif

/* Caller holds the store lock and owns the manifest for the entire read. */
static enum vcs_package_store_result store_chunk_reader_open(
    struct vcs_package_store *store, const struct vcs_package_file *file,
    uint32_t index, const uint8_t hash[32], struct store_chunk_reader *reader)
{
    platform_positioned_file_init(&reader->handle);
    store_cas_path(store, hash, reader->path, sizeof(reader->path));
    if (!platform_positioned_file_open(&reader->handle, reader->path)) {
        int saved_errno = errno;
        if (saved_errno == ENOENT)
            return store_cas_quarantine_if_bad(store, hash, file, index,
                                              VCS_PACKAGE_STORE_ERR_CHUNK_MISSING);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "CAS object %s open: %s", reader->path, strerror(saved_errno));
    }
    if (!platform_positioned_file_size(&reader->handle, &reader->size)) {
        platform_positioned_file_close(&reader->handle);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "CAS object %s size", reader->path);
    }
    uint64_t offset = (uint64_t)index * VCS_PACKAGE_CHUNK_BYTES;
    uint64_t remaining = file->size - offset;
    uint64_t expected = remaining > VCS_PACKAGE_CHUNK_BYTES ?
                            VCS_PACKAGE_CHUNK_BYTES : remaining;
    if (reader->size == 0 || reader->size != expected) {
        platform_positioned_file_close(&reader->handle);
        return store_cas_quarantine_if_bad(store, hash, file, index,
                                           VCS_PACKAGE_STORE_ERR_CHUNK_HASH);
    }
    return VCS_PACKAGE_STORE_OK;
}

static enum vcs_package_store_result store_chunk_reader_verify(
    struct vcs_package_store *store, const struct vcs_package_file *file,
    uint32_t index, const uint8_t hash[32], struct store_chunk_reader *reader,
    uint8_t *bytes)
{
    int64_t got = platform_positioned_file_read(&reader->handle, bytes,
                                                (size_t)reader->size, 0);
    platform_positioned_file_close(&reader->handle);
    if (got < 0 || (uint64_t)got != reader->size)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "read CAS object %s", reader->path);
    if (!vcs_package_verify_chunk(file, index, bytes, (size_t)reader->size))
        return store_cas_quarantine_if_bad(store, hash, file, index,
                                           VCS_PACKAGE_STORE_ERR_CHUNK_HASH);
#ifdef ZCL_TESTING
    store_read_stats.verified_bytes += reader->size;
#endif
    return VCS_PACKAGE_STORE_OK;
}

static enum vcs_package_store_result store_chunk_read_locked(
    struct vcs_package_store *store, struct store_package *pkg,
    const struct vcs_package_file *file, uint32_t index,
    uint8_t *destination, size_t capacity, uint8_t **allocated, size_t *out_len)
{
    if (!file || index >= file->chunk_count)
        return VCS_PACKAGE_STORE_ERR_CHUNK_COORD;
    const uint8_t *hash = file->chunk_hashes + (size_t)index * 32u;
    if (!store_cas_contains(store, hash))
        return VCS_PACKAGE_STORE_ERR_CHUNK_MISSING;
    struct store_chunk_reader reader;
    enum vcs_package_store_result result =
        store_chunk_reader_open(store, file, index, hash, &reader);
    if (result != VCS_PACKAGE_STORE_OK) return result;
    if (destination && reader.size > capacity) {
        platform_positioned_file_close(&reader.handle);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_LIMIT, STORE_LOG,
                   "chunk destination holds %zu of %llu bytes", capacity,
                   (unsigned long long)reader.size);
    }
    uint8_t *bytes = destination;
    if (!bytes) bytes = zcl_malloc((size_t)reader.size, "vcs_store_get_chunk");
    if (!bytes) {
        platform_positioned_file_close(&reader.handle);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_ALLOC, STORE_LOG,
                   "alloc %llu chunk bytes", (unsigned long long)reader.size);
    }
    result = store_chunk_reader_verify(store, file, index, hash, &reader, bytes);
    if (result != VCS_PACKAGE_STORE_OK) {
        if (!destination) free(bytes);
        return result;
    }
    pkg->access_count++;
    pkg->last_access = ++store->logical_clock;
    *out_len = (size_t)reader.size;
    if (allocated) *allocated = bytes;
#ifdef ZCL_TESTING
    if (destination) store_read_stats.into_reads++;
    else store_read_stats.allocated_reads++;
#endif
    return VCS_PACKAGE_STORE_OK;
}

enum vcs_package_store_result vcs_package_store_get_chunk(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *path, uint32_t chunk_index, uint8_t **out, size_t *out_len)
{
    if (!store || !package_root || !path || !out || !out_len)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_NULL, STORE_LOG,
                   "null store/root/path/out");
    *out = NULL;
    *out_len = 0;
    pthread_mutex_lock(&store->lock);
    struct store_package *pkg = store_find(store, package_root, NULL);
    enum vcs_package_store_result result = VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE;
    if (pkg)
        result = store_chunk_read_locked(store, pkg, store_resolve_file(pkg, path),
                                         chunk_index, NULL, 0, out, out_len);
    pthread_mutex_unlock(&store->lock);
    return result;
}

enum vcs_package_store_result vcs_package_store_get_chunk_at_into(
    struct vcs_package_store *store, const uint8_t package_root[32],
    uint32_t file_index, uint32_t chunk_index, uint8_t *destination,
    size_t capacity, size_t *out_len)
{
    if (out_len) *out_len = 0;
    if (!store || !package_root || !destination || !out_len)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_NULL, STORE_LOG,
                   "null store/root/destination/length");
    pthread_mutex_lock(&store->lock);
    struct store_package *pkg = store_find(store, package_root, NULL);
    enum vcs_package_store_result result = VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE;
    if (pkg) {
        result = VCS_PACKAGE_STORE_ERR_CHUNK_COORD;
        if (file_index < pkg->manifest.count)
            result = store_chunk_read_locked(store, pkg,
                &pkg->manifest.files[file_index], chunk_index,
                destination, capacity, NULL, out_len);
    }
    pthread_mutex_unlock(&store->lock);
    return result;
}

/* ── reads: slice-12 swarm coordinates ────────────────────────────── */

enum vcs_package_store_result vcs_package_store_get_chunk_at(
    struct vcs_package_store *store, const uint8_t package_root[32],
    uint32_t file_index, uint32_t chunk_index, uint8_t **out,
    size_t *out_len)
{
    if (!store || !package_root || !out || !out_len)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_NULL, STORE_LOG,
                   "null store/root/out");
    pthread_mutex_lock(&store->lock);
    struct store_package *pkg = store_find(store, package_root, NULL);
    if (!pkg) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE;
    }
    if (file_index >= pkg->manifest.count) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_CHUNK_COORD;
    }
    /* files[].path is heap memory owned by the record, and an eviction on
     * another thread can free it (and relocate the record itself) the
     * moment this lock is dropped — get_chunk re-locks and re-resolves, so
     * it must be handed a path that outlives the gap. Copy it out under
     * the lock, the same way get_manifest_wire copies its payload below.
     * Parse rejects any path longer than VCS_PACKAGE_PATH_MAX, so an
     * over-long one here means a corrupt record, not a legal coordinate. */
    const char *path = pkg->manifest.files[file_index].path;
    char path_copy[VCS_PACKAGE_PATH_MAX + 1];
    size_t path_len = path ? strnlen(path, sizeof(path_copy)) : sizeof(path_copy);
    if (path_len >= sizeof(path_copy)) {
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_CHUNK_COORD, STORE_LOG,
                   "manifest path for file %u is absent or exceeds %u bytes",
                   file_index, VCS_PACKAGE_PATH_MAX);
    }
    memcpy(path_copy, path, path_len + 1u);
    pthread_mutex_unlock(&store->lock);
    return vcs_package_store_get_chunk(store, package_root, path_copy,
                                       chunk_index, out, out_len);
}

enum vcs_package_store_result vcs_package_store_get_manifest_wire(
    struct vcs_package_store *store, const uint8_t package_root[32],
    uint8_t **out, size_t *out_len)
{
    if (!store || !package_root || !out || !out_len)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_NULL, STORE_LOG,
                   "null store/root/out");
    *out = NULL;
    *out_len = 0;
    pthread_mutex_lock(&store->lock);
    struct store_package *pkg = store_find(store, package_root, NULL);
    if (!pkg) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE;
    }
    uint8_t *buf = zcl_malloc(pkg->manifest_wire_len,
                              "vcs_store_get_manifest_wire");
    if (!buf) {
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_ALLOC, STORE_LOG,
                   "alloc %zu manifest wire bytes", pkg->manifest_wire_len);
    }
    memcpy(buf, pkg->manifest_wire, pkg->manifest_wire_len);
    *out = buf;
    *out_len = pkg->manifest_wire_len;
    pthread_mutex_unlock(&store->lock);
    return VCS_PACKAGE_STORE_OK;
}

bool vcs_package_store_chunk_present(
    struct vcs_package_store *store, const uint8_t package_root[32],
    uint32_t file_index, uint32_t chunk_index)
{
    if (!store || !package_root)
        return false;
    pthread_mutex_lock(&store->lock);
    struct store_package *pkg = store_find(store, package_root, NULL);
    bool present = false;
    if (pkg && file_index < pkg->manifest.count) {
        const struct vcs_package_file *file =
            &pkg->manifest.files[file_index];
        if (chunk_index < file->chunk_count)
            present = store_cas_contains(
                store, file->chunk_hashes + (size_t)chunk_index * 32u);
    }
    pthread_mutex_unlock(&store->lock);
    return present;
}

/* Lock-held status fill shared by the public snapshot and the dump. */
static bool store_status_locked(struct vcs_package_store *store,
                                const uint8_t package_root[32],
                                struct vcs_package_store_status *out)
{
    struct store_package *pkg = store_find(store, package_root, NULL);
    if (!pkg)
        return false;
    memset(out, 0, sizeof(*out));
    out->tracked = true;
    out->pinned = pkg->pinned;
    out->complete = store_package_complete(store, pkg);
    out->class_ = pkg->class_;
    out->pool = store_package_pool(store, pkg);
    out->replicas = pkg->replicas;
    out->access_count = pkg->access_count;
    uint32_t present = 0;
    uint64_t bytes = 0;
    store_package_present(store, pkg, &present, &bytes);
    out->present_chunks = present;
    out->present_bytes = bytes;
    out->total_chunks = (uint32_t)pkg->chunk_count;
    out->total_bytes = pkg->total_bytes;
    out->mutation_generation = pkg->mutation_generation;
    return true;
}

bool vcs_package_store_package_status(
    struct vcs_package_store *store, const uint8_t package_root[32],
    struct vcs_package_store_status *out)
{
    if (!store || !package_root || !out)
        return false;
    pthread_mutex_lock(&store->lock);
    bool ok = store_status_locked(store, package_root, out);
    pthread_mutex_unlock(&store->lock);
    return ok;
}

static void store_dump_pool_json(struct json_value *out,
                                 struct vcs_package_store *store,
                                 enum vcs_package_store_pool pool)
{
    const char *name = vcs_package_store_pool_string(pool);
    char key[64];
    snprintf(key, sizeof(key), "%s_budget_bytes", name);
    json_push_kv_int(out, key,
                     (int64_t)store_pool_budget(store, pool));
    snprintf(key, sizeof(key), "%s_usage_bytes", name);
    json_push_kv_int(out, key,
                     (int64_t)store_pool_usage_locked(store, pool));
    size_t packages = 0;
    for (size_t i = 0; i < store->pkg_count; i++)
        if (store_package_pool(store, &store->pkgs[i]) == pool)
            packages++;
    snprintf(key, sizeof(key), "%s_packages", name);
    json_push_kv_int(out, key, (int64_t)packages);
}

bool vcs_package_store_dump_state_json(struct json_value *out,
                                       const char *key)
{
    if (!out)
        return false;
    json_set_object(out);
    pthread_mutex_lock(&g_global_lock);
    struct vcs_package_store *store = g_global_store;
    if (!store) {
        json_push_kv_bool(out, "enabled", false);
        json_push_kv_bool(out, "hosting_flag",
                          vcs_package_store_hosting_enabled());
        pthread_mutex_unlock(&g_global_lock);
        return true;
    }
    pthread_mutex_lock(&store->lock);
    pthread_mutex_unlock(&g_global_lock);

    json_push_kv_bool(out, "enabled", true);
    json_push_kv_str(out, "root", store->root);
    json_push_kv_int(out, "quota_bytes", (int64_t)store->quota);
    json_push_kv_str(out, "accounting",
                     "per-package: a chunk shared by N packages charges "
                     "all N pools (conservative over-count of disk)");
    store_dump_pool_json(out, store, VCS_PACKAGE_STORE_POOL_PINS);
    store_dump_pool_json(out, store, VCS_PACKAGE_STORE_POOL_HOT);
    store_dump_pool_json(out, store, VCS_PACKAGE_STORE_POOL_RARE);
    store_dump_pool_json(out, store, VCS_PACKAGE_STORE_POOL_STAGING);
    json_push_kv_int(out, "tracked_packages", (int64_t)store->pkg_count);
    json_push_kv_int(out, "cas_chunks", (int64_t)store->cas_count);
    json_push_kv_int(out, "evictions_total",
                     (int64_t)store->evictions_total);
    json_push_kv_int(out, "gc_orphans_total",
                     (int64_t)store->gc_orphans_total);
    json_push_kv_int(out, "quota_rejects_total",
                     (int64_t)store->quota_rejects_total);
    /* Slice 3 publication state: persisted release envelopes on disk and
     * the last acceptance outcome this store produced. */
    json_push_kv_int(out, "releases_total",
                     (int64_t)store_releases_count(store));
    if (store->last_accept_set) {
        json_push_kv_str(out, "last_release_accept",
                         vcs_package_accept_result_string(
                             store->last_accept));
        char id_hex[65];
        zcl_hex_encode(store->last_accept_id, 32, id_hex);
        json_push_kv_str(out, "last_release_id", id_hex);
    } else {
        json_push_kv_str(out, "last_release_accept", "none");
    }

    if (key && key[0]) {
        uint8_t root[32];
        struct vcs_package_store_status st;
        if (!zcl_hex_decode_lower(key, root, 32) ||
            !store_status_locked(store, root, &st)) {
            json_push_kv_str(out, "error",
                             "package not tracked (want a 64-hex root)");
        } else {
            json_push_kv_bool(out, "tracked", st.tracked);
            json_push_kv_bool(out, "pinned", st.pinned);
            json_push_kv_bool(out, "complete", st.complete);
            json_push_kv_str(out, "pool",
                             vcs_package_store_pool_string(st.pool));
            json_push_kv_int(out, "replicas", (int64_t)st.replicas);
            json_push_kv_int(out, "access_count",
                             (int64_t)st.access_count);
            json_push_kv_int(out, "present_bytes",
                             (int64_t)st.present_bytes);
            json_push_kv_int(out, "total_bytes", (int64_t)st.total_bytes);
            json_push_kv_int(out, "present_chunks",
                             (int64_t)st.present_chunks);
            json_push_kv_int(out, "total_chunks",
                             (int64_t)st.total_chunks);
        }
    }
    pthread_mutex_unlock(&store->lock);
    return true;
}

/* The non-blocking totals read. Contract, cost bound and the reason BUSY is
 * not CLOSED are all in vcs/package_store.h; the rules here are:
 *
 *   - trylock only, both levels, and give up on the FIRST refusal rather
 *     than spinning: a collector that retries has just reinvented blocking;
 *   - the same acquire order the dumper uses (global, then store, then
 *     release the global) so this can never invert against it;
 *   - nothing under the store lock but plain loads and one integer sum, so
 *     the window this holds it for is independent of how much is stored. */
enum vcs_package_store_totals_result vcs_package_store_try_totals(
    struct vcs_package_store_totals *out)
{
    if (!out)
        LOG_RETURN(VCS_PACKAGE_STORE_TOTALS_NULL, STORE_LOG,
                   "try_totals: null out");
    memset(out, 0, sizeof(*out));
    out->last_release_accept = "none";

    if (pthread_mutex_trylock(&g_global_lock) != 0)
        return VCS_PACKAGE_STORE_TOTALS_BUSY;
    struct vcs_package_store *store = g_global_store;
    if (!store) {
        pthread_mutex_unlock(&g_global_lock);
        return VCS_PACKAGE_STORE_TOTALS_CLOSED;
    }
    if (pthread_mutex_trylock(&store->lock) != 0) {
        pthread_mutex_unlock(&g_global_lock);
        return VCS_PACKAGE_STORE_TOTALS_BUSY;
    }
    pthread_mutex_unlock(&g_global_lock);

    out->quota_bytes = store->quota;
    out->tracked_packages = (uint64_t)store->pkg_count;
    out->cas_chunks = (uint64_t)store->cas_count;
    out->manifest_bytes_total = store->manifest_bytes_total;
    out->evictions_total = store->evictions_total;
    out->gc_orphans_total = store->gc_orphans_total;
    out->quota_rejects_total = store->quota_rejects_total;
    if (store->last_accept_set)
        out->last_release_accept =
            vcs_package_accept_result_string(store->last_accept);
    pthread_mutex_unlock(&store->lock);
    return VCS_PACKAGE_STORE_TOTALS_OK;
}
