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
#include "crypto/sha3.h"
#include "json/json.h"
#include "util/util.h"
#include "vcs/package_recipe.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <sys/file.h>
#endif
#include <unistd.h>

#define STORE_LOG "vcs.store"

static bool store_process_lock(struct vcs_package_store *store)
{
#ifdef _WIN32
    (void)store;
    return false;
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

static void store_process_unlock(struct vcs_package_store *store)
{
#ifdef _WIN32
    (void)store;
#else
    if (store && store->process_lock_fd >= 0)
        (void)flock(store->process_lock_fd, LOCK_UN);
#endif
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
static uint64_t store_pool_budget(const struct vcs_package_store *store,
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

static struct store_package *store_find(struct vcs_package_store *store,
                                        const uint8_t root[32],
                                        size_t *index_out)
{
    for (size_t i = 0; i < store->pkg_count; i++) {
        if (memcmp(store->pkgs[i].root, root, 32) == 0) {
            if (index_out)
                *index_out = i;
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

static uint64_t store_pool_usage_locked(struct vcs_package_store *store,
                                        enum vcs_package_store_pool pool)
{
    uint64_t usage = 0;
    for (size_t i = 0; i < store->pkg_count; i++) {
        if (store_package_pool(store, &store->pkgs[i]) != pool)
            continue;
        uint64_t bytes = 0;
        store_package_present(store, &store->pkgs[i], NULL, &bytes);
        usage += bytes;
    }
    return usage;
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
static void store_drop_package(struct vcs_package_store *store, size_t index)
{
    struct store_package *pkg = &store->pkgs[index];
    store->next_mutation_generation++;
    if (!store->next_mutation_generation)
        store->next_mutation_generation++;
    char path[STORE_PATH_MAX];
    if (pkg->committed) {
        snprintf(path, sizeof(path), "%s/manifests/%s", store->root,
                 pkg->root_hex);
        if (unlink(path) != 0 && errno != ENOENT)
            LOG_ERROR(STORE_LOG, "evict unlink %s: %s", path,
                      strerror(errno));
    } else {
        snprintf(path, sizeof(path), "%s/staging/%s", store->root,
                 pkg->root_hex);
        if (!store_rm_rf(path))
            LOG_ERROR(STORE_LOG, "evict staging cleanup %s", path);
    }
    snprintf(path, sizeof(path), "%s/pins/%s", store->root, pkg->root_hex);
    if (unlink(path) != 0 && errno != ENOENT)
        LOG_ERROR(STORE_LOG, "evict pin unlink %s: %s", path,
                  strerror(errno));
    for (size_t c = 0; c < pkg->chunk_count; c++) {
        if (store_chunk_shared(store, pkg->chunks[c].hash, index))
            continue;
        store_cas_path(store, pkg->chunks[c].hash, path, sizeof(path));
        if (unlink(path) != 0 && errno != ENOENT)
            LOG_ERROR(STORE_LOG, "evict chunk unlink %s: %s", path,
                      strerror(errno));
        store_cas_remove(store, pkg->chunks[c].hash);
    }
    vcs_package_manifest_free(&pkg->manifest);
    free(pkg->manifest_wire);
    free(pkg->chunks);
    store->pkgs[index] = store->pkgs[store->pkg_count - 1];
    store->pkg_count--;
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

/* Make room for incoming_bytes in pool, evicting (HOT/RARE only) until
 * it fits. STAGING and PINS never evict. False = no room and no victim. */
static bool store_ensure_room(struct vcs_package_store *store,
                              enum vcs_package_store_pool pool,
                              uint64_t incoming,
                              const uint8_t protect_root[32])
{
    while (store_pool_usage_locked(store, pool) + incoming >
           store_pool_budget(store, pool)) {
        if (pool == VCS_PACKAGE_STORE_POOL_PINS ||
            pool == VCS_PACKAGE_STORE_POOL_STAGING)
            return false;
        long victim = store_pick_victim(store, pool, protect_root);
        if (victim < 0)
            return false;
        LOG_INFO(STORE_LOG, "evicting %s package %s (pool %s over budget)",
                 vcs_package_store_pool_string(pool),
                 store->pkgs[victim].root_hex,
                 vcs_package_store_pool_string(pool));
        store_drop_package(store, (size_t)victim);
        store->evictions_total++;
    }
    return true;
}

/* ── open / close ─────────────────────────────────────────────────── */
struct vcs_package_store *vcs_package_store_open(const char *datadir,
                                                 uint64_t quota_bytes)
{
    if (!datadir)
        LOG_NULL(STORE_LOG, "null datadir");
#ifdef _WIN32
    (void)quota_bytes;
    /* Refuse before allocating, creating the root, opening recovery state, or
     * taking a pathname lock. Native admission requires a retained private
     * root capability and a process-wide handle lock that survives recovery. */
    LOG_NULL(STORE_LOG,
             "Windows package store disabled pending retained-root and "
             "process-lock qualification");
#else
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
    store->process_lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC,
                                  0600);
    if (store->process_lock_fd < 0 || !store_process_lock(store)) {
        if (store->process_lock_fd >= 0)
            close(store->process_lock_fd);
        free(store);
        LOG_NULL(STORE_LOG, "could not lock store recovery at %s", lock_path);
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
#endif
}

void vcs_package_store_close(struct vcs_package_store *store)
{
    if (!store)
        return;
    for (size_t i = 0; i < store->pkg_count; i++) {
        vcs_package_manifest_free(&store->pkgs[i].manifest);
        free(store->pkgs[i].manifest_wire);
        free(store->pkgs[i].chunks);
    }
    free(store->pkgs);
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
    bool ok = g_global_store != NULL;
    pthread_mutex_unlock(&g_global_lock);
    return ok;
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

enum vcs_package_store_result vcs_package_store_put_manifest(
    struct vcs_package_store *store, const uint8_t *wire, size_t wire_len,
    uint8_t root_out[32])
{
    if (!store || !wire)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_NULL, STORE_LOG,
                   "null store/wire");
    pthread_mutex_lock(&store->lock);

    struct vcs_package_manifest manifest;
    if (!vcs_package_manifest_parse(wire, wire_len, &manifest)) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_MANIFEST;
    }
    uint8_t root[32];
    if (!vcs_package_manifest_root(&manifest, root)) {
        vcs_package_manifest_free(&manifest);
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_MANIFEST;
    }
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    uint64_t total_bytes = 0;
    for (size_t i = 0; i < manifest.count; i++)
        total_bytes += manifest.files[i].size;
    vcs_package_manifest_free(&manifest);

    if (root_out)
        memcpy(root_out, root, 32);
    if (store_find(store, root, NULL)) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_OK; /* same root = same content: no-op */
    }
    if (total_bytes > VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_PACKAGE_CAP;
    }
    if (store->pkg_count >= VCS_PACKAGE_STORE_MAX_TRACKED) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_LIMIT;
    }

    /* Early feasibility: the package must fit the pool it will end in
     * (pins if a marker pre-exists, else rare) and, unpinned, the staging
     * pool it assembles in. A package that can never fit is refused now. */
    char pin[STORE_PATH_MAX];
    snprintf(pin, sizeof(pin), "%s/pins/%s", store->root, root_hex);
    bool pre_pinned = access(pin, F_OK) == 0;
    enum vcs_package_store_pool eventual =
        pre_pinned ? VCS_PACKAGE_STORE_POOL_PINS : VCS_PACKAGE_STORE_POOL_RARE;
    if (total_bytes > store_pool_budget(store, eventual) ||
        (!pre_pinned &&
         total_bytes > store_pool_budget(store,
                                         VCS_PACKAGE_STORE_POOL_STAGING))) {
        store->quota_rejects_total++;
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_QUOTA;
    }

    char staging_dir[STORE_PATH_MAX];
    char staged[STORE_PATH_MAX];
    snprintf(staging_dir, sizeof(staging_dir), "%s/staging/%s", store->root,
             root_hex);
    snprintf(staged, sizeof(staged), "%s/manifest", staging_dir);
    if (!store_process_lock(store) || !store_mkdir_p(staging_dir) ||
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
    size_t index = store->pkg_count - 1;
    struct store_package *pkg = &store->pkgs[index];

    /* Full-dedup arrival: every chunk already in the CAS. The package is
     * complete immediately and its bytes charge the eventual pool. */
    if (store_package_complete(store, pkg)) {
        uint64_t bytes = 0;
        store_package_present(store, pkg, NULL, &bytes);
        enum vcs_package_store_pool pool =
            pkg->pinned ? VCS_PACKAGE_STORE_POOL_PINS
                        : VCS_PACKAGE_STORE_POOL_RARE;
        if (!store_ensure_room(store, pool, bytes, pkg->root)) {
            store_drop_package(store, index);
            store->quota_rejects_total++;
            store_process_unlock(store);
            pthread_mutex_unlock(&store->lock);
            return VCS_PACKAGE_STORE_ERR_QUOTA;
        }
        if (!store_commit_if_complete(store, root)) {
            store_process_unlock(store);
            pthread_mutex_unlock(&store->lock);
            return VCS_PACKAGE_STORE_ERR_IO;
        }
    }
    store_process_unlock(store);
    pthread_mutex_unlock(&store->lock);
    return VCS_PACKAGE_STORE_OK;
}

/* ── admission: chunks ────────────────────────────────────────────── */
/* Resolve (path, chunk_index) to a manifest file; NULL = bad coords. */
static const struct vcs_package_file *store_resolve_file(
    const struct store_package *pkg, const char *path)
{
    for (size_t i = 0; i < pkg->manifest.count; i++)
        if (strcmp(pkg->manifest.files[i].path, path) == 0)
            return &pkg->manifest.files[i];
    return NULL;
}

enum vcs_package_store_result vcs_package_store_put_chunk(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *path, uint32_t chunk_index, const uint8_t *chunk,
    size_t chunk_len)
{
    if (!store || !package_root || !path || !chunk)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_NULL, STORE_LOG,
                   "null store/root/path/chunk");
    pthread_mutex_lock(&store->lock);

    struct store_package *pkg = store_find(store, package_root, NULL);
    if (!pkg) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE;
    }
    const struct vcs_package_file *file = store_resolve_file(pkg, path);
    if (!file || chunk_index >= file->chunk_count) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_CHUNK_COORD;
    }
    if (!vcs_package_verify_chunk(file, chunk_index, chunk, chunk_len)) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_CHUNK_HASH;
    }
    uint8_t hash[32];
    memcpy(hash, file->chunk_hashes + (size_t)chunk_index * 32u, 32);

    /* Dedup: the content is already in the CAS, so it was already
     * present-for-this-package too — nothing changes. */
    if (store_cas_contains(store, hash)) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_OK;
    }
    if (!store_process_lock(store)) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_IO;
    }

    uint32_t present_before = 0;
    uint64_t bytes_before = 0;
    store_package_present(store, pkg, &present_before, &bytes_before);
    bool will_complete =
        (uint64_t)present_before + 1u == (uint64_t)pkg->chunk_count;

    enum vcs_package_store_result result = VCS_PACKAGE_STORE_OK;
    if (will_complete) {
        /* The whole package's bytes move into its destination pool with
         * this chunk; enforce that pool (with eviction) up front. */
        enum vcs_package_store_pool pool =
            pkg->pinned ? VCS_PACKAGE_STORE_POOL_PINS
                        : (pkg->class_ == VCS_PACKAGE_STORE_CLASS_HOT
                               ? VCS_PACKAGE_STORE_POOL_HOT
                               : VCS_PACKAGE_STORE_POOL_RARE);
        if (!store_ensure_room(store, pool, bytes_before + chunk_len,
                               package_root)) {
            store->quota_rejects_total++;
            result = VCS_PACKAGE_STORE_ERR_QUOTA;
        }
    } else {
        enum vcs_package_store_pool pool =
            pkg->pinned ? VCS_PACKAGE_STORE_POOL_PINS
                        : VCS_PACKAGE_STORE_POOL_STAGING;
        if (!store_ensure_room(store, pool, chunk_len, package_root)) {
            store->quota_rejects_total++;
            result = VCS_PACKAGE_STORE_ERR_QUOTA;
        }
    }
    if (result != VCS_PACKAGE_STORE_OK) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        return result;
    }

    /* Verified above; store it. Temp + fsync + atomic rename beside the
     * final name, so a crash never leaves a partial chunk under a hash. */
    char cas_path[STORE_PATH_MAX];
    store_cas_path(store, hash, cas_path, sizeof(cas_path));
    char cas_dir[STORE_PATH_MAX];
    snprintf(cas_dir, sizeof(cas_dir), "%s", cas_path);
    char *slash = strrchr(cas_dir, '/');
    if (!slash) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "malformed CAS path %s", cas_path);
    }
    *slash = '\0';
    if (!store_mkdir_p(cas_dir) ||
        !store_atomic_write(cas_path, chunk, chunk_len) ||
        !store_cas_insert(store, hash)) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_IO;
    }
    store_packages_touch_hash(store, hash);
    if (will_complete && !store_commit_if_complete(store, package_root)) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_IO;
    }
    store_process_unlock(store);
    pthread_mutex_unlock(&store->lock);
    return VCS_PACKAGE_STORE_OK;
}

/* ── admission: releases (slice 1 consumption) ────────────────────── */

enum vcs_package_store_result vcs_package_store_put_release(
    struct vcs_package_store *store,
    const struct vcs_package_release *release,
    enum vcs_package_accept_result *accept_out)
{
    if (!store || !release)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_NULL, STORE_LOG,
                   "null store/release");
    pthread_mutex_lock(&store->lock);
    enum vcs_package_accept_result ar =
        vcs_package_accept(store->accept, release);
    if (accept_out)
        *accept_out = ar;
    /* Slice 3 diagnostics: record the last acceptance outcome even when it
     * rejects (the id is best-effort — an invalid envelope may have none). */
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    bool have_id =
        vcs_package_release_id(release, id) == VCS_PACKAGE_RELEASE_OK;
    store->last_accept_set = true;
    store->last_accept = ar;
    if (have_id)
        memcpy(store->last_accept_id, id, 32);
    if (ar != VCS_PACKAGE_ACCEPT_OK && ar != VCS_PACKAGE_ACCEPT_DUPLICATE) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_ACCEPT;
    }
    if (!have_id) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_ALLOC;
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_release_serialize(release, &wire, &wire_len) !=
            VCS_PACKAGE_RELEASE_OK) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_ALLOC;
    }
    char id_hex[65];
    zcl_hex_encode(id, 32, id_hex);
    char path[STORE_PATH_MAX];
    snprintf(path, sizeof(path), "%s/releases/%s", store->root, id_hex);
    bool ok = store_atomic_write(path, wire, wire_len);
    free(wire);
    /* An accepted envelope changes what the package IS to the outside
     * world: an unsigned root nobody may host becomes a signed, licensed
     * one that may be announced and served. Observers key their public-
     * hosting decision on the mutation generation, so a release landing
     * after its manifest must advance it — otherwise the package stays
     * privately hostable-in-name-only until some unrelated byte arrives. */
    if (ok) {
        struct store_package *pkg =
            store_find(store, release->package_root, NULL);
        if (pkg)
            store_package_touch(store, pkg);
    }
    pthread_mutex_unlock(&store->lock);
    return ok ? VCS_PACKAGE_STORE_OK : VCS_PACKAGE_STORE_ERR_IO;
}

/* ── admission: recipes (slice 5) ───────────────────────────────────── */

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
    if (!pkg) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE;
    }
    const struct vcs_package_file *file = store_resolve_file(pkg, path);
    if (!file || chunk_index >= file->chunk_count) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_CHUNK_COORD;
    }
    uint8_t hash[32];
    memcpy(hash, file->chunk_hashes + (size_t)chunk_index * 32u, 32);
    if (!store_cas_contains(store, hash)) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_CHUNK_MISSING;
    }
    char cas_path[STORE_PATH_MAX];
    store_cas_path(store, hash, cas_path, sizeof(cas_path));
    struct stat st;
    if (stat(cas_path, &st) != 0) {
        int saved_errno = errno;
        if (saved_errno == ENOENT) {
            store_cas_remove(store, hash);
            store_packages_touch_hash(store, hash);
            pthread_mutex_unlock(&store->lock);
            LOG_RETURN(VCS_PACKAGE_STORE_ERR_CHUNK_MISSING, STORE_LOG,
                       "CAS index named missing object %s", cas_path);
        }
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "CAS object %s stat: %s", cas_path,
                   strerror(saved_errno));
    }
    if (st.st_size <= 0 ||
        (uint64_t)st.st_size > VCS_PACKAGE_CHUNK_BYTES) {
        int remove_errno = 0;
        if (unlink(cas_path) != 0 && errno != ENOENT)
            remove_errno = errno;
        if (!remove_errno) {
            store_cas_remove(store, hash);
            store_packages_touch_hash(store, hash);
        }
        pthread_mutex_unlock(&store->lock);
        if (remove_errno)
            LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                       "quarantine corrupt CAS object %s: %s", cas_path,
                       strerror(remove_errno));
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_CHUNK_HASH, STORE_LOG,
                   "quarantined corrupt CAS object %s with invalid size %lld",
                   cas_path, (long long)st.st_size);
    }
    size_t len = (size_t)st.st_size;
    uint8_t *buf = zcl_malloc(len, "vcs_store_get_chunk");
    if (!buf) {
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_ALLOC, STORE_LOG,
                   "alloc %zu chunk bytes", len);
    }
    FILE *f = fopen(cas_path, "rb");
    if (!f || fread(buf, 1, len, f) != len) {
        if (f)
            fclose(f);
        free(buf);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "read CAS object %s", cas_path);
    }
    fclose(f);
    if (!vcs_package_verify_chunk(file, chunk_index, buf, len)) {
        free(buf);
        int remove_errno = 0;
        if (unlink(cas_path) != 0 && errno != ENOENT)
            remove_errno = errno;
        if (!remove_errno) {
            store_cas_remove(store, hash);
            store_packages_touch_hash(store, hash);
        }
        pthread_mutex_unlock(&store->lock);
        if (remove_errno)
            LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                       "quarantine corrupt CAS object %s: %s", cas_path,
                       strerror(remove_errno));
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_CHUNK_HASH, STORE_LOG,
                   "quarantined CAS object whose bytes do not match address %s",
                   cas_path);
    }
    pkg->access_count++;
    pkg->last_access = ++store->logical_clock;
    *out = buf;
    *out_len = len;
    pthread_mutex_unlock(&store->lock);
    return VCS_PACKAGE_STORE_OK;
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

size_t vcs_package_store_list_summaries(
    struct vcs_package_store *store, bool complete_only,
    struct vcs_package_store_summary *out, size_t max)
{
    if (!store || (!out && max > 0))
        LOG_RETURN(0, STORE_LOG, "null store/summaries out");
    size_t n = 0;
    pthread_mutex_lock(&store->lock);
    for (size_t i = 0; i < store->pkg_count && n < max; i++) {
        struct store_package *pkg = &store->pkgs[i];
        bool complete = store_package_complete(store, pkg);
        if (complete_only && !complete)
            continue;
        struct vcs_package_store_summary *s = &out[n++];
        memset(s, 0, sizeof(*s));
        memcpy(s->root, pkg->root, 32);
        s->manifest_bytes = (uint32_t)pkg->manifest_wire_len;
        s->file_count = (uint32_t)pkg->manifest.count;
        s->total_bytes = pkg->total_bytes;
        /* The true coordinate total (the announce consistency rules speak
         * of every chunk position, not the deduped unique-hash count). */
        for (size_t f = 0; f < pkg->manifest.count; f++)
            s->total_chunks += pkg->manifest.files[f].chunk_count;
        s->complete = complete;
        s->pinned = pkg->pinned;
    }
    pthread_mutex_unlock(&store->lock);
    return n;
}

/* ── operator: pins and class ─────────────────────────────────────── */
enum vcs_package_store_result vcs_package_store_pin(
    struct vcs_package_store *store, const uint8_t package_root[32],
    bool pinned)
{
    if (!store || !package_root)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_NULL, STORE_LOG,
                   "null store/root");
    pthread_mutex_lock(&store->lock);
    struct store_package *pkg = store_find(store, package_root, NULL);
    if (!pkg) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE;
    }
    if (pkg->pinned == pinned) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_OK;
    }
    char pin[STORE_PATH_MAX];
    snprintf(pin, sizeof(pin), "%s/pins/%s", store->root, pkg->root_hex);
    if (pinned) {
        /* Pins are never made room for by eviction: the package's bytes
         * must fit the pins budget as-is. */
        uint64_t bytes = 0;
        store_package_present(store, pkg, NULL, &bytes);
        if (!store_ensure_room(store, VCS_PACKAGE_STORE_POOL_PINS, bytes,
                               package_root)) {
            store->quota_rejects_total++;
            pthread_mutex_unlock(&store->lock);
            return VCS_PACKAGE_STORE_ERR_QUOTA;
        }
        if (!store_atomic_write(pin, NULL, 0)) {
            pthread_mutex_unlock(&store->lock);
            return VCS_PACKAGE_STORE_ERR_IO;
        }
        pkg = store_find(store, package_root, NULL);
        if (!pkg) {
            pthread_mutex_unlock(&store->lock);
            LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                       "pinned package vanished mid-pin");
        }
        pkg->pinned = true;
        store_package_touch(store, pkg);
    } else {
        if (unlink(pin) != 0 && errno != ENOENT) {
            pthread_mutex_unlock(&store->lock);
            LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                       "unlink pin %s: %s", pin, strerror(errno));
        }
        pkg->pinned = false;
        store_package_touch(store, pkg);
    }
    pthread_mutex_unlock(&store->lock);
    return VCS_PACKAGE_STORE_OK;
}

enum vcs_package_store_result vcs_package_store_set_class(
    struct vcs_package_store *store, const uint8_t package_root[32],
    enum vcs_package_store_class class_, uint32_t replicas)
{
    if (!store || !package_root)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_NULL, STORE_LOG,
                   "null store/root");
    pthread_mutex_lock(&store->lock);
    struct store_package *pkg = store_find(store, package_root, NULL);
    if (!pkg) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE;
    }
    if (pkg->class_ == class_ && pkg->replicas == replicas) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_OK;
    }
    /* A complete package changes pools only when its class changes:
     * enforce the target pool (with eviction) before the move. A replica
     * update under an unchanged class moves nothing and must not charge
     * the pool a second time. An incomplete package charges staging
     * regardless; the class takes effect at completion. */
    if (pkg->class_ != class_ && store_package_complete(store, pkg) &&
        !pkg->pinned) {
        uint64_t bytes = 0;
        store_package_present(store, pkg, NULL, &bytes);
        enum vcs_package_store_pool pool =
            class_ == VCS_PACKAGE_STORE_CLASS_HOT
                ? VCS_PACKAGE_STORE_POOL_HOT
                : VCS_PACKAGE_STORE_POOL_RARE;
        if (!store_ensure_room(store, pool, bytes, package_root)) {
            store->quota_rejects_total++;
            pthread_mutex_unlock(&store->lock);
            return VCS_PACKAGE_STORE_ERR_QUOTA;
        }
        pkg = store_find(store, package_root, NULL);
        if (!pkg) {
            pthread_mutex_unlock(&store->lock);
            LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                       "package vanished mid-reclassify");
        }
    }
    pkg->class_ = class_;
    pkg->replicas = replicas;
    pthread_mutex_unlock(&store->lock);
    return VCS_PACKAGE_STORE_OK;
}

/* ── status + introspection ───────────────────────────────────────── */
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
    for (size_t i = 0; i < store->pkg_count; i++)
        out->manifest_bytes_total += store->pkgs[i].total_bytes;
    out->evictions_total = store->evictions_total;
    out->gc_orphans_total = store->gc_orphans_total;
    out->quota_rejects_total = store->quota_rejects_total;
    if (store->last_accept_set)
        out->last_release_accept =
            vcs_package_accept_result_string(store->last_accept);
    pthread_mutex_unlock(&store->lock);
    return VCS_PACKAGE_STORE_TOTALS_OK;
}
