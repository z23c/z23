/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Package-store catalog validation, bounded paging, and policy mutation. */
#include "package_store_priv.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "platform/positioned_file.h"
#include "platform/clock.h"
#include "platform/directory_compat.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <wchar.h>
#include <windows.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#define STORE_LOG "vcs.store"

#if defined(_WIN32)
static bool store_release_wide_path(const char *path,
                                    wchar_t out[STORE_PATH_MAX])
{
    int count = path ? MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           path, -1, NULL, 0) : 0;
    return count > 0 && count <= (int)STORE_PATH_MAX &&
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, out,
                            count) == count;
}
#endif

bool store_chunk_inputs_valid(struct vcs_package_store *store,
                              const uint8_t package_root[32],
                              const char *path, const uint8_t *chunk)
{
    return store && package_root && path && chunk;
}

bool store_manifest_identity(const uint8_t *wire, size_t wire_len,
                             uint8_t root[32], uint64_t *total_bytes)
{
    struct vcs_package_manifest manifest;
    if (!vcs_package_manifest_parse(wire, wire_len, &manifest))
        return false;
    if (!vcs_package_manifest_root(&manifest, root)) {
        vcs_package_manifest_free(&manifest);
        return false;
    }
    *total_bytes = 0;
    for (size_t i = 0; i < manifest.count; i++)
        *total_bytes += manifest.files[i].size;
    vcs_package_manifest_free(&manifest);
    return true;
}

const struct vcs_package_file *store_resolve_file(
    const struct store_package *pkg, const char *path)
{
    for (size_t i = 0; i < pkg->manifest.count; i++)
        if (strcmp(pkg->manifest.files[i].path, path) == 0)
            return &pkg->manifest.files[i];
    return NULL;
}

enum vcs_package_store_result store_chunk_hash_checked(
    const struct store_package *pkg, const char *path, uint32_t chunk_index,
    const uint8_t *chunk, size_t chunk_len, uint8_t hash[32])
{
    const struct vcs_package_file *file = store_resolve_file(pkg, path);
    if (!file || chunk_index >= file->chunk_count)
        return VCS_PACKAGE_STORE_ERR_CHUNK_COORD;
    if (!vcs_package_verify_chunk(file, chunk_index, chunk, chunk_len))
        return VCS_PACKAGE_STORE_ERR_CHUNK_HASH;
    memcpy(hash, file->chunk_hashes + (size_t)chunk_index * 32u, 32);
    return VCS_PACKAGE_STORE_OK;
}

/* A CAS hash may complete several staged manifests at once. Project all
 * derived pools while holding the store and process locks, then remove the
 * temporary index entry before any eviction can inspect CAS ownership. */
static bool store_chunk_project(struct vcs_package_store *store,
                                const uint8_t hash[32], uint64_t usage[4])
{
    if (!store_cas_insert(store, hash)) return false;
    store_pool_usages_locked(store, usage);
    store_cas_remove(store, hash);
    return true;
}

enum vcs_package_store_result store_chunk_room(
    struct vcs_package_store *store, struct store_package *pkg,
    const uint8_t hash[32], const uint8_t package_root[32],
    bool *will_complete)
{
    uint32_t present = 0;
    store_package_present(store, pkg, &present, NULL);
    *will_complete = (uint64_t)present + 1u == pkg->chunk_count;
    for (;;) {
        uint64_t before[4], after[4];
        store_pool_usages_locked(store, before);
        if (!store_chunk_project(store, hash, after))
            LOG_RETURN(VCS_PACKAGE_STORE_ERR_ALLOC, STORE_LOG,
                       "project shared chunk admission");
        if (after[VCS_PACKAGE_STORE_POOL_PINS] >
                store_pool_budget(store, VCS_PACKAGE_STORE_POOL_PINS) ||
            after[VCS_PACKAGE_STORE_POOL_STAGING] >
                store_pool_budget(store, VCS_PACKAGE_STORE_POOL_STAGING))
            break;
        bool evicted = false;
        for (int pool = VCS_PACKAGE_STORE_POOL_HOT;
             pool <= VCS_PACKAGE_STORE_POOL_RARE; pool++) {
            uint64_t incoming = after[pool] > before[pool]
                                    ? after[pool] - before[pool] : 0;
            uint64_t old_evictions = store->evictions_total;
            if (!store_ensure_room(store, pool, incoming, package_root)) {
                if (store->catalog_incomplete)
                    LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                               "shared chunk admission: catalog incomplete");
                store->quota_rejects_total++;
                return VCS_PACKAGE_STORE_ERR_QUOTA;
            }
            if (store->evictions_total != old_evictions) {
                evicted = true;
                break;
            }
        }
        if (!evicted) return VCS_PACKAGE_STORE_OK;
    }
    store->quota_rejects_total++;
    return VCS_PACKAGE_STORE_ERR_QUOTA;
}

uint8_t *store_read_file(const char *path, size_t *out_len)
{
    *out_len = 0;
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        LOG_NULL(STORE_LOG, "open regular file %s", path);
    uint64_t size = 0;
    if (!platform_positioned_file_size(&file, &size) || size == 0 ||
        size > VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES) {
        platform_positioned_file_close(&file);
        LOG_NULL(STORE_LOG, "%s: invalid file or size", path);
    }
    size_t len = (size_t)size;
    uint8_t *buf = zcl_malloc(len, "store_read_file");
    if (!buf) {
        platform_positioned_file_close(&file);
        LOG_NULL(STORE_LOG, "alloc %zu for %s", len, path);
    }
    int64_t got = platform_positioned_file_read(&file, buf, len, 0);
    platform_positioned_file_close(&file);
    if (got != (int64_t)len) {
        free(buf);
        LOG_NULL(STORE_LOG, "read exact file %s", path);
    }
    *out_len = len;
    return buf;
}

static enum vcs_package_store_page_result store_catalog_count_names(
    const char *dir, bool committed, size_t *seen)
{
#if defined(_WIN32)
    struct platform_directory_list files = {0};
    bool listed = committed
        ? platform_directory_list_regular_sorted(dir, &files)
        : platform_directory_list_real_sorted(dir, &files);
    if (!listed)
        return VCS_PACKAGE_STORE_PAGE_INCOMPLETE;
    for (size_t j = 0; j < files.count; j++) {
        const char *name = files.entries[j].name;
        if (!store_name_is_hex64(name)) continue;
        (*seen)++;
    }
    platform_directory_list_free(&files);
#else
    (void)committed;
    DIR *d = opendir(dir);
    if (!d) return VCS_PACKAGE_STORE_PAGE_INCOMPLETE;
    enum vcs_package_store_page_result result = VCS_PACKAGE_STORE_PAGE_OK;
    while (true) {
        errno = 0;
        struct dirent *ent = readdir(d);
        if (!ent) {
            if (errno != 0) result = VCS_PACKAGE_STORE_PAGE_INCOMPLETE;
            break;
        }
        if (!store_name_is_hex64(ent->d_name)) continue;
        (*seen)++;
    }
    closedir(d);
    if (result != VCS_PACKAGE_STORE_PAGE_OK) return result;
#endif
    return VCS_PACKAGE_STORE_PAGE_OK;
}

static enum vcs_package_store_page_result store_catalog_names_match(
    const struct vcs_package_store *store, bool committed)
{
    char dir[STORE_PATH_MAX];
    int dn = snprintf(dir, sizeof(dir), "%s/%s", store->root,
                      committed ? "manifests" : "staging");
    if (dn <= 0 || (size_t)dn >= sizeof(dir))
        return VCS_PACKAGE_STORE_PAGE_IO;
    size_t seen = 0, expected = 0;
    for (size_t i = 0; i < store->pkg_count; i++)
        if (store->pkgs[i].committed == committed)
            expected++;
    enum vcs_package_store_page_result result =
        store_catalog_count_names(dir, committed, &seen);
    if (result != VCS_PACKAGE_STORE_PAGE_OK) return result;
    return seen == expected ? VCS_PACKAGE_STORE_PAGE_OK
                            : VCS_PACKAGE_STORE_PAGE_INCOMPLETE;
}

static enum vcs_package_store_page_result store_catalog_validate_package(
    const struct vcs_package_store *store, const struct store_package *pkg,
    bool check_pin)
{
    char path[STORE_PATH_MAX];
    int n = snprintf(path, sizeof(path), pkg->committed
                         ? "%s/manifests/%s" : "%s/staging/%s/manifest",
                         store->root, pkg->root_hex);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return VCS_PACKAGE_STORE_PAGE_IO;
    size_t len = 0;
    uint8_t *wire = store_read_file(path, &len);
    if (!wire) return VCS_PACKAGE_STORE_PAGE_INCOMPLETE;
    bool same = len == pkg->manifest_wire_len;
    if (same && pkg->manifest_loaded)
        same = memcmp(wire, pkg->manifest_wire, len) == 0;
    else if (same) {
        struct vcs_package_manifest parsed;
        same = vcs_package_manifest_parse(wire, len, &parsed);
        if (same) {
            uint8_t root[32];
            same = vcs_package_manifest_root(&parsed, root) &&
                   memcmp(root, pkg->root, sizeof(root)) == 0;
            vcs_package_manifest_free(&parsed);
        }
    }
    free(wire);
    if (!same) return VCS_PACKAGE_STORE_PAGE_STALE;
    if (check_pin) {
        n = snprintf(path, sizeof(path), "%s/pins/%s", store->root,
                     pkg->root_hex);
        if (n <= 0 || (size_t)n >= sizeof(path))
            return VCS_PACKAGE_STORE_PAGE_IO;
        if (store_path_exists(path) != pkg->pinned)
            return VCS_PACKAGE_STORE_PAGE_STALE;
    }
    return VCS_PACKAGE_STORE_PAGE_OK;
}

enum vcs_package_store_page_result store_catalog_validate_record_disk(
    const struct vcs_package_store *store, const struct store_package *pkg)
{
    enum vcs_package_store_page_result result =
        store_catalog_validate_package(store, pkg, false);
    if (result != VCS_PACKAGE_STORE_PAGE_OK) return result;
    for (size_t i = 0; i < pkg->chunk_count; i++) {
        const uint8_t *hash = pkg->chunks[i].hash;
        if (!store_cas_contains(store, hash)) continue;
        char path[STORE_PATH_MAX];
        store_cas_path(store, hash, path, sizeof(path));
        if (!store_path_exists(path))
            return VCS_PACKAGE_STORE_PAGE_INCOMPLETE;
    }
    return VCS_PACKAGE_STORE_PAGE_OK;
}

/* A read can finish against an old inode while another handle replaces its
 * path. Recheck the current leaf under the process lock before quarantine. */
static int store_cas_current_state(const char *path,
                                   const struct vcs_package_file *file,
                                   uint32_t chunk_index)
{
    struct platform_positioned_file current;
    platform_positioned_file_init(&current);
    if (!platform_positioned_file_open(&current, path))
        return errno == ENOENT ? 0 : -1;
    uint64_t size = 0;
    if (!platform_positioned_file_size(&current, &size)) {
        platform_positioned_file_close(&current);
        return -1;
    }
    if (size == 0 || size > VCS_PACKAGE_CHUNK_BYTES) {
        platform_positioned_file_close(&current);
        return 0;
    }
    uint8_t *bytes = zcl_malloc((size_t)size, "store_cas_recheck");
    if (!bytes) {
        platform_positioned_file_close(&current);
        return -1;
    }
    int64_t got = platform_positioned_file_read(
        &current, bytes, (size_t)size, 0);
    platform_positioned_file_close(&current);
    int state = got == (int64_t)size
        ? (vcs_package_verify_chunk(file, chunk_index, bytes,
                                    (size_t)size) ? 1 : 0)
        : -1;
    free(bytes);
    return state;
}

enum vcs_package_store_result store_cas_quarantine_if_bad(
    struct vcs_package_store *store, const uint8_t hash[32],
    const struct vcs_package_file *file, uint32_t chunk_index,
    enum vcs_package_store_result observed)
{
    char path[STORE_PATH_MAX];
    store_cas_path(store, hash, path, sizeof(path));
    if (!store_process_lock(store))
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "lock store to quarantine CAS %s", path);
    if (!store_generation_check(store)) {
        store_process_unlock(store);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "stale handle during CAS quarantine %s", path);
    }
    int state = store_cas_current_state(path, file, chunk_index);
    if (state < 0) {
        store_process_unlock(store);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "recheck CAS before quarantine %s", path);
    }
    if (state > 0) {
        store_process_unlock(store);
        LOG_RETURN(observed, STORE_LOG,
                   "CAS changed to valid bytes during read %s", path);
    }
    if (!store_generation_advance(store) || !store_unlink(path)) {
        store_process_unlock(store);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "advance and quarantine invalid CAS %s", path);
    }
    store_cas_remove(store, hash);
    store_packages_touch_hash(store, hash);
    store_process_unlock(store);
    LOG_RETURN(observed, STORE_LOG, "quarantined invalid CAS %s", path);
}

static struct store_package *store_catalog_find_metadata(
    struct vcs_package_store *store, const uint8_t root[32])
{
    size_t lo = 0, hi = store->pkg_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = memcmp(store->pkgs[store->root_order[mid]].root, root, 32);
        if (cmp < 0) lo = mid + 1;
        else hi = mid;
    }
    if (lo == store->pkg_count) return NULL;
    struct store_package *pkg = &store->pkgs[store->root_order[lo]];
    return memcmp(pkg->root, root, 32) == 0 ? pkg : NULL;
}

static enum vcs_package_store_page_result store_catalog_validate_known(
    const struct vcs_package_store *store, bool check_pin)
{
    if (!store || store->catalog_incomplete)
        return VCS_PACKAGE_STORE_PAGE_INCOMPLETE;
    for (size_t i = 0; i < store->pkg_count; i++) {
        enum vcs_package_store_page_result result =
            store_catalog_validate_package(store, &store->pkgs[i], check_pin);
        if (result != VCS_PACKAGE_STORE_PAGE_OK) return result;
    }
    for (size_t i = 0; i < store->cas_count; i++) {
        char path[STORE_PATH_MAX];
        store_cas_path(store, store->cas[i], path, sizeof(path));
        if (!store_path_exists(path))
            return VCS_PACKAGE_STORE_PAGE_INCOMPLETE;
    }
    return VCS_PACKAGE_STORE_PAGE_OK;
}

enum vcs_package_store_page_result store_catalog_validate_observed_disk(
    const struct vcs_package_store *store)
{
    /* Pin markers may legitimately change through another locked handle.
     * The rebuild below replays those markers from disk; immutable manifests
     * and CAS bytes already observed by this handle must still exist. */
    return store_catalog_validate_known(store, false);
}

enum vcs_package_store_page_result store_catalog_validate_disk(
    const struct vcs_package_store *store)
{
    enum vcs_package_store_page_result result =
        store_catalog_validate_known(store, true);
    if (result != VCS_PACKAGE_STORE_PAGE_OK) return result;
    result = store_catalog_names_match(store, true);
    if (result != VCS_PACKAGE_STORE_PAGE_OK) return result;
    return store_catalog_names_match(store, false);
}

bool vcs_package_store_generation_moved(struct vcs_package_store *store,
                                        uint64_t *disk_generation_out)
{
    if (!store) return false;
    uint64_t disk_generation = 0;
    pthread_mutex_lock(&store->lock);
    bool read = store_generation_read(store, &disk_generation);
    bool moved = read && disk_generation != store->shared_generation;
    pthread_mutex_unlock(&store->lock);
    if (moved && disk_generation_out)
        *disk_generation_out = disk_generation;
    return moved;
}

bool vcs_package_store_refresh(struct vcs_package_store *store)
{
    if (!store) return false;
    pthread_mutex_lock(&store->lock);
    if (!store_process_lock(store)) {
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(false, STORE_LOG, "lock store for catalog refresh");
    }
    uint64_t disk_generation = 0;
    if (!store_generation_read(store, &disk_generation)) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(false, STORE_LOG, "read store generation for refresh");
    }
    if (disk_generation == store->shared_generation &&
        !store->catalog_incomplete) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        return true;
    }
    if (store_catalog_validate_observed_disk(store) !=
        VCS_PACKAGE_STORE_PAGE_OK) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(false, STORE_LOG,
                   "refresh refused: previously observed catalog changed");
    }

    struct vcs_package_store rebuilt = {0};
    memcpy(rebuilt.root, store->root, sizeof(rebuilt.root));
    rebuilt.preexisting_root = true;
    rebuilt.process_lock_fd = store->process_lock_fd;
    rebuilt.quota = store->quota;
    rebuilt.shared_generation = disk_generation;
    rebuilt.logical_clock = store->logical_clock;
    rebuilt.next_mutation_generation = store->next_mutation_generation;
    rebuilt.hot_clock = store->hot_clock;
    bool ready = store_open_recover(&rebuilt) &&
        store_generation_check(&rebuilt) &&
        store_catalog_validate_disk(&rebuilt) == VCS_PACKAGE_STORE_PAGE_OK;
    if (!ready) {
        store_partial_catalog_free(&rebuilt);
        vcs_package_accept_free(rebuilt.accept);
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(false, STORE_LOG, "rebuild stale package catalog");
    }
    /* Preserve this handle's quota class and eviction hints for retained
     * immutable roots. Pins are disk authority and come from the rebuild. */
    for (size_t i = 0; i < store->pkg_count; i++) {
        const struct store_package *old = &store->pkgs[i];
        struct store_package *same =
            store_catalog_find_metadata(&rebuilt, old->root);
        if (!same) {
            store_partial_catalog_free(&rebuilt);
            vcs_package_accept_free(rebuilt.accept);
            store_process_unlock(store);
            pthread_mutex_unlock(&store->lock);
            LOG_RETURN(false, STORE_LOG,
                       "refresh refused: observed manifest missing from rebuild");
        }
        same->class_ = old->class_;
        same->replicas = old->replicas;
        same->access_count = old->access_count;
        same->last_access = old->last_access;
        same->mutation_generation = old->mutation_generation;
    }
    struct vcs_package_store retired = {
        .pkgs = store->pkgs, .pkg_count = store->pkg_count,
        .root_order = store->root_order, .cas = store->cas,
        .accept = store->accept,
    };
    store->pkgs = rebuilt.pkgs;
    store->pkg_count = rebuilt.pkg_count;
    store->pkg_cap = rebuilt.pkg_cap;
    store->root_order = rebuilt.root_order;
    store->hot_count = rebuilt.hot_count;
    store->hot_clock = rebuilt.hot_clock;
    store->catalog_incomplete = rebuilt.catalog_incomplete;
    store->cas = rebuilt.cas;
    store->cas_count = rebuilt.cas_count;
    store->cas_cap = rebuilt.cas_cap;
    store->accept = rebuilt.accept;
    store->manifest_bytes_total = rebuilt.manifest_bytes_total;
    store->logical_clock = rebuilt.logical_clock;
    store->next_mutation_generation = rebuilt.next_mutation_generation;
    store->shared_generation = rebuilt.shared_generation;
    store->gc_orphans_total += rebuilt.gc_orphans_total;
    store_partial_catalog_free(&retired);
    vcs_package_accept_free(retired.accept);
    store_process_unlock(store);
    pthread_mutex_unlock(&store->lock);
    return true;
}

enum vcs_package_store_result vcs_package_store_put_manifest_resync(
    struct vcs_package_store *store, const uint8_t *wire, size_t wire_len,
    uint8_t root_out[32])
{
    if (!vcs_package_store_refresh(store))
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "refresh package catalog before manifest admission");
    return vcs_package_store_put_manifest(store, wire, wire_len, root_out);
}

static void store_fill_summary(struct vcs_package_store *store,
                               struct store_package *pkg,
                               struct vcs_package_store_summary *s)
{
    memset(s, 0, sizeof(*s));
    memcpy(s->root, pkg->root, 32);
    s->manifest_bytes = (uint32_t)pkg->manifest_wire_len;
    s->file_count = pkg->file_count;
    s->total_bytes = pkg->total_bytes;
    s->total_chunks = pkg->total_chunks;
    s->complete = store_package_complete(store, pkg);
    s->pinned = pkg->pinned;
}

static size_t store_page_after(const struct vcs_package_store *store,
                               const uint8_t after_root[32])
{
    if (!after_root) return 0;
    size_t lo = 0, hi = store->pkg_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = memcmp(store->pkgs[store->root_order[mid]].root,
                         after_root, 32);
        if (cmp <= 0) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

enum vcs_package_store_page_result vcs_package_store_page_summaries(
    struct vcs_package_store *store, const uint8_t after_root[32],
    size_t limit, uint64_t expected_generation,
    struct vcs_package_store_summary *rows,
    struct vcs_package_store_page *page)
{
    if (!store || !rows || !page || !limit ||
        limit > VCS_PACKAGE_STORE_PAGE_MAX ||
        (!after_root && expected_generation))
        LOG_RETURN(VCS_PACKAGE_STORE_PAGE_INPUT, STORE_LOG,
                   "invalid package page arguments");
    memset(page, 0, sizeof(*page));
    pthread_mutex_lock(&store->lock);
    if (!store_process_lock(store)) {
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_PAGE_IO, STORE_LOG,
                   "lock store for catalog page");
    }
    if (!store_generation_check(store)) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_PAGE_STALE, STORE_LOG,
                   "package catalog changed in another handle");
    }
    if (store->catalog_incomplete) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_PAGE_INCOMPLETE, STORE_LOG,
                   "package catalog is incomplete");
    }
    if (after_root && expected_generation != store->shared_generation) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_PAGE_STALE, STORE_LOG,
                   "package page generation changed");
    }
    page->generation = store->shared_generation;
    size_t lo = store_page_after(store, after_root);
    for (size_t i = lo; i < store->pkg_count && page->count < limit; i++) {
        struct store_package *pkg = &store->pkgs[store->root_order[i]];
        store_fill_summary(store, pkg, &rows[page->count++]);
        memcpy(page->next_root, pkg->root, 32);
    }
    page->has_more = lo + page->count < store->pkg_count;
    store_process_unlock(store);
    pthread_mutex_unlock(&store->lock);
    return VCS_PACKAGE_STORE_PAGE_OK;
}

enum vcs_package_store_page_result vcs_package_store_catalog_rows(
    struct vcs_package_store *store, size_t *rows, uint64_t *generation)
{
    if (rows) *rows = 0;
    if (generation) *generation = 0;
    if (!store || !rows || !generation)
        LOG_RETURN(VCS_PACKAGE_STORE_PAGE_INPUT, STORE_LOG,
                   "invalid catalog size arguments");
    pthread_mutex_lock(&store->lock);
    if (!store_process_lock(store)) {
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_PAGE_IO, STORE_LOG,
                   "lock store for catalog size");
    }
    enum vcs_package_store_page_result result = VCS_PACKAGE_STORE_PAGE_OK;
    if (!store_generation_check(store))
        result = VCS_PACKAGE_STORE_PAGE_STALE;
    else if (store->catalog_incomplete)
        result = VCS_PACKAGE_STORE_PAGE_INCOMPLETE;
    else {
        *rows = store->pkg_count;
        *generation = store->shared_generation;
    }
    store_process_unlock(store);
    pthread_mutex_unlock(&store->lock);
    if (result != VCS_PACKAGE_STORE_PAGE_OK)
        LOG_ERROR(STORE_LOG, "catalog size refused (%d)", (int)result);
    return result;
}

static enum vcs_package_store_page_result store_validate_chunks(
    const struct vcs_package_store *store,
    const uint8_t (*hashes)[32], size_t count)
{
    for (size_t i = 0; i < count; i++) {
        char path[STORE_PATH_MAX];
        store_cas_path(store, hashes[i], path, sizeof(path));
        size_t len = 0;
        uint8_t *wire = store_read_file(path, &len);
        if (!wire) return VCS_PACKAGE_STORE_PAGE_INCOMPLETE;
        uint8_t actual[32];
        bool valid = vcs_package_chunk_hash(wire, len, actual) &&
                     memcmp(actual, hashes[i], sizeof(actual)) == 0;
        free(wire);
        if (!valid) return VCS_PACKAGE_STORE_PAGE_INCOMPLETE;
    }
    return VCS_PACKAGE_STORE_PAGE_OK;
}

enum vcs_package_store_page_result vcs_package_store_publish_checked(
    struct vcs_package_store *store, uint64_t generation,
    const uint8_t (*chunk_hashes)[32], size_t chunk_count,
    void (*publish)(void *context), void *context)
{
    if (!store || !publish || (chunk_count && !chunk_hashes))
        LOG_RETURN(VCS_PACKAGE_STORE_PAGE_INPUT, STORE_LOG,
                   "invalid guarded publish arguments");
    pthread_mutex_lock(&store->lock);
    if (!store_process_lock(store)) {
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_PAGE_IO, STORE_LOG,
                   "lock store for guarded projection publication");
    }
    if (!store_generation_check(store)) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_PAGE_STALE, STORE_LOG,
                   "store changed in another handle before publish");
    }
    if (generation != store->shared_generation) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_PAGE_STALE, STORE_LOG,
                   "stale guarded publication");
    }
    enum vcs_package_store_page_result disk =
        store_catalog_validate_disk(store);
    if (disk == VCS_PACKAGE_STORE_PAGE_OK)
        disk = store_validate_chunks(store, chunk_hashes, chunk_count);
    if (disk != VCS_PACKAGE_STORE_PAGE_OK) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(disk, STORE_LOG, "store changed before projection publish");
    }
    publish(context);
    store_process_unlock(store);
    pthread_mutex_unlock(&store->lock);
    return VCS_PACKAGE_STORE_PAGE_OK;
}

enum vcs_package_store_page_result vcs_package_store_publish_if_generation(
    struct vcs_package_store *store, uint64_t generation,
    void (*publish)(void *context), void *context)
{
    return vcs_package_store_publish_checked(store, generation, NULL, 0,
                                             publish, context);
}

enum vcs_package_store_page_result vcs_package_store_commit_if_generation(
    struct vcs_package_store *store, uint64_t generation,
    size_t max_catalog_rows,
    const uint8_t (*chunk_hashes)[32], size_t chunk_count,
    bool (*commit)(void *context), void *context, bool *committed_out)
{
    if (committed_out) *committed_out = false;
    if (!store || !commit || !committed_out || !max_catalog_rows ||
        (chunk_count && !chunk_hashes))
        LOG_RETURN(VCS_PACKAGE_STORE_PAGE_INPUT, STORE_LOG,
                   "invalid guarded DB commit arguments");
    pthread_mutex_lock(&store->lock);
    if (!store_process_lock(store)) {
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_PAGE_IO, STORE_LOG,
                   "lock store for guarded DB commit");
    }
    enum vcs_package_store_page_result result = VCS_PACKAGE_STORE_PAGE_OK;
    if (!store_generation_check(store) ||
        generation != store->shared_generation)
        result = VCS_PACKAGE_STORE_PAGE_STALE;
    else if (store->pkg_count > max_catalog_rows)
        result = VCS_PACKAGE_STORE_PAGE_INCOMPLETE;
    else
        result = store_catalog_validate_disk(store);
    if (result == VCS_PACKAGE_STORE_PAGE_OK)
        result = store_validate_chunks(store, chunk_hashes, chunk_count);
    if (result == VCS_PACKAGE_STORE_PAGE_OK)
        *committed_out = commit(context);
    store_process_unlock(store);
    pthread_mutex_unlock(&store->lock);
    if (result != VCS_PACKAGE_STORE_PAGE_OK)
        LOG_ERROR(STORE_LOG, "guarded DB commit refused (%d)", (int)result);
    return result;
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
        store_fill_summary(store, pkg, &out[n++]);
    }
    pthread_mutex_unlock(&store->lock);
    return n;
}

/* ── operator: pins and class ─────────────────────────────────────── */
static enum vcs_package_store_result store_pin_change_locked(
    struct vcs_package_store *store, const uint8_t package_root[32],
    struct store_package *pkg, bool pinned)
{
    char pin[STORE_PATH_MAX];
    snprintf(pin, sizeof(pin), "%s/pins/%s", store->root, pkg->root_hex);
    if (!store_process_lock(store))
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "lock store to change package pin");
    if (!store_generation_check(store) ||
        store_catalog_validate_disk(store) != VCS_PACKAGE_STORE_PAGE_OK) {
        store_process_unlock(store);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "pin change refused: package catalog changed");
    }
    if (pkg->pinned == pinned) {
        store_process_unlock(store);
        return VCS_PACKAGE_STORE_OK;
    }
    if (pinned) {
        uint64_t bytes = 0;
        store_package_present(store, pkg, NULL, &bytes);
        if (!store_ensure_room(store, VCS_PACKAGE_STORE_POOL_PINS, bytes,
                               package_root)) {
            store->quota_rejects_total++;
            store_process_unlock(store);
            return VCS_PACKAGE_STORE_ERR_QUOTA;
        }
        if (!store_generation_advance(store) ||
            !store_atomic_write(pin, NULL, 0)) {
            store_process_unlock(store);
            LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                       "write package pin %s", pin);
        }
        pkg = store_find(store, package_root, NULL);
        if (!pkg) {
            store_process_unlock(store);
            LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                       "pinned package vanished mid-pin");
        }
    } else {
        if (!store_generation_advance(store) || !store_unlink(pin)) {
            store_process_unlock(store);
            LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                       "unlink pin %s: %s", pin, strerror(errno));
        }
    }
    pkg->pinned = pinned;
    store_package_touch(store, pkg);
    store_process_unlock(store);
    return VCS_PACKAGE_STORE_OK;
}

enum vcs_package_store_result vcs_package_store_pin(
    struct vcs_package_store *store, const uint8_t package_root[32],
    bool pinned)
{
    if (!store || !package_root)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_NULL, STORE_LOG,
                   "null store/root");
    pthread_mutex_lock(&store->lock);
    struct store_package *pkg = store_find(store, package_root, NULL);
    if (store->catalog_incomplete) {
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "pin refused: catalog incomplete");
    }
    if (!pkg) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE;
    }
    enum vcs_package_store_result result =
        store_pin_change_locked(store, package_root, pkg, pinned);
    pthread_mutex_unlock(&store->lock);
    return result;
}

static enum vcs_package_store_result store_class_room_locked(
    struct vcs_package_store *store, const uint8_t package_root[32],
    enum vcs_package_store_class class_, struct store_package **pkg_ptr)
{
    struct store_package *pkg = *pkg_ptr;
    if (pkg->class_ == class_ || !store_package_complete(store, pkg) ||
        pkg->pinned)
        return VCS_PACKAGE_STORE_OK;
    uint64_t bytes = 0;
    store_package_present(store, pkg, NULL, &bytes);
    enum vcs_package_store_pool pool =
        class_ == VCS_PACKAGE_STORE_CLASS_HOT
            ? VCS_PACKAGE_STORE_POOL_HOT : VCS_PACKAGE_STORE_POOL_RARE;
    if (!store_ensure_room(store, pool, bytes, package_root)) {
        if (store->catalog_incomplete)
            LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                       "reclassification stopped: catalog incomplete");
        store->quota_rejects_total++;
        return VCS_PACKAGE_STORE_ERR_QUOTA;
    }
    pkg = store_find(store, package_root, NULL);
    if (!pkg)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "package vanished mid-reclassify");
    *pkg_ptr = pkg;
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
    if (store->catalog_incomplete) {
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "reclassify refused: catalog incomplete");
    }
    if (!pkg) {
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE;
    }
    if (!store_process_lock(store)) {
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "lock store to reclassify package");
    }
    if (!store_generation_check(store) ||
        store_catalog_validate_disk(store) != VCS_PACKAGE_STORE_PAGE_OK) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "reclassification refused: package catalog changed");
    }
    if (pkg->class_ == class_ && pkg->replicas == replicas) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        return VCS_PACKAGE_STORE_OK;
    }
    if (!store_generation_advance(store)) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_IO, STORE_LOG,
                   "advance store generation for reclassification");
    }
    /* A complete class change charges the target pool. Replica updates and
     * incomplete packages retain their current pool accounting. */
    enum vcs_package_store_result room = store_class_room_locked(
        store, package_root, class_, &pkg);
    if (room != VCS_PACKAGE_STORE_OK) {
        store_process_unlock(store);
        pthread_mutex_unlock(&store->lock);
        return room;
    }
    pkg->class_ = class_;
    pkg->replicas = replicas;
    store_package_touch(store, pkg);
    store_process_unlock(store);
    pthread_mutex_unlock(&store->lock);
    return VCS_PACKAGE_STORE_OK;
}

/* ── status + introspection ───────────────────────────────────────── */
#define STORE_RELEASE_REPLAY_BUDGET_BYTES (64u * 1024u * 1024u)

struct store_release_row {
    struct vcs_package_release release;
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
};

static int store_release_row_cmp(const void *left, const void *right)
{
    const struct store_release_row *a = left;
    const struct store_release_row *b = right;
    int order = memcmp(a->release.publisher_pubkey,
                       b->release.publisher_pubkey,
                       VCS_PACKAGE_RELEASE_PUBKEY_BYTES);
    if (order) return order;
    if (a->release.publisher_sequence != b->release.publisher_sequence)
        return a->release.publisher_sequence < b->release.publisher_sequence
                   ? -1 : 1;
    return memcmp(a->id, b->id, sizeof(a->id));
}

struct store_replay {
    const char *root;
    const char *dir;
    struct store_release_row *rows;
    size_t count;
    size_t capacity;
    uint64_t quarantined;
};

enum store_release_read {
    STORE_RELEASE_READ_OK,
    STORE_RELEASE_READ_DAMAGED, /* proven not a release: size out of range */
    STORE_RELEASE_READ_IO,      /* the read itself failed: not proof of damage */
};

static enum store_release_read store_release_read(const char *path,
                                                  uint8_t **wire,
                                                  size_t *wire_len)
{
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return STORE_RELEASE_READ_IO;
    uint64_t size = 0;
    if (!platform_positioned_file_size(&file, &size)) {
        platform_positioned_file_close(&file);
        return STORE_RELEASE_READ_IO;
    }
    if (size == 0 || size > VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES) {
        platform_positioned_file_close(&file);
        return STORE_RELEASE_READ_DAMAGED;
    }
    uint8_t *buf = zcl_malloc((size_t)size, "store_release_read");
    int64_t got = buf ? platform_positioned_file_read(&file, buf,
                                                      (size_t)size, 0) : -1;
    platform_positioned_file_close(&file);
    if (got != (int64_t)size) {
        free(buf);
        return STORE_RELEASE_READ_IO;
    }
    *wire = buf;
    *wire_len = (size_t)size;
    return STORE_RELEASE_READ_OK;
}

/* Only proof that the bytes are not the release they name counts as damage:
 * a broken wire structure or a digest that differs from the file name. A
 * refusal that depends on the reader (schema version, licence allowlist,
 * field grammar) may be a valid release from a newer build, so it fails the
 * open instead. Signatures are checked later by acceptance, whose refusal
 * also fails the open. */
static bool store_release_error_is_damage(enum vcs_package_release_error e)
{
    switch (e) {
    case VCS_PACKAGE_RELEASE_ERR_WIRE_MAGIC:
    case VCS_PACKAGE_RELEASE_ERR_WIRE_OVERSIZE:
    case VCS_PACKAGE_RELEASE_ERR_WIRE_TRUNCATED:
    case VCS_PACKAGE_RELEASE_ERR_WIRE_TRAILING:
        return true;
    default:
        return false;
    }
}

static const char *store_release_damage(const uint8_t *wire, size_t wire_len,
                                        const char *name,
                                        struct store_release_row *row,
                                        enum vcs_package_release_error *refused)
{
    enum vcs_package_release_error e =
        vcs_package_release_parse(wire, wire_len, &row->release);
    if (e == VCS_PACKAGE_RELEASE_OK)
        e = vcs_package_release_id(&row->release, row->id);
    if (e != VCS_PACKAGE_RELEASE_OK && !store_release_error_is_damage(e)) {
        *refused = e;
        return NULL;
    }
    if (e != VCS_PACKAGE_RELEASE_OK)
        return "unparseable release";
    char id_hex[65];
    zcl_hex_encode(row->id, sizeof(row->id), id_hex);
    return strcmp(id_hex, name) == 0 ? NULL
                                     : "digest does not match file name";
}

static bool store_move_noreplace(const char *from, const char *to)
{
#if defined(_WIN32)
    wchar_t wide_from[STORE_PATH_MAX];
    wchar_t wide_to[STORE_PATH_MAX];
    return store_release_wide_path(from, wide_from) &&
        store_release_wide_path(to, wide_to) &&
        MoveFileExW(wide_from, wide_to, MOVEFILE_WRITE_THROUGH) != 0;
#else
    return rename(from, to) == 0;
#endif
}

static bool store_sync_directory(const char *dir)
{
#if defined(_WIN32)
    (void)dir;
    return true;
#else
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    bool synced = fsync(fd) == 0;
    close(fd);
    return synced;
#endif
}

/* First unused <name>.<unix_ts>[.<n>] under qdir. */
static bool store_quarantine_target(const char *qdir, const char *name,
                                    char *to, size_t to_size)
{
    long long stamp = (long long)(clock_now_wall_ms() / 1000);
    for (unsigned n = 0; n < 100u; n++) {
        int len = n == 0
            ? snprintf(to, to_size, "%s/%s.%lld", qdir, name, stamp)
            : snprintf(to, to_size, "%s/%s.%lld.%u", qdir, name, stamp, n);
        if (len <= 0 || (size_t)len >= to_size) return false;
        if (!store_path_exists(to)) return true;
    }
    return false;
}

/* Rename, never delete: the damaged record stays inspectable in the store. */
static bool store_release_quarantine(struct store_replay *rp,
                                     const char *name, const char *reason)
{
    char qdir[STORE_PATH_MAX], from[STORE_PATH_MAX], to[STORE_PATH_MAX];
    int a = snprintf(qdir, sizeof(qdir), "%s/quarantine/releases", rp->root);
    int b = snprintf(from, sizeof(from), "%s/%s", rp->dir, name);
    if (a <= 0 || (size_t)a >= sizeof(qdir) || b <= 0 ||
        (size_t)b >= sizeof(from))
        LOG_FAIL(STORE_LOG, "quarantine path too long for release %s", name);
    if (!store_mkdir_p(qdir) ||
        !store_quarantine_target(qdir, name, to, sizeof(to)) ||
        !store_move_noreplace(from, to) ||
        !store_sync_directory(qdir) || !store_sync_directory(rp->dir))
        LOG_FAIL(STORE_LOG, "quarantine damaged release %s (%s): %s", from,
                 reason, strerror(errno));
    rp->quarantined++;
    LOG_ERROR(STORE_LOG, "quarantined damaged release %s -> %s: %s", from, to,
              reason);
    return true;
}

static bool store_release_row_push(struct store_replay *rp,
                                   const struct store_release_row *row)
{
    if (rp->count == rp->capacity) {
        size_t maximum = STORE_RELEASE_REPLAY_BUDGET_BYTES / sizeof(*rp->rows);
        if (rp->count >= maximum)
            LOG_FAIL(STORE_LOG, "persisted release replay memory bound");
        size_t next = rp->capacity ? rp->capacity * 2u : 64u;
        if (next > maximum) next = maximum;
        struct store_release_row *grown = zcl_realloc(
            rp->rows, next * sizeof(*rp->rows), "store_release_replay");
        if (!grown)
            LOG_FAIL(STORE_LOG, "allocate persisted release replay");
        rp->rows = grown;
        rp->capacity = next;
    }
    rp->rows[rp->count++] = *row;
    return true;
}

static bool store_release_row_add(struct store_replay *rp, const char *name)
{
    if (!store_name_is_hex64(name))
        LOG_FAIL(STORE_LOG, "invalid persisted release filename %s", name);
    char path[STORE_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", rp->dir, name);
    if (n <= 0 || (size_t)n >= sizeof(path))
        LOG_FAIL(STORE_LOG, "persisted release path too long");
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    enum store_release_read read = store_release_read(path, &wire, &wire_len);
    if (read == STORE_RELEASE_READ_IO)
        LOG_FAIL(STORE_LOG, "unreadable persisted release %s: %s", name,
                 strerror(errno));
    struct store_release_row row = {0};
    enum vcs_package_release_error refused = VCS_PACKAGE_RELEASE_OK;
    const char *damage = read == STORE_RELEASE_READ_DAMAGED
        ? "zero length or oversize"
        : store_release_damage(wire, wire_len, name, &row, &refused);
    free(wire);
    if (refused != VCS_PACKAGE_RELEASE_OK)
        LOG_FAIL(STORE_LOG, "persisted release %s is refused by this build: %s",
                 name, vcs_package_release_error_string(refused));
    if (damage)
        return store_release_quarantine(rp, name, damage);
    return store_release_row_push(rp, &row);
}

#if defined(_WIN32)
static bool store_release_collect(struct store_replay *rp)
{
    const char *dir = rp->dir;
    bool complete = true;
    wchar_t wide_dir[STORE_PATH_MAX];
    wchar_t pattern[STORE_PATH_MAX];
    complete = store_release_wide_path(dir, wide_dir);
    int pattern_len = complete
        ? swprintf(pattern, STORE_PATH_MAX, L"%ls\\*", wide_dir) : -1;
    complete = complete && pattern_len > 0 &&
        (size_t)pattern_len < STORE_PATH_MAX;
    if (complete) {
        WIN32_FIND_DATAW entry;
        HANDLE find = FindFirstFileW(pattern, &entry);
        if (find == INVALID_HANDLE_VALUE)
            complete = GetLastError() == ERROR_FILE_NOT_FOUND;
        else {
            do {
                if (wcscmp(entry.cFileName, L".") == 0 ||
                    wcscmp(entry.cFileName, L"..") == 0)
                    continue;
                if ((entry.dwFileAttributes &
                     (FILE_ATTRIBUTE_DIRECTORY |
                      FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
                    complete = false;
                    break;
                }
                int bytes = WideCharToMultiByte(
                    CP_UTF8, WC_ERR_INVALID_CHARS, entry.cFileName, -1,
                    NULL, 0, NULL, NULL);
                char name[65];
                if (bytes != 65 ||
                    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                        entry.cFileName, -1, name, bytes,
                                        NULL, NULL) != bytes ||
                    !store_release_row_add(rp, name)) {
                    complete = false;
                    break;
                }
            } while (FindNextFileW(find, &entry));
            if (complete && GetLastError() != ERROR_NO_MORE_FILES)
                complete = false;
            FindClose(find);
        }
    }
    return complete;
}
#else
static bool store_release_collect(struct store_replay *rp)
{
    const char *dir = rp->dir;
    bool complete = true;
    DIR *d = opendir(dir);
    if (!d) {
        LOG_ERROR(STORE_LOG, "open persisted releases under %s: %s", dir,
                  strerror(errno));
        return false;
    }
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(d);
        if (!entry) {
            if (errno != 0) complete = false;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (!store_release_row_add(rp, entry->d_name)) {
            complete = false;
            break;
        }
    }
    if (closedir(d) != 0) complete = false;
    return complete;
}
#endif

static struct vcs_package_accept *store_replay_project(
    struct store_replay *rp)
{
    struct vcs_package_accept *projection = vcs_package_accept_new();
    if (!projection) return NULL;
    if (rp->count > 1)
        qsort(rp->rows, rp->count, sizeof(*rp->rows), store_release_row_cmp);
    for (size_t i = 0; i < rp->count; i++) {
        enum vcs_package_accept_result result =
            vcs_package_accept(projection, &rp->rows[i].release);
        if (result == VCS_PACKAGE_ACCEPT_OK) continue;
        LOG_ERROR(STORE_LOG, "persisted release %zu refuses replay: %s", i,
                  vcs_package_accept_result_string(result));
        vcs_package_accept_free(projection);
        return NULL;
    }
    return projection;
}

struct vcs_package_accept *store_replay_releases(const char *root,
                                                 uint64_t *quarantined)
{
    char dir[STORE_PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s/releases", root);
    if (n <= 0 || (size_t)n >= sizeof(dir)) {
        LOG_ERROR(STORE_LOG, "persisted release directory path too long");
        return NULL;
    }
    struct store_replay rp = { .root = root, .dir = dir };
    struct vcs_package_accept *projection =
        store_release_collect(&rp) ? store_replay_project(&rp) : NULL;
    *quarantined = rp.quarantined;
    free(rp.rows);
    if (!projection)
        LOG_ERROR(STORE_LOG, "persisted release history incomplete under %s",
                  dir);
    return projection;
}

/* ── admission: releases ────────────────────── */

static enum vcs_package_store_result store_release_persist(
    struct vcs_package_store *store,
    const struct vcs_package_release *release,
    const uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES])
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_release_serialize(release, &wire, &wire_len) !=
            VCS_PACKAGE_RELEASE_OK) {
        LOG_ERROR(STORE_LOG, "serialize accepted release");
        return VCS_PACKAGE_STORE_ERR_ALLOC;
    }
    char id_hex[65];
    zcl_hex_encode(id, 32, id_hex);
    char path[STORE_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/releases/%s", store->root,
                     id_hex);
    bool persisted = n > 0 && (size_t)n < sizeof(path) &&
        store_generation_advance(store) &&
        store_atomic_write(path, wire, wire_len);
    free(wire);
    if (!persisted) {
        LOG_ERROR(STORE_LOG, "persist accepted release %s", id_hex);
        return VCS_PACKAGE_STORE_ERR_IO;
    }
    return VCS_PACKAGE_STORE_OK;
}

static bool store_release_history_matches_locked(
    const struct vcs_package_store *store,
    const struct vcs_package_release *release)
{
    uint8_t id[32];
    if (vcs_package_release_id(release, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    char hex[65], path[STORE_PATH_MAX];
    zcl_hex_encode(id, 32, hex);
    int n = snprintf(path, sizeof(path), "%s/releases/%s", store->root, hex);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    uint8_t *wire = NULL, *requested = NULL;
    size_t length = 0, requested_length = 0;
    /* The positioned reader opens a regular file without following the
     * final symlink/reparse point and bounds bytes by the release codec. */
    if (store_release_read(path, &wire, &length) != STORE_RELEASE_READ_OK)
        return false;
    struct store_release_row row = {0};
    enum vcs_package_release_error refused = VCS_PACKAGE_RELEASE_OK;
    const char *damage = store_release_damage(wire, length, hex, &row, &refused);
    bool matches = !damage && refused == VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_verify(&row.release) == VCS_PACKAGE_RELEASE_OK &&
        vcs_package_release_serialize(release, &requested, &requested_length) ==
            VCS_PACKAGE_RELEASE_OK;
    if (matches)
        matches = length == requested_length &&
                  memcmp(wire, requested, length) == 0;
    free(requested);
    free(wire);
    return matches;
}

bool vcs_package_store_release_history_matches(
    struct vcs_package_store *store, const struct vcs_package_release *release)
{
    if (!store || !release) return false;
    pthread_mutex_lock(&store->lock);
    bool process_locked = store_process_lock(store);
    bool matches = process_locked && store_generation_check(store) &&
        store_release_history_matches_locked(store, release);
    if (process_locked) store_process_unlock(store);
    pthread_mutex_unlock(&store->lock);
    return matches;
}

enum vcs_package_store_result vcs_package_store_put_release(
    struct vcs_package_store *store,
    const struct vcs_package_release *release,
    enum vcs_package_accept_result *accept_out)
{
    if (!store || !release)
        LOG_RETURN(VCS_PACKAGE_STORE_ERR_NULL, STORE_LOG,
                   "null store/release");
    pthread_mutex_lock(&store->lock);
    enum vcs_package_store_result result = VCS_PACKAGE_STORE_ERR_IO;
    struct vcs_package_accept *proposal = NULL;
    bool process_locked = store_process_lock(store);
    if (!process_locked || !store_generation_check(store)) {
        LOG_ERROR(STORE_LOG, "release admission needs current store generation");
        goto release_done;
    }
    proposal = vcs_package_accept_clone(store->accept);
    if (!proposal) {
        result = VCS_PACKAGE_STORE_ERR_ALLOC;
        LOG_ERROR(STORE_LOG, "release admission proposal allocation");
        goto release_done;
    }
    enum vcs_package_accept_result ar =
        vcs_package_accept(proposal, release);
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
        result = VCS_PACKAGE_STORE_ERR_ACCEPT;
        LOG_ERROR(STORE_LOG, "release admission refused: %s",
                  vcs_package_accept_result_string(ar));
        goto release_done;
    }
    if (!have_id) {
        result = VCS_PACKAGE_STORE_ERR_ALLOC;
        LOG_ERROR(STORE_LOG, "accepted release has no id");
        goto release_done;
    }
    result = store_release_persist(store, release, id);
    if (result != VCS_PACKAGE_STORE_OK)
        goto release_done;
    struct vcs_package_accept *retired = store->accept;
    store->accept = proposal;
    proposal = NULL;
    vcs_package_accept_free(retired);
    /* An accepted envelope changes what the package IS to the outside
     * world: an unsigned root nobody may host becomes a signed, licensed
     * one that may be announced and served. Observers key their public-
     * hosting decision on the mutation generation, so a release landing
     * after its manifest must advance it — otherwise the package stays
     * privately hostable-in-name-only until some unrelated byte arrives. */
    struct store_package *pkg =
        store_find(store, release->package_root, NULL);
    if (pkg)
        store_package_touch(store, pkg);
    result = VCS_PACKAGE_STORE_OK;
release_done:
    vcs_package_accept_free(proposal);
    if (process_locked)
        store_process_unlock(store);
    pthread_mutex_unlock(&store->lock);
    return result;
}

bool vcs_package_store_cache_counts(struct vcs_package_store *store,
                                    struct vcs_package_store_cache_counts *out)
{
    if (!store || !out)
        LOG_RETURN(false, STORE_LOG, "cache counts: null store or output");
    pthread_mutex_lock(&store->lock);
    out->manifest_loads = store->hot_loads;
    out->trim_passes = store->hot_trim_passes;
    pthread_mutex_unlock(&store->lock);
    return true;
}

uint64_t vcs_package_store_quarantined_releases(
    struct vcs_package_store *store)
{
    if (!store) return 0;
    pthread_mutex_lock(&store->lock);
    uint64_t total = store->releases_quarantined_total;
    pthread_mutex_unlock(&store->lock);
    return total;
}
