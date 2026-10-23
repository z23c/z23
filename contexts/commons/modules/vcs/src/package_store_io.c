/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_store_io — filesystem layout and crash recovery for the local
 * ZCODE package store. See vcs/package_store.h for the frozen contract
 * (layout, verify-before-store, resumable staging, orphan GC). This unit
 * owns path construction, durable writes (temp + fsync + atomic rename),
 * the CAS presence set, and the open-time recovery sweep; policy (quota,
 * pools, eviction) lives in package_store.c. */

#if !defined(_WIN32)
#define _GNU_SOURCE
#endif

#include "package_store_priv.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <wchar.h>
#include <windows.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define STORE_LOG "vcs.store"
/* See vcs/package_store.h: OFF by default, so every store_atomic_write
 * fsyncs/FlushFileBuffers before its atomic rename exactly as the
 * crash-recovery contract requires. */
_Atomic bool g_store_deferred_sync = false;

void vcs_package_store_set_deferred_sync(bool enabled)
{
    atomic_store(&g_store_deferred_sync, enabled);
}

bool vcs_package_store_deferred_sync_enabled(void)
{
    return atomic_load(&g_store_deferred_sync);
}

bool store_name_is_hex64(const char *name)
{
    uint8_t scratch[32];
    return zcl_hex_decode_lower(name, scratch, 32);
}

bool store_path_exists(const char *path)
{
#if defined(_WIN32)
    wchar_t wide[STORE_PATH_MAX];
    if (!store_wide_path(path, wide))
        return false;
    HANDLE file = CreateFileW(
        wide, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    FILE_ATTRIBUTE_TAG_INFO tag;
    bool exists = GetFileInformationByHandleEx(file, FileAttributeTagInfo,
                                                &tag, sizeof(tag)) != 0 &&
                  (tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
                                         FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
    CloseHandle(file);
    return exists;
#else
    return access(path, F_OK) == 0;
#endif
}

bool store_directory_exists(const char *path)
{
#if defined(_WIN32)
    wchar_t wide[STORE_PATH_MAX];
    return store_wide_path(path, wide) && store_win32_real_directory(wide);
#else
    struct stat st;
    return lstat(path, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

static bool store_directory_empty(const char *path)
{
#if defined(_WIN32)
    wchar_t wide[STORE_PATH_MAX];
    if (!store_wide_path(path, wide) || !store_win32_real_directory(wide))
        return false;
    size_t len = wcslen(wide);
    if (len + 3 >= STORE_PATH_MAX) return false;
    wide[len++] = L'\\';
    wide[len++] = L'*';
    wide[len] = L'\0';
    WIN32_FIND_DATAW data;
    HANDLE found = FindFirstFileW(wide, &data);
    if (found == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    bool empty = true;
    do {
        if (wcscmp(data.cFileName, L".") != 0 &&
            wcscmp(data.cFileName, L"..") != 0) {
            empty = false;
            break;
        }
    } while (FindNextFileW(found, &data));
    DWORD error = GetLastError();
    FindClose(found);
    return empty && error == ERROR_NO_MORE_FILES;
#else
    DIR *dir = opendir(path);
    if (!dir) return false;
    for (;;) {
        errno = 0;
        struct dirent *ent = readdir(dir);
        if (!ent) {
            bool empty = errno == 0;
            closedir(dir);
            return empty;
        }
        if (strcmp(ent->d_name, ".") != 0 &&
            strcmp(ent->d_name, "..") != 0) {
            closedir(dir);
            return false;
        }
    }
#endif
}

bool store_unlink(const char *path)
{
#if defined(_WIN32)
    wchar_t wide[STORE_PATH_MAX];
    if (!store_wide_path(path, wide)) {
        errno = EINVAL;
        return false;
    }
    DWORD attrs = GetFileAttributesW(wide);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
            return true;
        store_set_errno(error);
        return false;
    }
    if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        errno = EISDIR;
        return false;
    }
    if (store_win32_delete_leaf(wide, attrs))
        return true;
    store_set_errno(GetLastError());
    return false;
#else
    return unlink(path) == 0 || errno == ENOENT;
#endif
}

void store_cas_path(const struct vcs_package_store *store,
                    const uint8_t hash[32], char *out, size_t out_size)
{
    char hex[65];
    zcl_hex_encode(hash, 32, hex);
    snprintf(out, out_size, "%s/cas/sha3/%.2s/%s", store->root, hex, hex);
}

/* Read-only presence probe by directory. Deliberately does NOT take a
 * store: vcs_package_store_open() runs the mutating recovery sweep (temp
 * cleanup, staging commit, orphan GC), so a read-only projection must not
 * open one. Pure stat over the same frozen layout store_cas_path builds. */
bool vcs_package_cas_present_in(const char *zcode_dir, const uint8_t hash[32])
{
    char hex[65];
    char path[STORE_PATH_MAX];
    int n;

    if (!zcode_dir || !hash)
        return false;
    zcl_hex_encode(hash, 32, hex);
    n = snprintf(path, sizeof(path), "%s/cas/sha3/%.2s/%s", zcode_dir, hex,
                 hex);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;
    struct platform_positioned_file file;
    uint64_t size = 0;
    platform_positioned_file_init(&file);
    bool present = platform_positioned_file_open(&file, path) &&
                   platform_positioned_file_size(&file, &size) && size > 0;
    platform_positioned_file_close(&file);
    return present;
}

/* ── CAS presence set (ascending hashes, bsearch) ─────────────────── */

static size_t store_cas_lower_bound(const struct vcs_package_store *store,
                                    const uint8_t hash[32], bool *found)
{
    size_t lo = 0;
    size_t hi = store->cas_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = memcmp(store->cas[mid], hash, 32);
        if (cmp == 0) {
            *found = true;
            return mid;
        }
        if (cmp < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    *found = false;
    return lo;
}

bool store_cas_contains(const struct vcs_package_store *store,
                        const uint8_t hash[32])
{
    bool found = false;
    store_cas_lower_bound(store, hash, &found);
    return found;
}

bool store_cas_insert(struct vcs_package_store *store,
                      const uint8_t hash[32])
{
    bool found = false;
    size_t at = store_cas_lower_bound(store, hash, &found);
    if (found)
        return true;
    if (store->cas_count == store->cas_cap) {
        if (store->cas_cap > SIZE_MAX / 2 / sizeof(*store->cas))
            LOG_FAIL(STORE_LOG, "CAS catalog capacity overflow");
        size_t cap = store->cas_cap ? store->cas_cap * 2 : 256;
        uint8_t(*cas)[32] =
            zcl_realloc(store->cas, cap * sizeof(*cas), "store_cas");
        if (!cas)
            LOG_FAIL(STORE_LOG, "grow CAS set to %zu", cap);
        store->cas = cas;
        store->cas_cap = cap;
    }
    memmove(&store->cas[at + 1], &store->cas[at],
            (store->cas_count - at) * sizeof(*store->cas));
    memcpy(store->cas[at], hash, 32);
    store->cas_count++;
    return true;
}

void store_cas_remove(struct vcs_package_store *store,
                      const uint8_t hash[32])
{
    bool found = false;
    size_t at = store_cas_lower_bound(store, hash, &found);
    if (!found)
        return;
    memmove(&store->cas[at], &store->cas[at + 1],
            (store->cas_count - at - 1) * sizeof(*store->cas));
    store->cas_count--;
}

bool store_chunk_write_verified(struct vcs_package_store *store,
                                const uint8_t hash[32],
                                const uint8_t *chunk, size_t chunk_len)
{
    char cas_path[STORE_PATH_MAX];
    store_cas_path(store, hash, cas_path, sizeof(cas_path));
    char cas_dir[STORE_PATH_MAX];
    snprintf(cas_dir, sizeof(cas_dir), "%s", cas_path);
    char *slash = strrchr(cas_dir, '/');
    if (!slash)
        LOG_RETURN(false, STORE_LOG, "malformed CAS path %s", cas_path);
    *slash = '\0';
    if (!store_mkdir_p(cas_dir) ||
        !store_atomic_write(cas_path, chunk, chunk_len) ||
        !store_cas_insert(store, hash))
        LOG_RETURN(false, STORE_LOG, "write verified CAS chunk");
    return true;
}

void store_package_touch(struct vcs_package_store *store,
                         struct store_package *pkg)
{
    if (!store || !pkg)
        return;
    store->next_mutation_generation++;
    if (!store->next_mutation_generation)
        store->next_mutation_generation++;
    pkg->mutation_generation = store->next_mutation_generation;
}

void store_packages_touch_hash(struct vcs_package_store *store,
                               const uint8_t hash[32])
{
    if (!store || !hash)
        return;
    for (size_t i = 0; i < store->pkg_count; i++)
        for (size_t c = 0; c < store->pkgs[i].chunk_count; c++)
            if (memcmp(store->pkgs[i].chunks[c].hash, hash, 32) == 0) {
                store_package_touch(store, &store->pkgs[i]);
                break;
            }
}

/* ── derived per-package state ────────────────────────────────────── */

void store_package_present(const struct vcs_package_store *store,
                           const struct store_package *pkg,
                           uint32_t *chunks_out, uint64_t *bytes_out)
{
    uint32_t chunks = 0;
    uint64_t bytes = 0;
    for (size_t i = 0; i < pkg->chunk_count; i++) {
        if (store_cas_contains(store, pkg->chunks[i].hash)) {
            chunks++;
            bytes += pkg->chunks[i].size;
        }
    }
    if (chunks_out)
        *chunks_out = chunks;
    if (bytes_out)
        *bytes_out = bytes;
}

bool store_package_complete(const struct vcs_package_store *store,
                            const struct store_package *pkg)
{
    uint32_t present = 0;
    store_package_present(store, pkg, &present, NULL);
    return (uint64_t)present == (uint64_t)pkg->chunk_count;
}

/* Staging directory, staged manifest and final manifest paths for a commit. */
static bool store_commit_paths(const struct vcs_package_store *store,
                               const struct store_package *pkg,
                               char staging_dir[STORE_PATH_MAX],
                               char staged[STORE_PATH_MAX],
                               char final[STORE_PATH_MAX])
{
    int dn = snprintf(staging_dir, STORE_PATH_MAX, "%s/staging/%s",
                      store->root, pkg->root_hex);
    int sn = snprintf(staged, STORE_PATH_MAX, "%s/manifest", staging_dir);
    int fn = snprintf(final, STORE_PATH_MAX, "%s/manifests/%s", store->root,
                      pkg->root_hex);
    return dn > 0 && (size_t)dn < STORE_PATH_MAX && sn > 0 &&
           (size_t)sn < STORE_PATH_MAX && fn > 0 &&
           (size_t)fn < STORE_PATH_MAX;
}

bool store_package_commit(struct vcs_package_store *store,
                          struct store_package *pkg)
{
    char staging_dir[STORE_PATH_MAX];
    char staged[STORE_PATH_MAX];
    char final[STORE_PATH_MAX];
#if defined(_WIN32)
    wchar_t wide_staged[STORE_PATH_MAX], wide_final[STORE_PATH_MAX];
    if (!store_commit_paths(store, pkg, staging_dir, staged, final) ||
        !store_wide_path(staged, wide_staged) ||
        !store_wide_path(final, wide_final))
        LOG_FAIL(STORE_LOG, "commit path too long for %s", pkg->root_hex);
    if (!MoveFileExW(wide_staged, wide_final,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        LOG_FAIL(STORE_LOG, "commit rename %s -> %s: Win32 error %lu", staged,
                 final, (unsigned long)GetLastError());
#else
    if (!store_commit_paths(store, pkg, staging_dir, staged, final))
        LOG_FAIL(STORE_LOG, "commit path too long for %s", pkg->root_hex);
    if (rename(staged, final) != 0)
        LOG_FAIL(STORE_LOG, "commit rename %s -> %s: %s", staged, final,
                 strerror(errno));
#endif
    if (!store_rm_rf(staging_dir))
        LOG_FAIL(STORE_LOG, "commit cleanup %s", staging_dir);
    pkg->committed = true;
    store_package_touch(store, pkg);
    return true;
}

/* ── open / recovery ──────────────────────────────────────────────── */

/* Read a whole file bounded by VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES. */
static int store_chunk_hash_cmp(const void *a, const void *b)
{
    const struct store_unique_chunk *ca = a;
    const struct store_unique_chunk *cb = b;
    return memcmp(ca->hash, cb->hash, 32);
}

static int store_hash_cmp(const void *a, const void *b)
{
    return memcmp(a, b, 32);
}

/* Build the unique (sorted, deduped) chunk list for a parsed manifest. */
static bool store_package_build_chunks(struct store_package *pkg)
{
    size_t total = 0;
    for (size_t i = 0; i < pkg->manifest.count; i++)
        total += pkg->manifest.files[i].chunk_count;
    pkg->total_bytes = 0;
    for (size_t i = 0; i < pkg->manifest.count; i++)
        pkg->total_bytes += pkg->manifest.files[i].size;
    pkg->chunks = NULL;
    pkg->chunk_count = 0;
    if (total == 0)
        return true;
    struct store_unique_chunk *chunks = zcl_malloc(
        total * sizeof(*chunks), "store_chunks");
    if (!chunks)
        LOG_FAIL(STORE_LOG, "alloc %zu chunk records", total);
    size_t n = 0;
    for (size_t i = 0; i < pkg->manifest.count; i++) {
        const struct vcs_package_file *f = &pkg->manifest.files[i];
        for (uint32_t c = 0; c < f->chunk_count; c++) {
            memcpy(chunks[n].hash, f->chunk_hashes + (size_t)c * 32u, 32);
            uint64_t off = (uint64_t)c * VCS_PACKAGE_CHUNK_BYTES;
            chunks[n].size = f->size - off > VCS_PACKAGE_CHUNK_BYTES
                                 ? VCS_PACKAGE_CHUNK_BYTES
                                 : f->size - off;
            n++;
        }
    }
    /* Sort by hash, then dedupe (same hash = same content = same size). */
    qsort(chunks, n, sizeof(*chunks), store_chunk_hash_cmp);
    size_t unique = 0;
    for (size_t i = 0; i < n; i++) {
        if (unique > 0 &&
            memcmp(chunks[unique - 1].hash, chunks[i].hash, 32) == 0)
            continue;
        chunks[unique++] = chunks[i];
    }
    pkg->chunks = chunks;
    pkg->chunk_count = unique;
    return true;
}

void store_package_release_hot(struct vcs_package_store *store,
                               struct store_package *pkg)
{
    if (!store || !pkg || !pkg->manifest_loaded) return;
    vcs_package_manifest_free(&pkg->manifest);
    free(pkg->manifest_wire);
    pkg->manifest_wire = NULL;
    pkg->manifest_loaded = false;
    pkg->hot_clock = 0;
    if (store->hot_count) store->hot_count--;
}

/* Finding the least recently used parsed manifests is a pass over the whole
 * catalog. Each pass releases the cache down to half its bound, so a scan
 * that touches every record pays one catalog pass per STORE_HOT_KEEP misses
 * instead of one per miss. The bound itself is unchanged. */
#define STORE_HOT_KEEP (STORE_HOT_MANIFESTS / 2u)

/* Indexes of the `want` least recently used loaded records, oldest first. */
static size_t store_hot_oldest(const struct vcs_package_store *store,
                               const struct store_package *protect,
                               size_t *oldest, size_t want)
{
    size_t found = 0;
    for (size_t i = 0; i < store->pkg_count; i++) {
        const struct store_package *candidate = &store->pkgs[i];
        if (candidate == protect || !candidate->manifest_loaded)
            continue;
        uint64_t clock = candidate->hot_clock;
        if (found == want &&
            clock >= store->pkgs[oldest[found - 1u]].hot_clock)
            continue;
        size_t at = found < want ? found++ : want - 1u;
        while (at > 0 && store->pkgs[oldest[at - 1u]].hot_clock > clock) {
            oldest[at] = oldest[at - 1u];
            at--;
        }
        oldest[at] = i;
    }
    return found;
}

static void store_hot_trim(struct vcs_package_store *store,
                           const struct store_package *protect)
{
    while (store->hot_count > STORE_HOT_MANIFESTS) {
        size_t oldest[STORE_HOT_MANIFESTS];
        size_t want = store->hot_count - STORE_HOT_KEEP;
        if (want > STORE_HOT_MANIFESTS) want = STORE_HOT_MANIFESTS;
        size_t found = store_hot_oldest(store, protect, oldest, want);
        store->hot_trim_passes++;
        if (!found) break;
        for (size_t i = 0; i < found; i++)
            store_package_release_hot(store, &store->pkgs[oldest[i]]);
    }
}

bool store_package_materialize(struct vcs_package_store *store,
                               struct store_package *pkg)
{
    if (!store || !pkg) return false;
    if (pkg->manifest_loaded) {
        pkg->hot_clock = ++store->hot_clock;
        return true;
    }
    char path[STORE_PATH_MAX];
    int n = snprintf(path, sizeof(path), pkg->committed
                     ? "%s/manifests/%s" : "%s/staging/%s/manifest",
                     store->root, pkg->root_hex);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    size_t wire_len = 0;
    uint8_t *wire = store_read_file(path, &wire_len);
    if (!wire) return false;
    struct vcs_package_manifest manifest;
    uint8_t root[32];
    bool valid = wire_len == pkg->manifest_wire_len &&
                 vcs_package_manifest_parse(wire, wire_len, &manifest);
    if (valid) {
        valid = vcs_package_manifest_root(&manifest, root) &&
                memcmp(root, pkg->root, sizeof(root)) == 0;
        if (!valid) vcs_package_manifest_free(&manifest);
    }
    if (!valid) {
        free(wire);
        LOG_ERROR(STORE_LOG, "catalog manifest changed at %s", path);
        return false;
    }
    pkg->manifest = manifest;
    pkg->manifest_wire = wire;
    pkg->manifest_loaded = true;
    pkg->hot_clock = ++store->hot_clock;
    store->hot_count++;
    store->hot_loads++;
    store_hot_trim(store, pkg);
    return true;
}

uint32_t store_releases_count(const struct vcs_package_store *store)
{
    char dir[STORE_PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s/releases", store->root);
    if (n < 0 || (size_t)n >= sizeof(dir))
        return 0;
    uint32_t count = 0;
#if defined(_WIN32)
    struct platform_directory_list files = {0};
    if (!platform_directory_list_regular_sorted(dir, &files))
        return 0;
    for (size_t i = 0; i < files.count; i++)
        if (store_name_is_hex64(files.entries[i].name))
            count++;
    platform_directory_list_free(&files);
#else
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL)
        if (store_name_is_hex64(de->d_name))
            count++;
    closedir(d);
#endif
    return count;
}

static void store_record_dispose(struct store_package *pkg)
{
    free(pkg->manifest_wire);
    free(pkg->chunks);
    vcs_package_manifest_free(&pkg->manifest);
}

static bool store_record_reserve(struct vcs_package_store *store)
{
    if (store->pkg_count < store->pkg_cap) return true;
    if (store->pkg_cap > SIZE_MAX / 2 ||
        store->pkg_cap > SIZE_MAX / sizeof(*store->pkgs) / 2 ||
        store->pkg_cap > SIZE_MAX / sizeof(*store->root_order) / 2)
        LOG_FAIL(STORE_LOG, "package catalog capacity overflow");
    size_t cap = store->pkg_cap ? store->pkg_cap * 2 : 32;
    struct store_package *pkgs = zcl_realloc(
        store->pkgs, cap * sizeof(*pkgs), "store_pkgs");
    if (!pkgs) LOG_FAIL(STORE_LOG, "grow package table");
    store->pkgs = pkgs;
    size_t *order = zcl_realloc(store->root_order,
                                cap * sizeof(*order), "store_root_order");
    if (!order) LOG_FAIL(STORE_LOG, "grow root index");
    store->root_order = order;
    store->pkg_cap = cap;
    return true;
}

static struct store_package *store_record_publish(
    struct vcs_package_store *store, struct store_package *pkg)
{
    if (!store_record_reserve(store) ||
        UINT64_MAX - store->manifest_bytes_total < pkg->total_bytes) {
        store_record_dispose(pkg);
        LOG_NULL(STORE_LOG, "package catalog capacity or byte overflow");
    }
    size_t lo = 0, hi = store->pkg_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = memcmp(store->pkgs[store->root_order[mid]].root,
                         pkg->root, sizeof(pkg->root));
        if (cmp < 0) lo = mid + 1;
        else hi = mid;
    }
    if (lo < store->pkg_count &&
        memcmp(store->pkgs[store->root_order[lo]].root, pkg->root,
               sizeof(pkg->root)) == 0) {
        store_record_dispose(pkg);
        LOG_NULL(STORE_LOG, "duplicate package root");
    }
    memmove(store->root_order + lo + 1, store->root_order + lo,
            (store->pkg_count - lo) * sizeof(*store->root_order));
    store->root_order[lo] = store->pkg_count;
    store->pkgs[store->pkg_count] = *pkg;
    struct store_package *added = &store->pkgs[store->pkg_count++];
    store->manifest_bytes_total += added->total_bytes;
    store->hot_count++;
    store_hot_trim(store, added);
    return added;
}

struct store_package *store_record_add(struct vcs_package_store *store,
                                       const uint8_t *wire,
                                       size_t wire_len,
                                       const char *expect_hex,
                                       bool committed)
{
    struct store_package pkg;
    memset(&pkg, 0, sizeof(pkg));
    if (!vcs_package_manifest_parse(wire, wire_len, &pkg.manifest))
        LOG_NULL(STORE_LOG, "manifest %s does not parse", expect_hex);
    if (!vcs_package_manifest_root(&pkg.manifest, pkg.root)) {
        vcs_package_manifest_free(&pkg.manifest);
        LOG_NULL(STORE_LOG, "manifest %s has no root", expect_hex);
    }
    zcl_hex_encode(pkg.root, 32, pkg.root_hex);
    if (strcmp(pkg.root_hex, expect_hex) != 0) {
        vcs_package_manifest_free(&pkg.manifest);
        LOG_NULL(STORE_LOG, "manifest at %s commits a different root %s",
                 expect_hex, pkg.root_hex);
    }
    if (!store_package_build_chunks(&pkg)) {
        vcs_package_manifest_free(&pkg.manifest);
        LOG_NULL(STORE_LOG, "manifest %s chunk table", expect_hex);
    }
    pkg.manifest_wire = zcl_malloc(wire_len, "store_manifest_wire");
    if (!pkg.manifest_wire) {
        free(pkg.chunks);
        vcs_package_manifest_free(&pkg.manifest);
        LOG_NULL(STORE_LOG, "wire copy %s", expect_hex);
    }
    memcpy(pkg.manifest_wire, wire, wire_len);
    pkg.manifest_wire_len = wire_len;
    pkg.file_count = (uint32_t)pkg.manifest.count;
    for (size_t i = 0; i < pkg.manifest.count; i++)
        pkg.total_chunks += pkg.manifest.files[i].chunk_count;
    pkg.manifest_loaded = true;
    pkg.hot_clock = ++store->hot_clock;
    pkg.committed = committed;
    /* New packages start RARE: no observed demand or replication yet
     * (the enum's zero value is HOT, so this must be explicit). */
    pkg.class_ = VCS_PACKAGE_STORE_CLASS_RARE;
    store_package_touch(store, &pkg);
    {
        char pin[STORE_PATH_MAX];
        snprintf(pin, sizeof(pin), "%s/pins/%s", store->root,
                 pkg.root_hex);
        pkg.pinned = store_path_exists(pin);
    }
    return store_record_publish(store, &pkg);
}

static bool store_committed_root_loaded(const struct vcs_package_store *store,
                                        const char *root_hex)
{
    for (size_t i = 0; i < store->pkg_count; i++)
        if (store->pkgs[i].committed &&
            strcmp(store->pkgs[i].root_hex, root_hex) == 0)
            return true;
    return false;
}

static bool store_load_staged_record(struct vcs_package_store *store,
                                     const char *dir, const char *name)
{
    char sdir[STORE_PATH_MAX], path[STORE_PATH_MAX];
    snprintf(sdir, sizeof(sdir), "%s/%s", dir, name);
    snprintf(path, sizeof(path), "%s/manifest", sdir);
    size_t wire_len = 0;
    uint8_t *wire = store_read_file(path, &wire_len);
    if (!wire && store_committed_root_loaded(store, name) &&
        store_directory_empty(sdir)) {
        if (!store_generation_advance(store) || !store_rm_rf(sdir))
            LOG_FAIL(STORE_LOG, "clean committed staging remainder %s", sdir);
        return true;
    }
    bool loaded = wire &&
        store_record_add(store, wire, wire_len, name, false) != NULL;
    free(wire);
    if (!loaded)
        LOG_FAIL(STORE_LOG, "staged manifest unreadable at %s", sdir);
    return true;
}

static void store_load_committed_record(struct vcs_package_store *store,
                                         const char *dir, const char *name)
{
    char path[STORE_PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    size_t wire_len = 0;
    uint8_t *wire = store_read_file(path, &wire_len);
    if (!wire) {
        store->catalog_incomplete = true;
        return;
    }
    if (!store_record_add(store, wire, wire_len, name, true))
        store->catalog_incomplete = true;
    free(wire);
}

/* Every committed manifest under dir. An unreadable entry or listing marks
 * the catalog incomplete; the caller decides whether that refuses open. */
static void store_load_committed(struct vcs_package_store *store,
                                 const char *dir)
{
#if defined(_WIN32)
    struct platform_directory_list files = {0};
    if (platform_directory_list_regular_sorted(dir, &files)) {
        for (size_t i = 0; i < files.count; i++) {
            const char *name = files.entries[i].name;
            if (!store_name_is_hex64(name))
                continue;
            store_load_committed_record(store, dir, name);
        }
        platform_directory_list_free(&files);
    } else
        store->catalog_incomplete = true;
#else
    DIR *d = opendir(dir);
    if (d) {
        errno = 0;
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (!store_name_is_hex64(ent->d_name))
                continue;
            store_load_committed_record(store, dir, ent->d_name);
            errno = 0;
        }
        if (errno != 0)
            store->catalog_incomplete = true;
        closedir(d);
    } else
        store->catalog_incomplete = true;
#endif
}

/* Load every committed and staged manifest. Any indeterminate staged read or
 * catalog failure refuses open without deleting the bytes: allocation and
 * I/O failures cannot be distinguished safely from malformed staging here.
 * A manifest already renamed into verified committed storage may leave an
 * empty staging directory after a crash; that directory alone is discarded. */
static bool store_load_manifests(struct vcs_package_store *store)
{
    char dir[STORE_PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/manifests", store->root);
    store_load_committed(store, dir);
    snprintf(dir, sizeof(dir), "%s/staging", store->root);
#if defined(_WIN32)
    struct platform_directory_list dirs = {0};
    if (!platform_directory_list_real_sorted(dir, &dirs))
        LOG_FAIL(STORE_LOG, "list staging manifests under %s", dir);
    for (size_t i = 0; i < dirs.count; i++) {
        const char *name = dirs.entries[i].name;
        if (!store_name_is_hex64(name))
            continue;
        if (!store_load_staged_record(store, dir, name)) {
            platform_directory_list_free(&dirs);
            return false;
        }
    }
    platform_directory_list_free(&dirs);
    return true;
#else
    DIR *d = opendir(dir);
    if (!d)
        LOG_FAIL(STORE_LOG, "open staging manifests under %s: %s", dir,
                 strerror(errno));
    struct dirent *ent;
    for (;;) {
        errno = 0;
        ent = readdir(d);
        if (!ent) break;
        if (!store_name_is_hex64(ent->d_name))
            continue;
        if (!store_load_staged_record(store, dir, ent->d_name)) {
            closedir(d);
            return false;
        }
    }
    if (errno != 0) {
        int saved_errno = errno;
        closedir(d);
        LOG_FAIL(STORE_LOG, "read staging manifests under %s: %s", dir,
                 strerror(saved_errno));
    }
    closedir(d);
    return true;
#endif
}

static bool store_gc_cas_record(struct vcs_package_store *store,
                                const uint8_t hash[32], const char *path,
                                const uint8_t (*refs)[32], size_t ref_count,
                                bool *marked)
{
    bool referenced = ref_count > 0 &&
        bsearch(hash, refs, ref_count, sizeof(*refs),
                store_hash_cmp) != NULL;
    if (referenced)
        return store_cas_insert(store, hash);
    if (!*marked && !store_generation_advance(store))
        LOG_FAIL(STORE_LOG, "mark CAS recovery before orphan GC");
    *marked = true;
#if defined(_WIN32)
    wchar_t wide[STORE_PATH_MAX];
    if (store_wide_path(path, wide) && DeleteFileW(wide))
        store->gc_orphans_total++;
#else
    if (unlink(path) == 0)
        store->gc_orphans_total++;
#endif
    return true;
}

static bool store_gc_ref_capacity(const struct vcs_package_store *store,
                                   size_t *capacity)
{
    size_t total = 0;
    for (size_t i = 0; i < store->pkg_count; i++) {
        if (store->pkgs[i].chunk_count > SIZE_MAX - total)
            LOG_FAIL(STORE_LOG, "GC reference count overflow");
        total += store->pkgs[i].chunk_count;
    }
    if (total > SIZE_MAX / sizeof(uint8_t[32]))
        LOG_FAIL(STORE_LOG, "GC reference bytes overflow");
    *capacity = total;
    return true;
}

/* Concat every loaded record's unique hashes into refs, sorted; returns the
 * count. refs holds ref_cap entries as sized by store_gc_ref_capacity. */
static size_t store_gc_collect_refs(const struct vcs_package_store *store,
                                    uint8_t (*refs)[32])
{
    size_t ref_count = 0;
    for (size_t i = 0; i < store->pkg_count; i++)
        for (size_t c = 0; c < store->pkgs[i].chunk_count; c++)
            memcpy(refs[ref_count++], store->pkgs[i].chunks[c].hash, 32);
    if (ref_count > 0)
        qsort(refs, ref_count, sizeof(*refs), store_hash_cmp);
    return ref_count;
}

/* Delete CAS objects no loaded manifest references; build the CAS set. */
static bool store_gc_cas(struct vcs_package_store *store)
{
    bool marked = false;
    /* Global referenced set: concat every record's unique hashes. */
    size_t ref_cap = 0;
    if (!store_gc_ref_capacity(store, &ref_cap)) return false;
    uint8_t(*refs)[32] = NULL;
    if (ref_cap > 0) {
        refs = zcl_malloc(ref_cap * sizeof(*refs), "store_gc_refs");
        if (!refs)
            LOG_FAIL(STORE_LOG, "alloc %zu GC refs", ref_cap);
    }
    size_t ref_count = store_gc_collect_refs(store, refs);

    char cas_dir[STORE_PATH_MAX];
    snprintf(cas_dir, sizeof(cas_dir), "%s/cas/sha3", store->root);
#if defined(_WIN32)
    struct platform_directory_list dirs = {0};
    if (!platform_directory_list_real_sorted(cas_dir, &dirs)) {
        free(refs);
        LOG_FAIL(STORE_LOG, "list CAS directory %s", cas_dir);
    }
    for (size_t i = 0; i < dirs.count; i++) {
        const char *prefix = dirs.entries[i].name;
        uint8_t prefix_byte;
        if (!zcl_hex_decode_lower(prefix, &prefix_byte, 1))
            continue;
        char sub[STORE_PATH_MAX];
        snprintf(sub, sizeof(sub), "%s/%s", cas_dir, prefix);
        struct platform_directory_list files = {0};
        if (!platform_directory_list_regular_sorted(sub, &files)) {
            platform_directory_list_free(&dirs);
            free(refs);
            LOG_FAIL(STORE_LOG, "list CAS shard %s", sub);
        }
        for (size_t c = 0; c < files.count; c++) {
            uint8_t hash[32];
            const char *name = files.entries[c].name;
            if (!zcl_hex_decode_lower(name, hash, 32) ||
                strncmp(name, prefix, 2) != 0)
                continue;
            char path[STORE_PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", sub, name);
            if (!store_gc_cas_record(store, hash, path, refs,
                                      ref_count, &marked)) {
                platform_directory_list_free(&files);
                platform_directory_list_free(&dirs);
                free(refs);
                LOG_FAIL(STORE_LOG, "CAS object recovery in %s", sub);
            }
        }
        platform_directory_list_free(&files);
        wchar_t wide_sub[STORE_PATH_MAX];
        if (store_wide_path(sub, wide_sub))
            (void)RemoveDirectoryW(wide_sub);
    }
    platform_directory_list_free(&dirs);
#else
    DIR *d = opendir(cas_dir);
    if (!d) {
        free(refs);
        LOG_FAIL(STORE_LOG, "open CAS directory %s: %s", cas_dir,
                 strerror(errno));
    }
    struct dirent *ent;
    for (;;) {
        errno = 0;
        ent = readdir(d);
        if (!ent) break;
        uint8_t prefix_byte;
        if (!zcl_hex_decode_lower(ent->d_name, &prefix_byte, 1))
            continue;
        char sub[STORE_PATH_MAX];
        snprintf(sub, sizeof(sub), "%s/%s", cas_dir, ent->d_name);
        DIR *sd = opendir(sub);
        if (!sd) {
            int saved_errno = errno;
            closedir(d);
            free(refs);
            LOG_FAIL(STORE_LOG, "open CAS shard %s: %s", sub,
                     strerror(saved_errno));
        }
        struct dirent *sent;
        for (;;) {
            errno = 0;
            sent = readdir(sd);
            if (!sent) break;
            uint8_t hash[32];
            if (!zcl_hex_decode_lower(sent->d_name, hash, 32))
                continue;
            char hex3[3] = { ent->d_name[0], ent->d_name[1], '\0' };
            if (strncmp(sent->d_name, hex3, 2) != 0)
                continue;
            char path[STORE_PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", sub, sent->d_name);
            if (!store_gc_cas_record(store, hash, path, refs,
                                      ref_count, &marked)) {
                closedir(sd);
                closedir(d);
                free(refs);
                LOG_FAIL(STORE_LOG, "CAS object recovery in %s", sub);
            }
        }
        if (errno != 0) {
            int saved_errno = errno;
            closedir(sd);
            closedir(d);
            free(refs);
            LOG_FAIL(STORE_LOG, "read CAS shard %s: %s", sub,
                     strerror(saved_errno));
        }
        closedir(sd);
        rmdir(sub); /* no-op unless empty */
    }
    if (errno != 0) {
        int saved_errno = errno;
        closedir(d);
        free(refs);
        LOG_FAIL(STORE_LOG, "read CAS directory %s: %s", cas_dir,
                 strerror(saved_errno));
    }
    closedir(d);
#endif
    free(refs);
    return true;
}

/* Commit every CAS-complete staged package, ascending root hex. */
static bool store_commit_sweep(struct vcs_package_store *store)
{
    bool marked = false;
    for (size_t i = 0; i < store->pkg_count; i++) {
        struct store_package *pkg = &store->pkgs[store->root_order[i]];
        if (!pkg->committed && store_package_complete(store, pkg)) {
            if (!marked && !store_generation_advance(store))
                LOG_FAIL(STORE_LOG, "mark recovery commit before %s",
                         pkg->root_hex);
            marked = true;
            if (!store_package_materialize(store, pkg) ||
                !store_package_commit(store, pkg))
                LOG_FAIL(STORE_LOG, "commit sweep %s", pkg->root_hex);
        }
    }
    return true;
}

static bool store_existing_layout_safe(const struct vcs_package_store *store)
{
    if (store->preexisting_root) {
        static const char *const required[] = {
            "/manifests", "/releases", "/staging", "/cas",
            "/cas/sha3", "/pins",
        };
        bool missing = false;
        for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
            char path[STORE_PATH_MAX];
            int n = snprintf(path, sizeof(path), "%s%s", store->root,
                             required[i]);
            if (n <= 0 || (size_t)n >= sizeof(path))
                LOG_FAIL(STORE_LOG, "required store path too long");
            if (!store_directory_exists(path)) missing = true;
        }
        if (missing) {
            /* A crash during first layout creation may leave only empty
             * directories. Complete that layout, but never synthesize an
             * empty manifest view while any store evidence still exists. */
            static const char *const evidence[] = {
                "/manifests", "/staging", "/cas/sha3", "/pins",
                "/releases", "/recipes", "/attestations", "/badges",
            };
            for (size_t i = 0;
                 i < sizeof(evidence) / sizeof(evidence[0]); i++) {
                char path[STORE_PATH_MAX];
                int n = snprintf(path, sizeof(path), "%s%s", store->root,
                                 evidence[i]);
                if (n <= 0 || (size_t)n >= sizeof(path))
                    LOG_FAIL(STORE_LOG, "evidence path too long");
                if (store_directory_exists(path) &&
                    !store_directory_empty(path))
                    LOG_FAIL(STORE_LOG,
                             "existing store missing layout with evidence %s",
                             evidence[i]);
            }
        }
    }
    return true;
}

bool store_open_recover(struct vcs_package_store *store)
{
    if (!store_existing_layout_safe(store))
        LOG_FAIL(STORE_LOG, "existing store layout is incomplete");
    static const char *const k_dirs[] = {
        "", "/manifests", "/releases", "/recipes", "/attestations",
        "/badges", "/cas", "/cas/sha3", "/staging", "/pins",
    };
    for (size_t i = 0; i < sizeof(k_dirs) / sizeof(k_dirs[0]); i++) {
        char path[STORE_PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s%s", store->root,
                         k_dirs[i]);
        if (n <= 0 || (size_t)n >= sizeof(path) || !store_mkdir_p(path))
            LOG_FAIL(STORE_LOG, "layout mkdir %s%s", store->root,
                     k_dirs[i]);
    }
    store_sweep_temps(store, store->root);
    if (!store_load_manifests(store))
        LOG_FAIL(STORE_LOG, "load manifests under %s", store->root);
    /* A committed manifest is authority for its chunks. If even one cannot
     * be read and root-checked, no orphan decision is justified. Opening a
     * partial store would also let later quota eviction delete those chunks. */
    if (store->catalog_incomplete)
        LOG_FAIL(STORE_LOG, "committed manifest history incomplete under %s",
                 store->root);
    struct vcs_package_accept *replayed = store_replay_releases(
        store->root, &store->releases_quarantined_total);
    if (!replayed)
        LOG_FAIL(STORE_LOG, "release history recovery under %s", store->root);
    if (!store_gc_cas(store) || !store_commit_sweep(store)) {
        vcs_package_accept_free(replayed);
        LOG_FAIL(STORE_LOG, "CAS recovery under %s", store->root);
    }
    vcs_package_accept_free(store->accept);
    store->accept = replayed;
    return true;
}
