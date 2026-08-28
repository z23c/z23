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
#include "platform/positioned_file.h"

#include <stdatomic.h>
#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define STORE_LOG "vcs.store"

bool store_name_is_hex64(const char *name)
{
    uint8_t scratch[32];
    return zcl_hex_decode_lower(name, scratch, 32);
}

bool store_mkdir_p(const char *path)
{
#if defined(_WIN32)
    (void)path;
    return false;
#else
    char buf[STORE_PATH_MAX];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf))
        return false;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    if (mkdir(buf, 0700) != 0 && errno != EEXIST)
        return false;
    return true;
#endif
}

bool store_rm_rf(const char *path)
{
#if defined(_WIN32)
    (void)path;
    return false;
#else
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0;
    DIR *dir = opendir(path);
    if (!dir)
        return false;
    bool ok = true;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[STORE_PATH_MAX];
        int n = snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child)) {
            ok = false;
            continue;
        }
        if (!store_rm_rf(child))
            ok = false;
    }
    closedir(dir);
    if (rmdir(path) != 0)
        ok = false;
    return ok;
#endif
}

bool store_atomic_write(const char *path, const uint8_t *data,
                        size_t data_len)
{
#if defined(_WIN32)
    (void)path;
    (void)data;
    (void)data_len;
    return false;
#else
    static _Atomic uint64_t g_seq = 0;
    uint64_t seq = atomic_fetch_add(&g_seq, 1);
    char tmp[STORE_PATH_MAX];
    int tn = snprintf(tmp, sizeof(tmp), "%s%s.%ld.%llu", path,
                      STORE_TEMP_SUFFIX, (long)getpid(),
                      (unsigned long long)seq);
    if (tn <= 0 || (size_t)tn >= sizeof(tmp))
        LOG_FAIL(STORE_LOG, "temp path too long for %s", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        LOG_FAIL(STORE_LOG, "open temp %s: %s", tmp, strerror(errno));
    size_t off = 0;
    while (off < data_len) {
        ssize_t w = write(fd, data + off, data_len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            unlink(tmp);
            LOG_FAIL(STORE_LOG, "write temp %s: %s", tmp, strerror(errno));
        }
        off += (size_t)w;
    }
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp);
        LOG_FAIL(STORE_LOG, "fsync temp %s: %s", tmp, strerror(errno));
    }
    if (close(fd) != 0) {
        unlink(tmp);
        LOG_FAIL(STORE_LOG, "close temp %s: %s", tmp, strerror(errno));
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        LOG_FAIL(STORE_LOG, "rename %s -> %s: %s", tmp, path,
                 strerror(errno));
    }
    return true;
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

bool store_package_commit(struct vcs_package_store *store,
                          struct store_package *pkg)
{
#if defined(_WIN32)
    (void)store;
    (void)pkg;
    return false;
#else
    char staging_dir[STORE_PATH_MAX];
    char staged[STORE_PATH_MAX];
    char final[STORE_PATH_MAX];
    int dn = snprintf(staging_dir, sizeof(staging_dir), "%s/staging/%s",
                      store->root, pkg->root_hex);
    int sn = snprintf(staged, sizeof(staged), "%s/manifest", staging_dir);
    int fn = snprintf(final, sizeof(final), "%s/manifests/%s", store->root,
                      pkg->root_hex);
    if (dn <= 0 || (size_t)dn >= sizeof(staging_dir) || sn <= 0 ||
        (size_t)sn >= sizeof(staged) || fn <= 0 ||
        (size_t)fn >= sizeof(final))
        LOG_FAIL(STORE_LOG, "commit path too long for %s", pkg->root_hex);
    if (rename(staged, final) != 0)
        LOG_FAIL(STORE_LOG, "commit rename %s -> %s: %s", staged, final,
                 strerror(errno));
    if (!store_rm_rf(staging_dir))
        LOG_FAIL(STORE_LOG, "commit cleanup %s", staging_dir);
    pkg->committed = true;
    store_package_touch(store, pkg);
    return true;
#endif
}

/* ── open / recovery ──────────────────────────────────────────────── */

#if !defined(_WIN32)

static void store_sweep_temps(struct vcs_package_store *store,
                              const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[STORE_PATH_MAX];
        int n = snprintf(child, sizeof(child), "%s/%s", dir, ent->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child))
            continue;
        struct stat st;
        if (lstat(child, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            store_sweep_temps(store, child);
        } else if (strstr(ent->d_name, STORE_TEMP_SUFFIX ".") != NULL) {
            const char *owner_text = strstr(
                ent->d_name, STORE_TEMP_SUFFIX ".");
            long owner = 0;
            unsigned long long sequence = 0;
            int consumed = 0;
            bool owned_by_live_process = owner_text &&
                sscanf(owner_text + sizeof(STORE_TEMP_SUFFIX),
                       "%ld.%llu%n", &owner, &sequence, &consumed) == 2 &&
                owner > 0 &&
                owner_text[sizeof(STORE_TEMP_SUFFIX) + consumed] == '\0' &&
                (kill((pid_t)owner, 0) == 0 || errno == EPERM);
            (void)sequence;
            if (!owned_by_live_process && unlink(child) == 0)
                LOG_INFO(STORE_LOG, "swept leftover temp %s", child);
        }
    }
    closedir(d);
}

/* Read a whole file bounded by VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES. */
static uint8_t *store_read_file(const char *path, size_t *out_len)
{
    *out_len = 0;
    struct stat st;
    if (stat(path, &st) != 0)
        LOG_NULL(STORE_LOG, "stat %s: %s", path, strerror(errno));
    if (st.st_size <= 0 ||
        (uint64_t)st.st_size > VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES)
        LOG_NULL(STORE_LOG, "%s: bad size %lld", path,
                 (long long)st.st_size);
    size_t len = (size_t)st.st_size;
    uint8_t *buf = zcl_malloc(len, "store_read_file");
    if (!buf)
        LOG_NULL(STORE_LOG, "alloc %zu for %s", len, path);
    FILE *f = fopen(path, "rb");
    if (!f) {
        free(buf);
        LOG_NULL(STORE_LOG, "open %s: %s", path, strerror(errno));
    }
    if (fread(buf, 1, len, f) != len) {
        fclose(f);
        free(buf);
        LOG_NULL(STORE_LOG, "read %s", path);
    }
    fclose(f);
    *out_len = len;
    return buf;
}

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

static int store_pkg_root_cmp(const void *a, const void *b)
{
    const struct store_package *pa = a;
    const struct store_package *pb = b;
    return memcmp(pa->root, pb->root, 32);
}

uint32_t store_releases_count(const struct vcs_package_store *store)
{
    char dir[STORE_PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s/releases", store->root);
    if (n < 0 || (size_t)n >= sizeof(dir))
        return 0;
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    uint32_t count = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL)
        if (store_name_is_hex64(de->d_name))
            count++;
    closedir(d);
    return count;
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
    pkg.committed = committed;
    /* New packages start RARE: no observed demand or replication yet
     * (the enum's zero value is HOT, so this must be explicit). */
    pkg.class_ = VCS_PACKAGE_STORE_CLASS_RARE;
    store_package_touch(store, &pkg);
    {
        char pin[STORE_PATH_MAX];
        snprintf(pin, sizeof(pin), "%s/pins/%s", store->root,
                 pkg.root_hex);
        pkg.pinned = access(pin, F_OK) == 0;
    }
    if (store->pkg_count == store->pkg_cap) {
        size_t cap = store->pkg_cap ? store->pkg_cap * 2 : 32;
        struct store_package *pkgs = zcl_realloc(
            store->pkgs, cap * sizeof(*pkgs), "store_pkgs");
        if (!pkgs) {
            free(pkg.manifest_wire);
            free(pkg.chunks);
            vcs_package_manifest_free(&pkg.manifest);
            LOG_NULL(STORE_LOG, "grow package table");
        }
        store->pkgs = pkgs;
        store->pkg_cap = cap;
    }
    store->pkgs[store->pkg_count] = pkg;
    return &store->pkgs[store->pkg_count++];
}

/* Load every committed manifest (manifests/<hex>) and staged manifest
 * (staging/<hex>/manifest). A staged entry that fails to load is
 * discarded (documented choice); a committed one is logged and skipped. */
static bool store_load_manifests(struct vcs_package_store *store)
{
    char dir[STORE_PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/manifests", store->root);
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (!store_name_is_hex64(ent->d_name))
                continue;
            char path[STORE_PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
            size_t wire_len = 0;
            uint8_t *wire = store_read_file(path, &wire_len);
            if (!wire)
                continue;
            store_record_add(store, wire, wire_len, ent->d_name, true);
            free(wire);
        }
        closedir(d);
    }
    snprintf(dir, sizeof(dir), "%s/staging", store->root);
    d = opendir(dir);
    if (!d)
        return true;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!store_name_is_hex64(ent->d_name))
            continue;
        char sdir[STORE_PATH_MAX];
        char path[STORE_PATH_MAX];
        snprintf(sdir, sizeof(sdir), "%s/%s", dir, ent->d_name);
        snprintf(path, sizeof(path), "%s/manifest", sdir);
        size_t wire_len = 0;
        uint8_t *wire = store_read_file(path, &wire_len);
        bool loaded = false;
        if (wire) {
            loaded = store_record_add(store, wire, wire_len, ent->d_name,
                                      false) != NULL;
            free(wire);
        }
        if (!loaded) {
            LOG_ERROR(STORE_LOG,
                      "discarding unrecoverable staging entry %s", sdir);
            if (!store_rm_rf(sdir))
                LOG_FAIL(STORE_LOG, "discard staging %s", sdir);
        }
    }
    closedir(d);
    return true;
}

/* Delete CAS objects no loaded manifest references; build the CAS set. */
static bool store_gc_cas(struct vcs_package_store *store)
{
    /* Global referenced set: concat every record's unique hashes. */
    size_t ref_cap = 0;
    for (size_t i = 0; i < store->pkg_count; i++)
        ref_cap += store->pkgs[i].chunk_count;
    uint8_t(*refs)[32] = NULL;
    if (ref_cap > 0) {
        refs = zcl_malloc(ref_cap * sizeof(*refs), "store_gc_refs");
        if (!refs)
            LOG_FAIL(STORE_LOG, "alloc %zu GC refs", ref_cap);
    }
    size_t ref_count = 0;
    for (size_t i = 0; i < store->pkg_count; i++)
        for (size_t c = 0; c < store->pkgs[i].chunk_count; c++)
            memcpy(refs[ref_count++], store->pkgs[i].chunks[c].hash, 32);
    if (ref_count > 0)
        qsort(refs, ref_count, sizeof(*refs), store_hash_cmp);

    char cas_dir[STORE_PATH_MAX];
    snprintf(cas_dir, sizeof(cas_dir), "%s/cas/sha3", store->root);
    DIR *d = opendir(cas_dir);
    if (!d) {
        free(refs);
        return true;
    }
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strlen(ent->d_name) != 2)
            continue;
        char sub[STORE_PATH_MAX];
        snprintf(sub, sizeof(sub), "%s/%s", cas_dir, ent->d_name);
        DIR *sd = opendir(sub);
        if (!sd)
            continue;
        struct dirent *sent;
        while ((sent = readdir(sd)) != NULL) {
            uint8_t hash[32];
            if (!zcl_hex_decode_lower(sent->d_name, hash, 32))
                continue;
            char hex3[3] = { ent->d_name[0], ent->d_name[1], '\0' };
            if (strncmp(sent->d_name, hex3, 2) != 0)
                continue;
            char path[STORE_PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", sub, sent->d_name);
            bool referenced = ref_count > 0 &&
                bsearch(hash, refs, ref_count, sizeof(*refs),
                        store_hash_cmp) != NULL;
            if (!referenced) {
                if (unlink(path) == 0)
                    store->gc_orphans_total++;
                continue;
            }
            if (!store_cas_insert(store, hash))
                LOG_FAIL(STORE_LOG, "CAS set insert during GC");
        }
        closedir(sd);
        rmdir(sub); /* no-op unless empty */
    }
    closedir(d);
    free(refs);
    return true;
}

/* Commit every CAS-complete staged package, ascending root hex. */
static bool store_commit_sweep(struct vcs_package_store *store)
{
    /* pkgs stays NULL until the first staged package, and qsort declares
     * its base argument non-null even for a zero count. */
    if (store->pkg_count > 1)
        qsort(store->pkgs, store->pkg_count, sizeof(*store->pkgs),
              store_pkg_root_cmp);
    for (size_t i = 0; i < store->pkg_count; i++) {
        struct store_package *pkg = &store->pkgs[i];
        if (!pkg->committed && store_package_complete(store, pkg) &&
            !store_package_commit(store, pkg))
            LOG_FAIL(STORE_LOG, "commit sweep %s", pkg->root_hex);
    }
    return true;
}

bool store_open_recover(struct vcs_package_store *store)
{
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
    if (!store_gc_cas(store))
        LOG_FAIL(STORE_LOG, "CAS GC under %s", store->root);
    if (!store_commit_sweep(store))
        LOG_FAIL(STORE_LOG, "commit sweep under %s", store->root);
    return true;
}
#else
bool store_open_recover(struct vcs_package_store *store)
{
    (void)store;
    return false;
}
#endif
