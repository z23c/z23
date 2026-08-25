/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the zcl.fastobj.v1 object-set carrier (vcs/fastobj_carrier.h). */

#define _POSIX_C_SOURCE 200809L

#include "vcs/fastobj_carrier.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"
#include "vcs/fastobj.h"
#include "vcs/package_content.h"
#include "vcs/package_manifest.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* An object near the whole-package cap is not a translation unit. */
#define FASTOBJ_CARRIER_MAX_OBJECT_BYTES VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES

static const char carrier_dir[] = VCS_FASTOBJ_CARRIER_DIR "/";

/* ── small local io helpers (the lib/vcs revert convention) ─────────── */

static bool fc_read_file(const char *path, size_t cap, uint8_t **out,
                         size_t *out_len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (uint64_t)st.st_size > (uint64_t)cap) {
        close(fd);
        return false;
    }
    size_t len = (size_t)st.st_size;
    uint8_t *buf = zcl_malloc(len ? len : 1u, "fastobj-carrier-read");
    if (!buf) {
        close(fd);
        return false;
    }
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) {
            free(buf);
            close(fd);
            return false;
        }
        got += (size_t)n;
    }
    close(fd);
    *out = buf;
    *out_len = len;
    return true;
}

/* Write bytes to a temp beside dst, fsync, then atomically rename — the
 * same discipline as the worker's cache store and the store's commits. */
static bool fc_atomic_write(const char *dst, const uint8_t *bytes,
                            size_t len, mode_t mode)
{
    char tmp[4096];
    int tn = snprintf(tmp, sizeof(tmp), "%s.zfctmp.%ld", dst,
                      (long)getpid());
    if (tn <= 0 || (size_t)tn >= sizeof(tmp))
        return false;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0)
        return false;
    size_t put = 0;
    bool ok = true;
    while (put < len) {
        ssize_t n = write(fd, bytes + put, len - put);
        if (n <= 0) {
            ok = false;
            break;
        }
        put += (size_t)n;
    }
    if (ok && fsync(fd) != 0)
        ok = false;
    if (close(fd) != 0)
        ok = false;
    if (ok && rename(tmp, dst) != 0)
        ok = false;
    if (!ok)
        (void)unlink(tmp);
    return ok;
}

static bool fc_mkdir_p(const char *path)
{
    char buf[4096];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf))
        return false;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST) {
            *p = '/';
            return false;
        }
        *p = '/';
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

static bool fc_is_lower_hex(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

/* ── entry scanning ─────────────────────────────────────────────────── */

/* One cache entry: the full 64-hex key (shard dir + basename) and which
 * pair members were seen (bit 1 = object, bit 2 = sidecar) so a torn
 * pair refuses. */
struct fc_entry {
    char key[65];
    uint8_t members;
};

static int fc_entry_cmp(const void *a, const void *b)
{
    return strcmp(((const struct fc_entry *)a)->key,
                  ((const struct fc_entry *)b)->key);
}

/* Collect the sorted entry keys of a fastobj cache. A pair member with
 * no twin is a torn entry and refuses. */
static bool fc_scan_cache(const char *cache_dir, struct fc_entry **entries,
                          size_t *count, char *err, size_t err_cap)
{
    char objects[4096];
    int on = snprintf(objects, sizeof(objects), "%s/objects", cache_dir);
    if (on <= 0 || (size_t)on >= sizeof(objects)) {
        (void)snprintf(err, err_cap, "cache path overflow");
        return false;
    }
    DIR *shards = opendir(objects);
    if (!shards) {
        (void)snprintf(err, err_cap, "no objects/ under %s", cache_dir);
        return false;
    }
    struct fc_entry *list = NULL;
    size_t n = 0, cap = 0;
    bool ok = true;
    struct dirent *sh;
    while (ok && (sh = readdir(shards)) != NULL) {
        /* The shard directory name IS the key's first two hex chars. */
        if (strlen(sh->d_name) != 2 || !fc_is_lower_hex(sh->d_name, 2))
            continue;
        char shard[4096];
        int sn = snprintf(shard, sizeof(shard), "%s/%s", objects,
                          sh->d_name);
        if (sn <= 0 || (size_t)sn >= sizeof(shard))
            continue;
        struct stat sst;
        if (stat(shard, &sst) != 0 || !S_ISDIR(sst.st_mode))
            continue;
        DIR *d = opendir(shard);
        if (!d)
            continue;
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            size_t namelen = strlen(e->d_name);
            /* A member is <62 hex>.o or <62 hex>.json; anything else is
             * not a cache entry and is ignored. */
            bool is_obj = namelen == 64 && strcmp(e->d_name + 62, ".o") == 0;
            bool is_side = namelen == 67 &&
                           strcmp(e->d_name + 62, ".json") == 0;
            if ((!is_obj && !is_side) || !fc_is_lower_hex(e->d_name, 62))
                continue;
            char key[65];
            key[0] = sh->d_name[0];
            key[1] = sh->d_name[1];
            memcpy(key + 2, e->d_name, 62);
            key[64] = '\0';
            uint8_t member = is_obj ? 1u : 2u;
            bool found = false;
            for (size_t i = 0; i < n; i++) {
                if (strcmp(list[i].key, key) == 0) {
                    list[i].members |= member;
                    found = true;
                    break;
                }
            }
            if (!found) {
                if (n == cap) {
                    size_t want = cap ? cap * 2u : 64u;
                    struct fc_entry *grown = zcl_realloc(list,
                        want * sizeof(*list), "fastobj-carrier-scan");
                    if (!grown) {
                        (void)snprintf(err, err_cap, "entry scan alloc");
                        ok = false;
                        break;
                    }
                    list = grown;
                    cap = want;
                }
                memcpy(list[n].key, key, 65);
                list[n].members = member;
                n++;
            }
        }
        closedir(d);
    }
    closedir(shards);
    if (ok) {
        for (size_t i = 0; i < n; i++) {
            if (list[i].members != 3u) {
                (void)snprintf(err, err_cap,
                               "torn cache entry %.64s (%s missing)",
                               list[i].key,
                               (list[i].members & 1u) ? "sidecar"
                                                      : "object");
                ok = false;
            }
        }
    }
    if (ok && n > VCS_FASTOBJ_CARRIER_MAX_ENTRIES) {
        (void)snprintf(err, err_cap,
                       "cache holds %zu entries (cap %u)", n,
                       VCS_FASTOBJ_CARRIER_MAX_ENTRIES);
        ok = false;
    }
    if (!ok) {
        free(list);
        return false;
    }
    qsort(list, n, sizeof(*list), fc_entry_cmp);
    *entries = list;
    *count = n;
    return true;
}

/* Stream one object file: compute every 1 MiB chunk hash (canonical
 * content.v2 chunk identity) and the whole-file SHA3-256 in one pass,
 * without holding the object in memory. Exactly `size` bytes must be
 * consumed across exactly chunk_count chunks. */
static bool fc_hash_object_stream(const char *path, uint64_t size,
                                  uint8_t *chunk_hashes_out,
                                  uint32_t chunk_count,
                                  uint8_t file_sha3_out[32])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    uint8_t *buf = zcl_malloc(VCS_PACKAGE_CHUNK_BYTES, "fastobj-carrier-chunk");
    if (!buf) {
        close(fd);
        return false;
    }
    struct sha3_256_ctx whole;
    sha3_256_init(&whole);
    uint32_t hashed_chunks = 0;
    uint64_t hashed_bytes = 0;
    bool ok = true;
    while (ok && hashed_bytes < size) {
        size_t want = VCS_PACKAGE_CHUNK_BYTES;
        if ((uint64_t)want > size - hashed_bytes)
            want = (size_t)(size - hashed_bytes);
        size_t got = 0;
        while (got < want) {
            ssize_t n = read(fd, buf + got, want - got);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                ok = false;
                break;
            }
            if (n == 0)
                break;
            got += (size_t)n;
        }
        if (!ok || got == 0) {
            if (ok)
                ok = false; /* short file: fewer bytes than stat claimed */
            break;
        }
        if (!vcs_package_chunk_hash(buf, got, chunk_hashes_out +
                                             (size_t)hashed_chunks * 32u)) {
            ok = false;
            break;
        }
        sha3_256_write(&whole, buf, got);
        hashed_bytes += got;
        hashed_chunks++;
    }
    if (ok && (hashed_chunks != chunk_count || hashed_bytes != size))
        ok = false;
    free(buf);
    close(fd);
    if (ok)
        sha3_256_finalize(&whole, file_sha3_out);
    return ok;
}

/* Verify one cache entry pair: sidecar schema + key-at-filename + object
 * hash. Only the sidecar is held in memory; the object is streamed. */
static bool fc_verify_entry(const char *cache_dir, const char *key,
                            uint8_t **side_out, size_t *side_len,
                            uint64_t *object_len_out,
                            uint8_t *chunk_hashes, uint32_t chunk_count,
                            uint8_t object_sha3_out[32],
                            char *err, size_t err_cap)
{
    char obj_path[4096], side_path[4096];
    if (!vcs_fastobj_cache_paths(cache_dir, key, obj_path,
                                 sizeof(obj_path), side_path,
                                 sizeof(side_path))) {
        (void)snprintf(err, err_cap, "entry %.16s...: path overflow", key);
        return false;
    }
    struct stat st;
    if (stat(obj_path, &st) != 0 || !S_ISREG(st.st_mode) ||
        (uint64_t)st.st_size > FASTOBJ_CARRIER_MAX_OBJECT_BYTES) {
        (void)snprintf(err, err_cap,
                       "entry %.16s...: object unreadable or over cap",
                       key);
        return false;
    }
    if (!fc_read_file(side_path, VCS_FASTOBJ_SIDECAR_MAX_BYTES, side_out,
                      side_len)) {
        (void)snprintf(err, err_cap, "entry %.16s...: sidecar unreadable",
                       key);
        return false;
    }
    uint8_t expect[32];
    if (!vcs_fastobj_sidecar_verify(*side_out, *side_len, key, expect, err,
                                    err_cap)) {
        free(*side_out);
        *side_out = NULL;
        return false;
    }
    uint64_t size = (uint64_t)st.st_size;
    if (!fc_hash_object_stream(obj_path, size, chunk_hashes, chunk_count,
                               object_sha3_out)) {
        free(*side_out);
        *side_out = NULL;
        (void)snprintf(err, err_cap,
                       "entry %.16s...: object read failed", key);
        return false;
    }
    if (memcmp(object_sha3_out, expect, 32) != 0) {
        free(*side_out);
        *side_out = NULL;
        (void)snprintf(err, err_cap,
                       "entry %.16s...: object does not hash to its "
                       "sidecar object_sha3", key);
        return false;
    }
    *object_len_out = size;
    memcpy(object_sha3_out, expect, 32);
    return true;
}

static void fc_fill_stats(const struct vcs_package_manifest *manifest,
                          uint32_t entries, uint64_t object_bytes,
                          struct vcs_fastobj_carrier_stats *stats)
{
    if (!stats)
        return;
    memset(stats, 0, sizeof(*stats));
    stats->entries = entries;
    stats->object_bytes = object_bytes;
    stats->files = (uint32_t)manifest->count;
    for (size_t i = 0; i < manifest->count; i++) {
        stats->total_bytes += manifest->files[i].size;
        stats->chunks += manifest->files[i].chunk_count;
    }
}

static const char *fc_store_err(enum vcs_package_store_result r)
{
    return vcs_package_store_result_string(r);
}

/* ── export ─────────────────────────────────────────────────────────── */

bool vcs_fastobj_carrier_export(const char *cache_dir,
                                struct vcs_package_store *store,
                                uint8_t root_out[32],
                                struct vcs_fastobj_carrier_stats *stats,
                                char *err, size_t err_cap)
{
    if (!cache_dir || !store || !root_out) {
        (void)snprintf(err, err_cap, "null argument");
        return false;
    }
    struct fc_entry *entries = NULL;
    size_t count = 0;
    if (!fc_scan_cache(cache_dir, &entries, &count, err, err_cap))
        return false;

    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    /* Sidecars stay in memory (capped small); objects are streamed, so
     * only their chunk-hash lists are retained. */
    uint8_t **sides = NULL;
    size_t *side_lens = NULL;
    uint8_t *chunk_hashes = NULL;
    bool ok = count > 0;
    if (!ok)
        (void)snprintf(err, err_cap,
                       "cache %s holds no entries", cache_dir);
    if (ok) {
        sides = zcl_calloc(count, sizeof(*sides), "fastobj-admit-sides");
        side_lens = zcl_calloc(count, sizeof(*side_lens), "fastobj-admit-lens");
        chunk_hashes = zcl_malloc((size_t)(FASTOBJ_CARRIER_MAX_OBJECT_BYTES /
                                       VCS_PACKAGE_CHUNK_BYTES + 1u) *
                              32u, "fastobj-admit-chunks");
        if (!sides || !side_lens || !chunk_hashes) {
            (void)snprintf(err, err_cap, "entry alloc failed");
            ok = false;
        }
    }
    uint64_t object_bytes = 0;
    for (size_t i = 0; ok && i < count; i++) {
        struct stat st;
        char obj_path[4096], side_path[4096];
        char key_arg[65];
        memcpy(key_arg, entries[i].key, 65);
        if (!vcs_fastobj_cache_paths(cache_dir, key_arg, obj_path,
                                     sizeof(obj_path), side_path,
                                     sizeof(side_path)) ||
            stat(obj_path, &st) != 0) {
            (void)snprintf(err, err_cap, "entry %.16s...: object vanished",
                           key_arg);
            ok = false;
            break;
        }
        uint32_t chunks = st.st_size == 0
            ? 0u
            : (uint32_t)(((uint64_t)st.st_size +
                          VCS_PACKAGE_CHUNK_BYTES - 1u) /
                         VCS_PACKAGE_CHUNK_BYTES);
        uint64_t obj_len = 0;
        uint8_t obj_sha[32];
        if (!fc_verify_entry(cache_dir, key_arg, &sides[i], &side_lens[i],
                             &obj_len, chunk_hashes, chunks, obj_sha, err,
                             err_cap)) {
            ok = false;
            break;
        }
        object_bytes += obj_len;
        char obj_cpath[4096], side_cpath[4096];
        int on = snprintf(obj_cpath, sizeof(obj_cpath), "%s%s.o",
                          carrier_dir, key_arg);
        int sn = snprintf(side_cpath, sizeof(side_cpath), "%s%s.json",
                          carrier_dir, key_arg);
        if (on <= 0 || (size_t)on >= sizeof(obj_cpath) || sn <= 0 ||
            (size_t)sn >= sizeof(side_cpath) ||
            !vcs_package_path_valid(obj_cpath) ||
            !vcs_package_path_valid(side_cpath) ||
            !vcs_package_manifest_add(&manifest, obj_cpath,
                                      VCS_PACKAGE_MODE_FILE, obj_len,
                                      chunk_hashes, chunks) ||
            !vcs_package_content_add_file(&manifest, side_cpath,
                                          VCS_PACKAGE_MODE_FILE, sides[i],
                                          side_lens[i])) {
            (void)snprintf(err, err_cap,
                           "entry %.16s...: manifest add failed", key_arg);
            ok = false;
            break;
        }
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t root[32] = {0};
    if (ok && (!vcs_package_manifest_serialize(&manifest, &wire,
                                               &wire_len) ||
               !vcs_package_manifest_root(&manifest, root))) {
        (void)snprintf(err, err_cap, "carrier manifest serialize failed");
        ok = false;
    }
    uint8_t stored_root[32] = {0};
    if (ok) {
        enum vcs_package_store_result r = vcs_package_store_put_manifest(
            store, wire, wire_len, stored_root);
        if (r != VCS_PACKAGE_STORE_OK) {
            (void)snprintf(err, err_cap, "store refused the carrier "
                         "manifest: %s", fc_store_err(r));
            ok = false;
        } else if (memcmp(stored_root, root, 32) != 0) {
            (void)snprintf(err, err_cap,
                           "store computed a different carrier root");
            ok = false;
        }
    }
    /* Stream each object's chunks in from disk again at put time; the
     * sidecar is small enough to admit whole. */
    for (size_t i = 0; ok && i < count; i++) {
        char obj_cpath[4096], side_cpath[4096], obj_path[4096],
             side_path[4096];
        (void)snprintf(obj_cpath, sizeof(obj_cpath), "%s%s.o", carrier_dir,
                       entries[i].key);
        (void)snprintf(side_cpath, sizeof(side_cpath), "%s%s.json",
                       carrier_dir, entries[i].key);
        (void)vcs_fastobj_cache_paths(cache_dir, entries[i].key, obj_path,
                                      sizeof(obj_path), side_path,
                                      sizeof(side_path));
        struct stat st;
        if (stat(obj_path, &st) != 0) {
            (void)snprintf(err, err_cap, "entry %.16s...: object vanished",
                           entries[i].key);
            ok = false;
            break;
        }
        uint32_t chunks = st.st_size == 0
            ? 0u
            : (uint32_t)(((uint64_t)st.st_size +
                          VCS_PACKAGE_CHUNK_BYTES - 1u) /
                         VCS_PACKAGE_CHUNK_BYTES);
        int fd = open(obj_path, O_RDONLY | O_CLOEXEC);
        uint8_t *buf = fd >= 0 ? zcl_malloc(VCS_PACKAGE_CHUNK_BYTES,
                                             "fastobj-admit-obj") : NULL;
        if (fd < 0 || !buf) {
            (void)snprintf(err, err_cap, "entry %.16s...: object reopen "
                         "failed", entries[i].key);
            if (fd >= 0)
                close(fd);
            free(buf);
            ok = false;
            break;
        }
        for (uint32_t c = 0; ok && c < chunks; c++) {
            size_t want = VCS_PACKAGE_CHUNK_BYTES, got = 0;
            while (got < want) {
                ssize_t n = read(fd, buf + got, want - got);
                if (n < 0) {
                    if (errno == EINTR)
                        continue;
                    break;
                }
                if (n == 0)
                    break;
                got += (size_t)n;
            }
            enum vcs_package_store_result wr = vcs_package_store_put_chunk(
                store, root, obj_cpath, c, buf, got);
            if (wr != VCS_PACKAGE_STORE_OK) {
                (void)snprintf(err, err_cap,
                               "store refused object chunk %s[%u]: %s",
                               obj_cpath, c, fc_store_err(wr));
                ok = false;
            }
        }
        close(fd);
        free(buf);
        if (ok) {
            enum vcs_package_store_result wr =
                vcs_package_content_put_file(store, root, side_cpath,
                                             sides[i], side_lens[i]);
            if (wr != VCS_PACKAGE_STORE_OK) {
                (void)snprintf(err, err_cap,
                               "store refused sidecar %s: %s", side_cpath,
                               fc_store_err(wr));
                ok = false;
            }
        }
    }
    if (ok) {
        struct vcs_package_store_status status;
        /* bool return, not a store result code. */
        if (!vcs_package_store_package_status(store, root, &status) ||
            !status.complete) {
            (void)snprintf(err, err_cap, "carrier incomplete in store");
            ok = false;
        }
    }
    if (ok) {
        memcpy(root_out, root, 32);
        fc_fill_stats(&manifest, (uint32_t)count, object_bytes, stats);
    }
    free(wire);
    if (sides) {
        for (size_t i = 0; i < count; i++)
            free(sides[i]);
        free(sides);
    }
    free(side_lens);
    free(chunk_hashes);
    vcs_package_manifest_free(&manifest);
    free(entries);
    return ok;
}

/* ── fetch (offline wire leg) ───────────────────────────────────────── */

bool vcs_fastobj_carrier_fetch(struct vcs_package_store *dst,
                               struct vcs_package_store *src,
                               const uint8_t root[32],
                               struct vcs_fastobj_carrier_stats *stats,
                               char *err, size_t err_cap)
{
    if (!dst || !src || !root) {
        (void)snprintf(err, err_cap, "null argument");
        return false;
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    enum vcs_package_store_result r = vcs_package_store_get_manifest_wire(
        src, root, &wire, &wire_len);
    if (r != VCS_PACKAGE_STORE_OK) {
        (void)snprintf(err, err_cap, "source store: %s", fc_store_err(r));
        return false;
    }
    struct vcs_package_manifest manifest;
    if (!vcs_package_manifest_parse(wire, wire_len, &manifest)) {
        free(wire);
        (void)snprintf(err, err_cap, "source manifest does not parse");
        return false;
    }
    uint8_t derived[32];
    bool ok = vcs_package_manifest_root(&manifest, derived) &&
              memcmp(derived, root, 32) == 0;
    if (!ok) {
        (void)snprintf(err, err_cap,
                       "source manifest does not root to the given root");
    }
    uint8_t dst_root[32] = {0};
    if (ok) {
        enum vcs_package_store_result pr = vcs_package_store_put_manifest(
            dst, wire, wire_len, dst_root);
        if (pr != VCS_PACKAGE_STORE_OK) {
            (void)snprintf(err, err_cap, "destination store: %s",
                           fc_store_err(pr));
            ok = false;
        }
    }
    for (size_t i = 0; ok && i < manifest.count; i++) {
        const struct vcs_package_file *f = &manifest.files[i];
        for (uint32_t c = 0; c < f->chunk_count; c++) {
            if (vcs_package_store_chunk_present(dst, root, (uint32_t)i, c))
                continue;
            uint8_t *chunk = NULL;
            size_t chunk_len = 0;
            enum vcs_package_store_result gr =
                vcs_package_store_get_chunk_at(src, root, (uint32_t)i, c,
                                               &chunk, &chunk_len);
            if (gr != VCS_PACKAGE_STORE_OK) {
                (void)snprintf(err, err_cap, "chunk read %s[%u]: %s",
                               f->path, c, fc_store_err(gr));
                ok = false;
                break;
            }
            enum vcs_package_store_result wr = vcs_package_store_put_chunk(
                dst, root, f->path, c, chunk, chunk_len);
            free(chunk);
            if (wr != VCS_PACKAGE_STORE_OK) {
                (void)snprintf(err, err_cap, "chunk store %s[%u]: %s",
                               f->path, c, fc_store_err(wr));
                ok = false;
                break;
            }
        }
    }
    if (ok) {
        struct vcs_package_store_status status;
        /* bool return, not a store result code. */
        if (!vcs_package_store_package_status(dst, root, &status) ||
            !status.complete) {
            (void)snprintf(err, err_cap,
                           "carrier incomplete in destination store");
            ok = false;
        }
    }
    if (ok) {
        uint32_t entries = 0;
        uint64_t object_bytes = 0;
        for (size_t i = 0; i < manifest.count; i++) {
            const char *name = strrchr(manifest.files[i].path, '/');
            if (!name)
                continue;
            name++;
            size_t namelen = strlen(name);
            if (namelen == 66 && strcmp(name + 64, ".o") == 0) {
                entries++;
                object_bytes += manifest.files[i].size;
            }
        }
        fc_fill_stats(&manifest, entries, object_bytes, stats);
    }
    vcs_package_manifest_free(&manifest);
    free(wire);
    return ok;
}

/* ── verify / admit ─────────────────────────────────────────────────── */

/* Validate one carrier member path: exactly <prefix>/<64 hex><ext> with
 * the extension copied into ext_out. */
static bool fc_carrier_member(const char *path, const char *ext,
                              char key_out[65])
{
    size_t plen = strlen(path);
    size_t extlen = strlen(ext);
    if (plen != sizeof(carrier_dir) - 1u + 64u + extlen)
        return false;
    if (strncmp(path, carrier_dir, sizeof(carrier_dir) - 1u) != 0)
        return false;
    if (strcmp(path + plen - extlen, ext) != 0)
        return false;
    memcpy(key_out, path + sizeof(carrier_dir) - 1u, 64u);
    key_out[64] = '\0';
    return fc_is_lower_hex(key_out, 64u);
}

/* Walk one carrier root in the store, verifying every entry pair; when
 * `cache_dir` is non-NULL each verified pair also lands in the receiving
 * cache (admit). A NULL cache_dir is the read-only walk behind
 * vcs_fastobj_carrier_verify(): it changes nothing, not even a directory,
 * so serve-time classification re-proves bytes this node already holds
 * without touching a cache. */
static bool fc_carrier_apply(const char *cache_dir,
                             struct vcs_package_store *store,
                             const uint8_t root[32],
                             struct vcs_fastobj_carrier_stats *stats,
                             char *err, size_t err_cap)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    enum vcs_package_store_result r = vcs_package_store_get_manifest_wire(
        store, root, &wire, &wire_len);
    if (r != VCS_PACKAGE_STORE_OK) {
        (void)snprintf(err, err_cap, "store: %s", fc_store_err(r));
        return false;
    }
    struct vcs_package_manifest manifest;
    if (!vcs_package_manifest_parse(wire, wire_len, &manifest)) {
        free(wire);
        (void)snprintf(err, err_cap, "carrier manifest does not parse");
        return false;
    }
    uint8_t derived[32];
    bool ok = vcs_package_manifest_root(&manifest, derived) &&
              memcmp(derived, root, 32) == 0;
    if (!ok)
        (void)snprintf(err, err_cap,
                       "carrier manifest does not root to the given root");

    /* Canonical path order keeps each key's .json ('j' = 0x6a) immediately
     * before its .o ('o' = 0x6f) — both extensions start with '.', so the
     * first differing byte is 'j' < 'o'. Members pair as adjacent files
     * (2i = sidecar, 2i+1 = object). */
    size_t n = manifest.count / 2u;
    if (ok && (manifest.count % 2u != 0u || n == 0 ||
               n > VCS_FASTOBJ_CARRIER_MAX_ENTRIES)) {
        (void)snprintf(err, err_cap,
                       "carrier holds %zu files — not entry pairs",
                       manifest.count);
        ok = false;
    }
    if (ok && cache_dir && !fc_mkdir_p(cache_dir)) {
        (void)snprintf(err, err_cap, "cannot create cache dir %s",
                       cache_dir);
        ok = false;
    }
    uint64_t object_bytes = 0;
    for (size_t i = 0; ok && i < n; i++) {
        const struct vcs_package_file *side_f = &manifest.files[2u * i];
        const struct vcs_package_file *obj_f = &manifest.files[2u * i + 1u];
        char key[65], side_key[65];
        if (!fc_carrier_member(side_f->path, ".json", side_key) ||
            !fc_carrier_member(obj_f->path, ".o", key) ||
            strcmp(key, side_key) != 0) {
            (void)snprintf(err, err_cap,
                           "carrier files %.60s / %.60s are not an entry "
                           "pair", side_f->path, obj_f->path);
            ok = false;
            break;
        }
        if (obj_f->size > FASTOBJ_CARRIER_MAX_OBJECT_BYTES ||
            side_f->size > VCS_FASTOBJ_SIDECAR_MAX_BYTES) {
            (void)snprintf(err, err_cap,
                           "carrier entry %.16s...: member over cap", key);
            ok = false;
            break;
        }
        uint8_t *obj = NULL, *side = NULL;
        size_t obj_len = 0, side_len = 0;
        enum vcs_package_store_result r1 = vcs_package_content_get_file_at(
            store, root, &manifest, (uint32_t)(2u * i + 1u), &obj, &obj_len);
        enum vcs_package_store_result r2 = vcs_package_content_get_file_at(
            store, root, &manifest, (uint32_t)(2u * i), &side, &side_len);
        if (r1 != VCS_PACKAGE_STORE_OK || r2 != VCS_PACKAGE_STORE_OK) {
            free(obj);
            free(side);
            (void)snprintf(err, err_cap, "entry %.16s...: %s", key,
                           fc_store_err(r1 != VCS_PACKAGE_STORE_OK ? r1
                                                                   : r2));
            ok = false;
            break;
        }
        uint8_t expect[32];
        bool entry_ok = vcs_fastobj_sidecar_verify(side, side_len, key,
                                                   expect, err, err_cap);
        if (entry_ok) {
            uint8_t actual[32];
            zcl_sha3_256(obj, obj_len, actual);
            if (memcmp(actual, expect, 32) != 0) {
                (void)snprintf(err, err_cap,
                               "entry %.16s...: object does not hash to "
                               "its sidecar object_sha3", key);
                entry_ok = false;
            }
        }
        if (entry_ok && cache_dir) {
            char obj_path[4096], side_path[4096];
            entry_ok = vcs_fastobj_cache_paths(cache_dir, key, obj_path,
                                               sizeof(obj_path), side_path,
                                               sizeof(side_path));
            struct stat st;
            bool have_obj = stat(obj_path, &st) == 0;
            bool have_side = stat(side_path, &st) == 0;
            if (entry_ok && (have_obj || have_side)) {
                /* Existing entry: byte-verify, never overwrite. */
                uint8_t *eobj = NULL, *eside = NULL;
                size_t eobj_len = 0, eside_len = 0;
                bool same = have_obj && have_side &&
                    fc_read_file(obj_path,
                                 FASTOBJ_CARRIER_MAX_OBJECT_BYTES, &eobj,
                                 &eobj_len) &&
                    fc_read_file(side_path, VCS_FASTOBJ_SIDECAR_MAX_BYTES,
                                 &eside, &eside_len) &&
                    eobj_len == obj_len && eside_len == side_len &&
                    memcmp(eobj, obj, obj_len) == 0 &&
                    memcmp(eside, side, side_len) == 0;
                free(eobj);
                free(eside);
                if (!same) {
                    (void)snprintf(err, err_cap,
                                   "cache CORRUPTION: existing entry "
                                   "%.16s... differs from the carrier",
                                   key);
                    entry_ok = false;
                }
            } else if (entry_ok) {
                char shard[4096];
                (void)snprintf(shard, sizeof(shard), "%s", obj_path);
                char *slash = strrchr(shard, '/');
                if (slash)
                    *slash = '\0';
                if (!fc_mkdir_p(shard)) {
                    (void)snprintf(err, err_cap,
                                   "cannot create cache shard for "
                                   "%.16s...", key);
                    entry_ok = false;
                } else if (!fc_atomic_write(obj_path, obj, obj_len,
                                            0444) ||
                           !fc_atomic_write(side_path, side, side_len,
                                            0600)) {
                    (void)snprintf(err, err_cap,
                                   "cannot store entry %.16s...", key);
                    entry_ok = false;
                }
            }
        }
        if (entry_ok)
            object_bytes += obj_len;
        free(obj);
        free(side);
        if (!entry_ok) {
            ok = false;
            break;
        }
    }
    if (ok)
        fc_fill_stats(&manifest, (uint32_t)n, object_bytes, stats);
    vcs_package_manifest_free(&manifest);
    free(wire);
    return ok;
}

bool vcs_fastobj_carrier_verify(struct vcs_package_store *store,
                                const uint8_t root[32],
                                char *err, size_t err_cap)
{
    if (!store || !root) {
        (void)snprintf(err, err_cap, "null argument");
        return false;
    }
    return fc_carrier_apply(NULL, store, root, NULL, err, err_cap);
}

bool vcs_fastobj_carrier_admit(const char *cache_dir,
                               struct vcs_package_store *store,
                               const uint8_t root[32],
                               struct vcs_fastobj_carrier_stats *stats,
                               char *err, size_t err_cap)
{
    if (!cache_dir || !store || !root) {
        (void)snprintf(err, err_cap, "null argument");
        return false;
    }
    return fc_carrier_apply(cache_dir, store, root, stats, err, err_cap);
}
