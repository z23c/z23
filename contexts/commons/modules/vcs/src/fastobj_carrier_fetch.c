/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the zcl.fastobj.v1 carrier's offline wire leg
 * (vcs/fastobj_carrier.h), split out of fastobj_carrier.c. Unlike
 * export/verify/admit, fetch touches no local fastobj cache directory at
 * all: it moves an already-built carrier package from one open
 * vcs_package_store to another through the ordinary public store paths —
 * every chunk read from the source is re-hashed by the store, every
 * chunk written to the destination is verified against the
 * root-committed manifest before it lands. This is the same admission
 * shape the package swarm uses; a live swarm fetch just replaces the
 * source reads with network reads, nothing else. */

#if defined(_WIN32)

/* The whole carrier is disabled on native Windows (see the
 * fastobj_carrier_windows_refused() stub in fastobj_carrier.c, which
 * already defines vcs_fastobj_carrier_fetch() for this platform); this
 * translation unit has nothing to add there. ISO C forbids an empty
 * translation unit under -Wpedantic -Werror. */
typedef int fastobj_carrier_fetch_win32_no_op_placeholder;

#else

#include "vcs/fastobj_carrier.h"
#include "vcs/package_manifest.h"
#include "vcs/package_store.h"

#include "fastobj_carrier_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A CAS index entry is only a hint; the verified read also quarantines
 * missing or corrupt bytes so ordinary admission can repair them. */
static bool fc_fetch_chunk(struct vcs_package_store *dst,
                           struct vcs_package_store *src,
                           const uint8_t root[32], uint32_t file_index,
                           const char *path, uint32_t chunk_index,
                           char *err, size_t err_cap)
{
    uint8_t *chunk = NULL;
    size_t chunk_len = 0;
    enum vcs_package_store_result r = vcs_package_store_get_chunk_at(
        dst, root, file_index, chunk_index, &chunk, &chunk_len);
    free(chunk);
    if (r == VCS_PACKAGE_STORE_OK)
        return true;
    if (r != VCS_PACKAGE_STORE_ERR_CHUNK_MISSING &&
        r != VCS_PACKAGE_STORE_ERR_CHUNK_HASH) {
        (void)snprintf(err, err_cap, "destination chunk read %s[%u]: %s",
                       path, chunk_index, fc_store_err(r));
        return false;
    }
    chunk = NULL;
    r = vcs_package_store_get_chunk_at(src, root, file_index, chunk_index,
                                      &chunk, &chunk_len);
    if (r != VCS_PACKAGE_STORE_OK) {
        (void)snprintf(err, err_cap, "chunk read %s[%u]: %s",
                       path, chunk_index, fc_store_err(r));
        return false;
    }
    r = vcs_package_store_put_chunk(dst, root, path, chunk_index,
                                    chunk, chunk_len);
    free(chunk);
    if (r != VCS_PACKAGE_STORE_OK) {
        (void)snprintf(err, err_cap, "chunk store %s[%u]: %s",
                       path, chunk_index, fc_store_err(r));
        return false;
    }
    return true;
}

static bool fc_fetch_all_chunks(struct vcs_package_store *dst,
                                struct vcs_package_store *src,
                                const uint8_t root[32],
                                const struct vcs_package_manifest *manifest,
                                char *err, size_t err_cap)
{
    for (size_t i = 0; i < manifest->count; i++) {
        const struct vcs_package_file *f = &manifest->files[i];
        for (uint32_t c = 0; c < f->chunk_count; c++)
            if (!fc_fetch_chunk(dst, src, root, (uint32_t)i, f->path, c,
                                err, err_cap))
                return false;
    }
    return true;
}

static bool fc_fetch_args_present(struct vcs_package_store *dst,
                                  struct vcs_package_store *src,
                                  const uint8_t root[32])
{
    if (!dst || !src || !root)
        return false;
    return true;
}

static bool fc_fetch_source_roots(const struct vcs_package_manifest *manifest,
                                  const uint8_t root[32],
                                  char *err, size_t err_cap)
{
    uint8_t derived[32];
    bool ok = vcs_package_manifest_root(manifest, derived) &&
              memcmp(derived, root, 32) == 0;
    if (!ok) {
        (void)snprintf(err, err_cap,
                       "source manifest does not root to the given root");
    }
    return ok;
}

static bool fc_fetch_destination_already_tracked(bool ok,
                                                 struct vcs_package_store *dst,
                                                 const uint8_t root[32])
{
    struct vcs_package_store_status prior;
    return ok &&
        vcs_package_store_package_status(dst, root, &prior);
}

static bool fc_fetch_admit_manifest(struct vcs_package_store *dst,
                                    const uint8_t *wire, size_t wire_len,
                                    char *err, size_t err_cap)
{
    uint8_t dst_root[32] = {0};
    enum vcs_package_store_result pr = vcs_package_store_put_manifest(
        dst, wire, wire_len, dst_root);
    if (pr != VCS_PACKAGE_STORE_OK) {
        (void)snprintf(err, err_cap, "destination store: %s",
                       fc_store_err(pr));
        return false;
    }
    return true;
}

static bool fc_fetch_destination_is_complete(struct vcs_package_store *dst,
                                             const uint8_t root[32],
                                             char *err, size_t err_cap)
{
    struct vcs_package_store_status status;
    /* bool return, not a store result code. */
    if (!vcs_package_store_package_status(dst, root, &status) ||
        !status.complete) {
        (void)snprintf(err, err_cap,
                       "carrier incomplete in destination store");
        return false;
    }
    return true;
}

static void fc_fetch_record_object_stats(
    const struct vcs_package_manifest *manifest,
    struct vcs_fastobj_carrier_stats *stats)
{
    uint32_t entries = 0;
    uint64_t object_bytes = 0;
    for (size_t i = 0; i < manifest->count; i++) {
        const char *name = strrchr(manifest->files[i].path, '/');
        if (!name)
            continue;
        name++;
        size_t namelen = strlen(name);
        if (namelen == 66 && strcmp(name + 64, ".o") == 0) {
            entries++;
            object_bytes += manifest->files[i].size;
        }
    }
    fc_fill_stats(manifest, entries, object_bytes, stats);
}

bool vcs_fastobj_carrier_fetch(struct vcs_package_store *dst,
                               struct vcs_package_store *src,
                               const uint8_t root[32],
                               struct vcs_fastobj_carrier_stats *stats,
                               char *err, size_t err_cap)
{
    if (!fc_fetch_args_present(dst, src, root)) {
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
    bool ok = fc_fetch_source_roots(&manifest, root, err, err_cap);
    bool already_tracked =
        fc_fetch_destination_already_tracked(ok, dst, root);
    /* An existing manifest's no-op admission checks its present CAS paths.
     * Repair verified missing bytes first, then require that strict check. */
    if (already_tracked)
        ok = fc_fetch_all_chunks(dst, src, root, &manifest, err, err_cap);
    if (ok)
        ok = fc_fetch_admit_manifest(dst, wire, wire_len, err, err_cap);
    if (ok && !already_tracked)
        ok = fc_fetch_all_chunks(dst, src, root, &manifest, err, err_cap);
    if (ok)
        ok = fc_fetch_destination_is_complete(dst, root, err, err_cap);
    if (ok)
        fc_fetch_record_object_stats(&manifest, stats);
    vcs_package_manifest_free(&manifest);
    free(wire);
    return ok;
}

#endif
