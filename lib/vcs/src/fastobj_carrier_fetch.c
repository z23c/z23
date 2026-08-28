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

#endif
