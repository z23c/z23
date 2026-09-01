/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * blob_store — implementation. See vcs/blob_store.h.
 *
 * Everything here is a thin, hostile-input-checked adapter over
 * primitives that already exist: package_manifest for the shape and the
 * root, package_store for admission and CAS reads, package_swarm_node
 * for the network. No new wire message, no new bound raised. */

#include "vcs/blob_store.h"

#include "vcs/package_manifest.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"

#include "crypto/sha3.h"
#include "base/log_macros.h"

#include <stdlib.h>
#include <string.h>

#define BLOB_LOG "vcs.blob"

const char *vcs_blob_result_string(enum vcs_blob_result r)
{
    switch (r) {
    case VCS_BLOB_OK:            return "ok";
    case VCS_BLOB_ERR_NULL:      return "null-argument";
    case VCS_BLOB_ERR_EMPTY:     return "empty-blob";
    case VCS_BLOB_ERR_TOO_LARGE: return "blob-too-large";
    case VCS_BLOB_ERR_NO_STORE:  return "no-package-store";
    case VCS_BLOB_ERR_NO_ENGINE: return "no-swarm-engine";
    case VCS_BLOB_ERR_MANIFEST:  return "manifest-failure";
    case VCS_BLOB_ERR_STORE:     return "store-refused";
    case VCS_BLOB_ERR_ABSENT:    return "blob-absent";
    case VCS_BLOB_ERR_SHAPE:     return "not-a-blob-package";
    case VCS_BLOB_ERR_CORRUPT:   return "blob-bytes-corrupt";
    case VCS_BLOB_ERR_CAPACITY:  return "buffer-too-small";
    case VCS_BLOB_ERR_FETCH:     return "swarm-refused";
    }
    return "unknown";
}

/* Every entry point funnels through this: hostile input dies here, by
 * name, before anything is hashed, allocated, or stored. */
static enum vcs_blob_result blob_check_input(const uint8_t *bytes, size_t len)
{
    if (!bytes)
        return VCS_BLOB_ERR_NULL;
    if (len == 0)
        return VCS_BLOB_ERR_EMPTY;
    if (len > VCS_BLOB_MAX_BYTES)
        return VCS_BLOB_ERR_TOO_LARGE;
    return VCS_BLOB_OK;
}

/* Build the frozen one-file/one-chunk blob manifest. On OK the caller
 * owns *out and must vcs_package_manifest_free() it. */
static enum vcs_blob_result blob_build_manifest(
    const uint8_t *bytes, size_t len, struct vcs_package_manifest *out)
{
    enum vcs_blob_result vr = blob_check_input(bytes, len);
    if (vr != VCS_BLOB_OK)
        return vr;
    if (!out)
        return VCS_BLOB_ERR_NULL;

    /* Structural, not incidental: VCS_BLOB_MAX_BYTES is far below one
     * chunk, so a blob is always exactly one chunk. */
    uint8_t chunk_hash[32];
    if (!vcs_package_chunk_hash(bytes, len, chunk_hash))
        LOG_RETURN(VCS_BLOB_ERR_MANIFEST, BLOB_LOG,
                   "chunk hash of %zu blob bytes failed", len);

    vcs_package_manifest_init(out);
    if (!vcs_package_manifest_add(out, VCS_BLOB_PATH, VCS_PACKAGE_MODE_FILE,
                                  (uint64_t)len, chunk_hash, 1u)) {
        vcs_package_manifest_free(out);
        LOG_RETURN(VCS_BLOB_ERR_MANIFEST, BLOB_LOG,
                   "blob manifest add failed (len=%zu)", len);
    }
    return VCS_BLOB_OK;
}

enum vcs_blob_result vcs_blob_root_of(const uint8_t *bytes, size_t len,
                                      uint8_t out_root[32])
{
    if (!out_root)
        return VCS_BLOB_ERR_NULL;
    struct vcs_package_manifest manifest;
    enum vcs_blob_result vr = blob_build_manifest(bytes, len, &manifest);
    if (vr != VCS_BLOB_OK)
        return vr;
    bool ok = vcs_package_manifest_root(&manifest, out_root);
    vcs_package_manifest_free(&manifest);
    if (!ok)
        LOG_RETURN(VCS_BLOB_ERR_MANIFEST, BLOB_LOG,
                   "blob manifest root failed (len=%zu)", len);
    return VCS_BLOB_OK;
}

bool vcs_blob_root(const uint8_t *bytes, size_t len, uint8_t out_root[32])
{
    return vcs_blob_root_of(bytes, len, out_root) == VCS_BLOB_OK;
}

enum vcs_blob_result vcs_blob_put_to(struct vcs_package_store *store,
                                     const uint8_t *bytes, size_t len,
                                     uint8_t out_root[32])
{
    if (!store)
        return VCS_BLOB_ERR_NO_STORE;
    struct vcs_package_manifest manifest;
    enum vcs_blob_result vr = blob_build_manifest(bytes, len, &manifest);
    if (vr != VCS_BLOB_OK)
        return vr;

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!vcs_package_manifest_serialize(&manifest, &wire, &wire_len)) {
        vcs_package_manifest_free(&manifest);
        LOG_RETURN(VCS_BLOB_ERR_MANIFEST, BLOB_LOG,
                   "blob manifest serialize failed (len=%zu)", len);
    }
    uint8_t root[32];
    bool root_ok = vcs_package_manifest_root(&manifest, root);
    vcs_package_manifest_free(&manifest);
    if (!root_ok) {
        free(wire);
        LOG_RETURN(VCS_BLOB_ERR_MANIFEST, BLOB_LOG,
                   "blob manifest root failed (len=%zu)", len);
    }

    uint8_t admitted[32];
    enum vcs_package_store_result sr =
        vcs_package_store_put_manifest(store, wire, wire_len, admitted);
    free(wire);
    if (sr != VCS_PACKAGE_STORE_OK)
        LOG_RETURN(VCS_BLOB_ERR_STORE, BLOB_LOG,
                   "blob manifest refused: %s",
                   vcs_package_store_result_string(sr));
    if (memcmp(admitted, root, 32) != 0)
        LOG_RETURN(VCS_BLOB_ERR_CORRUPT, BLOB_LOG,
                   "admitted root != computed blob root");

    sr = vcs_package_store_put_chunk(store, root, VCS_BLOB_PATH, 0u, bytes,
                                     len);
    if (sr != VCS_PACKAGE_STORE_OK)
        LOG_RETURN(VCS_BLOB_ERR_STORE, BLOB_LOG, "blob chunk refused: %s",
                   vcs_package_store_result_string(sr));

    if (out_root)
        memcpy(out_root, root, 32);
    return VCS_BLOB_OK;
}

bool vcs_blob_put(const uint8_t *bytes, size_t len, uint8_t out_root[32])
{
    struct vcs_package_store *store = vcs_package_store_global();
    if (!store)
        LOG_RETURN(false, BLOB_LOG, "blob put: %s",
                   vcs_blob_result_string(VCS_BLOB_ERR_NO_STORE));
    return vcs_blob_put_to(store, bytes, len, out_root) == VCS_BLOB_OK;
}

/* Confirm a tracked root really is the frozen blob shape and hand back
 * its committed length + chunk hash. Re-derives the root from the
 * PARSED manifest so a store index that disagrees with its own bytes
 * cannot pass. */
static enum vcs_blob_result blob_shape_of(struct vcs_package_store *store,
                                          const uint8_t root[32],
                                          size_t *out_len,
                                          uint8_t out_chunk_hash[32])
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    enum vcs_package_store_result sr =
        vcs_package_store_get_manifest_wire(store, root, &wire, &wire_len);
    if (sr != VCS_PACKAGE_STORE_OK) {
        if (sr == VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE)
            return VCS_BLOB_ERR_ABSENT;
        LOG_RETURN(VCS_BLOB_ERR_STORE, BLOB_LOG, "blob manifest read: %s",
                   vcs_package_store_result_string(sr));
    }
    struct vcs_package_manifest manifest;
    bool parsed = vcs_package_manifest_parse(wire, wire_len, &manifest);
    free(wire);
    if (!parsed)
        LOG_RETURN(VCS_BLOB_ERR_MANIFEST, BLOB_LOG,
                   "stored blob manifest does not parse");

    enum vcs_blob_result vr = VCS_BLOB_OK;
    uint8_t derived[32];
    if (!vcs_package_manifest_root(&manifest, derived) ||
        memcmp(derived, root, 32) != 0) {
        vr = VCS_BLOB_ERR_CORRUPT;
    } else if (manifest.count != 1u || manifest.files[0].chunk_count != 1u ||
               manifest.files[0].mode != VCS_PACKAGE_MODE_FILE ||
               !manifest.files[0].path ||
               strcmp(manifest.files[0].path, VCS_BLOB_PATH) != 0 ||
               manifest.files[0].size == 0 ||
               manifest.files[0].size > (uint64_t)VCS_BLOB_MAX_BYTES) {
        vr = VCS_BLOB_ERR_SHAPE;
    } else {
        if (out_len)
            *out_len = (size_t)manifest.files[0].size;
        if (out_chunk_hash)
            memcpy(out_chunk_hash, manifest.files[0].chunk_hashes, 32);
    }
    vcs_package_manifest_free(&manifest);
    if (vr != VCS_BLOB_OK)
        LOG_RETURN(vr, BLOB_LOG, "blob shape check: %s",
                   vcs_blob_result_string(vr));
    return VCS_BLOB_OK;
}

enum vcs_blob_result vcs_blob_get_from(struct vcs_package_store *store,
                                       const uint8_t root[32], uint8_t *out,
                                       size_t out_cap, size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    if (!store)
        return VCS_BLOB_ERR_NO_STORE;
    if (!root || !out)
        return VCS_BLOB_ERR_NULL;

    size_t blob_len = 0;
    uint8_t chunk_hash[32];
    enum vcs_blob_result vr = blob_shape_of(store, root, &blob_len,
                                            chunk_hash);
    if (vr != VCS_BLOB_OK)
        return vr;
    if (out_cap < blob_len)
        LOG_RETURN(VCS_BLOB_ERR_CAPACITY, BLOB_LOG,
                   "blob is %zu bytes, buffer is %zu", blob_len, out_cap);

    uint8_t *chunk = NULL;
    size_t chunk_len = 0;
    enum vcs_package_store_result sr =
        vcs_package_store_get_chunk_at(store, root, 0u, 0u, &chunk,
                                       &chunk_len);
    if (sr != VCS_PACKAGE_STORE_OK) {
        if (sr == VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE ||
            sr == VCS_PACKAGE_STORE_ERR_CHUNK_MISSING)
            return VCS_BLOB_ERR_ABSENT;
        if (sr == VCS_PACKAGE_STORE_ERR_CHUNK_HASH)
            return VCS_BLOB_ERR_CORRUPT;
        LOG_RETURN(VCS_BLOB_ERR_STORE, BLOB_LOG, "blob chunk read: %s",
                   vcs_package_store_result_string(sr));
    }

    /* Defense in depth for adapters whose store implementation predates
     * verified reads: corrupt bytes must never escape this semantic layer. */
    uint8_t actual[32];
    sha3_256(chunk, chunk_len, actual);
    if (chunk_len != blob_len || memcmp(actual, chunk_hash, 32) != 0) {
        free(chunk);
        LOG_RETURN(VCS_BLOB_ERR_CORRUPT, BLOB_LOG,
                   "blob bytes do not match the committed hash (%zu/%zu)",
                   chunk_len, blob_len);
    }
    memcpy(out, chunk, blob_len);
    free(chunk);
    if (out_len)
        *out_len = blob_len;
    return VCS_BLOB_OK;
}

int vcs_blob_get(const uint8_t root[32], uint8_t *out, size_t out_cap)
{
    struct vcs_package_store *store = vcs_package_store_global();
    if (!store)
        LOG_RETURN(-1, BLOB_LOG, "blob get: %s",
                   vcs_blob_result_string(VCS_BLOB_ERR_NO_STORE));
    size_t len = 0;
    enum vcs_blob_result vr = vcs_blob_get_from(store, root, out, out_cap,
                                                &len);
    if (vr != VCS_BLOB_OK)
        LOG_RETURN(-1, BLOB_LOG, "blob get: %s", vcs_blob_result_string(vr));
    if (len > (size_t)VCS_BLOB_MAX_BYTES)
        LOG_RETURN(-1, BLOB_LOG, "blob length %zu over ceiling", len);
    return (int)len;
}

enum vcs_blob_result vcs_blob_fetch_via(struct vcs_swarm_engine *engine,
                                        const uint8_t root[32], int64_t day,
                                        uint64_t now)
{
    if (!engine)
        return VCS_BLOB_ERR_NO_ENGINE;
    if (!root)
        return VCS_BLOB_ERR_NULL;
    enum vcs_swarm_fetch_result fr =
        vcs_swarm_engine_fetch(engine, root, day, now);
    if (fr == VCS_SWARM_FETCH_OK || fr == VCS_SWARM_FETCH_ALREADY_COMPLETE)
        return VCS_BLOB_OK;
    if (fr == VCS_SWARM_FETCH_NO_STORE)
        LOG_RETURN(VCS_BLOB_ERR_NO_STORE, BLOB_LOG, "blob fetch: %s",
                   vcs_swarm_fetch_result_string(fr));
    LOG_RETURN(VCS_BLOB_ERR_FETCH, BLOB_LOG, "blob fetch refused: %s",
               vcs_swarm_fetch_result_string(fr));
}

bool vcs_blob_fetch(const uint8_t root[32], int64_t day, uint64_t now)
{
    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    if (!engine)
        LOG_RETURN(false, BLOB_LOG, "blob fetch: %s",
                   vcs_blob_result_string(VCS_BLOB_ERR_NO_ENGINE));
    return vcs_blob_fetch_via(engine, root, day, now) == VCS_BLOB_OK;
}

size_t vcs_blob_announce_via(struct vcs_swarm_engine *engine)
{
    if (!engine)
        LOG_RETURN(0, BLOB_LOG, "blob announce: %s",
                   vcs_blob_result_string(VCS_BLOB_ERR_NO_ENGINE));
    uint64_t peers[VCS_SWARM_MAX_PEERS];
    size_t n = vcs_swarm_engine_peer_ids(engine, peers, VCS_SWARM_MAX_PEERS);
    size_t queued = 0;
    for (size_t i = 0; i < n; i++)
        queued += vcs_swarm_engine_announce_to(engine, peers[i]);
    return queued;
}

size_t vcs_blob_announce(void)
{
    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    if (!engine)
        LOG_RETURN(0, BLOB_LOG, "blob announce: %s",
                   vcs_blob_result_string(VCS_BLOB_ERR_NO_ENGINE));
    return vcs_blob_announce_via(engine);
}
