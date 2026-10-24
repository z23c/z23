/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * bundle_carry — implementation. See vcs/bundle_carry.h.
 *
 * A thin, hostile-input-checked adapter over package_manifest (shape and
 * root) and package_store (admission and verified CAS reads). No new wire
 * message, no new bound raised on any existing surface. */

#include "vcs/bundle_carry.h"

#include "vcs/package_manifest.h"
#include "vcs/package_store.h"

#include "base/log_macros.h"

#include <stdlib.h>
#include <string.h>

#define BUNDLE_LOG "vcs.bundle"

const char *vcs_bundle_result_string(enum vcs_bundle_result r)
{
    switch (r) {
    case VCS_BUNDLE_OK:           return "ok";
    case VCS_BUNDLE_ERR_NULL:     return "null-argument";
    case VCS_BUNDLE_ERR_EMPTY:    return "empty-bundle";
    case VCS_BUNDLE_ERR_TOO_LARGE: return "bundle-too-large";
    case VCS_BUNDLE_ERR_NO_STORE: return "no-package-store";
    case VCS_BUNDLE_ERR_MANIFEST: return "manifest-failure";
    case VCS_BUNDLE_ERR_STORE:    return "store-refused";
    case VCS_BUNDLE_ERR_ABSENT:   return "bundle-absent";
    case VCS_BUNDLE_ERR_SHAPE:    return "not-a-bundle-package";
    case VCS_BUNDLE_ERR_CORRUPT:  return "bundle-bytes-corrupt";
    case VCS_BUNDLE_ERR_CAPACITY: return "buffer-too-small";
    }
    return "unknown";
}

bool vcs_bundle_manifest_is_bundle(const struct vcs_package_manifest *m)
{
    if (!m || m->count != 1u || !m->files)
        return false;
    const struct vcs_package_file *f = &m->files[0];
    return f->path && strcmp(f->path, VCS_BUNDLE_PATH) == 0 &&
           f->mode == VCS_PACKAGE_MODE_FILE && f->size >= 1u &&
           f->size <= (uint64_t)VCS_BUNDLE_MAX_BYTES &&
           f->chunk_count >= 1u && f->chunk_count <= VCS_BUNDLE_MAX_CHUNKS;
}

static enum vcs_bundle_result bundle_check_input(const uint8_t *bytes,
                                                 size_t len)
{
    if (!bytes)
        return VCS_BUNDLE_ERR_NULL;
    if (len == 0)
        return VCS_BUNDLE_ERR_EMPTY;
    if (len > VCS_BUNDLE_MAX_BYTES)
        return VCS_BUNDLE_ERR_TOO_LARGE;
    return VCS_BUNDLE_OK;
}

static size_t bundle_chunk_len(size_t len, uint32_t index)
{
    size_t start = (size_t)index * VCS_PACKAGE_CHUNK_BYTES;
    size_t rest = len - start;
    return rest < VCS_PACKAGE_CHUNK_BYTES ? rest : VCS_PACKAGE_CHUNK_BYTES;
}

/* Build the frozen one-file bundle manifest. A non-NULL *out is initialised
 * before anything can fail, so it is always safe to free; on OK the caller
 * owns it and must vcs_package_manifest_free() it. */
static enum vcs_bundle_result bundle_build_manifest(
    const uint8_t *bytes, size_t len, struct vcs_package_manifest *out)
{
    if (!out)
        return VCS_BUNDLE_ERR_NULL;
    vcs_package_manifest_init(out);
    enum vcs_bundle_result vr = bundle_check_input(bytes, len);
    if (vr != VCS_BUNDLE_OK)
        return vr;

    uint32_t chunks = (uint32_t)((len + VCS_PACKAGE_CHUNK_BYTES - 1u) /
                                 VCS_PACKAGE_CHUNK_BYTES);
    if (chunks > VCS_BUNDLE_MAX_CHUNKS)
        return VCS_BUNDLE_ERR_TOO_LARGE;
    uint8_t hashes[VCS_BUNDLE_MAX_CHUNKS * 32u];
    for (uint32_t i = 0; i < chunks; i++) {
        if (!vcs_package_chunk_hash(bytes + (size_t)i * VCS_PACKAGE_CHUNK_BYTES,
                                    bundle_chunk_len(len, i),
                                    hashes + (size_t)i * 32u))
            LOG_RETURN(VCS_BUNDLE_ERR_MANIFEST, BUNDLE_LOG,
                       "chunk %u hash of %zu bundle bytes failed", i, len);
    }
    if (!vcs_package_manifest_add(out, VCS_BUNDLE_PATH,
                                  VCS_PACKAGE_MODE_FILE, (uint64_t)len,
                                  hashes, chunks)) {
        vcs_package_manifest_free(out);
        LOG_RETURN(VCS_BUNDLE_ERR_MANIFEST, BUNDLE_LOG,
                   "bundle manifest add failed (len=%zu)", len);
    }
    return VCS_BUNDLE_OK;
}

enum vcs_bundle_result vcs_bundle_root_of(const uint8_t *bytes, size_t len,
                                          uint8_t out_root[32])
{
    if (!out_root)
        return VCS_BUNDLE_ERR_NULL;
    struct vcs_package_manifest manifest;
    enum vcs_bundle_result vr = bundle_build_manifest(bytes, len, &manifest);
    if (vr != VCS_BUNDLE_OK)
        return vr;
    bool ok = vcs_package_manifest_root(&manifest, out_root);
    vcs_package_manifest_free(&manifest);
    if (!ok)
        LOG_RETURN(VCS_BUNDLE_ERR_MANIFEST, BUNDLE_LOG,
                   "bundle manifest root failed (len=%zu)", len);
    return VCS_BUNDLE_OK;
}

/* Serialize `manifest` and admit it; leaves the derived root in `root`. */
static enum vcs_bundle_result bundle_admit_manifest(
    struct vcs_package_store *store, const struct vcs_package_manifest *manifest,
    uint8_t root[32])
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!vcs_package_manifest_serialize(manifest, &wire, &wire_len))
        LOG_RETURN(VCS_BUNDLE_ERR_MANIFEST, BUNDLE_LOG,
                   "bundle manifest serialize failed");
    if (!vcs_package_manifest_root(manifest, root)) {
        free(wire);
        LOG_RETURN(VCS_BUNDLE_ERR_MANIFEST, BUNDLE_LOG,
                   "bundle manifest root failed");
    }
    uint8_t admitted[32];
    enum vcs_package_store_result sr =
        vcs_package_store_put_manifest_no_evict(store, wire, wire_len,
                                                admitted);
    free(wire);
    if (sr != VCS_PACKAGE_STORE_OK)
        LOG_RETURN(VCS_BUNDLE_ERR_STORE, BUNDLE_LOG,
                   "bundle manifest refused: %s",
                   vcs_package_store_result_string(sr));
    if (memcmp(admitted, root, 32) != 0)
        LOG_RETURN(VCS_BUNDLE_ERR_CORRUPT, BUNDLE_LOG,
                   "admitted root != computed bundle root");
    return VCS_BUNDLE_OK;
}

enum vcs_bundle_result vcs_bundle_put_to_no_evict(
    struct vcs_package_store *store, const uint8_t *bytes, size_t len,
    uint8_t out_root[32])
{
    if (!store)
        return VCS_BUNDLE_ERR_NO_STORE;
    struct vcs_package_manifest manifest;
    enum vcs_bundle_result vr = bundle_build_manifest(bytes, len, &manifest);
    if (vr != VCS_BUNDLE_OK)
        return vr;
    uint8_t root[32];
    vr = bundle_admit_manifest(store, &manifest, root);
    uint32_t chunks = manifest.files[0].chunk_count;
    vcs_package_manifest_free(&manifest);
    if (vr != VCS_BUNDLE_OK)
        return vr;

    for (uint32_t i = 0; i < chunks; i++) {
        enum vcs_package_store_result sr = vcs_package_store_put_chunk_no_evict(
            store, root, VCS_BUNDLE_PATH, i,
            bytes + (size_t)i * VCS_PACKAGE_CHUNK_BYTES,
            bundle_chunk_len(len, i));
        if (sr != VCS_PACKAGE_STORE_OK)
            LOG_RETURN(VCS_BUNDLE_ERR_STORE, BUNDLE_LOG,
                       "bundle chunk %u refused: %s", i,
                       vcs_package_store_result_string(sr));
    }
    if (out_root)
        memcpy(out_root, root, 32);
    return VCS_BUNDLE_OK;
}

/* Parse the stored manifest of `root`, re-derive its root and check the
 * frozen shape. On OK the caller owns *out. */
static enum vcs_bundle_result bundle_load_manifest(
    struct vcs_package_store *store, const uint8_t root[32],
    struct vcs_package_manifest *out)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    enum vcs_package_store_result sr =
        vcs_package_store_get_manifest_wire(store, root, &wire, &wire_len);
    if (sr != VCS_PACKAGE_STORE_OK) {
        if (sr == VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE)
            return VCS_BUNDLE_ERR_ABSENT;
        LOG_RETURN(VCS_BUNDLE_ERR_STORE, BUNDLE_LOG,
                   "bundle manifest read: %s",
                   vcs_package_store_result_string(sr));
    }
    bool parsed = vcs_package_manifest_parse(wire, wire_len, out);
    free(wire);
    if (!parsed)
        LOG_RETURN(VCS_BUNDLE_ERR_MANIFEST, BUNDLE_LOG,
                   "stored bundle manifest does not parse");
    uint8_t derived[32];
    enum vcs_bundle_result vr = VCS_BUNDLE_OK;
    if (!vcs_package_manifest_root(out, derived) ||
        memcmp(derived, root, 32) != 0)
        vr = VCS_BUNDLE_ERR_CORRUPT;
    else if (!vcs_bundle_manifest_is_bundle(out))
        vr = VCS_BUNDLE_ERR_SHAPE;
    if (vr != VCS_BUNDLE_OK) {
        vcs_package_manifest_free(out);
        LOG_RETURN(vr, BUNDLE_LOG, "bundle shape check: %s",
                   vcs_bundle_result_string(vr));
    }
    return VCS_BUNDLE_OK;
}

enum vcs_bundle_result vcs_bundle_size_of(struct vcs_package_store *store,
                                          const uint8_t root[32],
                                          size_t *out_len)
{
    if (!store)
        return VCS_BUNDLE_ERR_NO_STORE;
    if (!root || !out_len)
        return VCS_BUNDLE_ERR_NULL;
    struct vcs_package_manifest manifest;
    enum vcs_bundle_result vr = bundle_load_manifest(store, root, &manifest);
    if (vr != VCS_BUNDLE_OK)
        return vr;
    *out_len = (size_t)manifest.files[0].size;
    vcs_package_manifest_free(&manifest);
    return VCS_BUNDLE_OK;
}

static enum vcs_bundle_result bundle_read_chunks(
    struct vcs_package_store *store, const uint8_t root[32], uint8_t *out,
    size_t total, uint32_t chunks)
{
    for (uint32_t i = 0; i < chunks; i++) {
        size_t want = bundle_chunk_len(total, i);
        size_t got = 0;
        enum vcs_package_store_result sr = vcs_package_store_get_chunk_at_into(
            store, root, 0u, i, out + (size_t)i * VCS_PACKAGE_CHUNK_BYTES,
            want, &got);
        if (sr == VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE ||
            sr == VCS_PACKAGE_STORE_ERR_CHUNK_MISSING)
            return VCS_BUNDLE_ERR_ABSENT;
        if (sr == VCS_PACKAGE_STORE_ERR_CHUNK_HASH)
            return VCS_BUNDLE_ERR_CORRUPT;
        if (sr != VCS_PACKAGE_STORE_OK)
            LOG_RETURN(VCS_BUNDLE_ERR_STORE, BUNDLE_LOG,
                       "bundle chunk %u read: %s", i,
                       vcs_package_store_result_string(sr));
        if (got != want)
            return VCS_BUNDLE_ERR_CORRUPT;
    }
    return VCS_BUNDLE_OK;
}

enum vcs_bundle_result vcs_bundle_get_from(struct vcs_package_store *store,
                                           const uint8_t root[32],
                                           uint8_t *out, size_t out_cap,
                                           size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    if (!store)
        return VCS_BUNDLE_ERR_NO_STORE;
    if (!root || !out)
        return VCS_BUNDLE_ERR_NULL;
    struct vcs_package_manifest manifest;
    enum vcs_bundle_result vr = bundle_load_manifest(store, root, &manifest);
    if (vr != VCS_BUNDLE_OK)
        return vr;
    size_t total = (size_t)manifest.files[0].size;
    uint32_t chunks = manifest.files[0].chunk_count;
    vcs_package_manifest_free(&manifest);
    if (out_cap < total)
        return VCS_BUNDLE_ERR_CAPACITY;
    vr = bundle_read_chunks(store, root, out, total, chunks);
    if (vr == VCS_BUNDLE_OK && out_len)
        *out_len = total;
    return vr;
}
