/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: encode, parse, derive, and commit bounded package API capsules. */

#include "vcs/package_capsule.h"

#include "crypto/sha3.h"
#include "util/safe_alloc.h"

#include "vcs_priv.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t capsule_magic[8] =
    { 'Z', 'C', 'L', 'A', 'P', 'I', '\r', '\n' };
static const uint8_t capsule_domain[] = VCS_PACKAGE_CAPSULE_ROOT_DOMAIN;

const char *vcs_package_capsule_error_string(
    enum vcs_package_capsule_error error)
{
    switch (error) {
    case VCS_PACKAGE_CAPSULE_OK: return "ok";
    case VCS_PACKAGE_CAPSULE_ERR_NULL: return "null-argument";
    case VCS_PACKAGE_CAPSULE_ERR_ALLOC: return "allocation-failure";
    case VCS_PACKAGE_CAPSULE_ERR_HEADER: return "header-not-in-manifest";
    case VCS_PACKAGE_CAPSULE_ERR_COUNT: return "header-count-bound";
    case VCS_PACKAGE_CAPSULE_ERR_MAGIC: return "wire-magic";
    case VCS_PACKAGE_CAPSULE_ERR_VERSION: return "wire-version";
    case VCS_PACKAGE_CAPSULE_ERR_TRUNCATED: return "wire-truncated";
    case VCS_PACKAGE_CAPSULE_ERR_TRAILING: return "wire-trailing";
    case VCS_PACKAGE_CAPSULE_ERR_ORDER: return "header-order";
    case VCS_PACKAGE_CAPSULE_ERR_OVERSIZE: return "wire-oversize";
    }
    return "unknown-error";
}

void vcs_package_capsule_init(struct vcs_package_capsule *capsule)
{
    if (capsule)
        memset(capsule, 0, sizeof(*capsule));
}

static const struct vcs_package_file *capsule_file(
    const struct vcs_package_manifest *manifest, const char *path)
{
    for (size_t i = 0; i < manifest->count; i++)
        if (strcmp(manifest->files[i].path, path) == 0)
            return &manifest->files[i];
    return NULL;
}

enum vcs_package_capsule_error vcs_package_capsule_derive(
    const struct vcs_package_manifest *manifest,
    const struct vcs_package_recipe *recipe,
    struct vcs_package_capsule *out)
{
    if (!manifest || !recipe || !out)
        return VCS_PACKAGE_CAPSULE_ERR_NULL;
    vcs_package_capsule_init(out);
    if (recipe->public_headers.count > VCS_PACKAGE_CAPSULE_MAX_HEADERS)
        return VCS_PACKAGE_CAPSULE_ERR_COUNT;
    for (size_t i = 0; i < recipe->public_headers.count; i++) {
        const char *path = recipe->public_headers.items[i];
        const struct vcs_package_file *file = capsule_file(manifest, path);
        if (!file || strlen(path) > VCS_PACKAGE_PATH_MAX ||
            !vcs_package_file_hash(file, out->headers[i].file_root)) {
            vcs_package_capsule_init(out);
            return VCS_PACKAGE_CAPSULE_ERR_HEADER;
        }
        memcpy(out->headers[i].path, path, strlen(path) + 1u);
        out->count++;
    }
    return VCS_PACKAGE_CAPSULE_OK;
}

static enum vcs_package_capsule_error capsule_validate(
    const struct vcs_package_capsule *capsule)
{
    if (!capsule)
        return VCS_PACKAGE_CAPSULE_ERR_NULL;
    if (capsule->count > VCS_PACKAGE_CAPSULE_MAX_HEADERS)
        return VCS_PACKAGE_CAPSULE_ERR_COUNT;
    for (size_t i = 0; i < capsule->count; i++) {
        const char *path = capsule->headers[i].path;
        size_t len = strnlen(path, sizeof(capsule->headers[i].path));
        if (len == 0 || len > VCS_PACKAGE_PATH_MAX ||
            !vcs_package_path_valid(path))
            return VCS_PACKAGE_CAPSULE_ERR_HEADER;
        if (i && strcmp(capsule->headers[i - 1u].path, path) >= 0)
            return VCS_PACKAGE_CAPSULE_ERR_ORDER;
    }
    return VCS_PACKAGE_CAPSULE_OK;
}

enum vcs_package_capsule_error vcs_package_capsule_serialize(
    const struct vcs_package_capsule *capsule, uint8_t **wire,
    size_t *wire_len)
{
    if (!wire || !wire_len)
        return VCS_PACKAGE_CAPSULE_ERR_NULL;
    *wire = NULL;
    *wire_len = 0;
    enum vcs_package_capsule_error err = capsule_validate(capsule);
    if (err != VCS_PACKAGE_CAPSULE_OK)
        return err;
    size_t total = sizeof(capsule_magic) + 2u + 2u;
    for (size_t i = 0; i < capsule->count; i++)
        total += 2u + strlen(capsule->headers[i].path) + 32u;
    if (total > VCS_PACKAGE_CAPSULE_MAX_WIRE_BYTES)
        return VCS_PACKAGE_CAPSULE_ERR_OVERSIZE;
    uint8_t *buf = zcl_malloc(total, "vcs.package.capsule.wire");
    if (!buf)
        return VCS_PACKAGE_CAPSULE_ERR_ALLOC;
    size_t off = 0;
    memcpy(buf + off, capsule_magic, sizeof(capsule_magic));
    off += sizeof(capsule_magic);
    vcs_wr_u16le(buf + off, VCS_PACKAGE_CAPSULE_VERSION); off += 2u;
    vcs_wr_u16le(buf + off, (uint16_t)capsule->count); off += 2u;
    for (size_t i = 0; i < capsule->count; i++) {
        size_t len = strlen(capsule->headers[i].path);
        vcs_wr_u16le(buf + off, (uint16_t)len); off += 2u;
        memcpy(buf + off, capsule->headers[i].path, len); off += len;
        memcpy(buf + off, capsule->headers[i].file_root, 32); off += 32u;
    }
    *wire = buf;
    *wire_len = off;
    return VCS_PACKAGE_CAPSULE_OK;
}

enum vcs_package_capsule_error vcs_package_capsule_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_package_capsule *out)
{
    if (!wire || !out)
        return VCS_PACKAGE_CAPSULE_ERR_NULL;
    vcs_package_capsule_init(out);
    if (wire_len > VCS_PACKAGE_CAPSULE_MAX_WIRE_BYTES)
        return VCS_PACKAGE_CAPSULE_ERR_OVERSIZE;
    if (wire_len < sizeof(capsule_magic) + 4u)
        return VCS_PACKAGE_CAPSULE_ERR_TRUNCATED;
    size_t off = 0;
    if (memcmp(wire, capsule_magic, sizeof(capsule_magic)) != 0)
        return VCS_PACKAGE_CAPSULE_ERR_MAGIC;
    off += sizeof(capsule_magic);
    if (vcs_rd_u16le(wire + off) != VCS_PACKAGE_CAPSULE_VERSION)
        return VCS_PACKAGE_CAPSULE_ERR_VERSION;
    off += 2u;
    uint16_t count = vcs_rd_u16le(wire + off); off += 2u;
    if (count > VCS_PACKAGE_CAPSULE_MAX_HEADERS)
        return VCS_PACKAGE_CAPSULE_ERR_COUNT;
    for (uint16_t i = 0; i < count; i++) {
        if (off > wire_len || wire_len - off < 2u)
            goto truncated;
        uint16_t len = vcs_rd_u16le(wire + off); off += 2u;
        if (len == 0 || len > VCS_PACKAGE_PATH_MAX ||
            off > wire_len || wire_len - off < (size_t)len + 32u)
            goto truncated;
        memcpy(out->headers[i].path, wire + off, len); off += len;
        memcpy(out->headers[i].file_root, wire + off, 32); off += 32u;
        out->count++;
    }
    if (off != wire_len) {
        vcs_package_capsule_init(out);
        return VCS_PACKAGE_CAPSULE_ERR_TRAILING;
    }
    enum vcs_package_capsule_error err = capsule_validate(out);
    if (err != VCS_PACKAGE_CAPSULE_OK)
        vcs_package_capsule_init(out);
    return err;
truncated:
    vcs_package_capsule_init(out);
    return VCS_PACKAGE_CAPSULE_ERR_TRUNCATED;
}

enum vcs_package_capsule_error vcs_package_capsule_root(
    const struct vcs_package_capsule *capsule, uint8_t out[32])
{
    if (!out)
        return VCS_PACKAGE_CAPSULE_ERR_NULL;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    enum vcs_package_capsule_error err =
        vcs_package_capsule_serialize(capsule, &wire, &wire_len);
    if (err != VCS_PACKAGE_CAPSULE_OK)
        return err;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, capsule_domain, sizeof(capsule_domain));
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
    free(wire);
    return VCS_PACKAGE_CAPSULE_OK;
}
