/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical path scope for model-neutral ZCODE candidate writes. */

#include "vcs/zcode_write_scope.h"

#include "vcs_priv.h"

#include "crypto/sha3.h"
#include "util/safe_alloc.h"
#include "vcs/package_manifest.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t scope_magic[8] = {
    'Z', 'C', 'S', 'C', 'O', 'P', 'E', '\n'
};

const char *vcs_zcode_write_scope_result_string(
    enum vcs_zcode_write_scope_result result)
{
    switch (result) {
    case VCS_ZCODE_WRITE_SCOPE_OK: return "ok";
    case VCS_ZCODE_WRITE_SCOPE_NULL: return "null-argument";
    case VCS_ZCODE_WRITE_SCOPE_SHAPE: return "noncanonical-scope";
    case VCS_ZCODE_WRITE_SCOPE_LIMIT: return "scope-limit";
    case VCS_ZCODE_WRITE_SCOPE_ALLOC: return "allocation-failed";
    }
    return "unknown";
}

void vcs_zcode_write_scope_init(struct vcs_zcode_write_scope_v1 *scope)
{
    if (scope) memset(scope, 0, sizeof(*scope));
}

static bool scope_path_valid(const char *path)
{
    if (!path || !path[0] ||
        strnlen(path, VCS_ZCODE_WRITE_SCOPE_PATH_MAX + 1u) >
            VCS_ZCODE_WRITE_SCOPE_PATH_MAX ||
        !vcs_package_path_valid(path))
        return false;
    return true;
}

enum vcs_zcode_write_scope_result vcs_zcode_write_scope_add(
    struct vcs_zcode_write_scope_v1 *scope, const char *path_prefix)
{
    if (!scope || !path_prefix) return VCS_ZCODE_WRITE_SCOPE_NULL;
    if (!scope_path_valid(path_prefix)) return VCS_ZCODE_WRITE_SCOPE_SHAPE;
    if (scope->count >= VCS_ZCODE_WRITE_SCOPE_MAX_PATHS)
        return VCS_ZCODE_WRITE_SCOPE_LIMIT;
    size_t at = 0;
    while (at < scope->count && strcmp(scope->paths[at], path_prefix) < 0)
        at++;
    if (at < scope->count && strcmp(scope->paths[at], path_prefix) == 0)
        return VCS_ZCODE_WRITE_SCOPE_SHAPE;
    for (size_t i = scope->count; i > at; i--)
        memcpy(scope->paths[i], scope->paths[i - 1u],
               sizeof(scope->paths[i]));
    memcpy(scope->paths[at], path_prefix, strlen(path_prefix) + 1u);
    scope->count++;
    return VCS_ZCODE_WRITE_SCOPE_OK;
}

enum vcs_zcode_write_scope_result vcs_zcode_write_scope_validate(
    const struct vcs_zcode_write_scope_v1 *scope)
{
    if (!scope) return VCS_ZCODE_WRITE_SCOPE_NULL;
    if (scope->count == 0 || scope->count > VCS_ZCODE_WRITE_SCOPE_MAX_PATHS)
        return VCS_ZCODE_WRITE_SCOPE_SHAPE;
    for (size_t i = 0; i < scope->count; i++) {
        if (!scope_path_valid(scope->paths[i]) ||
            (i > 0 && strcmp(scope->paths[i - 1u], scope->paths[i]) >= 0))
            return VCS_ZCODE_WRITE_SCOPE_SHAPE;
    }
    return VCS_ZCODE_WRITE_SCOPE_OK;
}

enum vcs_zcode_write_scope_result vcs_zcode_write_scope_serialize(
    const struct vcs_zcode_write_scope_v1 *scope,
    uint8_t **wire_out, size_t *wire_len)
{
    if (!wire_out || !wire_len) return VCS_ZCODE_WRITE_SCOPE_NULL;
    *wire_out = NULL; *wire_len = 0;
    enum vcs_zcode_write_scope_result valid =
        vcs_zcode_write_scope_validate(scope);
    if (valid != VCS_ZCODE_WRITE_SCOPE_OK) return valid;
    size_t total = VCS_ZCODE_WRITE_SCOPE_HEADER_BYTES;
    for (size_t i = 0; i < scope->count; i++)
        total += 2u + strlen(scope->paths[i]);
    if (total > VCS_ZCODE_WRITE_SCOPE_WIRE_MAX)
        return VCS_ZCODE_WRITE_SCOPE_LIMIT;
    uint8_t *wire = zcl_malloc(total, "zcode.write_scope");
    if (!wire) return VCS_ZCODE_WRITE_SCOPE_ALLOC;
    memcpy(wire, scope_magic, 8);
    vcs_wr_u16le(wire + 8, VCS_ZCODE_WRITE_SCOPE_VERSION);
    vcs_wr_u16le(wire + 10, (uint16_t)scope->count);
    vcs_wr_u32le(wire + 12, 0);
    size_t off = VCS_ZCODE_WRITE_SCOPE_HEADER_BYTES;
    for (size_t i = 0; i < scope->count; i++) {
        size_t len = strlen(scope->paths[i]);
        vcs_wr_u16le(wire + off, (uint16_t)len); off += 2;
        memcpy(wire + off, scope->paths[i], len); off += len;
    }
    *wire_out = wire; *wire_len = total;
    return VCS_ZCODE_WRITE_SCOPE_OK;
}

enum vcs_zcode_write_scope_result vcs_zcode_write_scope_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_write_scope_v1 *out)
{
    if (!wire || !out) return VCS_ZCODE_WRITE_SCOPE_NULL;
    vcs_zcode_write_scope_init(out);
    if (wire_len < VCS_ZCODE_WRITE_SCOPE_HEADER_BYTES ||
        wire_len > VCS_ZCODE_WRITE_SCOPE_WIRE_MAX ||
        memcmp(wire, scope_magic, 8) != 0 ||
        vcs_rd_u16le(wire + 8) != VCS_ZCODE_WRITE_SCOPE_VERSION ||
        vcs_rd_u32le(wire + 12) != 0)
        return VCS_ZCODE_WRITE_SCOPE_SHAPE;
    uint16_t count = vcs_rd_u16le(wire + 10);
    if (count == 0 || count > VCS_ZCODE_WRITE_SCOPE_MAX_PATHS)
        return VCS_ZCODE_WRITE_SCOPE_SHAPE;
    size_t off = VCS_ZCODE_WRITE_SCOPE_HEADER_BYTES;
    for (size_t i = 0; i < count; i++) {
        if (wire_len - off < 2u) return VCS_ZCODE_WRITE_SCOPE_SHAPE;
        uint16_t len = vcs_rd_u16le(wire + off); off += 2;
        if (len == 0 || len > VCS_ZCODE_WRITE_SCOPE_PATH_MAX ||
            len > wire_len - off)
            return VCS_ZCODE_WRITE_SCOPE_SHAPE;
        memcpy(out->paths[i], wire + off, len);
        out->paths[i][len] = '\0'; off += len;
    }
    out->count = count;
    if (off != wire_len) return VCS_ZCODE_WRITE_SCOPE_SHAPE;
    return vcs_zcode_write_scope_validate(out);
}

enum vcs_zcode_write_scope_result vcs_zcode_write_scope_root(
    const struct vcs_zcode_write_scope_v1 *scope, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_WRITE_SCOPE_NULL;
    uint8_t *wire = NULL; size_t wire_len = 0;
    enum vcs_zcode_write_scope_result result =
        vcs_zcode_write_scope_serialize(scope, &wire, &wire_len);
    if (result != VCS_ZCODE_WRITE_SCOPE_OK) return result;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = VCS_ZCODE_WRITE_SCOPE_DOMAIN;
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
    free(wire);
    return VCS_ZCODE_WRITE_SCOPE_OK;
}

bool vcs_zcode_write_scope_contains(
    const struct vcs_zcode_write_scope_v1 *scope, const char *path)
{
    if (vcs_zcode_write_scope_validate(scope) != VCS_ZCODE_WRITE_SCOPE_OK ||
        !vcs_package_path_valid(path))
        return false;
    for (size_t i = 0; i < scope->count; i++) {
        size_t len = strlen(scope->paths[i]);
        if (strncmp(path, scope->paths[i], len) == 0 &&
            (path[len] == '\0' || path[len] == '/'))
            return true;
    }
    return false;
}

bool vcs_zcode_write_scope_overlaps(
    const struct vcs_zcode_write_scope_v1 *a,
    const struct vcs_zcode_write_scope_v1 *b)
{
    if (vcs_zcode_write_scope_validate(a) != VCS_ZCODE_WRITE_SCOPE_OK ||
        vcs_zcode_write_scope_validate(b) != VCS_ZCODE_WRITE_SCOPE_OK)
        return false;
    for (size_t i = 0; i < a->count; i++)
        if (vcs_zcode_write_scope_contains(b, a->paths[i]))
            return true;
    for (size_t i = 0; i < b->count; i++)
        if (vcs_zcode_write_scope_contains(a, b->paths[i]))
            return true;
    return false;
}
