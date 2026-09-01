/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical path scope for model-neutral ZCODE candidate writes. */

#ifndef ZCL_VCS_ZCODE_WRITE_SCOPE_H
#define ZCL_VCS_ZCODE_WRITE_SCOPE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_WRITE_SCOPE_VERSION 1u
#define VCS_ZCODE_WRITE_SCOPE_DOMAIN "zcl.zcode.write_scope.v1"
#define VCS_ZCODE_WRITE_SCOPE_HEADER_BYTES 16u
#define VCS_ZCODE_WRITE_SCOPE_MAX_PATHS 64u
#define VCS_ZCODE_WRITE_SCOPE_PATH_MAX 255u
#define VCS_ZCODE_WRITE_SCOPE_WIRE_MAX \
    (VCS_ZCODE_WRITE_SCOPE_HEADER_BYTES + \
     VCS_ZCODE_WRITE_SCOPE_MAX_PATHS * \
        (2u + VCS_ZCODE_WRITE_SCOPE_PATH_MAX))

enum vcs_zcode_write_scope_result {
    VCS_ZCODE_WRITE_SCOPE_OK = 0,
    VCS_ZCODE_WRITE_SCOPE_NULL,
    VCS_ZCODE_WRITE_SCOPE_SHAPE,
    VCS_ZCODE_WRITE_SCOPE_LIMIT,
    VCS_ZCODE_WRITE_SCOPE_ALLOC,
};

struct vcs_zcode_write_scope_v1 {
    size_t count;
    char paths[VCS_ZCODE_WRITE_SCOPE_MAX_PATHS]
              [VCS_ZCODE_WRITE_SCOPE_PATH_MAX + 1u];
};

const char *vcs_zcode_write_scope_result_string(
    enum vcs_zcode_write_scope_result result);
void vcs_zcode_write_scope_init(struct vcs_zcode_write_scope_v1 *scope);
enum vcs_zcode_write_scope_result vcs_zcode_write_scope_add(
    struct vcs_zcode_write_scope_v1 *scope, const char *path_prefix);
enum vcs_zcode_write_scope_result vcs_zcode_write_scope_validate(
    const struct vcs_zcode_write_scope_v1 *scope);
enum vcs_zcode_write_scope_result vcs_zcode_write_scope_serialize(
    const struct vcs_zcode_write_scope_v1 *scope,
    uint8_t **wire, size_t *wire_len);
enum vcs_zcode_write_scope_result vcs_zcode_write_scope_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_write_scope_v1 *out);
enum vcs_zcode_write_scope_result vcs_zcode_write_scope_root(
    const struct vcs_zcode_write_scope_v1 *scope, uint8_t out[32]);

/* A prefix names either one exact path or a directory and everything below
 * it. Component boundaries are mandatory: scope "src" admits "src/a.c" but
 * not "src-old/a.c". */
bool vcs_zcode_write_scope_contains(
    const struct vcs_zcode_write_scope_v1 *scope, const char *path);

/* True when either canonical scope grants a path prefix also granted by the
 * other.  This is a collision predicate only: it does not establish an
 * owner, assignment, lease, or active execution. */
bool vcs_zcode_write_scope_overlaps(
    const struct vcs_zcode_write_scope_v1 *a,
    const struct vcs_zcode_write_scope_v1 *b);

#endif /* ZCL_VCS_ZCODE_WRITE_SCOPE_H */
