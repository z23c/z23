/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Shared internals of the fixed result.c receiver: the inputs it
 *          measures in the generation (profile, fresh -E, source content)
 *          and the bounded file helpers both halves use. Not a public API. */
#ifndef ZCL_TOOLS_DEV_VERIFY_RECEIVER_INTERNAL_H
#define ZCL_TOOLS_DEV_VERIFY_RECEIVER_INTERNAL_H

#include "verify_receiver.h"
#include "verify/fixed_result_contract.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VR_PROFILE_TOKENS ZCL_FR_PROFILE_ARGC
#define VR_PROFILE_MAX 65536u
#define VR_OBJECT_MAX (8u * 1024u * 1024u)
#define VR_DEP_MAX (4u * 1024u * 1024u)
#define VR_PP_MAX (16u * 1024u * 1024u)
#define VR_LOG_MAX (16u * 1024u * 1024u)
#define VR_TOKEN_MAX 8192u

struct vr_bytes {
    uint8_t *p;
    size_t n;
};

/* The pinned profile, its fixed tokens with @CWD@ expanded once to the
 * generation's physical cwd. Tokens point into `text` or `expanded`. */
struct vr_profile {
    uint8_t text[VR_PROFILE_MAX + 1u];
    size_t len;
    char expanded[VR_TOKEN_MAX];
    char *tokens[VR_PROFILE_TOKENS + 1u];
};

/* Read a regular, single-link file of at most `limit` bytes, opened with
 * O_NOFOLLOW beneath `dir_fd`. Returns NULL or a token. */
const char *vr_read_at(int dir_fd, const char *name, size_t limit,
                       struct vr_bytes *out);
/* Create `name` beneath `dir_fd` exclusively (0600) with these bytes. */
bool vr_write_at(int dir_fd, const char *name, const void *bytes,
                 size_t len);

/* Read the regular file `rel` names beneath `root_fd` (zcl_fr_open_beneath:
 * no link followed) whole, checked unchanged across the read. */
const char *vr_read_beneath(int root_fd, const char *rel, size_t limit,
                            struct vr_bytes *out);

/* A root-owned, non-writable file down a root-owned, non-writable chain,
 * opened one component at a time. Returns NULL or a token. */
const char *vr_read_root_owned(const char *absolute, size_t limit,
                               struct vr_bytes *out);

/* Check the digest and shape and expand @CWD@. Returns NULL or a token. */
const char *vr_profile_load(const struct vr_bytes *bytes, const char *cwd,
                            struct vr_profile *out);

/* The receiver's own -E in `cwd` with the fixed four-entry environment and
 * the placeholder target: SHA3 of the stream and the depfile bytes. */
const char *vr_preprocess(const char *compiler, const char *cwd,
                          const struct vr_profile *profile, int work_fd,
                          const char *work, uint8_t pp_sha3[32],
                          struct vr_bytes *dep);

#endif
