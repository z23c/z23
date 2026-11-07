/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Share the guarded materializer with fully verified bundle bytes. */
#ifndef ZCL_VCS_MATERIALIZE_INTERNAL_H
#define ZCL_VCS_MATERIALIZE_INTERNAL_H
#include "vcs/vcs_manifest.h"
#include <stddef.h>
#include <stdint.h>
/* Internal: manifest and concatenated bytes have already been authenticated.
 * Destination must be fresh, empty and private, under trusted ancestors, and
 * exclusively owned by the caller until completion. No concurrent mutation
 * or hostile ancestor replacement is supported by the pathname writer.
 * Does not flush, create CAS, or overwrite. I/O failure may leave partial
 * output for caller cleanup. Windows refuses pending equivalent qualification. */
int vcs_materialize_verified_bytes_disposable(const struct vcs_manifest *tree,
    const uint8_t *bytes, size_t length, const char *destination);
#endif
