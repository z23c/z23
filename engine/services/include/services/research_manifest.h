/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Checksum the Ironwood release manifest file. */
#ifndef ZCL_RESEARCH_MANIFEST_H
#define ZCL_RESEARCH_MANIFEST_H

#include "base/result.h"

#include <stddef.h>

/* Copies SHA3-256 of the bytes in path. Does not select the chain or
 * write a store. digest_cap is the byte count of digest. On failure
 * digest is left untouched. */
struct zcl_result research_manifest_read(const char *path,
                                         unsigned char *digest,
                                         size_t digest_cap);

#endif
