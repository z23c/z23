/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared between the two halves of the proving-parameter fetcher:
 *
 *   params_fetch.c          the trust root — the pin table, the Merkle
 *                           construction, and everything that answers
 *                           "do these bytes match what is compiled in?"
 *   params_fetch_session.c  the machinery that acts on those answers —
 *                           the resumable download session and the serve
 *                           side.
 *
 * The split is along that line deliberately. Everything in the first file is
 * a pure function of its inputs and the compiled-in table, and can be reasoned
 * about without a filesystem; everything in the second file has state. The
 * helpers below are the small pieces the second half needs from the first.
 *
 * NOT a public header — only the two params_fetch*.c files include it.
 */

#ifndef ZCL_SAPLING_PARAMS_FETCH_INTERNAL_H
#define ZCL_SAPLING_PARAMS_FETCH_INTERNAL_H

#include "sapling/params_fetch.h"

/* Parse a 64-character lowercase-or-uppercase hex digest. False on any
 * non-hex byte or a wrong length — a malformed pinned constant must fail
 * closed, never silently become a zero digest that something could match. */
bool zcl_pf_hex_to_32(const char *hex, uint8_t out[ZCL_PARAM_HASH_BYTES]);

/* 32-byte compare that does not short-circuit on the first differing byte. */
bool zcl_pf_digest_equal(const uint8_t a[ZCL_PARAM_HASH_BYTES],
                         const uint8_t b[ZCL_PARAM_HASH_BYTES]);

/* True when file_idx addresses a real entry in the pin table. Every wire
 * value that names a file passes through here first. */
bool zcl_pf_pin_valid(int file_idx);

/* ceil(bytes / ZCL_PARAM_CHUNK_BYTES) for a pinned file, or 0 if that would
 * exceed ZCL_PARAM_MAX_CHUNKS. This is the ONLY source of a chunk count used
 * to size anything; a count that arrived from a peer is compared against it
 * and never substituted for it. */
uint32_t zcl_pf_derived_chunk_count(const struct zcl_param_pin *p);

/* dir + "/" + name + suffix, always NUL-terminated within cap. `name` is
 * always a pin-table constant, never a wire string. */
void zcl_pf_join_path(char *dst, size_t cap, const char *dir, const char *name,
                      const char *suffix);

#endif /* ZCL_SAPLING_PARAMS_FETCH_INTERNAL_H */
