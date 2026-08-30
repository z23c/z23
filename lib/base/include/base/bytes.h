/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * bytes — the one branchless "is this buffer all zero" test in the tree.
 *
 * WHY THIS EXISTS
 * ---------------
 * The same six-line helper was written 119 times under 20-odd names
 * (bytes_nonzero, root_nonzero, exec_root_nonzero, shf_nonzero,
 * digest_nonzero, mapping_root_nonzero, zero_bytes, bytes_zero, ...).
 * Every copy is the same accumulate-then-compare, and every copy is a place
 * where the next person gets the polarity backwards.
 *
 * THE POLARITY IS THE WHOLE POINT
 * -------------------------------
 * Of the 119 copies, 103 returned `any != 0` and 13 returned `any == 0`.
 * They are opposite predicates that look identical at a glance, which is
 * exactly why they must not share one name. There are two functions here and
 * each says in its name what it answers, so a call site reads correctly
 * without the reader going to find the body.
 *
 * NULL AND ZERO LENGTH FAIL CLOSED, AND THAT DECIDED THE SIGNATURES
 * -----------------------------------------------------------------
 * The copies disagreed about NULL. One guarded inside the loop condition and
 * so answered "all zero: true". Several had no guard at all and would simply
 * dereference it. Picking the other answer — "a NULL buffer is not all
 * zero" — would read at a call site as "this root has content", and a caller
 * that rejects zero roots would then ACCEPT a NULL one. That is fail-open,
 * so it is not the answer chosen here.
 *
 *   zcl_bytes_any_set(NULL, n)   is false — nothing is set
 *   zcl_bytes_all_zero(NULL, n)  is true  — nothing is non-zero
 *
 * Both directions therefore fail closed on NULL, they are exact negations of
 * each other for every input including NULL and length 0, and the copies that
 * had no guard stop being undefined behaviour.
 *
 * BRANCHLESS ON PURPOSE
 * ---------------------
 * These are called on hashes, roots and commitments. The accumulate-with-OR
 * form does not branch on the bytes and does not return on the first non-zero
 * one, so its timing does not depend on WHERE the buffer stops being zero. A
 * memcmp against a zero buffer would be shorter and would give that property
 * away, because memcmp is free to return early. Do not "simplify" these into
 * one call to something else.
 */

#ifndef ZCL_BASE_BYTES_H
#define ZCL_BASE_BYTES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* True when at least one of `len` bytes is non-zero. Does not branch on the
 * contents and does not stop early. False for a NULL buffer and for len 0. */
static inline bool zcl_bytes_any_set(const uint8_t *bytes, size_t len)
{
    uint8_t any = 0;
    for (size_t i = 0; bytes && i < len; i++)
        any |= bytes[i];
    return any != 0;
}

/* True when every one of `len` bytes is zero. The exact negation of
 * zcl_bytes_any_set for every input, NULL and len 0 included. */
static inline bool zcl_bytes_all_zero(const uint8_t *bytes, size_t len)
{
    return !zcl_bytes_any_set(bytes, len);
}

#endif /* ZCL_BASE_BYTES_H */
