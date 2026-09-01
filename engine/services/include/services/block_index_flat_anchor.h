/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A backward-compatible trailer for block_index.bin carrying one complete,
 * hash-bound header.  The flat rows intentionally omit the Equihash solution;
 * without the compiled checkpoint's complete header a fresh peer can own the
 * checkpoint hash yet remain unable to pass the bundle install gate. */

#ifndef ZCL_SERVICES_BLOCK_INDEX_FLAT_ANCHOR_H
#define ZCL_SERVICES_BLOCK_INDEX_FLAT_ANCHOR_H

#include <stddef.h>
#include <stdint.h>

#include "util/result.h"

struct block_index;
struct main_state;

/* Maximum encoded trailer: 12-byte envelope plus one canonical header. */
#define BIFA_TRAILER_MAX (12u + 4u + 32u + 32u + 32u + 4u + 4u + 32u + 9u + 1344u)

/* Capture the selected complete header while node.db is still open.  Shutdown
 * closes authoritative storage before publishing best-effort restart caches;
 * this small hash-bound value bridges that deliberate durability boundary. */
struct zcl_result block_index_flat_anchor_prepare(struct main_state *ms);

/* Select the compiled checkpoint when it is present, otherwise the highest
 * complete in-memory header (the latter keeps non-mainnet fixtures useful).
 * A node.db lookup or the prepared shutdown value supplies the checkpoint
 * solution when the memory-saving block index omitted it.  Returns encoded
 * bytes, or zero when no complete, hash-bound header is available. */
struct zcl_result block_index_flat_anchor_encode(
    struct main_state *ms, struct block_index **sorted, size_t count,
    uint8_t *out, size_t out_cap, size_t *out_len);

/* Parse an optional trailer and attach its full fixed fields + solution to the
 * already-loaded block-index row only when the canonical header hash equals
 * that row's hash.  Unknown/absent trailers are a clean no-op; a malformed or
 * unbound known trailer is refused and logged. */
struct zcl_result block_index_flat_anchor_apply(
    struct main_state *ms, const uint8_t *trailer, size_t trailer_len);

#endif /* ZCL_SERVICES_BLOCK_INDEX_FLAT_ANCHOR_H */
