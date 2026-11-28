/* purpose: Recover an Ironwood frontier from authenticated canonical bodies. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_UTXO_APPLY_IRONWOOD_HISTORY_H
#define ZCL_UTXO_APPLY_IRONWOOD_HISTORY_H
#include "base/result.h"
#include "core/uint256.h"
#include "services/ironwood_note_frontier.h"
#include <stdbool.h>
#include <stddef.h>

/* Only an unavailable body uses this code; all contradictions fail separately. */
enum { UTXO_IRONWOOD_HISTORY_BODY_MISSING = -2 };
struct block;
struct block_index;
typedef bool (*ironwood_history_reader_fn)(struct block *, const struct block_index *,
                                           const char *, void *);

/* Private scratch: caller owns slots for parent height + 1 pointers, and keeps
 * the accepted parent and its indices alive until replay ends. A step scans
 * one ancestry link or authenticates one body. The cursor and event outputs
 * change only on success and can be discarded for rollback. Scan slots are
 * scratch and may be rewritten by retrying the same step. */
struct ironwood_history_cursor {
    const struct block_index *parent, *scan;
    const struct block_index **slots;
    size_t slot_count;
    int scan_height, replay_height, parent_height;
    bool scanning, complete;
    struct uint256 parent_hash, previous_hash;
    struct ironwood_note_frontier frontier;
    uint8_t root[32];
};
struct ironwood_history_event {
    bool available;
    int height;
    struct uint256 block_hash;
    uint64_t count;
    uint8_t root[32];
};

struct zcl_result utxo_ironwood_history_begin(const struct block_index *parent,
    const struct block_index **slots, size_t slot_count, struct ironwood_history_cursor *out);
/* Reader NULL uses the normal stage disk reader. Event is available only when
 * a complete body has been authenticated and folded. A complete cursor has
 * emitted every height through the supplied accepted parent. */
struct zcl_result utxo_ironwood_history_step(const struct ironwood_history_cursor *in,
    ironwood_history_reader_fn reader, const char *datadir, void *user,
    struct ironwood_history_cursor *out, struct ironwood_history_event *event);
#endif
