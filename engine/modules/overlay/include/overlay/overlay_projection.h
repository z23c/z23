/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Overlay SDK — rebuildable-projection scaffold + the shared lokad registry
 * and explorer-ingestion seam.
 *
 * Every on-chain overlay (ZNAM/ZSLP/ZMSG/ZANC) maintains a rebuildable
 * projection: a table folded from confirmed OP_RETURN outputs, never
 * authoritative, keyed on txid, idempotent (INSERT OR REPLACE), and never
 * fatal on a write failure. Each overlay registers ONE descriptor — its 4-byte
 * lokad tag, a human name, and an `apply` callback that projects a matching
 * confirmed OP_RETURN into the overlay's table.
 *
 * The registry (a caller-owned table, like rpc_table) is the single place that
 * enumerates every overlay by lokad tag. overlay_ingest is the explorer-index
 * seam: peek an OP_RETURN's lokad, look it up, dispatch its apply. The apply
 * callback lives in the app layer (it touches ActiveRecord models); this lib
 * stays pure and only forward-declares the opaque node_db/transaction handles.
 *
 * To keep the registry decoupled from any single subsystem's headers, the
 * apply callback receives the raw script bytes; each overlay re-parses with its
 * own codec (built on overlay/overlay_codec.h) inside apply. This mirrors how
 * explorer_index.c already dispatches, but as a registry instead of a hand-
 * rolled if-chain — so adding an overlay is a registration, not a code edit to
 * the dispatcher. */

#ifndef ZCL_OVERLAY_PROJECTION_H
#define ZCL_OVERLAY_PROJECTION_H

#include "overlay/overlay_codec.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;
struct transaction;

/* Project one confirmed overlay OP_RETURN into its rebuildable table.
 *   ndb    — the open node database (projection target).
 *   tx     — the confirming transaction (for its txid / outputs).
 *   script — the OP_RETURN scriptPubKey bytes (lokad already matched).
 *   height — the confirming block height.
 *   ctx    — the descriptor's opaque context pointer.
 * Must be idempotent (keyed on txid) and never fatal: on a write failure it
 * logs and returns false. Returns true on a successful projection. */
typedef bool (*overlay_apply_fn)(struct node_db *ndb,
                                 const struct transaction *tx,
                                 const uint8_t *script, size_t script_len,
                                 int height, void *ctx);

/* One overlay's registration. `name` and `ctx` are borrowed, not copied by
 * value beyond the pointer — keep them alive for the registry's lifetime. */
struct overlay_descriptor {
    char lokad[OVERLAY_LOKAD_LEN];
    const char *name;
    overlay_apply_fn apply;
    void *ctx;
};

/* Caller-owned registry. Fixed capacity — there are only a handful of overlays
 * and the set is compile-time known; a bounded table keeps this alloc-free. */
#define OVERLAY_REGISTRY_MAX 16
struct overlay_registry {
    struct overlay_descriptor entries[OVERLAY_REGISTRY_MAX];
    size_t count;
};

/* Zero the registry to empty. */
void overlay_registry_init(struct overlay_registry *reg);

/* Register one overlay. Rejects a NULL/missing apply, a NULL/mis-sized name,
 * a duplicate lokad tag, or an overflow of OVERLAY_REGISTRY_MAX. The lokad tag
 * is 1-4 non-NUL bytes NUL-padded to four — trailing padding is what the chain
 * carries for the SLP-lineage three-character tags ("SLP\0", "ZID\0"), while an
 * EMBEDDED NUL (a leading NUL, or a NUL followed by a non-NUL) is refused.
 * Returns true on success. */
bool overlay_registry_add(struct overlay_registry *reg,
                          const struct overlay_descriptor *desc);

/* Look up the overlay registered for `lokad`, or NULL if none. */
const struct overlay_descriptor *
overlay_registry_find(const struct overlay_registry *reg,
                      const char lokad[OVERLAY_LOKAD_LEN]);

/* Number of registered overlays. */
size_t overlay_registry_count(const struct overlay_registry *reg);

/* Peek an OP_RETURN script's lokad tag without a full parse: verifies the
 * 0x6a prefix and copies the first 4-byte PUSH into out_tag. Fail-anything on
 * malformed input (returns false, out_tag untouched on failure). */
bool overlay_peek_lokad(const uint8_t *script, size_t script_len,
                        char out_tag[OVERLAY_LOKAD_LEN]);

/* The explorer-ingestion seam. Peek the script's lokad, find its registered
 * overlay, and dispatch apply. Returns true iff an overlay matched AND its
 * apply succeeded. A malformed / non-overlay / unregistered script returns
 * false with no side effects. This is the one call the explorer index makes
 * per OP_RETURN to fan out to every overlay projection. */
bool overlay_ingest(const struct overlay_registry *reg, struct node_db *ndb,
                    const struct transaction *tx, const uint8_t *script,
                    size_t script_len, int height);

#endif /* ZCL_OVERLAY_PROJECTION_H */
