/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Parse checked borrowed views of serialized v6 transactions.
 */
#ifndef Z23_TRANSACTION_V6_WIRE_H
#define Z23_TRANSACTION_V6_WIRE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct v6_span { const uint8_t *data; size_t size; };
struct v6_bundle {
    struct v6_span wire, anchor, actions, value_balance;
    uint64_t count;
    struct v6_span flags, proof, signatures, binding_signature;
};
struct v6_action_view { struct v6_span nullifier, cmx, cv, rk, signature; };
/* Borrow checked public fields from a successfully parsed nonempty bundle;
 * output remains unchanged on failure and bytes live with the input wire. */
bool v6_core_bundle_action(const struct v6_bundle *, uint64_t, struct v6_action_view *);
struct v6_wire_view {
    struct v6_span header, transparent, sapling_tail;
    uint64_t inputs, outputs;
    struct v6_bundle sapling_spends, sapling_outputs, orchard, ironwood;
};
enum v6_wire_error { V6_WIRE_OK, V6_WIRE_TRUNCATED, V6_WIRE_NONCANONICAL,
    V6_WIRE_HEADER, V6_WIRE_FLAGS, V6_WIRE_TRAILING };
enum v6_wire_error v6_core_parse(const uint8_t *, size_t, struct v6_wire_view *);
/* A prefix succeeds only after one full frame; consumed is zero on failure. */
enum v6_wire_error v6_core_parse_prefix(const uint8_t *, size_t, struct v6_wire_view *, size_t *);
/* Project one parsed Ironwood action into a 163-byte verifier statement.
 * Output remains unchanged on failure; no cryptographic validity is implied. */
enum { V6_IRONWOOD_STATEMENT_SIZE = 163 };
bool v6_core_ironwood_statement(const struct v6_wire_view *, uint64_t, uint8_t *, size_t);
/* Iterators borrow a successfully parsed view and advance once per item. */
struct v6_wire_cursor { struct v6_span remaining; uint64_t count; bool input; }; // hardening-ok: Iterator advances through bounds-checked parsed fields.
bool v6_core_cursor_init(const struct v6_wire_view *, bool, struct v6_wire_cursor *);
bool v6_core_cursor_next(struct v6_wire_cursor *, struct v6_span *);
#endif
