/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Parse checked borrowed views of serialized v6 transactions.
 */
#ifndef Z23_TRANSACTION_V6_INSPECT_H
#define Z23_TRANSACTION_V6_INSPECT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct v6_span { const uint8_t *data; size_t size; };
struct v6_bundle { struct v6_span wire, anchor; uint64_t count; };
struct v6_wire_view {
    struct v6_span header, transparent, sapling_tail;
    uint64_t inputs, outputs;
    struct v6_bundle sapling_spends, sapling_outputs, orchard, ironwood;
};
enum v6_wire_error { V6_WIRE_OK, V6_WIRE_TRUNCATED, V6_WIRE_NONCANONICAL,
    V6_WIRE_HEADER, V6_WIRE_FLAGS, V6_WIRE_TRAILING };
enum v6_wire_error v6_wire_parse(const uint8_t *, size_t, struct v6_wire_view *);
/* Iterators borrow a successfully parsed view and advance once per item. */
struct v6_wire_cursor { struct v6_span remaining; uint64_t count; bool input; }; // hardening-ok: Iterator advances through bounds-checked parsed fields.
bool v6_wire_cursor_init(const struct v6_wire_view *, bool, struct v6_wire_cursor *);
bool v6_wire_cursor_next(struct v6_wire_cursor *, struct v6_span *);
#endif
