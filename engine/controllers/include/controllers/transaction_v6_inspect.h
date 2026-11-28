/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Inspect checked borrowed views of serialized v6 transactions.
 */
#ifndef Z23_TRANSACTION_V6_INSPECT_H
#define Z23_TRANSACTION_V6_INSPECT_H
#include "primitives/transaction_v6_wire.h"
bool v6_bundle_action(const struct v6_bundle *, uint64_t, struct v6_action_view *);
enum v6_wire_error v6_wire_parse(const uint8_t *, size_t, struct v6_wire_view *);
enum v6_wire_error v6_wire_parse_prefix(const uint8_t *, size_t, struct v6_wire_view *, size_t *);
bool v6_ironwood_statement(const struct v6_wire_view *, uint64_t, uint8_t *, size_t);
bool v6_wire_cursor_init(const struct v6_wire_view *, bool, struct v6_wire_cursor *);
bool v6_wire_cursor_next(struct v6_wire_cursor *, struct v6_span *);
#endif
