/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Forward research v6 inspection to the checked core wire parser.
 */
#include "controllers/transaction_v6_inspect.h"
bool v6_bundle_action(const struct v6_bundle *b, uint64_t i, struct v6_action_view *out)
{
    return v6_core_bundle_action(b, i, out);
}
enum v6_wire_error v6_wire_parse(const uint8_t *b, size_t n, struct v6_wire_view *out)
{
    return v6_core_parse(b, n, out);
}
enum v6_wire_error v6_wire_parse_prefix(const uint8_t *b, size_t n,
                                        struct v6_wire_view *out, size_t *consumed)
{
    return v6_core_parse_prefix(b, n, out, consumed);
}
bool v6_ironwood_statement(const struct v6_wire_view *v, uint64_t i, uint8_t *out, size_t n)
{
    return v6_core_ironwood_statement(v, i, out, n);
}
bool v6_wire_cursor_init(const struct v6_wire_view *v, bool input, struct v6_wire_cursor *c)
{
    return v6_core_cursor_init(v, input, c);
}
bool v6_wire_cursor_next(struct v6_wire_cursor *c, struct v6_span *out)
{
    return v6_core_cursor_next(c, out);
}
