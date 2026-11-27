/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Parse checked borrowed views of serialized v6 transactions.
 */
#include "controllers/transaction_v6_inspect.h"
#include "base/serialize_le.h"
#include <string.h>
/* Fixed wire widths in bytes, excluding CompactSize prefixes. */
enum { V6_HEADER = 20, PREVOUT = 36, SEQUENCE = 4, AMOUNT = 8,
       SAPLING_SPEND = 96, SAPLING_OUTPUT = 756, PROOF = 192,
       SIGNATURE = 64, ANCHOR = 32, ACTION = 820 };
struct reader { const uint8_t *p; size_t left; enum v6_wire_error error; };
static struct v6_span take(struct reader *r, uint64_t count, size_t width)
{
    struct v6_span s = {0};
    if (r->error) return s;
    if (!width || count > r->left / width) { r->error = V6_WIRE_TRUNCATED; return s; }
    s.data = r->p; s.size = (size_t)count * width;
    r->p += s.size; r->left -= s.size;
    return s;
}
static uint64_t compact(struct reader *r)
{
    struct v6_span tag = take(r, 1, 1);
    if (r->error) return 0;
    if (tag.data[0] < 253) return tag.data[0];
    size_t width = (size_t)1 << (tag.data[0] - 252);
    struct v6_span n = take(r, width, 1);
    if (r->error) return 0;
    uint64_t value = width == 2 ? zcl_read_u16_le(n.data) :
                     width == 4 ? zcl_read_u32_le(n.data) : zcl_read_u64_le(n.data);
    uint64_t minimum = width == 2 ? 253 : width == 4 ? 65536 : UINT64_C(4294967296);
    if (value < minimum) r->error = V6_WIRE_NONCANONICAL;
    return value;
}
static void script(struct reader *r) { uint64_t n = compact(r); (void)take(r, n, 1); }
static struct v6_span item(struct reader *r, bool input)
{
    const uint8_t *start = r->p;
    (void)take(r, input ? PREVOUT : AMOUNT, 1); script(r);
    if (input) (void)take(r, SEQUENCE, 1);
    return (struct v6_span){start, (size_t)(r->p - start)};
}
static void transparent(struct reader *r, struct v6_wire_view *v)
{
    const uint8_t *start = r->p;
    v->inputs = compact(r);
    for (uint64_t i = 0; i < v->inputs && !r->error; ++i) (void)item(r, true);
    v->outputs = compact(r);
    for (uint64_t i = 0; i < v->outputs && !r->error; ++i) (void)item(r, false);
    v->transparent = (struct v6_span){start, (size_t)(r->p - start)};
}
static void sapling(struct reader *r, struct v6_wire_view *v)
{
    v->sapling_spends.count = compact(r);
    v->sapling_spends.wire = take(r, v->sapling_spends.count, SAPLING_SPEND);
    v->sapling_outputs.count = compact(r);
    v->sapling_outputs.wire = take(r, v->sapling_outputs.count, SAPLING_OUTPUT);
    const uint8_t *start = r->p;
    if (v->sapling_spends.count || v->sapling_outputs.count) {
        (void)take(r, AMOUNT, 1);
        if (v->sapling_spends.count) (void)take(r, ANCHOR, 1);
        (void)take(r, v->sapling_spends.count, PROOF);
        (void)take(r, v->sapling_spends.count, SIGNATURE);
        (void)take(r, v->sapling_outputs.count, PROOF);
        (void)take(r, SIGNATURE, 1);
    }
    v->sapling_tail = (struct v6_span){start, (size_t)(r->p - start)};
}
static void actions(struct reader *r, struct v6_bundle *bundle, uint8_t mask)
{
    const uint8_t *start = r->p;
    bundle->count = compact(r);
    (void)take(r, bundle->count, ACTION);
    if (bundle->count && !r->error) {
        struct v6_span flags = take(r, 1, 1);
        if (!r->error && (flags.data[0] & (uint8_t)~mask)) r->error = V6_WIRE_FLAGS;
        (void)take(r, AMOUNT, 1);
        bundle->anchor = take(r, ANCHOR, 1);
        uint64_t proof = compact(r);
        (void)take(r, proof, 1);
        (void)take(r, bundle->count, SIGNATURE);
        (void)take(r, SIGNATURE, 1);
    }
    bundle->wire = (struct v6_span){start, (size_t)(r->p - start)};
}
enum v6_wire_error v6_wire_parse(const uint8_t *bytes, size_t size, struct v6_wire_view *destination)
{
    if (!destination) return V6_WIRE_TRUNCATED;
    memset(destination, 0, sizeof(*destination));
    if (!bytes) return V6_WIRE_TRUNCATED;
    struct v6_wire_view value;
    struct v6_wire_view *out = &value;
    memset(out, 0, sizeof(*out));
    struct reader r = {bytes, size, V6_WIRE_OK};
    out->header = take(&r, V6_HEADER, 1);
    static const uint8_t magic[8] = {6,0,0,128,0x98,0xb6,0x84,0xd8};
    if (r.error) return r.error;
    if (memcmp(out->header.data, magic, sizeof(magic))) return V6_WIRE_HEADER;
    transparent(&r, out); sapling(&r, out);
    actions(&r, &out->orchard, 3); actions(&r, &out->ironwood, 7);
    if (r.error) return r.error;
    if (r.left) return V6_WIRE_TRAILING;
    *destination = value;
    return V6_WIRE_OK;
}
bool v6_wire_cursor_init(const struct v6_wire_view *v, bool input,
                         struct v6_wire_cursor *cursor)
{
    if (!v || !cursor || !v->transparent.data) return false;
    struct reader r = {v->transparent.data, v->transparent.size, V6_WIRE_OK};
    uint64_t n = compact(&r);
    if (!input) {
        for (uint64_t i = 0; i < n && !r.error; ++i) (void)item(&r, true);
        n = compact(&r);
    }
    if (r.error) return false;
    *cursor = (struct v6_wire_cursor){{r.p, r.left}, n, input};
    return true;
}
bool v6_wire_cursor_next(struct v6_wire_cursor *cursor, struct v6_span *out)
{
    if (!cursor || !out || !cursor->count) return false;
    struct reader r = {cursor->remaining.data, cursor->remaining.size, V6_WIRE_OK};
    struct v6_span value = item(&r, cursor->input);
    if (r.error) return false;
    *out = value;
    cursor->remaining = (struct v6_span){r.p, r.left};
    --cursor->count;
    return true;
}
