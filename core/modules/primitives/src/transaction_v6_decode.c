/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Decode bounded opaque v6 transaction frames from block wire streams.
 */
#include "primitives/transaction_v6_decode.h"

#include "core/serialize.h"
#include "primitives/transaction.h"
#include "primitives/transaction_v6_wire.h"
#include "util/log_macros.h"

#include <string.h>

bool transaction_v6_decode_is_prefix(const struct byte_stream *s)
{
    static const uint8_t header[8] = {
        6, 0, 0, 0x80, 0x98, 0xb6, 0x84, 0xd8
    };
    return s && !s->error && s->data && s->read_pos <= s->size &&
           stream_remaining(s) >= sizeof(header) &&
           memcmp(s->data + s->read_pos, header, sizeof(header)) == 0;
}

bool transaction_v6_decode_prefix(struct transaction *tx, struct byte_stream *s,
                                  size_t max_size)
{
    if (!tx) return false;
    transaction_init(tx);
    if (!transaction_v6_decode_is_prefix(s)) return false;

    const uint8_t *data = s->data + s->read_pos;
    struct v6_wire_view view;
    size_t consumed = 0;
    enum v6_wire_error error =
        v6_core_parse_prefix(data, stream_remaining(s), &view, &consumed);
    if (error != V6_WIRE_OK)
        LOG_FAIL("tx", "v6 wire parse failed with error %d", (int)error);
    if (consumed > max_size)
        LOG_FAIL("tx", "v6 wire size %zu exceeds limit %zu", consumed, max_size);

    tx->overwintered = true;
    tx->version = IRONWOOD_TX_VERSION;
    tx->version_group_id = IRONWOOD_VERSION_GROUP_ID;
    if (!transaction_v6_store_wire(tx, data, consumed, max_size))
        LOG_FAIL("tx", "failed to store checked v6 wire frame of %zu bytes",
                 consumed);

    s->read_pos += consumed;
    return true;
}
