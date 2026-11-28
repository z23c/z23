/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Decode bounded v6 transaction frames into checked wire and model views.
 */
#include "primitives/transaction_v6_decode.h"

#include "base/serialize_le.h"
#include "core/serialize.h"
#include "primitives/transaction.h"
#include "primitives/transaction_v6_digest.h"
#include "primitives/transaction_v6_wire.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <string.h>

enum {
    V6_SPEND_SIZE = 3 * 32,
    V6_OUTPUT_SIZE = 3 * 32 + ZC_SAPLING_ENCCIPHERTEXT_SIZE +
        ZC_SAPLING_OUTCIPHERTEXT_SIZE
};

struct v6_sapling_parts {
    int64_t value_balance;
    struct uint256 anchor;
    const uint8_t *spend_proofs;
    const uint8_t *spend_signatures;
    const uint8_t *output_proofs;
    const uint8_t *binding_signature;
};

static bool v6_take(const uint8_t **cursor, size_t *remaining, size_t size,
                    const uint8_t **out)
{
    if (size > *remaining) return false;
    *out = *cursor;
    *cursor += size;
    *remaining -= size;
    return true;
}

static bool v6_sapling_parts(const struct v6_wire_view *view,
                             struct v6_sapling_parts *parts)
{
    memset(parts, 0, sizeof(*parts));
    size_t spends = (size_t)view->sapling_spends.count;
    size_t outputs = (size_t)view->sapling_outputs.count;
    if (!spends && !outputs) return view->sapling_tail.size == 0;

    struct byte_stream tail;
    stream_init_from_data(&tail, view->sapling_tail.data,
                          view->sapling_tail.size);
    if (!stream_read_i64_le(&tail, &parts->value_balance)) return false;
    if (spends && !stream_read_bytes(&tail, parts->anchor.data,
                                    sizeof parts->anchor.data)) return false;
    const uint8_t *cursor = tail.data + tail.read_pos;
    size_t remaining = stream_remaining(&tail);
    return v6_take(&cursor, &remaining, spends * GROTH_PROOF_SIZE,
                   &parts->spend_proofs) &&
        v6_take(&cursor, &remaining, spends * 64,
                &parts->spend_signatures) &&
        v6_take(&cursor, &remaining, outputs * GROTH_PROOF_SIZE,
                &parts->output_proofs) &&
        v6_take(&cursor, &remaining, 64, &parts->binding_signature) &&
        remaining == 0;
}

static bool v6_decode_transparent(struct transaction *tx,
                                  const struct v6_wire_view *view)
{
    if (view->inputs > MAX_TX_INPUTS || view->outputs > MAX_TX_OUTPUTS ||
        !transaction_alloc(tx, (size_t)view->inputs, (size_t)view->outputs))
        return false;

    struct v6_wire_cursor cursor;
    if (!v6_core_cursor_init(view, true, &cursor)) return false;
    for (size_t i = 0; i < tx->num_vin; ++i) {
        struct v6_span item;
        if (!v6_core_cursor_next(&cursor, &item)) return false;
        struct byte_stream input;
        stream_init_from_data(&input, item.data, item.size);
        if (!tx_in_deserialize(&tx->vin[i], &input) || stream_remaining(&input))
            return false;
    }
    if (!v6_core_cursor_init(view, false, &cursor)) return false;
    for (size_t i = 0; i < tx->num_vout; ++i) {
        struct v6_span item;
        if (!v6_core_cursor_next(&cursor, &item)) return false;
        struct byte_stream output;
        stream_init_from_data(&output, item.data, item.size);
        if (!tx_out_deserialize(&tx->vout[i], &output) || stream_remaining(&output))
            return false;
    }
    return true;
}

static bool v6_decode_spend(struct spend_description *spend, const uint8_t *raw,
                            const struct uint256 *anchor, const uint8_t *proof,
                            const uint8_t *signature)
{
    uint8_t wire[4 * 32 + GROTH_PROOF_SIZE + 64];
    memcpy(wire, raw, 32);
    memcpy(wire + 32, anchor->data, sizeof anchor->data);
    memcpy(wire + 64, raw + 32, 64);
    memcpy(wire + 128, proof, GROTH_PROOF_SIZE);
    memcpy(wire + 128 + GROTH_PROOF_SIZE, signature, 64);
    struct byte_stream input;
    stream_init_from_data(&input, wire, sizeof wire);
    return spend_description_deserialize(spend, &input) && !stream_remaining(&input);
}

static bool v6_decode_output(struct output_description *output, const uint8_t *raw,
                             const uint8_t *proof)
{
    uint8_t wire[V6_OUTPUT_SIZE + GROTH_PROOF_SIZE];
    memcpy(wire, raw, V6_OUTPUT_SIZE);
    memcpy(wire + V6_OUTPUT_SIZE, proof, GROTH_PROOF_SIZE);
    struct byte_stream input;
    stream_init_from_data(&input, wire, sizeof wire);
    return output_description_deserialize(output, &input) && !stream_remaining(&input);
}

static bool v6_sapling_allocate(struct transaction *tx, size_t spends, size_t outputs)
{
    if (spends) {
        tx->v_shielded_spend = zcl_calloc(spends, sizeof(*tx->v_shielded_spend),
                                         "tx_shielded_spend");
        if (!tx->v_shielded_spend) return false;
        tx->num_shielded_spend = spends;
    }
    if (outputs) {
        tx->v_shielded_output = zcl_calloc(outputs, sizeof(*tx->v_shielded_output),
                                          "tx_shielded_output");
        if (!tx->v_shielded_output) return false;
        tx->num_shielded_output = outputs;
    }
    return true;
}

static bool v6_decode_sapling(struct transaction *tx,
                              const struct v6_wire_view *view)
{
    if (view->sapling_spends.count > MAX_SHIELDED_SPENDS ||
        view->sapling_outputs.count > MAX_SHIELDED_OUTPUTS) return false;
    size_t spends = (size_t)view->sapling_spends.count;
    size_t outputs = (size_t)view->sapling_outputs.count;
    if (view->sapling_spends.wire.size != spends * V6_SPEND_SIZE ||
        view->sapling_outputs.wire.size != outputs * V6_OUTPUT_SIZE) return false;

    struct v6_sapling_parts parts;
    if (!v6_sapling_parts(view, &parts)) return false;
    tx->value_balance = parts.value_balance;
    if (!v6_sapling_allocate(tx, spends, outputs)) return false;

    for (size_t i = 0; i < spends; ++i) {
        if (!v6_decode_spend(&tx->v_shielded_spend[i],
                             view->sapling_spends.wire.data + i * V6_SPEND_SIZE,
                             &parts.anchor,
                             parts.spend_proofs + i * GROTH_PROOF_SIZE,
                             parts.spend_signatures + i * 64)) return false;
    }
    for (size_t i = 0; i < outputs; ++i) {
        if (!v6_decode_output(&tx->v_shielded_output[i],
                              view->sapling_outputs.wire.data + i * V6_OUTPUT_SIZE,
                              parts.output_proofs + i * GROTH_PROOF_SIZE))
            return false;
    }
    if (spends || outputs)
        memcpy(tx->binding_sig, parts.binding_signature, sizeof tx->binding_sig);
    return true;
}

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
    tx->lock_time = zcl_read_u32_le(view.header.data + 12);
    tx->expiry_height = zcl_read_u32_le(view.header.data + 16);
    if (!transaction_v6_store_wire(tx, data, consumed, max_size))
        LOG_FAIL("tx", "failed to store checked v6 wire frame of %zu bytes",
                 consumed);
    if (!v6_decode_transparent(tx, &view) || !v6_decode_sapling(tx, &view))
        LOG_FAIL("tx", "failed to populate checked v6 wire frame of %zu bytes",
                 consumed);
    struct v6_digests digests;
    if (!v6_wire_digests(&view, &digests))
        LOG_FAIL("tx", "failed to digest checked v6 wire frame of %zu bytes",
                 consumed);
    memcpy(tx->hash.data, digests.txid, sizeof tx->hash.data);

    s->read_pos += consumed;
    return true;
}
