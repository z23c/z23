/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood genesis wire length and coinbase message. */

#include "services/research_genesis.h"

#include "chain/chainparams.h"
#include "primitives/block.h"

#include <string.h>

_Static_assert(BLOCK_HEADER_SIZE == 140,
               "solution length follows the fixed header prefix");

static int read_one_byte_size(const uint8_t *wire, size_t wire_len, size_t *at,
                              size_t *value)
{
    if (*at >= wire_len || wire[*at] >= 253)
        return 0;
    *value = wire[*at];
    *at += 1;
    return 1;
}

static int skip_sized(const uint8_t *wire, size_t wire_len, size_t *at,
                      size_t *value)
{
    if (!read_one_byte_size(wire, wire_len, at, value) || *value == 0)
        return 0;
    if (*at + *value > wire_len)
        return 0;
    *at += *value;
    return 1;
}

static int skip_fixed(size_t wire_len, size_t *at, size_t n)
{
    if (*at + n > wire_len)
        return 0;
    *at += n;
    return 1;
}

static int push_is_text(const uint8_t *text, size_t text_len)
{
    size_t i;

    if (text_len == 0)
        return 0;
    for (i = 0; i < text_len; i++) {
        if (text[i] < 0x20 || text[i] > 0x7e)
            return 0;
    }
    return 1;
}

/* Locates the single direct push inside the genesis coinbase scriptSig.
 * Accepts only one-byte compact sizes, which is the published wire. */
static int coinbase_text(const uint8_t *wire, size_t wire_len,
                         const uint8_t **text, size_t *text_len)
{
    size_t at = BLOCK_HEADER_SIZE;
    size_t sol = 0;
    size_t tx_count = 0;
    size_t vin = 0;
    size_t script_len = 0;
    size_t push;

    if (!skip_sized(wire, wire_len, &at, &sol) || sol > MAX_SOLUTION_SIZE)
        return 0;
    if (!read_one_byte_size(wire, wire_len, &at, &tx_count) || tx_count != 1)
        return 0;
    if (!skip_fixed(wire_len, &at, 4))
        return 0;
    if (!read_one_byte_size(wire, wire_len, &at, &vin) || vin != 1)
        return 0;
    if (!skip_fixed(wire_len, &at, 36))
        return 0;
    if (!read_one_byte_size(wire, wire_len, &at, &script_len) || script_len < 2)
        return 0;
    if (at + script_len > wire_len)
        return 0;
    push = wire[at];
    if (push + 1 != script_len || !push_is_text(wire + at + 1, push))
        return 0;
    *text = wire + at + 1;
    *text_len = push;
    return 1;
}

struct zcl_result research_genesis_read(size_t *wire_len, char *message,
                                        size_t message_cap)
{
    const struct chain_research_descriptor *d;
    const uint8_t *text;
    size_t text_len;

    if (!wire_len || !message)
        return ZCL_ERR(-1, "Missing genesis");
    if (message_cap == 0)
        return ZCL_ERR(-2, "Genesis cap refused");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->genesis_wire || d->genesis_wire_len == 0)
        return ZCL_ERR(-3, "Research genesis missing");
    if (!coinbase_text(d->genesis_wire, d->genesis_wire_len, &text, &text_len))
        return ZCL_ERR(-4, "Genesis message refused");
    if (text_len + 1 > message_cap)
        return ZCL_ERR(-4, "Genesis message refused");
    *wire_len = d->genesis_wire_len;
    memcpy(message, text, text_len);
    message[text_len] = '\0';
    return ZCL_OK;
}
