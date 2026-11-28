/* purpose: Compute v6 shielded sighashes from authenticated prevout context. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "controllers/transaction_v6_sighash.h"
#include "crypto/blake2b.h"
#include "base/serialize_le.h"
#include "core/serialize.h"
#include "core/amount.h"
#include "script/script.h"
#include "util/log_macros.h"
#include <limits.h>
#include <string.h>
enum { HEADER = 20, PREVOUT = 36, SEQUENCE = 4 };
#define CHECK(x) do { if (!(x)) return false; } while (0)
static bool start(struct blake2b_ctx *h, const char name[16])
{ return blake2b_init_salt_personal(h, 32, NULL, 0, NULL, (const uint8_t *)name) == 0; }
static bool add(struct blake2b_ctx *h, const void *p, size_t n)
{ return !n || blake2b_update(h, p, n) == 0; }
static bool finish(struct blake2b_ctx *h, uint8_t out[32])
{ return blake2b_final(h, out, 32) == 0; }
static bool child(struct blake2b_ctx *parent, struct blake2b_ctx *nested)
{
    uint8_t out[32];
    return finish(nested, out) && add(parent, out, sizeof out);
}

/* ZIP 244 S.2: scriptPubKeys are serialized with CompactSize lengths. */
static bool sighash_script(struct blake2b_ctx *hash, struct v6_span script_bytes)
{
    if (script_bytes.size > MAX_SCRIPT_SIZE || (script_bytes.size && !script_bytes.data)) return false;
    struct byte_stream prefix;
    stream_init(&prefix, 9);
    bool ok = stream_write_compact_size(&prefix, script_bytes.size) &&
        add(hash, prefix.data, prefix.size) && add(hash, script_bytes.data, script_bytes.size);
    stream_free(&prefix);
    return ok;
}

static bool sighash_coinbase(const struct v6_wire_view *v, bool *coinbase)
{
    *coinbase = false;
    if (v->inputs != 1) return true;
    struct v6_wire_cursor c; struct v6_span input;
    if (!v6_core_cursor_init(v, true, &c) || !v6_core_cursor_next(&c, &input) || input.size < PREVOUT)
        LOG_FAIL("tx", "Cannot inspect transparent input for shielded signature hash");
    static const uint8_t null_prevout[36] = {
        [32] = 0xff, [33] = 0xff, [34] = 0xff, [35] = 0xff
    };
    *coinbase = memcmp(input.data, null_prevout, sizeof null_prevout) == 0;
    return true;
}

static bool sighash_inputs(const struct v6_wire_view *v, const struct v6_prevout *prevouts,
                           struct blake2b_ctx *prev, struct blake2b_ctx *seq,
                           struct blake2b_ctx *amounts, struct blake2b_ctx *scripts)
{
    struct v6_wire_cursor c; struct v6_span item;
    CHECK(v6_core_cursor_init(v, true, &c));
    for (size_t i = 0; c.count; ++i) {
        CHECK(v6_core_cursor_next(&c, &item));
        if (item.size < PREVOUT + SEQUENCE || prevouts[i].amount > (uint64_t)MAX_MONEY) return false;
        CHECK(add(prev, item.data, PREVOUT));
        CHECK(add(seq, item.data + item.size - SEQUENCE, SEQUENCE));
        uint8_t value[8]; zcl_write_u64_le(value, prevouts[i].amount);
        CHECK(add(amounts, value, sizeof value)); CHECK(sighash_script(scripts, prevouts[i].script_pubkey));
    }
    return true;
}

static bool sighash_transparent(const struct v6_wire_view *v, const struct v6_prevout *prevouts,
                                uint8_t out[32])
{
    struct blake2b_ctx root, prev, seq, amounts, scripts, outputs, input;
    CHECK(start(&root, "ZTxIdTranspaHash")); CHECK(start(&prev, "ZTxIdPrevoutHash"));
    CHECK(start(&seq, "ZTxIdSequencHash")); CHECK(start(&amounts, "ZTxTrAmountsHash"));
    CHECK(start(&scripts, "ZTxTrScriptsHash")); CHECK(start(&outputs, "ZTxIdOutputsHash"));
    CHECK(start(&input, "Zcash___TxInHash"));
    CHECK(sighash_inputs(v, prevouts, &prev, &seq, &amounts, &scripts));
    struct v6_wire_cursor c; struct v6_span item;
    CHECK(v6_core_cursor_init(v, false, &c));
    while (c.count) { CHECK(v6_core_cursor_next(&c, &item)); CHECK(add(&outputs, item.data, item.size)); }
    const uint8_t hash_type = 1; /* Shielded signatures always use SIGHASH_ALL. */
    CHECK(add(&root, &hash_type, 1)); CHECK(child(&root, &prev)); CHECK(child(&root, &amounts));
    CHECK(child(&root, &scripts)); CHECK(child(&root, &seq)); CHECK(child(&root, &outputs));
    CHECK(child(&root, &input));
    return finish(&root, out);
}

bool v6_shielded_sighash(const struct v6_wire_view *v, const struct v6_prevout *prevouts,
                         size_t count, uint8_t out[32])
{
    if (!v || !out) return false;
    bool coinbase;
    struct v6_digests d;
    if (!sighash_coinbase(v, &coinbase) || !v6_wire_digests(v, &d)) return false;
    if (!v->inputs || coinbase) {
        if (count || prevouts) return false;
        memcpy(out, d.txid, 32);
        return true;
    }
    if (!prevouts || v->inputs > SIZE_MAX || count > SIZE_MAX / sizeof *prevouts || count != (size_t)v->inputs) return false;
    uint8_t transparent_hash[32], result[32];
    if (!sighash_transparent(v, prevouts, transparent_hash)) return false;
    struct blake2b_ctx root, header;
    char name[16] = "ZcashTxHash_";
    memcpy(name + 12, v->header.data + 8, 4);
    CHECK(start(&root, name)); CHECK(start(&header, "ZTxIdHeadersHash"));
    CHECK(add(&header, v->header.data, HEADER)); CHECK(child(&root, &header));
    CHECK(add(&root, transparent_hash, 32)); CHECK(add(&root, d.sapling_effect, 32));
    CHECK(add(&root, d.orchard_effect, 32)); CHECK(add(&root, d.ironwood_effect, 32));
    CHECK(finish(&root, result));
    memcpy(out, result, sizeof result);
    return true;
}
