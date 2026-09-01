/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: zswap_ceremony implementation — the zswap_accept.v1 and
 * zswap_partial.v1 wires plus the seller/buyer state-machine handlers for
 * the atomic ZSLP-token/ZCL yardsale swap. See zswap/zswap_ceremony.h for
 * the ceremony and the safety argument. Codec style mirrors
 * zswap_quote.c: named error enums, exact sizes, zeroed outputs. */

#include "zswap/zswap_ceremony.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "chain/chainparams.h"
#include "keys/key_io.h"
#include "script/sighashtype.h"
#include "script/standard.h"
#include "support/cleanse.h"
#include "zslp/slp.h"

#include <string.h>

static const uint8_t accept_magic[8] = {'Z','S','W','A','C','P','\r','\n'};
static const uint8_t partial_magic[8] = {'Z','S','W','P','T','L','\r','\n'};

#define ACCEPT_FIXED_BYTES (8u + 2u + 32u)
#define PARTIAL_FIXED_BYTES (8u + 2u + 32u + 32u + 33u + 1u + \
                             ZSWAP_SIG_FIELD_BYTES)

const char *zswap_ceremony_error_string(enum zswap_ceremony_error error)
{
    switch (error) {
    case ZSWAP_CEREMONY_OK: return "ok";
    case ZSWAP_CEREMONY_ERR_NULL: return "null-argument";
    case ZSWAP_CEREMONY_ERR_VERSION: return "schema-version";
    case ZSWAP_CEREMONY_ERR_WIRE_SIZE: return "wire-size";
    case ZSWAP_CEREMONY_ERR_WIRE_MAGIC: return "wire-magic";
    case ZSWAP_CEREMONY_ERR_ROOT_ZERO: return "root-zero";
    case ZSWAP_CEREMONY_ERR_ACCEPT: return "accept-invalid";
    case ZSWAP_CEREMONY_ERR_INPUT_ORDER: return "input-order-noncanonical";
    case ZSWAP_CEREMONY_ERR_PUBKEY: return "pubkey-field-invalid";
    case ZSWAP_CEREMONY_ERR_SIG_FIELD: return "signature-field-invalid";
    case ZSWAP_CEREMONY_ERR_SIGHASH_TYPE: return "sighash-type-not-all";
    case ZSWAP_CEREMONY_ERR_AD: return "ad-invalid";
    case ZSWAP_CEREMONY_ERR_EXPIRED: return "ceremony-expired";
    case ZSWAP_CEREMONY_ERR_QUOTE_ROOT: return "quote-root-mismatch";
    case ZSWAP_CEREMONY_ERR_DEADLINE: return "deadline-mismatch";
    case ZSWAP_CEREMONY_ERR_ASSEMBLY_ROOT: return "assembly-root-mismatch";
    case ZSWAP_CEREMONY_ERR_ASSEMBLY: return "assembly-refused";
    case ZSWAP_CEREMONY_ERR_TERMS: return "terms-mismatch";
    case ZSWAP_CEREMONY_ERR_SCRIPT_TYPE: return "script-type-unsupported";
    case ZSWAP_CEREMONY_ERR_KEY_MISMATCH: return "key-mismatch";
    case ZSWAP_CEREMONY_ERR_SIGNATURE: return "signature-invalid";
    case ZSWAP_CEREMONY_ERR_SIGN: return "signing-failed";
    case ZSWAP_CEREMONY_ERR_INPUT_INDEX: return "input-index-out-of-range";
    }
    return "unknown";
}

/* ── wire cursor helpers ───────────────────────────────────────────── */

static void put_bytes(uint8_t *wire, size_t *off, const void *src, size_t n)
{
    memcpy(wire + *off, src, n);
    *off += n;
}

static void put_u16(uint8_t *wire, size_t *off, uint16_t v)
{
    zcl_write_u16_le(wire + *off, v);
    *off += 2;
}

static bool take_bytes(const uint8_t *wire, size_t wire_len, size_t *off,
                       void *out, size_t n)
{
    if (wire_len - *off < n) return false;
    memcpy(out, wire + *off, n);
    *off += n;
    return true;
}

static bool take_u8(const uint8_t *wire, size_t wire_len, size_t *off,
                    uint8_t *out)
{
    return take_bytes(wire, wire_len, off, out, 1);
}

static bool take_u16(const uint8_t *wire, size_t wire_len, size_t *off,
                     uint16_t *out)
{
    uint8_t b[2];
    if (!take_bytes(wire, wire_len, off, b, 2)) return false;
    *out = zcl_read_u16_le(b);
    return true;
}

static bool take_u32(const uint8_t *wire, size_t wire_len, size_t *off,
                     uint32_t *out)
{
    uint8_t b[4];
    if (!take_bytes(wire, wire_len, off, b, 4)) return false;
    *out = zcl_read_u32_le(b);
    return true;
}

static bool take_u64(const uint8_t *wire, size_t wire_len, size_t *off,
                     uint64_t *out)
{
    uint8_t b[8];
    if (!take_bytes(wire, wire_len, off, b, 8)) return false;
    *out = zcl_read_u64_le(b);
    return true;
}

/* ── input parse (shared by both decoders) ─────────────────────────── */

static enum zswap_ceremony_error take_input(const uint8_t *wire,
                                            size_t wire_len, size_t *off,
                                            struct zswap_swap_input *in)
{
    uint64_t value;
    uint8_t script_len;
    if (!take_bytes(wire, wire_len, off, in->txid, 32) ||
        !take_u32(wire, wire_len, off, &in->vout) ||
        !take_u64(wire, wire_len, off, &value) ||
        !take_u8(wire, wire_len, off, &script_len))
        return ZSWAP_CEREMONY_ERR_WIRE_SIZE;
    if (value > (uint64_t)INT64_MAX || (int64_t)value <= 0)
        return ZSWAP_CEREMONY_ERR_ACCEPT;
    in->value_sats = (int64_t)value;
    in->script_len = script_len;
    if (!take_bytes(wire, wire_len, off, in->script_pub_key, script_len))
        return ZSWAP_CEREMONY_ERR_WIRE_SIZE;
    return ZSWAP_CEREMONY_OK;
}

static int outpoint_cmp_fields(const uint8_t a_txid[32], uint32_t a_vout,
                               const uint8_t b_txid[32], uint32_t b_vout)
{
    int r = memcmp(a_txid, b_txid, 32);
    if (r != 0) return r;
    if (a_vout < b_vout) return -1;
    if (a_vout > b_vout) return 1;
    return 0;
}

/* ── msg1 zswap_accept.v1 ──────────────────────────────────────────── */

enum zswap_ceremony_error zswap_accept_validate(
    const struct zswap_accept_v1 *accept)
{
    if (!accept) return ZSWAP_CEREMONY_ERR_NULL;
    if (accept->schema_version != ZSWAP_ACCEPT_VERSION)
        return ZSWAP_CEREMONY_ERR_VERSION;
    if (!zcl_bytes_any_set(accept->quote_root, 32))
        return ZSWAP_CEREMONY_ERR_ROOT_ZERO;
    if (zswap_buyer_accept_validate(&accept->buyer) != ZSWAP_ASSEMBLY_OK)
        return ZSWAP_CEREMONY_ERR_ACCEPT;
    return ZSWAP_CEREMONY_OK;
}

size_t zswap_accept_wire_size(const struct zswap_accept_v1 *accept)
{
    return ACCEPT_FIXED_BYTES +
           zswap_buyer_accept_serialized_size(&accept->buyer);
}

enum zswap_ceremony_error zswap_accept_encode(
    const struct zswap_accept_v1 *accept,
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    enum zswap_ceremony_error e = zswap_accept_validate(accept);
    if (e != ZSWAP_CEREMONY_OK || !out || !out_len)
        return (e == ZSWAP_CEREMONY_OK) ? ZSWAP_CEREMONY_ERR_NULL : e;
    size_t need = zswap_accept_wire_size(accept);
    if (out_cap < need) return ZSWAP_CEREMONY_ERR_WIRE_SIZE;
    size_t off = 0, body_len = 0;
    put_bytes(out, &off, accept_magic, sizeof(accept_magic));
    put_u16(out, &off, accept->schema_version);
    put_bytes(out, &off, accept->quote_root, 32);
    if (zswap_buyer_accept_serialize(&accept->buyer, out + off,
                                     out_cap - off, &body_len) !=
        ZSWAP_ASSEMBLY_OK)
        return ZSWAP_CEREMONY_ERR_ACCEPT;
    off += body_len;
    *out_len = off;
    return ZSWAP_CEREMONY_OK;
}

enum zswap_ceremony_error zswap_accept_decode(
    const uint8_t *wire, size_t wire_len, struct zswap_accept_v1 *out)
{
    if (!wire || !out) return ZSWAP_CEREMONY_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len < ACCEPT_FIXED_BYTES + 1 ||
        wire_len > ZSWAP_ACCEPT_WIRE_MAX_BYTES)
        return ZSWAP_CEREMONY_ERR_WIRE_SIZE;
    if (memcmp(wire, accept_magic, sizeof(accept_magic)) != 0)
        return ZSWAP_CEREMONY_ERR_WIRE_MAGIC;
    size_t off = sizeof(accept_magic);
    if (!take_u16(wire, wire_len, &off, &out->schema_version))
        return ZSWAP_CEREMONY_ERR_WIRE_SIZE;
    if (out->schema_version != ZSWAP_ACCEPT_VERSION)
        return ZSWAP_CEREMONY_ERR_VERSION;
    if (!take_bytes(wire, wire_len, &off, out->quote_root, 32))
        return ZSWAP_CEREMONY_ERR_WIRE_SIZE;

    struct zswap_buyer_accept *b = &out->buyer;
    uint8_t num_inputs = 0;
    if (!take_u8(wire, wire_len, &off, &num_inputs))
        return ZSWAP_CEREMONY_ERR_WIRE_SIZE;
    if (num_inputs == 0 || num_inputs > ZSWAP_MAX_BUYER_INPUTS)
        return ZSWAP_CEREMONY_ERR_ACCEPT;
    b->num_inputs = num_inputs;
    enum zswap_ceremony_error err = ZSWAP_CEREMONY_OK;
    for (size_t i = 0; i < b->num_inputs; i++) {
        err = take_input(wire, wire_len, &off, &b->inputs[i]);
        if (err != ZSWAP_CEREMONY_OK) goto fail;
        /* The canonical wire is sorted: anything else is a hand-rolled or
         * corrupted message, not an accept we act on. */
        if (i > 0 && outpoint_cmp_fields(b->inputs[i - 1].txid,
                                         b->inputs[i - 1].vout,
                                         b->inputs[i].txid,
                                         b->inputs[i].vout) >= 0) {
            err = ZSWAP_CEREMONY_ERR_INPUT_ORDER;
            goto fail;
        }
    }
    uint64_t fee, deadline;
    if (!take_bytes(wire, wire_len, &off, b->token_recv_address,
                    ZSWAP_ADDRESS_FIELD_BYTES) ||
        !take_bytes(wire, wire_len, &off, b->change_address,
                    ZSWAP_ADDRESS_FIELD_BYTES) ||
        !take_u64(wire, wire_len, &off, &fee) ||
        !take_u64(wire, wire_len, &off, &deadline))
        return ZSWAP_CEREMONY_ERR_WIRE_SIZE;
    if (fee > (uint64_t)INT64_MAX || deadline > (uint64_t)INT64_MAX) {
        err = ZSWAP_CEREMONY_ERR_ACCEPT;
        goto fail;
    }
    b->fee_sats = fee;
    b->deadline_unix = (int64_t)deadline;
    if (off != wire_len)
        return ZSWAP_CEREMONY_ERR_WIRE_SIZE;
    err = zswap_accept_validate(out);
    if (err != ZSWAP_CEREMONY_OK) goto fail;
    return ZSWAP_CEREMONY_OK;
fail:
    memset(out, 0, sizeof(*out));
    return err;
}

/* ── msg2 zswap_partial.v1 ─────────────────────────────────────────── */

enum zswap_ceremony_error zswap_partial_validate(
    const struct zswap_partial_v1 *partial)
{
    if (!partial) return ZSWAP_CEREMONY_ERR_NULL;
    if (partial->schema_version != ZSWAP_PARTIAL_VERSION)
        return ZSWAP_CEREMONY_ERR_VERSION;
    if (!zcl_bytes_any_set(partial->quote_root, 32) ||
        !zcl_bytes_any_set(partial->assembly_root, 32))
        return ZSWAP_CEREMONY_ERR_ROOT_ZERO;
    if (zswap_seller_accept_validate(&partial->seller) != ZSWAP_ASSEMBLY_OK)
        return ZSWAP_CEREMONY_ERR_ACCEPT;
    if (partial->seller_pubkey[0] != 0x02 && partial->seller_pubkey[0] != 0x03)
        return ZSWAP_CEREMONY_ERR_PUBKEY;
    if (!zcl_bytes_any_set(partial->seller_pubkey + 1, 32))
        return ZSWAP_CEREMONY_ERR_PUBKEY;
    if (partial->sig_len < ZSWAP_SIG_MIN_BYTES ||
        partial->sig_len > ZSWAP_SIG_FIELD_BYTES)
        return ZSWAP_CEREMONY_ERR_SIG_FIELD;
    /* Canonical zero padding past the live signature bytes. */
    for (size_t i = partial->sig_len; i < ZSWAP_SIG_FIELD_BYTES; i++)
        if (partial->signature[i] != 0)
            return ZSWAP_CEREMONY_ERR_SIG_FIELD;
    /* v1 signs SIGHASH_ALL and nothing else: the trailing byte is part of
     * the signed statement's meaning, so it is a decode-time refusal. */
    if (partial->signature[partial->sig_len - 1] != SIGHASH_ALL)
        return ZSWAP_CEREMONY_ERR_SIGHASH_TYPE;
    return ZSWAP_CEREMONY_OK;
}

size_t zswap_partial_wire_size(const struct zswap_partial_v1 *partial)
{
    return PARTIAL_FIXED_BYTES +
           zswap_seller_accept_serialized_size(&partial->seller);
}

enum zswap_ceremony_error zswap_partial_encode(
    const struct zswap_partial_v1 *partial,
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    enum zswap_ceremony_error e = zswap_partial_validate(partial);
    if (e != ZSWAP_CEREMONY_OK || !out || !out_len)
        return (e == ZSWAP_CEREMONY_OK) ? ZSWAP_CEREMONY_ERR_NULL : e;
    size_t need = zswap_partial_wire_size(partial);
    if (out_cap < need) return ZSWAP_CEREMONY_ERR_WIRE_SIZE;
    size_t off = 0, body_len = 0;
    put_bytes(out, &off, partial_magic, sizeof(partial_magic));
    put_u16(out, &off, partial->schema_version);
    put_bytes(out, &off, partial->quote_root, 32);
    put_bytes(out, &off, partial->assembly_root, 32);
    if (zswap_seller_accept_serialize(&partial->seller, out + off,
                                      out_cap - off, &body_len) !=
        ZSWAP_ASSEMBLY_OK)
        return ZSWAP_CEREMONY_ERR_ACCEPT;
    off += body_len;
    put_bytes(out, &off, partial->seller_pubkey, 33);
    out[off++] = partial->sig_len;
    put_bytes(out, &off, partial->signature, ZSWAP_SIG_FIELD_BYTES);
    *out_len = off;
    return ZSWAP_CEREMONY_OK;
}

enum zswap_ceremony_error zswap_partial_decode(
    const uint8_t *wire, size_t wire_len, struct zswap_partial_v1 *out)
{
    if (!wire || !out) return ZSWAP_CEREMONY_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len < PARTIAL_FIXED_BYTES + (32 + 4 + 8 + 1 + 1) +
                       2 * ZSWAP_ADDRESS_FIELD_BYTES + 8 ||
        wire_len > ZSWAP_PARTIAL_WIRE_MAX_BYTES)
        return ZSWAP_CEREMONY_ERR_WIRE_SIZE;
    if (memcmp(wire, partial_magic, sizeof(partial_magic)) != 0)
        return ZSWAP_CEREMONY_ERR_WIRE_MAGIC;
    size_t off = sizeof(partial_magic);
    if (!take_u16(wire, wire_len, &off, &out->schema_version))
        return ZSWAP_CEREMONY_ERR_WIRE_SIZE;
    if (out->schema_version != ZSWAP_PARTIAL_VERSION)
        return ZSWAP_CEREMONY_ERR_VERSION;
    if (!take_bytes(wire, wire_len, &off, out->quote_root, 32) ||
        !take_bytes(wire, wire_len, &off, out->assembly_root, 32))
        return ZSWAP_CEREMONY_ERR_WIRE_SIZE;

    struct zswap_seller_accept *s = &out->seller;
    enum zswap_ceremony_error err =
        take_input(wire, wire_len, &off, &s->token_input);
    if (err != ZSWAP_CEREMONY_OK) goto fail;
    uint64_t deadline;
    if (!take_bytes(wire, wire_len, &off, s->zcl_recv_address,
                    ZSWAP_ADDRESS_FIELD_BYTES) ||
        !take_bytes(wire, wire_len, &off, s->change_address,
                    ZSWAP_ADDRESS_FIELD_BYTES) ||
        !take_u64(wire, wire_len, &off, &deadline))
        return ZSWAP_CEREMONY_ERR_WIRE_SIZE;
    if (deadline > (uint64_t)INT64_MAX) {
        err = ZSWAP_CEREMONY_ERR_ACCEPT;
        goto fail;
    }
    s->deadline_unix = (int64_t)deadline;
    if (!take_bytes(wire, wire_len, &off, out->seller_pubkey, 33) ||
        !take_u8(wire, wire_len, &off, &out->sig_len) ||
        !take_bytes(wire, wire_len, &off, out->signature,
                    ZSWAP_SIG_FIELD_BYTES))
        return ZSWAP_CEREMONY_ERR_WIRE_SIZE;
    if (off != wire_len)
        return ZSWAP_CEREMONY_ERR_WIRE_SIZE;
    err = zswap_partial_validate(out);
    if (err != ZSWAP_CEREMONY_OK) goto fail;
    return ZSWAP_CEREMONY_OK;
fail:
    memset(out, 0, sizeof(*out));
    return err;
}

/* ── shared checks ─────────────────────────────────────────────────── */

/* Map the ad's time-window validation onto ceremony errors. */
static enum zswap_ceremony_error ad_live_at(const struct zswap_quote_v1 *ad,
                                            int64_t now_unix)
{
    switch (zswap_quote_validate_at(ad, now_unix)) {
    case ZSWAP_QUOTE_OK: return ZSWAP_CEREMONY_OK;
    case ZSWAP_QUOTE_ERR_EXPIRED: return ZSWAP_CEREMONY_ERR_EXPIRED;
    default: return ZSWAP_CEREMONY_ERR_AD;
    }
}

static enum zswap_ceremony_error deadlines_match(
    const struct zswap_quote_v1 *ad,
    const struct zswap_buyer_accept *buyer,
    const struct zswap_seller_accept *seller)
{
    if (buyer->deadline_unix != ad->expires_unix ||
        seller->deadline_unix != ad->expires_unix)
        return ZSWAP_CEREMONY_ERR_DEADLINE;
    return ZSWAP_CEREMONY_OK;
}

static bool script_equals(const struct script *script,
                          const uint8_t *bytes, size_t len)
{
    return script->size == len && memcmp(script->data, bytes, len) == 0;
}

/* ── seller term verification ──────────────────────────────────────── */

enum zswap_ceremony_error zswap_ceremony_seller_verify_assembly(
    const struct zswap_quote_v1 *ad,
    const struct zswap_buyer_accept *buyer,
    const struct zswap_seller_accept *seller,
    const struct zswap_assembly *assembly,
    int64_t now_unix)
{
    if (!ad || !buyer || !seller || !assembly)
        return ZSWAP_CEREMONY_ERR_NULL;
    enum zswap_ceremony_error e = ad_live_at(ad, now_unix);
    if (e != ZSWAP_CEREMONY_OK) return e;
    e = deadlines_match(ad, buyer, seller);
    if (e != ZSWAP_CEREMONY_OK) return e;
    if (zswap_buyer_accept_validate(buyer) != ZSWAP_ASSEMBLY_OK ||
        zswap_seller_accept_validate(seller) != ZSWAP_ASSEMBLY_OK)
        return ZSWAP_CEREMONY_ERR_ACCEPT;

    const struct transaction *tx = &assembly->tx;
    /* Canonical envelope. */
    if (!tx->overwintered || tx->version != SAPLING_TX_VERSION ||
        tx->version_group_id != SAPLING_VERSION_GROUP_ID ||
        tx->lock_time != 0 || tx->expiry_height != 0 ||
        tx->value_balance != 0 || tx->num_shielded_spend != 0 ||
        tx->num_shielded_output != 0 || tx->num_joinsplit != 0)
        return ZSWAP_CEREMONY_ERR_TERMS;

    /* Inputs: the seller's token input leads, then the sorted buyer list. */
    if (assembly->seller_input_count != 1 ||
        assembly->buyer_input_count != buyer->num_inputs ||
        tx->num_vin != 1 + buyer->num_inputs)
        return ZSWAP_CEREMONY_ERR_TERMS;
    struct zswap_swap_input sorted[ZSWAP_MAX_BUYER_INPUTS];
    memcpy(sorted, buyer->inputs, sizeof(sorted));
    for (size_t i = 1; i < buyer->num_inputs; i++) {
        struct zswap_swap_input key = sorted[i];
        size_t j = i;
        while (j > 0 && outpoint_cmp_fields(sorted[j - 1].txid,
                                            sorted[j - 1].vout,
                                            key.txid, key.vout) > 0) {
            sorted[j] = sorted[j - 1];
            j--;
        }
        sorted[j] = key;
    }
    if (memcmp(tx->vin[0].prevout.hash.data, seller->token_input.txid, 32) != 0 ||
        tx->vin[0].prevout.n != seller->token_input.vout)
        return ZSWAP_CEREMONY_ERR_TERMS;
    for (size_t i = 0; i < buyer->num_inputs; i++) {
        if (memcmp(tx->vin[1 + i].prevout.hash.data, sorted[i].txid, 32) != 0 ||
            tx->vin[1 + i].prevout.n != sorted[i].vout)
            return ZSWAP_CEREMONY_ERR_TERMS;
    }
    for (size_t i = 0; i < tx->num_vin; i++)
        if (tx->vin[i].sequence != UINT32_MAX)
            return ZSWAP_CEREMONY_ERR_TERMS;

    /* Money math re-derived from the accept data. */
    int64_t buyer_total = 0;
    for (size_t i = 0; i < buyer->num_inputs; i++)
        buyer_total += buyer->inputs[i].value_sats;
    if (ad->zcl_amount > (uint64_t)INT64_MAX ||
        buyer->fee_sats > (uint64_t)INT64_MAX)
        return ZSWAP_CEREMONY_ERR_TERMS;
    int64_t zcl_amount = (int64_t)ad->zcl_amount;
    int64_t fee = (int64_t)buyer->fee_sats;
    int64_t buyer_change = buyer_total - zcl_amount - fee;
    int64_t seller_change =
        seller->token_input.value_sats - ZSWAP_TOKEN_DUST_ZAT;
    if (buyer_change < 0 || seller_change < 0)
        return ZSWAP_CEREMONY_ERR_TERMS;
    if (assembly->fee_sats != fee)
        return ZSWAP_CEREMONY_ERR_TERMS;
    size_t expected_vout = 3 + (seller_change > 0 ? 1 : 0) +
                           (buyer_change > 0 ? 1 : 0);
    if (tx->num_vout != expected_vout ||
        assembly->vout_slp_opreturn != 0 || assembly->vout_token_dust != 1 ||
        assembly->vout_seller_payment != 2)
        return ZSWAP_CEREMONY_ERR_TERMS;

    /* vout[0]: the SLP SEND declaring exactly token_amount of the ad's
     * token — rebuilt from the ad and byte-compared, never trusted. */
    struct uint256 wire_token_id;
    for (int i = 0; i < 32; i++)
        wire_token_id.data[i] = ad->token_id[31 - i];
    uint64_t quantities[1] = { ad->token_amount };
    uint8_t op_script[256];
    size_t op_len = slp_build_send(op_script, sizeof(op_script),
                                   &wire_token_id, quantities, 1);
    if (op_len == 0)
        return ZSWAP_CEREMONY_ERR_TERMS;
    if (tx->vout[0].value != 0 ||
        !script_equals(&tx->vout[0].script_pub_key, op_script, op_len))
        return ZSWAP_CEREMONY_ERR_TERMS;

    /* The four destinations, decoded from the accept address strings. */
    struct tx_destination buyer_token_dest, buyer_change_dest;
    struct tx_destination seller_recv_dest, seller_change_dest;
    const struct chain_params *cp = chain_params_get();
    size_t pk_len, sc_len;
    const unsigned char *pk_pfx =
        chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc_pfx =
        chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_len);
    if (!decode_destination(buyer->token_recv_address, pk_pfx, pk_len,
                            sc_pfx, sc_len, &buyer_token_dest) ||
        !decode_destination(buyer->change_address, pk_pfx, pk_len,
                            sc_pfx, sc_len, &buyer_change_dest) ||
        !decode_destination(seller->zcl_recv_address, pk_pfx, pk_len,
                            sc_pfx, sc_len, &seller_recv_dest) ||
        !decode_destination(seller->change_address, pk_pfx, pk_len,
                            sc_pfx, sc_len, &seller_change_dest))
        return ZSWAP_CEREMONY_ERR_ACCEPT;

    /* vout[1]: the dust that carries the token to the buyer. */
    struct script expect;
    script_for_destination(&expect, &buyer_token_dest);
    if (tx->vout[1].value != ZSWAP_TOKEN_DUST_ZAT ||
        !script_equals(&tx->vout[1].script_pub_key, expect.data, expect.size))
        return ZSWAP_CEREMONY_ERR_TERMS;
    /* vout[2]: EXACTLY the ad's price, to the seller's own address — the
     * check that makes a shortchanging assembly un-signable. */
    script_for_destination(&expect, &seller_recv_dest);
    if (tx->vout[2].value != zcl_amount ||
        !script_equals(&tx->vout[2].script_pub_key, expect.data, expect.size))
        return ZSWAP_CEREMONY_ERR_TERMS;

    size_t v = 3;
    if (seller_change > 0) {
        if (assembly->vout_seller_change != (int)v) return ZSWAP_CEREMONY_ERR_TERMS;
        script_for_destination(&expect, &seller_change_dest);
        if (tx->vout[v].value != seller_change ||
            !script_equals(&tx->vout[v].script_pub_key, expect.data,
                           expect.size))
            return ZSWAP_CEREMONY_ERR_TERMS;
        v++;
    } else if (assembly->vout_seller_change != -1) {
        return ZSWAP_CEREMONY_ERR_TERMS;
    }
    if (buyer_change > 0) {
        if (assembly->vout_buyer_change != (int)v) return ZSWAP_CEREMONY_ERR_TERMS;
        script_for_destination(&expect, &buyer_change_dest);
        if (tx->vout[v].value != buyer_change ||
            !script_equals(&tx->vout[v].script_pub_key, expect.data,
                           expect.size))
            return ZSWAP_CEREMONY_ERR_TERMS;
    } else if (assembly->vout_buyer_change != -1) {
        return ZSWAP_CEREMONY_ERR_TERMS;
    }
    return ZSWAP_CEREMONY_OK;
}

/* ── signing ───────────────────────────────────────────────────────── */

/* Produce DER || SIGHASH_ALL for one P2PKH input, verifying the key owns
 * the script first. */
static enum zswap_ceremony_error sign_p2pkh_der(
    const struct transaction *tx, size_t input_index,
    const uint8_t *script_pub_key, size_t script_len,
    int64_t value_sats, uint32_t branch_id,
    const struct privkey *key,
    uint8_t sig_out[ZSWAP_SIG_FIELD_BYTES], uint8_t *sig_len_out,
    struct pubkey *pubkey_out)
{
    struct script script_code;
    script_code.size = script_len;
    memcpy(script_code.data, script_pub_key, script_len);

    enum txnouttype type;
    unsigned char solutions[20][65];
    size_t solution_sizes[20];
    size_t num_solutions = 0;
    if (!script_solver(&script_code, &type, solutions, solution_sizes,
                       &num_solutions) || type != TX_PUBKEYHASH)
        return ZSWAP_CEREMONY_ERR_SCRIPT_TYPE;

    struct pubkey pk;
    if (!privkey_get_pubkey(key, &pk))
        return ZSWAP_CEREMONY_ERR_SIGN;
    struct key_id kid = pubkey_get_id(&pk);
    if (memcmp(kid.id.data, solutions[0], 20) != 0) {
        memory_cleanse(&kid, sizeof(kid));
        return ZSWAP_CEREMONY_ERR_KEY_MISMATCH;
    }

    struct uint256 sighash;
    if (!zswap_assembly_input_sighash(tx, input_index, script_pub_key,
                                      script_len, value_sats, branch_id,
                                      sighash.data))
        return ZSWAP_CEREMONY_ERR_SIGN;

    size_t siglen = 0;
    if (!privkey_sign(key, &sighash, sig_out, &siglen))
        return ZSWAP_CEREMONY_ERR_SIGN;
    sig_out[siglen++] = SIGHASH_ALL;
    *sig_len_out = (uint8_t)siglen;
    if (pubkey_out) *pubkey_out = pk;
    return ZSWAP_CEREMONY_OK;
}

/* The canonical P2PKH scriptSig: <sig||hashtype> <pubkey> — the same shape
 * sign_one_input (transaction_controller_sign.c) and the wallet builder
 * emit. */
static void scriptsig_p2pkh(struct script *ss,
                            const uint8_t *sig, uint8_t sig_len,
                            const struct pubkey *pk)
{
    ss->size = 0;
    ss->data[ss->size++] = sig_len;
    memcpy(&ss->data[ss->size], sig, sig_len);
    ss->size += sig_len;
    ss->data[ss->size++] = (unsigned char)pk->size;
    memcpy(&ss->data[ss->size], pk->vch, pk->size);
    ss->size += pk->size;
}

enum zswap_ceremony_error zswap_ceremony_sign_input_p2pkh(
    struct transaction *tx, size_t input_index,
    const uint8_t *script_pub_key, size_t script_len,
    int64_t value_sats, uint32_t branch_id,
    const struct privkey *key)
{
    if (!tx || !script_pub_key || !key)
        return ZSWAP_CEREMONY_ERR_NULL;
    if (input_index >= tx->num_vin)
        return ZSWAP_CEREMONY_ERR_INPUT_INDEX;
    if (script_len == 0 || script_len > ZSWAP_MAX_INPUT_SCRIPT_BYTES)
        return ZSWAP_CEREMONY_ERR_ACCEPT;

    uint8_t sig[ZSWAP_SIG_FIELD_BYTES];
    uint8_t sig_len = 0;
    struct pubkey pk;
    enum zswap_ceremony_error e =
        sign_p2pkh_der(tx, input_index, script_pub_key, script_len,
                       value_sats, branch_id, key, sig, &sig_len, &pk);
    if (e != ZSWAP_CEREMONY_OK) return e;
    scriptsig_p2pkh(&tx->vin[input_index].script_sig, sig, sig_len, &pk);
    memory_cleanse(sig, sizeof(sig));
    return ZSWAP_CEREMONY_OK;
}

/* ── seller msg2 builder ───────────────────────────────────────────── */

enum zswap_ceremony_error zswap_ceremony_seller_build_partial(
    const struct zswap_quote_v1 *ad,
    const struct zswap_accept_v1 *accept,
    const struct zswap_seller_accept *seller_terms,
    const struct privkey *seller_key,
    uint32_t branch_id,
    int64_t now_unix,
    struct zswap_partial_v1 *partial,
    struct zswap_assembly *out_assembly)
{
    if (!ad || !accept || !seller_terms || !seller_key || !partial)
        return ZSWAP_CEREMONY_ERR_NULL;
    memset(partial, 0, sizeof(*partial));
    if (out_assembly) memset(out_assembly, 0, sizeof(*out_assembly));

    enum zswap_ceremony_error e = ad_live_at(ad, now_unix);
    if (e != ZSWAP_CEREMONY_OK) return e;
    uint8_t quote_root[32];
    if (zswap_quote_root(ad, quote_root) != ZSWAP_QUOTE_OK)
        return ZSWAP_CEREMONY_ERR_AD;
    if (memcmp(accept->quote_root, quote_root, 32) != 0)
        return ZSWAP_CEREMONY_ERR_QUOTE_ROOT;
    if (zswap_accept_validate(accept) != ZSWAP_CEREMONY_OK)
        return ZSWAP_CEREMONY_ERR_ACCEPT;
    if (zswap_seller_accept_validate(seller_terms) != ZSWAP_ASSEMBLY_OK)
        return ZSWAP_CEREMONY_ERR_ACCEPT;

    struct zswap_assembly assembly;
    memset(&assembly, 0, sizeof(assembly));
    if (zswap_assemble(ad, &accept->buyer, seller_terms, &assembly) !=
        ZSWAP_ASSEMBLY_OK)
        return ZSWAP_CEREMONY_ERR_ASSEMBLY;
    e = zswap_ceremony_seller_verify_assembly(ad, &accept->buyer,
                                              seller_terms, &assembly,
                                              now_unix);
    if (e != ZSWAP_CEREMONY_OK) {
        zswap_assembly_free(&assembly);
        return e;
    }

    /* Sign ONLY the seller's token input (vin[0]) over the full tx. */
    uint8_t sig[ZSWAP_SIG_FIELD_BYTES] = {0};
    uint8_t sig_len = 0;
    struct pubkey pk;
    e = sign_p2pkh_der(&assembly.tx, 0,
                       seller_terms->token_input.script_pub_key,
                       seller_terms->token_input.script_len,
                       seller_terms->token_input.value_sats, branch_id,
                       seller_key, sig, &sig_len, &pk);
    if (e != ZSWAP_CEREMONY_OK) {
        zswap_assembly_free(&assembly);
        return e;
    }
    if (pk.size != COMPRESSED_PUBLIC_KEY_SIZE) {
        zswap_assembly_free(&assembly);
        return ZSWAP_CEREMONY_ERR_KEY_MISMATCH;
    }

    uint8_t assembly_root[32];
    if (zswap_assembly_root(quote_root, &accept->buyer, seller_terms,
                            assembly_root) != ZSWAP_ASSEMBLY_OK) {
        zswap_assembly_free(&assembly);
        return ZSWAP_CEREMONY_ERR_ASSEMBLY;
    }

    partial->schema_version = ZSWAP_PARTIAL_VERSION;
    memcpy(partial->quote_root, quote_root, 32);
    memcpy(partial->assembly_root, assembly_root, 32);
    partial->seller = *seller_terms;
    memcpy(partial->seller_pubkey, pk.vch, 33);
    partial->sig_len = sig_len;
    memcpy(partial->signature, sig, sig_len);
    memory_cleanse(sig, sizeof(sig));

    if (out_assembly) {
        *out_assembly = assembly; /* ownership moves to the caller */
    } else {
        zswap_assembly_free(&assembly);
    }
    return ZSWAP_CEREMONY_OK;
}

/* ── buyer msg2 handler ────────────────────────────────────────────── */

enum zswap_ceremony_error zswap_ceremony_buyer_verify_partial(
    const struct zswap_quote_v1 *ad,
    const struct zswap_accept_v1 *accept,
    const struct zswap_partial_v1 *partial,
    uint32_t branch_id,
    int64_t now_unix,
    struct transaction *tx_out)
{
    if (!ad || !accept || !partial || !tx_out)
        return ZSWAP_CEREMONY_ERR_NULL;
    memset(tx_out, 0, sizeof(*tx_out));

    enum zswap_ceremony_error e = ad_live_at(ad, now_unix);
    if (e != ZSWAP_CEREMONY_OK) return e;
    if (zswap_accept_validate(accept) != ZSWAP_CEREMONY_OK)
        return ZSWAP_CEREMONY_ERR_ACCEPT;
    if (zswap_partial_validate(partial) != ZSWAP_CEREMONY_OK)
        return ZSWAP_CEREMONY_ERR_ACCEPT;

    /* Both wires must name THIS signed ad. */
    uint8_t quote_root[32];
    if (zswap_quote_root(ad, quote_root) != ZSWAP_QUOTE_OK)
        return ZSWAP_CEREMONY_ERR_AD;
    if (memcmp(accept->quote_root, quote_root, 32) != 0 ||
        memcmp(partial->quote_root, quote_root, 32) != 0)
        return ZSWAP_CEREMONY_ERR_QUOTE_ROOT;
    e = deadlines_match(ad, &accept->buyer, &partial->seller);
    if (e != ZSWAP_CEREMONY_OK) return e;

    /* The seller's assembly_root must be the one this node derives from the
     * same accept tuple — the divergence tripwire before any crypto runs. */
    uint8_t assembly_root[32];
    if (zswap_assembly_root(quote_root, &accept->buyer, &partial->seller,
                            assembly_root) != ZSWAP_ASSEMBLY_OK)
        return ZSWAP_CEREMONY_ERR_ASSEMBLY;
    if (memcmp(assembly_root, partial->assembly_root, 32) != 0)
        return ZSWAP_CEREMONY_ERR_ASSEMBLY_ROOT;

    /* Re-assemble from the signed ad and the exchanged accept data. Every
     * ad term — token id, token amount, price, the seller's address binding
     * — enters the transaction here byte-for-byte from the ad itself. */
    struct zswap_assembly assembly;
    memset(&assembly, 0, sizeof(assembly));
    if (zswap_assemble(ad, &accept->buyer, &partial->seller, &assembly) !=
        ZSWAP_ASSEMBLY_OK)
        return ZSWAP_CEREMONY_ERR_ASSEMBLY;
    e = zswap_ceremony_seller_verify_assembly(ad, &accept->buyer,
                                              &partial->seller, &assembly,
                                              now_unix);
    if (e != ZSWAP_CEREMONY_OK) {
        zswap_assembly_free(&assembly);
        return e;
    }

    /* The seller's pubkey must be bound to the token input's script: a
     * valid signature under an unrelated key buys the buyer nothing. */
    const struct zswap_swap_input *token_input = &partial->seller.token_input;
    struct script seller_script;
    seller_script.size = token_input->script_len;
    memcpy(seller_script.data, token_input->script_pub_key,
           token_input->script_len);
    enum txnouttype type;
    unsigned char solutions[20][65];
    size_t solution_sizes[20];
    size_t num_solutions = 0;
    if (!script_solver(&seller_script, &type, solutions, solution_sizes,
                       &num_solutions) || type != TX_PUBKEYHASH) {
        zswap_assembly_free(&assembly);
        return ZSWAP_CEREMONY_ERR_SCRIPT_TYPE;
    }
    struct pubkey seller_pk;
    pubkey_set(&seller_pk, partial->seller_pubkey, 33);
    if (!pubkey_is_fully_valid(&seller_pk)) {
        zswap_assembly_free(&assembly);
        return ZSWAP_CEREMONY_ERR_PUBKEY;
    }
    struct key_id kid = pubkey_get_id(&seller_pk);
    if (memcmp(kid.id.data, solutions[0], 20) != 0) {
        zswap_assembly_free(&assembly);
        return ZSWAP_CEREMONY_ERR_KEY_MISMATCH;
    }

    /* The seller's SIGHASH_ALL signature over the FULL assembled tx. */
    struct uint256 sighash;
    if (!zswap_assembly_input_sighash(&assembly.tx, 0,
                                      token_input->script_pub_key,
                                      token_input->script_len,
                                      token_input->value_sats, branch_id,
                                      sighash.data)) {
        zswap_assembly_free(&assembly);
        return ZSWAP_CEREMONY_ERR_ASSEMBLY;
    }
    size_t der_len = partial->sig_len - 1;
    if (!pubkey_check_low_s(partial->signature, der_len) ||
        !pubkey_verify(&seller_pk, &sighash,
                       partial->signature, der_len)) {
        zswap_assembly_free(&assembly);
        return ZSWAP_CEREMONY_ERR_SIGNATURE;
    }

    /* Insert the seller's signature — the only bytes that crossed the wire
     * — and hand the buyer the half-signed transaction. */
    scriptsig_p2pkh(&assembly.tx.vin[0].script_sig, partial->signature,
                    partial->sig_len, &seller_pk);
    transaction_compute_hash(&assembly.tx);
    transaction_init(tx_out);
    if (!transaction_copy(tx_out, &assembly.tx)) {
        zswap_assembly_free(&assembly);
        memset(tx_out, 0, sizeof(*tx_out));
        return ZSWAP_CEREMONY_ERR_ASSEMBLY;
    }
    zswap_assembly_free(&assembly);
    return ZSWAP_CEREMONY_OK;
}

bool zswap_ceremony_all_inputs_signed(const struct transaction *tx)
{
    if (!tx || tx->num_vin == 0) return false;
    for (size_t i = 0; i < tx->num_vin; i++)
        if (tx->vin[i].script_sig.size == 0)
            return false;
    return true;
}
