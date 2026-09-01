/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: zswap_assembly implementation — the deterministic two-party
 * assembler for the atomic ZSLP-token/ZCL yardsale swap. See
 * zswap/zswap_assembly.h for the canonical form and the assembly_root
 * commitment.
 *
 * House style mirrors zswap_quote.c: pure functions, named error enums on
 * every refusal (no logging in a codec — the caller logs the named error),
 * exact canonical serializations reused by the ceremony wires. */

#include "zswap/zswap_assembly.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "chain/chainparams.h"
#include "core/serialize.h"
#include "crypto/sha3.h"
#include "keys/key_io.h"
#include "script/standard.h"
#include "validation/sighash.h"
#include "zslp/slp.h"

#include <string.h>

/* Minimum plausible Base58Check address length (version + 20-byte hash +
 * checksum encodes to ~26+ chars; ZCL t-addresses are 35). Anything shorter
 * is rejected at structural validation before decode_destination runs. */
#define ZSWAP_ADDRESS_MIN_CHARS 26u

const char *zswap_assembly_error_string(enum zswap_assembly_error error)
{
    switch (error) {
    case ZSWAP_ASSEMBLY_OK: return "ok";
    case ZSWAP_ASSEMBLY_ERR_NULL: return "null-argument";
    case ZSWAP_ASSEMBLY_ERR_AD: return "ad-invalid";
    case ZSWAP_ASSEMBLY_ERR_DEADLINE: return "deadline-mismatch";
    case ZSWAP_ASSEMBLY_ERR_BUYER_INPUT_COUNT: return "buyer-input-count";
    case ZSWAP_ASSEMBLY_ERR_INPUT_VALUE: return "input-value-invalid";
    case ZSWAP_ASSEMBLY_ERR_INPUT_SCRIPT: return "input-script-invalid";
    case ZSWAP_ASSEMBLY_ERR_INPUT_ORDER: return "duplicate-input";
    case ZSWAP_ASSEMBLY_ERR_SELLER_DUST: return "seller-input-under-dust";
    case ZSWAP_ASSEMBLY_ERR_ADDRESS: return "address-invalid";
    case ZSWAP_ASSEMBLY_ERR_FEE: return "fee-zero";
    case ZSWAP_ASSEMBLY_ERR_INSUFFICIENT: return "buyer-inputs-insufficient";
    case ZSWAP_ASSEMBLY_ERR_OVERFLOW: return "value-overflow";
    case ZSWAP_ASSEMBLY_ERR_SLP_SCRIPT: return "slp-script-build-failed";
    case ZSWAP_ASSEMBLY_ERR_ALLOC: return "allocation-failed";
    }
    return "unknown";
}

/* ── structural validation ─────────────────────────────────────────── */

static enum zswap_assembly_error input_validate(
    const struct zswap_swap_input *in)
{
    if (in->value_sats <= 0)
        return ZSWAP_ASSEMBLY_ERR_INPUT_VALUE;
    if (in->script_len == 0 || in->script_len > ZSWAP_MAX_INPUT_SCRIPT_BYTES)
        return ZSWAP_ASSEMBLY_ERR_INPUT_SCRIPT;
    return ZSWAP_ASSEMBLY_OK;
}

static enum zswap_assembly_error address_field_validate(
    const char field[ZSWAP_ADDRESS_FIELD_BYTES])
{
    size_t len = 0;
    while (len < ZSWAP_ADDRESS_FIELD_BYTES && field[len] != '\0') len++;
    if (len < ZSWAP_ADDRESS_MIN_CHARS || len > ZSWAP_ADDRESS_MAX_CHARS)
        return ZSWAP_ASSEMBLY_ERR_ADDRESS;
    /* Canonical padding: everything after the NUL must be zero. */
    for (size_t i = len + 1; i < ZSWAP_ADDRESS_FIELD_BYTES; i++)
        if (field[i] != '\0')
            return ZSWAP_ASSEMBLY_ERR_ADDRESS;
    return ZSWAP_ASSEMBLY_OK;
}

enum zswap_assembly_error zswap_buyer_accept_validate(
    const struct zswap_buyer_accept *buyer)
{
    if (!buyer) return ZSWAP_ASSEMBLY_ERR_NULL;
    if (buyer->num_inputs == 0 || buyer->num_inputs > ZSWAP_MAX_BUYER_INPUTS)
        return ZSWAP_ASSEMBLY_ERR_BUYER_INPUT_COUNT;
    for (size_t i = 0; i < buyer->num_inputs; i++) {
        enum zswap_assembly_error e = input_validate(&buyer->inputs[i]);
        if (e != ZSWAP_ASSEMBLY_OK) return e;
    }
    enum zswap_assembly_error e =
        address_field_validate(buyer->token_recv_address);
    if (e != ZSWAP_ASSEMBLY_OK) return e;
    e = address_field_validate(buyer->change_address);
    if (e != ZSWAP_ASSEMBLY_OK) return e;
    if (buyer->fee_sats == 0)
        return ZSWAP_ASSEMBLY_ERR_FEE;
    if (buyer->deadline_unix <= 0)
        return ZSWAP_ASSEMBLY_ERR_DEADLINE;
    return ZSWAP_ASSEMBLY_OK;
}

enum zswap_assembly_error zswap_seller_accept_validate(
    const struct zswap_seller_accept *seller)
{
    if (!seller) return ZSWAP_ASSEMBLY_ERR_NULL;
    enum zswap_assembly_error e = input_validate(&seller->token_input);
    if (e != ZSWAP_ASSEMBLY_OK) return e;
    e = address_field_validate(seller->zcl_recv_address);
    if (e != ZSWAP_ASSEMBLY_OK) return e;
    e = address_field_validate(seller->change_address);
    if (e != ZSWAP_ASSEMBLY_OK) return e;
    if (seller->deadline_unix <= 0)
        return ZSWAP_ASSEMBLY_ERR_DEADLINE;
    return ZSWAP_ASSEMBLY_OK;
}

/* ── canonical serialization ───────────────────────────────────────── */

static void put_bytes(uint8_t *wire, size_t *off, const void *src, size_t len)
{
    memcpy(wire + *off, src, len);
    *off += len;
}

static void put_u8(uint8_t *wire, size_t *off, uint8_t value)
{
    wire[(*off)++] = value;
}

static void put_u32(uint8_t *wire, size_t *off, uint32_t value)
{
    zcl_write_u32_le(wire + *off, value);
    *off += 4;
}

static void put_u64(uint8_t *wire, size_t *off, uint64_t value)
{
    zcl_write_u64_le(wire + *off, value);
    *off += 8;
}

static size_t input_serialized_size(const struct zswap_swap_input *in)
{
    return 32 + 4 + 8 + 1 + (size_t)in->script_len;
}

static void put_input(uint8_t *wire, size_t *off,
                      const struct zswap_swap_input *in)
{
    put_bytes(wire, off, in->txid, 32);
    put_u32(wire, off, in->vout);
    put_u64(wire, off, (uint64_t)in->value_sats);
    put_u8(wire, off, (uint8_t)in->script_len);
    put_bytes(wire, off, in->script_pub_key, in->script_len);
}

/* Outpoint ordering: txid bytes ascending (node-internal order), then vout
 * ascending — the same convention outpoint_cmp defines. */
static int swap_input_outpoint_cmp(const struct zswap_swap_input *a,
                                   const struct zswap_swap_input *b)
{
    int r = memcmp(a->txid, b->txid, 32);
    if (r != 0) return r;
    if (a->vout < b->vout) return -1;
    if (a->vout > b->vout) return 1;
    return 0;
}

/* Insertion sort — the lists are tiny (<= 16). Returns false on a duplicate
 * outpoint, which canonical form forbids outright. */
static bool sort_inputs(struct zswap_swap_input *inputs, size_t n)
{
    for (size_t i = 1; i < n; i++) {
        struct zswap_swap_input key = inputs[i];
        size_t j = i;
        while (j > 0 && swap_input_outpoint_cmp(&inputs[j - 1], &key) > 0) {
            inputs[j] = inputs[j - 1];
            j--;
        }
        if (j > 0 && swap_input_outpoint_cmp(&inputs[j - 1], &key) == 0)
            return false;
        inputs[j] = key;
    }
    return true;
}

size_t zswap_buyer_accept_serialized_size(const struct zswap_buyer_accept *b)
{
    size_t total = 1 + 2 * ZSWAP_ADDRESS_FIELD_BYTES + 8 + 8;
    for (size_t i = 0; i < b->num_inputs; i++)
        total += input_serialized_size(&b->inputs[i]);
    return total;
}

size_t zswap_seller_accept_serialized_size(const struct zswap_seller_accept *s)
{
    return input_serialized_size(&s->token_input) +
           2 * ZSWAP_ADDRESS_FIELD_BYTES + 8;
}

enum zswap_assembly_error zswap_buyer_accept_serialize(
    const struct zswap_buyer_accept *buyer,
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    enum zswap_assembly_error e = zswap_buyer_accept_validate(buyer);
    if (e != ZSWAP_ASSEMBLY_OK || !out || !out_len)
        return (e == ZSWAP_ASSEMBLY_OK) ? ZSWAP_ASSEMBLY_ERR_NULL : e;
    /* Serialize a SORTED COPY: the canonical bytes are input-order
     * independent, which is what lets two nodes that collected the same
     * list in different orders agree on the assembly_root. */
    struct zswap_buyer_accept sorted = *buyer;
    if (!sort_inputs(sorted.inputs, sorted.num_inputs))
        return ZSWAP_ASSEMBLY_ERR_INPUT_ORDER;
    size_t need = zswap_buyer_accept_serialized_size(&sorted);
    if (out_cap < need) return ZSWAP_ASSEMBLY_ERR_OVERFLOW;
    size_t off = 0;
    put_u8(out, &off, (uint8_t)sorted.num_inputs);
    for (size_t i = 0; i < sorted.num_inputs; i++)
        put_input(out, &off, &sorted.inputs[i]);
    put_bytes(out, &off, sorted.token_recv_address, ZSWAP_ADDRESS_FIELD_BYTES);
    put_bytes(out, &off, sorted.change_address, ZSWAP_ADDRESS_FIELD_BYTES);
    put_u64(out, &off, sorted.fee_sats);
    put_u64(out, &off, (uint64_t)sorted.deadline_unix);
    *out_len = off;
    return ZSWAP_ASSEMBLY_OK;
}

enum zswap_assembly_error zswap_seller_accept_serialize(
    const struct zswap_seller_accept *seller,
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    enum zswap_assembly_error e = zswap_seller_accept_validate(seller);
    if (e != ZSWAP_ASSEMBLY_OK || !out || !out_len)
        return (e == ZSWAP_ASSEMBLY_OK) ? ZSWAP_ASSEMBLY_ERR_NULL : e;
    size_t need = zswap_seller_accept_serialized_size(seller);
    if (out_cap < need) return ZSWAP_ASSEMBLY_ERR_OVERFLOW;
    size_t off = 0;
    put_input(out, &off, &seller->token_input);
    put_bytes(out, &off, seller->zcl_recv_address, ZSWAP_ADDRESS_FIELD_BYTES);
    put_bytes(out, &off, seller->change_address, ZSWAP_ADDRESS_FIELD_BYTES);
    put_u64(out, &off, (uint64_t)seller->deadline_unix);
    *out_len = off;
    return ZSWAP_ASSEMBLY_OK;
}

enum zswap_assembly_error zswap_assembly_root(
    const uint8_t quote_root[32],
    const struct zswap_buyer_accept *buyer,
    const struct zswap_seller_accept *seller,
    uint8_t out[32])
{
    if (!quote_root || !out) return ZSWAP_ASSEMBLY_ERR_NULL;
    if (!zcl_bytes_any_set(quote_root, 32)) return ZSWAP_ASSEMBLY_ERR_AD;
    uint8_t buyer_bytes[1 + ZSWAP_MAX_BUYER_INPUTS *
                            (32 + 4 + 8 + 1 + ZSWAP_MAX_INPUT_SCRIPT_BYTES) +
                        2 * ZSWAP_ADDRESS_FIELD_BYTES + 16];
    uint8_t seller_bytes[32 + 4 + 8 + 1 + ZSWAP_MAX_INPUT_SCRIPT_BYTES +
                         2 * ZSWAP_ADDRESS_FIELD_BYTES + 8];
    size_t buyer_len = 0, seller_len = 0;
    enum zswap_assembly_error e = zswap_buyer_accept_serialize(
        buyer, buyer_bytes, sizeof(buyer_bytes), &buyer_len);
    if (e != ZSWAP_ASSEMBLY_OK) return e;
    e = zswap_seller_accept_serialize(
        seller, seller_bytes, sizeof(seller_bytes), &seller_len);
    if (e != ZSWAP_ASSEMBLY_OK) return e;

    static const char domain[] = ZSWAP_ASSEMBLY_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, quote_root, 32);
    sha3_256_write(&sha, buyer_bytes, buyer_len);
    sha3_256_write(&sha, seller_bytes, seller_len);
    sha3_256_finalize(&sha, out);
    return ZSWAP_ASSEMBLY_OK;
}

/* ── address decoding ──────────────────────────────────────────────── */

static bool decode_address(const char field[ZSWAP_ADDRESS_FIELD_BYTES],
                           struct tx_destination *dest)
{
    const struct chain_params *cp = chain_params_get();
    size_t pk_len, sc_len;
    const unsigned char *pk_pfx =
        chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc_pfx =
        chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_len);
    return decode_destination(field, pk_pfx, pk_len, sc_pfx, sc_len, dest);
}

/* ── the assembler ─────────────────────────────────────────────────── */

enum zswap_assembly_error zswap_assemble(
    const struct zswap_quote_v1 *ad,
    const struct zswap_buyer_accept *buyer,
    const struct zswap_seller_accept *seller,
    struct zswap_assembly *out)
{
    if (!ad || !buyer || !seller || !out)
        return ZSWAP_ASSEMBLY_ERR_NULL;
    memset(out, 0, sizeof(*out));
    transaction_init(&out->tx);
    out->vout_slp_opreturn = -1;
    out->vout_token_dust = -1;
    out->vout_seller_payment = -1;
    out->vout_seller_change = -1;
    out->vout_buyer_change = -1;

    if (zswap_quote_validate(ad) != ZSWAP_QUOTE_OK)
        return ZSWAP_ASSEMBLY_ERR_AD;
    enum zswap_assembly_error e = zswap_buyer_accept_validate(buyer);
    if (e != ZSWAP_ASSEMBLY_OK) return e;
    e = zswap_seller_accept_validate(seller);
    if (e != ZSWAP_ASSEMBLY_OK) return e;
    /* The ceremony deadline IS the ad's expiry: a stale ceremony dies with
     * the ad, and both accepts must name the same instant. */
    if (buyer->deadline_unix != ad->expires_unix ||
        seller->deadline_unix != ad->expires_unix)
        return ZSWAP_ASSEMBLY_ERR_DEADLINE;

    /* v1 input shape: exactly one seller token input, funded with at least
     * the dust that carries the token to the buyer. */
    if (seller->token_input.value_sats < ZSWAP_TOKEN_DUST_ZAT)
        return ZSWAP_ASSEMBLY_ERR_SELLER_DUST;

    struct zswap_swap_input token_input = seller->token_input;
    struct zswap_swap_input buyer_inputs[ZSWAP_MAX_BUYER_INPUTS];
    memcpy(buyer_inputs, buyer->inputs, sizeof(buyer_inputs));
    size_t num_buyer = buyer->num_inputs;
    if (!sort_inputs(buyer_inputs, num_buyer))
        return ZSWAP_ASSEMBLY_ERR_INPUT_ORDER;
    for (size_t i = 0; i < num_buyer; i++)
        if (swap_input_outpoint_cmp(&token_input, &buyer_inputs[i]) == 0)
            return ZSWAP_ASSEMBLY_ERR_INPUT_ORDER;

    /* Addresses: the ad carries terms only — all four destinations arrive in
     * the accept data and must decode under this network's params. */
    struct tx_destination buyer_token_dest, buyer_change_dest;
    struct tx_destination seller_recv_dest, seller_change_dest;
    if (!decode_address(buyer->token_recv_address, &buyer_token_dest) ||
        !decode_address(buyer->change_address, &buyer_change_dest) ||
        !decode_address(seller->zcl_recv_address, &seller_recv_dest) ||
        !decode_address(seller->change_address, &seller_change_dest))
        return ZSWAP_ASSEMBLY_ERR_ADDRESS;

    /* Money math in int64 (values are int64 on the tx; the ad's amounts are
     * uint64, so guard the casts before any arithmetic). */
    if (ad->zcl_amount > (uint64_t)INT64_MAX ||
        buyer->fee_sats > (uint64_t)INT64_MAX)
        return ZSWAP_ASSEMBLY_ERR_OVERFLOW;
    int64_t zcl_amount = (int64_t)ad->zcl_amount;
    int64_t fee = (int64_t)buyer->fee_sats;
    int64_t buyer_total = 0;
    for (size_t i = 0; i < num_buyer; i++) {
        if (buyer_inputs[i].value_sats > INT64_MAX - buyer_total)
            return ZSWAP_ASSEMBLY_ERR_OVERFLOW;
        buyer_total += buyer_inputs[i].value_sats;
    }
    if (zcl_amount > INT64_MAX - fee)
        return ZSWAP_ASSEMBLY_ERR_OVERFLOW;
    if (buyer_total < zcl_amount + fee)
        return ZSWAP_ASSEMBLY_ERR_INSUFFICIENT;
    int64_t buyer_change = buyer_total - zcl_amount - fee;
    int64_t seller_change = token_input.value_sats - ZSWAP_TOKEN_DUST_ZAT;

    /* The SLP SEND declaration: exactly one quantity — token_amount of the
     * ad's token — paying vout[1]. token_id crosses to the SLP wire's
     * byte-reversed convention exactly as the single-party builder does. */
    struct uint256 wire_token_id;
    for (int i = 0; i < 32; i++)
        wire_token_id.data[i] = ad->token_id[31 - i];
    uint64_t quantities[1] = { ad->token_amount };
    uint8_t op_script[256];
    size_t op_len = slp_build_send(op_script, sizeof(op_script),
                                   &wire_token_id, quantities, 1);
    if (op_len == 0)
        return ZSWAP_ASSEMBLY_ERR_SLP_SCRIPT;

    size_t num_vin = 1 + num_buyer;
    size_t num_vout = 3 + (seller_change > 0 ? 1 : 0) +
                      (buyer_change > 0 ? 1 : 0);
    if (!transaction_alloc(&out->tx, num_vin, num_vout))
        return ZSWAP_ASSEMBLY_ERR_ALLOC;

    /* Canonical envelope: Sapling v4, no expiry (the ceremony deadline is
     * the ad's), no shielded components, final sequences. */
    out->tx.overwintered = true;
    out->tx.version = SAPLING_TX_VERSION;
    out->tx.version_group_id = SAPLING_VERSION_GROUP_ID;
    out->tx.lock_time = 0;
    out->tx.expiry_height = 0;
    out->tx.value_balance = 0;

    for (size_t i = 0; i < num_vout; i++)
        tx_out_set_null(&out->tx.vout[i]);

    /* Inputs: seller token input first, then the sorted buyer inputs. */
    memcpy(out->tx.vin[0].prevout.hash.data, token_input.txid, 32);
    out->tx.vin[0].prevout.n = token_input.vout;
    out->tx.vin[0].script_sig.size = 0;
    out->tx.vin[0].sequence = UINT32_MAX;
    for (size_t i = 0; i < num_buyer; i++) {
        memcpy(out->tx.vin[1 + i].prevout.hash.data, buyer_inputs[i].txid, 32);
        out->tx.vin[1 + i].prevout.n = buyer_inputs[i].vout;
        out->tx.vin[1 + i].script_sig.size = 0;
        out->tx.vin[1 + i].sequence = UINT32_MAX;
    }

    /* Outputs in fixed role order. */
    size_t v = 0;
    out->vout_slp_opreturn = (int)v;
    out->tx.vout[v].value = 0;
    out->tx.vout[v].script_pub_key.size = op_len;
    memcpy(out->tx.vout[v].script_pub_key.data, op_script, op_len);
    v++;

    out->vout_token_dust = (int)v;
    out->tx.vout[v].value = ZSWAP_TOKEN_DUST_ZAT;
    script_for_destination(&out->tx.vout[v].script_pub_key,
                           &buyer_token_dest);
    v++;

    out->vout_seller_payment = (int)v;
    out->tx.vout[v].value = zcl_amount;
    script_for_destination(&out->tx.vout[v].script_pub_key,
                           &seller_recv_dest);
    v++;

    if (seller_change > 0) {
        out->vout_seller_change = (int)v;
        out->tx.vout[v].value = seller_change;
        script_for_destination(&out->tx.vout[v].script_pub_key,
                               &seller_change_dest);
        v++;
    }
    if (buyer_change > 0) {
        out->vout_buyer_change = (int)v;
        out->tx.vout[v].value = buyer_change;
        script_for_destination(&out->tx.vout[v].script_pub_key,
                               &buyer_change_dest);
        v++;
    }

    out->seller_input_count = 1;
    out->buyer_input_count = num_buyer;
    out->fee_sats = fee;
    transaction_compute_hash(&out->tx);
    return ZSWAP_ASSEMBLY_OK;
}

void zswap_assembly_free(struct zswap_assembly *assembly)
{
    if (!assembly) return;
    transaction_free(&assembly->tx);
    memset(assembly, 0, sizeof(*assembly));
}

bool zswap_assembly_tx_serialize(const struct transaction *tx,
                                 uint8_t *out, size_t out_cap,
                                 size_t *out_len)
{
    if (!tx || !out || !out_len) return false;
    struct byte_stream s;
    stream_init(&s, 512);
    bool ok = transaction_serialize(tx, &s) && !s.error;
    if (ok) {
        if (s.size <= out_cap) {
            memcpy(out, s.data, s.size);
            *out_len = s.size;
        } else {
            ok = false;
        }
    }
    stream_free(&s);
    return ok;
}

bool zswap_assembly_input_sighash(const struct transaction *tx,
                                  size_t input_index,
                                  const uint8_t *script_pub_key,
                                  size_t script_len,
                                  int64_t value_sats,
                                  uint32_t branch_id,
                                  uint8_t out[32])
{
    if (!tx || !script_pub_key || !out) return false;
    if (input_index >= tx->num_vin) return false;
    if (script_len == 0 || script_len > MAX_SCRIPT_SIZE) return false;

    struct script script_code;
    script_code.size = script_len;
    memcpy(script_code.data, script_pub_key, script_len);

    struct precomputed_tx_data txdata;
    precompute_tx_data(tx, &txdata);

    struct sighash_type ht;
    ht.raw = SIGHASH_ALL;
    struct uint256 sighash;
    if (!signature_hash(&script_code, tx, (unsigned int)input_index, ht,
                        value_sats, branch_id, &txdata, &sighash))
        return false;
    memcpy(out, sighash.data, 32);
    return true;
}
