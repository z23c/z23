/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zswap ceremony handlers: the seller's term verification of an assembled
 * transaction (every envelope field, input, output and role index), the
 * input signer, the seller's partial builder and the buyer's partial
 * verifier, each refusal by its exact code. Called from
 * test_zswap_ceremony. A refusal row alters exactly one thing in a good
 * assembly, so a check that is weakened or removed changes that row. */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "crypto/ed25519.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "script/standard.h"
#include "zswap/zswap_assembly.h"
#include "zswap/zswap_ceremony.h"
#include "zswap/zswap_quote.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ZV_CHECK(name, expr) do {                                       \
    if (expr) { printf("  zswap verify: %s... OK\n", (name)); }          \
    else { printf("  zswap verify: %s... FAIL\n", (name));               \
        failures++; }                                                   \
} while (0)

#define ZV_ISSUED 1754000000LL
#define ZV_EXPIRES (ZV_ISSUED + 45LL)
#define ZV_NOW (ZV_ISSUED + 10LL)
#define ZV_BRANCH 0x76b809bbU
#define ZV_AMOUNT 125000000LL
#define ZV_FEE 10000LL
#define ZV_TERMS ZSWAP_CEREMONY_ERR_TERMS

struct zv {
    struct zswap_quote_v1 ad;
    struct zswap_buyer_accept buyer;
    struct zswap_seller_accept seller;
    struct zswap_accept_v1 accept;
    struct privkey seller_key;
    struct privkey buyer_key;
};

static struct zv g_w;

static void zv_key(struct privkey *key, uint8_t fill)
{
    memset(key->vch, fill, 32);
    key->fValid = true;
    key->fCompressed = true;
}

static bool zv_dest(const struct privkey *key, struct tx_destination *dest)
{
    struct pubkey pk;
    if (!privkey_get_pubkey(key, &pk)) return false;
    dest->type = DEST_KEY_ID;
    dest->id.key = pubkey_get_id(&pk);
    return true;
}

static size_t zv_script(const struct privkey *key, uint8_t out[25])
{
    struct tx_destination dest;
    if (!zv_dest(key, &dest)) return 0;
    out[0] = 0x76;
    out[1] = 0xa9;
    out[2] = 0x14;
    memcpy(out + 3, dest.id.key.id.data, 20);
    out[23] = 0x88;
    out[24] = 0xac;
    return 25;
}

static bool zv_address(const struct privkey *key,
                       char out[ZSWAP_ADDRESS_FIELD_BYTES])
{
    struct tx_destination dest;
    if (!zv_dest(key, &dest)) return false;
    const struct chain_params *cp = chain_params_get();
    size_t pk_len, sc_len;
    const unsigned char *pk_pfx =
        chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc_pfx =
        chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_len);
    return encode_destination(&dest, pk_pfx, pk_len, sc_pfx, sc_len, out,
                              ZSWAP_ADDRESS_FIELD_BYTES);
}

static void zv_input(struct zswap_swap_input *in, uint8_t base, uint32_t vout,
                     int64_t value, const uint8_t *script, uint16_t len)
{
    memset(in, 0, sizeof(*in));
    for (size_t i = 0; i < 32; i++) in->txid[i] = (uint8_t)(base + i);
    in->vout = vout;
    in->value_sats = value;
    in->script_len = len;
    memcpy(in->script_pub_key, script, len);
}

static bool zv_ad(struct zswap_quote_v1 *q)
{
    memset(q, 0, sizeof(*q));
    q->schema_version = ZSWAP_QUOTE_VERSION;
    for (size_t i = 0; i < 32; i++) {
        q->network_genesis_root[i] = (uint8_t)(0xa0 + i);
        q->token_id[i] = (uint8_t)(0x40 + i);
    }
    uint8_t seed[32], sk[32];
    memset(seed, 0x11, sizeof(seed));
    ed25519_keypair(q->seller_pubkey, sk, seed);
    q->nonce = 0x0102030405060708ULL;
    q->token_amount = 500000ULL;
    q->zcl_amount = (uint64_t)ZV_AMOUNT;
    q->issued_unix = ZV_ISSUED;
    q->expires_unix = ZV_EXPIRES;
    return zswap_quote_seal(q, seed) == ZSWAP_QUOTE_OK;
}

/* Seller token input 10000 sats; buyer inputs 150000000 (txid 0x50, vout 1)
 * and 50000000 (txid 0x60, vout 0), listed in the wrong order on purpose. */
static bool zv_init(struct zv *w)
{
    memset(w, 0, sizeof(*w));
    zv_key(&w->seller_key, 0x31);
    zv_key(&w->buyer_key, 0x42);
    struct privkey change_key, seller_change_key, buyer_change_key;
    zv_key(&change_key, 0x32);
    zv_key(&buyer_change_key, 0x43);
    seller_change_key = change_key;
    uint8_t script[25];
    if (!zv_ad(&w->ad) || zv_script(&w->buyer_key, script) != 25) return false;
    w->buyer.num_inputs = 2;
    zv_input(&w->buyer.inputs[0], 0x60, 0, 50000000, script, 25);
    zv_input(&w->buyer.inputs[1], 0x50, 1, 150000000, script, 25);
    if (!zv_address(&w->buyer_key, w->buyer.token_recv_address) ||
        !zv_address(&buyer_change_key, w->buyer.change_address))
        return false;
    w->buyer.fee_sats = (uint64_t)ZV_FEE;
    w->buyer.deadline_unix = ZV_EXPIRES;
    if (zv_script(&w->seller_key, script) != 25) return false;
    zv_input(&w->seller.token_input, 0x30, 2, 10000, script, 25);
    if (!zv_address(&w->seller_key, w->seller.zcl_recv_address) ||
        !zv_address(&seller_change_key, w->seller.change_address))
        return false;
    w->seller.deadline_unix = ZV_EXPIRES;
    w->accept.schema_version = ZSWAP_ACCEPT_VERSION;
    if (zswap_quote_root(&w->ad, w->accept.quote_root) != ZSWAP_QUOTE_OK)
        return false;
    w->accept.buyer = w->buyer;
    return true;
}

static bool zv_assemble(struct zv *w, struct zswap_assembly *a)
{
    return zswap_assemble(&w->ad, &w->buyer, &w->seller, a) == ZSWAP_ASSEMBLY_OK;
}

static enum zswap_ceremony_error zv_verify(struct zv *w,
                                           const struct zswap_assembly *a)
{
    return zswap_ceremony_seller_verify_assembly(&w->ad, &w->buyer, &w->seller,
                                                 a, ZV_NOW);
}

/* ── one-alteration refusal rows ───────────────────────────────────── */

typedef void (*zv_mut)(struct zswap_assembly *a, struct zv *w, size_t k);

struct zv_row {
    const char *name;
    zv_mut fn;
    size_t k;
    enum zswap_ceremony_error want;
};

static void zv_m_env(struct zswap_assembly *a, struct zv *w, size_t k)
{
    struct transaction *t = &a->tx;
    (void)w;
    switch (k) {
    case 0: t->overwintered = false; break;
    case 1: t->version ^= 1; break;
    case 2: t->version_group_id ^= 1u; break;
    case 3: t->lock_time = 1; break;
    case 4: t->expiry_height = 1; break;
    case 5: t->value_balance = 1; break;
    case 6: t->num_shielded_spend = 1; break;
    case 7: t->num_shielded_output = 1; break;
    default: t->num_joinsplit = 1; break;
    }
}

static void zv_m_in(struct zswap_assembly *a, struct zv *w, size_t k)
{
    struct transaction *t = &a->tx;
    (void)w;
    switch (k) {
    case 0: a->seller_input_count = 2; break;
    case 1: a->buyer_input_count = 1; break;
    case 2: t->num_vin -= 1; break;
    case 3: t->num_vin += 1; break;
    case 4: t->vin[0].prevout.hash.data[0] ^= 1; break;
    case 5: t->vin[0].prevout.n ^= 1u; break;
    case 6: t->vin[1].prevout.hash.data[31] ^= 1; break;
    case 7: t->vin[1].prevout.n ^= 1u; break;
    case 8: t->vin[2].prevout.hash.data[31] ^= 1; break;
    case 9: t->vin[2].prevout.n ^= 1u; break;
    default: {
        struct outpoint swap = t->vin[1].prevout;
        t->vin[1].prevout = t->vin[2].prevout;
        t->vin[2].prevout = swap;
        break;
    }
    }
}

static void zv_m_seq(struct zswap_assembly *a, struct zv *w, size_t k)
{
    (void)w;
    if (k < 3) a->tx.vin[k].sequence = 0;
    else a->tx.vin[2].sequence = UINT32_MAX - 1u;
}

static void zv_m_money(struct zswap_assembly *a, struct zv *w, size_t k)
{
    switch (k) {
    case 0: a->fee_sats += 1; break;
    case 1: a->tx.num_vout -= 1; break;
    case 2: a->tx.num_vout += 1; break;
    case 3: a->vout_slp_opreturn = 1; break;
    case 4: a->vout_token_dust = 0; break;
    case 5: a->vout_seller_payment = 3; break;
    case 6: w->buyer.fee_sats = (uint64_t)INT64_MAX + 1u; break;
    case 7: w->buyer.inputs[0].value_sats = INT64_MAX; break;
    case 8: w->seller.token_input.value_sats = ZSWAP_TOKEN_DUST_ZAT - 1; break;
    default:
        w->buyer.inputs[0].value_sats = 1;
        w->buyer.inputs[1].value_sats = 1;
        break;
    }
}

static void zv_m_out(struct zswap_assembly *a, struct zv *w, size_t k)
{
    struct tx_out *o = a->tx.vout;
    (void)w;
    switch (k) {
    case 0: o[0].value = 1; break;
    case 1: o[0].script_pub_key.data[o[0].script_pub_key.size - 1] ^= 1; break;
    case 2: o[0].script_pub_key.size -= 1; break;
    case 3: o[0].script_pub_key.size += 1; break;
    case 4: o[1].value += 1; break;
    case 5: o[1].script_pub_key.data[5] ^= 1; break;
    case 6: o[1].script_pub_key.size -= 1; break;
    case 7: o[2].script_pub_key.data[5] ^= 1; break;
    case 8: o[2].script_pub_key.size -= 1; break;
    default: o[2].value += 1; break;
    }
}

static void zv_m_chg(struct zswap_assembly *a, struct zv *w, size_t k)
{
    struct tx_out *o = a->tx.vout;
    (void)w;
    switch (k) {
    case 0: o[3].value += 1; break;
    case 1: o[3].script_pub_key.data[5] ^= 1; break;
    case 2: o[3].script_pub_key.size -= 1; break;
    case 3: a->vout_seller_change = 4; break;
    case 4: a->vout_buyer_change = 3; break;
    case 5: o[4].script_pub_key.data[5] ^= 1; break;
    default: o[4].script_pub_key.size -= 1; break;
    }
}

static void zv_m_pre(struct zswap_assembly *a, struct zv *w, size_t k)
{
    (void)a;
    switch (k) {
    case 0: w->buyer.token_recv_address[5] = '!'; break;
    case 1: w->buyer.change_address[5] = '!'; break;
    case 2: w->seller.zcl_recv_address[5] = '!'; break;
    case 3: w->seller.change_address[5] = '!'; break;
    case 4: w->buyer.num_inputs = 0; break;
    case 5: w->seller.token_input.script_len = 0; break;
    case 6: w->buyer.deadline_unix += 1; break;
    case 7: w->seller.deadline_unix += 1; break;
    default: w->ad.token_amount = 0; break;
    }
}

static int zv_run_rows(const struct zv_row *rows, size_t n)
{
    int failures = 0;
    for (size_t i = 0; i < n; i++) {
        struct zswap_assembly a;
        memset(&a, 0, sizeof(a));
        if (!zv_init(&g_w) || !zv_assemble(&g_w, &a)) {
            printf("  zswap verify: %s... FAIL (fixture)\n", rows[i].name);
            failures++;
            continue;
        }
        const struct transaction saved = a.tx;
        rows[i].fn(&a, &g_w, rows[i].k);
        enum zswap_ceremony_error e = zv_verify(&g_w, &a);
        /* The row may have altered a count; free with the real ones. */
        a.tx.num_vin = saved.num_vin;
        a.tx.num_vout = saved.num_vout;
        a.tx.num_shielded_spend = saved.num_shielded_spend;
        a.tx.num_shielded_output = saved.num_shielded_output;
        a.tx.num_joinsplit = saved.num_joinsplit;
        zswap_assembly_free(&a);
        if (e != rows[i].want) {
            printf("  zswap verify: %s... FAIL (got %d want %d)\n",
                   rows[i].name, (int)e, (int)rows[i].want);
            failures++;
        }
    }
    return failures;
}

#define ZV_ROW(n, f, k) { n, f, k, ZV_TERMS }

static int zv_rows_shape(void)
{
    static const struct zv_row rows[] = {
        ZV_ROW("overwintered flag", zv_m_env, 0),
        ZV_ROW("tx version", zv_m_env, 1),
        ZV_ROW("version group", zv_m_env, 2),
        ZV_ROW("lock time", zv_m_env, 3),
        ZV_ROW("expiry height", zv_m_env, 4),
        ZV_ROW("value balance", zv_m_env, 5),
        ZV_ROW("shielded spends", zv_m_env, 6),
        ZV_ROW("shielded outputs", zv_m_env, 7),
        ZV_ROW("joinsplits", zv_m_env, 8),
        ZV_ROW("seller input count", zv_m_in, 0),
        ZV_ROW("buyer input count", zv_m_in, 1),
        ZV_ROW("one input short", zv_m_in, 2),
        ZV_ROW("one input over", zv_m_in, 3),
        ZV_ROW("seller prevout hash", zv_m_in, 4),
        ZV_ROW("seller prevout index", zv_m_in, 5),
        ZV_ROW("first buyer prevout hash", zv_m_in, 6),
        ZV_ROW("first buyer prevout index", zv_m_in, 7),
        ZV_ROW("second buyer prevout hash", zv_m_in, 8),
        ZV_ROW("second buyer prevout index", zv_m_in, 9),
        ZV_ROW("buyer prevouts out of order", zv_m_in, 10),
        ZV_ROW("seller input sequence", zv_m_seq, 0),
        ZV_ROW("first buyer input sequence", zv_m_seq, 1),
        ZV_ROW("second buyer input sequence", zv_m_seq, 2),
        ZV_ROW("last input sequence one under final", zv_m_seq, 3),
    };
    return zv_run_rows(rows, sizeof(rows) / sizeof(rows[0]));
}

static int zv_rows_money(void)
{
    static const struct zv_row rows[] = {
        ZV_ROW("fee differs from the accept", zv_m_money, 0),
        ZV_ROW("output count one short", zv_m_money, 1),
        ZV_ROW("output count one over", zv_m_money, 2),
        ZV_ROW("SLP role index", zv_m_money, 3),
        ZV_ROW("token dust role index", zv_m_money, 4),
        ZV_ROW("payment role index", zv_m_money, 5),
        ZV_ROW("fee past INT64_MAX", zv_m_money, 6),
        ZV_ROW("buyer inputs overflow the sum", zv_m_money, 7),
        ZV_ROW("seller input under dust", zv_m_money, 8),
        ZV_ROW("buyer inputs under price and fee", zv_m_money, 9),
    };
    return zv_run_rows(rows, sizeof(rows) / sizeof(rows[0]));
}

static int zv_rows_outputs(void)
{
    static const struct zv_row rows[] = {
        ZV_ROW("SLP output carries value", zv_m_out, 0),
        ZV_ROW("SLP output last byte", zv_m_out, 1),
        ZV_ROW("SLP output one byte short", zv_m_out, 2),
        ZV_ROW("SLP output one byte long", zv_m_out, 3),
        ZV_ROW("token dust amount", zv_m_out, 4),
        ZV_ROW("token dust script", zv_m_out, 5),
        ZV_ROW("token dust script short", zv_m_out, 6),
        ZV_ROW("payment script", zv_m_out, 7),
        ZV_ROW("payment script short", zv_m_out, 8),
        ZV_ROW("payment over the price", zv_m_out, 9),
        ZV_ROW("seller change amount", zv_m_chg, 0),
        ZV_ROW("seller change script", zv_m_chg, 1),
        ZV_ROW("seller change script short", zv_m_chg, 2),
        ZV_ROW("seller change role index", zv_m_chg, 3),
        ZV_ROW("buyer change role index", zv_m_chg, 4),
        ZV_ROW("buyer change script", zv_m_chg, 5),
        ZV_ROW("buyer change script short", zv_m_chg, 6),
    };
    return zv_run_rows(rows, sizeof(rows) / sizeof(rows[0]));
}

static int zv_rows_accepts(void)
{
    static const struct zv_row rows[] = {
        { "buyer token address undecodable", zv_m_pre, 0, ZSWAP_CEREMONY_ERR_ACCEPT },
        { "buyer change address undecodable", zv_m_pre, 1, ZSWAP_CEREMONY_ERR_ACCEPT },
        { "seller payment address undecodable", zv_m_pre, 2, ZSWAP_CEREMONY_ERR_ACCEPT },
        { "seller change address undecodable", zv_m_pre, 3, ZSWAP_CEREMONY_ERR_ACCEPT },
        { "buyer without inputs", zv_m_pre, 4, ZSWAP_CEREMONY_ERR_ACCEPT },
        { "seller input without a script", zv_m_pre, 5, ZSWAP_CEREMONY_ERR_ACCEPT },
        { "buyer deadline off the ad", zv_m_pre, 6, ZSWAP_CEREMONY_ERR_DEADLINE },
        { "seller deadline off the ad", zv_m_pre, 7, ZSWAP_CEREMONY_ERR_DEADLINE },
        { "ad without a token amount", zv_m_pre, 8, ZSWAP_CEREMONY_ERR_AD },
    };
    return zv_run_rows(rows, sizeof(rows) / sizeof(rows[0]));
}

/* ── verify: arguments, clock, omitted change outputs ──────────────── */

static int zv_verify_basics(void)
{
    int failures = 0;
    struct zswap_assembly a;
    memset(&a, 0, sizeof(a));
    ZV_CHECK("basics: fixture", zv_init(&g_w) && zv_assemble(&g_w, &a));
    if (failures) return failures;
    ZV_CHECK("basics: good assembly passes",
             zv_verify(&g_w, &a) == ZSWAP_CEREMONY_OK);
    ZV_CHECK("basics: null ad",
             zswap_ceremony_seller_verify_assembly(
                 NULL, &g_w.buyer, &g_w.seller, &a, ZV_NOW) ==
                 ZSWAP_CEREMONY_ERR_NULL);
    ZV_CHECK("basics: null buyer",
             zswap_ceremony_seller_verify_assembly(
                 &g_w.ad, NULL, &g_w.seller, &a, ZV_NOW) ==
                 ZSWAP_CEREMONY_ERR_NULL);
    ZV_CHECK("basics: null seller",
             zswap_ceremony_seller_verify_assembly(
                 &g_w.ad, &g_w.buyer, NULL, &a, ZV_NOW) ==
                 ZSWAP_CEREMONY_ERR_NULL);
    ZV_CHECK("basics: null assembly",
             zswap_ceremony_seller_verify_assembly(
                 &g_w.ad, &g_w.buyer, &g_w.seller, NULL, ZV_NOW) ==
                 ZSWAP_CEREMONY_ERR_NULL);
    ZV_CHECK("basics: the last live second passes",
             zswap_ceremony_seller_verify_assembly(
                 &g_w.ad, &g_w.buyer, &g_w.seller, &a, ZV_EXPIRES - 1) ==
                 ZSWAP_CEREMONY_OK);
    ZV_CHECK("basics: the expiry second is refused",
             zswap_ceremony_seller_verify_assembly(
                 &g_w.ad, &g_w.buyer, &g_w.seller, &a, ZV_EXPIRES) ==
                 ZSWAP_CEREMONY_ERR_EXPIRED);
    zswap_assembly_free(&a);
    return failures;
}

/* The buyer funds the price and fee to the sat with one input. */
#define ZV_EXACT (ZV_AMOUNT + ZV_FEE)
#define ZV_OVER (ZV_EXACT + 5000)

/* An assembly with the seller input at seller_value and, when buyer_one is
 * not zero, a single buyer input of that value (the two-input fixture
 * otherwise). */
static bool zv_assemble_exact(struct zv *w, int64_t seller_value,
                              int64_t buyer_one, struct zswap_assembly *a)
{
    if (!zv_init(w)) return false;
    w->seller.token_input.value_sats = seller_value;
    if (buyer_one != 0) {
        w->buyer.num_inputs = 1;
        w->buyer.inputs[0].value_sats = buyer_one;
    }
    return zv_assemble(w, a);
}

static int zv_exact_one(const char *name, int64_t seller_value,
                        int64_t buyer_one, int want_seller_idx,
                        int want_buyer_idx, size_t want_vout)
{
    int failures = 0;
    struct zswap_assembly a;
    memset(&a, 0, sizeof(a));
    if (!zv_assemble_exact(&g_w, seller_value, buyer_one, &a)) {
        printf("  zswap verify: %s... FAIL (fixture)\n", name);
        return 1;
    }
    ZV_CHECK(name, zv_verify(&g_w, &a) == ZSWAP_CEREMONY_OK &&
                   a.vout_seller_change == want_seller_idx &&
                   a.vout_buyer_change == want_buyer_idx &&
                   a.tx.num_vout == want_vout);
    zswap_assembly_free(&a);
    return failures;
}

/* Built from one set of terms, checked against terms that differ only in
 * whether a change output is due. Both sides keep the input counts, so the
 * output count is what refuses. */
static int zv_exact_mismatch(const char *name, int64_t built_seller,
                             int64_t built_buyer, int64_t checked_seller,
                             int64_t checked_buyer)
{
    int failures = 0;
    struct zswap_assembly a;
    memset(&a, 0, sizeof(a));
    if (!zv_assemble_exact(&g_w, built_seller, built_buyer, &a)) return 1;
    struct zswap_seller_accept seller = g_w.seller;
    struct zswap_buyer_accept buyer = g_w.buyer;
    seller.token_input.value_sats = checked_seller;
    if (checked_buyer != 0) buyer.inputs[0].value_sats = checked_buyer;
    ZV_CHECK(name, zswap_ceremony_seller_verify_assembly(
                       &g_w.ad, &buyer, &seller, &a, ZV_NOW) == ZV_TERMS);
    zswap_assembly_free(&a);
    return failures;
}

static int zv_exact_role_index(void)
{
    int failures = 0;
    struct zswap_assembly a;
    memset(&a, 0, sizeof(a));
    if (!zv_assemble_exact(&g_w, ZSWAP_TOKEN_DUST_ZAT, 0, &a)) return 1;
    a.vout_seller_change = 3;
    ZV_CHECK("exact: an omitted seller change claims a role index",
             zv_verify(&g_w, &a) == ZV_TERMS);
    a.vout_seller_change = -1;
    a.vout_buyer_change = 4;
    ZV_CHECK("exact: buyer change index follows the omitted seller change",
             zv_verify(&g_w, &a) == ZV_TERMS);
    zswap_assembly_free(&a);
    if (!zv_assemble_exact(&g_w, 10000, ZV_EXACT, &a)) return failures + 1;
    a.vout_buyer_change = 3;
    ZV_CHECK("exact: an omitted buyer change claims a role index",
             zv_verify(&g_w, &a) == ZV_TERMS);
    zswap_assembly_free(&a);
    return failures;
}

static int zv_verify_exact(void)
{
    int failures = 0;
    failures += zv_exact_one("exact: seller input at dust omits seller change",
                             ZSWAP_TOKEN_DUST_ZAT, 0, -1, 3, 4);
    failures += zv_exact_one("exact: buyer funding to the sat omits buyer change",
                             10000, ZV_EXACT, 3, -1, 4);
    failures += zv_exact_one("exact: both change outputs omitted",
                             ZSWAP_TOKEN_DUST_ZAT, ZV_EXACT, -1, -1, 3);
    failures += zv_exact_mismatch("exact: seller change expected, none built",
                                  ZSWAP_TOKEN_DUST_ZAT, 0, 10000, 0);
    failures += zv_exact_mismatch("exact: seller change built, none expected",
                                  10000, 0, ZSWAP_TOKEN_DUST_ZAT, 0);
    failures += zv_exact_mismatch("exact: buyer change expected, none built",
                                  10000, ZV_EXACT, 10000, ZV_OVER);
    failures += zv_exact_mismatch("exact: buyer change built, none expected",
                                  10000, ZV_OVER, 10000, ZV_EXACT);
    failures += zv_exact_role_index();
    return failures;
}

/* ── signer ────────────────────────────────────────────────────────── */

static bool zv_scriptsig_is(const struct script *ss, const struct privkey *key,
                            const uint8_t *sighash, bool *verified)
{
    struct pubkey pk;
    if (!privkey_get_pubkey(key, &pk) || ss->size < 3) return false;
    size_t sig_len = ss->data[0];
    if (ss->size != 1 + sig_len + 1 + pk.size || ss->data[sig_len] != 0x01 ||
        ss->data[1 + sig_len] != pk.size ||
        memcmp(ss->data + 2 + sig_len, pk.vch, pk.size) != 0)
        return false;
    struct uint256 h;
    memcpy(h.data, sighash, 32);
    *verified = pubkey_verify(&pk, &h, ss->data + 1, sig_len - 1);
    return true;
}

static int zv_sign_args(struct zswap_assembly *a)
{
    int failures = 0;
    const uint8_t *sc = g_w.seller.token_input.script_pub_key;
    const struct privkey *key = &g_w.seller_key;
    struct transaction *tx = &a->tx;
    ZV_CHECK("sign: null tx",
             zswap_ceremony_sign_input_p2pkh(NULL, 0, sc, 25, 10000, ZV_BRANCH,
                                             key) == ZSWAP_CEREMONY_ERR_NULL);
    ZV_CHECK("sign: null script",
             zswap_ceremony_sign_input_p2pkh(tx, 0, NULL, 25, 10000, ZV_BRANCH,
                                             key) == ZSWAP_CEREMONY_ERR_NULL);
    ZV_CHECK("sign: null key",
             zswap_ceremony_sign_input_p2pkh(tx, 0, sc, 25, 10000, ZV_BRANCH,
                                             NULL) == ZSWAP_CEREMONY_ERR_NULL);
    ZV_CHECK("sign: index at the input count",
             zswap_ceremony_sign_input_p2pkh(tx, tx->num_vin, sc, 25, 10000,
                                             ZV_BRANCH, key) ==
                 ZSWAP_CEREMONY_ERR_INPUT_INDEX);
    ZV_CHECK("sign: empty script",
             zswap_ceremony_sign_input_p2pkh(tx, 0, sc, 0, 10000, ZV_BRANCH,
                                             key) == ZSWAP_CEREMONY_ERR_ACCEPT);
    ZV_CHECK("sign: script over the field",
             zswap_ceremony_sign_input_p2pkh(
                 tx, 0, sc, ZSWAP_MAX_INPUT_SCRIPT_BYTES + 1, 10000, ZV_BRANCH,
                 key) == ZSWAP_CEREMONY_ERR_ACCEPT);
    uint8_t big[ZSWAP_MAX_INPUT_SCRIPT_BYTES];
    memset(big, 0x51, sizeof(big));
    ZV_CHECK("sign: a field-sized script that is not P2PKH",
             zswap_ceremony_sign_input_p2pkh(
                 tx, 0, big, ZSWAP_MAX_INPUT_SCRIPT_BYTES, 10000, ZV_BRANCH,
                 key) == ZSWAP_CEREMONY_ERR_SCRIPT_TYPE);
    ZV_CHECK("sign: a refused call leaves the input unsigned",
             tx->vin[0].script_sig.size == 0);
    return failures;
}

static int zv_sign_inputs(struct zswap_assembly *a)
{
    int failures = 0;
    struct transaction *tx = &a->tx;
    const struct zswap_swap_input *last = &g_w.buyer.inputs[0];  /* vin[2] */
    uint8_t h2[32];
    ZV_CHECK("sign: last sighash computes",
             zswap_assembly_input_sighash(tx, 2, last->script_pub_key,
                                          last->script_len, last->value_sats,
                                          ZV_BRANCH, h2));
    ZV_CHECK("sign: nothing is signed yet",
             !zswap_ceremony_all_inputs_signed(tx));
    ZV_CHECK("sign: last input",
             zswap_ceremony_sign_input_p2pkh(
                 tx, 2, last->script_pub_key, last->script_len,
                 last->value_sats, ZV_BRANCH, &g_w.buyer_key) ==
                 ZSWAP_CEREMONY_OK);
    ZV_CHECK("sign: only the chosen input carries a script",
             tx->vin[0].script_sig.size == 0 && tx->vin[1].script_sig.size == 0 &&
             tx->vin[2].script_sig.size > 0);
    bool ok2 = false;
    ZV_CHECK("sign: the last input's scriptSig is sig, hash type, pubkey",
             zv_scriptsig_is(&tx->vin[2].script_sig, &g_w.buyer_key, h2, &ok2) &&
             ok2);
    ZV_CHECK("sign: a partly signed tx is not complete",
             !zswap_ceremony_all_inputs_signed(tx));
    return failures;
}

static int zv_sign_rest(struct zswap_assembly *a)
{
    int failures = 0;
    struct transaction *tx = &a->tx;
    const struct zswap_swap_input *mid = &g_w.buyer.inputs[1];   /* vin[1] */
    uint8_t h1[32];
    bool ok1 = false;
    ZV_CHECK("sign: middle sighash computes",
             zswap_assembly_input_sighash(tx, 1, mid->script_pub_key,
                                          mid->script_len, mid->value_sats,
                                          ZV_BRANCH, h1));
    ZV_CHECK("sign: middle input",
             zswap_ceremony_sign_input_p2pkh(
                 tx, 1, mid->script_pub_key, mid->script_len, mid->value_sats,
                 ZV_BRANCH, &g_w.buyer_key) == ZSWAP_CEREMONY_OK);
    ZV_CHECK("sign: the middle input's scriptSig verifies",
             zv_scriptsig_is(&tx->vin[1].script_sig, &g_w.buyer_key, h1, &ok1) &&
             ok1);
    ZV_CHECK("sign: the seller input is still the only gap",
             !zswap_ceremony_all_inputs_signed(tx));
    ZV_CHECK("sign: seller input",
             zswap_ceremony_sign_input_p2pkh(
                 tx, 0, g_w.seller.token_input.script_pub_key,
                 g_w.seller.token_input.script_len, 10000, ZV_BRANCH,
                 &g_w.seller_key) == ZSWAP_CEREMONY_OK);
    ZV_CHECK("sign: all signed", zswap_ceremony_all_inputs_signed(tx));
    return failures;
}

static int zv_sign_tests(void)
{
    int failures = 0;
    struct zswap_assembly a;
    memset(&a, 0, sizeof(a));
    ZV_CHECK("sign: fixture", zv_init(&g_w) && zv_assemble(&g_w, &a));
    if (failures) return failures;
    failures += zv_sign_args(&a);
    failures += zv_sign_inputs(&a);
    failures += zv_sign_rest(&a);
    zswap_assembly_free(&a);
    struct transaction empty;
    transaction_init(&empty);
    ZV_CHECK("sign: null tx is not complete",
             !zswap_ceremony_all_inputs_signed(NULL));
    ZV_CHECK("sign: a tx without inputs is not complete",
             !zswap_ceremony_all_inputs_signed(&empty));
    transaction_free(&empty);
    return failures;
}

/* ── seller partial builder ────────────────────────────────────────── */

static enum zswap_ceremony_error zv_build(struct zv *w,
                                          struct zswap_partial_v1 *p,
                                          struct zswap_assembly *a,
                                          const struct privkey *key)
{
    return zswap_ceremony_seller_build_partial(
        &w->ad, &w->accept, &w->seller, key, ZV_BRANCH, ZV_NOW, p, a);
}

static bool zv_partial_roots_ok(const struct zswap_partial_v1 *p)
{
    uint8_t root[32];
    if (zswap_assembly_root(g_w.accept.quote_root, &g_w.buyer, &g_w.seller,
                            root) != ZSWAP_ASSEMBLY_OK)
        return false;
    return memcmp(p->assembly_root, root, 32) == 0 &&
           memcmp(p->quote_root, g_w.accept.quote_root, 32) == 0 &&
           p->schema_version == ZSWAP_PARTIAL_VERSION;
}

static bool zv_partial_terms_ok(const struct zswap_partial_v1 *p)
{
    const struct zswap_swap_input *in = &p->seller.token_input;
    const struct zswap_swap_input *want = &g_w.seller.token_input;
    return memcmp(in->txid, want->txid, 32) == 0 && in->vout == want->vout &&
           in->value_sats == want->value_sats &&
           in->script_len == want->script_len &&
           memcmp(in->script_pub_key, want->script_pub_key, 25) == 0 &&
           memcmp(p->seller.zcl_recv_address, g_w.seller.zcl_recv_address,
                  ZSWAP_ADDRESS_FIELD_BYTES) == 0 &&
           memcmp(p->seller.change_address, g_w.seller.change_address,
                  ZSWAP_ADDRESS_FIELD_BYTES) == 0 &&
           p->seller.deadline_unix == ZV_EXPIRES;
}

static bool zv_partial_sig_shape_ok(const struct zswap_partial_v1 *p)
{
    if (p->sig_len < ZSWAP_SIG_MIN_BYTES || p->sig_len > ZSWAP_SIG_FIELD_BYTES)
        return false;
    for (size_t i = p->sig_len; i < ZSWAP_SIG_FIELD_BYTES; i++)
        if (p->signature[i] != 0) return false;
    return p->signature[p->sig_len - 1] == 0x01 &&
           zswap_partial_validate(p) == ZSWAP_CEREMONY_OK;
}

static bool zv_partial_sig_verifies(const struct zswap_partial_v1 *p,
                                    const struct zswap_assembly *a,
                                    const struct pubkey *pk)
{
    struct uint256 hash;
    if (!zswap_assembly_input_sighash(&a->tx, 0,
                                      g_w.seller.token_input.script_pub_key, 25,
                                      10000, ZV_BRANCH, hash.data))
        return false;
    return pubkey_verify(pk, &hash, p->signature, (size_t)p->sig_len - 1);
}

static int zv_build_good(void)
{
    int failures = 0;
    struct zswap_partial_v1 p;
    struct zswap_assembly a;
    memset(&a, 0xa5, sizeof(a));
    ZV_CHECK("build: fixture", zv_init(&g_w));
    if (failures) return failures;
    ZV_CHECK("build: builds with the assembly handed back",
             zv_build(&g_w, &p, &a, &g_w.seller_key) == ZSWAP_CEREMONY_OK &&
             a.tx.num_vin == 3 && a.seller_input_count == 1);
    ZV_CHECK("build: roots are the accept's", zv_partial_roots_ok(&p));
    ZV_CHECK("build: seller terms are the seller's", zv_partial_terms_ok(&p));
    struct pubkey pk;
    ZV_CHECK("build: pubkey is the seller key's",
             privkey_get_pubkey(&g_w.seller_key, &pk) &&
             memcmp(p.seller_pubkey, pk.vch, 33) == 0);
    ZV_CHECK("build: the signature is padded and ends in SIGHASH_ALL",
             zv_partial_sig_shape_ok(&p));
    ZV_CHECK("build: the signature verifies over the assembled tx",
             zv_partial_sig_verifies(&p, &a, &pk));
    zswap_assembly_free(&a);
    return failures;
}

static void zv_b_noop(struct zv *w) { (void)w; }
static void zv_b_version(struct zv *w) { w->accept.schema_version = 9; }
static void zv_b_noinputs(struct zv *w) { w->accept.buyer.num_inputs = 0; }
static void zv_b_noscript(struct zv *w) { w->seller.token_input.script_len = 0; }
static void zv_b_ad(struct zv *w) { w->ad.token_amount = 0; }
static void zv_b_short_funds(struct zv *w)
{
    w->accept.buyer.inputs[0].value_sats = 1;
    w->accept.buyer.inputs[1].value_sats = 1;
}
static void zv_b_deadline(struct zv *w) { w->seller.deadline_unix += 1; }
static void zv_b_root(struct zv *w) { w->accept.quote_root[3] ^= 1; }
static void zv_b_script(struct zv *w)
{
    memset(w->seller.token_input.script_pub_key, 0x51, 25);
}

static int zv_build_refusals(void)
{
    static const struct {
        const char *name;
        void (*alter)(struct zv *);
        enum zswap_ceremony_error want;
    } rows[] = {
        { "good terms", zv_b_noop, ZSWAP_CEREMONY_OK },
        { "accept schema version", zv_b_version, ZSWAP_CEREMONY_ERR_ACCEPT },
        { "accept without inputs", zv_b_noinputs, ZSWAP_CEREMONY_ERR_ACCEPT },
        { "seller input without a script", zv_b_noscript, ZSWAP_CEREMONY_ERR_ACCEPT },
        { "ad without a token amount", zv_b_ad, ZSWAP_CEREMONY_ERR_AD },
        { "buyer funds under price and fee", zv_b_short_funds, ZSWAP_CEREMONY_ERR_ASSEMBLY },
        { "seller deadline off the ad", zv_b_deadline, ZSWAP_CEREMONY_ERR_ASSEMBLY },
        { "accept names another ad", zv_b_root, ZSWAP_CEREMONY_ERR_QUOTE_ROOT },
        { "token script is not P2PKH", zv_b_script, ZSWAP_CEREMONY_ERR_SCRIPT_TYPE },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        struct zswap_partial_v1 p;
        struct zswap_assembly a;
        memset(&p, 0xa5, sizeof(p));
        memset(&a, 0xa5, sizeof(a));
        if (!zv_init(&g_w)) return failures + 1;
        rows[i].alter(&g_w);
        enum zswap_ceremony_error e = zv_build(&g_w, &p, &a, &g_w.seller_key);
        static const struct zswap_partial_v1 zero_p = {0};
        static const struct zswap_assembly zero_a = {0};
        bool wiped = memcmp(&p, &zero_p, sizeof(p)) == 0 &&
                     memcmp(&a, &zero_a, sizeof(a)) == 0;
        if (e != rows[i].want || (e != ZSWAP_CEREMONY_OK && !wiped)) {
            printf("  zswap verify: build %s... FAIL (got %d want %d wiped %d)\n",
                   rows[i].name, (int)e, (int)rows[i].want, (int)wiped);
            failures++;
        }
        if (e == ZSWAP_CEREMONY_OK) zswap_assembly_free(&a);
    }
    return failures;
}

static int zv_build_keys(void)
{
    int failures = 0;
    struct zswap_partial_v1 p;
    struct zswap_assembly a;
    struct privkey other;
    zv_key(&other, 0x77);
    ZV_CHECK("build keys: fixture", zv_init(&g_w));
    if (failures) return failures;
    memset(&a, 0, sizeof(a));
    ZV_CHECK("build keys: a key that does not own the input",
             zv_build(&g_w, &p, &a, &other) == ZSWAP_CEREMONY_ERR_KEY_MISMATCH);
    /* An uncompressed key whose own hash is in the script owns the input but
     * cannot ride the 33 byte pubkey field. */
    struct privkey wide = g_w.seller_key;
    wide.fCompressed = false;
    struct pubkey wide_pk;
    uint8_t script[25];
    ZV_CHECK("build keys: uncompressed key derives",
             privkey_get_pubkey(&wide, &wide_pk) &&
             zv_script(&wide, script) == 25);
    memcpy(g_w.seller.token_input.script_pub_key, script, 25);
    ZV_CHECK("build keys: an owning uncompressed key is refused",
             zv_build(&g_w, &p, &a, &wide) == ZSWAP_CEREMONY_ERR_KEY_MISMATCH);
    return failures;
}

static int zv_build_nulls(void)
{
    int failures = 0;
    struct zswap_partial_v1 p;
    struct zswap_partial_v1 *no_partial = NULL;
    ZV_CHECK("build nulls: fixture", zv_init(&g_w));
    if (failures) return failures;
    ZV_CHECK("build nulls: null partial",
             zswap_ceremony_seller_build_partial(
                 &g_w.ad, &g_w.accept, &g_w.seller, &g_w.seller_key, ZV_BRANCH,
                 ZV_NOW, no_partial, NULL) == ZSWAP_CEREMONY_ERR_NULL);
    ZV_CHECK("build nulls: null ad",
             zswap_ceremony_seller_build_partial(
                 NULL, &g_w.accept, &g_w.seller, &g_w.seller_key, ZV_BRANCH,
                 ZV_NOW, &p, NULL) == ZSWAP_CEREMONY_ERR_NULL);
    ZV_CHECK("build nulls: null accept",
             zswap_ceremony_seller_build_partial(
                 &g_w.ad, NULL, &g_w.seller, &g_w.seller_key, ZV_BRANCH, ZV_NOW,
                 &p, NULL) == ZSWAP_CEREMONY_ERR_NULL);
    ZV_CHECK("build nulls: null seller terms",
             zswap_ceremony_seller_build_partial(
                 &g_w.ad, &g_w.accept, NULL, &g_w.seller_key, ZV_BRANCH, ZV_NOW,
                 &p, NULL) == ZSWAP_CEREMONY_ERR_NULL);
    ZV_CHECK("build nulls: null key",
             zswap_ceremony_seller_build_partial(
                 &g_w.ad, &g_w.accept, &g_w.seller, NULL, ZV_BRANCH, ZV_NOW, &p,
                 NULL) == ZSWAP_CEREMONY_ERR_NULL);
    return failures;
}

/* ── buyer partial verifier ────────────────────────────────────────── */

typedef void (*zv_alter)(struct zv *w, struct zswap_partial_v1 *p);

static enum zswap_ceremony_error zv_bv(const struct zswap_partial_v1 *p,
                                       struct transaction *tx)
{
    return zswap_ceremony_buyer_verify_partial(
        &g_w.ad, &g_w.accept, p, ZV_BRANCH, ZV_NOW, tx);
}

/* The seller's root over the (possibly altered) accept tuple. */
static void zv_reroot(struct zv *w, struct zswap_partial_v1 *p)
{
    (void)zswap_assembly_root(w->accept.quote_root, &w->accept.buyer,
                              &p->seller, p->assembly_root);
}

static void zv_a_noinputs(struct zv *w, struct zswap_partial_v1 *p)
{
    (void)p;
    w->accept.buyer.num_inputs = 0;
}
static void zv_a_pubkey_prefix(struct zv *w, struct zswap_partial_v1 *p)
{
    (void)w;
    p->seller_pubkey[0] = 0x04;
}
static void zv_a_accept_root(struct zv *w, struct zswap_partial_v1 *p)
{
    (void)p;
    w->accept.quote_root[3] ^= 1;
}
static void zv_a_partial_root(struct zv *w, struct zswap_partial_v1 *p)
{
    (void)w;
    p->quote_root[3] ^= 1;
}
static void zv_a_accept_deadline(struct zv *w, struct zswap_partial_v1 *p)
{
    (void)p;
    w->accept.buyer.deadline_unix += 1;
}
static void zv_a_partial_deadline(struct zv *w, struct zswap_partial_v1 *p)
{
    (void)w;
    p->seller.deadline_unix += 1;
}
static void zv_a_ad(struct zv *w, struct zswap_partial_v1 *p)
{
    (void)p;
    w->ad.token_amount = 0;
}
static void zv_a_funds(struct zv *w, struct zswap_partial_v1 *p)
{
    w->accept.buyer.inputs[0].value_sats = 1;
    w->accept.buyer.inputs[1].value_sats = 1;
    zv_reroot(w, p);
}
static void zv_a_script(struct zv *w, struct zswap_partial_v1 *p)
{
    memset(p->seller.token_input.script_pub_key, 0x51, 25);
    zv_reroot(w, p);
}
static void zv_a_bad_pubkey(struct zv *w, struct zswap_partial_v1 *p)
{
    (void)w;
    p->seller_pubkey[0] = 0x02;
    memset(p->seller_pubkey + 1, 0xff, 32);
}

static int zv_buyer_refusals(void)
{
    static const struct {
        const char *name;
        zv_alter alter;
        enum zswap_ceremony_error want;
    } rows[] = {
        { "accept without inputs", zv_a_noinputs, ZSWAP_CEREMONY_ERR_ACCEPT },
        { "partial pubkey prefix", zv_a_pubkey_prefix, ZSWAP_CEREMONY_ERR_ACCEPT },
        { "accept names another ad", zv_a_accept_root, ZSWAP_CEREMONY_ERR_QUOTE_ROOT },
        { "partial names another ad", zv_a_partial_root, ZSWAP_CEREMONY_ERR_QUOTE_ROOT },
        { "accept deadline off the ad", zv_a_accept_deadline, ZSWAP_CEREMONY_ERR_DEADLINE },
        { "partial deadline off the ad", zv_a_partial_deadline, ZSWAP_CEREMONY_ERR_DEADLINE },
        { "ad without a token amount", zv_a_ad, ZSWAP_CEREMONY_ERR_AD },
        { "funds under price and fee, root agreed", zv_a_funds, ZSWAP_CEREMONY_ERR_ASSEMBLY },
        { "token script not P2PKH, root agreed", zv_a_script, ZSWAP_CEREMONY_ERR_SCRIPT_TYPE },
        { "pubkey off the curve", zv_a_bad_pubkey, ZSWAP_CEREMONY_ERR_PUBKEY },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        struct zswap_partial_v1 p;
        struct transaction tx;
        static const struct transaction zero_tx = {0};
        if (!zv_init(&g_w) || zv_build(&g_w, &p, NULL, &g_w.seller_key) !=
                                  ZSWAP_CEREMONY_OK) {
            printf("  zswap verify: buyer %s... FAIL (fixture)\n", rows[i].name);
            failures++;
            continue;
        }
        rows[i].alter(&g_w, &p);
        memset(&tx, 0xa5, sizeof(tx));
        enum zswap_ceremony_error e = zv_bv(&p, &tx);
        if (e != rows[i].want || memcmp(&tx, &zero_tx, sizeof(tx)) != 0) {
            printf("  zswap verify: buyer %s... FAIL (got %d want %d)\n",
                   rows[i].name, (int)e, (int)rows[i].want);
            failures++;
        }
    }
    return failures;
}

/* Replace the partial's S with n - S: still a valid ECDSA signature, no
 * longer low-S. The DER is rebuilt around the kept R. */
static bool zv_flip_s(struct zswap_partial_v1 *p)
{
    static const uint8_t n[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
        0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41 };
    const uint8_t *d = p->signature;
    size_t rl = d[3];
    if (d[0] != 0x30 || d[2] != 0x02 || rl > 33 || d[4 + rl] != 0x02)
        return false;
    size_t sl = d[5 + rl];
    if (sl > 33) return false;
    uint8_t s32[32] = {0}, ns[32];
    size_t skip = sl > 32 ? sl - 32 : 0;
    memcpy(s32 + (32 - (sl - skip)), d + 6 + rl + skip, sl - skip);
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int v = (int)n[i] - (int)s32[i] - borrow;
        borrow = v < 0;
        ns[i] = (uint8_t)(v + (borrow ? 256 : 0));
    }
    uint8_t out[ZSWAP_SIG_FIELD_BYTES + 8] = {0};
    size_t pos = 0;
    out[pos++] = 0x30;
    size_t lenpos = pos++;
    out[pos++] = 0x02;
    out[pos++] = (uint8_t)rl;
    memcpy(out + pos, d + 4, rl);
    pos += rl;
    out[pos++] = 0x02;
    const bool pad = (ns[0] & 0x80) != 0;
    out[pos++] = (uint8_t)(32 + (pad ? 1 : 0));
    if (pad) out[pos++] = 0;
    memcpy(out + pos, ns, 32);
    pos += 32;
    out[lenpos] = (uint8_t)(pos - 2);
    out[pos++] = 0x01;
    if (pos > ZSWAP_SIG_FIELD_BYTES) return false;
    memset(p->signature, 0, ZSWAP_SIG_FIELD_BYTES);
    memcpy(p->signature, out, pos);
    p->sig_len = (uint8_t)pos;
    return true;
}

static bool zv_scriptsig_matches_partial(const struct script *ss,
                                         const struct zswap_partial_v1 *p)
{
    const size_t sl = p->sig_len;
    return ss->size == 1 + sl + 1 + 33 && ss->data[0] == sl &&
           memcmp(ss->data + 1, p->signature, sl) == 0 &&
           ss->data[1 + sl] == 33 &&
           memcmp(ss->data + 2 + sl, p->seller_pubkey, 33) == 0;
}

static int zv_buyer_good(void)
{
    int failures = 0;
    struct zswap_partial_v1 p;
    struct transaction tx;
    ZV_CHECK("buyer: fixture", zv_init(&g_w) &&
             zv_build(&g_w, &p, NULL, &g_w.seller_key) == ZSWAP_CEREMONY_OK);
    if (failures) return failures;
    memset(&tx, 0xa5, sizeof(tx));
    ZV_CHECK("buyer: good partial verifies", zv_bv(&p, &tx) == ZSWAP_CEREMONY_OK);
    ZV_CHECK("buyer: the half-signed tx has three inputs", tx.num_vin == 3);
    ZV_CHECK("buyer: the seller's scriptSig is the partial's signature and key",
             zv_scriptsig_matches_partial(&tx.vin[0].script_sig, &p));
    struct uint256 before = tx.hash;
    transaction_compute_hash(&tx);
    ZV_CHECK("buyer: the tx hash was taken after the signature went in",
             memcmp(before.data, tx.hash.data, 32) == 0);
    transaction_free(&tx);
    return failures;
}

static int zv_buyer_nulls_and_low_s(void)
{
    int failures = 0;
    struct zswap_partial_v1 p;
    struct transaction tx;
    ZV_CHECK("buyer nulls: fixture", zv_init(&g_w) &&
             zv_build(&g_w, &p, NULL, &g_w.seller_key) == ZSWAP_CEREMONY_OK);
    if (failures) return failures;
    ZV_CHECK("buyer nulls: null ad",
             zswap_ceremony_buyer_verify_partial(
                 NULL, &g_w.accept, &p, ZV_BRANCH, ZV_NOW, &tx) ==
                 ZSWAP_CEREMONY_ERR_NULL);
    ZV_CHECK("buyer nulls: null accept",
             zswap_ceremony_buyer_verify_partial(
                 &g_w.ad, NULL, &p, ZV_BRANCH, ZV_NOW, &tx) ==
                 ZSWAP_CEREMONY_ERR_NULL);
    ZV_CHECK("buyer nulls: null partial",
             zswap_ceremony_buyer_verify_partial(
                 &g_w.ad, &g_w.accept, NULL, ZV_BRANCH, ZV_NOW, &tx) ==
                 ZSWAP_CEREMONY_ERR_NULL);
    ZV_CHECK("buyer nulls: null output",
             zswap_ceremony_buyer_verify_partial(
                 &g_w.ad, &g_w.accept, &p, ZV_BRANCH, ZV_NOW, NULL) ==
                 ZSWAP_CEREMONY_ERR_NULL);
    ZV_CHECK("low-s: the built signature is low-S",
             pubkey_check_low_s(p.signature, (size_t)p.sig_len - 1));
    ZV_CHECK("low-s: flipping S works", zv_flip_s(&p));
    ZV_CHECK("low-s: the flipped signature is high-S",
             !pubkey_check_low_s(p.signature, (size_t)p.sig_len - 1) &&
             zswap_partial_validate(&p) == ZSWAP_CEREMONY_OK);
    ZV_CHECK("low-s: a high-S signature is refused",
             zv_bv(&p, &tx) == ZSWAP_CEREMONY_ERR_SIGNATURE);
    return failures;
}

int zswap_ceremony_verify_tests(void)
{
    int failures = 0;
    failures += zv_buyer_refusals();
    failures += zv_buyer_good();
    failures += zv_buyer_nulls_and_low_s();
    failures += zv_verify_basics();
    failures += zv_rows_shape();
    failures += zv_rows_money();
    failures += zv_rows_outputs();
    failures += zv_rows_accepts();
    failures += zv_verify_exact();
    failures += zv_sign_tests();
    failures += zv_build_good();
    failures += zv_build_refusals();
    failures += zv_build_keys();
    failures += zv_build_nulls();
    return failures;
}
