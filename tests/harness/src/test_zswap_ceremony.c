/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zswap_ceremony — the deterministic swap assembler
 * (contexts/market/modules/zswap/zswap_assembly.*) and the 2-message ceremony wires
 * (contexts/market/modules/zswap/zswap_ceremony.*).
 *
 * Golden KATs: a fixed (ad, buyer accept, seller accept) tuple pins the
 * exact unsigned transaction bytes, the assembly_root, the zswap_accept.v1
 * wire, the zswap_partial.v1 wire (RFC6979 makes the seller's signature
 * deterministic), and the final fully-signed transaction. Negative tests:
 * money math (insufficient / zero fee / under-dust seller input), canonical
 * ordering (unsorted gets sorted; an unsorted wire is refused), exact-size
 * rejection (trailing byte, truncation), magic/version, SIGHASH_ALL-only
 * signatures, and the full ceremony tamper matrix. No datadir, no chain
 * state — address decoding reads the process chain params the runner
 * selects (CHAIN_MAIN). */

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

#include <stdio.h>
#include <string.h>

#define ZSC_CHECK(name, expr) do {                                    \
    if (expr) { printf("  zswap_ceremony: %s... OK\n", (name)); }     \
    else { printf("  zswap_ceremony: %s... FAIL\n", (name));          \
        failures++; }                                                 \
} while (0)

#define ZSC_ISSUED 1754000000LL
#define ZSC_EXPIRES (ZSC_ISSUED + 45LL)
#define ZSC_NOW (ZSC_ISSUED + 10LL)
#define ZSC_NONCE 0x0102030405060708ULL
#define ZSC_TOKEN_AMOUNT 500000ULL
#define ZSC_ZCL_AMOUNT 125000000ULL
#define ZSC_FEE_SATS 10000ULL

/* Sapling consensus branch id — the epoch both signers must agree on. */
#define ZSC_BRANCH_ID 0x76b809bbU

/* Seller token input: 10000 sats (546 dust to the buyer, 9454 change). */
#define ZSC_SELLER_INPUT_VALUE 10000LL
/* Buyer inputs: 150000000 + 50000000 = 200000000 sats in, 125000000 price,
 * 10000 fee, 74990000 change. */
#define ZSC_BUYER_IN_A_VALUE 150000000LL
#define ZSC_BUYER_IN_B_VALUE 50000000LL

/* Pinned golden vectors for the fixture below (sealed ad: net[i]=0xA0+i,
 * ed25519 seed 0x11, token[i]=0x40+i, nonce ZSC_NONCE, token_amount
 * ZSC_TOKEN_AMOUNT, zcl_amount ZSC_ZCL_AMOUNT, issued/expires ZSC_ISSUED/
 * ZSC_EXPIRES; seller key 0x31 (recv) / 0x32 (change), buyer key 0x42
 * (recv+inputs) / 0x43 (change); seller input txid[i]=0x30+i vout 2 value
 * 10000; buyer inputs txid[i]=0x50+i vout 1 value 150000000 and
 * txid[i]=0x60+i vout 0 value 50000000; fee ZSC_FEE_SATS; branch
 * ZSC_BRANCH_ID). Empty strings print the computed value and FAIL — a KAT
 * is never a hollow pass. */
#define ZSC_KAT_TX_HEX "0400008085202f8903303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f0200000000ffffffff505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f0100000000ffffffff606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0000000000ffffffff050000000000000000376a04534c500001010453454e44205f5e5d5c5b5a595857565554535251504f4e4d4c4b4a4948474645444342414008000000000007a12022020000000000001976a91414db4138d56a2ecfb10881a9be394d9f321985b288ac40597307000000001976a9148320611ff032223c1f4bb1fbbd2291fd2b3f43d988acee240000000000001976a914e13e93c4d1c15865bfa3cd3295a5e45b2a075e8e88acb0417804000000001976a914331eb609f3aacffe680f86309d6b7470e7215b0c88ac00000000000000000000000000000000000000"
#define ZSC_KAT_ASSEMBLY_ROOT_HEX "d62ba75743e52fcdd2c4b42c6f3a66deb18cf034d33394d6a8c1342a0e565c6b"
#define ZSC_KAT_ACCEPT_WIRE_HEX "5a53574143500d0a0100e104ed1f04da7980152906ccd88775cf615ba0e3ebccf89f4acb41da7b7dacd802505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f0100000080d1f008000000001976a91414db4138d56a2ecfb10881a9be394d9f321985b288ac606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0000000080f0fa02000000001976a91414db4138d56a2ecfb10881a9be394d9f321985b288ac74314b6d744247357976707a6f6534383745776e73736d52396e683935586a66336439000000000000000000000000000000000000000000000000000000000074314e587546786f4366674a714277326d4c5177544173386576424d59324d796f684800000000000000000000000000000000000000000000000000000000001027000000000000adea8b6800000000"
#define ZSC_KAT_PARTIAL_WIRE_HEX "5a535750544c0d0a0100e104ed1f04da7980152906ccd88775cf615ba0e3ebccf89f4acb41da7b7dacd8d62ba75743e52fcdd2c4b42c6f3a66deb18cf034d33394d6a8c1342a0e565c6b303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f0200000010270000000000001976a9148320611ff032223c1f4bb1fbbd2291fd2b3f43d988ac74315670774b45315064587534424237315976595a77634b4d66444a375169483846540000000000000000000000000000000000000000000000000000000000743165516231535239657a457a33414578543469774375544b42784e3436754a5470630000000000000000000000000000000000000000000000000000000000adea8b6800000000036930f46dd0b16d866d59d1054aa63298b357499cd1862ef16f3f55f1cafceb82483045022100e2d3b9df2e11aa0797f245d3cba97ccf4b982458314202ee9c2beb1c36ec4f7c02200f7609eebb7a75d3b3e75d28d1455660bbdd64b712ca401b130c597059254d100100"
#define ZSC_KAT_FINAL_TX_HEX "0400008085202f8903303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f020000006b483045022100e2d3b9df2e11aa0797f245d3cba97ccf4b982458314202ee9c2beb1c36ec4f7c02200f7609eebb7a75d3b3e75d28d1455660bbdd64b712ca401b130c597059254d100121036930f46dd0b16d866d59d1054aa63298b357499cd1862ef16f3f55f1cafceb82ffffffff505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f010000006a47304402203d7c3f4fa57e910c348778c3471bd688d358e16f0ff4bb28b83a0c0261d53d650220499e7cf0ff505de24f42a3b5def8fd71321740c21972712b146482076e22a16401210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1cffffffff606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f000000006a4730440220336b6435e33ac4f03c5044537a14e7438d5ef423bd2083ba67d52cbcd87c5ced02207a69ee4508ee53086bd48e52e7c192b70238cbb4301e23840e2f9751cb35543401210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1cffffffff050000000000000000376a04534c500001010453454e44205f5e5d5c5b5a595857565554535251504f4e4d4c4b4a4948474645444342414008000000000007a12022020000000000001976a91414db4138d56a2ecfb10881a9be394d9f321985b288ac40597307000000001976a9148320611ff032223c1f4bb1fbbd2291fd2b3f43d988acee240000000000001976a914e13e93c4d1c15865bfa3cd3295a5e45b2a075e8e88acb0417804000000001976a914331eb609f3aacffe680f86309d6b7470e7215b0c88ac00000000000000000000000000000000000000"

#define ZSC_TX_BUF_BYTES 4096u

static void zsc_hex(const uint8_t *bytes, size_t len, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hexd[(bytes[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[bytes[i] & 0xf];
    }
    out[2 * len] = '\0';
}

static bool zsc_kat_pin(const char *name, const char *expect, const char *got)
{
    if (expect[0] == '\0') {
        printf("  zswap_ceremony: KAT(%s)=%s\n", name, got);
        return false;
    }
    return strcmp(expect, got) == 0;
}

/* ── fixtures ──────────────────────────────────────────────────────── */

/* A deterministic compressed secp256k1 key from a repeated byte. */
static void zsc_key(struct privkey *key, uint8_t fill)
{
    memset(key->vch, fill, 32);
    key->fValid = true;
    key->fCompressed = true;
}

static void zsc_pattern32(uint8_t out[32], uint8_t base)
{
    for (size_t i = 0; i < 32; i++) out[i] = (uint8_t)(base + i);
}

/* The P2PKH scriptPubKey paying key's hash160: 76 a9 14 <20> 88 ac. */
static size_t zsc_p2pkh_script(const struct privkey *key, uint8_t out[25])
{
    struct pubkey pk;
    if (!privkey_get_pubkey(key, &pk)) return 0;
    struct key_id kid = pubkey_get_id(&pk);
    out[0] = 0x76;
    out[1] = 0xa9;
    out[2] = 0x14;
    memcpy(out + 3, kid.id.data, 20);
    out[23] = 0x88;
    out[24] = 0xac;
    return 25;
}

/* The mainnet Base58Check t-address for key's hash160. */
static bool zsc_address(const struct privkey *key,
                        char out[ZSWAP_ADDRESS_FIELD_BYTES])
{
    struct pubkey pk;
    if (!privkey_get_pubkey(key, &pk)) return false;
    struct tx_destination dest;
    dest.type = DEST_KEY_ID;
    dest.id.key = pubkey_get_id(&pk);
    const struct chain_params *cp = chain_params_get();
    size_t pk_len, sc_len;
    const unsigned char *pk_pfx =
        chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc_pfx =
        chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_len);
    return encode_destination(&dest, pk_pfx, pk_len, sc_pfx, sc_len,
                              out, ZSWAP_ADDRESS_FIELD_BYTES);
}

/* The sealed ad every ceremony fixture binds to. */
static bool zsc_ad(struct zswap_quote_v1 *q)
{
    memset(q, 0, sizeof(*q));
    q->schema_version = ZSWAP_QUOTE_VERSION;
    zsc_pattern32(q->network_genesis_root, 0xa0);
    uint8_t seed[32];
    memset(seed, 0x11, sizeof(seed));
    uint8_t sk[32];
    ed25519_keypair(q->seller_pubkey, sk, seed);
    q->nonce = ZSC_NONCE;
    zsc_pattern32(q->token_id, 0x40);
    q->token_amount = ZSC_TOKEN_AMOUNT;
    q->zcl_amount = ZSC_ZCL_AMOUNT;
    q->issued_unix = ZSC_ISSUED;
    q->expires_unix = ZSC_EXPIRES;
    return zswap_quote_seal(q, seed) == ZSWAP_QUOTE_OK;
}

static void zsc_fill_input(struct zswap_swap_input *in, uint8_t txid_base,
                           uint32_t vout, int64_t value,
                           const uint8_t *script, uint16_t script_len)
{
    memset(in, 0, sizeof(*in));
    zsc_pattern32(in->txid, txid_base);
    in->vout = vout;
    in->value_sats = value;
    in->script_len = script_len;
    memcpy(in->script_pub_key, script, script_len);
}

/* The buyer accept. Input A (txid 0x50..) sorts before input B (txid
 * 0x60..); the fixture lists B FIRST so every consumer exercises the
 * canonical sort. */
static bool zsc_buyer(struct zswap_buyer_accept *buyer)
{
    memset(buyer, 0, sizeof(*buyer));
    uint8_t script[25];
    struct privkey buyer_key;
    zsc_key(&buyer_key, 0x42);
    if (zsc_p2pkh_script(&buyer_key, script) != 25) return false;
    buyer->num_inputs = 2;
    zsc_fill_input(&buyer->inputs[0], 0x60, 0, ZSC_BUYER_IN_B_VALUE,
                   script, 25);
    zsc_fill_input(&buyer->inputs[1], 0x50, 1, ZSC_BUYER_IN_A_VALUE,
                   script, 25);
    struct privkey recv_key, change_key;
    zsc_key(&recv_key, 0x42);
    zsc_key(&change_key, 0x43);
    if (!zsc_address(&recv_key, buyer->token_recv_address) ||
        !zsc_address(&change_key, buyer->change_address))
        return false;
    buyer->fee_sats = ZSC_FEE_SATS;
    buyer->deadline_unix = ZSC_EXPIRES;
    return true;
}

/* The seller accept: one token input (txid 0x30.., vout 2) owned by the
 * seller key, receive/change on two distinct seller addresses. */
static bool zsc_seller(struct zswap_seller_accept *seller)
{
    memset(seller, 0, sizeof(*seller));
    uint8_t script[25];
    struct privkey seller_key;
    zsc_key(&seller_key, 0x31);
    if (zsc_p2pkh_script(&seller_key, script) != 25) return false;
    zsc_fill_input(&seller->token_input, 0x30, 2, ZSC_SELLER_INPUT_VALUE,
                   script, 25);
    struct privkey change_key;
    zsc_key(&change_key, 0x32);
    if (!zsc_address(&seller_key, seller->zcl_recv_address) ||
        !zsc_address(&change_key, seller->change_address))
        return false;
    seller->deadline_unix = ZSC_EXPIRES;
    return true;
}

static bool zsc_assembly(struct zswap_quote_v1 *ad,
                         struct zswap_buyer_accept *buyer,
                         struct zswap_seller_accept *seller,
                         struct zswap_assembly *out)
{
    return zsc_ad(ad) && zsc_buyer(buyer) && zsc_seller(seller) &&
           zswap_assemble(ad, buyer, seller, out) == ZSWAP_ASSEMBLY_OK;
}

/* ── KAT ───────────────────────────────────────────────────────────── */

static int t_kat(void)
{
    int failures = 0;
    struct zswap_quote_v1 ad;
    struct zswap_buyer_accept buyer;
    struct zswap_seller_accept seller;
    struct zswap_assembly assembly;
    ZSC_CHECK("kat: fixture assembles",
              zsc_assembly(&ad, &buyer, &seller, &assembly));

    uint8_t tx_bytes[ZSC_TX_BUF_BYTES];
    size_t tx_len = 0;
    ZSC_CHECK("kat: unsigned tx serializes",
              zswap_assembly_tx_serialize(&assembly.tx, tx_bytes,
                                          sizeof(tx_bytes), &tx_len));
    /* Keep the unsigned bytes: the final-tx serialization below reuses the
     * scratch buffer, and the re-assembly check compares against these. */
    uint8_t unsigned_bytes[ZSC_TX_BUF_BYTES];
    memcpy(unsigned_bytes, tx_bytes, tx_len);
    size_t unsigned_len = tx_len;
    char hex[2 * ZSC_TX_BUF_BYTES + 1];
    zsc_hex(tx_bytes, tx_len, hex);
    ZSC_CHECK("kat: unsigned tx golden",
              zsc_kat_pin("tx", ZSC_KAT_TX_HEX, hex));

    uint8_t quote_root[32], assembly_root[32];
    ZSC_CHECK("kat: roots compute",
              zswap_quote_root(&ad, quote_root) == ZSWAP_QUOTE_OK &&
              zswap_assembly_root(quote_root, &buyer, &seller,
                                  assembly_root) == ZSWAP_ASSEMBLY_OK);
    zsc_hex(assembly_root, 32, hex);
    ZSC_CHECK("kat: assembly root golden",
              zsc_kat_pin("assembly_root", ZSC_KAT_ASSEMBLY_ROOT_HEX, hex));

    struct zswap_accept_v1 accept;
    memset(&accept, 0, sizeof(accept));
    accept.schema_version = ZSWAP_ACCEPT_VERSION;
    memcpy(accept.quote_root, quote_root, 32);
    accept.buyer = buyer;
    uint8_t accept_wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    size_t accept_len = 0;
    ZSC_CHECK("kat: accept encodes",
              zswap_accept_encode(&accept, accept_wire, sizeof(accept_wire),
                                  &accept_len) == ZSWAP_CEREMONY_OK);
    zsc_hex(accept_wire, accept_len, hex);
    ZSC_CHECK("kat: accept wire golden",
              zsc_kat_pin("accept", ZSC_KAT_ACCEPT_WIRE_HEX, hex));

    struct privkey seller_key;
    zsc_key(&seller_key, 0x31);
    struct zswap_partial_v1 partial;
    ZSC_CHECK("kat: seller builds partial",
              zswap_ceremony_seller_build_partial(
                  &ad, &accept, &seller, &seller_key, ZSC_BRANCH_ID,
                  ZSC_NOW, &partial, NULL) == ZSWAP_CEREMONY_OK);
    uint8_t partial_wire[ZSWAP_PARTIAL_WIRE_MAX_BYTES];
    size_t partial_len = 0;
    ZSC_CHECK("kat: partial encodes",
              zswap_partial_encode(&partial, partial_wire,
                                   sizeof(partial_wire), &partial_len) ==
                  ZSWAP_CEREMONY_OK);
    zsc_hex(partial_wire, partial_len, hex);
    ZSC_CHECK("kat: partial wire golden",
              zsc_kat_pin("partial", ZSC_KAT_PARTIAL_WIRE_HEX, hex));

    /* Full ceremony: buyer verifies, signs his inputs, serializes the
     * broadcast-ready transaction. */
    struct zswap_partial_v1 partial_back;
    struct transaction final_tx;
    ZSC_CHECK("kat: partial decodes",
              zswap_partial_decode(partial_wire, partial_len,
                                   &partial_back) == ZSWAP_CEREMONY_OK);
    ZSC_CHECK("kat: buyer verifies partial",
              zswap_ceremony_buyer_verify_partial(
                  &ad, &accept, &partial_back, ZSC_BRANCH_ID, ZSC_NOW,
                  &final_tx) == ZSWAP_CEREMONY_OK);
    struct privkey buyer_key;
    zsc_key(&buyer_key, 0x42);
    uint8_t buyer_script[25];
    zsc_p2pkh_script(&buyer_key, buyer_script);
    bool signed_ok =
        zswap_ceremony_sign_input_p2pkh(&final_tx, 1, buyer_script, 25,
                                        ZSC_BUYER_IN_A_VALUE, ZSC_BRANCH_ID,
                                        &buyer_key) == ZSWAP_CEREMONY_OK &&
        zswap_ceremony_sign_input_p2pkh(&final_tx, 2, buyer_script, 25,
                                        ZSC_BUYER_IN_B_VALUE, ZSC_BRANCH_ID,
                                        &buyer_key) == ZSWAP_CEREMONY_OK;
    ZSC_CHECK("kat: buyer signs both inputs", signed_ok);
    ZSC_CHECK("kat: all inputs signed",
              zswap_ceremony_all_inputs_signed(&final_tx));
    size_t final_len = 0;
    ZSC_CHECK("kat: final tx serializes",
              zswap_assembly_tx_serialize(&final_tx, tx_bytes,
                                          sizeof(tx_bytes), &final_len));
    zsc_hex(tx_bytes, final_len, hex);
    ZSC_CHECK("kat: final tx golden",
              zsc_kat_pin("final_tx", ZSC_KAT_FINAL_TX_HEX, hex));
    transaction_free(&final_tx);

    /* Byte-identical re-assembly: the whole point of the deterministic
     * assembler. */
    struct zswap_assembly again;
    ZSC_CHECK("kat: re-assembly is byte-identical",
              zswap_assemble(&ad, &buyer, &seller, &again) ==
                  ZSWAP_ASSEMBLY_OK);
    uint8_t tx2[ZSC_TX_BUF_BYTES];
    size_t tx2_len = 0;
    ZSC_CHECK("kat: re-assembly serializes identically",
              zswap_assembly_tx_serialize(&again.tx, tx2, sizeof(tx2),
                                          &tx2_len) &&
              tx2_len == unsigned_len &&
              memcmp(unsigned_bytes, tx2, unsigned_len) == 0);
    zswap_assembly_free(&again);
    zswap_assembly_free(&assembly);
    return failures;
}

/* ── canonical ordering ────────────────────────────────────────────── */

static int t_ordering(void)
{
    int failures = 0;
    struct zswap_quote_v1 ad;
    struct zswap_buyer_accept buyer;
    struct zswap_seller_accept seller;
    struct zswap_assembly assembly;
    ZSC_CHECK("order: fixture assembles",
              zsc_assembly(&ad, &buyer, &seller, &assembly));

    /* The fixture listed input B (txid 0x60..) before input A (txid 0x50..);
     * the assembled vin is the canonical sort: seller input, then A, then B. */
    uint8_t txid_a[32], txid_b[32];
    zsc_pattern32(txid_a, 0x50);
    zsc_pattern32(txid_b, 0x60);
    ZSC_CHECK("order: unsorted inputs get sorted",
              assembly.tx.num_vin == 3 &&
              memcmp(assembly.tx.vin[1].prevout.hash.data, txid_a, 32) == 0 &&
              assembly.tx.vin[1].prevout.n == 1 &&
              memcmp(assembly.tx.vin[2].prevout.hash.data, txid_b, 32) == 0 &&
              assembly.tx.vin[2].prevout.n == 0);

    /* Encode sorts a copy too: the wire is input-order independent. */
    struct zswap_buyer_accept sorted = buyer;
    struct zswap_swap_input tmp = sorted.inputs[0];
    sorted.inputs[0] = sorted.inputs[1];
    sorted.inputs[1] = tmp;
    uint8_t w1[1024], w2[1024];
    size_t l1 = 0, l2 = 0;
    ZSC_CHECK("order: serialization is order-independent",
              zswap_buyer_accept_serialize(&buyer, w1, sizeof(w1), &l1) ==
                  ZSWAP_ASSEMBLY_OK &&
              zswap_buyer_accept_serialize(&sorted, w2, sizeof(w2), &l2) ==
                  ZSWAP_ASSEMBLY_OK &&
              l1 == l2 && memcmp(w1, w2, l1) == 0);

    /* An unsorted WIRE is refused: swap the two 70-byte input records in a
     * full accept wire and decode must name INPUT_ORDER. */
    uint8_t quote_root[32];
    ZSC_CHECK("order: quote root computes",
              zswap_quote_root(&ad, quote_root) == ZSWAP_QUOTE_OK);
    struct zswap_accept_v1 accept;
    memset(&accept, 0, sizeof(accept));
    accept.schema_version = ZSWAP_ACCEPT_VERSION;
    memcpy(accept.quote_root, quote_root, 32);
    accept.buyer = buyer;
    uint8_t wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    size_t wire_len = 0;
    ZSC_CHECK("order: accept encodes",
              zswap_accept_encode(&accept, wire, sizeof(wire), &wire_len) ==
                  ZSWAP_CEREMONY_OK);
    const size_t input_off = 8 + 2 + 32 + 1; /* magic, version, root, count */
    const size_t rec = 32 + 4 + 8 + 1 + 25;
    uint8_t save[70];
    memcpy(save, wire + input_off, rec);
    memcpy(wire + input_off, wire + input_off + rec, rec);
    memcpy(wire + input_off + rec, save, rec);
    struct zswap_accept_v1 back;
    ZSC_CHECK("order: unsorted wire refused",
              zswap_accept_decode(wire, wire_len, &back) ==
                  ZSWAP_CEREMONY_ERR_INPUT_ORDER);

    /* Duplicate outpoints are never canonical. */
    struct zswap_buyer_accept dup = buyer;
    dup.inputs[1] = dup.inputs[0];
    ZSC_CHECK("order: duplicate buyer outpoint refused",
              zswap_assemble(&ad, &dup, &seller, &assembly) ==
                  ZSWAP_ASSEMBLY_ERR_INPUT_ORDER);
    struct zswap_buyer_accept cross = buyer;
    cross.inputs[0] = seller.token_input;
    ZSC_CHECK("order: cross-party duplicate refused",
              zswap_assemble(&ad, &cross, &seller, &assembly) ==
                  ZSWAP_ASSEMBLY_ERR_INPUT_ORDER);
    return failures;
}

/* ── assembler money-math negatives ────────────────────────────────── */

static int t_assembly_negatives(void)
{
    int failures = 0;
    struct zswap_quote_v1 ad;
    struct zswap_buyer_accept buyer;
    struct zswap_seller_accept seller;
    struct zswap_assembly assembly;
    ZSC_CHECK("neg: fixture assembles",
              zsc_assembly(&ad, &buyer, &seller, &assembly));
    zswap_assembly_free(&assembly);

    /* Insufficient buyer funds: inputs < price + fee. */
    struct zswap_buyer_accept x = buyer;
    x.inputs[0].value_sats = 1000;
    x.inputs[1].value_sats = 1000;
    ZSC_CHECK("neg: insufficient buyer inputs",
              zswap_assemble(&ad, &x, &seller, &assembly) ==
                  ZSWAP_ASSEMBLY_ERR_INSUFFICIENT);
    /* Fee too high eats the whole margin: inputs == price, fee > 0. */
    x = buyer;
    x.inputs[0].value_sats = (int64_t)ZSC_ZCL_AMOUNT;
    x.num_inputs = 1;
    ZSC_CHECK("neg: fee too high",
              zswap_assemble(&ad, &x, &seller, &assembly) ==
                  ZSWAP_ASSEMBLY_ERR_INSUFFICIENT);
    /* Zero fee is refused outright. */
    x = buyer;
    x.fee_sats = 0;
    ZSC_CHECK("neg: zero fee",
              zswap_assemble(&ad, &x, &seller, &assembly) ==
                  ZSWAP_ASSEMBLY_ERR_FEE);
    /* Exact funding (change 0) omits the buyer change output. */
    x = buyer;
    x.inputs[0].value_sats = (int64_t)ZSC_ZCL_AMOUNT + (int64_t)ZSC_FEE_SATS;
    x.num_inputs = 1;
    ZSC_CHECK("neg: exact funding omits buyer change",
              zswap_assemble(&ad, &x, &seller, &assembly) ==
                  ZSWAP_ASSEMBLY_OK &&
              assembly.vout_buyer_change == -1 &&
              assembly.tx.num_vout == 4);
    zswap_assembly_free(&assembly);

    /* A seller input under the dust it must carry. */
    struct zswap_seller_accept s = seller;
    s.token_input.value_sats = ZSWAP_TOKEN_DUST_ZAT - 1;
    ZSC_CHECK("neg: seller input under dust",
              zswap_assemble(&ad, &buyer, &s, &assembly) ==
                  ZSWAP_ASSEMBLY_ERR_SELLER_DUST);
    /* Exact-dust seller input omits the seller change output. */
    s = seller;
    s.token_input.value_sats = ZSWAP_TOKEN_DUST_ZAT;
    ZSC_CHECK("neg: exact-dust seller omits change",
              zswap_assemble(&ad, &buyer, &s, &assembly) ==
                  ZSWAP_ASSEMBLY_OK &&
              assembly.vout_seller_change == -1);
    zswap_assembly_free(&assembly);

    /* A malformed address never reaches the assembler's outputs. */
    s = seller;
    memset(s.zcl_recv_address, 0, ZSWAP_ADDRESS_FIELD_BYTES);
    memset(s.zcl_recv_address, 'x', 35); /* right length, fails decode */
    ZSC_CHECK("neg: bad seller address",
              zswap_assemble(&ad, &buyer, &s, &assembly) ==
                  ZSWAP_ASSEMBLY_ERR_ADDRESS);

    /* The deadline IS the ad's expiry. */
    x = buyer;
    x.deadline_unix = ZSC_EXPIRES + 1;
    ZSC_CHECK("neg: buyer deadline mismatch",
              zswap_assemble(&ad, &x, &seller, &assembly) ==
                  ZSWAP_ASSEMBLY_ERR_DEADLINE);
    s = seller;
    s.deadline_unix = ZSC_EXPIRES - 1;
    ZSC_CHECK("neg: seller deadline mismatch",
              zswap_assemble(&ad, &buyer, &s, &assembly) ==
                  ZSWAP_ASSEMBLY_ERR_DEADLINE);

    /* Wrong token amount in the ad: token_amount 0 fails structural
     * validation before any assembly happens. */
    struct zswap_quote_v1 bad_ad = ad;
    bad_ad.token_amount = 0;
    ZSC_CHECK("neg: zero token amount ad refused",
              zswap_assemble(&bad_ad, &buyer, &seller, &assembly) ==
                  ZSWAP_ASSEMBLY_ERR_AD);
    return failures;
}

/* ── wire codec negatives ──────────────────────────────────────────── */

static int t_wire_negatives(void)
{
    int failures = 0;
    struct zswap_quote_v1 ad;
    struct zswap_buyer_accept buyer;
    struct zswap_seller_accept seller;
    struct zswap_assembly assembly;
    ZSC_CHECK("wire: fixture assembles",
              zsc_assembly(&ad, &buyer, &seller, &assembly));
    zswap_assembly_free(&assembly);

    uint8_t quote_root[32];
    ZSC_CHECK("wire: quote root computes",
              zswap_quote_root(&ad, quote_root) == ZSWAP_QUOTE_OK);
    struct zswap_accept_v1 accept;
    memset(&accept, 0, sizeof(accept));
    accept.schema_version = ZSWAP_ACCEPT_VERSION;
    memcpy(accept.quote_root, quote_root, 32);
    accept.buyer = buyer;
    uint8_t wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    size_t wire_len = 0;
    ZSC_CHECK("wire: accept encodes",
              zswap_accept_encode(&accept, wire, sizeof(wire), &wire_len) ==
                  ZSWAP_CEREMONY_OK);

    struct zswap_accept_v1 back;
    ZSC_CHECK("wire: accept roundtrip fields",
              zswap_accept_decode(wire, wire_len, &back) ==
                  ZSWAP_CEREMONY_OK &&
              memcmp(back.quote_root, quote_root, 32) == 0 &&
              back.buyer.num_inputs == buyer.num_inputs &&
              back.buyer.fee_sats == buyer.fee_sats &&
              back.buyer.deadline_unix == buyer.deadline_unix &&
              strcmp(back.buyer.token_recv_address,
                     buyer.token_recv_address) == 0);
    /* Decode sorts nothing — the wire was already canonical. */
    uint8_t rewire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    size_t rewire_len = 0;
    ZSC_CHECK("wire: accept re-encode identical",
              zswap_accept_encode(&back, rewire, sizeof(rewire),
                                  &rewire_len) == ZSWAP_CEREMONY_OK &&
              rewire_len == wire_len &&
              memcmp(rewire, wire, wire_len) == 0);

    /* Trailing byte / truncation / magic / version. */
    uint8_t long_wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES + 1];
    memcpy(long_wire, wire, wire_len);
    long_wire[wire_len] = 0x00;
    ZSC_CHECK("wire: accept trailing byte rejected",
              zswap_accept_decode(long_wire, wire_len + 1, &back) ==
                  ZSWAP_CEREMONY_ERR_WIRE_SIZE);
    ZSC_CHECK("wire: accept truncation rejected",
              zswap_accept_decode(wire, wire_len - 1, &back) ==
                  ZSWAP_CEREMONY_ERR_WIRE_SIZE);
    uint8_t bad[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    memcpy(bad, wire, wire_len);
    bad[0] ^= 0xff;
    ZSC_CHECK("wire: accept bad magic rejected",
              zswap_accept_decode(bad, wire_len, &back) ==
                  ZSWAP_CEREMONY_ERR_WIRE_MAGIC);
    memcpy(bad, wire, wire_len);
    bad[8] = 0x02;
    ZSC_CHECK("wire: accept bad version rejected",
              zswap_accept_decode(bad, wire_len, &back) ==
                  ZSWAP_CEREMONY_ERR_VERSION);

    /* partial: build a real one, then attack the wire. */
    struct privkey seller_key;
    zsc_key(&seller_key, 0x31);
    struct zswap_partial_v1 partial;
    ZSC_CHECK("wire: seller builds partial",
              zswap_ceremony_seller_build_partial(
                  &ad, &accept, &seller, &seller_key, ZSC_BRANCH_ID,
                  ZSC_NOW, &partial, NULL) == ZSWAP_CEREMONY_OK);
    uint8_t pwire[ZSWAP_PARTIAL_WIRE_MAX_BYTES];
    size_t pwire_len = 0;
    ZSC_CHECK("wire: partial encodes",
              zswap_partial_encode(&partial, pwire, sizeof(pwire),
                                   &pwire_len) == ZSWAP_CEREMONY_OK);
    struct zswap_partial_v1 pback;
    ZSC_CHECK("wire: partial roundtrip",
              zswap_partial_decode(pwire, pwire_len, &pback) ==
                  ZSWAP_CEREMONY_OK &&
              memcmp(pback.quote_root, quote_root, 32) == 0 &&
              memcmp(pback.assembly_root, partial.assembly_root, 32) == 0 &&
              pback.sig_len == partial.sig_len &&
              memcmp(pback.signature, partial.signature,
                     partial.sig_len) == 0);
    memcpy(long_wire, pwire, pwire_len);
    long_wire[pwire_len] = 0x00;
    ZSC_CHECK("wire: partial trailing byte rejected",
              zswap_partial_decode(long_wire, pwire_len + 1, &pback) ==
                  ZSWAP_CEREMONY_ERR_WIRE_SIZE);
    ZSC_CHECK("wire: partial truncation rejected",
              zswap_partial_decode(pwire, pwire_len - 1, &pback) ==
                  ZSWAP_CEREMONY_ERR_WIRE_SIZE);
    memcpy(bad, pwire, pwire_len);
    bad[0] ^= 0xff;
    ZSC_CHECK("wire: partial bad magic rejected",
              zswap_partial_decode(bad, pwire_len, &pback) ==
                  ZSWAP_CEREMONY_ERR_WIRE_MAGIC);

    /* SIGHASH_ALL only: the trailing signature byte is part of the signed
     * statement's meaning. */
    struct zswap_partial_v1 notall = partial;
    notall.signature[notall.sig_len - 1] = 0x03; /* SIGHASH_NONE */
    ZSC_CHECK("wire: non-ALL sighash refused",
              zswap_partial_validate(&notall) ==
                  ZSWAP_CEREMONY_ERR_SIGHASH_TYPE);
    /* Non-canonical signature padding. */
    struct zswap_partial_v1 pad = partial;
    pad.signature[pad.sig_len] = 0x01;
    ZSC_CHECK("wire: signature padding refused",
              zswap_partial_validate(&pad) ==
                  ZSWAP_CEREMONY_ERR_SIG_FIELD);
    /* A wrong assembly domain commitment: recompute the root against a
     * different quote root and it must differ. */
    uint8_t other_root[32], r1[32], r2[32];
    zsc_pattern32(other_root, 0xc0);
    ZSC_CHECK("wire: assembly root binds the ad",
              zswap_assembly_root(quote_root, &buyer, &seller, r1) ==
                  ZSWAP_ASSEMBLY_OK &&
              zswap_assembly_root(other_root, &buyer, &seller, r2) ==
                  ZSWAP_ASSEMBLY_OK &&
              memcmp(r1, r2, 32) != 0);
    return failures;
}

/* ── ceremony flow + tamper matrix ─────────────────────────────────── */

static int t_ceremony(void)
{
    int failures = 0;
    struct zswap_quote_v1 ad;
    struct zswap_buyer_accept buyer;
    struct zswap_seller_accept seller;
    struct zswap_assembly assembly;
    ZSC_CHECK("flow: fixture assembles",
              zsc_assembly(&ad, &buyer, &seller, &assembly));
    zswap_assembly_free(&assembly);

    uint8_t quote_root[32];
    ZSC_CHECK("flow: quote root computes",
              zswap_quote_root(&ad, quote_root) == ZSWAP_QUOTE_OK);
    struct zswap_accept_v1 accept;
    memset(&accept, 0, sizeof(accept));
    accept.schema_version = ZSWAP_ACCEPT_VERSION;
    memcpy(accept.quote_root, quote_root, 32);
    accept.buyer = buyer;

    struct privkey seller_key;
    zsc_key(&seller_key, 0x31);
    struct zswap_partial_v1 partial;
    ZSC_CHECK("flow: seller builds partial",
              zswap_ceremony_seller_build_partial(
                  &ad, &accept, &seller, &seller_key, ZSC_BRANCH_ID,
                  ZSC_NOW, &partial, NULL) == ZSWAP_CEREMONY_OK);

    /* Buyer verifies: half-signed tx comes back, seller input signed only. */
    struct transaction tx;
    ZSC_CHECK("flow: buyer verifies partial",
              zswap_ceremony_buyer_verify_partial(
                  &ad, &accept, &partial, ZSC_BRANCH_ID, ZSC_NOW, &tx) ==
                  ZSWAP_CEREMONY_OK);
    ZSC_CHECK("flow: only seller input signed",
              tx.num_vin == 3 && tx.vin[0].script_sig.size > 0 &&
              tx.vin[1].script_sig.size == 0 &&
              tx.vin[2].script_sig.size == 0 &&
              !zswap_ceremony_all_inputs_signed(&tx));
    transaction_free(&tx);

    /* Tamper: accept naming a different ad root. */
    struct zswap_accept_v1 bad_accept = accept;
    bad_accept.quote_root[0] ^= 0x01;
    struct zswap_partial_v1 out;
    ZSC_CHECK("flow: wrong ad root refused",
              zswap_ceremony_seller_build_partial(
                  &ad, &bad_accept, &seller, &seller_key, ZSC_BRANCH_ID,
                  ZSC_NOW, &out, NULL) == ZSWAP_CEREMONY_ERR_QUOTE_ROOT);

    /* Tamper: seller's assembly_root does not match the accept tuple. */
    struct zswap_partial_v1 bad_partial = partial;
    bad_partial.assembly_root[0] ^= 0x01;
    ZSC_CHECK("flow: assembly root mismatch refused",
              zswap_ceremony_buyer_verify_partial(
                  &ad, &accept, &bad_partial, ZSC_BRANCH_ID, ZSC_NOW, &tx) ==
                  ZSWAP_CEREMONY_ERR_ASSEMBLY_ROOT);

    /* Tamper: flipped signature byte fails ECDSA verification. */
    bad_partial = partial;
    bad_partial.signature[2] ^= 0x01;
    ZSC_CHECK("flow: signature bit-flip refused",
              zswap_ceremony_buyer_verify_partial(
                  &ad, &accept, &bad_partial, ZSC_BRANCH_ID, ZSC_NOW, &tx) ==
                  ZSWAP_CEREMONY_ERR_SIGNATURE);

    /* A pubkey not bound to the token input's script is KEY_MISMATCH even
     * with a self-consistent signature field. */
    bad_partial = partial;
    struct privkey wrong_key;
    zsc_key(&wrong_key, 0x77);
    struct pubkey wrong_pk;
    ZSC_CHECK("flow: wrong key derives",
              privkey_get_pubkey(&wrong_key, &wrong_pk));
    memcpy(bad_partial.seller_pubkey, wrong_pk.vch, 33);
    ZSC_CHECK("flow: unbound seller pubkey refused",
              zswap_ceremony_buyer_verify_partial(
                  &ad, &accept, &bad_partial, ZSC_BRANCH_ID, ZSC_NOW, &tx) ==
                  ZSWAP_CEREMONY_ERR_KEY_MISMATCH);

    /* A different branch id changes the sighash: the seller's signature no
     * longer verifies. */
    ZSC_CHECK("flow: wrong branch id refused",
              zswap_ceremony_buyer_verify_partial(
                  &ad, &accept, &partial, 0x00000000U, ZSC_NOW, &tx) ==
                  ZSWAP_CEREMONY_ERR_SIGNATURE);

    /* A stale ceremony dies with the ad. */
    ZSC_CHECK("flow: expired ceremony refused",
              zswap_ceremony_buyer_verify_partial(
                  &ad, &accept, &partial, ZSC_BRANCH_ID, ZSC_EXPIRES,
                  &tx) == ZSWAP_CEREMONY_ERR_EXPIRED &&
              zswap_ceremony_seller_build_partial(
                  &ad, &accept, &seller, &seller_key, ZSC_BRANCH_ID,
                  ZSC_EXPIRES, &out, NULL) == ZSWAP_CEREMONY_ERR_EXPIRED);

    /* Signing with a key that does not own the input is KEY_MISMATCH,
     * never a worthless signature. */
    ZSC_CHECK("flow: reassemble for wrong-key sign",
              zswap_assemble(&ad, &buyer, &seller, &assembly) ==
                  ZSWAP_ASSEMBLY_OK);
    ZSC_CHECK("flow: wrong signing key refused",
              zswap_ceremony_sign_input_p2pkh(
                  &assembly.tx, 0, seller.token_input.script_pub_key,
                  seller.token_input.script_len,
                  seller.token_input.value_sats, ZSC_BRANCH_ID,
                  &wrong_key) == ZSWAP_CEREMONY_ERR_KEY_MISMATCH);
    zswap_assembly_free(&assembly);

    /* Terms: a shortchanged assembly is un-signable. Flip the seller
     * payment down by one sat and seller_verify must name TERMS. */
    ZSC_CHECK("flow: good assembly passes terms",
              zswap_assemble(&ad, &buyer, &seller, &assembly) ==
                  ZSWAP_ASSEMBLY_OK &&
              zswap_ceremony_seller_verify_assembly(
                  &ad, &buyer, &seller, &assembly, ZSC_NOW) ==
                  ZSWAP_CEREMONY_OK);
    assembly.tx.vout[assembly.vout_seller_payment].value -= 1;
    ZSC_CHECK("flow: shortchanged payment refused",
              zswap_ceremony_seller_verify_assembly(
                  &ad, &buyer, &seller, &assembly, ZSC_NOW) ==
                  ZSWAP_CEREMONY_ERR_TERMS);
    zswap_assembly_free(&assembly);
    /* A skimmed change output is TERMS too. */
    ZSC_CHECK("flow: reassemble for change tamper",
              zswap_assemble(&ad, &buyer, &seller, &assembly) ==
                  ZSWAP_ASSEMBLY_OK);
    assembly.tx.vout[assembly.vout_buyer_change].value -= 1;
    ZSC_CHECK("flow: skimmed buyer change refused",
              zswap_ceremony_seller_verify_assembly(
                  &ad, &buyer, &seller, &assembly, ZSC_NOW) ==
                  ZSWAP_CEREMONY_ERR_TERMS);
    zswap_assembly_free(&assembly);
    return failures;
}

int test_zswap_ceremony(void)
{
    printf("\n=== zswap_ceremony: swap assembly + ceremony wires ===\n");
    int failures = 0;
    failures += t_kat();
    failures += t_ordering();
    failures += t_assembly_negatives();
    failures += t_wire_negatives();
    failures += t_ceremony();
    printf("=== zswap_ceremony complete: %d failure(s) ===\n", failures);
    return failures;
}
