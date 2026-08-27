/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_yardsale_app — the yardsale MVC app (apps/yardsale/app.def): the
 * manifest registration, and the swap ceremony driven end-to-end THROUGH
 * the controller functions (app/controllers/src/yardsale_controller.c)
 * with the Stage-3 KAT fixture — the same (ad, buyer, seller) tuple as
 * test_zswap_ceremony.c, so the controller must reproduce the exact
 * golden zswap_accept.v1 / zswap_partial.v1 / final-transaction bytes,
 * proving the app layer does not alter the wire semantics.
 *
 * Covers the P2P-port ingress shapes (yardsale_ceremony_accept_ingest /
 * yardsale_ceremony_partial_ingest: RESPOND/RELAY/DROP, dedup, the
 * per-peer clamp) and the seller web endpoint (POST /yardsale/accept)
 * in-process. No datadir, no chain state — address decoding reads the
 * process chain params the runner selects (CHAIN_MAIN). */

#include "test/test_core.h"

#include "base/hex.h"
#include "base/result.h"
#include "base/safe_alloc.h"
#include "chain/chainparams.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "controllers/yardsale_controller.h"
#include "controllers/yardsale_site_controller.h"
#include "crypto/ed25519.h"
#include "framework/app_definition.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "models/database.h"
#include "models/tx_index.h"
#include "models/yardsale_plan.h"
#include "models/zslp_ledger.h"
#include "models/zslp_validity.h"
#include "net/onion_service.h"
#include "platform/time_compat.h"
#include "script/standard.h"
#include "sim/simnet.h"
#include "services/yardsale_prevout_service.h"
#include "support/cleanse.h"
#include "znam/znam.h"
#include "zslp/slp.h"
#include "zswap/zswap_assembly.h"
#include "zswap/zswap_ceremony.h"
#include "zswap/zswap_quote.h"
#include "zswap/zswap_yardsale.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define YSA_CHECK(name, expr) do {                                     \
    if (expr) { printf("  yardsale_app: %s... OK\n", (name)); }        \
    else { printf("  yardsale_app: %s... FAIL\n", (name));             \
        failures++; }                                                  \
} while (0)

/* ── The Stage-3 KAT fixture (byte-identical to test_zswap_ceremony.c) ── */

#define YSA_ISSUED 1754000000LL
#define YSA_EXPIRES (YSA_ISSUED + 45LL)
#define YSA_NOW (YSA_ISSUED + 10LL)
#define YSA_NONCE 0x0102030405060708ULL
#define YSA_TOKEN_AMOUNT 500000ULL
#define YSA_ZCL_AMOUNT 125000000ULL
#define YSA_FEE_SATS 10000ULL
#define YSA_BRANCH_ID 0x76b809bbU
#define YSA_SELLER_INPUT_VALUE 10000LL
#define YSA_BUYER_IN_A_VALUE 150000000LL
#define YSA_BUYER_IN_B_VALUE 50000000LL

/* Golden vectors from test_zswap_ceremony.c — the controller must produce
 * byte-identical wires through its own code paths. */
#define YSA_KAT_ACCEPT_WIRE_HEX "5a53574143500d0a0100e104ed1f04da7980152906ccd88775cf615ba0e3ebccf89f4acb41da7b7dacd802505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f0100000080d1f008000000001976a91414db4138d56a2ecfb10881a9be394d9f321985b288ac606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0000000080f0fa02000000001976a91414db4138d56a2ecfb10881a9be394d9f321985b288ac74314b6d744247357976707a6f6534383745776e73736d52396e683935586a66336439000000000000000000000000000000000000000000000000000000000074314e587546786f4366674a714277326d4c5177544173386576424d59324d796f684800000000000000000000000000000000000000000000000000000000001027000000000000adea8b6800000000"
#define YSA_KAT_PARTIAL_WIRE_HEX "5a535750544c0d0a0100e104ed1f04da7980152906ccd88775cf615ba0e3ebccf89f4acb41da7b7dacd8d62ba75743e52fcdd2c4b42c6f3a66deb18cf034d33394d6a8c1342a0e565c6b303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f0200000010270000000000001976a9148320611ff032223c1f4bb1fbbd2291fd2b3f43d988ac74315670774b45315064587534424237315976595a77634b4d66444a375169483846540000000000000000000000000000000000000000000000000000000000743165516231535239657a457a33414578543469774375544b42784e3436754a5470630000000000000000000000000000000000000000000000000000000000adea8b6800000000036930f46dd0b16d866d59d1054aa63298b357499cd1862ef16f3f55f1cafceb82483045022100e2d3b9df2e11aa0797f245d3cba97ccf4b982458314202ee9c2beb1c36ec4f7c02200f7609eebb7a75d3b3e75d28d1455660bbdd64b712ca401b130c597059254d100100"
#define YSA_KAT_FINAL_TX_HEX "0400008085202f8903303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f020000006b483045022100e2d3b9df2e11aa0797f245d3cba97ccf4b982458314202ee9c2beb1c36ec4f7c02200f7609eebb7a75d3b3e75d28d1455660bbdd64b712ca401b130c597059254d100121036930f46dd0b16d866d59d1054aa63298b357499cd1862ef16f3f55f1cafceb82ffffffff505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f010000006a47304402203d7c3f4fa57e910c348778c3471bd688d358e16f0ff4bb28b83a0c0261d53d650220499e7cf0ff505de24f42a3b5def8fd71321740c21972712b146482076e22a16401210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1cffffffff606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f000000006a4730440220336b6435e33ac4f03c5044537a14e7438d5ef423bd2083ba67d52cbcd87c5ced02207a69ee4508ee53086bd48e52e7c192b70238cbb4301e23840e2f9751cb35543401210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1cffffffff050000000000000000376a04534c500001010453454e44205f5e5d5c5b5a595857565554535251504f4e4d4c4b4a4948474645444342414008000000000007a12022020000000000001976a91414db4138d56a2ecfb10881a9be394d9f321985b288ac40597307000000001976a9148320611ff032223c1f4bb1fbbd2291fd2b3f43d988acee240000000000001976a914e13e93c4d1c15865bfa3cd3295a5e45b2a075e8e88acb0417804000000001976a914331eb609f3aacffe680f86309d6b7470e7215b0c88ac00000000000000000000000000000000000000"

#define YSA_TX_BUF_BYTES 4096u

static void ysa_hex(const uint8_t *bytes, size_t len, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hexd[(bytes[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[bytes[i] & 0xf];
    }
    out[2 * len] = '\0';
}

static void ysa_key(struct privkey *key, uint8_t fill)
{
    memset(key->vch, fill, 32);
    key->fValid = true;
    key->fCompressed = true;
}

static void ysa_pattern32(uint8_t out[32], uint8_t base)
{
    for (size_t i = 0; i < 32; i++) out[i] = (uint8_t)(base + i);
}

static size_t ysa_p2pkh_script(const struct privkey *key, uint8_t out[25])
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

static bool ysa_address(const struct privkey *key,
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

static bool ysa_ad_at(struct zswap_quote_v1 *q, int64_t issued,
                      int64_t expires)
{
    memset(q, 0, sizeof(*q));
    q->schema_version = ZSWAP_QUOTE_VERSION;
    ysa_pattern32(q->network_genesis_root, 0xa0);
    uint8_t seed[32];
    memset(seed, 0x11, sizeof(seed));
    uint8_t sk[32];
    ed25519_keypair(q->seller_pubkey, sk, seed);
    q->nonce = YSA_NONCE;
    ysa_pattern32(q->token_id, 0x40);
    q->token_amount = YSA_TOKEN_AMOUNT;
    q->zcl_amount = YSA_ZCL_AMOUNT;
    q->issued_unix = issued;
    q->expires_unix = expires;
    return zswap_quote_seal(q, seed) == ZSWAP_QUOTE_OK;
}

static bool ysa_ad(struct zswap_quote_v1 *q)
{
    return ysa_ad_at(q, YSA_ISSUED, YSA_EXPIRES);
}

static void ysa_fill_input(struct zswap_swap_input *in, uint8_t txid_base,
                           uint32_t vout, int64_t value,
                           const uint8_t *script, uint16_t script_len)
{
    memset(in, 0, sizeof(*in));
    ysa_pattern32(in->txid, txid_base);
    in->vout = vout;
    in->value_sats = value;
    in->script_len = script_len;
    memcpy(in->script_pub_key, script, script_len);
}

static void ysa_fill_exact_input(struct zswap_swap_input *in,
                                 const uint8_t txid[32], uint32_t vout,
                                 int64_t value, const uint8_t *script,
                                 uint16_t script_len)
{
    memset(in, 0, sizeof(*in));
    memcpy(in->txid, txid, 32);
    in->vout = vout;
    in->value_sats = value;
    in->script_len = script_len;
    memcpy(in->script_pub_key, script, script_len);
}

/* ── The buyer's chain-content port (faked) ──────────────────────── */

/* Production wires the prevout service (node.db + active chain). Tests
 * serve one fabricated "confirmed" body instead; the fake reproduces the
 * real port's contract — the requested txid (internal byte order) must
 * match, and the caller receives a private copy — so the buyer-side
 * check is exercised against exactly the shape production hands it. */
static struct transaction ysa_prevout_tx;
static bool ysa_prevout_serve;

static void ysa_prevout_clear(void)
{
    transaction_free(&ysa_prevout_tx);
    transaction_init(&ysa_prevout_tx);
    ysa_prevout_serve = false;
}

/* Serve a copy of `body`, keyed by its own hash — the honest path (the
 * simnet test mints a real SLP SEND on the sim chain and serves it). */
static bool ysa_prevout_serve_body(const struct transaction *body)
{
    ysa_prevout_clear();
    transaction_init(&ysa_prevout_tx);
    ysa_prevout_serve = transaction_copy(&ysa_prevout_tx, body);
    return ysa_prevout_serve;
}

/* Fabricate a token-send body keyed by `key_txid`: vout[0] an SLP SEND
 * op-return declaring the ad's token with `amount` on vout[2] (the vout
 * the KAT terms claim), vout[2] paying (value, script). Field mutators
 * at the call sites corrupt exactly one claim per negative case. */
static bool ysa_prevout_build(const uint8_t key_txid[32],
                              const uint8_t internal_token_id[32],
                              uint64_t amount, int64_t value,
                              const uint8_t *script, uint16_t script_len)
{
    ysa_prevout_clear();
    transaction_init(&ysa_prevout_tx);
    if (!transaction_alloc(&ysa_prevout_tx, 1, 3))
        return false;
    struct uint256 wire_id;
    for (int i = 0; i < 32; i++)
        wire_id.data[i] = internal_token_id[31 - i];
    uint64_t quantities[2] = { 1, amount };
    uint8_t opret[256];
    size_t olen = slp_build_send(opret, sizeof(opret), &wire_id,
                                 quantities, 2);
    if (olen == 0 ||
        olen > sizeof(ysa_prevout_tx.vout[0].script_pub_key.data))
        return false;
    ysa_prevout_tx.vout[0].script_pub_key.size = olen;
    memcpy(ysa_prevout_tx.vout[0].script_pub_key.data, opret, olen);
    ysa_prevout_tx.vout[2].value = value;
    ysa_prevout_tx.vout[2].script_pub_key.size = script_len;
    memcpy(ysa_prevout_tx.vout[2].script_pub_key.data, script,
           script_len);
    transaction_compute_hash(&ysa_prevout_tx);
    memcpy(ysa_prevout_tx.hash.data, key_txid, 32);
    ysa_prevout_serve = true;
    return true;
}

/* Arm the fake with exactly what the seller's terms claim: the confirmed
 * body a passing check must find. */
static bool ysa_prevout_arm(const struct zswap_quote_v1 *ad,
                            const struct zswap_seller_accept *seller)
{
    return ysa_prevout_build(seller->token_input.txid, ad->token_id,
                             ad->token_amount,
                             seller->token_input.value_sats,
                             seller->token_input.script_pub_key,
                             seller->token_input.script_len);
}

static struct zcl_result ysa_prevout_fetch_fn(void *ctx,
                                              const uint8_t txid[32],
                                              uint32_t vout,
                                              const uint8_t token_id[32],
                                              uint64_t token_amount,
                                              struct transaction *out)
{
    (void)ctx;
    (void)vout;
    (void)token_id;
    (void)token_amount;
    if (!out)
        return ZCL_ERR(-1, "fake: no confirmed body for this txid");
    /* Same post-condition as the production port: on every return *out is
     * an initialized transaction the caller owns and may free. */
    transaction_free(out);
    transaction_init(out);
    if (!ysa_prevout_serve ||
        memcmp(txid, ysa_prevout_tx.hash.data, 32) != 0)
        return ZCL_ERR(-2, "fake: no confirmed body for this txid");
    if (!transaction_copy(out, &ysa_prevout_tx))
        return ZCL_ERR(-3, "fake: body copy failed");
    return ZCL_OK;
}

/* ── Production strict-prevout service ───────────────────────────── */

struct ysa_prevout_service_fixture {
    char dir[256];
    struct node_db ndb;
    struct main_state state;
    struct block_index canonical;
    struct block_index replacement;
    struct block body;
    struct yardsale_prevout_view view;
    uint8_t token_id[32];
    uint64_t amount;
    bool reorg_after_read;
    bool fail_result_copy;
    bool dir_ready;
    bool db_ready;
    bool state_ready;
};

static void ysa_prevout_service_fixture_free(
    struct ysa_prevout_service_fixture *fx);

static bool ysa_prevout_service_read(struct block *out,
                                     const struct block_index *index,
                                     const char *datadir, void *ctx)
{
    struct ysa_prevout_service_fixture *fx = ctx;
    (void)datadir;
    if (!fx || index != &fx->canonical || !block_clone(out, &fx->body))
        return false;
    if (fx->reorg_after_read) {
        zcl_mutex_lock(&fx->state.cs_main);
        bool moved = active_chain_install_tip_slot(&fx->state.chain_active,
                                                    &fx->replacement);
        zcl_mutex_unlock(&fx->state.cs_main);
        if (!moved)
            return false;
    }
    if (fx->fail_result_copy)
        zcl_alloc_fault_fail_next("tx_vin");
    return true;
}

static bool ysa_prevout_service_tx(struct transaction *tx, uint64_t amount)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 2))
        return false;
    memset(tx->vin[0].prevout.hash.data, 0x91, 32);
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = UINT32_MAX;
    uint8_t opret[256];
    size_t opret_len = slp_build_genesis(opret, sizeof(opret), "YSA", "YSA",
                                         "", NULL, 0, 0, amount);
    if (opret_len == 0 ||
        opret_len > sizeof(tx->vout[0].script_pub_key.data)) {
        transaction_free(tx);
        return false;
    }
    tx->vout[0].script_pub_key.size = opret_len;
    memcpy(tx->vout[0].script_pub_key.data, opret, opret_len);
    tx->vout[1].value = YSA_SELLER_INPUT_VALUE;
    tx->vout[1].script_pub_key.size = 1;
    tx->vout[1].script_pub_key.data[0] = 0x51;
    transaction_compute_hash(tx);
    return true;
}

static bool ysa_prevout_service_fixture_init(
    struct ysa_prevout_service_fixture *fx, const char *case_name,
    bool strict_valid, bool projection_current, bool spent,
    bool locator_mismatch)
{
    memset(fx, 0, sizeof(*fx));
    test_make_tmpdir(fx->dir, sizeof(fx->dir), "yardsale_prevout", case_name);
    fx->dir_ready = fx->dir[0] != '\0';
    char dbpath[320];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", fx->dir);
    if (!node_db_open(&fx->ndb, dbpath))
        goto fail;
    fx->db_ready = true;
    main_state_init(&fx->state);
    fx->state_ready = true;
    block_init(&fx->body);
    fx->amount = YSA_TOKEN_AMOUNT;

    struct transaction token_tx;
    if (!ysa_prevout_service_tx(&token_tx, fx->amount))
        goto fail;
    memcpy(fx->token_id, token_tx.hash.data, 32);
    fx->body.vtx = zcl_calloc(1, sizeof(*fx->body.vtx),
                              "yardsale.prevout.test.block");
    if (!fx->body.vtx || !transaction_copy(&fx->body.vtx[0], &token_tx)) {
        transaction_free(&token_tx);
        goto fail;
    }
    fx->body.num_vtx = 1;
    fx->body.header.nTime = 1;
    fx->body.header.nBits = 1;

    struct uint256 body_hash;
    block_header_get_hash(&fx->body.header, &body_hash);
    block_index_init(&fx->canonical);
    fx->canonical.nHeight = 0;
    fx->canonical.hashBlock = body_hash;
    fx->canonical.phashBlock = &fx->canonical.hashBlock;
    block_index_init(&fx->replacement);
    fx->replacement.nHeight = 0;
    fx->replacement.hashBlock = body_hash;
    fx->replacement.hashBlock.data[0] ^= 0x80;
    fx->replacement.phashBlock = &fx->replacement.hashBlock;
    if (!active_chain_install_tip_slot(&fx->state.chain_active,
                                       &fx->canonical)) {
        transaction_free(&token_tx);
        goto fail;
    }

    struct db_tx_index row;
    memset(&row, 0, sizeof(row));
    memcpy(row.txid, token_tx.hash.data, 32);
    memcpy(row.block_hash, locator_mismatch ? fx->replacement.hashBlock.data
                                            : body_hash.data, 32);
    row.block_height = 0;
    row.tx_index = 0;
    row.file_num = 0;
    row.file_pos = 0;
    bool ok = db_tx_save(&fx->ndb, &row);
    if (strict_valid) {
        struct slp_message msg;
        ok = ok && slp_parse(token_tx.vout[0].script_pub_key.data,
                             token_tx.vout[0].script_pub_key.size, &msg) &&
            zslp_validity_apply_live(&fx->ndb, &token_tx, &msg, 0);
    }
    uint8_t digest[32] = {0};
    ok = ok && zslp_ledger_set_cursor(&fx->ndb,
                                      projection_current ? 0 : -1, digest);
    if (ok && spent) {
        uint8_t spender[32];
        memset(spender, 0xa5, sizeof(spender));
        ok = zslp_ledger_mark_valid_spent(&fx->ndb, token_tx.hash.data, 1,
                                          spender, 1);
    }
    transaction_free(&token_tx);
    fx->view = (struct yardsale_prevout_view) {
        .state = &fx->state,
        .node_db = &fx->ndb,
        .datadir = fx->dir,
        .read_block = ysa_prevout_service_read,
        .read_block_ctx = fx,
    };
    if (ok)
        return true;

fail:
    ysa_prevout_service_fixture_free(fx);
    return false;
}

static void ysa_prevout_service_fixture_free(
    struct ysa_prevout_service_fixture *fx)
{
    zcl_alloc_fault_clear();
    block_free(&fx->body);
    if (fx->state_ready) {
        main_state_free(&fx->state);
        fx->state_ready = false;
    }
    if (fx->db_ready) {
        node_db_close(&fx->ndb);
        fx->db_ready = false;
    }
    if (fx->dir_ready) {
        test_cleanup_tmpdir(fx->dir);
        fx->dir_ready = false;
    }
}

static struct zcl_result ysa_prevout_service_call(
    struct ysa_prevout_service_fixture *fx, uint64_t amount,
    struct transaction *out)
{
    return yardsale_prevout_fetch_confirmed(
        &fx->view, fx->token_id, 1, fx->token_id, amount, out);
}

static int t_prevout_service_strict(void)
{
    int failures = 0;
    struct ysa_prevout_service_fixture fx;
    struct transaction out;

#define YSA_PREVOUT_CASE(label, valid, current, spent, mismatch, assertion)  \
    do {                                                                     \
        transaction_init(&out);                                              \
        bool ready = ysa_prevout_service_fixture_init(                       \
            &fx, (label), (valid), (current), (spent), (mismatch));          \
        struct zcl_result result = ready                                     \
            ? ysa_prevout_service_call(&fx, fx.amount, &out)                 \
            : ZCL_ERR(-99, "fixture setup failed");                         \
        YSA_CHECK((label), ready && (assertion));                            \
        transaction_free(&out);                                              \
        if (ready) ysa_prevout_service_fixture_free(&fx);                    \
    } while (0)

    YSA_PREVOUT_CASE("prevout service: strict unspent token accepted",
                     true, true, false, false,
                     result.ok && out.num_vout == 2);
    YSA_PREVOUT_CASE("prevout service: invalid ancestry refused",
                     false, true, false, false,
                     !result.ok && strstr(result.message, "ancestry"));
    YSA_PREVOUT_CASE("prevout service: spent token output refused",
                     true, true, true, false,
                     !result.ok && strstr(result.message, "spent"));
    YSA_PREVOUT_CASE("prevout service: stale projection refused",
                     true, false, false, false,
                     !result.ok && strstr(result.message, "stale"));
    YSA_PREVOUT_CASE("prevout service: noncanonical locator refused",
                     true, true, false, true,
                     !result.ok && strstr(result.message, "active chain"));
    YSA_PREVOUT_CASE("prevout service: exact amount required",
                     true, true, false, false,
                     result.ok &&
                     !ysa_prevout_service_call(&fx, fx.amount + 1, &out).ok);

    transaction_init(&out);
    bool ready = ysa_prevout_service_fixture_init(
        &fx, "reorg", true, true, false, false);
    if (ready) fx.reorg_after_read = true;
    struct zcl_result result = ready
        ? ysa_prevout_service_call(&fx, fx.amount, &out)
        : ZCL_ERR(-99, "fixture setup failed");
    YSA_CHECK("prevout service: reorg during read refused",
              ready && !result.ok && strstr(result.message, "changed"));
    transaction_free(&out);
    if (ready) ysa_prevout_service_fixture_free(&fx);

    transaction_init(&out);
    ready = ysa_prevout_service_fixture_init(
        &fx, "copy_oom", true, true, false, false) &&
        transaction_alloc(&out, 0, 1);
    struct tx_out *original_vout = ready ? out.vout : NULL;
    if (ready) {
        out.vout[0].value = 777;
        fx.fail_result_copy = true;
    }
    result = ready ? ysa_prevout_service_call(&fx, fx.amount, &out)
                   : ZCL_ERR(-99, "fixture setup failed");
    YSA_CHECK("prevout service: copy OOM leaves caller output untouched",
              ready && !result.ok && out.vout == original_vout &&
              out.num_vout == 1 && out.vout[0].value == 777);
    transaction_free(&out);
    if (ready) ysa_prevout_service_fixture_free(&fx);

#undef YSA_PREVOUT_CASE
    return failures;
}

/* The buyer accept; input B (txid 0x60..) is listed FIRST so the canonical
 * sort is exercised, exactly like the Stage-3 fixture. */
static bool ysa_buyer_dl(struct zswap_buyer_accept *buyer, int64_t deadline)
{
    memset(buyer, 0, sizeof(*buyer));
    uint8_t script[25];
    struct privkey buyer_key;
    ysa_key(&buyer_key, 0x42);
    if (ysa_p2pkh_script(&buyer_key, script) != 25) return false;
    buyer->num_inputs = 2;
    ysa_fill_input(&buyer->inputs[0], 0x60, 0, YSA_BUYER_IN_B_VALUE,
                   script, 25);
    ysa_fill_input(&buyer->inputs[1], 0x50, 1, YSA_BUYER_IN_A_VALUE,
                   script, 25);
    struct privkey recv_key, change_key;
    ysa_key(&recv_key, 0x42);
    ysa_key(&change_key, 0x43);
    if (!ysa_address(&recv_key, buyer->token_recv_address) ||
        !ysa_address(&change_key, buyer->change_address))
        return false;
    buyer->fee_sats = YSA_FEE_SATS;
    buyer->deadline_unix = deadline;
    return true;
}

static bool ysa_buyer(struct zswap_buyer_accept *buyer)
{
    return ysa_buyer_dl(buyer, YSA_EXPIRES);
}

static bool ysa_seller_dl(struct zswap_seller_accept *seller,
                          int64_t deadline)
{
    memset(seller, 0, sizeof(*seller));
    uint8_t script[25];
    struct privkey seller_key;
    ysa_key(&seller_key, 0x31);
    if (ysa_p2pkh_script(&seller_key, script) != 25) return false;
    ysa_fill_input(&seller->token_input, 0x30, 2, YSA_SELLER_INPUT_VALUE,
                   script, 25);
    struct privkey change_key;
    ysa_key(&change_key, 0x32);
    if (!ysa_address(&seller_key, seller->zcl_recv_address) ||
        !ysa_address(&change_key, seller->change_address))
        return false;
    seller->deadline_unix = deadline;
    return true;
}

static bool ysa_seller(struct zswap_seller_accept *seller)
{
    return ysa_seller_dl(seller, YSA_EXPIRES);
}

/* ── Injected ports ──────────────────────────────────────────────── */

static uint32_t ysa_branch_id(void *ctx)
{
    (void)ctx;
    return YSA_BRANCH_ID;
}

struct ysa_flood_capture {
    int count;
    char last_command[16];
    uint8_t last_wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    size_t last_len;
};

static void ysa_flood_capture_fn(const char *command, const uint8_t *wire,
                                 size_t wire_len, void *ctx)
{
    struct ysa_flood_capture *cap = ctx;
    cap->count++;
    snprintf(cap->last_command, sizeof(cap->last_command), "%s", command);
    if (wire_len <= sizeof(cap->last_wire)) {
        memcpy(cap->last_wire, wire, wire_len);
        cap->last_len = wire_len;
    }
}

struct ysa_broadcast_capture {
    int count;
    uint8_t tx_bytes[YSA_TX_BUF_BYTES];
    size_t tx_len;
};

static bool ysa_broadcast_capture_fn(const struct transaction *tx, void *ctx)
{
    struct ysa_broadcast_capture *cap = ctx;
    cap->count++;
    return zswap_assembly_tx_serialize(tx, cap->tx_bytes,
                                       sizeof(cap->tx_bytes), &cap->tx_len);
}

struct ysa_transaction_capture {
    int count;
    bool copied;
    struct transaction tx;
};

static bool ysa_transaction_capture_fn(const struct transaction *tx,
                                       void *ctx)
{
    struct ysa_transaction_capture *cap = ctx;
    if (!tx || !cap)
        return false;
    if (cap->copied)
        transaction_free(&cap->tx);
    cap->count++;
    cap->copied = transaction_copy(&cap->tx, tx);
    return cap->copied;
}

/* Shared fixture setup: reset every piece of yardsale state and pin the
 * fixture branch. The yardsale cache is the REAL one — the ceremony
 * ingress paths must answer out of the same cache the gossip layer fills. */
static void ysa_reset_all(void)
{
    zswap_yardsale_reset();
    yardsale_ceremony_reset();
    yardsale_seller_profile_clear();
    yardsale_ceremony_set_flood(NULL, NULL);
    yardsale_ceremony_set_broadcast(NULL, NULL);
    yardsale_ceremony_set_prevout_fetch(NULL, NULL);
    ysa_prevout_clear();
    yardsale_ceremony_set_branch_id_source(ysa_branch_id, NULL);
}

/* Ingest an already-built ad into the real yardsale cache at `now`. */
static bool ysa_ingest_ad(const struct zswap_quote_v1 *ad, int64_t now,
                          uint8_t quote_root[32])
{
    uint8_t ad_wire[ZSWAP_QUOTE_WIRE_BYTES];
    if (zswap_quote_encode(ad, ad_wire) != ZSWAP_QUOTE_OK) return false;
    uint8_t net[32];
    ysa_pattern32(net, 0xa0);
    struct zswap_yardsale_ad entry;
    if (zswap_yardsale_ingest_wire(ad_wire, sizeof(ad_wire), net, 1,
                                   now, &entry) !=
        ZSWAP_YARDSALE_INGEST_NEW)
        return false;
    return zswap_quote_root(ad, quote_root) == ZSWAP_QUOTE_OK;
}

/* Ingest the KAT ad into the real yardsale cache. */
static bool ysa_ingest_kat_ad(struct zswap_quote_v1 *ad,
                              uint8_t quote_root[32])
{
    if (!ysa_ad(ad)) return false;
    return ysa_ingest_ad(ad, YSA_NOW, quote_root);
}

/* ── Manifest ────────────────────────────────────────────────────── */

static int t_manifest(void)
{
    int failures = 0;
    struct zcl_app_definition_v1 def;
    YSA_CHECK("manifest: yardsale app.def compiles",
              zcl_app_definition_load_v1(".", "yardsale", &def).ok);
    YSA_CHECK("manifest: app id",
              strcmp(def.app_id, "yardsale") == 0);
    YSA_CHECK("manifest: one resource, the signs",
              def.resource_count == 1 &&
              strcmp(def.resources[0].name, "ads") == 0);
    YSA_CHECK("manifest: yardsale topic",
              def.topic_count == 1 &&
              strcmp(def.topics[0].name, "yardsale.ads.v1") == 0);
    YSA_CHECK("manifest: web mount + onion + znam",
              def.mount_count == 1 &&
              strcmp(def.mounts[0].path, "/yardsale") == 0 &&
              def.onion_declared && def.onion_enabled &&
              def.znam_declared && strcmp(def.znam, "yardsale") == 0);
    YSA_CHECK("manifest: registered as a builtin app",
              zcl_app_definition_builtin_v1("yardsale"));

    struct zcl_app_definition_catalog_v1 catalog;
    YSA_CHECK("manifest: builtin catalog compiles with yardsale",
              zcl_app_definition_builtin_catalog_compile_v1(".",
                                                            &catalog).ok &&
              catalog.app_count == 3 &&
              strcmp(catalog.apps[2].app_id, "yardsale") == 0);
    return failures;
}

/* ── The ceremony round-trip through the controller ──────────────── */

static int t_ceremony_roundtrip(void)
{
    int failures = 0;
    ysa_reset_all();

    struct zswap_quote_v1 ad;
    uint8_t quote_root[32];
    YSA_CHECK("ceremony: KAT ad ingested into the yardsale",
              ysa_ingest_kat_ad(&ad, quote_root));

    /* SELLER: the operator configures his standing terms + key. */
    struct zswap_seller_accept seller;
    struct privkey seller_key;
    YSA_CHECK("ceremony: seller terms fixture", ysa_seller(&seller));
    ysa_key(&seller_key, 0x31);
    yardsale_seller_profile_configure(&seller, &seller_key);
    YSA_CHECK("ceremony: profile configured",
              yardsale_seller_profile_configured());

    /* BUYER: begin the buy — the accept wire must be byte-identical to
     * the Stage-3 golden vector and must go out on the gossip port. */
    struct zswap_buyer_accept buyer;
    YSA_CHECK("ceremony: buyer terms fixture", ysa_buyer(&buyer));
    struct privkey buyer_keys[2];
    ysa_key(&buyer_keys[0], 0x42);
    ysa_key(&buyer_keys[1], 0x42);

    struct ysa_flood_capture flood = {0};
    yardsale_ceremony_set_flood(ysa_flood_capture_fn, &flood);

    uint8_t accept_wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    size_t accept_len = 0;
    YSA_CHECK("ceremony: buyer_begin accepts",
              yardsale_buyer_begin(&ad, &buyer, buyer_keys, 2, YSA_NOW,
                                   accept_wire, sizeof(accept_wire),
                                   &accept_len) == YARDSALE_OK);
    YSA_CHECK("ceremony: accept was flooded once on zswapaccept",
              flood.count == 1 &&
              strcmp(flood.last_command, ZSWAP_MSG_ACCEPT) == 0 &&
              flood.last_len == accept_len);
    char hex[2 * YSA_TX_BUF_BYTES + 1];
    ysa_hex(accept_wire, accept_len, hex);
    YSA_CHECK("ceremony: accept wire is the Stage-3 golden vector",
              strcmp(hex, YSA_KAT_ACCEPT_WIRE_HEX) == 0);
    YSA_CHECK("ceremony: one pending buy registered",
              yardsale_pending_count(YSA_NOW) == 1);

    /* SELLER: the accept arrives over the P2P ingress port — a node with
     * the sign remembered and a profile configured answers. */
    uint8_t partial_wire[ZSWAP_PARTIAL_WIRE_MAX_BYTES];
    size_t partial_len = 0;
    int verdict = yardsale_ceremony_accept_ingest(
        accept_wire, accept_len, 7, YSA_NOW,
        partial_wire, sizeof(partial_wire), &partial_len);
    YSA_CHECK("ceremony: accept ingress verdict is RESPOND",
              verdict == ZSWAP_CEREMONY_WIRE_RESPOND);
    ysa_hex(partial_wire, partial_len, hex);
    YSA_CHECK("ceremony: partial wire is the Stage-3 golden vector",
              strcmp(hex, YSA_KAT_PARTIAL_WIRE_HEX) == 0);

    /* A byte-identical re-delivery of the accept dedups to DROP. Keep the
     * golden partial length — the ingress zeroes *respond_len on entry. */
    size_t saved_len = partial_len;
    verdict = yardsale_ceremony_accept_ingest(
        accept_wire, accept_len, 8, YSA_NOW,
        partial_wire, sizeof(partial_wire), &partial_len);
    YSA_CHECK("ceremony: re-delivered accept dedups (DROP)",
              verdict == ZSWAP_CEREMONY_WIRE_DROP);

    /* BUYER: the partial arrives — the pending buy completes, signs, and
     * hands the fully-signed swap to the broadcast port. The chain-
     * content port serves the confirmed body the KAT terms claim; the
     * golden broadcast may only fire after it passes. */
    struct ysa_broadcast_capture broadcast = {0};
    yardsale_ceremony_set_broadcast(ysa_broadcast_capture_fn, &broadcast);
    YSA_CHECK("ceremony: prevout fixture armed",
              ysa_prevout_arm(&ad, &seller));
    yardsale_ceremony_set_prevout_fetch(ysa_prevout_fetch_fn, NULL);
    verdict = yardsale_ceremony_partial_ingest(partial_wire, saved_len,
                                               7, YSA_NOW);
    YSA_CHECK("ceremony: partial ingress consumes the pending buy",
              verdict == ZSWAP_CEREMONY_WIRE_DROP);
    YSA_CHECK("ceremony: completed swap reached the broadcast port",
              broadcast.count == 1);
    ysa_hex(broadcast.tx_bytes, broadcast.tx_len, hex);
    YSA_CHECK("ceremony: broadcast tx is the Stage-3 golden final tx",
              strcmp(hex, YSA_KAT_FINAL_TX_HEX) == 0);
    YSA_CHECK("ceremony: pending table drained",
              yardsale_pending_count(YSA_NOW) == 0);

    ysa_reset_all();
    return failures;
}

/* ── Exact controller-produced transaction through connect_block ─── */

static int t_simnet_atomic_purchase(void)
{
    int failures = 0;
    ysa_reset_all();

    struct simnet sim;
    bool sim_ok = simnet_init(&sim);
    YSA_CHECK("simnet: isolated chain initializes", sim_ok);
    if (!sim_ok)
        return failures;
    simnet_activate_sapling_at(&sim, simnet_tip_height(&sim) + 1);

    struct privkey seller_key, buyer_key;
    ysa_key(&seller_key, 0x31);
    ysa_key(&buyer_key, 0x42);
    uint8_t seller_spk_bytes[25], buyer_spk_bytes[25];
    bool scripts_ok =
        ysa_p2pkh_script(&seller_key, seller_spk_bytes) == 25 &&
        ysa_p2pkh_script(&buyer_key, buyer_spk_bytes) == 25;
    struct script seller_spk, buyer_spk;
    memset(&seller_spk, 0, sizeof(seller_spk));
    memset(&buyer_spk, 0, sizeof(buyer_spk));
    if (scripts_ok) {
        script_set(&seller_spk, seller_spk_bytes, sizeof(seller_spk_bytes));
        script_set(&buyer_spk, buyer_spk_bytes, sizeof(buyer_spk_bytes));
    }
    YSA_CHECK("simnet: seller and buyer funding scripts derive", scripts_ok);

    struct zswap_quote_v1 ad;
    uint8_t quote_root[32];
    bool ad_ok = ysa_ingest_kat_ad(&ad, quote_root);
    YSA_CHECK("simnet: signed Yardsale ad enters the app cache", ad_ok);

    /* Controller-only fixture: the injected port stands for a completed
     * strict-chain decision and returns the body whose value/script the
     * controller must bind. The direct production-service cases below prove
     * ancestry, projection freshness, unspent state, and canonicality. */

    /* Fixture-only funding coinbase the token send consumes; the 100
     * filler blocks minted below satisfy its coinbase maturity before
     * the send lands. */
    struct uint256 junk_fund;
    bool junk_ok = scripts_ok &&
        simnet_mint_coinbase_to(&sim, &seller_spk,
                                YSA_SELLER_INPUT_VALUE * 10, &junk_fund);

    struct uint256 buyer_fund_a, buyer_fund_b;
    bool funded = junk_ok &&
        simnet_mint_coinbase_to(&sim, &buyer_spk,
                                YSA_BUYER_IN_A_VALUE, &buyer_fund_a) &&
        simnet_mint_coinbase_to(&sim, &buyer_spk,
                                YSA_BUYER_IN_B_VALUE, &buyer_fund_b) &&
        simnet_mint_to_height(&sim, 201);
    YSA_CHECK("simnet: funding outputs mature", funded);
    if (!funded) {
        simnet_free(&sim);
        ysa_reset_all();
        return failures;
    }

    struct transaction token_tx;
    memset(&token_tx, 0, sizeof(token_tx));
    transaction_init(&token_tx);
    uint64_t token_send_q = ad_ok ? ad.token_amount : 0;
    bool token_built = ad_ok && transaction_alloc(&token_tx, 1, 2);
    if (token_built) {
        uint8_t opret[256];
        struct uint256 wire_id;
        for (int i = 0; i < 32; i++)
            wire_id.data[i] = ad.token_id[31 - i];
        size_t olen = slp_build_send(opret, sizeof(opret), &wire_id,
                                     &token_send_q, 1);
        uint8_t sig[] = {0x00, 0x00};
        script_set(&token_tx.vin[0].script_sig, sig, sizeof(sig));
        token_tx.vin[0].prevout.hash = junk_fund;
        token_tx.vin[0].prevout.n = 0;
        token_tx.vin[0].sequence = 0xFFFFFFFF;
        token_tx.vout[0].value = 0; /* op-return output */
        token_tx.vout[0].script_pub_key.size = olen;
        memcpy(token_tx.vout[0].script_pub_key.data, opret, olen);
        token_tx.vout[1].value = YSA_SELLER_INPUT_VALUE;
        token_tx.vout[1].script_pub_key.size = 25;
        memcpy(token_tx.vout[1].script_pub_key.data, seller_spk_bytes,
               25);
        transaction_compute_hash(&token_tx);
        token_built = olen > 0;
    }
    YSA_CHECK("simnet: seller token send body builds", token_built);

    uint8_t token_txid[32];
    memset(token_txid, 0, sizeof(token_txid));
    struct uint256 token_out;
    uint256_set_null(&token_out);
    bool token_served = false;
    if (token_built) {
        memcpy(token_txid, token_tx.hash.data, 32);
        memcpy(token_out.data, token_txid, 32);
        token_served = ysa_prevout_serve_body(&token_tx) &&
            simnet_mint_txs(&sim, &token_tx, 1); /* ownership -> sim */
        transaction_init(&token_tx); /* the sim owns the minted body */
    }
    YSA_CHECK("simnet: body confirms; trusted port fixture serves it",
              token_served);
    if (!token_served) {
        simnet_free(&sim);
        ysa_reset_all();
        return failures;
    }

    struct zswap_seller_accept seller;
    bool seller_ok = ysa_seller(&seller);
    if (seller_ok)
        ysa_fill_exact_input(&seller.token_input, token_txid, 1,
                             YSA_SELLER_INPUT_VALUE, seller_spk_bytes, 25);
    YSA_CHECK("simnet: seller terms name the confirmed token send",
              seller_ok);
    if (seller_ok)
        yardsale_seller_profile_configure(&seller, &seller_key);

    struct zswap_buyer_accept buyer;
    bool buyer_ok = ysa_buyer(&buyer);
    if (buyer_ok) {
        /* Deliberately list B before A; the ceremony must canonical-sort the
         * real outpoints rather than relying on collection order. */
        ysa_fill_exact_input(&buyer.inputs[0], buyer_fund_b.data, 0,
                             YSA_BUYER_IN_B_VALUE, buyer_spk_bytes, 25);
        ysa_fill_exact_input(&buyer.inputs[1], buyer_fund_a.data, 0,
                             YSA_BUYER_IN_A_VALUE, buyer_spk_bytes, 25);
    }
    YSA_CHECK("simnet: buyer terms name both isolated ZCL inputs", buyer_ok);

    struct privkey buyer_keys[2];
    buyer_keys[0] = buyer_key;
    buyer_keys[1] = buyer_key;
    struct ysa_flood_capture flood = {0};
    yardsale_ceremony_set_flood(ysa_flood_capture_fn, &flood);
    uint8_t accept_wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    size_t accept_len = 0;
    bool begun = ad_ok && seller_ok && buyer_ok &&
        yardsale_buyer_begin(&ad, &buyer, buyer_keys, 2, YSA_NOW,
                             accept_wire, sizeof(accept_wire), &accept_len) ==
            YARDSALE_OK;
    YSA_CHECK("simnet: buyer starts the real controller ceremony", begun);

    uint8_t partial_wire[ZSWAP_PARTIAL_WIRE_MAX_BYTES];
    size_t partial_len = 0;
    int seller_verdict = begun ? yardsale_ceremony_accept_ingest(
        accept_wire, accept_len, 17, YSA_NOW, partial_wire,
        sizeof(partial_wire), &partial_len) : ZSWAP_CEREMONY_WIRE_DROP;
    YSA_CHECK("simnet: seller validates terms and signs its input",
              seller_verdict == ZSWAP_CEREMONY_WIRE_RESPOND);

    struct ysa_transaction_capture broadcast = {0};
    yardsale_ceremony_set_broadcast(ysa_transaction_capture_fn, &broadcast);
    yardsale_ceremony_set_prevout_fetch(ysa_prevout_fetch_fn, NULL);
    int buyer_verdict = seller_verdict == ZSWAP_CEREMONY_WIRE_RESPOND
        ? yardsale_ceremony_partial_ingest(partial_wire, partial_len, 17,
                                           YSA_NOW)
        : ZSWAP_CEREMONY_WIRE_RELAY;
    YSA_CHECK("simnet: buyer verifies seller and signs both ZCL inputs",
              buyer_verdict == ZSWAP_CEREMONY_WIRE_DROP &&
              broadcast.count == 1 && broadcast.copied &&
              zswap_ceremony_all_inputs_signed(&broadcast.tx));

    bool exact_inputs = broadcast.copied && broadcast.tx.num_vin == 3 &&
        simnet_coin_value(&sim, &token_out, 1, NULL) &&
        simnet_coin_value(&sim, &buyer_fund_a, 0, NULL) &&
        simnet_coin_value(&sim, &buyer_fund_b, 0, NULL);
    YSA_CHECK("simnet: captured broadcast spends the three live inputs",
              exact_inputs);

    struct uint256 final_txid;
    uint256_set_null(&final_txid);
    if (broadcast.copied) {
        transaction_compute_hash(&broadcast.tx);
        final_txid = broadcast.tx.hash;
    }
    bool mined = exact_inputs && simnet_mint_txs(&sim, &broadcast.tx, 1);
    if (mined)
        broadcast.copied = false; /* ownership transferred to simnet */
    YSA_CHECK("simnet: exact controller broadcast passes connect_block",
              mined && simnet_tip_height(&sim) == 203);

    int64_t token_dust = 0, seller_paid = 0;
    int64_t seller_change = 0, buyer_change = 0;
    bool settled = mined &&
        !simnet_coin_value(&sim, &token_out, 1, NULL) &&
        !simnet_coin_value(&sim, &buyer_fund_a, 0, NULL) &&
        !simnet_coin_value(&sim, &buyer_fund_b, 0, NULL) &&
        simnet_coin_value(&sim, &final_txid, 1, &token_dust) &&
        simnet_coin_value(&sim, &final_txid, 2, &seller_paid) &&
        simnet_coin_value(&sim, &final_txid, 3, &seller_change) &&
        simnet_coin_value(&sim, &final_txid, 4, &buyer_change);
    YSA_CHECK("simnet: settlement values and fee are exact",
              settled && token_dust == ZSWAP_TOKEN_DUST_ZAT &&
              seller_paid == (int64_t)YSA_ZCL_AMOUNT &&
              seller_change ==
                  YSA_SELLER_INPUT_VALUE - ZSWAP_TOKEN_DUST_ZAT &&
              buyer_change == YSA_BUYER_IN_A_VALUE + YSA_BUYER_IN_B_VALUE -
                                  (int64_t)YSA_ZCL_AMOUNT -
                                  (int64_t)YSA_FEE_SATS);

    if (broadcast.copied)
        transaction_free(&broadcast.tx);
    simnet_free(&sim);
    ysa_reset_all();
    return failures;
}

/* ── Ingress policy negatives ────────────────────────────────────── */

static int t_ingress_negatives(void)
{
    int failures = 0;
    ysa_reset_all();

    struct zswap_quote_v1 ad;
    uint8_t quote_root[32];
    YSA_CHECK("neg: KAT ad ingested", ysa_ingest_kat_ad(&ad, quote_root));

    struct zswap_buyer_accept buyer;
    YSA_CHECK("neg: buyer terms fixture", ysa_buyer(&buyer));
    struct privkey keys[2];
    ysa_key(&keys[0], 0x42);
    ysa_key(&keys[1], 0x42);
    struct ysa_flood_capture flood = {0};
    yardsale_ceremony_set_flood(ysa_flood_capture_fn, &flood);
    uint8_t accept_wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    size_t accept_len = 0;
    YSA_CHECK("neg: accept built",
              yardsale_buyer_begin(&ad, &buyer, keys, 2, YSA_NOW,
                                   accept_wire, sizeof(accept_wire),
                                   &accept_len) == YARDSALE_OK);

    uint8_t respond[ZSWAP_PARTIAL_WIRE_MAX_BYTES];
    size_t respond_len = 0;

    /* A magic-tampered wire never decodes: DROP, never relayed. */
    uint8_t tampered[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    memcpy(tampered, accept_wire, accept_len);
    tampered[0] ^= 0xff;
    YSA_CHECK("neg: magic-tampered accept drops",
              yardsale_ceremony_accept_ingest(
                  tampered, accept_len, 3, YSA_NOW,
                  respond, sizeof(respond), &respond_len) ==
                  ZSWAP_CEREMONY_WIRE_DROP);

    /* A stranger's sign (unknown root): the accept relays onward — that
     * is how it reaches the seller. */
    struct zswap_quote_v1 stranger;
    YSA_CHECK("neg: stranger ad seals", ysa_ad(&stranger));
    stranger.nonce = 0x0badc0deULL;
    {
        uint8_t seed[32];
        memset(seed, 0x77, sizeof(seed));
        uint8_t sk[32], pk[32];
        ed25519_keypair(pk, sk, seed);
        memcpy(stranger.seller_pubkey, pk, 32);
        zswap_quote_seal(&stranger, seed);
    }
    uint8_t stranger_root[32];
    zswap_quote_root(&stranger, stranger_root);
    struct zswap_accept_v1 stray_accept;
    memset(&stray_accept, 0, sizeof(stray_accept));
    stray_accept.schema_version = ZSWAP_ACCEPT_VERSION;
    memcpy(stray_accept.quote_root, stranger_root, 32);
    stray_accept.buyer = buyer;
    uint8_t stray_wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    size_t stray_len = 0;
    YSA_CHECK("neg: stranger accept encodes",
              zswap_accept_encode(&stray_accept, stray_wire,
                                  sizeof(stray_wire), &stray_len) ==
                  ZSWAP_CEREMONY_OK);
    YSA_CHECK("neg: accept for unknown sign relays",
              yardsale_ceremony_accept_ingest(
                  stray_wire, stray_len, 3, YSA_NOW,
                  respond, sizeof(respond), &respond_len) ==
                  ZSWAP_CEREMONY_WIRE_RELAY);

    /* A partial with no pending buy behind it: someone else's ceremony —
     * relay. Drop the pending buy registered above WITHOUT touching the
     * yardsale cache (the sign stays remembered). */
    struct zswap_seller_accept seller;
    struct privkey seller_key;
    ysa_seller(&seller);
    ysa_key(&seller_key, 0x31);
    yardsale_seller_profile_configure(&seller, &seller_key);
    size_t partial_len = 0;
    YSA_CHECK("neg: seller answers the real accept (handler path)",
              yardsale_seller_handle_accept_wire(
                  accept_wire, accept_len, YSA_NOW,
                  respond, sizeof(respond), &partial_len) == YARDSALE_OK);
    yardsale_ceremony_reset();
    YSA_CHECK("neg: partial with no pending buy relays",
              yardsale_ceremony_partial_ingest(respond, partial_len,
                                               3, YSA_NOW) ==
                  ZSWAP_CEREMONY_WIRE_RELAY);

    /* A seller with no profile configured never signs: the accept for a
     * REMEMBERED sign relays instead of being answered. */
    yardsale_seller_profile_clear();
    YSA_CHECK("neg: no-profile node relays an accept for a known sign",
              yardsale_ceremony_accept_ingest(
                  accept_wire, accept_len, 4, YSA_NOW,
                  respond, sizeof(respond), &respond_len) ==
                  ZSWAP_CEREMONY_WIRE_RELAY);

    /* An expired sign refuses at the seller handler with the named
     * ceremony error, not a crash or a signature. */
    yardsale_seller_profile_configure(&seller, &seller_key);
    YSA_CHECK("neg: expired sign named EXPIRED",
              yardsale_seller_handle_accept_wire(
                  accept_wire, accept_len, YSA_EXPIRES + 1,
                  respond, sizeof(respond), &partial_len) ==
                  (enum yardsale_error)(YARDSALE_ERR_CEREMONY_BASE +
                                        ZSWAP_CEREMONY_ERR_EXPIRED));

    /* Buyer begin without a flood port refuses loudly and keeps no
     * pending state. */
    yardsale_ceremony_reset();
    yardsale_ceremony_set_flood(NULL, NULL);
    YSA_CHECK("neg: buyer begin with unwired flood refuses",
              yardsale_buyer_begin(&ad, &buyer, keys, 2, YSA_NOW,
                                   accept_wire, sizeof(accept_wire),
                                   &accept_len) ==
                  YARDSALE_ERR_NOT_CONFIGURED);
    YSA_CHECK("neg: refused begin leaves no pending buy",
              yardsale_pending_count(YSA_NOW) == 0);

    ysa_reset_all();
    return failures;
}

/* ── The buyer's chain-content guard ─────────────────────────────── */

/* One ceremony round per case, driven to the buyer's partial-ingest
 * verdict. Fresh buyer keys per round keep the accept wire distinct, so
 * the dedup table never swallows a later case's ceremony. */
static bool ysa_guard_setup(int case_i, struct zswap_quote_v1 *ad,
                            uint8_t partial_wire[], size_t *partial_len)
{
    uint8_t quote_root[32];
    if (!ysa_ingest_kat_ad(ad, quote_root))
        return false;
    struct zswap_seller_accept seller;
    struct privkey seller_key;
    if (!ysa_seller(&seller))
        return false;
    ysa_key(&seller_key, 0x31);
    yardsale_seller_profile_configure(&seller, &seller_key);
    struct zswap_buyer_accept buyer;
    if (!ysa_buyer(&buyer))
        return false;
    struct privkey keys[2];
    ysa_key(&keys[0], (uint8_t)(0x42 + case_i));
    ysa_key(&keys[1], (uint8_t)(0x42 + case_i));
    struct ysa_flood_capture flood = {0};
    yardsale_ceremony_set_flood(ysa_flood_capture_fn, &flood);
    uint8_t accept_wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    size_t accept_len = 0;
    if (yardsale_buyer_begin(ad, &buyer, keys, 2, YSA_NOW, accept_wire,
                             sizeof(accept_wire), &accept_len) !=
        YARDSALE_OK)
        return false;
    return yardsale_ceremony_accept_ingest(
               accept_wire, accept_len, (int64_t)(100 + case_i), YSA_NOW,
               partial_wire, ZSWAP_PARTIAL_WIRE_MAX_BYTES,
               partial_len) == ZSWAP_CEREMONY_WIRE_RESPOND;
}

static int t_prevout_guard(void)
{
    int failures = 0;
    enum {
        PV_SERVE = 0,   /* honest body: the positive control */
        PV_UNWIRED,     /* port left NULL */
        PV_MISS,        /* fetcher finds nothing confirmed */
        PV_WRONG_TOKEN, /* body holds a different token id */
        PV_WRONG_AMT,   /* body holds less than the ad's amount */
        PV_WRONG_VAL,   /* claimed sat value does not match the body */
        PV_WRONG_SPK,   /* claimed script does not match the body */
        PV_CASES
    };
    static const char *const names[PV_CASES] = {
        "guard: trusted port matching body signs and broadcasts",
        "guard: unwired port refuses to sign",
        "guard: unconfirmed token input refuses",
        "guard: wrong token id refuses",
        "guard: short token amount refuses",
        "guard: wrong sat value refuses",
        "guard: wrong output script refuses",
    };

    for (int c = 0; c < PV_CASES; c++) {
        ysa_reset_all();
        struct zswap_quote_v1 ad;
        uint8_t partial_wire[ZSWAP_PARTIAL_WIRE_MAX_BYTES];
        size_t partial_len = 0;
        bool ready = ysa_guard_setup(c, &ad, partial_wire, &partial_len);

        struct zswap_seller_accept seller;
        bool have_seller = ysa_seller(&seller);
        struct zswap_buyer_accept buyer;
        bool have_buyer = ysa_buyer(&buyer);
        bool armed = ready && have_seller && have_buyer;
        if (armed) {
            uint8_t spk[25];
            struct privkey bk;
            ysa_key(&bk, 0x42);
            size_t spk_len =
                ysa_p2pkh_script(&bk, spk) == 25 ? 25 : 0;
            switch (c) {
            case PV_SERVE:
                armed = ysa_prevout_arm(&ad, &seller);
                break;
            case PV_UNWIRED:
                armed = ysa_prevout_arm(&ad, &seller);
                break;
            case PV_MISS:
                armed = ysa_prevout_arm(&ad, &seller);
                ysa_prevout_serve = false;
                break;
            case PV_WRONG_TOKEN: {
                uint8_t bad[32];
                memcpy(bad, ad.token_id, 32);
                bad[0] ^= 0x01;
                armed = ysa_prevout_build(seller.token_input.txid, bad,
                                          ad.token_amount,
                                          seller.token_input.value_sats,
                                          seller.token_input.script_pub_key,
                                          seller.token_input.script_len);
                break;
            }
            case PV_WRONG_AMT:
                armed = ysa_prevout_build(
                    seller.token_input.txid, ad.token_id,
                    ad.token_amount - 1,
                    seller.token_input.value_sats,
                    seller.token_input.script_pub_key,
                    seller.token_input.script_len);
                break;
            case PV_WRONG_VAL:
                armed = ysa_prevout_build(
                    seller.token_input.txid, ad.token_id,
                    ad.token_amount,
                    seller.token_input.value_sats - 1,
                    seller.token_input.script_pub_key,
                    seller.token_input.script_len);
                break;
            case PV_WRONG_SPK:
                armed = spk_len == 25 &&
                    ysa_prevout_build(
                        seller.token_input.txid, ad.token_id,
                        ad.token_amount,
                        seller.token_input.value_sats, spk, 25);
                break;
            default:
                armed = false;
                break;
            }
        }

        /* The buyer's half: ports wired per case (UNWIRED leaves the
         * chain-content port NULL; the positive control alone may
         * broadcast). */
        struct ysa_broadcast_capture broadcast = {0};
        if (armed) {
            if (c != PV_UNWIRED)
                yardsale_ceremony_set_prevout_fetch(
                    ysa_prevout_fetch_fn, NULL);
            yardsale_ceremony_set_broadcast(ysa_broadcast_capture_fn,
                                            &broadcast);
        }
        int verdict = armed
            ? yardsale_ceremony_partial_ingest(partial_wire, partial_len,
                                               (int64_t)(100 + c), YSA_NOW)
            : ZSWAP_CEREMONY_WIRE_DROP;
        bool pass = armed && verdict == ZSWAP_CEREMONY_WIRE_DROP &&
            broadcast.count == (c == PV_SERVE ? 1 : 0);
        printf("  yardsale_app: %s... %s\n", names[c], pass ? "OK" : "FAIL");
        if (!pass)
            failures++;
    }

    ysa_reset_all();
    return failures;
}

/* ── The per-peer gossip clamp ───────────────────────────────────── */

static int t_peer_clamp(void)
{
    int failures = 0;
    ysa_reset_all();

    struct zswap_buyer_accept buyer;
    YSA_CHECK("clamp: buyer terms fixture", ysa_buyer(&buyer));
    struct zswap_quote_v1 ad;
    uint8_t quote_root[32];
    YSA_CHECK("clamp: KAT ad built", ysa_ad(&ad));
    YSA_CHECK("clamp: root computes",
              zswap_quote_root(&ad, quote_root) == ZSWAP_QUOTE_OK);

    /* One decodable accept wire naming an unknown sign; bump a buyer
     * input value byte per variant so each is a distinct wire (distinct
     * dedup hash) that still decodes. */
    struct zswap_accept_v1 accept;
    memset(&accept, 0, sizeof(accept));
    accept.schema_version = ZSWAP_ACCEPT_VERSION;
    memcpy(accept.quote_root, quote_root, 32);
    accept.buyer = buyer;

    uint8_t wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    size_t wire_len = 0;
    YSA_CHECK("clamp: base accept encodes",
              zswap_accept_encode(&accept, wire, sizeof(wire),
                                  &wire_len) == ZSWAP_CEREMONY_OK);

    uint8_t respond[ZSWAP_PARTIAL_WIRE_MAX_BYTES];
    size_t respond_len = 0;
    int relayed = 0, dropped = 0;
    /* Offset 42+1+32+4 = the least-significant byte of the first sorted
     * input's value_sats: flipping it yields a distinct wire (distinct
     * dedup hash) that still decodes — value stays positive, ordering is
     * by outpoint. */
    for (int i = 0; i < 9; i++) {
        wire[79] ^= (uint8_t)(1u << (i % 8));
        struct zswap_accept_v1 check;
        bool decodable =
            zswap_accept_decode(wire, wire_len, &check) == ZSWAP_CEREMONY_OK;
        int v = yardsale_ceremony_accept_ingest(wire, wire_len, 42,
                                                YSA_NOW, respond,
                                                sizeof(respond),
                                                &respond_len);
        if (decodable && v == ZSWAP_CEREMONY_WIRE_RELAY) relayed++;
        if (v == ZSWAP_CEREMONY_WIRE_DROP) dropped++;
    }
    YSA_CHECK("clamp: first 8 fresh wires from one peer relay",
              relayed == 8);
    YSA_CHECK("clamp: the 9th fresh wire in the window drops",
              dropped == 1);

    ysa_reset_all();
    return failures;
}

/* ── The seller web endpoint ─────────────────────────────────────── */

static int t_seller_web_endpoint(void)
{
    int failures = 0;
    ysa_reset_all();

    /* The seller endpoint answers against the wall clock (production
     * posture — the mount has no injected clock), so this fixture is a
     * LIVE ad around real now: the KAT window is long expired at any real
     * wall time and would draw the named EXPIRED refusal. Golden-byte
     * equality of the partial wire is already proven in
     * t_ceremony_roundtrip; here the mount owes the route, the
     * status/content-type, and a decodable partial naming the same
     * sign. */
    int64_t now = (int64_t)platform_time_wall_time_t();
    int64_t issued = now - 10;
    int64_t expires = now + 45;

    struct zswap_quote_v1 ad;
    uint8_t quote_root[32];
    YSA_CHECK("web: live ad built", ysa_ad_at(&ad, issued, expires));
    YSA_CHECK("web: live ad ingested", ysa_ingest_ad(&ad, now, quote_root));

    struct zswap_seller_accept seller;
    struct privkey seller_key;
    YSA_CHECK("web: seller terms fixture", ysa_seller_dl(&seller, expires));
    ysa_key(&seller_key, 0x31);
    yardsale_seller_profile_configure(&seller, &seller_key);

    struct zswap_buyer_accept buyer;
    YSA_CHECK("web: buyer terms fixture", ysa_buyer_dl(&buyer, expires));
    struct zswap_accept_v1 accept;
    memset(&accept, 0, sizeof(accept));
    accept.schema_version = ZSWAP_ACCEPT_VERSION;
    memcpy(accept.quote_root, quote_root, 32);
    accept.buyer = buyer;
    uint8_t accept_wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    size_t accept_len = 0;
    YSA_CHECK("web: accept encodes",
              zswap_accept_encode(&accept, accept_wire,
                                  sizeof(accept_wire), &accept_len) ==
                  ZSWAP_CEREMONY_OK);

    /* POST the raw wire to /yardsale/accept: 200 octet-stream whose body
     * decodes as the seller's partial naming the same sign. */
    uint8_t response[8192];
    size_t n = yardsale_site_handle_request("POST", "/yardsale/accept",
                                            accept_wire, accept_len,
                                            response, sizeof(response));
    bool terminated = n > 0 && n < sizeof(response);
    if (terminated)
        response[n] = '\0';
    YSA_CHECK("web: accept POST answered", terminated);
    YSA_CHECK("web: accept POST is 200 octet-stream",
              terminated &&
              strstr((const char *)response, "200 OK") != NULL &&
              strstr((const char *)response,
                     "application/octet-stream") != NULL);
    struct zswap_partial_v1 partial;
    memset(&partial, 0, sizeof(partial));
    bool body_partial = false;
    if (terminated) {
        const char *body_start = strstr((const char *)response, "\r\n\r\n");
        if (body_start) {
            body_start += 4;
            size_t body_len =
                n - (size_t)(body_start - (const char *)response);
            body_partial =
                zswap_partial_decode((const uint8_t *)body_start, body_len,
                                     &partial) == ZSWAP_CEREMONY_OK &&
                memcmp(partial.quote_root, quote_root, 32) == 0;
        }
    }
    YSA_CHECK("web: response body is the partial for this sign",
              body_partial);

    /* A refused accept is a named 422, never a signature over bad terms. */
    uint8_t tampered[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    memcpy(tampered, accept_wire, accept_len);
    tampered[0] ^= 0xff;
    n = yardsale_site_handle_request("POST", "/yardsale/accept",
                                     tampered, accept_len,
                                     response, sizeof(response));
    terminated = n > 0 && n < sizeof(response);
    if (terminated)
        response[n] = '\0';
    YSA_CHECK("web: tampered accept is a named refusal",
              terminated && strstr((const char *)response, "422") != NULL);

    /* The GET pages fail closed when node.db is absent (test process has
     * no runtime db): the mount returns 0 and the dispatcher 503s. */
    n = yardsale_site_handle_request("GET", "/yardsale", NULL, 0,
                                     response, sizeof(response));
    YSA_CHECK("web: index fails closed without the projection", n == 0);

    ysa_reset_all();
    return failures;
}

/* ── Known sellers on the landing page (Track 2) ─────────────────────
 *
 * The /yardsale index reads FRESH peer_directory rows advertising the
 * yardsale App and links their /yardsale mounts, with the ZNAM label join
 * beside the raw .onion. Asserted: fixture rows render, the ZNAM label
 * shows WITH the raw address, a stale seller and a non-yardsale peer are
 * withheld, a hostile stored apps token never reaches the page, and the
 * empty state is honest. The fixture wires a tmp node.db through a
 * db_service into app_runtime_set_current — the same seam
 * test_vault_session.c uses — and drives the REAL directory writer
 * (onion_service_directory_learn) for the live rows. */

#define YSA_SELLER_A \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax.onion"
#define YSA_SELLER_B \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbx.onion"
#define YSA_SELLER_STALE \
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccx.onion"

static int t_known_sellers(void)
{
    int failures = 0;
    ysa_reset_all();

    /* The onion address singleton is process-global; the sequential
     * runner shares it across groups. Snapshot and restore. */
    const char *prev = onion_service_get_address();
    char saved[128] = "";
    if (prev)
        snprintf(saved, sizeof(saved), "%s", prev);
    onion_service_set_address(NULL);

    /* Static: onion_service_start() borrows this pointer. */
    static char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "yardsale_site", "sellers");
    char dbpath[320];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, dbpath)) {
        printf("  yardsale_app: sellers fixture node_db_open... FAIL\n");
        test_cleanup_tmpdir(dir);
        onion_service_set_address(saved[0] ? saved : NULL);
        return 1;
    }
    struct db_service dbsvc;
    memset(&dbsvc, 0, sizeof(dbsvc));
    struct app_runtime_context rt;
    memset(&rt, 0, sizeof(rt));
    db_service_init(&dbsvc);
    if (!db_service_attach(&dbsvc, &ndb) || !db_service_start(&dbsvc)) {
        printf("  yardsale_app: sellers fixture db_service... FAIL\n");
        node_db_close(&ndb);
        test_cleanup_tmpdir(dir);
        onion_service_set_address(saved[0] ? saved : NULL);
        return 1;
    }
    rt.db_service = &dbsvc;
    app_runtime_set_current(&rt);
    onion_service_start(dir);   /* creates peer_directory in the same db */

    static uint8_t resp[262144];

    /* HONEST EMPTY: no sellers discovered yet, and the page says so. */
    memset(resp, 0, sizeof(resp));
    size_t n = yardsale_site_handle_request("GET", "/yardsale", NULL, 0,
                                            resp, sizeof(resp) - 1);
    YSA_CHECK("sellers: empty index renders", n > 0 && n < sizeof(resp));
    if (n > 0 && n < sizeof(resp))
        resp[n] = '\0';
    YSA_CHECK("sellers: the section is on the landing page",
              n > 0 && strstr((const char *)resp, "Known sellers") != NULL);
    YSA_CHECK("sellers: empty state is honest about gossip",
              n > 0 &&
              strstr((const char *)resp, "no sellers discovered yet") &&
              strstr((const char *)resp, "gossip"));

    /* Seed through the REAL harvest writer: one fresh yardsale seller,
     * one peer serving only the blog App. */
    YSA_CHECK("sellers: fresh yardsale peer learned",
              onion_service_directory_learn(YSA_SELLER_A, 8033, 777, 0,
                                            "yardsale,blog"));
    YSA_CHECK("sellers: non-yardsale peer learned",
              onion_service_directory_learn(YSA_SELLER_B, 8033, 100, 0,
                                            "blog"));

    /* The ZNAM label join: register a name for the seller. */
    bool named = node_db_exec(&ndb,
        "CREATE TABLE IF NOT EXISTS znam_names ("
        "name TEXT PRIMARY KEY,"
        "owner_address TEXT NOT NULL,"
        "target_type INTEGER NOT NULL,"
        "target_value TEXT NOT NULL,"
        "reg_txid BLOB NOT NULL,"
        "reg_height INTEGER NOT NULL,"
        "last_update_txid BLOB NOT NULL)");
    if (named) {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(ndb.db,
            "INSERT OR REPLACE INTO znam_names "
            "(name, owner_address, target_type, target_value, reg_txid,"
            " reg_height, last_update_txid) "
            "VALUES (?1,'t1owner',?2,?3,zeroblob(32),?4,zeroblob(32))",
            -1, &s, NULL) == SQLITE_OK && s) {
            sqlite3_bind_text(s, 1, "sellerama", -1, SQLITE_STATIC);
            sqlite3_bind_int(s, 2, ZNAM_TYPE_ONION);
            sqlite3_bind_text(s, 3, YSA_SELLER_A, -1, SQLITE_STATIC);
            sqlite3_bind_int(s, 4, 100);
            named = sqlite3_step(s) == SQLITE_DONE; // raw-sql-ok: test fixture write
        }
        sqlite3_finalize(s);
    }
    YSA_CHECK("sellers: ZNAM fixture name registered", named);

    /* A STALE seller (last_seen past the fresh window) and a junk-apps
     * row as a pre-validation binary might have stored them. */
    char sql[768];
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO peer_directory "
        "(onion_address, port, services, height, last_seen, version, self,"
        " apps) "
        "VALUES ('%s',8033,0,0,%lld,'test',0,'yardsale')",
        YSA_SELLER_STALE,
        (long long)((int64_t)platform_time_wall_time_t() -
                    ONION_DIR_STALE_SECS - 60));
    YSA_CHECK("sellers: stale seller fixture row",
              node_db_exec(&ndb, sql));
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO peer_directory "
        "(onion_address, port, services, height, last_seen, version, self,"
        " apps) "
        "VALUES ('%s',8033,0,0,%lld,'test',0,'yardsale,<img src=x>')",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddx.onion",
        (long long)platform_time_wall_time_t());
    YSA_CHECK("sellers: junk-apps fixture row",
              node_db_exec(&ndb, sql));

    memset(resp, 0, sizeof(resp));
    n = yardsale_site_handle_request("GET", "/yardsale", NULL, 0,
                                     resp, sizeof(resp) - 1);
    YSA_CHECK("sellers: populated index renders", n > 0 && n < sizeof(resp));
    if (n > 0 && n < sizeof(resp))
        resp[n] = '\0';
    const char *page = (const char *)resp;
    YSA_CHECK("sellers: fresh seller linked by its onion mount",
              n > 0 && strstr(page,
                  "http://" YSA_SELLER_A "/yardsale") != NULL);
    YSA_CHECK("sellers: the ZNAM label renders as the link text",
              n > 0 && strstr(page, ">sellerama</a>") != NULL);
    YSA_CHECK("sellers: the raw .onion shows beside the label",
              n > 0 && strstr(page, YSA_SELLER_A) != NULL);
    YSA_CHECK("sellers: the sanitized serves list renders",
              n > 0 && strstr(page, "serves: yardsale,blog") != NULL);
    YSA_CHECK("sellers: a peer serving only another App is withheld",
              n > 0 && strstr(page, YSA_SELLER_B) == NULL);
    YSA_CHECK("sellers: a stale seller is withheld",
              n > 0 && strstr(page, YSA_SELLER_STALE) == NULL);
    YSA_CHECK("sellers: the honest empty state is gone once peers exist",
              n > 0 && strstr(page, "no sellers discovered yet") == NULL);
    /* The junk-apps row DOES serve yardsale, so its onion renders — but
     * the hostile token in its stored apps list never reaches the page
     * (read-time re-validation drops it before html_escape ever sees
     * it). */
    YSA_CHECK("sellers: junk-apps peer renders sanitized",
              n > 0 && strstr(page,
                  "http://"
                  "dddddddddddddddddddddddddddddddddddddddddddddddddddddddx"
                  ".onion/yardsale") != NULL);
    YSA_CHECK("sellers: hostile stored apps token never rendered",
              n > 0 && strstr(page, "<img") == NULL);

    onion_service_stop();
    app_runtime_set_current(NULL);
    db_service_stop(&dbsvc);
    node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    onion_service_set_address(saved[0] ? saved : NULL);
    ysa_reset_all();
    return failures;
}

/* ── The /yardsale/buy plan gate ─────────────────────────────────── */

static int t_webbuy_plan_gate(void)
{
    int failures = 0;
    ysa_reset_all();

    /* A live ad at the real wall clock, so the plan row's expiry and
     * the ceremony's deadline share one coherent window (a quote may
     * live only ZSWAP_QUOTE_MAX_LIFETIME_SECS). */
    struct zswap_quote_v1 ad;
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (!ysa_ad_at(&ad, now - 5, now + ZSWAP_QUOTE_MAX_LIFETIME_SECS - 5)) {
        printf("  yardsale_app: webbuy fixture ad... FAIL\n");
        return 1;
    }
    uint8_t quote_root[32];
    if (!ysa_ingest_ad(&ad, now, quote_root)) {
        printf("  yardsale_app: webbuy ad ingest... FAIL\n");
        ysa_reset_all();
        return 1;
    }
    char root_hex[65];
    ysa_hex(quote_root, 32, root_hex);

    /* Runtime db so the plan ledger exists behind the mount. */
    static char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "yardsale_site", "webbuy");
    char dbpath[320];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, dbpath)) {
        printf("  yardsale_app: webbuy node_db_open... FAIL\n");
        test_cleanup_tmpdir(dir);
        ysa_reset_all();
        return 1;
    }
    struct db_service dbsvc;
    struct app_runtime_context rt;
    memset(&dbsvc, 0, sizeof(dbsvc));
    memset(&rt, 0, sizeof(rt));
    db_service_init(&dbsvc);
    if (!db_service_attach(&dbsvc, &ndb) || !db_service_start(&dbsvc)) {
        printf("  yardsale_app: webbuy db_service... FAIL\n");
        node_db_close(&ndb);
        test_cleanup_tmpdir(dir);
        ysa_reset_all();
        return 1;
    }
    rt.db_service = &dbsvc;
    app_runtime_set_current(&rt);

    /* One real p2pkh coin whose WIF the form carries, mirroring the
     * KAT buyer (the same 0x42 key funds the script and signs). */
    bool made = true;
    uint8_t script[25];
    struct privkey coin_key;
    ysa_key(&coin_key, 0x42);
    made = ysa_p2pkh_script(&coin_key, script) == 25;
    const struct chain_params *cp = chain_params_get();
    size_t sec_len = 0;
    const unsigned char *sec_pfx =
        chain_params_base58_prefix(cp, B58_SECRET_KEY, &sec_len);
    char wif[128] = { 0 };
    made = made && encode_secret(&coin_key, sec_pfx, sec_len, wif,
                                 sizeof(wif));
    char addr_recv[ZSWAP_ADDRESS_FIELD_BYTES];
    char addr_change[ZSWAP_ADDRESS_FIELD_BYTES];
    struct privkey recv_key, change_key;
    ysa_key(&recv_key, 0x42);
    ysa_key(&change_key, 0x43);
    made = made && ysa_address(&recv_key, addr_recv) &&
           ysa_address(&change_key, addr_change);

    char txid_b_hex[65] = "", txid_a_hex[65] = "";
    uint8_t txid_pat[32];
    ysa_pattern32(txid_pat, 0x60);
    ysa_hex(txid_pat, 32, txid_b_hex);
    ysa_pattern32(txid_pat, 0x50);
    ysa_hex(txid_pat, 32, txid_a_hex);
    char script_hex[64] = "";
    ysa_hex(script, 25, script_hex);

    /* Both KAT coins and the shared WIF: the same key funds and signs. */
    char base_form[1280], confirm_form[1320], variant_form[1320];
    snprintf(base_form, sizeof(base_form),
             "root=%s&token_recv=%s&change=%s&fee=%llu"
             "&in1=%s:0:%lld:%s&key1=%s&in2=%s:1:%lld:%s&key2=%s",
             root_hex, addr_recv, addr_change,
             (unsigned long long)YSA_FEE_SATS,
             txid_b_hex, (long long)YSA_BUYER_IN_B_VALUE, script_hex,
             wif,
             txid_a_hex, (long long)YSA_BUYER_IN_A_VALUE, script_hex,
             wif);
    snprintf(confirm_form, sizeof(confirm_form),
             "%s&confirm=true", base_form);
    /* Changed terms under confirm get their own plan identity — refuse
     * instead of arming on lookalike terms. */
    snprintf(variant_form, sizeof(variant_form),
             "root=%s&token_recv=%s&change=%s&fee=%llu"
             "&in1=%s:0:%lld:%s&key1=%s&in2=%s:1:%lld:%s&key2=%s"
             "&confirm=true",
             root_hex, addr_recv, addr_change,
             (unsigned long long)(YSA_FEE_SATS + 1),
             txid_b_hex, (long long)YSA_BUYER_IN_B_VALUE, script_hex,
             wif,
             txid_a_hex, (long long)YSA_BUYER_IN_A_VALUE, script_hex,
             wif);
    memory_cleanse(wif, sizeof(wif)); /* never leaves this stack dirty */

    static uint8_t resp[16384];

    /* Wire the ceremony's outbound gossip like the KAT roundtrip so
     * begin() can run; the capture also proves how many times the form
     * armed. */
    struct ysa_flood_capture flood = {0};
    yardsale_ceremony_set_flood(ysa_flood_capture_fn, &flood);

    if (made) {
        /* Phase A — no confirm field: exact terms get a PLANNED row and
         * the reply is a plan page, not an armed accept. */
        memset(resp, 0, sizeof(resp));
        size_t n = yardsale_site_handle_request(
            "POST", "/yardsale/buy", (const uint8_t *)base_form,
            strlen(base_form), resp, sizeof(resp) - 1);
        YSA_CHECK("webbuy: plan page renders before anything arms",
                  n > 0 &&
                  strstr((const char *)resp, "Accept planned") != NULL &&
                  strstr((const char *)resp, "confirm=true") != NULL);
        YSA_CHECK("webbuy: planning gossips nothing",
                  flood.count == 0);
        int planned_rows = 0;
        sqlite3_stmt *q = NULL;
        if (sqlite3_prepare_v2(ndb.db,
                "SELECT COUNT(*) FROM yardsale_plans WHERE state='PLANNED'",
                -1, &q, NULL) == SQLITE_OK &&
            sqlite3_step(q) == SQLITE_ROW)
            planned_rows = sqlite3_column_int(q, 0);
        sqlite3_finalize(q);
        YSA_CHECK("webbuy: phase A stored exactly one PLANNED row",
                  planned_rows == 1);

        char webbuy_request[65] = {0};
        q = NULL;
        if (sqlite3_prepare_v2(ndb.db,
                "SELECT request_hash FROM yardsale_plans LIMIT 1",
                -1, &q, NULL) == SQLITE_OK &&
            sqlite3_step(q) == SQLITE_ROW) {
            const unsigned char *text = sqlite3_column_text(q, 0);
            if (text)
                snprintf(webbuy_request, sizeof(webbuy_request), "%s",
                         (const char *)text);
        }
        sqlite3_finalize(q);

        struct db_yardsale_plan claim_a, claim_b;
        memset(&claim_a, 0, sizeof(claim_a));
        memset(&claim_b, 0, sizeof(claim_b));
        bool found_a = db_yardsale_plan_find_by_request(
            &ndb, webbuy_request, &claim_a);
        bool found_b = db_yardsale_plan_find_by_request(
            &ndb, webbuy_request, &claim_b);
        enum db_yardsale_plan_claim_result won_a = found_a
            ? db_yardsale_plan_claim(&ndb, &claim_a, now)
            : DB_YARDSALE_PLAN_CLAIM_ERROR;
        enum db_yardsale_plan_claim_result won_b = found_b
            ? db_yardsale_plan_claim(&ndb, &claim_b, now)
            : DB_YARDSALE_PLAN_CLAIM_ERROR;
        YSA_CHECK("webbuy: only one claimant can cross PLANNED to ARMING",
                  won_a == DB_YARDSALE_PLAN_CLAIMED &&
                  won_b == DB_YARDSALE_PLAN_CLAIM_REFUSED);
        memset(resp, 0, sizeof(resp));
        n = yardsale_site_handle_request(
            "POST", "/yardsale/buy", (const uint8_t *)confirm_form,
            strlen(confirm_form), resp, sizeof(resp) - 1);
        YSA_CHECK("webbuy: an uncertain ARMING row never replays",
                  n > 0 && strstr((const char *)resp, "400") != NULL &&
                  flood.count == 0);
        snprintf(claim_a.state, sizeof(claim_a.state), "%s",
                 YARDSALE_PLAN_STATE_PLANNED);
        claim_a.result[0] = '\0';
        YSA_CHECK("webbuy: fixture releases the claimed row",
                  db_yardsale_plan_save(&ndb, &claim_a));
        snprintf(claim_a.state, sizeof(claim_a.state), "%s",
                 YARDSALE_PLAN_STATE_EXPIRED);
        YSA_CHECK("webbuy: fixture expires the live-terms plan",
                  db_yardsale_plan_save(&ndb, &claim_a));
        memset(resp, 0, sizeof(resp));
        n = yardsale_site_handle_request(
            "POST", "/yardsale/buy", (const uint8_t *)base_form,
            strlen(base_form), resp, sizeof(resp) - 1);
        memset(&claim_a, 0, sizeof(claim_a));
        bool renewed = db_yardsale_plan_find_by_request(
            &ndb, webbuy_request, &claim_a);
        YSA_CHECK("webbuy: inspecting live terms renews an expired plan",
                  n > 0 && renewed &&
                  strcmp(claim_a.state, YARDSALE_PLAN_STATE_PLANNED) == 0);

        char alias_form[1340], junk_fee_form[1340];
        snprintf(alias_form, sizeof(alias_form), "%s&xconfirm=true",
                 base_form);
        memset(resp, 0, sizeof(resp));
        n = yardsale_site_handle_request(
            "POST", "/yardsale/buy", (const uint8_t *)alias_form,
            strlen(alias_form), resp, sizeof(resp) - 1);
        YSA_CHECK("webbuy: a field-name suffix cannot confirm",
                  n > 0 && strstr((const char *)resp, "Accept planned") &&
                  flood.count == 0);
        snprintf(junk_fee_form, sizeof(junk_fee_form), "%s&fee=1junk",
                 base_form);
        memset(resp, 0, sizeof(resp));
        n = yardsale_site_handle_request(
            "POST", "/yardsale/buy", (const uint8_t *)junk_fee_form,
            strlen(junk_fee_form), resp, sizeof(resp) - 1);
        YSA_CHECK("webbuy: duplicate or junk money fields never confirm",
                  n > 0 && strstr((const char *)resp, "400") != NULL &&
                  flood.count == 0);

        char disguised_confirm[1360];
        snprintf(disguised_confirm, sizeof(disguised_confirm),
                 "%s&memo=x?confirm=true", base_form);
        memset(resp, 0, sizeof(resp));
        n = yardsale_site_handle_request(
            "POST", "/yardsale/buy", (const uint8_t *)disguised_confirm,
            strlen(disguised_confirm), resp, sizeof(resp) - 1);
        YSA_CHECK("webbuy: question mark inside a value cannot arm money",
                  n > 0 &&
                  strstr((const char *)resp, "Accept planned") != NULL &&
                  flood.count == 0);

        char spaced_confirm[1360];
        snprintf(spaced_confirm, sizeof(spaced_confirm),
                 "%s&confirm=true anything", base_form);
        memset(resp, 0, sizeof(resp));
        n = yardsale_site_handle_request(
            "POST", "/yardsale/buy", (const uint8_t *)spaced_confirm,
            strlen(spaced_confirm), resp, sizeof(resp) - 1);
        YSA_CHECK("webbuy: a true prefix followed by space cannot arm money",
                  n > 0 &&
                  strstr((const char *)resp, "Accept planned") != NULL &&
                  flood.count == 0);

        char nul_confirm[1360];
        snprintf(nul_confirm, sizeof(nul_confirm),
                 "%s&confirm=true%%00false", base_form);
        memset(resp, 0, sizeof(resp));
        n = yardsale_site_handle_request(
            "POST", "/yardsale/buy", (const uint8_t *)nul_confirm,
            strlen(nul_confirm), resp, sizeof(resp) - 1);
        YSA_CHECK("webbuy: a decoded NUL cannot hide confirm suffix bytes",
                  n > 0 && strstr((const char *)resp, "400") != NULL &&
                  flood.count == 0);

        char malformed_confirm[1360];
        snprintf(malformed_confirm, sizeof(malformed_confirm),
                 "%s&confirm=true%%", base_form);
        memset(resp, 0, sizeof(resp));
        n = yardsale_site_handle_request(
            "POST", "/yardsale/buy", (const uint8_t *)malformed_confirm,
            strlen(malformed_confirm), resp, sizeof(resp) - 1);
        YSA_CHECK("webbuy: malformed escape cannot arm money",
                  n > 0 && strstr((const char *)resp, "400") != NULL &&
                  flood.count == 0);

        memset(resp, 0, sizeof(resp));
        n = yardsale_site_handle_request(
            "POST", "/yardsale/buy", (const uint8_t *)variant_form,
            strlen(variant_form), resp, sizeof(resp) - 1);
        YSA_CHECK(
            "webbuy: confirm on unplanned terms names the inspection gap",
            n > 0 && strstr((const char *)resp, "400") != NULL &&
                     strstr((const char *)resp,
                            "no plan names these exact terms") != NULL);

        /* Phase B — the same stored terms plus confirm=true arm once. */
        memset(resp, 0, sizeof(resp));
        n = yardsale_site_handle_request(
            "POST", "/yardsale/buy", (const uint8_t *)confirm_form,
            strlen(confirm_form), resp, sizeof(resp) - 1);
        YSA_CHECK("webbuy: confirm on stored terms pins the accept",
                  n > 0 &&
                  strstr((const char *)resp, "pinned on the seller") !=
                      NULL);
        YSA_CHECK("webbuy: arming gossips the accept exactly once",
                  flood.count == 1 &&
                  strcmp(flood.last_command, ZSWAP_MSG_ACCEPT) == 0);
        int committed_rows = 0;
        q = NULL;
        if (sqlite3_prepare_v2(ndb.db,
                "SELECT COUNT(*) FROM yardsale_plans "
                "WHERE state='COMMITTED' AND result='begun'",
                -1, &q, NULL) == SQLITE_OK &&
            sqlite3_step(q) == SQLITE_ROW)
            committed_rows = sqlite3_column_int(q, 0);
        sqlite3_finalize(q);
        YSA_CHECK("webbuy: armed row is COMMITTED exactly once",
                  committed_rows == 1 && planned_rows == 1);

        /* Phase B replay: identical resubmit answers idempotently from
         * the ledger instead of arming again. */
        memset(resp, 0, sizeof(resp));
        n = yardsale_site_handle_request(
            "POST", "/yardsale/buy", (const uint8_t *)confirm_form,
            strlen(confirm_form), resp, sizeof(resp) - 1);
        YSA_CHECK("webbuy: committed replay changes nothing",
                  n > 0 &&
                  strstr((const char *)resp, "already pinned") != NULL &&
                  flood.count == 1);
    } else {
        printf("  yardsale_app: webbuy fixture build... FAIL\n");
        failures++;
    }

    app_runtime_set_current(NULL);
    db_service_stop(&dbsvc);
    node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    ysa_reset_all();
    return failures;
}

int test_yardsale_app(void)
{
    printf("\n=== yardsale_app: manifest + ceremony through the controller ===\n");
    int failures = 0;
    failures += t_manifest();
    failures += t_ceremony_roundtrip();
    failures += t_prevout_service_strict();
    failures += t_simnet_atomic_purchase();
    failures += t_webbuy_plan_gate();
    failures += t_ingress_negatives();
    failures += t_prevout_guard();
    failures += t_peer_clamp();
    failures += t_seller_web_endpoint();
    failures += t_known_sellers();
    printf("=== yardsale_app complete: %d failure(s) ===\n", failures);
    return failures;
}
