/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_yardsale_wallet — the yardsale WALLET GLUE (app/services/src/
 * yardsale_wallet_service*.c): wallet-backed seller arm/disarm/status and
 * wallet-backed buy, driven end-to-end through the service with a real
 * in-memory wallet (the test_slp.c mock-wallet idiom) and a real
 * in-memory node.db plan ledger.
 *
 * Proofs (docs: the wallet-glue brief):
 *   - arm with an outpoint the wallet does not own refuses cleanly and
 *     never configures the profile;
 *   - arm -> commit -> a ceremony accept arrives -> the seller ANSWERS;
 *     arm -> disarm -> the accept arrives -> the seller does NOT answer
 *     (profile cleared, key cleansed);
 *   - buy with an insufficient confirmed balance refuses at plan time and
 *     names the shortfall;
 *   - committing after the plan expiry refuses and does not arm/buy;
 *   - idempotent retry: same request identity -> same plan/result, no
 *     double arm, no double pending buy;
 *   - key material never persists: the plan rows and the captured
 *     stdout/stderr are scanned for the exact key bytes (hex + WIF) with
 *     an anti-vacuous positive control. */

#define _GNU_SOURCE

#include "test/test_core.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "chain/chainparams.h"
#include "controllers/yardsale_controller.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "models/database.h"
#include "models/yardsale_plan.h"
#include "script/standard.h"
#include "services/yardsale_wallet_service.h"
#include "support/cleanse.h"
#include "wallet/wallet.h"
#include "zswap/zswap_ceremony.h"
#include "zswap/zswap_quote.h"
#include "zswap/zswap_yardsale.h"
#include "zslp/slp.h"

#include <sqlite3.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define YW_CHECK(name, expr) do {                                       \
    if (expr) { printf("  yardsale_wallet: %s... OK\n", (name)); }      \
    else { printf("  yardsale_wallet: %s... FAIL\n", (name));           \
        failures++; }                                                   \
} while (0)

#define YW_ISSUED 1754000000LL
#define YW_EXPIRES (YW_ISSUED + 45LL)
#define YW_NOW (YW_ISSUED + 10LL)
#define YW_BRANCH_ID 0x76b809bbU
#define YW_TOKEN_SUPPLY 1000ULL
#define YW_TOKEN_DUST_VALUE 10000LL
#define YW_ZCL_PRICE 50000ULL
#define YW_FUND_VALUE 100000LL
#define YW_WALLET_FEE WALLET_DEFAULT_FEE_ZAT

static void yw_pattern32(uint8_t out[32], uint8_t base)
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(base + i);
}

static void yw_test_key(struct privkey *key, uint8_t fill)
{
    memset(key->vch, fill, 32);
    key->fValid = true;
    key->fCompressed = true;
}

static size_t yw_p2pkh_script(const struct privkey *key, uint8_t out[25])
{
    struct pubkey pk;
    if (!privkey_get_pubkey(key, &pk))
        return 0;
    struct key_id kid = pubkey_get_id(&pk);
    out[0] = 0x76;
    out[1] = 0xa9;
    out[2] = 0x14;
    memcpy(out + 3, kid.id.data, 20);
    out[23] = 0x88;
    out[24] = 0xac;
    return 25;
}

static bool yw_address(const struct privkey *key,
                       char out[ZSWAP_ADDRESS_FIELD_BYTES])
{
    struct pubkey pk;
    if (!privkey_get_pubkey(key, &pk))
        return false;
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

/* One signed ad for token_id, valid [YW_ISSUED, YW_EXPIRES). */
static bool yw_make_ad(struct zswap_quote_v1 *q, const uint8_t token_id[32],
                       uint64_t token_amount, uint64_t zcl_amount,
                       uint64_t nonce)
{
    memset(q, 0, sizeof(*q));
    q->schema_version = ZSWAP_QUOTE_VERSION;
    yw_pattern32(q->network_genesis_root, 0xa0);
    uint8_t seed[32];
    memset(seed, 0x11, sizeof(seed));
    uint8_t sk[32];
    ed25519_keypair(q->seller_pubkey, sk, seed);
    q->nonce = nonce;
    memcpy(q->token_id, token_id, 32);
    q->token_amount = token_amount;
    q->zcl_amount = zcl_amount;
    q->issued_unix = YW_ISSUED;
    q->expires_unix = YW_EXPIRES;
    return zswap_quote_seal(q, seed) == ZSWAP_QUOTE_OK;
}

/* Ingest an ad into the REAL yardsale cache (the service answers out of
 * the same cache the gossip layer fills). */
static bool yw_ingest_ad(const struct zswap_quote_v1 *ad,
                         uint8_t quote_root[32])
{
    uint8_t wire[ZSWAP_QUOTE_WIRE_BYTES];
    if (zswap_quote_encode(ad, wire) != ZSWAP_QUOTE_OK)
        return false;
    uint8_t net[32];
    yw_pattern32(net, 0xa0);
    struct zswap_yardsale_ad entry;
    if (zswap_yardsale_ingest_wire(wire, sizeof(wire), net, 1, YW_NOW,
                                   &entry) != ZSWAP_YARDSALE_INGEST_NEW)
        return false;
    return zswap_quote_root(ad, quote_root) == ZSWAP_QUOTE_OK;
}

/* ── mock wallet (the test_slp.c idiom) ──────────────────────────── */

static bool yw_coin_reserved(const struct transaction *tx, uint32_t vout,
                             void *ctx)
{
    (void)ctx;
    struct slp_output_metadata meta;
    return slp_classify_tx_output(tx, vout, &meta);
}

static bool yw_wallet_open(struct wallet *w, uint8_t seed_fill,
                           struct key_id *owner_kid, char *addr,
                           size_t addr_cap)
{
    uint8_t seed[32];
    memset(seed, seed_fill, sizeof(seed));
    wallet_init(w);
    bool ok = wallet_init_hd(w, seed, sizeof(seed));
    ok = ok && wallet_get_new_address_with_key_id(w, addr, addr_cap,
                                                  owner_kid);
    memory_cleanse(seed, sizeof(seed));
    return ok;
}

/* Fund one ordinary P2PKH coin paying the wallet's owner address.
 * Returns the outpoint (txid internal order, vout 0). */
static bool yw_fund_ordinary(struct wallet *w, const struct key_id *owner,
                             int64_t value, uint8_t txid_out[32])
{
    struct tx_destination dest = { .type = DEST_KEY_ID, .id.key = *owner };
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    transaction_init(&wtx.tx);
    bool ok = transaction_alloc(&wtx.tx, 0, 1);
    if (ok) {
        wtx.tx.vout[0].value = value;
        script_for_destination(&wtx.tx.vout[0].script_pub_key, &dest);
        transaction_compute_hash(&wtx.tx);
        memcpy(txid_out, wtx.tx.hash.data, 32);
        wtx.confirms = 10;
        ok = wallet_add_to_wallet(w, &wtx);
        transaction_free(&wtx.tx);
    }
    return ok;
}

/* Fund one SLP token: a genesis tx whose vout[1] is a dust P2PKH coin to
 * the wallet's owner holding the full supply. The outpoint is
 * (txid_out, 1); token_id_out is the genesis tx hash. */
static bool yw_fund_token(struct wallet *w, const struct key_id *owner,
                          uint64_t supply, uint8_t txid_out[32])
{
    struct tx_destination dest = { .type = DEST_KEY_ID, .id.key = *owner };
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    transaction_init(&wtx.tx);
    bool ok = transaction_alloc(&wtx.tx, 0, 2);
    uint8_t script[256];
    size_t len = slp_build_genesis(script, sizeof(script), "YWT",
                                   "Yardsale Wallet Token", "", NULL, 0, 2,
                                   supply);
    ok = ok && len > 0;
    if (ok) {
        wtx.tx.vout[0].script_pub_key.size = len;
        memcpy(wtx.tx.vout[0].script_pub_key.data, script, len);
        wtx.tx.vout[1].value = YW_TOKEN_DUST_VALUE;
        script_for_destination(&wtx.tx.vout[1].script_pub_key, &dest);
        transaction_compute_hash(&wtx.tx);
        memcpy(txid_out, wtx.tx.hash.data, 32);
        wtx.confirms = 10;
        ok = wallet_add_to_wallet(w, &wtx);
        transaction_free(&wtx.tx);
    }
    return ok;
}

/* ── injected ports ──────────────────────────────────────────────── */

static uint32_t yw_branch_id(void *ctx)
{
    (void)ctx;
    return YW_BRANCH_ID;
}

struct yw_flood_capture {
    int count;
    char last_command[16];
    size_t last_len;
};

static void yw_flood_fn(const char *command, const uint8_t *wire,
                        size_t wire_len, void *ctx)
{
    struct yw_flood_capture *cap = ctx;
    (void)wire;
    cap->count++;
    snprintf(cap->last_command, sizeof(cap->last_command), "%s", command);
    cap->last_len = wire_len;
}

static int yw_test_buyer_begin(const struct zswap_quote_v1 *ad,
                               const struct zswap_buyer_accept *buyer,
                               const struct privkey *input_keys,
                               size_t num_keys, int64_t now_unix,
                               uint8_t *wire_out, size_t wire_cap,
                               size_t *wire_len)
{
    return (int)yardsale_buyer_begin(ad, buyer, input_keys, num_keys,
                                     now_unix, wire_out, wire_cap, wire_len);
}

static void yw_reset_all(void)
{
    static const struct yardsale_wallet_ceremony_port port = {
        .seller_profile_configure = yardsale_seller_profile_configure,
        .seller_profile_clear = yardsale_seller_profile_clear,
        .seller_profile_configured = yardsale_seller_profile_configured,
        .seller_profile_snapshot = yardsale_seller_profile_snapshot,
        .pending_count = yardsale_pending_count,
        .buyer_begin = yw_test_buyer_begin,
        .buyer_error_string = yardsale_error_string,
    };
    yardsale_wallet_set_ceremony_port(&port);
    zswap_yardsale_reset();
    yardsale_ceremony_reset();
    yardsale_seller_profile_clear();
    yardsale_ceremony_set_flood(NULL, NULL);
    yardsale_ceremony_set_broadcast(NULL, NULL);
    yardsale_ceremony_set_branch_id_source(yw_branch_id, NULL);
}

/* A structurally valid buyer accept for `ad` (one input of
 * YW_FUND_VALUE sats paying the exact price + fee), encoded into a
 * zswap_accept.v1 wire. txid_base varies the wire bytes. */
static bool yw_accept_wire(const struct zswap_quote_v1 *ad,
                           uint8_t txid_base, uint8_t *wire, size_t cap,
                           size_t *wire_len)
{
    struct zswap_accept_v1 accept;
    memset(&accept, 0, sizeof(accept));
    accept.schema_version = ZSWAP_ACCEPT_VERSION;
    if (zswap_quote_root(ad, accept.quote_root) != ZSWAP_QUOTE_OK)
        return false;
    struct zswap_buyer_accept *b = &accept.buyer;
    struct privkey buyer_key, change_key;
    yw_test_key(&buyer_key, 0x42);
    yw_test_key(&change_key, 0x43);
    uint8_t script[25];
    if (yw_p2pkh_script(&buyer_key, script) != 25)
        return false;
    b->num_inputs = 1;
    yw_pattern32(b->inputs[0].txid, txid_base);
    b->inputs[0].vout = 0;
    b->inputs[0].value_sats = YW_FUND_VALUE;
    b->inputs[0].script_len = 25;
    memcpy(b->inputs[0].script_pub_key, script, 25);
    if (!yw_address(&buyer_key, b->token_recv_address) ||
        !yw_address(&change_key, b->change_address))
        return false;
    b->fee_sats = YW_WALLET_FEE;
    b->deadline_unix = ad->expires_unix;
    return zswap_accept_encode(&accept, wire, cap, wire_len) ==
           ZSWAP_CEREMONY_OK;
}

/* ── plan-table / log key scans (negative proofs) ────────────────── */

/* Count plan rows carrying `needle` in any free-text column. */
static int yw_plans_contain(struct node_db *ndb, const char *needle)
{
    sqlite3_stmt *s = NULL;
    int count = 0;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT COUNT(*) FROM yardsale_plans WHERE "
            "instr(payload_hex,?)>0 OR instr(plan_root,?)>0 OR "
            "instr(request_hash,?)>0 OR instr(result,?)>0", -1, &s,
            NULL) == SQLITE_OK && s) {
        for (int i = 1; i <= 4; i++)
            sqlite3_bind_text(s, i, needle, -1, SQLITE_STATIC);
        if (sqlite3_step(s) == SQLITE_ROW) // raw-sql-ok:test-readonly-probe
            count = sqlite3_column_int(s, 0);
    }
    if (s)
        sqlite3_finalize(s);
    return count;
}

struct yw_capture {
    int saved_out, saved_err;
    int fd_out, fd_err;
    char path_out[1200], path_err[1200];
};

static bool yw_capture_begin(struct yw_capture *c, const char *dir)
{
    memset(c, 0, sizeof(*c));
    c->saved_out = c->saved_err = c->fd_out = c->fd_err = -1;
    snprintf(c->path_out, sizeof(c->path_out), "%s/cap.out", dir);
    snprintf(c->path_err, sizeof(c->path_err), "%s/cap.err", dir);
    fflush(stdout);
    fflush(stderr);
    c->saved_out = dup(STDOUT_FILENO);
    c->saved_err = dup(STDERR_FILENO);
    c->fd_out = open(c->path_out, O_RDWR | O_CREAT | O_TRUNC, 0600);
    c->fd_err = open(c->path_err, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (c->saved_out < 0 || c->saved_err < 0 || c->fd_out < 0 ||
        c->fd_err < 0)
        return false;
    return dup2(c->fd_out, STDOUT_FILENO) >= 0 &&
           dup2(c->fd_err, STDERR_FILENO) >= 0;
}

static void yw_capture_end(struct yw_capture *c)
{
    fflush(stdout);
    fflush(stderr);
    if (c->saved_out >= 0) { dup2(c->saved_out, STDOUT_FILENO); close(c->saved_out); }
    if (c->saved_err >= 0) { dup2(c->saved_err, STDERR_FILENO); close(c->saved_err); }
    if (c->fd_out >= 0) close(c->fd_out);
    if (c->fd_err >= 0) close(c->fd_err);
    c->saved_out = c->saved_err = c->fd_out = c->fd_err = -1;
}

/* True when `needle` appears in either capture file. */
static bool yw_capture_contains(const struct yw_capture *c,
                                const char *needle)
{
    char buf[65536];
    for (int i = 0; i < 2; i++) {
        const char *path = i == 0 ? c->path_out : c->path_err;
        FILE *f = fopen(path, "rb");
        if (!f)
            continue;
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';
        if (n > 0 && needle[0] && strstr(buf, needle))
            return true;
    }
    return false;
}

/* ── the group ───────────────────────────────────────────────────── */

int test_yardsale_wallet(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));

    wallet_set_coin_reservation_probe(yw_coin_reserved, NULL);
    yw_reset_all();

    /* Seller wallet: one token coin (YW_TOKEN_SUPPLY of its genesis
     * token) and one ordinary coin. Buyer wallet: one ordinary coin. */
    struct yw_wallet_pair {
        struct wallet seller;
        struct wallet buyer;
    };
    struct yw_wallet_pair *wallets = zcl_malloc(
        sizeof(*wallets), "yardsale wallet fixtures");
#define seller_w (wallets->seller)
#define buyer_w (wallets->buyer)
    struct key_id seller_kid, buyer_kid;
    char addr[128];
    uint8_t token_txid[32], seller_zcl_txid[32], buyer_zcl_txid[32];
    bool fixture = wallets != NULL &&
        node_db_open(&ndb, ":memory:") &&
        yw_wallet_open(&seller_w, 0x5a, &seller_kid, addr, sizeof(addr)) &&
        yw_fund_token(&seller_w, &seller_kid, YW_TOKEN_SUPPLY, token_txid) &&
        yw_fund_ordinary(&seller_w, &seller_kid, YW_FUND_VALUE,
                         seller_zcl_txid) &&
        yw_wallet_open(&buyer_w, 0x6b, &buyer_kid, addr, sizeof(addr)) &&
        yw_fund_ordinary(&buyer_w, &buyer_kid, YW_FUND_VALUE,
                         buyer_zcl_txid);
    YW_CHECK("fixture: wallets funded and plan ledger open", fixture);
    if (!fixture)
        goto done;

    /* The seller's sign for his token coin. */
    struct zswap_quote_v1 ad;
    uint8_t ad_root[32];
    YW_CHECK("fixture: ad sealed and ingested",
             yw_make_ad(&ad, token_txid, YW_TOKEN_SUPPLY, YW_ZCL_PRICE,
                        0x0102030405060708ULL) &&
             yw_ingest_ad(&ad, ad_root));

    /* ── status before any arm ───────────────────────────────────── */
    {
        struct json_value out;
        json_init(&out);
        YW_CHECK("status: unarmed node answers configured=false",
                 yardsale_wallet_seller_status(YW_NOW, &out) ==
                     YARDSALE_WALLET_OK &&
                 !json_get_bool(json_get(&out, "configured")));
        json_free(&out);
    }

    /* ── arm: plan ───────────────────────────────────────────────── */
    char plan_root_a[65];
    {
        struct json_value out;
        json_init(&out);
        bool ok = yardsale_wallet_seller_arm(
            &seller_w, &ndb, token_txid, 1, ad_root, false, YW_NOW,
            &out) == YARDSALE_WALLET_OK;
        const char *stage = json_get_str(json_get(&out, "stage"));
        const char *root = json_get_str(json_get(&out, "plan_root"));
        const struct json_value *terms = json_get(&out, "terms");
        YW_CHECK("arm plan: exact terms rendered, nothing armed", ok &&
            stage && strcmp(stage, "plan") == 0 &&
            !json_get_bool(json_get(&out, "committed")) &&
            root && strlen(root) == 64 && terms &&
            json_get_int(json_get(terms, "token_vout")) == 1 &&
            json_get_int(json_get(terms, "token_input_sats")) ==
                YW_TOKEN_DUST_VALUE &&
            json_get_int(json_get(terms, "token_amount")) ==
                (int64_t)YW_TOKEN_SUPPLY &&
            json_get_int(json_get(terms, "zcl_amount_sats")) ==
                (int64_t)YW_ZCL_PRICE &&
            json_get_str(json_get(terms, "zcl_recv_address")) != NULL &&
            json_get_str(json_get(terms, "change_address")) != NULL &&
            json_get_int(json_get(terms, "deadline_unix")) == YW_EXPIRES &&
            !yardsale_seller_profile_configured());
        if (root)
            snprintf(plan_root_a, sizeof(plan_root_a), "%s", root);
        else
            plan_root_a[0] = '\0';
        json_free(&out);

        struct db_yardsale_plan row;
        char request_hex[65];
        struct json_value probe;
        json_init(&probe);
        /* The row persisted; its plan_root matches the rendered one. */
        bool row_ok = false;
        if (yardsale_wallet_seller_arm(&seller_w, &ndb, token_txid, 1,
                                       ad_root, false, YW_NOW,
                                       &probe) == YARDSALE_WALLET_OK) {
            const char *rh = json_get_str(json_get(&probe, "request_hash"));
            const char *root2 = json_get_str(json_get(&probe, "plan_root"));
            if (rh && root2) {
                snprintf(request_hex, sizeof(request_hex), "%s", rh);
                row_ok = strcmp(root2, plan_root_a) == 0 &&
                         db_yardsale_plan_find(&ndb, plan_root_a, &row) &&
                         strcmp(row.state, YARDSALE_PLAN_STATE_PLANNED) ==
                             0;
            }
        }
        json_free(&probe);
        YW_CHECK("arm plan: idempotent re-plan, same plan_root, row "
                 "persisted", row_ok);
    }

    /* ── arm: outpoint the wallet does not own ───────────────────── */
    {
        uint8_t foreign[32];
        yw_pattern32(foreign, 0x77);
        struct json_value out;
        json_init(&out);
        enum yardsale_wallet_status st = yardsale_wallet_seller_arm(
            &seller_w, &ndb, foreign, 0, ad_root, false, YW_NOW, &out);
        const char *code = json_get_str(json_get(&out, "code"));
        YW_CHECK("arm: foreign outpoint refuses, names INPUT_NOT_OWNED",
                 st == YARDSALE_WALLET_ERR_INPUT_NOT_OWNED &&
                 !json_get_bool(json_get(&out, "ok")) && code &&
                 strcmp(code, "INPUT_NOT_OWNED") == 0);
        json_free(&out);
        YW_CHECK("arm: refusal configured no profile",
                 !yardsale_seller_profile_configured());
    }

    /* ── arm: token amount mismatch ──────────────────────────────── */
    {
        struct zswap_quote_v1 wrong_ad;
        uint8_t wrong_root[32];
        bool have = yw_make_ad(&wrong_ad, token_txid, YW_TOKEN_SUPPLY - 1,
                               YW_ZCL_PRICE, 0x0102030405060709ULL) &&
                    yw_ingest_ad(&wrong_ad, wrong_root);
        struct json_value out;
        json_init(&out);
        enum yardsale_wallet_status st = yardsale_wallet_seller_arm(
            &seller_w, &ndb, token_txid, 1, wrong_root, false, YW_NOW,
            &out);
        const char *code = json_get_str(json_get(&out, "code"));
        YW_CHECK("arm: coin holding the wrong amount refuses "
                 "TOKEN_MISMATCH", have &&
                 st == YARDSALE_WALLET_ERR_TOKEN_MISMATCH && code &&
                 strcmp(code, "TOKEN_MISMATCH") == 0);
        json_free(&out);
        YW_CHECK("arm: mismatch configured no profile",
                 !yardsale_seller_profile_configured());
    }

    /* ── arm: commit, replay, answer ─────────────────────────────── */
    {
        struct json_value out;
        json_init(&out);
        bool ok = yardsale_wallet_seller_arm(
            &seller_w, &ndb, token_txid, 1, ad_root, true, YW_NOW,
            &out) == YARDSALE_WALLET_OK;
        const char *digest = json_get_str(json_get(&out, "terms_digest"));
        YW_CHECK("arm commit: profile armed, digest rendered", ok &&
            json_get_bool(json_get(&out, "committed")) &&
            !json_get_bool(json_get(&out, "idempotent_replay")) &&
            json_get_bool(json_get(&out, "profile_configured")) &&
            digest && strlen(digest) == 64 &&
            yardsale_seller_profile_configured());
        json_free(&out);

        struct db_yardsale_plan row;
        YW_CHECK("arm commit: ledger row COMMITTED/armed",
                 db_yardsale_plan_find(&ndb, plan_root_a, &row) &&
                 strcmp(row.state, YARDSALE_PLAN_STATE_COMMITTED) == 0 &&
                 strcmp(row.result, "armed") == 0);

        struct json_value replay;
        json_init(&replay);
        YW_CHECK("arm commit: replay is idempotent, no double arm",
                 yardsale_wallet_seller_arm(&seller_w, &ndb, token_txid, 1,
                                            ad_root, true, YW_NOW,
                                            &replay) == YARDSALE_WALLET_OK &&
                 json_get_bool(json_get(&replay, "idempotent_replay")) &&
                 yardsale_seller_profile_configured());
        json_free(&replay);
    }

    /* ── status while armed ──────────────────────────────────────── */
    {
        struct json_value out;
        json_init(&out);
        bool ok = yardsale_wallet_seller_status(YW_NOW, &out) ==
                      YARDSALE_WALLET_OK &&
                  json_get_bool(json_get(&out, "configured"));
        const char *digest = json_get_str(json_get(&out, "terms_digest"));
        YW_CHECK("status: armed node renders digest + deadline, never a "
                 "key", ok && digest && strlen(digest) == 64 &&
                 json_get(json_get(&out, "terms"), "zcl_recv_address") &&
                 json_get_int(json_get(&out, "deadline_unix")) ==
                     YW_EXPIRES);
        json_free(&out);
    }

    /* ── armed: the ceremony accept is ANSWERED ──────────────────── */
    {
        uint8_t wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
        size_t wire_len = 0;
        uint8_t respond[ZSWAP_PARTIAL_WIRE_MAX_BYTES];
        size_t respond_len = 0;
        bool have = yw_accept_wire(&ad, 0x60, wire, sizeof(wire),
                                   &wire_len);
        int verdict = have ? yardsale_ceremony_accept_ingest(
            wire, wire_len, 7, YW_NOW, respond, sizeof(respond),
            &respond_len) : -1;
        YW_CHECK("armed seller answers the accept (RESPOND)",
                 verdict == ZSWAP_CEREMONY_WIRE_RESPOND && respond_len > 0);
    }

    /* ── disarm: the seller does NOT answer ──────────────────────── */
    {
        struct json_value out;
        json_init(&out);
        YW_CHECK("disarm: was_configured -> cleared",
                 yardsale_wallet_seller_disarm(&out) ==
                     YARDSALE_WALLET_OK &&
                 json_get_bool(json_get(&out, "was_configured")) &&
                 !json_get_bool(json_get(&out, "configured")) &&
                 !yardsale_seller_profile_configured());
        json_free(&out);

        /* A DIFFERENT accept wire (the first is dedup-consumed): known
         * sign, no profile -> relay, never an answer. */
        uint8_t wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
        size_t wire_len = 0;
        uint8_t respond[ZSWAP_PARTIAL_WIRE_MAX_BYTES];
        size_t respond_len = 0;
        bool have = yw_accept_wire(&ad, 0x61, wire, sizeof(wire),
                                   &wire_len);
        int verdict = have ? yardsale_ceremony_accept_ingest(
            wire, wire_len, 8, YW_NOW, respond, sizeof(respond),
            &respond_len) : -1;
        YW_CHECK("disarmed seller does NOT answer (RELAY, keys cleansed "
                 "out of the profile)",
                 verdict == ZSWAP_CEREMONY_WIRE_RELAY && respond_len == 0);

        struct json_value again;
        json_init(&again);
        YW_CHECK("disarm: idempotent on an unarmed node",
                 yardsale_wallet_seller_disarm(&again) ==
                     YARDSALE_WALLET_OK &&
                 !json_get_bool(json_get(&again, "was_configured")));
        json_free(&again);
    }

    /* ── arm: commit after plan expiry refuses and does not arm ──── */
    {
        struct zswap_quote_v1 ad2;
        uint8_t ad2_root[32];
        bool have = yw_make_ad(&ad2, token_txid, YW_TOKEN_SUPPLY,
                               YW_ZCL_PRICE, 0x010203040506070aULL) &&
                    yw_ingest_ad(&ad2, ad2_root);
        struct json_value out;
        json_init(&out);
        bool planned = have && yardsale_wallet_seller_arm(
            &seller_w, &ndb, token_txid, 1, ad2_root, false, YW_NOW,
            &out) == YARDSALE_WALLET_OK;
        json_free(&out);
        struct json_value late;
        json_init(&late);
        enum yardsale_wallet_status st = yardsale_wallet_seller_arm(
            &seller_w, &ndb, token_txid, 1, ad2_root, true,
            YW_NOW + YARDSALE_WALLET_PLAN_TTL_SECS + 1, &late);
        const char *code = json_get_str(json_get(&late, "code"));
        YW_CHECK("arm: commit after plan expiry refuses PLAN_EXPIRED",
                 planned && st == YARDSALE_WALLET_ERR_PLAN_EXPIRED &&
                 code && strcmp(code, "PLAN_EXPIRED") == 0);
        json_free(&late);
        YW_CHECK("arm: expired commit did NOT arm the profile",
                 !yardsale_seller_profile_configured());
    }

    /* ── buy: insufficient confirmed balance names the shortfall ─── */
    {
        struct zswap_quote_v1 dear_ad;
        uint8_t dear_root[32];
        bool have = yw_make_ad(&dear_ad, token_txid, YW_TOKEN_SUPPLY,
                               YW_FUND_VALUE * 5,
                               0x010203040506070bULL) &&
                    yw_ingest_ad(&dear_ad, dear_root);
        struct json_value out;
        json_init(&out);
        enum yardsale_wallet_status st = yardsale_wallet_buy(
            &buyer_w, &ndb, dear_root, false, YW_NOW, &out);
        const char *code = json_get_str(json_get(&out, "code"));
        int64_t required = json_get_int(json_get(&out, "required_sats"));
        int64_t available = json_get_int(json_get(&out, "available_sats"));
        int64_t shortfall = json_get_int(json_get(&out, "shortfall_sats"));
        YW_CHECK("buy: insufficient balance refuses and names the "
                 "shortfall", have &&
                 st == YARDSALE_WALLET_ERR_INSUFFICIENT && code &&
                 strcmp(code, "INSUFFICIENT_CONFIRMED_FUNDS") == 0 &&
                 required == (int64_t)YW_FUND_VALUE * 5 + YW_WALLET_FEE &&
                 available == YW_FUND_VALUE &&
                 shortfall == required - available);
        json_free(&out);
    }

    /* ── buy: plan, commit, replay ───────────────────────────────── */
    char buy_plan_root[65];
    struct yw_flood_capture flood = { 0 };
    yardsale_ceremony_set_flood(yw_flood_fn, &flood);
    {
        struct zswap_quote_v1 buy_ad;
        uint8_t buy_root[32];
        bool have = yw_make_ad(&buy_ad, token_txid, YW_TOKEN_SUPPLY,
                               YW_ZCL_PRICE, 0x010203040506070cULL) &&
                    yw_ingest_ad(&buy_ad, buy_root);
        struct json_value out;
        json_init(&out);
        bool ok = have && yardsale_wallet_buy(
            &buyer_w, &ndb, buy_root, false, YW_NOW,
            &out) == YARDSALE_WALLET_OK;
        const char *stage = json_get_str(json_get(&out, "stage"));
        const char *root = json_get_str(json_get(&out, "plan_root"));
        const struct json_value *terms = json_get(&out, "terms");
        const struct json_value *inputs =
            terms ? json_get(terms, "inputs") : NULL;
        YW_CHECK("buy plan: price, fee, and the selected input rendered",
                 ok && stage && strcmp(stage, "plan") == 0 &&
                 root && strlen(root) == 64 && terms &&
                 json_get_int(json_get(terms, "price_sats")) ==
                     (int64_t)YW_ZCL_PRICE &&
                 json_get_int(json_get(terms, "fee_sats")) ==
                     YW_WALLET_FEE &&
                 inputs && json_size(inputs) == 1 &&
                 json_get_int(json_get(terms, "deadline_unix")) ==
                     YW_EXPIRES);
        if (root)
            snprintf(buy_plan_root, sizeof(buy_plan_root), "%s", root);
        else
            buy_plan_root[0] = '\0';
        json_free(&out);

        struct json_value replan;
        json_init(&replan);
        const char *root2 = NULL;
        bool ok2 = yardsale_wallet_buy(&buyer_w, &ndb, buy_root, false,
                                       YW_NOW,
                                       &replan) == YARDSALE_WALLET_OK;
        root2 = json_get_str(json_get(&replan, "plan_root"));
        YW_CHECK("buy plan: idempotent re-plan, same plan_root",
                 ok2 && root2 && strcmp(root2, buy_plan_root) == 0);
        json_free(&replan);

        struct json_value commit;
        json_init(&commit);
        bool cok = yardsale_wallet_buy(&buyer_w, &ndb, buy_root, true,
                                       YW_NOW,
                                       &commit) == YARDSALE_WALLET_OK;
        YW_CHECK("buy commit: zswapaccept flooded once, one pending buy",
                 cok && json_get_bool(json_get(&commit, "committed")) &&
                 !json_get_bool(json_get(&commit, "idempotent_replay")) &&
                 flood.count == 1 &&
                 strcmp(flood.last_command, ZSWAP_MSG_ACCEPT) == 0 &&
                 flood.last_len > 0 &&
                 yardsale_pending_count(YW_NOW) == 1);
        json_free(&commit);

        struct db_yardsale_plan row;
        YW_CHECK("buy commit: ledger row COMMITTED/begun",
                 db_yardsale_plan_find(&ndb, buy_plan_root, &row) &&
                 strcmp(row.state, YARDSALE_PLAN_STATE_COMMITTED) == 0 &&
                 strcmp(row.result, "begun") == 0);

        struct json_value replay;
        json_init(&replay);
        YW_CHECK("buy commit: replay is idempotent — no double pending "
                 "buy, no second flood",
                 yardsale_wallet_buy(&buyer_w, &ndb, buy_root, true,
                                     YW_NOW, &replay) ==
                     YARDSALE_WALLET_OK &&
                 json_get_bool(json_get(&replay, "idempotent_replay")) &&
                 flood.count == 1 &&
                 yardsale_pending_count(YW_NOW) == 1);
        json_free(&replay);

        /* ── buy: commit after plan expiry refuses ──────────────── */
        struct zswap_quote_v1 ad3;
        uint8_t ad3_root[32];
        bool have3 = yw_make_ad(&ad3, token_txid, YW_TOKEN_SUPPLY,
                                YW_ZCL_PRICE, 0x010203040506070dULL) &&
                     yw_ingest_ad(&ad3, ad3_root);
        struct json_value p3;
        json_init(&p3);
        bool planned3 = have3 && yardsale_wallet_buy(
            &buyer_w, &ndb, ad3_root, false, YW_NOW,
            &p3) == YARDSALE_WALLET_OK;
        json_free(&p3);
        struct yw_flood_capture flood3 = { 0 };
        yardsale_ceremony_set_flood(yw_flood_fn, &flood3);
        struct json_value late;
        json_init(&late);
        enum yardsale_wallet_status st3 = yardsale_wallet_buy(
            &buyer_w, &ndb, ad3_root, true,
            YW_NOW + YARDSALE_WALLET_PLAN_TTL_SECS + 1, &late);
        const char *code3 = json_get_str(json_get(&late, "code"));
        YW_CHECK("buy: commit after plan expiry refuses, nothing "
                 "flooded, no pending buy",
                 planned3 && st3 == YARDSALE_WALLET_ERR_PLAN_EXPIRED &&
                 code3 && strcmp(code3, "PLAN_EXPIRED") == 0 &&
                 flood3.count == 0);
        json_free(&late);
        yardsale_ceremony_set_flood(yw_flood_fn, &flood);

        /* A durable ARMING claim is exclusive. A second confirmation must
         * refuse before key access or any outbound accept. */
        struct zswap_quote_v1 claim_ad;
        uint8_t claim_root[32];
        bool have_claim = yw_make_ad(&claim_ad, token_txid,
                                     YW_TOKEN_SUPPLY, YW_ZCL_PRICE,
                                     0x010203040506070fULL) &&
                          yw_ingest_ad(&claim_ad, claim_root);
        struct json_value claim_plan;
        json_init(&claim_plan);
        bool planned_claim = have_claim && yardsale_wallet_buy(
            &buyer_w, &ndb, claim_root, false, YW_NOW,
            &claim_plan) == YARDSALE_WALLET_OK;
        const char *claim_plan_root =
            json_get_str(json_get(&claim_plan, "plan_root"));
        struct db_yardsale_plan claimed_row;
        bool found_claim = claim_plan_root &&
            db_yardsale_plan_find(&ndb, claim_plan_root, &claimed_row);
        enum db_yardsale_plan_claim_result claim_result = found_claim
            ? db_yardsale_plan_claim(&ndb, &claimed_row, YW_NOW)
            : DB_YARDSALE_PLAN_CLAIM_ERROR;
        json_free(&claim_plan);
        struct yw_flood_capture claim_flood = { 0 };
        yardsale_ceremony_set_flood(yw_flood_fn, &claim_flood);
        struct json_value claim_retry;
        json_init(&claim_retry);
        enum yardsale_wallet_status claim_status = yardsale_wallet_buy(
            &buyer_w, &ndb, claim_root, true, YW_NOW, &claim_retry);
        const char *claim_code =
            json_get_str(json_get(&claim_retry, "code"));
        YW_CHECK("buy: an ARMING plan excludes a second confirmation",
                 planned_claim &&
                 claim_result == DB_YARDSALE_PLAN_CLAIMED &&
                 claim_status == YARDSALE_WALLET_ERR_PLAN_CONFLICT &&
                 claim_code && strcmp(claim_code, "PLAN_CONFLICT") == 0 &&
                 claim_flood.count == 0);
        json_free(&claim_retry);
        yardsale_ceremony_set_flood(yw_flood_fn, &flood);
    }

    /* ── key material never persists ─────────────────────────────── */
    {
        /* The exact key bytes the commits handled: the seller's token
         * coin key and the buyer's funding coin key. */
        struct privkey seller_key, buyer_key;
        memset(&seller_key, 0, sizeof(seller_key));
        memset(&buyer_key, 0, sizeof(buyer_key));
        bool have_keys = wallet_dump_key(&seller_w, &seller_kid,
                                         &seller_key) &&
                         wallet_dump_key(&buyer_w, &buyer_kid, &buyer_key);
        char seller_hex[65] = { 0 }, buyer_hex[65] = { 0 };
        zcl_hex_encode(seller_key.vch, 32, seller_hex);
        zcl_hex_encode(buyer_key.vch, 32, buyer_hex);
        const struct chain_params *cp = chain_params_get();
        size_t sec_len = 0;
        const unsigned char *sec_pfx =
            chain_params_base58_prefix(cp, B58_SECRET_KEY, &sec_len);
        char seller_wif[128] = { 0 }, buyer_wif[128] = { 0 };
        bool have_wifs =
            encode_secret(&seller_key, sec_pfx, sec_len, seller_wif,
                          sizeof(seller_wif)) &&
            encode_secret(&buyer_key, sec_pfx, sec_len, buyer_wif,
                          sizeof(buyer_wif));

        /* Plan rows: no key bytes in any column; the scan is proven by
         * the ad_root prefix that MUST be present in the payloads. */
        char ad_root_hex[65];
        zcl_hex_encode(ad_root, 32, ad_root_hex);
        YW_CHECK("keys: seller + buyer keys available for the scan",
                 have_keys && have_wifs && seller_key.fValid &&
                 buyer_key.fValid);
        YW_CHECK("keys: plan rows carry neither key (hex form)",
                 yw_plans_contain(&ndb, seller_hex) == 0 &&
                 yw_plans_contain(&ndb, buyer_hex) == 0);
        YW_CHECK("keys: plan rows carry neither key (WIF form)",
                 yw_plans_contain(&ndb, seller_wif) == 0 &&
                 yw_plans_contain(&ndb, buyer_wif) == 0);
        YW_CHECK("keys: anti-vacuous — the scan finds the ad root that "
                 "IS in a payload",
                 yw_plans_contain(&ndb, ad_root_hex) > 0);

        /* Logs: replay an arm commit (idempotent path touches no key —
         * so drive a FRESH arm plan+commit for a new ad under the
         * capture) plus a buy commit, then scan stdout/stderr. */
        char dir[] = "/tmp/ywlogXXXXXX";
        bool logged = false, anti = false;
        if (mkdtemp(dir)) {
            struct zswap_quote_v1 ad4;
            uint8_t ad4_root[32];
            bool have4 = yw_make_ad(&ad4, token_txid, YW_TOKEN_SUPPLY,
                                    YW_ZCL_PRICE,
                                    0x010203040506070eULL) &&
                         yw_ingest_ad(&ad4, ad4_root);
            struct yw_capture cap;
            if (have4 && yw_capture_begin(&cap, dir)) {
                struct json_value o1, o2;
                json_init(&o1);
                json_init(&o2);
                (void)yardsale_wallet_seller_arm(&seller_w, &ndb,
                                                 token_txid, 1, ad4_root,
                                                 false, YW_NOW, &o1);
                json_free(&o1);
                (void)yardsale_wallet_seller_arm(&seller_w, &ndb,
                                                 token_txid, 1, ad4_root,
                                                 true, YW_NOW, &o2);
                json_free(&o2);
                yw_capture_end(&cap);
                logged = !yw_capture_contains(&cap, seller_hex) &&
                         !yw_capture_contains(&cap, buyer_hex) &&
                         !yw_capture_contains(&cap, seller_wif) &&
                         !yw_capture_contains(&cap, buyer_wif);
                /* ANTI-VACUOUS: the same capture harness, handed the
                 * key hex through a plain fprintf, DOES find it. */
                if (yw_capture_begin(&cap, dir)) {
                    fprintf(stdout, "%s\n", seller_hex);
                    yw_capture_end(&cap);
                    anti = yw_capture_contains(&cap, seller_hex);
                }
                unlink(cap.path_out);
                unlink(cap.path_err);
            }
            rmdir(dir);
            yardsale_seller_profile_clear(); /* leave nothing armed */
        }
        YW_CHECK("keys: neither key reaches stdout/stderr during "
                 "plan+commit", logged);
        YW_CHECK("keys: anti-vacuous — the log scanner sees a real leak",
                 anti);
        memory_cleanse(&seller_key, sizeof(seller_key));
        memory_cleanse(&buyer_key, sizeof(buyer_key));
        memory_cleanse(seller_hex, sizeof(seller_hex));
        memory_cleanse(buyer_hex, sizeof(buyer_hex));
        memory_cleanse(seller_wif, sizeof(seller_wif));
        memory_cleanse(buyer_wif, sizeof(buyer_wif));
    }

    wallet_free(&seller_w);
    wallet_free(&buyer_w);

done:
    free(wallets);
    if (ndb.open)
        node_db_close(&ndb);
    yw_reset_all();
    wallet_set_coin_reservation_probe(NULL, NULL);
#undef seller_w
#undef buyer_w
    return failures;
}
