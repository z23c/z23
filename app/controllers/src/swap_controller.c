/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Atomic Swap RPC controller.
 * Cross-chain: ZCL <-> BTC, LTC, DOGE via HTLC. */

#include "platform/time_compat.h"
#include "controllers/swap_controller.h"
#include "controllers/rpc_chainstate_guard.h"
#include "script/htlc.h"
#include "znam/znam.h"
#include "models/swap_contract.h"
#include "services/swap_settlement_service.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "views/format_helpers.h"
#include "rpc/server.h"
#include "models/database.h"
#include "wallet/wallet.h"
#include "wallet/keystore.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "script/standard.h"
#include "core/hash.h"
#include "core/uint256.h"
#include "core/core_io.h"
#include "crypto/sha256.h"
#include "chain/chainparams.h"
#include "consensus/upgrades.h"
#include "coins/coins.h"
#include "coins/coins_view.h"

#include <math.h>
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/accept_to_mempool.h"
#include "validation/txmempool.h"
#include "net/connman.h"
#include "support/cleanse.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include "util/log_macros.h"

/* ── Context ────────────────────────────────────────────────────── */

static struct node_db *g_swap_ndb = NULL;
static struct wallet *g_swap_wallet = NULL;
static struct tx_mempool *g_swap_mempool = NULL;
static struct main_state *g_swap_main_state = NULL;
static struct coins_view_cache *g_swap_coins_tip = NULL;
static struct connman *g_swap_connman = NULL;

void rpc_swap_set_context(struct node_db *ndb, struct wallet *w,
                          struct tx_mempool *mp, struct main_state *ms,
                          struct coins_view_cache *coins_tip,
                          struct connman *cm)
{
    g_swap_ndb = ndb;
    g_swap_wallet = w;
    g_swap_mempool = mp;
    g_swap_main_state = ms;
    g_swap_coins_tip = coins_tip;
    g_swap_connman = cm;
}

/* Offsets of the two 20-byte pubkey-hashes inside the 97-byte HTLC contract
 * (see htlc_build_script): recipient (claim branch) at 43, refunder (refund
 * branch) at 74. */
#define HTLC_RECIPIENT_PKH_OFFSET 43
#define HTLC_REFUNDER_PKH_OFFSET  74

/* ── Helpers ────────────────────────────────────────────────────── */

static const char *state_name(enum swap_state s)
{
    switch (s) {
    case SWAP_PENDING:  return "pending";
    case SWAP_FUNDED:   return "funded";
    case SWAP_REDEEMED: return "redeemed";
    case SWAP_REFUNDED: return "refunded";
    case SWAP_EXPIRED:  return "expired";
    default: return "unknown";
    }
}

static void swap_to_json(const struct swap_contract *swap, struct json_value *obj)
{
    json_set_object(obj);
    json_push_kv_str(obj, "swap_id", swap->swap_id);
    json_push_kv_str(obj, "role",
                     swap->role == SWAP_INITIATOR ? "initiator" : "participant");
    json_push_kv_str(obj, "state", state_name(swap->state));

    const struct swap_chain_params *cp = swap_get_chain_params(swap->chain);
    json_push_kv_str(obj, "chain", cp ? cp->ticker : "?");

    char hex[513]; /* large enough for 256-byte redeem script */
    HexStr(swap->secret_hash, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "secret_hash", hex);

    if (swap->has_secret) {
        HexStr(swap->secret, 32, false, hex, sizeof(hex));
        json_push_kv_str(obj, "secret", hex);
    }

    double amt = swap->amount / 100000000.0;
    json_push_kv_real(obj, "amount", amt);
    json_push_kv_int(obj, "amount_zatoshi", swap->amount);
    json_push_kv_int(obj, "locktime", swap->locktime);
    json_push_kv_str(obj, "my_address", swap->my_address);
    json_push_kv_str(obj, "counter_address", swap->counter_address);
    json_push_kv_str(obj, "p2sh_address", swap->p2sh_address);

    HexStr(swap->redeem_script, swap->redeem_script_len, false, hex, sizeof(hex));
    json_push_kv_str(obj, "redeem_script_hex", hex);
    json_push_kv_int(obj, "redeem_script_size", (int64_t)swap->redeem_script_len);

    json_push_kv_int(obj, "created_at", swap->created_at);
}

/* Parse the optional amount argument (index 2): real if present, else int. */
static double swap_parse_amount(const struct json_value *params)
{
    const struct json_value *amt_val = json_at(params, 2);
    if (!amt_val) return 0;
    double amount = json_get_real(amt_val);
    if (amount == 0.0) amount = (double)json_get_int(amt_val);
    return amount;
}

/* See the contract in swap_controller.h. The overflow ceiling is the exact
 * whole-coin value whose zatoshis still fit int64_t; anything larger, or
 * anything that is not a finite positive number, would persist a money
 * contract this node cannot honour. */
bool swap_amount_to_zat(double amount_coins, int64_t *zat_out)
{
    static const double max_whole_coins =
        (double)(INT64_MAX / 100000000);
    if (!zat_out || !(amount_coins > 0.0) || !isfinite(amount_coins) ||
        amount_coins > max_whole_coins)
        return false;
    *zat_out = (int64_t)(amount_coins * 100000000.0);
    return true;
}

/* Shared build pipeline for swap_initiate / swap_participate: decode both
 * addresses, build the HTLC redeem script + P2SH address, assemble the
 * swap_contract, persist it, and emit it as JSON. secret_or_null is non-NULL
 * for the initiator (has_secret=true). strict_build_fail makes a build-script
 * failure return false (initiate); when false (participate) the legacy
 * fall-through is preserved. Returns false (with result set to an error
 * string) on a hard failure, true on success. */
static bool swap_build_and_persist(const char *my_addr, const char *counter_addr,
                                   double amount, int64_t locktime,
                                   enum swap_chain chain,
                                   const uint8_t secret_hash[32],
                                   const uint8_t *secret_or_null,
                                   enum swap_role role, bool strict_build_fail,
                                   struct json_value *result)
{
    struct htlc_params hp;
    int64_t amount_zat = 0;
    memset(&hp, 0, sizeof(hp));

    /* Money shape first: refuse before any address decodes or state
     * persists. swap_parse_amount yields a bare double straight from the
     * JSON wire, including its failure sentinel of 0 when absent. */
    if (!swap_amount_to_zat(amount, &amount_zat)) {
        json_set_str(result, "Invalid arguments");
        return false;
    }
    memcpy(hp.secret_hash, secret_hash, 32);
    hp.locktime = (uint32_t)locktime;

    if (!htlc_address_to_pkh(counter_addr, chain, hp.recipient_pkh)) {
        json_set_str(result, "Cannot decode counter_address");
        return false;
    }
    if (!htlc_address_to_pkh(my_addr, chain, hp.refunder_pkh)) {
        json_set_str(result, "Cannot decode my_address");
        return false;
    }

    uint8_t script[256];
    size_t script_len = htlc_build_script(&hp, script, sizeof(script));
    if (script_len == 0) {
        json_set_str(result, "Failed to build HTLC script");
        if (strict_build_fail) return false;
        LOG_FAIL("swap", "swap_participate: htlc_build_script failed");
    }

    /* Init: the snprintf below must never read indeterminate bytes. */
    char p2sh_addr[64] = "";
    if (!htlc_p2sh_address(script, script_len, chain, p2sh_addr,
                           sizeof(p2sh_addr)) && strict_build_fail) {
        json_set_str(result, "Failed to compute P2SH address");
        return false;
    }

    struct swap_contract swap;
    memset(&swap, 0, sizeof(swap));
    swap_compute_id(my_addr, counter_addr, secret_hash, swap.swap_id);
    swap.role = role;
    swap.state = SWAP_PENDING;
    swap.chain = chain;
    memcpy(swap.secret_hash, secret_hash, 32);
    if (secret_or_null) {
        memcpy(swap.secret, secret_or_null, 32);
        swap.has_secret = true;
    }
    swap.amount = amount_zat;
    swap.locktime = (uint32_t)locktime;
    snprintf(swap.my_address, sizeof(swap.my_address), "%s", my_addr);
    snprintf(swap.counter_address, sizeof(swap.counter_address), "%s", counter_addr);
    memcpy(swap.redeem_script, script, script_len);
    swap.redeem_script_len = script_len;
    snprintf(swap.p2sh_address, sizeof(swap.p2sh_address), "%s", p2sh_addr);
    swap.created_at = (int64_t)platform_time_wall_time_t();

    if (g_swap_ndb)
        db_swap_save(g_swap_ndb, &swap);

    swap_to_json(&swap, result);
    return true;
}

/* ── swap_chains ────────────────────────────────────────────────── */

static bool rpc_swap_chains(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (help) {
        json_set_str(result, "swap_chains\n\nList supported chains for atomic swaps.\n");
        return true;
    }
    (void)params;

    json_set_array(result);
    for (int i = 0; i <= SWAP_CHAIN_DOGE; i++) {
        const struct swap_chain_params *cp = swap_get_chain_params((enum swap_chain)i);
        struct json_value e = {0};
        json_set_object(&e);
        json_push_kv_str(&e, "name", cp->name);
        json_push_kv_str(&e, "ticker", cp->ticker);
        json_push_back(result, &e);
        json_free(&e);
    }
    return true;
}

/* ── swap_initiate ──────────────────────────────────────────────── */

static int swap_current_height(void);

/* Convert the user-supplied lock DURATION (blocks from the current tip)
 * into the absolute CLTV height embedded in the HTLC script. The script
 * and swap_refund compare against absolute chain height, so storing the
 * duration verbatim would make a "10 blocks from now" contract refundable
 * immediately (CLTV height 10 is ancient history) — the refunder could
 * reclaim before the recipient's claim window ever opened. Fails closed:
 * an unknown tip (height 0) or a non-ZCL chain (whose height this node
 * cannot observe) must not mint a contract with a wrong locktime. */
static bool swap_locktime_to_absolute(int64_t duration_blocks,
                                      enum swap_chain chain,
                                      uint32_t *out_abs,
                                      struct json_value *result)
{
    if (chain != SWAP_CHAIN_ZCL) {
        json_set_str(result, "locktime anchoring is ZCL-only for now: this "
                             "node cannot observe the counterparty chain's "
                             "height, so it cannot embed a correct absolute "
                             "CLTV for btc/ltc/doge contracts");
        return false;
    }
    if (duration_blocks <= 0 || duration_blocks > 1000000) {
        json_set_str(result, "locktime_blocks must be 1..1000000 (a duration "
                             "in blocks from the current tip)");
        return false;
    }
    int height = swap_current_height();
    if (height <= 0) {
        json_set_str(result, "chain tip unknown — cannot anchor the CLTV "
                             "locktime; retry once the node has a synced tip");
        return false;
    }
    *out_abs = (uint32_t)((int64_t)height + duration_blocks);
    return true;
}

static bool rpc_swap_initiate(const struct json_value *params, bool help,
                              struct json_value *result)
{
    if (help || !params || json_size(params) < 4) {
        json_set_str(result,
            "swap_initiate \"my_address\" \"counter_address\" amount locktime_blocks [\"chain\"]\n"
            "\nInitiate an atomic swap. Generates secret, builds HTLC contract.\n"
            "\nArguments:\n"
            "1. my_address      (string) Your address (refund path)\n"
            "2. counter_address (string) Counterparty address (claim path)\n"
            "3. amount          (number) Amount in coins\n"
            "4. locktime_blocks (number) Lock duration in blocks from the\n"
            "                   current tip (stored as absolute CLTV height\n"
            "                   = tip + N; ZCL chain only)\n"
            "5. chain           (string, optional) Chain: zcl, btc, ltc, doge (default: zcl)\n"
            "\nResult: swap contract with secret, secret_hash, P2SH address.\n");
        return true;
    }

    const char *my_addr = json_get_str(json_at(params, 0));
    const char *counter_addr = json_get_str(json_at(params, 1));
    double amount = swap_parse_amount(params);
    int64_t locktime = json_get_int(json_at(params, 3));

    enum swap_chain chain = SWAP_CHAIN_ZCL;
    if (json_size(params) >= 5) {
        const char *cstr = json_get_str(json_at(params, 4));
        int c = swap_parse_chain(cstr);
        if (c >= 0) chain = (enum swap_chain)c;
    }

    if (!my_addr || !counter_addr || amount <= 0 || locktime <= 0) {
        json_set_str(result, "Invalid arguments");
        return false;
    }

    uint32_t locktime_abs = 0;
    if (!swap_locktime_to_absolute(locktime, chain, &locktime_abs, result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)

    /* Generate secret */
    uint8_t secret[32], secret_hash[32];
    htlc_generate_secret(secret, secret_hash);

    if (!swap_build_and_persist(my_addr, counter_addr, amount, locktime_abs,
                                chain, secret_hash, secret, SWAP_INITIATOR,
                                /*strict_build_fail=*/true, result))
        return false;

    const struct swap_chain_params *cp = swap_get_chain_params(chain);
    printf("swap: initiated %s swap for %.8f %s (CLTV unlock height %u = "
           "tip + %lld)\n",
           cp->ticker, amount, cp->ticker, (unsigned)locktime_abs,
           (long long)locktime);
    printf("swap: Fund the P2SH address to activate the swap.\n");

    return true;
}

/* ── swap_participate ───────────────────────────────────────────── */

static bool rpc_swap_participate(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    if (help || !params || json_size(params) < 5) {
        json_set_str(result,
            "swap_participate \"my_address\" \"counter_address\" amount locktime_blocks \"secret_hash\" [\"chain\"]\n"
            "\nParticipate in an atomic swap (create counter-HTLC).\n"
            "\nArguments:\n"
            "1. my_address      (string) Your address (refund path)\n"
            "2. counter_address (string) Initiator's address (claim path)\n"
            "3. amount          (number) Amount in coins\n"
            "4. locktime_blocks (number) Lock duration in blocks from the\n"
            "                   current tip (should be SHORTER than the\n"
            "                   initiator's; stored as absolute CLTV height\n"
            "                   = tip + N; ZCL chain only)\n"
            "5. secret_hash     (string) 64-char hex secret hash from initiator\n"
            "6. chain           (string, optional) Chain: zcl, btc, ltc, doge (default: zcl)\n");
        return true;
    }

    const char *my_addr = json_get_str(json_at(params, 0));
    const char *counter_addr = json_get_str(json_at(params, 1));
    double amount = swap_parse_amount(params);
    int64_t locktime = json_get_int(json_at(params, 3));
    const char *hash_hex = json_get_str(json_at(params, 4));

    enum swap_chain chain = SWAP_CHAIN_ZCL;
    if (json_size(params) >= 6) {
        const char *cstr = json_get_str(json_at(params, 5));
        int c = swap_parse_chain(cstr);
        if (c >= 0) chain = (enum swap_chain)c;
    }

    if (!my_addr || !counter_addr || amount <= 0 || locktime <= 0 ||
        !zcl_is_hex_string(hash_hex, 64)) {
        json_set_str(result, "Invalid arguments");
        return false;
    }

    uint32_t locktime_abs = 0;
    if (!swap_locktime_to_absolute(locktime, chain, &locktime_abs, result))
        return false; // raw-return-ok:RPC error body already set via json_set_str(result,...)

    /* Parse secret hash */
    uint8_t secret_hash[32];
    if (ParseHex(hash_hex, secret_hash, 32) != 32) {
        json_set_str(result, "Invalid secret_hash (64-char hex)");
        return false;
    }

    return swap_build_and_persist(my_addr, counter_addr, amount, locktime_abs,
                                  chain, secret_hash, /*secret_or_null=*/NULL,
                                  SWAP_PARTICIPANT, /*strict_build_fail=*/false,
                                  result);
}

/* ── Settlement helpers (redeem / refund) ───────────────────────── */

/* Current provable chain height (0 if the tip is unknown). */
static int swap_current_height(void)
{
    if (!g_swap_main_state) return 0;
    struct block_index *tip = active_chain_tip(&g_swap_main_state->chain_active);
    return tip ? tip->nHeight : 0;
}

/* Build the 23-byte P2SH scriptPubKey (OP_HASH160 <h160> OP_EQUAL) for a
 * redeem script, into out. */
static void swap_p2sh_spk(const uint8_t *script, size_t slen, struct script *out)
{
    uint8_t h[20];
    hash160(script, slen, h);
    script_init(out);
    out->data[out->size++] = 0xa9; /* OP_HASH160 */
    out->data[out->size++] = 0x14; /* push 20 */
    memcpy(out->data + out->size, h, 20);
    out->size += 20;
    out->data[out->size++] = 0x87; /* OP_EQUAL */
}

/* Resolve the funding outpoint from explicit args (index arg_txid/arg_vout)
 * or the stored contract row. Returns false with an error body on failure. */
static bool swap_resolve_funding(const struct json_value *params,
                                 int arg_txid, int arg_vout,
                                 const struct swap_contract *swap,
                                 struct outpoint *out,
                                 struct json_value *result)
{
    outpoint_set_null(out);
    const char *txid_hex = json_get_str(json_at(params, arg_txid));
    if (txid_hex && txid_hex[0]) {
        if (!parse_hash_str(txid_hex, &out->hash)) {
            json_set_str(result, "Invalid funding_txid (expect 64-char hex)");
            return false;
        }
        out->n = (uint32_t)json_get_int(json_at(params, arg_vout));
        return true;
    }

    static const uint8_t zero32[32] = {0};
    if (memcmp(swap->funding_txid, zero32, 32) != 0) {
        memcpy(out->hash.data, swap->funding_txid, 32);
        out->n = swap->funding_vout;
        return true;
    }

    json_set_str(result,
        "No funding outpoint known for this swap. Pass funding_txid + vout "
        "(the output that paid the contract's P2SH address).");
    return false;
}

/* Look up the funding outpoint in the coins tip, verify it pays the contract
 * P2SH, and return its value. Returns false with an error body otherwise. */
static bool swap_load_funding_value(const struct outpoint *funding,
                                    const struct swap_contract *swap,
                                    int64_t *value_out,
                                    struct json_value *result)
{
    if (!g_swap_coins_tip) {
        json_set_str(result, "Chainstate unavailable — cannot verify funding");
        return false;
    }
    if (!rpc_require_chainstate_lookup_ready(g_swap_main_state, result,
                                             "swap settlement",
                                             "Funding lookup"))
        return false;

    struct coins entry;
    coins_init(&entry);
    if (!coins_view_cache_get_coins(g_swap_coins_tip, &funding->hash, &entry)) {
        coins_free(&entry);
        json_set_str(result,
            "Funding output not found in the UTXO set (unconfirmed or already "
            "spent). Confirm the funding transaction first.");
        return false;
    }
    if (!coins_is_available(&entry, funding->n)) {
        coins_free(&entry);
        json_set_str(result, "Funding output already spent");
        return false;
    }

    struct script expect;
    swap_p2sh_spk(swap->redeem_script, swap->redeem_script_len, &expect);
    const struct tx_out *o = &entry.vout[funding->n];
    if (o->script_pub_key.size != expect.size ||
        memcmp(o->script_pub_key.data, expect.data, expect.size) != 0) {
        coins_free(&entry);
        json_set_str(result,
            "Funding outpoint does not pay this contract's P2SH address");
        return false;
    }

    *value_out = o->value;
    coins_free(&entry);
    return true;
}

/* Fetch the wallet private key + pubkey for a 20-byte pubkey-hash taken from
 * the contract. Returns false with an error body if the wallet lacks it. */
static bool swap_key_for_pkh(const uint8_t pkh[20], struct privkey *key,
                             struct pubkey *pub, struct json_value *result)
{
    struct key_id kid;
    memcpy(kid.id.data, pkh, 20);

    zcl_mutex_lock(&g_swap_wallet->cs);
    bool got = keystore_get_key(&g_swap_wallet->keystore, &kid, key) &&
               privkey_get_pubkey(key, pub);
    zcl_mutex_unlock(&g_swap_wallet->cs);

    if (!got) {
        json_set_str(result,
            "Wallet does not hold the private key required to settle this "
            "swap (the pubkey-hash in the contract is not ours)");
        return false;
    }
    return true;
}

/* Broadcast a settled tx through the shared mempool-acceptance gate, then
 * relay. On success writes the txid hex (65 bytes) and returns true; on
 * failure sets an error body. */
static bool swap_broadcast(struct transaction *tx, char *txid_hex,
                           struct json_value *result)
{
    enum mempool_accept_result r = accept_to_mempool(
        g_swap_mempool, g_swap_coins_tip, g_swap_main_state,
        chain_params_get(), tx);
    if (r != MEMPOOL_ACCEPT_OK) {
        const char *msg;
        switch (r) {
        case MEMPOOL_ACCEPT_INVALID:
            msg = "Settlement tx rejected: failed verification "
                  "(bad signature/secret or structure)"; break;
        case MEMPOOL_ACCEPT_CONFLICT:
            msg = "Settlement tx rejected: conflicts with mempool "
                  "(the funding output is already being spent)"; break;
        case MEMPOOL_ACCEPT_MISSING_INPUTS:
            msg = "Settlement tx rejected: funding input missing or spent";
            break;
        case MEMPOOL_ACCEPT_NONFINAL:
            msg = "Settlement tx rejected: non-final lock time "
                  "(refund locktime not reached yet)"; break;
        case MEMPOOL_ACCEPT_BELOW_FEE:
            msg = "Settlement tx rejected: insufficient fee"; break;
        default:
            msg = "Settlement tx rejected by mempool"; break;
        }
        json_set_str(result, msg);
        return false;
    }
    if (g_swap_connman)
        connman_relay_transaction(g_swap_connman, &tx->hash);
    uint256_get_hex(&tx->hash, txid_hex);
    return true;
}

/* Shared preflight for redeem/refund: node context + chain-scope guard. */
static bool swap_settle_ready(const struct swap_contract *swap,
                              struct json_value *result)
{
    if (!g_swap_wallet || !g_swap_mempool || !g_swap_coins_tip ||
        !g_swap_main_state) {
        json_set_str(result,
            "Swap settlement is unavailable — node chain/wallet context is "
            "not wired (running headless?)");
        return false;
    }
    if (swap->chain != SWAP_CHAIN_ZCL) {
        const struct swap_chain_params *cp = swap_get_chain_params(swap->chain);
        char buf[160];
        snprintf(buf, sizeof(buf),
            "This node can only build + broadcast the ZCL-chain leg. The %s "
            "leg must be redeemed/refunded on that chain's own wallet.",
            cp ? cp->ticker : "counterparty");
        json_set_str(result, buf);
        return false;
    }
    return true;
}

/* ── swap_redeem ────────────────────────────────────────────────── */

static bool rpc_swap_redeem(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (help || !params || json_size(params) < 2) {
        json_set_str(result,
            "swap_redeem \"swap_id\" \"secret\" [\"funding_txid\" vout]\n"
            "\nClaim a FUNDED HTLC on the ZCL chain by revealing the secret.\n"
            "Builds the redeem tx (claim branch), signs it with the wallet's\n"
            "recipient key, broadcasts it, and marks the swap redeemed.\n"
            "\nArguments:\n"
            "1. swap_id      (string) The swap contract id\n"
            "2. secret       (string) 64-char hex preimage of secret_hash\n"
            "3. funding_txid (string, optional) The tx that funded the P2SH\n"
            "4. vout         (number, optional) Output index of the funding\n"
            "\nZCL-chain only: the counterparty leg on BTC/LTC/DOGE must be\n"
            "settled by that chain's wallet (cross-chain broadcast is out of\n"
            "scope here).\n");
        return true;
    }

    const char *swap_id = json_get_str(json_at(params, 0));
    const char *secret_hex = json_get_str(json_at(params, 1));
    if (!swap_id || !swap_id[0]) {
        json_set_str(result, "Missing swap_id");
        return false;
    }
    if (!g_swap_ndb) {
        json_set_str(result, "Swap database unavailable");
        return false;
    }

    struct swap_contract swap;
    if (!db_swap_find(g_swap_ndb, swap_id, &swap)) {
        json_set_str(result, "Swap not found");
        return false;
    }
    if (!swap_settle_ready(&swap, result)) return false;

    if (swap.state == SWAP_REDEEMED || swap.state == SWAP_REFUNDED) {
        json_set_str(result, "Swap already settled");
        return false;
    }

    uint8_t secret[32];
    if (!secret_hex || !zcl_is_hex_string(secret_hex, 64) ||
        ParseHex(secret_hex, secret, 32) != 32) {
        json_set_str(result, "Invalid secret (expect 64-char hex)");
        return false;
    }

    /* Verify SHA256(secret) == secret_hash before touching the chain. */
    uint8_t check[32];
    struct sha256_ctx sc;
    sha256_init(&sc);
    sha256_write(&sc, secret, 32);
    sha256_finalize(&sc, check);
    if (memcmp(check, swap.secret_hash, 32) != 0) {
        json_set_str(result, "secret does not hash to this swap's secret_hash");
        return false;
    }

    struct outpoint funding;
    if (!swap_resolve_funding(params, 2, 3, &swap, &funding, result))
        return false; /* raw-return-ok: callee set the JSON error body */

    int64_t funding_value = 0;
    if (!swap_load_funding_value(&funding, &swap, &funding_value, result))
        return false; /* raw-return-ok: callee set the JSON error body */

    struct privkey key;
    struct pubkey pub;
    if (!swap_key_for_pkh(swap.redeem_script + HTLC_RECIPIENT_PKH_OFFSET,
                          &key, &pub, result))
        return false;

    int height = swap_current_height();
    const struct chain_params *cp = chain_params_get();

    struct swap_settle_ctx sctx;
    memset(&sctx, 0, sizeof(sctx));
    sctx.contract = swap.redeem_script;
    sctx.contract_len = swap.redeem_script_len;
    sctx.funding = funding;
    sctx.funding_value = funding_value;
    zcl_mutex_lock(&g_swap_wallet->cs);
    sctx.fee = g_swap_wallet->default_fee;
    zcl_mutex_unlock(&g_swap_wallet->cs);
    struct key_id my_kid = pubkey_get_id(&pub);
    script_for_p2pkh(&sctx.dest_spk, &my_kid);
    sctx.branch_id = consensus_current_epoch_branch_id(height + 1,
                                                       &cp->consensus);
    sctx.expiry_height = (uint32_t)(height + 20);

    struct transaction tx;
    struct zcl_result br =
        swap_settlement_build_redeem(&sctx, &key, &pub, secret, &tx);
    memory_cleanse(key.vch, 32);
    if (!br.ok) {
        char buf[300];
        snprintf(buf, sizeof(buf), "Failed to build redeem tx: %s", br.message);
        json_set_str(result, buf);
        return false;
    }

    char txid_hex[65];
    if (!swap_broadcast(&tx, txid_hex, result)) {
        transaction_free(&tx);
        return false;
    }
    transaction_free(&tx);

    /* Persist: FUNDED -> REDEEMED, record the funding outpoint + secret. */
    swap.state = SWAP_REDEEMED;
    memcpy(swap.secret, secret, 32);
    swap.has_secret = true;
    memcpy(swap.funding_txid, funding.hash.data, 32);
    swap.funding_vout = funding.n;
    if (!db_swap_save(g_swap_ndb, &swap))
        LOG_WARN("swap", "swap_redeem: broadcast OK but state persist failed "
                 "for %s", swap_id);

    json_set_object(result);
    json_push_kv_str(result, "status", "redeemed");
    json_push_kv_str(result, "swap_id", swap_id);
    json_push_kv_str(result, "txid", txid_hex);
    json_push_kv_int(result, "amount_zatoshi", funding_value);
    return true;
}

/* ── swap_refund ────────────────────────────────────────────────── */

static bool rpc_swap_refund(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (help || !params || json_size(params) < 1) {
        json_set_str(result,
            "swap_refund \"swap_id\" [\"funding_txid\" vout]\n"
            "\nReclaim a FUNDED HTLC on the ZCL chain after its CLTV locktime.\n"
            "Builds the refund tx (timeout branch), signs it with the wallet's\n"
            "refunder key, broadcasts it, and marks the swap refunded.\n"
            "\nRejected before the locktime height is reached (the error names\n"
            "the unlock height).\n"
            "\nArguments:\n"
            "1. swap_id      (string) The swap contract id\n"
            "2. funding_txid (string, optional) The tx that funded the P2SH\n"
            "3. vout         (number, optional) Output index of the funding\n"
            "\nZCL-chain only (cross-chain broadcast is out of scope here).\n");
        return true;
    }

    const char *swap_id = json_get_str(json_at(params, 0));
    if (!swap_id || !swap_id[0]) {
        json_set_str(result, "Missing swap_id");
        return false;
    }
    if (!g_swap_ndb) {
        json_set_str(result, "Swap database unavailable");
        return false;
    }

    struct swap_contract swap;
    if (!db_swap_find(g_swap_ndb, swap_id, &swap)) {
        json_set_str(result, "Swap not found");
        return false;
    }
    if (!swap_settle_ready(&swap, result)) return false;

    if (swap.state == SWAP_REDEEMED || swap.state == SWAP_REFUNDED) {
        json_set_str(result, "Swap already settled");
        return false;
    }

    /* CLTV precondition: the chain must have reached the locktime height. */
    int height = swap_current_height();
    if ((uint32_t)height < swap.locktime) {
        char buf[200];
        snprintf(buf, sizeof(buf),
            "Refund locktime not reached: unlocks at height %u, current height "
            "is %d. Wait %u more block(s).",
            swap.locktime, height, swap.locktime - (uint32_t)height);
        json_set_str(result, buf);
        return false;
    }

    struct outpoint funding;
    if (!swap_resolve_funding(params, 1, 2, &swap, &funding, result))
        return false; /* raw-return-ok: callee set the JSON error body */

    int64_t funding_value = 0;
    if (!swap_load_funding_value(&funding, &swap, &funding_value, result))
        return false; /* raw-return-ok: callee set the JSON error body */

    struct privkey key;
    struct pubkey pub;
    if (!swap_key_for_pkh(swap.redeem_script + HTLC_REFUNDER_PKH_OFFSET,
                          &key, &pub, result))
        return false;

    const struct chain_params *cp = chain_params_get();

    struct swap_settle_ctx sctx;
    memset(&sctx, 0, sizeof(sctx));
    sctx.contract = swap.redeem_script;
    sctx.contract_len = swap.redeem_script_len;
    sctx.funding = funding;
    sctx.funding_value = funding_value;
    zcl_mutex_lock(&g_swap_wallet->cs);
    sctx.fee = g_swap_wallet->default_fee;
    zcl_mutex_unlock(&g_swap_wallet->cs);
    struct key_id my_kid = pubkey_get_id(&pub);
    script_for_p2pkh(&sctx.dest_spk, &my_kid);
    sctx.branch_id = consensus_current_epoch_branch_id(height + 1,
                                                       &cp->consensus);
    sctx.expiry_height = (uint32_t)(height + 20);

    struct transaction tx;
    struct zcl_result br =
        swap_settlement_build_refund(&sctx, &key, &pub, swap.locktime, &tx);
    memory_cleanse(key.vch, 32);
    if (!br.ok) {
        char buf[300];
        snprintf(buf, sizeof(buf), "Failed to build refund tx: %s", br.message);
        json_set_str(result, buf);
        return false;
    }

    char txid_hex[65];
    if (!swap_broadcast(&tx, txid_hex, result)) {
        transaction_free(&tx);
        return false;
    }
    transaction_free(&tx);

    swap.state = SWAP_REFUNDED;
    memcpy(swap.funding_txid, funding.hash.data, 32);
    swap.funding_vout = funding.n;
    if (!db_swap_save(g_swap_ndb, &swap))
        LOG_WARN("swap", "swap_refund: broadcast OK but state persist failed "
                 "for %s", swap_id);

    json_set_object(result);
    json_push_kv_str(result, "status", "refunded");
    json_push_kv_str(result, "swap_id", swap_id);
    json_push_kv_str(result, "txid", txid_hex);
    json_push_kv_int(result, "amount_zatoshi", funding_value);
    return true;
}

/* ── swap_extractsecret ─────────────────────────────────────────── */

static bool rpc_swap_extractsecret(const struct json_value *params, bool help,
                                   struct json_value *result)
{
    if (help || !params || json_size(params) < 1) {
        json_set_str(result,
            "swap_extractsecret \"scriptsig_hex\"\n"
            "\nExtract the 32-byte secret preimage from a counterparty's HTLC\n"
            "redeem scriptSig (dcrdex format: <sig> <pubkey> <secret> OP_1\n"
            "<contract>). Use it to complete the other leg of the swap.\n"
            "\nArguments:\n"
            "1. scriptsig_hex (string) The redeem input's scriptSig, hex.\n");
        return true;
    }

    const char *hex = json_get_str(json_at(params, 0));
    if (!hex || !hex[0]) {
        json_set_str(result, "Missing scriptsig_hex");
        return false;
    }
    size_t hexlen = strlen(hex);
    if (hexlen % 2 != 0 || hexlen / 2 > MAX_SCRIPT_SIZE) {
        json_set_str(result, "Invalid scriptsig_hex length");
        return false;
    }
    uint8_t buf[MAX_SCRIPT_SIZE];
    size_t n = ParseHex(hex, buf, sizeof(buf));
    if (n == 0) {
        json_set_str(result, "Invalid scriptsig_hex");
        return false;
    }

    uint8_t secret[32];
    if (!htlc_extract_secret(buf, n, secret)) {
        json_set_str(result,
            "No 32-byte secret found in scriptSig (not an HTLC redeem input?)");
        return false;
    }

    uint8_t hash[32];
    struct sha256_ctx sc;
    sha256_init(&sc);
    sha256_write(&sc, secret, 32);
    sha256_finalize(&sc, hash);

    char shex[65], hhex[65];
    HexStr(secret, 32, false, shex, sizeof(shex));
    HexStr(hash, 32, false, hhex, sizeof(hhex));

    json_set_object(result);
    json_push_kv_str(result, "secret", shex);
    json_push_kv_str(result, "secret_hash", hhex);
    return true;
}

/* ── swap_status ────────────────────────────────────────────────── */

static bool rpc_swap_status(const struct json_value *params, bool help,
                            struct json_value *result)
{
    if (help || !params || json_size(params) < 1) {
        json_set_str(result,
            "swap_status \"swap_id\" [\"funding_txid\" vout]\n"
            "\nReport a swap's state, enriched with an on-demand funding check.\n"
            "If a funding outpoint is known (passed or stored) and confirmed in\n"
            "the UTXO set paying the contract P2SH, a PENDING swap transitions\n"
            "to FUNDED (persisted). Also reports the refund unlock height.\n"
            "\nNote: there is no scriptPubKey/address index, so funding is not\n"
            "auto-discovered — pass funding_txid + vout the first time.\n"
            "\nArguments:\n"
            "1. swap_id      (string) The swap contract id\n"
            "2. funding_txid (string, optional) The tx that funded the P2SH\n"
            "3. vout         (number, optional) Output index of the funding\n");
        return true;
    }

    const char *swap_id = json_get_str(json_at(params, 0));
    if (!swap_id || !swap_id[0]) {
        json_set_str(result, "Missing swap_id");
        return false;
    }
    if (!g_swap_ndb) {
        json_set_str(result, "Swap database unavailable");
        return false;
    }

    struct swap_contract swap;
    if (!db_swap_find(g_swap_ndb, swap_id, &swap)) {
        json_set_str(result, "Swap not found");
        return false;
    }

    /* On-demand funding check (ZCL chain, coins tip available). */
    bool funded_now = false;
    struct outpoint funding;
    outpoint_set_null(&funding);
    struct json_value err = {0};
    json_set_object(&err);
    if (swap.chain == SWAP_CHAIN_ZCL && g_swap_coins_tip &&
        swap_resolve_funding(params, 1, 2, &swap, &funding, &err)) {
        int64_t val = 0;
        if (swap_load_funding_value(&funding, &swap, &val, &err)) {
            funded_now = true;
            if (swap.state == SWAP_PENDING) {
                swap.state = SWAP_FUNDED;
                memcpy(swap.funding_txid, funding.hash.data, 32);
                swap.funding_vout = funding.n;
                if (!db_swap_save(g_swap_ndb, &swap))
                    LOG_WARN("swap", "swap_status: FUNDED persist failed for %s",
                             swap_id);
            }
        }
    }
    json_free(&err);

    swap_to_json(&swap, result);
    int height = swap_current_height();
    json_push_kv_int(result, "chain_height", height);
    json_push_kv_bool(result, "funding_confirmed", funded_now);
    json_push_kv_int(result, "refund_unlock_height", (int64_t)swap.locktime);
    json_push_kv_bool(result, "refund_available",
                      (uint32_t)height >= swap.locktime);
    return true;
}

/* ── swap_list ──────────────────────────────────────────────────── */

static bool rpc_swap_list(const struct json_value *params, bool help,
                          struct json_value *result)
{
    if (help) {
        json_set_str(result,
            "swap_list [state]\n"
            "\nList atomic swap contracts.\n"
            "\nArguments:\n"
            "1. state (string, optional) Filter: pending, funded, redeemed, refunded\n");
        return true;
    }

    int state_filter = -1;
    if (params && json_size(params) > 0) {
        const char *s = json_get_str(json_at(params, 0));
        if (s) {
            if (strcmp(s, "pending") == 0) state_filter = SWAP_PENDING;
            else if (strcmp(s, "funded") == 0) state_filter = SWAP_FUNDED;
            else if (strcmp(s, "redeemed") == 0) state_filter = SWAP_REDEEMED;
            else if (strcmp(s, "refunded") == 0) state_filter = SWAP_REFUNDED;
        }
    }

    /* An OBJECT, not a bare array: the native command bridge rejects a
     * non-object body (tools/command/native_command.c), which is why
     * `z23 app swap list` answered BAD_TOOL_BODY for its whole
     * existence. The envelope is the one this command already declared as
     * its output schema, and matches rpc_name_list / zcl.names.index.v1. */
    struct json_value swaps_json;
    json_init(&swaps_json);
    json_set_array(&swaps_json);

    struct swap_contract swaps[50];
    int count = g_swap_ndb
        ? db_swap_list(g_swap_ndb, swaps, 50, state_filter)
        : 0;

    for (int i = 0; i < count; i++) {
        struct json_value e = {0};
        swap_to_json(&swaps[i], &e);
        json_push_back(&swaps_json, &e);
        json_free(&e);
    }

    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.app_swap_index.v1");
    json_push_kv(result, "swaps", &swaps_json);
    json_push_kv_int(result, "count", count);
    json_free(&swaps_json);
    return true;
}

/* ── REST API ───────────────────────────────────────────────────── */

bool api_swap_list(struct json_value *result)
{
    return rpc_swap_list(NULL, false, result);
}

bool api_swap_chains(struct json_value *result)
{
    return rpc_swap_chains(NULL, false, result);
}

/* ── Registration ───────────────────────────────────────────────── */

void register_swap_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "swap", "swap_chains",       rpc_swap_chains,       true },
        { "swap", "swap_initiate",     rpc_swap_initiate,     true },
        { "swap", "swap_participate",  rpc_swap_participate,  true },
        { "swap", "swap_redeem",       rpc_swap_redeem,       true },
        { "swap", "swap_refund",       rpc_swap_refund,       true },
        { "swap", "swap_status",       rpc_swap_status,       true },
        { "swap", "swap_extractsecret", rpc_swap_extractsecret, true },
        { "swap", "swap_list",         rpc_swap_list,         true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
