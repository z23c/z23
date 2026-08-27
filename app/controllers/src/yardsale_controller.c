/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the Yardsale MVC controller implementation — see
 * controllers/yardsale_controller.h for the design framing. Transports
 * (P2P gossip handlers, the /yardsale web mount) call in here; the Stage-3
 * ceremony core (lib/zswap) does the cryptography. All state is static and
 * bounded; one mutex, brief critical sections, crypto OUTSIDE the lock. */

#include "controllers/yardsale_controller.h"

#include "chain/chainparams.h"
#include "consensus/upgrades.h"
#include "controllers/transaction_controller_internal.h"
#include "crypto/sha3.h"
#include "net/connman.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include "validation/accept_to_mempool.h"
#include "validation/chainstate.h"
#include "zslp/slp.h"
#include "zswap/zswap_yardsale.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

/* ── Error names ────────────────────────────────────────────────── */

const char *yardsale_error_string(int error)
{
    if (error >= YARDSALE_ERR_CEREMONY_BASE)
        return zswap_ceremony_error_string(
            (enum zswap_ceremony_error)(error - YARDSALE_ERR_CEREMONY_BASE));
    switch ((enum yardsale_error)error) {
    case YARDSALE_OK: return "ok";
    case YARDSALE_ERR_NULL: return "null argument";
    case YARDSALE_ERR_AD_UNKNOWN: return "no remembered sign with that root";
    case YARDSALE_ERR_NOT_CONFIGURED: return "yardsale port not configured";
    case YARDSALE_ERR_PENDING_FULL: return "pending-buy table full";
    case YARDSALE_ERR_NO_PENDING: return "no pending buy for that sign";
    case YARDSALE_ERR_KEY_COUNT: return "one privkey per buyer input required";
    case YARDSALE_ERR_CEREMONY_BASE: break; /* handled above */
    }
    return "unknown yardsale error";
}

/* ── Ports ──────────────────────────────────────────────────────── */

static yardsale_broadcast_fn g_broadcast;
static void *g_broadcast_ctx;
static yardsale_flood_fn g_flood;
static void *g_flood_ctx;
static yardsale_branch_id_fn g_branch_id;
static void *g_branch_id_ctx;
static yardsale_prevout_fetch_fn g_prevout_fetch;
static void *g_prevout_fetch_ctx;

void yardsale_ceremony_set_broadcast(yardsale_broadcast_fn fn, void *ctx)
{
    g_broadcast = fn;
    g_broadcast_ctx = ctx;
}

void yardsale_ceremony_set_prevout_fetch(yardsale_prevout_fetch_fn fn,
                                         void *ctx)
{
    g_prevout_fetch = fn;
    g_prevout_fetch_ctx = ctx;
}

void yardsale_ceremony_set_flood(yardsale_flood_fn fn, void *ctx)
{
    g_flood = fn;
    g_flood_ctx = ctx;
}

void yardsale_ceremony_set_branch_id_source(yardsale_branch_id_fn fn,
                                            void *ctx)
{
    g_branch_id = fn;
    g_branch_id_ctx = ctx;
}

/* The default branch id: the consensus branch at (active tip + 1), read
 * through the same rawtx context signrawtransaction uses. */
static uint32_t yardsale_branch_id_now(void)
{
    if (g_branch_id)
        return g_branch_id(g_branch_id_ctx);
    struct rawtx_context *ctx = rawtx_ctx();
    int tip = ctx->main_state
        ? active_chain_height(&ctx->main_state->chain_active) : 0;
    return consensus_current_epoch_branch_id(
        tip + 1, &chain_params_get()->consensus);
}

bool yardsale_broadcast_default(const struct transaction *tx, void *ctx_)
{
    (void)ctx_;
    if (!tx)
        LOG_FAIL("yardsale", "broadcast_default: NULL tx");
    struct rawtx_context *ctx = rawtx_ctx();
    if (!ctx->mempool) {
        /* A named, logged no-op — the completed swap is dropped HERE, on
         * the record, never silently. */
        LOG_WARN("yardsale", "broadcast: mempool context unwired — the "
                 "signed swap transaction was not submitted");
        return false;
    }
    struct transaction copy;
    if (!transaction_copy(&copy, tx))
        LOG_FAIL("yardsale", "broadcast_default: transaction copy failed");
    transaction_compute_hash(&copy);
    struct uint256 hash = copy.hash;
    enum mempool_accept_result r = accept_to_mempool(
        ctx->mempool, ctx->coins_tip, ctx->main_state,
        chain_params_get(), &copy);
    if (r != MEMPOOL_ACCEPT_OK && r != MEMPOOL_ACCEPT_DUPLICATE) {
        LOG_WARN("yardsale", "broadcast: mempool rejected the completed "
                 "swap (result %d) — settlement did not happen", (int)r);
        transaction_free(&copy);
        return false;
    }
    if (ctx->connman)
        connman_relay_transaction(ctx->connman, &hash);
    transaction_free(&copy);
    return true;
}

/* ── Seller profile ─────────────────────────────────────────────── */

static pthread_mutex_t g_yardsale_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool g_profile_configured;
static struct zswap_seller_accept g_profile_terms;
static struct privkey g_profile_key;

void yardsale_seller_profile_configure(
    const struct zswap_seller_accept *terms, const struct privkey *key)
{
    if (!terms || !key || !key->fValid) {
        LOG_WARN("yardsale", "seller_profile_configure: bad terms/key — "
                 "profile left unchanged");
        return;
    }
    pthread_mutex_lock(&g_yardsale_mutex);
    g_profile_terms = *terms;
    g_profile_key = *key;
    g_profile_configured = true;
    pthread_mutex_unlock(&g_yardsale_mutex);
}

void yardsale_seller_profile_clear(void)
{
    pthread_mutex_lock(&g_yardsale_mutex);
    memory_cleanse(&g_profile_key, sizeof(g_profile_key));
    memset(&g_profile_terms, 0, sizeof(g_profile_terms));
    g_profile_configured = false;
    pthread_mutex_unlock(&g_yardsale_mutex);
}

bool yardsale_seller_profile_configured(void)
{
    pthread_mutex_lock(&g_yardsale_mutex);
    bool configured = g_profile_configured;
    pthread_mutex_unlock(&g_yardsale_mutex);
    return configured;
}

bool yardsale_seller_profile_snapshot(struct zswap_seller_accept *terms_out)
{
    if (!terms_out)
        LOG_FAIL("yardsale", "seller_profile_snapshot: NULL out");
    memset(terms_out, 0, sizeof(*terms_out));
    pthread_mutex_lock(&g_yardsale_mutex);
    bool configured = g_profile_configured;
    if (configured)
        *terms_out = g_profile_terms;
    pthread_mutex_unlock(&g_yardsale_mutex);
    return configured;
}

/* ── Gossip hygiene: dedup ring + per-peer clamp ─────────────────── */

/* Every distinct ceremony wire is forwarded at most once per node — the
 * zswapquote dedup-on-root idiom applied to wire content (an accept's root
 * is not precomputed like a quote's, so the ring keys the SHA3-256 of the
 * whole wire). */
#define YARDSALE_SEEN_RING 128
static uint8_t g_seen[YARDSALE_SEEN_RING][32];
static size_t g_seen_pos;

#define YARDSALE_PEER_SLOTS 64
#define YARDSALE_PEER_WINDOW_SECS 10
#define YARDSALE_PEER_WINDOW_MAX_WIRES 8
struct yardsale_peer_window {
    bool used;
    int64_t peer_id;
    int64_t window_start_unix;
    uint64_t wires_in_window;
};
static struct yardsale_peer_window g_peers[YARDSALE_PEER_SLOTS];

static void wire_hash(const uint8_t *wire, size_t wire_len, uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, wire, wire_len);
    sha3_256_finalize(&ctx, out);
}

/* Caller holds g_yardsale_mutex. */
static bool seen_lookup_locked(const uint8_t hash[32])
{
    for (size_t i = 0; i < YARDSALE_SEEN_RING; i++) {
        if (memcmp(g_seen[i], hash, 32) == 0)
            return true;
    }
    return false;
}

/* Caller holds g_yardsale_mutex. */
static void seen_mark_locked(const uint8_t hash[32])
{
    memcpy(g_seen[g_seen_pos], hash, 32);
    g_seen_pos = (g_seen_pos + 1) % YARDSALE_SEEN_RING;
}

/* True when the peer may offer another fresh wire this window. Caller
 * holds g_yardsale_mutex. */
static bool peer_clamp_admit_locked(int64_t peer_id, int64_t now_unix)
{
    struct yardsale_peer_window *slot = NULL;
    struct yardsale_peer_window *oldest = &g_peers[0];
    for (size_t i = 0; i < YARDSALE_PEER_SLOTS; i++) {
        if (!g_peers[i].used) {
            slot = &g_peers[i];
            break;
        }
        if (g_peers[i].peer_id == peer_id) {
            slot = &g_peers[i];
            break;
        }
        if (g_peers[i].window_start_unix < oldest->window_start_unix)
            oldest = &g_peers[i];
    }
    if (!slot)
        slot = oldest; /* table full: evict the stalest window */
    if (slot->peer_id != peer_id ||
        now_unix - slot->window_start_unix >= YARDSALE_PEER_WINDOW_SECS) {
        slot->used = true;
        slot->peer_id = peer_id;
        slot->window_start_unix = now_unix;
        slot->wires_in_window = 0;
    }
    if (slot->wires_in_window >= YARDSALE_PEER_WINDOW_MAX_WIRES)
        return false;
    slot->wires_in_window++;
    return true;
}

/* ── Pending buys ───────────────────────────────────────────────── */

#define YARDSALE_PENDING_MAX 8
struct yardsale_pending_buy {
    bool used;
    uint8_t quote_root[32];
    struct zswap_quote_v1 ad;
    struct zswap_accept_v1 accept;
    struct privkey input_keys[ZSWAP_MAX_BUYER_INPUTS];
    int64_t deadline_unix;
};
static struct yardsale_pending_buy g_pending[YARDSALE_PENDING_MAX];

static void pending_clear_locked(struct yardsale_pending_buy *p)
{
    memory_cleanse(p->input_keys, sizeof(p->input_keys));
    memset(p, 0, sizeof(*p));
}

int yardsale_pending_count(int64_t now_unix)
{
    int count = 0;
    pthread_mutex_lock(&g_yardsale_mutex);
    for (size_t i = 0; i < YARDSALE_PENDING_MAX; i++) {
        if (!g_pending[i].used)
            continue;
        if (g_pending[i].deadline_unix <= now_unix) {
            /* A stale ceremony dies with the ad — and takes the retained
             * buyer keys with it. */
            pending_clear_locked(&g_pending[i]);
            continue;
        }
        count++;
    }
    pthread_mutex_unlock(&g_yardsale_mutex);
    return count;
}

/* ── Seller side ─────────────────────────────────────────────────── */

enum yardsale_error yardsale_seller_handle_accept_wire(
    const uint8_t *wire, size_t wire_len, int64_t now_unix,
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    if (!wire || wire_len == 0 || !out || !out_len)
        LOG_RETURN(YARDSALE_ERR_NULL, "yardsale",
                   "seller_handle_accept_wire: NULL argument");

    struct zswap_accept_v1 accept;
    enum zswap_ceremony_error e =
        zswap_accept_decode(wire, wire_len, &accept);
    if (e != ZSWAP_CEREMONY_OK)
        return (enum yardsale_error)(YARDSALE_ERR_CEREMONY_BASE + e);

    /* The accept names a sign; we answer only signs we remember. */
    struct zswap_yardsale_ad ad_entry;
    if (!zswap_yardsale_find(accept.quote_root, &ad_entry))
        return YARDSALE_ERR_AD_UNKNOWN;

    struct zswap_seller_accept terms;
    struct privkey key;
    pthread_mutex_lock(&g_yardsale_mutex);
    bool configured = g_profile_configured;
    if (configured) {
        terms = g_profile_terms;
        key = g_profile_key;
    }
    pthread_mutex_unlock(&g_yardsale_mutex);
    if (!configured)
        return YARDSALE_ERR_NOT_CONFIGURED;

    /* The one function that can never shortchange us: it re-assembles the
     * transaction, verifies it pays the exact ad terms, and only then
     * signs — all inside the Stage-3 core. */
    struct zswap_partial_v1 partial;
    e = zswap_ceremony_seller_build_partial(
        &ad_entry.quote, &accept, &terms, &key, yardsale_branch_id_now(),
        now_unix, &partial, NULL);
    memory_cleanse(&key, sizeof(key));
    if (e != ZSWAP_CEREMONY_OK)
        return (enum yardsale_error)(YARDSALE_ERR_CEREMONY_BASE + e);

    e = zswap_partial_encode(&partial, out, out_cap, out_len);
    if (e != ZSWAP_CEREMONY_OK)
        return (enum yardsale_error)(YARDSALE_ERR_CEREMONY_BASE + e);
    return YARDSALE_OK;
}

/* ── Buyer side ──────────────────────────────────────────────────── */

enum yardsale_error yardsale_buyer_begin(
    const struct zswap_quote_v1 *ad,
    const struct zswap_buyer_accept *buyer,
    const struct privkey *input_keys, size_t num_keys,
    int64_t now_unix,
    uint8_t *wire_out, size_t wire_cap, size_t *wire_len)
{
    if (wire_len)
        *wire_len = 0;
    if (!ad || !buyer || !input_keys || !wire_out || !wire_len)
        LOG_RETURN(YARDSALE_ERR_NULL, "yardsale",
                   "buyer_begin: NULL argument");
    if (num_keys != buyer->num_inputs)
        return YARDSALE_ERR_KEY_COUNT;

    enum zswap_quote_error qe = zswap_quote_validate_at(ad, now_unix);
    if (qe == ZSWAP_QUOTE_ERR_EXPIRED || qe == ZSWAP_QUOTE_ERR_NOT_YET_VALID)
        return (enum yardsale_error)(
            YARDSALE_ERR_CEREMONY_BASE + ZSWAP_CEREMONY_ERR_EXPIRED);
    if (qe != ZSWAP_QUOTE_OK)
        return (enum yardsale_error)(
            YARDSALE_ERR_CEREMONY_BASE + ZSWAP_CEREMONY_ERR_AD);
    if (zswap_buyer_accept_validate(buyer) != ZSWAP_ASSEMBLY_OK)
        return (enum yardsale_error)(
            YARDSALE_ERR_CEREMONY_BASE + ZSWAP_CEREMONY_ERR_ACCEPT);

    struct zswap_accept_v1 accept;
    memset(&accept, 0, sizeof(accept));
    accept.schema_version = ZSWAP_ACCEPT_VERSION;
    if (zswap_quote_root(ad, accept.quote_root) != ZSWAP_QUOTE_OK)
        return (enum yardsale_error)(
            YARDSALE_ERR_CEREMONY_BASE + ZSWAP_CEREMONY_ERR_ROOT_ZERO);
    accept.buyer = *buyer;

    size_t len = 0;
    enum zswap_ceremony_error e =
        zswap_accept_encode(&accept, wire_out, wire_cap, &len);
    if (e != ZSWAP_CEREMONY_OK)
        return (enum yardsale_error)(YARDSALE_ERR_CEREMONY_BASE + e);

    if (!g_flood) {
        /* Registering a buy we cannot announce would retain buyer keys
         * for a ceremony that can never start — refuse loudly instead. */
        LOG_RETURN(YARDSALE_ERR_NOT_CONFIGURED, "yardsale",
                   "buyer_begin: outbound gossip port unwired");
    }

    pthread_mutex_lock(&g_yardsale_mutex);
    struct yardsale_pending_buy *slot = NULL;
    for (size_t i = 0; i < YARDSALE_PENDING_MAX; i++) {
        if (!g_pending[i].used) {
            slot = &g_pending[i];
            break;
        }
        if (memcmp(g_pending[i].quote_root, accept.quote_root, 32) == 0) {
            pending_clear_locked(&g_pending[i]); /* re-buy replaces */
            slot = &g_pending[i];
            break;
        }
        if (g_pending[i].deadline_unix <= now_unix) {
            pending_clear_locked(&g_pending[i]);
            slot = &g_pending[i];
            break;
        }
    }
    if (!slot) {
        pthread_mutex_unlock(&g_yardsale_mutex);
        return YARDSALE_ERR_PENDING_FULL;
    }
    slot->used = true;
    memcpy(slot->quote_root, accept.quote_root, 32);
    slot->ad = *ad;
    slot->accept = accept;
    for (size_t i = 0; i < num_keys; i++)
        slot->input_keys[i] = input_keys[i];
    slot->deadline_unix = ad->expires_unix;
    pthread_mutex_unlock(&g_yardsale_mutex);

    g_flood(ZSWAP_MSG_ACCEPT, wire_out, len, g_flood_ctx);
    *wire_len = len;
    return YARDSALE_OK;
}

/* ── P2P ingress ─────────────────────────────────────────────────── */

int yardsale_ceremony_accept_ingest(const uint8_t *wire, size_t wire_len,
                                    int64_t peer_id, int64_t now_unix,
                                    uint8_t *respond, size_t respond_cap,
                                    size_t *respond_len)
{
    if (respond_len)
        *respond_len = 0;
    if (!wire || wire_len == 0 || wire_len > ZSWAP_ACCEPT_WIRE_MAX_BYTES)
        return ZSWAP_CEREMONY_WIRE_DROP;

    uint8_t hash[32];
    wire_hash(wire, wire_len, hash);

    pthread_mutex_lock(&g_yardsale_mutex);
    bool dup = seen_lookup_locked(hash);
    bool admitted = !dup && peer_clamp_admit_locked(peer_id, now_unix);
    pthread_mutex_unlock(&g_yardsale_mutex);
    if (dup || !admitted)
        return ZSWAP_CEREMONY_WIRE_DROP;

    /* Decode + ad lookup outside the lock. An undecodable wire is dropped
     * and never relayed (drop-and-ignore, Bitcoin Core parity). */
    struct zswap_accept_v1 accept;
    if (zswap_accept_decode(wire, wire_len, &accept) != ZSWAP_CEREMONY_OK)
        return ZSWAP_CEREMONY_WIRE_DROP;

    struct zswap_yardsale_ad ad_entry;
    bool known = zswap_yardsale_find(accept.quote_root, &ad_entry);
    bool answerable = known && yardsale_seller_profile_configured();

    pthread_mutex_lock(&g_yardsale_mutex);
    seen_mark_locked(hash);
    pthread_mutex_unlock(&g_yardsale_mutex);

    if (!answerable) {
        /* Intermediary (or a seller with no profile): relay once. A
         * seller only ever does real work — assembly, two ECDSA ops — on
         * an accept naming a sign he actually pinned up. */
        return ZSWAP_CEREMONY_WIRE_RELAY;
    }

    size_t len = 0;
    enum yardsale_error e = yardsale_seller_handle_accept_wire(
        wire, wire_len, now_unix, respond, respond_cap, &len);
    if (e != YARDSALE_OK || len == 0) {
        LOG_WARN("yardsale", "zswapaccept for known sign dropped: %s",
                 yardsale_error_string(e));
        return ZSWAP_CEREMONY_WIRE_DROP;
    }
    if (respond_len)
        *respond_len = len;
    return ZSWAP_CEREMONY_WIRE_RESPOND;
}

int yardsale_ceremony_partial_ingest(const uint8_t *wire, size_t wire_len,
                                     int64_t peer_id, int64_t now_unix)
{
    if (!wire || wire_len == 0 || wire_len > ZSWAP_PARTIAL_WIRE_MAX_BYTES)
        return ZSWAP_CEREMONY_WIRE_DROP;

    uint8_t hash[32];
    wire_hash(wire, wire_len, hash);

    pthread_mutex_lock(&g_yardsale_mutex);
    bool dup = seen_lookup_locked(hash);
    bool admitted = !dup && peer_clamp_admit_locked(peer_id, now_unix);
    pthread_mutex_unlock(&g_yardsale_mutex);
    if (dup || !admitted)
        return ZSWAP_CEREMONY_WIRE_DROP;

    struct zswap_partial_v1 partial;
    if (zswap_partial_decode(wire, wire_len, &partial) != ZSWAP_CEREMONY_OK)
        return ZSWAP_CEREMONY_WIRE_DROP;

    /* Consume the pending buy under the lock (keys cleansed out of the
     * table immediately); the expensive verify/sign runs outside it on a
     * private copy. A second identical partial then finds no pending buy
     * and is relayed — it can never double-broadcast. */
    struct yardsale_pending_buy buy;
    bool found = false;
    pthread_mutex_lock(&g_yardsale_mutex);
    for (size_t i = 0; i < YARDSALE_PENDING_MAX; i++) {
        if (g_pending[i].used &&
            memcmp(g_pending[i].quote_root, partial.quote_root, 32) == 0) {
            buy = g_pending[i];
            pending_clear_locked(&g_pending[i]);
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_yardsale_mutex);

    pthread_mutex_lock(&g_yardsale_mutex);
    seen_mark_locked(hash);
    pthread_mutex_unlock(&g_yardsale_mutex);

    if (!found)
        return ZSWAP_CEREMONY_WIRE_RELAY; /* someone else's ceremony */

    struct transaction tx;
    memset(&tx, 0, sizeof(tx));
    enum zswap_ceremony_error e = zswap_ceremony_buyer_verify_partial(
        &buy.ad, &buy.accept, &partial, yardsale_branch_id_now(),
        now_unix, &tx);
    if (e != ZSWAP_CEREMONY_OK) {
        LOG_WARN("yardsale", "zswappartial rejected (%s) — the buy is off; "
                 "no transaction exists and nothing was lost",
                 zswap_ceremony_error_string(e));
        memory_cleanse(buy.input_keys, sizeof(buy.input_keys));
        return ZSWAP_CEREMONY_WIRE_DROP;
    }

    /* The ad's token leg was a CLAIM: now that the cryptography holds,
     * check the chain content it named — the buyer-side half of the duty
     * zswap_assembly.h states ("classify the seller's token input via
     * slp_classify_tx_output before accepting"), mirroring the seller
     * arm's own recheck at plan time. Fail-closed: an unwired port
     * refuses the ceremony entirely — a buyer must never sign an input
     * nobody chain-checked. */
    if (!g_prevout_fetch) {
        LOG_WARN("yardsale", "prevout port unwired — refusing to sign a "
                 "swap whose token input was never chain-checked");
        memory_cleanse(buy.input_keys, sizeof(buy.input_keys));
        transaction_free(&tx);
        return ZSWAP_CEREMONY_WIRE_DROP;
    }
    struct transaction token_tx;
    memset(&token_tx, 0, sizeof(token_tx));
    bool token_ok = g_prevout_fetch(g_prevout_fetch_ctx,
                                    partial.seller.token_input.txid,
                                    &token_tx) &&
        partial.seller.token_input.vout < token_tx.num_vout;
    const struct tx_out *claimed =
        token_ok ? &token_tx.vout[partial.seller.token_input.vout] : NULL;
    struct slp_output_metadata meta;
    memset(&meta, 0, sizeof(meta));
    token_ok = token_ok && claimed &&
        slp_classify_tx_output(&token_tx,
                               partial.seller.token_input.vout, &meta) &&
        meta.role == SLP_OUTPUT_TOKEN &&
        memcmp(meta.token_id, buy.ad.token_id, 32) == 0 &&
        meta.amount == buy.ad.token_amount &&
        claimed->value == partial.seller.token_input.value_sats &&
        claimed->script_pub_key.size ==
            partial.seller.token_input.script_len &&
        memcmp(claimed->script_pub_key.data,
               partial.seller.token_input.script_pub_key,
               partial.seller.token_input.script_len) == 0;
    transaction_free(&token_tx);
    if (!token_ok) {
        LOG_WARN("yardsale", "seller token input is not the confirmed "
                 "holder of the ad's exact token — the swap names money "
                 "this chain does not hold; the buy is off");
        memory_cleanse(buy.input_keys, sizeof(buy.input_keys));
        transaction_free(&tx);
        return ZSWAP_CEREMONY_WIRE_DROP;
    }

    /* Sign every buyer input: the vin holds seller inputs first, then the
     * buyer's in canonical sorted order — map each vin back to its accept
     * entry (and its key) by outpoint, never by position. */
    bool sign_ok = true;
    const struct zswap_buyer_accept *ba = &buy.accept.buyer;
    for (size_t vi = 0; vi < tx.num_vin && sign_ok; vi++) {
        for (size_t j = 0; j < ba->num_inputs; j++) {
            if (memcmp(tx.vin[vi].prevout.hash.data, ba->inputs[j].txid,
                       32) != 0 ||
                tx.vin[vi].prevout.n != ba->inputs[j].vout)
                continue;
            e = zswap_ceremony_sign_input_p2pkh(
                &tx, vi, ba->inputs[j].script_pub_key,
                ba->inputs[j].script_len, ba->inputs[j].value_sats,
                yardsale_branch_id_now(), &buy.input_keys[j]);
            if (e != ZSWAP_CEREMONY_OK) {
                LOG_WARN("yardsale", "buyer input %zu signing failed: %s",
                         vi, zswap_ceremony_error_string(e));
                sign_ok = false;
            }
            break;
        }
    }
    memory_cleanse(buy.input_keys, sizeof(buy.input_keys));

    if (sign_ok && !zswap_ceremony_all_inputs_signed(&tx))
        sign_ok = false;

    if (!sign_ok) {
        transaction_free(&tx);
        return ZSWAP_CEREMONY_WIRE_DROP;
    }

    yardsale_broadcast_fn broadcast =
        g_broadcast ? g_broadcast : yardsale_broadcast_default;
    if (!broadcast(&tx, g_broadcast_ctx))
        LOG_WARN("yardsale", "completed swap was not broadcast (named "
                 "above) — the ceremony produced a transaction the "
                 "network never saw");
    transaction_free(&tx);
    return ZSWAP_CEREMONY_WIRE_DROP;
}

void yardsale_ceremony_reset(void)
{
    pthread_mutex_lock(&g_yardsale_mutex);
    for (size_t i = 0; i < YARDSALE_PENDING_MAX; i++) {
        if (g_pending[i].used)
            pending_clear_locked(&g_pending[i]);
    }
    memset(g_seen, 0, sizeof(g_seen));
    g_seen_pos = 0;
    memset(g_peers, 0, sizeof(g_peers));
    pthread_mutex_unlock(&g_yardsale_mutex);
}
