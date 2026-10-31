/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private broadcast of the wallet's own sends: a send is validated into a
 * private pool, never enters the main mempool, and is pushed once, after a
 * random 2 to 20 s delay, to one outbound onion peer. Nothing reaches a
 * clearnet peer. Peers are real p2p_node objects with real connman state; the
 * bytes each one received are read back from its send queue. The relay clock
 * and RNG are injected; every other component is production code. */

#include "test/test_core.h"
#include "test/test_connman_addnode_fallback_priv.h"
#include "test/wallet_private_relay_probe.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "config/boot_internal.h"
#include "config/boot_msg_callbacks.h"
#include "consensus/upgrades.h"
#include "controllers/wallet_helpers.h"
#include "controllers/wallet_private_broadcast.h"
#include "core/serialize.h"
#include "crypto/random_secret.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "net/connman.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/netaddr.h"
#include "net/onion_v3_address.h"
#include "net/protocol.h"
#include "primitives/transaction.h"
#include "sim/simnet.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "script/standard.h"
#include "services/wallet_private_relay.h"
#include "util/safe_alloc.h"
#include "validation/accept_to_mempool.h"
#include "validation/main_state.h"
#include "validation/sighash.h"
#include "validation/txmempool.h"
#include "wallet/wallet.h"

#include <stdio.h>
#include <string.h>

static int64_t wprt_now;
static int64_t wprt_clock(void) { return wprt_now; }

/* Deterministic RNG: byte = fill, or the real CSPRNG when fill < 0. */
static int wprt_fill = -1;
static bool wprt_rng(uint8_t *out, size_t n)
{
    if (wprt_fill < 0)
        return zcl_random_secret_bytes(out, n, "wprt");
    memset(out, wprt_fill, n);
    return true;
}

struct wprt_fx {
    struct main_state ms;
    const struct chain_params *params;
    struct privkey key;
    struct pubkey pub;
    struct key_id kid;
    struct script spk;
    struct coins_view null_view;
    struct coins_view_cache coins;
    struct tx_mempool main_pool;
    struct connman cm;
    struct wallet *wallet;
    char dir[256];
    struct p2p_node *peers[16];
    size_t num_peers;
    uint8_t next_seed;
    struct p2p_node *doomed;
};

static struct wprt_fx *wprt_cur;

enum wprt_kind { WPRT_ONION_OUT, WPRT_ONION_IN, WPRT_CLEAR_OUT,
                 WPRT_ONION_DISCONNECT, WPRT_ONION_NO_RELAY };

static bool wprt_open(struct wprt_fx *f, enum wpr_mode mode)
{
    memset(f, 0, sizeof(*f));
    f->params = chain_params_get();
    main_state_init(&f->ms);
    privkey_make_new(&f->key, true);
    privkey_get_pubkey(&f->key, &f->pub);
    f->kid = pubkey_get_id(&f->pub);
    script_for_p2pkh(&f->spk, &f->kid);
    coins_view_cache_init(&f->coins, &f->null_view);
    tx_mempool_init(&f->main_pool, 0);
    f->wallet = zcl_calloc(1, sizeof(*f->wallet), "wprt_wallet");
    if (!f->wallet || !test_mkdtemp(f->dir, sizeof(f->dir), "wprt"))
        return false;
    wallet_init(f->wallet);
    struct node_signals sigs;
    memset(&sigs, 0, sizeof(sigs));
    if (!connman_init(&f->cm, f->params, &sigs))
        return false;
    f->cm.manager.nodes = zcl_calloc(16, sizeof(*f->cm.manager.nodes), "wprt_nodes");
    if (!f->cm.manager.nodes)
        return false;
    f->cm.manager.nodes_cap = 16;
    struct wpr *r = wpr_global();
    wpr_free(r);
    wpr_init(r);
    r->now_ms = wprt_clock;
    r->random_bytes = wprt_rng;
    wprt_cur = f;
    wprt_now = 1000000;
    wprt_fill = -1;
    struct wpr_env env = {
        .wallet = f->wallet, .connman = &f->cm, .coins_tip = &f->coins,
        .main_state = &f->ms, .params = f->params, .datadir = f->dir,
    };
    wpr_configure(r, mode, &env);
    wallet_rpc_context_set_base(f->wallet, &f->ms, f->dir, NULL,
                                &f->main_pool, &f->cm);
    wallet_rpc_context_set_coins_tip(&f->coins);
    return true;
}

static void wprt_close(struct wprt_fx *f)
{
    wprt_cur = NULL;
    wpr_free(wpr_global());
    wpr_init(wpr_global());
    connman_free(&f->cm);
    coins_view_cache_free(&f->coins);
    tx_mempool_free(&f->main_pool);
    wallet_free(f->wallet);
    free(f->wallet);
    main_state_free(&f->ms);
    test_rm_rf(f->dir);
}

static struct p2p_node *wprt_add_peer(struct wprt_fx *f, enum wprt_kind kind)
{
    struct net_address a;
    bool inbound = kind == WPRT_ONION_IN;
    if (kind == WPRT_CLEAR_OUT) {
        test_set_ipv4(&a, 93, 184, 216, (uint8_t)(34 + f->next_seed++), 8033);
    } else if (kind == WPRT_ONION_IN) {
        test_set_ipv4(&a, 127, 0, 0, 1, (uint16_t)(40000 + f->next_seed++));
    } else {
        uint8_t pub[32];
        char host[ONION_V3_ADDRESS_LEN + 1];
        memset(pub, 0x40 + f->next_seed++, sizeof(pub));
        net_address_init(&a);
        a.svc.port = 8033;
        if (!onion_v3_address_from_pubkey(pub, host) ||
            !net_addr_from_onion(host, &a.svc.addr))
            return NULL;
    }
    struct p2p_node *n = p2p_node_create(&f->cm.manager, ZCL_INVALID_SOCKET,
                                         &a, "wprt-peer", inbound);
    if (!n)
        return NULL;
    n->state = PEER_HANDSHAKE_COMPLETE;
    n->relay_txes = kind != WPRT_ONION_NO_RELAY;
    if (kind == WPRT_ONION_DISCONNECT) {
        n->disconnect = true;
        f->doomed = n;
    }
    f->cm.manager.nodes[f->cm.manager.num_nodes++] = n;
    f->peers[f->num_peers++] = n;
    return n;
}

/* Count messages of one command in a peer's send queue. */
static size_t wprt_count(const struct p2p_node *n, const char *cmd)
{
    size_t total = 0, count = 0;
    /* Announcements wait in the inventory queue until the trickle runs. */
    if (strcmp(cmd, "inv") == 0)
        count = n->inventory_to_send_count;
    for (const struct send_segment *s = n->send_head; s; s = s->next)
        total += s->size;
    uint8_t *buf = zcl_malloc(total ? total : 1, "wprt_flat");
    if (!buf)
        return 0;
    size_t off = 0;
    for (const struct send_segment *s = n->send_head; s; s = s->next) {
        memcpy(buf + off, s->data, s->size);
        off += s->size;
    }
    for (size_t p = 0; p + MSG_HEADER_SIZE <= total;) {
        uint32_t len = (uint32_t)buf[p + 16] | (uint32_t)buf[p + 17] << 8 |
                       (uint32_t)buf[p + 18] << 16 | (uint32_t)buf[p + 19] << 24;
        if (strncmp((const char *)buf + p + 4, cmd, 12) == 0)
            count++;
        p += MSG_HEADER_SIZE + len;
    }
    free(buf);
    return count;
}

static size_t wprt_total_bytes(const struct p2p_node *n)
{
    size_t total = 0;
    total += n->inventory_to_send_count;
    for (const struct send_segment *s = n->send_head; s; s = s->next)
        total += s->size;
    return total;
}

static size_t wprt_all(const struct wprt_fx *f, const char *cmd)
{
    size_t c = 0;
    for (size_t i = 0; i < f->num_peers; i++)
        c += wprt_count(f->peers[i], cmd);
    return c;
}

static bool wprt_clearnet_silent(const struct wprt_fx *f)
{
    for (size_t i = 0; i < f->num_peers; i++)
        if (!net_addr_is_tor(&f->peers[i]->addr.svc.addr) &&
            wprt_total_bytes(f->peers[i]) != 0)
            return false;
    return true;
}

static size_t wprt_receivers(const struct wprt_fx *f)
{
    size_t c = 0;
    for (size_t i = 0; i < f->num_peers; i++)
        c += wprt_count(f->peers[i], "tx") ? 1u : 0u;
    return c;
}

/* ── transactions ───────────────────────────────────────────────────── */

static const int64_t WPRT_UTXO = 100 * COIN_VALUE;

static bool wprt_add_utxo(struct wprt_fx *f, const struct uint256 *txid)
{
    struct coins_cache_entry *e = coins_view_cache_modify_new(&f->coins, txid);
    if (!e)
        return false;
    coins_alloc(&e->coins, 1);
    e->coins.vout[0].value = WPRT_UTXO;
    e->coins.vout[0].script_pub_key = f->spk;
    e->coins.height = 1;
    e->coins.version = 1;
    e->coins.is_coinbase = false;
    return true;
}

/* A signed 1-in/1-out spend of a fresh utxo. With `params` non-NULL the
 * transaction is Overwinter v3 with the given expiry, signed under that
 * parameter set's branch id. */
static bool wprt_build(struct wprt_fx *f, uint8_t seed,
                       const struct chain_params *params, uint32_t expiry,
                       struct wallet_tx *wtx)
{
    struct uint256 prev;
    memset(prev.data, seed, 32);
    if (!wprt_add_utxo(f, &prev))
        return false;
    memset(wtx, 0, sizeof(*wtx));
    struct transaction *tx = &wtx->tx;
    transaction_init(tx);
    transaction_alloc(tx, 1, 1);
    tx->version = 1;
    tx->vin[0].prevout.hash = prev;
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = 0xFFFFFFFF;
    tx->vout[0].value = WPRT_UTXO - 1000;
    uint8_t one[] = {0x51};
    script_set(&tx->vout[0].script_pub_key, one, 1);
    uint32_t branch = 0;
    if (params) {
        tx->overwintered = true;
        tx->version = OVERWINTER_TX_VERSION;
        tx->version_group_id = OVERWINTER_VERSION_GROUP_ID;
        tx->expiry_height = expiry;
        branch = consensus_current_epoch_branch_id(0, &params->consensus);
    }
    struct sighash_type ht = { .raw = SIGHASH_ALL };
    struct uint256 sighash;
    uint256_set_null(&sighash);
    signature_hash(&f->spk, tx, 0, ht, WPRT_UTXO, branch, NULL, &sighash);
    unsigned char sig[80];
    size_t siglen = sizeof(sig);
    privkey_sign(&f->key, &sighash, sig, &siglen);
    sig[siglen++] = SIGHASH_ALL;
    unsigned char ss[1 + 73 + 1 + 65];
    size_t n = 0;
    ss[n++] = (unsigned char)siglen;
    memcpy(ss + n, sig, siglen);
    n += siglen;
    ss[n++] = (unsigned char)f->pub.size;
    memcpy(ss + n, f->pub.vch, f->pub.size);
    n += f->pub.size;
    script_set(&tx->vin[0].script_sig, ss, n);
    transaction_compute_hash(tx);
    wtx->from_me = true;
    wtx->used = true;
    return true;
}

static void wprt_ctx(struct wprt_fx *f, struct wallet_rpc_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->wallet = f->wallet;
    ctx->main_state = &f->ms;
    ctx->mempool = &f->main_pool;
    ctx->connman = &f->cm;
    ctx->coins_tip = &f->coins;
}

/* The wallet send sequence, exactly as the four send paths run it. */
static bool wprt_send(struct wprt_fx *f, struct wallet_tx *wtx)
{
    struct wallet_rpc_context base, view;
    wprt_ctx(f, &base);
    struct wallet_rpc_context *ctx = wallet_send_view(&base, &view);
    struct zcl_result cr = wallet_commit_from_context(ctx, wtx);
    if (!cr.ok) {
        printf("wallet_private_relay: commit refused: %s\n", cr.message);
        return false;
    }
    struct zcl_result pr = wallet_persist_commit_before_relay(ctx, wtx);
    if (!pr.ok) {
        printf("wallet_private_relay: persist refused: %s\n", pr.message);
        return false;
    }
    return wallet_send_relay(ctx, wtx);
}

/* A node without a socket marks itself for disconnect on its first flush
 * attempt, which is a fixture artifact: undo it for every peer except the one
 * the case deliberately disconnects. */

static void wprt_revive_peers(void)
{
    for (size_t i = 0; wprt_cur && i < wprt_cur->num_peers; i++)
        if (wprt_cur->peers[i] != wprt_cur->doomed)
            wprt_cur->peers[i]->disconnect = false;
}

static void wprt_tick(int64_t advance_ms, int tip, struct wpr_tick_result *out)
{
    wprt_now += advance_ms;
    wpr_tick(wpr_global(), tip, out);
    wprt_revive_peers();
}

static enum wpr_state wprt_state(const struct uint256 *txid, bool *found)
{
    struct wpr_status *st = zcl_calloc(1, sizeof(*st), "wprt_status");
    enum wpr_state s = WPR_SEEN;
    *found = false;
    if (!st)
        return s;
    wpr_status_snapshot(wpr_global(), st);
    for (size_t i = 0; i < st->num_entries; i++)
        if (memcmp(st->entries[i].txid.data, txid->data, 32) == 0) {
            s = st->entries[i].state;
            *found = true;
        }
    free(st);
    return s;
}

static size_t wprt_pending(void)
{
    struct wpr_status *st = zcl_calloc(1, sizeof(*st), "wprt_status");
    size_t p = 0;
    if (st) {
        wpr_status_snapshot(wpr_global(), st);
        p = st->pending;
        free(st);
    }
    return p;
}

static void wprt_report(const char *name, bool ok, int *failures)
{
    printf("wallet_private_relay: %s... %s\n", name, ok ? "OK" : "FAIL");
    if (!ok)
        (*failures)++;
}

/* Run a pass of ticks, one second apart, up to `ms` total. */
static void wprt_run(int64_t ms, int tip)
{
    struct wpr_tick_result res;
    for (int64_t t = 0; t < ms; t += 1000)
        wprt_tick(1000, tip, &res);
}

/* ── cases ──────────────────────────────────────────────────────────── */

/* The previous behaviour: this is the witness the private path replaces. */
static int wprt_case_public_witness(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PUBLIC);
    struct p2p_node *clear = ok ? wprt_add_peer(&f, WPRT_CLEAR_OUT) : NULL;
    struct wallet_tx wtx;
    ok = ok && clear && wprt_build(&f, 0x51, NULL, 0, &wtx) &&
         wprt_send(&f, &wtx);
    wprt_report("public mode (old relay) holds the send in the main mempool "
                "and announces it to a clearnet peer",
                ok && tx_mempool_exists(&f.main_pool, &wtx.tx.hash) &&
                    wprt_count(clear, "inv") == 1,
                &failures);
    if (ok)
        transaction_free(&wtx.tx);
    wprt_close(&f);
    return failures;
}

static bool wprt_peer_serves_nothing(struct wprt_fx *f, struct p2p_node *peer,
                                     const struct uint256 *txid)
{
    struct msg_processor *mp = zcl_calloc(1, sizeof(*mp), "wprt_mp");
    if (!mp)
        return false;
    msg_processor_init(mp, &f->ms, &f->main_pool, &f->coins, f->params,
                       f->dir, &f->cm.manager, NULL);
    size_t before = wprt_total_bytes(peer);
    bool ok = process_mempool(mp, peer);
    struct byte_stream req;
    stream_init(&req, 64);
    struct inv_item inv;
    inv_item_init_typed(&inv, MSG_TX, txid);
    stream_write_compact_size(&req, 1);
    inv_item_serialize(&inv, &req);
    struct byte_stream rd;
    stream_init_from_data(&rd, req.data, req.size);
    ok = process_getdata(mp, peer, &rd) && ok;
    stream_free(&rd);
    stream_free(&req);
    ok = ok && wprt_count(peer, "tx") == 0 && wprt_count(peer, "inv") == 0;
    (void)before;
    free(mp);
    return ok;
}

static void wprt_private_send_status(struct wprt_fx *f, const struct wallet_tx *wtx,
                                     bool ok, int *failures)
{
    bool found = false;
    wprt_report("nothing is announced or pushed before the delay",
                ok && wprt_all(f, "inv") == 0 && wprt_all(f, "tx") == 0,
                failures);
    wprt_report("status is scheduled with one pending send",
                ok && wprt_state(&wtx->tx.hash, &found) == WPR_SCHEDULED &&
                    found && wprt_pending() == 1,
                failures);
}

static int wprt_case_private_send(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PRIVATE);
    struct p2p_node *clear = ok ? wprt_add_peer(&f, WPRT_CLEAR_OUT) : NULL;
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct wallet_tx wtx;
    ok = ok && clear && onion && wprt_build(&f, 0x52, NULL, 0, &wtx) &&
         wprt_send(&f, &wtx);
    wprt_report("a private send leaves the main mempool empty",
                ok && tx_mempool_size(&f.main_pool) == 0 &&
                    !tx_mempool_exists(&f.main_pool, &wtx.tx.hash) &&
                    tx_mempool_exists(wpr_pool(wpr_global()), &wtx.tx.hash),
                &failures);
    wprt_report("mempool and getdata from a clearnet peer and an onion peer "
                "reveal nothing",
                ok && wprt_peer_serves_nothing(&f, clear, &wtx.tx.hash) &&
                    wprt_peer_serves_nothing(&f, onion, &wtx.tx.hash),
                &failures);
    wprt_private_send_status(&f, &wtx, ok, &failures);
    if (ok)
        transaction_free(&wtx.tx);
    wprt_close(&f);
    return failures;
}

static int64_t wprt_due_delay(const struct uint256 *txid)
{
    struct wpr *r = wpr_global();
    for (size_t i = 0; i < WPR_MAX_ENTRIES; i++)
        if (r->entries[i].used &&
            memcmp(r->entries[i].txid.data, txid->data, 32) == 0)
            return r->entries[i].due_ms - r->now_ms();
    return -1;
}

/* The extreme RNG outputs map to the two ends of the delay range. */
static void wprt_delay_ends(struct wpr *r, const struct wallet_tx *wtx,
                            bool ok, int *failures)
{
    wprt_fill = 0x00;
    ok = ok && wpr_enqueue(r, &wtx->tx).ok;
    bool min_ok = wprt_due_delay(&wtx->tx.hash) == WPR_DELAY_MIN_MS;
    wpr_forget(r, &wtx->tx.hash);
    wprt_fill = 0xFF;
    ok = ok && wpr_enqueue(r, &wtx->tx).ok;
    int64_t dmax = wprt_due_delay(&wtx->tx.hash);
    bool max_ok = dmax >= WPR_DELAY_MIN_MS && dmax <= WPR_DELAY_MAX_MS;
    wpr_forget(r, &wtx->tx.hash);
    wprt_report("the extreme RNG outputs map to the range ends",
                ok && min_ok && max_ok, failures);
}

static int wprt_case_delay(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PRIVATE);
    struct wallet_tx wtx;
    ok = ok && wprt_build(&f, 0x53, NULL, 0, &wtx);
    struct wpr *r = wpr_global();
    int64_t lo = INT64_MAX, hi = 0;
    struct wpr_env quiet_env = r->env;
    quiet_env.datadir = NULL;  /* 800 durable writes would only time the disk */
    wpr_configure(r, WPR_MODE_PRIVATE, &quiet_env);
    bool in_range = ok;
    for (int i = 0; ok && i < 400; i++) {
        wprt_fill = -1;
        ok = wpr_enqueue(r, &wtx.tx).ok;
        int64_t d = wprt_due_delay(&wtx.tx.hash);
        in_range = in_range && d >= WPR_DELAY_MIN_MS && d <= WPR_DELAY_MAX_MS;
        lo = d < lo ? d : lo;
        hi = d > hi ? d : hi;
        wpr_forget(r, &wtx.tx.hash);
    }
    wprt_report("400 CSPRNG delays all fall in 2 to 20 s and spread over the "
                "range",
                ok && in_range && lo < 6000 && hi > 16000, &failures);
    wprt_delay_ends(r, &wtx, ok, &failures);
    if (ok)
        transaction_free(&wtx.tx);
    wprt_close(&f);
    return failures;
}

static bool wprt_pushed_to_eligible(const struct wprt_fx *f,
                                    const struct p2p_node *skip,
                                    struct p2p_node **got)
{
    *got = NULL;
    for (size_t i = 0; i < f->num_peers; i++)
        if (f->peers[i] != skip && wprt_count(f->peers[i], "tx"))
            *got = f->peers[i];
    return *got && wpr_peer_eligible(*got);
}

static void wprt_peer_first_attempt(struct wprt_fx *f, bool ok,
                                    struct p2p_node **first, int *failures)
{
    struct wpr_tick_result res;
    wprt_tick(WPR_DELAY_MIN_MS - 1, -1, &res);
    wprt_report("no push before the earliest delay",
                ok && wprt_all(f, "tx") == 0, failures);
    wprt_run(WPR_DELAY_MAX_MS, -1);
    bool eligible = wprt_pushed_to_eligible(f, NULL, first);
    wprt_report("exactly one eligible onion peer receives the first attempt",
                ok && eligible && wprt_all(f, "tx") == 1 &&
                    wprt_receivers(f) == 1,
                failures);
}

static void wprt_peer_silence(struct wprt_fx *f, const struct wallet_tx *wtx,
                              bool ok, int *failures)
{
    bool found = false;
    wprt_report("no clearnet, inbound, disconnecting or non-relaying peer "
                "received anything",
                ok && wprt_clearnet_silent(f) &&
                    wprt_total_bytes(f->peers[5]) == 0 &&
                    wprt_total_bytes(f->peers[6]) == 0 &&
                    wprt_total_bytes(f->peers[7]) == 0,
                failures);
    wprt_report("status is sent with one attempt",
                ok && wprt_state(&wtx->tx.hash, &found) == WPR_SENT && found,
                failures);
}

/* Not seen back: a different onion peer after the resend interval. */
static void wprt_peer_resend(struct wprt_fx *f, struct p2p_node *first,
                             bool ok, int *failures)
{
    wprt_run((int64_t)WPR_RESEND_AFTER_S * 1000 - 2000, -1);
    bool quiet = wprt_all(f, "tx") == 1;
    wprt_run(2000 + WPR_DELAY_MAX_MS + 10000, -1);
    size_t after = wprt_all(f, "tx");
    struct p2p_node *second = NULL;
    bool eligible = wprt_pushed_to_eligible(f, first, &second);
    wprt_report("no resend inside the interval; the resend goes to a "
                "different eligible onion peer",
                ok && quiet && after == 2 && eligible &&
                    wprt_receivers(f) == 2 && wprt_clearnet_silent(f),
                failures);
    wprt_run(3600 * 1000, -1);
    wprt_report("resends continue to onion peers only, never clearnet",
                ok && wprt_clearnet_silent(f) && wprt_all(f, "tx") >= 3 &&
                    wprt_total_bytes(f->peers[5]) == 0,
                failures);
}

static int wprt_case_one_peer_per_attempt(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PRIVATE);
    for (int i = 0; ok && i < 3; i++)
        ok = wprt_add_peer(&f, WPRT_ONION_OUT) != NULL;
    ok = ok && wprt_add_peer(&f, WPRT_CLEAR_OUT) &&
         wprt_add_peer(&f, WPRT_CLEAR_OUT) &&
         wprt_add_peer(&f, WPRT_ONION_IN) &&
         wprt_add_peer(&f, WPRT_ONION_DISCONNECT) &&
         wprt_add_peer(&f, WPRT_ONION_NO_RELAY);
    struct wallet_tx wtx;
    ok = ok && wprt_build(&f, 0x54, NULL, 0, &wtx) && wprt_send(&f, &wtx);
    wprt_fill = -1;
    struct p2p_node *first = NULL;
    wprt_peer_first_attempt(&f, ok, &first, &failures);
    wprt_peer_silence(&f, &wtx, ok && first, &failures);
    wprt_peer_resend(&f, first, ok, &failures);
    if (ok)
        transaction_free(&wtx.tx);
    wprt_close(&f);
    return failures;
}

static void wprt_no_route_held(struct wprt_fx *f, const struct wallet_tx *wtx,
                               bool ok, int *failures)
{
    bool found = false;
    struct wpr_status *st = zcl_calloc(1, sizeof(*st), "wprt_status");
    if (st)
        wpr_status_snapshot(wpr_global(), st);
    wprt_report("with no onion peer the send is held: waiting_for_route, "
                "zero eligible peers, nothing sent anywhere",
                ok && st &&
                    wprt_state(&wtx->tx.hash, &found) ==
                        WPR_WAITING_FOR_ROUTE &&
                    found && st->eligible_peers == 0 && st->pending == 1 &&
                    tx_mempool_size(&f->main_pool) == 0,
                failures);
    bool silent = true;
    for (size_t i = 0; i < f->num_peers; i++)
        silent = silent && wprt_total_bytes(f->peers[i]) == 0;
    wprt_report("no peer received any byte while no route existed", ok && silent,
                failures);
    free(st);
}

static int wprt_case_no_route(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PRIVATE);
    ok = ok && wprt_add_peer(&f, WPRT_CLEAR_OUT) &&
         wprt_add_peer(&f, WPRT_CLEAR_OUT) && wprt_add_peer(&f, WPRT_ONION_IN);
    struct wallet_tx wtx;
    ok = ok && wprt_build(&f, 0x55, NULL, 0, &wtx) && wprt_send(&f, &wtx);
    wprt_run(600 * 1000, -1);
    wprt_no_route_held(&f, &wtx, ok, &failures);
    /* A route appears: a fresh delay is drawn from that moment. */
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct wpr_tick_result res;
    wprt_tick(1000, -1, &res);
    int64_t d = wprt_due_delay(&wtx.tx.hash);
    wprt_report("a route appearing schedules a fresh 2 to 20 s delay",
                onion && d >= WPR_DELAY_MIN_MS && d <= WPR_DELAY_MAX_MS &&
                    wprt_all(&f, "tx") == 0,
                &failures);
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    wprt_report("then exactly the onion peer receives it",
                onion && wprt_count(onion, "tx") == 1 &&
                    wprt_receivers(&f) == 1 && wprt_clearnet_silent(&f),
                &failures);
    if (ok)
        transaction_free(&wtx.tx);
    wprt_close(&f);
    return failures;
}

static void wprt_seen_hook(struct wprt_fx *f, const struct wallet_tx *a,
                           bool ok, int *failures)
{
    /* The network offers it back: the node accepts it and the production
     * wallet hook fires. */
    struct boot_svc_ctx *svc = zcl_calloc(1, sizeof(*svc), "wprt_svc");
    ok = ok && svc;
    if (svc) {
        svc->wallet = f->wallet;
        boot_wallet_tx_accepted(&a->tx, svc);
    }
    free(svc);
    bool found = false;
    wprt_report("the wallet tx-accepted hook clears the pending state and "
                "empties the private pool entry",
                ok && wprt_state(&a->tx.hash, &found) == WPR_SEEN && found &&
                    !tx_mempool_exists(wpr_pool(wpr_global()), &a->tx.hash) &&
                    wprt_pending() == 1,
                failures);
}

static void wprt_seen_block(struct wprt_fx *f, const struct wallet_tx *b,
                            bool ok, int *failures)
{
    /* The other transaction appears in a connected block. */
    struct uint256 bh;
    memset(bh.data, 0xB1, 32);
    struct block_index bi;
    memset(&bi, 0, sizeof(bi));
    bi.nHeight = 1;
    bi.phashBlock = &bh;
    wallet_sync_transaction(f->wallet, &b->tx, &bi);
    wprt_run(1000, -1);
    bool found = false;
    wprt_report("inclusion in a block clears the pending state",
                ok && wprt_state(&b->tx.hash, &found) == WPR_SEEN && found &&
                    !tx_mempool_exists(wpr_pool(wpr_global()), &b->tx.hash) &&
                    wprt_pending() == 0,
                failures);
    size_t sent = wprt_all(f, "tx");
    wprt_run(1000 * 1000, -1);
    wprt_report("a cleared send is never pushed again",
                ok && wprt_all(f, "tx") == sent, failures);
}

static int wprt_case_seen_and_block(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PRIVATE);
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct wallet_tx a, b;
    ok = ok && onion && wprt_build(&f, 0x56, NULL, 0, &a) &&
         wprt_build(&f, 0x57, NULL, 0, &b) && wprt_send(&f, &a) &&
         wprt_send(&f, &b);
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    ok = ok && wprt_count(onion, "tx") == 2;
    wprt_seen_hook(&f, &a, ok, &failures);
    wprt_seen_block(&f, &b, ok, &failures);
    if (ok) {
        transaction_free(&a.tx);
        transaction_free(&b.tx);
    }
    wprt_close(&f);
    return failures;
}

static int wprt_case_expiry(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PRIVATE);
    /* A parameter set with Overwinter active from height 0, so the
     * transaction carries an expiry the consensus predicate honours. */
    struct chain_params p = *chain_params_get();
    p.consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight = 0;
    struct wpr_env env = {
        .wallet = f.wallet, .connman = &f.cm, .coins_tip = &f.coins,
        .main_state = &f.ms, .params = &p, .datadir = f.dir,
    };
    wpr_configure(wpr_global(), WPR_MODE_PRIVATE, &env);
    f.params = &p;
    struct wallet_tx wtx;
    ok = ok && wprt_build(&f, 0x58, &p, 50, &wtx);
    struct wallet_rpc_context base, view;
    wprt_ctx(&f, &base);
    struct wallet_rpc_context *ctx = NULL;
    wprt_report("private mode gives the send a private-pool view without a "
                "peer manager",
                (ctx = wallet_send_view(&base, &view)) == &view &&
                    ctx->mempool == wpr_pool(wpr_global()) &&
                    ctx->connman == NULL,
                &failures);
    struct wallet_tx_admission adm = {
        .mempool = ctx->mempool, .coins_tip = &f.coins, .main_state = &f.ms,
        .params = &p,
    };
    struct zcl_result cr = wallet_commit_transaction(f.wallet, &wtx, &adm);
    ok = ok && cr.ok && wallet_send_relay(ctx, &wtx);
    struct uint256 prev = wtx.tx.vin[0].prevout.hash;
    bool spent_before = ok && wallet_is_outpoint_spent(f.wallet, &prev, 0);
    wprt_run(WPR_DELAY_MAX_MS + 1000, 10);
    wallet_private_broadcast_tick_at(60);
    wprt_report("a send past its expiry height leaves the pending state and "
                "the wallet returns its input",
                ok && spent_before && wprt_pending() == 0 &&
                    !wallet_is_outpoint_spent(f.wallet, &prev, 0) &&
                    f.wallet->num_wallet_tx == 0 &&
                    f.wallet->num_spent == 0 &&
                    !tx_mempool_exists(wpr_pool(wpr_global()), &wtx.tx.hash),
                &failures);
    if (ok)
        transaction_free(&wtx.tx);
    wprt_close(&f);
    return failures;
}

static void wprt_resume_reports(struct wprt_fx *f, struct wpr *r,
                                const struct wallet_tx *wtx,
                                struct p2p_node *clear,
                                struct p2p_node *onion, bool ok,
                                int *failures)
{
    bool resumed = false;
    wprt_report("resume succeeds for a restarted relay",
                (resumed = ok && wpr_resume(r).ok), failures);
    int64_t d = wprt_due_delay(&wtx->tx.hash);
    wprt_report("resume revalidates into the private pool with a fresh "
                "2 to 20 s delay; the main mempool stays empty",
                resumed && wprt_pending() == 1 &&
                    tx_mempool_exists(wpr_pool(r), &wtx->tx.hash) &&
                    tx_mempool_size(&f->main_pool) == 0 &&
                    d >= WPR_DELAY_MIN_MS && d <= WPR_DELAY_MAX_MS,
                failures);
    wprt_report("resume announces nothing to any peer",
                resumed && wprt_all(f, "inv") == 0 &&
                    wprt_total_bytes(clear) == 0 &&
                    wprt_count(onion, "tx") == 0,
                failures);
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    wprt_report("after the delay exactly the onion peer receives it; "
                "clearnet stays silent",
                resumed && wprt_count(onion, "tx") == 1 &&
                    wprt_clearnet_silent(f) && wprt_all(f, "inv") == 0,
                failures);
}

static int wprt_case_restart(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PRIVATE);
    struct p2p_node *clear = ok ? wprt_add_peer(&f, WPRT_CLEAR_OUT) : NULL;
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct wallet_tx wtx;
    ok = ok && clear && onion && wprt_build(&f, 0x59, NULL, 0, &wtx) &&
         wprt_send(&f, &wtx);

    /* Restart: a fresh relay instance reads the durable pending set. The
     * wallet transaction and chain state persist; peers reconnect. */
    struct wpr_env env = wpr_global()->env;
    env.datadir = f.dir;
    struct wpr *r = wpr_global();
    wpr_free(r);
    wpr_init(r);
    r->now_ms = wprt_clock;
    r->random_bytes = wprt_rng;
    wpr_configure(r, WPR_MODE_PRIVATE, &env);
    wprt_report("a restarted relay holds nothing before it resumes",
                wprt_pending() == 0 &&
                    !tx_mempool_exists(wpr_pool(r), &wtx.tx.hash),
                &failures);
    wprt_resume_reports(&f, r, &wtx, clear, onion, ok, &failures);
    if (ok)
        transaction_free(&wtx.tx);
    wprt_close(&f);
    return failures;
}

static bool wprt_fund_wallet(struct wprt_fx *f)
{
    /* Two confirmed 100 ZCL coins owned by the wallet. */
    bool ok = wallet_import_key(f->wallet, &f->key);
    for (int i = 0; ok && i < 2; i++) {
        struct wallet_tx fund;
        memset(&fund, 0, sizeof(fund));
        transaction_init(&fund.tx);
        transaction_alloc(&fund.tx, 0, 1);
        fund.tx.version = 1;
        fund.tx.lock_time = (uint32_t)(i + 1);
        fund.tx.vout[0].value = WPRT_UTXO;
        fund.tx.vout[0].script_pub_key = f->spk;
        transaction_compute_hash(&fund.tx);
        fund.confirms = 10;
        fund.used = true;
        ok = wallet_add_to_wallet(f->wallet, &fund) &&
             wprt_add_utxo(f, &fund.tx.hash);
        transaction_free(&fund.tx);
    }
    return ok;
}

struct wprt_chain {
    struct tx_destination dest;
    int64_t value;
    struct wallet_tx tx[3];
    bool made[3];
};

static bool wprt_chain_make(struct wprt_fx *f, struct wprt_chain *c, int i,
                            bool send)
{
    const char *err = NULL;
    int64_t fee = 0;
    c->made[i] = wallet_create_transaction(f->wallet, &c->dest, c->value,
                                           &c->tx[i], &fee, &err);
    return c->made[i] && (!send || wprt_send(f, &c->tx[i]));
}

static void wprt_chain_reports(struct wprt_fx *f, struct wprt_chain *c,
                               struct p2p_node *onion, bool ok, int *failures)
{
    bool second = ok && wprt_chain_make(f, c, 1, true);
    wprt_report("a second send validates against the private pool and spends "
                "a different coin",
                second && memcmp(&c->tx[0].tx.vin[0].prevout,
                                 &c->tx[1].tx.vin[0].prevout,
                                 sizeof(struct outpoint)) != 0 &&
                    tx_mempool_size(wpr_pool(wpr_global())) == 2 &&
                    tx_mempool_size(&f->main_pool) == 0 && wprt_pending() == 2,
                failures);
    bool third = ok && wprt_chain_make(f, c, 2, false);
    wprt_report("a third send does not reselect either reserved coin",
                ok && second && !third, failures);
    /* The private pool itself refuses a double spend of a pending input. */
    struct wallet_tx dup;
    bool built = ok && wprt_build(f, 0x5A, NULL, 0, &dup);
    enum mempool_accept_result ar = MEMPOOL_ACCEPT_OK;
    if (built) {
        dup.tx.vin[0].prevout = c->tx[0].tx.vin[0].prevout;
        transaction_compute_hash(&dup.tx);
        ar = accept_to_mempool(wpr_pool(wpr_global()), &f->coins, &f->ms,
                               f->params, &dup.tx);
        transaction_free(&dup.tx);
    }
    wprt_report("the private pool rejects a conflicting spend of a pending "
                "input",
                built && ar != MEMPOOL_ACCEPT_OK, failures);
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    wprt_report("both chained sends reach the one onion peer and nobody else",
                second && wprt_count(onion, "tx") == 2 &&
                    wprt_clearnet_silent(f),
                failures);
}

static int wprt_case_chained(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PRIVATE);
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    ok = ok && onion && wprt_fund_wallet(&f);
    struct wprt_chain c;
    memset(&c, 0, sizeof(c));
    c.dest.type = DEST_KEY_ID;
    c.dest.id.key = f.kid;
    c.value = WPRT_UTXO - WALLET_DEFAULT_FEE_ZAT;
    ok = ok && wprt_chain_make(&f, &c, 0, true);
    wprt_chain_reports(&f, &c, onion, ok, &failures);
    for (int i = 0; i < 3; i++)
        if (c.made[i])
            transaction_free(&c.tx[i].tx);
    wprt_close(&f);
    return failures;
}

/* ── real shielded send ─────────────────────────────────────────────── */

static bool wprt_first_payload(const struct p2p_node *n, struct byte_stream *out)
{
    size_t total = 0;
    for (const struct send_segment *s = n->send_head; s; s = s->next)
        total += s->size;
    if (total < MSG_HEADER_SIZE)
        return false;
    uint8_t *buf = zcl_malloc(total, "wprt_payload");
    if (!buf)
        return false;
    size_t off = 0;
    for (const struct send_segment *s = n->send_head; s; s = s->next) {
        memcpy(buf + off, s->data, s->size);
        off += s->size;
    }
    uint32_t len = (uint32_t)buf[16] | (uint32_t)buf[17] << 8 |
                   (uint32_t)buf[18] << 16 | (uint32_t)buf[19] << 24;
    bool ok = strncmp((const char *)buf + 4, "tx", 12) == 0 &&
              MSG_HEADER_SIZE + (size_t)len <= total;
    if (ok) {
        stream_init(out, len ? len : 1);
        stream_write(out, buf + MSG_HEADER_SIZE, len);
    }
    free(buf);
    return ok;
}

/* A second node: its own mempool and main state on the same chain accepts
 * the transaction the onion peer received. */
static bool wprt_second_node_accepts(struct wprt_fx *f, struct simnet *s,
                                     const struct chain_params *p,
                                     const struct p2p_node *onion,
                                     const struct transaction *tx)
{
    struct net_manager nm;
    net_manager_init(&nm);
    struct main_state ms2;
    main_state_init(&ms2);
    struct tx_mempool pool2;
    tx_mempool_init(&pool2, 0);
    struct msg_processor *mp2 = zcl_calloc(1, sizeof(*mp2), "wprt_mp2");
    struct net_address a;
    test_set_ipv4(&a, 10, 0, 0, 2, 8033);
    struct p2p_node *from = p2p_node_create(&nm, ZCL_INVALID_SOCKET, &a,
                                            "wprt-sender", true);
    struct byte_stream payload;
    memset(&payload, 0, sizeof(payload));
    bool have = mp2 && from && wprt_first_payload(onion, &payload);
    bool accepted = false;
    if (have) {
        msg_processor_init(mp2, &ms2, &pool2, &s->view, p, f->dir, &nm, NULL);
        struct byte_stream rd;
        stream_init_from_data(&rd, payload.data, payload.size);
        accepted = process_tx_msg(mp2, from, &rd) &&
                   tx_mempool_exists(&pool2, &tx->hash);
        stream_free(&rd);
        stream_free(&payload);
    }
    free(mp2);
    if (from)
        p2p_node_free(from);
    tx_mempool_free(&pool2);
    main_state_free(&ms2);
    net_manager_free(&nm);
    return accepted;
}

static void wprt_probe_delivery(struct wprt_fx *f, struct simnet *s,
                                const struct chain_params *p,
                                struct p2p_node *clear,
                                struct p2p_node *onion,
                                const struct transaction *tx, bool ok,
                                int *failures)
{
    wprt_report("shielded send: exactly the onion peer receives the full "
                "transaction; the clearnet peer receives nothing",
                ok && clear && onion && wprt_count(onion, "tx") == 1 &&
                    wprt_total_bytes(clear) == 0,
                failures);
    wprt_report("shielded send: a second node accepts the pushed transaction "
                "into its mempool",
                ok && onion && wprt_second_node_accepts(f, s, p, onion, tx),
                failures);
}

int wallet_private_relay_shielded_probe(struct simnet *s,
                                        struct transaction *tx)
{
    int failures = 0;
    static bool done;
    if (done)
        return 0;  /* the determinism reruns rebuild the same transaction */
    done = true;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PRIVATE);
    /* The sender's view of the chain: Overwinter and Sapling active at the
     * next height, the simulator's live coin view and anchor registry. */
    struct chain_params p = s->params;
    p.consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight = 0;
    p.consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight = 0;
    struct wpr_env env = {
        .connman = &f.cm, .coins_tip = &s->view, .main_state = &f.ms,
        .params = &p, .datadir = f.dir,
    };
    struct p2p_node *clear = ok ? wprt_add_peer(&f, WPRT_CLEAR_OUT) : NULL;
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    wpr_configure(wpr_global(), WPR_MODE_PRIVATE, &env);

    char detail[128];
    transaction_compute_hash(tx);
    enum mempool_accept_result ar = ok ? accept_to_mempool_detailed(
        wpr_pool(wpr_global()), &s->view, &f.ms, &p, tx, detail,
        sizeof(detail)) : MEMPOOL_ACCEPT_INTERNAL_ERROR;
    wprt_report("shielded send: the full proof, signature and anchor gate "
                "admits it to the private pool",
                ok && ar == MEMPOOL_ACCEPT_OK &&
                    tx_mempool_exists(wpr_pool(wpr_global()), &tx->hash),
                &failures);
    wprt_report("shielded send: the main mempool never holds it",
                ok && tx_mempool_size(&f.main_pool) == 0, &failures);
    ok = ok && ar == MEMPOOL_ACCEPT_OK && wpr_enqueue(wpr_global(), tx).ok;
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    wprt_probe_delivery(&f, s, &p, clear, onion, tx, ok, &failures);
    wprt_close(&f);
    return failures;
}

int test_wallet_private_relay(void);
int test_wallet_private_relay(void)
{
    int failures = 0;
    failures += wprt_case_public_witness();
    failures += wprt_case_private_send();
    failures += wprt_case_delay();
    failures += wprt_case_one_peer_per_attempt();
    failures += wprt_case_no_route();
    failures += wprt_case_seen_and_block();
    failures += wprt_case_expiry();
    failures += wprt_case_restart();
    failures += wprt_case_chained();
    return failures;
}
