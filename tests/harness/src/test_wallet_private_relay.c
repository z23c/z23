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
#include "config/args.h"
#include "config/boot_internal.h"
#include "config/boot_msg_callbacks.h"
#include "consensus/upgrades.h"
#include "controllers/wallet_controller.h"
#include "controllers/vault_intent_controller.h"
#include "models/wallet_identity.h"
#include "wallet/wallet_canary.h"
#include "models/block.h"
#include "services/wallet_backup_service.h"
#include "services/sync_monitor.h"
#include "sync/sync_state.h"
#include "controllers/wallet_helpers.h"
#include "controllers/transaction_controller.h"
#include "controllers/wallet_private_broadcast.h"
#include "core/serialize.h"
#include "crypto/random_secret.h"
#include "keys/key.h"
#include "json/json.h"
#include "keys/pubkey.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "net/connman.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/netaddr.h"
#include "net/onion_v3_address.h"
#include "net/tor_integration.h"
#include "net/protocol.h"
#include "platform/clock.h"
#include "platform/file_stream.h"
#include "platform/private_file.h"
#include "platform/private_directory.h"
#include "platform/time_compat.h"
#include "util/authority_receipt.h"
#include "util/sync.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
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
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"
#include "jobs/reducer_frontier.h"
#include "jobs/reducer_frontier_schema.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static _Atomic int64_t wprt_now;
static int64_t wprt_clock(void) { return atomic_load(&wprt_now); }

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
    struct rpc_table tbl;
    struct node_db ndb;
    struct wallet_sqlite wsql;
    bool db_open;
    bool wsql_open;
    bool trust_open;
    struct uint256 funding[8];
    size_t num_funding;
    struct chain_params saved_params;
    bool params_saved;
};

static struct wprt_fx *wprt_cur;
static bool wprt_file_database;

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
    if (!wallet_readiness_initialize(f->wallet, WALLET_READINESS_READY, true, 42))
        return false;
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
    atomic_store(&wprt_now, 1000000);
    wprt_fill = -1;
    struct wpr_env env = {
        .wallet = f->wallet, .connman = &f->cm, .coins_tip = &f->coins,
        .main_state = &f->ms, .params = f->params, .datadir = f->dir,
    };
    wpr_configure(r, mode, &env);
    wallet_require_admission_pool(mode == WPR_MODE_PRIVATE ? wpr_pool(r)
                                                           : NULL);
    wallet_rpc_context_set_base(f->wallet, &f->ms, f->dir, NULL,
                                &f->main_pool, &f->cm);
    wallet_rpc_context_set_coins_tip(&f->coins);
    return true;
}

static void wprt_close(struct wprt_fx *f)
{
    wprt_cur = NULL;
    wallet_require_admission_pool(NULL);
    if (f->trust_open)
        progress_store_close();
    if (f->wsql_open)
        wallet_sqlite_close(&f->wsql);
    /* The wallet RPC context keeps the node DB pointer after this frame's
     * fixture is gone; the next case's registration would read it. */
    if (f->db_open && wallet_rpc_node_db() == &f->ndb)
        rpc_wallet_set_node_db(NULL);
    if (f->db_open)
        node_db_close(&f->ndb);
    if (f->params_saved)
        *(struct chain_params *)chain_params_get() = f->saved_params;
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

/* Overwinter active from height 0, so wallet sends carry an expiry height.
 * The saved parameters are restored when the fixture closes. */
static void wprt_overwinter_on(struct wprt_fx *f)
{
    struct chain_params *p = (struct chain_params *)chain_params_get();
    f->saved_params = *p;
    f->params_saved = true;
    p->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight = 0;
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
    atomic_fetch_add(&wprt_now, advance_ms);
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

static struct wallet_tx_admission wprt_admission(struct wprt_fx *f,
                                                 struct tx_mempool *pool)
{
    struct wallet_tx_admission a = {
        .mempool = pool, .coins_tip = &f->coins, .main_state = &f->ms,
        .params = f->params,
    };
    return a;
}

/* Run a pass of ticks, one second apart, up to `ms` total. */
static void wprt_run(int64_t ms, int tip)
{
    struct wpr_tick_result res;
    for (int64_t t = 0; t < ms; t += 1000)
        wprt_tick(1000, tip, &res);
}

/* ── the wallet send surface: the real RPC handlers ─────────────────── */

static bool wprt_self_address(const struct wprt_fx *f, char *out, size_t cap)
{
    struct tx_destination dest;
    memset(&dest, 0, sizeof(dest));
    dest.type = DEST_KEY_ID;
    dest.id.key = f->kid;
    return wallet_encode_destination(&dest, out, cap);
}

static bool wprt_db_utxo(struct wprt_fx *f, const struct uint256 *txid)
{
    if (!f->db_open)
        return true;
    struct db_wallet_utxo u;
    memset(&u, 0, sizeof(u));
    memcpy(u.txid, txid->data, sizeof(u.txid));
    u.value = WPRT_UTXO;
    memcpy(u.address_hash, f->kid.id.data, sizeof(u.address_hash));
    u.script = (uint8_t *)f->spk.data;
    u.script_len = f->spk.size;
    u.height = 1;
    return db_wallet_utxo_save(&f->ndb, &u);
}

static bool wprt_fund_one(struct wprt_fx *f, int i)
{
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
    bool ok = wallet_add_to_wallet(f->wallet, &fund) &&
              wprt_add_utxo(f, &fund.tx.hash) &&
              wprt_db_utxo(f, &fund.tx.hash);
    if (ok)
        f->funding[f->num_funding++] = fund.tx.hash;
    transaction_free(&fund.tx);
    return ok;
}

/* Spend RPCs are sovereignty-gated: give them the minimal self-folded
 * progress projection a running node has. */
static bool wprt_trust_fixture(const char *dir)
{
    if (!progress_store_open(dir))
        return false;
    sqlite3 *db = progress_store_db();
    uint8_t txid[32] = {0x51};
    uint8_t migrated = 1, hash[32];
    memset(hash, 0x50, sizeof(hash));
    if (!db || !coins_kv_ensure_schema(db) || !reducer_frontier_ensure_schema(db))
        return false;
    reducer_frontier_provable_tip_set(10);
    const unsigned char script[4] = {0xE0, 0xE0, 0xE0, 0xE0};
    if (!coins_kv_add(db, txid, 0, 1234, 10, true, script, sizeof(script)) ||
        sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return false;
    sqlite3_stmt *st = NULL;
    bool ok = coins_kv_set_applied_height_in_tx(db, 11) &&
        progress_meta_set_in_tx(db, COINS_KV_MIGRATION_COMPLETE_KEY, &migrated, 1) &&
        sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO validate_headers_log"
            "(height,hash,ok,validated_at) VALUES(10,?1,1,0)", -1, &st, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_blob(st, 1, hash, sizeof(hash), SQLITE_STATIC);
        ok = sqlite3_step(st) == SQLITE_DONE;
    }
    sqlite3_finalize(st);
    ok = sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK && ok;
    return ok && coins_kv_mark_self_folded(db);
}

/* Registers the real wallet RPC table over the fixture, with a real node
 * database and wallet database when asked. */
static bool wprt_rpc_start(struct wprt_fx *f, bool with_db)
{
    if (!wprt_trust_fixture(f->dir))
        return false;
    f->trust_open = true;
    rpc_table_init(&f->tbl);
    register_wallet_rpc_commands(&f->tbl);
    char warm[64];
    if (rpc_is_in_warmup(warm, sizeof(warm)))
        set_rpc_warmup_finished();
    if (with_db) {
        wallet_lock_reset_for_test();
        wallet_lock_note_encrypted_at_rest();
        char dbpath[320];
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", f->dir);
        if (!node_db_open(&f->ndb, wprt_file_database ? dbpath : ":memory:"))
            return false;
        f->db_open = true;
        if (!wallet_sqlite_open_r(&f->wsql, f->ndb.db).ok)
            return false;
        f->wsql_open = true;
        if (!wallet_lock_unlock(NULL, NULL, "wallet-private-relay").ok)
            return false;
    }
    rpc_wallet_set_state(f->wallet, &f->ms, f->dir,
                         f->wsql_open ? &f->wsql : NULL, &f->main_pool,
                         &f->cm);
    rpc_wallet_set_node_db(f->db_open ? &f->ndb : NULL);
    rpc_wallet_set_coins_tip(&f->coins);
    return true;
}

/* Change keys the wallet may hand out: owned keys registered in the pool. */
static bool wprt_fill_pool(struct wallet *w, int n)
{
    for (int i = 0; i < n; i++) {
        struct privkey k;
        struct pubkey pk;
        privkey_make_new(&k, true);
        privkey_get_pubkey(&k, &pk);
        struct key_id kid = pubkey_get_id(&pk);
        if (!wallet_import_key(w, &k) ||
            !wallet_key_pool_restore(w, &kid, 1000 + i))
            return false;
    }
    return true;
}

/* Two or more confirmed 100 ZCL coins owned by the wallet, ready to be sent
 * through sendtoaddress and sendmany. */
static bool wprt_wallet_ready(struct wprt_fx *f, enum wpr_mode mode, int coins,
                              bool with_db)
{
    bool ok = wprt_open(f, mode) && wprt_rpc_start(f, with_db) &&
              wallet_import_key(f->wallet, &f->key) &&
              wprt_fill_pool(f->wallet, 8);
    for (int i = 0; ok && i < coins; i++)
        ok = wprt_fund_one(f, i);
    return ok;
}

static void wprt_json_str(struct json_value *arr, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s);
    json_push_back(arr, &v);
    json_free(&v);
}

static void wprt_json_real(struct json_value *arr, double d)
{
    struct json_value v;
    json_init(&v);
    json_set_real(&v, d);
    json_push_back(arr, &v);
    json_free(&v);
}

static void wprt_send_params(struct json_value *params, bool many,
                             const char *addr, double zcl)
{
    json_set_array(params);
    if (!many) {
        wprt_json_str(params, addr);
        wprt_json_real(params, zcl);
        return;
    }
    wprt_json_str(params, "");
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_real(&obj, addr, zcl);
    json_push_back(params, &obj);
    json_free(&obj);
}

/* One send of `zcl` coins to the wallet's own address through the RPC
 * handler: sendtoaddress, or sendmany when `many`. */
static bool wprt_rpc_send(struct wprt_fx *f, bool many, double zcl,
                          struct uint256 *id)
{
    char addr[128];
    if (!wprt_self_address(f, addr, sizeof(addr)))
        return false;
    struct json_value params, result;
    json_init(&params);
    json_init(&result);
    wprt_send_params(&params, many, addr, zcl);
    bool ok = rpc_table_execute(&f->tbl, many ? "sendmany" : "sendtoaddress",
                                &params, &result);
    const char *hex = result.type == JSON_STR ? json_get_str(&result) : NULL;
    ok = ok && hex && strlen(hex) == 64;
    if (ok)
        uint256_set_hex(id, hex);
    else
        printf("wallet_private_relay: %s refused: %s\n",
               many ? "sendmany" : "sendtoaddress", hex ? hex : "(no text)");
    json_free(&params);
    json_free(&result);
    return ok;
}

static bool wprt_copy_tx(struct wprt_fx *f, const struct uint256 *id,
                         struct wallet_tx *out)
{
    memset(out, 0, sizeof(*out));
    return wallet_get_tx_copy(f->wallet, id, out);
}

/* The status read through the real RPC; the caller frees *out. */
static bool wprt_status_json(struct wprt_fx *f, struct json_value *out)
{
    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    json_init(out);
    bool ok = rpc_table_execute(&f->tbl, "walletbroadcaststatus", &params, out);
    json_free(&params);
    return ok;
}

static const char *wprt_jstr(const struct json_value *v)
{
    return v ? json_get_str(v) : NULL;
}

static const struct json_value *wprt_status_entry(const struct json_value *st,
                                                  const struct uint256 *id)
{
    char hex[65];
    uint256_get_hex(id, hex);
    const struct json_value *list = json_get(st, "transactions");
    for (size_t i = 0; list && i < json_size(list); i++) {
        const struct json_value *e = json_at(list, i);
        const char *t = wprt_jstr(json_get(e, "txid"));
        if (t && strcmp(t, hex) == 0)
            return e;
    }
    return NULL;
}

static bool wprt_status_says(struct wprt_fx *f, const struct uint256 *id,
                             const char *state, const char *next_part)
{
    struct json_value st;
    bool ok = wprt_status_json(f, &st);
    const struct json_value *e = ok ? wprt_status_entry(&st, id) : NULL;
    const char *s = e ? wprt_jstr(json_get(e, "state")) : NULL;
    const char *n = e ? wprt_jstr(json_get(e, "next_step")) : NULL;
    ok = ok && s && n && strcmp(s, state) == 0 && strstr(n, next_part);
    json_free(&st);
    return ok;
}

static void wprt_set_wallet_height(struct wprt_fx *f, int height)
{
    zcl_mutex_lock(&f->wallet->cs);
    f->wallet->best_block_height = height;
    zcl_mutex_unlock(&f->wallet->cs);
}

/* ── cases ──────────────────────────────────────────────────────────── */

/* The previous behaviour: this is the witness the private path replaces. */
static int wprt_case_public_witness(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PUBLIC, 1, false);
    struct p2p_node *clear = ok ? wprt_add_peer(&f, WPRT_CLEAR_OUT) : NULL;
    struct uint256 id;
    ok = ok && clear && wprt_rpc_send(&f, false, 10.0, &id);
    wprt_report("public mode (old relay) holds the send in the main mempool "
                "and announces it to a clearnet peer",
                ok && tx_mempool_exists(&f.main_pool, &id) &&
                    wprt_count(clear, "inv") == 1,
                &failures);
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
    free(mp);
    return ok;
}

static void wprt_private_send_status(struct wprt_fx *f,
                                     const struct uint256 *a,
                                     const struct uint256 *b, bool ok,
                                     int *failures)
{
    bool found = false;
    wprt_report("nothing is announced or pushed before the delay",
                ok && wprt_all(f, "inv") == 0 && wprt_all(f, "tx") == 0,
                failures);
    wprt_report("status is scheduled with two pending sends",
                ok && wprt_state(a, &found) == WPR_SCHEDULED && found &&
                    wprt_state(b, &found) == WPR_SCHEDULED && found &&
                    wprt_pending() == 2,
                failures);
}

/* sendtoaddress and sendmany, through the registered RPC handlers. */
static void wprt_private_send_pools(struct wprt_fx *f, struct p2p_node *clear,
                                    struct p2p_node *onion,
                                    const struct uint256 *a,
                                    const struct uint256 *b, bool ok,
                                    int *failures)
{
    wprt_report("a private sendtoaddress and a private sendmany leave the "
                "main mempool empty",
                ok && tx_mempool_size(&f->main_pool) == 0 &&
                    !tx_mempool_exists(&f->main_pool, a) &&
                    !tx_mempool_exists(&f->main_pool, b) &&
                    tx_mempool_exists(wpr_pool(wpr_global()), a) &&
                    tx_mempool_exists(wpr_pool(wpr_global()), b),
                failures);
    wprt_report("mempool and getdata from a clearnet peer and an onion peer "
                "reveal neither send",
                ok && wprt_peer_serves_nothing(f, clear, a) &&
                    wprt_peer_serves_nothing(f, onion, a) &&
                    wprt_peer_serves_nothing(f, clear, b) &&
                    wprt_peer_serves_nothing(f, onion, b),
                failures);
}

static int wprt_case_private_send(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 3, false);
    struct p2p_node *clear = ok ? wprt_add_peer(&f, WPRT_CLEAR_OUT) : NULL;
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct uint256 a, b;
    ok = ok && clear && onion && wprt_rpc_send(&f, false, 10.0, &a) &&
         wprt_rpc_send(&f, true, 10.0, &b);
    wprt_private_send_pools(&f, clear, onion, &a, &b, ok, &failures);
    wprt_private_send_status(&f, &a, &b, ok, &failures);
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

static void wprt_peer_silence(struct wprt_fx *f, const struct uint256 *id,
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
                ok && wprt_state(id, &found) == WPR_SENT && found, failures);
}

/* Not seen back: a different onion peer after the resend interval. */
static void wprt_peer_resend(struct wprt_fx *f, struct p2p_node *first,
                             const struct uint256 *id, bool ok, int *failures)
{
    /* The first push happened at a random moment of its 2 to 20 s delay, so
     * the end of the resend interval is read from the entry, not assumed. */
    int64_t left = wprt_due_delay(id);
    ok = ok && left > 0 && left <= (int64_t)WPR_RESEND_AFTER_S * 1000;
    wprt_run(left > 1000 ? left - 1000 : 0, -1);
    bool quiet = wprt_all(f, "tx") == 1;
    /* Then the rest of the interval and one maximum delay for the resend. */
    wprt_run(1000 + WPR_DELAY_MAX_MS + 5000, -1);
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
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 1, false);
    for (int i = 0; ok && i < 3; i++)
        ok = wprt_add_peer(&f, WPRT_ONION_OUT) != NULL;
    ok = ok && wprt_add_peer(&f, WPRT_CLEAR_OUT) &&
         wprt_add_peer(&f, WPRT_CLEAR_OUT) &&
         wprt_add_peer(&f, WPRT_ONION_IN) &&
         wprt_add_peer(&f, WPRT_ONION_DISCONNECT) &&
         wprt_add_peer(&f, WPRT_ONION_NO_RELAY);
    struct uint256 id;
    ok = ok && wprt_rpc_send(&f, false, 10.0, &id);
    wprt_fill = -1;
    struct p2p_node *first = NULL;
    wprt_peer_first_attempt(&f, ok, &first, &failures);
    wprt_peer_silence(&f, &id, ok && first, &failures);
    wprt_peer_resend(&f, first, &id, ok, &failures);
    wprt_close(&f);
    return failures;
}

static void wprt_no_route_held(struct wprt_fx *f, const struct uint256 *id,
                               bool ok, int *failures)
{
    bool found = false;
    struct wpr_status *st = zcl_calloc(1, sizeof(*st), "wprt_status");
    if (st)
        wpr_status_snapshot(wpr_global(), st);
    wprt_report("with no onion peer the send is held: waiting_for_route, "
                "zero eligible peers, nothing sent anywhere",
                ok && st &&
                    wprt_state(id, &found) == WPR_WAITING_FOR_ROUTE &&
                    found && st->eligible_peers == 0 && st->pending == 1 &&
                    tx_mempool_size(&f->main_pool) == 0,
                failures);
    bool silent = true;
    for (size_t i = 0; i < f->num_peers; i++)
        silent = silent && wprt_total_bytes(f->peers[i]) == 0;
    wprt_report("no peer received any byte while no route existed", ok && silent,
                failures);
    wprt_report("the status read tells the owner it is safe to wait",
                ok && wprt_status_says(f, id, "waiting_for_route",
                                       "safe to wait"),
                failures);
    free(st);
}

static int wprt_case_no_route(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 1, false);
    ok = ok && wprt_add_peer(&f, WPRT_CLEAR_OUT) &&
         wprt_add_peer(&f, WPRT_CLEAR_OUT) && wprt_add_peer(&f, WPRT_ONION_IN);
    struct uint256 id;
    ok = ok && wprt_rpc_send(&f, false, 10.0, &id);
    wprt_run(600 * 1000, -1);
    wprt_no_route_held(&f, &id, ok, &failures);
    /* A route appears: a fresh delay is drawn from that moment. */
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct wpr_tick_result res;
    wprt_tick(1000, -1, &res);
    int64_t d = wprt_due_delay(&id);
    wprt_report("a route appearing schedules a fresh 2 to 20 s delay",
                onion && d >= WPR_DELAY_MIN_MS && d <= WPR_DELAY_MAX_MS &&
                    wprt_all(&f, "tx") == 0,
                &failures);
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    wprt_report("then exactly the onion peer receives it",
                onion && wprt_count(onion, "tx") == 1 &&
                    wprt_receivers(&f) == 1 && wprt_clearnet_silent(&f),
                &failures);
    wprt_close(&f);
    return failures;
}

/* Embedded Tor found a service registered in private mode: the one onion
 * peer stays connected, but nothing is pushed until the node is restarted. */
static int wprt_case_service_violated(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 1, false);
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct uint256 id;
    ok = ok && onion && wprt_rpc_send(&f, false, 10.0, &id);
    struct { void *hs_service; } minted = { (void *)&f };
    tor_integration_service_reset_for_test();
    bool eligible_before = onion && wpr_peer_eligible(onion);
    (void)tor_integration_service_step_for_test(&minted, false);
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    bool found = false;
    wprt_report("a registered onion service makes the connected onion peer "
                "ineligible and nothing is pushed",
                ok && eligible_before && !wpr_peer_eligible(onion) &&
                    wprt_all(&f, "tx") == 0 &&
                    wprt_state(&id, &found) == WPR_WAITING_FOR_ROUTE && found,
                &failures);
    tor_integration_service_reset_for_test();
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    wprt_report("with the violation cleared the same send reaches the peer",
                ok && onion && wprt_count(onion, "tx") == 1, &failures);
    wprt_close(&f);
    return failures;
}

static void wprt_seen_hook(struct wprt_fx *f, const struct uint256 *a,
                           bool ok, int *failures)
{
    /* The network offers it back: the node accepts it and the production
     * wallet hook fires. */
    struct wallet_tx wtx;
    bool have = ok && wprt_copy_tx(f, a, &wtx);
    struct boot_svc_ctx *svc = zcl_calloc(1, sizeof(*svc), "wprt_svc");
    if (have && svc) {
        svc->wallet = f->wallet;
        boot_wallet_tx_accepted(&wtx.tx, svc);
    }
    if (have)
        transaction_free(&wtx.tx);
    bool allocated = svc != NULL;
    free(svc);
    bool found = false;
    int state = -1, in_pool = -1; size_t pending = 0; bool pending_read = false;
    bool passed = ok && have && allocated &&
        (state = wprt_state(a, &found)) == WPR_SEEN && found &&
        !(in_pool = tx_mempool_exists(wpr_pool(wpr_global()), a)) &&
        (pending_read = true, pending = wprt_pending()) == 1;
    if (!passed)
        printf("[seen hook ok=%d copied=%d context=%d state=%d found=%d pool=%d pending_read=%d pending=%zu] ",
               ok, have, allocated, state, found, in_pool, pending_read, pending);
    wprt_report("the wallet tx-accepted hook clears the pending state and "
                "empties the private pool entry",
                passed,
                failures);
}

static void wprt_seen_block(struct wprt_fx *f, const struct uint256 *b,
                            bool ok, int *failures)
{
    /* The other transaction appears in a connected block. */
    struct wallet_tx wtx;
    bool have = ok && wprt_copy_tx(f, b, &wtx);
    struct uint256 bh;
    memset(bh.data, 0xB1, 32);
    struct block_index bi;
    memset(&bi, 0, sizeof(bi));
    bi.nHeight = 1;
    bi.phashBlock = &bh;
    if (have) {
        wallet_sync_transaction(f->wallet, &wtx.tx, &bi);
        transaction_free(&wtx.tx);
    }
    wprt_run(1000, -1);
    bool found = false;
    int state = -1, in_pool = -1; size_t pending = 0; bool pending_read = false;
    bool passed = ok && have && (state = wprt_state(b, &found)) == WPR_SEEN && found &&
        !(in_pool = tx_mempool_exists(wpr_pool(wpr_global()), b)) &&
        (pending_read = true, pending = wprt_pending()) == 0;
    if (!passed)
        printf("[block ok=%d copied=%d state=%d found=%d pool=%d pending_read=%d pending=%zu] ",
               ok, have, state, found, in_pool, pending_read, pending);
    wprt_report("inclusion in a block clears the pending state",
                passed,
                failures);
    size_t sent = wprt_all(f, "tx");
    wprt_run(1000 * 1000, -1);
    size_t after = 0; bool after_read = false;
    bool unchanged = ok && (after_read = true, after = wprt_all(f, "tx")) == sent;
    if (!unchanged) printf("[repush ok=%d sent=%zu after_read=%d after=%zu] ", ok, sent, after_read, after);
    wprt_report("a cleared send is never pushed again",
                unchanged, failures);
}

static int wprt_case_seen_and_block(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool wallet_ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, false);
    struct p2p_node *onion = wallet_ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct uint256 a, b;
    int send_a = -1, send_b = -1; size_t count = 0; bool count_read = false;
    bool ok = wallet_ok && onion && (send_a = wprt_rpc_send(&f, false, 10.0, &a)) &&
              (send_b = wprt_rpc_send(&f, true, 10.0, &b));
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    ok = ok && (count_read = true, count = wprt_count(onion, "tx")) == 2;
    if (!ok)
        printf("[seen setup wallet=%d peer=%d send_a=%d send_b=%d count_read=%d tx_count=%zu] ",
               wallet_ok, onion != NULL, send_a, send_b, count_read, count);
    wprt_seen_hook(&f, &a, ok, &failures);
    wprt_seen_block(&f, &b, ok, &failures);
    wprt_close(&f);
    return failures;
}

/* ── expiry: the wallet height, the margin, the real databases ─────── */

static uint32_t wprt_expiry_of(struct wprt_fx *f, const struct uint256 *id,
                               struct outpoint *spent)
{
    struct wallet_tx wtx;
    uint32_t e = 0;
    if (wprt_copy_tx(f, id, &wtx)) {
        e = wtx.tx.expiry_height;
        if (spent && wtx.tx.num_vin)
            *spent = wtx.tx.vin[0].prevout;
        transaction_free(&wtx.tx);
    }
    return e;
}

static void wprt_tick_at_height(struct wprt_fx *f, int height)
{
    wprt_set_wallet_height(f, height);
    wallet_private_broadcast_tick();
    wprt_revive_peers();
}

static bool wprt_pending_and_reserved(struct wprt_fx *f,
                                      const struct uint256 *id,
                                      const struct outpoint *spent)
{
    bool found = false;
    return wprt_state(id, &found) != WPR_EXPIRED && found &&
           wprt_pending() == 1 &&
           wallet_is_outpoint_spent(f->wallet, &spent->hash, spent->n);
}

/* A wallet send is rolled back only once the wallet has read past its
 * expiry height plus the margin; the chain's next-block lookahead is not
 * enough. */
static int wprt_case_expiry_margin(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, false);
    wprt_overwinter_on(&f);
    struct uint256 id;
    struct outpoint spent;
    memset(&spent, 0, sizeof(spent));
    ok = ok && wprt_add_peer(&f, WPRT_ONION_OUT) &&
         wprt_rpc_send(&f, false, 10.0, &id);
    int e = (int)wprt_expiry_of(&f, &id, &spent);
    wprt_report("a wallet send carries an expiry height", ok && e > 0,
                &failures);
    wprt_tick_at_height(&f, e + 1);
    wprt_report("one block past expiry (the chain lookahead) is not enough",
                ok && wprt_pending_and_reserved(&f, &id, &spent), &failures);
    wprt_tick_at_height(&f, e + WPR_EXPIRY_MARGIN_BLOCKS);
    wprt_report("the full margin past expiry is still not enough",
                ok && wprt_pending_and_reserved(&f, &id, &spent), &failures);
    wprt_tick_at_height(&f, e + WPR_EXPIRY_MARGIN_BLOCKS + 1);
    bool found = false;
    wprt_report("past the margin the send is rolled back, its input returns "
                "and a terminal expired record remains",
                ok && wprt_state(&id, &found) == WPR_EXPIRED && found &&
                    wprt_pending() == 0 &&
                    !wallet_is_outpoint_spent(f.wallet, &spent.hash, spent.n) &&
                    !tx_mempool_exists(wpr_pool(wpr_global()), &id),
                &failures);
    wprt_close(&f);
    return failures;
}

/* A send the wallet shows confirmed is never rolled back, even when the
 * relay had already flagged it. */
static int wprt_case_expiry_confirmed(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, false);
    wprt_overwinter_on(&f);
    struct uint256 id;
    struct outpoint spent;
    memset(&spent, 0, sizeof(spent));
    ok = ok && wprt_add_peer(&f, WPRT_ONION_OUT) &&
         wprt_rpc_send(&f, false, 10.0, &id);
    int e = (int)wprt_expiry_of(&f, &id, &spent);
    struct wallet_tx wtx;
    struct uint256 bh;
    memset(bh.data, 0xB2, 32);
    struct block_index bi;
    memset(&bi, 0, sizeof(bi));
    bi.nHeight = e;
    bi.phashBlock = &bh;
    bool have = ok && wprt_copy_tx(&f, &id, &wtx);
    wprt_set_wallet_height(&f, e);
    if (have) {
        wallet_sync_transaction(f.wallet, &wtx.tx, &bi);
        transaction_free(&wtx.tx);
    }
    bool expired_now = wallet_private_broadcast_expire(&id);
    bool found = false;
    wprt_report("a send mined at its expiry height is not rolled back, even "
                "when the expiry path runs for it",
                ok && have && !expired_now &&
                    wprt_state(&id, &found) == WPR_SEEN && found &&
                    wallet_is_outpoint_spent(f.wallet, &spent.hash, spent.n),
                &failures);
    wprt_tick_at_height(&f, e + WPR_EXPIRY_MARGIN_BLOCKS + 50);
    struct wallet_tx still;
    bool kept = wprt_copy_tx(&f, &id, &still);
    if (kept)
        transaction_free(&still.tx);
    wprt_report("and the wallet record survives long after the margin", kept,
                &failures);
    wprt_close(&f);
    return failures;
}

static bool wprt_db_coin_state(struct wprt_fx *f, const struct uint256 *coin,
                               const struct uint256 *spender, bool want_spent)
{
    struct db_wallet_utxo u;
    memset(&u, 0, sizeof(u));
    if (!db_wallet_utxo_find(&f->ndb, coin->data, 0, &u))
        return false;
    bool spent_by = memcmp(u.spent_txid, spender->data, 32) == 0;
    bool ok = want_spent ? (u.is_spent && spent_by) : !u.is_spent;
    db_wallet_utxo_free(&u);
    return ok;
}

static bool wprt_db_spendable(struct wprt_fx *f, size_t coins)
{
    struct db_wallet_utxo list[8];
    int n = db_wallet_utxo_list_unspent(&f->ndb, list, 8);
    int64_t balance = db_wallet_utxo_balance(&f->ndb);
    for (int i = 0; i < n; i++)
        db_wallet_utxo_free(&list[i]);
    return n == (int)coins && balance == (int64_t)coins * WPRT_UTXO;
}

static void wprt_expiry_db_before(struct wprt_fx *f, const struct uint256 *id,
                                  const struct outpoint *spent, bool ok,
                                  int *failures)
{
    wprt_report("before expiry the database shows the funding coin spent by "
                "the send and its output rows",
                ok && wprt_db_coin_state(f, &spent->hash, id, true) &&
                    db_wallet_utxo_count_for_tx(&f->ndb, id->data) >= 1 &&
                    !wprt_db_spendable(f, f->num_funding),
                failures);
}

static void wprt_expiry_db_after(struct wprt_fx *f, const struct uint256 *id,
                                 const struct outpoint *spent, bool ok,
                                 int *failures)
{
    struct db_wallet_tx row;
    memset(&row, 0, sizeof(row));
    bool row_gone = !db_wallet_tx_find(&f->ndb, id->data, &row);
    wprt_report("after expiry the database releases the funding coin and "
                "drops the send's output rows and wallet row, so "
                "listunspent sees every coin again",
                ok && wprt_db_coin_state(f, &spent->hash, id, false) &&
                    db_wallet_utxo_count_for_tx(&f->ndb, id->data) == 0 &&
                    row_gone && wprt_db_spendable(f, f->num_funding),
                failures);
}

static void wprt_expiry_status(struct wprt_fx *f, const struct uint256 *id,
                               bool ok, int *failures)
{
    struct json_value st;
    bool have = ok && wprt_status_json(f, &st);
    const struct json_value *e = have ? wprt_status_entry(&st, id) : NULL;
    wprt_report("the status read reports the terminal expired state and says "
                "the payment may be sent again with a new key",
                ok && wprt_status_says(f, id, "expired", "new key"),
                failures);
    wprt_report("the status read carries no amount or address",
                e && !json_get(e, "amount") && !json_get(e, "address") &&
                    json_get(&st, "mode") && json_get(&st, "expired"),
                failures);
    if (have)
        json_free(&st);
}

/* A real node database and wallet database behind the real handlers. */
static int wprt_case_expiry_database(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, true);
    wprt_overwinter_on(&f);
    struct uint256 id;
    struct outpoint spent;
    memset(&spent, 0, sizeof(spent));
    ok = ok && wprt_add_peer(&f, WPRT_ONION_OUT) &&
         wprt_rpc_send(&f, false, 10.0, &id);
    int e = (int)wprt_expiry_of(&f, &id, &spent);
    wprt_expiry_db_before(&f, &id, &spent, ok, &failures);
    wprt_tick_at_height(&f, e + WPR_EXPIRY_MARGIN_BLOCKS + 1);
    wprt_expiry_db_after(&f, &id, &spent, ok, &failures);
    wprt_expiry_status(&f, &id, ok, &failures);
    wprt_close(&f);
    return failures;
}

/* ── restart ────────────────────────────────────────────────────────── */

static void wprt_resume_reports(struct wprt_fx *f, struct wpr *r,
                                const struct uint256 *id,
                                struct p2p_node *clear,
                                struct p2p_node *onion, bool ok,
                                int *failures)
{
    bool resumed = false;
    wprt_report("resume succeeds for a restarted relay",
                (resumed = ok && wpr_resume(r).ok), failures);
    int64_t d = wprt_due_delay(id);
    wprt_report("resume revalidates into the private pool with a fresh "
                "2 to 20 s delay; the main mempool stays empty",
                resumed && wprt_pending() == 1 &&
                    tx_mempool_exists(wpr_pool(r), id) &&
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

static void wprt_restart_relay(struct wprt_fx *f)
{
    struct wpr_env env = wpr_global()->env;
    env.datadir = f->dir;
    struct wpr *r = wpr_global();
    wpr_free(r);
    wpr_init(r);
    r->now_ms = wprt_clock;
    r->random_bytes = wprt_rng;
    wpr_configure(r, WPR_MODE_PRIVATE, &env);
}

static int wprt_case_restart(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 1, false);
    struct p2p_node *clear = ok ? wprt_add_peer(&f, WPRT_CLEAR_OUT) : NULL;
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct uint256 id;
    ok = ok && clear && onion && wprt_rpc_send(&f, false, 10.0, &id);
    /* Restart: a fresh relay instance reads the durable pending set. The
     * wallet transaction and chain state persist; peers reconnect. */
    wprt_restart_relay(&f);
    wprt_report("a restarted relay holds nothing before it resumes",
                wprt_pending() == 0 &&
                    !tx_mempool_exists(wpr_pool(wpr_global()), &id),
                &failures);
    wprt_resume_reports(&f, wpr_global(), &id, clear, onion, ok, &failures);
    wprt_close(&f);
    return failures;
}

/* A held send restarted in public mode: the ticker still runs, nothing is
 * pushed, and the send still expires and returns its coins. */
static bool wprt_wait_state(const struct uint256 *id, enum wpr_state want,
                            int seconds)
{
    bool found = false;
    for (int i = 0; i < seconds * 10; i++) {
        if (wprt_state(id, &found) == want && found)
            return true;
        platform_sleep_ms(100);
    }
    return false;
}

static void wprt_public_restart_steps(struct wprt_fx *f,
                                      const struct uint256 *id,
                                      struct p2p_node *onion, int expiry,
                                      const struct outpoint *spent, bool ok,
                                      int *failures)
{
    atomic_fetch_add(&wprt_now, 60 * 1000);
    platform_sleep_ms(2500);
    wprt_report("a public-mode restart resumes the held send and sends "
                "nothing, though an onion peer is connected",
                ok && wpr_get_mode(wpr_global()) == WPR_MODE_PUBLIC &&
                    wprt_pending() == 1 && wprt_total_bytes(onion) == 0 &&
                    wprt_all(f, "tx") == 0,
                failures);
    wprt_set_wallet_height(f, expiry + WPR_EXPIRY_MARGIN_BLOCKS + 1);
    bool expired = wprt_wait_state(id, WPR_EXPIRED, 8);
    wprt_report("the ticker still expires it after a public-mode restart: "
                "the coins return and no pending record is left",
                ok && expired && wprt_pending() == 0 &&
                    !wallet_is_outpoint_spent(f->wallet, &spent->hash,
                                              spent->n) &&
                    wprt_total_bytes(onion) == 0,
                failures);
}

static int wprt_case_public_restart(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, false);
    wprt_overwinter_on(&f);
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct uint256 id;
    struct outpoint spent;
    memset(&spent, 0, sizeof(spent));
    ok = ok && onion && wprt_rpc_send(&f, false, 10.0, &id);
    int e = (int)wprt_expiry_of(&f, &id, &spent);
    struct wpr_env env = wpr_global()->env;
    env.datadir = f.dir;
    struct wpr *r = wpr_global();
    wpr_free(r);
    wpr_init(r);
    r->now_ms = wprt_clock;
    r->random_bytes = wprt_rng;
    ok = ok && wallet_private_broadcast_start(WPR_MODE_PUBLIC, &env);
    wprt_public_restart_steps(&f, &id, onion, e, &spent, ok, &failures);
    wallet_private_broadcast_stop();
    wprt_close(&f);
    return failures;
}

/* ── boot: private broadcast needs onion-only networking ──────────── */

static bool wprt_boot_try(struct wprt_fx *f, int mode, bool onlynet,
                          const char *external_ip)
{
    struct app_context *ctx = zcl_calloc(1, sizeof(*ctx), "wprt_app");
    struct boot_svc_ctx *svc = zcl_calloc(1, sizeof(*svc), "wprt_svc");
    bool started = false;
    if (ctx && svc) {
        ctx->wallet_broadcast = mode;
        ctx->onlynet_onion = onlynet;
        ctx->external_ip = external_ip;
        ctx->datadir = f->dir;
        svc->wallet = f->wallet;
        svc->connman = &f->cm;
        svc->coins_tip = &f->coins;
        svc->state = &f->ms;
        started = boot_start_wallet_broadcast(svc, ctx, f->params);
    }
    free(ctx);
    free(svc);
    return started;
}

static int wprt_case_boot(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PUBLIC);
    bool no_onlynet = ok && !wprt_boot_try(&f, 1, false, NULL);
    bool no_extip = ok && !wprt_boot_try(&f, 1, true, "198.51.100.7:8033");
    wprt_report("private broadcast without -onlynet=onion is refused at boot",
                no_onlynet && wpr_get_mode(wpr_global()) == WPR_MODE_PUBLIC,
                &failures);
    wprt_report("private broadcast with -externalip is refused at boot",
                no_extip && wpr_get_mode(wpr_global()) == WPR_MODE_PUBLIC,
                &failures);
    bool private_ok = ok && wprt_boot_try(&f, 1, true, NULL);
    enum wpr_mode m1 = wpr_get_mode(wpr_global());
    wallet_private_broadcast_stop();
    struct wallet_tx_admission main_adm = wprt_admission(&f, &f.main_pool);
    bool main_refused = !wallet_admission_pool_check(&main_adm).ok;
    wprt_report("private broadcast with onion-only networking starts, and "
                "from then on the main pool is refused to the wallet",
                private_ok && m1 == WPR_MODE_PRIVATE && main_refused,
                &failures);
    bool default_ok = ok && wprt_boot_try(&f, 0, false, NULL);
    enum wpr_mode m2 = wpr_get_mode(wpr_global());
    wallet_private_broadcast_stop();
    wprt_report("the default is public relay, with or without onion-only, and the main pool is accepted",
                default_ok && m2 == WPR_MODE_PUBLIC &&
                    wallet_admission_pool_check(&main_adm).ok, &failures);
    wprt_close(&f);
    return failures;
}

static bool wprt_write_pending_bytes(const char *dir, const char *bytes, size_t len)
{
    return authority_receipt_write_atomic(dir, "wallet_private_relay.pending",
                                           (const uint8_t *)bytes, len, NULL, 0);
}

static void wprt_pending_failure_cases(struct wprt_fx *f, char *record, int n, int *failures)
{
    struct wpr_pending_record rows[2]; size_t count = 0;
    record[n - 2] = 'z';
    bool ok = wprt_write_pending_bytes(f->dir, record, (size_t)n);
    enum wpr_pending_read_status s = wpr_pending_snapshot(wpr_global(), rows, 2, &count);
    wprt_report("checked pending reader refuses malformed data", ok && s == WPR_PENDING_MALFORMED && count == 0, failures);
    char path[512]; snprintf(path, sizeof(path), "%s/wallet_private_relay.pending", f->dir);
    ok = platform_private_file_unlink_missing_ok(path) && platform_private_directory_create(path);
    s = wpr_pending_snapshot(wpr_global(), rows, 2, &count);
    wprt_report("checked pending reader distinguishes I/O error", ok && s == WPR_PENDING_IO_ERROR && count == 0, failures);
    if (ok) (void)platform_private_directory_remove_empty(path);
}

static int wprt_case_invalid_pending_count(void)
{
    int failures = 0;
    size_t count = 99;
    enum wpr_pending_read_status status = wpr_pending_snapshot(NULL, NULL, 0, &count);
    wprt_report("invalid pending snapshot clears count", status == WPR_PENDING_IO_ERROR && count == 0, &failures);
    count = 99;
    status = wpr_pending_proof_begin(NULL, NULL, NULL, 0, &count);
    wprt_report("invalid pending proof clears count", status == WPR_PENDING_IO_ERROR && count == 0, &failures);
    return failures;
}

static int wprt_case_checked_pending_reader(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PUBLIC);
    if (!ok) { wprt_close(&f); return 1; }
    struct wpr_pending_record rows[2]; size_t count = 99;
    enum wpr_pending_read_status s = wpr_pending_snapshot(wpr_global(), rows, 2, &count);
    wprt_report("checked pending reader distinguishes absent", s == WPR_PENDING_ABSENT && count == 0, &failures);
    char record[128];
    int n = snprintf(record, sizeof(record), "# wallet_private_relay v1\n%064x\n", 1);
    ok = n > 0 && (size_t)n < sizeof(record) && wprt_write_pending_bytes(f.dir, record, (size_t)n);
    s = wpr_pending_snapshot(wpr_global(), rows, 2, &count);
    struct uint256 expected; uint256_set_hex(&expected, "0000000000000000000000000000000000000000000000000000000000000001");
    wprt_report("checked pending reader preserves exact record", ok && s == WPR_PENDING_OK && count == 1 &&
        uint256_eq(&rows[0].txid, &expected) && !rows[0].expired && !rows[0].handed, &failures);
    s = wpr_pending_snapshot(wpr_global(), rows, 0, &count);
    wprt_report("checked pending reader refuses bounded overflow", s == WPR_PENDING_OVERFLOW && count == 0, &failures);
    if (n > 1) wprt_pending_failure_cases(&f, record, n, &failures);
    wprt_close(&f);
    return failures;
}

static int wprt_case_pending_guard_bound(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PUBLIC);
    if (!ok) { wprt_close(&f); return 1; }
    char file[sizeof("# wallet_private_relay v1\n") + (WPR_MAX_ENTRIES + 1) * 65];
    int first = snprintf(file, sizeof(file), "# wallet_private_relay v1\n");
    size_t used = first > 0 ? (size_t)first : sizeof(file);
    for (unsigned i = 0; ok && i <= WPR_MAX_ENTRIES; ++i) {
        int n = snprintf(file + used, sizeof(file) - used, "%064x\n", i + 1);
        ok = n == 65 && (size_t)n < sizeof(file) - used;
        if (ok) used += (size_t)n;
    }
    ok = ok && wprt_write_pending_bytes(f.dir, file, used);
    struct wpr_pending_record rows[WPR_MAX_ENTRIES + 1];
    struct wpr_pending_guard guard = {0}; size_t count = 99;
    enum wpr_pending_read_status status = ok ? wpr_pending_proof_begin(
        wpr_global(), &guard, rows, WPR_MAX_ENTRIES + 1, &count) : WPR_PENDING_IO_ERROR;
    wprt_report("held proof refuses records beyond its fixed bound", ok &&
        status == WPR_PENDING_OVERFLOW && !guard.relay && count == 0, &failures);
    wpr_pending_proof_end(&guard);
    wprt_close(&f);
    return failures;
}

struct wprt_guard_probe { enum wpr_pending_read_status status; };
static void *wprt_guard_try(void *arg)
{
    struct wprt_guard_probe *probe = arg;
    struct wpr_pending_guard guard = {0};
    struct wpr_pending_record rows[1];
    size_t count = 0;
    probe->status = wpr_pending_proof_begin(wpr_global(), &guard, rows, 1, &count);
    wpr_pending_proof_end(&guard);
    return NULL;
}

static int wprt_case_pending_guard(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PUBLIC);
    if (!ok) { wprt_close(&f); return 1; }
    struct wpr_pending_guard guard = {0};
    struct wpr_pending_record rows[1]; size_t count = 1;
    enum wpr_pending_read_status status = wpr_pending_proof_begin(wpr_global(), &guard, rows, 1, &count);
    struct wprt_guard_probe probe = {0}; pthread_t thread;
    bool started = status == WPR_PENDING_ABSENT && guard.relay &&
        pthread_create(&thread, NULL, wprt_guard_try, &probe) == 0;
    if (started) (void)pthread_join(thread, NULL);
    wprt_report("held pending proof excludes concurrent relay writer", started && probe.status == WPR_PENDING_BUSY, &failures);
    wpr_pending_proof_end(&guard);
    count = 1;
    status = wpr_pending_proof_begin(wpr_global(), &guard, rows, 1, &count);
    wprt_report("released pending proof can be reacquired", status == WPR_PENDING_ABSENT && guard.relay && count == 0, &failures);
    wpr_pending_proof_end(&guard);
    wpr_global()->persist_dirty = true;
    status = wpr_pending_proof_begin(wpr_global(), &guard, rows, 1, &count);
    wprt_report("dirty relay state refuses proof", status == WPR_PENDING_IO_ERROR && !guard.relay, &failures);
    wpr_global()->persist_dirty = false;
    struct uint256 id = {0}; id.data[0] = 1;
    char path[512]; snprintf(path, sizeof(path), "%s/wallet_private_relay.pending", f.dir);
    ok = wpr_prepare(wpr_global(), &id).ok && platform_private_file_unlink_missing_ok(path);
    status = wpr_pending_proof_begin(wpr_global(), &guard, rows, 1, &count);
    wprt_report("in-memory hold missing from durable file refuses proof", ok && status == WPR_PENDING_IO_ERROR && !guard.relay, &failures);
    wprt_close(&f);
    return failures;
}

static bool wprt_hook_state_unchanged(const struct wprt_fx *f, const struct uint256 *id,
                                      enum wpr_state before, bool found)
{
    bool after_found = false;
    enum wpr_state after = wprt_state(id, &after_found);
    const struct wallet_tx *stored = wallet_get_tx(f->wallet, id);
    return found && after_found && before == after && f->wallet->num_wallet_tx == 1 &&
        stored && stored->confirms == 8 && tx_mempool_exists(wpr_pool(wpr_global()), id);
}

static int wprt_case_unready_accepted_hook(bool pending)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 1, false);
    struct uint256 id = {0};
    ok = ok && wprt_rpc_send(&f, false, 10.0, &id);
    struct wallet_tx snapshot;
    bool copied = ok && wprt_copy_tx(&f, &id, &snapshot);
    bool found = false;
    enum wpr_state before = copied ? wprt_state(&id, &found) : WPR_SEEN;
    wallet_free(f.wallet);
    wallet_init(f.wallet);
    if (pending) ok = ok && wallet_readiness_initialize(f.wallet, WALLET_READINESS_PENDING, true, 42);
    if (copied) { snapshot.confirms = 8; ok = ok && wallet_add_to_wallet(f.wallet, &snapshot); }
    struct boot_svc_ctx *svc = zcl_calloc(1, sizeof(*svc), "wprt_pending_svc");
    if (copied && svc) {
        svc->wallet = f.wallet;
        boot_wallet_tx_accepted(&snapshot.tx, svc);
    }
    bool unchanged = wprt_hook_state_unchanged(&f, &id, before, found);
    wprt_report(pending ? "pending tx callback leaves wallet and relay unchanged" :
                          "unknown tx callback leaves wallet and relay unchanged",
        ok && copied && svc && unchanged, &failures);
    if (copied) transaction_free(&snapshot.tx);
    free(svc);
    wprt_close(&f);
    return failures;
}

static bool wprt_held_record_matches(const char *dir, const char *record, size_t len)
{
    char path[512], actual[128] = {0};
    snprintf(path, sizeof(path), "%s/wallet_private_relay.pending", dir);
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    size_t n = fread(actual, 1, sizeof(actual), fp);
    bool closed = fclose(fp) == 0;
    return closed && n == len && memcmp(actual, record, n) == 0;
}

static int wprt_case_unready_boot_configuration(bool pending)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PUBLIC);
    if (!ok) { wprt_close(&f); return 1; }
    wallet_free(f.wallet);
    wallet_init(f.wallet);
    if (pending)
        ok = wallet_readiness_initialize(f.wallet, WALLET_READINESS_PENDING, true, 42);
    char record[128];
    int len = snprintf(record, sizeof(record), "# wallet_private_relay v1\n%064x\n", 1);
    ok = ok && len > 0 && (size_t)len < sizeof(record) &&
        authority_receipt_write_atomic(f.dir, "wallet_private_relay.pending",
                                       (const uint8_t *)record, (size_t)len, NULL, 0);
    bool configured = ok && wprt_boot_try(&f, 1, true, NULL);
    struct wallet_tx_admission main_adm = wprt_admission(&f, &f.main_pool);
    wprt_report(pending ? "pending boot configures private pool without resuming held sends" :
        "unknown boot configures private pool without resuming held sends",
        configured && wpr_get_mode(wpr_global()) == WPR_MODE_PRIVATE &&
        !wallet_admission_pool_check(&main_adm).ok && wprt_pending() == 0 &&
        wprt_held_record_matches(f.dir, record, (size_t)len), &failures);
    wallet_private_broadcast_stop();
    wprt_close(&f);
    return failures;
}

/* ── a send the chain may already hold ──────────────────────────────── */

/* The chain consumed the funding coin in a block the wallet never read. */
static void wprt_chain_consumes(struct wprt_fx *f, const struct outpoint *spent)
{
    struct coins_cache_entry *e =
        coins_view_cache_modify(&f->coins, &spent->hash);
    if (e)
        coins_spend(&e->coins, spent->n);
}

static bool wprt_status_next_has(struct wprt_fx *f, const struct uint256 *id,
                                 const char *part)
{
    struct json_value st;
    bool have = wprt_status_json(f, &st);
    const struct json_value *e = have ? wprt_status_entry(&st, id) : NULL;
    const char *n = e ? wprt_jstr(json_get(e, "next_step")) : NULL;
    bool ok = n && strstr(n, part);
    if (have)
        json_free(&st);
    return ok;
}

static bool wprt_record_kept(struct wprt_fx *f, const struct uint256 *id,
                             const struct outpoint *spent)
{
    bool found = false;
    struct wallet_tx still;
    bool in_wallet = wprt_copy_tx(f, id, &still);
    if (in_wallet)
        transaction_free(&still.tx);
    return in_wallet && wprt_state(id, &found) != WPR_EXPIRED && found &&
           wallet_is_outpoint_spent(f->wallet, &spent->hash, spent->n);
}

/* Sent, the node went off, the send was mined, the wallet skipped the block
 * and later reads past the margin with no confirmation: the coins must not
 * come back, because the payment could be made twice. */
static int wprt_case_expiry_unverified(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, false);
    wprt_overwinter_on(&f);
    struct uint256 id;
    struct outpoint spent;
    memset(&spent, 0, sizeof(spent));
    ok = ok && wprt_add_peer(&f, WPRT_ONION_OUT) &&
         wprt_rpc_send(&f, false, 10.0, &id);
    int e = (int)wprt_expiry_of(&f, &id, &spent);
    wprt_chain_consumes(&f, &spent);
    wprt_tick_at_height(&f, e + WPR_EXPIRY_MARGIN_BLOCKS + 1);
    wprt_report("a send whose input the chain has spent is not rolled back, "
                "though the wallet never read the block",
                ok && wprt_record_kept(&f, &id, &spent), &failures);
    wprt_report("the status says it may be on chain and not to pay again",
                ok && wprt_status_next_has(&f, &id,
                                           "Do not send the payment again"),
                &failures);
    atomic_fetch_add(&wprt_now, (WPR_RETRY_S + 1) * 1000);
    wprt_tick_at_height(&f, e + WPR_EXPIRY_MARGIN_BLOCKS + 500);
    wprt_report("a later tick, far past the margin, still keeps the record",
                ok && wprt_record_kept(&f, &id, &spent), &failures);
    wprt_close(&f);
    return failures;
}

/* ── disk full at expiry ────────────────────────────────────────────── */

/* The database refuses the row delete. Memory is rolled back, so the next tick
 * must not mistake that for a finished rollback. */
static int wprt_case_expiry_disk_full(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, true);
    wprt_overwinter_on(&f);
    struct uint256 id;
    struct outpoint spent;
    memset(&spent, 0, sizeof(spent));
    ok = ok && wprt_add_peer(&f, WPRT_ONION_OUT) &&
         wprt_rpc_send(&f, false, 10.0, &id);
    int e = (int)wprt_expiry_of(&f, &id, &spent);
    f.ndb.open = false;
    wprt_tick_at_height(&f, e + WPR_EXPIRY_MARGIN_BLOCKS + 1);
    bool found = false;
    wprt_report("a failed row delete does not mark the send expired",
                ok && wprt_state(&id, &found) != WPR_EXPIRED && found,
                &failures);
    atomic_fetch_add(&wprt_now, (WPR_RETRY_S + 1) * 1000);
    wprt_tick_at_height(&f, e + WPR_EXPIRY_MARGIN_BLOCKS + 2);
    wprt_report("a second tick with the database still refusing does not "
                "either, and the status says it is retried",
                ok && wprt_state(&id, &found) != WPR_EXPIRED && found &&
                    wprt_status_next_has(&f, &id, "retried"),
                &failures);
    f.ndb.open = true;
    atomic_fetch_add(&wprt_now, (WPR_RETRY_S + 1) * 1000);
    wprt_tick_at_height(&f, e + WPR_EXPIRY_MARGIN_BLOCKS + 3);
    struct db_wallet_tx row;
    memset(&row, 0, sizeof(row));
    wprt_report("once the database accepts writes the retry deletes the row, "
                "releases the coin and marks the send expired",
                ok && wprt_state(&id, &found) == WPR_EXPIRED && found &&
                    !db_wallet_tx_find(&f.ndb, id.data, &row) &&
                    wprt_db_coin_state(&f, &spent.hash, &id, false),
                &failures);
    wprt_close(&f);
    return failures;
}

/* ── record before the wallet writes ────────────────────────────────── */

/* The same funnel the send paths use, stopped before anything queues it:
 * the state a power loss leaves behind. */
static bool wprt_commit_unqueued(struct wprt_fx *f, struct uint256 *id,
                                 struct zcl_result *commit)
{
    char addr[128];
    struct tx_destination dest;
    struct wallet_tx wtx;
    int64_t fee = 0;
    const char *error = NULL;
    if (!wprt_self_address(f, addr, sizeof(addr)) ||
        !wallet_decode_address(addr, &dest) ||
        !wallet_create_transaction(f->wallet, &dest, 10 * COIN_VALUE, &wtx,
                                   &fee, &error))
        return false;
    struct wallet_rpc_context sv;
    struct wallet_rpc_context *ctx = wallet_send_view(
        wallet_rpc_context_current(), &sv);
    *id = wtx.tx.hash;
    *commit = wallet_commit_from_context(ctx, &wtx);
    transaction_free(&wtx.tx);
    return true;
}

static int wprt_case_prepared_before_wallet(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, false);
    struct p2p_node *clear = ok ? wprt_add_peer(&f, WPRT_CLEAR_OUT) : NULL;
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct uint256 id;
    struct zcl_result commit = ZCL_OK;
    ok = ok && clear && onion && wprt_commit_unqueued(&f, &id, &commit) &&
         commit.ok;
    bool found = false;
    wprt_report("the send is already recorded when the wallet has admitted it, "
                "before anything queued it",
                ok && wprt_state(&id, &found) == WPR_PREPARED && found,
                &failures);
    /* Power loss here: the wallet holds the send, the queue never saw it. */
    wprt_restart_relay(&f);
    wprt_resume_reports(&f, wpr_global(), &id, clear, onion, ok, &failures);
    wprt_close(&f);
    return failures;
}

/* When the record cannot be made durable the wallet must not admit the send. */
static int wprt_case_record_refused(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, false);
    snprintf(wpr_global()->datadir, sizeof(wpr_global()->datadir), "%s",
             "/nonexistent/wallet-private-relay");
    struct uint256 id;
    struct zcl_result commit = ZCL_OK;
    bool ran = ok && wprt_commit_unqueued(&f, &id, &commit);
    struct wallet_tx held;
    bool in_wallet = ran && wprt_copy_tx(&f, &id, &held);
    if (in_wallet)
        transaction_free(&held.tx);
    wprt_report("a send whose record cannot be made durable is refused: not "
                "admitted to the wallet or either pool",
                ran && !commit.ok && !in_wallet && wprt_pending() == 0 &&
                    tx_mempool_size(&f.main_pool) == 0 &&
                    tx_mempool_size(wpr_pool(wpr_global())) == 0,
                &failures);
    wprt_close(&f);
    return failures;
}

/* ── transactions the private mode cannot protect ───────────────────── */

static bool wprt_error_is_typed(const struct json_value *r)
{
    const char *s = wprt_jstr(r);
    return s && strncmp(s, "PRIVATE_BROADCAST_UNSUPPORTED", 29) == 0;
}

static bool wprt_raw_send(struct wprt_fx *f, struct json_value *result)
{
    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    wprt_json_str(&params, "00");
    json_init(result);
    bool ok = rpc_table_execute(&f->tbl, "sendrawtransaction", &params,
                                result);
    json_free(&params);
    return ok;
}

static int wprt_case_unsupported(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 1, false);
    register_rawtransaction_rpc_commands(&f.tbl);
    struct p2p_node *clear = ok ? wprt_add_peer(&f, WPRT_CLEAR_OUT) : NULL;
    struct json_value r1, r2;
    bool ran1 = ok && !wprt_raw_send(&f, &r1);
    wprt_report("sendrawtransaction is refused with a typed error in private "
                "mode and nothing reaches a peer",
                ran1 && wprt_error_is_typed(&r1) &&
                    wprt_total_bytes(clear) == 0 &&
                    tx_mempool_size(&f.main_pool) == 0,
                &failures);
    wprt_report("the refusal helper is typed in private mode",
                !wallet_private_broadcast_unsupported("a swap").ok &&
                    wallet_private_broadcast_unsupported("a swap").code ==
                        WALLET_PBCAST_UNSUPPORTED_CODE,
                &failures);
    struct wpr_env env = wpr_global()->env;
    wpr_configure(wpr_global(), WPR_MODE_PUBLIC, &env);
    bool ran2 = ok && !wprt_raw_send(&f, &r2);
    wprt_report("in public mode the same call is not refused for that reason",
                ran2 && !wprt_error_is_typed(&r2) &&
                    wallet_private_broadcast_unsupported("a swap").ok,
                &failures);
    if (ran1)
        json_free(&r1);
    if (ran2)
        json_free(&r2);
    wprt_close(&f);
    return failures;
}

/* ── chained sends ──────────────────────────────────────────────────── */

static void wprt_chain_reports(struct wprt_fx *f, const struct uint256 *a,
                               const struct uint256 *b, bool ok,
                               int *failures)
{
    struct wallet_tx s1, s2;
    bool have = ok && wprt_copy_tx(f, a, &s1);
    bool have2 = have && wprt_copy_tx(f, b, &s2);
    wprt_report("a second send validates against the private pool and spends "
                "a different coin",
                have2 && memcmp(&s1.tx.vin[0].prevout, &s2.tx.vin[0].prevout,
                                sizeof(struct outpoint)) != 0 &&
                    tx_mempool_size(wpr_pool(wpr_global())) == 2 &&
                    tx_mempool_size(&f->main_pool) == 0 && wprt_pending() == 2,
                failures);
    struct uint256 c;
    bool third = ok && wprt_rpc_send(f, false, 60.0, &c);
    wprt_report("a third send does not reselect either reserved coin",
                ok && have2 && !third, failures);
    /* The private pool itself refuses a double spend of a pending input. */
    struct wallet_tx dup;
    bool built = have && wprt_build(f, 0x5A, NULL, 0, &dup);
    enum mempool_accept_result ar = MEMPOOL_ACCEPT_OK;
    if (built) {
        dup.tx.vin[0].prevout = s1.tx.vin[0].prevout;
        transaction_compute_hash(&dup.tx);
        ar = accept_to_mempool(wpr_pool(wpr_global()), &f->coins, &f->ms,
                               f->params, &dup.tx);
        transaction_free(&dup.tx);
    }
    wprt_report("the private pool rejects a conflicting spend of a pending "
                "input",
                built && ar != MEMPOOL_ACCEPT_OK, failures);
    if (have)
        transaction_free(&s1.tx);
    if (have2)
        transaction_free(&s2.tx);
}

static int wprt_case_chained(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, false);
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct uint256 a, b;
    ok = ok && onion && wprt_rpc_send(&f, false, 60.0, &a) &&
         wprt_rpc_send(&f, true, 60.0, &b);
    wprt_chain_reports(&f, &a, &b, ok, &failures);
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    wprt_report("both chained sends reach the one onion peer and nobody else",
                ok && wprt_count(onion, "tx") == 2 && wprt_clearnet_silent(&f),
                &failures);
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
static bool wprt_second_node_accepts(struct wprt_fx *f,
                                     struct coins_view_cache *view,
                                     struct main_state *ms_in,
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
        msg_processor_init(mp2, ms_in ? ms_in : &ms2, &pool2, view, p, f->dir, &nm, NULL);
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

static void wprt_probe_delivery(struct wprt_fx *f, struct coins_view_cache *view,
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
                ok && onion && wprt_second_node_accepts(f, view, NULL, p, onion, tx),
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
    wprt_probe_delivery(&f, &s->view, &p, clear, onion, tx, ok, &failures);
    wprt_close(&f);
    return failures;
}


/* ── the real wallet shielded send, private mode ────────────────────── */

static bool wprt_leg_second_coin(const struct wallet_private_relay_leg *l)
{
    struct uint256 txid;
    memset(&txid, 0, sizeof(txid));
    txid.data[0] = 0x66;
    txid.data[31] = 0x42;
    struct db_wallet_utxo u;
    memset(&u, 0, sizeof(u));
    memcpy(u.txid, txid.data, sizeof(u.txid));
    u.value = 3 * 100000000LL;
    memcpy(u.address_hash, l->funding_kid->id.data, sizeof(u.address_hash));
    u.script = (uint8_t *)l->funding_script->data;
    u.script_len = l->funding_script->size;
    u.height = l->funding_height;
    u.is_coinbase = true;
    struct coins_cache_entry *e = db_wallet_utxo_save(l->ndb, &u)
        ? coins_view_cache_modify_new(l->coins_tip, &txid) : NULL;
    if (!e)
        return false;
    coins_alloc(&e->coins, 1);
    if (!e->coins.vout)
        return false;
    e->coins.vout[0].value = u.value;
    e->coins.vout[0].script_pub_key = *l->funding_script;
    e->coins.height = u.height;
    e->coins.version = 1;
    e->coins.is_coinbase = true;
    return true;
}

static void wprt_leg_say(const char *step, bool rpc_ok,
                          const struct json_value *r)
{
    const char *code = json_get_str(json_get(r, "code"));
    const char *msg = json_get_str(json_get(r, "message"));
    if (!msg)
        msg = json_get_str(r);
    printf("wallet_private_relay: leg %s rpc=%d code=%s message=%s\n", step,
           rpc_ok, code ? code : "-", msg ? msg : "-");
}

/* z_sendmany from the funded transparent address to the shielded address:
 * the wallet's own RPC handler, not the vault route (which keeps public
 * relay). The result is the transaction id. */
static bool wprt_leg_send(const struct wallet_private_relay_leg *l,
                          struct json_value *result)
{
    struct json_value params, list, to;
    json_init(&params); json_set_array(&params);
    json_init(&list); json_set_array(&list);
    json_init(&to); json_set_object(&to);
    json_push_kv_str(&to, "address", l->zaddr);
    json_push_kv_real(&to, "amount", 1.0);
    json_push_back(&list, &to);
    wprt_json_str(&params, l->from_addr);
    json_push_back(&params, &list);
    json_init(result);
    bool ok = rpc_table_execute(l->tbl, "z_sendmany", &params, result) &&
              result->type == JSON_STR;
    if (!ok)
        wprt_leg_say("z_sendmany", ok, result);
    json_free(&params);
    json_free(&list);
    json_free(&to);
    return ok;
}

/* The caller's wallet state, which opening the fixture replaced. */
static void wprt_leg_rebind(const struct wallet_private_relay_leg *l)
{
    rpc_wallet_set_state(l->wallet, l->ms, l->datadir, l->wsql, l->main_pool,
                         NULL);
    rpc_wallet_set_node_db(l->ndb);
    rpc_wallet_set_coins_tip(l->coins_tip);
}

/* After the delay: the onion peer holds the transaction, the clearnet peer
 * nothing, and a second node accepts it. */
static int wprt_leg_delivery(const struct wallet_private_relay_leg *l,
                             struct wprt_fx *f, struct p2p_node *clear,
                             struct p2p_node *onion,
                             const struct json_value *result)
{
    int failures = 0;
    struct transaction sent;
    transaction_init(&sent);
    struct uint256 txid;
    memset(&txid, 0, sizeof(txid));
    const char *hex = result ? json_get_str(result) : NULL;
    if (hex)
        uint256_set_hex(&txid, hex);
    bool have = hex && wprt_count(onion, "tx") == 1 &&
        tx_mempool_lookup(wpr_pool(wpr_global()), &txid, &sent);
    wprt_report("real wallet shielded send: exactly the onion peer receives "
                "it; the clearnet peer receives nothing",
                have && wprt_total_bytes(clear) == 0, &failures);
    wprt_report("real wallet shielded send: a second node accepts the pushed "
                "transaction",
                have && wprt_second_node_accepts(f, l->coins_tip, l->ms,
                    chain_params_get(), onion, &sent), &failures);
    transaction_free(&sent);
    return failures;
}

int wallet_private_relay_gate_leg(const struct wallet_private_relay_leg *l)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_open(&f, WPR_MODE_PRIVATE) && wprt_leg_second_coin(l);
    wprt_leg_rebind(l);
    struct p2p_node *clear = ok ? wprt_add_peer(&f, WPRT_CLEAR_OUT) : NULL;
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct wpr_env env = {
        .connman = &f.cm, .coins_tip = l->coins_tip, .main_state = l->ms,
        .params = chain_params_get(), .datadir = l->datadir,
    };
    wpr_configure(wpr_global(), WPR_MODE_PRIVATE, &env);
    size_t main_before = tx_mempool_size(l->main_pool);
    struct json_value result;
    json_init(&result);
    ok = ok && clear && onion && wprt_leg_send(l, &result);
    wprt_report("real wallet shielded send in private mode: the wallet "
                "accepts it and holds exactly one pending send",
                ok && wprt_pending() == 1, &failures);
    wprt_report("real wallet shielded send: the main mempool is unchanged "
                "and the private pool holds it",
                ok && tx_mempool_size(l->main_pool) == main_before &&
                    tx_mempool_size(wpr_pool(wpr_global())) == 1, &failures);
    wprt_report("real wallet shielded send: nothing is announced before the "
                "delay", ok && wprt_count(onion, "tx") == 0 &&
                    wprt_total_bytes(clear) == 0, &failures);
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    failures += wprt_leg_delivery(l, &f, clear, onion, ok ? &result : NULL);
    json_free(&result);
    wprt_close(&f);
    wprt_leg_rebind(l);
    return failures;
}

/* ── every wallet-originated pool entry goes through one gate ───────── */

/* Whichever controller authors a transaction (names, identities, anchors,
 * directories, ZSLP, vault intents, a caller added tomorrow), the wallet's
 * commit and re-admission refuse the main pool in private mode. */
#ifdef ZCL_TESTING
struct zcl_result zcl_test_ztic_publish(void *, const uint8_t *, size_t, const uint8_t[32]);
struct zcl_result zcl_test_znic_publish(void *, const uint8_t *, size_t, const uint8_t[32]);

static bool wprt_pending_intent_retries(struct wprt_fx *f,
    struct wallet_rpc_context *ctx, const struct byte_stream *raw,
    const struct wallet_tx *tx)
{
    struct wallet *pending = zcl_calloc(1, sizeof(*pending), "wprt_pending_wallet");
    if (!pending) return false;
    wallet_init(pending);
    bool ok = wallet_readiness_initialize(pending, WALLET_READINESS_PENDING, true, 42);
    struct wallet_rpc_context view = *ctx; view.wallet = pending;
    struct zcl_result a = ok ? zcl_test_ztic_publish(&view, raw->data, raw->size, tx->tx.hash.data) : ZCL_ERR(-1, "setup");
    struct zcl_result b = ok ? zcl_test_znic_publish(&view, raw->data, raw->size, tx->tx.hash.data) : ZCL_ERR(-1, "setup");
    ok = ok && !a.ok && a.code == -5 && !b.ok && b.code == -5 && tx_mempool_size(&f->main_pool) == 0;
    wallet_free(pending); free(pending);
    return ok;
}

static bool wprt_ready_intent_retries(struct wprt_fx *f,
    struct wallet_rpc_context *ctx, const struct byte_stream *raw,
    const struct wallet_tx *tx)
{
    struct zcl_result a = zcl_test_ztic_publish(ctx, raw->data, raw->size, tx->tx.hash.data);
    bool admitted = a.ok && tx_mempool_exists(&f->main_pool, &tx->tx.hash);
    if (admitted) {
        struct zcl_result repeat = zcl_test_ztic_publish(ctx, raw->data, raw->size, tx->tx.hash.data);
        admitted = repeat.ok;
        if (admitted) tx_mempool_remove(&f->main_pool, &tx->tx.hash);
    }
    struct zcl_result b = zcl_test_znic_publish(ctx, raw->data, raw->size, tx->tx.hash.data);
    struct zcl_result repeat = b.ok ? zcl_test_znic_publish(ctx, raw->data, raw->size, tx->tx.hash.data) : ZCL_ERR(-1, "setup");
    return admitted && b.ok && repeat.ok && tx_mempool_exists(&f->main_pool, &tx->tx.hash);
}

static int wprt_case_intent_retry_readiness(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PUBLIC, 1, false);
    struct wallet_tx tx = {0};
    ok = ok && wprt_build(&f, 0x66, NULL, 0, &tx) && wallet_add_to_wallet(f.wallet, &tx);
    struct byte_stream raw; stream_init(&raw, 512);
    ok = ok && transaction_serialize(&tx.tx, &raw);
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    wprt_report("market and naming retry refuse pending before admission",
                ok && wprt_pending_intent_retries(&f, ctx, &raw, &tx), &failures);
    wprt_report("signed market and naming retries pass current-chain admission",
                ok && wprt_ready_intent_retries(&f, ctx, &raw, &tx), &failures);
    stream_free(&raw);
    if (ok) transaction_free(&tx.tx);
    wprt_close(&f);
    return failures;
}
#endif

static bool wprt_plan_tip(struct wprt_fx *f, struct block_index *tip)
{
    memset(tip, 0, sizeof(*tip));
    tip->nHeight = 10; tip->nTime = (uint32_t)platform_time_wall_time_t();
    memset(tip->hashBlock.data, 0x50, 32);
    active_chain_move_window_tip(&f->ms.chain_active, tip);
    f->wallet->best_block = tip; f->wallet->best_block_height = 10;
    struct db_block block = {0};
    memcpy(block.hash, tip->hashBlock.data, 32);
    memset(block.prev_hash, 0x4f, 32); memset(block.merkle_root, 0x4d, 32);
    memset(block.chain_work, 0x4c, 32); block.height = 10; block.time = tip->nTime;
    block.bits = 0x1d00ffffU; block.status = 3;
    uint8_t sol[] = {1, 2}; block.solution = sol; block.solution_len = sizeof(sol);
    struct p2p_node *peer = wprt_add_peer(f, WPRT_CLEAR_OUT);
    if (!peer || !db_block_save(&f->ndb, &block)) return false;
    peer->starting_height = 10; peer->state = PEER_ACTIVE; peer->services = NODE_NETWORK;
    sync_monitor_set_context(&f->cm, NULL, &f->ms);
    (void)sync_set_state(SYNC_IDLE, "wallet intent fixture reset");
    return sync_set_state(SYNC_FINDING_PEERS, "wallet intent fixture") &&
        sync_set_state(SYNC_HEADERS_DOWNLOAD, "wallet intent fixture") &&
        sync_set_state(SYNC_BLOCKS_DOWNLOAD, "wallet intent fixture") &&
        sync_set_state(SYNC_CONNECTING_BLOCKS, "wallet intent fixture") &&
        sync_set_state(SYNC_AT_TIP, "wallet intent fixture");
}

static bool wprt_plan_prepare_context(struct wprt_fx *f)
{
    struct wallet_identity_row identity;
    if (!wallet_sqlite_self_test(&f->wsql).ok || wallet_canary_run(f->ndb.db, NULL) != WALLET_CANARY_OK ||
        !wallet_sqlite_flush_r(&f->wsql, f->wallet).ok ||
        !wallet_identity_ensure(&f->ndb, f->params->consensus.hashGenesisBlock.data, "test", &identity)) return false;
    wallet_key_pool_mark_persisted_through(f->wallet, wallet_key_pool_generation_ceiling(f->wallet));
    char path[320]; snprintf(path, sizeof(path), "%s/fixture-backup.enc", f->dir);
    FILE *backup = fopen(path, "wb"); if (!backup) return false;
    bool ok = fputs("fixture", backup) >= 0 && fclose(backup) == 0;
    if (!ok) return false;
    wallet_backup_seed_encrypted_authority_for_test(path, (int64_t)platform_time_wall_time_t(), (int64_t)f->wallet->keystore.num_keys);
    return true;
}

static bool wprt_plan_call(struct wprt_fx *f, char id[65])
{
    char address[128]; if (!wprt_self_address(f, address, sizeof(address))) return false;
    struct json_value params = {0}, in = {0}, effects = {0}, effect = {0}, out = {0};
    json_set_array(&params); json_set_object(&in); json_set_array(&effects); json_set_object(&effect);
    json_push_kv_str(&in, "wallet_scope", "test"); json_push_kv_str(&in, "route", "transparent");
    json_push_kv_str(&in, "idempotency_key", "readiness-reopen");
    json_push_kv_str(&effect, "asset", "ZCL"); json_push_kv_str(&effect, "to", address);
    json_push_kv_str(&effect, "amount", "1.00000000"); json_push_back(&effects, &effect);
    json_push_kv(&in, "effects", &effects); json_push_back(&params, &in);
    bool ok = rpc_table_execute(&f->tbl, "vault_intent_plan", &params, &out) && json_get_bool(json_get(&out, "ok"));
    const char *found = json_get_str(json_get(&out, "plan_id"));
    ok = ok && found && strlen(found) == 64;
    if (ok) snprintf(id, 65, "%s", found);
    else printf("(plan code=%s) ", json_get_str(json_get(&out, "code")) ? json_get_str(json_get(&out, "code")) : "missing");
    json_free(&out); json_free(&effect); json_free(&effects); json_free(&in); json_free(&params);
    return ok;
}

static bool wprt_plan_reopen(struct wprt_fx *f, struct block_index *tip, uint64_t generation)
{
    char path[320]; snprintf(path, sizeof(path), "%s/node.db", f->dir);
    wallet_sqlite_close(&f->wsql); f->wsql_open = false;
    node_db_close(&f->ndb); f->db_open = false;
    wallet_free(f->wallet); free(f->wallet); f->wallet = NULL;
    if (!node_db_open(&f->ndb, path)) return false;
    f->db_open = true;
    if (!wallet_sqlite_open_r(&f->wsql, f->ndb.db).ok) return false;
    f->wsql_open = true;
    f->wallet = zcl_calloc(1, sizeof(*f->wallet), "reopened_wallet");
    if (!f->wallet) return false;
    wallet_init(f->wallet);
    if (!wallet_readiness_initialize(f->wallet, WALLET_READINESS_READY, true, generation) ||
        !wallet_sqlite_read_keys_r(&f->wsql, f->wallet).ok ||
        !wallet_sqlite_read_keypool_r(&f->wsql, f->wallet).ok ||
        !wallet_sqlite_read_txs(&f->wsql, f->wallet)) return false;
    f->wallet->best_block = tip; f->wallet->best_block_height = tip->nHeight;
    rpc_wallet_set_state(f->wallet, &f->ms, f->dir, &f->wsql, &f->main_pool, &f->cm);
    rpc_wallet_set_node_db(&f->ndb); rpc_wallet_set_coins_tip(&f->coins);
    return true;
}

static bool wprt_plan_commit(struct wprt_fx *f, const char *id, bool changed)
{
    struct json_value params = {0}, in = {0}, out = {0};
    json_set_array(&params); json_set_object(&in);
    json_push_kv_str(&in, "wallet_scope", "test"); json_push_kv_str(&in, "plan_id", id);
    json_push_kv_bool(&in, "confirm", true); json_push_back(&params, &in);
    bool called = rpc_table_execute(&f->tbl, "vault_intent_commit", &params, &out);
    const char *code = json_get_str(json_get(&out, "code"));
    bool ok = called && (changed ? (code && strcmp(code, "PLAN_REPLAN_REQUIRED") == 0 && tx_mempool_size(&f->main_pool) == 0)
                                : (json_get_bool(json_get(&out, "ok")) && tx_mempool_size(&f->main_pool) == 1));
    if (!ok) printf("(commit changed=%d code=%s) ", changed, code ? code : "missing");
    json_free(&out); json_free(&in); json_free(&params); return ok;
}

static int wprt_case_plan_reopen(bool changed)
{
    int failures = 0;
    struct wprt_fx f; struct block_index tip; char id[65] = {0};
    wprt_file_database = true;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PUBLIC, 1, true);
    wprt_file_database = false;
    ok = ok && wprt_plan_tip(&f, &tip) && wprt_plan_prepare_context(&f) && wprt_plan_call(&f, id);
    ok = ok && wprt_plan_reopen(&f, &tip, changed ? 43 : 42) && wprt_plan_commit(&f, id, changed);
    wprt_report(changed ? "reopened public plan rejects changed generation" : "reopened public plan commits on same generation", ok, &failures);
    sync_monitor_set_context(NULL, NULL, NULL);
    wprt_close(&f);
    return failures;
}

static int wprt_case_main_pool_refused(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 1, false);
    struct wallet_tx wtx;
    ok = ok && wprt_build(&f, 0x61, NULL, 0, &wtx);
    struct wallet_tx_admission main_adm = wprt_admission(&f, &f.main_pool);
    struct wallet_tx_admission priv_adm =
        wprt_admission(&f, wpr_pool(wpr_global()));
    struct zcl_result commit = ok ? wallet_commit_transaction(f.wallet, &wtx,
                                                              &main_adm)
                                  : ZCL_ERR(-1, "setup");
    struct zcl_result again = ok ? wallet_reaccept_transaction(&wtx, &main_adm)
                                 : ZCL_ERR(-1, "setup");
    struct wallet_tx held;
    bool in_wallet = ok && wprt_copy_tx(&f, &wtx.tx.hash, &held);
    if (in_wallet)
        transaction_free(&held.tx);
    wprt_report("a commit or re-admission into the main pool is refused with "
                "the typed error in private mode, for any caller",
                ok && commit.code == WALLET_ADMISSION_POOL_REFUSED_CODE &&
                    again.code == WALLET_ADMISSION_POOL_REFUSED_CODE &&
                    !in_wallet && tx_mempool_size(&f.main_pool) == 0,
                &failures);
    wprt_report("the private pool is not refused",
                ok && wallet_admission_pool_check(&priv_adm).ok, &failures);
    wallet_require_admission_pool(NULL);
    wprt_report("with the requirement lifted (public mode) the main pool is "
                "accepted", wallet_admission_pool_check(&main_adm).ok,
                &failures);
    if (ok)
        transaction_free(&wtx.tx);
    wprt_close(&f);
    return failures;
}

/* ── once handed to a peer, never "nothing was sent" ────────────────── */

static size_t wprt_attempts(const struct uint256 *id)
{
    struct wpr_status *st = zcl_calloc(1, sizeof(*st), "wprt_status");
    size_t n = 0;
    if (!st)
        return 0;
    wpr_status_snapshot(wpr_global(), st);
    for (size_t i = 0; i < st->num_entries; i++)
        if (memcmp(st->entries[i].txid.data, id->data, 32) == 0)
            n = st->entries[i].attempts;
    free(st);
    return n;
}

static bool wprt_status_never_unsent(struct wprt_fx *f,
                                     const struct uint256 *id,
                                     const struct outpoint *spent)
{
    return !wprt_status_next_has(f, id, "Nothing was sent") &&
           wprt_status_next_has(f, id, "Do not send the payment again") &&
           wallet_is_outpoint_spent(f->wallet, &spent->hash, spent->n);
}

/* One onion peer: after it received the push the relay will not reuse it, so
 * the send waits for a second peer. The status must still say it may be on the
 * network, in the same run and after a restart, and the coins stay reserved. */
static int wprt_case_sole_peer_handed(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, false);
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct uint256 id;
    struct outpoint spent;
    memset(&spent, 0, sizeof(spent));
    ok = ok && onion && wprt_rpc_send(&f, false, 10.0, &id);
    (void)wprt_expiry_of(&f, &id, &spent);
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    wprt_run((int64_t)WPR_RESEND_AFTER_S * 1000 + 2 * WPR_DELAY_MAX_MS, -1);
    wprt_report("with the only peer already tried, the status never says "
                "nothing was sent and the coins stay reserved",
                ok && wprt_attempts(&id) == 1 &&
                    wprt_count(onion, "tx") == 1 &&
                    wprt_status_never_unsent(&f, &id, &spent), &failures);
    wprt_restart_relay(&f);
    bool resumed = ok && wpr_resume(wpr_global()).ok;
    wprt_report("after a restart the same holds: the push is remembered",
                resumed && wprt_status_never_unsent(&f, &id, &spent),
                &failures);
    wprt_close(&f);
    return failures;
}

/* ── a refused queue is not an attempt ──────────────────────────────── */

static int wprt_case_queue_refused(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 1, false);
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct uint256 id;
    ok = ok && onion && wprt_rpc_send(&f, false, 10.0, &id);
    if (onion)
        onion->send_size = net_send_peer_bytes_hard_cap();
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    bool found = false;
    wprt_report("a peer queue that refuses the message records no attempt and "
                "the status does not say it was handed over",
                ok && wprt_attempts(&id) == 0 &&
                    wprt_state(&id, &found) != WPR_SENT && found &&
                    wprt_count(onion, "tx") == 0 &&
                    !wprt_status_next_has(&f, &id, "Handed"), &failures);
    if (onion)
        onion->send_size = 0;
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    wprt_report("once the queue accepts it, it is handed over once and the "
                "status says delivery is not confirmed",
                ok && wprt_attempts(&id) == 1 &&
                    wprt_count(onion, "tx") == 1 &&
                    wprt_status_next_has(&f, &id, "delivery is not confirmed"),
                &failures);
    wprt_close(&f);
    return failures;
}

/* ── disk full while queueing: unknown, not "rolled back" ───────────── */

static bool wprt_commit_keep(struct wprt_fx *f, struct wallet_tx *wtx)
{
    char addr[128];
    struct tx_destination dest;
    int64_t fee = 0;
    const char *error = NULL;
    if (!wprt_self_address(f, addr, sizeof(addr)) ||
        !wallet_decode_address(addr, &dest) ||
        !wallet_create_transaction(f->wallet, &dest, 10 * COIN_VALUE, wtx,
                                   &fee, &error))
        return false;
    struct wallet_rpc_context sv;
    struct wallet_rpc_context *ctx = wallet_send_view(
        wallet_rpc_context_current(), &sv);
    return wallet_commit_from_context(ctx, wtx).ok;
}

static void wprt_relay_with_full_disk(struct wprt_fx *f, bool row_delete_fails,
                                      bool *relayed, const char **text)
{
    struct wallet_tx wtx;
    snprintf(wpr_global()->datadir, sizeof(wpr_global()->datadir), "%s",
             f->dir);
    bool ok = wprt_commit_keep(f, &wtx);
    snprintf(wpr_global()->datadir, sizeof(wpr_global()->datadir), "%s",
             "/nonexistent/wallet-private-relay");
    f->ndb.open = !row_delete_fails;
    struct wallet_rpc_context sv;
    struct wallet_rpc_context *ctx = wallet_send_view(
        wallet_rpc_context_current(), &sv);
    *relayed = ok && wallet_send_relay(ctx, &wtx);
    *text = wallet_send_relay_failure_text();
    f->ndb.open = true;
    if (ok)
        transaction_free(&wtx.tx);
}

static int wprt_case_unknown_after_failed_rollback(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, true);
    bool relayed = true;
    const char *text = "";
    wprt_relay_with_full_disk(&f, false, &relayed, &text);
    wprt_report("a queue write that fails with the rollback working says the "
                "send was rolled back",
                ok && !relayed && strstr(text, "rolled back") &&
                    !strstr(text, "unknown") && wprt_pending() == 0,
                &failures);
    wprt_relay_with_full_disk(&f, true, &relayed, &text);
    wprt_report("a queue write and a row delete that both fail answer that "
                "the outcome is unknown, and keep the record",
                ok && !relayed && strstr(text, "outcome is unknown") &&
                    strstr(text, "Do not pay again") && wprt_pending() == 1,
                &failures);
    wprt_close(&f);
    return failures;
}

/* ── a crash between the wallet write and the note reservation ──────── */

static bool wprt_zspend_tx(struct wprt_fx *f, uint8_t seed, uint8_t nf,
                           struct wallet_tx *wtx)
{
    if (!wprt_build(f, seed, NULL, 0, wtx))
        return false;
    struct transaction *tx = &wtx->tx;
    tx->v_shielded_spend = zcl_calloc(1, sizeof(*tx->v_shielded_spend),
                                      "wprt_zspend");
    if (!tx->v_shielded_spend)
        return false;
    tx->num_shielded_spend = 1;
    memset(tx->v_shielded_spend[0].nullifier.data, nf, 32);
    tx->overwintered = true;
    tx->version = SAPLING_TX_VERSION;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    transaction_compute_hash(tx);
    return true;
}

static bool wprt_seed_note(struct wprt_fx *f, uint8_t nf)
{
    struct db_sapling_note n;
    memset(&n, 0, sizeof(n));
    memset(n.txid, 0xAA, 32);
    memset(n.ivk, 0xBB, 32);
    memset(n.nullifier, nf, 32);
    memset(n.diversifier, 0xDD, 11);
    memset(n.pk_d, 0xEE, 32);
    memset(n.cm, 0xFF, 32);
    memset(n.rcm, 0x11, 32);
    n.value = 200000;
    n.block_height = 5;
    if (!db_sapling_note_save(&f->ndb, &n))
        return false;
    struct wallet *w = f->wallet;
    w->sapling_notes = zcl_calloc(1, sizeof(*w->sapling_notes), "wprt_note");
    if (!w->sapling_notes)
        return false;
    w->num_sapling_notes = 1;
    w->sapling_notes_cap = 1;
    w->sapling_notes[0].used = true;
    memcpy(w->sapling_notes[0].nf, n.nullifier, 32);
    return true;
}

static bool wprt_note_free(struct wprt_fx *f)
{
    struct db_sapling_note notes[4];
    uint8_t ivk[32];
    memset(ivk, 0xBB, sizeof(ivk));
    return db_sapling_note_list_unspent_for_ivk(&f->ndb, ivk, notes, 4) == 1 &&
           !f->wallet->sapling_notes[0].spent;
}

/* The wallet holds a shielded send whose notes were never reserved: the
 * state power loss leaves between the wallet write and the reservation. A
 * resume must reserve them again, or the next send picks them a second time. */
static int wprt_deny_select(void *ctx, int action, const char *a,
                            const char *b, const char *c, const char *d)
{
    (void)ctx; (void)a; (void)b; (void)c; (void)d;
    return action == SQLITE_SELECT ? SQLITE_DENY : SQLITE_OK;
}

static int wprt_case_missing_hold_proof(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 1, true);
    wallet_free(f.wallet); wallet_init(f.wallet);
    ok = ok && wallet_readiness_initialize(f.wallet, WALLET_READINESS_PENDING, true, 42);
    struct uint256 id = {0}; id.data[0] = 1;
    ok = ok && wpr_prepare(wpr_global(), &id).ok;
    wpr_global()->env.node_db = &f.ndb;
    struct wpr_pending_guard guard = {0};
    struct wpr_pending_record rows[WPR_MAX_ENTRIES]; size_t count = 0;
    ok = ok && wpr_pending_proof_begin(wpr_global(), &guard, rows, WPR_MAX_ENTRIES, &count) == WPR_PENDING_OK &&
        sqlite3_exec(f.ndb.db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    enum wallet_hold_proof_result status = ok ?
        wallet_private_broadcast_reserve_in_open_tx(&guard, &f.ndb, f.wallet) : WALLET_HOLD_PROOF_ERROR;
    wprt_report("absent pending tx remains unavailable instead of being presumed prepared",
                ok && count == 1 && status == WALLET_HOLD_PROOF_TX_ABSENT, &failures);
    bool denied = ok && sqlite3_set_authorizer(f.ndb.db, wprt_deny_select, NULL) == SQLITE_OK;
    if (denied) status = wallet_private_broadcast_reserve_in_open_tx(&guard, &f.ndb, f.wallet);
    (void)sqlite3_set_authorizer(f.ndb.db, NULL, NULL);
    wprt_report("transaction lookup failure is distinct from absence",
                denied && status == WALLET_HOLD_PROOF_ERROR, &failures);
    if (sqlite3_get_autocommit(f.ndb.db) == 0) (void)sqlite3_exec(f.ndb.db, "ROLLBACK", NULL, NULL, NULL);
    wpr_pending_proof_end(&guard);
    wprt_close(&f);
    return failures;
}

static bool wprt_setup_pending_hold(struct wprt_fx *f, struct wallet_tx *tx)
{
    wallet_free(f->wallet);
    wallet_init(f->wallet);
    return wallet_readiness_initialize(f->wallet, WALLET_READINESS_PENDING, true, 42) &&
        wallet_add_to_wallet(f->wallet, tx) && wprt_seed_note(f, 0x79) &&
        wallet_sqlite_flush_transactions_r(&f->wsql, f->wallet).ok &&
        wpr_prepare(wpr_global(), &tx->tx.hash).ok;
}

static bool wprt_hold_validator_detects_loss(struct wprt_fx *f, struct wpr_pending_guard *guard)
{
    zcl_mutex_lock(&f->wallet->cs);
    bool valid = wallet_private_broadcast_validate_holds_locked(guard, f->wallet, f->ndb.db);
    f->wallet->sapling_notes[0].spent = false;
    bool detects_loss = !wallet_private_broadcast_validate_holds_locked(guard, f->wallet, f->ndb.db);
    f->wallet->sapling_notes[0].spent = true;
    bool changed = sqlite3_exec(f->ndb.db, "UPDATE wallet_sapling_notes SET spent_txid=zeroblob(32)",
                                NULL, NULL, NULL) == SQLITE_OK;
    bool detects_conflict = changed && !wallet_private_broadcast_validate_holds_locked(guard, f->wallet, f->ndb.db);
    zcl_mutex_unlock(&f->wallet->cs);
    return valid && detects_loss && detects_conflict;
}

static int wprt_case_checked_hold_proof(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 1, true);
    struct wallet_tx tx;
    bool built = ok && wprt_zspend_tx(&f, 0x64, 0x79, &tx);
    ok = built && wprt_setup_pending_hold(&f, &tx);
    wpr_global()->env.node_db = &f.ndb;
    struct wpr_pending_guard guard = {0};
    struct wpr_pending_record rows[WPR_MAX_ENTRIES]; size_t count = 0;
    ok = ok && wpr_pending_proof_begin(wpr_global(), &guard, rows, WPR_MAX_ENTRIES, &count) == WPR_PENDING_OK &&
        sqlite3_exec(f.ndb.db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    enum wallet_hold_proof_result result = ok ?
        wallet_private_broadcast_reserve_in_open_tx(&guard, &f.ndb, f.wallet) : WALLET_HOLD_PROOF_ERROR;
    bool valid = ok && result == WALLET_HOLD_PROOF_OK &&
        wprt_hold_validator_detects_loss(&f, &guard);
    wprt_report("held send reservations are restored and final proof detects lost hold",
                ok && count == 1 && result == WALLET_HOLD_PROOF_OK && valid, &failures);
    if (sqlite3_get_autocommit(f.ndb.db) == 0) (void)sqlite3_exec(f.ndb.db, "ROLLBACK", NULL, NULL, NULL);
    wpr_pending_proof_end(&guard);
    if (built) transaction_free(&tx.tx);
    wprt_close(&f);
    return failures;
}

static int wprt_case_resume_reserves_notes(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 1, true);
    struct wallet_tx wtx;
    ok = ok && wprt_zspend_tx(&f, 0x62, 0x77, &wtx) &&
         wallet_add_to_wallet(f.wallet, &wtx) &&
         wprt_seed_note(&f, 0x77) &&
         wpr_prepare(wpr_global(), &wtx.tx.hash).ok;
    bool free_before = ok && wprt_note_free(&f);
    /* The boot order: the relay resumes from its own environment, before the
     * shared wallet context is filled. */
    struct wpr_env boot_env = wpr_global()->env;
    boot_env.node_db = &f.ndb;
    wallet_private_broadcast_arm_env(&boot_env, &wpr_global()->env);
    wallet_rpc_context_set_base(NULL, NULL, NULL, NULL, NULL, NULL);
    wallet_rpc_context_set_node_db(NULL);
    wprt_restart_relay(&f);
    bool resumed = ok && wpr_resume(wpr_global()).ok;
    bool free_after = ok && wprt_note_free(&f);
    wprt_report("before the resume the crash left the note free",
                free_before, &failures);
    wprt_report("a resume re-reserves the note of a send the wallet holds",
                resumed && !free_after, &failures);
    if (ok)
        transaction_free(&wtx.tx);
    wprt_close(&f);
    return failures;
}

/* ── a shielded send the chain may hold is never rolled back ────────── */

static int wprt_case_nullifier_hold(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 1, false);
    struct wallet_tx wtx;
    ok = ok && wprt_zspend_tx(&f, 0x63, 0x78, &wtx) &&
         wallet_add_to_wallet(f.wallet, &wtx) &&
         wpr_prepare(wpr_global(), &wtx.tx.hash).ok;
    bool released = ok && wallet_private_broadcast_expire(&wtx.tx.hash);
    bool found = false;
    wprt_report("an expired shielded send whose nullifiers cannot be proved "
                "unseen is held, not rolled back",
                ok && !released &&
                    wprt_state(&wtx.tx.hash, &found) != WPR_EXPIRED && found &&
                    wprt_status_next_has(&f, &wtx.tx.hash,
                                         "Do not send the payment again"),
                &failures);
    if (ok)
        transaction_free(&wtx.tx);
    wprt_close(&f);
    return failures;
}

/* ── held with no route, and seen back but not yet mined ────────────── */

static int wprt_case_held_and_seen(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 1, false);
    struct uint256 id;
    ok = ok && wprt_rpc_send(&f, false, 10.0, &id);
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    wprt_report("a send with no onion peer is reported held to its callers",
                ok && wallet_private_broadcast_is_held(&id), &failures);
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    wprt_run(2 * WPR_DELAY_MAX_MS, -1);
    wprt_report("once handed to a peer it is no longer reported held",
                onion && !wallet_private_broadcast_is_held(&id), &failures);
    wpr_note_seen(wpr_global(), &id);
    wprt_run(2 * WPR_SEEN_RETAIN_S * 1000, -1);
    bool found = false;
    wprt_report("a send seen back but never mined keeps a status that says so",
                ok && wprt_state(&id, &found) == WPR_SEEN && found &&
                    wprt_status_next_has(&f, &id, "not in a block yet"),
                &failures);
    wprt_close(&f);
    return failures;
}

/* ── accepted is not sent: held until handed to a peer ──────────────── */

static int wprt_case_held_at_zero(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, false);
    struct uint256 a, b;
    ok = ok && wprt_rpc_send(&f, false, 10.0, &a);
    wprt_report("right after a send with no onion peer it is reported held",
                ok && wallet_private_broadcast_is_held(&a), &failures);
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    ok = ok && onion && wprt_rpc_send(&f, true, 10.0, &b);
    wprt_report("right after a send with a peer, still inside its delay, it "
                "is reported held, not sent",
                ok && wprt_count(onion, "tx") == 0 &&
                    wallet_private_broadcast_is_held(&b), &failures);
    wprt_run(2 * WPR_DELAY_MAX_MS, -1);
    wprt_report("once handed to the peer neither is reported held",
                onion && wprt_count(onion, "tx") >= 1 &&
                    !wallet_private_broadcast_is_held(&b), &failures);
    wprt_close(&f);
    return failures;
}

/* ── the handed fact is saved before the push ───────────────────────── */

static int wprt_case_handed_saved_first(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 1, false);
    struct p2p_node *onion = ok ? wprt_add_peer(&f, WPRT_ONION_OUT) : NULL;
    struct uint256 id;
    ok = ok && onion && wprt_rpc_send(&f, false, 10.0, &id);
    snprintf(wpr_global()->datadir, sizeof(wpr_global()->datadir), "%s",
             "/nonexistent/wallet-private-relay");
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    wprt_report("with the pending record unwritable nothing is pushed",
                ok && wprt_count(onion, "tx") == 0 &&
                    wprt_attempts(&id) == 0, &failures);
    snprintf(wpr_global()->datadir, sizeof(wpr_global()->datadir), "%s",
             f.dir);
    wprt_run((int64_t)WPR_RETRY_S * 1000 + 2 * WPR_DELAY_MAX_MS, -1);
    wprt_report("once the record can be written it is pushed once",
                ok && wprt_count(onion, "tx") == 1 && wprt_attempts(&id) == 1,
                &failures);
    wprt_restart_relay(&f);
    bool resumed = ok && wpr_resume(wpr_global()).ok;
    wprt_report("a restart remembers the push: the status never says nothing "
                "was sent",
                resumed && !wprt_status_next_has(&f, &id, "Nothing was sent")
                    && wprt_status_next_has(&f, &id,
                                            "Do not send the payment again"),
                &failures);
    wprt_close(&f);
    return failures;
}

/* ── seen back, then dropped, then past expiry ──────────────────────── */

static int wprt_case_seen_then_expired(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, false);
    wprt_overwinter_on(&f);
    struct uint256 id;
    struct outpoint spent;
    memset(&spent, 0, sizeof(spent));
    ok = ok && wprt_add_peer(&f, WPRT_ONION_OUT) &&
         wprt_rpc_send(&f, false, 10.0, &id);
    int e = (int)wprt_expiry_of(&f, &id, &spent);
    wprt_run(WPR_DELAY_MAX_MS + 1000, -1);
    wpr_note_seen(wpr_global(), &id);
    wprt_tick_at_height(&f, e + WPR_EXPIRY_MARGIN_BLOCKS);
    bool found = false;
    wprt_report("a seen-back send inside the expiry margin keeps its status",
                ok && wprt_state(&id, &found) == WPR_SEEN && found &&
                    wallet_is_outpoint_spent(f.wallet, &spent.hash, spent.n),
                &failures);
    wprt_tick_at_height(&f, e + WPR_EXPIRY_MARGIN_BLOCKS + 1);
    wprt_report("a seen-back send never mined is rolled back past its expiry "
                "and its coins return",
                ok && wprt_state(&id, &found) == WPR_EXPIRED && found &&
                    !wallet_is_outpoint_spent(f.wallet, &spent.hash, spent.n),
                &failures);
    wprt_close(&f);
    return failures;
}

/* ── configuration that cannot be honored is refused ────────────────── */

static int wprt_case_config(void)
{
    int failures = 0;
    struct app_context *c = zcl_calloc(1, sizeof(*c), "wprt_cfg");
    if (!c) {
        wprt_report("allocate the configuration", false, &failures);
        return failures;
    }
    bool conf_private = args_resolve_wallet_broadcast(c, "private") == 0 &&
                        c->wallet_broadcast == 1;
    bool conf_public = args_resolve_wallet_broadcast(c, "public") == 0 &&
                       c->wallet_broadcast == 0;
    c->wallet_broadcast = 1;
    bool unset_keeps = args_resolve_wallet_broadcast(c, NULL) == 0 &&
                       c->wallet_broadcast == 1;
    bool bogus = args_resolve_wallet_broadcast(c, "privte") == 1;
    wprt_report("a walletbroadcast value from z23.conf is honored, an unset "
                "one changes nothing, an unknown one is refused",
                conf_private && conf_public && unset_keeps && bogus,
                &failures);
    c->onion_persist = true;
    bool persist = args_private_mode_onion_policy(c) == 1;
    c->onion_persist = false;
    c->onion_rotate = true;
    bool rotate = args_private_mode_onion_policy(c) == 1;
    c->onion_rotate = false;
    bool clean = args_private_mode_onion_policy(c) == 0 &&
                 c->onion_persist_forced_off;
    c->wallet_broadcast = 0;
    c->onion_persist = true;
    bool public_ok = args_private_mode_onion_policy(c) == 0;
    wprt_report("private mode refuses -onion-persist and -onion-rotate and "
                "keeps the persistent identity default off",
                persist && rotate && clean && public_ok, &failures);
    free(c);
    return failures;
}

/* ── mutation-gap units: a bare relay, no wallet, no peers ──────────────
 * These cases aim at the boundaries the mutation sweep measured: exact
 * names, the delay arithmetic, the slot reuse order, the pending file's
 * exact bytes and the way a hand-written file is read back. */

#define WPRT_U_FILE "wallet_private_relay.pending"
static const char WPRT_U_HDR[] = "# wallet_private_relay v1\n";
#define WPRT_U_HDR_LEN (sizeof(WPRT_U_HDR) - 1)

static uint8_t wprt_u_raw[8];
static bool wprt_u_rng_ok = true;
static size_t wprt_u_asked;
static bool wprt_u_rng(uint8_t *out, size_t n)
{
    wprt_u_asked = n;
    if (!wprt_u_rng_ok)
        return false;
    memset(out, 0, n);
    memcpy(out, wprt_u_raw, n < sizeof(wprt_u_raw) ? n : sizeof(wprt_u_raw));
    return true;
}

struct wprt_u {
    struct wpr *r;
    char dir[256];
};

static bool wprt_u_open(struct wprt_u *u, bool with_dir)
{
    memset(u, 0, sizeof(*u));
    u->r = zcl_calloc(1, sizeof(*u->r), "wprt_u");
    if (!u->r)
        return false;
    wpr_init(u->r);
    u->r->now_ms = wprt_clock;
    u->r->random_bytes = wprt_u_rng;
    atomic_store(&wprt_now, 5000000);
    wprt_u_rng_ok = true;
    memset(wprt_u_raw, 0, sizeof(wprt_u_raw));
    struct wpr_env env;
    memset(&env, 0, sizeof(env));
    env.datadir = "";
    if (with_dir) {
        if (!test_mkdtemp(u->dir, sizeof(u->dir), "wprtu"))
            return false;
        env.datadir = u->dir;
    }
    wpr_configure(u->r, WPR_MODE_PRIVATE, &env);
    return true;
}

static void wprt_u_close(struct wprt_u *u)
{
    if (u->r) {
        wpr_free(u->r);
        free(u->r);
    }
    if (u->dir[0])
        test_rm_rf(u->dir);
}

static void wprt_u_reconfigure(struct wprt_u *u, const char *datadir)
{
    struct wpr_env env;
    memset(&env, 0, sizeof(env));
    env.datadir = datadir;
    wpr_configure(u->r, WPR_MODE_PRIVATE, &env);
}

static struct uint256 wprt_u_id(uint8_t fill, uint8_t last)
{
    struct uint256 id;
    memset(id.data, fill, sizeof(id.data));
    id.data[31] = last;
    return id;
}

static struct wpr_entry *wprt_u_entry(struct wpr *r, const struct uint256 *id)
{
    for (size_t i = 0; i < WPR_MAX_ENTRIES; i++)
        if (r->entries[i].used &&
            memcmp(r->entries[i].txid.data, id->data, 32) == 0)
            return &r->entries[i];
    return NULL;
}

static size_t wprt_u_used(const struct wpr *r)
{
    size_t n = 0;
    for (size_t i = 0; i < WPR_MAX_ENTRIES; i++)
        if (r->entries[i].used)
            n++;
    return n;
}

static size_t wprt_u_count_state(const struct wpr *r, enum wpr_state s)
{
    size_t n = 0;
    for (size_t i = 0; i < WPR_MAX_ENTRIES; i++)
        if (r->entries[i].used && r->entries[i].state == s)
            n++;
    return n;
}

/* A thread other than the caller can take the relay's lock: nothing leaked it
 * (the lock is recursive, so the caller's own trylock cannot tell). */
struct wprt_try {
    zcl_mutex_t *m;
    bool got;
};

static void *wprt_try_main(void *arg)
{
    struct wprt_try *t = arg;
    t->got = zcl_mutex_trylock(t->m);
    if (t->got)
        zcl_mutex_unlock(t->m);
    return NULL;
}

static bool wprt_mutex_free(zcl_mutex_t *m)
{
    struct wprt_try t = { .m = m, .got = false };
    pthread_t th;
    if (pthread_create(&th, NULL, wprt_try_main, &t) != 0)
        return false;
    pthread_join(th, NULL);
    return t.got;
}

static bool wprt_lock_free(struct wpr *r) { return wprt_mutex_free(&r->lock); }

static char wprt_u_buf[20000];

static long wprt_u_slurp(const struct wprt_u *u)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", u->dir, WPRT_U_FILE);
    FILE *fp = platform_file_stream_open_read(path);
    if (!fp)
        return -1;
    size_t n = fread(wprt_u_buf, 1, sizeof(wprt_u_buf) - 1, fp);
    fclose(fp);
    wprt_u_buf[n] = '\0';
    return (long)n;
}

static bool wprt_u_put(const struct wprt_u *u, const char *data, size_t len)
{
    return authority_receipt_write_atomic(u->dir, WPRT_U_FILE,
                                          (const uint8_t *)data, len, NULL, 0);
}

struct wprt_line {
    char pfx;  /* 0, 'x' (expired) or 'a' (handed) */
    const struct uint256 *id;
};

/* The pending file is exactly the header and these lines, byte for byte. */
static bool wprt_u_file_is(const struct wprt_u *u,
                           const struct wprt_line *lines, size_t n)
{
    static char want[20000];
    memcpy(want, WPRT_U_HDR, WPRT_U_HDR_LEN);
    size_t len = WPRT_U_HDR_LEN;
    for (size_t i = 0; i < n; i++) {
        if (lines[i].pfx)
            want[len++] = lines[i].pfx;
        uint256_get_hex(lines[i].id, want + len);
        len += 64;
        want[len++] = '\n';
    }
    return wprt_u_slurp(u) == (long)len && memcmp(wprt_u_buf, want, len) == 0;
}

static int wprt_u_open_failed(struct wprt_u *u, int failures)
{
    wprt_report("the unit relay opens", false, &failures);
    wprt_u_close(u);
    return failures;
}

/* ── names, init, argument refusal ──────────────────────────────────── */

static bool wprt_u_names_exact(void)
{
    static const struct { enum wpr_state s; const char *name; } t[] = {
        { WPR_WAITING_FOR_ROUTE, "waiting_for_route" },
        { WPR_EXPIRED, "expired" },
        { WPR_PREPARED, "preparing" },
        { WPR_SCHEDULED, "scheduled" },
        { WPR_SENT, "sent" },
        { WPR_SEEN, "seen" },
    };
    bool ok = strcmp(wpr_state_name((enum wpr_state)99), "unknown") == 0 &&
              strcmp(wpr_mode_name(WPR_MODE_PRIVATE), "private") == 0 &&
              strcmp(wpr_mode_name(WPR_MODE_PUBLIC), "public") == 0;
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++)
        ok = ok && strcmp(wpr_state_name(t[i].s), t[i].name) == 0;
    return ok;
}

static bool wprt_recursive(zcl_mutex_t *m)
{
    if (!zcl_mutex_trylock(m))
        return false;
    bool again = zcl_mutex_trylock(m);
    if (again)
        zcl_mutex_unlock(m);
    zcl_mutex_unlock(m);
    return again;
}

static bool wprt_u_default_clock(const struct wpr *d)
{
    int64_t before = clock_now_monotonic_ns() / 1000000;
    int64_t got = d->now_ms();
    int64_t after = clock_now_monotonic_ns() / 1000000;
    return got >= before && got <= after;
}

static bool wprt_u_init_state(void)
{
    struct wpr *d = zcl_calloc(1, sizeof(*d), "wprt_u_init");
    if (!d)
        return false;
    memset(d, 0xA5, sizeof(*d));
    wpr_init(d);
    uint8_t raw[8];
    bool ok = wprt_recursive(&d->lock) && d->pool.min_relay_fee == 0 &&
              d->mode == WPR_MODE_PUBLIC && wprt_u_used(d) == 0 &&
              wprt_u_default_clock(d) && d->random_bytes &&
              d->random_bytes(raw, sizeof(raw));
    wpr_free(d);
    free(d);
    return ok;
}

static bool wprt_u_no_connman_peers(void)
{
    struct connman *cm = zcl_calloc(1, sizeof(*cm), "wprt_u_cm");
    struct node_signals sigs;
    memset(&sigs, 0, sizeof(sigs));
    if (!cm || !connman_init(cm, chain_params_get(), &sigs)) {
        free(cm);
        return false;
    }
    bool ok = wpr_count_eligible_peers(NULL) == 0 &&
              wpr_count_eligible_peers(cm) == 0 &&
              wprt_mutex_free(&cm->manager.cs_nodes);
    connman_free(cm);
    free(cm);
    return ok;
}

static int wprt_u_case_names_and_init(void)
{
    int failures = 0;
    struct wpr *g = wpr_global();
    wprt_report("every state and mode name is exact; an unknown state is "
                "named unknown", wprt_u_names_exact(), &failures);
    wprt_report("a first-use global relay has a clock and a random source",
                g && g->now_ms && g->random_bytes, &failures);
    wprt_report("an initialised relay: recursive lock, free pool fee, public "
                "mode, no entries, the monotonic millisecond clock, a working "
                "random source", wprt_u_init_state(), &failures);
    wprt_report("no connman or an empty one has no eligible peer and the "
                "node lock is released", wprt_u_no_connman_peers(), &failures);
    return failures;
}

static bool wprt_u_null_void_calls(struct wprt_u *u, const struct uint256 *id)
{
    struct wpr *r = u->r;
    wpr_mark_held(r, NULL, true);
    wpr_mark_held(NULL, id, true);
    wpr_set_disk_retry(r, NULL, true);
    wpr_set_disk_retry(NULL, id, true);
    wpr_note_seen(r, NULL);
    wpr_note_seen(NULL, id);
    wpr_mark_expired(r, NULL);
    wpr_mark_expired(NULL, id);
    wpr_forget(r, NULL);
    wpr_forget(NULL, id);
    struct wpr_entry *e = wprt_u_entry(r, id);
    return wprt_u_used(r) == 1 && e && e->state == WPR_PREPARED;
}

static bool wprt_u_null_results(struct wprt_u *u, const struct uint256 *id)
{
    struct wpr *r = u->r;
    struct transaction tx;
    transaction_init(&tx);
    struct zcl_result a = wpr_prepare(r, NULL);
    struct zcl_result b = wpr_prepare(NULL, id);
    struct zcl_result c = wpr_enqueue(r, NULL);
    struct zcl_result d = wpr_enqueue(NULL, &tx);
    transaction_free(&tx);
    return !a.ok && a.code == -1 && !b.ok && b.code == -1 && !c.ok &&
           c.code == -1 && !d.ok && d.code == -1;
}

static int wprt_u_case_null_arguments(void)
{
    int failures = 0;
    struct wprt_u u;
    if (!wprt_u_open(&u, false))
        return wprt_u_open_failed(&u, failures);
    struct uint256 id = wprt_u_id(0x31, 0);
    struct uint256 other = wprt_u_id(0x32, 0);
    bool prepared = wpr_prepare(u.r, &id).ok;
    struct wpr_entry *e = wprt_u_entry(u.r, &id);
    if (!prepared || !e)
        return wprt_u_open_failed(&u, failures);
    e->disk_retry = true;
    wprt_report("a missing relay or id is refused with code -1 by prepare and "
                "enqueue", prepared && wprt_u_null_results(&u, &id),
                &failures);
    wprt_report("a missing relay or id changes nothing in any other call",
                wprt_u_null_void_calls(&u, &id), &failures);
    wprt_report("disk_retry is false for a missing relay, a missing id and an "
                "unknown id, true for the recorded one",
                !wpr_disk_retry(NULL, &id) && !wpr_disk_retry(u.r, NULL) &&
                    !wpr_disk_retry(u.r, &other) && wpr_disk_retry(u.r, &id),
                &failures);
    wpr_note_seen(u.r, &other);
    wpr_mark_expired(u.r, &other);
    wpr_forget(u.r, &other);
    wpr_mark_held(u.r, &other, true);
    wpr_set_disk_retry(u.r, &other, true);
    wprt_report("calls for an unknown id add nothing and release the lock",
                wprt_u_used(u.r) == 1 && wprt_lock_free(u.r), &failures);
    wprt_u_close(&u);
    return failures;
}

/* ── the delay draw and the enqueue fields ──────────────────────────── */

static bool wprt_u_delay_is(struct wprt_u *u, uint8_t seed,
                            const uint8_t raw[8], int64_t want)
{
    memcpy(wprt_u_raw, raw, sizeof(wprt_u_raw));
    wprt_u_asked = 0;
    struct uint256 id = wprt_u_id(seed, 0);
    struct transaction tx;
    transaction_init(&tx);
    tx.hash = id;
    struct zcl_result res = wpr_enqueue(u->r, &tx);
    transaction_free(&tx);
    struct wpr_entry *e = wprt_u_entry(u->r, &id);
    return res.ok && e && wprt_u_asked == 8 &&
           e->due_ms - atomic_load(&wprt_now) == want &&
           wprt_lock_free(u->r);
}

static bool wprt_u_expiry_flag(struct wprt_u *u, uint8_t seed, bool overwinter,
                               uint32_t height, bool want)
{
    struct uint256 id = wprt_u_id(seed, 0);
    struct transaction tx;
    transaction_init(&tx);
    tx.hash = id;
    tx.overwintered = overwinter;
    tx.expiry_height = height;
    struct zcl_result res = wpr_enqueue(u->r, &tx);
    transaction_free(&tx);
    struct wpr_entry *e = wprt_u_entry(u->r, &id);
    return res.ok && e && e->has_expiry == want &&
           e->expiry_height == height && e->last_attempt_ms == -1 &&
           e->state == WPR_SCHEDULED && e->in_pool;
}

static bool wprt_u_rng_refused(struct wprt_u *u)
{
    struct uint256 id = wprt_u_id(0x45, 0);
    struct transaction tx;
    transaction_init(&tx);
    tx.hash = id;
    wprt_u_rng_ok = false;
    size_t before = wprt_u_used(u->r);
    struct zcl_result res = wpr_enqueue(u->r, &tx);
    wprt_u_rng_ok = true;
    transaction_free(&tx);
    return !res.ok && res.code == -3 && wprt_u_used(u->r) == before &&
           !wprt_u_entry(u->r, &id) && wprt_lock_free(u->r);
}

static bool wprt_u_enqueue_twice(struct wprt_u *u)
{
    struct uint256 id = wprt_u_id(0x46, 0);
    struct transaction tx;
    transaction_init(&tx);
    tx.hash = id;
    struct zcl_result first = wpr_enqueue(u->r, &tx);
    struct wpr_entry *e = wprt_u_entry(u->r, &id);
    int64_t due = e ? e->due_ms : -5;
    wprt_u_raw[7] = 77;
    struct zcl_result again = wpr_enqueue(u->r, &tx);
    transaction_free(&tx);
    return first.ok && again.ok && e && e->due_ms == due &&
           wprt_lock_free(u->r);
}

static int wprt_u_case_delay_and_fields(void)
{
    int failures = 0;
    struct wprt_u u;
    if (!wprt_u_open(&u, false))
        return wprt_u_open_failed(&u, failures);
    static const uint8_t mixed[8] = { 0x12, 0x34, 0x56, 0x78,
                                      0x9A, 0xBC, 0xDE, 0xF0 };
    static const uint8_t top[8] = { 0, 0, 0, 0, 0, 0, 0x46, 0x50 };
    static const uint8_t over[8] = { 0, 0, 0, 0, 0, 0, 0x46, 0x51 };
    static const uint8_t zero[8] = { 0 };
    /* 0x123456789ABCDEF0 mod 18001 = 11306; 18000 is the top of the span. */
    wprt_report("the delay is the eight random bytes read big-endian, taken "
                "modulo 18001, plus 2000 ms",
                wprt_u_delay_is(&u, 0x41, mixed, 2000 + 11306), &failures);
    wprt_report("the largest delay is exactly 20000 ms",
                wprt_u_delay_is(&u, 0x42, top, WPR_DELAY_MAX_MS), &failures);
    wprt_report("one past the span wraps to exactly 2000 ms",
                wprt_u_delay_is(&u, 0x43, over, WPR_DELAY_MIN_MS), &failures);
    wprt_report("a zero draw is exactly 2000 ms",
                wprt_u_delay_is(&u, 0x44, zero, WPR_DELAY_MIN_MS), &failures);
    wprt_report("an unavailable random source is refused with code -3, "
                "records nothing and releases the lock",
                wprt_u_rng_refused(&u), &failures);
    wprt_report("an overwinter send with expiry 1 carries an expiry",
                wprt_u_expiry_flag(&u, 0x51, true, 1, true), &failures);
    wprt_report("an overwinter send with expiry 0 carries none",
                wprt_u_expiry_flag(&u, 0x52, true, 0, false), &failures);
    wprt_report("a send that is not overwinter carries none whatever its "
                "expiry field", wprt_u_expiry_flag(&u, 0x53, false, 5, false),
                &failures);
    wprt_report("enqueuing a scheduled send again keeps its schedule and "
                "releases the lock", wprt_u_enqueue_twice(&u), &failures);
    wprt_u_close(&u);
    return failures;
}

/* ── the pending file, byte for byte ────────────────────────────────── */

struct wprt_ids {
    struct uint256 a, b, c;
};

static bool wprt_u_prepare_steps(struct wprt_u *u, const struct wprt_ids *i)
{
    struct wpr *r = u->r;
    const struct wprt_line one[] = { { 0, &i->a } };
    bool first = wpr_prepare(r, &i->a).ok;
    struct wpr_entry *ea = wprt_u_entry(r, &i->a);
    bool ok = first && ea == &r->entries[0] && ea->state == WPR_PREPARED &&
              ea->last_attempt_ms == -1 &&
              ea->seen_ms == atomic_load(&wprt_now) &&
              wprt_u_file_is(u, one, 1) && wprt_lock_free(r);
    bool again = wpr_prepare(r, &i->a).ok;
    ok = ok && again && wprt_u_used(r) == 1 && wprt_u_file_is(u, one, 1) &&
         wprt_lock_free(r);
    bool second = wpr_prepare(r, &i->b).ok;
    struct wpr_entry *eb = wprt_u_entry(r, &i->b);
    return ok && second && eb && eb != ea && wprt_u_used(r) == 2;
}

static bool wprt_u_expire_steps(struct wprt_u *u, const struct wprt_ids *i)
{
    struct wpr *r = u->r;
    const struct wprt_line two[] = { { 0, &i->a }, { 'x', &i->b } };
    struct wpr_entry *eb = wprt_u_entry(r, &i->b);
    if (!eb)
        return false;
    eb->held = true;
    eb->disk_retry = true;
    eb->expired = true;
    eb->in_pool = true;
    wpr_mark_expired(r, &i->b);
    return eb->state == WPR_EXPIRED && !eb->in_pool && !eb->expired &&
           !eb->held && !eb->disk_retry &&
           eb->seen_ms == atomic_load(&wprt_now) &&
           wprt_u_file_is(u, two, 2) && wprt_lock_free(r);
}

static bool wprt_u_flag_steps(struct wprt_u *u, const struct wprt_ids *i)
{
    struct wpr *r = u->r;
    struct wpr_entry *ea = wprt_u_entry(r, &i->a);
    if (!ea)
        return false;
    wpr_mark_held(r, &i->a, true);
    bool held = ea->held && wprt_lock_free(r);
    wpr_set_disk_retry(r, &i->a, true);
    bool retry = wpr_disk_retry(r, &i->a) && ea->disk_retry &&
                 wprt_lock_free(r);
    wpr_mark_held(r, &i->a, false);
    wpr_set_disk_retry(r, &i->a, false);
    return held && retry && !ea->held && !wpr_disk_retry(r, &i->a) &&
           wprt_lock_free(r);
}

static bool wprt_u_seen_steps(struct wprt_u *u, const struct wprt_ids *i)
{
    struct wpr *r = u->r;
    const struct wprt_line three[] = { { 'a', &i->a }, { 'x', &i->b },
                                       { 0, &i->c } };
    const struct wprt_line after_seen[] = { { 'a', &i->a }, { 'x', &i->b } };
    struct wpr_entry *ea = wprt_u_entry(r, &i->a);
    if (!ea)
        return false;
    ea->handed = true;
    bool third = wpr_prepare(r, &i->c).ok;
    bool ok = third && wprt_u_file_is(u, three, 3);
    struct wpr_entry *ec = wprt_u_entry(r, &i->c);
    if (!ec)
        return false;
    ec->in_pool = true;
    ec->mined = true;
    wpr_note_seen(r, &i->c);
    return ok && ec->state == WPR_SEEN && !ec->in_pool && !ec->mined &&
           ec->seen_ms == atomic_load(&wprt_now) &&
           wprt_u_file_is(u, after_seen, 2) && wprt_lock_free(r);
}

static bool wprt_u_forget_steps(struct wprt_u *u, const struct wprt_ids *i)
{
    const struct wprt_line left[] = { { 'x', &i->b } };
    wpr_forget(u->r, &i->a);
    return !wprt_u_entry(u->r, &i->a) && wprt_u_file_is(u, left, 1) &&
           wprt_lock_free(u->r);
}

static int wprt_u_case_pending_file(void)
{
    int failures = 0;
    struct wprt_u u;
    if (!wprt_u_open(&u, true))
        return wprt_u_open_failed(&u, failures);
    struct wprt_ids i = { wprt_u_id(0x11, 0), wprt_u_id(0x11, 1),
                          wprt_u_id(0x22, 0) };
    wprt_report("a prepared send takes the first slot, is PREPARED with no "
                "attempt, is recorded durably, and an id that differs only "
                "in its last byte is its own send",
                wprt_u_prepare_steps(&u, &i), &failures);
    wprt_report("an expired send is recorded with an x prefix and its flags "
                "are cleared", wprt_u_expire_steps(&u, &i), &failures);
    wprt_report("held and disk_retry are set and cleared by their calls",
                wprt_u_flag_steps(&u, &i), &failures);
    wprt_report("a handed send is recorded with an a prefix; a seen-back send "
                "leaves the record and loses its pool and mined flags",
                wprt_u_seen_steps(&u, &i), &failures);
    wprt_report("a forgotten send leaves the table and the record",
                wprt_u_forget_steps(&u, &i), &failures);
    wprt_u_close(&u);
    return failures;
}

/* ── a record that cannot be made durable ───────────────────────────── */

static bool wprt_u_refused_new(struct wprt_u *u)
{
    struct uint256 q = wprt_u_id(0x62, 0);
    struct uint256 t = wprt_u_id(0x63, 0);
    struct zcl_result prep = wpr_prepare(u->r, &q);
    bool ok = !prep.ok && prep.code == -4 && !wprt_u_entry(u->r, &q) &&
              wprt_u_used(u->r) == 1 && wprt_lock_free(u->r);
    struct transaction tx;
    transaction_init(&tx);
    tx.hash = t;
    struct zcl_result enq = wpr_enqueue(u->r, &tx);
    transaction_free(&tx);
    return ok && !enq.ok && enq.code == -4 && !wprt_u_entry(u->r, &t) &&
           wprt_u_used(u->r) == 1;
}

static bool wprt_u_refused_over(struct wprt_u *u, const struct uint256 *p)
{
    struct transaction tx;
    transaction_init(&tx);
    tx.hash = *p;
    struct zcl_result over = wpr_enqueue(u->r, &tx);
    transaction_free(&tx);
    struct wpr_entry *ep = wprt_u_entry(u->r, p);
    return !over.ok && over.code == -4 && ep && ep->state == WPR_PREPARED &&
           !ep->in_pool && ep->due_ms == 0 &&
           ep->seen_ms == atomic_load(&wprt_now) && wprt_lock_free(u->r);
}

static bool wprt_u_refusals(struct wprt_u *u, const struct uint256 *p)
{
    return wprt_u_refused_new(u) && wprt_u_refused_over(u, p);
}

static int wprt_u_case_record_refused(void)
{
    int failures = 0;
    struct wprt_u u;
    if (!wprt_u_open(&u, true))
        return wprt_u_open_failed(&u, failures);
    struct uint256 p = wprt_u_id(0x61, 0);
    bool first = wpr_prepare(u.r, &p).ok;
    wprt_u_reconfigure(&u, "/nonexistent/wprt-units-refused");
    wprt_report("when the record cannot be written, prepare and enqueue fail "
                "with code -4, a new send leaves no entry, a prepared send "
                "stays as it was, and the lock is released",
                first && wprt_u_refusals(&u, &p), &failures);
    wprt_u_close(&u);
    return failures;
}

/* ── slot reuse order ───────────────────────────────────────────────── */

static void wprt_u_fill_table(struct wpr *r)
{
    for (size_t i = 0; i < WPR_MAX_ENTRIES; i++) {
        struct wpr_entry *e = &r->entries[i];
        memset(e, 0, sizeof(*e));
        e->used = true;
        e->state = WPR_PREPARED;
        memset(e->txid.data, 0x90, sizeof(e->txid.data));
        e->txid.data[0] = (uint8_t)i;
        e->txid.data[1] = 0xEE;
        e->last_attempt_ms = -1;
    }
}

static void wprt_u_terminal(struct wpr *r, size_t slot, enum wpr_state s,
                            int64_t seen_ms)
{
    r->entries[slot].state = s;
    r->entries[slot].seen_ms = seen_ms;
}

static size_t wprt_u_slot_of_new(struct wpr *r, uint8_t seed, bool *ok)
{
    struct uint256 id = wprt_u_id(seed, 0x77);
    struct zcl_result res = wpr_prepare(r, &id);
    struct wpr_entry *e = wprt_u_entry(r, &id);
    *ok = res.ok && e && e->state == WPR_PREPARED;
    return e ? (size_t)(e - r->entries) : WPR_MAX_ENTRIES;
}

static bool wprt_u_full_refused(struct wprt_u *u)
{
    struct uint256 id = wprt_u_id(0x7A, 0x77);
    struct zcl_result prep = wpr_prepare(u->r, &id);
    bool ok = !prep.ok && prep.code == -2 && wprt_lock_free(u->r);
    struct transaction tx;
    transaction_init(&tx);
    tx.hash = id;
    struct zcl_result enq = wpr_enqueue(u->r, &tx);
    transaction_free(&tx);
    return ok && !enq.ok && enq.code == -2 && wprt_u_used(u->r) == 256 &&
           wprt_lock_free(u->r);
}

static int wprt_u_case_slot_reuse(void)
{
    int failures = 0;
    struct wprt_u u;
    if (!wprt_u_open(&u, false))
        return wprt_u_open_failed(&u, failures);
    wprt_u_fill_table(u.r);
    /* Scan order: expired 50 (seen 100), seen 100 (500), expired 150 (50),
     * seen 200 (300), seen 220 (300). Seen records go first, oldest first,
     * the earlier slot on a tie; then expired records, oldest first. */
    wprt_u_terminal(u.r, 50, WPR_EXPIRED, 100);
    wprt_u_terminal(u.r, 100, WPR_SEEN, 500);
    wprt_u_terminal(u.r, 150, WPR_EXPIRED, 50);
    wprt_u_terminal(u.r, 200, WPR_SEEN, 300);
    wprt_u_terminal(u.r, 220, WPR_SEEN, 300);
    static const size_t want[] = { 200, 220, 100, 150, 50 };
    bool all_ok = true;
    bool in_order = true;
    for (size_t k = 0; k < 5; k++) {
        bool ok = false;
        size_t slot = wprt_u_slot_of_new(u.r, (uint8_t)(0x70 + k), &ok);
        all_ok = all_ok && ok;
        in_order = in_order && slot == want[k];
    }
    wprt_report("a full table reuses the oldest seen-back slot, then the "
                "oldest expired one, and never a live send",
                all_ok && in_order, &failures);
    wprt_report("a full table of live sends refuses both prepare and enqueue "
                "with code -2 and releases the lock",
                wprt_u_full_refused(&u), &failures);
    wprt_u_close(&u);
    return failures;
}

/* An unused slot with leftovers is reused clean. */
static int wprt_u_case_dirty_free_slot(void)
{
    int failures = 0;
    struct wprt_u u;
    if (!wprt_u_open(&u, false))
        return wprt_u_open_failed(&u, failures);
    u.r->entries[0].disk_retry = true;
    u.r->entries[0].held = true;
    struct uint256 id = wprt_u_id(0x81, 0);
    bool ok = wpr_prepare(u.r, &id).ok;
    struct wpr_entry *e = wprt_u_entry(u.r, &id);
    wprt_report("a prepared send reuses a free slot without its leftovers",
                ok && e == &u.r->entries[0] && !e->disk_retry && !e->held,
                &failures);
    wprt_u_close(&u);
    return failures;
}

/* ── a hand-written record read back ────────────────────────────────── */

struct wprt_hand {
    const char *pfx;
    char fill;
    size_t len;     /* characters after the prefix */
    size_t bad_at;  /* index of one bad character, or >= len for none */
    char bad;
    bool want;      /* restored as an expired send */
};

static size_t wprt_u_hand_line(char *out, const struct wprt_hand *h)
{
    size_t n = 0;
    while (h->pfx[n]) {
        out[n] = h->pfx[n];
        n++;
    }
    memset(out + n, h->fill, h->len);
    if (h->bad_at < h->len)
        out[n + h->bad_at] = h->bad;
    return n + h->len;
}

static struct uint256 wprt_u_hex_id(char fill)
{
    char hex[65];
    struct uint256 id;
    memset(hex, fill, 64);
    hex[64] = '\0';
    uint256_set_hex(&id, hex);
    return id;
}

/* Only the three good lines may come back. Every bad one has a character
 * outside 0-9a-f at an edge of its range, or a wrong length or prefix. The
 * last good line has no trailing newline. */
static const struct wprt_hand wprt_hand_lines[] = {
    { "x", '1', 64, 99, 0, true },
    { "x", '2', 64, 0, 'g', false },
    { "x", '3', 64, 63, 'g', false },
    { "x", '4', 64, 17, '/', false },
    { "x", '5', 64, 40, ':', false },
    { "x", '6', 64, 7, 'A', false },
    { "x", '7', 64, 9, '`', false },
    { "x", '8', 63, 99, 0, false },
    { "x", '9', 65, 99, 0, false },
    { "y", 'a', 64, 99, 0, false },
    { "X", 'b', 64, 99, 0, false },
    { "x", 'd', 64, 99, 0, true },
    { "x", 'e', 64, 99, 0, true },
};

static size_t wprt_u_hand_file(char *out)
{
    memcpy(out, WPRT_U_HDR, WPRT_U_HDR_LEN);
    size_t len = WPRT_U_HDR_LEN;
    size_t n = sizeof(wprt_hand_lines) / sizeof(wprt_hand_lines[0]);
    for (size_t i = 0; i < n; i++) {
        len += wprt_u_hand_line(out + len, &wprt_hand_lines[i]);
        if (i + 1 < n)
            out[len++] = '\n';
    }
    return len;
}

static bool wprt_u_hand_restored(struct wprt_u *u)
{
    size_t good = 0;
    bool ok = true;
    size_t n = sizeof(wprt_hand_lines) / sizeof(wprt_hand_lines[0]);
    for (size_t i = 0; i < n; i++) {
        if (!wprt_hand_lines[i].want)
            continue;
        good++;
        struct uint256 id = wprt_u_hex_id(wprt_hand_lines[i].fill);
        struct wpr_entry *e = wprt_u_entry(u->r, &id);
        ok = ok && e && e->state == WPR_EXPIRED && e->last_attempt_ms == -1 &&
             e->seen_ms == atomic_load(&wprt_now) && !e->in_pool &&
             !e->handed && !e->held && !e->disk_retry && e->attempts == 0;
    }
    return ok && wprt_u_used(u->r) == good &&
           wprt_u_count_state(u->r, WPR_EXPIRED) == good;
}

static int wprt_u_case_hand_written(void)
{
    int failures = 0;
    struct wprt_u u;
    if (!wprt_u_open(&u, true))
        return wprt_u_open_failed(&u, failures);
    /* The record 'd' is already in the table with leftovers: reading it
     * back must reuse its slot and clear them. */
    struct uint256 d = wprt_u_hex_id('d');
    bool prepared = wpr_prepare(u.r, &d).ok;
    struct wpr_entry *ed = wprt_u_entry(u.r, &d);
    if (!prepared || !ed)
        return wprt_u_open_failed(&u, failures);
    ed->held = true;
    ed->disk_retry = true;
    ed->handed = true;
    ed->attempts = 3;
    static char file[4096];
    size_t len = wprt_u_hand_file(file);
    bool put = wprt_u_put(&u, file, len);
    bool resumed = prepared && put && wpr_resume(u.r).ok;
    wprt_report("reading a record back restores exactly the well-formed "
                "expired lines, however the bad ones are malformed, with a "
                "clean entry each, including a last line with no newline",
                resumed && wprt_u_hand_restored(&u), &failures);
    wprt_report("the restored record is rewritten as three expired lines, "
                "and the lock is released",
                resumed && wprt_u_slurp(&u) ==
                    (long)(WPRT_U_HDR_LEN + 3 * 66) && wprt_lock_free(u.r),
                &failures);
    wprt_u_close(&u);
    return failures;
}

/* ── a full record, and a longer one than the table ─────────────────── */

static size_t wprt_u_full_file(char *out, char pfx)
{
    memcpy(out, WPRT_U_HDR, WPRT_U_HDR_LEN);
    size_t len = WPRT_U_HDR_LEN;
    size_t lines = pfx ? WPR_MAX_ENTRIES : WPR_MAX_ENTRIES + 2;
    for (size_t i = 0; i < lines; i++) {
        if (pfx)
            out[len++] = pfx;
        snprintf(out + len, 3, "%02x", (unsigned)(i & 0xff));
        memset(out + len + 2, (int)(0x35 + (i >> 8)), 62);
        len += 64;
        out[len++] = '\n';
    }
    return len;
}

static int wprt_u_case_full_record(void)
{
    int failures = 0;
    struct wprt_u u;
    if (!wprt_u_open(&u, true))
        return wprt_u_open_failed(&u, failures);
    static char file[20000];
    size_t len = wprt_u_full_file(file, 'x');
    bool resumed = wprt_u_put(&u, file, len) && wpr_resume(u.r).ok;
    long got = wprt_u_slurp(&u);
    wprt_report("a record of 256 expired lines (the longest the table "
                "holds) is read back whole",
                resumed && wprt_u_used(u.r) == WPR_MAX_ENTRIES &&
                    wprt_u_count_state(u.r, WPR_EXPIRED) == WPR_MAX_ENTRIES,
                &failures);
    wprt_report("and is written out again byte for byte",
                resumed && got == (long)len &&
                    memcmp(wprt_u_buf, file, len) == 0,
                &failures);
    wprt_u_close(&u);
    return failures;
}

static int wprt_u_case_overlong_record(void)
{
    int failures = 0;
    struct wprt_u u;
    if (!wprt_u_open(&u, true))
        return wprt_u_open_failed(&u, failures);
    static char file[20000];
    size_t len = wprt_u_full_file(file, 0);
    bool resumed = wprt_u_put(&u, file, len) && wpr_resume(u.r).ok;
    wprt_report("a record with more lines than the table holds is read "
                "without overrunning it; the wallet holds none of them, so "
                "none is kept",
                resumed && wprt_u_used(u.r) == 0 && wprt_lock_free(u.r),
                &failures);
    wprt_u_close(&u);
    return failures;
}

/* ── nothing to read, and a send the wallet does not hold ───────────── */

/* The next call's locals land on the bytes this one leaves behind. */
__attribute__((noinline)) static void wprt_u_dirty_stack(void)
{
    volatile unsigned char junk[60000];
    for (size_t i = 0; i < sizeof(junk); i++)
        junk[i] = 1;
}

static bool wprt_u_resume_finds_nothing(struct wprt_u *u)
{
    wprt_u_dirty_stack();
    bool ok = wpr_resume(u->r).ok;
    return ok && wprt_u_used(u->r) == 0 && wprt_lock_free(u->r);
}

static bool wprt_u_resume_forgets(struct wprt_u *u)
{
    struct uint256 id = wprt_u_id(0x91, 0);
    bool prepared = wpr_prepare(u->r, &id).ok;
    bool ok = prepared && wprt_u_entry(u->r, &id) && wpr_resume(u->r).ok;
    return ok && !wprt_u_entry(u->r, &id) && wprt_u_file_is(u, NULL, 0) &&
           wprt_lock_free(u->r);
}

static int wprt_u_case_resume_nothing(void)
{
    int failures = 0;
    struct wprt_u none, dir;
    bool a = wprt_u_open(&none, false);
    bool b = wprt_u_open(&dir, true);
    wprt_report("a relay without a data directory resumes nothing",
                a && wprt_u_resume_finds_nothing(&none), &failures);
    wprt_report("a data directory without a record resumes nothing",
                b && wprt_u_resume_finds_nothing(&dir), &failures);
    wprt_report("a recorded send the wallet does not hold is dropped from "
                "the table and the record",
                b && wprt_u_resume_forgets(&dir), &failures);
    wprt_u_close(&none);
    wprt_u_close(&dir);
    return failures;
}


static int wprt_units_run(void)
{
    int failures = 0;
    failures += wprt_u_case_names_and_init();
    failures += wprt_u_case_null_arguments();
    failures += wprt_u_case_delay_and_fields();
    failures += wprt_u_case_pending_file();
    failures += wprt_u_case_record_refused();
    failures += wprt_u_case_slot_reuse();
    failures += wprt_u_case_dirty_free_slot();
    failures += wprt_u_case_hand_written();
    failures += wprt_u_case_full_record();
    failures += wprt_u_case_overlong_record();
    failures += wprt_u_case_resume_nothing();
    return failures;
}

/* ── resume against a real wallet ───────────────────────────────────── */

/* The wallet holds a send the chain has since consumed an input of: the
 * private pool refuses it, so a resumed relay must not call it scheduled. */
static int wprt_case_resume_refused_by_pool(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, false);
    struct uint256 id;
    ok = ok && wprt_add_peer(&f, WPRT_ONION_OUT) &&
         wprt_rpc_send(&f, false, 10.0, &id);
    struct outpoint spent;
    memset(&spent, 0, sizeof(spent));
    struct wallet_tx held;
    bool have = ok && wprt_copy_tx(&f, &id, &held);
    if (have) {
        have = held.tx.num_vin > 0;
        if (have)
            spent = held.tx.vin[0].prevout;
        transaction_free(&held.tx);
    }
    if (have)
        wprt_chain_consumes(&f, &spent);
    ok = ok && have;
    wprt_restart_relay(&f);
    bool resumed = ok && wpr_resume(wpr_global()).ok;
    bool found = false;
    enum wpr_state st = wprt_state(&id, &found);
    wprt_report("a resumed send whose input the chain has consumed is held "
                "for a route, never scheduled, and is not in the private pool",
                resumed && found && st == WPR_WAITING_FOR_ROUTE &&
                    !tx_mempool_exists(wpr_pool(wpr_global()), &id) &&
                    tx_mempool_size(&f.main_pool) == 0,
                &failures);
    wprt_close(&f);
    return failures;
}

/* A send with one confirmation is done: resume must not schedule it. */
static int wprt_case_resume_confirmed_once(void)
{
    int failures = 0;
    struct wprt_fx f;
    bool ok = wprt_wallet_ready(&f, WPR_MODE_PRIVATE, 2, false);
    struct uint256 id;
    ok = ok && wprt_add_peer(&f, WPRT_ONION_OUT) &&
         wprt_rpc_send(&f, false, 10.0, &id);
    struct wallet_tx wtx;
    struct uint256 bh;
    memset(bh.data, 0xB3, 32);
    struct block_index bi;
    memset(&bi, 0, sizeof(bi));
    bi.nHeight = 50;
    bi.phashBlock = &bh;
    bool have = ok && wprt_copy_tx(&f, &id, &wtx);
    wprt_set_wallet_height(&f, 50);
    if (have) {
        wallet_sync_transaction(f.wallet, &wtx.tx, &bi);
        transaction_free(&wtx.tx);
    }
    struct wallet_tx now;
    bool once = have && wprt_copy_tx(&f, &id, &now) && now.confirms == 1;
    if (once)
        transaction_free(&now.tx);
    wprt_restart_relay(&f);
    bool recorded = once && wpr_prepare(wpr_global(), &id).ok;
    bool resumed = recorded && wpr_resume(wpr_global()).ok;
    bool found = false;
    enum wpr_state st = wprt_state(&id, &found);
    wprt_report("the wallet shows the send with exactly one confirmation",
                once, &failures);
    wprt_report("a resumed send with one confirmation is not scheduled and "
                "not in the private pool",
                resumed && found && st != WPR_SCHEDULED &&
                    st != WPR_WAITING_FOR_ROUTE &&
                    !tx_mempool_exists(wpr_pool(wpr_global()), &id),
                &failures);
    wprt_close(&f);
    return failures;
}

int wprp_run_tests(void);
int test_wallet_private_relay(void);
int test_wallet_private_relay(void)
{
    int failures = 0;
    failures += wprp_run_tests();
    failures += wprt_units_run();
    failures += wprt_case_resume_refused_by_pool();
    failures += wprt_case_resume_confirmed_once();
    failures += wprt_case_public_witness();
    failures += wprt_case_private_send();
    failures += wprt_case_delay();
    failures += wprt_case_one_peer_per_attempt();
    failures += wprt_case_no_route();
    failures += wprt_case_service_violated();
    failures += wprt_case_seen_and_block();
    failures += wprt_case_expiry_margin();
    failures += wprt_case_expiry_confirmed();
    failures += wprt_case_expiry_database();
    failures += wprt_case_expiry_unverified();
    failures += wprt_case_expiry_disk_full();
    failures += wprt_case_prepared_before_wallet();
    failures += wprt_case_record_refused();
    failures += wprt_case_unsupported();
    failures += wprt_case_restart();
    failures += wprt_case_public_restart();
    failures += wprt_case_boot();
    failures += wprt_case_checked_pending_reader();
    failures += wprt_case_invalid_pending_count();
    failures += wprt_case_pending_guard();
    failures += wprt_case_pending_guard_bound();
    failures += wprt_case_unready_accepted_hook(true);
    failures += wprt_case_unready_accepted_hook(false);
    failures += wprt_case_unready_boot_configuration(true);
    failures += wprt_case_unready_boot_configuration(false);
    failures += wprt_case_chained();
#ifdef ZCL_TESTING
    failures += wprt_case_intent_retry_readiness();
#endif
    failures += wprt_case_plan_reopen(true);
    failures += wprt_case_plan_reopen(false);
    failures += wprt_case_main_pool_refused();
    failures += wprt_case_sole_peer_handed();
    failures += wprt_case_queue_refused();
    failures += wprt_case_unknown_after_failed_rollback();
    failures += wprt_case_resume_reserves_notes();
    failures += wprt_case_missing_hold_proof();
    failures += wprt_case_checked_hold_proof();
    failures += wprt_case_nullifier_hold();
    failures += wprt_case_held_and_seen();
    failures += wprt_case_held_at_zero();
    failures += wprt_case_handed_saved_first();
    failures += wprt_case_seen_then_expired();
    failures += wprt_case_config();
    return failures;
}
