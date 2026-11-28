/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Relay a private tip after hash-bound durable application. */
// one-result-type-ok:retry-predicate — false means retry the next supervisor tick.
#include "services/private_applied_relay.h"
#include "services/chain_activation_service.h"
#include "base/safe_alloc.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "jobs/tip_finalize_stage.h"
#include "net/connman.h"
#include "storage/progress_store.h"
#include "util/sync.h"
#include "util/log_macros.h"
#include "validation/main_state.h"
#include <sqlite3.h>
#include <stdlib.h>

static zcl_once_t g_once = ZCL_ONCE_INIT;
static zcl_mutex_t g_relay_lock;
struct private_relay_peer {
    struct p2p_node *node;
    node_id_t id;
    struct uint256 hash;
    bool sent;
};
static struct connman *g_cm;
static struct private_relay_peer *g_peers;
static size_t g_peer_count;
#ifdef ZCL_TESTING
static void (*g_test_recheck_hook)(void *);
static void *g_test_recheck_ctx;
static bool g_test_evidence;
void private_applied_relay_test_before_recheck(void (*hook)(void *), void *ctx)
{
    g_test_recheck_hook = hook;
    g_test_recheck_ctx = ctx;
}
void private_applied_relay_test_evidence(bool allow) { g_test_evidence = allow; }
#endif

static void private_relay_init(void) { zcl_mutex_init(&g_relay_lock); }

void private_applied_relay_reset(void)
{
    if (!zcl_once_call(&g_once, private_relay_init)) return;
    zcl_mutex_lock(&g_relay_lock);
    free(g_peers);
    g_peers = NULL;
    g_peer_count = 0;
    g_cm = NULL;
#ifdef ZCL_TESTING
    g_test_recheck_hook = NULL;
    g_test_recheck_ctx = NULL;
    g_test_evidence = false;
#endif
    zcl_mutex_unlock(&g_relay_lock);
}

/* Caller holds both g_relay_lock and cs_nodes. Retain only live identities. */
static bool private_relay_sync_peers(struct connman *cm)
{
    size_t n = cm->manager.num_nodes;
    bool same = g_cm == cm && n == g_peer_count;
    for (size_t i = 0; same && i < n; i++)
        same = g_peers[i].node == cm->manager.nodes[i] &&
               g_peers[i].id == cm->manager.nodes[i]->id;
    if (same) return true;
    struct private_relay_peer *next = n ? zcl_calloc(n, sizeof(*next), "private_relay_peers") : NULL;
    if (n && !next) return false;
    for (size_t i = 0; i < n; i++) {
        struct p2p_node *peer = cm->manager.nodes[i];
        next[i].node = peer;
        next[i].id = peer->id;
        for (size_t j = 0; g_cm == cm && j < g_peer_count; j++) {
            if (g_peers[j].node == peer && g_peers[j].id == peer->id) {
                next[i].hash = g_peers[j].hash;
                next[i].sent = g_peers[j].sent;
                break;
            }
        }
    }
    free(g_peers);
    g_peers = next;
    g_peer_count = n;
    g_cm = cm;
    return true;
}

/* Caller holds g_relay_lock; -1 retries, 0 is already delivered, 1 needs work. */
static int private_relay_needed(struct connman *cm, const struct uint256 *hash)
{
    int result = -1;
    zcl_mutex_lock(&cm->manager.cs_nodes);
    if (private_relay_sync_peers(cm)) {
        for (size_t i = 0; i < g_peer_count; i++) {
            struct p2p_node *peer = g_peers[i].node;
            if (peer->state < PEER_HANDSHAKE_COMPLETE || peer->disconnect) continue;
            if (result < 0) result = 0;
            if (!g_peers[i].sent || !uint256_eq(&g_peers[i].hash, hash)) result = 1;
        }
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);
    return result;
}

/* Read only the peer's existing inventory authority, under its own lock. */
static bool private_peer_has_inventory_locked(struct p2p_node *peer,
                                              const struct uint256 *hash)
{
    bool found = false;
    for (size_t i = 0; i < peer->inventory_to_send_count && !found; i++)
        found = uint256_eq(&peer->inventory_to_send[i].hash, hash);
    for (size_t i = 0; i < peer->inventory_known_count && !found; i++)
        found = uint256_eq(&peer->inventory_known_hashes[i], hash);
    return found;
}

/* The core enqueue API is void: inspect its protected queue afterwards so
 * an allocation failure or absence of eligible peers retains the wakeup. */
static bool private_relay_locked(struct connman *cm, const struct uint256 *hash,
                                 size_t *queued_out)
{
    struct inv_item inv;
    inv_item_init_typed(&inv, MSG_BLOCK, hash);
    bool ok = true;
    size_t eligible = 0;
    size_t queued = 0;
    zcl_mutex_lock(&cm->manager.cs_nodes);
    if (!private_relay_sync_peers(cm)) {
        zcl_mutex_unlock(&cm->manager.cs_nodes);
        return false;
    }
    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        struct p2p_node *peer = cm->manager.nodes[i];
        if (peer->state < PEER_HANDSHAKE_COMPLETE || peer->disconnect) continue;
        eligible++;
        if (g_peers[i].sent && uint256_eq(&g_peers[i].hash, hash)) continue;
        /* cs_inventory is recursive; keep it held through the existing
         * enqueue so the sender cannot drain the item before inspection. */
        zcl_mutex_lock(&peer->cs_inventory);
        bool had = private_peer_has_inventory_locked(peer, hash);
        if (!had)
            p2p_node_push_inventory(peer, &inv);
        if (!private_peer_has_inventory_locked(peer, hash)) ok = false;
        else {
            g_peers[i].hash = *hash;
            g_peers[i].sent = true;
            if (!had) queued++;
        }
        zcl_mutex_unlock(&peer->cs_inventory);
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);
    *queued_out = queued;
    return eligible > 0 && ok;
}

static void private_relay_log(const struct uint256 *hash, size_t queued)
{
    if (queued) {
        char hex[65];
        uint256_get_hex(hash, hex);
        LOG_INFO("net", "private applied relay queued %s peers=%zu", hex, queued);
    }
}

#ifdef ZCL_TESTING
bool private_applied_relay_now(struct connman *cm, const struct uint256 *hash)
{
    if (!cm || !hash || !zcl_once_call(&g_once, private_relay_init)) return false;
    zcl_mutex_lock(&g_relay_lock);
    size_t queued = 0;
    bool ok = private_relay_locked(cm, hash, &queued);
    zcl_mutex_unlock(&g_relay_lock);
    private_relay_log(hash, queued);
    return ok;
}
#endif

static bool private_relay_evidence(const struct block_index *tip)
{
#ifdef ZCL_TESTING
    if (g_test_evidence) return true;
#endif
    if (!progress_store_tx_trylock()) return false;
    sqlite3 *db = progress_store_db();
    bool ok = db && sqlite3_get_autocommit(db) &&
              tip_finalize_full_evidence_at(db, tip->nHeight, tip->phashBlock) == 1;
    progress_store_tx_unlock();
    return ok;
}

/* With evidence=true, require that the selected hash has not changed since
 * the first observation and authenticate it from committed validation rows. */
static bool private_relay_select(struct chain_activation_controller *ctl,
                                 struct uint256 *hash, bool evidence)
{
    if (!zcl_mutex_trylock(&ctl->mutex)) return false;
    if (!ctl->ms || !zcl_mutex_trylock(&ctl->ms->cs_main)) {
        zcl_mutex_unlock(&ctl->mutex);
        return false;
    }
    struct block_index *tip = active_chain_tip(&ctl->ms->chain_active);
    bool ok = tip && tip->phashBlock && !(tip->nStatus & BLOCK_FAILED_MASK);
    if (ok && evidence)
        ok = uint256_eq(tip->phashBlock, hash) && private_relay_evidence(tip);
    else if (ok)
        *hash = *tip->phashBlock;
    zcl_mutex_unlock(&ctl->ms->cs_main);
    zcl_mutex_unlock(&ctl->mutex);
    return ok;
}

bool private_applied_relay_check(struct chain_activation_controller *ctl,
                                 struct connman *cm)
{
    const struct chain_research_descriptor *profile = chain_research_profile_current();
    if (!profile || profile->id != CHAIN_RESEARCH_IRONWOOD ||
        !ctl || ctl->params != profile->chain) return true;
    if (!cm || !zcl_once_call(&g_once, private_relay_init)) return false;
    zcl_mutex_lock(&g_relay_lock);
    struct uint256 hash;
    if (!private_relay_select(ctl, &hash, false)) {
        zcl_mutex_unlock(&g_relay_lock);
        return false;
    }
    int needed = private_relay_needed(cm, &hash);
    if (needed <= 0) {
        zcl_mutex_unlock(&g_relay_lock);
        return needed == 0;
    }
#ifdef ZCL_TESTING
    if (g_test_recheck_hook) g_test_recheck_hook(g_test_recheck_ctx);
#endif
    bool ok = private_relay_select(ctl, &hash, true);
    size_t queued = 0;
    if (ok) ok = private_relay_locked(cm, &hash, &queued);
    zcl_mutex_unlock(&g_relay_lock);
    if (ok || queued) private_relay_log(&hash, queued);
    return ok;
}
