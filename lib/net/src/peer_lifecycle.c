/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "net/peer_lifecycle.h"

#include "core/utiltime.h"
#include "event/event.h"
#include "net/connman.h"
#include "net/net.h"
#include "net/download.h"
#include "net/fast_sync.h"
#include "net/peer_scoring.h"
#include "storage/peers_projection.h"
#include "storage/event_log_payloads.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "peer_lifecycle_internal.h"

static struct {
    pthread_mutex_t lock;
    struct peer_lifecycle_entry entries[PEER_LIFECYCLE_MAX];
    struct peer_lifecycle_summary totals;
    uint64_t seq;
} g_pl = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

const char *peer_lifecycle_source_name(enum peer_lifecycle_source source)
{
    switch (source) {
        case PEER_LIFECYCLE_SOURCE_INBOUND:  return "inbound";
        case PEER_LIFECYCLE_SOURCE_ADDNODE:  return "addnode";
        case PEER_LIFECYCLE_SOURCE_ADDRMAN:  return "addrman";
        case PEER_LIFECYCLE_SOURCE_ZCL23_DB: return "zcl23_db";
        case PEER_LIFECYCLE_SOURCE_MANUAL:   return "manual";
        case PEER_LIFECYCLE_SOURCE_ANCHOR:   return "anchor";
        case PEER_LIFECYCLE_SOURCE_UNKNOWN:
        default:                             return "unknown";
    }
}

static void addr_key_from_netaddr(const struct net_address *addr,
                                  char *out, size_t out_sz)
{
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    if (!addr) {
        snprintf(out, out_sz, "unknown");
        return;
    }
    net_service_to_string(&addr->svc, out, out_sz);
}

static void addr_key_from_node(const struct p2p_node *node,
                               char *out, size_t out_sz)
{
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    if (node && node->addr_name[0])
        snprintf(out, out_sz, "%s", node->addr_name);
    else if (node)
        addr_key_from_netaddr(&node->addr, out, out_sz);
    else
        snprintf(out, out_sz, "unknown");
}

static struct peer_lifecycle_entry *find_entry_locked(const char *addr,
                                                      int64_t peer_id,
                                                      bool create)
{
    struct peer_lifecycle_entry *free_slot = NULL;
    for (size_t i = 0; i < PEER_LIFECYCLE_MAX; i++) {
        struct peer_lifecycle_entry *e = &g_pl.entries[i];
        if (!e->used) {
            if (!free_slot) free_slot = e;
            continue;
        }
        if (peer_id >= 0 && e->peer_id == peer_id)
            return e;
        if (addr && addr[0] && strcmp(e->addr, addr) == 0)
            return e;
    }
    if (!create)
        return NULL;
    struct peer_lifecycle_entry *e = free_slot;
    if (!e)
        e = &g_pl.entries[(size_t)(GetTime() % PEER_LIFECYCLE_MAX)];
    memset(e, 0, sizeof(*e));
    e->used = true;
    e->peer_id = peer_id;
    e->first_seen = GetTime();
    e->last_seen = e->first_seen;
    e->source = PEER_LIFECYCLE_SOURCE_UNKNOWN;
    if (addr && addr[0])
        snprintf(e->addr, sizeof(e->addr), "%s", addr);
    return e;
}

static struct peer_lifecycle_entry *entry_for_node_locked(
    const struct p2p_node *node, bool create)
{
    char addr[256];
    addr_key_from_node(node, addr, sizeof(addr));
    return find_entry_locked(addr, node ? node->id : -1, create);
}

static bool subver_is_magicbean(const char *subver)
{
    return subver && strstr(subver, "MagicBean") != NULL;
}

static bool subver_is_zcl23(const char *subver, uint64_t services)
{
    return peer_supports_fast_sync(services) ||
           (subver && (strstr(subver, "ZClassic23") != NULL ||
                       strstr(subver, "ZClassic-C23") != NULL));
}

static int64_t handshake_duration_secs(const struct peer_lifecycle_entry *e)
{
    if (!e || e->connected_at <= 0 || e->handshake_complete_at <= 0)
        return 0;
    if (e->handshake_complete_at <= e->connected_at)
        return 0;
    return e->handshake_complete_at - e->connected_at;
}

static void addr_host_key(const char *addr, char *out, size_t out_sz)
{
    if (!out || out_sz == 0)
        return;
    out[0] = '\0';
    if (!addr || !addr[0]) {
        snprintf(out, out_sz, "unknown");
        return;
    }

    if (addr[0] == '[') {
        const char *end = strchr(addr, ']');
        if (end && end > addr + 1) {
            size_t n = (size_t)(end - addr - 1);
            if (n >= out_sz)
                n = out_sz - 1;
            memcpy(out, addr + 1, n);
            out[n] = '\0';
            return;
        }
    }

    const char *first_colon = strchr(addr, ':');
    const char *last_colon = strrchr(addr, ':');
    if (first_colon && first_colon == last_colon && first_colon > addr) {
        size_t n = (size_t)(first_colon - addr);
        if (n >= out_sz)
            n = out_sz - 1;
        memcpy(out, addr, n);
        out[n] = '\0';
        return;
    }

    snprintf(out, out_sz, "%s", addr);
}

static bool source_is_inbound(enum peer_lifecycle_source source)
{
    return source == PEER_LIFECYCLE_SOURCE_INBOUND;
}

static bool source_is_outbound(enum peer_lifecycle_source source)
{
    return source == PEER_LIFECYCLE_SOURCE_ADDNODE ||
           source == PEER_LIFECYCLE_SOURCE_ADDRMAN ||
           source == PEER_LIFECYCLE_SOURCE_ZCL23_DB ||
           source == PEER_LIFECYCLE_SOURCE_MANUAL ||
           source == PEER_LIFECYCLE_SOURCE_ANCHOR;
}

static const char *entry_direction(const struct peer_lifecycle_entry *e)
{
    if (!e)
        return "unknown";
    if (source_is_inbound(e->source))
        return "inbound";
    if (source_is_outbound(e->source))
        return "outbound";
    return "unknown";
}

static int direction_count(int64_t inbound, int64_t outbound, int64_t unknown)
{
    int n = 0;
    if (inbound > 0)
        n++;
    if (outbound > 0)
        n++;
    if (unknown > 0)
        n++;
    return n;
}

static bool direction_mixed(int64_t inbound, int64_t outbound,
                            int64_t unknown)
{
    return direction_count(inbound, outbound, unknown) > 1;
}

static const char *direction_summary(int64_t inbound, int64_t outbound,
                                     int64_t unknown)
{
    int n = direction_count(inbound, outbound, unknown);
    if (n > 1)
        return "mixed";
    if (inbound > 0)
        return "inbound";
    if (outbound > 0)
        return "outbound";
    return "unknown";
}

static const char *host_group_direction(
    const struct peer_lifecycle_host_group *g)
{
    if (!g)
        return "unknown";
    return direction_summary(g->inbound_entries, g->outbound_entries,
                             g->unknown_entries);
}

static bool host_group_mixed_direction(
    const struct peer_lifecycle_host_group *g)
{
    if (!g)
        return false;
    return direction_mixed(g->inbound_entries, g->outbound_entries,
                           g->unknown_entries);
}

static bool entry_connection_open(const struct peer_lifecycle_entry *e)
{
    if (!e || e->connected_seq == 0)
        return false;
    return e->connected_seq > e->terminal_seq;
}

static bool entry_current_connection_handshaked(
    const struct peer_lifecycle_entry *e)
{
    if (!entry_connection_open(e))
        return false;
    return e->handshake_complete_seq >= e->connected_seq &&
           e->handshake_complete_seq > e->terminal_seq;
}

static int64_t entry_handshake_age_secs(const struct peer_lifecycle_entry *e,
                                        int64_t now)
{
    if (!entry_current_connection_handshaked(e))
        return -1;
    if (now <= e->handshake_complete_at)
        return 0;
    return now - e->handshake_complete_at;
}

static int64_t entry_reconnects(const struct peer_lifecycle_entry *e)
{
    if (!e || e->connected <= 1)
        return 0;
    return e->connected - 1;
}

static void append_summary_token(char *out, size_t out_sz, const char *token)
{
    if (!out || out_sz == 0 || !token || !token[0])
        return;
    size_t used = strlen(out);
    if (used >= out_sz - 1)
        return;
    int n = snprintf(out + used, out_sz - used, "%s%s",
                     used > 0 ? "|" : "", token);
    if (n < 0)
        out[out_sz - 1] = '\0';
}

static void services_summary(uint64_t services, char *out, size_t out_sz)
{
    if (!out || out_sz == 0)
        return;
    out[0] = '\0';
    if ((services & NODE_NETWORK) != 0)
        append_summary_token(out, out_sz, "NODE_NETWORK");
    if ((services & NODE_BLOOM) != 0)
        append_summary_token(out, out_sz, "NODE_BLOOM");
    if ((services & NODE_ZCL23) != 0)
        append_summary_token(out, out_sz, "NODE_ZCL23");
    uint64_t known = NODE_NETWORK | NODE_BLOOM | NODE_ZCL23;
    uint64_t unknown = services & ~known;
    if (unknown != 0) {
        char buf[48];
        snprintf(buf, sizeof(buf), "UNKNOWN_0x%llx",
                 (unsigned long long)unknown);
        append_summary_token(out, out_sz, buf);
    }
    if (out[0] == '\0')
        snprintf(out, out_sz, "none");
}

static bool entry_advertised_height_trusted(
    const struct peer_lifecycle_entry *e)
{
    return entry_current_connection_handshaked(e) &&
           (e->services & NODE_NETWORK) != 0 &&
           e->start_height > 0;
}

static bool entry_bootstrap_useful(const struct peer_lifecycle_entry *e)
{
    return entry_advertised_height_trusted(e);
}

static const char *entry_advertised_height_trust(
    const struct peer_lifecycle_entry *e)
{
    if (!e || e->start_height <= 0)
        return "missing";
    if (!entry_connection_open(e))
        return "stale_connection";
    if (!entry_current_connection_handshaked(e))
        return "handshake_incomplete";
    if ((e->services & NODE_NETWORK) == 0)
        return "untrusted_missing_NODE_NETWORK";
    return "trusted";
}

static const char *entry_bootstrap_readiness(
    const struct peer_lifecycle_entry *e)
{
    if (!e || !entry_connection_open(e))
        return "not_connected";
    if (!entry_current_connection_handshaked(e))
        return "handshake_incomplete";
    if ((e->services & NODE_NETWORK) == 0)
        return "missing_NODE_NETWORK";
    if (e->start_height <= 0)
        return "missing_advertised_height";
    return "useful";
}

static bool entry_fast_sync_useful(const struct peer_lifecycle_entry *e)
{
    return entry_bootstrap_useful(e) &&
           subver_is_zcl23(e->subver, e->services);
}

static const char *host_group_bootstrap_readiness(
    const struct peer_lifecycle_host_group *g)
{
    if (!g || g->entries <= 0)
        return "no_peer_history";
    if (g->bootstrap_useful)
        return "useful";
    if (g->handshaked_open_connections <= 0)
        return "no_current_handshaked_connection";
    if (g->handshaked_network_connections <= 0)
        return "missing_NODE_NETWORK";
    if (g->handshaked_advertised_height_connections <= 0)
        return "missing_advertised_height";
    return "split_bootstrap_capabilities";
}

static const char *host_group_advertised_height_trust(
    const struct peer_lifecycle_host_group *g)
{
    if (!g || g->handshaked_open_connections <= 0)
        return "no_current_handshaked_connection";
    if (g->handshaked_trusted_advertised_height_connections > 0)
        return "trusted";
    if (g->handshaked_advertised_height_connections <= 0)
        return "missing";
    if (g->handshaked_network_connections > 0)
        return "split_bootstrap_capabilities";
    if (g->handshaked_untrusted_advertised_height_connections > 0)
        return "untrusted_missing_NODE_NETWORK";
    return "split_bootstrap_capabilities";
}

static const char *host_group_fast_sync_readiness(
    const struct peer_lifecycle_host_group *g)
{
    if (!g || g->entries <= 0)
        return "no_peer_history";
    if (g->fast_sync_useful)
        return "useful";
    const char *bootstrap = host_group_bootstrap_readiness(g);
    if (strcmp(bootstrap, "useful") != 0)
        return bootstrap;
    return "missing_zclassic23_fast_sync";
}

static bool entry_cache_skip_actionable(const struct peer_lifecycle_entry *e)
{
    if (!e || e->cache_skipped <= 0)
        return false;
    if (source_is_inbound(e->source) &&
        entry_current_connection_handshaked(e) &&
        strcmp(e->last_reason, "inbound_ephemeral_port") == 0)
        return false;
    return true;
}

static int64_t entry_incident_score(const struct peer_lifecycle_entry *e,
                                    int64_t duplicate_host_entries)
{
    if (!e)
        return 0;
    int64_t score = 0;
    score += entry_reconnects(e) * 3;
    score += e->timeout * 3;
    score += e->rejected * 3;
    score += e->pre_handshake_disconnects * 2;
    score += e->disconnected;
    if (entry_cache_skip_actionable(e))
        score += e->cache_skipped;
    if (duplicate_host_entries > 1)
        score += (duplicate_host_entries - 1) * 2;
    return score;
}

void peer_lifecycle_note_attempt(const struct net_address *addr,
                                 enum peer_lifecycle_source source)
{
    char key[256];
    addr_key_from_netaddr(addr, key, sizeof(key));
    pthread_mutex_lock(&g_pl.lock);
    struct peer_lifecycle_entry *e = find_entry_locked(key, -1, true);
    if (e) {
        e->attempted++;
        e->last_seen = GetTime();
        if (source != PEER_LIFECYCLE_SOURCE_UNKNOWN)
            e->source = source;
    }
    g_pl.totals.attempted++;
    pthread_mutex_unlock(&g_pl.lock);
    event_emitf(EV_PEER_HANDSHAKE_ATTEMPT, 0, "%s source=%s", key,
                peer_lifecycle_source_name(source));
}

void peer_lifecycle_note_connected(const struct p2p_node *node,
                                   enum peer_lifecycle_source source)
{
    pthread_mutex_lock(&g_pl.lock);
    struct peer_lifecycle_entry *e = entry_for_node_locked(node, true);
    if (e) {
        int64_t now = GetTime();
        uint64_t seq = ++g_pl.seq;
        bool terminal_after_connect =
            e->terminal_seq > 0 && e->terminal_seq >= e->connected_seq;
        e->peer_id = node ? node->id : e->peer_id;
        if (terminal_after_connect && e->connected_at > 0) {
            e->last_reconnect_at = now;
            e->last_reconnect_interval_secs =
                now >= e->connected_at ? now - e->connected_at : 0;
        }
        e->connected++;
        if (e->connected_at == 0 || terminal_after_connect) {
            e->connected_at = now;
            e->connected_seq = seq;
            e->version_sent_at = 0;
            e->version_received_at = 0;
            e->verack_received_at = 0;
            e->handshake_complete_at = 0;
            e->handshake_complete_seq = 0;
            e->active_at = 0;
        }
        e->last_seen = now;
        if (source != PEER_LIFECYCLE_SOURCE_UNKNOWN)
            e->source = source;
    }
    g_pl.totals.connected++;
    pthread_mutex_unlock(&g_pl.lock);
}

void peer_lifecycle_note_version_sent(const struct p2p_node *node,
                                      uint64_t services,
                                      int start_height,
                                      const char *subver)
{
    (void)services;
    (void)start_height;
    (void)subver;
    pthread_mutex_lock(&g_pl.lock);
    struct peer_lifecycle_entry *e = entry_for_node_locked(node, true);
    if (e) {
        e->version_sent++;
        e->version_sent_at = GetTime();
        e->last_seen = e->version_sent_at;
    }
    g_pl.totals.version_sent++;
    pthread_mutex_unlock(&g_pl.lock);
    if (node) {
        event_emitf(EV_PEER_HANDSHAKE_ATTEMPT, (uint32_t)node->id,
                    "version_sent addr=%s services=%llu height=%d subver=%s",
                    node->addr_name, (unsigned long long)services,
                    start_height, subver ? subver : "");
    }
}

void peer_lifecycle_note_version_received(const struct p2p_node *node,
                                          uint64_t services,
                                          int start_height,
                                          const char *subver)
{
    pthread_mutex_lock(&g_pl.lock);
    struct peer_lifecycle_entry *e = entry_for_node_locked(node, true);
    if (e) {
        e->version_received++;
        e->version_received_at = GetTime();
        e->last_seen = e->version_received_at;
        e->services = services;
        e->start_height = start_height;
        snprintf(e->subver, sizeof(e->subver), "%s", subver ? subver : "");
    }
    g_pl.totals.version_received++;
    pthread_mutex_unlock(&g_pl.lock);
    if (node) {
        event_emitf(EV_PEER_VERSION, (uint32_t)node->id,
                    "version_received addr=%s services=%llu height=%d subver=%s",
                    node->addr_name, (unsigned long long)services,
                    start_height, subver ? subver : "");
    }
}

void peer_lifecycle_note_verack_received(const struct p2p_node *node)
{
    pthread_mutex_lock(&g_pl.lock);
    struct peer_lifecycle_entry *e = entry_for_node_locked(node, true);
    if (e) {
        e->verack_received++;
        e->verack_received_at = GetTime();
        e->last_seen = e->verack_received_at;
    }
    g_pl.totals.verack_received++;
    pthread_mutex_unlock(&g_pl.lock);
}

void peer_lifecycle_note_handshake_complete(const struct p2p_node *node)
{
    bool magicbean = false;
    bool zcl23 = false;
    int64_t duration = 0;
    pthread_mutex_lock(&g_pl.lock);
    struct peer_lifecycle_entry *e = entry_for_node_locked(node, true);
    if (e) {
        e->handshake_complete++;
        e->handshake_complete_at = GetTime();
        e->handshake_complete_seq = ++g_pl.seq;
        e->last_seen = e->handshake_complete_at;
        magicbean = subver_is_magicbean(e->subver);
        zcl23 = subver_is_zcl23(e->subver, e->services);
        duration = handshake_duration_secs(e);
    }
    g_pl.totals.handshake_complete++;
    if (magicbean) {
        g_pl.totals.magicbean_handshakes++;
        g_pl.totals.legacy_compatible_handshakes++;
    }
    if (zcl23) g_pl.totals.zcl23_handshakes++;
    pthread_mutex_unlock(&g_pl.lock);

    /* Omniscience time-to-first-peer: this is the single production choke point
     * every completed handshake passes through (msg_version.c inbound + outbound
     * + verack). Idempotent + a no-op before connman_start(). */
    connman_note_first_handshaked_peer();

    /* Honest witness for the bounded last-peer ban (peer_misbehaving() in
     * net.c): a completed handshake IS the route back to the network, so the
     * "we just banned our only peer" signage is now stale. Clearing on
     * observed peer state, never on wall time. No-op when not raised. */
    blocker_clear(PEER_LAST_PEER_BAN_BLOCKER_ID);

    if (node) {
        event_emitf(EV_PEER_HANDSHAKE_SUCCESS, (uint32_t)node->id,
                    "addr=%s duration=%llds services=%llu subver=%s",
                    node->addr_name, (long long)duration,
                    (unsigned long long)node->services, node->sub_ver);

        /* Bank the node-identity census from this completed handshake (source =
         * real peer). Key onions on their torv3 head (their ip[16] is a
         * placeholder that would collide); clearnet keeps its real IP. The emit
         * fails closed on a malformed user-agent and is a no-op if no event log
         * is wired — so this never blocks or corrupts on bad input. Called
         * OUTSIDE g_pl.lock: the emit does event-log I/O. */
        const struct net_addr *na = &node->addr.svc.addr;
        uint8_t census_key[16];
        if (na->has_torv3)
            memcpy(census_key, na->torv3, 16);
        else
            memcpy(census_key, na->ip, 16);
        (void)peers_projection_emit_census_observed(
            census_key, node->addr.svc.port, EV_CENSUS_SOURCE_PEER,
            /*success=*/true, node->sub_ver, node->version, node->services,
            (int64_t)node->starting_height, GetTime());
    }
}

void peer_lifecycle_note_active(const struct p2p_node *node)
{
    pthread_mutex_lock(&g_pl.lock);
    struct peer_lifecycle_entry *e = entry_for_node_locked(node, true);
    if (e) {
        e->active++;
        e->active_at = GetTime();
        e->last_seen = e->active_at;
    }
    g_pl.totals.active++;
    pthread_mutex_unlock(&g_pl.lock);
}

/* NET-2: bank a closed peer session's final reputation + transfer totals into
 * the durable peers_projection ledger. Called exactly once per session (from
 * note_terminal's recorded-once path), only for sessions that actually
 * handshaked. Fail-open — no event log wired ⇒ no-op. */
static void note_session_closed(const struct p2p_node *node, uint8_t reason,
                                int64_t connected_at, int64_t now_ts)
{
    if (!node)
        return;
    uint32_t duration = 0;
    if (connected_at > 0 && now_ts >= connected_at &&
        now_ts - connected_at <= (int64_t)UINT32_MAX)
        duration = (uint32_t)(now_ts - connected_at);
    uint32_t bw = dl_peer_bandwidth_score(msg_get_download_mgr(),
                                          (uint32_t)node->id);
    int64_t last_useful = node->last_useful_headers_time;
    if (node->last_block_time > last_useful)
        last_useful = node->last_block_time;
    uint64_t blocks = node->blocks_received > 0
                          ? (uint64_t)node->blocks_received : 0;
    (void)peers_projection_emit_session_closed(
        node->addr.svc.addr.ip, node->addr.svc.port, reason, duration,
        node->recv_bytes, node->send_bytes, node->total_headers_delivered,
        blocks, bw, node->avg_latency_us, last_useful);
}

static void note_terminal(const struct p2p_node *node, const char *reason,
                          const char *event_name, bool timeout, bool reject)
{
    char addr[256];
    bool recorded = false;
    bool emit_session = false;
    int64_t sess_connected_at = 0;
    int64_t sess_now = 0;
    addr_key_from_node(node, addr, sizeof(addr));
    pthread_mutex_lock(&g_pl.lock);
    struct peer_lifecycle_entry *e = entry_for_node_locked(node, true);
    if (e) {
        /* A timeout/reject marks the connection terminal before connman's
         * normal cleanup sweep calls note_disconnected() for the same node.
         * Count and emit exactly one causal terminal outcome per connected
         * generation; otherwise every timed-out pre-handshake connection is
         * reported twice and cleanup overwrites the useful first reason.
         * connected_seq advances on reconnect, re-arming the next generation.
         * terminal_seq==0 deliberately admits a first terminal observation
         * even when a caller did not publish note_connected() beforehand. */
        bool terminal_already_recorded =
            e->terminal_seq > 0 && e->terminal_seq >= e->connected_seq;
        if (!terminal_already_recorded) {
            int64_t now = GetTime();
            bool pre_handshake =
                e->handshake_complete_seq <= e->connected_seq;
            e->last_seen = now;
            snprintf(e->last_reason, sizeof(e->last_reason), "%s",
                     reason ? reason : "");
            e->terminal_seq = ++g_pl.seq;
            if (timeout) {
                e->timeout++;
                e->timeout_at = now;
                g_pl.totals.timeout++;
            } else if (reject) {
                e->rejected++;
                e->rejected_at = now;
                g_pl.totals.rejected++;
            } else {
                e->disconnected++;
                e->disconnected_at = now;
                g_pl.totals.disconnected++;
            }
            if (pre_handshake) {
                g_pl.totals.pre_handshake_disconnects++;
                e->pre_handshake_disconnects++;
            }
            /* Bank the session's reputation exactly once, but only for a
             * session that actually handshaked (a failed pre-handshake dial is
             * not a peer session worth remembering). */
            if (!pre_handshake) {
                emit_session = true;
                sess_connected_at = e->connected_at;
                sess_now = now;
            }
            recorded = true;
        }
    }
    pthread_mutex_unlock(&g_pl.lock);
    if (recorded && node) {
        event_emitf(timeout ? EV_PEER_CONNECT_TIMEOUT :
                    reject ? EV_PEER_HANDSHAKE_FAILURE :
                    EV_TCP_DISCONNECTED,
                    (uint32_t)node->id, "%s addr=%s state=%s reason=%s",
                    event_name, addr, peer_state_name(node->state),
                    reason ? reason : "");
    }
    if (emit_session)
        note_session_closed(node, timeout ? 1u : reject ? 2u : 0u,
                            sess_connected_at, sess_now);
}

void peer_lifecycle_note_timeout(const struct p2p_node *node,
                                 const char *reason)
{
    note_terminal(node, reason, "timeout", true, false);
}

void peer_lifecycle_note_reject(const struct p2p_node *node,
                                const char *reason)
{
    note_terminal(node, reason, "reject", false, true);
}

void peer_lifecycle_note_disconnected(const struct p2p_node *node,
                                      const char *reason)
{
    /* Cleanup is the single lifetime fold for the typed causal record. It is
     * deliberately independent of note_terminal's generation dedupe: a
     * timeout/reject may already own the human-facing terminal incident, but
     * the exact typed cleanup cause must still enter cumulative telemetry. */
    if (node) {
        int typed_reason = atomic_load_explicit(&node->disconnect_reason,
                                                memory_order_acquire);
        int typed_source = atomic_load_explicit(&node->disconnect_source,
                                                memory_order_relaxed);
        uint64_t generation = atomic_load_explicit(
            &node->disconnect_endpoint_generation, memory_order_relaxed);
        pthread_mutex_lock(&g_pl.lock);
        if (typed_reason > P2P_DISCONNECT_NONE &&
            typed_reason < P2P_DISCONNECT_REASON_COUNT)
            g_pl.totals.disconnect_reason_counts[typed_reason]++;
        if (typed_source > P2P_DISCONNECT_SOURCE_UNKNOWN &&
            typed_source < P2P_DISCONNECT_SOURCE_COUNT)
            g_pl.totals.disconnect_source_counts[typed_source]++;
        if (generation > g_pl.totals.max_endpoint_generation)
            g_pl.totals.max_endpoint_generation = generation;
        pthread_mutex_unlock(&g_pl.lock);
    }
    note_terminal(node, reason, "disconnect", false, false);
}

void peer_lifecycle_note_cache_skipped_addr(const char *addr,
                                            int64_t peer_id,
                                            const char *reason)
{
    const char *key = (addr && addr[0]) ? addr : "unknown";
    pthread_mutex_lock(&g_pl.lock);
    struct peer_lifecycle_entry *e = find_entry_locked(key, peer_id, true);
    if (e) {
        e->cache_skipped++;
        e->last_seen = GetTime();
        snprintf(e->last_reason, sizeof(e->last_reason), "%s",
                 reason ? reason : "");
    }
    g_pl.totals.cache_skipped++;
    pthread_mutex_unlock(&g_pl.lock);
    event_emitf(EV_PEER_CACHE_SKIPPED,
                peer_id >= 0 ? (uint32_t)peer_id : 0,
                "addr=%s reason=%s", key, reason ? reason : "");
}

void peer_lifecycle_note_cache_skipped(const struct p2p_node *node,
                                       const char *reason)
{
    char addr[256];
    addr_key_from_node(node, addr, sizeof(addr));
    peer_lifecycle_note_cache_skipped_addr(addr, node ? node->id : -1,
                                           reason);
}

static void entry_to_json(const struct peer_lifecycle_entry *e,
                          struct json_value *out)
{
    json_set_object(out);
    json_push_kv_int(out, "peer_id", e->peer_id);
    json_push_kv_str(out, "addr", e->addr);
    json_push_kv_str(out, "source", peer_lifecycle_source_name(e->source));
    json_push_kv_int(out, "attempted", e->attempted);
    json_push_kv_int(out, "connected", e->connected);
    json_push_kv_int(out, "version_sent", e->version_sent);
    json_push_kv_int(out, "version_received", e->version_received);
    json_push_kv_int(out, "verack_received", e->verack_received);
    json_push_kv_int(out, "handshake_complete", e->handshake_complete);
    json_push_kv_int(out, "active", e->active);
    json_push_kv_int(out, "disconnected", e->disconnected);
    json_push_kv_int(out, "timeout", e->timeout);
    json_push_kv_int(out, "rejected", e->rejected);
    json_push_kv_int(out, "cache_skipped", e->cache_skipped);
    json_push_kv_int(out, "pre_handshake_disconnects",
                     e->pre_handshake_disconnects);
    json_push_kv_str(out, "direction", entry_direction(e));
    json_push_kv_int(out, "reconnects", entry_reconnects(e));
    json_push_kv_int(out, "last_reconnect_at", e->last_reconnect_at);
    json_push_kv_int(out, "last_reconnect_interval_secs",
                     e->last_reconnect_interval_secs);
    json_push_kv_bool(out, "connection_open", entry_connection_open(e));
    json_push_kv_bool(out, "current_connection_handshaked",
                      entry_current_connection_handshaked(e));
    json_push_kv_int(out, "handshake_age_secs",
                     entry_handshake_age_secs(e, GetTime()));
    json_push_kv_int(out, "first_seen", e->first_seen);
    json_push_kv_int(out, "last_seen", e->last_seen);
    json_push_kv_int(out, "connected_at", e->connected_at);
    json_push_kv_int(out, "handshake_complete_at", e->handshake_complete_at);
    json_push_kv_int(out, "handshake_duration_secs",
                     handshake_duration_secs(e));
    json_push_kv_int(out, "services", (int64_t)e->services);
    char summary[128];
    services_summary(e->services, summary, sizeof(summary));
    json_push_kv_str(out, "services_summary", summary);
    json_push_kv_int(out, "startingheight", e->start_height);
    json_push_kv_int(out, "advertised_height", e->start_height);
    json_push_kv_str(out, "advertised_height_trust",
                     entry_advertised_height_trust(e));
    json_push_kv_bool(out, "advertised_height_trusted",
                      entry_advertised_height_trusted(e));
    json_push_kv_str(out, "subver", e->subver);
    json_push_kv_str(out, "bootstrap_readiness",
                     entry_bootstrap_readiness(e));
    json_push_kv_bool(out, "bootstrap_useful",
                      entry_bootstrap_useful(e));
    json_push_kv_bool(out, "fast_sync_useful",
                      entry_fast_sync_useful(e));
    json_push_kv_bool(out, "magicbean",
                      subver_is_magicbean(e->subver));
    json_push_kv_bool(out, "legacy_compatible",
                      subver_is_magicbean(e->subver));
    json_push_kv_bool(out, "zclassic23",
                      subver_is_zcl23(e->subver, e->services));
    json_push_kv_bool(out, "zclassic_c23",
                      subver_is_zcl23(e->subver, e->services));
    json_push_kv_str(out, "last_reason", e->last_reason);
    json_push_kv_str(out, "last_disconnect_reason", e->last_reason);
}

bool peer_lifecycle_peer_json(const struct p2p_node *node,
                              struct json_value *out)
{
    if (!node || !out) return false;
    pthread_mutex_lock(&g_pl.lock);
    const struct peer_lifecycle_entry *e = entry_for_node_locked(node, false);
    if (e)
        entry_to_json(e, out);
    pthread_mutex_unlock(&g_pl.lock);
    if (!e) {
        json_set_object(out);
        json_push_kv_str(out, "source",
                         node->inbound ? "inbound" : "unknown");
        json_push_kv_int(out, "handshake_duration_secs", 0);
        json_push_kv_bool(out, "magicbean",
                          subver_is_magicbean(node->sub_ver));
        json_push_kv_bool(out, "legacy_compatible",
                          subver_is_magicbean(node->sub_ver));
        json_push_kv_bool(out, "zclassic23",
                          subver_is_zcl23(node->sub_ver, node->services));
        json_push_kv_bool(out, "zclassic_c23",
                          subver_is_zcl23(node->sub_ver, node->services));
    }
    return true;
}

bool peer_lifecycle_addr_json(const char *addr, struct json_value *out)
{
    struct peer_lifecycle_entry copy;
    bool found = false;

    if (!addr || !addr[0] || !out)
        return false;

    pthread_mutex_lock(&g_pl.lock);
    const struct peer_lifecycle_entry *e =
        find_entry_locked(addr, -1, false);
    if (e) {
        copy = *e;
        found = true;
    }
    pthread_mutex_unlock(&g_pl.lock);

    if (!found)
        return false;

    entry_to_json(&copy, out);
    return true;
}

static void summary_to_json(const struct peer_lifecycle_summary *s,
                            struct json_value *out)
{
    json_set_object(out);
    json_push_kv_int(out, "attempted", s->attempted);
    json_push_kv_int(out, "connected", s->connected);
    json_push_kv_int(out, "version_sent", s->version_sent);
    json_push_kv_int(out, "version_received", s->version_received);
    json_push_kv_int(out, "verack_received", s->verack_received);
    json_push_kv_int(out, "handshake_complete", s->handshake_complete);
    json_push_kv_int(out, "active", s->active);
    json_push_kv_int(out, "disconnected", s->disconnected);
    json_push_kv_int(out, "timeout", s->timeout);
    json_push_kv_int(out, "rejected", s->rejected);
    json_push_kv_int(out, "cache_skipped", s->cache_skipped);
    json_push_kv_int(out, "magicbean_handshakes",
                     s->magicbean_handshakes);
    json_push_kv_int(out, "legacy_compatible_handshakes",
                     s->legacy_compatible_handshakes);
    json_push_kv_int(out, "legacy_magicbean_handshakes",
                     s->legacy_compatible_handshakes);
    json_push_kv_int(out, "zclassic23_handshakes",
                     s->zcl23_handshakes);
    json_push_kv_int(out, "zclassic_c23_handshakes",
                     s->zcl23_handshakes);
    json_push_kv_int(out, "pre_handshake_disconnects",
                     s->pre_handshake_disconnects);
}

static void causal_disconnects_to_json(
    const struct peer_lifecycle_summary *s, struct json_value *out)
{
    struct json_value reasons = {0};
    json_set_object(&reasons);
    for (int reason = P2P_DISCONNECT_NONE + 1;
         reason < P2P_DISCONNECT_REASON_COUNT; reason++)
        json_push_kv_int(&reasons,
                         p2p_disconnect_reason_name(reason),
                         s->disconnect_reason_counts[reason]);
    json_push_kv(out, "causal_disconnects", &reasons);
    json_free(&reasons);

    struct json_value sources = {0};
    json_set_object(&sources);
    for (int source = P2P_DISCONNECT_SOURCE_UNKNOWN + 1;
         source < P2P_DISCONNECT_SOURCE_COUNT; source++)
        json_push_kv_int(&sources,
                         p2p_disconnect_source_name(source),
                         s->disconnect_source_counts[source]);
    json_push_kv(out, "causal_disconnect_sources", &sources);
    json_free(&sources);
    json_push_kv_int(out, "max_endpoint_generation",
                     (int64_t)s->max_endpoint_generation);
}

static void summary_add_entry(struct peer_lifecycle_summary *s,
                              const struct peer_lifecycle_entry *e)
{
    if (!s || !e)
        return;

    s->attempted += e->attempted;
    s->connected += e->connected;
    s->version_sent += e->version_sent;
    s->version_received += e->version_received;
    s->verack_received += e->verack_received;
    s->handshake_complete += e->handshake_complete;
    s->active += e->active;
    s->disconnected += e->disconnected;
    s->timeout += e->timeout;
    s->rejected += e->rejected;
    s->cache_skipped += e->cache_skipped;
    if (e->handshake_complete > 0 && subver_is_magicbean(e->subver))
        s->magicbean_handshakes += e->handshake_complete;
    if (e->handshake_complete > 0 && subver_is_magicbean(e->subver))
        s->legacy_compatible_handshakes += e->handshake_complete;
    if (e->handshake_complete > 0 &&
        subver_is_zcl23(e->subver, e->services))
        s->zcl23_handshakes += e->handshake_complete;
    s->pre_handshake_disconnects += e->pre_handshake_disconnects;
}

static struct peer_lifecycle_host_group *find_host_group(
    struct peer_lifecycle_host_group *groups, const char *host,
    int64_t *overflow)
{
    struct peer_lifecycle_host_group *free_slot = NULL;
    for (size_t i = 0; i < PEER_LIFECYCLE_GROUP_LIMIT; i++) {
        if (!groups[i].used) {
            if (!free_slot)
                free_slot = &groups[i];
            continue;
        }
        if (strcmp(groups[i].host, host) == 0)
            return &groups[i];
    }
    if (!free_slot) {
        if (overflow)
            (*overflow)++;
        return NULL;
    }
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->used = true;
    snprintf(free_slot->host, sizeof(free_slot->host), "%s", host);
    return free_slot;
}

static void host_group_add_entry(struct peer_lifecycle_host_group *group,
                                 const struct peer_lifecycle_entry *e)
{
    if (!group || !e)
        return;
    group->entries++;
    if (source_is_inbound(e->source))
        group->inbound_entries++;
    else if (source_is_outbound(e->source))
        group->outbound_entries++;
    else
        group->unknown_entries++;
    bool open = entry_connection_open(e);
    bool handshaked = entry_current_connection_handshaked(e);
    if (open) {
        group->open_connections++;
        if (source_is_inbound(e->source))
            group->open_inbound_connections++;
        else if (source_is_outbound(e->source))
            group->open_outbound_connections++;
        else
            group->open_unknown_connections++;
    }
    if (handshaked) {
        group->handshaked_open_connections++;
        if (source_is_inbound(e->source))
            group->handshaked_inbound_connections++;
        else if (source_is_outbound(e->source))
            group->handshaked_outbound_connections++;
        else
            group->handshaked_unknown_connections++;
        if ((e->services & NODE_NETWORK) != 0)
            group->handshaked_network_connections++;
        if (e->start_height > 0) {
            group->handshaked_advertised_height_connections++;
            if (entry_advertised_height_trusted(e))
                group->handshaked_trusted_advertised_height_connections++;
            else
                group->handshaked_untrusted_advertised_height_connections++;
        }
        if (subver_is_zcl23(e->subver, e->services))
            group->handshaked_zclassic23_connections++;
    }
    if (entry_bootstrap_useful(e))
        group->bootstrap_useful_connections++;
    if (entry_fast_sync_useful(e))
        group->fast_sync_useful_connections++;
    group->connected += e->connected;
    group->handshake_complete += e->handshake_complete;
    group->active += e->active;
    group->disconnected += e->disconnected;
    group->timeout += e->timeout;
    group->rejected += e->rejected;
    group->reconnects += entry_reconnects(e);
    group->pre_handshake_disconnects += e->pre_handshake_disconnects;
    if (e->last_reconnect_interval_secs > 0) {
        if (group->min_reconnect_interval_secs == 0 ||
            e->last_reconnect_interval_secs <
                group->min_reconnect_interval_secs)
            group->min_reconnect_interval_secs =
                e->last_reconnect_interval_secs;
        if (e->last_reconnect_interval_secs >
            group->max_reconnect_interval_secs)
            group->max_reconnect_interval_secs =
                e->last_reconnect_interval_secs;
        if (e->last_reconnect_at >= group->last_reconnect_at) {
            group->last_reconnect_at = e->last_reconnect_at;
            group->last_reconnect_interval_secs =
                e->last_reconnect_interval_secs;
        }
    }
    group->services_or |= e->services;
    if (e->start_height > group->max_advertised_height)
        group->max_advertised_height = e->start_height;
    if (entry_bootstrap_useful(e))
        group->bootstrap_useful = true;
    if (entry_fast_sync_useful(e))
        group->fast_sync_useful = true;
    if (e->last_seen >= group->last_seen) {
        group->last_seen = e->last_seen;
        snprintf(group->last_reason, sizeof(group->last_reason), "%s",
                 e->last_reason);
    }
}

static int64_t build_host_groups_locked(
    struct peer_lifecycle_host_group *groups)
{
    int64_t overflow = 0;
    for (size_t i = 0; i < PEER_LIFECYCLE_MAX; i++) {
        const struct peer_lifecycle_entry *e = &g_pl.entries[i];
        if (!e->used)
            continue;
        char host[256];
        addr_host_key(e->addr, host, sizeof(host));
        struct peer_lifecycle_host_group *group =
            find_host_group(groups, host, &overflow);
        host_group_add_entry(group, e);
    }
    return overflow;
}

static void append_incident_peer_json(
    const struct peer_lifecycle_incident_pick *pick, int64_t now,
    struct json_value *arr)
{
    const struct peer_lifecycle_entry *e = pick->entry;
    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_int(&obj, "peer_id", e->peer_id);
    json_push_kv_str(&obj, "addr", e->addr);
    json_push_kv_str(&obj, "host", pick->host);
    json_push_kv_str(&obj, "source", peer_lifecycle_source_name(e->source));
    json_push_kv_str(&obj, "direction", entry_direction(e));
    json_push_kv_int(&obj, "incident_score", pick->score);
    json_push_kv_int(&obj, "duplicate_host_entries",
                     pick->duplicate_host_entries);
    json_push_kv_int(&obj, "reconnects", entry_reconnects(e));
    json_push_kv_int(&obj, "last_reconnect_at", e->last_reconnect_at);
    json_push_kv_int(&obj, "last_reconnect_interval_secs",
                     e->last_reconnect_interval_secs);
    json_push_kv_int(&obj, "connected", e->connected);
    json_push_kv_int(&obj, "handshake_complete", e->handshake_complete);
    json_push_kv_int(&obj, "disconnected", e->disconnected);
    json_push_kv_int(&obj, "timeout", e->timeout);
    json_push_kv_int(&obj, "rejected", e->rejected);
    json_push_kv_int(&obj, "pre_handshake_disconnects",
                     e->pre_handshake_disconnects);
    json_push_kv_bool(&obj, "connection_open", entry_connection_open(e));
    json_push_kv_bool(&obj, "current_connection_handshaked",
                      entry_current_connection_handshaked(e));
    json_push_kv_int(&obj, "handshake_age_secs",
                     entry_handshake_age_secs(e, now));
    json_push_kv_int(&obj, "services", (int64_t)e->services);
    char summary[128];
    services_summary(e->services, summary, sizeof(summary));
    json_push_kv_str(&obj, "services_summary", summary);
    json_push_kv_int(&obj, "advertised_height", e->start_height);
    json_push_kv_str(&obj, "advertised_height_trust",
                     entry_advertised_height_trust(e));
    json_push_kv_bool(&obj, "advertised_height_trusted",
                      entry_advertised_height_trusted(e));
    json_push_kv_str(&obj, "subver", e->subver);
    json_push_kv_str(&obj, "bootstrap_readiness",
                     entry_bootstrap_readiness(e));
    json_push_kv_bool(&obj, "bootstrap_useful",
                      entry_bootstrap_useful(e));
    json_push_kv_bool(&obj, "fast_sync_useful",
                      entry_fast_sync_useful(e));
    json_push_kv_str(&obj, "last_reason", e->last_reason);
    json_push_kv_str(&obj, "last_disconnect_reason", e->last_reason);
    json_push_kv_int(&obj, "last_seen", e->last_seen);
    json_push_back(arr, &obj);
    json_free(&obj);
}

static void host_group_to_json(const struct peer_lifecycle_host_group *g,
                               int64_t score, struct json_value *obj)
{
    json_set_object(obj);
    json_push_kv_str(obj, "host", g->host);
    json_push_kv_int(obj, "incident_score", score);
    json_push_kv_str(obj, "issue_class", host_group_issue_class(g));
    json_push_kv_str(obj, "next_action", host_group_next_action(g));
    json_push_kv_str(obj, "direction", host_group_direction(g));
    json_push_kv_bool(obj, "mixed_direction",
                      host_group_mixed_direction(g));
    json_push_kv_int(obj, "entries", g->entries);
    json_push_kv_int(obj, "inbound_entries", g->inbound_entries);
    json_push_kv_int(obj, "outbound_entries", g->outbound_entries);
    json_push_kv_int(obj, "unknown_entries", g->unknown_entries);
    json_push_kv_int(obj, "open_connections", g->open_connections);
    json_push_kv_str(obj, "current_open_direction",
                     direction_summary(g->open_inbound_connections,
                                       g->open_outbound_connections,
                                       g->open_unknown_connections));
    json_push_kv_bool(obj, "current_open_mixed_direction",
                      direction_mixed(g->open_inbound_connections,
                                      g->open_outbound_connections,
                                      g->open_unknown_connections));
    json_push_kv_int(obj, "current_open_inbound_connections",
                     g->open_inbound_connections);
    json_push_kv_int(obj, "current_open_outbound_connections",
                     g->open_outbound_connections);
    json_push_kv_int(obj, "current_open_unknown_connections",
                     g->open_unknown_connections);
    json_push_kv_int(obj, "handshaked_open_connections",
                     g->handshaked_open_connections);
    json_push_kv_str(obj, "current_handshaked_direction",
                     direction_summary(g->handshaked_inbound_connections,
                                       g->handshaked_outbound_connections,
                                       g->handshaked_unknown_connections));
    json_push_kv_bool(obj, "current_handshaked_mixed_direction",
                      direction_mixed(g->handshaked_inbound_connections,
                                      g->handshaked_outbound_connections,
                                      g->handshaked_unknown_connections));
    json_push_kv_int(obj, "current_handshaked_inbound_connections",
                     g->handshaked_inbound_connections);
    json_push_kv_int(obj, "current_handshaked_outbound_connections",
                     g->handshaked_outbound_connections);
    json_push_kv_int(obj, "current_handshaked_unknown_connections",
                     g->handshaked_unknown_connections);
    json_push_kv_int(obj, "handshaked_network_connections",
                     g->handshaked_network_connections);
    json_push_kv_int(obj, "handshaked_advertised_height_connections",
                     g->handshaked_advertised_height_connections);
    json_push_kv_int(obj,
                     "handshaked_trusted_advertised_height_connections",
                     g->handshaked_trusted_advertised_height_connections);
    json_push_kv_int(obj,
                     "handshaked_untrusted_advertised_height_connections",
                     g->handshaked_untrusted_advertised_height_connections);
    json_push_kv_int(obj, "handshaked_zclassic23_connections",
                     g->handshaked_zclassic23_connections);
    json_push_kv_int(obj, "bootstrap_useful_connections",
                     g->bootstrap_useful_connections);
    json_push_kv_int(obj, "fast_sync_useful_connections",
                     g->fast_sync_useful_connections);
    json_push_kv_bool(obj, "duplicate_current_connections",
                      g->open_connections > 1);
    json_push_kv_bool(obj, "duplicate_handshaked_connections",
                      g->handshaked_open_connections > 1);
    json_push_kv_int(obj, "connected", g->connected);
    json_push_kv_int(obj, "handshake_complete", g->handshake_complete);
    json_push_kv_int(obj, "active", g->active);
    json_push_kv_int(obj, "disconnected", g->disconnected);
    json_push_kv_int(obj, "timeout", g->timeout);
    json_push_kv_int(obj, "rejected", g->rejected);
    json_push_kv_int(obj, "reconnects", g->reconnects);
    json_push_kv_int(obj, "last_reconnect_at", g->last_reconnect_at);
    json_push_kv_int(obj, "last_reconnect_interval_secs",
                     g->last_reconnect_interval_secs);
    json_push_kv_int(obj, "min_reconnect_interval_secs",
                     g->min_reconnect_interval_secs);
    json_push_kv_int(obj, "max_reconnect_interval_secs",
                     g->max_reconnect_interval_secs);
    json_push_kv_int(obj, "pre_handshake_disconnects",
                     g->pre_handshake_disconnects);
    json_push_kv_int(obj, "services_or", (int64_t)g->services_or);
    char summary[128];
    services_summary(g->services_or, summary, sizeof(summary));
    json_push_kv_str(obj, "services_summary", summary);
    json_push_kv_int(obj, "max_advertised_height",
                     g->max_advertised_height);
    json_push_kv_str(obj, "advertised_height_trust",
                     host_group_advertised_height_trust(g));
    json_push_kv_str(obj, "bootstrap_readiness",
                     host_group_bootstrap_readiness(g));
    json_push_kv_str(obj, "fast_sync_readiness",
                     host_group_fast_sync_readiness(g));
    json_push_kv_bool(obj, "bootstrap_useful", g->bootstrap_useful);
    json_push_kv_bool(obj, "fast_sync_useful", g->fast_sync_useful);
    json_push_kv_int(obj, "last_seen", g->last_seen);
    json_push_kv_str(obj, "last_reason", g->last_reason);
    json_push_kv_str(obj, "last_disconnect_reason", g->last_reason);
}

static void append_host_group_json(const struct peer_lifecycle_host_group *g,
                                   int64_t score,
                                   struct json_value *arr)
{
    struct json_value obj = {0};
    host_group_to_json(g, score, &obj);
    json_push_back(arr, &obj);
    json_free(&obj);
}

static void append_primary_host_issue_json(
    const struct peer_lifecycle_host_pick *pick, struct json_value *out)
{
    struct json_value obj = {0};
    if (pick && pick->group) {
        host_group_to_json(pick->group, pick->score, &obj);
        json_push_kv_str(&obj, "status", "attention");
    } else {
        json_set_object(&obj);
        json_push_kv_str(&obj, "status", "ok");
        json_push_kv_str(&obj, "issue_class", "none");
        json_push_kv_str(&obj, "next_action", "monitor_peer_lifecycle");
    }
    json_push_kv(out, "primary_host_issue", &obj);
    json_free(&obj);
}

static const char *peer_incidents_bootstrap_readiness(
    int64_t open_connections, int64_t handshaked_connections,
    int64_t bootstrap_useful_connections)
{
    if (bootstrap_useful_connections > 0)
        return "ready";
    if (open_connections <= 0)
        return "no_current_open_connection";
    if (handshaked_connections <= 0)
        return "no_current_handshaked_connection";
    return "no_bootstrap_useful_peer";
}

static const char *peer_incidents_fast_sync_readiness(
    int64_t bootstrap_useful_connections, int64_t fast_sync_useful_connections,
    const char *bootstrap_readiness)
{
    if (fast_sync_useful_connections > 0)
        return "ready";
    if (bootstrap_useful_connections <= 0)
        return bootstrap_readiness ? bootstrap_readiness
                                   : "no_bootstrap_useful_peer";
    return "no_zclassic23_fast_sync_peer";
}

static const char *peer_incidents_severity(
    int64_t incident_count, int64_t host_incident_count,
    int64_t duplicate_group_count)
{
    if (host_incident_count > 0 || duplicate_group_count > 0)
        return "attention";
    if (incident_count > 0)
        return "info";
    return "ok";
}

static const char *peer_incidents_next_action(
    size_t host_pick_count, int64_t incident_count,
    bool bootstrap_blocked, bool fast_sync_blocked)
{
    if (host_pick_count > 0)
        return "inspect primary_host_issue and top_host_incidents";
    if (incident_count > 0)
        return "inspect top_incidents";
    if (bootstrap_blocked)
        return "add_or_fix_bootstrap_peers";
    if (fast_sync_blocked)
        return "prefer_zclassic23_fast_sync_peer";
    return "peer lifecycle has no scored incidents";
}

bool peer_lifecycle_incidents_json(struct json_value *out)
{
    if (!out)
        return false;
    pthread_mutex_lock(&g_pl.lock);
    int64_t now = GetTime();
    struct peer_lifecycle_host_group groups[PEER_LIFECYCLE_GROUP_LIMIT];
    memset(groups, 0, sizeof(groups));
    int64_t group_overflow = build_host_groups_locked(groups);

    struct peer_lifecycle_incident_pick picks[PEER_LIFECYCLE_INCIDENT_LIMIT];
    memset(picks, 0, sizeof(picks));
    struct peer_lifecycle_host_pick host_picks[
        PEER_LIFECYCLE_HOST_INCIDENT_LIMIT];
    memset(host_picks, 0, sizeof(host_picks));
    size_t pick_count = 0;
    size_t host_pick_count = 0;
    int64_t incident_count = 0;
    int64_t host_incident_count = 0;
    int64_t duplicate_group_count = 0;
    int64_t duplicate_open_group_count = 0;
    int64_t duplicate_handshaked_group_count = 0;
    int64_t open_connection_count = 0;
    int64_t handshaked_open_connection_count = 0;
    int64_t bootstrap_useful_count = 0;
    int64_t fast_sync_useful_count = 0;

    for (size_t i = 0; i < PEER_LIFECYCLE_GROUP_LIMIT; i++) {
        if (!groups[i].used)
            continue;
        if (groups[i].entries > 1)
            duplicate_group_count++;
        if (groups[i].open_connections > 1)
            duplicate_open_group_count++;
        if (groups[i].handshaked_open_connections > 1)
            duplicate_handshaked_group_count++;
        if (host_group_incident_score(&groups[i]) > 0)
            host_incident_count++;
        host_pick_consider(host_picks, &host_pick_count, &groups[i]);
    }

    for (size_t i = 0; i < PEER_LIFECYCLE_MAX; i++) {
        const struct peer_lifecycle_entry *e = &g_pl.entries[i];
        if (!e->used)
            continue;
        char host[256];
        addr_host_key(e->addr, host, sizeof(host));
        int64_t duplicate_entries = duplicate_entries_for_host(groups, host);
        int64_t score = entry_incident_score(e, duplicate_entries);
        if (score > 0)
            incident_count++;
        if (entry_connection_open(e))
            open_connection_count++;
        if (entry_current_connection_handshaked(e))
            handshaked_open_connection_count++;
        if (entry_bootstrap_useful(e))
            bootstrap_useful_count++;
        if (entry_fast_sync_useful(e))
            fast_sync_useful_count++;
        incident_pick_consider(picks, &pick_count, e, score,
                               duplicate_entries, host);
    }

    const char *bootstrap_readiness =
        peer_incidents_bootstrap_readiness(open_connection_count,
                                           handshaked_open_connection_count,
                                           bootstrap_useful_count);
    const char *fast_sync_readiness =
        peer_incidents_fast_sync_readiness(bootstrap_useful_count,
                                           fast_sync_useful_count,
                                           bootstrap_readiness);
    bool bootstrap_blocked = strcmp(bootstrap_readiness, "ready") != 0;
    bool fast_sync_blocked = strcmp(fast_sync_readiness, "ready") != 0;
    const char *incident_severity =
        peer_incidents_severity(incident_count, host_incident_count,
                                duplicate_group_count);
    const char *next_action =
        peer_incidents_next_action(host_pick_count, incident_count,
                                   bootstrap_blocked, fast_sync_blocked);
    const struct peer_lifecycle_host_pick *primary_pick =
        host_pick_count > 0 ? &host_picks[0] : NULL;
    const struct peer_lifecycle_host_group *primary_group =
        primary_pick ? primary_pick->group : NULL;

    json_set_object(out);
    json_push_kv_str(out, "schema", "zcl.peer_incidents.v2");
    json_push_kv_int(out, "schema_version", 1);
    json_push_kv_bool(out, "bounded", true);
    json_push_kv_int(out, "peer_limit", PEER_LIFECYCLE_INCIDENT_LIMIT);
    json_push_kv_int(out, "group_limit", PEER_LIFECYCLE_GROUP_LIMIT);
    json_push_kv_int(out, "host_incident_limit",
                     PEER_LIFECYCLE_HOST_INCIDENT_LIMIT);
    json_push_kv_int(out, "incident_count", incident_count);
    json_push_kv_int(out, "count_returned", (int64_t)pick_count);
    json_push_kv_int(out, "host_incident_count", host_incident_count);
    json_push_kv_int(out, "host_count_returned",
                     (int64_t)host_pick_count);
    json_push_kv_int(out, "duplicate_host_group_count",
                     duplicate_group_count);
    json_push_kv_int(out, "duplicate_open_host_group_count",
                     duplicate_open_group_count);
    json_push_kv_int(out, "duplicate_handshaked_host_group_count",
                     duplicate_handshaked_group_count);
    json_push_kv_int(out, "current_open_connection_count",
                     open_connection_count);
    json_push_kv_int(out, "current_handshaked_connection_count",
                     handshaked_open_connection_count);
    json_push_kv_int(out, "host_group_overflow", group_overflow);
    json_push_kv_int(out, "bootstrap_useful_count",
                     bootstrap_useful_count);
    json_push_kv_int(out, "fast_sync_useful_count", fast_sync_useful_count);
    json_push_kv_str(out, "bootstrap_readiness", bootstrap_readiness);
    json_push_kv_str(out, "fast_sync_readiness", fast_sync_readiness);
    json_push_kv_bool(out, "bootstrap_blocked", bootstrap_blocked);
    json_push_kv_bool(out, "fast_sync_blocked", fast_sync_blocked);
    json_push_kv_str(out, "incident_severity", incident_severity);
    json_push_kv_bool(out, "stability_blocker",
                      strcmp(incident_severity, "attention") == 0 ||
                      bootstrap_blocked);
    json_push_kv_str(out, "semantics",
                     "bounded peer lifecycle incident view grouped by host; "
                     "use full peer_lifecycle only for raw forensic dumps");
    json_push_kv_str(out, "safe_next_action", next_action);
    json_push_kv_str(out, "primary_issue_host",
                     primary_group ? primary_group->host : "");
    json_push_kv_int(out, "primary_issue_score",
                     primary_pick ? primary_pick->score : 0);
    json_push_kv_str(out, "primary_issue_class",
                     primary_group ? host_group_issue_class(primary_group)
                                   : "none");
    json_push_kv_str(out, "primary_issue_next_action",
                     primary_group ? host_group_next_action(primary_group)
                                   : "monitor_peer_lifecycle");
    append_primary_host_issue_json(primary_pick, out);

    struct json_value incidents = {0};
    json_set_array(&incidents);
    for (size_t i = 0; i < pick_count; i++)
        append_incident_peer_json(&picks[i], now, &incidents);
    json_push_kv(out, "top_incidents", &incidents);
    json_free(&incidents);

    struct json_value host_incidents = {0};
    json_set_array(&host_incidents);
    for (size_t i = 0; i < host_pick_count; i++)
        append_host_group_json(host_picks[i].group, host_picks[i].score,
                               &host_incidents);
    json_push_kv(out, "top_host_incidents", &host_incidents);
    json_free(&host_incidents);

    struct json_value duplicate_groups = {0};
    json_set_array(&duplicate_groups);
    for (size_t i = 0; i < PEER_LIFECYCLE_GROUP_LIMIT; i++) {
        if (!groups[i].used)
            continue;
        if (groups[i].entries <= 1 && groups[i].reconnects == 0 &&
            groups[i].timeout == 0 && groups[i].rejected == 0 &&
            groups[i].pre_handshake_disconnects == 0)
            continue;
        append_host_group_json(&groups[i],
                               host_group_incident_score(&groups[i]),
                               &duplicate_groups);
    }
    json_push_kv(out, "duplicate_host_groups", &duplicate_groups);
    json_free(&duplicate_groups);

    struct json_value drilldowns = {0};
    json_set_array(&drilldowns);
    struct json_value d = {0};
    json_set_str(&d, "z23 dumpstate peer_lifecycle");
    json_push_back(&drilldowns, &d);
    json_set_str(&d, "z23 timeline '{\"category\":\"peer\",\"count\":50,\"since_secs\":3600}'");
    json_push_back(&drilldowns, &d);
    json_set_str(&d, "z23 dumpstate chain_advance_coordinator");
    json_push_back(&drilldowns, &d);
    json_free(&d);
    json_push_kv(out, "recommended_drilldowns", &drilldowns);
    json_free(&drilldowns);
    pthread_mutex_unlock(&g_pl.lock);
    return true;
}

static void append_sources_locked(struct json_value *out)
{
    struct peer_lifecycle_summary by_source[PEER_LIFECYCLE_SOURCE_MANUAL + 1];
    memset(by_source, 0, sizeof(by_source));

    for (size_t i = 0; i < PEER_LIFECYCLE_MAX; i++) {
        if (!g_pl.entries[i].used)
            continue;
        enum peer_lifecycle_source source = g_pl.entries[i].source;
        if (source < PEER_LIFECYCLE_SOURCE_UNKNOWN ||
            source > PEER_LIFECYCLE_SOURCE_MANUAL)
            source = PEER_LIFECYCLE_SOURCE_UNKNOWN;
        summary_add_entry(&by_source[source], &g_pl.entries[i]);
    }

    struct json_value sources = {0};
    json_set_array(&sources);
    for (int source = PEER_LIFECYCLE_SOURCE_UNKNOWN;
         source <= PEER_LIFECYCLE_SOURCE_MANUAL; source++) {
        struct json_value entry = {0};
        summary_to_json(&by_source[source], &entry);
        json_push_kv_str(&entry, "source",
                         peer_lifecycle_source_name(source));
        json_push_back(&sources, &entry);
        json_free(&entry);
    }
    json_push_kv(out, "sources", &sources);
    json_free(&sources);
}

bool peer_lifecycle_summary_json(struct json_value *out)
{
    if (!out) return false;
    pthread_mutex_lock(&g_pl.lock);
    summary_to_json(&g_pl.totals, out);
    causal_disconnects_to_json(&g_pl.totals, out);
    append_sources_locked(out);
    pthread_mutex_unlock(&g_pl.lock);
    return true;
}

bool peer_lifecycle_dump_state_json(struct json_value *out,
                                    const char *key)
{
    if (!out) return false;
    pthread_mutex_lock(&g_pl.lock);
    if (key && (strcmp(key, "incidents") == 0 ||
                strcmp(key, "incident") == 0)) {
        pthread_mutex_unlock(&g_pl.lock);
        return peer_lifecycle_incidents_json(out);
    }
    struct peer_lifecycle_summary totals = g_pl.totals;
    struct json_value summary = {0};
    summary_to_json(&totals, &summary);
    causal_disconnects_to_json(&totals, &summary);
    json_push_kv(out, "summary", &summary);
    json_free(&summary);

    struct json_value peers = {0};
    json_set_array(&peers);
    for (size_t i = 0; i < PEER_LIFECYCLE_MAX; i++) {
        if (!g_pl.entries[i].used)
            continue;
        struct json_value entry = {0};
        entry_to_json(&g_pl.entries[i], &entry);
        json_push_back(&peers, &entry);
        json_free(&entry);
    }
    json_push_kv(out, "peers", &peers);
    json_free(&peers);
    append_sources_locked(out);
    pthread_mutex_unlock(&g_pl.lock);

    /* connman_get_reactor_stats reads process-global atomics, not a
     * connman lock, so this is safe to call outside g_pl.lock. */
    struct connman_reactor_stats rs;
    connman_get_reactor_stats(&rs);
    struct json_value reactor = {0};
    json_set_object(&reactor);
    json_push_kv_int(&reactor, "npfds_high_water", (int64_t)rs.npfds_high_water);
    json_push_kv_int(&reactor, "reactor_max_fds", (int64_t)rs.reactor_max_fds);
    json_push_kv_int(&reactor, "configured_max_connections",
                     (int64_t)rs.configured_max_connections);
    json_push_kv_int(&reactor, "configured_listen_sockets",
                     (int64_t)rs.configured_listen_sockets);
    json_push_kv(out, "reactor", &reactor);
    json_free(&reactor);

    return true;
}

void peer_lifecycle_get_summary(struct peer_lifecycle_summary *out)
{
    if (!out) return;
    pthread_mutex_lock(&g_pl.lock);
    *out = g_pl.totals;
    pthread_mutex_unlock(&g_pl.lock);
}

void peer_lifecycle_reset_for_test(void)
{
    pthread_mutex_lock(&g_pl.lock);
    memset(g_pl.entries, 0, sizeof(g_pl.entries));
    memset(&g_pl.totals, 0, sizeof(g_pl.totals));
    g_pl.seq = 0;
    pthread_mutex_unlock(&g_pl.lock);
}
