/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Owner-facing local pairing ceremony core (see the header). The
 * pure helpers are exported for the wire-format-free test group; the live
 * plan/commit lane re-derives session, delegation, and time at call time
 * and never dials. */

// one-result-type-ok:closed-security-verdict — plan/commit return bounded
// verdict enums the caller must branch on; refusal text is mapped at the
// RPC edge. Failure logging happens here with context.

#include "config/boot_mesh_pairing.h"

#include "config/boot_internal.h"
#include "config/boot_zcode_dht.h"
#include "config/boot_zcode_dht_access.h"
#include "config/runtime.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "net/net.h"
#include "net/v2_identity.h"
#include "net/v2_transport.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/sync.h"
#include "vcs/zcode_dht_service.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* Commit reuses the plan layer's live-derivation verdicts by value pun. */
_Static_assert((int)MESH_PAIR_PLAN_BAD_ARGUMENT ==
                       (int)MESH_PAIR_COMMIT_BAD_ARGUMENT &&
                   (int)MESH_PAIR_PLAN_DELEGATION_UNAVAILABLE ==
                       (int)MESH_PAIR_COMMIT_DELEGATION_UNAVAILABLE,
               "plan/commit derivation verdicts must stay value-aligned");

static zcl_mutex_t g_pair_lock;
static _Atomic int g_pair_lock_state;
static struct boot_svc_ctx *g_pair_svc; /* borrowed; set by wire() */

static void pair_lock(void)
{
    if (atomic_load_explicit(&g_pair_lock_state, memory_order_acquire) != 2) {
        int expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &g_pair_lock_state, &expected, 1, memory_order_acq_rel,
                memory_order_acquire)) {
            zcl_mutex_init(&g_pair_lock);
            atomic_store_explicit(&g_pair_lock_state, 2, memory_order_release);
        } else {
            while (atomic_load_explicit(&g_pair_lock_state,
                                        memory_order_acquire) != 2)
                ;
        }
    }
    zcl_mutex_lock(&g_pair_lock);
}

void boot_mesh_pairing_wire(struct boot_svc_ctx *svc)
{
    pair_lock();
    g_pair_svc = svc;
    zcl_mutex_unlock(&g_pair_lock);
}

void boot_mesh_pairing_shutdown(void)
{
    pair_lock();
    g_pair_svc = NULL;
    zcl_mutex_unlock(&g_pair_lock);
}

/* ── Pure helpers ────────────────────────────────────────────────────── */

bool boot_mesh_pairing_days_valid(int64_t days)
{
    return days >= 1 && days <= BOOT_MESH_PAIRING_MAX_DAYS;
}

int64_t boot_mesh_pairing_expiry(int64_t now, int64_t days)
{
    return now + days * 86400;
}

const char *boot_mesh_pairing_state(const struct db_mesh_pairing *row,
                                    int64_t now)
{
    if (row->revoked_at != 0)
        return "revoked";
    if (now >= row->expires_at)
        return "expired";
    return "active";
}

bool boot_mesh_pairing_selector_matches(const char *selector,
                                        const char *addr_name,
                                        const char fingerprint_hex[65])
{
    if (!selector || !selector[0])
        return true;
    if (addr_name && strstr(addr_name, selector))
        return true;
    size_t len = strlen(selector);
    return len <= 64 && strncmp(fingerprint_hex, selector, len) == 0;
}

bool boot_mesh_pairing_decode_fingerprint(const char *hex, uint8_t out[32])
{
    memset(out, 0, 32);
    return hex && strlen(hex) == 64 && zcl_hex_decode_lower(hex, out, 32);
}

const char *boot_mesh_pairing_reason_code(enum mesh_pairing_reason reason)
{
    switch (reason) {
    case MESH_PAIRING_OK: return "OK";
    case MESH_PAIRING_BAD_ARGUMENT: return "BAD_ARGUMENT";
    case MESH_PAIRING_CAPABILITY_UNAVAILABLE: return "CAPABILITY_UNAVAILABLE";
    case MESH_PAIRING_FINGERPRINT_MISMATCH: return "FINGERPRINT_MISMATCH";
    case MESH_PAIRING_NETWORK_MISMATCH: return "NETWORK_MISMATCH";
    case MESH_PAIRING_MASTER_INACTIVE: return "MASTER_INACTIVE";
    case MESH_PAIRING_BEACON_UNAVAILABLE: return "BEACON_UNAVAILABLE";
    case MESH_PAIRING_BEACON_PROVISIONAL: return "BEACON_PROVISIONAL";
    case MESH_PAIRING_DELEGATION_INVALID: return "DELEGATION_INVALID";
    case MESH_PAIRING_WINDOW_INVALID: return "WINDOW_INVALID";
    case MESH_PAIRING_ALREADY_REVOKED: return "ALREADY_REVOKED";
    case MESH_PAIRING_IDENTITY_COLLISION: return "IDENTITY_COLLISION";
    case MESH_PAIRING_PERSIST_FAILED: return "PERSIST_FAILED";
    case MESH_PAIRING_NOT_FOUND: return "NOT_FOUND";
    case MESH_PAIRING_EXPIRED: return "EXPIRED";
    case MESH_PAIRING_SESSION_MISMATCH: return "SESSION_MISMATCH";
    case MESH_PAIRING_AUTHORITY_CHANGED: return "AUTHORITY_CHANGED";
    }
    return "BAD_ARGUMENT";
}

const char *boot_mesh_pairing_plan_result_string(
    enum boot_mesh_pairing_plan_result result)
{
    switch (result) {
    case MESH_PAIR_PLAN_OK: return "ok";
    case MESH_PAIR_PLAN_BAD_ARGUMENT: return "bad_argument";
    case MESH_PAIR_PLAN_UNAVAILABLE: return "unavailable";
    case MESH_PAIR_PLAN_V2_DISABLED: return "v2_transport_disabled";
    case MESH_PAIR_PLAN_PEER_NOT_CONNECTED: return "peer_not_connected";
    case MESH_PAIR_PLAN_AMBIGUOUS_PEER: return "ambiguous_peer";
    case MESH_PAIR_PLAN_DELEGATION_UNAVAILABLE: return "delegation_unavailable";
    }
    return "bad_argument";
}

const char *boot_mesh_pairing_commit_result_string(
    enum boot_mesh_pairing_commit_result result)
{
    switch (result) {
    case MESH_PAIR_COMMIT_OK: return "ok";
    case MESH_PAIR_COMMIT_BAD_ARGUMENT: return "bad_argument";
    case MESH_PAIR_COMMIT_UNAVAILABLE: return "unavailable";
    case MESH_PAIR_COMMIT_V2_DISABLED: return "v2_transport_disabled";
    case MESH_PAIR_COMMIT_PEER_NOT_CONNECTED: return "peer_not_connected";
    case MESH_PAIR_COMMIT_AMBIGUOUS_PEER: return "ambiguous_peer";
    case MESH_PAIR_COMMIT_DELEGATION_UNAVAILABLE: return "delegation_unavailable";
    case MESH_PAIR_COMMIT_SERVICE_REFUSED: return "service_refused";
    }
    return "bad_argument";
}

/* ── Live peer pick + held-delegation lookup ─────────────────────────── */

/* Snapshot connected peers under cs_nodes, keep those with an established
 * v2 session, then apply the selector (address substring or fingerprint
 * prefix). Returns the match count; on exactly one match *node_out holds an
 * owned reference the caller releases. Never dials. */
static int mesh_pair_pick_peer(struct net_manager *nm, const char *selector,
                               struct p2p_node **node_out,
                               struct v2_transport_snapshot *session_out)
{
    struct p2p_node *candidates[VCS_ZCODE_DHT_SERVICE_MAX_PEERS];
    size_t count = 0;
    zcl_mutex_lock(&nm->cs_nodes);
    for (size_t i = 0;
         i < nm->num_nodes && count < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++) {
        struct p2p_node *node = nm->nodes[i];
        if (!boot_zcode_dht_peer_ready(node))
            continue;
        candidates[count++] = node;
        p2p_node_add_ref(node);
    }
    zcl_mutex_unlock(&nm->cs_nodes);
    int matches = 0;
    for (size_t i = 0; i < count; i++) {
        struct v2_transport_snapshot snapshot;
        memset(&snapshot, 0, sizeof(snapshot));
        bool established = candidates[i]->transport &&
            v2_transport_snapshot(candidates[i]->transport, &snapshot) &&
            snapshot.established;
        bool matched = false;
        if (established) {
            uint8_t fingerprint[32];
            char fingerprint_hex[65] = {0};
            if (v2_identity_public_fingerprint(snapshot.remote_static,
                                               fingerprint))
                zcl_hex_encode(fingerprint, 32, fingerprint_hex);
            matched = boot_mesh_pairing_selector_matches(
                selector, candidates[i]->addr_name, fingerprint_hex);
        }
        if (matched) {
            matches++;
            if (matches == 1) {
                *node_out = candidates[i];
                *session_out = snapshot;
                continue; /* keep the reference */
            }
        }
        p2p_node_release(candidates[i]);
    }
    return matches;
}

struct mesh_pair_delegation_collect {
    struct vcs_zcode_dht_delegation *held; /* heap snapshot buffer */
    size_t held_max;
    struct vcs_zcode_dht_delegation matched;
    size_t matched_count;
    uint8_t remote_static[32];
};

/* Runs under the DHT global lock (boot_zcode_dht_service_apply): memory
 * copies only, no I/O. */
static void mesh_pair_collect_delegation(
    struct vcs_zcode_dht_service *service, void *opaque)
{
    struct mesh_pair_delegation_collect *collect = opaque;
    if (!service || !collect || !collect->held)
        return;
    size_t count = vcs_zcode_dht_service_delegations(service, collect->held,
                                                     collect->held_max);
    for (size_t i = 0; i < count && collect->matched_count < 1; i++) {
        if (memcmp(collect->held[i].noise_static_pubkey,
                   collect->remote_static, 32) == 0) {
            collect->matched = collect->held[i];
            collect->matched_count++;
        }
    }
}

/* The peer's held delegation, exactly the lookup the status responder uses.
 * Latest-first match on the session's remote Noise static. */
static bool mesh_pair_held_delegation(const uint8_t remote_static[32],
                                      struct vcs_zcode_dht_delegation *out)
{
    struct mesh_pair_delegation_collect collect;
    memset(&collect, 0, sizeof(collect));
    collect.held = zcl_malloc(VCS_ZCODE_DHT_SERVICE_MAX_CHAIN_DELEGATIONS *
                                  sizeof(*collect.held),
                              "mesh_pairing.delegations");
    if (!collect.held) {
        LOG_ERROR("net.mesh_pairing", "delegation snapshot alloc failed");
        return false;
    }
    collect.held_max = VCS_ZCODE_DHT_SERVICE_MAX_CHAIN_DELEGATIONS;
    memcpy(collect.remote_static, remote_static, 32);
    (void)boot_zcode_dht_service_apply(mesh_pair_collect_delegation, &collect);
    bool found = collect.matched_count == 1;
    if (found)
        *out = collect.matched;
    free(collect.held);
    return found;
}

/* Shared live derivation for plan and commit: wired composition, v2 enabled,
 * exactly one matching session peer (owned ref out), its held delegation. */
static enum boot_mesh_pairing_plan_result mesh_pair_derive(
    const char *selector, struct p2p_node **node_out,
    struct v2_transport_snapshot *session_out,
    struct vcs_zcode_dht_delegation *delegation_out)
{
    pair_lock();
    struct boot_svc_ctx *svc = g_pair_svc;
    zcl_mutex_unlock(&g_pair_lock);
    if (!svc || !svc->msg_processor)
        return MESH_PAIR_PLAN_UNAVAILABLE;
    struct msg_processor *mp = svc->msg_processor;
    if (!mp->net_mgr || !mp->params) {
        LOG_ERROR("net.mesh_pairing", "derive: msg_processor incomplete");
        return MESH_PAIR_PLAN_UNAVAILABLE;
    }
    if (!mp->net_mgr->v2_enabled)
        return MESH_PAIR_PLAN_V2_DISABLED;
    struct p2p_node *node = NULL;
    int matches = mesh_pair_pick_peer(mp->net_mgr, selector, &node,
                                      session_out);
    if (matches == 0)
        return MESH_PAIR_PLAN_PEER_NOT_CONNECTED;
    if (matches > 1)
        return MESH_PAIR_PLAN_AMBIGUOUS_PEER;
    if (!mesh_pair_held_delegation(session_out->remote_static,
                                   delegation_out)) {
        p2p_node_release(node);
        return MESH_PAIR_PLAN_DELEGATION_UNAVAILABLE;
    }
    *node_out = node;
    return MESH_PAIR_PLAN_OK;
}

/* ── Plan / commit / list / revoke ───────────────────────────────────── */

enum boot_mesh_pairing_plan_result boot_mesh_pairing_plan(
    const char *selector, struct boot_mesh_pairing_plan *out)
{
    if (!out)
        return MESH_PAIR_PLAN_BAD_ARGUMENT;
    memset(out, 0, sizeof(*out));
    struct p2p_node *node = NULL;
    struct v2_transport_snapshot session;
    struct vcs_zcode_dht_delegation delegation;
    enum boot_mesh_pairing_plan_result derived =
        mesh_pair_derive(selector, &node, &session, &delegation);
    if (derived != MESH_PAIR_PLAN_OK)
        return derived;
    memcpy(out->peer_addr, node->addr_name, sizeof(out->peer_addr) - 1);
    p2p_node_release(node);
    memcpy(out->peer_noise_static, session.remote_static, 32);
    if (!v2_identity_public_fingerprint(session.remote_static,
                                        out->peer_noise_fingerprint)) {
        LOG_ERROR("net.mesh_pairing", "plan: fingerprint derivation failed");
        return MESH_PAIR_PLAN_UNAVAILABLE;
    }
    memcpy(out->peer_master_pubkey, delegation.doc.master_pubkey, 32);
    out->delegation_not_before = delegation.not_before;
    out->delegation_expiry = delegation.doc.expiry;
    out->delegation_sequence = delegation.doc.seq;
    out->delegation_beacon_height = delegation.beacon_height;
    out->capability_mask = MESH_PAIRING_CAP_STATUS_READ;
    out->now = (int64_t)platform_time_wall_time_t();
    out->default_expires_at =
        boot_mesh_pairing_expiry(out->now, BOOT_MESH_PAIRING_DEFAULT_DAYS);
    if (!mesh_pairing_id_derive(delegation.network_genesis,
                                delegation.doc.master_pubkey,
                                delegation.noise_static_pubkey,
                                out->pairing_id)) {
        LOG_ERROR("net.mesh_pairing", "plan: pairing id derivation failed");
        return MESH_PAIR_PLAN_UNAVAILABLE;
    }
    /* Advisory only: commit re-checks authority from scratch. */
    struct node_db *ndb = app_runtime_node_db();
    struct db_mesh_pairing existing;
    if (ndb && app_runtime_node_db_handle_open(ndb) &&
        db_mesh_pairing_find(ndb, out->pairing_id, &existing)) {
        const char *state = boot_mesh_pairing_state(&existing, out->now);
        snprintf(out->existing_state, sizeof(out->existing_state), "%s",
                 state);
    }
    return MESH_PAIR_PLAN_OK;
}

enum boot_mesh_pairing_commit_result boot_mesh_pairing_commit(
    const char *selector, const uint8_t expected_fingerprint[32],
    int64_t days, bool days_given, struct db_mesh_pairing *out,
    enum mesh_pairing_reason *service_reason_out)
{
    if (service_reason_out)
        *service_reason_out = MESH_PAIRING_OK;
    if (!expected_fingerprint || !out)
        return MESH_PAIR_COMMIT_BAD_ARGUMENT;
    if (!days_given)
        days = BOOT_MESH_PAIRING_DEFAULT_DAYS;
    if (!boot_mesh_pairing_days_valid(days))
        return MESH_PAIR_COMMIT_BAD_ARGUMENT;
    struct p2p_node *node = NULL;
    struct v2_transport_snapshot session;
    struct vcs_zcode_dht_delegation delegation;
    enum boot_mesh_pairing_plan_result derived =
        mesh_pair_derive(selector, &node, &session, &delegation);
    if (derived != MESH_PAIR_PLAN_OK)
        return (enum boot_mesh_pairing_commit_result)derived;
    p2p_node_release(node);
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !app_runtime_node_db_handle_open(ndb)) {
        LOG_ERROR("net.mesh_pairing", "commit: node_db unavailable");
        return MESH_PAIR_COMMIT_UNAVAILABLE;
    }
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (now <= 0) {
        LOG_ERROR("net.mesh_pairing", "commit: wall clock unavailable");
        return MESH_PAIR_COMMIT_UNAVAILABLE;
    }
    enum mesh_pairing_reason reason = mesh_pairing_service_accept(
        ndb, &delegation, expected_fingerprint, session.remote_static,
        session.established, MESH_PAIRING_CAP_STATUS_READ, now,
        boot_mesh_pairing_expiry(now, days), out);
    if (reason != MESH_PAIRING_OK) {
        if (service_reason_out)
            *service_reason_out = reason;
        return MESH_PAIR_COMMIT_SERVICE_REFUSED;
    }
    return MESH_PAIR_COMMIT_OK;
}

int boot_mesh_pairing_list(struct db_mesh_pairing *out, size_t max)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !app_runtime_node_db_handle_open(ndb)) {
        LOG_ERROR("net.mesh_pairing", "list: node_db unavailable");
        return -1;
    }
    return db_mesh_pairing_list(ndb, out, max);
}

enum mesh_pairing_reason boot_mesh_pairing_revoke(const char *pairing_id)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !app_runtime_node_db_handle_open(ndb)) {
        LOG_ERROR("net.mesh_pairing", "revoke: node_db unavailable");
        return MESH_PAIRING_BAD_ARGUMENT;
    }
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (now <= 0) {
        LOG_ERROR("net.mesh_pairing", "revoke: wall clock unavailable");
        return MESH_PAIRING_BAD_ARGUMENT;
    }
    return mesh_pairing_service_revoke(ndb, pairing_id, now);
}
