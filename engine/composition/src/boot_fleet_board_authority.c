/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Who the "board" stream lane serves, pulls from and pushes to:
 * the pairing row, the peer's delegation and whether it is current, the read
 * role and the fleet roster, each asked the same way by the answering half
 * (boot_fleet_board_fleet.c), the asking half and the push
 * (boot_fleet_board_push.c). Moved out of boot_fleet_board_fleet.c unchanged
 * so the stream lane keeps to its size limit; refusals are counted and named
 * here, never the peer.
 */

#include "boot_fleet_board_authority_internal.h"

#include "boot_mesh_status_internal.h"
#include "config/boot_fleet_roster.h"
#include "config/boot_zcode_dht.h"
#include "config/runtime.h"

#include "base/safe_alloc.h"
#include "models/mesh_pairing.h"
#include "platform/time_compat.h"
#include "services/mesh_pairing_service.h"
#include "util/fleet_role_check.h"
#include "util/log_macros.h"
#include "util/sync.h"
#include "vcs/zcode_dht_identity.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

static _Atomic uint64_t g_delegation_refused;
static _Atomic uint64_t g_role_refused;

#ifdef ZCL_TESTING
/* See boot_fleet_board_fleet_test_bind_authority / _bind_second_peer. */
static zcl_mutex_t g_test_lock;
static zcl_once_t g_test_once = ZCL_ONCE_INIT;
static bool g_test_authority;
static struct vcs_zcode_dht_delegation g_test_delegation;
static struct vcs_zcode_dht_delegation g_test_second;
static bool g_test_second_set;
static uint8_t g_test_genesis[32];
static int64_t g_test_now;

static void board_test_lock_init(void)
{
    zcl_mutex_init(&g_test_lock);
}

static void board_test_lock(void)
{
    (void)zcl_once_call(&g_test_once, board_test_lock_init);
    zcl_mutex_lock(&g_test_lock);
}
#endif

/* The composition roots this decision reads, named so the test group can
 * stand in for the DHT lookup it cannot host (boot_fleet_ledger.c has the
 * same three, for the same reason). */
bool board_peer_delegation(const struct db_mesh_pairing *row,
                           struct vcs_zcode_dht_delegation *out)
{
#ifdef ZCL_TESTING
    if (g_test_authority) {
        const struct vcs_zcode_dht_delegation *d =
            memcmp(row->peer_noise_pubkey,
                   g_test_delegation.noise_static_pubkey, 32) == 0
                ? &g_test_delegation
            : g_test_second_set &&
                    memcmp(row->peer_noise_pubkey,
                           g_test_second.noise_static_pubkey, 32) == 0
                ? &g_test_second
                : NULL;
        if (d)
            *out = *d;
        return d != NULL;
    }
#endif
    return boot_mesh_peer_delegation(row, out);
}

bool board_network_genesis(uint8_t out[32])
{
#ifdef ZCL_TESTING
    if (g_test_authority) {
        memcpy(out, g_test_genesis, 32);
        return true;
    }
#endif
    return boot_zcode_dht_network_genesis(out);
}

int64_t board_now(void)
{
#ifdef ZCL_TESTING
    if (g_test_authority)
        return g_test_now;
#endif
    return (int64_t)platform_time_wall_time_t();
}

/* The pairing row's own window cannot say whether the peer's master
 * identity is still ACTIVE on chain, so that is asked separately. A
 * refusal is counted and named, never the peer. */
bool board_delegation_current(struct node_db *ndb,
                              const struct db_mesh_pairing *row,
                              const struct vcs_zcode_dht_delegation *peer,
                              const uint8_t session_noise_static[32],
                              int64_t now)
{
    uint8_t network_genesis[32];
    enum mesh_pairing_reason reason = MESH_PAIRING_BAD_ARGUMENT;
    if (board_network_genesis(network_genesis))
        reason = mesh_pairing_service_authorize_status(
            ndb, network_genesis, row->pairing_id, peer,
            session_noise_static, now);
    if (reason == MESH_PAIRING_OK)
        return true;
    atomic_fetch_add_explicit(&g_delegation_refused, 1, memory_order_relaxed);
    LOG_WARN("fleet.board", "fleet pull refused: delegation %s",
             mesh_pairing_reason_token(reason));
    return false;
}

/* The pairing row for one Noise static: bounded, and fail-closed on an
 * unreadable list. */
bool board_pairing_for_peer(struct node_db *ndb,
                            const uint8_t peer_noise_static[32],
                            struct db_mesh_pairing *out)
{
    struct db_mesh_pairing *rows = zcl_calloc(
        FLEET_BOARD_FLEET_PEERS_MAX, sizeof *rows, "fleet_board_pairing");
    if (!rows)
        return false;
    int count = db_mesh_pairing_list(ndb, rows, FLEET_BOARD_FLEET_PEERS_MAX);
    bool found = false;
    for (int i = 0; i < count && !found; i++) {
        if (memcmp(rows[i].peer_noise_pubkey, peer_noise_static, 32) != 0)
            continue;
        *out = rows[i];
        found = true;
    }
    free(rows);
    return found;
}

/* A paired, current peer still reads fleet-private posts only when the
 * key it signs with holds a role granting the board's read leaf here. */
bool board_peer_may_read(const uint8_t signer[32])
{
    char why[ZCL_FLEET_ROLE_WHY_MAX];
    if (zcl_fleet_role_allows(signer, FLEET_BOARD_FLEET_READ_LEAF, NULL, why,
                              sizeof why))
        return true;
    atomic_fetch_add_explicit(&g_role_refused, 1, memory_order_relaxed);
    LOG_WARN("fleet.board", "fleet pull refused: %s", why);
    return false;
}

/* ZRC 0012 step 2: is this peer's board key on the fleet roster? The roster
 * is read from the board store this box serves from. Unarmed (no fleet root,
 * or no sealed row yet) admits, exactly as before this step; an armed roster
 * admits members only; an unverifiable one admits nobody. */
bool board_roster_admits(const uint8_t online_pubkey[32])
{
    struct node_db *store = board_db();
    if (!store)
        return false;
    int64_t now = board_now();
    bool ok = boot_fleet_roster_admits_peer(store, online_pubkey, now);
    uint64_t skipped = 0;
    if (!ok && boot_fleet_roster_log_due(BOOT_FLEET_ROSTER_LOG_PEER_REFUSED,
                                         now, &skipped))
        LOG_WARN("fleet.board", "fleet pull refused: not on the fleet roster "
                 "(%llu more since the last line)",
                 (unsigned long long)skipped);
    return ok;
}

/* Everything the answering half proves about a peer that is already
 * through the primitive's Noise and capability gates, before any post is
 * read. */
bool board_accept_authorized(const uint8_t peer_noise_static[32])
{
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !app_runtime_node_db_handle_open(ndb))
        return false;
    struct db_mesh_pairing row;
    struct vcs_zcode_dht_delegation peer;
    if (!board_pairing_for_peer(ndb, peer_noise_static, &row) ||
        !board_peer_delegation(&row, &peer)) {
        atomic_fetch_add_explicit(&g_delegation_refused, 1,
                                  memory_order_relaxed);
        LOG_WARN("fleet.board", "fleet pull refused: delegation_unresolved");
        return false;
    }
    return board_delegation_current(ndb, &row, &peer, peer_noise_static,
                                    board_now()) &&
           board_peer_may_read(peer.online_pubkey) &&
           board_roster_admits(peer.online_pubkey);
}

void board_authority_counts(struct boot_fleet_board_fleet_counts *out)
{
    out->delegation_refused =
        atomic_load_explicit(&g_delegation_refused, memory_order_relaxed);
    out->role_refused =
        atomic_load_explicit(&g_role_refused, memory_order_relaxed);
}

#ifdef ZCL_TESTING
void boot_fleet_board_fleet_test_bind_authority(
    const struct vcs_zcode_dht_delegation *peer_delegation,
    const uint8_t network_genesis[32], int64_t now)
{
    board_test_lock();
    g_test_authority = peer_delegation && network_genesis && now > 0;
    memset(&g_test_delegation, 0, sizeof g_test_delegation);
    memset(g_test_genesis, 0, sizeof g_test_genesis);
    g_test_now = 0;
    if (g_test_authority) {
        g_test_delegation = *peer_delegation;
        memcpy(g_test_genesis, network_genesis, 32);
        g_test_now = now;
    }
    memset(&g_test_second, 0, sizeof g_test_second);
    g_test_second_set = false;
    zcl_mutex_unlock(&g_test_lock);
}

void boot_fleet_board_fleet_test_bind_second_peer(
    const struct vcs_zcode_dht_delegation *peer_delegation)
{
    board_test_lock();
    g_test_second_set = peer_delegation != NULL;
    memset(&g_test_second, 0, sizeof g_test_second);
    if (peer_delegation)
        g_test_second = *peer_delegation;
    zcl_mutex_unlock(&g_test_lock);
}
#endif
