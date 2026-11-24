/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Who the "board" stream lane serves, pulls from and pushes to:
 * the pairing rows, the peer's delegation and whether it is current, the read
 * role and the fleet roster, each asked the same way by the answering half
 * (boot_fleet_board_fleet.c), the asking half and the push
 * (boot_fleet_board_push.c). Moved out of boot_fleet_board_fleet.c so the
 * stream lane keeps to its size limit. The pull's refusals are counted and
 * named here, never the peer. The push's sending half asks the answering
 * half's own disclosure decision (board_disclosure, through
 * board_push_disclosure) with recording off, so it computes exactly what a
 * pull from that peer would and counts and logs nothing as a pull; the
 * receiving half asks board_push_pusher_keys. The push names its own
 * refusals.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static _Atomic uint64_t g_delegation_refused;
static _Atomic uint64_t g_role_refused;

#ifdef ZCL_TESTING
/* See boot_fleet_board_fleet_test_bind_authority / _bind_second_peer /
 * _bind_third_peer. */
static zcl_mutex_t g_test_lock;
static zcl_once_t g_test_once = ZCL_ONCE_INIT;
static bool g_test_authority;
static struct vcs_zcode_dht_delegation g_test_delegation;
static struct vcs_zcode_dht_delegation g_test_second;
static bool g_test_second_set;
static struct vcs_zcode_dht_delegation g_test_third;
static bool g_test_third_set;
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
            : g_test_third_set &&
                    memcmp(row->peer_noise_pubkey,
                           g_test_third.noise_static_pubkey, 32) == 0
                ? &g_test_third
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

/* One refused pull, logged with the stage that said no and the command that
 * clears it (boot_fleet_board_refusal.c). */
static void board_refusal_log(enum boot_fleet_board_stage stage,
                              const char *why)
{
    char line[512];
    LOG_WARN("fleet.board", "fleet pull refused: %s",
             boot_fleet_board_stage_line(stage, why, line, sizeof line));
}

/* The pairing row's own window cannot say whether the peer's master
 * identity is still ACTIVE on chain, so that is asked separately. */
static enum mesh_pairing_reason board_delegation_reason(
    struct node_db *ndb, const struct db_mesh_pairing *row,
    const struct vcs_zcode_dht_delegation *peer,
    const uint8_t session_noise_static[32], int64_t now)
{
    uint8_t network_genesis[32];
    if (!board_network_genesis(network_genesis))
        return MESH_PAIRING_BAD_ARGUMENT;
    return mesh_pairing_service_authorize_status(
        ndb, network_genesis, row->pairing_id, peer, session_noise_static,
        now);
}

/* The delegation question; with `record` a refusal is counted and named as
 * the pull's, never the peer. */
static bool board_delegation_check(struct node_db *ndb,
                                   const struct db_mesh_pairing *row,
                                   const struct vcs_zcode_dht_delegation *peer,
                                   const uint8_t session_noise_static[32],
                                   int64_t now, bool record)
{
    enum mesh_pairing_reason reason =
        board_delegation_reason(ndb, row, peer, session_noise_static, now);
    if (reason == MESH_PAIRING_OK)
        return true;
    if (!record)
        return false;
    atomic_fetch_add_explicit(&g_delegation_refused, 1, memory_order_relaxed);
    board_refusal_log(BOARD_STAGE_DELEGATION, mesh_pairing_reason_token(reason));
    return false;
}

/* The pull's question. A refusal is counted and named, never the peer. */
bool board_delegation_current(struct node_db *ndb,
                              const struct db_mesh_pairing *row,
                              const struct vcs_zcode_dht_delegation *peer,
                              const uint8_t session_noise_static[32],
                              int64_t now)
{
    return board_delegation_check(ndb, row, peer, session_noise_static, now,
                                  true);
}

/* The pairing rows that may authorise a disclosure to one Noise static now:
 * those granting the status capability at `now` (not revoked, unexpired),
 * newest first (the list runs oldest first), at most
 * FLEET_BOARD_DISCLOSURE_ROWS_MAX. Bounded, and fail-closed on an unreadable
 * list. */
static size_t board_disclosure_rows(
    struct node_db *ndb, const uint8_t peer_noise_static[32], int64_t now,
    struct db_mesh_pairing out[FLEET_BOARD_DISCLOSURE_ROWS_MAX])
{
    struct db_mesh_pairing *rows = zcl_calloc(
        FLEET_BOARD_FLEET_PEERS_MAX, sizeof *rows, "fleet_board_pairing");
    if (!rows)
        return 0;
    int count = db_mesh_pairing_list(ndb, rows, FLEET_BOARD_FLEET_PEERS_MAX);
    size_t n = 0;
    for (int i = count - 1; i >= 0 && n < FLEET_BOARD_DISCLOSURE_ROWS_MAX; i--)
        if (memcmp(rows[i].peer_noise_pubkey, peer_noise_static, 32) == 0 &&
            mesh_pairing_allows(&rows[i], MESH_PAIRING_CAP_STATUS_READ, now))
            out[n++] = rows[i];
    free(rows);
    return n;
}

/* Add `key` to the first `n` of `keys` unless it is there or they are full. */
static size_t board_key_add(uint8_t (*keys)[32], size_t n, size_t cap,
                            const uint8_t key[32])
{
    for (size_t i = 0; i < n; i++)
        if (memcmp(keys[i], key, 32) == 0)
            return n;
    if (n == cap)
        return n;
    memcpy(keys[n], key, 32);
    return n + 1;
}

size_t board_push_pusher_keys(struct node_db *ndb,
                              const uint8_t peer_noise_static[32], int64_t now,
                              uint8_t (*keys)[32], size_t cap,
                              enum fleet_board_push_refusal *why)
{
    *why = FLEET_BOARD_PUSH_REFUSAL_PAIRING;
    struct db_mesh_pairing *rows = zcl_calloc(
        FLEET_BOARD_FLEET_PEERS_MAX, sizeof *rows, "fleet_board_push_pairing");
    if (!rows)
        return 0;
    int count = db_mesh_pairing_list(ndb, rows, FLEET_BOARD_FLEET_PEERS_MAX);
    size_t n = 0;
    bool judged = false;
    /* The list runs oldest first: walk it from the end, newest first. */
    for (int i = count - 1; i >= 0 && n < cap; i--) {
        if (memcmp(rows[i].peer_noise_pubkey, peer_noise_static, 32) != 0 ||
            !mesh_pairing_allows(&rows[i], MESH_PAIRING_CAP_STATUS_READ, now))
            continue;
        uint8_t online[32];
        enum fleet_board_push_refusal r =
            board_push_judge_peer(&rows[i], now, online);
        if (r == FLEET_BOARD_PUSH_REFUSALS)
            n = board_key_add(keys, n, cap, online);
        else if (!judged)
            *why = r; /* the newest allowing row's failure names the refusal */
        judged = true;
    }
    free(rows);
    return n;
}

enum fleet_board_push_refusal board_push_judge_peer(
    const struct db_mesh_pairing *row, int64_t now, uint8_t online_out[32])
{
    struct node_db *ndb = app_runtime_node_db();
    if (!row || !ndb || !app_runtime_node_db_handle_open(ndb) ||
        !mesh_pairing_allows(row, MESH_PAIRING_CAP_STATUS_READ, now))
        return FLEET_BOARD_PUSH_REFUSAL_PAIRING;
    struct vcs_zcode_dht_delegation peer;
    if (!board_peer_delegation(row, &peer) ||
        board_delegation_reason(ndb, row, &peer, row->peer_noise_pubkey,
                                now) != MESH_PAIRING_OK)
        return FLEET_BOARD_PUSH_REFUSAL_DELEGATION;
    struct node_db *store = board_db();
    if (!store || !boot_fleet_roster_admits_peer(store, peer.online_pubkey, now))
        return FLEET_BOARD_PUSH_REFUSAL_ROSTER;
    if (online_out)
        memcpy(online_out, peer.online_pubkey, 32);
    return FLEET_BOARD_PUSH_REFUSALS;
}

/* The read-role question; with `record` a refusal is counted and named as
 * the pull's. */
static bool board_read_check(const uint8_t signer[32], bool record)
{
    char why[ZCL_FLEET_ROLE_WHY_MAX];
    if (zcl_fleet_role_allows(signer, FLEET_BOARD_FLEET_READ_LEAF, NULL, why,
                              sizeof why))
        return true;
    if (!record)
        return false;
    atomic_fetch_add_explicit(&g_role_refused, 1, memory_order_relaxed);
    board_refusal_log(BOARD_STAGE_ANSWER_ROLE, why);
    return false;
}

/* A paired, current peer still reads fleet-private posts only when the
 * key it signs with holds a role granting the board's read leaf here. */
bool board_peer_may_read(const uint8_t signer[32])
{
    return board_read_check(signer, true);
}

bool board_push_may_read(const uint8_t signer[32])
{
    return board_read_check(signer, false);
}

/* The roster question; with `record` a refusal is logged as the pull's,
 * rate limited. */
static bool board_roster_check(const uint8_t online_pubkey[32], bool record)
{
    struct node_db *store = board_db();
    if (!store)
        return false;
    int64_t now = board_now();
    bool ok = boot_fleet_roster_admits_peer(store, online_pubkey, now);
    uint64_t skipped = 0;
    if (!ok && record &&
        boot_fleet_roster_log_due(BOOT_FLEET_ROSTER_LOG_PEER_REFUSED, now,
                                  &skipped)) {
        char why[96];
        (void)snprintf(why, sizeof why, "not on the fleet roster (%llu more "
                       "since the last line)", (unsigned long long)skipped);
        board_refusal_log(BOARD_STAGE_ROSTER, why);
    }
    return ok;
}

/* ZRC 0012 step 2: is this peer's board key on the fleet roster? The roster
 * is read from the board store this box serves from. Unarmed (no fleet root,
 * or no sealed row yet) admits, exactly as before this step; an armed roster
 * admits members only; an unverifiable one admits nobody. */
bool board_roster_admits(const uint8_t online_pubkey[32])
{
    return board_roster_check(online_pubkey, true);
}

/* A pull refusal that names no row's check; with `record` it is counted
 * and logged as the pull's. */
static void board_pull_refused(bool record, enum boot_fleet_board_stage stage,
                               const char *why)
{
    if (!record)
        return;
    atomic_fetch_add_explicit(&g_delegation_refused, 1, memory_order_relaxed);
    board_refusal_log(stage, why);
}

/* One pairing row's whole chain: the delegation of its master resolves, is
 * current and bound to this session's Noise key under this row, the read
 * role, the roster. FLEET_BOARD_PUSH_REFUSALS when it passes, with the
 * board key the delegation proves in `online_out` (may be NULL). */
static enum fleet_board_push_refusal board_disclosure_row(
    struct node_db *ndb, const struct db_mesh_pairing *row,
    const uint8_t peer_noise_static[32], int64_t now, bool record,
    uint8_t online_out[32])
{
    struct vcs_zcode_dht_delegation peer;
    if (!board_peer_delegation(row, &peer)) {
        board_pull_refused(record, BOARD_STAGE_DELEGATION,
                           "delegation_unresolved");
        return FLEET_BOARD_PUSH_REFUSAL_DELEGATION;
    }
    if (!board_delegation_check(ndb, row, &peer, peer_noise_static, now,
                                record))
        return FLEET_BOARD_PUSH_REFUSAL_DELEGATION;
    if (!board_read_check(peer.online_pubkey, record))
        return FLEET_BOARD_PUSH_REFUSAL_ROLE;
    if (!board_roster_check(peer.online_pubkey, record))
        return FLEET_BOARD_PUSH_REFUSAL_ROSTER;
    if (online_out)
        memcpy(online_out, peer.online_pubkey, 32);
    return FLEET_BOARD_PUSH_REFUSALS;
}

/* Everything the answering half proves about a peer that is already
 * through the primitive's Noise and capability gates, before any post is
 * read. The one decision for the pull (`record`: refusals counted and
 * logged as the pull's) and for the push's sending half (`record` clear:
 * the same computation, nothing recorded). The rows judged are
 * board_disclosure_rows; the peer is served when any one of them passes
 * board_disclosure_row, newest first, and the first that passes supplies
 * `online_out` (may be NULL). When none passes, the newest row's refusal is
 * the answer, recorded once: rows are judged with nothing recorded, and with
 * `record` the newest is judged again recording (only when it is not the
 * only row, which is judged recording at once). No allowing row: PAIRING. */
static enum fleet_board_push_refusal board_disclosure(
    const uint8_t peer_noise_static[32], bool record, uint8_t online_out[32])
{
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !app_runtime_node_db_handle_open(ndb))
        return FLEET_BOARD_PUSH_REFUSAL_PAIRING;
    int64_t now = board_now();
    struct db_mesh_pairing rows[FLEET_BOARD_DISCLOSURE_ROWS_MAX];
    size_t n = board_disclosure_rows(ndb, peer_noise_static, now, rows);
    if (n == 0) {
        board_pull_refused(record, BOARD_STAGE_PAIRING, "no live pairing");
        return FLEET_BOARD_PUSH_REFUSAL_PAIRING;
    }
    enum fleet_board_push_refusal newest = FLEET_BOARD_PUSH_REFUSAL_PAIRING;
    for (size_t i = 0; i < n; i++) {
        enum fleet_board_push_refusal r = board_disclosure_row(
            ndb, &rows[i], peer_noise_static, now, record && n == 1,
            online_out);
        if (r == FLEET_BOARD_PUSH_REFUSALS)
            return r;
        if (i == 0)
            newest = r;
    }
    if (record && n > 1)
        newest = board_disclosure_row(ndb, &rows[0], peer_noise_static, now,
                                      true, online_out);
    return newest;
}

bool board_accept_authorized(const uint8_t peer_noise_static[32])
{
    return board_disclosure(peer_noise_static, true, NULL) ==
           FLEET_BOARD_PUSH_REFUSALS;
}

enum fleet_board_push_refusal board_push_disclosure(
    const uint8_t peer_noise_static[32], uint8_t online_out[32])
{
    return board_disclosure(peer_noise_static, false, online_out);
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
    memset(&g_test_third, 0, sizeof g_test_third);
    g_test_third_set = false;
    zcl_mutex_unlock(&g_test_lock);
}

void boot_fleet_board_fleet_test_bind_third_peer(
    const struct vcs_zcode_dht_delegation *peer_delegation)
{
    board_test_lock();
    g_test_third_set = peer_delegation != NULL;
    memset(&g_test_third, 0, sizeof g_test_third);
    if (peer_delegation)
        g_test_third = *peer_delegation;
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

bool board_author_may_post(struct board_author_memo *m,
                           const struct fleet_board_post *p)
{
    if (!m->known || m->kind != p->kind || memcmp(m->host, p->host_pubkey, 32)) {
        m->allowed = zcl_fleet_role_allows(p->host_pubkey, ZCL_FLEET_LEAF_BOARD_POST,
                                           fleet_board_kind_name(p->kind), NULL, 0);
        memcpy(m->host, p->host_pubkey, 32);
        m->kind = p->kind;
        m->known = true;
    }
    return m->allowed;
}
