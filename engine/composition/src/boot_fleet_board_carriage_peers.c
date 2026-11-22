/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The fleet board's per-peer carriage state (see
 * boot_fleet_board_carriage_peers_internal.h). One small table under its own
 * lock, written by the lane tick and the stream close callback, read by the
 * status RPC. It records what the lane already decided; it decides nothing.
 */

#include "boot_fleet_board_carriage_peers_internal.h"

#include "config/boot_fleet_roster.h"
#include "config/boot_mesh_status.h"
#include "util/log_macros.h"
#include "util/sync.h"

#include <stdio.h>
#include <string.h>

static zcl_mutex_t g_lock;
static zcl_once_t g_once = ZCL_ONCE_INIT;
static struct board_carriage_peer g_peers[FLEET_BOARD_FLEET_PEERS_MAX];
static int64_t g_logged_at[FLEET_BOARD_FLEET_PEERS_MAX];
static size_t g_count;

static void carriage_lock_init(void)
{
    zcl_mutex_init(&g_lock);
}

static void carriage_lock(void)
{
    (void)zcl_once_call(&g_once, carriage_lock_init);
    zcl_mutex_lock(&g_lock);
}

static void carriage_unlock(void)
{
    zcl_mutex_unlock(&g_lock);
}

const char *board_carriage_reason_name(enum board_carriage_reason r)
{
    static const char *const names[BOARD_CARRIAGE_REASONS] = {
        [BOARD_CARRIAGE_NONE] = "",
        [BOARD_CARRIAGE_PAIRING_WINDOW_CLOSED] = "pairing_window_closed",
        [BOARD_CARRIAGE_NO_DELEGATION] = "no_delegation",
        [BOARD_CARRIAGE_DELEGATION_REFUSED] = "delegation_refused",
        [BOARD_CARRIAGE_ROSTER_GATED] = "roster_gated",
        [BOARD_CARRIAGE_PULL_IN_FLIGHT] = "pull_in_flight",
        [BOARD_CARRIAGE_PEER_NOT_CONNECTED] = "peer_not_connected",
        [BOARD_CARRIAGE_STREAM_OPEN_FAILED] = "stream_open_failed",
        [BOARD_CARRIAGE_ANSWER_REFUSED] = "answer_refused",
        [BOARD_CARRIAGE_NOT_DUE_YET] = "not_due_yet",
    };
    return (unsigned)r < BOARD_CARRIAGE_REASONS ? names[r] : "unknown";
}

/* The entry for `peer`, made when it is new; NULL when the table is full.
 * Lock held. */
static struct board_carriage_peer *carriage_entry(const uint8_t peer[32])
{
    for (size_t i = 0; i < g_count; i++)
        if (memcmp(g_peers[i].peer, peer, 32) == 0)
            return &g_peers[i];
    if (g_count >= FLEET_BOARD_FLEET_PEERS_MAX)
        return NULL;
    memcpy(g_peers[g_count].peer, peer, 32);
    return &g_peers[g_count++];
}

/* Reasons that are the lane working normally, not something to log. */
static bool carriage_quiet(enum board_carriage_reason r)
{
    return r == BOARD_CARRIAGE_NONE || r == BOARD_CARRIAGE_NOT_DUE_YET ||
           r == BOARD_CARRIAGE_PULL_IN_FLIGHT;
}

/* Lock held. True when this change should be logged now: the reason
 * changed to one that needs attention and this peer's window has passed. */
static bool carriage_set_reason(struct board_carriage_peer *e,
                                enum board_carriage_reason reason,
                                const char *detail, int64_t now)
{
    const char *d = detail ? detail : "";
    bool changed = e->reason != reason || strcmp(e->detail, d) != 0;
    e->reason = reason;
    (void)snprintf(e->detail, sizeof e->detail, "%s", d);
    if (!changed || carriage_quiet(reason))
        return false;
    int64_t *last = &g_logged_at[e - g_peers];
    if (*last != 0 && now >= *last &&
        now - *last < BOOT_FLEET_ROSTER_LOG_WINDOW_S)
        return false;
    *last = now;
    return true;
}

static void carriage_log(const uint8_t peer[32], enum board_carriage_reason r,
                         const char *detail)
{
    char hex[65];
    boot_mesh_status_key_fingerprint("zcl.mesh.master.fingerprint.v1", peer,
                                     hex);
    hex[12] = '\0';
    LOG_INFO("fleet.board", "fleet pull toward peer %s: %s%s%s", hex,
             board_carriage_reason_name(r), detail[0] ? ":" : "", detail);
}

void board_carriage_skip(const uint8_t peer[32],
                         enum board_carriage_reason reason,
                         const char *detail, int64_t now)
{
    char kept[BOARD_CARRIAGE_DETAIL_MAX];
    (void)snprintf(kept, sizeof kept, "%s", detail ? detail : "");
    carriage_lock();
    struct board_carriage_peer *e = carriage_entry(peer);
    bool log = e && carriage_set_reason(e, reason, kept, now);
    carriage_unlock();
    if (log)
        carriage_log(peer, reason, kept);
}

void board_carriage_gate(const uint8_t peer[32],
                         enum boot_fleet_board_gate_reason gate, int64_t now)
{
    static const enum board_carriage_reason map[] = {
        [FLEET_BOARD_GATE_PAIRING] = BOARD_CARRIAGE_PAIRING_WINDOW_CLOSED,
        [FLEET_BOARD_GATE_DELEGATION_UNRESOLVED] = BOARD_CARRIAGE_NO_DELEGATION,
        [FLEET_BOARD_GATE_DELEGATION_REFUSED] =
            BOARD_CARRIAGE_DELEGATION_REFUSED,
        [FLEET_BOARD_GATE_ROSTER] = BOARD_CARRIAGE_ROSTER_GATED,
    };
    if ((unsigned)gate < sizeof map / sizeof map[0])
        board_carriage_skip(peer, map[gate], NULL, now);
}

void board_carriage_pull(const uint8_t peer[32], int64_t now, bool opened,
                         bool not_connected, const char *refusal)
{
    carriage_lock();
    struct board_carriage_peer *e = carriage_entry(peer);
    if (e) {
        e->pulls++;
        e->last_pull_attempt_at = now;
        /* A stream that opens ends every earlier skip; only an answer
         * clears a refused one. */
        if (opened && e->reason != BOARD_CARRIAGE_ANSWER_REFUSED)
            (void)carriage_set_reason(e, BOARD_CARRIAGE_NONE, NULL, now);
    }
    carriage_unlock();
    if (!opened)
        board_carriage_skip(peer,
                            not_connected ? BOARD_CARRIAGE_PEER_NOT_CONNECTED
                                          : BOARD_CARRIAGE_STREAM_OPEN_FAILED,
                            not_connected ? NULL : refusal, now);
}

void board_carriage_answer(const uint8_t peer[32], size_t stored, int64_t now)
{
    carriage_lock();
    struct board_carriage_peer *e = carriage_entry(peer);
    if (e) {
        e->answers++;
        e->stored += stored;
        e->last_answer_at = now;
        (void)carriage_set_reason(e, BOARD_CARRIAGE_NONE, NULL, now);
    }
    carriage_unlock();
}

void board_carriage_refused(const uint8_t peer[32], const char *detail,
                            int64_t now)
{
    char kept[BOARD_CARRIAGE_DETAIL_MAX];
    (void)snprintf(kept, sizeof kept, "%s", detail ? detail : "");
    carriage_lock();
    struct board_carriage_peer *e = carriage_entry(peer);
    bool log = false;
    if (e) {
        e->refused++;
        log = carriage_set_reason(e, BOARD_CARRIAGE_ANSWER_REFUSED, kept, now);
    }
    carriage_unlock();
    if (log)
        carriage_log(peer, BOARD_CARRIAGE_ANSWER_REFUSED, kept);
}

void board_carriage_not_due(int64_t now)
{
    carriage_lock();
    for (size_t i = 0; i < g_count; i++)
        if (g_peers[i].reason == BOARD_CARRIAGE_NONE)
            (void)carriage_set_reason(&g_peers[i],
                                      BOARD_CARRIAGE_NOT_DUE_YET, NULL, now);
    carriage_unlock();
}

size_t board_carriage_snapshot(struct board_carriage_peer *out, size_t cap)
{
    carriage_lock();
    size_t n = g_count < cap ? g_count : cap;
    if (out && n)
        memcpy(out, g_peers, n * sizeof *out);
    size_t total = g_count;
    carriage_unlock();
    return total;
}

#ifdef ZCL_TESTING
void board_carriage_test_reset(void)
{
    carriage_lock();
    memset(g_peers, 0, sizeof g_peers);
    memset(g_logged_at, 0, sizeof g_logged_at);
    g_count = 0;
    carriage_unlock();
}
#endif
