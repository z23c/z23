/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM-fetch peer scoring — see net/rom_peer_scoring.h.
 *
 * Bounded local deprioritize list, same insert/expire shape as
 * snapsync_blacklist_peer / snapsync_is_peer_blacklisted
 * (engine/services/src/snapshot_sync_service.c): refresh-in-place on repeat
 * offence, evict expired entries before inserting, drop silently if still
 * full of live entries (a bounded resource never grows unbounded under
 * attack). Keyed by "addr:port" text — ROM seeders are not P2P peers, so
 * there is no node_id/peer_id to key on. */

#include "net/rom_peer_scoring.h"
#include "net/peer_scoring.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define RPS_SUBSYS "rom_peer_scoring"

struct rom_peer_deprio_entry {
    char    key[128 + 8]; /* "addr:port" */
    int64_t last_offence_us;
    uint32_t offence_count;
};

static struct rom_peer_deprio_entry g_deprio[ROM_PEER_MAX_DEPRIORITIZE];
static int g_deprio_count;
static pthread_mutex_t g_deprio_mutex = PTHREAD_MUTEX_INITIALIZER;

static void rps_make_key(char *out, size_t out_cap, const char *addr,
                         uint16_t port)
{
    snprintf(out, out_cap, "%s:%u", addr, (unsigned)port);
}

/* Caller holds g_deprio_mutex. */
static void rps_evict_expired_locked(int64_t now_us)
{
    int64_t expiry_us = ROM_PEER_DEPRIORITIZE_SECS * 1000000LL;
    for (int i = 0; i < g_deprio_count; ) {
        if ((now_us - g_deprio[i].last_offence_us) >= expiry_us) {
            g_deprio[i] = g_deprio[--g_deprio_count];
        } else {
            i++;
        }
    }
}

static bool rps_note_local(const char *peer_addr, uint16_t port,
                           uint32_t idx, const char *reason)
{
    char key[sizeof(g_deprio[0].key)];
    rps_make_key(key, sizeof(key), peer_addr, port);
    int64_t now_us = platform_time_monotonic_us();

    pthread_mutex_lock(&g_deprio_mutex);

    /* Refresh in place if already listed. */
    for (int i = 0; i < g_deprio_count; i++) {
        if (strcmp(g_deprio[i].key, key) == 0) {
            g_deprio[i].last_offence_us = now_us;
            g_deprio[i].offence_count++;
            pthread_mutex_unlock(&g_deprio_mutex);
            LOG_WARN(RPS_SUBSYS, "bad ROM chunk from %s idx=%u reason=%s "
                     "(deprioritize refreshed, offence_count=%u)",
                     key, idx, reason ? reason : "?",
                     g_deprio[i].offence_count);
            return true;
        }
    }

    rps_evict_expired_locked(now_us);

    bool recorded = false;
    if (g_deprio_count < ROM_PEER_MAX_DEPRIORITIZE) {
        struct rom_peer_deprio_entry *e = &g_deprio[g_deprio_count++];
        snprintf(e->key, sizeof(e->key), "%s", key);
        e->last_offence_us = now_us;
        e->offence_count = 1;
        recorded = true;
    }
    pthread_mutex_unlock(&g_deprio_mutex);

    if (recorded) {
        LOG_WARN(RPS_SUBSYS, "bad ROM chunk from %s idx=%u reason=%s "
                 "(deprioritized for %ds)", key, idx, reason ? reason : "?",
                 ROM_PEER_DEPRIORITIZE_SECS);
    } else {
        LOG_WARN(RPS_SUBSYS, "bad ROM chunk from %s idx=%u reason=%s "
                 "(deprioritize list full of other live entries — not "
                 "recorded)", key, idx, reason ? reason : "?");
    }
    return recorded;
}

bool rom_peer_note_bad_chunk(const char *peer_addr, uint16_t port,
                             uint32_t idx, const char *reason)
{
    return rom_peer_note_bad_chunk_ex(NULL, NULL, peer_addr, port, idx,
                                      reason);
}

bool rom_peer_note_bad_chunk_ex(struct net_manager *nm, struct p2p_node *node,
                                const char *peer_addr, uint16_t port,
                                uint32_t idx, const char *reason)
{
    if (!peer_addr || !peer_addr[0])
        LOG_FAIL(RPS_SUBSYS, "NULL/empty peer_addr");

    if (nm && node) {
        char ctx[192];
        snprintf(ctx, sizeof(ctx), "ROM chunk idx=%u reason=%s from %s:%u",
                 idx, reason ? reason : "?", peer_addr, (unsigned)port);
        peer_scoring_record(nm, node, PEER_OFFENCE_INVALID_CHUNK, ctx);
        return true;
    }

    return rps_note_local(peer_addr, port, idx, reason);
}

bool rom_peer_is_deprioritized(const char *peer_addr, uint16_t port)
{
    if (!peer_addr || !peer_addr[0])
        return false;

    char key[sizeof(g_deprio[0].key)];
    rps_make_key(key, sizeof(key), peer_addr, port);
    int64_t now_us = platform_time_monotonic_us();
    int64_t expiry_us = ROM_PEER_DEPRIORITIZE_SECS * 1000000LL;

    pthread_mutex_lock(&g_deprio_mutex);
    bool found = false;
    for (int i = 0; i < g_deprio_count; i++) {
        if (strcmp(g_deprio[i].key, key) == 0 &&
            (now_us - g_deprio[i].last_offence_us) < expiry_us) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_deprio_mutex);
    return found;
}

void rom_peer_scoring_test_reset(void)
{
    pthread_mutex_lock(&g_deprio_mutex);
    g_deprio_count = 0;
    memset(g_deprio, 0, sizeof(g_deprio));
    pthread_mutex_unlock(&g_deprio_mutex);
}
