/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM seeding SERVE CAPS — the free tier's in-memory DDoS bound.
 *
 * Split out of rom_seed.c along the file-size ceiling seam. This file owns a
 * complete, self-contained state group and nothing else: the enable flag, the
 * three cap knobs, the per-peer accounting table, its mutex, and the serve
 * counters. Every function that reads or writes any of them lives here, so the
 * statics stay file-scope-private exactly as they were before the split —
 * nothing is exported, and no caller anywhere touches the table or the mutex
 * directly. Nothing here is persisted or a consensus predicate.
 *
 * LOCKING (unchanged by the split): g_caps_mutex guards g_peers,
 * g_global_win_start/g_global_win_bytes and the three serve counters.
 * peer_slot_locked() is the only function whose name states the contract —
 * its caller already holds g_caps_mutex — and both of its callers
 * (rom_seed_peer_acquire, rom_seed_rate_charge) are in this file, take the
 * mutex themselves, and release it before returning. The cap knobs and the
 * enable flag are _Atomic and are read WITHOUT the mutex, so no lock order
 * exists to violate: this file never takes a second lock while holding
 * g_caps_mutex, and never calls out of the translation unit under it.
 *
 * The public entry points stay declared in net/rom_seed.h; the two names
 * rom_seed.c and rom_seed_report.c reach back for are in rom_seed_internal.h.
 */
#include "rom_seed_internal.h"

#include "net/rom_seed.h"
#include "json/json.h"
#include "platform/time_compat.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

/* ── Config (read from serve threads; set at boot) ──────────────────── */
static _Atomic bool     g_enabled = true;
static _Atomic uint32_t g_max_inflight_per_peer = ROM_SEED_DEFAULT_MAX_INFLIGHT_PER_PEER;
static _Atomic uint64_t g_peer_bps_cap   = ROM_SEED_DEFAULT_PEER_BPS_CAP;
static _Atomic uint64_t g_global_bps_cap = ROM_SEED_DEFAULT_GLOBAL_BPS_CAP;
/* ── Caps + stats state (one mutex) ─────────────────────────────────── */
struct rom_peer_stat {
    uint8_t  ip[16];
    bool     used;
    bool     ever_served;
    uint32_t concurrent;   /* active in-flight serves for this peer   */
    int64_t  win_start;    /* rolling 1-second byte-rate window start  */
    uint64_t win_bytes;    /* bytes charged in the current window      */
    int64_t  last_seen;    /* LRU eviction when the table is full      */
};
static struct rom_peer_stat g_peers[ROM_SEED_PEER_TABLE_CAP];
static pthread_mutex_t g_caps_mutex = PTHREAD_MUTEX_INITIALIZER;
static int64_t  g_global_win_start = 0;
static uint64_t g_global_win_bytes = 0;

static uint64_t g_chunks_served = 0;
static uint64_t g_bytes_served_total = 0;
static uint64_t g_unique_peers_served = 0;

/* ── Caps ───────────────────────────────────────────────────────────── */

void rom_seed_set_enabled(bool on) { atomic_store(&g_enabled, on); }
bool rom_seed_enabled(void) { return atomic_load(&g_enabled); }

void rom_seed_set_max_inflight_per_peer(uint32_t n)
{
    if (n == 0) n = 1;
    atomic_store(&g_max_inflight_per_peer, n);
}
void rom_seed_set_peer_bps_cap(uint64_t bps)
{
    atomic_store(&g_peer_bps_cap, bps ? bps : 1);
}
void rom_seed_set_global_bps_cap(uint64_t bps)
{
    atomic_store(&g_global_bps_cap, bps ? bps : 1);
}

/* Find-or-allocate the peer slot (caller holds g_caps_mutex). Evicts the LRU
 * idle slot when full; never evicts a slot with active in-flight serves. */
static struct rom_peer_stat *peer_slot_locked(const uint8_t ip[16], int64_t now)
{
    struct rom_peer_stat *lru = NULL;
    for (unsigned i = 0; i < ROM_SEED_PEER_TABLE_CAP; i++) {
        if (g_peers[i].used && memcmp(g_peers[i].ip, ip, 16) == 0)
            return &g_peers[i];
        if (!g_peers[i].used)
            return &g_peers[i];
    }
    for (unsigned i = 0; i < ROM_SEED_PEER_TABLE_CAP; i++) {
        if (g_peers[i].concurrent == 0 &&
            (!lru || g_peers[i].last_seen < lru->last_seen))
            lru = &g_peers[i];
    }
    if (!lru)
        return NULL;   /* table full and every slot has an active serve: fail
                          closed rather than corrupt a live slot's in-flight
                          count. Callers deny the serve on NULL. */
    memset(lru, 0, sizeof(*lru));
    (void)now;
    return lru;
}

bool rom_seed_peer_acquire(const uint8_t peer_ip[16])
{
    if (!peer_ip) return false;
    if (!atomic_load(&g_enabled)) return false;
    uint32_t cap = atomic_load(&g_max_inflight_per_peer);
    int64_t now = (int64_t)platform_time_wall_time_t();
    bool ok = false;
    pthread_mutex_lock(&g_caps_mutex);
    struct rom_peer_stat *s = peer_slot_locked(peer_ip, now);
    if (s) {
        if (!s->used) {
            s->used = true;
            memcpy(s->ip, peer_ip, 16);
            s->win_start = now;
        }
        s->last_seen = now;
        if (s->concurrent < cap) {
            s->concurrent++;
            ok = true;
        }
    }
    pthread_mutex_unlock(&g_caps_mutex);
    return ok;
}

void rom_seed_peer_release(const uint8_t peer_ip[16])
{
    if (!peer_ip) return;
    pthread_mutex_lock(&g_caps_mutex);
    for (unsigned i = 0; i < ROM_SEED_PEER_TABLE_CAP; i++) {
        if (g_peers[i].used && memcmp(g_peers[i].ip, peer_ip, 16) == 0) {
            if (g_peers[i].concurrent > 0)
                g_peers[i].concurrent--;
            break;
        }
    }
    pthread_mutex_unlock(&g_caps_mutex);
}

bool rom_seed_rate_charge(const uint8_t peer_ip[16], uint64_t n, int64_t now)
{
    if (!peer_ip) return false;
    uint64_t peer_cap = atomic_load(&g_peer_bps_cap);
    uint64_t global_cap = atomic_load(&g_global_bps_cap);
    bool ok = true;

    pthread_mutex_lock(&g_caps_mutex);

    /* Global rolling-1s window. */
    if (now != g_global_win_start) {
        g_global_win_start = now;
        g_global_win_bytes = 0;
    }
    if (g_global_win_bytes > UINT64_MAX - n) g_global_win_bytes = UINT64_MAX;
    else g_global_win_bytes += n;
    if (g_global_win_bytes > global_cap) ok = false;

    /* Per-peer rolling-1s window. */
    struct rom_peer_stat *s = peer_slot_locked(peer_ip, now);
    if (s) {
        if (!s->used) {
            s->used = true;
            memcpy(s->ip, peer_ip, 16);
            s->win_start = now;
            s->win_bytes = 0;
        }
        if (now != s->win_start) {
            s->win_start = now;
            s->win_bytes = 0;
        }
        s->last_seen = now;
        if (s->win_bytes > UINT64_MAX - n) s->win_bytes = UINT64_MAX;
        else s->win_bytes += n;
        if (s->win_bytes > peer_cap) ok = false;

        if (ok) {
            if (!s->ever_served) {
                s->ever_served = true;
                g_unique_peers_served++;
            }
            g_bytes_served_total += n;
        }
    } else {
        ok = false;
    }

    pthread_mutex_unlock(&g_caps_mutex);
    return ok;
}

void rom_seed_note_chunk_served(void)
{
    pthread_mutex_lock(&g_caps_mutex);
    g_chunks_served++;
    pthread_mutex_unlock(&g_caps_mutex);
}

/* The caps half of rom_seed_reset(): clear the peer table, the rate windows
 * and the counters, then restore the default config so a serving session (or
 * a test) starts from a known clean slate — enabled, default caps. Takes and
 * releases g_caps_mutex itself, exactly as the inline block it replaces did,
 * and is called with no other lock held. */
void rom_seed_throttle_reset(void)
{
    pthread_mutex_lock(&g_caps_mutex);
    memset(g_peers, 0, sizeof(g_peers));
    g_global_win_start = 0;
    g_global_win_bytes = 0;
    g_chunks_served = 0;
    g_bytes_served_total = 0;
    g_unique_peers_served = 0;
    pthread_mutex_unlock(&g_caps_mutex);

    atomic_store(&g_enabled, true);
    atomic_store(&g_max_inflight_per_peer, ROM_SEED_DEFAULT_MAX_INFLIGHT_PER_PEER);
    atomic_store(&g_peer_bps_cap, ROM_SEED_DEFAULT_PEER_BPS_CAP);
    atomic_store(&g_global_bps_cap, ROM_SEED_DEFAULT_GLOBAL_BPS_CAP);
}

/* The caps half of rom_seed_dump_state_json(): the four config knobs, then
 * one snapshot of the four counters taken under g_caps_mutex. Emitted in the
 * order the dump has always emitted them, so the introspection JSON's field
 * order is unchanged. json_push_kv_* is called OUTSIDE the mutex; only the
 * scalar snapshot is taken under it, exactly as before. */
void rom_seed_throttle_push_json(struct json_value *out)
{
    json_push_kv_bool(out, "enabled", atomic_load(&g_enabled));
    json_push_kv_int(out, "max_inflight_per_peer",
                     (int64_t)atomic_load(&g_max_inflight_per_peer));
    json_push_kv_int(out, "peer_bps_cap",
                     (int64_t)atomic_load(&g_peer_bps_cap));
    json_push_kv_int(out, "global_bps_cap",
                     (int64_t)atomic_load(&g_global_bps_cap));

    uint64_t chunks_served, bytes_total, unique_peers, cur_bps;
    int64_t now = (int64_t)platform_time_wall_time_t();
    pthread_mutex_lock(&g_caps_mutex);
    chunks_served = g_chunks_served;
    bytes_total = g_bytes_served_total;
    unique_peers = g_unique_peers_served;
    cur_bps = (now == g_global_win_start) ? g_global_win_bytes : 0;
    pthread_mutex_unlock(&g_caps_mutex);

    json_push_kv_int(out, "chunks_served", (int64_t)chunks_served);
    json_push_kv_int(out, "bytes_served_total", (int64_t)bytes_total);
    json_push_kv_int(out, "unique_peers_served", (int64_t)unique_peers);
    json_push_kv_int(out, "current_bps", (int64_t)cur_bps);
}
