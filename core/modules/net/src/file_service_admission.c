/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Apply file-service proof-of-work and per-client serving admission. */
#include <stdint.h>
#include "net/file_service.h"
#include "base/serialize_le.h"
static void fs_parse_serve_reset(bool *is_all, bool *is_rng,
    const uint8_t **puzzle, uint16_t *rng_start, uint16_t *rng_end);
#if !defined(_WIN32)
#include "file_service_priv.h"
#include "net/file_service.h"
#include "base/serialize_le.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/log_json.h"
#include <stdio.h>
#include <string.h>

/* ── PoW-gated admission + per-IP resource caps ─────────────────────
 *
 * In-memory only. The gate mints rotating adaptive challenges; the IP table
 * bounds concurrency and hourly volume. Nothing here is persisted or a
 * consensus predicate — it only decides whether to SPEND uplink on a public
 * stream. */
static struct puzzle_gate g_fs_pow_gate;

struct fs_ip_stat g_fs_ip[FS_IP_TABLE_CAP];
pthread_mutex_t g_fs_ip_mutex = PTHREAD_MUTEX_INITIALIZER;

struct puzzle_gate *fs_pow_gate(void)
{
    return &g_fs_pow_gate;
}

static void fs_pow_reset_state_posix(void)
{
    puzzle_gate_init(&g_fs_pow_gate, NULL);
    pthread_mutex_lock(&g_fs_ip_mutex);
    memset(g_fs_ip, 0, sizeof(g_fs_ip));
    pthread_mutex_unlock(&g_fs_ip_mutex);
}

/* Find-or-allocate the stat slot for ip (caller holds g_fs_ip_mutex).
 * When the table is full, evict the least-recently-seen entry. */
static struct fs_ip_stat *fs_ip_slot_locked(const uint8_t ip[16], int64_t now)
{
    struct fs_ip_stat *lru = NULL;
    for (size_t i = 0; i < FS_IP_TABLE_CAP; i++) {
        if (g_fs_ip[i].used && memcmp(g_fs_ip[i].ip, ip, 16) == 0)
            return &g_fs_ip[i];
        if (!g_fs_ip[i].used)
            return &g_fs_ip[i];  /* first free slot (unused → all-zero) */
        if (!lru || g_fs_ip[i].last_seen < lru->last_seen)
            lru = &g_fs_ip[i];
    }
    /* Table full — reclaim the LRU slot, but never evict an entry that still
     * holds active serves (that would double-count concurrency). Fall back to
     * the numerically-first slot if every entry is busy (degrades to shared
     * accounting under a >512-IP flood, still bounded). */
    for (size_t i = 0; i < FS_IP_TABLE_CAP; i++) {
        if (g_fs_ip[i].concurrent == 0 &&
            (!lru || lru->concurrent > 0 ||
             g_fs_ip[i].last_seen < lru->last_seen))
            lru = &g_fs_ip[i];
    }
    if (!lru) lru = &g_fs_ip[0];
    memset(lru, 0, sizeof(*lru));
    (void)now;
    return lru;
}

static bool fs_ip_serve_acquire_posix(const uint8_t ip[16])
{
    if (!ip) return false;
    int64_t now = (int64_t)platform_time_wall_time_t();
    bool ok = false;
    pthread_mutex_lock(&g_fs_ip_mutex);
    struct fs_ip_stat *s = fs_ip_slot_locked(ip, now);
    if (s) {
        if (!s->used) {
            s->used = true;
            memcpy(s->ip, ip, 16);
            s->hour_start = now;
            s->bytes_this_hour = 0;
            s->concurrent = 0;
        }
        s->last_seen = now;
        if (s->concurrent < FS_MAX_CONCURRENT_PER_IP) {
            s->concurrent++;
            ok = true;
        }
    }
    pthread_mutex_unlock(&g_fs_ip_mutex);
    return ok;
}

static void fs_ip_serve_release_posix(const uint8_t ip[16])
{
    if (!ip) return;
    pthread_mutex_lock(&g_fs_ip_mutex);
    for (size_t i = 0; i < FS_IP_TABLE_CAP; i++) {
        if (g_fs_ip[i].used && memcmp(g_fs_ip[i].ip, ip, 16) == 0) {
            if (g_fs_ip[i].concurrent > 0)
                g_fs_ip[i].concurrent--;
            break;
        }
    }
    pthread_mutex_unlock(&g_fs_ip_mutex);
}

static bool fs_ip_bytes_charge_posix(const uint8_t ip[16], uint64_t n)
{
    if (!ip) return false;
    int64_t now = (int64_t)platform_time_wall_time_t();
    bool ok = false;
    pthread_mutex_lock(&g_fs_ip_mutex);
    struct fs_ip_stat *s = fs_ip_slot_locked(ip, now);
    if (s) {
        if (!s->used) {
            s->used = true;
            memcpy(s->ip, ip, 16);
            s->hour_start = now;
            s->bytes_this_hour = 0;
            s->concurrent = 0;
        }
        if (now - s->hour_start > 3600) {
            s->hour_start = now;
            s->bytes_this_hour = 0;
        }
        s->last_seen = now;
        /* Saturating add so a huge n can't wrap under the ceiling. */
        if (s->bytes_this_hour > UINT64_MAX - n)
            s->bytes_this_hour = UINT64_MAX;
        else
            s->bytes_this_hour += n;
        ok = s->bytes_this_hour <= FS_IP_MAX_BYTES_PER_HOUR;
    }
    pthread_mutex_unlock(&g_fs_ip_mutex);
    return ok;
}

static bool fs_conn_budget_ok_posix(uint64_t bytes_sent, int64_t start_monotonic_ms,
                       int64_t now_monotonic_ms)
{
    if (bytes_sent > FS_CONN_MAX_BYTES)
        return false;
    if (start_monotonic_ms <= 0 || now_monotonic_ms < start_monotonic_ms)
        return false;
    if ((uint64_t)(now_monotonic_ms - start_monotonic_ms) >
        (uint64_t)FS_CONN_MAX_SECONDS * 1000u)
        return false;
    return true;
}

bool fs_conn_deadline_ms(const struct fs_session *session,
                                int64_t *deadline_ms)
{
    int64_t budget_ms = (int64_t)FS_CONN_MAX_SECONDS * 1000;
    if (!session || !deadline_ms || session->start_monotonic_ms <= 0 ||
        session->start_monotonic_ms > INT64_MAX - budget_ms)
        return false;
    *deadline_ms = session->start_monotonic_ms + budget_ms;
    return true;
}

static bool fs_parse_serve_classify(const uint8_t *body, uint32_t blen,
                                    bool *is_all, bool *is_rng,
                                    uint16_t *rng_start, uint16_t *rng_end)
{
    if (blen == 3 && memcmp(body, "ALL", 3) == 0) {
        if (is_all) *is_all = true;
        return true;
    }
    if (blen >= 8 && memcmp(body, "RNG", 3) == 0) {
        if (is_rng) *is_rng = true;
        if (rng_start) *rng_start = zcl_read_u16_le(body + 3);
        if (rng_end) *rng_end = zcl_read_u16_le(body + 5);
        return true;
    }
    return false;
}

static bool fs_parse_serve_request_posix(const uint8_t *payload, uint32_t plen,
                            bool *is_all, bool *is_rng,
                            const uint8_t **puzzle,
                            uint16_t *rng_start, uint16_t *rng_end)
{
    fs_parse_serve_reset(is_all, is_rng, puzzle, rng_start, rng_end);
    if (!payload) return false;

    const uint8_t *body = payload;
    uint32_t blen = plen;
    /* A gated request carries a 48-byte solution prefix. Detect it by total
     * length: gated ALL is 51 bytes, gated RNG is 56 bytes. */
    if (plen >= FS_POW_SOLUTION_SIZE + 3) {
        body = payload + FS_POW_SOLUTION_SIZE;
        blen = plen - FS_POW_SOLUTION_SIZE;
        if (puzzle) *puzzle = payload;
    }

    if (fs_parse_serve_classify(body, blen, is_all, is_rng, rng_start,
                                rng_end))
        return true;
    /* Not a large-serve request (e.g., no puzzle prefix present). Retry the
     * ungated interpretation so a pre-puzzle probe still classifies. */
    if (puzzle) *puzzle = NULL;
    return fs_parse_serve_classify(payload, plen, is_all, is_rng, rng_start,
                                   rng_end);
}

static enum fs_admit_result fs_admit_serve_pow_posix(const uint8_t *puzzle,
                                        const uint8_t peer_token[32],
                                        uint8_t out_seed[32], int *out_bits,
                                        int64_t *out_server_time)
{
    /* No puzzle → hand back a fresh challenge (graceful, not a drop). */
    if (!puzzle || !peer_token) {
        puzzle_gate_challenge(&g_fs_pow_gate, out_seed, out_bits,
                                     out_server_time);
        return FS_ADMIT_CHALLENGE;
    }

    /* Solution layout: [token(32)][ts(8, LE)][nonce(8, LE)]. The token must
     * match the handshake nonce so a solution can't be replayed onto another
     * connection. */
    uint8_t tok[32];
    int64_t ts = 0;
    uint64_t nonce = 0;
    memcpy(tok, puzzle, 32);
    ts = zcl_read_i64_le(puzzle + 32);
    nonce = zcl_read_u64_le(puzzle + 40);

    bool bound = memcmp(tok, peer_token, 32) == 0;
    if (bound && puzzle_gate_verify(&g_fs_pow_gate, tok, ts, nonce))
        return FS_ADMIT_SERVE;

    puzzle_gate_challenge(&g_fs_pow_gate, out_seed, out_bits,
                                 out_server_time);
    return FS_ADMIT_CHALLENGE;
}

/* Build the FS_CHALLENGE frame payload the server hands to a client. */
static void fs_build_challenge_payload(const uint8_t seed[32], int bits,
                                       int64_t server_time,
                                       uint8_t out[FS_CHALLENGE_PAYLOAD_SIZE])
{
    memcpy(out, seed, 32);
    out[32] = (uint8_t)(bits < 0 ? 0 : (bits > 255 ? 255 : bits));
    zcl_write_u64_le(out + 33, (uint64_t)server_time);
}
/* Bounded logging for the admission gate: the invalid-puzzle / refusal paths
 * are exactly what a flood hammers, so throttle to at most one line per 5 s so
 * an attacker can't turn the defense into a log-flood amplifier. */
static _Atomic int64_t g_fs_gate_log_ts = 0;
void fs_gate_log_throttled(const char *event, int detail)
{
    int64_t now = (int64_t)platform_time_wall_time_t();
    int64_t prev = atomic_load(&g_fs_gate_log_ts);
    if (now - prev < 5)
        return;
    if (!atomic_compare_exchange_strong(&g_fs_gate_log_ts, &prev, now))
        return;
    log_jsonf(LOG_JSON_INFO, "file_service_pow_gate",
              "\"event\":\"%s\",\"detail\":%d", event, detail);
}

/* Send a fresh challenge frame to a requester (graceful retry, not a drop). */
static bool fs_send_challenge(struct fs_session *session,
                              const uint8_t seed[32], int bits,
                              int64_t server_time)
{
    uint8_t payload[FS_CHALLENGE_PAYLOAD_SIZE];
    fs_build_challenge_payload(seed, bits, server_time, payload);
    return fs_send_frame(session, FS_CHALLENGE, payload, sizeof(payload));
}
bool fs_client_budget_check(const struct fs_session *session)
{
    if (!fs_conn_budget_ok(session->bytes_sent,
                           session->start_monotonic_ms,
                           platform_time_monotonic_ms())) {
        fs_gate_log_throttled("connection_lifetime_exceeded", 0);
        return false;
    }
    return true;
}

bool fs_client_recv_checked(struct fs_session *session,
                                   uint8_t *type, const uint8_t **payload,
                                   uint32_t *plen, int64_t deadline_ms)
{
    if (!fs_recv_frame_until(session, type, payload, plen, deadline_ms))
        return false;
    return fs_client_budget_check(session);
}

bool fs_client_serve_challenge(struct fs_session *session)
{
    uint8_t seed[32];
    int bits = PUZZLE_MIN_BITS;
    int64_t st = 0;
    puzzle_gate_challenge(fs_pow_gate(), seed, &bits, &st);
    return fs_send_challenge(session, seed, bits, st);
}
static void fs_client_stream_admitted(struct fs_session *session,
                                      const struct file_manifest *manifest,
                                      const uint8_t client_ip[16],
                                      bool snapshot_allowed, bool is_rng,
                                      uint16_t rng_start, uint16_t rng_end)
{
    puzzle_gate_serve_begin(fs_pow_gate());
    if (is_rng) {
        uint32_t end = rng_end;
        if (end > manifest->num_chunks) end = manifest->num_chunks;
        fs_stream_range(session, manifest, rng_start, end,
                        client_ip, snapshot_allowed);
    } else { /* is_all */
        printf("file_service: streaming %u chunks (%.1f GB)...\n",
               manifest->num_chunks,
               (double)manifest->total_bytes / (1024.0*1024.0*1024.0));
        fs_stream_range(session, manifest, 0, manifest->num_chunks,
                        client_ip, snapshot_allowed);
        printf("file_service: streaming done (%.1f MB/s)\n",
               fs_session_mbps(session));
    }
    puzzle_gate_serve_end(fs_pow_gate());
    fs_ip_serve_release(client_ip);
}

bool fs_client_serve_gated(struct fs_session *session,
                                  const struct file_manifest *manifest,
                                  const uint8_t client_ip[16],
                                  bool snapshot_allowed, const uint8_t *puzzle,
                                  bool is_rng, uint16_t rng_start,
                                  uint16_t rng_end)
{
    /* ── PoW admission gate (mirrors snapsync_validate_serve_request
     * for the P2P path) — required BEFORE committing a worker to a
     * large stream. Missing/invalid/stale puzzle → challenge + retry,
     * never a silent drop. ─────────────────────────────────────── */
    uint8_t seed[32];
    int bits = PUZZLE_MIN_BITS;
    int64_t st = 0;
    enum fs_admit_result adm =
        fs_admit_serve_pow(puzzle, session->peer_nonce, seed, &bits, &st);
    if (adm == FS_ADMIT_CHALLENGE) {
        fs_gate_log_throttled("challenge_issued", bits);
        return fs_send_challenge(session, seed, bits, st);
    }

    /* Puzzle valid — enforce the per-IP concurrent-serve cap. */
    if (!fs_ip_serve_acquire(client_ip)) {
        fs_gate_log_throttled("ip_concurrency_refused", 0);
        return fs_send_frame(session, FS_DONE, NULL, 0);
    }

    fs_client_stream_admitted(session, manifest, client_ip, snapshot_allowed,
                              is_rng, rng_start, rng_end);
    return true;
}

bool fs_client_serve_manifest(struct fs_session *session,
                                     const struct file_manifest *manifest,
                                     bool snapshot_allowed)
{
    for (uint32_t i = 0; i < manifest->num_chunks; i++) {
        if (manifest->chunks[i].file_index == 254 &&
            !snapshot_allowed)
            continue;
        uint8_t entry[45]; /* sha3(32)+size(4)+file_idx(1)+offset(8) */
        memcpy(entry, manifest->chunks[i].sha3, 32);
        zcl_write_u32_le(entry + 32, manifest->chunks[i].size);
        entry[36] = manifest->chunks[i].file_index;
        zcl_write_u64_le(entry + 37, manifest->chunks[i].offset);
        if (!fs_send_frame(session, FS_MANIFEST, entry, 45))
            break;
    }
    return fs_send_frame(session, FS_DONE, NULL, 0);
}
#endif

void fs_pow_reset_state(void)
{
#if !defined(_WIN32)
    fs_pow_reset_state_posix();
#endif
}

bool fs_ip_serve_acquire(const uint8_t ip[16])
{
#if defined(_WIN32)
    (void)ip; return false;
#else
    return fs_ip_serve_acquire_posix(ip);
#endif
}

void fs_ip_serve_release(const uint8_t ip[16])
{
#if !defined(_WIN32)
    fs_ip_serve_release_posix(ip);
#else
    (void)ip;
#endif
}

bool fs_ip_bytes_charge(const uint8_t ip[16], uint64_t n)
{
#if defined(_WIN32)
    (void)ip; (void)n; return false;
#else
    return fs_ip_bytes_charge_posix(ip, n);
#endif
}

bool fs_conn_budget_ok(uint64_t bytes_sent, int64_t start_monotonic_ms,
                       int64_t now_monotonic_ms)
{
#if defined(_WIN32)
    return now_monotonic_ms >= start_monotonic_ms && bytes_sent <= FS_CONN_MAX_BYTES &&
        now_monotonic_ms - start_monotonic_ms <= FS_CONN_MAX_SECONDS * INT64_C(1000);
#else
    return fs_conn_budget_ok_posix(bytes_sent, start_monotonic_ms, now_monotonic_ms);
#endif
}

#if defined(_WIN32)
static uint32_t fs_win_serve_offset(const uint8_t *payload, uint32_t plen,
                                    const uint8_t **puzzle)
{
    if (plen >= FS_POW_SOLUTION_SIZE + 3 &&
        (memcmp(payload + FS_POW_SOLUTION_SIZE, "ALL", 3) == 0 ||
         memcmp(payload + FS_POW_SOLUTION_SIZE, "RNG", 3) == 0)) {
        if (puzzle) *puzzle = payload;
        return FS_POW_SOLUTION_SIZE;
    }
    return 0;
}

static bool fs_parse_serve_request_windows(const uint8_t *payload, uint32_t plen,
    bool *is_all, bool *is_rng, const uint8_t **puzzle,
    uint16_t *rng_start, uint16_t *rng_end)
{
    fs_parse_serve_reset(is_all, is_rng, puzzle, rng_start, rng_end);
    if (!payload) return false;
    uint32_t offset = fs_win_serve_offset(payload, plen, puzzle);
    if (plen == offset + 3 && memcmp(payload + offset, "ALL", 3) == 0) {
        if (is_all) *is_all = true;
        return true;
    }
    if (plen == offset + 7 && memcmp(payload + offset, "RNG", 3) == 0) {
        if (is_rng) *is_rng = true;
        if (rng_start) *rng_start = zcl_read_u16_le(payload + offset + 3);
        if (rng_end) *rng_end = zcl_read_u16_le(payload + offset + 5);
        return true;
    }
    return false;
}
#endif

bool fs_parse_serve_request(const uint8_t *payload, uint32_t plen,
                            bool *is_all, bool *is_rng,
                            const uint8_t **puzzle,
                            uint16_t *rng_start, uint16_t *rng_end)
{
#if defined(_WIN32)
    return fs_parse_serve_request_windows(payload, plen, is_all, is_rng,
                                          puzzle, rng_start, rng_end);
#else
    return fs_parse_serve_request_posix(payload, plen, is_all, is_rng, puzzle, rng_start, rng_end);
#endif
}

enum fs_admit_result fs_admit_serve_pow(const uint8_t *puzzle,
                                        const uint8_t peer_token[32],
                                        uint8_t out_seed[32], int *out_bits,
                                        int64_t *out_server_time)
{
#if defined(_WIN32)
    (void)puzzle; (void)peer_token; (void)out_seed; (void)out_bits; (void)out_server_time;
    return FS_ADMIT_REFUSED_CAP;
#else
    return fs_admit_serve_pow_posix(puzzle, peer_token, out_seed, out_bits, out_server_time);
#endif
}

static void fs_parse_serve_reset(bool *is_all, bool *is_rng,
                                 const uint8_t **puzzle,
                                 uint16_t *rng_start, uint16_t *rng_end)
{
    if (is_all) *is_all = false;
    if (is_rng) *is_rng = false;
    if (puzzle) *puzzle = NULL;
    if (rng_start) *rng_start = 0;
    if (rng_end) *rng_end = 0;
}
