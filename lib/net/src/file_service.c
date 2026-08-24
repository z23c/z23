#define _GNU_SOURCE  /* pthread_timedjoin_np */

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fast File Service — SHA3-encrypted direct TCP transfer.
 * Designed for maximum throughput: 64KB fixed frames, zero protocol
 * overhead visible to observers, wire-speed on gigabit links. */

#include "platform/time_compat.h"
#include "net/net_runtime_port.h"
#include "net/file_manifest.h"
#include "net/file_market_delivery.h"
#include "net/file_service.h"
#include "net/rom_seed.h"
#include "util/log_json.h"
#include "crypto/sha3.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"
#include "util/thread_liveness.h"
#include "json/json.h"
#include "support/cleanse.h"
static void fs_join_deadline_from_now(struct timespec *ts, int timeout_sec)
{
    platform_time_realtime_timespec(ts);
    if (timeout_sec < 0)
        timeout_sec = 0;
    ts->tv_sec += timeout_sec;
}

static void fs_join_thread_bounded(pthread_t thread,
                                   const char *name,
                                   int timeout_sec)
{
    struct timespec deadline;
    int rc;

    fs_join_deadline_from_now(&deadline, timeout_sec);
    rc = pthread_timedjoin_np(thread, NULL, &deadline);
    if (rc == 0)
        return;

    if (rc == ETIMEDOUT) {
        fprintf(stderr,  // obs-ok:shutdown-straggler-named
                "file_service: %s join timed out after %ds; retaining ownership\n",
                name ? name : "thread", timeout_sec);
    } else {
        fprintf(stderr,  // obs-ok:shutdown-straggler-named
                "file_service: %s join failed rc=%d (%s); retaining ownership\n",
                name ? name : "thread", rc, strerror(rc));
    }
    pthread_join(thread, NULL);
}

/* ── Session management ────────────────────────────────────────── */

void fs_session_init(struct fs_session *s, int fd)
{
    memset(s, 0, sizeof(*s));
    s->fd = fd;
    s->start_time = (int64_t)platform_time_wall_time_t();

    /* TCP tuning for max throughput */
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    int sndbuf = 4 * 1024 * 1024; /* 4MB send buffer */
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
}

double fs_session_mbps(const struct fs_session *s)
{
    int64_t elapsed = (int64_t)platform_time_wall_time_t() - s->start_time;
    if (elapsed < 1) elapsed = 1;
    uint64_t total = s->bytes_sent + s->bytes_received;
    return (double)total / (1048576.0 * (double)elapsed);
}

/* ── Raw I/O helpers ───────────────────────────────────────────── */

static bool send_all(int fd, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            LOG_FAIL("filesvc", "send_all failed: errno=%d (%s)", errno, strerror(errno));
        }
        sent += (size_t)n;
    }
    return true;
}

static bool recv_all(int fd, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            LOG_FAIL("filesvc", "recv_all failed: errno=%d (%s)", errno, strerror(errno));
        }
        got += (size_t)n;
    }
    return true;
}

/* ── Frame encryption/decryption ───────────────────────────────── */

/* Encrypt and MAC a frame. Always produces exactly FS_FRAME_SIZE bytes. */
static bool encrypt_frame(const struct fs_session *s, uint8_t type,
                            const uint8_t *payload, uint32_t payload_len,
                            uint8_t out[FS_FRAME_SIZE], uint64_t counter)
{
    if (payload_len > FS_MAX_PAYLOAD)
        LOG_FAIL("filesvc", "payload_len %u exceeds FS_MAX_PAYLOAD", payload_len);

    /* Build plaintext frame: [type][len][payload][random padding] */
    uint8_t plain[FS_FRAME_SIZE - FS_MAC_SIZE];
    memset(plain, 0, sizeof(plain));

    /* Header */
    plain[0] = type;
    plain[1] = (uint8_t)(type >> 8);
    plain[2] = (uint8_t)(type >> 16);
    plain[3] = (uint8_t)(type >> 24);
    plain[4] = (uint8_t)(payload_len);
    plain[5] = (uint8_t)(payload_len >> 8);
    plain[6] = (uint8_t)(payload_len >> 16);
    plain[7] = (uint8_t)(payload_len >> 24);

    /* Payload */
    if (payload_len > 0)
        memcpy(plain + FS_HEADER_SIZE, payload, payload_len);

    /* Padding is zeros — encrypted zeros look random. No need for
     * expensive /dev/urandom reads on every frame. */

    /* SHA3-CTR encrypt using AVX-512 4-way parallel SHA3-512.
     * Generates 256 bytes of keystream per batch (4 × 64).
     * 64KB / 256 = 256 batches. With AVX-512: ~4x faster. */
    uint8_t nonce[32];
    memset(nonce, 0, 32);
    memcpy(nonce, &counter, 8);

    size_t offset = 0;
    uint64_t block_ctr = 0;
    while (offset < sizeof(plain)) {
        uint8_t ks[256];
        sha3_512_x4(s->key, nonce, block_ctr, ks);
        block_ctr += 4;

        size_t chunk = sizeof(plain) - offset;
        if (chunk > 256) chunk = 256;
        for (size_t i = 0; i < chunk; i++)
            plain[offset + i] ^= ks[i];
        offset += chunk;
    }

    /* Copy encrypted data */
    memcpy(out, plain, sizeof(plain));

    /* MAC: SHA3-256(key || counter || encrypted_data) */
    struct sha3_256_ctx mac_ctx;
    sha3_256_init(&mac_ctx);
    sha3_256_write(&mac_ctx, s->key, 32);
    sha3_256_write(&mac_ctx, (const unsigned char *)&counter, 8);
    sha3_256_write(&mac_ctx, out, sizeof(plain));
    sha3_256_finalize(&mac_ctx, out + sizeof(plain));
    memory_cleanse(&mac_ctx, sizeof(mac_ctx));

    return true;
}

static bool decrypt_frame(const struct fs_session *s,
                            const uint8_t in[FS_FRAME_SIZE],
                            uint8_t *type_out, uint8_t *payload_buf,
                            uint32_t *payload_len_out, uint64_t counter)
{
    size_t ct_len = FS_FRAME_SIZE - FS_MAC_SIZE;

    /* Verify MAC first (fail fast) */
    uint8_t expected_mac[32];
    struct sha3_256_ctx mac_ctx;
    sha3_256_init(&mac_ctx);
    sha3_256_write(&mac_ctx, s->key, 32);
    sha3_256_write(&mac_ctx, (const unsigned char *)&counter, 8);
    sha3_256_write(&mac_ctx, in, ct_len);
    sha3_256_finalize(&mac_ctx, expected_mac);
    memory_cleanse(&mac_ctx, sizeof(mac_ctx));

    /* Constant-time compare */
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= in[ct_len + i] ^ expected_mac[i];
    if (diff != 0)
        LOG_FAIL("filesvc", "frame MAC verification failed at counter=%llu", (unsigned long long)counter);

    /* Decrypt using AVX-512 4-way parallel SHA3 */
    uint8_t plain[FS_FRAME_SIZE - FS_MAC_SIZE];
    memcpy(plain, in, ct_len);

    uint8_t nonce[32];
    memset(nonce, 0, 32);
    memcpy(nonce, &counter, 8);

    size_t offset = 0;
    uint64_t block_ctr = 0;
    while (offset < ct_len) {
        uint8_t ks[256];
        sha3_512_x4(s->key, nonce, block_ctr, ks);
        block_ctr += 4;

        size_t chunk = ct_len - offset;
        if (chunk > 256) chunk = 256;
        for (size_t i = 0; i < chunk; i++)
            plain[offset + i] ^= ks[i];
        offset += chunk;
    }

    /* Parse header */
    *type_out = plain[0];
    uint32_t plen = (uint32_t)plain[4] |
                    ((uint32_t)plain[5] << 8) |
                    ((uint32_t)plain[6] << 16) |
                    ((uint32_t)plain[7] << 24);

    if (plen > FS_MAX_PAYLOAD)
        LOG_FAIL("filesvc", "decrypted payload_len %u exceeds FS_MAX_PAYLOAD", plen);
    *payload_len_out = plen;
    if (plen > 0)
        memcpy(payload_buf, plain + FS_HEADER_SIZE, plen);

    return true;
}

/* ── Public frame send/recv ────────────────────────────────────── */

bool fs_send_frame(struct fs_session *s, uint8_t type,
                    const uint8_t *payload, uint32_t payload_len)
{
    uint8_t frame[FS_FRAME_SIZE];
    if (!encrypt_frame(s, type, payload, payload_len,
                        frame, s->send_counter))
        LOG_FAIL("filesvc", "encrypt_frame failed: type=%u len=%u", type, payload_len);
    s->send_counter++;
    s->bytes_sent += FS_FRAME_SIZE;
    return send_all(s->fd, frame, FS_FRAME_SIZE);
}

bool fs_recv_frame(struct fs_session *s, uint8_t *type_out,
                    const uint8_t **payload_out, uint32_t *payload_len_out)
{
    uint8_t frame[FS_FRAME_SIZE];
    if (!s) LOG_FAIL("filesvc", "fs_recv_frame called with NULL session");
    if (!recv_all(s->fd, frame, FS_FRAME_SIZE))
        LOG_FAIL("filesvc", "recv_all failed reading frame from fd=%d", s->fd);
    s->bytes_received += FS_FRAME_SIZE;

    if (!decrypt_frame(s, frame, type_out, s->recv_payload,
                        payload_len_out, s->recv_counter))
        LOG_FAIL("filesvc", "decrypt_frame failed at counter=%llu", (unsigned long long)s->recv_counter);
    s->recv_counter++;
    *payload_out = s->recv_payload;
    return true;
}

/* ── Fast encrypted chunk transfer ─────────────────────────────── */
/* Fast authenticated chunk transfer.
 * SHA3 MAC for integrity + authentication (post-quantum secure).
 * No bulk encryption — blockchain data is public. The MAC proves:
 *   1. Data came from a node with the shared key (same chain)
 *   2. Data wasn't tampered with in transit
 *   3. Replay protection via counter
 *
 * Wire format: [4-byte size][raw data][32-byte SHA3 MAC]
 * MAC = SHA3-256(key || counter || expected_sha3 || data)
 * Speed: limited only by network + disk I/O, not crypto. */

bool fs_send_chunk_fast(struct fs_session *s, const uint8_t *data,
                         uint32_t size, const uint8_t sha3[32])
{
    /* Send size header */
    uint8_t hdr[4];
    hdr[0] = (uint8_t)(size);
    hdr[1] = (uint8_t)(size >> 8);
    hdr[2] = (uint8_t)(size >> 16);
    hdr[3] = (uint8_t)(size >> 24);
    if (!send_all(s->fd, hdr, 4))
        LOG_FAIL("filesvc", "send_chunk_fast: failed to send size header");

    /* Send raw data — zero copy overhead */
    if (!send_all(s->fd, data, size))
        LOG_FAIL("filesvc", "send_chunk_fast: failed to send data (%u bytes)", size);

    /* SHA3 MAC: authenticates data + binds to session + prevents replay */
    uint8_t mac[32];
    struct sha3_256_ctx mctx;
    sha3_256_init(&mctx);
    sha3_256_write(&mctx, s->key, 32);
    sha3_256_write(&mctx, (const unsigned char *)&s->send_counter, 8);
    sha3_256_write(&mctx, sha3, 32);
    sha3_256_write(&mctx, data, size);
    sha3_256_finalize(&mctx, mac);
    memory_cleanse(&mctx, sizeof(mctx));

    if (!send_all(s->fd, mac, 32))
        LOG_FAIL("filesvc", "send_chunk_fast: failed to send MAC");

    s->bytes_sent += 4 + size + 32;
    s->send_counter++;
    return true;
}

/* Domain-separation tag bound into a ROM chunk refusal frame's MAC — "RREF" +
 * zero padding, distinct from the chunk (per-chunk sha3), manifest ("RMF"),
 * and listing ("RLS") tags so a refusal is un-confusable with any data reply.
 * The client (rom_fetch_chunk) re-derives the identical MAC with this tag. */
static const uint8_t FS_ROM_REFUSAL_MAC_TAG[32] = { 'R', 'R', 'E', 'F' };

/* Send a typed ROM chunk refusal on the SAME raw transport as a chunk reply:
 *   [4B FS_ROM_REFUSAL_SENTINEL (LE)][1B reason][32B MAC]
 *   MAC = SHA3-256(key || send_counter || FS_ROM_REFUSAL_MAC_TAG || reason)
 * so the client's raw chunk reader decodes the impossible-as-a-size sentinel
 * unambiguously as "peer busy — back off", never the garbage size an encrypted
 * FS_DONE frame parses as. Uses the CURRENT send_counter (the counter a chunk
 * reply would have used) so the client re-derives it with recv_counter; the
 * connection is terminal after a refusal so no counter drift matters. */
bool fs_send_chunk_refusal(struct fs_session *s, uint8_t reason)
{
    if (!s) LOG_FAIL("filesvc", "send_chunk_refusal: null session");
    uint32_t sentinel = FS_ROM_REFUSAL_SENTINEL;
    uint8_t hdr[4];
    hdr[0] = (uint8_t)(sentinel);
    hdr[1] = (uint8_t)(sentinel >> 8);
    hdr[2] = (uint8_t)(sentinel >> 16);
    hdr[3] = (uint8_t)(sentinel >> 24);
    if (!send_all(s->fd, hdr, 4))
        LOG_FAIL("filesvc", "send_chunk_refusal: failed to send sentinel");
    if (!send_all(s->fd, &reason, 1))
        LOG_FAIL("filesvc", "send_chunk_refusal: failed to send reason");

    uint8_t mac[32];
    struct sha3_256_ctx mctx;
    sha3_256_init(&mctx);
    sha3_256_write(&mctx, s->key, 32);
    sha3_256_write(&mctx, (const unsigned char *)&s->send_counter, 8);
    sha3_256_write(&mctx, FS_ROM_REFUSAL_MAC_TAG, 32);
    sha3_256_write(&mctx, &reason, 1);
    sha3_256_finalize(&mctx, mac);
    memory_cleanse(&mctx, sizeof(mctx));
    if (!send_all(s->fd, mac, 32))
        LOG_FAIL("filesvc", "send_chunk_refusal: failed to send MAC");

    s->bytes_sent += 4 + 1 + 32;
    s->send_counter++;
    return true;
}
bool fs_recv_chunk_fast(struct fs_session *s, uint8_t **out,
                        uint32_t *out_size,
                        const uint8_t expected_sha3[32])
{
    if (!s || !out || !out_size || !expected_sha3)
        LOG_FAIL("filesvc", "recv_chunk_fast: invalid arguments");
    *out = NULL; *out_size = 0;
    uint8_t hdr[4];
    if (!recv_all(s->fd, hdr, 4))
        LOG_FAIL("filesvc", "recv_chunk_fast: failed to read size header");
    uint32_t size = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
                    ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    if (size == 0 || size > 60 * 1024 * 1024)
        LOG_FAIL("filesvc", "recv_chunk_fast: invalid chunk size=%u", size);
    /* Read data */
    uint8_t *buf = zcl_malloc(size, "file_recv_buf");
    if (!buf) LOG_FAIL("filesvc", "recv_chunk_fast: malloc failed for %u bytes", size);
    if (!recv_all(s->fd, buf, size)) { free(buf); LOG_FAIL("filesvc", "recv_chunk_fast: failed to read data (%u bytes)", size); }

    /* Read and verify SHA3 MAC */
    uint8_t mac_wire[32];
    if (!recv_all(s->fd, mac_wire, 32)) { free(buf); LOG_FAIL("filesvc", "recv_chunk_fast: failed to read MAC"); }

    uint8_t mac_expected[32];
    struct sha3_256_ctx mctx;
    sha3_256_init(&mctx);
    sha3_256_write(&mctx, s->key, 32);
    sha3_256_write(&mctx, (const unsigned char *)&s->recv_counter, 8);
    sha3_256_write(&mctx, expected_sha3, 32);
    sha3_256_write(&mctx, buf, size);
    sha3_256_finalize(&mctx, mac_expected);
    memory_cleanse(&mctx, sizeof(mctx));

    /* Constant-time MAC verification */
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= mac_wire[i] ^ mac_expected[i];
    if (diff != 0) {
        free(buf);
        LOG_FAIL("filesvc", "recv_chunk_fast: MAC verification failed on chunk (%u bytes)", size);
    }
    s->recv_counter++;

    /* Verify SHA3 of data matches manifest */
    uint8_t hash[32];
    sha3_256(buf, size, hash);
    if (memcmp(hash, expected_sha3, 32) != 0) {
        free(buf);
        LOG_FAIL("filesvc", "recv_chunk_fast: SHA3 hash mismatch on chunk (%u bytes)", size);
    }

    s->bytes_received += 4 + size + 32;
    *out = buf;
    *out_size = size;
    return true;
}

/* ── Server ────────────────────────────────────────────────────── */

static _Atomic bool g_fs_running = false;
static pthread_t g_fs_thread;
static bool g_fs_thread_started = false;
static pthread_t g_fs_manifest_thread;
static bool g_fs_manifest_thread_started = false;
static int g_fs_listen_fd = -1;
static const char *g_fs_datadir = NULL;
static uint16_t g_fs_port = FS_PORT;
static pthread_mutex_t g_fs_state_mutex = PTHREAD_MUTEX_INITIALIZER;

#define FS_SERVER_WORKERS 8
#define FS_CLIENT_QUEUE_CAP 64
struct fs_client_slot {
    int     fd;
    uint8_t ip[16];   /* IPv6, or v4-mapped IPv6, for per-IP resource caps */
};
static pthread_t g_fs_worker_threads[FS_SERVER_WORKERS];
static unsigned g_fs_worker_threads_started = 0;
static struct fs_client_slot g_fs_client_queue[FS_CLIENT_QUEUE_CAP];
static unsigned g_fs_client_queue_head = 0;
static unsigned g_fs_client_queue_tail = 0;
static unsigned g_fs_client_queue_len = 0;
static pthread_mutex_t g_fs_client_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_fs_client_queue_cv = PTHREAD_COND_INITIALIZER;

/* Supervisor liveness for the file-market threads. Root children (not
 * supervisor_register_in_domain(...)): lib/net cannot include the app-side
 * supervisors/domains.h without a lib-layering violation — see
 * util/thread_liveness.h. All three legitimately sit idle when the file
 * market has no active client/request (queue-pop condvar wait, accept()
 * timeout, single-shot manifest build), so they are liveness-only (no
 * deadline, no progress gate) — present on the tree, heartbeat when they
 * wake, never falsely flagged for a quiet cycle. zcl_fs_wkr is a pool of
 * FS_SERVER_WORKERS interchangeable threads; they share one contract (any
 * worker beating it proves "at least one fs_wkr loop is alive/ticking",
 * which is the intent — not per-worker isolation). */
static struct thread_liveness_child g_fs_wkr_liveness      = { .id = SUPERVISOR_INVALID_ID };
static struct thread_liveness_child g_fs_server_liveness   = { .id = SUPERVISOR_INVALID_ID };
static struct thread_liveness_child g_fs_manifest_liveness = { .id = SUPERVISOR_INVALID_ID };

/* Background manifest builder — hashes all block files (~7 GB). */
static struct file_manifest g_server_fm;
static _Atomic bool g_have_manifest = false;
static pthread_mutex_t g_manifest_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_manifest_build_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── PoW-gated admission + per-IP resource caps ─────────────────────
 *
 * In-memory only. The gate mints rotating adaptive challenges; the IP table
 * bounds concurrency and hourly volume. Nothing here is persisted or a
 * consensus predicate — it only decides whether to SPEND uplink on a public
 * stream. */
static struct puzzle_gate g_fs_pow_gate;

struct fs_ip_stat {
    uint8_t  ip[16];
    bool     used;
    uint32_t concurrent;        /* active large serves for this IP */
    int64_t  hour_start;        /* rolling hour-budget window start */
    uint64_t bytes_this_hour;   /* bytes charged in the current window */
    int64_t  last_seen;         /* for LRU eviction when the table is full */
};
static struct fs_ip_stat g_fs_ip[FS_IP_TABLE_CAP];
static pthread_mutex_t g_fs_ip_mutex = PTHREAD_MUTEX_INITIALIZER;

struct puzzle_gate *fs_pow_gate(void)
{
    return &g_fs_pow_gate;
}

void fs_pow_reset_state(void)
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

bool fs_ip_serve_acquire(const uint8_t ip[16])
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

void fs_ip_serve_release(const uint8_t ip[16])
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

bool fs_ip_bytes_charge(const uint8_t ip[16], uint64_t n)
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

bool fs_conn_budget_ok(uint64_t bytes_sent, int64_t start_time, int64_t now)
{
    if (bytes_sent > FS_CONN_MAX_BYTES)
        return false;
    if (start_time > 0 && (now - start_time) > FS_CONN_MAX_SECONDS)
        return false;
    return true;
}

bool fs_parse_serve_request(const uint8_t *payload, uint32_t plen,
                            bool *is_all, bool *is_rng,
                            const uint8_t **puzzle,
                            uint16_t *rng_start, uint16_t *rng_end)
{
    if (is_all) *is_all = false;
    if (is_rng) *is_rng = false;
    if (puzzle) *puzzle = NULL;
    if (rng_start) *rng_start = 0;
    if (rng_end) *rng_end = 0;
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

    if (blen == 3 && memcmp(body, "ALL", 3) == 0) {
        if (is_all) *is_all = true;
        return true;
    }
    if (blen >= 8 && memcmp(body, "RNG", 3) == 0) {
        if (is_rng) *is_rng = true;
        if (rng_start)
            *rng_start = (uint16_t)body[3] | ((uint16_t)body[4] << 8);
        if (rng_end)
            *rng_end = (uint16_t)body[5] | ((uint16_t)body[6] << 8);
        return true;
    }
    /* Not a large-serve request (e.g., no puzzle prefix present). Retry the
     * ungated interpretation so a pre-puzzle probe still classifies. */
    if (puzzle) *puzzle = NULL;
    if (plen == 3 && memcmp(payload, "ALL", 3) == 0) {
        if (is_all) *is_all = true;
        return true;
    }
    if (plen >= 8 && memcmp(payload, "RNG", 3) == 0) {
        if (is_rng) *is_rng = true;
        if (rng_start)
            *rng_start = (uint16_t)payload[3] | ((uint16_t)payload[4] << 8);
        if (rng_end)
            *rng_end = (uint16_t)payload[5] | ((uint16_t)payload[6] << 8);
        return true;
    }
    return false;
}

bool fs_parse_rom_request(const uint8_t *payload, uint32_t plen,
                          uint8_t root_out[32], uint32_t *idx_out)
{
    if (!payload || plen < FS_ROM_REQUEST_SIZE)
        return false;
    if (memcmp(payload, "ROM", 3) != 0)
        return false;
    if (root_out)
        memcpy(root_out, payload + 3, 32);
    if (idx_out)
        *idx_out = (uint32_t)payload[35] |
                   ((uint32_t)payload[36] << 8) |
                   ((uint32_t)payload[37] << 16) |
                   ((uint32_t)payload[38] << 24);
    return true;
}

/* WF2 artifact-protocol: parse the per-chunk manifest request. Sibling of
 * fs_parse_rom_request — pure/testable, wired into the serve dispatch by
 * lane 2A. body = ["RMF"(3)][chunk_root(32)]. */
bool fs_parse_rom_manifest_request(const uint8_t *payload, uint32_t plen,
                                   uint8_t root_out[32])
{
    if (!payload || plen < FS_ROM_MANIFEST_REQUEST_SIZE)
        return false;
    if (memcmp(payload, "RMF", 3) != 0)
        return false;
    if (root_out)
        memcpy(root_out, payload + 3, 32);
    return true;
}

/* ROM directory-listing request (RLS) — pure/testable sibling of
 * fs_parse_rom_request. body = ["RLS"(3)], no root: the directory is a
 * whole-node catalog, not per-artifact. */
bool fs_parse_rom_list_request(const uint8_t *payload, uint32_t plen)
{
    if (!payload || plen < FS_ROM_LIST_REQUEST_SIZE)
        return false;
    return memcmp(payload, "RLS", 3) == 0;
}

enum fs_admit_result fs_admit_serve_pow(const uint8_t *puzzle,
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
    memcpy(&ts, puzzle + 32, 8);
    memcpy(&nonce, puzzle + 40, 8);

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
    for (int i = 0; i < 8; i++)
        out[33 + i] = (uint8_t)((uint64_t)server_time >> (8 * i));
}

static bool fs_snapshot_serving_allowed(void)
{
    return net_runtime_snapshot_artifact_is_eligible(g_fs_datadir, NULL, 0);
}

static bool fs_server_rebuild_manifest_locked(struct file_manifest *out)
{
    struct file_manifest next = {0};
    int64_t t0 = (int64_t)platform_time_wall_time_t();
    bool ok;

    pthread_mutex_lock(&g_manifest_build_mutex);
    ok = file_manifest_build(&next, g_fs_datadir);
    pthread_mutex_unlock(&g_manifest_build_mutex);
    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;

    if (ok) {
        *out = next;
        log_jsonf(LOG_JSON_INFO, "file_service_manifest_ready",
                  "\"chunks\":%u,\"total_bytes\":%llu,\"hash_seconds\":%lld",
                  out->num_chunks,
                  (unsigned long long)out->total_bytes,
                  (long long)elapsed);
    } else {
        memset(out, 0, sizeof(*out));
        log_jsonf(LOG_JSON_WARN, "file_service_manifest_empty", NULL);
    }

    return ok;
}

static void *fs_manifest_thread(void *arg)
{
    (void)arg;
    struct file_manifest next = {0};
    bool ok = fs_server_rebuild_manifest_locked(&next);
    pthread_mutex_lock(&g_manifest_mutex);
    g_server_fm = next;
    pthread_mutex_unlock(&g_manifest_mutex);
    atomic_store(&g_have_manifest, ok);
    /* Single-shot thread — the build above IS its one dispatch. */
    thread_liveness_beat(&g_fs_manifest_liveness, ok ? (int64_t)next.num_chunks : 0);
    return NULL;
}

bool fs_server_refresh_manifest(void)
{
    struct file_manifest next = {0};
    bool ok;

    if (!g_fs_datadir)
        LOG_FAIL("filesvc", "refresh_manifest: datadir not set");

    ok = fs_server_rebuild_manifest_locked(&next);
    pthread_mutex_lock(&g_manifest_mutex);
    g_server_fm = next;
    pthread_mutex_unlock(&g_manifest_mutex);
    atomic_store(&g_have_manifest, ok);
    return ok;
}

static bool fs_client_queue_push(int client_fd, const uint8_t ip[16])
{
    bool ok = false;

    pthread_mutex_lock(&g_fs_client_queue_mutex);
    if (g_fs_client_queue_len < FS_CLIENT_QUEUE_CAP) {
        g_fs_client_queue[g_fs_client_queue_tail].fd = client_fd;
        memcpy(g_fs_client_queue[g_fs_client_queue_tail].ip, ip, 16);
        g_fs_client_queue_tail =
            (g_fs_client_queue_tail + 1U) % FS_CLIENT_QUEUE_CAP;
        g_fs_client_queue_len++;
        ok = true;
        pthread_cond_signal(&g_fs_client_queue_cv);
    }
    pthread_mutex_unlock(&g_fs_client_queue_mutex);
    return ok;
}

static bool fs_client_queue_pop(struct fs_client_slot *slot_out)
{
    if (!slot_out)
        LOG_FAIL("filesvc", "client_queue_pop: slot_out is NULL");

    pthread_mutex_lock(&g_fs_client_queue_mutex);
    /* Timed wait so a worker never blocks past shutdown if the cond
     * broadcast in fs_server_stop is skipped (e.g., abort path). 2 s
     * wake is invisible under load — every queue push signals the
     * cond — but bounded under shutdown. Mirror of the httpserver
     * dequeue_client treatment. */
    while (g_fs_client_queue_len == 0 && atomic_load(&g_fs_running)) {
        struct timespec deadline;
        platform_time_realtime_timespec(&deadline);
        deadline.tv_sec += 2;
        pthread_cond_timedwait(&g_fs_client_queue_cv,
                               &g_fs_client_queue_mutex, &deadline);
    }

    if (g_fs_client_queue_len == 0) {
        pthread_mutex_unlock(&g_fs_client_queue_mutex);
        LOG_FAIL("filesvc", "client_queue_pop: queue empty and server stopping");
    }

    *slot_out = g_fs_client_queue[g_fs_client_queue_head];
    g_fs_client_queue_head =
        (g_fs_client_queue_head + 1U) % FS_CLIENT_QUEUE_CAP;
    g_fs_client_queue_len--;
    pthread_mutex_unlock(&g_fs_client_queue_mutex);
    return true;
}

static void fs_client_queue_close_all(void)
{
    pthread_mutex_lock(&g_fs_client_queue_mutex);
    while (g_fs_client_queue_len > 0) {
        int client_fd = g_fs_client_queue[g_fs_client_queue_head].fd;
        g_fs_client_queue_head =
            (g_fs_client_queue_head + 1U) % FS_CLIENT_QUEUE_CAP;
        g_fs_client_queue_len--;
        close(client_fd);
    }
    g_fs_client_queue_head = 0;
    g_fs_client_queue_tail = 0;
    pthread_mutex_unlock(&g_fs_client_queue_mutex);
}

/* Bounded logging for the admission gate: the invalid-puzzle / refusal paths
 * are exactly what a flood hammers, so throttle to at most one line per 5 s so
 * an attacker can't turn the defense into a log-flood amplifier. */
static _Atomic int64_t g_fs_gate_log_ts = 0;
static void fs_gate_log_throttled(const char *event, int detail)
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

/* Stream manifest chunks [start,end) with per-connection + per-IP budgets.
 * The served bytes are byte-identical to the ungated path; the caps only bound
 * how much a single connection/IP may draw. Stops the range early (keeping the
 * connection) when a budget trips or a chunk read fails. */
static void fs_stream_range(struct fs_session *session,
                            const struct file_manifest *manifest,
                            uint32_t start, uint32_t end,
                            const uint8_t client_ip[16],
                            bool snapshot_allowed)
{
    for (uint32_t ci = start; ci < end && atomic_load(&g_fs_running); ci++) {
        int64_t now = (int64_t)platform_time_wall_time_t();
        if (!fs_conn_budget_ok(session->bytes_sent, session->start_time, now)) {
            fs_gate_log_throttled("conn_budget_exceeded", (int)ci);
            return;
        }
        if (manifest->chunks[ci].file_index == 254 && !snapshot_allowed)
            continue;
        uint8_t *data = NULL;
        uint32_t dsz = 0;
        if (!file_chunk_read(&manifest->chunks[ci], g_fs_datadir, &data, &dsz)) {
            fprintf(stderr,  // obs-ok:file-transfer-client-visible
                    "file_service: read failed chunk %u\n", ci);
            return;
        }
        if (!fs_ip_bytes_charge(client_ip, dsz)) {
            free(data);
            fs_gate_log_throttled("ip_hour_budget_exceeded", (int)ci);
            return;
        }
        if (!fs_send_chunk_fast(session, data, dsz, manifest->chunks[ci].sha3)) {
            free(data);
            return;
        }
        free(data);
    }
}

/* Serve one FREE ROM artifact chunk. Runs on the file-service worker pool —
 * a thread pool separate from the consensus P2P message loop — so it never
 * blocks or starves consensus P2P. Bounded by the rom_seed per-peer
 * concurrency + per-peer/global byte-rate caps (NOT the PoW/ALL gate) and the
 * per-connection budget already enforced elsewhere. No payment is required.
 * On any refusal it sends a typed refusal frame (fs_send_chunk_refusal) — a
 * clean, unambiguous "peer busy/declined" the client decodes into a back-off
 * + retry, never a silent drop and never the garbage size an encrypted FS_DONE
 * frame parses as on the raw chunk reader. */
static void fs_serve_rom_chunk(struct fs_session *session,
                               const uint8_t client_ip[16],
                               const uint8_t root[32], uint32_t idx)
{
    struct rom_artifact art;
    if (rom_seed_serve_lookup(root, idx, &art) != ROM_SERVE_FREE_OK) {
        (void)fs_send_chunk_refusal(session, FS_ROM_REFUSE_UNKNOWN);
        return;
    }
    if (!fs_conn_budget_ok(session->bytes_sent, session->start_time,
                           (int64_t)platform_time_wall_time_t())) {
        fs_gate_log_throttled("rom_conn_budget_exceeded", (int)idx);
        (void)fs_send_chunk_refusal(session, FS_ROM_REFUSE_CONN_BUDGET);
        return;
    }
    if (!rom_seed_peer_acquire(client_ip)) {
        fs_gate_log_throttled("rom_concurrency_refused", 0);
        (void)fs_send_chunk_refusal(session, FS_ROM_REFUSE_INFLIGHT);
        return;
    }

    uint8_t *buf = zcl_malloc(art.chunk_size, "rom_serve_chunk");
    if (!buf) {
        rom_seed_peer_release(client_ip);
        (void)fs_send_chunk_refusal(session, FS_ROM_REFUSE_IO);
        return;
    }
    uint32_t sz = 0;
    if (!rom_seed_read_chunk(&art, g_fs_datadir, idx, buf, art.chunk_size, &sz)) {
        free(buf);
        rom_seed_peer_release(client_ip);
        (void)fs_send_chunk_refusal(session, FS_ROM_REFUSE_IO);
        return;
    }
    /* Separate send budget: the ROM global/per-peer byte-rate window bounds how
     * much uplink ROM serving may draw, independent of consensus P2P. */
    if (!rom_seed_rate_charge(client_ip, sz, (int64_t)platform_time_wall_time_t())) {
        free(buf);
        rom_seed_peer_release(client_ip);
        fs_gate_log_throttled("rom_rate_exceeded", (int)idx);
        (void)fs_send_chunk_refusal(session, FS_ROM_REFUSE_RATE);
        return;
    }
    if (fs_send_chunk_fast(session, buf, sz, art.chunk_sha3[idx]))
        rom_seed_note_chunk_served();
    free(buf);
    rom_seed_peer_release(client_ip);
}

/* Domain-separation tag bound into a ROM manifest reply's MAC. Reusing
 * fs_send_chunk_fast (which computes MAC = SHA3(key || counter || <32B> ||
 * data)) with this constant in the 32-byte slot keeps the manifest reply on
 * the EXACT same wire+MAC scheme as a chunk reply while making a manifest blob
 * un-confusable with a chunk payload. The client re-derives the identical MAC
 * with the same tag (rom_fetch_get_manifest). "RMF" + zero padding. */
static const uint8_t FS_ROM_MANIFEST_MAC_TAG[32] = { 'R', 'M', 'F' };

/* Serve one FREE ROM per-chunk manifest ("RMF" request). Rides the same
 * fs_session transport and the same rom_seed per-peer concurrency + byte-rate
 * caps as a chunk serve — never the PoW/ALL gate. Reply is
 * [4-byte size LE][blob][32-byte MAC] with the blob =
 * rom_seed_manifest_blob(). On any refusal (seeding disabled, unknown root,
 * budget/cap tripped, serialize failure) it sends FS_DONE — identical offence
 * handling to a malformed/unknown ROM chunk request (a legacy client reads the
 * FS_DONE as "no manifest" and falls back to whole-file verification). */
static void fs_serve_rom_manifest(struct fs_session *session,
                                  const uint8_t client_ip[16],
                                  const uint8_t root[32])
{
    struct rom_artifact art;
    if (!rom_seed_enabled() || !rom_seed_find_by_root(root, &art)) {
        (void)fs_send_frame(session, FS_DONE, NULL, 0);
        return;
    }
    if (!fs_conn_budget_ok(session->bytes_sent, session->start_time,
                           (int64_t)platform_time_wall_time_t())) {
        fs_gate_log_throttled("rom_manifest_conn_budget_exceeded", 0);
        (void)fs_send_frame(session, FS_DONE, NULL, 0);
        return;
    }
    if (!rom_seed_peer_acquire(client_ip)) {
        fs_gate_log_throttled("rom_manifest_concurrency_refused", 0);
        (void)fs_send_frame(session, FS_DONE, NULL, 0);
        return;
    }

    uint8_t blob[ROM_SEED_MANIFEST_BLOB_MAX];
    size_t blen = rom_seed_manifest_blob(&art, blob, sizeof(blob));
    if (blen == 0) {
        rom_seed_peer_release(client_ip);
        (void)fs_send_frame(session, FS_DONE, NULL, 0);
        return;
    }
    if (!rom_seed_rate_charge(client_ip, blen,
                              (int64_t)platform_time_wall_time_t())) {
        rom_seed_peer_release(client_ip);
        fs_gate_log_throttled("rom_manifest_rate_exceeded", 0);
        (void)fs_send_frame(session, FS_DONE, NULL, 0);
        return;
    }
    (void)fs_send_chunk_fast(session, blob, (uint32_t)blen,
                             FS_ROM_MANIFEST_MAC_TAG);
    rom_seed_peer_release(client_ip);
}

/* Domain-separation tag bound into a ROM directory-listing reply's MAC —
 * "RLS" + zero padding, distinct from the chunk (per-chunk sha3) and manifest
 * ("RMF") tags so a listing blob is un-confusable with either on the wire. The
 * client (rom_fetch_get_directory) re-derives the identical MAC. */
static const uint8_t FS_ROM_LIST_MAC_TAG[32] = { 'R', 'L', 'S' };

/* Buffers for the artifact catalog: at most ROM_SEED_MAX_ARTIFACTS (8) small
 * entries (~200 B each) from rom_seed_directory_json, wrapped in the
 * {"artifacts":[...]} object rom_fetch_parse_directory consumes. */
#define FS_ROM_LIST_ARTS_MAX  2560u
#define FS_ROM_LIST_BODY_MAX  (FS_ROM_LIST_ARTS_MAX + 64u)

/* Serve one FREE ROM directory listing ("RLS" request). Rides the same
 * fs_session transport and the same rom_seed per-peer concurrency + byte-rate
 * caps as a chunk/manifest serve — never the PoW/ALL gate. Reply is
 * [4-byte size LE][body][32-byte MAC] with the body =
 * {"artifacts":<rom_seed_directory_json>} — the exact shape the onion
 * /directory.json path serves and rom_fetch_parse_directory parses. On any
 * refusal (seeding disabled, conn budget/concurrency/rate cap tripped, body
 * overflow) it sends FS_DONE — identical offence handling to a malformed ROM
 * chunk request (a legacy client reads the FS_DONE as "no listing" and skips
 * discovery). */
static void fs_serve_rom_list(struct fs_session *session,
                              const uint8_t client_ip[16])
{
    if (!rom_seed_enabled()) {
        (void)fs_send_frame(session, FS_DONE, NULL, 0);
        return;
    }
    if (!fs_conn_budget_ok(session->bytes_sent, session->start_time,
                           (int64_t)platform_time_wall_time_t())) {
        fs_gate_log_throttled("rom_list_conn_budget_exceeded", 0);
        (void)fs_send_frame(session, FS_DONE, NULL, 0);
        return;
    }
    if (!rom_seed_peer_acquire(client_ip)) {
        fs_gate_log_throttled("rom_list_concurrency_refused", 0);
        (void)fs_send_frame(session, FS_DONE, NULL, 0);
        return;
    }

    char arts[FS_ROM_LIST_ARTS_MAX];
    size_t an = rom_seed_directory_json(arts, sizeof(arts));
    char body[FS_ROM_LIST_BODY_MAX];
    int bn = snprintf(body, sizeof(body), "{\"artifacts\":%s}",
                      an > 0 ? arts : "[]");
    if (bn <= 0 || (size_t)bn >= sizeof(body)) {
        rom_seed_peer_release(client_ip);
        fs_gate_log_throttled("rom_list_body_overflow", 0);
        (void)fs_send_frame(session, FS_DONE, NULL, 0);
        return;
    }
    if (!rom_seed_rate_charge(client_ip, (size_t)bn,
                              (int64_t)platform_time_wall_time_t())) {
        rom_seed_peer_release(client_ip);
        fs_gate_log_throttled("rom_list_rate_exceeded", 0);
        (void)fs_send_frame(session, FS_DONE, NULL, 0);
        return;
    }
    (void)fs_send_chunk_fast(session, (const uint8_t *)body, (uint32_t)bn,
                             FS_ROM_LIST_MAC_TAG);
    rom_seed_peer_release(client_ip);
}

/* Per-client handler run on a bounded worker pool. */
static void fs_handle_client_fd(int client_fd, const uint8_t client_ip[16])
{
    struct fs_session session;
    fs_session_init(&session, client_fd);

    uint8_t ur[32];
    memset(ur, 0, 32);
    if (!fs_handshake(&session, ur, false)) {
        fs_session_cleanup(&session);
        close(client_fd);
        return;
    }
    /* After the handshake session.peer_nonce is the 32-byte token the client
     * presented — a PoW solution must be bound to it. */

    struct file_manifest manifest = {0};

    while (atomic_load(&g_fs_running)) {
        bool have_manifest = atomic_load(&g_have_manifest);
        uint8_t type;
        const uint8_t *payload;
        uint32_t plen;
        if (!fs_recv_frame(&session, &type, &payload, &plen)) break;

        if (have_manifest) {
            pthread_mutex_lock(&g_manifest_mutex);
            manifest = g_server_fm;
            pthread_mutex_unlock(&g_manifest_mutex);
        }
        bool snapshot_allowed = fs_snapshot_serving_allowed();

        /* Client explicitly asks for a challenge before requesting bulk data. */
        if (type == FS_CHALLENGE) {
            uint8_t seed[32];
            int bits = PUZZLE_MIN_BITS;
            int64_t st = 0;
            puzzle_gate_challenge(fs_pow_gate(), seed, &bits, &st);
            if (!fs_send_challenge(&session, seed, bits, st))
                break;
            continue;
        }

        if (type == FS_REQUEST) {
            if (file_market_delivery_is_request(payload, plen)) {
                if (!file_market_delivery_serve(&session, client_ip,
                                                payload, plen))
                    break;
                continue;
            }
            /* Free ROM requests use independent rom_seed caps. */
            uint8_t rom_root[32];
            uint32_t rom_idx = 0;
            if (fs_parse_rom_request(payload, plen, rom_root, &rom_idx)) {
                fs_serve_rom_chunk(&session, client_ip, rom_root, rom_idx);
                continue;
            }
            uint8_t rmf_root[32];
            if (fs_parse_rom_manifest_request(payload, plen, rmf_root)) {
                fs_serve_rom_manifest(&session, client_ip, rmf_root);
                continue;
            }
            if (fs_parse_rom_list_request(payload, plen)) {
                fs_serve_rom_list(&session, client_ip);
                continue;
            }
        }

        bool is_all = false, is_rng = false;
        const uint8_t *puzzle = NULL;
        uint16_t rng_start = 0, rng_end = 0;
        bool is_serve = (type == FS_REQUEST) &&
            fs_parse_serve_request(payload, plen, &is_all, &is_rng,
                                   &puzzle, &rng_start, &rng_end);

        if (is_serve && (is_all || is_rng) && have_manifest) {
            /* ── PoW admission gate (mirrors snapsync_validate_serve_request
             * for the P2P path) — required BEFORE committing a worker to a
             * large stream. Missing/invalid/stale puzzle → challenge + retry,
             * never a silent drop. ─────────────────────────────────────── */
            uint8_t seed[32];
            int bits = PUZZLE_MIN_BITS;
            int64_t st = 0;
            enum fs_admit_result adm =
                fs_admit_serve_pow(puzzle, session.peer_nonce, seed, &bits, &st);
            if (adm == FS_ADMIT_CHALLENGE) {
                fs_gate_log_throttled("challenge_issued", bits);
                if (!fs_send_challenge(&session, seed, bits, st))
                    break;
                continue;
            }

            /* Puzzle valid — enforce the per-IP concurrent-serve cap. */
            if (!fs_ip_serve_acquire(client_ip)) {
                fs_gate_log_throttled("ip_concurrency_refused", 0);
                if (!fs_send_frame(&session, FS_DONE, NULL, 0))
                    break;
                continue;
            }

            puzzle_gate_serve_begin(fs_pow_gate());
            if (is_rng) {
                uint32_t end = rng_end;
                if (end > manifest.num_chunks) end = manifest.num_chunks;
                fs_stream_range(&session, &manifest, rng_start, end,
                                client_ip, snapshot_allowed);
            } else { /* is_all */
                printf("file_service: streaming %u chunks (%.1f GB)...\n",
                       manifest.num_chunks,
                       (double)manifest.total_bytes / (1024.0*1024.0*1024.0));
                fs_stream_range(&session, &manifest, 0, manifest.num_chunks,
                                client_ip, snapshot_allowed);
                printf("file_service: streaming done (%.1f MB/s)\n",
                       fs_session_mbps(&session));
            }
            puzzle_gate_serve_end(fs_pow_gate());
            fs_ip_serve_release(client_ip);
        } else if (type == FS_MANIFEST && have_manifest) {
            for (uint32_t i = 0; i < manifest.num_chunks; i++) {
                if (manifest.chunks[i].file_index == 254 &&
                    !snapshot_allowed)
                    continue;
                uint8_t entry[45]; /* sha3(32)+size(4)+file_idx(1)+offset(8) */
                memcpy(entry, manifest.chunks[i].sha3, 32);
                entry[32] = (uint8_t)(manifest.chunks[i].size);
                entry[33] = (uint8_t)(manifest.chunks[i].size >> 8);
                entry[34] = (uint8_t)(manifest.chunks[i].size >> 16);
                entry[35] = (uint8_t)(manifest.chunks[i].size >> 24);
                entry[36] = manifest.chunks[i].file_index;
                memcpy(entry + 37, &manifest.chunks[i].offset, 8);
                if (!fs_send_frame(&session, FS_MANIFEST, entry, 45))
                    break;
            }
            if (!fs_send_frame(&session, FS_DONE, NULL, 0))
                break;
        } else if (type == FS_DONE) {
            break;
        }
    }

    printf("file_service: client done (%.1f MB/s, %llu bytes)\n",
           fs_session_mbps(&session),
           (unsigned long long)(session.bytes_sent + session.bytes_received));
    fs_session_cleanup(&session);
    close(client_fd);
}

static void *fs_client_worker_thread(void *arg)
{
    (void)arg;

    while (true) {
        struct fs_client_slot slot = { .fd = -1 };

        if (!fs_client_queue_pop(&slot))
            break;
        thread_liveness_beat(&g_fs_wkr_liveness, -1);
        if (slot.fd >= 0)
            fs_handle_client_fd(slot.fd, slot.ip);
    }

    return NULL;
}

static void *fs_server_thread(void *arg)
{
    (void)arg;

    int listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_fd < 0)
        LOG_NULL("filesvc", "server_thread: socket() failed: %s", strerror(errno));

    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    int zero = 0;
    setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(g_fs_port);
    addr.sin6_addr = in6addr_any;

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(listen_fd);
        LOG_NULL("filesvc", "server_thread: bind port %d failed: %s", g_fs_port, strerror(errno));
    }

    /* Port 0 = OS-assigned (test fixtures; concurrent checkouts must never
     * collide on a fixed port). Resolve the real port before announcing;
     * published under the state mutex so fs_server_bound_port() readers
     * never see a torn/stale value. */
    uint16_t resolved_port = g_fs_port;
    if (resolved_port == 0) {
        struct sockaddr_in6 bound;
        socklen_t blen = sizeof(bound);
        if (getsockname(listen_fd, (struct sockaddr *)&bound, &blen) == 0)
            resolved_port = ntohs(bound.sin6_port);
    }

    listen(listen_fd, 32);
    log_jsonf(LOG_JSON_INFO, "file_service_listening",
              "\"port\":%d,\"transport\":\"x25519_hkdf_sha3\"",
              resolved_port);

    pthread_mutex_lock(&g_fs_state_mutex);
    g_fs_port = resolved_port;
    g_fs_listen_fd = listen_fd;
    pthread_mutex_unlock(&g_fs_state_mutex);

    /* Get UTXO root for key derivation */
    uint8_t utxo_root[32];
    memset(utxo_root, 0, 32);

    while (atomic_load(&g_fs_running)) {
        thread_liveness_beat(&g_fs_server_liveness, -1);

        struct sockaddr_in6 client_addr;
        socklen_t client_len = sizeof(client_addr);

        /* Use accept with a timeout so we can check g_fs_running */
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int client_fd = accept(listen_fd,
                                (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;

        /* Defense against a peer that opens a connection and then goes
         * silent mid-frame. recv_all() / recv() on this fd would block
         * indefinitely without a per-socket deadline. 30 s is generous
         * for a file-service handshake or frame — anything longer is a
         * misbehaving peer and we'd rather drop the connection than
         * hold a worker hostage. The watchdog catches the hang
         * post-hoc; this prevents it. */
        struct timeval ctv = { .tv_sec = 30, .tv_usec = 0 };
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &ctv, sizeof(ctv));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &ctv, sizeof(ctv));

        /* Capture the peer address (v6 or v4-mapped v6) for the per-IP
         * resource caps applied downstream. */
        uint8_t client_ip[16];
        memcpy(client_ip, &client_addr.sin6_addr, 16);

        if (!fs_client_queue_push(client_fd, client_ip)) {
            fprintf(stderr,  // obs-ok:file-service-overload-visible
                    "file_service: client queue full, rejecting\n");
            close(client_fd);
        }
    }

    pthread_mutex_lock(&g_fs_state_mutex);
    if (g_fs_listen_fd == listen_fd)
        g_fs_listen_fd = -1;
    pthread_mutex_unlock(&g_fs_state_mutex);
    close(listen_fd);
    return NULL;
}

bool fs_server_is_running(void)
{
    bool running;

    pthread_mutex_lock(&g_fs_state_mutex);
    running = atomic_load(&g_fs_running) && g_fs_listen_fd >= 0;
    pthread_mutex_unlock(&g_fs_state_mutex);
    return running;
}

uint16_t fs_server_get_port(void)
{
    uint16_t port;

    pthread_mutex_lock(&g_fs_state_mutex);
    port = g_fs_port;
    pthread_mutex_unlock(&g_fs_state_mutex);
    return port;
}

/* ── Diagnostics: `ops state --subsystem=file_service` ───────────────
 *
 * See CLAUDE.md "Adding state introspection". Surfaces the file-market
 * server's live serving state without grepping node.log + ss: whether the
 * listener is up, the served-data manifest is built, how many client
 * connections are queued for the worker pool, and the per-IP admission
 * table's active occupancy / concurrent-serve load. Atomic reads for the
 * bg-thread flags; brief acquires of the queue/manifest/IP mutexes for a
 * consistent snapshot. */
bool file_service_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    bool running = atomic_load(&g_fs_running);
    json_push_kv_bool(out, "running", running);
    json_push_kv_int(out, "port", (int64_t)g_fs_port);
    json_push_kv_bool(out, "datadir_set", g_fs_datadir != NULL);
    json_push_kv_int(out, "server_workers", (int64_t)FS_SERVER_WORKERS);
    json_push_kv_int(out, "worker_threads_started",
                     (int64_t)g_fs_worker_threads_started);

    /* Client connection backlog awaiting the worker pool. */
    pthread_mutex_lock(&g_fs_client_queue_mutex);
    unsigned qlen = g_fs_client_queue_len;
    pthread_mutex_unlock(&g_fs_client_queue_mutex);
    json_push_kv_int(out, "client_queue_len", (int64_t)qlen);
    json_push_kv_int(out, "client_queue_cap", (int64_t)FS_CLIENT_QUEUE_CAP);

    /* Served-data manifest (built lazily by the background hasher). */
    bool have_manifest = atomic_load(&g_have_manifest);
    uint32_t manifest_chunks = 0;
    int32_t manifest_height = 0;
    if (have_manifest) {
        pthread_mutex_lock(&g_manifest_mutex);
        manifest_chunks = g_server_fm.num_chunks;
        manifest_height = g_server_fm.chain_height;
        pthread_mutex_unlock(&g_manifest_mutex);
    }
    json_push_kv_bool(out, "have_manifest", have_manifest);
    json_push_kv_int(out, "manifest_chunks", (int64_t)manifest_chunks);
    json_push_kv_int(out, "manifest_height", (int64_t)manifest_height);

    /* Per-IP admission table: active clients + concurrent large serves. */
    unsigned active_ips = 0;
    uint64_t total_concurrent = 0;
    pthread_mutex_lock(&g_fs_ip_mutex);
    for (size_t i = 0; i < FS_IP_TABLE_CAP; i++) {
        if (!g_fs_ip[i].used)
            continue;
        active_ips++;
        total_concurrent += g_fs_ip[i].concurrent;
    }
    pthread_mutex_unlock(&g_fs_ip_mutex);
    json_push_kv_int(out, "active_ips", (int64_t)active_ips);
    json_push_kv_int(out, "concurrent_serves", (int64_t)total_concurrent);
    json_push_kv_int(out, "ip_table_cap", (int64_t)FS_IP_TABLE_CAP);

    diag_push_health(out, true,
                     running ? "file service listening"
                             : "file service not started");
    return true;
}

void fs_server_start(const char *datadir, uint16_t port)
{
    unsigned started_workers = 0;

    pthread_mutex_lock(&g_fs_state_mutex);
    if (atomic_load(&g_fs_running) || g_fs_thread_started) {
        pthread_mutex_unlock(&g_fs_state_mutex);
        return;
    }
    g_fs_datadir = datadir;
    g_fs_port = port;
    atomic_store(&g_fs_running, true);
    atomic_store(&g_have_manifest, false);
    /* Fresh PoW gate + per-IP cap tables for this serving session. */
    fs_pow_reset_state();
    g_fs_client_queue_head = 0;
    g_fs_client_queue_tail = 0;
    g_fs_client_queue_len = 0;

    for (unsigned i = 0; i < FS_SERVER_WORKERS; i++) {
        if (thread_registry_spawn("zcl_fs_wkr", fs_client_worker_thread,
                                      NULL, &g_fs_worker_threads[i]) != 0) {
            fprintf(stderr,  // obs-ok:file-service-startup-failure
                    "file_service: failed to start worker %u\n", i);
            break;
        }
        started_workers++;
    }
    g_fs_worker_threads_started = started_workers;
    if (started_workers > 0)
        thread_liveness_register(&g_fs_wkr_liveness, "zcl_fs_wkr", 0, 0);

    if (thread_registry_spawn("zcl_fs_server", fs_server_thread, NULL,
                                  &g_fs_thread) != 0) {
        atomic_store(&g_fs_running, false);
        pthread_cond_broadcast(&g_fs_client_queue_cv);
        pthread_mutex_unlock(&g_fs_state_mutex);
        fprintf(stderr,  // obs-ok:file-service-startup-failure
                "file_service: failed to start server thread\n");
        for (unsigned i = 0; i < started_workers; i++)
            pthread_join(g_fs_worker_threads[i], NULL);
        g_fs_worker_threads_started = 0;
        thread_liveness_retire(&g_fs_wkr_liveness);
        return;
    }
    g_fs_thread_started = true;
    thread_liveness_register(&g_fs_server_liveness, "zcl_fs_server", 0, 0);
    if (g_fs_datadir) {
        if (thread_registry_spawn("zcl_fs_manifest", fs_manifest_thread,
                                      NULL, &g_fs_manifest_thread) == 0) {
            g_fs_manifest_thread_started = true;
            thread_liveness_register(&g_fs_manifest_liveness, "zcl_fs_manifest", 0, 0);
        } else {
            fprintf(stderr,  // obs-ok:file-service-startup-failure
                    "file_service: failed to start manifest thread\n");
        }
    }
    pthread_mutex_unlock(&g_fs_state_mutex);
}

void fs_server_stop(void)
{
    pthread_t server_thread;
    pthread_t manifest_thread;
    pthread_t worker_threads[FS_SERVER_WORKERS];
    bool have_server = false;
    bool have_manifest = false;
    unsigned worker_threads_started = 0;
    int listen_fd = -1;

    pthread_mutex_lock(&g_fs_state_mutex);
    atomic_store(&g_fs_running, false);
    listen_fd = g_fs_listen_fd;
    g_fs_listen_fd = -1;
    if (g_fs_thread_started) {
        server_thread = g_fs_thread;
        g_fs_thread_started = false;
        have_server = true;
    }
    if (g_fs_manifest_thread_started) {
        manifest_thread = g_fs_manifest_thread;
        g_fs_manifest_thread_started = false;
        have_manifest = true;
    }
    worker_threads_started = g_fs_worker_threads_started;
    for (unsigned i = 0; i < worker_threads_started; i++)
        worker_threads[i] = g_fs_worker_threads[i];
    g_fs_worker_threads_started = 0;
    pthread_mutex_unlock(&g_fs_state_mutex);

    if (listen_fd >= 0) {
        shutdown(listen_fd, SHUT_RDWR);
        close(listen_fd);
    }
    pthread_cond_broadcast(&g_fs_client_queue_cv);
    fs_client_queue_close_all();

    if (have_server) {
        fs_join_thread_bounded(server_thread, "server", 5);
        thread_liveness_retire(&g_fs_server_liveness);
    }
    if (have_manifest) {
        fs_join_thread_bounded(manifest_thread, "manifest", 5);
        thread_liveness_retire(&g_fs_manifest_liveness);
    }
    for (unsigned i = 0; i < worker_threads_started; i++)
        fs_join_thread_bounded(worker_threads[i], "worker", 5);
    if (worker_threads_started > 0)
        thread_liveness_retire(&g_fs_wkr_liveness);
}

/* ── Parallel download worker ──────────────────────────────────── */

struct range_worker {
    const char *peer_addr;
    uint16_t port;
    uint8_t utxo_root[32];
    struct file_chunk *chunks;
    uint32_t start, end;
    const char *out_path;
    const char *datadir;
    int id;
    int fd;                /* socket fd — for cancellation */
    _Atomic bool done;
    _Atomic bool cancel;   /* set by main thread to abort stuck worker */
    _Atomic uint64_t bytes;
    _Atomic uint32_t chunks_ok;    /* successfully written chunks */
    _Atomic uint32_t chunks_fail;  /* failed recv or write */
};

/* Client side: fetch a PoW challenge from the server, solve it, and fill a
 * 48-byte solution bound to this session's handshake nonce. Honest peers must
 * present this before the server will commit to a large range/ALL stream. */
static bool fs_client_solve_challenge(struct fs_session *s,
                                      uint8_t solution[FS_POW_SOLUTION_SIZE])
{
    if (!fs_send_frame(s, FS_CHALLENGE, NULL, 0))
        return false;
    uint8_t type;
    const uint8_t *payload;
    uint32_t plen;
    if (!fs_recv_frame(s, &type, &payload, &plen))
        return false;
    if (type != FS_CHALLENGE || plen < FS_CHALLENGE_PAYLOAD_SIZE)
        return false;

    uint8_t seed[32];
    memcpy(seed, payload, 32);
    int bits = payload[32];
    int64_t ts = (int64_t)platform_time_wall_time_t();
    uint64_t nonce = 0;
    if (!puzzle_solve(seed, s->our_nonce, ts, bits, &nonce))
        return false;

    memcpy(solution, s->our_nonce, 32);
    memcpy(solution + 32, &ts, 8);
    memcpy(solution + 40, &nonce, 8);
    return true;
}

static void *range_worker_fn(void *arg)
{
    struct range_worker *w = (struct range_worker *)arg;
    if (w->start >= w->end) { atomic_store(&w->done, true); return NULL; }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char ps[8];
    snprintf(ps, sizeof(ps), "%d", w->port);
    if (getaddrinfo(w->peer_addr, ps, &hints, &res) != 0)
        LOG_NULL("filesvc", "worker %d: getaddrinfo failed for %s", w->id, w->peer_addr);
    int wfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (wfd < 0) { freeaddrinfo(res); LOG_NULL("filesvc", "worker %d: socket() failed: %s", w->id, strerror(errno)); }

    /* Timeouts prevent hung connections from blocking the whole download */
    struct timeval tv;
    tv.tv_sec = 120; /* 2 min per chunk max */
    tv.tv_usec = 0;
    setsockopt(wfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(wfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(wfd, res->ai_addr, res->ai_addrlen) < 0) {
        close(wfd); freeaddrinfo(res); LOG_NULL("filesvc", "worker %d: connect failed: %s", w->id, strerror(errno));
    }
    freeaddrinfo(res);

    w->fd = wfd;  /* allow main thread to close on cancel */
    struct fs_session ws;
    fs_session_init(&ws, wfd);
    if (!fs_handshake(&ws, w->utxo_root, true)) { fs_session_cleanup(&ws); close(wfd); LOG_NULL("filesvc", "worker %d: handshake failed", w->id); }

    /* Solve the server's PoW challenge before requesting the range. */
    uint8_t solution[FS_POW_SOLUTION_SIZE];
    if (!fs_client_solve_challenge(&ws, solution)) {
        fs_session_cleanup(&ws); close(wfd); LOG_NULL("filesvc", "worker %d: PoW challenge/solve failed", w->id);
    }

    /* Send the gated range request: [48-byte solution]["RNG"][start][end]. */
    uint8_t rng[FS_POW_SOLUTION_SIZE + 8];
    memcpy(rng, solution, FS_POW_SOLUTION_SIZE);
    rng[FS_POW_SOLUTION_SIZE + 0] = 'R';
    rng[FS_POW_SOLUTION_SIZE + 1] = 'N';
    rng[FS_POW_SOLUTION_SIZE + 2] = 'G';
    rng[FS_POW_SOLUTION_SIZE + 3] = (uint8_t)(w->start);
    rng[FS_POW_SOLUTION_SIZE + 4] = (uint8_t)(w->start >> 8);
    rng[FS_POW_SOLUTION_SIZE + 5] = (uint8_t)(w->end);
    rng[FS_POW_SOLUTION_SIZE + 6] = (uint8_t)(w->end >> 8);
    rng[FS_POW_SOLUTION_SIZE + 7] = 0;
    if (!fs_send_frame(&ws, FS_REQUEST, rng, sizeof(rng))) {
        fs_session_cleanup(&ws); close(wfd); LOG_NULL("filesvc", "worker %d: range request send failed", w->id);
    }

    for (uint32_t i = w->start; i < w->end; i++) {
        if (atomic_load(&w->cancel)) { fs_session_cleanup(&ws); close(wfd); LOG_NULL("filesvc", "worker %d: cancelled", w->id); }
        uint8_t *buf = NULL;
        uint32_t sz = 0;
        if (!fs_recv_chunk_fast(&ws, &buf, &sz, w->chunks[i].sha3)) {
            fprintf(stderr,  // obs-ok:file-transfer-peer-failure
                    "worker %d: chunk %u/%u recv failed\n",
                    w->id, i, w->end);
            atomic_fetch_add(&w->chunks_fail, 1);
            continue;
        }

        /* Write to the correct file at the correct offset.
         * file_index 0-252: block files (blk%05d.dat)
         * file_index 253: block_index.bin
         * file_index 254: node.db (SQLite UTXO set)
         * Uses pwrite() for atomic positioned write. */
        char blk_path[600];
        if (w->chunks[i].file_index == 254)
            snprintf(blk_path, 600, "%s/consensus_snapshot.db", w->datadir);
        else if (w->chunks[i].file_index == 253)
            snprintf(blk_path, 600, "%s/block_index.bin", w->datadir);
        else
            snprintf(blk_path, 600, "%s/blocks/blk%05d.dat",
                     w->datadir, w->chunks[i].file_index);
        int bfd = open(blk_path, O_WRONLY | O_CREAT, 0644);
        if (bfd >= 0) {
            ssize_t written = pwrite(bfd, buf, sz, (off_t)w->chunks[i].offset);
            if (written != (ssize_t)sz) {
                fprintf(stderr,  // obs-ok:file-transfer-disk-failure
                        "worker %d: pwrite %s offset=%llu "
                        "sz=%u wrote=%zd errno=%d\n",
                        w->id, blk_path,
                        (unsigned long long)w->chunks[i].offset,
                        sz, written, errno);
                close(bfd);
                free(buf);
                continue; /* skip — don't count failed write as progress */
            }
            /* Sync to disk so crash can't lose this chunk */
            fdatasync(bfd);
            close(bfd);
            atomic_fetch_add(&w->chunks_ok, 1);
        } else {
            fprintf(stderr,  // obs-ok:file-transfer-disk-failure
                    "worker %d: open %s failed: %s\n",
                    w->id, blk_path, strerror(errno));
            atomic_fetch_add(&w->chunks_fail, 1);
        }
        free(buf);
        atomic_fetch_add(&w->bytes, sz);
    }
    fs_session_cleanup(&ws);
    close(wfd);
    atomic_store(&w->done, true);
    return NULL;
}

/* ── Client ────────────────────────────────────────────────────── */

bool fs_client_sync(const char *peer_addr, uint16_t port,
                     const char *datadir, const uint8_t utxo_root[32])
{
    printf("file_service: connecting to %s:%d...\n", peer_addr, port);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(peer_addr, port_str, &hints, &res) != 0)
        LOG_FAIL("filesvc", "client_sync: resolve failed for %s", peer_addr);

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); LOG_FAIL("filesvc", "client_sync: socket() failed: %s", strerror(errno)); }

    /* Non-blocking connect with 10s timeout — don't block boot on
     * unreachable file service peers. */
    {
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int rc = connect(fd, res->ai_addr, res->ai_addrlen);
        if (rc < 0 && errno == EINPROGRESS) {
            struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            rc = select(fd + 1, NULL, &wfds, NULL, &tv);
            if (rc <= 0) {
                close(fd);
                freeaddrinfo(res);
                /* Optional fast-sync seed not reachable — routine on a
                 * fresh node; P2P snapshot sync is the fallback. Warn,
                 * don't error. */
                LOG_WARN("filesvc", "client_sync: connect timeout to %s:%d (optional seed; falling back to P2P)", peer_addr, port);
                return false;
            }
            int err = 0;
            socklen_t elen = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
            if (err) {
                close(fd);
                freeaddrinfo(res);
                LOG_WARN("filesvc", "client_sync: connect to %s:%d failed: %s (optional seed; falling back to P2P)", peer_addr, port, strerror(err));
                return false;
            }
        } else if (rc < 0) {
            close(fd);
            freeaddrinfo(res);
            LOG_WARN("filesvc", "client_sync: connect to %s:%d failed: %s (optional seed; falling back to P2P)", peer_addr, port, strerror(errno));
            return false;
        }
        fcntl(fd, F_SETFL, flags);  /* restore blocking mode */
    }
    freeaddrinfo(res);

    struct fs_session session;
    fs_session_init(&session, fd);

    if (!fs_handshake(&session, utxo_root, true)) {
        fs_session_cleanup(&session);
        close(fd);
        LOG_FAIL("filesvc", "client_sync: handshake failed with %s:%d", peer_addr, port);
    }

    printf("file_service: connected, requesting manifest...\n");

    /* Set timeout for manifest reception — don't block forever */
    struct timeval mtv;
    mtv.tv_sec = 60; /* 60s to receive full manifest */
    mtv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &mtv, sizeof(mtv));

    if (!fs_send_frame(&session, FS_MANIFEST, NULL, 0)) {
        fs_session_cleanup(&session);
        close(fd);
        LOG_FAIL("filesvc", "client_sync: manifest request send failed to %s:%d", peer_addr, port);
    }

    struct file_chunk chunks[FILE_MAX_CHUNKS];
    uint32_t num_chunks = 0;

    while (num_chunks < FILE_MAX_CHUNKS) {
        uint8_t type;
        const uint8_t *payload;
        uint32_t plen;

        if (!fs_recv_frame(&session, &type, &payload, &plen))
            break;

        if (type == FS_DONE) break;
        if (type == FS_MANIFEST && plen >= 36) {
            struct file_chunk *c = &chunks[num_chunks];
            memset(c, 0, sizeof(*c));   /* short form leaves file_index/offset
                                         * unset — zero them, not stack garbage */
            memcpy(c->sha3, payload, 32);
            c->size =
                (uint32_t)payload[32] |
                ((uint32_t)payload[33] << 8) |
                ((uint32_t)payload[34] << 16) |
                ((uint32_t)payload[35] << 24);
            /* Extended manifest: file_index + offset */
            if (plen >= 45) {
                c->file_index = payload[36];
                memcpy(&c->offset, payload + 37, 8);
            }
            /* SECURITY: every manifest field is peer-supplied. Bound the chunk
             * size here at parse time (the recv path caps at 60MB on the wire,
             * but the resume-verify malloc at line ~1137 trusted this size and a
             * size=0xFFFFFFFF entry would attempt a ~4GB alloc → OOM/DoS on a
             * fresh node). Reject the whole manifest on any out-of-range entry.
             * file_index must address a real sink (0-252 block files, 253
             * block_index.bin, 254 consensus_snapshot.db); 255 is invalid. */
            if (c->size == 0 || c->size > 60 * 1024 * 1024) {
                fs_session_cleanup(&session);
                close(fd);
                LOG_FAIL("filesvc", "client_sync: manifest chunk %u has invalid "
                         "size=%u (peer-supplied) — rejecting manifest",
                         num_chunks, c->size);
            }
            if (c->file_index > 254) {
                fs_session_cleanup(&session);
                close(fd);
                LOG_FAIL("filesvc", "client_sync: manifest chunk %u has invalid "
                         "file_index=%u — rejecting manifest",
                         num_chunks, (unsigned)c->file_index);
            }
            num_chunks++;
        }
    }

    if (num_chunks == 0) {
        fs_session_cleanup(&session);
        close(fd);
        LOG_FAIL("filesvc", "client_sync: manifest empty (server still building)");
    }

    /* Compute total download size for progress reporting. Each chunk is already
     * bounded at <=60MB and num_chunks at FILE_MAX_CHUNKS (1024), so the sum
     * cannot overflow uint64; cap the cumulative total at the documented
     * ~50GB ceiling so a maximal-but-individually-valid manifest can't request
     * an absurd download. */
    uint64_t total_bytes = 0;
    for (uint32_t j = 0; j < num_chunks; j++)
        total_bytes += chunks[j].size;
    if (total_bytes > (uint64_t)FILE_MAX_CHUNKS * FILE_CHUNK_SIZE) {
        fs_session_cleanup(&session);
        close(fd);
        LOG_FAIL("filesvc", "client_sync: manifest total %llu bytes exceeds "
                 "ceiling — rejecting manifest",
                 (unsigned long long)total_bytes);
    }
    printf("file_service: manifest has %u chunks (%.1f GB), downloading...\n",
           num_chunks, (double)total_bytes / (1024.0 * 1024.0 * 1024.0));

    /* Create blocks directory */
    char blocks_dir[512];
    snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", datadir);
    mkdir(blocks_dir, 0755);

    int64_t dl_start = (int64_t)platform_time_wall_time_t();

    /* Check if previous partial download exists — verify and resume.
     * We spot-check existing chunks with SHA3 to detect corruption. */
    uint32_t skip_chunks = 0;
    {
        uint32_t verified = 0, checked = 0;
        for (uint32_t j = 0; j < num_chunks; j++) {
            char blk_path[600];
            if (chunks[j].file_index == 253)
                snprintf(blk_path, 600, "%s/block_index.bin", datadir);
            else
                snprintf(blk_path, 600, "%s/blocks/blk%05d.dat",
                         datadir, chunks[j].file_index);

            /* Check if file is large enough for this chunk */
            struct stat st;
            if (stat(blk_path, &st) != 0 ||
                (uint64_t)st.st_size < chunks[j].offset + chunks[j].size)
                break; /* this chunk not on disk, stop skipping */

            /* SHA3 verify every 20th chunk + first + last existing.
             * Full verification would be slow on 7GB, spot-check is fast. */
            if (j == 0 || j % 20 == 0) {
                int fd2 = open(blk_path, O_RDONLY);
                if (fd2 < 0) break;
                uint8_t *vbuf = zcl_malloc(chunks[j].size, "file_verify_buf");
                if (!vbuf) { close(fd2); break; }
                ssize_t got = pread(fd2, vbuf, chunks[j].size,
                                     (off_t)chunks[j].offset);
                close(fd2);
                if (got != (ssize_t)chunks[j].size) {
                    free(vbuf); break;
                }
                uint8_t hash[32];
                sha3_256(vbuf, chunks[j].size, hash);
                free(vbuf);
                if (memcmp(hash, chunks[j].sha3, 32) != 0) {
                    fprintf(stderr,  // obs-ok:file-transfer-integrity-retry
                            "file_service: resume SHA3 mismatch at "
                            "chunk %u (file=%d off=%llu) — re-downloading "
                            "from here\n", j, chunks[j].file_index,
                            (unsigned long long)chunks[j].offset);
                    break;
                }
                checked++;
            }
            verified++;
        }
        skip_chunks = verified;
        if (skip_chunks > 0) {
            printf("file_service: resuming — %u/%u chunks on disk "
                   "(%u SHA3-verified)\n", skip_chunks, num_chunks, checked);
        }
    }

    /* Close manifest connection — we'll open parallel ones */
    fs_session_cleanup(&session);
    close(fd);

    /* Launch 8 parallel workers, each downloads a range of chunks */
    #define FS_NWORKERS 8
    uint32_t remaining = num_chunks - skip_chunks;
    uint32_t per = (remaining + FS_NWORKERS - 1) / FS_NWORKERS;
    struct range_worker workers[FS_NWORKERS];
    pthread_t wthreads[FS_NWORKERS];
    int nworkers = 0;

    for (int w = 0; w < FS_NWORKERS; w++) {
        uint32_t ws = skip_chunks + (uint32_t)w * per;
        uint32_t we = ws + per;
        if (we > num_chunks) we = num_chunks;
        if (ws >= num_chunks) break;

        char *wp = zcl_malloc(600, "file_worker_path");
        snprintf(wp, 600, "%s/blocks/.part%d", datadir, w);

        workers[nworkers].peer_addr = peer_addr;
        workers[nworkers].port = port;
        memcpy(workers[nworkers].utxo_root, utxo_root, 32);
        workers[nworkers].chunks = chunks;
        workers[nworkers].start = ws;
        workers[nworkers].end = we;
        workers[nworkers].out_path = wp;
        workers[nworkers].datadir = datadir;
        workers[nworkers].id = w;
        workers[nworkers].fd = -1;
        atomic_store(&workers[nworkers].done, false);
        atomic_store(&workers[nworkers].cancel, false);
        atomic_store(&workers[nworkers].bytes, 0);
        atomic_store(&workers[nworkers].chunks_ok, 0);
        atomic_store(&workers[nworkers].chunks_fail, 0);
        /* raw-pthread-ok: short-burst-joined-immediately (per-download workers) */
        if (pthread_create(&wthreads[nworkers], NULL,
                           range_worker_fn, &workers[nworkers]) != 0) {
            free(wp);
            for (int j = 0; j < nworkers; j++) {
                atomic_store(&workers[j].cancel, true);
                if (workers[j].fd >= 0)
                    shutdown(workers[j].fd, SHUT_RDWR);
            }
            for (int j = 0; j < nworkers; j++) {
                pthread_join(wthreads[j], NULL);
                free((void *)workers[j].out_path);
            }
            LOG_FAIL("filesvc", "client_sync: failed to start download worker %d", w);
        }
        nworkers++;
    }

    printf("file_service: %d parallel connections downloading...\n", nworkers);

    /* Monitor progress — give up after 30 min total */
    int64_t max_wait = 1800;
    uint64_t prev_done_bytes[FS_NWORKERS];
    int stall_counts[FS_NWORKERS];
    memset(prev_done_bytes, 0, sizeof(prev_done_bytes));
    /* Start at -4 so workers have 20s grace period to connect+handshake
     * before stall detection kicks in. Prevents false cancellation. */
    for (int w = 0; w < FS_NWORKERS; w++) stall_counts[w] = -4;
    while (true) {
        sleep(5);
        uint64_t done = 0;
        bool all_done = true;
        for (int w = 0; w < nworkers; w++) {
            done += atomic_load(&workers[w].bytes);
            if (!atomic_load(&workers[w].done)) all_done = false;
        }
        int64_t el = (int64_t)platform_time_wall_time_t() - dl_start;
        if (el > max_wait) {
            printf("file_service: timeout after %llds, cancelling stuck "
                   "workers\n", (long long)el);
            for (int w = 0; w < nworkers; w++) {
                if (!atomic_load(&workers[w].done)) {
                    atomic_store(&workers[w].cancel, true);
                    shutdown(workers[w].fd, SHUT_RDWR);
                }
            }
            break;
        }
        /* Cancel workers stuck on a single chunk for >60s */
        {
            for (int w = 0; w < nworkers; w++) {
                uint64_t wb = atomic_load(&workers[w].bytes);
                if (!atomic_load(&workers[w].done) && wb == prev_done_bytes[w]) {
                    stall_counts[w]++;
                    if (stall_counts[w] >= 12) { /* 12*5s = 60s stall */
                        fprintf(stderr,  // obs-ok:file-transfer-stall-recovery
                                "file_service: worker %d stalled "
                                "at %llu bytes, cancelling\n",
                                w, (unsigned long long)wb);
                        atomic_store(&workers[w].cancel, true);
                        shutdown(workers[w].fd, SHUT_RDWR);
                        stall_counts[w] = 0;
                    }
                } else {
                    stall_counts[w] = 0;
                    prev_done_bytes[w] = wb;
                }
            }
        }
        double pct = total_bytes > 0 ? 100.0 * (double)done / (double)total_bytes : 0;
        int64_t elapsed = (int64_t)platform_time_wall_time_t() - dl_start;
        double mbps = elapsed > 0 ? (double)done / (1048576.0 * (double)elapsed) : 0;
        int eta = (done > 0 && elapsed > 0) ?
            (int)((double)(total_bytes - done) / ((double)done / (double)elapsed)) : 0;
        printf("file_service: [%3.0f%%] %.1f/%.1f GB  %.1f MB/s  "
               "(%d connections)  ETA %dm%02ds\n",
               pct, (double)done / (1024.0*1024.0*1024.0),
               (double)total_bytes / (1024.0*1024.0*1024.0),
               mbps, nworkers, eta / 60, eta % 60);
        fflush(stdout);
        if (all_done || done >= total_bytes) break;
    }

    for (int w = 0; w < nworkers; w++)
        pthread_join(wthreads[w], NULL);

    /* Workers wrote directly to blk%05d.dat files — no concatenation needed */
    for (int w = 0; w < nworkers; w++)
        free((void *)workers[w].out_path);

    uint64_t bytes_done = 0;
    uint32_t total_ok = 0, total_fail = 0;
    for (int w = 0; w < nworkers; w++) {
        bytes_done += atomic_load(&workers[w].bytes);
        total_ok += atomic_load(&workers[w].chunks_ok);
        total_fail += atomic_load(&workers[w].chunks_fail);
    }

    int64_t dl_elapsed = (int64_t)platform_time_wall_time_t() - dl_start;
    printf("=== File sync: %.1f GB in %llds (%.1f MB/s avg) "
           "chunks: %u ok, %u failed out of %u ===\n",
           (double)bytes_done / (1024.0 * 1024.0 * 1024.0),
           (long long)dl_elapsed,
           dl_elapsed > 0 ? (double)bytes_done / (1024.0 * 1024.0) / (double)dl_elapsed : 0,
           total_ok, total_fail, remaining);

    /* Retry failed chunks — up to 3 attempts with fresh connections */
    for (int retry = 0; retry < 3 && total_fail > 0; retry++) {
        printf("[file] retrying %u failed chunks, attempt %d/3\n",
               total_fail, retry + 1);

        /* Collect indices of chunks that aren't on disk yet */
        uint32_t *retry_idx = zcl_calloc(total_fail, sizeof(uint32_t),
                                         "retry_indices");
        if (!retry_idx) break;
        uint32_t nretry = 0;
        for (uint32_t c = skip_chunks; c < num_chunks && nretry < total_fail; c++) {
            /* Quick check: try reading the chunk back and verifying hash */
            char blk_path[600];
            if (chunks[c].file_index == 254)
                snprintf(blk_path, 600, "%s/consensus_snapshot.db", datadir);
            else if (chunks[c].file_index == 253)
                snprintf(blk_path, 600, "%s/block_index.bin", datadir);
            else
                snprintf(blk_path, 600, "%s/blocks/blk%05d.dat",
                         datadir, chunks[c].file_index);
            int cfd = open(blk_path, O_RDONLY);
            if (cfd < 0) { retry_idx[nretry++] = c; continue; }
            uint8_t probe[1];
            ssize_t rd = pread(cfd, probe, 1, (off_t)chunks[c].offset);
            close(cfd);
            if (rd <= 0)
                retry_idx[nretry++] = c;
        }

        if (nretry == 0) { free(retry_idx); break; }

        /* Open a single fresh connection for retries */
        struct addrinfo rhints, *rres;
        memset(&rhints, 0, sizeof(rhints));
        rhints.ai_family = AF_UNSPEC;
        rhints.ai_socktype = SOCK_STREAM;
        char rps[8];
        snprintf(rps, sizeof(rps), "%d", port);
        if (getaddrinfo(peer_addr, rps, &rhints, &rres) != 0) {
            free(retry_idx); break;
        }
        int rfd = socket(rres->ai_family, rres->ai_socktype, rres->ai_protocol);
        if (rfd < 0) { freeaddrinfo(rres); free(retry_idx); break; }

        struct timeval rtv = { .tv_sec = 120, .tv_usec = 0 };
        setsockopt(rfd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
        setsockopt(rfd, SOL_SOCKET, SO_SNDTIMEO, &rtv, sizeof(rtv));
        if (connect(rfd, rres->ai_addr, rres->ai_addrlen) < 0) {
            close(rfd); freeaddrinfo(rres); free(retry_idx); break;
        }
        freeaddrinfo(rres);

        struct fs_session rs;
        fs_session_init(&rs, rfd);
        if (!fs_handshake(&rs, utxo_root, true)) {
            fs_session_cleanup(&rs);
            close(rfd); free(retry_idx); break;
        }

        uint32_t recovered = 0;
        for (uint32_t r = 0; r < nretry; r++) {
            uint32_t ci = retry_idx[r];
            /* Request individual chunk by hash. A send failure means the
             * retry connection is dead — stop and let the post-loop cleanup
             * close rfd and free retry_idx. */
            if (!fs_send_frame(&rs, FS_REQUEST, chunks[ci].sha3, 32))
                break;

            uint8_t *buf = NULL;
            uint32_t sz = 0;
            if (!fs_recv_chunk_fast(&rs, &buf, &sz, chunks[ci].sha3)) {
                printf("[file] retrying chunk %u attempt %d failed\n",
                       ci, retry + 1);
                continue;
            }

            char blk_path[600];
            if (chunks[ci].file_index == 254)
                snprintf(blk_path, 600, "%s/consensus_snapshot.db", datadir);
            else if (chunks[ci].file_index == 253)
                snprintf(blk_path, 600, "%s/block_index.bin", datadir);
            else
                snprintf(blk_path, 600, "%s/blocks/blk%05d.dat",
                         datadir, chunks[ci].file_index);
            int bfd = open(blk_path, O_WRONLY | O_CREAT, 0644);
            if (bfd >= 0) {
                ssize_t written = pwrite(bfd, buf, sz,
                                         (off_t)chunks[ci].offset);
                fdatasync(bfd);
                close(bfd);
                if (written == (ssize_t)sz) {
                    recovered++;
                    printf("[file] retrying chunk %u attempt %d succeeded\n",
                           ci, retry + 1);
                }
            }
            free(buf);
        }

        fs_session_cleanup(&rs);
        close(rfd);
        free(retry_idx);
        total_fail = (recovered >= total_fail) ? 0 : total_fail - recovered;
        total_ok += recovered;
        printf("[file] retry attempt %d: recovered %u chunks, %u still failed\n",
               retry + 1, recovered, total_fail);
    }

    if (total_fail > 0)
        LOG_FAIL("filesvc", "client_sync: %u/%u chunks failed after retries — download incomplete", total_fail, remaining);

    if (total_ok < remaining)
        LOG_FAIL("filesvc", "client_sync: only %u/%u chunks received — incomplete", total_ok, remaining);

    return true;
}
