#if !defined(_WIN32)
#define _GNU_SOURCE  /* pthread_timedjoin_np */
#endif

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fast File Service — SHA3-encrypted direct TCP transfer.
 * Designed for maximum throughput: 64KB fixed frames, zero protocol
 * overhead visible to observers, wire-speed on gigabit links. */

#include "platform/time_compat.h"
#include "platform/thread_compat.h"
#include "platform/file_sync.h"
#include "platform/barrier.h"
#include "net/net_runtime_port.h"
#include "net/file_manifest.h"
#include "net/file_market_delivery.h"
#include "net/file_service.h"
#include "net/netbase.h"
#include "file_service_worker_internal.h"
#include "net/rom_seed.h"
#include "util/log_json.h"
#include "crypto/sha3.h"
#include "json/json.h"

#include <string.h>

/* ── Pure ROM wire-parsers — deliberately OUTSIDE the platform split ────
 * fs_parse_rom_request / fs_parse_rom_manifest_request /
 * fs_parse_rom_list_request do no I/O and touch no platform API. Until this
 * fix, each had a second body inside the `#if defined(_WIN32)` arm below,
 * and the two bodies had DRIFTED: Windows required an exact payload length
 * and refused a NULL output; POSIX accepted any payload at least the
 * minimum length (silently ignoring trailing bytes) and treated the
 * root/idx out-params as optional, returning true having written nothing.
 * A Windows node and a Linux node could therefore disagree about whether
 * identical wire bytes form a valid request. Hoisting these here, defined
 * exactly once, makes that drift impossible by construction. Semantics
 * kept: the STRICTER of both axes — exact length (the header's documented
 * FS_ROM*_SIZE contract) and non-NULL outputs required. */
bool fs_parse_rom_request(const uint8_t *payload, uint32_t plen,
                          uint8_t root_out[32], uint32_t *idx_out)
{
    if (!payload || !root_out || !idx_out || plen != FS_ROM_REQUEST_SIZE)
        return false;
    if (memcmp(payload, "ROM", 3) != 0)
        return false;
    memcpy(root_out, payload + 3, 32);
    *idx_out = (uint32_t)payload[35] |
               ((uint32_t)payload[36] << 8) |
               ((uint32_t)payload[37] << 16) |
               ((uint32_t)payload[38] << 24);
    return true;
}

bool fs_parse_rom_manifest_request(const uint8_t *payload, uint32_t plen,
                                   uint8_t root_out[32])
{
    if (!payload || !root_out || plen != FS_ROM_MANIFEST_REQUEST_SIZE)
        return false;
    if (memcmp(payload, "RMF", 3) != 0)
        return false;
    memcpy(root_out, payload + 3, 32);
    return true;
}

bool fs_parse_rom_list_request(const uint8_t *payload, uint32_t plen)
{
    if (!payload || plen != FS_ROM_LIST_REQUEST_SIZE)
        return false;
    return memcmp(payload, "RLS", 3) == 0;
}

#if defined(_WIN32)

#include <errno.h>
#include <string.h>

void fs_server_start(const char *datadir, uint16_t port)
{ (void)datadir; (void)port; errno = ENOTSUP; }
void fs_server_stop(void) {}
bool fs_server_is_running(void) { return false; }
uint16_t fs_server_get_port(void) { return 0; }
bool fs_server_refresh_manifest(void) { errno = ENOTSUP; return false; }
bool fs_client_sync(const char *peer, uint16_t port, const char *datadir,
                    const uint8_t root[32])
{
    (void)peer; (void)port; (void)datadir; (void)root;
    errno = ENOTSUP;
    return false;
}

bool file_service_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);
    json_push_kv_bool(out, "running", false);
    json_push_kv_bool(out, "available", false);
    json_push_kv_str(out, "reason",
                     "native Windows inbound file-service server disabled "
                     "pending trusted manifest and snapshot transactions");
    return true;
}

struct puzzle_gate *fs_pow_gate(void) { return NULL; }
void fs_pow_reset_state(void) {}
bool fs_ip_serve_acquire(const uint8_t ip[16]) { (void)ip; return false; }
void fs_ip_serve_release(const uint8_t ip[16]) { (void)ip; }
bool fs_ip_bytes_charge(const uint8_t ip[16], uint64_t n)
{ (void)ip; (void)n; return false; }
bool fs_conn_budget_ok(uint64_t bytes, int64_t start, int64_t now)
{
    return now >= start && bytes <= FS_CONN_MAX_BYTES &&
           now - start <= FS_CONN_MAX_SECONDS * INT64_C(1000);
}
/* NOT hoisted alongside the three fs_parse_rom_* parsers above: unlike
 * those, the Windows and POSIX bodies of fs_parse_serve_request implement
 * genuinely different logic (this stub never learned the POW-gated-prefix
 * detection the POSIX body has), not just a length/NULL-output divergence
 * on an otherwise-identical parser. Collapsing it into one definition is a
 * real behavior change to the PoW admission path, out of this fix's scope.
 * Tracked, not silently accepted, in tools/lint/arm_symbol_single_baseline.txt. */
bool fs_parse_serve_request(const uint8_t *p, uint32_t n, bool *all,
                            bool *range, const uint8_t **puzzle,
                            uint16_t *start, uint16_t *end)
{
    if (all) *all = false;
    if (range) *range = false;
    if (puzzle) *puzzle = NULL;
    if (start) *start = 0;
    if (end) *end = 0;
    if (!p) return false;
    uint32_t off = 0;
    if (n >= FS_POW_SOLUTION_SIZE + 3 &&
        (memcmp(p + FS_POW_SOLUTION_SIZE, "ALL", 3) == 0 ||
         memcmp(p + FS_POW_SOLUTION_SIZE, "RNG", 3) == 0)) {
        if (puzzle) *puzzle = p;
        off = FS_POW_SOLUTION_SIZE;
    }
    if (n == off + 3 && memcmp(p + off, "ALL", 3) == 0) {
        if (all) *all = true;
        return true;
    }
    if (n == off + 7 && memcmp(p + off, "RNG", 3) == 0) {
        if (range) *range = true;
        if (start) *start = (uint16_t)p[off + 3] | (uint16_t)p[off + 4] << 8;
        if (end) *end = (uint16_t)p[off + 5] | (uint16_t)p[off + 6] << 8;
        return true;
    }
    return false;
}
enum fs_admit_result fs_admit_serve_pow(const uint8_t *p,
    const uint8_t token[32], uint8_t seed[32], int *bits, int64_t *server_time)
{
    (void)p; (void)token; (void)seed; (void)bits; (void)server_time;
    return FS_ADMIT_REFUSED_CAP;
}

#ifdef ZCL_TESTING
bool fs_test_range_worker_socket_lifecycle(void) { return false; }
bool fs_test_resolved_connect_lifecycle(void) { return false; }
#endif

#else

#include <fcntl.h>
#include <limits.h>
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
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"
#include "util/thread_liveness.h"
#include "support/cleanse.h"

static void fs_join_thread_bounded(pthread_t thread,
                                   const char *name,
                                   int timeout_sec)
{
    struct timespec deadline;
    int rc;

    platform_time_realtime_timespec(&deadline);
    deadline.tv_sec += timeout_sec > 0 ? timeout_sec : 0;
    rc = platform_thread_join_until(thread, NULL, &deadline);
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

/* ── Server ────────────────────────────────────────────────────── */

static _Atomic bool g_fs_running = false;
static _Atomic bool g_fs_stopping = false;
static pthread_cond_t g_fs_stop_cv = PTHREAD_COND_INITIALIZER;
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
/* Workers own close(); this mutex prevents shutdown of a reused descriptor. */
static int g_fs_active_fds[FS_SERVER_WORKERS];
static pthread_mutex_t g_fs_active_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct fs_client_slot g_fs_client_queue[FS_CLIENT_QUEUE_CAP];
static unsigned g_fs_client_queue_head = 0;
static unsigned g_fs_client_queue_tail = 0;
static unsigned g_fs_client_queue_len = 0;
static pthread_mutex_t g_fs_client_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_fs_client_queue_cv = PTHREAD_COND_INITIALIZER;

/* Supervisor liveness for the file-market threads. Root children (not
 * supervisor_register_in_domain(...)): core/modules/net cannot include the app-side
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

bool fs_conn_budget_ok(uint64_t bytes_sent, int64_t start_monotonic_ms,
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

static bool fs_conn_deadline_ms(const struct fs_session *session,
                                int64_t *deadline_ms)
{
    int64_t budget_ms = (int64_t)FS_CONN_MAX_SECONDS * 1000;
    if (!session || !deadline_ms || session->start_monotonic_ms <= 0 ||
        session->start_monotonic_ms > INT64_MAX - budget_ms)
        return false;
    *deadline_ms = session->start_monotonic_ms + budget_ms;
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
    if (atomic_load(&g_fs_running) && g_fs_client_queue_len < FS_CLIENT_QUEUE_CAP) {
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
    /* Timed wait bounds shutdown even if its broadcast is skipped. */
    while (g_fs_client_queue_len == 0 && atomic_load(&g_fs_running)) {
        struct timespec deadline;
        platform_time_realtime_timespec(&deadline);
        deadline.tv_sec += 2;
        pthread_cond_timedwait(&g_fs_client_queue_cv,
                               &g_fs_client_queue_mutex, &deadline);
    }

    if (g_fs_client_queue_len == 0) {
        pthread_mutex_unlock(&g_fs_client_queue_mutex);
        return false; /* normal shutdown */
    }

    *slot_out = g_fs_client_queue[g_fs_client_queue_head];
    g_fs_client_queue_head = (g_fs_client_queue_head + 1U) % FS_CLIENT_QUEUE_CAP;
    g_fs_client_queue_len--;
    pthread_mutex_unlock(&g_fs_client_queue_mutex);
    return true;
}

static void fs_client_queue_close_all(void)
{
    pthread_mutex_lock(&g_fs_client_queue_mutex);
    while (g_fs_client_queue_len > 0) {
        int client_fd = g_fs_client_queue[g_fs_client_queue_head].fd;
        g_fs_client_queue_head = (g_fs_client_queue_head + 1U) % FS_CLIENT_QUEUE_CAP;
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
        int64_t now = platform_time_monotonic_ms();
        if (!fs_conn_budget_ok(session->bytes_sent,
                               session->start_monotonic_ms, now)) {
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
    if (!fs_conn_budget_ok(session->bytes_sent, session->start_monotonic_ms,
                           platform_time_monotonic_ms())) {
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
    if (!fs_conn_budget_ok(session->bytes_sent, session->start_monotonic_ms,
                           platform_time_monotonic_ms())) {
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

/* Artifact-catalog buffers: 8 rom_seed_directory_json entries wrapped in
 * {"artifacts":[...]}, sized to the LARGEST shape (a source bundle carries a
 * third 64-hex field, ~360 B); overflow DROPS entries, so undersizing hides. */
#define FS_ROM_LIST_ARTS_MAX  4096u
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
    if (!fs_conn_budget_ok(session->bytes_sent, session->start_monotonic_ms,
                           platform_time_monotonic_ms())) {
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
        return;
    }
    /* After the handshake session.peer_nonce is the 32-byte token the client
     * presented — a PoW solution must be bound to it. */

    struct file_manifest manifest = {0};
    int64_t connection_deadline_ms = 0;
    if (!fs_conn_deadline_ms(&session, &connection_deadline_ms)) {
        fs_gate_log_throttled("connection_deadline_unavailable", 0);
        fs_session_cleanup(&session);
        return;
    }

    while (atomic_load(&g_fs_running)) {
        if (!fs_conn_budget_ok(session.bytes_sent,
                               session.start_monotonic_ms,
                               platform_time_monotonic_ms())) {
            fs_gate_log_throttled("connection_lifetime_exceeded", 0);
            break;
        }
        bool have_manifest = atomic_load(&g_have_manifest);
        uint8_t type;
        const uint8_t *payload;
        uint32_t plen;
        if (!fs_recv_frame_until(&session, &type, &payload, &plen,
                                 connection_deadline_ms))
            break;
        if (!fs_conn_budget_ok(session.bytes_sent,
                               session.start_monotonic_ms,
                               platform_time_monotonic_ms())) {
            fs_gate_log_throttled("connection_lifetime_exceeded", 0);
            break;
        }

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
}

static void *fs_client_worker_thread(void *arg)
{
    int *active_fd = arg;

    while (true) {
        struct fs_client_slot slot = { .fd = -1 };
        if (!fs_client_queue_pop(&slot))
            break;
        thread_liveness_beat(&g_fs_wkr_liveness, -1);
        pthread_mutex_lock(&g_fs_active_mutex);
        bool serve = atomic_load(&g_fs_running);
        if (serve)
            *active_fd = slot.fd;
        pthread_mutex_unlock(&g_fs_active_mutex);
        if (serve && slot.fd >= 0)
            fs_handle_client_fd(slot.fd, slot.ip);
        pthread_mutex_lock(&g_fs_active_mutex);
        *active_fd = -1;
        if (slot.fd >= 0)
            close(slot.fd);
        pthread_mutex_unlock(&g_fs_active_mutex);
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

    /* Resolve an OS-assigned port before publishing it under the state mutex. */
    uint16_t resolved_port = g_fs_port;
    if (resolved_port == 0) {
        struct sockaddr_in6 bound;
        socklen_t blen = sizeof(bound);
        if (getsockname(listen_fd, (struct sockaddr *)&bound, &blen) == 0)
            resolved_port = ntohs(bound.sin6_port);
    }

    if (listen(listen_fd, 32) < 0 ||
        fcntl(listen_fd, F_SETFL, O_NONBLOCK) < 0) {
        close(listen_fd);
        LOG_NULL("filesvc", "server_thread: nonblocking listen failed: %s", strerror(errno));
    }
    log_jsonf(LOG_JSON_INFO, "file_service_listening",
              "\"port\":%d,\"transport\":\"x25519_hkdf_sha3\"",
              resolved_port);

    pthread_mutex_lock(&g_fs_state_mutex);
    g_fs_port = resolved_port;
    g_fs_listen_fd = listen_fd;
    pthread_mutex_unlock(&g_fs_state_mutex);

    uint8_t utxo_root[32];
    memset(utxo_root, 0, 32);

    while (atomic_load(&g_fs_running)) {
        thread_liveness_beat(&g_fs_server_liveness, -1);

        struct sockaddr_in6 client_addr;
        socklen_t client_len = sizeof(client_addr);

        /* Darwin accept ignores SO_RCVTIMEO; poll and nonblocking fd bound stop. */
        struct pollfd ready = { .fd = listen_fd, .events = POLLIN };
        if (poll(&ready, 1, 200) <= 0 || !(ready.revents & POLLIN))
            continue;
        int client_fd = accept(listen_fd,
                                (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;
        int client_flags = fcntl(client_fd, F_GETFL, 0);
        if (client_flags < 0 ||
            fcntl(client_fd, F_SETFL, client_flags & ~O_NONBLOCK) < 0) {
            close(client_fd);
            continue;
        }

        /* Bound a peer that goes silent mid-frame. */
        struct timeval ctv = { .tv_sec = 30, .tv_usec = 0 };
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &ctv, sizeof(ctv));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &ctv, sizeof(ctv));

        /* Capture the peer for per-IP caps. */
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

/* Diagnostics for the live file-service state. */
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
    while (atomic_load(&g_fs_stopping))
        pthread_cond_wait(&g_fs_stop_cv, &g_fs_state_mutex);
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
        g_fs_active_fds[i] = -1;
        if (thread_registry_spawn("zcl_fs_wkr", fs_client_worker_thread,
                                      &g_fs_active_fds[i],
                                      &g_fs_worker_threads[i]) != 0) {
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
        atomic_store(&g_fs_stopping, true);
        pthread_cond_broadcast(&g_fs_client_queue_cv);
        pthread_mutex_unlock(&g_fs_state_mutex);
        fprintf(stderr,  // obs-ok:file-service-startup-failure
                "file_service: failed to start server thread\n");
        for (unsigned i = 0; i < started_workers; i++)
            pthread_join(g_fs_worker_threads[i], NULL);
        g_fs_worker_threads_started = 0;
        thread_liveness_retire(&g_fs_wkr_liveness);
        pthread_mutex_lock(&g_fs_state_mutex);
        atomic_store(&g_fs_stopping, false);
        pthread_cond_broadcast(&g_fs_stop_cv);
        pthread_mutex_unlock(&g_fs_state_mutex);
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
    if (atomic_load(&g_fs_stopping)) {
        while (atomic_load(&g_fs_stopping))
            pthread_cond_wait(&g_fs_stop_cv, &g_fs_state_mutex);
        pthread_mutex_unlock(&g_fs_state_mutex);
        return;
    }
    atomic_store(&g_fs_stopping, true);
    atomic_store(&g_fs_running, false);
    listen_fd = g_fs_listen_fd;
    g_fs_listen_fd = -1;
    if (listen_fd >= 0)
        (void)shutdown(listen_fd, SHUT_RDWR);
    have_server = g_fs_thread_started;
    server_thread = g_fs_thread;
    g_fs_thread_started = false;
    have_manifest = g_fs_manifest_thread_started;
    manifest_thread = g_fs_manifest_thread;
    g_fs_manifest_thread_started = false;
    worker_threads_started = g_fs_worker_threads_started;
    for (unsigned i = 0; i < worker_threads_started; i++)
        worker_threads[i] = g_fs_worker_threads[i];
    g_fs_worker_threads_started = 0;
    pthread_mutex_unlock(&g_fs_state_mutex);
    pthread_cond_broadcast(&g_fs_client_queue_cv);
    fs_client_queue_close_all();
    pthread_mutex_lock(&g_fs_active_mutex);
    for (unsigned i = 0; i < worker_threads_started; i++)
        if (g_fs_active_fds[i] >= 0)
            (void)shutdown(g_fs_active_fds[i], SHUT_RDWR);
    pthread_mutex_unlock(&g_fs_active_mutex);
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
    pthread_mutex_lock(&g_fs_state_mutex);
    atomic_store(&g_fs_stopping, false);
    pthread_cond_broadcast(&g_fs_stop_cv);
    pthread_mutex_unlock(&g_fs_state_mutex);
}

#endif /* _WIN32 */
