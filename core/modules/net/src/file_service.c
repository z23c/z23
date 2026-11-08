#if !defined(_WIN32)
#define _GNU_SOURCE  /* pthread_timedjoin_np */
#endif

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fast File Service — SHA3-encrypted direct TCP transfer.
 * Designed for maximum throughput: 64KB fixed frames, zero protocol
 * overhead visible to observers, wire-speed on gigabit links. */

#include "platform/time_compat.h"
#include "base/hex.h"
#include "platform/socket_compat.h"
#include "platform/thread_compat.h"
#include "platform/file_sync.h"
#include "platform/barrier.h"
#include "net/net_runtime_port.h"
#include "net/file_manifest.h"
#include "net/file_market_delivery.h"
#include "net/file_service.h"
#include "net/file_service_generation.h"
#include "net/tor_integration.h"
#include "net/netbase.h"
#include "file_service_worker_internal.h"
#include "file_service_priv.h"
#include "net/rom_seed.h"
#include "util/log_json.h"
#include "util/safe_alloc.h"
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

static platform_socket_t fs_listen_fd_snapshot(void);

bool fs_server_listener_name(char *text, size_t text_size, uint16_t *port)
{
    return platform_socket_local_name(fs_listen_fd_snapshot(), text, text_size,
                                      port);
}

#if defined(_WIN32)

#include <errno.h>
#include <string.h>

bool fs_server_start(const char *datadir, uint16_t port, const char *bind_address)
{ (void)datadir; (void)port; (void)bind_address; errno = ENOTSUP; return true; }
static platform_socket_t fs_listen_fd_snapshot(void)
{ return PLATFORM_SOCKET_INVALID; }
void fs_server_stop(void) {}
bool fs_server_is_running(void) { return false; }
#ifdef ZCL_TESTING
void fs_server_onion_stop_hook_for_test(void (*hook)(void)) { (void)hook; }

#endif
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
static struct fs_history_generation g_fs_history;
static _Atomic bool g_fs_history_active;
static char g_fs_snapshot_datadir[1024];
static uint64_t g_fs_epoch;
#ifdef ZCL_TESTING
static _Atomic int g_test_fs_spawn_failure = -1;
static _Atomic(void (*)(void)) g_test_history_before_read;
static _Atomic(bool (*)(struct file_manifest *, const char *)) g_test_refresh_builder;
void fs_server_test_spawn_failure(int index);
void fs_server_test_history_before_read(void (*hook)(void));
void fs_server_test_refresh_builder(bool (*builder)(struct file_manifest *, const char *));
void fs_server_test_spawn_failure(int index)
{
    atomic_store(&g_test_fs_spawn_failure, index);
}
void fs_server_test_history_before_read(void (*hook)(void))
{
    atomic_store(&g_test_history_before_read, hook);
}
void fs_server_test_refresh_builder(bool (*builder)(struct file_manifest *, const char *))
{
    atomic_store(&g_test_refresh_builder, builder);
}
#endif
static uint16_t g_fs_port = FS_PORT;
static struct sockaddr_storage g_fs_addr;
static socklen_t g_fs_addr_len;
static pthread_mutex_t g_fs_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static enum fs_onion_decision g_fs_onion_decision = FS_ONION_PENDING;
static uint64_t g_fs_onion_generation;
static bool g_fs_onion_pinned;
static bool g_fs_onion_published;
static bool g_fs_tor_retired = true;

#ifdef ZCL_TESTING
static void (*g_fs_onion_stop_hook)(void);
static _Atomic bool g_fs_test_fatal;

void fs_server_onion_stop_hook_for_test(void (*hook)(void))
{
    g_fs_onion_stop_hook = hook;
}

#endif

static void fs_onion_stop_tor(void)
{
#ifdef ZCL_TESTING
    if (g_fs_onion_stop_hook) {
        g_fs_onion_stop_hook();
        return;
    }
#endif
    tor_integration_stop();
}


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


static bool fs_snapshot_serving_allowed(void)
{
    return net_runtime_snapshot_artifact_is_eligible(g_fs_datadir, NULL, 0);
}

static bool fs_server_rebuild_manifest_locked(struct file_manifest *out,
                                               const char *datadir)
{
    struct file_manifest next = {0};
    int64_t t0 = (int64_t)platform_time_wall_time_t();
    bool ok;

    pthread_mutex_lock(&g_manifest_build_mutex);
    ok = file_manifest_build(&next, datadir);
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
    bool ok = fs_server_rebuild_manifest_locked(&next, g_fs_datadir);
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
    pthread_mutex_lock(&g_fs_state_mutex);
    if (g_fs_history_active) {
        pthread_mutex_unlock(&g_fs_state_mutex);
        LOG_FAIL("filesvc", "refresh_manifest: retained history is immutable");
    }
    if (!g_fs_datadir || !atomic_load(&g_fs_running) || atomic_load(&g_fs_stopping)) {
        pthread_mutex_unlock(&g_fs_state_mutex);
        LOG_FAIL("filesvc", "refresh_manifest: server is not running");
    }
    char *datadir = strdup(g_fs_datadir);
    uint64_t epoch = g_fs_epoch;
    pthread_mutex_unlock(&g_fs_state_mutex);
    if (!datadir)
        LOG_FAIL("filesvc", "refresh_manifest: cannot copy datadir");
    bool ok;
#ifdef ZCL_TESTING
    bool (*builder)(struct file_manifest *, const char *) = atomic_load(&g_test_refresh_builder);
    if (builder)
        ok = builder(&next, datadir);
    else
#endif
        ok = fs_server_rebuild_manifest_locked(&next, datadir);
    free(datadir);
    pthread_mutex_lock(&g_fs_state_mutex);
    if (epoch != g_fs_epoch || g_fs_history_active ||
        !atomic_load(&g_fs_running) || atomic_load(&g_fs_stopping)) {
        pthread_mutex_unlock(&g_fs_state_mutex);
        return false;
    }
    pthread_mutex_lock(&g_manifest_mutex);
    g_server_fm = next;
    pthread_mutex_unlock(&g_manifest_mutex);
    atomic_store(&g_have_manifest, ok);
    pthread_mutex_unlock(&g_fs_state_mutex);
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


/* Stream manifest chunks [start,end) with per-connection + per-IP budgets.
 * The served bytes are byte-identical to the ungated path; the caps only bound
 * how much a single connection/IP may draw. Stops the range early (keeping the
 * connection) when a budget trips or a chunk read fails. */
void fs_stream_range(struct fs_session *session,
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
#ifdef ZCL_TESTING
        void (*hook)(void) = atomic_load(&g_test_history_before_read);
        if (g_fs_history_active && hook)
            hook();
#endif
        bool read_ok = g_fs_history_active ?
            fs_history_generation_read(&g_fs_history, ci, &data, &dsz) :
            file_chunk_read(&manifest->chunks[ci], g_fs_datadir, &data, &dsz);
        if (!read_ok) {
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
static bool fs_rom_artifact_allowed(const struct rom_artifact *art)
{
    return !g_fs_history_active ||
           (art->kind == ROM_ARTIFACT_CONSENSUS_BUNDLE &&
            memcmp(art->whole_sha3, g_fs_history.snapshot_digest, 32) == 0);
}

static void fs_serve_rom_chunk(struct fs_session *session,
                               const uint8_t client_ip[16],
                               const uint8_t root[32], uint32_t idx)
{
    struct rom_artifact art;
    if (rom_seed_serve_lookup(root, idx, &art) != ROM_SERVE_FREE_OK ||
        !fs_rom_artifact_allowed(&art)) {
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
    const char *rom_datadir = g_fs_history_active ? g_fs_snapshot_datadir : g_fs_datadir;
    if (!rom_seed_read_chunk(&art, rom_datadir, idx, buf, art.chunk_size, &sz)) {
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
    if (!rom_seed_enabled() || !rom_seed_find_by_root(root, &art) ||
        !fs_rom_artifact_allowed(&art)) {
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

static size_t fs_history_directory_json(char *out, size_t cap)
{
    struct rom_artifact *arts = zcl_calloc(ROM_SEED_MAX_ARTIFACTS, sizeof(*arts), "ROM artifact catalog");
    if (!arts)
        return 0;
    int count = rom_seed_list(arts, ROM_SEED_MAX_ARTIFACTS);
    int n = snprintf(out, cap, "[]");
    for (int i = 0; i < count; i++) {
        if (!fs_rom_artifact_allowed(&arts[i]))
            continue;
        char chunk[65], whole[65];
        zcl_hex_encode(arts[i].chunk_root, 32, chunk);
        zcl_hex_encode(arts[i].whole_sha3, 32, whole);
        n = snprintf(out, cap, "[{\"kind\":\"consensus_bundle\",\"digest\":\"%s\","
            "\"whole_sha3\":\"%s\",\"size\":%llu,\"chunk_size\":%u,"
            "\"chunks\":%u,\"height\":%d}]", chunk, whole,
            (unsigned long long)arts[i].size_bytes, arts[i].chunk_size,
            arts[i].num_chunks, g_fs_history.endpoint_height);
        break;
    }
    free(arts);
    return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

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
    size_t an = g_fs_history_active ? fs_history_directory_json(arts, sizeof(arts)) :
                                      rom_seed_directory_json(arts, sizeof(arts));
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

/* Outcome of the per-request-frame dispatch for one received frame. */
enum fs_request_step {
    FS_REQUEST_STEP_STOP,
    FS_REQUEST_STEP_NEXT,
    FS_REQUEST_STEP_FALL,
};


static enum fs_request_step fs_client_serve_request(
    struct fs_session *session, const uint8_t client_ip[16],
    const uint8_t *payload, uint32_t plen)
{
    if (file_market_delivery_is_request(payload, plen)) {
        if (!file_market_delivery_serve(session, client_ip,
                                        payload, plen))
            return FS_REQUEST_STEP_STOP;
        return FS_REQUEST_STEP_NEXT;
    }
    /* Free ROM requests use independent rom_seed caps. */
    uint8_t rom_root[32];
    uint32_t rom_idx = 0;
    if (fs_parse_rom_request(payload, plen, rom_root, &rom_idx)) {
        fs_serve_rom_chunk(session, client_ip, rom_root, rom_idx);
        return FS_REQUEST_STEP_NEXT;
    }
    uint8_t rmf_root[32];
    if (fs_parse_rom_manifest_request(payload, plen, rmf_root)) {
        fs_serve_rom_manifest(session, client_ip, rmf_root);
        return FS_REQUEST_STEP_NEXT;
    }
    if (fs_parse_rom_list_request(payload, plen)) {
        fs_serve_rom_list(session, client_ip);
        return FS_REQUEST_STEP_NEXT;
    }
    return FS_REQUEST_STEP_FALL;
}


/* Handle one received frame: false means stop serving this connection. */
static bool fs_client_dispatch(struct fs_session *session,
                               const struct file_manifest *manifest,
                               const uint8_t client_ip[16],
                               uint8_t type, const uint8_t *payload,
                               uint32_t plen, bool have_manifest,
                               bool snapshot_allowed)
{
    /* Client explicitly asks for a challenge before requesting bulk data. */
    if (type == FS_CHALLENGE)
        return fs_client_serve_challenge(session);

    if (type == FS_REQUEST) {
        enum fs_request_step step =
            fs_client_serve_request(session, client_ip, payload, plen);
        if (step != FS_REQUEST_STEP_FALL)
            return step == FS_REQUEST_STEP_NEXT;
    }

    bool is_all = false, is_rng = false;
    const uint8_t *puzzle = NULL;
    uint16_t rng_start = 0, rng_end = 0;
    bool is_serve = (type == FS_REQUEST) &&
        fs_parse_serve_request(payload, plen, &is_all, &is_rng,
                               &puzzle, &rng_start, &rng_end);

    if (is_serve && (is_all || is_rng) && have_manifest)
        return fs_client_serve_gated(session, manifest, client_ip,
                                     snapshot_allowed, puzzle, is_rng,
                                     rng_start, rng_end);
    if (type == FS_MANIFEST && have_manifest)
        return fs_client_serve_manifest(session, manifest, snapshot_allowed);
    return type != FS_DONE;
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
        if (!fs_client_budget_check(&session))
            break;
        bool have_manifest = atomic_load(&g_have_manifest);
        uint8_t type;
        const uint8_t *payload;
        uint32_t plen;
        if (!fs_client_recv_checked(&session, &type, &payload, &plen,
                                    connection_deadline_ms))
            break;

        if (have_manifest) {
            pthread_mutex_lock(&g_manifest_mutex);
            manifest = g_server_fm;
            pthread_mutex_unlock(&g_manifest_mutex);
        }
        bool snapshot_allowed = !g_fs_history_active && fs_snapshot_serving_allowed();

        if (!fs_client_dispatch(&session, &manifest, client_ip, type, payload,
                                plen, have_manifest, snapshot_allowed))
            break;
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

/* A fatal listener exit cannot close a mapped fd until Tor has joined. */
static void fs_listener_fatal_retire(void)
{
    pthread_mutex_lock(&g_fs_state_mutex);
    if (atomic_load(&g_fs_stopping)) {
        while (!g_fs_tor_retired)
            pthread_cond_wait(&g_fs_stop_cv, &g_fs_state_mutex);
        pthread_mutex_unlock(&g_fs_state_mutex);
        return;
    }
    atomic_store(&g_fs_stopping, true);
    g_fs_epoch++;
    g_fs_onion_decision = FS_ONION_RETIRING;
    g_fs_onion_published = false;
    bool pinned = g_fs_onion_pinned;
    g_fs_tor_retired = !pinned;
    pthread_mutex_unlock(&g_fs_state_mutex);
    if (pinned)
        fs_onion_stop_tor();
    pthread_mutex_lock(&g_fs_state_mutex);
    g_fs_tor_retired = true;
    atomic_store(&g_fs_running, false);
    g_fs_onion_decision = FS_ONION_FAILED;
    g_fs_onion_pinned = false;
    g_fs_listen_fd = -1;
    atomic_store(&g_fs_stopping, false);
    pthread_cond_broadcast(&g_fs_stop_cv);
    pthread_mutex_unlock(&g_fs_state_mutex);
    pthread_cond_broadcast(&g_fs_client_queue_cv);
}

static int fs_listener_wait(int fd)
{
#ifdef ZCL_TESTING
    if (atomic_exchange(&g_fs_test_fatal, false))
        return -1;
#endif
    struct pollfd ready = { .fd = fd, .events = POLLIN };
    int result = poll(&ready, 1, 200);
    if ((result < 0 && errno != EINTR) ||
        (result > 0 && (ready.revents & (POLLERR | POLLHUP | POLLNVAL))))
        return -1;
    return result > 0 && (ready.revents & POLLIN) ? 1 : 0;
}

static bool fs_listener_publish(int fd, uint16_t port)
{
    pthread_mutex_lock(&g_fs_state_mutex);
    if (atomic_load(&g_fs_stopping) || !g_fs_worker_threads_started) {
        if (!atomic_load(&g_fs_stopping))
            g_fs_onion_decision = FS_ONION_FAILED;
        pthread_mutex_unlock(&g_fs_state_mutex);
        return false;
    }
    g_fs_port = port;
    g_fs_listen_fd = fd;
    g_fs_onion_generation++;
    g_fs_onion_decision = FS_ONION_AVAILABLE;
    pthread_mutex_unlock(&g_fs_state_mutex);
    return true;
}

static int fs_listener_accept(int fd, struct sockaddr_in6 *addr)
{
    socklen_t len = sizeof(*addr);
    int client = accept(fd, (struct sockaddr *)addr, &len);
    if (client < 0)
        return -1;
    int flags = fcntl(client, F_GETFL, 0);
    if (flags < 0 || fcntl(client, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        close(client);
        return -1;
    }
    return client;
}

static void *fs_server_thread(void *arg)
{
    (void)arg;

    int listen_fd = socket(g_fs_addr.ss_family, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        fs_server_onion_decide(FS_ONION_FAILED);
        LOG_NULL("filesvc", "server_thread: socket() failed: %s", strerror(errno));
    }

    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    int zero = 0;
    setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));

    if (bind(listen_fd, (struct sockaddr *)&g_fs_addr, g_fs_addr_len) < 0) {
        close(listen_fd);
        fs_server_onion_decide(FS_ONION_FAILED);
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
        fs_server_onion_decide(FS_ONION_FAILED);
        LOG_NULL("filesvc", "server_thread: nonblocking listen failed: %s", strerror(errno));
    }
    log_jsonf(LOG_JSON_INFO, "file_service_listening",
              "\"port\":%d,\"transport\":\"x25519_hkdf_sha3\"",
              resolved_port);

    if (!fs_listener_publish(listen_fd, resolved_port)) {
        close(listen_fd);
        return NULL;
    }

    uint8_t utxo_root[32];
    memset(utxo_root, 0, 32);

    while (atomic_load(&g_fs_running)) {
        thread_liveness_beat(&g_fs_server_liveness, -1);

        struct sockaddr_in6 client_addr;

        /* Darwin accept ignores SO_RCVTIMEO; poll and nonblocking fd bound stop. */
        int poll_result = fs_listener_wait(listen_fd);
        if (poll_result < 0) {
            fs_listener_fatal_retire();
            break;
        }
        if (poll_result == 0)
            continue;
        int client_fd = fs_listener_accept(listen_fd, &client_addr);
        if (client_fd < 0) continue;

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
    running = atomic_load(&g_fs_running) && !atomic_load(&g_fs_stopping) &&
              g_fs_listen_fd >= 0;
    pthread_mutex_unlock(&g_fs_state_mutex);
    return running;
}

static platform_socket_t fs_listen_fd_snapshot(void)
{
    pthread_mutex_lock(&g_fs_state_mutex);
    platform_socket_t fd = g_fs_listen_fd >= 0 ? g_fs_listen_fd
                                                : PLATFORM_SOCKET_INVALID;
    pthread_mutex_unlock(&g_fs_state_mutex);
    return fd;
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

static int fs_server_spawn(const char *name, void *(*fn)(void *), void *arg,
                           pthread_t *thread, int index)
{
#ifdef ZCL_TESTING
    if (atomic_load(&g_test_fs_spawn_failure) == index) {
        atomic_store(&g_test_fs_spawn_failure, -1);
        return EAGAIN;
    }
#else
    (void)index;
#endif
    return thread_registry_spawn(name, fn, arg, thread);
}

static unsigned fs_server_start_workers(void)
{
    unsigned count = 0;
    for (unsigned i = 0; i < FS_SERVER_WORKERS; i++) {
        g_fs_active_fds[i] = -1;
        if (fs_server_spawn("zcl_fs_wkr", fs_client_worker_thread,
                            &g_fs_active_fds[i], &g_fs_worker_threads[i],
                            (int)i) != 0) {
            fprintf(stderr,  // obs-ok:file-service-startup-failure
                    "file_service: failed to start worker %u\n", i);
            break;
        }
        count++;
    }
    g_fs_worker_threads_started = count;
    if (count > 0)
        thread_liveness_register(&g_fs_wkr_liveness, "zcl_fs_wkr", 0, 0);
    return count;
}

/* Called with the state lock held; returns with it released. */
static void fs_server_start_failed(unsigned workers, bool history)
{
    g_fs_onion_decision = FS_ONION_FAILED;
    atomic_store(&g_fs_running, false);
    atomic_store(&g_fs_stopping, true);
    pthread_cond_broadcast(&g_fs_client_queue_cv);
    pthread_mutex_unlock(&g_fs_state_mutex);
    fprintf(stderr,  // obs-ok:file-service-startup-failure
            "file_service: failed to start server or worker thread\n");
    for (unsigned i = 0; i < workers; i++)
        pthread_join(g_fs_worker_threads[i], NULL);
    g_fs_worker_threads_started = 0;
    thread_liveness_retire(&g_fs_wkr_liveness);
    pthread_mutex_lock(&g_fs_state_mutex);
    if (history) {
        g_fs_history_active = false;
        fs_history_generation_init(&g_fs_history);
        atomic_store(&g_have_manifest, false);
    }
    atomic_store(&g_fs_stopping, false);
    pthread_cond_broadcast(&g_fs_stop_cv);
    pthread_mutex_unlock(&g_fs_state_mutex);
}

static bool fs_history_start_valid(const struct fs_history_generation *generation,
                                   const char *snapshot_datadir)
{
    return !generation || (generation->ready && snapshot_datadir &&
        snapshot_datadir[0] && strlen(snapshot_datadir) < sizeof(g_fs_snapshot_datadir));
}

static bool fs_server_start_common(const char *datadir, uint16_t port, const char *bind_address,
                                   struct fs_history_generation *generation,
                                   const char *snapshot_datadir)
{
    if (!fs_history_start_valid(generation, snapshot_datadir))
        return false;
    struct sockaddr_storage listen_addr;
    socklen_t listen_len = 0;
    if (!platform_socket_listen_address(bind_address, port, true, &listen_addr,
                                        &listen_len)) {
        LOG_ERROR("filesvc", "the file service will not listen: bind address "
                             "'%s' is not a literal IPv4 or IPv6 address",
                  bind_address);
        return false;
    }
    pthread_mutex_lock(&g_fs_state_mutex);
    while (atomic_load(&g_fs_stopping))
        pthread_cond_wait(&g_fs_stop_cv, &g_fs_state_mutex);
    if (generation && thread_registry_shutdown_requested()) {
        pthread_mutex_unlock(&g_fs_state_mutex);
        return false;
    }
    if (atomic_load(&g_fs_running) || g_fs_thread_started) {
        pthread_mutex_unlock(&g_fs_state_mutex);
        return generation == NULL;
    }
    if (generation) {
        snprintf(g_fs_snapshot_datadir, sizeof(g_fs_snapshot_datadir), "%s", snapshot_datadir);
        fs_history_generation_init(&g_fs_history);
        g_fs_history = *generation;
        g_fs_history_active = true;
        pthread_mutex_lock(&g_manifest_mutex);
        g_server_fm = generation->manifest;
        pthread_mutex_unlock(&g_manifest_mutex);
    }
    g_fs_datadir = datadir;
    g_fs_epoch++;
    g_fs_onion_decision = FS_ONION_PENDING;
    g_fs_onion_pinned = false;
    g_fs_port = port;
    g_fs_addr = listen_addr;
    g_fs_addr_len = listen_len;
    atomic_store(&g_fs_running, true);
    atomic_store(&g_have_manifest, generation != NULL);
    /* Fresh PoW gate + per-IP cap tables for this serving session. */
    fs_pow_reset_state();
    g_fs_client_queue_head = 0;
    g_fs_client_queue_tail = 0;
    g_fs_client_queue_len = 0;
    unsigned started_workers = fs_server_start_workers();
    if ((generation && started_workers != FS_SERVER_WORKERS) ||
        fs_server_spawn("zcl_fs_server", fs_server_thread, NULL, &g_fs_thread,
                        FS_SERVER_WORKERS) != 0) {
        fs_server_start_failed(started_workers, generation != NULL);
        return generation == NULL;
    }
    if (generation) fs_history_generation_init(generation);
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
    return true;
}

bool fs_server_start(const char *datadir, uint16_t port, const char *bind_address)
{ return fs_server_start_common(datadir, port, bind_address, NULL, NULL); }

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
    while (atomic_load(&g_fs_stopping))
        pthread_cond_wait(&g_fs_stop_cv, &g_fs_state_mutex);
    atomic_store(&g_fs_stopping, true);
    g_fs_epoch++;
    g_fs_onion_decision = FS_ONION_RETIRING;
    g_fs_onion_published = false;
    bool pinned = g_fs_onion_pinned;
    g_fs_tor_retired = !pinned;
    pthread_mutex_unlock(&g_fs_state_mutex);
    if (pinned)
        fs_onion_stop_tor();
    pthread_mutex_lock(&g_fs_state_mutex);
    g_fs_tor_retired = true;
    pthread_cond_broadcast(&g_fs_stop_cv);
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
    if (g_fs_history_active) {
        fs_history_generation_close(&g_fs_history);
        g_fs_snapshot_datadir[0] = '\0';
        g_fs_history_active = false;
        atomic_store(&g_have_manifest, false);
    }
    g_fs_onion_pinned = false;
    g_fs_onion_decision = FS_ONION_DISABLED;
    atomic_store(&g_fs_stopping, false);
    pthread_cond_broadcast(&g_fs_stop_cv);
    pthread_mutex_unlock(&g_fs_state_mutex);
}

#endif /* _WIN32 */
#ifdef ZCL_TESTING
void fs_server_onion_fatal_for_test(void)
{
#if defined(_WIN32)
    return;
#else
    atomic_store(&g_fs_test_fatal, true);
#endif
}
#endif
void fs_server_onion_decide(enum fs_onion_decision decision)
{
#if defined(_WIN32)
    (void)decision;
#else
    if (decision != FS_ONION_DISABLED && decision != FS_ONION_DEFERRED &&
        decision != FS_ONION_FAILED)
        return;
    pthread_mutex_lock(&g_fs_state_mutex);
    if (!atomic_load(&g_fs_stopping) && g_fs_listen_fd < 0)
        g_fs_onion_decision = decision;
    pthread_mutex_unlock(&g_fs_state_mutex);
#endif
}

bool fs_server_onion_retiring(void)
{
#if defined(_WIN32)
    return false;
#else
    pthread_mutex_lock(&g_fs_state_mutex);
    bool retiring = atomic_load(&g_fs_stopping);
    pthread_mutex_unlock(&g_fs_state_mutex);
    return retiring;
#endif
}

bool fs_server_onion_pin(struct fs_onion_listener *out)
{
#if defined(_WIN32)
    if (!out) return false;
    *out = (struct fs_onion_listener){ .decision = FS_ONION_FAILED, .fd = -1 };
    return true;
#else
    if (!out)
        return false;
    *out = (struct fs_onion_listener){ .fd = -1 };
    pthread_mutex_lock(&g_fs_state_mutex);
    out->decision = g_fs_onion_decision;
    if (atomic_load(&g_fs_stopping))
        out->decision = FS_ONION_RETIRING;
    if (out->decision == FS_ONION_AVAILABLE) {
        out->fd = g_fs_listen_fd;
        out->generation = g_fs_onion_generation;
        if (out->fd < 0 || !platform_socket_local_name(
                (platform_socket_t)out->fd, out->address,
                sizeof(out->address), &out->port) || !out->port) {
            out->decision = FS_ONION_FAILED;
        } else {
            g_fs_onion_pinned = true;
        }
    }
    pthread_mutex_unlock(&g_fs_state_mutex);
    return true;
#endif
}

bool fs_server_onion_publish(uint64_t generation)
{
#if defined(_WIN32)
    (void)generation;
    return false;
#else
    pthread_mutex_lock(&g_fs_state_mutex);
    bool valid = g_fs_onion_pinned && !atomic_load(&g_fs_stopping) &&
                 g_fs_onion_decision == FS_ONION_AVAILABLE &&
                 g_fs_listen_fd >= 0 && generation == g_fs_onion_generation;
    g_fs_onion_published = valid;
    pthread_mutex_unlock(&g_fs_state_mutex);
    return valid;
#endif
}

void fs_server_onion_unpublish(void)
{
#if !defined(_WIN32)
    pthread_mutex_lock(&g_fs_state_mutex);
    g_fs_onion_published = false;
    pthread_mutex_unlock(&g_fs_state_mutex);
#endif
}

bool fs_server_onion_published_port(uint16_t *port)
{
#if defined(_WIN32)
    (void)port;
    return false;
#else
    if (!port)
        return false;
    pthread_mutex_lock(&g_fs_state_mutex);
    bool valid = g_fs_onion_published && g_fs_onion_pinned &&
                 !atomic_load(&g_fs_stopping) && g_fs_listen_fd >= 0 &&
                 g_fs_onion_decision == FS_ONION_AVAILABLE;
    if (valid)
        *port = g_fs_port;
    pthread_mutex_unlock(&g_fs_state_mutex);
    return valid;
#endif
}
bool fs_server_start_with_history(struct fs_history_generation *generation,
                                  const char *snapshot_datadir, uint16_t port,
                                  const char *bind_address)
{
#if defined(_WIN32)
    (void)generation; (void)snapshot_datadir; (void)port; (void)bind_address;
    return false;
#else
    return generation && fs_server_start_common(NULL, port, bind_address, generation, snapshot_datadir);
#endif
}

bool fs_server_history_matches(const uint8_t digest[32], int32_t height,
                               const uint8_t hash[32])
{
#if defined(_WIN32)
    (void)digest; (void)height; (void)hash;
    return false;
#else
    if (!digest || !hash)
        return false;
    pthread_mutex_lock(&g_fs_state_mutex);
    bool matches = g_fs_history_active && atomic_load(&g_fs_running) &&
        !atomic_load(&g_fs_stopping) && g_fs_listen_fd >= 0 &&
        g_fs_history.endpoint_height == height &&
        memcmp(g_fs_history.snapshot_digest, digest, 32) == 0 &&
        memcmp(g_fs_history.endpoint_hash, hash, 32) == 0;
    pthread_mutex_unlock(&g_fs_state_mutex);
    return matches;
#endif
}
