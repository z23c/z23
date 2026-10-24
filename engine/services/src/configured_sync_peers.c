/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: record the operator's explicitly named connection targets, the
 * Noise identity this node authenticated at each of them, and decide whether
 * an inbound session proven to carry that identity may serve headers.
 * The rule and its security argument live in services/configured_sync_peers.h. */

// supervisor-ok:bounded-identity-probe — the only thread is a one-shot identity probe with an absolute per-target deadline, joined before the next one starts and by configured_sync_peers_stop
// one-result-type-ok:configured-sync-peer-predicates — exported bools are pure membership/eligibility answers, not fallible operations
#include "services/configured_sync_peers.h"

#include "sync/sync_planner.h"
#include "net/netbase.h"
#include "net/noise_transport.h"
#include "services/p2p_node_noise.h"
#include "base/cleanse.h"
#include "platform/socket_compat.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Bounds for one identity probe. Connect, every read and every write share
 * one absolute deadline per target; each wait lasts at most one slice so a
 * stop request is seen promptly. XXhfs message 2 is 1200 bytes; anything past
 * PROBE_MAX_BYTES without an established session is not a Noise responder. */
#define PROBE_WAIT_SLICE_MS      100
#define PROBE_MAX_BYTES          2048

struct configured_target {
    struct net_service svc;
    bool have_identity;
    uint8_t identity[32];
    bool probe_running;
    bool probe_finished_once;
    int64_t probe_finished_s;
};

static pthread_mutex_t g_configured_lock = PTHREAD_MUTEX_INITIALIZER;
static struct configured_target g_configured[CONFIGURED_SYNC_PEERS_MAX];
static size_t g_configured_count;
/* Lock-free hint for the per-tick outbound observation fast path. */
static _Atomic size_t g_configured_count_hint;
static const struct net_manager *g_network;
static configured_sync_peer_prober_fn g_test_prober;
static int64_t (*g_test_clock)(void);

static int64_t configured_now_s(void)
{
    if (g_test_clock)
        return g_test_clock();
    return platform_time_monotonic_us() / 1000000;
}

/* A target whose address cannot authenticate an inbound source is never
 * recorded: Tor names have no inbound IP, loopback is where every Tor
 * hidden-service stream arrives from, and an unspecified address matches
 * nothing real. */
static bool configured_address_usable(const struct net_addr *ip)
{
    return ip && net_addr_is_valid(ip) && !net_addr_is_tor(ip) &&
           !net_addr_is_local(ip);
}

static struct configured_target *find_target_locked(
    const struct net_service *svc)
{
    for (size_t i = 0; i < g_configured_count; i++)
        if (net_service_eq(&g_configured[i].svc, svc))
            return &g_configured[i];
    return NULL;
}

bool configured_sync_peer_note(const struct net_service *target)
{
    if (!target || !configured_address_usable(&target->addr))
        return false;  // raw-return-ok:unusable-address-is-refused-by-the-bool
    bool recorded = false;
    pthread_mutex_lock(&g_configured_lock);
    recorded = find_target_locked(target) != NULL;
    if (!recorded && g_configured_count < CONFIGURED_SYNC_PEERS_MAX) {
        struct configured_target *t = &g_configured[g_configured_count++];
        memset(t, 0, sizeof(*t));
        t->svc = *target;
        recorded = true;
    }
    atomic_store(&g_configured_count_hint, g_configured_count);
    pthread_mutex_unlock(&g_configured_lock);
    return recorded;
}

bool configured_sync_peer_forget(const struct net_service *target)
{
    if (!target)
        return false;
    bool removed = false;
    pthread_mutex_lock(&g_configured_lock);
    struct configured_target *t = find_target_locked(target);
    if (t) {
        *t = g_configured[g_configured_count - 1];
        memset(&g_configured[g_configured_count - 1], 0,
               sizeof(g_configured[0]));
        g_configured_count--;
        removed = true;
    }
    atomic_store(&g_configured_count_hint, g_configured_count);
    pthread_mutex_unlock(&g_configured_lock);
    return removed;
}

void configured_sync_peer_record_identity(const struct net_service *target,
                                          const uint8_t remote_static[32])
{
    if (!target || !remote_static)
        return;
    bool changed = false;
    pthread_mutex_lock(&g_configured_lock);
    struct configured_target *t = find_target_locked(target);
    if (t) {
        changed = !t->have_identity ||
                  memcmp(t->identity, remote_static, 32) != 0;
        memcpy(t->identity, remote_static, 32);
        t->have_identity = true;
    }
    pthread_mutex_unlock(&g_configured_lock);
    if (changed) {
        char addr[NET_SERVICE_STR_MAX + 1];
        net_service_to_string(target, addr, sizeof(addr));
        LOG_INFO("header_sync",
                 "configured sync peer identity authenticated on our own "
                 "outbound Noise session: target=%s static=%02x%02x%02x%02x…",
                 addr, remote_static[0], remote_static[1], remote_static[2],
                 remote_static[3]);
    }
}

bool configured_sync_peer_identity(const struct net_service *target,
                                   uint8_t out_static[32])
{
    if (!target || !out_static)
        return false;
    bool have = false;
    pthread_mutex_lock(&g_configured_lock);
    struct configured_target *t = find_target_locked(target);
    if (t && t->have_identity) {
        memcpy(out_static, t->identity, 32);
        have = true;
    }
    pthread_mutex_unlock(&g_configured_lock);
    return have;
}

/* An established Noise session's authenticated remote static, or false. */
static bool session_remote_static(const struct p2p_node *node,
                                  uint8_t out_static[32])
{
    struct noise_transport_snapshot snap;
    if (!p2p_node_noise_snapshot(node, &snap))
        return false;  // raw-return-ok:no-established-noise-session-is-an-answer
    memcpy(out_static, snap.remote_static, 32);
    return true;
}

void configured_sync_peer_observe_outbound(const struct p2p_node *node)
{
    if (!node || node->inbound || node->is_feeler ||
        atomic_load(&g_configured_count_hint) == 0)
        return;
    uint8_t remote[32];
    if (!session_remote_static(node, remote))
        return;
    bool is_target = false;
    pthread_mutex_lock(&g_configured_lock);
    is_target = find_target_locked(&node->addr.svc) != NULL;
    pthread_mutex_unlock(&g_configured_lock);
    if (is_target)
        configured_sync_peer_record_identity(&node->addr.svc, remote);
}

bool syncsvc_peer_is_configured_inbound(const struct p2p_node *node)
{
    if (!node || !node->inbound ||
        atomic_load(&g_configured_count_hint) == 0 ||
        !configured_address_usable(&node->addr.svc.addr))
        return false;  // raw-return-ok:not-a-candidate-is-an-answer
    uint8_t remote[32];
    if (!session_remote_static(node, remote))
        return false;  // raw-return-ok:unauthenticated-session-never-binds
    bool bound = false;
    pthread_mutex_lock(&g_configured_lock);
    for (size_t i = 0; i < g_configured_count && !bound; i++) {
        const struct configured_target *t = &g_configured[i];
        bound = t->have_identity &&
                net_addr_eq(&t->svc.addr, &node->addr.svc.addr) &&
                memcmp(t->identity, remote, 32) == 0;
    }
    pthread_mutex_unlock(&g_configured_lock);
    return bound;
}

bool syncsvc_peer_may_serve_headers(const struct p2p_node *node)
{
    return node && (!node->inbound || syncsvc_peer_is_configured_inbound(node));
}

bool syncsvc_configured_inbound_body_stalled(const struct p2p_node *node,
                                             int our_height,
                                             uint64_t body_received,
                                             uint64_t body_timed_out,
                                             uint64_t dark_received,
                                             uint64_t dark_timed_out,
                                             int64_t last_body_time,
                                             int64_t now_seconds)
{
    if (!syncsvc_peer_is_configured_inbound(node) ||
        node->state < PEER_SYNCING_HEADERS)
        return false;  // raw-return-ok:rules-c-d-cover-only-sync-sources
    return syncsvc_should_disconnect_body_stalled_peer(
               node, our_height, body_received, body_timed_out,
               now_seconds) ||
           syncsvc_should_disconnect_body_dark_peer(
               node, our_height, dark_received, dark_timed_out,
               last_body_time, now_seconds);
}

/* ── identity probe ───────────────────────────────────────────────────── */

void configured_sync_peers_attach_network(const struct net_manager *nm)
{
    pthread_mutex_lock(&g_configured_lock);
    g_network = nm;
    pthread_mutex_unlock(&g_configured_lock);
}

static void probe_finished(const struct net_service *target, bool ok,
                           const uint8_t remote_static[32])
{
    pthread_mutex_lock(&g_configured_lock);
    struct configured_target *t = find_target_locked(target);
    if (t) {
        t->probe_running = false;
        t->probe_finished_once = true;
        t->probe_finished_s = configured_now_s();
    }
    pthread_mutex_unlock(&g_configured_lock);
    char addr[NET_SERVICE_STR_MAX + 1];
    net_service_to_string(target, addr, sizeof(addr));
    if (ok) {
        configured_sync_peer_record_identity(target, remote_static);
        LOG_INFO("header_sync", "configured sync peer identity probe "
                 "completed Noise XX with target=%s", addr);
    } else {
        LOG_WARN("header_sync", "configured sync peer identity probe of "
                 "target=%s did not complete a Noise XX handshake; an inbound "
                 "session from its IP stays refused as a header source", addr);
    }
}

/* One probe thread at a time. It carries its own copy of the local static
 * key and network magic, so it never reads the net manager, which shutdown
 * may free while a probe is still waiting on a socket. */
struct probe_job {
    size_t count;
    struct net_service targets[CONFIGURED_SYNC_PEERS_MAX];
    uint8_t identity_priv[32];
    unsigned char magic[MESSAGE_START_SIZE];
    configured_sync_peer_prober_fn prober;  /* NULL: the network prober */
};

static pthread_mutex_t g_probe_thread_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_probe_tid;
static bool g_probe_tid_live;
static _Atomic bool g_probe_busy;
static _Atomic bool g_probe_stop;
static configured_sync_peer_prober_fn g_test_threaded_prober;
static int64_t (*g_test_clock_ms)(void);

void configured_sync_peers_start(const struct net_manager *nm)
{
    pthread_mutex_lock(&g_probe_thread_lock);
    atomic_store(&g_probe_stop, false);
    configured_sync_peers_attach_network(nm);
    pthread_mutex_unlock(&g_probe_thread_lock);
}

static int64_t probe_now_ms(void)
{
    if (g_test_clock_ms)
        return g_test_clock_ms();
    return platform_time_monotonic_us() / 1000;
}

bool configured_sync_peers_probe_should_stop(void)
{
    return atomic_load(&g_probe_stop) || thread_registry_shutdown_requested();
}

/* Wait until `sock` is readable (or writable) without passing `deadline_ms`,
 * in slices short enough to notice a stop request. An interrupted wait
 * resumes against the same absolute deadline. */
static bool probe_wait(platform_socket_t sock, bool writable,
                       int64_t deadline_ms)
{
    for (;;) {
        int64_t left = deadline_ms - probe_now_ms();
        if (left <= 0 || configured_sync_peers_probe_should_stop())
            return false;  // raw-return-ok:deadline-or-stop-ends-the-probe
        int slice = left < PROBE_WAIT_SLICE_MS ? (int)left : PROBE_WAIT_SLICE_MS;
        int ready = writable ? platform_socket_wait_writable(sock, slice)
                             : platform_socket_wait_readable(sock, slice);
        if (ready > 0)
            return true;
        if (ready < 0 &&
            !platform_socket_error_interrupted(platform_socket_last_error()))
            return false;  // raw-return-ok:socket-error-ends-the-probe
    }
}

static bool probe_retryable(int result)
{
    if (result >= 0)
        return false;
    int error = platform_socket_last_error();
    return platform_socket_error_would_block(error) ||
           platform_socket_error_interrupted(error);
}

static bool probe_send(platform_socket_t sock, const uint8_t *bytes,
                       size_t len, int64_t deadline_ms)
{
    size_t sent = 0;
    while (sent < len) {
        if (!probe_wait(sock, true, deadline_ms))
            return false;  // raw-return-ok:deadline-or-stop-ends-the-probe
        int n = platform_socket_send_nonblocking(sock, bytes + sent,
                                                 len - sent);
        if (n > 0)
            sent += (size_t)n;
        else if (!probe_retryable(n))
            return false;  // raw-return-ok:peer-refused-the-handshake-bytes
    }
    return true;
}

/* Bytes read, 0 when the peer closed, -1 on deadline, stop or error. */
static int probe_receive(platform_socket_t sock, uint8_t *buf, size_t cap,
                         int64_t deadline_ms)
{
    for (;;) {
        if (!probe_wait(sock, false, deadline_ms))
            return -1;  // raw-return-ok:deadline-stop-or-error-is-the-probe-answer
        int n = platform_socket_receive_nonblocking(sock, buf, cap);
        if (!probe_retryable(n))
            return n;
    }
}

/* Drive the initiator side until the session is established. Feeding XX
 * message 2 yields message 3, which is sent so the responder also sees a
 * completed handshake; the socket then closes before any VERSION, so the
 * responder's connection manager never evaluates it as a peer. Bytes that
 * arrive slowly do not extend `deadline_ms`. */
static bool probe_handshake(platform_socket_t sock, struct noise_transport *t,
                            int64_t deadline_ms, uint8_t out_static[32])
{
    uint8_t buf[256];
    size_t total = 0;
    while (total < PROBE_MAX_BYTES) {
        int n = probe_receive(sock, buf, sizeof(buf), deadline_ms);
        if (n <= 0)
            return false;  // raw-return-ok:peer-closed-or-deadline-before-xx-msg2
        total += (size_t)n;
        uint8_t *wire = NULL, *plain = NULL;
        size_t wire_len = 0, plain_len = 0;
        bool fed = noise_transport_feed(t, buf, (size_t)n, &wire, &wire_len,
                                        &plain, &plain_len);
        bool sent = fed && probe_send(sock, wire, wire_len, deadline_ms);
        free(wire);
        free(plain);
        if (!sent)
            return false;  // raw-return-ok:handshake-refused-is-the-probe-answer
        struct noise_transport_snapshot snap;
        if (noise_transport_snapshot(t, &snap)) {
            memcpy(out_static, snap.remote_static, 32);
            return true;
        }
    }
    return false;
}

/* A non-blocking connect that honours the deadline and stop requests. */
static bool probe_connect(const struct net_service *target,
                          int64_t deadline_ms, zcl_socket_t *sock_out)
{
    zcl_socket_t sock = ZCL_INVALID_SOCKET;
    enum zcl_connect_start started = connect_socket_start(target, &sock);
    if (started == ZCL_CONNECT_START_ERROR)
        return false;  // raw-return-ok:unreachable-target-is-the-probe-answer
    if (started != ZCL_CONNECT_START_CONNECTED &&
        (!probe_wait(sock, true, deadline_ms) || !connect_socket_check(sock))) {
        (void)close_socket(&sock);
        return false;  // raw-return-ok:unreachable-target-is-the-probe-answer
    }
    *sock_out = sock;
    return true;
}

/* Dial `target`, complete Noise XX as initiator with `identity_priv`, and
 * return the responder's authenticated static key. Connect, every read and
 * every write share one absolute deadline of CONFIGURED_SYNC_PEER_PROBE_DEADLINE_MS, and a
 * stop request ends the probe within PROBE_WAIT_SLICE_MS. Only table targets
 * reach it, and the table admits no Tor, loopback or unspecified address
 * (configured_sync_peer_note). */
static bool probe_noise_identity(const struct net_service *target,
                                 const uint8_t identity_priv[32],
                                 const unsigned char *magic,
                                 uint8_t out_static[32])
{
    int64_t deadline_ms = probe_now_ms() + CONFIGURED_SYNC_PEER_PROBE_DEADLINE_MS;
    zcl_socket_t sock = ZCL_INVALID_SOCKET;
    if (configured_sync_peers_probe_should_stop() ||
        !probe_connect(target, deadline_ms, &sock))
        return false;  // raw-return-ok:stopped-or-unreachable-target
    uint8_t *msg1 = NULL;
    size_t msg1_len = 0;
    struct noise_transport *t =
        noise_transport_begin(true, identity_priv, magic, &msg1, &msg1_len);
    bool ok = t && probe_send(sock, msg1, msg1_len, deadline_ms) &&
              probe_handshake(sock, t, deadline_ms, out_static);
    free(msg1);
    noise_transport_free(t);
    (void)close_socket(&sock);
    return ok;
}

static void *probe_thread(void *arg)
{
    struct probe_job *job = arg;
    for (size_t i = 0; i < job->count; i++) {
        uint8_t remote[32];
        bool ok = !configured_sync_peers_probe_should_stop() &&
                  (job->prober
                       ? job->prober(&job->targets[i], remote)
                       : probe_noise_identity(&job->targets[i],
                                              job->identity_priv, job->magic,
                                              remote));
        probe_finished(&job->targets[i], ok, ok ? remote : NULL);
    }
    memory_cleanse(job->identity_priv, sizeof(job->identity_priv));
    free(job);
    atomic_store(&g_probe_busy, false);
    return NULL;
}

static bool probe_due_locked(const struct configured_target *t, int64_t now)
{
    if (t->probe_running)
        return false;  // raw-return-ok:one-probe-per-target-at-a-time
    return !t->probe_finished_once ||
           now - t->probe_finished_s >= CONFIGURED_SYNC_PEER_PROBE_RETRY_SECS;
}

/* Mark every due target at `ip` running and copy it into `out` (or only
 * count them when `out` is NULL). */
static size_t collect_due_locked(const struct net_addr *ip,
                                 struct net_service *out, int64_t now)
{
    size_t n = 0;
    for (size_t i = 0; i < g_configured_count; i++) {
        struct configured_target *t = &g_configured[i];
        if (!net_addr_eq(&t->svc.addr, ip) || !probe_due_locked(t, now))
            continue;
        if (out) {
            t->probe_running = true;
            out[n] = t->svc;
        }
        n++;
    }
    return n;
}

/* The deterministic seam: the injected prober runs inline. */
static size_t request_probe_with_test_prober(const struct net_addr *ip,
                                             configured_sync_peer_prober_fn fn)
{
    struct net_service due[CONFIGURED_SYNC_PEERS_MAX];
    pthread_mutex_lock(&g_configured_lock);
    size_t n = collect_due_locked(ip, due, configured_now_s());
    pthread_mutex_unlock(&g_configured_lock);
    for (size_t i = 0; i < n; i++) {
        uint8_t remote[32];
        bool ok = fn(&due[i], remote);
        probe_finished(&due[i], ok, ok ? remote : NULL);
    }
    return n;
}

/* Cheap pre-check, one lock and no allocation: a thread-path probe could
 * start for `ip` now. */
static bool probe_thread_wanted(const struct net_addr *ip)
{
    if (atomic_load(&g_probe_busy) || configured_sync_peers_probe_should_stop())
        return false;  // raw-return-ok:a-probe-is-running-or-stopping
    pthread_mutex_lock(&g_configured_lock);
    bool can_probe = g_test_threaded_prober ||
                     (g_network && g_network->noise_enabled);
    bool wanted = can_probe &&
                  collect_due_locked(ip, NULL, configured_now_s()) > 0;
    pthread_mutex_unlock(&g_configured_lock);
    return wanted;
}

/* Fill `job` under the table lock: the prober, the key and the due targets. */
static size_t probe_job_fill(struct probe_job *job, const struct net_addr *ip)
{
    pthread_mutex_lock(&g_configured_lock);
    const struct net_manager *nm = g_network;
    job->prober = g_test_threaded_prober;
    if (job->prober || (nm && nm->noise_enabled)) {
        if (!job->prober) {
            memcpy(job->identity_priv, nm->identity_priv, 32);
            memcpy(job->magic, nm->message_start, sizeof(job->magic));
        }
        job->count = collect_due_locked(ip, job->targets, configured_now_s());
    }
    pthread_mutex_unlock(&g_configured_lock);
    return job->count;
}

/* Join a finished probe thread. Caller holds g_probe_thread_lock. */
static void probe_join_locked(void)
{
    if (!g_probe_tid_live)
        return;
    (void)pthread_join(g_probe_tid, NULL);
    g_probe_tid_live = false;
}

static size_t request_probe_on_thread(const struct net_addr *ip)
{
    if (!probe_thread_wanted(ip))
        return 0;
    pthread_mutex_lock(&g_probe_thread_lock);
    if (atomic_load(&g_probe_busy) || configured_sync_peers_probe_should_stop()) {
        pthread_mutex_unlock(&g_probe_thread_lock);
        return 0;
    }
    probe_join_locked();
    struct probe_job *job = zcl_calloc(1, sizeof(*job), "configured_sync_probe");
    size_t n = job ? probe_job_fill(job, ip) : 0;
    atomic_store(&g_probe_busy, n > 0);
    // thread-supervision-ok:bounded one-shot identity probe; caller-owned tid joined before the next probe and by configured_sync_peers_stop, with one CONFIGURED_SYNC_PEER_PROBE_DEADLINE_MS deadline per target and a stop check every PROBE_WAIT_SLICE_MS
    if (n > 0 && thread_registry_spawn("cfg-sync-probe", probe_thread, job,
                                       &g_probe_tid) == 0) {
        g_probe_tid_live = true;
        pthread_mutex_unlock(&g_probe_thread_lock);
        return n;
    }
    atomic_store(&g_probe_busy, false);
    for (size_t i = 0; job && i < job->count; i++)
        probe_finished(&job->targets[i], false, NULL);
    if (job)
        memory_cleanse(job->identity_priv, sizeof(job->identity_priv));
    free(job);
    pthread_mutex_unlock(&g_probe_thread_lock);
    return 0;
}

size_t configured_sync_peer_request_probe(const struct p2p_node *inbound)
{
    if (!inbound || !inbound->inbound ||
        atomic_load(&g_configured_count_hint) == 0 ||
        !configured_address_usable(&inbound->addr.svc.addr))
        return 0;
    pthread_mutex_lock(&g_configured_lock);
    configured_sync_peer_prober_fn test_prober = g_test_prober;
    pthread_mutex_unlock(&g_configured_lock);
    if (test_prober)
        return request_probe_with_test_prober(&inbound->addr.svc.addr,
                                              test_prober);
    return request_probe_on_thread(&inbound->addr.svc.addr);
}

void configured_sync_peer_observe_session(const struct p2p_node *node)
{
    if (!node || atomic_load(&g_configured_count_hint) == 0)
        return;
    if (!node->inbound)
        configured_sync_peer_observe_outbound(node);
    else if (!syncsvc_peer_is_configured_inbound(node))
        (void)configured_sync_peer_request_probe(node);
}

void configured_sync_peers_stop(void)
{
    atomic_store(&g_probe_stop, true);
    pthread_mutex_lock(&g_probe_thread_lock);
    probe_join_locked();
    atomic_store(&g_probe_busy, false);
    configured_sync_peers_attach_network(NULL);
    pthread_mutex_unlock(&g_probe_thread_lock);
}

/* ── test seams ───────────────────────────────────────────────────────── */

void configured_sync_peers_set_prober_for_testing(
    configured_sync_peer_prober_fn prober)
{
    pthread_mutex_lock(&g_configured_lock);
    g_test_prober = prober;
    pthread_mutex_unlock(&g_configured_lock);
}

void configured_sync_peers_set_threaded_prober_for_testing(
    configured_sync_peer_prober_fn prober)
{
    pthread_mutex_lock(&g_configured_lock);
    g_test_threaded_prober = prober;
    pthread_mutex_unlock(&g_configured_lock);
}

void configured_sync_peers_set_clock_for_testing(int64_t (*now_seconds)(void))
{
    g_test_clock = now_seconds;
}

void configured_sync_peers_set_probe_clock_ms_for_testing(
    int64_t (*now_ms)(void))
{
    g_test_clock_ms = now_ms;
}

bool configured_sync_peers_join_probe_for_testing(void)
{
    pthread_mutex_lock(&g_probe_thread_lock);
    bool joined = g_probe_tid_live;
    probe_join_locked();
    pthread_mutex_unlock(&g_probe_thread_lock);
    return joined;
}

void configured_sync_peers_reset_for_testing(void)
{
    configured_sync_peers_stop();
    atomic_store(&g_probe_stop, false);
    pthread_mutex_lock(&g_configured_lock);
    memset(g_configured, 0, sizeof(g_configured));
    g_configured_count = 0;
    atomic_store(&g_configured_count_hint, 0);
    pthread_mutex_unlock(&g_configured_lock);
}

bool configured_sync_peer_probe_socket_for_testing(
    const struct net_service *target, const uint8_t identity_priv[32],
    const unsigned char magic[4], uint8_t out_static[32])
{
    if (!target || !identity_priv || !magic || !out_static)
        return false;  // raw-return-ok:missing-argument-is-a-refused-probe
    return probe_noise_identity(target, identity_priv, magic, out_static);
}
