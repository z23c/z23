/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tor is compiled INTO zclassic23. No external binary. zclassic23 does not
 * proxy application traffic through SOCKS; dynhost handles .onion requests
 * via direct C callbacks. A localhost-only SocksPort remains as a temporary
 * Tor bootstrap workaround in tor_write_torrc(). */

#define _GNU_SOURCE  /* pthread_timedjoin_np */
#define _DEFAULT_SOURCE
#include "platform/clock.h"
#include "platform/time_compat.h"
#include "platform/thread_compat.h"
#include "platform/socket_compat.h"
#include "platform/file_metadata.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "base/compiler.h"
#include "encoding/utilstrencodings.h"
#include "support/cleanse.h"
#include "net/tor_integration.h"
#include "net/tor_request_state.h"
#include "net/net.h"      /* net_set_onion_ingress_port() */
#ifndef _WIN32
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "util/log_macros.h"
#include "util/thread_liveness.h"
#include "util/thread_registry.h"

static pthread_t g_tor_thread;
static pthread_t g_monitor_thread;
static _Atomic bool g_tor_running = false;
static _Atomic bool g_tor_ready = false;
static _Atomic bool g_tor_dial_ready = false;
static _Atomic bool g_tor_started = false;   /* true once tor thread spawn succeeds */
static _Atomic bool g_monitor_started = false;

/* Supervisor liveness (root children — core/modules/net cannot include the app-side
 * supervisors/domains.h, see util/thread_liveness.h). zcl_tor is opaque
 * vendored/forked Tor code (tor_thread_fn just calls into tor_run_main) —
 * its internal loop is NEVER instrumented directly. Instead g_tor_liveness
 * is beaten as a proxy FROM WITHIN g_tor_monitor_liveness's own poll loop
 * (read_onion_address, called synchronously from tor_onion_monitor): a
 * successful poll iteration there is evidence Tor is alive. Both
 * liveness-only (no deadline / no progress gate) — the monitor polls on a
 * bootstrap loop bounded by g_tor_running, and it keeps polling after the
 * address lands until onion DESCRIPTOR PUBLICATION is observed. */
static struct thread_liveness_child g_tor_liveness = { .id = SUPERVISOR_INVALID_ID };
static struct thread_liveness_child g_tor_monitor_liveness = { .id = SUPERVISOR_INVALID_ID };
static _Atomic uint64_t g_tor_monitor_poll_count = 0;
static char g_onion_address[128];
static char g_tor_datadir[512];
/* The node's public P2P port, captured by tor_integration_start(). Used by
 * tor_try_install_persistent_identity() for the SECOND port mapping on the
 * persistent onion service: <onion>:<p2p_port> forwards to the local P2P
 * listener (see the install site for why this is NOT a dynhost virtual
 * port). 0 = unknown (no mapping installed). */
static _Atomic uint16_t g_tor_p2p_port = 0;
/* tor.log size at THIS boot's Tor start. The log is append-mode across
 * boots and (in default mode) dynhost mints a fresh ephemeral service
 * every start, so any address line below this offset names a dead
 * service. */
static long g_tor_log_scan_from = 0;
/* Same, for the info-level [rend] destination that carries the descriptor
 * publication line. It is a SEPARATE file with a separate size, so it needs
 * its own offset: reusing tor.log's would either skip real evidence or
 * re-read a previous boot's. */
static long g_tor_rend_log_scan_from = 0;

/* Persistent identity (-onion-persist / -onion-rotate). Set once by
 * tor_integration_configure_identity() before tor_integration_start();
 * read by the monitor thread after spawn. */
static _Atomic bool g_onion_persist = false;
static _Atomic bool g_onion_rotate = false;
/* 0 = install pending, 1 = persistent service registered with dynhost,
 * -1 = install failed (already named via LOG_ERR). */
static _Atomic int g_persist_install_state = 0;
/* Old identity's address ("<56 chars>.onion") when -onion-rotate archived
 * one this boot; printed next to the new address after install. */
static char g_rotated_old_address[128];

static tor_request_handler_fn g_request_handler = NULL;
static void *g_request_handler_ctx = NULL;

static void tor_join_deadline_from_now(struct timespec *ts, int timeout_sec)
{
    platform_time_realtime_timespec(ts);
    if (timeout_sec < 0)
        timeout_sec = 0;
    ts->tv_sec += timeout_sec;
}

static void tor_join_thread_bounded(pthread_t thread,
                                    const char *name,
                                    int timeout_sec)
{
    struct timespec deadline;
    int rc;

    tor_join_deadline_from_now(&deadline, timeout_sec);
    rc = platform_thread_join_until(thread, NULL, &deadline);
    if (rc == 0)
        return;

    if (rc == ETIMEDOUT) {
        fprintf(stderr,  // obs-ok:shutdown-straggler-named
                "Tor: %s join timed out after %ds; retaining ownership\n",
                name ? name : "thread", timeout_sec);
    } else {
        fprintf(stderr,  // obs-ok:shutdown-straggler-named
                "Tor: %s join failed rc=%d (%s); retaining ownership\n",
                name ? name : "thread", rc, strerror(rc));
    }
    pthread_join(thread, NULL);
}

static void ensure_onion_suffix(void)
{
    if (!strstr(g_onion_address, ".onion")) {
        size_t alen = strlen(g_onion_address);
        if (alen + 7 <= sizeof(g_onion_address) - 1)
            memcpy(g_onion_address + alen, ".onion", 7);
    }
}

void tor_integration_set_handler(tor_request_handler_fn handler, void *ctx)
{
    g_request_handler = handler;
    g_request_handler_ctx = ctx;
}

/* Write torrc — we do NOT use SOCKS.
 *
 * Our forked Tor (RhettCreighton/tor, dynhost branch) does NOT use SOCKS.
 * Dynhost handles .onion connections via direct C function calls inside
 * the process — no SOCKS proxy, no proxy clients, nothing.
 *
 * WORKAROUND: Tor's bootstrap code refuses to start without at least
 * one listener. The dynhost service is created AFTER bootstrap, so it
 * can't satisfy this requirement. We open a localhost-only SocksPort
 * that nothing ever connects to, purely to make Tor's startup check
 * happy. The port is derived from p2p_port so multiple instances
 * don't collide. */
/* Scan the dynhost log from byte offset scan_from and return the LAST
 * "ephemeral service created with address:" match. Last-match + offset are
 * both load-bearing: the log appends across boots and every Tor start mints
 * a fresh ephemeral service, so an earlier line names a dead service (the
 * old first-match-from-zero scan reported/published a dead onion after
 * every restart). If the file shrank below scan_from (rotated/truncated),
 * the scan restarts from the top. Exposed for testing. */
/* ── Persistent onion identity ─────────────────────────────────
 *
 * Two layers:
 *
 * 1. PURE layer (no Tor): the identity is a 32-byte ed25519 seed at
 *    <datadir>/tor_data/onion_service/identity_seed (mode 0600) plus the
 *    standard Tor HiddenServiceDir-style hostname file. The v3 address is
 *    derived with the project's own ed25519 + SHA3-256, so the whole
 *    create/reuse/rotate lifecycle is unit-testable without a linked Tor.
 *
 * 2. INSTALL layer (real-Tor builds only): the vendored dynhost fork only
 *    routes .onion connections to the registered external handler for the
 *    ONE service whose identity key matches dynhost's global hs_service
 *    (dynhost_intercept_service_connection), and by default that service
 *    is a throwaway ephemeral key minted every boot. So persistence cannot
 *    come from a torrc HiddenServiceDir (such a service would fall through
 *    to a real-port connect and die). Instead the monitor thread waits for
 *    the dynhost subsystem to appear inside the Tor thread, holds dynhost's
 *    service slot so no throwaway is minted, sends ADD_ONION with OUR
 *    persisted key over the owning control connection, and points dynhost's
 *    global hs_service at the result. Tor registers the service from its own
 *    loop: registering one changes which periodic events run, and that touches
 *    the event base, which only the Tor thread may do. If a throwaway exists
 *    anyway, it stays registered but unreferenced (harmless): the pointer swap
 *    below still retargets interception at our persistent service because the
 *    comparison reads dynhost->hs_service at connection time. */

/* ── Persistent identity install (real-Tor builds only) ────────
 *
 * Layout mirrors of the vendored dynhost/HS types. tor_integration.c
 * declares the Tor embedding API locally (the same style as
 * tor_main_configuration_* above) because vendor/tor headers are not on
 * the include path; the fork is pinned, and the boot-time cross-check
 * below (pure-derived address vs Tor-derived) fails loudly if these ever
 * drift. All weak: NULL under the Tor stub. */
typedef struct { uint8_t pubkey[32]; } tor_ed25519_public_key_t;

/* dynhost_service_t: only the first member is ever touched. */
struct dynhost_service_head_compat {
    void *hs_service;
};

extern void *dynhost_get_global_service(void) ZCL_WEAK_IMPORT;
extern int hs_parse_address(const char *address,
    tor_ed25519_public_key_t *key_out, uint8_t *checksum_out,
    uint8_t *version_out) ZCL_WEAK_IMPORT;
extern void *hs_service_find(const tor_ed25519_public_key_t *identity_pk)
    ZCL_WEAK_IMPORT;

/* True when every Tor/dynhost symbol the install path needs is linked. */
static bool tor_persist_symbols_available(void)
{
    return dynhost_get_global_service && hs_parse_address && hs_service_find;
}

/* Look up the registered service for a Tor-derived address, NULL if the
 * address does not parse or no service is registered. */
static void *tor_persist_find_service(const char *address)
{
    tor_ed25519_public_key_t pk;
    void *service = NULL;
    if (hs_parse_address(address, &pk, NULL, NULL) == 0)
        service = hs_service_find(&pk);
    return service;
}

#ifdef ZCL_TESTING
void *tor_integration_find_service_for_test(const char *address)
{
    return tor_persist_symbols_available() ? tor_persist_find_service(address)
                                           : NULL;
}
#endif

/* Print the install summary lines. */
static void tor_persist_announce(bool created, const char *address)
{
    printf("Tor: persistent onion identity %s: %s.onion\n",
           created ? "minted" : "loaded", address);
    fflush(stdout);
    if (g_rotated_old_address[0]) {
        printf("Tor: onion identity rotated: old=%s new=%s.onion\n",
               g_rotated_old_address, address);
        fflush(stdout);
    }
}

static int tor_try_install_persistent_identity(const char *datadir);

void tor_integration_configure_identity(bool persist, bool rotate)
{
    if (rotate && !persist)
        fprintf(stderr,  // obs-ok:flag-combo-named
                "Warning: -onion-rotate requires -onion-persist; "
                "ignoring -onion-rotate\n");
    atomic_store(&g_onion_persist, persist);
    atomic_store(&g_onion_rotate, persist && rotate);
}

bool tor_integration_persistence_enabled(void)
{
    return atomic_load(&g_onion_persist);
}

const char *tor_onion_port_map_state_name(
    enum tor_onion_port_map_state state)
{
    switch (state) {
    case TOR_ONION_PORT_MAP_DISABLED:  return "disabled";
    case TOR_ONION_PORT_MAP_PENDING:   return "pending";
    case TOR_ONION_PORT_MAP_INSTALLED: return "installed";
    case TOR_ONION_PORT_MAP_FAILED:    return "failed";
    }
    return "unknown";
}

static enum tor_onion_port_map_state tor_port_map_state_of(
    bool enabled, bool ready, bool persistent, int install_state)
{
    if (!enabled)
        return TOR_ONION_PORT_MAP_DISABLED;
    if (persistent && install_state < 0)
        return TOR_ONION_PORT_MAP_FAILED;
    if (!ready || (persistent && install_state != 1))
        return TOR_ONION_PORT_MAP_PENDING;
    return TOR_ONION_PORT_MAP_INSTALLED;
}

void tor_integration_port_map_snapshot(struct tor_onion_port_map *out)
{
    if (!out)
        return;

    memset(out, 0, sizeof(*out));
    bool enabled = atomic_load(&g_tor_running);
    bool ready = atomic_load(&g_tor_ready);
    bool persistent = atomic_load(&g_onion_persist);
    int install_state = atomic_load(&g_persist_install_state);
    uint16_t p2p_port = atomic_load(&g_tor_p2p_port);

    out->persistent_identity = persistent;
    out->application_virtual_port = 80;
    out->p2p_virtual_port = p2p_port;
    out->p2p_target_port = p2p_port;
    out->p2p_route_expected = persistent && p2p_port > 0 && p2p_port != 80;
    out->expected_route_count = 1 + (out->p2p_route_expected ? 1 : 0);

    out->state = tor_port_map_state_of(enabled, ready, persistent,
                                       install_state);

    out->application_route_installed = ready;
    out->p2p_route_installed = ready && out->p2p_route_expected &&
                               install_state == 1;
    out->installed_route_count =
        (out->application_route_installed ? 1 : 0) +
        (out->p2p_route_installed ? 1 : 0);
    out->complete = enabled && ready &&
                    out->installed_route_count == out->expected_route_count;
}


/* Read .onion address from persistent hostname file (HiddenServiceDir).
 * Returns true if address was read successfully. */
static bool read_onion_from_hostname_file(const char *datadir)
{
    char path[1024];
    snprintf(path, sizeof(path),
             "%s/tor_data/onion_service/hostname", datadir);

    FILE *f = fopen(path, "r");
    if (!f) return false;  /* not yet available — normal during bootstrap */

    char line[128];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        LOG_FAIL("tor", "hostname file empty: %s", path);
    }
    fclose(f);

    /* Strip trailing whitespace */
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'
                       || line[len - 1] == ' '))
        line[--len] = '\0';

    if (len == 0 || len >= sizeof(g_onion_address))
        LOG_FAIL("tor", "hostname file has invalid length: %zu", len);

    memcpy(g_onion_address, line, len + 1);
    ensure_onion_suffix();
    return true;
}

/* Size of one Tor log at this Tor start, used as the scan floor so a poll
 * cannot mistake a previous boot's evidence for this one's. Zero when the
 * file is absent, unmeasurable, or larger than a long can carry. */
static long tor_log_scan_offset(const char *datadir,
                                bool (*compose)(const char *, char *, size_t))
{
    char path[1024];
    if (!compose(datadir, path, sizeof(path)))
        return 0;
    struct platform_file_metadata md;
    if (platform_file_metadata_read(path, &md) != PLATFORM_FILE_METADATA_OK ||
        md.size > (uint64_t)LONG_MAX)
        return 0;
    return (long)md.size;
}

static bool tor_poll_onion_address_once(const char *datadir,
                                        const char *log_path)
{
    bool have_addr = false;
    if (atomic_load(&g_onion_persist)) {
        /* -onion-persist: the address comes from OUR persisted
         * identity, registered with dynhost by the install step. The
         * ephemeral log-scan fallback is deliberately skipped here —
         * in persist mode an ephemeral line would name dynhost's
         * throwaway race-loser service, not this node's identity.
         * Install failure is already a named LOG_ERR; the poll's
         * "still waiting" line keeps the stall named. */
        if (atomic_load(&g_persist_install_state) == 0) {
            int rc = tor_try_install_persistent_identity(datadir);
            if (rc != 0)
                atomic_store(&g_persist_install_state, rc);
        }
        if (atomic_load(&g_persist_install_state) == 1 &&
            read_onion_from_hostname_file(datadir))
            have_addr = true;
    } else {
        /* Default ephemeral mode: a hostname file left by a previous
         * -onion-persist boot is deliberately NOT read here — no
         * service is registered for that identity this boot. */
        if (tor_log_last_ephemeral_address(log_path,
                                           g_tor_log_scan_from,
                                           g_onion_address,
                                           sizeof(g_onion_address))) {
            ensure_onion_suffix();
            have_addr = true;
        }
    }
    return have_addr;
}

static void tor_report_slow_wait(int waited, bool have_addr)
{
    if (have_addr)
        fprintf(stderr,  // obs-ok:bootstrap-progress-named
                "Tor: still waiting for onion DESCRIPTOR PUBLICATION "
                "after %ds (HSDir upload may be slow)\n", waited);
    else
        fprintf(stderr,  // obs-ok:bootstrap-progress-named
                "Tor: still waiting for .onion address after %ds "
                "(bootstrap may be slow)\n", waited);
}

/* Wait for the .onion address AND onion DESCRIPTOR PUBLICATION.

 * Default (ephemeral) mode: parse the dynhost log for THIS start's
 * ephemeral service. -onion-persist mode: install our persisted identity
 * into dynhost, then read the hostname file it (re)wrote.
 *
 * Hostname-only is not ready: HSDir upload can lag the hostname file, and
 * a Type=notify first-boot that fires READY=1 on hostname lets clients
 * dial a service the network cannot intro.
 *
 * Polls until both are observed or Tor dies — deliberately NO fixed
 * attempt cap. A slow public-network bootstrap (e.g. a ~120 s guard
 * retry before the first circuit) legitimately delays the dynhost
 * ephemeral-service line past any small cap, and the old 120-attempt
 * cap gave up permanently seconds before the address landed: the
 * monitor exited, g_tor_ready never set, and the node ran the rest of
 * the boot with no .onion and no further polling. The poll is bounded
 * by g_tor_running (Tor's own lifetime), so shutdown still exits it. */
static bool read_onion_address(const char *datadir)
{
    char log_path[1024];
    char rend_log_path[1024];
    if (!tor_log_path(datadir, log_path, sizeof(log_path)) ||
        !tor_rend_log_path(datadir, rend_log_path, sizeof(rend_log_path)))
        return false;

    int waited = 0;
    bool have_addr = false;
    bool announced_addr = false;
    for (;;) {
        /* g_tor is opaque vendored code and is never beaten from inside
         * its own loop — this poll iteration is the proxy for "Tor is
         * alive" instead (see the file-header comment). */
        thread_liveness_beat(&g_tor_monitor_liveness,
                             (int64_t)atomic_fetch_add(&g_tor_monitor_poll_count, 1) + 1);
        thread_liveness_beat(&g_tor_liveness, -1);

        if (!atomic_load(&g_tor_running))
            return false;

        if (!have_addr) {
            have_addr = tor_poll_onion_address_once(datadir, log_path);
            if (have_addr && !announced_addr) {
                /* Outbound dynhost streams can be queued now. Do not wait for
                 * our own inbound descriptor upload: Tor will build the peer
                 * circuit in parallel while HSDir publication completes. */
                atomic_store(&g_tor_dial_ready, true);
                printf("Tor .onion: %s (waiting for DESCRIPTOR PUBLICATION)\n",
                       g_onion_address);
                fflush(stdout);
                announced_addr = true;
            }
        }

        /* The publication line is info-level [rend], which now has its OWN
         * destination so tor.log can stay at notice — see tor_config_log.c. */
        if (have_addr &&
            tor_log_has_descriptor_publication(rend_log_path,
                                               g_tor_rend_log_scan_from))
            return true;

        /* Slow bootstrap is a named state, not a silent hang. */
        if (++waited % 60 == 0)
            tor_report_slow_wait(waited, have_addr);
        platform_sleep_ms(1000);
    }
}

/* Tor embedding API */
typedef struct tor_main_configuration_t tor_main_configuration_t;
extern tor_main_configuration_t *tor_main_configuration_new(void);
extern int tor_main_configuration_set_command_line(
    tor_main_configuration_t *cfg, int argc, char *argv[]);
extern void tor_main_configuration_free(tor_main_configuration_t *cfg);
extern int tor_run_main(const tor_main_configuration_t *);

/* The owning control connection: an unnamed socket pair, not a listener, so
 * it exposes no control port. Tor's event base and main-loop globals have no
 * locks and belong to the Tor thread alone, so every request from another
 * thread goes through this socket and Tor acts on it from its own loop.
 * Closing our direction ends Tor: Tor reads end-of-file, logs that its owning
 * controller closed, and shuts down on its own thread. End-of-file waits in
 * the socket, so a request made before Tor reached its loop is not lost.
 *
 * We make the pair and pass __OwningControllerFD ourselves instead of calling
 * tor_main_configuration_setup_control_socket(). That helper also records
 * Tor's end in the configuration, and tor_main_configuration_free() closes
 * that number after Tor has already closed it, when another thread may own
 * the number. Passing it on the command line leaves one closer.
 *
 * Both values are written before the Tor thread starts. g_tor_control is
 * closed only after that thread and the monitor have been joined.
 *
 * Tor closes its end when it reads its options. A start that fails before that
 * leaves the end open with nothing on the far side once ours is closed. Nothing
 * closes it: by then the number may belong to another thread, and looking at a
 * number to find out touches that thread's descriptor. A process makes at most
 * TOR_MAX_STARTS_IN_PROCESS of these. */
static platform_socket_t g_tor_control = PLATFORM_SOCKET_INVALID;
static platform_socket_t g_tor_control_peer = PLATFORM_SOCKET_INVALID;
#if defined(ZCL_TESTING) && !defined(_WIN32)
static struct stat g_tor_control_peer_id;
#endif
static _Atomic bool g_serve_onion = true;
static _Atomic int64_t g_claim_ms = -1;
static _Atomic int64_t g_network_enabled_ms = -1;
static _Atomic unsigned g_enable_failures;
static _Atomic int64_t g_enable_retry_ms;

static int64_t tor_wall_ms(void)
{
    return clock_now_wall_ms();
}

/* True when a real Tor is linked; the stub has no dynhost and no control
 * connection to own. */
static bool tor_is_linked(void)
{
    return dynhost_get_global_service != NULL;
}

/* Open the owning control connection, before the Tor thread exists. The tor
 * stub never reads it, so it gets none. */
static bool tor_control_open(void)
{
    if (!tor_is_linked())
        return true;
    platform_socket_t pair[2];
    /* A child process must not inherit either end: Tor pre-authenticates this
     * connection. Another thread may fork and exec at any moment, so where the
     * flag exists the pair is close-on-exec from birth. */
#ifdef SOCK_CLOEXEC
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0)
        return false;
#else
    if (!platform_socket_pair(pair))
        return false;
#ifndef _WIN32
    (void)fcntl(pair[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(pair[1], F_SETFD, FD_CLOEXEC);
#endif
#endif
#if defined(ZCL_TESTING) && !defined(_WIN32)
    if (fstat(pair[1], &g_tor_control_peer_id) != 0) {
        (void)platform_socket_close(pair[0]);
        (void)platform_socket_close(pair[1]);
        return false;
    }
#endif
    g_tor_control = pair[0];
    g_tor_control_peer = pair[1];
    return true;
}

/* Ask Tor to exit, from any thread, any number of times. shutdown() rather
 * than close(): the number stays ours until the join, so a monitor blocked in
 * recv() wakes instead of reading a number some other thread now owns. */
static void tor_request_exit(void)
{
    if (g_tor_control != PLATFORM_SOCKET_INVALID)
        (void)platform_socket_shutdown_both(g_tor_control);
}

/* Dynhost external handler — routes .onion requests to our code */
typedef size_t (*dynhost_external_handler_fn)(const char *, const char *,
    const uint8_t *, size_t, uint8_t *, size_t, void *);
extern void dynhost_webserver_set_external_handler(
    dynhost_external_handler_fn handler, void *ctx);

/* Bridge: dynhost calls this → we call the registered handler */
static size_t dynhost_bridge(const char *method, const char *path,
                              const uint8_t *body, size_t body_len,
                              uint8_t *response, size_t response_max,
                              void *ctx)
{
    (void)ctx;
    if (!g_request_handler) return 0;
    return g_request_handler(method, path, body, body_len,
                              response, response_max,
                              g_request_handler_ctx);
}

static void *tor_onion_monitor(void *arg);

static void *tor_thread_fn(void *arg)
{
    (void)arg;
    char torrc_path[1024];
    snprintf(torrc_path, sizeof(torrc_path), "%s/torrc", g_tor_datadir);

    printf("Tor: starting embedded (no ports, no SOCKS, dynhost only)\n");
    fflush(stdout);

    tor_main_configuration_t *cfg = tor_main_configuration_new();
    /* Tor pre-authenticates this control connection. Stop ends Tor through it,
     * and a node that serves no onion starts with the network disabled and
     * clears it here. */
    char owner_fd[32];
    snprintf(owner_fd, sizeof(owner_fd), "%" PRIu64,
             (uint64_t)g_tor_control_peer);
    char *argv[] = {"tor", "-f", torrc_path,
                    "__OwningControllerFD", owner_fd};
    int argc = g_tor_control != PLATFORM_SOCKET_INVALID ? 5 : 3;
    tor_main_configuration_set_command_line(cfg, argc, argv);

    /* Monitor for .onion address in parallel when the helper thread starts. */
    if (thread_registry_spawn("zcl_tor_monitor", tor_onion_monitor, NULL,
                                  &g_monitor_thread) == 0) {
        atomic_store(&g_monitor_started, true);
        thread_liveness_register(&g_tor_monitor_liveness, "zcl_tor_monitor", 0, 0);
    } else {
        perror("Tor: thread_registry_spawn onion monitor");
        atomic_store(&g_monitor_started, false);
    }

    /* Run Tor in this thread (blocks until exit) */
    int result = tor_run_main(cfg);
    tor_main_configuration_free(cfg);

    /* Signal monitor to stop, then join it if it actually started. */
    atomic_store(&g_tor_running, false);
    atomic_store(&g_tor_ready, false);
    atomic_store(&g_tor_dial_ready, false);
    if (atomic_exchange(&g_monitor_started, false)) {
        tor_join_thread_bounded(g_monitor_thread, "monitor", 5);
        thread_liveness_retire(&g_tor_monitor_liveness);
    }

    printf("Tor: exited with code %d\n", result);
    return NULL;
}

/* ── No onion service (private wallet broadcast) ───────────────
 *
 * dynhost mints its throwaway service from dynhost_check_and_activate()
 * only while its global hs_service is NULL. A node that serves no onion
 * claims that slot with an inert sentinel (a zeroed block no real service
 * can equal) the moment the global exists, so nothing is minted, no
 * ADD_ONION-equivalent registration happens and no descriptor is uploaded.
 *
 * The claim is a compare-and-swap from NULL, polled every millisecond from
 * the monitor thread, which starts before tor_run_main(). The global is
 * allocated and activated inside Tor's own thread and core has no hook
 * between the two, so the order is made as tight as core can make it, and
 * not guaranteed. The guarantee is the fail-closed verification: once the
 * slot holds anything but the sentinel the node is marked violated, dialling
 * and private sends stop, and Tor is shut down. */
enum tor_service_claim {
    TOR_CLAIM_NONE = 0,   /* this node serves an onion: nothing to claim */
    TOR_CLAIM_HELD = 1,   /* the slot holds the sentinel */
    TOR_CLAIM_LOST = 2,   /* a real service occupies the slot */
};

static _Atomic bool g_service_violated = false;
static struct { _Alignas(64) uint8_t bytes[65536]; } g_no_service_sentinel;

void tor_integration_set_serve_onion(bool serve)
{
    atomic_store(&g_serve_onion, serve);
}

bool tor_integration_serves_onion(void)
{
    return atomic_load(&g_serve_onion);
}

bool tor_integration_service_violated(void)
{
    return atomic_load(&g_service_violated);
}

bool tor_integration_is_usable(void)
{
    if (atomic_load(&g_serve_onion))
        return atomic_load(&g_tor_ready);
    return atomic_load(&g_tor_dial_ready) &&
           !atomic_load(&g_service_violated);
}

static int tor_service_claim_step(void *global, bool serve)
{
    if (serve || !global)
        return TOR_CLAIM_NONE;
    struct dynhost_service_head_compat *head = global;
    void *sentinel = g_no_service_sentinel.bytes;
    void *expected = NULL;
    if (__atomic_compare_exchange_n(&head->hs_service, &expected, sentinel,
                                    false, __ATOMIC_ACQ_REL,
                                    __ATOMIC_ACQUIRE)) {
        atomic_store(&g_claim_ms, tor_wall_ms());
        return TOR_CLAIM_HELD;
    }
    return expected == sentinel ? TOR_CLAIM_HELD : TOR_CLAIM_LOST;
}

/* Verify the claim once; a lost slot marks the node violated. */
static bool tor_service_verify(void *global)
{
    if (tor_service_claim_step(global, false) != TOR_CLAIM_LOST)
        return true;
    if (!atomic_exchange(&g_service_violated, true))
        LOG_ERROR("tor", "private mode: dynhost registered an onion service "
                        "despite the claim; refusing to dial or send and "
                        "shutting Tor down");
    atomic_store(&g_tor_dial_ready, false);
    return false;
}

/* True once Tor's reply is complete: its last line has a space after the
 * status code. */
static bool tor_control_reply_complete(const char *reply)
{
    for (const char *line = reply;;) {
        const char *eol = strstr(line, "\r\n");
        if (!eol)
            return false;
        if (eol - line >= 4 && line[3] == ' ')
            return true;
        line = eol + 2;
    }
}

/* Send one command over the owning control connection and read Tor's whole
 * reply. Tor answers from its loop, which may not be running yet, so this waits
 * for as long as Tor runs; a stop ends the wait at once by shutting the socket
 * down. False when Tor ended, or the reply did not fit. */
static bool tor_control_exchange(const char *cmd, char *reply, size_t reply_size)
{
    size_t cmd_len = strlen(cmd);
    (void)platform_socket_set_receive_timeout(g_tor_control, 1000);
    if ((size_t)send(g_tor_control, cmd, (int)cmd_len, 0) != cmd_len)
        return false;
    size_t have = 0;
    while (atomic_load(&g_tor_running) && have + 1 < reply_size) {
        long n = (long)recv(g_tor_control, reply + have,
                            (int)(reply_size - 1 - have), 0);
        if (n > 0) {
            have += (size_t)n;
            reply[have] = '\0';
            if (tor_control_reply_complete(reply))
                return true;
            continue;
        }
        int error = platform_socket_last_error();
        if (n == 0 || (!platform_socket_error_would_block(error) &&
                       !platform_socket_error_timed_out(error) &&
                       !platform_socket_error_interrupted(error)))
            return false;
        thread_liveness_beat(&g_tor_monitor_liveness,
                             (int64_t)atomic_fetch_add(
                                 &g_tor_monitor_poll_count, 1) + 1);
    }
    return false;
}

/* The ADD_ONION command for this seed. Same service as dynhost's own: virtual
 * port 80 is taken by dynhost's interception before any target is consulted,
 * so its target is a path that can never exist. Flags=Detach keeps the service
 * registered until Tor exits, whatever happens to this connection. */
static bool tor_add_onion_compose(const uint8_t seed[32], uint16_t p2p_port,
                                  char *cmd, size_t cmd_size)
{
    uint8_t secret[64];
    char key[96];
    onion_identity_tor_secret_from_seed(seed, secret);
    size_t key_len = EncodeBase64(secret, sizeof(secret), key, sizeof(key));
    memory_cleanse(secret, sizeof(secret));
    /* SECOND port mapping: the node's P2P port. Inbound P2P rides the
     * persistent onion identity at <onion>:<p2p_port>, forwarded to the
     * local listener by stock Tor hidden-service machinery
     * (hs_service.c -> connection_exit_connect) as an ordinary TCP
     * connection from 127.0.0.1 — no fork change needed. Deliberately NOT
     * dynhost_add_virtual_port: that would route the port into the HTTP
     * interception layer (dynhost_handlers.c), which exists for port-80
     * traffic only. */
    char p2p[48] = "";
    if (p2p_port > 0 && p2p_port != 80)
        snprintf(p2p, sizeof(p2p), " Port=%u,127.0.0.1:%u",
                 (unsigned)p2p_port, (unsigned)p2p_port);
    int n = snprintf(cmd, cmd_size,
                     "ADD_ONION ED25519-V3:%s Flags=Detach "
                     "Port=80,unix:/dev/null/no-target%s\r\n", key, p2p);
    memory_cleanse(key, sizeof(key));
    return key_len > 0 && n > 0 && (size_t)n < cmd_size;
}

/* True when Tor accepted ADD_ONION and named this address. */
static bool tor_add_onion_reply_names(const char *reply, const char *addr)
{
    static const char id_prefix[] = "250-ServiceID=";
    if (strncmp(reply, id_prefix, sizeof(id_prefix) - 1) != 0)
        LOG_FAIL("tor", "ADD_ONION for the persistent onion identity was "
                        "refused (%.3s)", reply);

    /* Cross-check: Tor's derivation MUST equal the pure layer's (the unit
     * vector pins the pure layer to prop224). A mismatch means the
     * vendored fork drifted under us — fail loudly, never report one
     * address while serving another. */
    const char *tor_addr = reply + sizeof(id_prefix) - 1;
    if (strncmp(tor_addr, addr, 56) != 0 ||
        strncmp(tor_addr + 56, "\r\n", 2) != 0)
        LOG_FAIL("tor", "Tor-derived persistent address does not match the "
                        "pure prop224 derivation — vendored fork drift");
    return true;
}

/* One install attempt from the monitor poll loop.
 * Returns 1 once the persistent service is registered with dynhost,
 * 0 while the dynhost subsystem is not up yet or Tor is stopping (retried on
 * the next poll, which ends if Tor ended — not an error), -1 on a named hard
 * failure. */
static int tor_try_install_persistent_identity(const char *datadir)
{
    void *global = dynhost_get_global_service();
    if (!global)
        return 0;   /* Tor thread still in early startup; retried */

    uint8_t seed[32];
    char addr[57];
    bool created = false;
    if (!onion_identity_ensure(datadir, seed, addr, sizeof(addr), &created))
        LOG_ERR("tor", "persistent onion identity ensure failed for %s",
                datadir);

    /* Hold the slot: with it taken dynhost mints no throwaway, so nothing else
     * adds to Tor's service table and the lookup below cannot race an insert. */
    (void)tor_service_claim_step(global, false);

    char cmd[256];
    char reply[256];
    uint16_t p2p_port = atomic_load(&g_tor_p2p_port);
    bool composed = tor_add_onion_compose(seed, p2p_port, cmd, sizeof(cmd));
    memory_cleanse(seed, sizeof(seed));
    bool answered = composed && tor_control_exchange(cmd, reply, sizeof(reply));
    memory_cleanse(cmd, sizeof(cmd));
    if (!composed)
        LOG_ERR("tor", "could not compose ADD_ONION for the persistent onion "
                       "identity");
    if (!answered) {
        if (!atomic_load(&g_tor_running))
            return 0;
        LOG_ERR("tor", "no complete reply to ADD_ONION for the persistent "
                       "onion identity");
    }

    if (!tor_add_onion_reply_names(reply, addr))
        return -1;

    void *service = tor_persist_find_service(addr);
    if (!service)
        LOG_ERR("tor", "persistent onion service missing right after "
                       "registration: %s", addr);

    /* Become the dynhost service (see the layer-2 comment above). */
    __atomic_store_n(&((struct dynhost_service_head_compat *)global)->hs_service,
                     service, __ATOMIC_RELEASE);
    /* Tor reads that slot without atomics and later frees the block holding
     * it. One more exchange orders our store before everything Tor does after
     * answering; no reply only means Tor is ending, which needs no order. */
    (void)tor_control_exchange("GETINFO version\r\n", reply, sizeof(reply));

    /* The P2P route is live: from here on, inbound connections arriving at
     * 127.0.0.1:<p2p_port> may be anonymous strangers Tor forwarded, not
     * same-host processes. Tell core/modules/net so it stops handing those peers the
     * trusted-peer exemption from misbehaviour scoring — see
     * net_set_onion_ingress_port() in net/net.h for why the two are
     * indistinguishable at accept() and what the operator escape is. */
    if (p2p_port > 0 && p2p_port != 80)
        net_set_onion_ingress_port(p2p_port);

    tor_persist_announce(created, addr);
    return 1;
}

#ifdef ZCL_TESTING
int tor_integration_service_step_for_test(void *global, bool serve)
{
    if (serve)
        return tor_service_claim_step(global, true);
    return tor_service_verify(global) ? TOR_CLAIM_HELD : TOR_CLAIM_LOST;
}

void tor_integration_service_reset_for_test(void)
{
    atomic_store(&g_serve_onion, true);
    atomic_store(&g_service_violated, false);
}
#endif

/* Order of events for a node that serves no onion. Tor is started with
 * DisableNetwork 1. Both places that mint dynhost's service run only after a
 * circuit has completed with the network enabled (mainloop.c: dynhost
 * scheduled events and hs_service_callback), and Tor opens no socket while
 * the network is disabled, so nothing can be minted or uploaded yet. The
 * monitor claims the slot, verifies the claim, and only then clears
 * DisableNetwork through the owning control connection. A claim that is
 * already lost leaves the network disabled for good. */
enum tor_gate {
    TOR_GATE_WAIT = 0,    /* dynhost is not up yet; the network stays off */
    TOR_GATE_OPEN = 1,    /* claim verified and the network enabled */
    TOR_GATE_CLOSED = 2,  /* claim lost; the network was never enabled */
};

static enum tor_gate tor_network_gate_step(void *global, bool serve,
                                           bool (*enable)(void),
                                           bool *enabled)
{
    if (serve)
        return TOR_GATE_OPEN;  /* the network was never disabled */
    if (!global)
        return TOR_GATE_WAIT;
    if (!*enabled) {
        if (tor_service_claim_step(global, false) != TOR_CLAIM_HELD) {
            (void)tor_service_verify(global);  /* marks the node violated */
            return TOR_GATE_CLOSED;
        }
        if (!tor_service_verify(global))
            return TOR_GATE_CLOSED;
        if (!enable())
            return TOR_GATE_WAIT;
        *enabled = true;
        return TOR_GATE_OPEN;
    }
    return tor_service_verify(global) ? TOR_GATE_OPEN : TOR_GATE_CLOSED;
}

#ifdef ZCL_TESTING
int tor_integration_network_gate_step_for_test(void *global, bool serve,
                                               bool (*enable)(void),
                                               bool *enabled)
{
    return (int)tor_network_gate_step(global, serve, enable, enabled);
}
#endif

/* Clear DisableNetwork over the owning control connection, which Tor
 * pre-authenticates. NULL only on Tor's "250 OK"; otherwise why it failed. */
static const char *tor_control_enable(void)
{
#ifdef _WIN32
    return "clearing DisableNetwork is not supported on this platform";
#else
    if (g_tor_control == PLATFORM_SOCKET_INVALID)
        return "no control connection to enable the network";
    static const char cmd[] = "SETCONF DisableNetwork=0\r\n";
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    (void)setsockopt(g_tor_control, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (send(g_tor_control, cmd, sizeof(cmd) - 1, 0) !=
        (ssize_t)(sizeof(cmd) - 1))
        return "sending SETCONF DisableNetwork=0 failed";
    char reply[128];
    ssize_t n = recv(g_tor_control, reply, sizeof(reply) - 1, 0);
    if (n < 3)
        return "no reply to SETCONF DisableNetwork=0";
    reply[n] = '\0';
    if (strncmp(reply, "250", 3) != 0)
        return "SETCONF DisableNetwork=0 was refused";
    return NULL;
#endif
}

/* A failed enable is retried with a doubling pause (20 ms up to about 5 s)
 * and logged on attempts 1, 2, 4, 8, ... only, so a missing control socket
 * does not spin the monitor or flood the log. */
static bool tor_enable_network(void)
{
    if (tor_wall_ms() < atomic_load(&g_enable_retry_ms))
        return false;
    const char *why = tor_control_enable();
    if (why) {
        unsigned failures = atomic_fetch_add(&g_enable_failures, 1) + 1;
        unsigned shift = failures < 9 ? failures : 9;
        atomic_store(&g_enable_retry_ms, tor_wall_ms() + (10LL << shift));
        if ((failures & (failures - 1)) == 0)
            LOG_ERROR("tor", "%s (attempt %u); the network stays disabled "
                             "and the enable is retried", why, failures);
        return false;
    }
    atomic_store(&g_enable_failures, 0);
    atomic_store(&g_enable_retry_ms, 0);
    int64_t now = tor_wall_ms();
    atomic_store(&g_network_enabled_ms, now);
    printf("Tor: claim verified at %lld ms, network enabled at %lld ms "
           "(DisableNetwork 0)\n",
           (long long)atomic_load(&g_claim_ms), (long long)now);
    fflush(stdout);
    return true;
}

#ifdef ZCL_TESTING
bool tor_integration_enable_network_for_test(void)
{
    return tor_enable_network();
}

unsigned tor_integration_enable_failures_for_test(void)
{
    return atomic_load(&g_enable_failures);
}

void tor_integration_enable_reset_for_test(void)
{
    atomic_store(&g_enable_failures, 0);
    atomic_store(&g_enable_retry_ms, 0);
}

/* Test seam: the monitor reads the gate as closed without running it, so a
 * fixture reaches that path with the network still disabled. */
static _Atomic bool g_test_gate_closed = false;

void tor_integration_close_gate_for_test(bool closed)
{
    atomic_store(&g_test_gate_closed, closed);
}
#endif

/* One gate pass from the monitor loop. */
static enum tor_gate tor_monitor_gate_step(bool *enabled)
{
#ifdef ZCL_TESTING
    if (atomic_load(&g_test_gate_closed))
        return TOR_GATE_CLOSED;
#endif
    return tor_network_gate_step(dynhost_get_global_service(), false,
                                 tor_enable_network, enabled);
}

/* The monitor of a node that serves no onion: run the gate, then wait for
 * Tor to bootstrap, then keep verifying for as long as Tor runs. */
static void tor_monitor_without_service(const char *datadir)
{
    char log_path[1024];
    if (!dynhost_get_global_service ||
        !tor_log_path(datadir, log_path, sizeof(log_path)))
        return;  /* Tor stub: there is no dynhost to claim */
    bool enabled = false;
    bool announced = false;
    for (unsigned spin = 0; atomic_load(&g_tor_running); spin++) {
        enum tor_gate gate = tor_monitor_gate_step(&enabled);
        if (gate == TOR_GATE_CLOSED) {
            tor_request_exit();
            return;
        }
        if (enabled && !announced &&
            tor_log_has_bootstrap_complete(log_path, g_tor_log_scan_from)) {
            atomic_store(&g_tor_dial_ready, true);
            printf("Tor: bootstrapped; outbound only, no onion service\n");
            fflush(stdout);
            announced = true;
        }
        if (!enabled || (spin & 0xFF) == 0)
            thread_liveness_beat(&g_tor_monitor_liveness,
                                 (int64_t)atomic_fetch_add(
                                     &g_tor_monitor_poll_count, 1) + 1);
        platform_sleep_ms(enabled ? 1000 : 1);
    }
}

static void *tor_onion_monitor(void *arg)
{
    (void)arg;
    if (!atomic_load(&g_serve_onion)) {
        tor_monitor_without_service(g_tor_datadir);
        return NULL;
    }
    if (read_onion_address(g_tor_datadir)) {
        atomic_store(&g_tor_ready, true);

        /* Propagate address to onion service layer */
        extern void onion_service_set_address(const char *);
        onion_service_set_address(g_onion_address);

        printf("Tor: DESCRIPTOR PUBLICATION observed for %s\n",
               g_onion_address);
        fflush(stdout);
    } else {
        if (atomic_load(&g_tor_running))
            fprintf(stderr, "Tor: timed out waiting for .onion\n");
    }
    return NULL;
}

/* Android embedded Tor sends a padding cell on each idle OR channel, and
 * every one wakes the zcl_tor thread. ReducedConnectionPadding (Tor's
 * mobile-client setting) sends less channel padding and does not hold OR
 * connections open as long. Circuit padding is deliberately left at Tor's
 * default: it protects onion circuit setup (proposal 302 intro and rend
 * hiding) and runs only during circuit setup, so it adds no idle wake-ups.
 * Z23 is never a relay, so only the phone build takes this; servers and
 * desktop keep Tor's default padding, which defends against traffic
 * analysis. */
static bool tor_reduced_padding_for_platform(void)
{
#if defined(__ANDROID__)
    return true;
#else
    return false;
#endif
}

#ifdef ZCL_TESTING
/* Test seam: one extra torrc line appended after tor_write_torrc(), so an
 * in-process test can start the real Tor with DisableNetwork 1 and never
 * touch the public network. Absent from production builds. */
static char g_test_extra_torrc[128];

void tor_integration_set_extra_torrc_for_test(const char *line)
{
    snprintf(g_test_extra_torrc, sizeof(g_test_extra_torrc), "%s",
             line ? line : "");
}

static bool tor_append_test_torrc(const char *datadir)
{
    if (!g_test_extra_torrc[0])
        return true;
    char path[1024];
    int pn = snprintf(path, sizeof(path), "%s/torrc", datadir);
    if (pn < 0 || (size_t)pn >= sizeof(path))
        return false;
    FILE *f = fopen(path, "a");
    if (!f)
        return false;
    bool ok = fprintf(f, "%s\n", g_test_extra_torrc) > 0;
    ok = (fflush(f) == 0 && !ferror(f)) && ok;
    return (fclose(f) == 0) && ok;
}
#endif

/* Serializes start and stop, so a stop racing a start ends one whole run: it
 * either finds nothing started yet or finds a run it can end and join. */
static pthread_mutex_t g_tor_lifecycle = PTHREAD_MUTEX_INITIALIZER;

#ifdef ZCL_TESTING
/* Test seam: runs inside a start, after the Tor thread exists and before the
 * run can be stopped, so a test can put a stop in exactly that window. */
static void (*g_test_start_window)(void);

void tor_integration_set_start_window_for_test(void (*window)(void))
{
    g_test_start_window = window;
}
#endif

/* End the current run, if any, and release everything it held. Caller holds
 * g_tor_lifecycle.
 *
 * The request is event-driven, so a healthy Tor is joined as soon as its loop
 * reads it. Bound: if the thread has not ended after 10 s (the same total as
 * the earlier 5 s of retries plus a 5 s join) the join names the straggler on
 * stderr and keeps waiting, retaining ownership. What ends a node with Tor
 * stuck is the shutdown stage this runs in: frontend-stop's 15 s alarm
 * (engine/composition/src/boot_services_shutdown.c) forces the exit. The 90 s
 * watchdog (engine/entry/main.c) covers the time before a stage is armed.
 * Once Tor runs its shutdown, its own timer asserts if the loop fails to exit
 * within 10 s, as it always has. */
static void tor_run_end(void)
{
    if (!atomic_exchange(&g_tor_started, false))
        return; /* Never started or already stopped */

    atomic_store(&g_tor_running, false);
    atomic_store(&g_tor_ready, false);
    atomic_store(&g_tor_dial_ready, false);
    /* No hidden-service route any more: loopback goes back to meaning
     * same-host. Disarming can only ever RESTORE a trust exemption, so it
     * belongs here, on the way down. */
    net_set_onion_ingress_port(0);

    tor_request_exit();
    tor_join_thread_bounded(g_tor_thread, "main", 10);
    if (g_tor_control != PLATFORM_SOCKET_INVALID)
        (void)platform_socket_close(g_tor_control);
    g_tor_control = PLATFORM_SOCKET_INVALID;
    g_tor_control_peer = PLATFORM_SOCKET_INVALID;
    atomic_store(&g_network_enabled_ms, -1);
    atomic_store(&g_claim_ms, -1);
    thread_liveness_retire(&g_tor_liveness);
}

static _Atomic int g_tor_starts_in_process;

bool tor_integration_start_limit_reached(void)
{
    return tor_is_linked() &&
           atomic_load(&g_tor_starts_in_process) >= TOR_MAX_STARTS_IN_PROCESS;
}

#ifdef ZCL_TESTING
void tor_integration_set_start_count_for_test(int starts)
{
    atomic_store(&g_tor_starts_in_process, starts);
}
#endif

/* -onion-rotate asks for one new identity for this process, at its first start.
 * A later start in the same process (the watch retrying a Tor that died, or Tor
 * ended by itself) must come back on the address already announced. Caller holds
 * g_tor_lifecycle. False only when the retired name is invalid. */
static bool tor_onion_rotate_once(const char *datadir)
{
    static bool rotated_this_process;
    if (!atomic_load(&g_onion_rotate) || rotated_this_process)
        return true;
    rotated_this_process = true;

    char old[128];
    if (onion_identity_rotate(datadir, old, sizeof(old))) {
        size_t old_len = strlen(old);
        if (old_len + sizeof(".onion") > sizeof(g_rotated_old_address)) {
            LOG_WARN("tor", "rotated onion identity name is invalid");
            return false;
        }
        memcpy(g_rotated_old_address, old, old_len);
        memcpy(g_rotated_old_address + old_len, ".onion", sizeof(".onion"));
    } else {
        fprintf(stderr,  // obs-ok:rotation-named-noop
                "Tor: -onion-rotate found no existing persistent "
                "identity to archive; a fresh one will be minted\n");
    }
    return true;
}

#ifdef ZCL_TESTING
bool tor_integration_rotate_once_for_test(const char *datadir)
{
    pthread_mutex_lock(&g_tor_lifecycle);
    bool ok = tor_onion_rotate_once(datadir);
    pthread_mutex_unlock(&g_tor_lifecycle);
    return ok;
}
#endif

static bool tor_start_locked(const char *datadir, uint16_t p2p_port)
{
    if (atomic_load(&g_tor_running))
        return true;
    /* A run that ended on its own still holds a thread and a socket. */
    tor_run_end();

    if (tor_integration_start_limit_reached())
        LOG_FAIL("tor", "Tor has started %d times in this process, the most it "
                        "can take; the onion stays off until the process is "
                        "restarted", TOR_MAX_STARTS_IN_PROCESS);

    snprintf(g_tor_datadir, sizeof(g_tor_datadir), "%s", datadir);
    atomic_store(&g_tor_p2p_port, p2p_port);
    g_onion_address[0] = '\0';
    g_rotated_old_address[0] = '\0';
    atomic_store(&g_persist_install_state, 0);

    if (atomic_load(&g_onion_persist) && !tor_persist_symbols_available()) {
        LOG_WARN("tor", "-onion-persist requested but Tor is disabled "
                        "(stub build) — the .onion identity will NOT "
                        "persist across boots");
        atomic_store(&g_onion_persist, false);
        atomic_store(&g_onion_rotate, false);
    }
    if (!tor_onion_rotate_once(datadir))
        return false;

    char path[1024];
    snprintf(path, sizeof(path), "%s/tor_data", datadir);
    if (!platform_private_directory_ensure(path))
        LOG_FAIL("tor", "failed to create private Tor datadir");
    snprintf(path, sizeof(path), "%s/tor_data/onion_service", datadir);
    if (!platform_private_directory_ensure(path))
        LOG_FAIL("tor", "failed to create private onion-service datadir");

    /* Remove stale lock file from previous session. When the node is
     * killed (SIGTERM from systemctl), Tor may not clean up its lock.
     * Safe to remove: we're the only process that uses this tor_data. */
    snprintf(path, sizeof(path), "%s/tor_data/lock", datadir);
    if (!platform_private_file_unlink_missing_ok(path))
        LOG_FAIL("tor", "failed to retire stale Tor lock");

    /* Record each Tor log's current size BEFORE the tor thread can append:
     * the address scan in read_onion_address starts here, so it can only see
     * the service THIS start creates (see tor_log_last_ephemeral_address).
     * Both logs are ALSO size-bounded by the periodic housekeeping, which
     * can truncate one between boots; a recorded offset past the end of a
     * rotated file would hide every line of this boot, so an offset larger
     * than the file is discarded rather than trusted. */
    g_tor_log_scan_from = tor_log_scan_offset(datadir, tor_log_path);
    g_tor_rend_log_scan_from = tor_log_scan_offset(datadir, tor_rend_log_path);

    if (!tor_write_torrc_ex(datadir, p2p_port,
                             tor_reduced_padding_for_platform(),
                             !atomic_load(&g_serve_onion)))
        LOG_FAIL("tor", "failed to write torrc to %s", datadir);

#ifdef ZCL_TESTING
    if (!tor_append_test_torrc(datadir))
        LOG_FAIL("tor", "failed to append test torrc line in %s", datadir);
#endif

    /* Register our handler with Tor's dynhost before starting.
     * All .onion HTTP requests will route through dynhost_bridge →
     * g_request_handler → onion_service_handle_request. */
    if (g_request_handler) {
        dynhost_webserver_set_external_handler(dynhost_bridge, NULL);
        printf("Tor: external handler registered for .onion requests\n");
    }

    atomic_store(&g_tor_ready, false);
    atomic_store(&g_tor_dial_ready, false);
    atomic_store(&g_monitor_started, false);

    /* Tor exits only through this socket, so no socket means no start. */
    if (!tor_control_open())
        LOG_FAIL("tor", "cannot create Tor's owning control connection: %s",
                 strerror(errno));

    atomic_fetch_add(&g_tor_starts_in_process, 1);
    atomic_store(&g_tor_running, true);
    if (thread_registry_spawn("zcl_tor", tor_thread_fn, NULL,
                                  &g_tor_thread) != 0) {
        atomic_store(&g_tor_running, false);
        (void)platform_socket_close(g_tor_control);
        (void)platform_socket_close(g_tor_control_peer);
        g_tor_control = PLATFORM_SOCKET_INVALID;
        g_tor_control_peer = PLATFORM_SOCKET_INVALID;
        LOG_FAIL("tor", "thread_registry_spawn failed for tor thread");
    }
#ifdef ZCL_TESTING
    if (g_test_start_window)
        g_test_start_window();
#endif
    atomic_store(&g_tor_started, true);
    thread_liveness_register(&g_tor_liveness, "zcl_tor", 0, 0);
    return true;
}

/* Set by a stop, cleared by an explicit start, guarded by g_tor_lifecycle. A retry
 * decided on before a stop must not bring Tor back after it. */
static bool g_tor_stop_latched;

bool tor_integration_start(const char *datadir, uint16_t p2p_port)
{
    pthread_mutex_lock(&g_tor_lifecycle);
    g_tor_stop_latched = false;
    bool started = tor_start_locked(datadir, p2p_port);
    pthread_mutex_unlock(&g_tor_lifecycle);
    return started;
}

bool tor_integration_retry_start(const char *datadir, uint16_t p2p_port)
{
    pthread_mutex_lock(&g_tor_lifecycle);
    bool started = !g_tor_stop_latched && tor_start_locked(datadir, p2p_port);
    pthread_mutex_unlock(&g_tor_lifecycle);
    return started;
}

void tor_integration_stop(void)
{
    tor_integration_clear_requested();
    pthread_mutex_lock(&g_tor_lifecycle);
    g_tor_stop_latched = true;
    tor_run_end();
    pthread_mutex_unlock(&g_tor_lifecycle);
}

#ifdef ZCL_TESTING
/* Test seam: this run's two control sockets and the identity of Tor's end, or
 * false when it holds none. */
bool tor_integration_control_sockets_for_test(int64_t *ours, int64_t *tors,
                                              uint64_t *tors_dev,
                                              uint64_t *tors_ino)
{
    pthread_mutex_lock(&g_tor_lifecycle);
    bool held = g_tor_control != PLATFORM_SOCKET_INVALID;
    *ours = (int64_t)g_tor_control;
    *tors = (int64_t)g_tor_control_peer;
#ifndef _WIN32
    *tors_dev = (uint64_t)g_tor_control_peer_id.st_dev;
    *tors_ino = (uint64_t)g_tor_control_peer_id.st_ino;
#else
    *tors_dev = 0;
    *tors_ino = 0;
#endif
    pthread_mutex_unlock(&g_tor_lifecycle);
    return held;
}
#endif

const char *tor_integration_get_onion_address(void)
{
    if (!atomic_load(&g_tor_ready))
        return NULL;  /* not ready yet — normal during startup */
    return g_onion_address;
}

bool tor_integration_is_ready(void)
{
    return atomic_load(&g_tor_ready);
}

bool tor_integration_is_dial_ready(void)
{
    return atomic_load(&g_tor_dial_ready) &&
           !atomic_load(&g_service_violated);
}

#ifdef ZCL_TESTING
void tor_integration_set_dial_ready_for_test(bool ready)
{
    atomic_store(&g_tor_dial_ready, ready);
}
#endif

bool tor_integration_is_enabled(void)
{
    return atomic_load(&g_tor_running);
}
