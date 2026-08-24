/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tor is compiled INTO zclassic23. No external binary. zclassic23 does not
 * proxy application traffic through SOCKS; dynhost handles .onion requests
 * via direct C callbacks. A localhost-only SocksPort remains as a temporary
 * Tor bootstrap workaround in tor_write_torrc(). */

#define _GNU_SOURCE  /* pthread_timedjoin_np */
#define _DEFAULT_SOURCE
#include "platform/time_compat.h"
#include "net/tor_integration.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>   /* AF_INET for the inbound P2P port mapping */
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "crypto/ed25519.h"
#include "crypto/random_secret.h"
#include "sha3/sha3.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include "util/thread_liveness.h"
#include "util/thread_registry.h"

static pthread_t g_tor_thread;
static pthread_t g_monitor_thread;
static _Atomic bool g_tor_running = false;
static _Atomic bool g_tor_ready = false;
static _Atomic bool g_tor_dial_ready = false;
static _Atomic bool g_tor_requested = false; /* operator asked for onion */
static _Atomic bool g_tor_started = false;   /* true once tor thread spawn succeeds */
static _Atomic bool g_tor_thread_done = false; /* true once tor thread returns */
static _Atomic bool g_monitor_started = false;

/* Supervisor liveness (root children — lib/net cannot include the app-side
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
    rc = pthread_timedjoin_np(thread, NULL, &deadline);
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
bool tor_write_torrc(const char *datadir, uint16_t p2p_port)
{
    char torrc_path[1024];
    snprintf(torrc_path, sizeof(torrc_path), "%s/torrc", datadir);

    FILE *f = fopen(torrc_path, "w");
    if (!f) LOG_FAIL("tor", "failed to open torrc for writing: %s", torrc_path);

    /* Localhost-only SocksPort — NOTHING connects to this.
     * It exists only because Tor won't bootstrap without a listener.
     * Derived from p2p_port to avoid collisions (8033→19999, 8035→20001).
     * When the Tor fork supports SocksPort 0 with dynhost, replace
     * this with "SocksPort 0\n". */
    uint16_t bootstrap_port = (uint16_t)(p2p_port + 11966);
    fprintf(f,
        "SocksPort 127.0.0.1:%u\n"
        "DataDirectory %s/tor_data\n"
        "Log notice file %s/tor.log\n"
        "Log info [rend] file %s/tor.log\n",
        bootstrap_port, datadir, datadir, datadir);

    fclose(f);
    return true;
}

/* Scan the dynhost log from byte offset scan_from and return the LAST
 * "ephemeral service created with address:" match. Last-match + offset are
 * both load-bearing: the log appends across boots and every Tor start mints
 * a fresh ephemeral service, so an earlier line names a dead service (the
 * old first-match-from-zero scan reported/published a dead onion after
 * every restart). If the file shrank below scan_from (rotated/truncated),
 * the scan restarts from the top. Exposed for testing. */
bool tor_log_last_ephemeral_address(const char *log_path, long scan_from,
                                    char *out, size_t out_size)
{
    if (!log_path || !out || out_size == 0)
        return false;

    FILE *f = fopen(log_path, "r");
    if (!f)
        return false;

    if (scan_from > 0) {
        if (fseek(f, 0, SEEK_END) != 0 || ftell(f) < scan_from ||
            fseek(f, scan_from, SEEK_SET) != 0)
            rewind(f);
    }

    static const char marker[] = "ephemeral service created with address: ";
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        char *p = strstr(line, marker);
        if (!p)
            continue;
        p += sizeof(marker) - 1;
        char *end = p;
        while (*end && *end != '\n' && *end != '\r' && *end != ' ')
            end++;
        size_t len = (size_t)(end - p);
        if (len > 0 && len < out_size) {
            memcpy(out, p, len);
            out[len] = '\0';
            found = true;   /* keep scanning — a later line supersedes */
        }
    }
    fclose(f);
    return found;
}

bool tor_log_has_descriptor_publication(const char *log_path, long scan_from)
{
    if (!log_path)
        return false;

    FILE *f = fopen(log_path, "r");
    if (!f)
        return false;

    if (scan_from > 0) {
        if (fseek(f, 0, SEEK_END) != 0 || ftell(f) < scan_from ||
            fseek(f, scan_from, SEEK_SET) != 0)
            rewind(f);
    }

    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        /* Success-only: a hostname file or a failed upload must not count.
         * "DESCRIPTOR PUBLICATION" is the first-boot ready marker the
         * installer selftest greps for; the rest are stock Tor rend lines
         * that become visible once torrc logs info [rend]. */
        if (strstr(line, "DESCRIPTOR PUBLICATION") != NULL ||
            strstr(line, "Uploaded hidden service descriptor (status 200") != NULL ||
            strstr(line, "finished with status 200") != NULL ||
            strstr(line, "HS_DESC UPLOADED") != NULL) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

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
 *    the dynhost subsystem to appear inside the Tor thread, registers an
 *    ephemeral service built from OUR persisted seed via
 *    hs_service_add_ephemeral, and points dynhost's global hs_service at
 *    it before dynhost_check_and_activate can mint its throwaway (that
 *    activation is gated on a live consensus + completed circuit, which
 *    takes seconds after the 1s poll here sees the subsystem). If the race
 *    is ever lost, dynhost's throwaway stays registered but unreferenced
 *    (harmless): the pointer swap below still retargets interception at
 *    our persistent service because the comparison reads
 *    dynhost->hs_service at connection time. */

/* RFC 4648 base32, lowercase, no padding (the prop224 alphabet). */
static void base32_lower_encode(const uint8_t *data, size_t len, char *out)
{
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyz234567";
    unsigned int buffer = 0;
    int bits = 0;
    char *p = out;
    for (size_t i = 0; i < len; i++) {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            *p++ = alpha[(buffer >> (bits - 5)) & 31u];
            bits -= 5;
        }
    }
    if (bits > 0)
        *p++ = alpha[(buffer << (5 - bits)) & 31u];
    *p = '\0';
}

bool onion_identity_address_from_seed(const uint8_t seed[32],
                                      char *out, size_t out_size)
{
    if (!seed || !out || out_size < 57)
        LOG_FAIL("tor", "onion_identity_address_from_seed: bad args "
                        "(out_size=%zu)", out_size);

    uint8_t pk[32], sk[32];
    ed25519_keypair(pk, sk, seed);

    /* prop224: checksum = SHA3-256(".onion checksum" || pubkey || version)
     * [0..1]; address = base32(pubkey || checksum || version), version 3. */
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const char prefix[] = ".onion checksum";
    sha3_256_write(&ctx, (const unsigned char *)prefix, sizeof(prefix) - 1);
    sha3_256_write(&ctx, pk, sizeof(pk));
    const uint8_t version = 3;
    sha3_256_write(&ctx, &version, 1);
    uint8_t digest[SHA3_256_OUTPUT_SIZE];
    sha3_256_finalize(&ctx, digest);

    uint8_t blob[35];
    memcpy(blob, pk, 32);
    blob[32] = digest[0];
    blob[33] = digest[1];
    blob[34] = version;
    base32_lower_encode(blob, sizeof(blob), out);   /* exactly 56 chars */
    return true;
}

/* Resolve <datadir>/tor_data/onion_service, creating it (and tor_data) with
 * mode 0700 when missing. */
static bool onion_identity_dir(const char *datadir, char *dir_out,
                               size_t dir_size)
{
    if (!datadir || !dir_out)
        LOG_FAIL("tor", "onion_identity_dir: missing datadir or dir_out");
    int n = snprintf(dir_out, dir_size, "%s/tor_data/onion_service", datadir);
    if (n < 0 || (size_t)n >= dir_size)
        LOG_FAIL("tor", "onion identity path too long for datadir: %s",
                 datadir);

    char td[1024];
    snprintf(td, sizeof(td), "%s/tor_data", datadir);
    if (mkdir(td, 0700) != 0 && errno != EEXIST)
        LOG_FAIL("tor", "mkdir %s failed: %s", td, strerror(errno));
    if (mkdir(dir_out, 0700) != 0 && errno != EEXIST)
        LOG_FAIL("tor", "mkdir %s failed: %s", dir_out, strerror(errno));
    return true;
}

bool onion_identity_ensure(const char *datadir, uint8_t seed_out[32],
                           char *addr_out, size_t addr_out_size,
                           bool *created_out)
{
    if (!datadir || !seed_out)
        LOG_FAIL("tor", "onion_identity_ensure: missing datadir or seed_out");

    char dir[1024];
    if (!onion_identity_dir(datadir, dir, sizeof(dir)))
        return false;

    char seed_path[1152], hostname_path[1152];
    snprintf(seed_path, sizeof(seed_path), "%s/identity_seed", dir);
    snprintf(hostname_path, sizeof(hostname_path), "%s/hostname", dir);

    bool created = false;
    int fd = open(seed_path, O_RDONLY);
    if (fd >= 0) {
        ssize_t got = read(fd, seed_out, 32);
        close(fd);
        if (got != 32)
            LOG_FAIL("tor", "onion identity seed corrupt (%zd bytes, want "
                            "32): %s — refusing to silently remint (that "
                            "would change the shop's address); restore the "
                            "file or pass -onion-rotate", got, seed_path);
    } else {
        if (errno != ENOENT)
            LOG_FAIL("tor", "cannot open onion identity seed %s: %s",
                     seed_path, strerror(errno));
        if (!zcl_random_secret_bytes(seed_out, 32, "onion_identity_seed"))
            LOG_FAIL("tor", "CSPRNG refused the onion identity seed");
        fd = open(seed_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0)
            LOG_FAIL("tor", "cannot write onion identity seed %s: %s",
                     seed_path, strerror(errno));
        ssize_t put = write(fd, seed_out, 32);
        close(fd);
        if (put != 32)
            LOG_FAIL("tor", "short write on onion identity seed %s",
                     seed_path);
        created = true;
    }

    char addr[57];
    if (!onion_identity_address_from_seed(seed_out, addr, sizeof(addr)))
        return false;

    /* Standard Tor hostname-file semantics: "<addr>.onion\n". Rewritten
     * every boot (idempotent content) so a lost hostname file self-heals. */
    int hfd = open(hostname_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (hfd < 0)
        LOG_FAIL("tor", "cannot write onion hostname file %s: %s",
                 hostname_path, strerror(errno));
    char hline[80];
    int hlen = snprintf(hline, sizeof(hline), "%s.onion\n", addr);
    ssize_t hput = write(hfd, hline, (size_t)hlen);
    close(hfd);
    if (hput != hlen)
        LOG_FAIL("tor", "short write on onion hostname file %s",
                 hostname_path);

    if (addr_out) {
        if (addr_out_size < 57)
            LOG_FAIL("tor", "addr_out too small (%zu, want 57)",
                     addr_out_size);
        memcpy(addr_out, addr, 57);
    }
    if (created_out)
        *created_out = created;
    return true;
}

bool onion_identity_rotate(const char *datadir, char *old_addr_out,
                           size_t old_addr_size)
{
    if (!datadir || !old_addr_out || old_addr_size < 57)
        LOG_FAIL("tor", "onion_identity_rotate: bad args");

    char dir[1024];
    if (!onion_identity_dir(datadir, dir, sizeof(dir)))
        return false;

    char seed_path[1152], hostname_path[1152];
    snprintf(seed_path, sizeof(seed_path), "%s/identity_seed", dir);
    snprintf(hostname_path, sizeof(hostname_path), "%s/hostname", dir);

    uint8_t seed[32];
    int fd = open(seed_path, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) {
            LOG_WARN("tor", "-onion-rotate: no persistent identity at %s — "
                            "nothing to archive", seed_path);
            return false;
        }
        LOG_FAIL("tor", "cannot open onion identity seed %s: %s",
                 seed_path, strerror(errno));
    }
    ssize_t got = read(fd, seed, sizeof(seed));
    close(fd);
    if (got != (ssize_t)sizeof(seed))
        LOG_FAIL("tor", "onion identity seed corrupt (%zd bytes, want 32): "
                        "%s — refusing to rotate a corrupt identity; restore "
                        "or delete the file deliberately", got, seed_path);

    char addr[57];
    if (!onion_identity_address_from_seed(seed, addr, sizeof(addr)))
        return false;

    char archive[1280];
    snprintf(archive, sizeof(archive), "%s/archive", dir);
    if (mkdir(archive, 0700) != 0 && errno != EEXIST)
        LOG_FAIL("tor", "mkdir %s failed: %s", archive, strerror(errno));

    /* Archive under the old address: each rotated identity lands at a
     * unique, self-describing path. */
    char seed_arch[1408], host_arch[1408];
    snprintf(seed_arch, sizeof(seed_arch), "%s/identity_seed.%s",
             archive, addr);
    snprintf(host_arch, sizeof(host_arch), "%s/hostname.%s", archive, addr);
    if (rename(seed_path, seed_arch) != 0)
        LOG_FAIL("tor", "failed to archive onion identity seed to %s: %s",
                 seed_arch, strerror(errno));
    if (rename(hostname_path, host_arch) != 0 && errno != ENOENT)
        LOG_FAIL("tor", "failed to archive onion hostname to %s: %s",
                 host_arch, strerror(errno));

    memcpy(old_addr_out, addr, 57);
    return true;
}

/* ── Persistent identity install (real-Tor builds only) ────────
 *
 * Layout mirrors of the vendored dynhost/HS types. tor_integration.c
 * declares the Tor embedding API locally (the same style as
 * tor_main_configuration_* above) because vendor/tor headers are not on
 * the include path; the fork is pinned, and the boot-time cross-check
 * below (pure-derived address vs Tor-derived) fails loudly if these ever
 * drift. All weak: NULL under the Tor stub. */
typedef struct { uint8_t seckey[64]; } tor_ed25519_secret_key_t;
typedef struct { uint8_t pubkey[32]; } tor_ed25519_public_key_t;
typedef struct smartlist_t tor_smartlist_t;

struct tor_addr_compat {                 /* tor_addr_t (linux layout) */
    uint16_t family;                     /* sa_family_t; 0 == AF_UNSPEC */
    union {
        uint32_t dummy_;
        uint8_t in_addr[4];
        uint8_t in6_addr[16];
    } addr;
};
typedef struct {                         /* hs_port_config_t */
    uint16_t virtual_port;
    unsigned int is_unix_addr : 1;
    uint16_t real_port;
    struct tor_addr_compat real_addr;
    char unix_addr[];
} tor_hs_port_config_t;

/* dynhost_service_t: only the first member is ever touched. */
struct dynhost_service_head_compat {
    void *hs_service;
};

extern void *dynhost_get_global_service(void) __attribute__((weak));
/* Tor names the real symbol tor_malloc_zero_ (tor_malloc_zero is a macro
 * over it); the weak extern must use the underscored name or it resolves
 * NULL against libtor.a and reads as "stub build". */
extern void *tor_malloc_zero_(size_t n) __attribute__((weak));
extern void tor_free_(void *ptr) __attribute__((weak));
extern tor_smartlist_t *smartlist_new(void) __attribute__((weak));
extern void smartlist_free_(tor_smartlist_t *sl) __attribute__((weak));
extern void smartlist_add(tor_smartlist_t *sl, void *element)
    __attribute__((weak));
extern int ed25519_secret_key_from_seed(tor_ed25519_secret_key_t *out,
                                        const uint8_t *seed)
    __attribute__((weak));
extern int hs_service_add_ephemeral(tor_ed25519_secret_key_t *sk,
    tor_smartlist_t *ports, int max_streams_per_rdv_circuit,
    int max_streams_close_circuit, int pow_defenses_enabled,
    uint32_t pow_queue_rate, uint32_t pow_queue_burst,
    tor_smartlist_t *auth_clients_v3, char **address_out)
    __attribute__((weak));
extern int hs_parse_address(const char *address,
    tor_ed25519_public_key_t *key_out, uint8_t *checksum_out,
    uint8_t *version_out) __attribute__((weak));
extern void *hs_service_find(const tor_ed25519_public_key_t *identity_pk)
    __attribute__((weak));

/* True when every Tor/dynhost symbol the install path needs is linked. */
static bool tor_persist_symbols_available(void)
{
    return dynhost_get_global_service && tor_malloc_zero_ && tor_free_ &&
           smartlist_new && smartlist_free_ && smartlist_add &&
           ed25519_secret_key_from_seed && hs_service_add_ephemeral &&
           hs_parse_address && hs_service_find;
}

/* One install attempt from the monitor poll loop.
 * Returns 1 once the persistent service is registered with dynhost,
 * 0 while the dynhost subsystem is not up yet (retry next poll — not an
 * error), -1 on a named hard failure. */
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

    /* Build the Tor-side service key from the SAME persisted seed. */
    tor_ed25519_secret_key_t *sk = tor_malloc_zero_(sizeof(*sk));
    if (!sk)
        LOG_ERR("tor", "tor_malloc_zero_ failed for service key");
    if (ed25519_secret_key_from_seed(sk, seed) != 0) {
        tor_free_(sk);
        LOG_ERR("tor", "ed25519_secret_key_from_seed rejected the "
                       "persisted onion identity seed");
    }

    /* Virtual port 80 with NO real port — exactly how dynhost.c configures
     * its own service: interception happens before any real-port mapping
     * is consulted, so real_addr stays AF_UNSPEC. */
    tor_smartlist_t *ports = smartlist_new();
    tor_hs_port_config_t *pc = NULL;
    tor_hs_port_config_t *p2p_pc = NULL;
    if (ports) {
        pc = tor_malloc_zero_(sizeof(*pc) + 1);
        p2p_pc = tor_malloc_zero_(sizeof(*p2p_pc) + 1);
    }
    if (!ports || !pc || !p2p_pc) {
        if (pc) tor_free_(pc);
        if (p2p_pc) tor_free_(p2p_pc);
        if (ports) smartlist_free_(ports);
        tor_free_(sk);
        LOG_ERR("tor", "allocation failed for persistent onion ports");
    }
    pc->virtual_port = 80;
    smartlist_add(ports, pc);

    /* SECOND port mapping: the node's P2P port. Inbound P2P rides the
     * persistent onion identity at <onion>:<p2p_port>, forwarded to the
     * local listener by stock Tor hidden-service machinery
     * (hs_service.c -> connection_exit_connect) as an ordinary TCP
     * connection from 127.0.0.1 — no fork change needed. Deliberately NOT
     * dynhost_add_virtual_port: that would route the port into the HTTP
     * interception layer (dynhost_handlers.c), which exists for port-80
     * traffic only. */
    uint16_t p2p_port = atomic_load(&g_tor_p2p_port);
    if (p2p_port > 0 && p2p_port != 80) {
        p2p_pc->virtual_port = p2p_port;
        p2p_pc->is_unix_addr = 0;
        p2p_pc->real_port = p2p_port;
        p2p_pc->real_addr.family = AF_INET;
        p2p_pc->real_addr.addr.in_addr[0] = 127;
        p2p_pc->real_addr.addr.in_addr[1] = 0;
        p2p_pc->real_addr.addr.in_addr[2] = 0;
        p2p_pc->real_addr.addr.in_addr[3] = 1;
        smartlist_add(ports, p2p_pc);
    } else {
        tor_free_(p2p_pc);
    }

    char *address_out = NULL;
    /* Ownership of sk and ports passes to Tor on EVERY path below. */
    int status = hs_service_add_ephemeral(sk, ports, 0, 0, 0, 0, 0, NULL,
                                          &address_out);
    if (status != 0 || !address_out)
        LOG_ERR("tor", "hs_service_add_ephemeral failed (status=%d) for "
                       "the persistent onion identity", status);

    /* Cross-check: Tor's derivation MUST equal the pure layer's (the unit
     * vector pins the pure layer to prop224). A mismatch means the
     * vendored fork drifted under us — fail loudly, never report one
     * address while serving another. */
    if (strcmp(address_out, addr) != 0) {
        tor_free_(address_out);
        LOG_ERR("tor", "Tor-derived persistent address does not match the "
                       "pure prop224 derivation — vendored fork drift");
    }

    tor_ed25519_public_key_t pk;
    void *service = NULL;
    if (hs_parse_address(address_out, &pk, NULL, NULL) == 0)
        service = hs_service_find(&pk);
    if (!service) {
        tor_free_(address_out);
        LOG_ERR("tor", "persistent onion service missing right after "
                       "registration: %s", address_out);
    }

    /* Become the dynhost service (see the layer-2 comment above). */
    ((struct dynhost_service_head_compat *)global)->hs_service = service;

    printf("Tor: persistent onion identity %s: %s.onion\n",
           created ? "minted" : "loaded", address_out);
    fflush(stdout);
    if (g_rotated_old_address[0]) {
        printf("Tor: onion identity rotated: old=%s new=%s.onion\n",
               g_rotated_old_address, address_out);
        fflush(stdout);
    }
    tor_free_(address_out);
    return 1;
}

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

    if (!enabled)
        out->state = TOR_ONION_PORT_MAP_DISABLED;
    else if (persistent && install_state < 0)
        out->state = TOR_ONION_PORT_MAP_FAILED;
    else if (!ready || (persistent && install_state != 1))
        out->state = TOR_ONION_PORT_MAP_PENDING;
    else
        out->state = TOR_ONION_PORT_MAP_INSTALLED;

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

/* Wait for the .onion address AND onion DESCRIPTOR PUBLICATION.
 * Default (ephemeral) mode: parse the dynhost log for THIS start's
 * ephemeral service. -onion-persist mode: install our persisted identity
 * into dynhost, then read the hostname file it (re)wrote.
 *
 * Hostname-only is not ready: HSDir upload can lag the hostname file, and
 * a Type=notify first-boot that fires READY=1 on hostname lets clients
 * dial a service the network cannot intro (docs/work/ONION_DIAL_GAP.md).
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
    snprintf(log_path, sizeof(log_path), "%s/tor.log", datadir);

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

        if (have_addr &&
            tor_log_has_descriptor_publication(log_path, g_tor_log_scan_from))
            return true;

        /* Slow bootstrap is a named state, not a silent hang. */
        if (++waited % 60 == 0) {
            if (have_addr)
                fprintf(stderr,  // obs-ok:bootstrap-progress-named
                        "Tor: still waiting for onion DESCRIPTOR PUBLICATION "
                        "after %ds (HSDir upload may be slow)\n", waited);
            else
                fprintf(stderr,  // obs-ok:bootstrap-progress-named
                        "Tor: still waiting for .onion address after %ds "
                        "(bootstrap may be slow)\n", waited);
        }
        sleep(1);
    }
}

/* Tor embedding API */
typedef struct tor_main_configuration_t tor_main_configuration_t;
extern tor_main_configuration_t *tor_main_configuration_new(void);
extern int tor_main_configuration_set_command_line(
    tor_main_configuration_t *cfg, int argc, char *argv[]);
extern void tor_main_configuration_free(tor_main_configuration_t *cfg);
extern int tor_run_main(const tor_main_configuration_t *);
extern void tor_shutdown_event_loop_and_exit(int exitcode);

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
    tor_main_configuration_t *cfg = tor_main_configuration_new();
    char *argv[] = {"tor", "-f", torrc_path};
    tor_main_configuration_set_command_line(cfg, 3, argv);
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
    atomic_store(&g_tor_thread_done, true);
    return NULL;
}

static void *tor_onion_monitor(void *arg)
{
    (void)arg;
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

bool tor_integration_start(const char *datadir, uint16_t p2p_port)
{
    if (atomic_load(&g_tor_running))
        return true;

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
    if (atomic_load(&g_onion_rotate)) {
        char old[128];
        if (onion_identity_rotate(datadir, old, sizeof(old))) {
            snprintf(g_rotated_old_address, sizeof(g_rotated_old_address),
                     "%s.onion", old);
        } else {
            fprintf(stderr,  // obs-ok:rotation-named-noop
                    "Tor: -onion-rotate found no existing persistent "
                    "identity to archive; a fresh one will be minted\n");
        }
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/tor_data", datadir);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "%s/tor_data/onion_service", datadir);
    mkdir(path, 0700);

    /* Remove stale lock file from previous session. When the node is
     * killed (SIGTERM from systemctl), Tor may not clean up its lock.
     * Safe to remove: we're the only process that uses this tor_data. */
    snprintf(path, sizeof(path), "%s/tor_data/lock", datadir);
    unlink(path);

    /* Record tor.log's current size BEFORE the tor thread can append: the
     * address scan in read_onion_address starts here, so it can only see
     * the service THIS start creates (see tor_log_last_ephemeral_address). */
    snprintf(path, sizeof(path), "%s/tor.log", datadir);
    struct stat log_st;
    g_tor_log_scan_from =
        (stat(path, &log_st) == 0) ? (long)log_st.st_size : 0;

    if (!tor_write_torrc(datadir, p2p_port))
        LOG_FAIL("tor", "failed to write torrc to %s", datadir);

    /* Register our handler with Tor's dynhost before starting.
     * All .onion HTTP requests will route through dynhost_bridge →
     * g_request_handler → onion_service_handle_request. */
    if (g_request_handler) {
        dynhost_webserver_set_external_handler(dynhost_bridge, NULL);
        printf("Tor: external handler registered for .onion requests\n");
    }

    atomic_store(&g_tor_running, true);
    atomic_store(&g_tor_ready, false);
    atomic_store(&g_tor_dial_ready, false);
    atomic_store(&g_tor_thread_done, false);
    atomic_store(&g_monitor_started, false);

    if (thread_registry_spawn("zcl_tor", tor_thread_fn, NULL,
                                  &g_tor_thread) != 0) {
        atomic_store(&g_tor_running, false);
        LOG_FAIL("tor", "thread_registry_spawn failed for tor thread");
    }
    atomic_store(&g_tor_started, true);
    thread_liveness_register(&g_tor_liveness, "zcl_tor", 0, 0);
    return true;
}

void tor_integration_stop(void)
{
    atomic_store(&g_tor_requested, false);
    if (!atomic_exchange(&g_tor_started, false))
        return; /* Never started or already stopped */

    atomic_store(&g_tor_running, false);
    atomic_store(&g_tor_ready, false);
    atomic_store(&g_tor_dial_ready, false);

    /* Tell Tor's event loop to exit. Retry briefly in case Tor
     * hasn't entered its main loop yet when we first call. */
    for (int i = 0; i < 50; i++) {
        tor_shutdown_event_loop_and_exit(0);
        if (atomic_load(&g_tor_thread_done))
            break;
        usleep(100000); /* 100ms, up to 5s total */
    }

    tor_join_thread_bounded(g_tor_thread, "main", 5);
    atomic_store(&g_tor_thread_done, false);
    thread_liveness_retire(&g_tor_liveness);
}

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
    return atomic_load(&g_tor_dial_ready);
}

bool tor_integration_is_enabled(void)
{
    return atomic_load(&g_tor_running);
}

void tor_integration_mark_requested(void)
{
    atomic_store(&g_tor_requested, true);
}

bool tor_integration_is_requested(void)
{
    return atomic_load(&g_tor_requested);
}

/* ── Outbound .onion fetch ─────────────────────────────────── */

/* Weak reference to dynhost_client_fetch — resolved at link time.
 * When linked against libtor_stub.a, this is NULL. */
extern int dynhost_client_fetch(const char *, uint16_t, const char *,
    void (*)(int, const uint8_t *, size_t, void *), void *, int)
    __attribute__((weak));

int tor_integration_fetch_onion(const char *onion_address,
                                 const char *path,
                                 tor_fetch_callback_fn callback,
                                 void *ctx,
                                 int timeout_secs)
{
    if (!dynhost_client_fetch)
        LOG_ERR("tor", "dynhost_client_fetch not linked (stub build)");
    if (!atomic_load(&g_tor_running))
        LOG_ERR("tor", "fetch_onion called but Tor not running");

    return dynhost_client_fetch(onion_address, 80, path,
        (void (*)(int, const uint8_t *, size_t, void *))callback,
        ctx, timeout_secs);
}

/* Callback for blocking fetch — sets result and signals completion */
/* Hard ceiling on what one onion response may allocate here, regardless of
 * what the far side claims. The remote is chosen from on-chain data or a
 * peer's directory — never trusted — and every caller applies its own,
 * tighter, purpose-specific cap on top of this one. This exists only so a
 * hostile responder cannot pick our allocation size. */
#define ONION_FETCH_BODY_MAX (1u << 20)   /* 1 MiB */

/* The waiter's deadline and the fetch callback are independent: dynhost may
 * complete AFTER we have given up. So the shared state is heap-owned and
 * refcounted rather than being the caller's stack frame — the last of the
 * two to let go frees it. Handing a stack address to a callback we cannot
 * cancel is a use-after-free waiting for a slow remote to trigger it, and
 * with the name gateway an anonymous visitor gets to choose that remote. */
struct blocking_fetch_ctx {
    _Atomic int refs;        /* waiter + callback; 0 => free */
    _Atomic int complete;    /* 0=pending, 1=ok, -1=error */
    int         status;
    uint8_t    *body;
    size_t      body_len;
};

static void blocking_fetch_release(struct blocking_fetch_ctx *c)
{
    if (atomic_fetch_sub(&c->refs, 1) == 1) {
        free(c->body);
        free(c);
    }
}

static void blocking_fetch_cb(int status, const uint8_t *body,
                                size_t body_len, void *ctx)
{
    struct blocking_fetch_ctx *c = (struct blocking_fetch_ctx *)ctx;
    c->status = status;

    if (body_len > ONION_FETCH_BODY_MAX) {
        /* Refuse, never truncate: a caller cannot tell a clipped body from a
         * short one, and half a document is the kind of input that gets
         * parsed as if it were whole. */
        LOG_WARN("tor", "onion response of %zu bytes exceeds the %u-byte "
                        "ceiling — refused", body_len,
                 (unsigned)ONION_FETCH_BODY_MAX);
        atomic_store(&c->complete, -1);
        blocking_fetch_release(c);
        return;
    }

    if (body && body_len > 0) {
        c->body = zcl_malloc(body_len + 1, "onion_fetch_body");
        if (c->body) {
            memcpy(c->body, body, body_len);
            c->body[body_len] = '\0';
            c->body_len = body_len;
        }
    }
    atomic_store(&c->complete, status >= 200 ? 1 : -1);
    blocking_fetch_release(c);
}

int tor_integration_fetch_onion_blocking(const char *onion_address,
                                          const char *path,
                                          struct onion_fetch_result *result,
                                          int timeout_secs)
{
    if (!result) LOG_ERR("tor", "fetch_onion_blocking called with NULL result");
    memset(result, 0, sizeof(*result));

    struct blocking_fetch_ctx *c =
        zcl_malloc(sizeof(*c), "onion_fetch_ctx");
    if (!c) LOG_ERR("tor", "onion fetch context allocation failed");
    memset(c, 0, sizeof(*c));
    atomic_init(&c->refs, 2);        /* one for us, one for the callback */
    atomic_init(&c->complete, 0);

    int rc = tor_integration_fetch_onion(onion_address, path,
                                          blocking_fetch_cb, c,
                                          timeout_secs);
    if (rc < 0) {
        /* Dispatch failed, so the callback will never run and never release
         * its reference — drop it on its behalf. */
        blocking_fetch_release(c);
        blocking_fetch_release(c);
        atomic_store(&result->complete, -1);
        LOG_ERR("tor", "fetch_onion failed for %s%s", onion_address, path);
    }

    int wait_ms = (timeout_secs > 0 ? timeout_secs : 60) * 1000;
    for (int elapsed = 0; elapsed < wait_ms; elapsed += 100) {
        if (atomic_load(&c->complete) != 0) {
            /* The callback is done touching the context, so the body can be
             * handed to the caller outright rather than copied again. */
            int ok = atomic_load(&c->complete) == 1;
            result->status   = c->status;
            result->body     = c->body;
            result->body_len = c->body_len;
            c->body = NULL;                     /* ownership transferred */
            atomic_store(&result->complete, ok ? 1 : -1);
            blocking_fetch_release(c);
            return ok ? 0 : -1;
        }
        usleep(100000); /* 100ms */
    }

    /* Timed out. We let go; if the fetch lands later the callback writes to
     * the heap context it still owns and frees it there. Nothing of ours
     * outlives this frame. */
    blocking_fetch_release(c);
    atomic_store(&result->complete, -1);
    LOG_ERR("tor", "fetch_onion_blocking timed out after %ds for %s%s",
            timeout_secs > 0 ? timeout_secs : 60, onion_address, path);
}
