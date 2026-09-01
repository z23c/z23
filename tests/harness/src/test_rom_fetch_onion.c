/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The ROM artifact fetch path over Tor (core/modules/net/src/rom_fetch_transport.c).
 *
 * Before this route existed, a Tor-only machine had NO way to fetch a
 * consensus-state bundle or a C23 source bundle at all: rf_connect() was a
 * bare getaddrinfo(), which cannot resolve a .onion name in principle. This
 * group proves the route exists and that it is a ROUTE, not a preference:
 *
 *   1. A .onion seeder is dialed over the SAME raw-stream path the P2P
 *      dialer uses (net/onion_stream.h -> the embedded Tor fork's dynhost
 *      streams), and the resulting fd carries bytes both ways. The dial is
 *      observed at the backend, which receives the exact onion hostname --
 *      getaddrinfo could never have produced a connected fd for that name,
 *      so the backend seeing it IS the proof of routing.
 *   2. A clearnet seeder still takes the resolver path, unchanged: it
 *      connects to a real loopback listener while the onion backend is
 *      never opened and the onion stage ledger never moves.
 *   3. A malformed .onion name fails CLOSED at the fetch layer -- refused
 *      without resolution and without a circuit. It must never degrade to
 *      DNS, and it must never degrade to clearnet.
 *   4. Reachability and speed stay separate axes. The onion budgets are
 *      their own numbers, strictly larger than the clearnet ones, and the
 *      clearnet numbers are untouched -- asserted as VALUES, never by
 *      timing a wall clock.
 *
 * No live Tor network is required or used: the raw-stream backend is a
 * loopback double, exactly as tests/harness/src/test_onion_bridge.c does it. What
 * this group therefore proves is the ROUTING and the BUDGET SHAPE, not the
 * behaviour of a real circuit.
 *
 * Nothing here touches verification. The per-chunk digest+MAC check, the
 * chunk-root fold and the whole-file digest all live in rom_fetch.c and are
 * covered by the rom_fetch group; transport cannot reach them. */

#define _DEFAULT_SOURCE   /* usleep */
#include "test/test_core.h"
#include "net/rom_fetch.h"
#include "net/onion_stream.h"
#include "net/onion_v3_address.h"
#include "net/netbase.h"
#include "platform/socket_compat.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Loopback stand-in for the embedded Tor fork ─────────────────────────
 *
 * Mirrors the fork's threading contract: read/event callbacks fire on a
 * thread that is not the caller's, and exactly one terminal event fires. */

#define STUB_ECHO_CAP (64u * 1024u)

struct rf_stub {
    onion_stream_read_fn  read_cb;
    onion_stream_event_fn event_cb;
    void                 *ctx;

    pthread_t    tid;
    bool         tid_valid;
    _Atomic bool stop;
    _Atomic bool terminal;
    _Atomic bool closed;

    /* What the fetch layer asked the circuit for. This is the observation
     * that distinguishes "routed to Tor" from "routed to the resolver". */
    char     dialed_host[ONION_V3_ADDRESS_LEN + 1];
    uint16_t dialed_port;
    unsigned opens;

    uint8_t *echo;
    size_t   echo_len;
};

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static struct rf_stub g_stub;

static void *stub_thread(void *arg)
{
    struct rf_stub *s = (struct rf_stub *)arg;

    usleep(20 * 1000);              /* circuit build */
    s->event_cb((struct onion_stream_raw *)s, ONION_STREAM_EVENT_CONNECTED,
                s->ctx);

    while (!atomic_load(&s->stop)) {
        uint8_t *out = NULL;
        size_t   out_len = 0;
        pthread_mutex_lock(&g_mu);
        if (s->echo_len > 0) {
            out = malloc(s->echo_len);
            if (out) {
                memcpy(out, s->echo, s->echo_len);
                out_len = s->echo_len;
                s->echo_len = 0;
            }
        }
        pthread_mutex_unlock(&g_mu);
        if (out_len > 0)
            s->read_cb((struct onion_stream_raw *)s, out, out_len, s->ctx);
        free(out);
        usleep(5 * 1000);
    }

    atomic_store(&s->terminal, true);
    s->event_cb((struct onion_stream_raw *)s, ONION_STREAM_EVENT_CLOSED,
                s->ctx);
    return NULL;
}

static struct onion_stream_raw *stub_open(const char *onion, uint16_t port,
                                          onion_stream_read_fn read_cb,
                                          onion_stream_event_fn event_cb,
                                          void *ctx, int lifetime_secs)
{
    (void)lifetime_secs;
    struct rf_stub *s = &g_stub;
    pthread_mutex_lock(&g_mu);
    s->opens++;
    s->dialed_host[0] = '\0';
    if (onion)
        snprintf(s->dialed_host, sizeof(s->dialed_host), "%s", onion);
    s->dialed_port = port;
    pthread_mutex_unlock(&g_mu);

    s->read_cb = read_cb;
    s->event_cb = event_cb;
    s->ctx = ctx;
    if (pthread_create(&s->tid, NULL, stub_thread, s) != 0)
        return NULL;
    s->tid_valid = true;
    return (struct onion_stream_raw *)s;
}

static int stub_write(struct onion_stream_raw *raw, const uint8_t *data,
                      size_t len)
{
    struct rf_stub *s = (struct rf_stub *)raw;
    if (atomic_load(&s->terminal))
        return -1;
    pthread_mutex_lock(&g_mu);
    if (s->echo_len + len > STUB_ECHO_CAP) {
        pthread_mutex_unlock(&g_mu);
        return -1;
    }
    memcpy(s->echo + s->echo_len, data, len);
    s->echo_len += len;
    pthread_mutex_unlock(&g_mu);
    return 0;
}

static void stub_close(struct onion_stream_raw *raw)
{
    struct rf_stub *s = (struct rf_stub *)raw;
    atomic_store(&s->stop, true);
    if (s->tid_valid) {
        pthread_join(s->tid, NULL);
        s->tid_valid = false;
    }
    atomic_store(&s->closed, true);
}

static const struct onion_stream_backend g_stub_backend = {
    .open = stub_open, .write = stub_write, .close = stub_close,
};

/* The bridge's pump owns the close; wait for it rather than racing it. */
static void stub_reset(void)
{
    if (g_stub.tid_valid || atomic_load(&g_stub.closed)) {
        for (int i = 0; i < 1200 && !atomic_load(&g_stub.closed); i++)
            usleep(5 * 1000);
        if (!atomic_load(&g_stub.closed) && g_stub.tid_valid) {
            atomic_store(&g_stub.stop, true);
            pthread_join(g_stub.tid, NULL);
            g_stub.tid_valid = false;
        }
    }
    free(g_stub.echo);
    memset(&g_stub, 0, sizeof(g_stub));
    g_stub.echo = malloc(STUB_ECHO_CAP);
    onion_stream_reset_stages_for_test();
}

/* ── Helpers ─────────────────────────────────────────────────────────── */

static bool make_onion_host(char host[ONION_V3_ADDRESS_LEN + 1])
{
    uint8_t pub[32];
    for (int i = 0; i < 32; i++)
        pub[i] = (uint8_t)(0x27 + i);
    return onion_v3_address_from_pubkey(pub, host);
}

/* The dial hands back a BLOCKING fd with SO_RCVTIMEO armed (that is the
 * contract rf_connect owes every caller above it), so a plain recv loop is
 * the right shape here -- it cannot hang unbounded. */
static bool read_exact_blocking(platform_socket_t fd, uint8_t *out, size_t want)
{
    /* platform_socket_receive already retries on EINTR/WSAEINTR. */
    size_t got = 0;
    while (got < want) {
        int n = platform_socket_receive(fd, out + got, want - got);
        if (n > 0) { got += (size_t)n; continue; }
        return false;
    }
    return true;
}

static bool write_all_blocking(platform_socket_t fd, const uint8_t *buf,
                               size_t len)
{
    return platform_socket_send_all(fd, buf, len);
}

/* A real clearnet listener on an ephemeral loopback port -- no hardcoded
 * port, nothing outside this process. */
static bool loopback_listen(platform_socket_t *fd_out, uint16_t *port_out)
{
    *fd_out = PLATFORM_SOCKET_INVALID;
    *port_out = 0;

    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID)
        return false;
    (void)platform_socket_set_reuse_address(fd, true);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (platform_socket_bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        platform_socket_listen(fd, 4) != 0) {
        platform_socket_close(fd);
        return false;
    }
    size_t sl = sizeof(sa);
    if (platform_socket_local_address(fd, (struct sockaddr *)&sa, &sl) != 0) {
        platform_socket_close(fd);
        return false;
    }
    *fd_out = fd;
    *port_out = ntohs(sa.sin_port);
    return true;
}

int test_rom_fetch_onion(void);
int test_rom_fetch_onion(void)
{
    int failures = 0;

    /* ── 1. an onion seeder is dialed over a circuit, not the resolver ── */
    printf("rom_fetch_onion: .onion seeder routes to the Tor stream, not "
           "getaddrinfo... ");
    {
        stub_reset();
        rom_fetch_set_onion_backend_for_test(&g_stub_backend);

        char host[ONION_V3_ADDRESS_LEN + 1];
        bool ok = make_onion_host(host);

        platform_socket_t fd = PLATFORM_SOCKET_INVALID;
        if (ok) {
            fd = rom_fetch_dial_for_test(host, 39411);
            ok = fd != PLATFORM_SOCKET_INVALID;
        }

        /* The circuit backend -- not the resolver -- was asked for exactly
         * this endpoint. */
        pthread_mutex_lock(&g_mu);
        ok = ok && g_stub.opens == 1 &&
             strcmp(g_stub.dialed_host, host) == 0 &&
             g_stub.dialed_port == 39411;
        pthread_mutex_unlock(&g_mu);

        /* The onion stage ledger recorded a real dial that reached a bridge. */
        struct onion_stream_stages st;
        onion_stream_get_stages(&st);
        ok = ok && st.dial_started == 1 && st.circuit_ready == 1 &&
             st.bridge_up == 1;

        /* And the fd behaves like the clearnet one: blocking, bytes both
         * ways. This is the fs_handshake/frame path's only requirement. */
        uint8_t tx[126], rx[126];
        for (size_t i = 0; i < sizeof(tx); i++)
            tx[i] = (uint8_t)(0x5a + (i & 0x1f));
        ok = ok && write_all_blocking(fd, tx, sizeof(tx)) &&
             read_exact_blocking(fd, rx, sizeof(rx)) &&
             memcmp(tx, rx, sizeof(tx)) == 0;

        if (fd != PLATFORM_SOCKET_INVALID)
            platform_socket_close(fd);
        rom_fetch_set_onion_backend_for_test(NULL);
        stub_reset();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── 2. clearnet is untouched: same resolver path, no circuit ─────── */
    printf("rom_fetch_onion: clearnet seeder still takes the resolver path... ");
    {
        stub_reset();
        rom_fetch_set_onion_backend_for_test(&g_stub_backend);

        platform_socket_t lfd = PLATFORM_SOCKET_INVALID;
        uint16_t lport = 0;
        bool ok = loopback_listen(&lfd, &lport);

        platform_socket_t fd = PLATFORM_SOCKET_INVALID;
        if (ok) {
            fd = rom_fetch_dial_for_test("127.0.0.1", lport);
            ok = fd != PLATFORM_SOCKET_INVALID;
        }

        /* No circuit was opened and the onion ledger never moved. */
        pthread_mutex_lock(&g_mu);
        ok = ok && g_stub.opens == 0;
        pthread_mutex_unlock(&g_mu);
        struct onion_stream_stages st;
        onion_stream_get_stages(&st);
        ok = ok && st.dial_started == 0 && st.bridge_up == 0;

        /* It really is connected to the listener. */
        if (ok) {
            struct sockaddr_storage peer_addr;
            size_t peer_len = sizeof(peer_addr);
            platform_socket_t afd = platform_socket_accept(
                lfd, (struct sockaddr *)&peer_addr, &peer_len);
            ok = afd != PLATFORM_SOCKET_INVALID;
            if (afd != PLATFORM_SOCKET_INVALID)
                platform_socket_close(afd);
        }

        if (fd != PLATFORM_SOCKET_INVALID)
            platform_socket_close(fd);
        if (lfd != PLATFORM_SOCKET_INVALID)
            platform_socket_close(lfd);
        rom_fetch_set_onion_backend_for_test(NULL);
        stub_reset();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── 3. a malformed onion name fails closed - no DNS, no circuit ──── */
    printf("rom_fetch_onion: malformed .onion refused without resolution or "
           "circuit... ");
    {
        stub_reset();
        rom_fetch_set_onion_backend_for_test(&g_stub_backend);

        /* Every one of these carries the .onion suffix, so each is claimed
         * by the onion route and must die there rather than fall through to
         * getaddrinfo (which would leak the name to a resolver) or to
         * clearnet (which would be a downgrade). */
        static const char *const bad[] = {
            "notavalidonion.onion",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
            "0000000000000000000000000000000000000000000000000000000d.onion",
        };
        bool ok = true;
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            /* Classification is the proof this spelling is claimed before
             * rf_connect's resolver branch. The strict onion parser below may
             * refuse it, but it may never fall through to DNS. */
            ok = ok && net_name_is_onion(bad[i]);
            platform_socket_t fd = rom_fetch_dial_for_test(bad[i], 39412);
            if (fd != PLATFORM_SOCKET_INVALID) {
                platform_socket_close(fd);
                ok = false;
            }
        }

        /* DNS names are case-insensitive and may carry one terminal root dot,
         * so suffix detection must claim these spellings too. The canonical
         * onion decoder is intentionally stricter: both are refused inside
         * the onion route, before either a resolver or a circuit is opened. */
        char canonical[ONION_V3_ADDRESS_LEN + 1];
        char uppercase[ONION_V3_ADDRESS_LEN + 1];
        char trailing_dot[ONION_V3_ADDRESS_LEN + 2];
        ok = ok && make_onion_host(canonical);
        if (ok) {
            memcpy(uppercase, canonical, sizeof(uppercase));
            for (size_t i = 0; uppercase[i]; i++) {
                if (uppercase[i] >= 'a' && uppercase[i] <= 'z')
                    uppercase[i] = (char)(uppercase[i] - ('a' - 'A'));
            }
            int n = snprintf(trailing_dot, sizeof(trailing_dot), "%s.",
                             canonical);
            ok = n == ONION_V3_ADDRESS_LEN + 1 &&
                 net_name_is_onion(uppercase) &&
                 net_name_is_onion(trailing_dot);
        }
        if (ok) {
            const char *const noncanonical[] = { uppercase, trailing_dot };
            for (size_t i = 0;
                 i < sizeof(noncanonical) / sizeof(noncanonical[0]); i++) {
                platform_socket_t fd =
                    rom_fetch_dial_for_test(noncanonical[i], 39412);
                if (fd != PLATFORM_SOCKET_INVALID) {
                    platform_socket_close(fd);
                    ok = false;
                }
            }
        }

        pthread_mutex_lock(&g_mu);
        ok = ok && g_stub.opens == 0;
        pthread_mutex_unlock(&g_mu);
        struct onion_stream_stages st;
        onion_stream_get_stages(&st);
        ok = ok && st.dial_started == 0;

        rom_fetch_set_onion_backend_for_test(NULL);
        stub_reset();

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── 4. reachability and speed are separate, per transport ────────── */
    printf("rom_fetch_onion: onion budgets are their own axis and clearnet "
           "is unchanged... ");
    {
        struct rom_fetch_dial_budgets b;
        memset(&b, 0, sizeof(b));
        rom_fetch_dial_budgets_for_test(&b);

        /* The clearnet budgets are exactly what they were before a Tor route
         * existed. A regression here is a behaviour change on a path this
         * work promised not to touch. */
        bool ok = b.clearnet_connect_ms == 10000 &&
                  b.clearnet_io_ms == 120000 &&
                  b.clearnet_probe_io_ms == 15000;

        /* Connect is reachability; io is speed. Neither may be derived from
         * the other, and an onion budget may never be tightened below the
         * clearnet one -- that is how an honest slow transport gets graded
         * dead. */
        ok = ok && b.onion_connect_ms > b.clearnet_connect_ms &&
             b.onion_io_ms > b.clearnet_io_ms &&
             b.onion_probe_io_ms > b.clearnet_probe_io_ms;

        /* The onion connect budget is the P2P dialer's own measured circuit
         * budget, not a second opinion invented here. */
        ok = ok && b.onion_connect_ms == ONION_STREAM_CONNECT_TIMEOUT_MS;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    free(g_stub.echo);
    g_stub.echo = NULL;
    return failures;
}
