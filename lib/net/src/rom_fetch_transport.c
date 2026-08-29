/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Bounded socket transport for the ROM artifact fetch client.
 *
 * TWO transports, ONE verification contract.
 *
 *   - A clearnet peer takes the getaddrinfo + connect(2) path below, byte
 *     for byte as it always has.
 *   - A .onion peer takes the SAME raw-stream route the P2P dialer uses
 *     (net/onion_stream.h -> the embedded Tor fork's dynhost_stream_* API,
 *     bridged to an ordinary socket fd). There is NO SOCKS client in this
 *     tree and none is added here: dynhost replaces SOCKS entirely
 *     (lib/net/src/tor_integration.c), so there is no proxy host or port to
 *     hardcode -- the circuit is opened by direct C call into the
 *     in-process Tor. See docs/work/NAT_AND_ONION_TRANSPORT.md.
 *
 * Transport chooses only HOW the bytes arrive. It cannot influence whether
 * they are accepted: the per-chunk MAC/digest check, the chunk-root fold and
 * the whole-file digest all live in rom_fetch.c and run identically on both
 * routes.
 *
 * Onion is NEVER a fallback and clearnet is never a fallback for onion. A
 * .onion name must not reach getaddrinfo (netbase.c lookup_onion), and a
 * clearnet name must not be handed to a circuit. Each address has exactly
 * one route and fails closed on it. */
#include "rom_fetch_transport.h"
#include "net/netbase.h"
#include "net/onion_stream.h"
#include "net/rom_fetch.h"
#include "util/log_macros.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define RF_SUBSYS "rom_fetch"

/* ── Budgets: reachability and speed are separate axes, never one scalar ──
 *
 * The clearnet numbers are unchanged. The onion numbers are NOT derived from
 * "how much slower we will tolerate a peer being" -- they are derived from
 * what each transport physically does, so an honest Tor-only seeder is never
 * graded dead by a budget shaped for a fast link.
 *
 *  connect: clearnet is one TCP handshake (10 s is already generous). Onion
 *           is a rendezvous circuit build, measured at 10-60 s on a cold Tor
 *           in this tree. Rather than mint a second opinion, reuse the P2P
 *           dialer's own budget (ONION_STREAM_CONNECT_TIMEOUT_MS), so the
 *           artifact path and the peer path grade the same cold Tor the same
 *           way and one constant moves both.
 *
 *  io:      a per-recv SILENCE window, not a transfer deadline -- how long a
 *           live link may deliver nothing before we call it gone. A three-hop
 *           circuit multiplies both the round trip and the length of a stall
 *           (a rendezvous re-establishing is silent, not broken), so the
 *           onion window is the clearnet window scaled by an explicit,
 *           reviewable factor instead of a fresh absolute nobody can audit.
 *
 *  probe:   the manifest/directory pre-flight deliberately uses a SHORT
 *           window, because a legacy seeder that does not know RMF/RLS never
 *           replies at all and the timeout is the fall-back signal. That
 *           short window is a clearnet round-trip budget; applied unchanged
 *           to a circuit it would mistake Tor latency for a legacy seeder,
 *           so it scales by the same factor. */
#define RF_CONNECT_TIMEOUT_MS 10000
#define RF_IO_TIMEOUT_MS 120000
#define RF_PROBE_IO_TIMEOUT_MS 15000

#define RF_ONION_SLOWDOWN 4
#define RF_ONION_CONNECT_TIMEOUT_MS ONION_STREAM_CONNECT_TIMEOUT_MS
#define RF_ONION_IO_TIMEOUT_MS (RF_IO_TIMEOUT_MS * RF_ONION_SLOWDOWN)
#define RF_ONION_PROBE_IO_TIMEOUT_MS (RF_PROBE_IO_TIMEOUT_MS * RF_ONION_SLOWDOWN)

/* Test-only injection of the raw-stream backend, mirroring
 * onion_stream_connect_backend_for_test. NULL in production and on every
 * path a release build can reach -- the whole block compiles out. */
#ifdef ZCL_TESTING
static const struct onion_stream_backend *g_rf_onion_backend;

/* Dial counters — see rom_fetch_dial_count_for_test. Both are bumped in one
 * place (rf_connect's single return) so they cannot drift from reality.
 * g_rf_dial_fail_count counts dials that came back with NO socket: a refused
 * port, an unresolvable name, or the full transport-scaled connect budget
 * elapsing. Each one is a stall a boot paid for; counting them is how the
 * cost of re-dialling a peer already found unreachable becomes visible
 * without timing anything. */
static _Atomic uint64_t g_rf_dial_count;
static _Atomic uint64_t g_rf_dial_fail_count;
#define RF_NOTE_DIAL() atomic_fetch_add(&g_rf_dial_count, 1u)
#define RF_NOTE_DIAL_FAIL() atomic_fetch_add(&g_rf_dial_fail_count, 1u)
#else
#define RF_NOTE_DIAL() ((void)0)
#define RF_NOTE_DIAL_FAIL() ((void)0)
#endif

int rf_probe_io_timeout_ms(const char *peer_addr)
{
    return net_name_is_onion(peer_addr) ? RF_ONION_PROBE_IO_TIMEOUT_MS
                                        : RF_PROBE_IO_TIMEOUT_MS;
}

void rf_session_close(struct fs_session *session, platform_socket_t fd)
{
    fs_session_cleanup(session);
    platform_socket_close(fd);
}

bool rf_recv_exact(platform_socket_t fd, uint8_t *buf, size_t size)
{
    size_t received = 0;
    while (received < size) {
        int result = platform_socket_receive(fd, buf + received,
                                             size - received);
        if (result < 0) {
            if (platform_socket_error_interrupted(
                    platform_socket_last_error()))
                continue;
            return false;
        }
        if (result == 0)
            return false;
        received += (size_t)result;
    }
    return true;
}

/* Dial a .onion seeder over a Tor circuit and hand back a socket with the
 * SAME properties rf_connect's clearnet path returns: blocking, with recv/
 * send silence windows armed. Everything above this function -- handshake,
 * framing, MACs, digests -- cannot tell the two apart, which is the point. */
static platform_socket_t rf_connect_onion(const char *peer_addr, uint16_t port)
{
    struct net_service svc;
    net_service_init(&svc);

    /* lookup_onion NEVER falls back to DNS: a malformed onion name is
     * refused here rather than leaking to getaddrinfo. */
    if (!lookup_onion(peer_addr, &svc, port))
        LOG_RETURN(PLATFORM_SOCKET_INVALID, RF_SUBSYS,
                   "chunk: '%s' is not a valid v3 onion address — refused "
                   "without resolution", peer_addr);

    zcl_socket_t sock = ZCL_INVALID_SOCKET;
    bool dialed;
#ifdef ZCL_TESTING
    if (g_rf_onion_backend)
        dialed = onion_stream_connect_backend_for_test(
            &svc, &sock, RF_ONION_CONNECT_TIMEOUT_MS, g_rf_onion_backend);
    else
#endif
        dialed = onion_stream_connect(&svc, &sock,
                                      RF_ONION_CONNECT_TIMEOUT_MS);
    if (!dialed || sock == ZCL_INVALID_SOCKET)
        LOG_RETURN(PLATFORM_SOCKET_INVALID, RF_SUBSYS,
                   "chunk: onion circuit to %s:%u not established",
                   peer_addr, (unsigned)port);

    platform_socket_t fd = (platform_socket_t)sock;
    /* The bridge hands back a non-blocking fd (connman polls it); this
     * client reads with blocking recv + SO_RCVTIMEO, exactly as it does on
     * clearnet. */
    if (!platform_socket_set_nonblocking(fd, false)) {
        platform_socket_close(fd);
        LOG_RETURN(PLATFORM_SOCKET_INVALID, RF_SUBSYS,
                   "chunk: restore blocking socket failed (onion)");
    }
    (void)platform_socket_set_receive_timeout(fd, RF_ONION_IO_TIMEOUT_MS);
    (void)platform_socket_set_send_timeout(fd, RF_ONION_IO_TIMEOUT_MS);
    return fd;
}

static platform_socket_t rf_connect_route(const char *peer_addr, uint16_t port)
{
    /* Route by address family, not by preference: an onion name has exactly
     * one route and never reaches the resolver below. */
    if (net_name_is_onion(peer_addr))
        return rf_connect_onion(peer_addr, port);

    char port_text[8];
    snprintf(port_text, sizeof(port_text), "%u", (unsigned)port);

    struct addrinfo hints = {0};
    struct addrinfo *addresses = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(peer_addr, port_text, &hints, &addresses) != 0 ||
        !addresses)
        LOG_ERR(RF_SUBSYS, "chunk: resolve failed for %s", peer_addr);

    platform_socket_t fd = platform_socket_open(
        addresses->ai_family, addresses->ai_socktype, addresses->ai_protocol,
        true, true);
    if (fd == PLATFORM_SOCKET_INVALID) {
        freeaddrinfo(addresses);
        LOG_ERR(RF_SUBSYS, "chunk: socket() failed: %s", strerror(errno));
    }

    int result = platform_socket_connect(fd, addresses->ai_addr,
                                         addresses->ai_addrlen);
    int connect_error = result == 0 ? 0 : platform_socket_last_error();
    if (result != 0 && platform_socket_error_in_progress(connect_error)) {
        result = platform_socket_wait_writable(fd, RF_CONNECT_TIMEOUT_MS);
        int pending_error = 0;
        if (result > 0)
            (void)platform_socket_pending_error(fd, &pending_error);
        if (result <= 0 || pending_error != 0) {
            platform_socket_close(fd);
            freeaddrinfo(addresses);
            LOG_ERR(RF_SUBSYS, "chunk: connect to %s:%u failed/timed out",
                    peer_addr, (unsigned)port);
        }
    } else if (result != 0) {
        platform_socket_close(fd);
        freeaddrinfo(addresses);
        LOG_ERR(RF_SUBSYS, "chunk: connect to %s:%u failed: %s",
                peer_addr, (unsigned)port, strerror(errno));
    }
    freeaddrinfo(addresses);

    if (!platform_socket_set_nonblocking(fd, false)) {
        platform_socket_close(fd);
        LOG_ERR(RF_SUBSYS, "chunk: restore blocking socket failed");
    }
    (void)platform_socket_set_receive_timeout(fd, RF_IO_TIMEOUT_MS);
    (void)platform_socket_set_send_timeout(fd, RF_IO_TIMEOUT_MS);
    return fd;
}

platform_socket_t rf_connect(const char *peer_addr, uint16_t port)
{
    platform_socket_t fd = rf_connect_route(peer_addr, port);
    if (fd != PLATFORM_SOCKET_INVALID)
        RF_NOTE_DIAL();
    else
        RF_NOTE_DIAL_FAIL();
    return fd;
}

#ifdef ZCL_TESTING
void rom_fetch_dial_count_reset_for_test(void)
{
    atomic_store(&g_rf_dial_count, 0);
    atomic_store(&g_rf_dial_fail_count, 0);
}

uint64_t rom_fetch_dial_count_for_test(void)
{
    return atomic_load(&g_rf_dial_count);
}

uint64_t rom_fetch_dial_fail_count_for_test(void)
{
    return atomic_load(&g_rf_dial_fail_count);
}

void rom_fetch_set_onion_backend_for_test(const struct onion_stream_backend *be)
{
    g_rf_onion_backend = be;
}

platform_socket_t rom_fetch_dial_for_test(const char *peer_addr, uint16_t port)
{
    return rf_connect(peer_addr, port);
}

void rom_fetch_dial_budgets_for_test(struct rom_fetch_dial_budgets *out)
{
    if (!out)
        return;
    out->clearnet_connect_ms = RF_CONNECT_TIMEOUT_MS;
    out->clearnet_io_ms = RF_IO_TIMEOUT_MS;
    out->clearnet_probe_io_ms = RF_PROBE_IO_TIMEOUT_MS;
    out->onion_connect_ms = RF_ONION_CONNECT_TIMEOUT_MS;
    out->onion_io_ms = RF_ONION_IO_TIMEOUT_MS;
    out->onion_probe_io_ms = RF_ONION_PROBE_IO_TIMEOUT_MS;
}
#endif
