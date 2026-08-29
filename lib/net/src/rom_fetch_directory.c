/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_fetch_directory — the ROM directory-listing fetch ("RLS"), the step a
 * fresh node uses to DISCOVER what a seeder holds before committing to a
 * manifest. Split out of lib/net/src/rom_fetch.c (which is at its shrink-only
 * file-size baseline) because discovery has its own concern and, above all,
 * its own STALL BOUND: this is the one call made against a peer whose only
 * claim to be a seeder is that it said so, so how long a lie may cost is a
 * decision that deserves to be readable in one place.
 *
 * Trust is unchanged and unchangeable here: the listing is transport-MAC
 * verified, and the manifest digests inside it are UNTRUSTED — they are a
 * commitment the caller then holds the downloaded bytes to (per-chunk and
 * whole-file SHA3, rom_fetch.c), with the install path binding the result to
 * the compiled checkpoint. Nothing in this file may relax any of that. */

#include "net/rom_fetch.h"
#include "rom_fetch_internal.h"
#include "net/file_service.h"
#include "rom_fetch_transport.h"
#include "crypto/sha3.h"
#include "platform/socket_compat.h"
#include "platform/time_compat.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>

#define RF_SUBSYS "rom_fetch"

/* ── Directory-listing fetch (clearnet peer discovery) ──────────────── */

/* Must byte-match FS_ROM_LIST_MAC_TAG in file_service.c: the listing reply
 * rides fs_send_chunk_fast's MAC scheme with this constant in the 32-byte
 * binding slot. "RLS" + zero padding. */
static const uint8_t RF_ROM_LIST_MAC_TAG[32] = { 'R', 'L', 'S' };

/* THE STALL BOUND for peer discovery.
 *
 * A seed that ACCEPTS the connection and then never speaks is the expensive
 * case: it cannot be distinguished from a slow-but-honest seeder except by
 * waiting. This is what a peer-discovered seed costs when it advertises a file
 * service and does not serve one, so the wait must be ONE number, not a per-
 * wire-step timeout that a drip-feeding peer can re-arm at every step.
 *
 * rom_fetch_get_directory therefore stamps a SINGLE absolute deadline right
 * after connect and reduces every subsequent wait — the handshake (via
 * fs_handshake_until, whose own FS_HANDSHAKE_RECV_BUDGET_MS is 30 s and would
 * otherwise dominate) and each of the three reply reads — to the time
 * remaining against it. One stalled seed can therefore cost at most
 *
 *   RF_CONNECT_TIMEOUT_MS (10 s, rom_fetch_transport.c)
 * + RF_MANIFEST_IO_TIMEOUT_SEC (15 s, the whole post-connect budget)
 * = 25 s,
 *
 * after which the call returns false and config/src/boot_bundle_fetch.c's
 * bbf_discover_from_peers `continue`s to the NEXT seed AND leaves the stalled
 * one out of the download peer set (struct bbf_discovery.live), so it is never
 * retried this boot. The seed set is capped at ROM_FETCH_MAX_WORKERS (8), so
 * the entire sweep is bounded at 8 * 25 s even if every seed stalls.
 *
 * Held in a variable rather than used as a literal so a test can drive the
 * abandon-and-move-on path without spending the production wait. The setter is
 * ZCL_TESTING-only; production always uses the constant above. */
static int g_rf_directory_io_timeout_ms = RF_MANIFEST_IO_TIMEOUT_SEC * 1000;

/* Milliseconds left before `deadline_ms`, floored at 1 so a socket timeout is
 * never set to "block forever". */
static int rf_ms_left(int64_t deadline_ms)
{
    int64_t left = deadline_ms - platform_time_monotonic_ms();
    return left < 1 ? 1 : (int)left;
}

#ifdef ZCL_TESTING
void rom_fetch_set_directory_io_timeout_ms_for_test(int ms)
{
    g_rf_directory_io_timeout_ms =
        (ms > 0) ? ms : RF_MANIFEST_IO_TIMEOUT_SEC * 1000;
}
int rom_fetch_directory_io_timeout_ms_for_test(void)
{
    return g_rf_directory_io_timeout_ms;
}
int rom_fetch_directory_io_timeout_default_ms_for_test(void)
{
    return RF_MANIFEST_IO_TIMEOUT_SEC * 1000;
}
#endif

bool rom_fetch_get_directory(const char *peer_addr, uint16_t port,
                             char *buf, size_t cap)
{
    if (!peer_addr || !peer_addr[0] || !buf || cap == 0)
        LOG_FAIL(RF_SUBSYS, "directory: null/empty arg");

    platform_socket_t fd = rf_connect(peer_addr, port);
    if (fd == PLATFORM_SOCKET_INVALID)
        return false; /* rf_connect logged; caller just skips this seed */

    /* ONE deadline for everything after connect — see the stall bound note
     * above g_rf_directory_io_timeout_ms. Every wait below is set from the
     * time remaining against it, so a legacy (RLS-unaware) or deliberately
     * silent seeder is abandoned within the budget instead of re-arming a
     * fresh window at each wire step. */
    const int64_t rls_deadline_ms =
        platform_time_monotonic_ms() + g_rf_directory_io_timeout_ms;
    (void)platform_socket_set_receive_timeout(fd, rf_ms_left(rls_deadline_ms));

    struct fs_session s;
    fs_session_init(&s, fd);
    uint8_t zero_root[32];
    memset(zero_root, 0, sizeof(zero_root));
    /* fs_handshake() would apply its own 30 s FS_HANDSHAKE_RECV_BUDGET_MS,
     * which alone exceeds this whole budget; bound it to our deadline. */
    if (!fs_handshake_until(&s, zero_root, true, rls_deadline_ms)) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "directory: handshake failed with %s:%u — skipping "
                 "seed", peer_addr, (unsigned)port);
        return false;
    }

    /* Request: ["RLS"(3)]. */
    uint8_t req[FS_ROM_LIST_REQUEST_SIZE];
    memcpy(req, "RLS", 3);
    if (!fs_send_frame(&s, FS_REQUEST, req, sizeof(req))) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "directory: request send failed to %s:%u — skipping "
                 "seed", peer_addr, (unsigned)port);
        return false;
    }

    /* Reply is size/body/MAC; FS_DONE parses as an invalid size and is skipped.
     * Each read gets only the REMAINING budget, so three reads cannot cost
     * three full windows. */
    uint8_t hdr[4];
    (void)platform_socket_set_receive_timeout(fd, rf_ms_left(rls_deadline_ms));
    if (!rf_recv_exact(fd, hdr, 4)) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "directory: no reply from %s:%u (legacy seeder?) — "
                 "skipping seed", peer_addr, (unsigned)port);
        return false;
    }
    uint32_t size = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
                    ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    /* Bounded by the caller's cap, leaving one byte for the NUL terminator. A
     * zero-length body or one at/over cap (incl. the FS_DONE refusal) fails. */
    if (size == 0 || size >= cap) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "directory: implausible body size %u (cap %zu) from "
                 "%s:%u — skipping seed", size, cap, peer_addr, (unsigned)port);
        return false;
    }
    (void)platform_socket_set_receive_timeout(fd, rf_ms_left(rls_deadline_ms));
    if (!rf_recv_exact(fd, (uint8_t *)buf, size)) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "directory: body read failed from %s:%u — skipping "
                 "seed", peer_addr, (unsigned)port);
        return false;
    }
    uint8_t mac_wire[32];
    (void)platform_socket_set_receive_timeout(fd, rf_ms_left(rls_deadline_ms));
    if (!rf_recv_exact(fd, mac_wire, 32)) {
        rf_session_close(&s, fd);
        LOG_INFO(RF_SUBSYS, "directory: MAC read failed from %s:%u — skipping "
                 "seed", peer_addr, (unsigned)port);
        return false;
    }
    platform_socket_close(fd);

    /* Transport MAC: SHA3(key || recv_counter || "RLS"tag || body), matching the
     * serve side's fs_send_chunk_fast(body, tag). */
    uint8_t mac_expect[32];
    struct sha3_256_ctx mctx;
    sha3_256_init(&mctx);
    sha3_256_write(&mctx, s.key, 32);
    sha3_256_write(&mctx, (const unsigned char *)&s.recv_counter, 8);
    sha3_256_write(&mctx, RF_ROM_LIST_MAC_TAG, 32);
    sha3_256_write(&mctx, (const uint8_t *)buf, size);
    sha3_256_finalize(&mctx, mac_expect);
    memory_cleanse(&mctx, sizeof(mctx));
    fs_session_cleanup(&s);
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= mac_wire[i] ^ mac_expect[i];
    if (diff != 0) {
        LOG_INFO(RF_SUBSYS, "directory: MAC mismatch from %s:%u — skipping seed",
                 peer_addr, (unsigned)port);
        return false;
    }

    buf[size] = '\0';
    LOG_INFO(RF_SUBSYS, "directory: got %u-byte listing from %s:%u",
             size, peer_addr, (unsigned)port);
    return true;
}
