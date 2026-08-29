/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_fetch_session — the verified chunk fetch and the seeder SESSION it
 * rides: one dial, many chunks.
 *
 * Split out of lib/net/src/rom_fetch.c (which sits at its file-size ceiling)
 * because this is its own concern and, above all, its own COST model.
 * Everything here exists to answer one question — how many times must a
 * downloader pay to ESTABLISH a connection — and that answer decides how long
 * a fresh node waits before it can serve, most of all over a Tor circuit,
 * where establishing one is the expensive part and is slow without being in
 * any way dishonest.
 *
 * Nothing here relaxes verification: the typed refusal frame is
 * MAC-authenticated, every chunk reply's transport MAC is checked against the
 * session key and counter, the content digest is checked by the caller
 * (rf_ver_acquire_chunk in rom_fetch.c), and the whole-file proof still gates
 * the install. */

#include "net/rom_fetch.h"
#include "rom_fetch_internal.h"
#include "net/file_service.h"
#include "net/rom_peer_scoring.h"
#include "rom_fetch_transport.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "platform/socket_compat.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RF_SUBSYS "rom_fetch"

/* ── Verified chunk fetch ───────────────────────────────────────────── */

/* Must byte-match FS_ROM_REFUSAL_MAC_TAG in file_service.c: the typed ROM
 * chunk refusal frame rides fs_send_chunk_refusal's MAC scheme with this
 * constant in the tag slot. "RREF" + zero padding. */
static const uint8_t RF_ROM_REFUSAL_MAC_TAG[32] = { 'R', 'R', 'E', 'F' };

/* Pure decode of the 4-byte chunk-reply size field: true iff it is the ROM
 * refusal sentinel (server declined this chunk). A real chunk size never
 * reaches the sentinel (it is bounded by ROM_SEED_CHUNK_SIZE), so this cleanly
 * separates a refusal from a data reply — and a corrupt/garbage size is NOT
 * mistaken for a refusal (only the exact sentinel is). */
bool rom_fetch_wire_is_refusal(const uint8_t hdr4[4])
{
    if (!hdr4)
        return false;
    return zcl_read_u32_le(hdr4) == FS_ROM_REFUSAL_SENTINEL;
}

/* Human label for a refusal reason code (bounded; unknown codes fold to a
 * stable string). Used for clean "peer busy" logging and in tests. */
const char *rom_fetch_refusal_reason_name(uint8_t reason)
{
    switch (reason) {
    case FS_ROM_REFUSE_UNKNOWN:     return "unknown-artifact";
    case FS_ROM_REFUSE_CONN_BUDGET: return "conn-budget";
    case FS_ROM_REFUSE_INFLIGHT:    return "inflight-cap";
    case FS_ROM_REFUSE_RATE:        return "rate-window";
    case FS_ROM_REFUSE_IO:          return "server-io";
    default:                        return "declined";
    }
}

/* ── One dial, many chunks: the seeder session ──────────────────────────
 *
 * A DIAL is the expensive unit of a fetch, and it is expensive for reasons
 * that have nothing to do with how fast the seeder is: a TCP open (or a whole
 * Tor circuit), then the two-round-trip X25519/HKDF key confirmation, before
 * a single byte of chunk can be asked for. Four round trips before the first
 * request. Paying that per CHUNK made an artifact's dial count equal to its
 * chunk count, so the price of distance scaled with the size of the download
 * — on a Tor circuit, where a dial is a circuit build, ruinously so.
 *
 * The serve path never required it. fs_handle_client_fd loops: it serves a
 * ROM chunk and `continue`s, ready for the next request on the same session,
 * and publishes its own opinion of how long that may go on (FS_CONN_MAX_BYTES
 * 4 GB, FS_CONN_MAX_SECONDS 30 min, plus a 30 s idle recv timeout on the
 * client fd). A worker therefore keeps ONE session and asks it for chunk
 * after chunk.
 *
 * Two things this must get exactly right:
 *
 *  1. COUNTER ALIGNMENT. fs_send_chunk_fast and fs_send_chunk_refusal both
 *     advance the server's send_counter, and that counter is bound into the
 *     reply MAC. A client that never advanced recv_counter could only ever
 *     verify the FIRST reply on a session. rf_chunk_exchange advances
 *     recv_counter on every reply it accepts, so the anti-replay counter now
 *     does its job across a session instead of being a constant zero.
 *
 *  2. WHEN A SESSION MAY SURVIVE. Only two outcomes leave the byte stream
 *     where both ends agree it is: a complete verified chunk, and a complete
 *     authenticated refusal. Everything else — a short read, an implausible
 *     size, a MAC that does not verify — means the stream is desynchronised
 *     or gone, and the session is dropped rather than reused. Reuse is never
 *     allowed to paper over a stream we cannot account for.
 *
 * None of this touches verification: the per-chunk transport MAC, the
 * content digest check in rf_ver_acquire_chunk and the whole-file proof
 * before install all run exactly as before, on exactly the same bytes. */


/* How many chunks one session may carry before the worker re-dials.
 *
 * This is a FAIRNESS bound, not a speed one. A seeder serves its clients from
 * a fixed pool of worker threads (FS_SERVER_WORKERS, 8), and a held session
 * occupies one of them. Without a bound, the first downloaders to arrive
 * could hold every thread for the length of a multi-GB transfer while later
 * arrivals — the fresh nodes this whole path exists to serve — queued behind
 * them. Re-dialling periodically returns the thread to the pool and lets the
 * swarm interleave. It is deliberately far below the seeder's own 4 GB /
 * 30 min per-connection budget: the client yields before the server has to
 * evict it. At 8 MB chunks this is 256 MB per session, so even a large
 * artifact costs a handful of dials per worker instead of one per chunk. */
#define RF_SESSION_MAX_CHUNKS 32u

void rf_conn_drop(struct rf_peer_conn *c)
{
    if (!c || !c->is_open)
        return;
    rf_session_close(&c->s, c->fd);
    c->is_open = false;
    c->fd = PLATFORM_SOCKET_INVALID;
    c->served = 0;
}

/* Guarantee `c` holds a handshaked session with addr:port, dialling only if
 * it does not already (a different peer, an exhausted session, or none). */
bool rf_conn_ensure(struct rf_peer_conn *c, const char *addr,
                           uint16_t port)
{
    if (c->is_open && (c->port != port || strcmp(c->addr, addr) != 0 ||
                    c->served >= RF_SESSION_MAX_CHUNKS))
        rf_conn_drop(c);
    if (c->is_open)
        return true;

    platform_socket_t fd = rf_connect(addr, port);
    if (fd == PLATFORM_SOCKET_INVALID)
        return false; /* rf_connect logged; caller fails over */

    fs_session_init(&c->s, fd);
    /* The ROM serve path keys its sessions on an all-zero utxo_root (see
     * fs_handle_client_fd, file_service.c) — match it exactly. */
    uint8_t zero_root[32];
    memset(zero_root, 0, sizeof(zero_root));
    if (!fs_handshake(&c->s, zero_root, true)) {
        rf_session_close(&c->s, fd);
        LOG_FAIL(RF_SUBSYS, "chunk: handshake failed with %s:%u",
                 addr, (unsigned)port);
    }
    c->fd = fd;
    c->port = port;
    snprintf(c->addr, sizeof(c->addr), "%s", addr);
    c->served = 0;
    c->is_open = true;
    return true;
}

/* Ask an ALREADY handshaked session for one chunk and verify the reply's
 * transport MAC. Never dials and never closes: the caller owns the session's
 * life and acts on the returned verdict. */
enum rf_xchg rf_chunk_exchange(struct rf_peer_conn *c,
                                      const uint8_t chunk_root[32],
                                      uint32_t idx, uint8_t *buf,
                                      uint32_t *out_sz)
{
    struct fs_session *s = &c->s;
    platform_socket_t fd = c->fd;
    const char *peer_addr = c->addr;
    uint16_t port = c->port;

    /* Request: ["ROM"(3)][chunk_root(32)][chunk_index(4 LE)]. */
    uint8_t req[FS_ROM_REQUEST_SIZE];
    memcpy(req, "ROM", 3);
    memcpy(req + 3, chunk_root, 32);
    zcl_write_u32_le(req + 35, idx);
    if (!fs_send_frame(s, FS_REQUEST, req, sizeof(req)))
        LOG_RETURN(RF_XCHG_BROKEN, RF_SUBSYS,
                   "chunk: request send failed to %s:%u",
                   peer_addr, (unsigned)port);

    /* Reply is raw size/data/MAC or a typed refusal sentinel. */
    uint8_t hdr[4];
    if (!rf_recv_exact(fd, hdr, 4))
        LOG_RETURN(RF_XCHG_BROKEN, RF_SUBSYS,
                   "chunk: size header read failed (peer %s:%u refused or "
                   "went away)", peer_addr, (unsigned)port);

    if (rom_fetch_wire_is_refusal(hdr)) {
        /* Fixed-size authenticated refusal; never a peer-sized read. */
        uint8_t reason = 0;
        uint8_t rmac_wire[32];
        if (!rf_recv_exact(fd, &reason, 1) ||
            !rf_recv_exact(fd, rmac_wire, 32)) {
            LOG_INFO(RF_SUBSYS, "chunk %u: peer %s:%u refused (truncated "
                     "refusal frame) — backing off", idx, peer_addr,
                     (unsigned)port);
            return RF_XCHG_BROKEN;
        }
        uint8_t rmac_expect[32];
        struct sha3_256_ctx rmc;
        sha3_256_init(&rmc);
        sha3_256_write(&rmc, s->key, 32);
        sha3_256_write(&rmc, (const unsigned char *)&s->recv_counter, 8);
        sha3_256_write(&rmc, RF_ROM_REFUSAL_MAC_TAG, 32);
        sha3_256_write(&rmc, &reason, 1);
        sha3_256_finalize(&rmc, rmac_expect);
        memory_cleanse(&rmc, sizeof(rmc));
        uint8_t rdiff = 0;
        for (int i = 0; i < 32; i++) rdiff |= rmac_wire[i] ^ rmac_expect[i];
        if (rdiff != 0) {
            LOG_INFO(RF_SUBSYS, "chunk %u: peer %s:%u sent an unauthenticated "
                     "refusal (MAC mismatch) — backing off", idx, peer_addr,
                     (unsigned)port);
            return RF_XCHG_BROKEN;
        }
        /* The seeder advanced its send_counter for this refusal; stay level
         * with it so the NEXT reply on this session still verifies. */
        s->recv_counter++;
        LOG_INFO(RF_SUBSYS, "chunk %u: peer %s:%u busy (%s) — backing off + "
                 "retry", idx, peer_addr, (unsigned)port,
                 rom_fetch_refusal_reason_name(reason));
        return RF_XCHG_REFUSED;
    }

    uint32_t size = zcl_read_u32_le(hdr);
    if (size == 0 || size > ROM_SEED_CHUNK_SIZE)
        LOG_RETURN(RF_XCHG_BROKEN, RF_SUBSYS,
                   "chunk: implausible chunk size %u from %s:%u (refusal or "
                   "corrupt stream)", size, peer_addr, (unsigned)port);
    if (!rf_recv_exact(fd, buf, size))
        LOG_RETURN(RF_XCHG_BROKEN, RF_SUBSYS,
                   "chunk: data read failed (%u bytes) from %s:%u",
                   size, peer_addr, (unsigned)port);
    uint8_t mac_wire[32];
    if (!rf_recv_exact(fd, mac_wire, 32))
        LOG_RETURN(RF_XCHG_BROKEN, RF_SUBSYS,
                   "chunk: MAC read failed from %s:%u",
                   peer_addr, (unsigned)port);

    /* The chunk's content digest is learned from the received bytes: the
     * serve side binds the true per-chunk SHA3 into the MAC, so a tampered
     * payload fails the MAC; content-vs-manifest verification is the
     * whole-file pass (rom_fetch_verify_file). */
    uint8_t data_sha3[32];
    sha3_256(buf, size, data_sha3);

    uint8_t mac_expect[32];
    struct sha3_256_ctx mctx;
    sha3_256_init(&mctx);
    sha3_256_write(&mctx, s->key, 32);
    sha3_256_write(&mctx, (const unsigned char *)&s->recv_counter, 8);
    sha3_256_write(&mctx, data_sha3, 32);
    sha3_256_write(&mctx, buf, size);
    sha3_256_finalize(&mctx, mac_expect);
    memory_cleanse(&mctx, sizeof(mctx));

    uint8_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= mac_wire[i] ^ mac_expect[i];
    if (diff != 0) {
        /* Scoring, not a content verdict: chunk-level whole-file content
         * proof is a separate later step. This only stops us from wasting
         * more retries on a peer whose transport MAC keeps failing. */
        (void)rom_peer_note_bad_chunk(peer_addr, port, idx, "mac");
        LOG_RETURN(RF_XCHG_BROKEN, RF_SUBSYS,
                   "chunk: transport MAC mismatch on chunk %u from %s:%u",
                   idx, peer_addr, (unsigned)port);
    }

    s->recv_counter++;
    c->served++;
    *out_sz = size;
    return RF_XCHG_OK;
}

bool rom_fetch_chunk(const char *peer_addr, uint16_t port,
                     const uint8_t chunk_root[32], uint32_t idx,
                     uint8_t *buf, uint32_t buf_cap, uint32_t *out_sz)
{
    if (!peer_addr || !chunk_root || !buf || !out_sz)
        LOG_FAIL(RF_SUBSYS, "chunk: null arg");
    if (buf_cap < ROM_SEED_CHUNK_SIZE)
        LOG_FAIL(RF_SUBSYS, "chunk: buf_cap %u < ROM chunk size %u",
                 buf_cap, (unsigned)ROM_SEED_CHUNK_SIZE);

    /* The one-shot entry point: dial, ask once, hang up. Unchanged contract
     * for every caller that fetches a single chunk; the download workers use
     * rf_conn_ensure + rf_chunk_exchange directly and keep the session. The
     * session is heap-held because struct fs_session carries a 64 KB receive
     * buffer that has no business on a worker's stack. */
    struct rf_peer_conn *c = zcl_malloc(sizeof(*c), "rom_fetch_conn");
    if (!c)
        LOG_FAIL(RF_SUBSYS, "chunk: session alloc failed");
    memset(c, 0, sizeof(*c));
    c->fd = PLATFORM_SOCKET_INVALID;
    if (!rf_conn_ensure(c, peer_addr, port)) {
        free(c);
        return false;
    }
    enum rf_xchg r = rf_chunk_exchange(c, chunk_root, idx, buf, out_sz);
    rf_conn_drop(c);
    free(c);
    return r == RF_XCHG_OK;
}

