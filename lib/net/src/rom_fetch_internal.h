/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Internal header shared by the rom_fetch*.c translation units. NOT part
 * of the public API — only included by rom_fetch*.c files. Mirrors the
 * msgprocessor_snapshot.c/msgprocessor_snapshot_serve.c split shape (see
 * msgprocessor_snapshot_internal.h): a small header for the one seam one
 * file needs to call into the other, promoted from `static` only as
 * needed.
 *
 * The split is by responsibility:
 *   rom_fetch.c        — the wire drivers: whole-file and per-chunk-
 *                         verified download (serial + parallel), the "RMF"
 *                         per-chunk manifest fetch, chunk fetch/verify.
 *   rom_fetch_directory.c — the "RLS" directory-listing fetch: DISCOVERY,
 *                         i.e. the one call aimed at a peer whose only claim
 *                         to be a seeder is that it said so, and therefore
 *                         the one that owns the stall bound.
 *   rom_fetch_session.c — the verified per-chunk fetch and the seeder
 *                         SESSION it rides: one dial, many chunks. Owns the
 *                         typed-refusal decode, the reply MAC check, and the
 *                         rules for when a session may be reused at all.
 *   rom_fetch_status.c — the fetch-status observability side: the g_status
 *                         record every driver above narrates progress into
 *                         (rf_note_begin/progress/end) and its two readers
 *                         (rom_fetch_status_snapshot, rom_fetch_dump_state_
 *                         json). Shares no state with the drivers except
 *                         these three calls.
 *
 * Everything declared here used to be `static` in rom_fetch.c; it is
 * promoted to external linkage (single definition, still in whichever
 * file owns it) purely so the other file can call it — no behavior
 * changed by the split. */

#ifndef ZCL_NET_ROM_FETCH_INTERNAL_H
#define ZCL_NET_ROM_FETCH_INTERNAL_H

#include "net/rom_fetch.h"
#include "net/file_service.h"
#include "platform/socket_compat.h"
#include <stdint.h>

/* A stalled/absent reply on a PRE-download probe (the "RMF" per-chunk manifest
 * in rom_fetch.c, the "RLS" directory listing in rom_fetch_directory.c) must
 * fall back FAST, not sit on the 120 s chunk-IO timeout: both probes precede
 * the download and both may be aimed at a peer whose only claim to be a seeder
 * is that it said so. ONE number, shared, so the two probes cannot drift. */
#define RF_MANIFEST_IO_TIMEOUT_SEC 15

/* ── rom_fetch_status.c: called from every download driver in rom_fetch.c
 * to narrate progress into the shared status record ──────────────────── */

/* Begin narrating a new attempt against peer_addr:port for manifest m. */
void rf_note_begin(const char *peer_addr, uint16_t port,
                   const struct rom_fetch_manifest *m);

/* Update the in-progress chunk/byte counters for the current attempt. */
void rf_note_progress(uint32_t chunks_done, uint64_t bytes_done);

/* Close out the current attempt: ok plus a short human-readable detail
 * (installed path on success, failure reason otherwise). */
void rf_note_end(bool ok, const char *detail);

/* ── rom_fetch_session.c: the seeder session, held across chunks ───────
 *
 * The download workers in rom_fetch.c drive a session directly instead of
 * dialling per chunk, so the three calls below and the two types they use are
 * the seam between the two files. See rom_fetch_session.c for why a dial is
 * the expensive unit and what a session is and is not allowed to survive. */

/* What one chunk exchange did to the session it ran on. */
enum rf_xchg {
    RF_XCHG_OK,      /* verified bytes in buf; session still aligned    */
    RF_XCHG_REFUSED, /* authenticated typed refusal; session aligned    */
    RF_XCHG_BROKEN,  /* stream desynchronised or gone; drop the session */
};

/* A worker's live session with one seeder. */
struct rf_peer_conn {
    struct fs_session s;
    platform_socket_t fd;
    char     addr[128];
    uint16_t port;
    uint32_t served;   /* chunks delivered on THIS session */
    bool     open;
};

/* Close and forget the session `c` holds, if any. Idempotent. */
void rf_conn_drop(struct rf_peer_conn *c);

/* Guarantee `c` holds a handshaked session with addr:port, DIALLING only if it
 * does not already (a different peer, an exhausted session, or none). False
 * means the dial itself produced no socket — the caller's signal that this
 * peer is unreachable right now. */
bool rf_conn_ensure(struct rf_peer_conn *c, const char *addr, uint16_t port);

/* Ask an ALREADY handshaked session for one chunk and verify the reply's
 * transport MAC. Never dials and never closes: the caller owns the session's
 * life and acts on the returned verdict. */
enum rf_xchg rf_chunk_exchange(struct rf_peer_conn *c,
                               const uint8_t chunk_root[32], uint32_t idx,
                               uint8_t *buf, uint32_t *out_sz);

#endif /* ZCL_NET_ROM_FETCH_INTERNAL_H */
