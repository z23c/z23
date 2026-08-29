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
 *                         verified download (serial + parallel), manifest
 *                         and directory-listing fetch, chunk fetch/verify.
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
#include <stdint.h>

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

#endif /* ZCL_NET_ROM_FETCH_INTERNAL_H */
