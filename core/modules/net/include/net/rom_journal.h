/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM download resume journal — the durable sidecar that makes a per-chunk
 * ROM fetch kill-9-safe. For an in-progress `<out>.part` download, a sibling
 * `<out>.part.journal` records which chunks are already on disk AND
 * digest-verified, so a restart re-fetches only the missing tail instead of
 * the whole file.
 *
 * Durability ordering (owned by rom_fetch.c): pwrite the chunk data →
 * fdatasync(.part) → set the chunk's journal bit → fdatasync(journal). A set
 * bit therefore ALWAYS implies durable, digest-verified data for that chunk.
 *
 * Trust: the journal header pins the manifest identity (chunk_root, whole_sha3,
 * chunk_size, num_chunks). On resume, a header that does not match the caller's
 * current manifest ⇒ discard both files (no partial trust) — mirrors the
 * "recompute, never repair" rule.
 *
 * This module owns one open file descriptor per journal and an in-memory
 * bitmap; no threads, no sockets. */

#ifndef ZCL_NET_ROM_JOURNAL_H
#define ZCL_NET_ROM_JOURNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* 8-byte magic identifying a v1 journal file. Not NUL-terminated on disk. */
#define ROM_JOURNAL_MAGIC "ROMJRNL1"
#define ROM_JOURNAL_MAGIC_LEN 8u
#define ROM_JOURNAL_VERSION 1u

/* On-disk fixed header preceding the chunk bitmap. Exactly 88 bytes, natural
 * alignment (no padding): 8 + 4 + 4 + 4 + 4 + 32 + 32. The bitmap that follows
 * is ceil(num_chunks/8) bytes. */
struct rom_journal_header {
    uint8_t  magic[ROM_JOURNAL_MAGIC_LEN]; /* "ROMJRNL1"                        */
    uint32_t version;                      /* ROM_JOURNAL_VERSION               */
    uint32_t chunk_size;                   /* must match the manifest           */
    uint32_t num_chunks;                   /* must match the manifest           */
    uint32_t reserved;                     /* 0 (future flags / header crc)     */
    uint8_t  chunk_root[32];               /* artifact content identity         */
    uint8_t  whole_sha3[32];               /* whole-file digest                 */
};

_Static_assert(sizeof(struct rom_journal_header) == 88,
               "rom_journal_header must be exactly 88 bytes on disk");

/* Opaque runtime handle (fd + in-memory bitmap). */
struct rom_journal;

/* Open or create the journal at `journal_path` for a download whose manifest
 * identity is (chunk_root, whole_sha3, chunk_size, num_chunks). If an existing
 * journal's header does not match those parameters, it is discarded and a
 * fresh one is created (no partial trust). Returns NULL on hard error. */
struct rom_journal *rom_journal_open(const char *journal_path,
                                     const uint8_t chunk_root[32],
                                     const uint8_t whole_sha3[32],
                                     uint32_t chunk_size, uint32_t num_chunks);

/* True iff chunk `idx` is recorded as durably present and digest-verified. */
bool rom_journal_is_done(const struct rom_journal *j, uint32_t idx);

/* Record chunk `idx` as done: set the bit and fdatasync the journal. The
 * caller MUST have already fdatasync'd the chunk data into the .part file.
 * Returns false on an out-of-range index or an IO/durability failure. */
bool rom_journal_mark(struct rom_journal *j, uint32_t idx);

/* Number of chunks currently recorded done (0..num_chunks). */
uint32_t rom_journal_count_done(const struct rom_journal *j);

/* Flush (best-effort) and close the handle. NULL-safe. */
void rom_journal_close(struct rom_journal *j);

/* Remove the journal file at `journal_path` (e.g. after a successful rename or
 * a header mismatch). NULL-safe; returns false only on an unexpected IO error
 * (a missing file is success). */
bool rom_journal_discard(const char *journal_path);

#endif /* ZCL_NET_ROM_JOURNAL_H */
