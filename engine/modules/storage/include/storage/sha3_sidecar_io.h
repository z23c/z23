/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sha3_sidecar_io — shared SHA3 "body + 48-byte sidecar" machinery.
 *
 * Both net/addrman_integrity (peers.dat / "ADIX") and
 * block_index_sidecar_integrity (block_index.bin / "BIIX") store a
 * body file alongside a 48-byte sidecar that commits to the body's
 * size and SHA3-256 digest. The streaming hash, atomic sidecar
 * write, sidecar header parse, and quarantine-rename logic are shared
 * between the two consumers. They differ only in the body/sidecar
 * filenames, the 4-byte magic, the schema
 * version, a domain string used in log/quarantine messages, and the
 * corruption event type.
 *
 * This module is the single source of truth for that shared logic.
 * The aii_* / bii_* public functions remain thin wrappers that pass
 * their own constants in via `struct ssio_spec`, so callers, the
 * lint gates, and the existing tests stay unchanged.
 */

#ifndef ZCL_STORAGE_SHA3_SIDECAR_IO_H
#define ZCL_STORAGE_SHA3_SIDECAR_IO_H

#include "event/event.h"
#include "util/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* The on-disk sidecar header. Both consumers share this exact 48-byte
 * layout; the _Static_assert pins it for every future field change. */
struct ssio_sidecar_header {
    uint8_t  magic[4];
    uint32_t version;
    uint64_t body_size;
    uint8_t  body_sha3[32];
};

_Static_assert(sizeof(struct ssio_sidecar_header) == 48u,
               "ssio sidecar header must be 48 bytes");

/* Verdicts returned by ssio_read_sidecar. The aii_/bii_ verdict
 * enums map these one-to-one in their thin wrappers. */
enum ssio_read_verdict {
    SSIO_READ_OK = 0,
    SSIO_READ_MISSING,       /* sidecar file absent (ENOENT) */
    SSIO_READ_UNREADABLE,    /* open failed for a reason other than ENOENT */
    SSIO_READ_STALE,         /* short read / I/O error reading the header */
    SSIO_READ_BAD_MAGIC,     /* magic mismatch */
    SSIO_READ_UNSUPPORTED,   /* version mismatch */
};

/* Per-consumer constants. Filenames are the bare basenames; the
 * helper joins them onto datadir and appends ".sha3" for the
 * sidecar path itself. */
struct ssio_spec {
    const char       *body_name;    /* e.g. "peers.dat" */
    const char       *sidecar_name; /* e.g. "peers.dat.sha3" */
    const char       *magic;        /* 4-char magic, e.g. "ADIX" (only [0..3] read) */
    uint32_t          version;
    const char       *domain;       /* log/quarantine domain, e.g. "aii" */
    const char       *malloc_label; /* zcl_malloc label for the hash buffer */
    enum event_type   corrupt_event;/* emitted by ssio_quarantine */
};

/* Stream the body at <datadir>/<body_name> through SHA3-256.
 * Returns false on open/read error. Fills out_hash (32 bytes) and,
 * if non-NULL, *out_size with the total bytes hashed. */
bool ssio_hash_body(const char *datadir, const struct ssio_spec *spec,
                    uint8_t out_hash[32], uint64_t *out_size);

/* Compute the sidecar and write it atomically (fwrite to .tmp,
 * fsync, rename). Returns a non-ok zcl_result on any I/O error.
 * Domain string flows into the error messages. */
struct zcl_result ssio_write_sidecar(const char *datadir,
                                     const struct ssio_spec *spec);

/* Write the sidecar from a CALLER-SUPPLIED size + SHA3 (no body read,
 * no rehash). For writers that stream the hash while producing the
 * body: re-hashing a 500 MB body after the rename leaves a multi-
 * second crash window where the new body sits under a stale sidecar
 * and the next boot quarantines a perfectly good file. Same atomic
 * tmp+fsync+rename. */
struct zcl_result ssio_write_sidecar_raw(const char *datadir,
                                         const struct ssio_spec *spec,
                                         uint64_t body_size,
                                         const uint8_t body_sha3[32]);

/* Read + validate the sidecar header at <datadir>/<sidecar_name>.
 * On SSIO_READ_OK, *out holds the parsed header. */
enum ssio_read_verdict ssio_read_sidecar(const char *datadir,
                                         const struct ssio_spec *spec,
                                         struct ssio_sidecar_header *out);

/* ── Embedded single-file integrity ─────────────────────────────
 *
 * Two files (body + sidecar) can never be published as ONE atomic
 * step: a crash between the two renames orphans or mismatches them
 * (a killed shutdown can leave a fresh body under a
 * stale sidecar, and the next boot quarantines a perfectly good file).
 *
 * The embedded format closes that window: the 48-byte
 * `ssio_sidecar_header` is the FIRST 48 bytes of the body file
 * itself, and `body_sha3`/`body_size` commit to the PAYLOAD (every
 * byte AFTER the header). One temp file, one fsync, one rename — the
 * integrity metadata and the bytes it certifies can never diverge.
 *
 * The header uses the SAME 48-byte layout as the sidecar but carries
 * the caller's `spec->magic` so a sidecar header and an embedded
 * header are distinguished by the magic the caller assigns each. */
#define SSIO_EMBEDDED_HEADER_BYTES 48u

/* Write an embedded-integrity file atomically:
 *   1. open <datadir>/<body_name>.tmp
 *   2. write a 48-byte placeholder header
 *   3. call emit_payload(f, ctx) — it streams the payload AND a SHA3
 *      over exactly those payload bytes; it returns the byte count and
 *      finalized digest (false on any write error)
 *   4. fseek back to 0, stamp the real {magic, version, size, sha3}
 *   5. fflush + fsync(fd) + fsync(datadir) + ONE rename to <body_name>
 * On any error the .tmp is unlinked and a non-ok zcl_result returned.
 * `emit_payload` must NOT write the 48-byte header (this helper owns
 * it) — it writes only the payload, starting at file offset 48. */
struct zcl_result ssio_write_embedded(
    const char *datadir, const struct ssio_spec *spec,
    bool (*emit_payload)(FILE *f, void *ctx,
                         uint64_t *out_payload_size,
                         uint8_t out_payload_sha3[32]),
    void *ctx);

/* Verify the embedded header that prefixes <datadir>/<body_name>:
 * checks magic, version, that the on-disk file is exactly
 * 48 + header.body_size bytes, and that a re-hash of the payload
 * (bytes [48, EOF)) matches header.body_sha3. On SSIO_READ_OK,
 * *out holds the parsed header and *out_payload_off is 48 (the
 * loader reads the payload from there). A file whose first 4 bytes
 * are NOT spec->magic returns SSIO_READ_BAD_MAGIC WITHOUT hashing —
 * the caller treats that as "legacy format, try the sidecar path". */
enum ssio_read_verdict ssio_verify_embedded(const char *datadir,
                                            const struct ssio_spec *spec,
                                            struct ssio_sidecar_header *out,
                                            uint64_t *out_payload_off);

/* Rename both the body and sidecar aside as <name>.corrupt.<ts> and
 * emit spec->corrupt_event with "verdict=<verdict_name> ts=<ts>".
 * Missing files are silently ignored. `verdict_name` is the
 * caller's human-readable verdict string. */
void ssio_quarantine(const char *datadir, const struct ssio_spec *spec,
                     const char *verdict_name);

#endif /* ZCL_STORAGE_SHA3_SIDECAR_IO_H */
