/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * blob_store — a generic content-addressed BLOB surface layered on the
 * existing ZCODE package swarm. It adds NO wire message, NO new store,
 * and NO new bound: a blob is just a content.v2 package with exactly one
 * file and exactly one chunk, so it announces, is wanted, and transfers
 * over the already-frozen 'zpkgswm' codec unchanged.
 *
 * Frozen blob package shape (a WIRE CONTRACT from the first publish):
 *   one file, path VCS_BLOB_PATH ("blob"), mode VCS_PACKAGE_MODE_FILE
 *   (0100644), size = len, chunk_count = 1, chunk hash = SHA3-256(bytes).
 * The blob root is therefore vcs_package_manifest_root() of that
 * one-file manifest: a PURE function of the bytes, identical on every
 * node forever. Freeze it with the golden vector in test_zcode_store.
 *
 * AUTHENTICATION SPLIT (preserved, deliberately): this layer proves
 * BYTES ONLY — the root commits the length and the SHA3-256 of the
 * content, nothing else. It carries no signature, no publisher, no
 * authorship, and no chain binding. A signed identity document moves as
 * a blob; whether that document is genuine is contexts/wallet/modules/zid's question, asked
 * after the bytes arrive, never here.
 *
 * BOUND (new, deliberately small): VCS_BLOB_MAX_BYTES caps a blob at
 * 8 KiB — well under the 1 MiB VCS_PACKAGE_CHUNK_BYTES, so the one-file
 * one-chunk shape is structural rather than incidental, and this surface
 * cannot be used to pump 64 MiB packages into a quota'd store. Anything
 * larger is refused by name (VCS_BLOB_ERR_TOO_LARGE) before a byte is
 * hashed. Every other bound (store quota, package cap, tracked count,
 * manifest limits, the 2 MiB swarm frame ceiling) is inherited
 * unchanged; nothing here raises any of them.
 *
 * Reads re-verify at both layers. The package store hashes CAS bytes before
 * return and quarantines a corrupt object; vcs_blob_get also re-parses the
 * stored manifest, re-derives the root, and re-hashes the chunk. Corruption
 * fails VCS_BLOB_ERR_CORRUPT instead of being returned as content. */

#ifndef ZCL_VCS_BLOB_STORE_H
#define ZCL_VCS_BLOB_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The single canonical path inside every blob package. Frozen: it is
 * committed by the manifest root, so changing it changes every root. */
#define VCS_BLOB_PATH "blob"

/* Blob size ceiling. A signed zid_doc is at most ZID_DOC_MAX (1139)
 * bytes; 8 KiB leaves generous headroom while staying far below one
 * chunk. Never raise this to admit a large object — publish a real
 * package instead. */
#define VCS_BLOB_MAX_BYTES 8192u

struct vcs_package_store;
struct vcs_swarm_engine;

enum vcs_blob_result {
    VCS_BLOB_OK = 0,
    VCS_BLOB_ERR_NULL,      /* null argument */
    VCS_BLOB_ERR_EMPTY,     /* zero-length blob: not a content object */
    VCS_BLOB_ERR_TOO_LARGE, /* len > VCS_BLOB_MAX_BYTES */
    VCS_BLOB_ERR_NO_STORE,  /* no package store (hosting disabled) */
    VCS_BLOB_ERR_NO_ENGINE, /* no swarm engine wired */
    VCS_BLOB_ERR_MANIFEST,  /* manifest build/serialize/parse failure */
    VCS_BLOB_ERR_STORE,     /* store refused (quota, cap, I/O, ...) */
    VCS_BLOB_ERR_ABSENT,    /* root not tracked / chunk not present */
    VCS_BLOB_ERR_SHAPE,     /* tracked root is not a one-file blob */
    VCS_BLOB_ERR_CORRUPT,   /* stored bytes do not match the root */
    VCS_BLOB_ERR_CAPACITY,  /* caller buffer smaller than the blob */
    VCS_BLOB_ERR_FETCH,     /* swarm refused the download (named) */
};

const char *vcs_blob_result_string(enum vcs_blob_result r);

/* ── pure: the root of these bytes, no store touched ───────────────── */

/* Same bytes -> same root, on any node, forever. */
enum vcs_blob_result vcs_blob_root_of(const uint8_t *bytes, size_t len,
                                      uint8_t out_root[32]);
bool vcs_blob_root(const uint8_t *bytes, size_t len, uint8_t out_root[32]);

/* ── put / get against an explicit store ───────────────────────────── */

/* Admit the blob (manifest + its single chunk) into `store`. Idempotent:
 * re-putting identical bytes is OK and yields the same root. */
enum vcs_blob_result vcs_blob_put_to(struct vcs_package_store *store,
                                     const uint8_t *bytes, size_t len,
                                     uint8_t out_root[32]);

/* Read the blob back, re-verified against `root`. Writes at most
 * out_cap bytes and reports the exact length in *out_len (may be NULL
 * when the caller only wants OK/not-OK). */
enum vcs_blob_result vcs_blob_get_from(struct vcs_package_store *store,
                                       const uint8_t root[32], uint8_t *out,
                                       size_t out_cap, size_t *out_len);

/* ── put / get against the node-global store ───────────────────────── */

bool vcs_blob_put(const uint8_t *bytes, size_t len, uint8_t out_root[32]);
/* Bytes written, or -1 on any failure (logged, named internally). */
int vcs_blob_get(const uint8_t root[32], uint8_t *out, size_t out_cap);

/* ── network: fetch by root over the existing swarm ────────────────── */

/* Schedule a swarm download of the blob's package root. No new message:
 * this is vcs_swarm_engine_fetch(), which walks the frozen
 * WANT(manifest) -> WANT(chunk 0 of file 0) -> DATA path. `day`/`now`
 * are the engine's caller-driven clock, exactly as elsewhere. Already
 * complete locally is OK. */
enum vcs_blob_result vcs_blob_fetch_via(struct vcs_swarm_engine *engine,
                                        const uint8_t root[32], int64_t day,
                                        uint64_t now);
bool vcs_blob_fetch(const uint8_t root[32], int64_t day, uint64_t now);

/* Queue ANNOUNCE frames for every complete tracked package (a stored
 * blob included) to every registered swarm peer. Returns the frame
 * count queued; the transport glue drains them as usual. */
size_t vcs_blob_announce_via(struct vcs_swarm_engine *engine);
size_t vcs_blob_announce(void);

#endif /* ZCL_VCS_BLOB_STORE_H */
