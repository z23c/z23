/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Obtain the Zcash zk PROVING parameters from the peer network, with every
 * byte checked against digests compiled into this binary.
 *
 * WHY THIS EXISTS
 * ---------------
 * A Zcash parameter file is a verifying key followed by a much larger proving
 * key. The verifying keys — 6357 bytes — are compiled in
 * (sapling/params_vk_embedded.h), so a node with an empty $HOME already syncs,
 * validates every shielded proof, and serves peers. The one capability it
 * lacks is CREATING a shielded transaction, which needs ~777 MB of proving
 * key. Until now the only way to get those bytes was an out-of-band download
 * from a host with a DNS name and a certificate authority behind it — the
 * single largest sovereignty hole in the project.
 *
 * This module moves those bytes over the transport the node already has,
 * without adding a name server, a CA, or a dependency.
 *
 * WHAT IS TRUSTED
 * ---------------
 * Exactly one thing: the table `zcl_param_pins` below. Each entry carries the
 * file's exact byte length and its SHA-256, both of which are public outputs
 * of the Zcash parameter ceremonies and are corroborated in
 * tools/scripts/zcash_params.sh, docs/PARAMS.md, and upstream zcash's own
 * zcutil/fetch-params.sh. Each entry also carries a chunk Merkle root, which
 * is not published by anyone but is a deterministic function of the file the
 * SHA-256 already pins: recompute it from a file that matches the pinned
 * digest and you must get the pinned root. `zcl_param_pin_recompute_from_file`
 * is that recomputation, and the test suite runs it against the real files
 * whenever they are present on the machine.
 *
 * NOTHING ELSE IS TRUSTED. A peer supplies a manifest, and the manifest is
 * accepted only if the Merkle root over the chunk hashes it contains equals
 * the compiled-in root. A peer supplies chunk bytes, and they are accepted
 * only if their SHA-256 equals the manifest entry for that index — checked
 * before the bytes are written, so a hostile peer cannot make us commit
 * garbage to disk. The completed file is re-hashed end to end against the
 * compiled-in SHA-256 before it is renamed into place. Any single one of
 * those three checks failing is fatal to the transfer.
 *
 * WHAT THIS MODULE IS NOT
 * -----------------------
 * There is no socket, no peer, and no message in this file. It is a pure
 * verifier and on-disk state machine; net/params_service.h drives it with
 * bytes that arrived from somewhere. That split is what lets the tests prove
 * every refusal path without a network.
 */

#ifndef ZCL_SAPLING_PARAMS_FETCH_H
#define ZCL_SAPLING_PARAMS_FETCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Hard bounds ────────────────────────────────────────────────────
 *
 * Every length that arrives from the wire is hostile input. These are the
 * ceilings it is measured against, and they are compile-time constants so
 * that no peer can move them.
 *
 * The chunk size is part of the trust root: the pinned Merkle roots are only
 * meaningful for this exact chunking. Changing it invalidates every pinned
 * root and the test that recomputes them will say so.
 */
#define ZCL_PARAM_CHUNK_BYTES     (1u << 20)   /* 1 MiB, fixed forever */
#define ZCL_PARAM_MAX_CHUNKS      4096u        /* ⇒ ≤ 4 GiB addressable */
#define ZCL_PARAM_MAX_FILE_BYTES  (1024ull * 1024ull * 1024ull) /* 1 GiB */
#define ZCL_PARAM_HASH_BYTES      32u
#define ZCL_PARAM_MANIFEST_MAX_BYTES (ZCL_PARAM_MAX_CHUNKS * ZCL_PARAM_HASH_BYTES)

/* The four files a proving-capable node needs. */
#define ZCL_PARAM_FILE_COUNT 4

/* One pinned parameter file. `bytes` and `sha256_hex` are the corroborated
 * ceremony outputs; `chunk_root_hex` is derived from them (see above). */
struct zcl_param_pin {
    const char *name;
    uint64_t    bytes;
    const char *sha256_hex;
    const char *chunk_root_hex;
    uint32_t    chunk_count;   /* ceil(bytes / ZCL_PARAM_CHUNK_BYTES) */
};

extern const struct zcl_param_pin zcl_param_pins[ZCL_PARAM_FILE_COUNT];

/* Index of a pinned file by name, or -1. Name lookup is exact: a peer cannot
 * ask us to serve, or persuade us to fetch, a path that is not in the table,
 * so no wire string ever reaches the filesystem as a path component. */
int zcl_param_pin_index(const char *name);

/* Byte length of chunk `idx` of pinned file `file_idx`. 0 if either index is
 * out of range — the last chunk is short for every one of our files. */
size_t zcl_param_chunk_len(int file_idx, uint32_t idx);

/* ── Merkle tree over chunks ────────────────────────────────────────
 *
 * leaf_i   = SHA256(0x00 || chunk_i)
 * node     = SHA256(0x01 || left || right)
 * odd node = promoted unchanged (never duplicated)
 *
 * The leaf/interior domain separation and the fact that the leaf count is
 * itself derived from the pinned file length together mean there is no
 * ambiguity a second-preimage construction could exploit: a manifest with a
 * different chunk count is refused before its root is ever computed.
 */
void zcl_param_leaf_hash(const uint8_t *chunk, size_t len,
                         uint8_t out[ZCL_PARAM_HASH_BYTES]);

/* Fold `count` leaf hashes (contiguous, 32 bytes each) into a root.
 * Returns false for count == 0 or count > ZCL_PARAM_MAX_CHUNKS. */
bool zcl_param_merkle_root(const uint8_t *leaves, uint32_t count,
                           uint8_t out[ZCL_PARAM_HASH_BYTES]);

/* Check a peer-supplied manifest for `file_idx` against the compiled-in pin.
 * `count` is the peer's claimed chunk count and is checked against the derived
 * count BEFORE `leaves` is read, so a lying count cannot walk off the buffer.
 * Returns true only when the Merkle root matches the pinned root exactly. */
bool zcl_param_manifest_verify(int file_idx, const uint8_t *leaves,
                               uint32_t count);

/* ── Recomputation from a real file (trust-root corroboration) ─────
 *
 * Stream `path`, and report its length, its SHA-256, and its chunk Merkle
 * root. Used by the pin-regeneration tool and by the test that proves the
 * pinned roots really are a function of the pinned digests. Reads with a
 * bounded buffer; never maps or allocates the whole file. */
bool zcl_param_pin_recompute_from_file(const char *path, uint64_t *out_bytes,
                                       uint8_t out_sha256[ZCL_PARAM_HASH_BYTES],
                                       uint8_t out_root[ZCL_PARAM_HASH_BYTES]);

/* ── Installed-file verification ────────────────────────────────────── */

/* True when `dir/<pinned name>` exists and matches its pinned length AND
 * SHA-256. Streams the file; allocates a fixed buffer, never the file. */
bool zcl_param_verify_installed(const char *dir, int file_idx);

/* True when all ZCL_PARAM_FILE_COUNT files are installed and verified.
 * This is the predicate the boot path should use to decide whether the
 * proving parameters are genuinely present — never a bare access() check. */
bool zcl_params_all_installed_verified(const char *dir);

/* ── Fetch session ──────────────────────────────────────────────────
 *
 * One session owns one file's download. It is resumable across process
 * restarts: progress lives in `dir/<name>.part` (the bytes) and
 * `dir/<name>.zpart` (which chunks are verified). Nothing is ever renamed
 * into `dir/<name>` until the whole file re-hashes to the pinned SHA-256, so
 * a half-written parameter file is never visible to the loader.
 */
struct zcl_param_fetch;

enum zcl_param_chunk_result {
    ZCL_PARAM_CHUNK_OK = 0,       /* verified and written */
    ZCL_PARAM_CHUNK_DUPLICATE,    /* already had it; peer wasted our time */
    ZCL_PARAM_CHUNK_BAD_INDEX,    /* index out of range for this file */
    ZCL_PARAM_CHUNK_BAD_LENGTH,   /* not the exact length this index must be */
    ZCL_PARAM_CHUNK_BAD_HASH,     /* bytes do not match the verified manifest */
    ZCL_PARAM_CHUNK_NO_MANIFEST,  /* nothing to check against yet */
    ZCL_PARAM_CHUNK_IO_ERROR,
};

/* Open (or resume) a session for pinned file `file_idx` under `dir`.
 * On resume, every chunk the state file claims is verified is re-read from
 * `.part` and re-hashed before it is believed: an unclean shutdown can leave
 * the state file ahead of the data, and the cost of being wrong here is a
 * corrupt proving key. Returns NULL on bad index or I/O failure. */
struct zcl_param_fetch *zcl_param_fetch_open(const char *dir, int file_idx);

/* Install a manifest. Refused unless zcl_param_manifest_verify passes, so a
 * lying manifest is rejected outright and no chunk is ever requested against
 * it. Safe to call again with the same verified manifest; a second, different
 * manifest is refused. */
bool zcl_param_fetch_set_manifest(struct zcl_param_fetch *s,
                                  const uint8_t *leaves, uint32_t count);

bool zcl_param_fetch_has_manifest(const struct zcl_param_fetch *s);

/* Lowest chunk index not yet verified, or UINT32_MAX when the file is
 * complete. `zcl_param_fetch_pick_missing` fills `out` with up to `max`
 * distinct missing indices starting after `after`, for requesting a spread of
 * chunks from several peers at once; returns how many it wrote. */
uint32_t zcl_param_fetch_next_needed(const struct zcl_param_fetch *s);
uint32_t zcl_param_fetch_pick_missing(const struct zcl_param_fetch *s,
                                      uint32_t after, uint32_t *out,
                                      uint32_t max);

/* Verify and store one chunk. `len` is hostile input and is compared against
 * the exact required length for `idx` before `data` is touched. */
enum zcl_param_chunk_result
zcl_param_fetch_accept_chunk(struct zcl_param_fetch *s, uint32_t idx,
                             const uint8_t *data, size_t len);

/* Counters for progress reporting and for peer accounting. */
uint32_t zcl_param_fetch_chunks_have(const struct zcl_param_fetch *s);
uint32_t zcl_param_fetch_chunks_total(const struct zcl_param_fetch *s);
uint64_t zcl_param_fetch_bytes_rejected(const struct zcl_param_fetch *s);

bool zcl_param_fetch_is_complete(const struct zcl_param_fetch *s);

/* Re-hash the assembled `.part` end to end against the pinned SHA-256, fsync
 * it, and rename it onto `dir/<name>`. Returns false — leaving `.part` in
 * place for another attempt — if the whole-file digest does not match, which
 * would mean chunk verification and whole-file verification disagree.
 * Removes the state file on success. */
bool zcl_param_fetch_finalize(struct zcl_param_fetch *s);

void zcl_param_fetch_close(struct zcl_param_fetch *s);

/* Peak resident bytes this module has allocated for a session, for the
 * memory claim in the transfer report. */
size_t zcl_param_fetch_session_footprint(const struct zcl_param_fetch *s);

/* ── Serving side ───────────────────────────────────────────────────
 *
 * A node serves proving parameters only after it has verified its own copy,
 * and only when serving has been explicitly armed. `prepare` is the expensive
 * step — it streams every file to verify it and to build the manifests — and
 * it is never run on a message-handling thread.
 */

/* Verify the local parameter set and build the served manifests. Returns the
 * number of files armed (0..ZCL_PARAM_FILE_COUNT). Safe to call twice. */
int zcl_param_serve_prepare(const char *dir);

/* True when `file_idx` has been armed by a successful prepare. */
bool zcl_param_serve_ready(int file_idx);

/* Copy the armed manifest for `file_idx`. Returns false if not armed or if
 * `cap` is too small. */
bool zcl_param_serve_manifest(int file_idx, uint8_t *out, size_t cap,
                              uint32_t *out_count);

/* Read one chunk out of the armed local file. Bounded by construction: never
 * reads or writes more than ZCL_PARAM_CHUNK_BYTES, and refuses an index the
 * pin does not cover. */
bool zcl_param_serve_chunk(int file_idx, uint32_t idx, uint8_t *out,
                           size_t cap, size_t *out_len);

/* Release the armed manifests and close the served descriptors.
 *
 * Intended for process teardown. It clears each armed flag before it frees
 * anything, but it does not wait for a serve already in flight on another
 * thread, so calling it while peers are actively being served is not safe.
 * Arm once at boot, release once at exit. */
void zcl_param_serve_shutdown(void);

#endif /* ZCL_SAPLING_PARAMS_FETCH_H */
