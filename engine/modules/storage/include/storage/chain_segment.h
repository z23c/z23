/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chain_segment: the OS-Core ROM layer — an immutable, sealed, hash-committed
 * segment store for finalized block bodies. Finalized history (the first ~3M
 * ZClassic blocks) is structurally immutable; this gives it an immutable
 * container so it is no longer indistinguishable from mutable tip state.
 *
 * On-disk format (all integers little-endian):
 *
 *   Segment file  "seg-<first_height>-<count>.dat":
 *     Header (32 bytes)
 *       [ 0.. 8)  magic          "ZCLSEG01"
 *       [ 8..12)  u32 format_version   (= 1)
 *       [12..16)  u32 first_height
 *       [16..20)  u32 block_count
 *       [20..24)  u32 index_entry_size (= 48)
 *       [24..32)  u64 data_offset      (= 32 + block_count*48)
 *     Index (block_count entries, 48 bytes each, ascending height)
 *       [ 0.. 4)  u32 height
 *       [ 4.. 8)  u32 length           (raw block byte length)
 *       [ 8..16)  u64 offset           (absolute file offset of the bytes)
 *       [16..48)  u8[32] sha3          SHA3-256 of the raw block bytes
 *     Block data
 *       raw serialized block bytes, concatenated at their index offsets
 *     Trailer (32 bytes)
 *       u8[32] segment_digest          SHA3-256 over [0, trailer_offset)
 *
 *   Manifest file "manifest.dat":
 *     Header (16 bytes)
 *       [ 0.. 8)  magic          "ZCLMAN01"
 *       [ 8..12)  u32 format_version   (= 1)
 *       [12..16)  u32 segment_count
 *     Entries (segment_count entries, 40 bytes each, ascending first_height)
 *       [ 0.. 4)  u32 first_height
 *       [ 4.. 8)  u32 count
 *       [ 8..40)  u8[32] segment_digest
 *     Trailer (32 bytes)
 *       u8[32] manifest_root           SHA3-256 over [0, trailer_offset)
 *
 * Segments are written once (atomic tmp -> fsync -> rename, then chmod 0444)
 * and never rewritten or appended. Corruption is a typed error naming the
 * segment and height, never a silent fallback.
 */

#ifndef ZCL_STORAGE_CHAIN_SEGMENT_H
#define ZCL_STORAGE_CHAIN_SEGMENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CHAIN_SEGMENT_FORMAT_VERSION 1u
#define CHAIN_SEGMENT_HEADER_SIZE      32u
#define CHAIN_SEGMENT_INDEX_ENTRY_SIZE 48u
#define CHAIN_SEGMENT_TRAILER_SIZE     32u
#define CHAIN_SEGMENT_BLOCKS_PER_SEG   10000u

#define CHAIN_MANIFEST_FORMAT_VERSION 1u
#define CHAIN_MANIFEST_HEADER_SIZE   16u
#define CHAIN_MANIFEST_ENTRY_SIZE    40u
#define CHAIN_MANIFEST_TRAILER_SIZE  32u

enum cseg_status {
    CSEG_OK = 0,
    CSEG_ERR_ARG,            /* NULL / nonsensical argument */
    CSEG_ERR_EMPTY_RANGE,    /* count == 0 */
    CSEG_ERR_BODY_MISSING,   /* body source returned nothing for a height */
    CSEG_ERR_IO,             /* open/read/write/rename/mmap failed */
    CSEG_ERR_FORMAT,         /* bad magic / truncated / inconsistent header */
    CSEG_ERR_SEGMENT_DIGEST, /* whole-segment SHA3 mismatch */
    CSEG_ERR_BLOCK_DIGEST,   /* per-block SHA3 mismatch */
    CSEG_ERR_NOT_FOUND,      /* height not present in the segment */
    CSEG_ERR_MANIFEST,       /* manifest bad / segment digest disagrees */
};

const char *cseg_status_str(enum cseg_status s);

/* Body source: yields the raw serialized bytes of the block at `height`.
 * On success sets *bytes to a malloc'd buffer (caller frees) and *len, and
 * returns true. Returns false when the body is missing or short — the writer
 * fails closed on any false return. */
typedef bool (*chain_segment_body_fn)(void *user, uint32_t height,
                                      uint8_t **bytes, size_t *len);

/* ── Writer ──────────────────────────────────────────────────────────
 * Seal [first_height, first_height+count) into `dir`, chunked into segment
 * files of at most CHAIN_SEGMENT_BLOCKS_PER_SEG blocks each, then rebuild the
 * manifest to cover every segment file present in `dir`. Fails closed
 * (CSEG_ERR_BODY_MISSING) if the body source cannot supply any height in the
 * range; a partially written tmp file is unlinked, no segment is left behind.
 * `err`/`errlen` receive a bounded human message on any non-OK return. */
enum cseg_status chain_segment_seal_range(const char *dir,
                                          chain_segment_body_fn body,
                                          void *user,
                                          uint32_t first_height,
                                          uint32_t count,
                                          char *err, size_t errlen);

/* Rebuild `dir`/manifest.dat from the seg-*.dat files present. Each segment is
 * opened and its digest verified before it is listed. */
enum cseg_status chain_segment_manifest_rebuild(const char *dir,
                                                char *err, size_t errlen);

/* ── Reader ──────────────────────────────────────────────────────────
 * chain_segment_open mmaps the file and verifies the whole-segment SHA3 digest
 * on open (full pass over the mapped bytes — O(segment size); pay it once, then
 * per-block reads are a bounded index lookup + one 32-byte digest check). */
struct chain_segment;

enum cseg_status chain_segment_open(const char *path,
                                    struct chain_segment **out,
                                    char *err, size_t errlen);
void chain_segment_close(struct chain_segment *seg);

uint32_t chain_segment_first_height(const struct chain_segment *seg);
uint32_t chain_segment_count(const struct chain_segment *seg);
void     chain_segment_digest(const struct chain_segment *seg, uint8_t out[32]);

/* Copy the raw block bytes for `height` into a fresh malloc'd buffer (caller
 * frees) after re-checking the per-block SHA3. A digest mismatch returns
 * CSEG_ERR_BLOCK_DIGEST with the segment + height named in `err`. */
enum cseg_status chain_segment_get_block(struct chain_segment *seg,
                                         uint32_t height,
                                         uint8_t **bytes, size_t *len,
                                         char *err, size_t errlen);

/* ── Store-level view (a directory of segments + its manifest) ───────── */
struct chain_segment_stat {
    uint32_t segment_count;      /* segments listed in the manifest */
    bool     have_range;         /* false when no segments exist */
    uint32_t min_height;         /* lowest covered height */
    uint32_t max_height;         /* highest covered height */
    uint8_t  manifest_root[32];  /* SHA3 manifest root */
    bool     full_verify;        /* verified_count came from a full digest pass */
    uint32_t verified_count;     /* segments proven present (or digest-verified) */
};

/* Load `dir`/manifest.dat and summarize it. An absent manifest is not an error
 * (segment_count = 0). With full_verify, each segment file is opened and its
 * digest recomputed and matched against the manifest (O(store size)); without
 * it, verified_count counts segments whose file exists with a matching header
 * (cheap). A digest disagreement under full_verify returns CSEG_ERR_MANIFEST
 * naming the offending segment. */
enum cseg_status chain_segment_store_stat(const char *dir,
                                          bool full_verify,
                                          struct chain_segment_stat *out,
                                          char *err, size_t errlen);

/* ── Resident store reader (the fold substrate) ──────────────────────────
 * A long-lived, thread-safe handle over a directory of sealed segments. It
 * locates the segment covering a height by the seg-<first>-<count>.dat file
 * name (no manifest needed) and keeps a small LRU of mmap'd, digest-verified
 * segment handles resident so a sequential fold pays the whole-segment SHA3
 * verify once per segment, then only a per-block 32-byte digest per read.
 *
 * This is the source the fold prefers below the sealed frontier: reading a
 * finalized body from a sealed segment is a sequential mmap read instead of a
 * blk*.dat pread, and it is byte-identical to the on-disk body (the segment
 * stored exactly the block_serialize output). An absent/empty segments dir is
 * not an error — the store simply covers nothing and every read falls through
 * to blk*.dat, so a node with no segments is byte-for-byte unchanged. */
struct chain_segment_store;

/* Open a resident reader over `dir`. An absent directory yields an empty store
 * (covers nothing), not an error. Individual segment files are opened+verified
 * lazily on first access, not here, so open is cheap (one directory scan). */
enum cseg_status chain_segment_store_open(const char *dir,
                                          struct chain_segment_store **out,
                                          char *err, size_t errlen);
void chain_segment_store_close(struct chain_segment_store *s);

/* True when some sealed segment contains `height`. Cheap (bounded search over
 * the segment table); does not open or hash any segment. */
bool chain_segment_store_covers(const struct chain_segment_store *s,
                                uint32_t height);

/* Highest height covered by any sealed segment (0 when the store is empty —
 * pair with chain_segment_store_have to disambiguate a genuine height 0). */
uint32_t chain_segment_store_sealed_max(const struct chain_segment_store *s);
bool     chain_segment_store_have(const struct chain_segment_store *s);

/* Copy the raw block bytes for `height` from its covering segment into a fresh
 * malloc'd buffer (caller frees), re-checking the per-block SHA3. Returns
 * CSEG_ERR_NOT_FOUND when no segment covers `height`. Thread-safe. */
enum cseg_status chain_segment_store_get_block(struct chain_segment_store *s,
                                               uint32_t height,
                                               uint8_t **bytes, size_t *len,
                                               char *err, size_t errlen);

/* Number of sealed segments the store knows about, and the [first,count) range
 * of the i-th (ascending by first_height). For bounded corruption sweeps. */
uint32_t chain_segment_store_segment_count(const struct chain_segment_store *s);
bool chain_segment_store_segment_range(const struct chain_segment_store *s,
                                       uint32_t i, uint32_t *first,
                                       uint32_t *count);

/* Force a full digest verify of the i-th segment (opens it, which re-hashes the
 * whole segment). CSEG_ERR_SEGMENT_DIGEST/CSEG_ERR_FORMAT names a corrupt
 * segment; the covered height range is in `err`. Bounded: one segment. */
enum cseg_status chain_segment_store_verify_index(struct chain_segment_store *s,
                                                  uint32_t i,
                                                  char *err, size_t errlen);

#endif /* ZCL_STORAGE_CHAIN_SEGMENT_H */
