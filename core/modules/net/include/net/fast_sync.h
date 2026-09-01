/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fast P2P sync protocol for zclassic23 nodes.
 *
 * When two zclassic23 nodes connect, they can use this protocol
 * instead of legacy block-by-block sync. The protocol:
 *
 * 1. SNAPSHOT_OFFER: "I have a UTXO snapshot at height H with root R"
 * 2. SNAPSHOT_REQUEST: "Send me the snapshot"
 * 3. SNAPSHOT_DATA: Chunked UTXO set transfer
 * 4. SNAPSHOT_VERIFY: Recipient verifies Merkle root matches
 * 5. DELTA_SYNC: Sync remaining blocks from snapshot height to tip
 *
 * This reduces initial sync from hours to minutes.
 *
 * Detection: zclassic23 nodes advertise service bit NODE_ZCL23 (1<<10)
 * in the version message. If both peers have it, fast sync activates. */

#ifndef ZCL_NET_FAST_SYNC_H
#define ZCL_NET_FAST_SYNC_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

/* Service bit for zclassic23 extended protocol */
#define NODE_ZCL23 (1 << 10)

/* Fast sync message types (command names for P2P) */
#define MSG_SNAPSHOT_OFFER   "zsnapshot"
#define MSG_SNAPSHOT_REQ     "zsnapreq"
#define MSG_SNAPSHOT_DATA    "zsnapdata"
#define MSG_SNAPSHOT_END     "zsnapend"

/* BitTorrent-style parallel chunk sync messages */
#define MSG_CHUNK_REQ        "zchunkreq"   /* request chunk by index */
#define MSG_CHUNK_DATA       "zchunkdata"  /* chunk response with index + hash */
#define MSG_MANIFEST         "zmanifest"   /* manifest with chunk count + merkle root */

/* Default UTXOs per chunk for parallel sync */
#define SYNC_CHUNK_SIZE 500

/* cap on num_chunks in a wire manifest. The MSG_MANIFEST payload
 * carries num_chunks*32 bytes of per-chunk SHA3-256 hashes after the
 * fixed header; this cap keeps the message comfortably below
 * MAX_PROTOCOL_MESSAGE_LENGTH (2 MiB) and bounds the calloc a peer can
 * force us to perform. At SYNC_CHUNK_SIZE=500 it still covers 32.5M
 * UTXOs — many decades of ZCL mainnet growth. */
#define MANIFEST_MAX_CHUNKS 65000u
#define FAST_SYNC_PROTOCOL_VERSION 2u
#define FAST_SYNC_SNAPSHOT_SCHEMA_VERSION 1u

/* ── Rate limiting + PoW defense ─────────────────────────── */

/* Difficulty for snapshot request PoW (number of leading zero bits).
 * 20 bits ≈ ~1M hashes ≈ ~0.5s on modern CPU. Prevents spam. */
#define FAST_SYNC_POW_BITS 20

/* Max snapshot chunks per IP per hour */
#define FAST_SYNC_MAX_CHUNKS_PER_HOUR 5000

/* PoW challenge: client must find nonce such that
 * SHA256(peer_id || timestamp || nonce) has FAST_SYNC_POW_BITS leading zeros.
 * This is included in the zsnapreq message. */
struct fast_sync_pow {
    uint8_t  peer_id[32];   /* SHA256 of requester's IP or node ID */
    int64_t  timestamp;     /* unix timestamp (must be within 5 min) */
    uint64_t nonce;         /* PoW solution */
};

/* Verify a PoW proof. Returns true if valid. */
bool fast_sync_verify_pow(const struct fast_sync_pow *pow);

/* Solve a PoW challenge (blocking, ~0.5s). */
bool fast_sync_solve_pow(const uint8_t peer_id[32], struct fast_sync_pow *pow);

/* The hardened, challenge-bound, adaptive, single-use puzzle that used to
 * live here (fast_sync_verify_pow_ex / fast_sync_solve_pow_ex /
 * struct fast_sync_pow_gate) is now the surface-neutral primitive in
 * net/puzzle.h — puzzle_verify / puzzle_solve / struct puzzle_gate. Same
 * SHA3-256(challenge_seed || peer_token || ts || nonce) puzzle, same
 * rotating server-issued seed and single-use ring; the load term is an
 * EWMA instead of a tumbling window. Snapshot serving, the file service,
 * and the onion service all draw from that one implementation. */

/* Max total chunks across all IPs per hour (global cap) */
#define FAST_SYNC_MAX_GLOBAL_CHUNKS_PER_HOUR 50000

/* Block pieces (zblkreq) get their own limiter: each piece is a
 * manifest-hash-bound batch of BLOCKS_PER_PIECE blocks, so a full-tip
 * swarm sync needs ~48k pieces from one peer — the snapshot-chunk caps
 * above would floor a single-peer sync at ~10 hours and starve the
 * swarm mid-download (requester re-requests on timeout, burning the
 * shared bucket). 100k/hr per IP ≈ two full-tip syncs with re-request
 * headroom; still a hard DoS cap (each serve is ≤2 MB on the wire). */
#define FAST_SYNC_MAX_BLOCK_PIECES_PER_HOUR 100000
#define FAST_SYNC_MAX_GLOBAL_BLOCK_PIECES_PER_HOUR 1000000

/* Rate limiter state (per node, tracks IPs + global) */
struct fast_sync_rate_limiter {
    struct {
        uint8_t ip[16];
        int64_t window_start;
        uint32_t chunks_sent;
    } entries[1024];
    size_t num_entries;
    /* Global rate tracking */
    int64_t global_window_start;
    uint64_t global_chunks_sent;
};

/* Check if an IP is rate-limited. Returns true if OK to serve.
 * Uses the snapshot-chunk caps (FAST_SYNC_MAX_*_CHUNKS_PER_HOUR). */
bool fast_sync_rate_check(struct fast_sync_rate_limiter *rl,
                           const uint8_t ip[16]);

/* Same check against caller-supplied caps — used by block piece
 * serving with FAST_SYNC_MAX_*_BLOCK_PIECES_PER_HOUR. */
bool fast_sync_rate_check_n(struct fast_sync_rate_limiter *rl,
                            const uint8_t ip[16],
                            uint32_t max_per_ip_per_hour,
                            uint64_t max_global_per_hour);

/* UTXO snapshot chunk: batch of UTXOs for transfer.
 * Max 1000 entries for legacy full-snapshot transfer.
 * Parallel sync uses SYNC_CHUNK_SIZE (500) entries per chunk. */
struct utxo_chunk {
    uint32_t num_entries;
    uint32_t chunk_index;     /* index within manifest (for parallel sync) */
    struct {
        uint8_t  txid[32];
        uint32_t vout;
        int64_t  value;
        uint8_t  script[520]; /* matches snapshot writer script cap */
        uint16_t script_len;
        int32_t  height;
        bool     is_coinbase;
    } entries[1000]; /* 1000 max; parallel sync uses 500 */
};

/* Snapshot offer message */
struct snapshot_offer {
    int32_t  height;         /* snapshot height */
    uint32_t protocol_version;
    uint32_t snapshot_schema_version;
    int32_t  peer_tip_height; /* serving peer chain tip; height must be finality-safe */
    uint8_t  block_hash[32]; /* block hash at height */
    uint8_t  utxo_root[32]; /* SHA3 Merkle root of UTXO set */
    uint8_t  mmr_root[32];  /* MMR root over all block hashes (legacy) */
    uint8_t  mmb_root[32];  /* MMB root — FlyClient O(log k) proofs */
    uint8_t  chain_work[32]; /* cumulative work at anchor height */
    uint64_t num_utxos;      /* total UTXO count */
    uint64_t total_bytes;    /* estimated transfer size */
};

/* Check if a peer supports zclassic23 fast sync */
static inline bool peer_supports_fast_sync(uint64_t services)
{
    return (services & NODE_ZCL23) != 0;
}

/* Build a snapshot offer from current chain state */
bool fast_sync_build_offer(const char *datadir,
                            struct snapshot_offer *offer);

/* Publish, clear, or read the cached UTXO root used when rebuilding
 * snapshot offers. The cached root is keyed by the matching UTXO count. */
bool fast_sync_publish_utxo_root_cache(const uint8_t root[32], uint64_t count);
void fast_sync_reset_utxo_root_cache(void);
bool fast_sync_get_utxo_root_cache(uint8_t out[32], uint64_t *count);
uint64_t fast_sync_utxo_root_cache_version(void);

/* Path to the pre-serialized snapshot file ({datadir}/snapshot.bin).
 * Built by fast_sync_prebuild_snapshot() for zero-copy serving. */
void fast_sync_snapshot_path(char *out, size_t max, const char *datadir);

/* Caller-owned snapshot serializer. Fast sync owns the protocol file path and
 * metadata publishing; the app/model layer owns how UTXOs are read. */
typedef int64_t (*fast_sync_snapshot_serialize_fn)(void *ctx,
                                                   const char *path,
                                                   uint32_t chunk_size,
                                                   uint8_t sha3_out[32]);

/* Pre-serialize all UTXOs into a binary snapshot file for fast serving.
 * Must be called after the UTXO set is stable (at tip).
 * Returns total UTXOs serialized, or -1 on error. */
int64_t fast_sync_prebuild_snapshot(const char *datadir,
                                    fast_sync_snapshot_serialize_fn serialize,
                                    void *serialize_ctx);

/* Publish or clear the in-memory snapshot cache and its matching SHA3
 * metadata. Ownership of snapshot_buf transfers to the cache on success.
 * On failure the caller remains responsible for freeing snapshot_buf. */
bool fast_sync_publish_snapshot_cache(uint8_t *snapshot_buf, int64_t size,
                                      const uint8_t sha3[32],
                                      uint64_t count);
void fast_sync_reset_snapshot_cache(void);
uint64_t fast_sync_snapshot_cache_version(void);

/* Get the size of the pre-built snapshot file in bytes. Returns 0 if none. */
uint64_t fast_sync_snapshot_file_size(const char *datadir);

/* Get the optional in-memory snapshot buffer.
 * Normal public-node startup publishes disk-backed snapshot metadata and
 * returns NULL here; explicit tests/callers can still publish a bounded RAM
 * cache through fast_sync_publish_snapshot_cache(). */
const uint8_t *fast_sync_get_snapshot_buf(int64_t *size);

/* Get the SHA3-256 hash computed during pre-serialization.
 * This hash is guaranteed to match the file contents exactly.
 * Returns false if no snapshot has been pre-built yet. */
bool fast_sync_get_snapshot_sha3(uint8_t out[32], uint64_t *count);

/* Receive and apply a snapshot */
bool fast_sync_apply_chunk(const char *datadir,
                            const struct utxo_chunk *chunk);

/* Internal: compute the SHA3 UTXO root from an open db handle. */
struct sqlite3;
void fast_sync_compute_utxo_root_db(struct sqlite3 *db,
                                     uint8_t root_out[32]);

/* Diagnostics dump (`ops state --subsystem=fast_sync`).
 * See CLAUDE.md "Adding state introspection". Reentrant-safe; the caller
 * runs json_set_object(out) semantics — this implementation initializes out. */
struct json_value;
bool fast_sync_dump_state_json(struct json_value *out, const char *key);

/* ── BitTorrent-style parallel chunk sync ────────────────── */

/* Manifest: describes the UTXO snapshot as a set of verified chunks.
 * Each chunk contains chunk_size UTXOs (last chunk may have fewer).
 * A Merkle tree of chunk hashes enables independent verification. */
struct sync_manifest {
    int32_t  height;
    uint32_t protocol_version;
    uint32_t snapshot_schema_version;
    int32_t  peer_tip_height;
    uint8_t  block_hash[32];
    uint8_t  anchor_block_hash[32];
    uint8_t  chain_work[32];
    uint8_t  utxo_sha3[32];
    uint64_t total_bytes;
    uint64_t num_utxos;
    uint32_t num_chunks;
    uint32_t chunk_size;      /* UTXOs per chunk (default 500) */
    uint8_t  merkle_root[32]; /* root of chunk hash Merkle tree */
    uint8_t  (*chunk_hashes)[32]; /* array of num_chunks hashes (heap) */
};

/* Build manifest from current UTXO set.
 * Allocates chunk_hashes array; caller must call sync_manifest_free(). */
bool fast_sync_build_manifest(const char *datadir,
                               struct sync_manifest *out);

/* Build manifest from an open database handle. */
bool fast_sync_build_manifest_db(struct sqlite3 *db,
                                  struct sync_manifest *out);

/* Free heap memory inside a manifest. */
void sync_manifest_free(struct sync_manifest *m);

/* Compute SHA-256 hash of a single chunk's contents. */
void fast_sync_chunk_hash(const struct utxo_chunk *chunk,
                           uint8_t hash_out[32]);

/* Upper bound on the serialized length of one chunk (see
 * fast_sync_serialize_chunk_for_hash). */
#define FAST_SYNC_CHUNK_SER_MAX (8u + 1000u * (32u + 4u + 8u + 520u + 2u + 4u + 1u))

/* Serialize a chunk into the EXACT byte stream fast_sync_chunk_hash() feeds to
 * SHA3-256, so sha3_256(buf, ret) == fast_sync_chunk_hash(chunk). The manifest
 * builder batches four independent chunk hashes through sha3_256_x4 on top of
 * this. `buf` must hold FAST_SYNC_CHUNK_SER_MAX bytes; returns bytes written.
 * Exposed (not internal-static) so the `fast_sync` chunk_serialize test can
 * assert byte-identity against the streaming reference. */
size_t fast_sync_serialize_chunk_for_hash(const struct utxo_chunk *chunk,
                                          uint8_t *buf);

/* Verify a chunk against its expected hash. */
bool fast_sync_verify_chunk(const struct utxo_chunk *chunk,
                             const uint8_t expected_hash[32]);

/* Serve a specific chunk by index only from the already-published immutable
 * snapshot cache. `datadir` is retained for API compatibility and is not
 * opened: a live node.db read could diverge from the published manifest. */
bool fast_sync_serve_chunk(const char *datadir, uint32_t chunk_index,
                            struct utxo_chunk *out);

/* Explicit legacy/test helper for an open node.db `utxos` mirror. Production
 * request serving must use fast_sync_serve_chunk() and may not fall back here. */
bool fast_sync_serve_chunk_db(struct sqlite3 *db, uint32_t chunk_index,
                               uint32_t chunk_size,
                               struct utxo_chunk *out);

/* Compute Merkle root from an array of leaf hashes.
 * Returns root in root_out. Handles power-of-two padding. */
void fast_sync_merkle_root(const uint8_t (*hashes)[32],
                            uint32_t count,
                            uint8_t root_out[32]);

/* Verify a chunk against the Merkle root using a proof path. */
bool fast_sync_verify_chunk_proof(uint32_t chunk_index,
                                   const uint8_t chunk_hash[32],
                                   const uint8_t (*proof)[32],
                                   uint32_t proof_len,
                                   const uint8_t merkle_root[32]);

/* Build a Merkle proof for a given chunk index. Allocates proof array.
 * Caller must free(*proof_out). Returns proof length. */
uint32_t fast_sync_build_proof(const uint8_t (*hashes)[32],
                                uint32_t count,
                                uint32_t chunk_index,
                                uint8_t (**proof_out)[32]);

/* ── Swarm coordinator: BitTorrent-style parallel UTXO sync ── */

/* Chunk download state */
enum chunk_state {
    CHUNK_NEEDED   = 0,  /* Not yet requested */
    CHUNK_INFLIGHT = 1,  /* Requested from a peer */
    CHUNK_COMPLETE = 2,  /* Received and verified */
    CHUNK_FAILED   = 3   /* Verification failed, needs re-request */
};

/* Swarm sync state — coordinates parallel download from multiple peers */
struct swarm_sync {
    struct sync_manifest manifest;
    enum chunk_state *chunk_states;    /* array[num_chunks] */
    int *chunk_peer;                   /* which peer has each inflight chunk */
    int64_t *chunk_request_time;       /* when each chunk was requested (ms) */
    int *chunk_retries;                /* retry count per chunk (max 5) */
    uint32_t chunks_complete;
    uint32_t chunks_inflight;
    uint32_t chunks_failed;
    const char *datadir;               /* for applying chunks */
};

/* Initialize swarm sync from a manifest */
bool swarm_sync_init(struct swarm_sync *ss, const struct sync_manifest *manifest,
                      const char *datadir);

/* Free swarm state */
void swarm_sync_free(struct swarm_sync *ss);

/* Assign next needed chunk to a peer. Returns chunk index or -1 if none. */
int32_t swarm_sync_assign_chunk(struct swarm_sync *ss, int peer_id);

/* Mark a chunk as received and verified. Returns false if bad hash. */
bool swarm_sync_receive_chunk(struct swarm_sync *ss,
                                const struct utxo_chunk *chunk,
                                int peer_id);

/* Check if sync is complete (all chunks verified) */
bool swarm_sync_is_complete(const struct swarm_sync *ss);

/* Get progress as percentage (0-100) */
int swarm_sync_progress(const struct swarm_sync *ss);

/* Handle timeout: re-assign inflight chunks older than timeout_ms */
void swarm_sync_handle_timeouts(struct swarm_sync *ss, int timeout_secs);

/* ── Block swarm: BitTorrent-style parallel block download ──── */
/* Groups blocks into independently hashable/verifiable pieces. Each piece is
 * independently hashable and verifiable. Legacy peers contribute
 * via normal getdata/block; ZCL23 peers use the swarm protocol.
 *
 * Wire messages (all ≤12 chars, ignored by legacy peers):
 *   zblkmanfst  — block piece manifest (height range, piece count, merkle root)
 *   zblkreq     — request piece by index
 *   zblkdata    — piece response (serialized blocks)
 *   zblkbitmap  — piece availability bitmap
 */

#define MSG_BLOCK_MANIFEST  "zblkmanfst"
#define MSG_BLOCK_REQ       "zblkreq"
#define MSG_BLOCK_DATA      "zblkdata"
#define MSG_BLOCK_BITMAP    "zblkbitmap"

/* Keep a realistic post-snapshot piece below the 2 MiB P2P message cap. The
 * prior 512-block shape exceeded that cap on the copied production tail, so
 * the sender emitted hashes without bodies and the swarm could never complete.
 * The sender still enforces MAX_PROTOCOL_MESSAGE_LENGTH for every response. */
#define BLOCKS_PER_PIECE 64

/* Max inflight block pieces per peer. Each piece is independently hashed
 * against the manifest before payload blocks are submitted, so this only
 * controls bandwidth-delay utilization, not trust. */
/* One peer may keep 256 independently hash-bound 64-block pieces in flight.
 * The global contiguous window and loopback proof derive from this constant.
 * 64 under-filled the bandwidth-delay product even on loopback (~10 s piece
 * turnaround at ~6 pieces/s pinned the inflight count and capped fold at
 * ~300 blocks/s vs ~2000 blocks/s raw serve capacity); 256 restores
 * throughput without changing trust (each piece is hash-bound on arrival). */
#define PIECE_PIPELINE_DEPTH 256

/* Endgame threshold: when fewer than this many pieces remain,
 * request all remaining from every available peer. */
#define ENDGAME_THRESHOLD 8

/* Block piece manifest: describes a range of blocks as verified pieces. */
struct block_piece_manifest {
    int32_t  start_height;       /* first block height in manifest */
    int32_t  end_height;         /* last block height (inclusive) */
    uint32_t num_pieces;         /* ceil((end - start + 1) / BLOCKS_PER_PIECE) */
    uint8_t  tip_hash[32];      /* block hash at end_height */
    uint8_t  merkle_root[32];   /* Merkle root of piece hashes */
    uint8_t  (*piece_hashes)[32]; /* array[num_pieces] (heap-allocated) */
};

/* Piece state (reuses chunk_state enum) */

/* Per-peer block swarm pipeline slot */
struct piece_slot {
    int32_t piece_index;         /* -1 = empty */
    int64_t request_time;        /* when requested */
};

/* Block swarm coordinator — manages parallel block download from
 * multiple peers. Thread-safe access via external mutex. */
struct block_swarm {
    struct block_piece_manifest manifest;
    enum chunk_state *piece_states;     /* array[num_pieces] */
    int *piece_peer;                    /* which peer has each piece */
    int64_t *piece_request_time;        /* when each piece was requested */
    uint32_t *piece_availability;       /* how many peers have each piece */
    uint32_t pieces_complete;
    uint32_t pieces_inflight;
    uint32_t pieces_failed;
    int64_t  last_complete_unix;        /* last piece-completion stamp; the
                                         * stall watchdog (msgprocessor_snapshot.c)
                                         * abandons the swarm when this goes quiet */
    bool endgame;                       /* true when < ENDGAME_THRESHOLD remain */
    const char *datadir;
};

/* Initialize block swarm from a manifest */
bool block_swarm_init(struct block_swarm *bs,
                      const struct block_piece_manifest *manifest,
                      const char *datadir);

/* Free block swarm state */
void block_swarm_free(struct block_swarm *bs);

/* Assign next piece to a peer using rarest-first selection.
 * Returns piece index or -1 if none available.
 * peer_bitmap/peer_bitmap_bytes: which pieces this peer has
 * (NULL = assume all; bits at or past the span read as absent). */
int32_t block_swarm_assign_piece(struct block_swarm *bs, int peer_id,
                                  const uint8_t *peer_bitmap,
                                  size_t peer_bitmap_bytes);

/* Same selection, but only assigns pieces whose ending block height is at or
 * below max_height. Use this when body transfer must not outrun local header
 * admission. Bitmap bounds follow block_swarm_assign_piece. */
int32_t block_swarm_assign_piece_through_height(struct block_swarm *bs,
                                                 int peer_id,
                                                 const uint8_t *peer_bitmap,
                                                 size_t peer_bitmap_bytes,
                                                 int32_t max_height);

/* Mark a piece as received. Caller must verify hash before calling.
 * Returns true on success. */
bool block_swarm_receive_piece(struct block_swarm *bs,
                                uint32_t piece_index, int peer_id);

/* Mark a piece as failed (bad hash). Will be re-requested. */
void block_swarm_fail_piece(struct block_swarm *bs, uint32_t piece_index);

/* Check if block swarm is complete */
bool block_swarm_is_complete(const struct block_swarm *bs);

/* Get progress as percentage (0-100) */
int block_swarm_progress(const struct block_swarm *bs);

/* Handle timeouts: re-queue pieces older than timeout_secs */
void block_swarm_handle_timeouts(struct block_swarm *bs, int timeout_secs);

/* Update piece availability from peer's bitmap.
 * bitmap: bit array, bit i set = peer has piece i. */
void block_swarm_update_availability(struct block_swarm *bs,
                                      const uint8_t *bitmap,
                                      uint32_t bitmap_len);

/* Check if in endgame mode and return list of needed pieces.
 * Returns count of pieces written to out_indices (up to max). */
uint32_t block_swarm_endgame_pieces(const struct block_swarm *bs,
                                     uint32_t *out_indices, uint32_t max);

struct active_chain;

/* Build a block piece manifest from the trusted active chain.
 * Skips leading heights without BLOCK_HAVE_DATA, then requires every
 * remaining height through end_height to be present and marked.
 * Allocates piece_hashes; caller must call block_piece_manifest_free(). */
bool block_piece_manifest_build_active_chain(
                                 const struct active_chain *chain,
                                 int32_t start_height, int32_t end_height,
                                 struct block_piece_manifest *out);

/* Decide whether a cached block manifest must be rebuilt at tip. Besides the
 * normal end-height cadence, this detects a sparse-tail cache whose immediate
 * predecessor has since gained trusted body data. Without that second edge, a
 * node that published only its two newest bodies before checkpoint-delta
 * catch-up could remain "fresh" forever and hide the newly serveable range. */
bool block_piece_manifest_should_refresh(
                                 const struct active_chain *chain,
                                 bool has_cached,
                                 const struct block_piece_manifest *cached,
                                 int32_t built_at_height,
                                 int32_t tip_height,
                                 int32_t refresh_interval);

/* Build a block piece manifest from SQLite block metadata.
 * Legacy fallback for tests or boot paths that do not have an active chain.
 * Allocates piece_hashes; caller must call block_piece_manifest_free(). */
bool block_piece_manifest_build(const char *datadir,
                                 int32_t start_height, int32_t end_height,
                                 struct block_piece_manifest *out);

/* Free heap memory inside a block piece manifest. */
void block_piece_manifest_free(struct block_piece_manifest *m);

/* Compute SHA3-256 hash of a piece (128 block headers concatenated).
 * block_hashes: array of 32-byte block hashes for this piece.
 * count: number of blocks in this piece (≤ BLOCKS_PER_PIECE). */
void block_piece_hash(const uint8_t (*block_hashes)[32], uint32_t count,
                       uint32_t piece_index, uint8_t hash_out[32]);

/* Serialize a piece availability bitmap.
 * Returns bytes written to out (ceil(num_pieces/8)). */
uint32_t block_swarm_serialize_bitmap(const struct block_swarm *bs,
                                       uint8_t *out, uint32_t max_len);

#endif
