/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Serve zclassicd v2.1.2-beta6 fast-bootstrap snapshots wire-compatibly.
 *
 * A stock beta6 client dials its compiled bootstrap peers on the ordinary P2P
 * port, requires the peer's `version` to carry NODE_BOOTSTRAP (1<<24), then
 * drives eight messages over that socket: getbsman/bsman + getbschk/bschk for
 * the chain snapshot and getbspman/bspman + getbspchk/bspchk for the Zcash
 * zk-SNARK parameter files. Without a server it logs
 * "bootstrap peer does not advertise NODE_BOOTSTRAP" and falls back to a
 * multi-day P2P sync.
 *
 * This module is the SERVER half, ported from the beta6 C++ tree
 * (src/bootstrap.cpp, src/protocol.h). It is dormant unless
 * -beta6-bootstrap-source=<dir> (env ZCL_BETA6_BOOTSTRAP_SOURCE) names a
 * directory that passes the same preflight the C++ server applies. The source
 * tree is opened O_RDONLY only; nothing here ever writes into it.
 *
 * Wire format is Bitcoin/Zcash CDataStream: little-endian fixed ints,
 * CompactSize length prefixes, uint256 as 32 raw internal-order bytes,
 * std::string as CompactSize + bytes.
 */
#ifndef ZCLASSIC23_SERVICES_BETA6_BOOTSTRAP_H
#define ZCLASSIC23_SERVICES_BETA6_BOOTSTRAP_H

#include "core/serialize.h"
#include "core/uint256.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* bootstrap.h:26 — the server always advertises this as the manifest's
 * nChunkSize and the client sizes every request from it. */
#define BETA6_BS_CHUNK_SIZE ((uint32_t)(1024u * 1024u))
/* protocol.h:173-174 — read-side caps on the two attacker-controlled strings. */
#define BETA6_BS_MAX_PATH_LEN 256u
#define BETA6_BS_MAX_NETWORK_LEN 32u
/* Bound on the served file set. The real snapshot is ~1.2k files (103 blk +
 * 103 rev + a LevelDB index + chainstate); 32k leaves two decimal orders of
 * headroom while keeping the manifest well inside MAX_PROTOCOL_MESSAGE_LENGTH. */
#define BETA6_BS_MAX_FILES 32768u
/* net.h:52 — the whole bsman/bschk message must fit under this. */
#define BETA6_BS_MAX_MESSAGE_LEN (2u * 1024u * 1024u)

/* bootstrap.h:43-44 — per-IP serve quota defaults. */
#define BETA6_BS_DEFAULT_MAX_BYTES_PER_DAY (100LL * 1024 * 1024 * 1024)
#define BETA6_BS_DEFAULT_THROTTLE_KBPS (1024LL)
#define BETA6_BS_QUOTA_WINDOW_MS (24LL * 60 * 60 * 1000)
/* bootstrap.cpp:4697 — hard bound on tracked quota buckets. */
#define BETA6_BS_QUOTA_MAX_TRACKED 16384u

/* One advertised file. `path` is a forward-slash relative path under the
 * serve root ("chainstate/000005.ldb", "blocks/blk00000.dat"), or a bare
 * parameter file name in a param manifest. */
struct beta6_bs_file {
    char path[BETA6_BS_MAX_PATH_LEN];
    uint64_t size;
    struct uint256 sha256;
    /* Handle-bound mtime captured when the manifest was built. A chunk read
     * refuses when the file's size or mtime moved since (bootstrap.cpp:4362-
     * 4372). Not serialized. */
    int64_t mtime_seconds;
};

/* CBootstrapSnapshotManifest (protocol.h:205-289). v1 is the compiled-anchor
 * snapshot, v2 appends hashChainstateSerialized, v3 additionally appends the
 * growable block-bundle tip. Append-only: never reorder. */
struct beta6_bs_manifest {
    int32_t version;
    char network[BETA6_BS_MAX_NETWORK_LEN];
    int32_t height;
    struct uint256 hash_block;
    struct uint256 hash_anchor_sha256;
    struct uint256 hash_anchor_sha3;
    uint64_t snapshot_bytes;
    uint32_t chunk_size;
    struct beta6_bs_file *files; /* owned; freed by beta6_bs_manifest_free */
    size_t file_count;
    struct uint256 hash_chainstate; /* v2+ */
    int32_t block_tip_height;       /* v3 */
    struct uint256 hash_block_tip;  /* v3 */
};

/* CBootstrapSnapshotChunkRequest (protocol.h:292-318). */
struct beta6_bs_chunk_request {
    uint32_t file_index;
    uint64_t offset;
    uint32_t length;
};

/* One compiled beta6 fast-sync anchor (chainparams.cpp:205-219). A served
 * ".anchor" sidecar is only honored when it names one of these. */
struct beta6_bs_anchor {
    int32_t height;
    struct uint256 hash_block;
    struct uint256 hash_anchor_sha256;
    struct uint256 hash_anchor_sha3;
    struct uint256 hash_chainstate;
};

/* ── Compiled anchors + sidecars ─────────────────────────────────────── */

/* The compiled beta6 anchor set, newest first. Count in *count. */
const struct beta6_bs_anchor *beta6_bs_anchors(size_t *count);
/* The anchor matching (height, hash_block), or NULL. */
const struct beta6_bs_anchor *beta6_bs_find_anchor(int32_t height,
                                                   const struct uint256 *hash_block);

/* Parse a "<height> <blockhash>" sidecar (".anchor" / ".blocktip"). Returns
 * false when the file is absent or malformed. */
bool beta6_bs_read_height_hash_sidecar(const char *sidecar_path, int32_t *height,
                                       struct uint256 *hash_block);
/* Parse a "<height> <blockhash> <chainstate-commitment>" v2 ".meta" sidecar. */
bool beta6_bs_read_meta_sidecar(const char *sidecar_path, int32_t *height,
                                struct uint256 *hash_block,
                                struct uint256 *hash_chainstate);
/* Build "<source_dir><suffix>" — the sidecars are siblings of the serve dir,
 * never inside it, so the manifest scan never picks them up
 * (bootstrap.cpp:1960-1965). False when the result would not fit. */
bool beta6_bs_sidecar_path(const char *source_dir, const char *suffix, char *out,
                           size_t out_size);

/* BootstrapSnapshotPathsExist (bootstrap.cpp:770-774): blocks/, blocks/index/
 * and chainstate/ must all be directories under `source_dir`. */
bool beta6_bs_source_paths_exist(const char *source_dir);
/* IsBootstrapSnapshotDataPath (bootstrap.cpp:3389-3397): a non-empty relative
 * path with no "." / ".." component whose first component is blocks or
 * chainstate. */
bool beta6_bs_is_data_path(const char *relative_path);

/* ── Manifest ────────────────────────────────────────────────────────── */

void beta6_bs_manifest_init(struct beta6_bs_manifest *manifest);
void beta6_bs_manifest_free(struct beta6_bs_manifest *manifest);

/* Scan `source_dir`, SHA-256 every regular file, and order the result the way
 * the C++ server does: every chainstate/ entry first, then blocks/, each group
 * lexicographic (bootstrap.cpp:3498-3508). Fills `files`/`file_count`/
 * `snapshot_bytes` only. Expensive (hashes the whole snapshot); never call it
 * from a request path. */
bool beta6_bs_collect_files(const char *source_dir, struct beta6_bs_manifest *manifest,
                            char *err, size_t err_size);

/* ── Serve state ─────────────────────────────────────────────────────── */

/* Arm the service against `source_dir` for `network` ("main"/"test"/
 * "regtest"). Runs the C++ preflight (paths exist, a compiled anchor or a v2
 * .meta describes the copy), builds the manifest once and caches it.
 * Idempotent for a repeated identical source. Returns false with a named
 * reason in `err` and leaves the service disarmed. */
bool beta6_bs_arm(const char *source_dir, const char *network, char *err,
                  size_t err_size);
void beta6_bs_disarm(void);
bool beta6_bs_is_armed(void);
/* The armed source directory, or "" when disarmed. */
const char *beta6_bs_source_dir(void);
/* The cached manifest, or NULL when disarmed. Immutable while armed. */
const struct beta6_bs_manifest *beta6_bs_manifest(void);

/* ── Chunk reads ─────────────────────────────────────────────────────── */

/* ValidateBootstrapChunkRange (bootstrap.cpp:4285-4309): the range must lie
 * inside the file, the offset must be chunk-aligned, and the length must be
 * exactly min(chunk_size, file_size - offset). */
bool beta6_bs_validate_chunk_range(uint64_t offset, uint64_t length, uint64_t file_size,
                                   uint64_t chunk_size, const char *label, char *err,
                                   size_t err_size);

/* Read one bounded chunk of the armed snapshot into `out` (capacity
 * `out_capacity` >= request->length). Refuses an unknown file index, an
 * unsafe manifest path, a size/mtime that moved since the manifest was built,
 * and any range the validator rejects. Never reads a whole file. */
bool beta6_bs_read_chunk(const struct beta6_bs_chunk_request *request, unsigned char *out,
                         size_t out_capacity, char *err, size_t err_size);

/* The bounded read both serve paths share: validate the range, open the file
 * beneath `root` without following a link, prove its size and mtime still
 * match `file`, then one positioned read of exactly request->length bytes.
 * `label` names the service in a refusal ("bootstrap" / "zcash param"). */
bool beta6_bs_read_file_chunk(const char *root, const struct beta6_bs_file *file,
                              const struct beta6_bs_chunk_request *request,
                              const char *label, unsigned char *out, size_t out_capacity,
                              char *err, size_t err_size);

/* ── Zcash parameter files ───────────────────────────────────────────── */

/* Build the manifest of zk-SNARK parameter files held in `params_dir` whose
 * size matches the compiled spec (bootstrap.cpp:3923-3961). v1 shape: no
 * height, no anchor hashes. */
bool beta6_bs_param_manifest(const char *params_dir, const char *network,
                             struct beta6_bs_manifest *manifest, char *err,
                             size_t err_size);
/* Read one bounded chunk of a served parameter file. */
bool beta6_bs_read_param_chunk(const char *params_dir, const char *network,
                               const struct beta6_bs_chunk_request *request,
                               unsigned char *out, size_t out_capacity, char *err,
                               size_t err_size);

/* ── Wire codec ──────────────────────────────────────────────────────── */

bool beta6_bs_manifest_encode(const struct beta6_bs_manifest *manifest,
                              struct byte_stream *out);
/* Decode a manifest. Allocates `files`; free with beta6_bs_manifest_free. */
bool beta6_bs_manifest_decode(struct byte_stream *in, struct beta6_bs_manifest *out);
bool beta6_bs_chunk_request_encode(const struct beta6_bs_chunk_request *request,
                                   struct byte_stream *out);
bool beta6_bs_chunk_request_decode(struct byte_stream *in,
                                   struct beta6_bs_chunk_request *out);
bool beta6_bs_chunk_encode(uint32_t file_index, uint64_t offset, const unsigned char *data,
                           size_t data_len, struct byte_stream *out);

/* ── Per-IP serve quota (bootstrap.cpp:4707-4790) ────────────────────── */

/* Collapse a printable address to its quota bucket: IPv4 to "v4/24:a.b.c",
 * IPv6 to "v6/64:<16 hex>", anything else to the address itself. */
bool beta6_bs_quota_key(const char *ip, char *out, size_t out_size);
/* True when a chunk may be served to `key` now. When the bucket is over its
 * daily cap and throttling is off, returns false with *stop set. */
bool beta6_bs_quota_allow(const char *key, bool whitelisted, int64_t now_ms, bool *stop);
void beta6_bs_quota_charge(const char *key, bool whitelisted, int64_t now_ms,
                           uint64_t bytes);
void beta6_bs_quota_clear(void);
/* Override the compiled cap/throttle (operator config; tests). A cap <= 0
 * disables the quota; a throttle <= 0 turns the over-cap case into a hard
 * stop. */
void beta6_bs_quota_configure(int64_t max_bytes_per_day, int64_t throttle_kbps);

/* ── In-band P2P serving (the production path) ───────────────────────── */

/* A beta6 client only fast-syncs from a peer it reaches on the ORDINARY P2P
 * port, which on any real deployment is z23's own peer-to-peer socket. These
 * three functions are the engine half of the core/modules/net seam declared in
 * net/msgprocessor.h; the boot glue installs them once the snapshot is armed.
 * Until then nothing is installed, NODE_BOOTSTRAP stays out of the services
 * word, and the eight commands are ignored. */
struct msg_processor;
struct p2p_node;

/* Cache the manifest wire bytes and remember which network and zk-SNARK
 * parameter directory this node serves. Requires an already-armed snapshot;
 * returns false with a named reason otherwise. */
bool beta6_bs_inband_arm(const char *network, const char *params_dir, char *err,
                         size_t err_size);
void beta6_bs_inband_disarm(void);
/* True when this node will both advertise NODE_BOOTSTRAP and answer the eight
 * messages on an ordinary peer connection. */
bool beta6_bs_inband_armed(void);
/* Answer one beta6 message from `node`. Refusals are by name through a beta6
 * `reject`; the four reply commands are dropped. Never blocks: this runs on
 * the shared message thread. */
bool beta6_bs_inband_serve(struct msg_processor *mp, struct p2p_node *node,
                           const char *command, const unsigned char *payload,
                           size_t payload_len);

/* ── Listener (optional; superseded by the in-band path above) ────────── */

/* Start the beta6 bootstrap listener on `bind_ip`:`port`, framing messages
 * with the active network's 4-byte `magic` and serving the already-armed
 * snapshot plus the zk-SNARK parameters in `params_dir`. Returns false with a
 * named reason when the service is not armed or the socket cannot be bound. */
bool beta6_bs_listen_start(const char *bind_ip, uint16_t port, const unsigned char magic[4],
                           const char *network, const char *params_dir, char *err,
                           size_t err_size);
void beta6_bs_listen_stop(void);
bool beta6_bs_listen_running(void);
/* The port actually bound, or 0. */
uint16_t beta6_bs_listen_port(void);

#endif /* ZCLASSIC23_SERVICES_BETA6_BOOTSTRAP_H */
