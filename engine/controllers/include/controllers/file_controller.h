/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * File Transfer Controller — X25519/HKDF session with SHA3-verified files.
 *
 * Splits blockchain state (block files, UTXO snapshots) into ~50MB chunks.
 * Each chunk is SHA3-256 hashed. The manifest (ordered list of chunk hashes)
 * SHA3-hashes to a root that can be verified against on-chain data.
 *
 * REST API:
 *   GET /api/files/manifest     → JSON manifest (chunk hashes, sizes)
 *   GET /api/files/:sha3hash    → raw chunk bytes
 *
 * RPC:
 *   getfilemanifest             → JSON manifest
 *   getfilechunk "sha3hash"     → hex-encoded chunk (or error)
 *
 * P2P messages (encrypted with SHA3 stream cipher):
 *   zfilelist   → manifest exchange on ZCL23 handshake
 *   zfilereq    → request chunk by SHA3 hash
 *   zfiledata   → chunk data response */

#ifndef ZCL_FILE_CONTROLLER_H
#define ZCL_FILE_CONTROLLER_H

#include "net/file_manifest.h"
#include "rpc/server.h"
#include <stdint.h>
#include <stdbool.h>

struct file_manifest_status {
    bool     datadir_configured;
    bool     manifest_valid;
    bool     snapshot_present;
    bool     snapshot_served;
    bool     block_index_present;
    bool     block_index_served;
    uint32_t num_chunks;
    uint64_t total_bytes;
};

/* Register RPC commands. */
void register_file_rpc_commands(struct rpc_table *t);

/* Set state for the file controller. */
void file_controller_init(const char *datadir);

/* Copy the cached manifest (built in background) into out. */
bool file_controller_get_manifest_copy(struct file_manifest *out);

/* Explicitly rebuild the cached manifest from the current datadir. */
bool file_controller_refresh_manifest(void);

/* Build a complete manifest from an operator-guaranteed immutable private copy.
 * block_files is the exact contiguous count (1..253); no snapshot is included.
 * Caller guarantees the entire source tree, including parent paths, stays immutable.
 * This operation is unsupported on Windows and returns false there.
 * On failure out is unchanged. This grants no publication or chain authority. */
bool file_controller_build_immutable_manifest(struct file_manifest *out,
                                               const char *datadir,
                                               unsigned block_files);

/* Get the current manifest/export readiness summary. */
void file_controller_get_manifest_status(struct file_manifest_status *out);

#endif
