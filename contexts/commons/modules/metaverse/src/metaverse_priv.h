/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal helpers shared by the metaverse property adapters. Not a public
 * surface: nothing outside contexts/commons/modules/metaverse/src includes this.
 *
 * Everything here is READ-ONLY over the frozen <datadir>/zcode layout that
 * vcs/package_store.h documents. It opens no store, because opening one
 * runs the mutating recovery sweep — see the "READ MEANS READ" note in
 * metaverse/property_adapter.h. */

#ifndef ZCL_METAVERSE_PRIV_H
#define ZCL_METAVERSE_PRIV_H

#include "vcs/package_manifest.h"
#include "vcs/package_store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bounded scan of <zcode_dir>/manifests. The store's own tracked bound is
 * VCS_PACKAGE_STORE_MAX_TRACKED (4096); a projection page never needs that
 * many, and an unbounded readdir over an operator directory is a cost the
 * caller cannot see. Truncation is always reported, never silent. */
#define MV_MANIFEST_SCAN_MAX 512u

/* A single SHOW may verify one store-admissible package.  LIST shares the
 * same byte budget across its whole page and also caps filesystem operations,
 * so a directory containing thousands of tiny chunks cannot turn a read
 * command into an unbounded scrub. */
#define MV_PROPERTY_VERIFY_BYTES VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES
#define MV_PROPERTY_SHOW_VERIFY_OPS (2u * VCS_PACKAGE_MAX_TOTAL_CHUNKS)
#define MV_PROPERTY_LIST_VERIFY_OPS 4096u

/* One manifest read back from the store, with the facts a view needs. */
struct mv_manifest_read {
    uint8_t root[32];          /* root RE-DERIVED from the parsed wire */
    bool root_matches_name;    /* re-derived root == the filename */
    struct vcs_package_manifest manifest; /* owned; mv_manifest_free() it */
    uint32_t chunk_total;      /* chunks committed by the manifest */
    uint32_t chunks_present;   /* of those, present in the CAS */
    bool manifest_root_verified;
    uint32_t chunks_verified;
    uint64_t bytes_verified;
    bool verification_complete;
    char verification_gap[96];
    uint64_t total_bytes;
    uint32_t file_count;
};

/* A missing object is an inventory fact. An unreadable or malformed object
 * is an integrity failure. Keep those states distinct all the way to the
 * operator surface. */
enum mv_manifest_read_status {
    MV_MANIFEST_READ_OK = 0,
    MV_MANIFEST_READ_ABSENT,
    MV_MANIFEST_READ_IO_ERROR,
    MV_MANIFEST_READ_INVALID,
};

/* Read + parse <zcode_dir>/manifests/<root_hex> and re-derive its root.
 * ABSENT is reserved for ENOENT. IO_ERROR and INVALID must never be projected
 * as absence. On OK the caller MUST call mv_manifest_free(out); on every
 * other result *out is zeroed and needs no free.
 *
 * This only reads the manifest. Call mv_manifest_verify_possession() before
 * projecting possession or availability. */
enum mv_manifest_read_status mv_manifest_read(
    const char *zcode_dir, const char *root_hex, struct mv_manifest_read *out);
const char *mv_manifest_read_status_name(enum mv_manifest_read_status status);
void mv_manifest_free(struct mv_manifest_read *m);

/* Read-only, bounded proof over the manifest's committed CAS coordinates.
 * Every chunk is opened O_NOFOLLOW, required to be a regular file of the
 * exact coordinate length, SHA3-verified, then fingerprinted and re-statted
 * after the last hash to detect replacement/mutation during the proof.
 * Budgets are consumed across calls by the caller; this function never
 * creates or repairs store state. */
void mv_manifest_verify_possession(const char *zcode_dir,
                                   struct mv_manifest_read *manifest,
                                   uint64_t byte_budget,
                                   uint32_t operation_budget,
                                   uint64_t *bytes_used,
                                   uint32_t *operations_used);
#ifdef ZCL_TESTING
typedef void (*mv_manifest_verify_test_hook)(void *context,
                                             uint32_t chunks_verified);
void mv_manifest_verify_possession_test(
    const char *zcode_dir, struct mv_manifest_read *manifest,
    uint64_t byte_budget, uint32_t operation_budget,
    mv_manifest_verify_test_hook hook, void *hook_context,
    uint64_t *bytes_used, uint32_t *operations_used);
#endif

/* True when the manifest has the frozen blob shape: exactly one file at
 * VCS_BLOB_PATH, one chunk, regular-file mode, size within the blob cap. */
bool mv_manifest_is_blob(const struct vcs_package_manifest *m);

/* Enumerate the 64-hex filenames under <zcode_dir>/manifests in ascending
 * name order (deterministic output regardless of readdir order). Writes up
 * to out_cap names of 65 bytes each; returns the count written.
 * *total_out receives the number of hex64 entries SEEN (capped at
 * MV_MANIFEST_SCAN_MAX) and *truncated_out is set when the scan itself hit
 * that cap or when more entries were seen than written. */
bool mv_manifest_names(const char *zcode_dir, char (*out)[65],
                       size_t out_cap, size_t *written_out,
                       size_t *total_out, bool *truncated_out);

/* Can <zcode_dir>/manifests be ENUMERATED right now?
 *
 * True also when the directory does not exist: a datadir that has never
 * published anything is honestly empty, and that is a fact, not a fault.
 * False ONLY when something is there and cannot be read — a plain file
 * where the directory belongs, a permission wall, an I/O error — and
 * `reason` (when non-NULL) then carries what the OS said.
 *
 * This distinction is the whole point. mv_manifest_names() cannot make it:
 * it returns 0 either way, so "the store is unreadable" and "the node owns
 * nothing" would reach the operator as the same empty catalog. That
 * conflation is the defect class this project has already paid for on
 * node.db, and tests/harness/src/test_read_leaf_no_datadir_write.c exists to
 * keep it from recurring. Callers ask this FIRST and disclose a false. */
bool mv_store_enumerable(const char *zcode_dir, char *reason, size_t cap);

/* The same question in adapter-hook shape, so a row can wire it directly
 * as metaverse_adapter.store_ready. */
struct metaverse_adapter_ctx;
bool mv_zcode_store_ready(const struct metaverse_adapter_ctx *ctx,
                          char *reason, size_t reason_cap);

/* Read + parse <zcode_dir>/releases/<release_id_hex> and VERIFY its
 * signature (vcs_package_release_verify) during this call. False when the
 * file is absent/unparseable or the signature does not verify — the caller
 * must then not claim the local_signature evidence grade. */
struct vcs_package_release;
bool mv_release_read_verified(const char *zcode_dir,
                             const char *release_id_hex,
                             struct vcs_package_release *out);

/* The adapter rows, one accessor per implementing translation unit. Only
 * adapter_registry.c calls these; the registry is the single dispatch
 * point every consumer goes through. */
struct metaverse_adapter;
const struct metaverse_adapter *metaverse_adapter_content(void);
const struct metaverse_adapter *metaverse_adapter_zcode_package(void);
const struct metaverse_adapter *metaverse_adapter_znam(void);
const struct metaverse_adapter *metaverse_adapter_zslp(void);

#endif /* ZCL_METAVERSE_PRIV_H */
