/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Full-history consensus-state bundle exporter. */

#ifndef ZCL_CONSENSUS_STATE_SNAPSHOT_EXPORT_H
#define ZCL_CONSENSUS_STATE_SNAPSHOT_EXPORT_H

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;

enum consensus_state_export_status {
    CONSENSUS_EXPORT_REFUSED = 0,
    CONSENSUS_EXPORT_MISSING_PROOF = 1,
    CONSENSUS_EXPORT_STORE_ERROR = 2,
    CONSENSUS_EXPORT_OUTPUT_ERROR = 3,
    CONSENSUS_EXPORT_EXPORTED = 4,
};

struct consensus_state_snapshot_export_request {
    /* Borrowed directory descriptor plus one-component final name. The
     * exporter duplicates the descriptor, builds through an anonymous
     * O_TMPFILE and an fd-only SQLite VFS, then atomically links that exact
     * validated inode into the pinned directory. The caller retains ownership
     * of output_dir_fd. Existing names, symlinks, slash-containing names, dot,
     * and dot-dot are refused. */
    int output_dir_fd;
    const char *output_name;
    /* Assertions against the frozen reducer view. They prevent a caller from
     * exporting the wrong quiesced generation, but are not chain authority. */
    int32_t expected_height;
    uint8_t expected_block_hash[32];
    /* Checkpoint-content export: admit the export by a cryptographic content
     * proof instead of the fold-binary-identity receipt gate. When true,
     * consensus_export_prove_source additionally REQUIRES the frozen coins set
     * to reproduce the compiled SHA3 UTXO checkpoint (sha3 + count) at
     * expected_height == checkpoint height, and the Sapling tip frontier to
     * Pedersen-root to checkpoint_sapling_root — the block header's committed
     * hashFinalSaplingRoot at expected_height, read by the caller from this
     * node's own validated header chain. That transparent-SHA3 + PoW-header
     * pair is a stronger, protocol-aligned content proof than "a specific
     * binary folded this": it relaxes ONLY the export-side requirement that the
     * receipt's running-binary digest equal the running binary (a fold-process
     * provenance claim no downstream gate re-checks), never any downstream
     * crypto gate. The emitted bundle is byte-identical in shape to a
     * fold-produced bundle and passes the same install/verify re-derivation.
     * Default false = unchanged fold-binary-bound export. */
    bool checkpoint_content_export;
    uint8_t checkpoint_sapling_root[32];
};

struct consensus_state_export_result {
    enum consensus_state_export_status status;
    bool history_complete;
    bool source_clean;
    uint8_t validation_profile;
    int32_t height;
    uint64_t utxo_count;
    uint64_t anchor_count;
    uint64_t nullifier_count;
    uint8_t artifact_digest[32];
    /* Wide enough for a refusal that names both compared 32-byte hex
     * digests plus a height (e.g. the checkpoint-content Sapling-root
     * mismatch) — a refusal message you cannot debug from is a defect. */
    char reason[384];
};

/* Export one zcl.consensus_state_bundle.v1 from an already-quiesced
 * progress.kv handle. This function additionally owns progress_store_tx_lock
 * and one read transaction while deriving and copying the source generation.
 *
 * Success is deliberately narrow: durable coins only, exact H-star/tip generation,
 * convention-correct stage cursors, explicit genesis anchor/nullifier coverage,
 * and complete successful reducer proof rows are all required. Missing proof
 * returns MISSING_PROOF and leaves
 * no final artifact. On success the file has been independently reopened and
 * validated, fsynced, chmod 0400, atomically linked without replacement, and
 * its directory
 * fsynced. It does not mutate or publish node state. */
bool consensus_state_snapshot_export(
    struct sqlite3 *progress_db,
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_state_export_result *result);

/* ── Live-node exporter (standing producer) ─────────────────────────────────
 *
 * Prove + export one zcl.consensus_state_bundle.v1 from a PRIVATE read-only WAL
 * snapshot of the owned progress.kv, so a SERVING node is never stalled for the
 * (potentially multi-second) proof + copy. Unlike consensus_state_snapshot_export
 * — which owns progress_store_tx_lock for the whole derive/copy and is meant for
 * the quiesced offline mint — this entry holds the process lock ONLY to pin the
 * WAL read snapshot (milliseconds: open a second read-only connection + BEGIN +
 * one probe read), then runs the identical proof/write/finalize pipeline against
 * that private consistent snapshot with NO lock held.
 *
 * On a live mutable store coins_kv is the UTXO set AT THE TIP, so a bundle can
 * only be exported at the snapshot's frozen H*: the caller MUST have already
 * monotonic-finalized the source receipt at the current durable tip and set
 * request->expected_height / expected_block_hash to that exact durable tip. If
 * the reducer advanced H* between the receipt finalize and the snapshot pin, the
 * proof fails closed (MISSING_PROOF) and the caller simply retries next cycle.
 *
 * The caller MUST also ensure the in-RAM coins overlay is inactive
 * (!coins_ram_active()) — the durable snapshot reflects durable coins only; the
 * proof independently refuses while the overlay is live. Same fail-closed
 * publication guarantees (independent reopen+validate, fsync, chmod 0400, atomic
 * no-replace link, dir fsync) as consensus_state_snapshot_export. */
bool consensus_state_snapshot_export_from_progress_snapshot(
    const struct consensus_state_snapshot_export_request *request,
    struct consensus_state_export_result *result);

#ifdef ZCL_TESTING
/* Deterministic adversarial hooks around directory binding and anonymous
 * staging-inode creation. */
void consensus_state_snapshot_export_test_set_after_output_bind_hook(
    void (*hook)(void *), void *ctx);
void consensus_state_snapshot_export_test_set_after_staging_create_hook(
    void (*hook)(void *, int staging_fd), void *ctx);
#endif

#endif /* ZCL_CONSENSUS_STATE_SNAPSHOT_EXPORT_H */
