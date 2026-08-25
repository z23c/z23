/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Producer-owned durable source receipt for the full-history
 * zcl.consensus_state_bundle.v1 exporter.
 *
 * The contained exporter (consensus_state_snapshot_export.c) refuses to
 * publish unless the frozen producer progress.kv carries a
 * consensus_state_source_receipt singleton that is bound to the ACTUAL running
 * executable (running_binary_digest == SHA3(/proc/self/exe)), the genesis->H*
 * header corpus (chain_corpus_digest), and the exact fold cursor (H*+1). This
 * module lets a -mint-anchor producer honestly earn that receipt:
 *
 *   begin()    - at producer start, before the fold. Records the running
 *                executable, start time, and the source-tree identity claim,
 *                and publishes the source-epoch digest into progress_meta so
 *                every fold stage stamps its rows with the same epoch (the
 *                binding the exporter's stage-row proof requires). Idempotent:
 *                a resume by the SAME running binary with the SAME claim is a
 *                no-op; a different binary/claim/profile refuses (fail closed).
 *
 *   finalize() - at producer completion (fold reached the target height/hash),
 *                verifies the running executable still owns the start session,
 *                binds the receipt to the completed generation (height, hash,
 *                and fold cursor),
 *                and writes the consensus_state_source_receipt singleton the
 *                exporter reads. A missing/foreign start session refuses.
 *
 * The source-tree/toolchain/build-inputs fields are honest producer CLAIMS,
 * not an independent rebuild proof; their authority comes from the known
 * running executable that emitted and durably recorded them (see
 * storage/consensus_state_bundle_codec.h).
 */

#ifndef ZCL_CONFIG_CONSENSUS_STATE_PRODUCER_RECEIPT_H
#define ZCL_CONFIG_CONSENSUS_STATE_PRODUCER_RECEIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sqlite3.h>

/* Producer datadirs are bounded before any path composition or status text
 * rendering. The limit is intentionally below the platform path ceiling and
 * matches the progress-store path contract. */
#define CONSENSUS_STATE_PRODUCER_DATADIR_MAX 1024U

/* Start-of-fold ownership marker. `validation_profile` is one of
 * CONSENSUS_STATE_VALIDATION_FULL / _CHECKPOINT_FOLD
 * (storage/consensus_state_bundle_codec.h). Returns false and fills `err` on
 * any refusal (missing 64-hex source identity, foreign existing session,
 * profile mismatch, store error). */
bool consensus_state_producer_receipt_begin(sqlite3 *pdb,
                                            uint8_t validation_profile,
                                            char *err, size_t err_size);

/* Completion finalization bound to the folded (height, block_hash). Requires a
 * matching start session written by the SAME running executable. Writes the
 * consensus_state_source_receipt singleton the exporter admits. Returns false
 * and fills `err` on any refusal.
 *
 * MONOTONIC RE-FINALIZE: may be called repeatedly by the SAME running binary at
 * NON-DECREASING heights. The standing live exporter (config/src/bundle_exporter
 * .c) re-finalizes each export cycle at the current durable tip so the receipt's
 * fold_cursor tracks H*+1. A re-finalize at a LOWER height than the committed
 * fold cursor is refused (the committed generation only rolls forward); an equal
 * height is an idempotent re-emit. The session's source epoch is build-derived
 * and stable across re-finalizes, so every stage row stamped since begin() keeps
 * carrying the one epoch the exporter's stage-row proof requires. */
bool consensus_state_producer_receipt_finalize(sqlite3 *pdb, int32_t height,
                                               const uint8_t block_hash[32],
                                               char *err, size_t err_size);

/* Operator retirement of a FOREIGN start session. begin() adopts nothing: when
 * the datadir's session row was written by a different build, every subsequent
 * boot of a newer binary degrades the exporter (STATUS_SOURCE_UNAVAILABLE /
 * bundle_exporter.degraded) until an operator explicitly retires the stale
 * row. This is that explicit act — offline, typed, audited:
 *
 *   RETIRED  - the stored session was written by a DIFFERENT build; the row is
 *              deleted and an audit digest of the retired session's binary is
 *              written to progress_meta. The next begin() inserts a fresh
 *              session owned by the then-running build.
 *   ABSENT   - no session row exists; nothing to do (not an error).
 *   CURRENT  - the stored session exactly matches THIS running build's
 *              identity; refused, because deleting it would destroy a session
 *              the running build legitimately owns and can resume.
 *   ERROR    - store failure, or this build carries no exact source identity
 *              (an unstamped build cannot judge a session — fail closed).
 *
 * The match is decided by build identity alone (running binary digest, source
 * tree root, toolchain, build inputs, source epoch, cleanliness, commit): the
 * current claim is recomputed at the STORED session's validation profile so a
 * profile difference alone never marks a same-build session foreign. */
enum consensus_state_producer_session_retire_result {
    CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_ERROR = 0,
    CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_RETIRED,
    CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_ABSENT,
    CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_CURRENT,
};

struct consensus_state_producer_session_retired {
    char    running_binary_digest[65]; /* lowercase hex; "" never happens */
    char    source_tree_root[65];      /* lowercase hex claim of retired row */
    char    source_epoch_digest[65];   /* lowercase hex epoch of retired row */
    int     validation_profile;        /* retired session's profile */
    int64_t started_us;                /* retired session's start time */
};

/* `pdb` must be an OPEN read-write consensus/progress store handle. On every
 * non-ERROR result `out` (may be NULL) receives what an operator needs to
 * audit the decision. Single DELETE + audit write in one transaction; a store
 * error rolls back and leaves the session row untouched. */
enum consensus_state_producer_session_retire_result
consensus_state_producer_session_retire(
    sqlite3 *pdb, struct consensus_state_producer_session_retired *out,
    char *err, size_t err_size);

/* This running executable's build-epoch digest: the same domain-separated
 * SHA3-256 binding of the exact current source tree
 * (zcl_build_source_id_sha256()), toolchain identity, and build inputs used
 * for the producer's source_epoch_digest — but computed standalone, with no
 * dependency on an active producer session, a datadir, or a fold. Any other
 * consumer that needs to know "is this exactly the same build that already
 * did X" (e.g. an install-time content-verify receipt) should key on this
 * value rather than re-deriving it. Returns false only when this build
 * carries no exact 64-hex source-identity stamp (a dev/unstamped build): the
 * caller must then treat epoch-keyed authority as unavailable, never
 * fabricate a key. */
bool consensus_state_producer_receipt_current_binary_epoch(uint8_t out[32]);

/* Read-only producer status. Opens <datadir>/progress.kv READONLY (no writes,
 * no migrations — safe against a running producer over WAL) and reports the
 * fold session/receipt lifecycle, reducer stage cursors, and a bounded
 * successful-apply rate window for the `z23 ops producer status`
 * command. NEVER mutates state; human log text is not rate authority. */
struct producer_status_read {
    bool    progress_kv_present;   /* <datadir>/progress.kv exists and opened */
    bool    session_open;          /* a producer session row exists (fold started) */
    bool    receipt_finalized;     /* full receipt parsed + digests reproduced */
    int64_t utxo_apply_cursor;     /* stage_cursor 'utxo_apply' (-1 if absent) */
    int64_t tip_finalize_cursor;   /* stage_cursor 'tip_finalize' (-1 if absent) */
    int64_t fold_cursor;           /* receipt fold cursor H*+1 (-1 if not finalized) */
    int64_t start_time_us;         /* session start (0 if no session) */
    bool    durable_rate_available; /* >=60s of successful apply-log evidence */
    int64_t rate_older_height;     /* older successful durable sample */
    int64_t rate_older_time_unix;
    int64_t rate_newer_height;     /* newest successful durable sample */
    int64_t rate_newer_time_unix;
    int64_t rate_blocks_per_second_milli; /* fixed point; never log-derived */
    int     validation_profile;    /* session/receipt validation profile (-1 if none) */
    char    receipt_schema[64];    /* exact v1/v2 session or receipt schema */
    char    source_tree_root[65];  /* lowercase hex source claim ("" if none) */
    char    source_epoch_digest[65]; /* lowercase hex epoch ("" if none) */
    char    producer_commit[64];   /* legacy v1 Git claim ("" for v2/none) */
};

/* Fill *out from <datadir>/progress.kv. ENOENT is a successful absent status;
 * an opened old/empty store may omit optional projection tables. Other I/O,
 * schema, SQL, type, or identity errors fail closed with `err` instead of
 * being reported as absence. Datadirs must contain fewer than
 * CONSENSUS_STATE_PRODUCER_DATADIR_MAX bytes. Node-free. */
bool consensus_state_producer_status_read(const char *datadir,
                                          struct producer_status_read *out,
                                          char *err, size_t err_size);

#ifdef ZCL_TESTING
/* Deterministic hermetic override for the source-identity claim so a test does
 * not depend on the build's baked source identity. `source_id` must be 64
 * lowercase hex (a SHA-256 identity) or begin() rejects it like a real
 * unstamped build. `source_clean` exercises the legacy-named completeness
 * column; production v2 writers always set it true after exact capture and do
 * not derive it from Git cleanliness. Pass source_id=NULL to clear. */
void consensus_state_producer_receipt_test_set_identity(const char *source_id,
                                                        bool source_clean);
#endif

#endif /* ZCL_CONFIG_CONSENSUS_STATE_PRODUCER_RECEIPT_H */
