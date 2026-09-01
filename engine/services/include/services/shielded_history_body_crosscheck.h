/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Local-body cross-check witness for the shielded-history promote path.
 *
 * Sprout frontiers and the nullifier set are not committed by any block
 * header, so a promoted producer table needs an independent trust root:
 * the locally-held, PoW/merkle-verified block bodies. This verifier
 * re-derives both from bodies over [0, checkpoint_height] — the same
 * zk-free syntactic derivation zclassicd performs below its checkpoints —
 * and compares against the producer's tables. It writes NOTHING; both
 * datadirs are opened read-only. See shielded_history_promote_service.h
 * for the installer that consumes this result (gates G3/G3b/G4).
 */
#ifndef SERVICES_SHIELDED_HISTORY_BODY_CROSSCHECK_H
#define SERVICES_SHIELDED_HISTORY_BODY_CROSSCHECK_H

#include <stdbool.h>
#include <stdint.h>

struct crosscheck_result {
    bool sprout_ok;      /* every shard's sprout end-root == producer's   */
    bool nullifiers_ok;  /* body-derived nf set == producer set, both ways */
    int64_t max_height;  /* highest body height the walk covered           */
    uint64_t nf_count;   /* body-derived nullifier count (diagnostics)     */
    uint64_t sprout_frontier_count; /* producer sprout rows verified       */
};

/* Re-derive sprout frontiers + the (nf, pool) set from local bodies in
 * copy_datadir over [0, checkpoint_height], sharded across workers at the
 * producer's own sprout-frontier heights, and compare against the producer
 * tables in producer_datadir (attached SQLITE_OPEN_READONLY). Every body
 * read is PoW/merkle-bound (nbf_chain_body_verify). Returns false only on
 * infrastructure failure (unreadable body, missing table); comparison
 * verdicts land in *out. Reentrant-safe; owns no global state. */
bool shielded_history_body_crosscheck_run(const char *copy_datadir,
                                          const char *producer_datadir,
                                          int64_t checkpoint_height,
                                          struct crosscheck_result *out);

#endif /* SERVICES_SHIELDED_HISTORY_BODY_CROSSCHECK_H */
