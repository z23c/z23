/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the replay receipt's private cross-TU contract — the decoded
 * receipt record, the shared refusal reporter, and the entry point of the
 * independent derivation pass.
 *
 * consensus_state_replay_receipt.c owns the RECEIPT half (payload codec,
 * atomic write, read-back, the verifier-binary digest, and the public
 * authority/binding queries); consensus_state_replay_receipt_derive.c owns
 * the DERIVATION half — the UTXO/anchor/nullifier row scans over the
 * datadir's OWN folded progress-store tables. The split happened when the
 * combined file passed the 800-line shape ceiling. These three declarations
 * are all that crosses that seam, so they live here and nowhere else —
 * nothing outside those two translation units may include this header.
 */

#ifndef ZCL_CONFIG_CONSENSUS_STATE_REPLAY_RECEIPT_INTERNAL_H
#define ZCL_CONFIG_CONSENSUS_STATE_REPLAY_RECEIPT_INTERNAL_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

struct consensus_state_bundle_manifest;
struct consensus_state_replay_result;

/* One decoded receipt, independent of the on-disk byte order. */
struct rr_receipt {
    uint8_t bundle_file_digest[32];
    uint8_t artifact_digest[32];
    uint8_t block_hash[32];
    int64_t height;
    uint8_t utxo_root[32];
    uint64_t utxo_count;
    int64_t total_supply;
    uint8_t anchor_digest[32];
    uint64_t anchor_count;
    uint8_t nullifier_digest[32];
    uint64_t nullifier_count;
    uint8_t verifier_binary_digest[32];
    uint8_t receipt_digest[32];
};

/* Record the refusal `reason` on `out` (when present), log it, and return
 * false so a caller can `return rr_fail(...)`. Defined in
 * consensus_state_replay_receipt.c. */
bool rr_fail(struct consensus_state_replay_result *out, const char *fmt, ...);

/* Fill `r`'s independently derived components from the datadir progress store
 * and return the derived digests; the caller compares them to the manifest.
 * Defined in consensus_state_replay_receipt_derive.c. */
bool rr_derive_from_datadir(sqlite3 *db,
                            const struct consensus_state_bundle_manifest *m,
                            struct rr_receipt *r,
                            struct consensus_state_replay_result *out);

#endif /* ZCL_CONFIG_CONSENSUS_STATE_REPLAY_RECEIPT_INTERNAL_H */
