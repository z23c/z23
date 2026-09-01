/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal durable evidence for extending an admitted consensus-state bundle.
 * A bundle install replaces the reducer logs with an anchor plus a suffix.  It
 * must therefore retain the bundle's already-validated genesis..anchor proof
 * summaries if this datadir is ever to export a later generation honestly.
 *
 * This is inherited EVIDENCE, never local producer authority.  The install
 * still deletes the bundle producer's session and receipt; a new exporter must
 * bind any extension to its own running binary and locally verified suffix. */

#ifndef ZCL_CONFIG_CONSENSUS_STATE_PROOF_PREFIX_H
#define ZCL_CONFIG_CONSENSUS_STATE_PROOF_PREFIX_H

#include "storage/consensus_state_bundle_codec.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

struct consensus_state_proof_prefix {
    bool present;
    int32_t height;
    uint8_t block_hash[32];
    uint8_t validation_profile;
    uint8_t proof_manifest_digest[32];
    uint8_t source_digest[32];
    uint8_t artifact_digest[32];
    struct consensus_state_bundle_proof_summary
        components[CONSENSUS_STATE_BUNDLE_PROOF_COUNT];
};

/* Replace inherited prefix evidence from an already-admitted bundle.  The
 * caller holds progress_store_tx_lock() and an open BEGIN IMMEDIATE; this
 * function starts no transaction, so evidence and activated state commit or
 * roll back together. */
bool consensus_state_proof_prefix_install_in_tx(
    sqlite3 *progress_db, sqlite3 *bundle_db,
    const struct consensus_state_bundle_manifest *manifest);

/* Load and fully shape-check the retained prefix.  Absence is a successful
 * read with out->present=false; malformed or partial evidence returns false. */
bool consensus_state_proof_prefix_load(
    sqlite3 *progress_db, struct consensus_state_proof_prefix *out);

/* Derive the header component over either a locally present genesis..height
 * corpus or an admitted prefix plus the locally stored linked suffix.  When
 * parent_out is non-NULL it receives the explicit lineage and suffix digest
 * needed for a compositional bundle to disclose and validate that boundary. */
bool consensus_state_proof_header_digest(
    sqlite3 *progress_db, int32_t height, const uint8_t expected_hash[32],
    uint8_t out[32], struct consensus_state_bundle_proof_parent *parent_out);

#endif /* ZCL_CONFIG_CONSENSUS_STATE_PROOF_PREFIX_H */
