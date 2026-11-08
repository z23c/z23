/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: retain an admitted bundle in the leased private datadir. */
#ifndef ZCL_CONSENSUS_STATE_INSTALL_STAGE_H
#define ZCL_CONSENSUS_STATE_INSTALL_STAGE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct consensus_state_artifact_evidence;
struct wallet_cutover_binding;
bool consensus_state_old_artifact_matches(const char *path,
    const struct wallet_cutover_binding *expected);
/* Caller holds the datadir lease. On success out names a durable read-only
 * copy with the same admitted bytes; caller must re-admit for its receipt. */
bool consensus_state_install_stage(const char *datadir,
    const struct consensus_state_artifact_evidence *source, char *out, size_t cap,
    struct consensus_state_artifact_evidence **staged);
bool consensus_state_stage_evidence_matches(const struct consensus_state_artifact_evidence *artifact,
    const uint8_t whole[32], const uint8_t logical[32]);
#endif
