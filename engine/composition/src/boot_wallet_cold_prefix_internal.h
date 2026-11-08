/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: stage and adopt a verified wallet cold prefix
 */
#ifndef ZCL_BOOT_WALLET_COLD_PREFIX_INTERNAL_H
#define ZCL_BOOT_WALLET_COLD_PREFIX_INTERNAL_H
#include "config/boot_wallet_pending_restore.h"
struct block_header;
struct bound_history_preflight;
struct boot_bound_bundle_observation;
struct consensus_state_artifact_evidence;
struct wallet_history_capability;
typedef bool (*boot_wallet_cold_header_source)(void *, int32_t, const uint8_t[32], struct block_header *);
struct boot_wallet_cold_terminal_guard {
    struct bound_history_preflight *preflight;
    const struct boot_bound_bundle_observation *request;
    const struct consensus_state_artifact_evidence *artifact;
    const struct wallet_history_capability *held;
};
enum boot_pending_restore_result boot_wallet_prebinding_restore_terminal(
    struct main_state *ms, struct chain_state_repository *csr, int datadir_fd,
    const struct boot_wallet_frontier *expected, boot_wallet_cold_header_source source,
    void *ctx, const struct boot_wallet_cold_terminal_guard *guard);
#endif
