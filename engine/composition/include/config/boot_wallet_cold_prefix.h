/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Stage a verified old header prefix for a bound terminal install. */
#ifndef ZCL_CONFIG_BOOT_WALLET_COLD_PREFIX_H
#define ZCL_CONFIG_BOOT_WALLET_COLD_PREFIX_H
#include <stdbool.h>
#include <stddef.h>
struct main_state;
struct block_index;
struct chain_state_repository;
struct bound_history_preflight;
struct boot_bound_bundle_observation;
struct consensus_state_artifact_evidence;
struct wallet_history_capability;
typedef struct boot_wallet_cold_prefix boot_wallet_cold_prefix_t;
enum boot_wallet_cold_result {
    BOOT_WALLET_COLD_ERROR, BOOT_WALLET_COLD_UNAVAILABLE,
    BOOT_WALLET_COLD_STOPPED, BOOT_WALLET_COLD_READY,
    BOOT_WALLET_COLD_ADOPTED, BOOT_WALLET_COLD_TERMINAL
};
/* Startup only; caller excludes workers/writers, retains datadir authority,
 * keeps stop/context alive and discards this stage before normal startup.
 * No map, chain, wallet or persistent rows are modified. UNAVAILABLE includes
 * frontier capture failure because the existing capture is boolean; callers
 * must refuse, not interpret it as an absent row. */
enum boot_wallet_cold_result boot_wallet_cold_prefix_stage(
    struct main_state *ms, int dirfd, size_t max_headers,
    bool (*stop)(void *), void *ctx, boot_wallet_cold_prefix_t **out);
/* Terminal stage may fill compact projection rows from this retained archive.
 * The preflight, artifact and capability must outlive the stage. */
enum boot_wallet_cold_result boot_wallet_cold_prefix_stage_with_history(
    struct main_state *ms, int dirfd, size_t max_headers, struct bound_history_preflight *history,
    bool (*stop)(void *), void *ctx, boot_wallet_cold_prefix_t **out);
/* Borrowed staged tip; valid until the stage is released. */
const struct block_index *boot_wallet_cold_prefix_tip(const boot_wallet_cold_prefix_t *stage);
/* Terminal-only: exact retained preflight and frontier are rechecked before
 * insert and CSR publication. TERMINAL requires immediate startup exit. */
enum boot_wallet_cold_result boot_wallet_cold_prefix_adopt(boot_wallet_cold_prefix_t *stage,
    struct chain_state_repository *csr, struct bound_history_preflight *preflight,
    const struct boot_bound_bundle_observation *request,
    const struct consensus_state_artifact_evidence *artifact,
    const struct wallet_history_capability *held);
/* Close pinned readers after terminal use; inserted arena stays alive. */
bool boot_wallet_cold_prefix_close_readers(boot_wallet_cold_prefix_t *stage);
/* Refuses after an insertion attempt: mapped nodes retain stage storage for
 * process lifetime. Otherwise releases stage and reports close errors. */
bool boot_wallet_cold_prefix_release(boot_wallet_cold_prefix_t *stage);
#endif
