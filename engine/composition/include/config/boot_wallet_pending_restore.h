/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Restore a verified pending-cutover chain view before workers start. */
#ifndef ZCL_CONFIG_BOOT_WALLET_PENDING_RESTORE_H
#define ZCL_CONFIG_BOOT_WALLET_PENDING_RESTORE_H

#include <stdint.h>

struct main_state;
struct chain_state_repository;
struct uint256;

enum boot_pending_restore_result {
    BOOT_PENDING_RESTORE_OK,
    BOOT_PENDING_RESTORE_INVALID_CONTEXT,
    BOOT_PENDING_RESTORE_HEADER_UNAVAILABLE,
    BOOT_PENDING_RESTORE_ANCESTRY_INVALID,
    BOOT_PENDING_RESTORE_TREE_UNAVAILABLE,
    BOOT_PENDING_RESTORE_TREE_MISMATCH,
    BOOT_PENDING_RESTORE_CSR_REFUSED,
};

/* Startup only: no reducer, RPC or background worker may run concurrently.
 * The caller has proved coins_height/hash from durable consensus authority,
 * opened the authoritative progress store, provided the installed binding target,
 * bound csr to ms and its coins
 * cache, and verified/registered any sparse island. Complete hash-bound header
 * sources must be available for every non-genesis entry back to genesis or
 * that island root. No persistent state is modified. On failure the previous
 * in-memory view and Sapling tree remain usable and unchanged. */
enum boot_pending_restore_result boot_wallet_pending_restore(
    struct main_state *ms, struct chain_state_repository *csr,
    int32_t coins_height, const struct uint256 *coins_hash,
    int32_t installed_height, const struct uint256 *installed_hash);

#endif
