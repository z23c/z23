/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Restore a verified pending-cutover chain view before workers start. */
#ifndef ZCL_CONFIG_BOOT_WALLET_PENDING_RESTORE_H
#define ZCL_CONFIG_BOOT_WALLET_PENDING_RESTORE_H

#include <stdbool.h>
#include <stdint.h>

struct main_state;
struct chain_state_repository;
struct uint256;
struct wallet_cutover_binding;
struct sqlite3;

enum boot_pending_restore_result {
    BOOT_PENDING_RESTORE_OK,
    BOOT_PENDING_RESTORE_INVALID_CONTEXT,
    BOOT_PENDING_RESTORE_HEADER_UNAVAILABLE,
    BOOT_PENDING_RESTORE_ANCESTRY_INVALID,
    BOOT_PENDING_RESTORE_TREE_UNAVAILABLE,
    BOOT_PENDING_RESTORE_TREE_MISMATCH,
    BOOT_PENDING_RESTORE_CSR_REFUSED,
    BOOT_PENDING_RESTORE_AUTHORITY_UNAVAILABLE,
};

/* Caller holds the progress-store lock and owns the read transaction. */
bool boot_wallet_authority_generation(struct sqlite3 *db, bool *present, uint64_t *generation);

/* Startup only: caller holds the datadir authority and excludes all writers and
 * workers for the entire call. datadir_fd is a retained descriptor for that
 * directory; the open progress store must match it. The in-memory index and genesis must already be
 * validated and complete through the coins frontier. No persistent writes,
 * import, projection rebuild, repair or wallet mutation are performed.
 * Clean empty genesis is unavailable; sparse islands are refused.
 * On refusal chain, header, coins cursor and Sapling tree are unchanged;
 * existing CSR linkage diagnostics may still record a refusal. */
enum boot_pending_restore_result boot_wallet_prebinding_restore(
    struct main_state *ms, struct chain_state_repository *csr, int datadir_fd);

/* Caller must cryptographically verify and register the persisted island first. */
enum boot_pending_restore_result boot_wallet_old_partial_restore(
    struct main_state *ms, struct chain_state_repository *csr,
    const struct wallet_cutover_binding *binding);

enum boot_pending_restore_result boot_wallet_old_genesis_restore(
    struct main_state *ms, struct chain_state_repository *csr,
    const struct wallet_cutover_binding *binding);

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

#ifdef ZCL_TESTING
unsigned boot_wallet_prebinding_test_take_header_reads(void);
void boot_wallet_prebinding_test_before_recheck(void (*hook)(void *), void *context);
#endif
#endif
