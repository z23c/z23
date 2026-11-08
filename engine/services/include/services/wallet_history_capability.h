/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Retain a verified private history tree under a cooperating lease. */
#ifndef ZCL_WALLET_HISTORY_CAPABILITY_H
#define ZCL_WALLET_HISTORY_CAPABILITY_H
#include "platform/directory_transaction.h"
#include "util/result.h"
#include <stdint.h>
struct wallet_history_names {
    char root[140], stage[145], lock[144];
};
static_assert(sizeof(((struct wallet_history_names *)0)->stage) >= 145, "history stage leaf fits");
struct zcl_result wallet_history_capability_names(const uint8_t snapshot[32], const uint8_t root[32],
                                     struct wallet_history_names *out);
struct wallet_history_capability {
    struct platform_directory_transaction parent, root, blocks;
    struct platform_directory_lock lease;
    char path[64];
    uint8_t verified_root[32];
    bool verified;
};
void wallet_history_capability_init(struct wallet_history_capability *cap);
/* On Linux, consumes parent, retained_root and lease on valid input, including refusal;
 * all must be initialized and held by the caller, with lease exclusive and
 * acquired from lock_leaf in parent. root_leaf names the tree.
 * Every owner must lock the same leaf before changing the tree. The caller
 * guarantees immutable bytes and namespace from entry through release; the
 * lease and descriptors do not prevent same-user writes. Linux procfs is
 * required. A receiver must retain this very object for its whole use; a
 * pathname, copied descriptor, or released/reacquired lock is not a handoff. */
struct zcl_result wallet_history_capability_acquire(
    struct wallet_history_capability *cap, struct platform_directory_transaction *parent,
    struct platform_directory_transaction *retained_root, struct platform_directory_lock *lease,
    const char *root_leaf, const char *lock_leaf, unsigned block_files,
    const uint8_t expected_root[32]);
enum { WALLET_HISTORY_CAPABILITY_CANCELLED = -2 };
/* Return WALLET_HISTORY_CAPABILITY_CANCELLED only for observed cancellation; -1 denotes another refusal.
 * Inputs transfer on valid Linux calls, including cancellation. */
struct zcl_result wallet_history_capability_acquire_cancelable(
    struct wallet_history_capability *cap, struct platform_directory_transaction *parent,
    struct platform_directory_transaction *retained_root, struct platform_directory_lock *lease,
    const char *root_leaf, const char *lock_leaf, unsigned block_files,
    const uint8_t expected_root[32], bool (*cancelled)(void *), void *context);
/* Rebuild the receiver's named root and exclusive lease from a durable binding.
 * The path must be absolute and name history-<snapshot>-<root>; the sibling
 * lock and complete contiguous block inventory are verified before success. */
struct zcl_result wallet_history_capability_acquire_bound(
    struct wallet_history_capability *cap, const char *history_path,
    const uint8_t snapshot_digest[32], const uint8_t history_root[32]);
const char *wallet_history_capability_path(const struct wallet_history_capability *cap);
/* The capability must have been initialized and remain held. */
struct zcl_result wallet_history_capability_matches(const struct wallet_history_capability *cap,
                                       const uint8_t expected_root[32]);
/* Check the opened private final directory against the held root identity.
 * The caller must keep all ancestors stable; intermediate links may be followed. */
struct zcl_result wallet_history_capability_matches_path(const struct wallet_history_capability *cap,
                                            const char *path);
void wallet_history_capability_release(struct wallet_history_capability *cap);
#if defined(ZCL_TESTING) && defined(__linux__)
void wallet_history_capability_test_after_manifest(void (*hook)(void));
#endif
#endif
