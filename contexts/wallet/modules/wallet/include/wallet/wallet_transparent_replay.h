/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: transparent wallet transaction replay without persistence. */
#ifndef Z23_WALLET_TRANSPARENT_REPLAY_H
#define Z23_WALLET_TRANSPARENT_REPLAY_H
struct wallet;
struct transaction;
struct uint256;
enum wallet_transparent_fold_result {
    WALLET_TRANSPARENT_NOT_OWNED,
    WALLET_TRANSPARENT_APPLIED,
    WALLET_TRANSPARENT_ERROR
};
/* Caller holds wallet and keystore locks. The block hash and depth are from
 * an authenticated chain snapshot. No persistence or cursor update occurs.
 * Failure leaves the transaction wallet state unchanged. */
enum wallet_transparent_fold_result wallet_transparent_fold_locked(
    struct wallet *w, const struct transaction *tx,
    const struct uint256 *block_hash, int depth);
#endif
