/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: pinned coin state for wallet checkpoint publication. */
#ifndef Z23_BOOT_WALLET_CUTOVER_COINS_H
#define Z23_BOOT_WALLET_CUTOVER_COINS_H
#include "models/wallet_tx.h"
#include "storage/coins_kv_read_snapshot.h"
#include "wallet/wallet_sqlite.h"

struct boot_cutover_coins;
enum boot_cutover_coins_status {
    BOOT_CUTOVER_COINS_OK, BOOT_CUTOVER_COINS_BUSY,
    BOOT_CUTOVER_COINS_INVALID, BOOT_CUTOVER_COINS_LIMIT,
    BOOT_CUTOVER_COINS_ERROR
};
/* Startup-only. Caller keeps chain mutation quiescent and retains the same
 * pinned snapshot and its matching open-time info through publication. Resolver
 * is read-only/nonblocking and uses caller-held chain authority. No wallet or
 * chain locks may be acquired by the caller before this function. */
enum boot_cutover_coins_status boot_cutover_coins_prepare(
    struct wallet *wallet, struct coins_kv_read_snapshot *snapshot,
    const struct coins_kv_read_snapshot_info *info, int reference_height,
    const uint8_t reference_hash[32], uint64_t generation, const uint8_t scan_identity[32],
    wallet_height_resolver resolver, void *chain_ctx, struct boot_cutover_coins **out);
/* Publication must recheck all bindings before using cached verdicts. */
bool boot_cutover_coins_matches(const struct boot_cutover_coins *cache,
    int reference_height, const uint8_t reference_hash[32], uint64_t generation,
    const uint8_t scan_identity[32]);
/* Callback does no I/O or locking; mismatched or uncaptured output is UNKNOWN. */
enum db_cutover_coin_verdict boot_cutover_coins_verdict(void *cache,
    const uint8_t txid[32], uint32_t vout, const struct tx_out *expected,
    int height, bool coinbase);
void boot_cutover_coins_free(struct boot_cutover_coins *cache);
#endif
