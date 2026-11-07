/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: guarded publication of replayed wallet checkpoint state. */
#ifndef Z23_BOOT_WALLET_CUTOVER_PUBLISH_H
#define Z23_BOOT_WALLET_CUTOVER_PUBLISH_H
#include <stdbool.h>
struct boot_cutover_replay;
struct wpr_pending_guard;
struct coins_kv_read_snapshot;
struct coins_kv_read_snapshot_info;
struct wallet_cutover_v2_plan;
struct db_wallet_utxo_cutover_delivery;
/* Startup only: chain mutation and wallet workers are quiescent. Caller owns
 * the relay guard and a preallocated plan, and keeps the pinned snapshot open.
 * The delivery is zero-initialized and must survive commit; after releasing
 * the guard the caller flushes and clears it. Failed valid pending input remains pending. */
bool boot_wallet_cutover_publish(struct boot_cutover_replay *replay,
    struct wpr_pending_guard *guard, struct coins_kv_read_snapshot *snapshot,
    const struct coins_kv_read_snapshot_info *info, struct wallet_cutover_v2_plan *plan,
    struct db_wallet_utxo_cutover_delivery *delivery);
struct wpr;
/* Startup quiescence and a stopped, configured relay are required. Allocates
 * the plan and pins coins before acquiring the relay guard; releases both
 * before returning. Caller retains delivery through commit, then flushes it
 * without the guard. A failed post-commit flush does not undo wallet READY. */
bool boot_wallet_cutover_publish_guarded(struct boot_cutover_replay *replay,
    struct wpr *relay, struct db_wallet_utxo_cutover_delivery *delivery);
#endif
