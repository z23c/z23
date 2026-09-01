/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain State Validator — boot-time cross-check between block_map,
 * SQLite, coins_best_block, and active_chain.
 *
 * Background
 * ----------
 * At boot, the node must verify that the UTXO set (coins_best_block) agrees
 * with the active chain tip. If they disagree, the node must take a recovery
 * action: reimport from LevelDB, wipe and wait for P2P snapshot, or reset the
 * chain tip to match coins.
 *
 * This service encapsulates the validation logic and returns a
 * structured decision, freeing boot.c from hosting 150+ lines of
 * diagnostic cross-checking.
 */

#ifndef ZCL_SERVICES_CHAIN_STATE_VALIDATOR_H
#define ZCL_SERVICES_CHAIN_STATE_VALIDATOR_H

#include <stdbool.h>
#include <stdint.h>
#include "core/uint256.h"

/* Forward declarations */
struct main_state;
struct coins_view_cache;

/* ── Recovery actions ────────────────────────────────────── */

enum boot_recovery_action {
    BOOT_OK = 0,               /* coins and chain agree */
    BOOT_RECOVER_REIMPORT,     /* LevelDB chainstate exists, reimport */
    BOOT_RECOVER_WIPE_WAIT,    /* wipe UTXOs, wait for P2P snapshot */
    BOOT_RECOVER_RESET_CHAIN,  /* coins behind chain, reset chain tip */
    BOOT_RECOVER_RESET_COINS_TO_CHAIN_TIP,
    BOOT_RECOVER_RESET_COINS_TO_GENESIS,
};

struct boot_validation_result {
    enum boot_recovery_action action;
    int chain_height;
    int coins_height;      /* -1 if coins_best_block not found in index */
    struct uint256 coins_hash;
};

/* ── Public API ──────────────────────────────────────────── */

/* ActiveRecord-style validation for coins/chain agreement at boot.
 * Detects mismatch between coins_best_block and active chain tip,
 * returns the appropriate recovery action.
 * Emits EV_BOOT_VALIDATION_FAILED on any mismatch. */
struct boot_validation_result validate_coins_chain_agreement(
    struct main_state *ms,
    struct coins_view_cache *cvtip,
    const char *datadir);

#endif /* ZCL_SERVICES_CHAIN_STATE_VALIDATOR_H */
