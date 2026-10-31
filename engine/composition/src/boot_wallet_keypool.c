/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Fail-closed boot loading and durable upgrade of the wallet keypool. */

#include "config/boot_internal.h"
#include "event/event.h"
#include "wallet/wallet.h"
#include "wallet/wallet_keystore.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"

#include <stdio.h>
#include <stdlib.h>

void boot_wallet_read_keypool_or_exit(struct wallet_sqlite *wallet_db,
                                      struct wallet *wallet)
{
    struct zcl_result result = wallet_sqlite_read_keypool_r(wallet_db, wallet);
    if (result.ok)
        return;
    fprintf(stderr, "wallet keypool load failed: code=%d %s (%s:%d)\n",
            result.code, result.message,
            result.source_file ? result.source_file : "?", result.source_line);
    event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                "wallet_keypool_load_failed code=%d", result.code);
    exit(1);
}

bool boot_wallet_is_sealed(const struct wallet *wallet)
{
    return wallet_sqlite_read_keys_locked_count() > 0 ||
           wallet->sapling_keys.locked;
}

bool boot_wallet_keys_plaintext_at_rest(int64_t pre_open_key_rows)
{
    return pre_open_key_rows > 0 &&
           wallet_at_rest_creation_policy() != WALLET_AT_REST_ENCRYPTED &&
           !wallet_lock_encrypted_at_rest();
}

void boot_wallet_top_up_legacy_keypool_or_exit(
    int64_t pre_open_key_rows, struct wallet_sqlite *wallet_db,
    struct wallet *wallet)
{
    if (boot_wallet_is_sealed(wallet))
        printf("Wallet is LOCKED: %d transparent key(s) sealed, %zu shielded "
               "viewing key(s) loaded; unlock to spend.\n",
               wallet_sqlite_read_keys_locked_count(),
               wallet->sapling_keys.num_keys);
    /* v72 cannot infer which historical keys were never issued. An upgraded
     * or exhausted wallet gets a fresh durable pool before WALLET_LOADED. */
    /* A wallet booted locked has no key material to extend the pool with; a
     * top-up would mint unrelated random keys beside the sealed ones. */
    if (pre_open_key_rows <= 0 || wallet->key_pool_size != 0 ||
        wallet_lock_is_locked())
        return;
    if (!wallet_top_up_key_pool(wallet, DEFAULT_KEYPOOL_SIZE)) {
        fprintf(stderr, "FATAL: wallet keypool top-up failed during restart.\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "wallet_keypool_restart_topup_failed");
        exit(1);
    }
    int64_t generation = wallet_key_pool_generation_ceiling(wallet);
    struct zcl_result result = wallet_sqlite_flush_r(wallet_db, wallet);
    if (!result.ok) {
        fprintf(stderr, "FATAL: wallet keypool persistence failed (code=%d).\n",
                result.code);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "wallet_keypool_restart_flush_failed code=%d",
                    result.code);
        exit(1);
    }
    wallet_key_pool_mark_persisted_through(wallet, generation);
}
