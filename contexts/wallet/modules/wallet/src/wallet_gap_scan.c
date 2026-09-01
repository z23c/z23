/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The BIP44 gap-limit scan a wallet recovery rebuilds its keys with.
 *
 * What went wrong without it. A wallet created by this node mints
 * DEFAULT_KEYPOOL_SIZE keys at indices 0..99 and leaves its HD counter at
 * 100, so the FIRST address it ever hands a user is index 100 — one past
 * the end of that range. A recovery that re-minted the same fixed 100 keys
 * therefore rebuilt every index the user never saw and NOT the one they
 * published, reported "recovered": true, and then recommended a rescan
 * that structurally could not find their coins.
 *
 * The convention that fixes it, from BIP44's "Address gap limit": walk the
 * indices upward and stop only after WALLET_GAP_LIMIT consecutive addresses
 * with no history, rather than at a fixed count. Whether an address HAS
 * history is not this file's business — the caller passes an oracle, and a
 * caller with nothing to consult passes NULL and gets the floor.
 *
 * The bounds (floor, gap, ceiling) and what each one means to the user are
 * documented on wallet_derive_gap_limited in wallet/wallet.h; this file is
 * the loop, not the contract.
 */

#include "wallet/wallet.h"

#include "wallet/bip44.h"
#include "keys/pubkey.h"
#include "util/log_macros.h"

#include <string.h>

/* One chain — receiving (BIP44_EXTERNAL) or change (BIP44_INTERNAL). */
static bool wallet_gap_scan_chain(struct wallet *w, uint32_t change,
                                  wallet_address_used_fn used, void *ctx,
                                  uint32_t *derived_out, uint32_t *used_out,
                                  bool *ceiling_out)
{
    uint32_t derived = 0;
    uint32_t used_count = 0;
    uint32_t run_unused = 0;

    while (derived < (uint32_t)WALLET_RECOVERY_MAX_LOOKAHEAD) {
        struct pubkey pk;
        /* Mints at the HD counter and advances it under the wallet lock, so
         * the wallet's own idea of "next index" stays the truth about what
         * was derived and a later boot's counter scan agrees with it. */
        if (!wallet_mint_next_hd_key(w, change, &pk))
            LOG_FAIL("wallet", "gap scan: derive %u/%u failed", change,
                     derived);
        derived++;

        bool is_used = false;
        if (used) {
            struct key_id kid = pubkey_get_id(&pk);
            is_used = used(&kid, ctx);
        }
        if (is_used) {
            used_count++;
            run_unused = 0;
        } else {
            run_unused++;
        }

        /* The floor wins over the gap. Stopping after 20 unused indices on
         * a chain nobody can see would rebuild FEWER addresses than the
         * fixed-100 behaviour this replaced — including, again, not the one
         * the user published. */
        if (derived >= (uint32_t)WALLET_RECOVERY_MIN_LOOKAHEAD &&
            run_unused >= (uint32_t)WALLET_GAP_LIMIT)
            break;
    }

    *derived_out = derived;
    *used_out = used_count;
    /* The loop only leaves early on the gap condition, so a full run means
     * the oracle was still reporting activity when the bound stopped us.
     * The caller has to tell the user the scan was truncated — a silent
     * truncation here is a silently incomplete wallet. */
    if (derived >= (uint32_t)WALLET_RECOVERY_MAX_LOOKAHEAD)
        *ceiling_out = true;
    return true;
}

bool wallet_derive_gap_limited(struct wallet *w, wallet_address_used_fn used,
                               void *ctx, struct wallet_gap_scan *out)
{
    GUARD_NOT_NULL(w, "wallet", "wallet");
    GUARD_NOT_NULL(out, "wallet", "out");
    memset(out, 0, sizeof(*out));
    out->oracle_consulted = (used != NULL);

    if (!w->has_master_key)
        LOG_FAIL("wallet", "gap scan: no HD master — root the wallet on its "
                           "recovery phrase first");

    if (!wallet_gap_scan_chain(w, BIP44_EXTERNAL, used, ctx,
                               &out->external_derived, &out->external_used,
                               &out->ceiling_hit))
        return false;
    if (!wallet_gap_scan_chain(w, BIP44_INTERNAL, used, ctx,
                               &out->internal_derived, &out->internal_used,
                               &out->ceiling_hit))
        return false;

    LOG_INFO("wallet",
             "gap-limit recovery scan: receiving %u derived (%u with "
             "history), change %u derived (%u with history), oracle=%s%s",
             out->external_derived, out->external_used,
             out->internal_derived, out->internal_used,
             out->oracle_consulted ? "chain" : "none",
             out->ceiling_hit ? ", CEILING HIT — scan truncated" : "");
    return true;
}
