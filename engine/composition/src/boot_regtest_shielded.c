/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_regtest_shielded — the -regtestshielded runtime override, split out
 * of boot.c (E1 file-size ceiling) so boot_step_select_chain_and_datadir
 * stays a short call site. See config/boot_internal.h for the declaration.
 *
 * -regtestshielded activates Overwinter + Sapling from genesis on THIS
 * node's runtime chain params (the zcashd -nuparams equivalent — zcashd's
 * own regtest semantics). It mutates only the runtime copy selected by
 * boot_step_select_chain_and_datadir: the sealed core/chainparams.c table
 * keeps its bytes, and the flag is unreachable on mainnet/testnet. Without
 * it a regtest node rejects every Overwintered tx at mempool admission
 * (tx-overwinter-not-active — regtest pins all post-Sprout upgrades at
 * NO_ACTIVATION), so no shielded payment can ever be proven against an
 * isolated node. */

#include "config/boot_internal.h"

#include "chain/chainparams.h"
#include "consensus/params.h"

#include <stdio.h>

void boot_apply_regtest_shielded(bool enabled, bool regtest)
{
    if (!enabled)
        return;
    if (!regtest) {
        printf("Warning: -regtestshielded without -regtest is ignored "
               "(mainnet/testnet activation heights are never overridden)\n");
        return;
    }
    /* chain_params_get() is const by API; the selected params struct is
     * mutable storage (the same cast lib/test already uses), and boot
     * performs this exactly once, before any consumer reads the upgrade
     * table. */
    struct chain_params *rw = (struct chain_params *)chain_params_get();
    rw->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight =
        NETWORK_UPGRADE_ALWAYS_ACTIVE;
    rw->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight =
        NETWORK_UPGRADE_ALWAYS_ACTIVE;
    printf("regtestshielded: Overwinter+Sapling active from genesis "
           "on this regtest node\n");
}
