/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: create custody identity before boot loads or creates wallet keys. */

#include "config/boot_internal.h"

#include "event/event.h"
#include "models/wallet_identity.h"

bool boot_wallet_identity_ensure(struct node_db *ndb,
                                 const uint8_t network_genesis[32],
                                 const char *operator_lane)
{
    struct wallet_identity_row wallet_identity;
    if (wallet_identity_ensure(ndb, network_genesis, operator_lane,
                               &wallet_identity))
        return true;
    event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                "wallet_identity_unavailable lane=%s", operator_lane);
    return false; /* raw-return-ok:boot caller halts after named event */
}
