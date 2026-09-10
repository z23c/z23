/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: refuse the three BIP37 bloom-filter commands and score the sender.
 *
 * BIP37 is a known privacy leak: a peer can probe which addresses a node owns
 * by watching false-positive rates across crafted filters. Default OFF —
 * enable only with ZCL_ENABLE_BIP37=1. When disabled,
 * filterload/filteradd/filterclear score the peer as misbehaving.
 *
 * Split out of msgprocessor.c, which is a shrink-only legacy file: these three
 * handlers share no state with the dispatch loop that file owns, so they
 * belong beside the other per-family msg_*.c files. The dispatch rows that
 * name them stay in msgprocessor.c's one table, unchanged.
 */

#include "msgprocessor_internal.h"

#include "bloom/bloom.h"
#include "net/peer_scoring.h"
#include "base/log_macros.h"

#include <stdio.h>

/* Shared reject path for the three BIP37 filter commands. When BIP37 is
 * disabled (the default) the peer is scored as misbehaving and dropped.
 * Full BIP37 filter loading is not implemented — reject even when enabled
 * until a use case justifies it. */
static bool handle_bip37_rejected(struct msg_processor *mp, struct p2p_node *node,
                                  struct byte_stream *s, const char *cmd)
{
    (void)s;
    if (!bip37_enabled()) {
        char reason[64];
        snprintf(reason, sizeof(reason), "%s rejected: BIP37 disabled", cmd);
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_PROTOCOL_VIOLATION, reason);
        LOG_FAIL("bip37", "%s from %s — BIP37 disabled, disconnecting",
                 cmd, node->addr_name);
    }
    return true;
}

bool mp_handle_filterload(struct msg_processor *mp, struct p2p_node *node,
                          struct byte_stream *s)
{
    return handle_bip37_rejected(mp, node, s, "filterload");
}

bool mp_handle_filteradd(struct msg_processor *mp, struct p2p_node *node,
                         struct byte_stream *s)
{
    return handle_bip37_rejected(mp, node, s, "filteradd");
}

bool mp_handle_filterclear(struct msg_processor *mp, struct p2p_node *node,
                           struct byte_stream *s)
{
    return handle_bip37_rejected(mp, node, s, "filterclear");
}
