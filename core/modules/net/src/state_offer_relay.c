/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Split out of core/modules/net/src/msgprocessor.c to keep that legacy
 * shrink-only file at its baseline line ceiling (tools/lint/
 * file_size_policy_baseline.txt). Pure relocation of the ZRC-0011 phase 1a
 * "zfileaddr" state-offer receive path added in "Carry those offers on the
 * message peers already exchange" — no behaviour change. */

#include "net/state_offer_relay.h"

#include "platform/time_compat.h"
#include "core/serialize.h"
#include "net/net.h"
#include "net/msgprocessor.h"
#include "net/peer_scoring.h"
#include "net/state_offer.h"
#include "util/log_macros.h"

/* One sink per process, mirroring state_offer.c's own g_provider on the send
 * side: there is exactly one msg_processor per running node, and composition
 * registers its sink once at boot (engine/composition/src/
 * state_offer_service.c). Storing it here rather than as two more fields on
 * `struct msg_processor` keeps msgprocessor.c's registration boilerplate out
 * of the legacy shrink-only file entirely. */
static msg_state_offer_record_fn g_state_offer_record;
static void *g_state_offer_record_ctx;

void msg_processor_set_state_offer_record(struct msg_processor *mp,
                                          msg_state_offer_record_fn record,
                                          void *ctx)
{
    (void)mp;
    g_state_offer_record = record;
    g_state_offer_record_ctx = ctx;
}

void zcl_state_offer_relay_handle_zfileaddr_tail(struct msg_processor *mp,
                                                 struct p2p_node *node,
                                                 struct byte_stream *s,
                                                 uint16_t fport,
                                                 const uint8_t fip[16])
{
    /* Bounded before it is read: the batch ceiling is the message's ceiling
     * too, so an oversized tail costs one named refusal rather than a large
     * read. */
    size_t remaining = s->size > s->read_pos ? s->size - s->read_pos : 0;
    if (remaining == 0)
        return;

    uint8_t wire[STATE_OFFER_BATCH_V1_MAX_WIRE_BYTES];
    if (remaining > sizeof(wire)) {
        LOG_WARN("filesvc",
                 "peer %s: zfileaddr tail of %zu bytes exceeds the "
                 "state-offer ceiling — offers dropped",
                 node->addr_name, remaining);
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
                            "zfileaddr: oversized state offer tail");
        return;
    }
    if (!stream_read_bytes(s, wire, remaining))
        return;

    struct state_offer_batch_v1 batch;
    enum state_offer_error error =
        state_offer_batch_v1_decode(&batch, wire, remaining);
    if (error != STATE_OFFER_OK) {
        LOG_WARN("filesvc",
                 "peer %s: state offers refused (%s) — port kept, offers "
                 "dropped", node->addr_name, state_offer_error_string(error));
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
                            "zfileaddr: malformed state offer batch");
        return;
    }

    int64_t now = (int64_t)platform_time_wall_time_t();
    for (uint32_t i = 0; i < batch.count; i++) {
        /* Verified here so the sink never has to wonder, and so a forged row
         * is scored as a proof failure rather than as a parse failure — the
         * two are different peers doing different things. */
        error = state_offer_v1_verify(&batch.offers[i]);
        if (error != STATE_OFFER_OK) {
            LOG_WARN("filesvc",
                     "peer %s: state offer %u failed its own signature (%s)",
                     node->addr_name, i, state_offer_error_string(error));
            peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PROOF,
                                "zfileaddr: state offer signature");
            return; /* one forged row discredits the batch it arrived in */
        }
    }
    if (!g_state_offer_record)
        return;
    for (uint32_t i = 0; i < batch.count; i++)
        g_state_offer_record(&batch.offers[i], fip, fport, (int64_t)node->id,
                             now, g_state_offer_record_ctx);
}
