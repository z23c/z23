/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Keep ZCODE swarm membership derived from live peer sessions. */

#include "config/boot_zcode_swarm_membership.h"

#include "crypto/sha3.h"
#include "net/fast_sync.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/peer_identity.h"
#include "net/peer_scoring.h"
#include "util/log_macros.h"
#include "vcs/package_swarm_node.h"
#include "vcs/zcode_work_node.h"

#include <stdatomic.h>
#include <string.h>

#define ZCODE_SWARM_KEY_DOMAIN "zcl.zcode_swarm_peer.v1"

uint64_t boot_zcode_swarm_peer_id(const struct p2p_node *node)
{
    return (uint64_t)node->id + 1u;
}

bool boot_zcode_swarm_peer_key(const struct p2p_node *node, uint8_t out[33])
{
    char host[ZCL_PEER_HOST_KEY_MAX];
    if (!zcl_peer_host_key(node, host, sizeof(host)))
        return false;
    out[0] = 0x02;
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    sha3_256_write(&h, (const unsigned char *)ZCODE_SWARM_KEY_DOMAIN,
                   sizeof(ZCODE_SWARM_KEY_DOMAIN) - 1);
    sha3_256_write(&h, (const unsigned char *)host, strlen(host));
    sha3_256_finalize(&h, out + 1);
    return true;
}

bool boot_zcode_swarm_eligible(const struct p2p_node *node)
{
    enum peer_state st = atomic_load(&node->state);
    return st >= PEER_HANDSHAKE_COMPLETE && st <= PEER_SNAPSHOT_RECEIVING &&
           !atomic_load(&node->disconnect) && !node->is_feeler &&
           !node->one_shot && peer_supports_fast_sync(node->services);
}

bool boot_zcode_swarm_add_peer(
    struct vcs_swarm_engine *engine, struct vcs_zcode_work_node *work,
    struct p2p_node *node, bool announce_complete)
{
    if (!engine || !work || !boot_zcode_swarm_eligible(node))
        return false;
    uint8_t key[33];
    if (!boot_zcode_swarm_peer_key(node, key))
        return false;
    uint64_t peer = boot_zcode_swarm_peer_id(node);
    bool known = vcs_swarm_engine_peer_known(engine, peer);
    if (!vcs_swarm_engine_peer_add(engine, peer, key) ||
        !vcs_zcode_work_node_peer_add(work, peer))
        return false;
    if (!known || announce_complete)
        (void)vcs_swarm_engine_announce_to(engine, peer);
    return true;
}

void boot_zcode_swarm_sync_membership(
    struct msg_processor *mp, struct vcs_swarm_engine *engine,
    struct vcs_zcode_work_node *work)
{
    struct net_manager *nm = mp ? mp->net_mgr : NULL;
    if (!nm || !engine || !work)
        return;
    zcl_mutex_lock(&nm->cs_nodes);
    for (size_t i = 0; i < nm->num_nodes; i++)
        if (nm->nodes[i])
            (void)boot_zcode_swarm_add_peer(
                engine, work, nm->nodes[i], true);
    uint64_t ids[VCS_SWARM_MAX_PEERS];
    size_t count = vcs_swarm_engine_peer_ids(
        engine, ids, VCS_SWARM_MAX_PEERS);
    for (size_t i = 0; i < count; i++) {
        bool live = false;
        for (size_t j = 0; j < nm->num_nodes; j++) {
            struct p2p_node *node = nm->nodes[j];
            if (node && boot_zcode_swarm_peer_id(node) == ids[i] &&
                boot_zcode_swarm_eligible(node)) {
                live = true;
                break;
            }
        }
        if (!live) {
            vcs_swarm_engine_peer_drop(engine, ids[i]);
            vcs_zcode_work_node_peer_drop(work, ids[i]);
        }
    }
    zcl_mutex_unlock(&nm->cs_nodes);
}

void boot_zcode_swarm_send(struct msg_processor *mp, struct p2p_node *node,
                           const uint8_t *frame, size_t frame_len)
{
    if (!p2p_node_begin_message(node, "zpkgswm",
                                mp->params->pchMessageStart)) {
        LOG_ERROR("net.zcode_swarm", "begin_message failed for peer %lld",
                  (long long)node->id);
        return;
    }
    p2p_node_write_message_data(node, frame, frame_len);
    if (!p2p_node_end_message(node))
        LOG_ERROR("net.zcode_swarm", "end_message failed for peer %lld",
                  (long long)node->id);
}

enum peer_offence boot_zcode_swarm_offence(enum vcs_swarm_penalty penalty)
{
    switch (penalty) {
    case VCS_SWARM_PENALTY_MALFORMED:
        return PEER_OFFENCE_INVALID_MESSAGE;
    case VCS_SWARM_PENALTY_ANNOUNCE_FLOOD:
    case VCS_SWARM_PENALTY_REQUEST_FLOOD:
        return PEER_OFFENCE_FLOOD;
    case VCS_SWARM_PENALTY_REPLAYED_REQUEST:
    case VCS_SWARM_PENALTY_REPLAYED_DATA:
        return PEER_OFFENCE_INVALID_PAYLOAD;
    case VCS_SWARM_PENALTY_UNREQUESTED_DATA:
        return PEER_OFFENCE_UNREQUESTED;
    case VCS_SWARM_PENALTY_INVALID_DATA:
        return PEER_OFFENCE_INVALID_CHUNK;
    case VCS_SWARM_PENALTY_NONE:
    default:
        return PEER_OFFENCE_NONE;
    }
}
