/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Authenticated session membership for the ZCODE swarm adapter. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_SWARM_MEMBERSHIP_H
#define ZCL_CONFIG_BOOT_ZCODE_SWARM_MEMBERSHIP_H

#include "net/peer_scoring.h"
#include "vcs/package_swarm_node.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct msg_processor;
struct p2p_node;
struct vcs_swarm_engine;
struct vcs_zcode_work_node;

uint64_t boot_zcode_swarm_peer_id(const struct p2p_node *node);
bool boot_zcode_swarm_peer_key(const struct p2p_node *node, uint8_t out[33]);
bool boot_zcode_swarm_eligible(const struct p2p_node *node);
bool boot_zcode_swarm_add_peer(
    struct vcs_swarm_engine *engine, struct vcs_zcode_work_node *work,
    struct p2p_node *node, bool announce_complete);
void boot_zcode_swarm_sync_membership(
    struct msg_processor *mp, struct vcs_swarm_engine *engine,
    struct vcs_zcode_work_node *work);
void boot_zcode_swarm_send(struct msg_processor *mp, struct p2p_node *node,
                           const uint8_t *frame, size_t frame_len);
enum peer_offence boot_zcode_swarm_offence(enum vcs_swarm_penalty penalty);

#endif /* ZCL_CONFIG_BOOT_ZCODE_SWARM_MEMBERSHIP_H */
