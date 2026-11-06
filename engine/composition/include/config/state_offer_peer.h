/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Integrate state discovery and transfers with public peer lifecycle events. */
#ifndef ZCL_STATE_OFFER_PEER_H
#define ZCL_STATE_OFFER_PEER_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "net/protocol.h"
struct msg_processor;
struct p2p_node;
bool state_offer_peer_start(const char *datadir);
void state_offer_peer_shutdown(void);
bool state_offer_peer_begin(uint64_t peer);
void state_offer_peer_end(uint64_t peer);
bool state_offer_peer_frame(struct msg_processor *mp, struct p2p_node *node,
                            const uint8_t *wire, size_t len);
/* Only the message owner tick discovers offers and writes the offer store. */
void state_offer_peer_tick(struct msg_processor *mp, struct p2p_node *node);
/* Supervisor may drain owned frames, never mutate discovery or offer state. */
void state_offer_peer_pump(struct msg_processor *mp);
#endif
