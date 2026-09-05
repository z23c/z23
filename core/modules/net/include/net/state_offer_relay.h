/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: The "zfileaddr" state-offer receive path, split out of
 * msgprocessor.c to keep that legacy shrink-only file at its baseline line
 * ceiling (tools/lint/file_size_policy_baseline.txt).
 *
 * ZRC-0011 phase 1a. See net/state_offer.h for the codec and the trust
 * boundary in full; this header only exposes the one call site msgprocessor.c
 * needs after "zfileaddr"'s two-byte port is read. */

#ifndef ZCL_NET_STATE_OFFER_RELAY_H
#define ZCL_NET_STATE_OFFER_RELAY_H

#include <stddef.h>
#include <stdint.h>

struct msg_processor;
struct p2p_node;
struct byte_stream;

/* Handles the optional signed offer batch a peer may APPEND after
 * "zfileaddr"'s two-byte port: bounds the tail against the batch wire
 * ceiling before it is read, decodes and verifies it under the codec's
 * fail-closed rules, and hands each verified row to the msg_processor's
 * registered state_offer_record sink. Absent bytes mean "a file service,
 * contents unstated" and are never a violation; a batch that will not parse
 * or a row whose signature will not verify is SCORED, not address-banned —
 * every inbound Tor-forwarded peer arrives from the same loopback source, so
 * an address ban for one bad batch would shut the whole inbound front door
 * (see the ban-path note in net.c).
 *
 * `fport`/`fip` are the endpoint a consumer would dial: the message's own
 * port field and the peer's live-connection IP, exactly as msgprocessor.c
 * already resolved them for the file-service save above this call. */
void zcl_state_offer_relay_handle_zfileaddr_tail(struct msg_processor *mp,
                                                 struct p2p_node *node,
                                                 struct byte_stream *s,
                                                 uint16_t fport,
                                                 const uint8_t fip[16]);

#endif /* ZCL_NET_STATE_OFFER_RELAY_H */
