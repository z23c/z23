/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Bounded peer-link frame and registered bundle serving interfaces. */
#ifndef ZCL_CONFIG_STATE_OFFER_LINK_H
#define ZCL_CONFIG_STATE_OFFER_LINK_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The digest is the ROM chunk_tree_root. Each outstanding object request has
 * a fresh nonce and names offset plus range length in total. A PART instead
 * names its offset and the entire object length in total. All parts belong to
 * the requesting live connection and nonce; frame parsing alone proves none. */
#define STATE_OFFER_LINK_FRAME_MAX 65536u
#define STATE_OFFER_LINK_HEADER 64u
#define STATE_OFFER_LINK_PAYLOAD_MAX (STATE_OFFER_LINK_FRAME_MAX - STATE_OFFER_LINK_HEADER)
enum state_offer_link_kind {
    STATE_OFFER_LINK_MANIFEST_REQUEST = 1,
    STATE_OFFER_LINK_CHUNK_REQUEST,
    STATE_OFFER_LINK_MANIFEST_PART,
    STATE_OFFER_LINK_CHUNK_PART,
    STATE_OFFER_LINK_REFUSAL,
    STATE_OFFER_LINK_OFFER_REQUEST,
    STATE_OFFER_LINK_OFFER_REPLY
};
struct state_offer_link_frame {
    enum state_offer_link_kind kind;
    uint64_t nonce;
    uint8_t digest[32];
    uint32_t index, offset, total, size;
    const uint8_t *data;
};
/* The caller owns data and output buffers. Parsing never allocates or reads
 * beyond len; encoding refuses inconsistent or overlong frames. */
bool state_offer_link_encode(const struct state_offer_link_frame *frame, uint8_t *out, size_t cap, size_t *used);
bool state_offer_link_decode(const uint8_t *wire, size_t len, struct state_offer_link_frame *out);
/* Worker-only: read a registered public ROM object into caller-owned scratch.
 * The caller enforces peer concurrency and byte-rate admission before calling. */
bool state_offer_link_read_registered(const char *datadir, enum state_offer_link_kind request_kind,
                                      const uint8_t root[32], uint32_t index,
                                      uint8_t *scratch, uint32_t cap, uint32_t *size);
bool state_offer_link_server_start(const char *datadir, void (*wake)(void));
bool state_offer_link_server_request(uint64_t peer, const uint8_t ip[16], const struct state_offer_link_frame *request);
bool state_offer_link_server_next(uint64_t peer, uint8_t *wire, size_t cap, size_t *size);
void state_offer_link_server_drop(uint64_t peer);
uint64_t state_offer_link_server_peer(void);
void state_offer_link_server_tick(void);
void state_offer_link_server_shutdown(void);
#endif
