/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Chain-bound short-lived ZID delegation for the ZCODE DHT. */

#ifndef ZCL_VCS_ZCODE_DHT_DELEGATION_H
#define ZCL_VCS_ZCODE_DHT_DELEGATION_H

#include "zid/zid.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_DHT_DELEGATION_TAG "ZIDN"
#define VCS_ZCODE_DHT_DELEGATION_BODY_BYTES 144u
#define VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES \
    (1u + 32u + 8u + 8u + 2u + VCS_ZCODE_DHT_DELEGATION_BODY_BYTES + 64u)
#define VCS_ZCODE_DHT_DELEGATION_DEFAULT_SECONDS UINT64_C(259200)

struct vcs_zcode_dht_delegation {
    struct zid_doc doc;
    uint8_t network_genesis[32];
    uint8_t online_pubkey[32];
    uint8_t noise_static_pubkey[32];
    uint32_t beacon_height;
    uint8_t beacon_hash[32];
    uint64_t not_before;
};

enum vcs_zcode_dht_delegation_error {
    VCS_ZCODE_DHT_DELEGATION_OK = 0,
    VCS_ZCODE_DHT_DELEGATION_NULL,
    VCS_ZCODE_DHT_DELEGATION_SIZE,
    VCS_ZCODE_DHT_DELEGATION_BODY,
    VCS_ZCODE_DHT_DELEGATION_ZERO_KEY,
    VCS_ZCODE_DHT_DELEGATION_WINDOW,
    VCS_ZCODE_DHT_DELEGATION_NOT_YET_VALID,
    VCS_ZCODE_DHT_DELEGATION_SIGNATURE,
    VCS_ZCODE_DHT_DELEGATION_NETWORK,
    VCS_ZCODE_DHT_DELEGATION_NOISE_KEY,
    VCS_ZCODE_DHT_DELEGATION_BEACON,
};

const char *vcs_zcode_dht_delegation_error_string(
    enum vcs_zcode_dht_delegation_error error);

/* Sign canonical zcode_dht_delegation.v1. The enclosing zid_doc contributes
 * master_pubkey, seq, expiry and the master signature. */
enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_sign(
    struct vcs_zcode_dht_delegation *out,
    const uint8_t network_genesis[32],
    const uint8_t online_pubkey[32],
    const uint8_t noise_static_pubkey[32],
    uint32_t beacon_height, const uint8_t beacon_hash[32],
    uint64_t not_before, uint64_t expiry, uint64_t sequence,
    const uint8_t master_seed[32]);

enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_encode(
    const struct vcs_zcode_dht_delegation *delegation,
    uint8_t out[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES]);

enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_decode(
    struct vcs_zcode_dht_delegation *out, const uint8_t *wire,
    size_t wire_len);

/* Cryptographic and structural verification. Chain projection checks remain
 * a caller obligation: the caller must additionally require doc.master_pubkey
 * ACTIVE and beacon_height/hash equal to the selected active chain. Optional
 * expected values are checked when non-NULL/non-zero. */
enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_verify(
    const struct vcs_zcode_dht_delegation *delegation,
    const uint8_t expected_genesis[32],
    const uint8_t expected_noise_static[32],
    uint32_t expected_beacon_height,
    const uint8_t expected_beacon_hash[32], uint64_t now_unix);

/* Stable node identity: genesis + active master key + the finality-delayed
 * beacon block. Renewals and online-key rotations leave this unchanged. */
bool vcs_zcode_dht_delegation_node_id(
    uint8_t out[32], const struct vcs_zcode_dht_delegation *delegation);

#endif /* ZCL_VCS_ZCODE_DHT_DELEGATION_H */
