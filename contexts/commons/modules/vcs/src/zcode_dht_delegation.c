/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Chain-bound short-lived ZID delegation for the ZCODE DHT. */

#include "vcs/zcode_dht_delegation.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "vcs/zcode_dht.h"
#include "zid/zendp.h"

#include <string.h>

static const char *roster_error_string(
    enum vcs_zcode_dht_delegation_error error)
{
    switch (error) {
    case VCS_ZCODE_DHT_DELEGATION_ROSTER_MODE: return "roster-mode-unsupported";
    case VCS_ZCODE_DHT_DELEGATION_MODE_UNKNOWN: return "unknown-delegation-mode";
    case VCS_ZCODE_DHT_DELEGATION_PROJECTION: return "projection-mismatch";
    default: return "unknown";
    }
}

const char *vcs_zcode_dht_delegation_error_string(
    enum vcs_zcode_dht_delegation_error error)
{
    switch (error) {
    case VCS_ZCODE_DHT_DELEGATION_OK: return "ok";
    case VCS_ZCODE_DHT_DELEGATION_NULL: return "null-argument";
    case VCS_ZCODE_DHT_DELEGATION_SIZE: return "wire-size";
    case VCS_ZCODE_DHT_DELEGATION_BODY: return "delegation-body";
    case VCS_ZCODE_DHT_DELEGATION_ZERO_KEY: return "zero-key";
    case VCS_ZCODE_DHT_DELEGATION_WINDOW: return "validity-window";
    case VCS_ZCODE_DHT_DELEGATION_NOT_YET_VALID: return "not-yet-valid";
    case VCS_ZCODE_DHT_DELEGATION_SIGNATURE: return "master-signature";
    case VCS_ZCODE_DHT_DELEGATION_NETWORK: return "wrong-network";
    case VCS_ZCODE_DHT_DELEGATION_NOISE_KEY: return "noise-key-mismatch";
    case VCS_ZCODE_DHT_DELEGATION_BEACON: return "beacon-mismatch";
    case VCS_ZCODE_DHT_DELEGATION_EXPIRED: return "expired";
    default: return roster_error_string(error);
    }
    return "unknown";
}

static void delegation_body(uint8_t out[VCS_ZCODE_DHT_DELEGATION_BODY_BYTES],
                            const uint8_t genesis[32],
                            const uint8_t online[32],
                            const uint8_t noise_key[32], uint32_t height,
                            const uint8_t hash[32], uint64_t not_before)
{
    size_t off = 0;
    memcpy(out + off, VCS_ZCODE_DHT_DELEGATION_TAG, 4); off += 4;
    memcpy(out + off, genesis, 32); off += 32;
    memcpy(out + off, online, 32); off += 32;
    memcpy(out + off, noise_key, 32); off += 32;
    zcl_write_u32_le(out + off, height); off += 4;
    memcpy(out + off, hash, 32); off += 32;
    zcl_write_u64_le(out + off, not_before);
}

static enum vcs_zcode_dht_delegation_error delegation_decode_body(
    struct vcs_zcode_dht_delegation *out)
{
    if (out->doc.body_len != VCS_ZCODE_DHT_DELEGATION_BODY_BYTES ||
        memcmp(out->doc.body, VCS_ZCODE_DHT_DELEGATION_TAG, 4) != 0)
        return VCS_ZCODE_DHT_DELEGATION_BODY;
    size_t off = 4;
    memcpy(out->network_genesis, out->doc.body + off, 32); off += 32;
    memcpy(out->online_pubkey, out->doc.body + off, 32); off += 32;
    memcpy(out->noise_static_pubkey, out->doc.body + off, 32); off += 32;
    out->beacon_height = zcl_read_u32_le(out->doc.body + off); off += 4;
    memcpy(out->beacon_hash, out->doc.body + off, 32); off += 32;
    out->not_before = zcl_read_u64_le(out->doc.body + off);
    return VCS_ZCODE_DHT_DELEGATION_OK;
}

enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_sign(
    struct vcs_zcode_dht_delegation *out,
    const uint8_t network_genesis[32], const uint8_t online_pubkey[32],
    const uint8_t noise_static_pubkey[32], uint32_t beacon_height,
    const uint8_t beacon_hash[32], uint64_t not_before, uint64_t expiry,
    uint64_t sequence, const uint8_t master_seed[32])
{
    if (!out || !network_genesis || !online_pubkey ||
        !noise_static_pubkey || !beacon_hash || !master_seed)
        return VCS_ZCODE_DHT_DELEGATION_NULL;
    memset(out, 0, sizeof(*out));
    if (!zcl_bytes_any_set(network_genesis, 32) || !zcl_bytes_any_set(online_pubkey, 32) ||
        !zcl_bytes_any_set(noise_static_pubkey, 32) || !zcl_bytes_any_set(beacon_hash, 32) ||
        beacon_height == 0)
        return VCS_ZCODE_DHT_DELEGATION_ZERO_KEY;
    if (zendp_window_check(not_before, expiry) != ZENDP_WINDOW_OK)
        return VCS_ZCODE_DHT_DELEGATION_WINDOW;
    uint8_t body[VCS_ZCODE_DHT_DELEGATION_BODY_BYTES];
    delegation_body(body, network_genesis, online_pubkey,
                    noise_static_pubkey, beacon_height, beacon_hash,
                    not_before);
    if (!zid_doc_sign(&out->doc, body, sizeof(body), sequence, expiry,
                      master_seed))
        return VCS_ZCODE_DHT_DELEGATION_SIGNATURE;
    return delegation_decode_body(out);
}

/* Mode dispatch is explicit: a value that is neither CHAIN nor ROSTER is
 * refused by name, a known-but-wrong mode is a body mismatch. */
static enum vcs_zcode_dht_delegation_error mode_refusal(uint8_t mode)
{
    return mode == VCS_ZCODE_DHT_DELEGATION_MODE_CHAIN ||
                   mode == VCS_ZCODE_DHT_DELEGATION_MODE_ROSTER
        ? VCS_ZCODE_DHT_DELEGATION_BODY
        : VCS_ZCODE_DHT_DELEGATION_MODE_UNKNOWN;
}

static enum vcs_zcode_dht_delegation_error chain_precheck(
    const struct vcs_zcode_dht_delegation *d)
{
    /* Roster mode is codec-only until a later unit adds acceptance. */
    if (d->mode == VCS_ZCODE_DHT_DELEGATION_MODE_ROSTER)
        return VCS_ZCODE_DHT_DELEGATION_ROSTER_MODE;
    if (d->mode != VCS_ZCODE_DHT_DELEGATION_MODE_CHAIN)
        return VCS_ZCODE_DHT_DELEGATION_MODE_UNKNOWN;
    if (d->doc.body_len != VCS_ZCODE_DHT_DELEGATION_BODY_BYTES ||
        memcmp(d->doc.body, VCS_ZCODE_DHT_DELEGATION_TAG, 4) != 0)
        return VCS_ZCODE_DHT_DELEGATION_BODY;
    return VCS_ZCODE_DHT_DELEGATION_OK;
}

enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_encode(
    const struct vcs_zcode_dht_delegation *delegation,
    uint8_t out[VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES])
{
    if (!delegation || !out) return VCS_ZCODE_DHT_DELEGATION_NULL;
    if (delegation->mode != VCS_ZCODE_DHT_DELEGATION_MODE_CHAIN)
        return mode_refusal(delegation->mode);
    if (delegation->doc.body_len != VCS_ZCODE_DHT_DELEGATION_BODY_BYTES)
        return VCS_ZCODE_DHT_DELEGATION_BODY;
    size_t n = zid_doc_encode(out, VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES,
                              &delegation->doc);
    return n == VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES
        ? VCS_ZCODE_DHT_DELEGATION_OK : VCS_ZCODE_DHT_DELEGATION_SIZE;
}

enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_decode(
    struct vcs_zcode_dht_delegation *out, const uint8_t *wire,
    size_t wire_len)
{
    if (!out || !wire) return VCS_ZCODE_DHT_DELEGATION_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES)
        return VCS_ZCODE_DHT_DELEGATION_SIZE;
    if (!zid_doc_decode(&out->doc, wire, wire_len))
        return VCS_ZCODE_DHT_DELEGATION_BODY;
    return delegation_decode_body(out);
}

static bool chain_fields_present(const struct vcs_zcode_dht_delegation *d)
{
    return zcl_bytes_any_set(d->doc.master_pubkey, 32) &&
           zcl_bytes_any_set(d->network_genesis, 32) &&
           zcl_bytes_any_set(d->online_pubkey, 32) &&
           zcl_bytes_any_set(d->noise_static_pubkey, 32) &&
           zcl_bytes_any_set(d->beacon_hash, 32) && d->beacon_height != 0;
}

/* The signed doc.body is the only authority; a cached field that differs
 * from it is refused, as in roster mode. */
static bool chain_projection_matches(const struct vcs_zcode_dht_delegation *d)
{
    struct vcs_zcode_dht_delegation p;
    memset(&p, 0, sizeof(p));
    p.doc.body_len = d->doc.body_len;
    memcpy(p.doc.body, d->doc.body, sizeof(p.doc.body));
    return delegation_decode_body(&p) == VCS_ZCODE_DHT_DELEGATION_OK &&
           memcmp(p.network_genesis, d->network_genesis, 32) == 0 &&
           memcmp(p.online_pubkey, d->online_pubkey, 32) == 0 &&
           memcmp(p.noise_static_pubkey, d->noise_static_pubkey, 32) == 0 &&
           p.beacon_height == d->beacon_height &&
           memcmp(p.beacon_hash, d->beacon_hash, 32) == 0 &&
           p.not_before == d->not_before;
}

static enum vcs_zcode_dht_delegation_error chain_structure_check(
    const struct vcs_zcode_dht_delegation *d)
{
    if (!chain_fields_present(d))
        return VCS_ZCODE_DHT_DELEGATION_ZERO_KEY;
    if (!chain_projection_matches(d))
        return VCS_ZCODE_DHT_DELEGATION_PROJECTION;
    return VCS_ZCODE_DHT_DELEGATION_OK;
}

static enum vcs_zcode_dht_delegation_error delegation_expected_chain_check(
    const struct vcs_zcode_dht_delegation *delegation,
    const uint8_t expected_genesis[32],
    const uint8_t expected_noise_static[32],
    uint32_t expected_beacon_height,
    const uint8_t expected_beacon_hash[32])
{
    if (expected_genesis &&
        memcmp(delegation->network_genesis, expected_genesis, 32) != 0)
        return VCS_ZCODE_DHT_DELEGATION_NETWORK;
    if (expected_noise_static &&
        memcmp(delegation->noise_static_pubkey, expected_noise_static, 32) != 0)
        return VCS_ZCODE_DHT_DELEGATION_NOISE_KEY;
    if ((expected_beacon_height != 0 &&
         delegation->beacon_height != expected_beacon_height) ||
        (expected_beacon_hash &&
         memcmp(delegation->beacon_hash, expected_beacon_hash, 32) != 0))
        return VCS_ZCODE_DHT_DELEGATION_BEACON;
    return VCS_ZCODE_DHT_DELEGATION_OK;
}

enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_verify(
    const struct vcs_zcode_dht_delegation *delegation,
    const uint8_t expected_genesis[32],
    const uint8_t expected_noise_static[32],
    uint32_t expected_beacon_height,
    const uint8_t expected_beacon_hash[32], uint64_t now_unix)
{
    if (!delegation) return VCS_ZCODE_DHT_DELEGATION_NULL;
    enum vcs_zcode_dht_delegation_error pre = chain_precheck(delegation);
    if (pre != VCS_ZCODE_DHT_DELEGATION_OK) return pre;
    enum vcs_zcode_dht_delegation_error st = chain_structure_check(delegation);
    if (st != VCS_ZCODE_DHT_DELEGATION_OK) return st;
    if (zendp_window_check(delegation->not_before,
                           delegation->doc.expiry) != ZENDP_WINDOW_OK)
        return VCS_ZCODE_DHT_DELEGATION_WINDOW;
    if (now_unix < delegation->not_before)
        return VCS_ZCODE_DHT_DELEGATION_NOT_YET_VALID;
    /* Named separately from a signature failure so a caller can tell
     * "renew or evict this" (expected lifecycle) from "reject this, it is
     * tampered or corrupt" (never renew/evict on this path). */
    if (now_unix >= delegation->doc.expiry)
        return VCS_ZCODE_DHT_DELEGATION_EXPIRED;
    if (!zid_doc_verify(&delegation->doc, now_unix))
        return VCS_ZCODE_DHT_DELEGATION_SIGNATURE;
    return delegation_expected_chain_check(delegation, expected_genesis,
                                           expected_noise_static,
                                           expected_beacon_height,
                                           expected_beacon_hash);
}

bool vcs_zcode_dht_delegation_node_id(
    uint8_t out[32], const struct vcs_zcode_dht_delegation *delegation)
{
    if (!out || !delegation) return false;
    if (delegation->mode == VCS_ZCODE_DHT_DELEGATION_MODE_CHAIN)
        return vcs_zcode_dht_node_id(out, delegation->network_genesis,
                                     delegation->doc.master_pubkey,
                                     delegation->beacon_hash);
    if (delegation->mode != VCS_ZCODE_DHT_DELEGATION_MODE_ROSTER)
        return false;
    return vcs_zcode_dht_roster_node_id(out, delegation->network_genesis,
                                        delegation->doc.master_pubkey);
}

/* ---- Roster mode (codec only). Chain code above is untouched. ---- */

#define ROSTER_DOMAIN_BYTES (sizeof(VCS_ZCODE_DHT_DELEGATION_ROSTER_DOMAIN) - 1)
static_assert(ROSTER_DOMAIN_BYTES + 1 + 32 + 32 + 32 + 8 ==
                  VCS_ZCODE_DHT_DELEGATION_ROSTER_BODY_BYTES,
              "roster body layout");

static bool roster_window_ok(uint64_t not_before, uint64_t expiry)
{
    return expiry > not_before &&
           expiry - not_before <= VCS_ZCODE_DHT_DELEGATION_ROSTER_MAX_SECONDS;
}

static void roster_body(
    uint8_t out[VCS_ZCODE_DHT_DELEGATION_ROSTER_BODY_BYTES],
    const uint8_t genesis[32], const uint8_t online[32],
    const uint8_t noise_key[32], uint64_t not_before)
{
    size_t off = 0;
    memcpy(out + off, VCS_ZCODE_DHT_DELEGATION_ROSTER_DOMAIN,
           ROSTER_DOMAIN_BYTES);
    off += ROSTER_DOMAIN_BYTES;
    out[off++] = VCS_ZCODE_DHT_DELEGATION_MODE_ROSTER;
    memcpy(out + off, genesis, 32); off += 32;
    memcpy(out + off, online, 32); off += 32;
    memcpy(out + off, noise_key, 32); off += 32;
    zcl_write_u64_le(out + off, not_before);
}

static enum vcs_zcode_dht_delegation_error roster_decode_body(
    struct vcs_zcode_dht_delegation *out)
{
    if (out->doc.body_len != VCS_ZCODE_DHT_DELEGATION_ROSTER_BODY_BYTES ||
        memcmp(out->doc.body, VCS_ZCODE_DHT_DELEGATION_ROSTER_DOMAIN,
               ROSTER_DOMAIN_BYTES) != 0 ||
        out->doc.body[ROSTER_DOMAIN_BYTES] !=
            VCS_ZCODE_DHT_DELEGATION_MODE_ROSTER)
        return VCS_ZCODE_DHT_DELEGATION_BODY;
    size_t off = ROSTER_DOMAIN_BYTES + 1;
    memcpy(out->network_genesis, out->doc.body + off, 32); off += 32;
    memcpy(out->online_pubkey, out->doc.body + off, 32); off += 32;
    memcpy(out->noise_static_pubkey, out->doc.body + off, 32); off += 32;
    out->not_before = zcl_read_u64_le(out->doc.body + off);
    out->beacon_height = 0;
    memset(out->beacon_hash, 0, 32);
    out->mode = VCS_ZCODE_DHT_DELEGATION_MODE_ROSTER;
    return VCS_ZCODE_DHT_DELEGATION_OK;
}

enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_roster_sign(
    struct vcs_zcode_dht_delegation *out,
    const uint8_t network_genesis[32], const uint8_t online_pubkey[32],
    const uint8_t noise_static_pubkey[32], uint32_t beacon_height,
    const uint8_t *beacon_hash, uint64_t not_before, uint64_t expiry,
    uint64_t sequence, const uint8_t master_seed[32])
{
    if (!out || !network_genesis || !online_pubkey ||
        !noise_static_pubkey || !master_seed)
        return VCS_ZCODE_DHT_DELEGATION_NULL;
    memset(out, 0, sizeof(*out));
    if (beacon_height != 0 ||
        (beacon_hash && zcl_bytes_any_set(beacon_hash, 32)))
        return VCS_ZCODE_DHT_DELEGATION_BEACON;
    if (!zcl_bytes_any_set(network_genesis, 32) ||
        !zcl_bytes_any_set(online_pubkey, 32) ||
        !zcl_bytes_any_set(noise_static_pubkey, 32))
        return VCS_ZCODE_DHT_DELEGATION_ZERO_KEY;
    if (!roster_window_ok(not_before, expiry))
        return VCS_ZCODE_DHT_DELEGATION_WINDOW;
    uint8_t body[VCS_ZCODE_DHT_DELEGATION_ROSTER_BODY_BYTES];
    roster_body(body, network_genesis, online_pubkey, noise_static_pubkey,
                not_before);
    if (!zid_doc_sign(&out->doc, body, sizeof(body), sequence, expiry,
                      master_seed))
        return VCS_ZCODE_DHT_DELEGATION_SIGNATURE;
    return roster_decode_body(out);
}

enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_roster_encode(
    const struct vcs_zcode_dht_delegation *delegation,
    uint8_t out[VCS_ZCODE_DHT_DELEGATION_ROSTER_WIRE_BYTES])
{
    if (!delegation || !out) return VCS_ZCODE_DHT_DELEGATION_NULL;
    if (delegation->mode != VCS_ZCODE_DHT_DELEGATION_MODE_ROSTER)
        return mode_refusal(delegation->mode);
    if (delegation->doc.body_len !=
            VCS_ZCODE_DHT_DELEGATION_ROSTER_BODY_BYTES)
        return VCS_ZCODE_DHT_DELEGATION_BODY;
    size_t n = zid_doc_encode(out, VCS_ZCODE_DHT_DELEGATION_ROSTER_WIRE_BYTES,
                              &delegation->doc);
    return n == VCS_ZCODE_DHT_DELEGATION_ROSTER_WIRE_BYTES
        ? VCS_ZCODE_DHT_DELEGATION_OK : VCS_ZCODE_DHT_DELEGATION_SIZE;
}

enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_roster_decode(
    struct vcs_zcode_dht_delegation *out, const uint8_t *wire,
    size_t wire_len)
{
    if (!out || !wire) return VCS_ZCODE_DHT_DELEGATION_NULL;
    memset(out, 0, sizeof(*out));
    if (wire_len != VCS_ZCODE_DHT_DELEGATION_ROSTER_WIRE_BYTES)
        return VCS_ZCODE_DHT_DELEGATION_SIZE;
    if (!zid_doc_decode(&out->doc, wire, wire_len))
        return VCS_ZCODE_DHT_DELEGATION_BODY;
    return roster_decode_body(out);
}

/* The signed doc.body is the only authority. Re-derive the canonical
 * projection from it and require every cached field to equal it. */
static bool roster_projection_matches(
    const struct vcs_zcode_dht_delegation *d)
{
    struct vcs_zcode_dht_delegation p;
    memset(&p, 0, sizeof(p));
    p.doc.body_len = d->doc.body_len;
    memcpy(p.doc.body, d->doc.body, sizeof(p.doc.body));
    return roster_decode_body(&p) == VCS_ZCODE_DHT_DELEGATION_OK &&
           memcmp(p.network_genesis, d->network_genesis, 32) == 0 &&
           memcmp(p.online_pubkey, d->online_pubkey, 32) == 0 &&
           memcmp(p.noise_static_pubkey, d->noise_static_pubkey, 32) == 0 &&
           p.not_before == d->not_before;
}

static enum vcs_zcode_dht_delegation_error roster_structure_check(
    const struct vcs_zcode_dht_delegation *d)
{
    if (d->mode != VCS_ZCODE_DHT_DELEGATION_MODE_ROSTER)
        return mode_refusal(d->mode);
    if (d->doc.body_len != VCS_ZCODE_DHT_DELEGATION_ROSTER_BODY_BYTES ||
        memcmp(d->doc.body, VCS_ZCODE_DHT_DELEGATION_ROSTER_DOMAIN,
               ROSTER_DOMAIN_BYTES) != 0)
        return VCS_ZCODE_DHT_DELEGATION_BODY;
    if (d->beacon_height != 0 || zcl_bytes_any_set(d->beacon_hash, 32))
        return VCS_ZCODE_DHT_DELEGATION_BEACON;
    if (!roster_projection_matches(d))
        return VCS_ZCODE_DHT_DELEGATION_PROJECTION;
    if (!zcl_bytes_any_set(d->doc.master_pubkey, 32) ||
        !zcl_bytes_any_set(d->network_genesis, 32) ||
        !zcl_bytes_any_set(d->online_pubkey, 32) ||
        !zcl_bytes_any_set(d->noise_static_pubkey, 32))
        return VCS_ZCODE_DHT_DELEGATION_ZERO_KEY;
    if (!roster_window_ok(d->not_before, d->doc.expiry))
        return VCS_ZCODE_DHT_DELEGATION_WINDOW;
    return VCS_ZCODE_DHT_DELEGATION_OK;
}

enum vcs_zcode_dht_delegation_error vcs_zcode_dht_delegation_roster_check(
    const struct vcs_zcode_dht_delegation *delegation,
    const uint8_t expected_genesis[32],
    const uint8_t expected_noise_static[32], uint64_t now_unix)
{
    if (!delegation) return VCS_ZCODE_DHT_DELEGATION_NULL;
    enum vcs_zcode_dht_delegation_error e =
        roster_structure_check(delegation);
    if (e != VCS_ZCODE_DHT_DELEGATION_OK) return e;
    if (now_unix < delegation->not_before)
        return VCS_ZCODE_DHT_DELEGATION_NOT_YET_VALID;
    if (now_unix >= delegation->doc.expiry)
        return VCS_ZCODE_DHT_DELEGATION_EXPIRED;
    if (!zid_doc_verify(&delegation->doc, now_unix))
        return VCS_ZCODE_DHT_DELEGATION_SIGNATURE;
    if (expected_genesis &&
        memcmp(delegation->network_genesis, expected_genesis, 32) != 0)
        return VCS_ZCODE_DHT_DELEGATION_NETWORK;
    if (expected_noise_static &&
        memcmp(delegation->noise_static_pubkey, expected_noise_static, 32) != 0)
        return VCS_ZCODE_DHT_DELEGATION_NOISE_KEY;
    return VCS_ZCODE_DHT_DELEGATION_OK;
}
