/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Stable event-log payload schemas.
 *
 * These helpers serialize protocol payloads in little-endian byte order.
 * The structs are an in-process convenience only; never fwrite them
 * directly because C padding is not a wire format.
 */

#ifndef ZCL_STORAGE_EVENT_LOG_PAYLOADS_H
#define ZCL_STORAGE_EVENT_LOG_PAYLOADS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define EV_PEER_ONION_MAX 62u
#define EV_TX_ADMIT_MEMPOOL_FIXED_LEN 56u
#define EV_TX_REMOVE_MEMPOOL_LEN 40u
#define EV_PEER_OBSERVED_FIXED_LEN 40u
#define EV_PEER_DROPPED_LEN 24u
#define EV_WALLET_PAYLOAD_MAX 256u
#define EV_WALLET_ADDRESS_MAX 128u
#define EV_WALLET_LABEL_MAX 96u
#define EV_WALLET_KEY_ADD_FIXED_LEN 32u
#define EV_WALLET_ADDR_DERIVED_LEN 48u
#define EV_WALLET_TX_SEEN_LEN 52u
#define EV_WALLET_NOTE_DECRYPTED_LEN 80u
#define EV_WALLET_UTXO_SEEN_LEN 72u
#define EV_CONTACT_ADDRESS_MAX 64u
#define EV_CONTACT_NAME_MAX 64u
#define EV_CONTACT_SET_FIXED_LEN 8u
#define EV_CONTACT_TOUCHED_LEN 8u
#define EV_CONTACT_DELETE_FIXED_LEN 8u
#define EV_ONION_ANNOUNCEMENT_FIXED_LEN 8u
#define EV_ONION_ADDRESS_MAX 96u
#define EV_ONION_SCRIPT_HEX_MAX 250u
#define EV_HODL_SNAPSHOT_LEN 32u
#define EV_PEER_SESSION_CLOSED_LEN 76u
#define EV_NET_FORK_TIP_HEX_MAX 64u
#define EV_NET_FORK_OBSERVED_FIXED_LEN 32u
/* Census UA hard cap (bytes). Any longer input is truncated to this length
 * WITH the ua_overflow flag set — never silently. */
#define EV_CENSUS_UA_MAX 256u
#define EV_NODE_CENSUS_OBSERVED_FIXED_LEN 52u

struct ev_tx_admit_mempool {
    uint8_t  txid[32];
    int64_t  fee;
    uint32_t size_bytes;
    uint32_t weight;
    uint32_t admitted_unix;
    uint8_t  priority_class;
    uint8_t  reserved[3];
    const uint8_t *raw_tx;
    size_t raw_tx_len;
};

struct ev_tx_remove_mempool {
    uint8_t  txid[32];
    uint8_t  reason;
    uint8_t  reserved[7];
};

struct ev_peer_observed {
    uint8_t  ip_v4_or_v6[16];
    uint16_t port;
    uint8_t  is_onion;
    uint8_t  reserved;
    uint64_t services_bitmap;
    uint32_t observed_unix;
    int32_t  height_hint;
    uint8_t  onion_len;
    char     onion[EV_PEER_ONION_MAX];
};

struct ev_peer_dropped {
    uint8_t  ip_v4_or_v6[16];
    uint16_t port;
    uint8_t  reason;
    uint8_t  reserved[5];
};

struct ev_wallet_key_add {
    uint8_t  pubkey_hash[20];  /* HASH160(pubkey); public metadata. */
    uint8_t  reserved[4];
    uint32_t created_unix;
    uint8_t  address_len;
    uint8_t  label_len;
    uint8_t  reserved2[2];
    const char *address;
    const char *label;
};

struct ev_wallet_addr_derived {
    uint8_t  pubkey_hash[20];
    uint8_t  derived_pubkey_hash[20];
    uint32_t derivation_index;
    uint32_t derived_unix;
};

struct ev_wallet_tx_seen {
    uint8_t  txid[32];
    int32_t  block_height;
    int64_t  fee;
    uint8_t  from_me;
    uint8_t  reserved[7];
};

struct ev_wallet_note_decrypted {
    uint8_t  txid[32];
    uint32_t output_index;
    int32_t  block_height;
    int64_t  value;
    uint8_t  cm[32];           /* Note commitment; public. */
};

struct ev_wallet_utxo_seen {
    uint8_t  txid[32];
    uint32_t vout;
    int64_t  value;
    uint8_t  address_hash[20];
    int32_t  height;
    uint8_t  is_coinbase;
    uint8_t  reserved[3];
};

struct ev_contact_set {
    uint8_t address_len;
    uint8_t name_len;
    uint8_t reserved[6];
    const char *address;
    const char *name;
};

struct ev_contact_touched {
    uint8_t address_len;
    uint8_t reserved[3];
    uint32_t last_used_unix;
    const char *address;
};

struct ev_contact_delete {
    uint8_t address_len;
    uint8_t reserved[7];
    const char *address;
};

struct ev_onion_announcement {
    uint32_t announced_at_unix;
    uint8_t onion_addr_len;
    uint8_t script_hex_len;
    uint8_t reserved[2];
    const char *onion_address;
    const char *script_hex;
};

struct ev_hodl_snapshot {
    int32_t height;
    uint32_t time_unix;
    int64_t total_zat;
    int64_t older_1y_zat;
    double older_1y_pct;
};

/* EV_PEER_SESSION_CLOSED — a peer session's final reputation + transfer
 * totals, banked at disconnect. Fixed 76-byte wire form (LE):
 *   [16B ip][2B port][1B reason][1B reserved]
 *   [4B duration_secs][8B bytes_in][8B bytes_out]
 *   [8B headers_delivered][8B blocks_delivered]
 *   [4B bandwidth_score][8B avg_latency_us][8B last_useful_time] */
struct ev_peer_session_closed {
    uint8_t  ip_v4_or_v6[16];
    uint16_t port;
    uint8_t  reason;
    uint8_t  reserved;
    uint32_t duration_secs;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t headers_delivered;
    uint64_t blocks_delivered;
    uint32_t bandwidth_score;
    int64_t  avg_latency_us;
    int64_t  last_useful_time;
};

/* EV_NET_FORK_OBSERVED — a network fork observation (two clusters at one
 * height). Fixed 32-byte prefix (LE) + two variable hex tip-hash strings:
 *   [8B height][8B observed_unix][4B num_clusters][4B count_a][4B count_b]
 *   [1B hash_a_len][1B hash_b_len][2B reserved][hash_a][hash_b] */
struct ev_net_fork_observed {
    int64_t  height;
    int64_t  observed_unix;
    uint32_t num_clusters;
    uint32_t count_a;
    uint32_t count_b;
    uint8_t  hash_a_len;
    uint8_t  hash_b_len;
    char     tip_hash_a[EV_NET_FORK_TIP_HEX_MAX + 1];
    char     tip_hash_b[EV_NET_FORK_TIP_HEX_MAX + 1];
};

/* EV_NODE_CENSUS_OBSERVED — one node-identity observation from a version
 * handshake (real peer OR crawler contact). Fixed 52-byte prefix (LE) + a
 * variable, pedantically bounded user-agent string:
 *   [16B ip][2B port][1B source][1B success][1B ua_overflow][1B reserved]
 *   [4B protocol_version][8B services][8B reported_height][8B observed_unix]
 *   [2B ua_len][ua bytes]
 * `source`: 0=real peer, 1=crawler. `success`: 1=completed handshake carrying
 * version data, 0=dial failed (fail observations only bump an EXISTING row's
 * fail counter — they never insert). `ua_overflow`: the UA was longer than
 * EV_CENSUS_UA_MAX and was truncated (never silently). */
enum {
    EV_CENSUS_SOURCE_PEER    = 0,
    EV_CENSUS_SOURCE_CRAWLER = 1,
};

struct ev_node_census_observed {
    uint8_t  ip_v4_or_v6[16];
    uint16_t port;
    uint8_t  source;
    uint8_t  success;
    uint8_t  ua_overflow;
    uint8_t  reserved;
    int32_t  protocol_version;
    uint64_t services;
    int64_t  reported_height;
    int64_t  observed_unix;
    uint16_t ua_len;
    char     user_agent[EV_CENSUS_UA_MAX + 1];  /* NUL-terminated for readers */
};

static inline void ev_put_u16_le(uint8_t *dst, uint16_t v)
{
    dst[0] = (uint8_t)(v & 0xFFu);
    dst[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static inline uint16_t ev_get_u16_le(const uint8_t *src)
{
    return (uint16_t)((uint16_t)src[0] | ((uint16_t)src[1] << 8));
}

static inline void ev_put_u32_le(uint8_t *dst, uint32_t v)
{
    dst[0] = (uint8_t)(v & 0xFFu);
    dst[1] = (uint8_t)((v >> 8) & 0xFFu);
    dst[2] = (uint8_t)((v >> 16) & 0xFFu);
    dst[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static inline uint32_t ev_get_u32_le(const uint8_t *src)
{
    return (uint32_t)src[0]
        | ((uint32_t)src[1] << 8)
        | ((uint32_t)src[2] << 16)
        | ((uint32_t)src[3] << 24);
}

static inline void ev_put_u64_le(uint8_t *dst, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        dst[i] = (uint8_t)((v >> (i * 8)) & 0xFFu);
}

static inline uint64_t ev_get_u64_le(const uint8_t *src)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)src[i] << (i * 8);
    return v;
}

static inline void ev_put_double_le(uint8_t *dst, double v)
{
    uint64_t bits;
    memcpy(&bits, &v, sizeof(bits));
    ev_put_u64_le(dst, bits);
}

static inline double ev_get_double_le(const uint8_t *src)
{
    uint64_t bits = ev_get_u64_le(src);
    double v;
    memcpy(&v, &bits, sizeof(v));
    return v;
}

static inline size_t
ev_tx_admit_mempool_serialized_len(const struct ev_tx_admit_mempool *ev)
{
    if (!ev) return 0;
    return EV_TX_ADMIT_MEMPOOL_FIXED_LEN + ev->raw_tx_len;
}

static inline bool
ev_tx_admit_mempool_serialize(const struct ev_tx_admit_mempool *ev,
                              uint8_t *buf, size_t cap, size_t *out_len)
{
    if (!ev || !buf || !out_len) return false;
    if (ev->raw_tx_len > UINT32_MAX) return false;
    if (ev->raw_tx_len && !ev->raw_tx) return false;
    size_t need = ev_tx_admit_mempool_serialized_len(ev);
    if (cap < need) return false;

    memcpy(buf, ev->txid, 32);
    ev_put_u64_le(buf + 32, (uint64_t)ev->fee);
    ev_put_u32_le(buf + 40, ev->size_bytes);
    ev_put_u32_le(buf + 44, ev->weight);
    ev_put_u32_le(buf + 48, ev->admitted_unix);
    buf[52] = ev->priority_class;
    buf[53] = buf[54] = buf[55] = 0u;
    if (ev->raw_tx_len)
        memcpy(buf + EV_TX_ADMIT_MEMPOOL_FIXED_LEN, ev->raw_tx,
               ev->raw_tx_len);
    *out_len = need;
    return true;
}

static inline bool
ev_tx_admit_mempool_parse(const void *payload, size_t len,
                          struct ev_tx_admit_mempool *out)
{
    if (!payload || !out || len < EV_TX_ADMIT_MEMPOOL_FIXED_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    memset(out, 0, sizeof(*out));
    memcpy(out->txid, buf, 32);
    out->fee = (int64_t)ev_get_u64_le(buf + 32);
    out->size_bytes = ev_get_u32_le(buf + 40);
    out->weight = ev_get_u32_le(buf + 44);
    out->admitted_unix = ev_get_u32_le(buf + 48);
    out->priority_class = buf[52];
    out->raw_tx = buf + EV_TX_ADMIT_MEMPOOL_FIXED_LEN;
    out->raw_tx_len = len - EV_TX_ADMIT_MEMPOOL_FIXED_LEN;
    if (out->raw_tx_len != out->size_bytes)
        return false;
    return true;
}

static inline bool
ev_tx_remove_mempool_serialize(const struct ev_tx_remove_mempool *ev,
                               uint8_t buf[EV_TX_REMOVE_MEMPOOL_LEN])
{
    if (!ev || !buf) return false;
    memcpy(buf, ev->txid, 32);
    buf[32] = ev->reason;
    memset(buf + 33, 0, 7);
    return true;
}

static inline bool
ev_tx_remove_mempool_parse(const void *payload, size_t len,
                           struct ev_tx_remove_mempool *out)
{
    if (!payload || !out || len != EV_TX_REMOVE_MEMPOOL_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    memset(out, 0, sizeof(*out));
    memcpy(out->txid, buf, 32);
    out->reason = buf[32];
    return true;
}

static inline size_t
ev_peer_observed_serialized_len(const struct ev_peer_observed *ev)
{
    if (!ev) return 0;
    return EV_PEER_OBSERVED_FIXED_LEN + (size_t)ev->onion_len;
}

static inline bool
ev_peer_observed_serialize(const struct ev_peer_observed *ev,
                           uint8_t *buf, size_t cap, size_t *out_len)
{
    if (!ev || !buf || !out_len) return false;
    if (ev->onion_len > EV_PEER_ONION_MAX) return false;
    size_t need = ev_peer_observed_serialized_len(ev);
    if (cap < need) return false;

    memcpy(buf, ev->ip_v4_or_v6, 16);
    ev_put_u16_le(buf + 16, ev->port);
    buf[18] = ev->is_onion ? 1u : 0u;
    buf[19] = 0u;
    ev_put_u64_le(buf + 20, ev->services_bitmap);
    ev_put_u32_le(buf + 28, ev->observed_unix);
    ev_put_u32_le(buf + 32, (uint32_t)ev->height_hint);
    buf[36] = ev->onion_len;
    buf[37] = buf[38] = buf[39] = 0u;
    if (ev->onion_len)
        memcpy(buf + EV_PEER_OBSERVED_FIXED_LEN, ev->onion,
               ev->onion_len);
    *out_len = need;
    return true;
}

static inline bool
ev_peer_observed_parse(const void *payload, size_t len,
                       struct ev_peer_observed *out)
{
    if (!payload || !out || len < EV_PEER_OBSERVED_FIXED_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    uint8_t onion_len = buf[36];
    if (onion_len > EV_PEER_ONION_MAX)
        return false;
    if (len != EV_PEER_OBSERVED_FIXED_LEN + (size_t)onion_len)
        return false;

    memset(out, 0, sizeof(*out));
    memcpy(out->ip_v4_or_v6, buf, 16);
    out->port = ev_get_u16_le(buf + 16);
    out->is_onion = buf[18] ? 1u : 0u;
    out->services_bitmap = ev_get_u64_le(buf + 20);
    out->observed_unix = ev_get_u32_le(buf + 28);
    out->height_hint = (int32_t)ev_get_u32_le(buf + 32);
    out->onion_len = onion_len;
    if (onion_len)
        memcpy(out->onion, buf + EV_PEER_OBSERVED_FIXED_LEN, onion_len);
    return true;
}

static inline bool
ev_peer_dropped_serialize(const struct ev_peer_dropped *ev,
                          uint8_t buf[EV_PEER_DROPPED_LEN])
{
    if (!ev || !buf) return false;
    memcpy(buf, ev->ip_v4_or_v6, 16);
    ev_put_u16_le(buf + 16, ev->port);
    buf[18] = ev->reason;
    memset(buf + 19, 0, 5);
    return true;
}

static inline bool
ev_peer_dropped_parse(const void *payload, size_t len,
                      struct ev_peer_dropped *out)
{
    if (!payload || !out || len != EV_PEER_DROPPED_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    memset(out, 0, sizeof(*out));
    memcpy(out->ip_v4_or_v6, buf, 16);
    out->port = ev_get_u16_le(buf + 16);
    out->reason = buf[18];
    return true;
}

/* ── EV_WALLET_* public-only payloads ───────────────────────────── */

static inline size_t
ev_wallet_key_add_serialized_len(const struct ev_wallet_key_add *ev)
{
    if (!ev) return 0;
    return EV_WALLET_KEY_ADD_FIXED_LEN +
           (size_t)ev->address_len + (size_t)ev->label_len;
}

static inline bool
ev_wallet_key_add_serialize(const struct ev_wallet_key_add *ev,
                            uint8_t *buf, size_t cap, size_t *out_len)
{
    if (!ev || !buf || !out_len) return false;
    if (ev->address_len > EV_WALLET_ADDRESS_MAX) return false;
    if (ev->label_len > EV_WALLET_LABEL_MAX) return false;
    if (ev->address_len && !ev->address) return false;
    if (ev->label_len && !ev->label) return false;
    size_t need = ev_wallet_key_add_serialized_len(ev);
    if (need > EV_WALLET_PAYLOAD_MAX || cap < need) return false;

    memcpy(buf + 0, ev->pubkey_hash, 20);
    memset(buf + 20, 0, 4);
    ev_put_u32_le(buf + 24, ev->created_unix);
    buf[28] = ev->address_len;
    buf[29] = ev->label_len;
    buf[30] = 0u;
    buf[31] = 0u;
    if (ev->address_len)
        memcpy(buf + EV_WALLET_KEY_ADD_FIXED_LEN, ev->address,
               ev->address_len);
    if (ev->label_len)
        memcpy(buf + EV_WALLET_KEY_ADD_FIXED_LEN + ev->address_len,
               ev->label, ev->label_len);
    *out_len = need;
    return true;
}

static inline bool
ev_wallet_key_add_parse(const void *payload, size_t len,
                        struct ev_wallet_key_add *out)
{
    if (!payload || !out || len < EV_WALLET_KEY_ADD_FIXED_LEN)
        return false;
    if (len > EV_WALLET_PAYLOAD_MAX)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    uint8_t address_len = buf[28];
    uint8_t label_len = buf[29];
    if (address_len > EV_WALLET_ADDRESS_MAX) return false;
    if (label_len > EV_WALLET_LABEL_MAX) return false;
    size_t need = EV_WALLET_KEY_ADD_FIXED_LEN +
                  (size_t)address_len + (size_t)label_len;
    if (len != need)
        return false;

    memset(out, 0, sizeof(*out));
    memcpy(out->pubkey_hash, buf + 0, 20);
    out->created_unix = ev_get_u32_le(buf + 24);
    out->address_len = address_len;
    out->label_len = label_len;
    out->address = address_len
                 ? (const char *)(buf + EV_WALLET_KEY_ADD_FIXED_LEN)
                 : NULL;
    out->label = label_len
               ? (const char *)(buf + EV_WALLET_KEY_ADD_FIXED_LEN +
                                address_len)
               : NULL;
    return true;
}

static inline bool
ev_wallet_addr_derived_serialize(const struct ev_wallet_addr_derived *ev,
                                 uint8_t buf[EV_WALLET_ADDR_DERIVED_LEN])
{
    if (!ev || !buf) return false;
    memcpy(buf + 0, ev->pubkey_hash, 20);
    memcpy(buf + 20, ev->derived_pubkey_hash, 20);
    ev_put_u32_le(buf + 40, ev->derivation_index);
    ev_put_u32_le(buf + 44, ev->derived_unix);
    return true;
}

static inline bool
ev_wallet_addr_derived_parse(const void *payload, size_t len,
                             struct ev_wallet_addr_derived *out)
{
    if (!payload || !out || len != EV_WALLET_ADDR_DERIVED_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    memset(out, 0, sizeof(*out));
    memcpy(out->pubkey_hash, buf + 0, 20);
    memcpy(out->derived_pubkey_hash, buf + 20, 20);
    out->derivation_index = ev_get_u32_le(buf + 40);
    out->derived_unix = ev_get_u32_le(buf + 44);
    return true;
}

static inline bool
ev_wallet_tx_seen_serialize(const struct ev_wallet_tx_seen *ev,
                            uint8_t buf[EV_WALLET_TX_SEEN_LEN])
{
    if (!ev || !buf) return false;
    memcpy(buf + 0, ev->txid, 32);
    ev_put_u32_le(buf + 32, (uint32_t)ev->block_height);
    ev_put_u64_le(buf + 36, (uint64_t)ev->fee);
    buf[44] = ev->from_me ? 1u : 0u;
    memset(buf + 45, 0, 7);
    return true;
}

static inline bool
ev_wallet_tx_seen_parse(const void *payload, size_t len,
                        struct ev_wallet_tx_seen *out)
{
    if (!payload || !out || len != EV_WALLET_TX_SEEN_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    memset(out, 0, sizeof(*out));
    memcpy(out->txid, buf + 0, 32);
    out->block_height = (int32_t)ev_get_u32_le(buf + 32);
    out->fee = (int64_t)ev_get_u64_le(buf + 36);
    out->from_me = buf[44] ? 1u : 0u;
    return true;
}

static inline bool
ev_wallet_note_decrypted_serialize(
    const struct ev_wallet_note_decrypted *ev,
    uint8_t buf[EV_WALLET_NOTE_DECRYPTED_LEN])
{
    if (!ev || !buf) return false;
    memcpy(buf + 0, ev->txid, 32);
    ev_put_u32_le(buf + 32, ev->output_index);
    ev_put_u32_le(buf + 36, (uint32_t)ev->block_height);
    ev_put_u64_le(buf + 40, (uint64_t)ev->value);
    memcpy(buf + 48, ev->cm, 32);
    return true;
}

static inline bool
ev_wallet_note_decrypted_parse(const void *payload, size_t len,
                               struct ev_wallet_note_decrypted *out)
{
    if (!payload || !out || len != EV_WALLET_NOTE_DECRYPTED_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    memset(out, 0, sizeof(*out));
    memcpy(out->txid, buf + 0, 32);
    out->output_index = ev_get_u32_le(buf + 32);
    out->block_height = (int32_t)ev_get_u32_le(buf + 36);
    out->value = (int64_t)ev_get_u64_le(buf + 40);
    memcpy(out->cm, buf + 48, 32);
    return true;
}

static inline bool
ev_wallet_utxo_seen_serialize(const struct ev_wallet_utxo_seen *ev,
                              uint8_t buf[EV_WALLET_UTXO_SEEN_LEN])
{
    if (!ev || !buf) return false;
    memcpy(buf + 0, ev->txid, 32);
    ev_put_u32_le(buf + 32, ev->vout);
    ev_put_u64_le(buf + 36, (uint64_t)ev->value);
    memcpy(buf + 44, ev->address_hash, 20);
    ev_put_u32_le(buf + 64, (uint32_t)ev->height);
    buf[68] = ev->is_coinbase ? 1u : 0u;
    memset(buf + 69, 0, 3);
    return true;
}

static inline bool
ev_wallet_utxo_seen_parse(const void *payload, size_t len,
                          struct ev_wallet_utxo_seen *out)
{
    if (!payload || !out || len != EV_WALLET_UTXO_SEEN_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    memset(out, 0, sizeof(*out));
    memcpy(out->txid, buf + 0, 32);
    out->vout = ev_get_u32_le(buf + 32);
    out->value = (int64_t)ev_get_u64_le(buf + 36);
    memcpy(out->address_hash, buf + 44, 20);
    out->height = (int32_t)ev_get_u32_le(buf + 64);
    out->is_coinbase = buf[68] ? 1u : 0u;
    return true;
}

/* ── EV_CONTACT_* / EV_ONION_ANNOUNCEMENT / EV_HODL_SNAPSHOT
 *    small-batch projection payloads ────────────────────────────── */

static inline size_t
ev_contact_set_serialized_len(const struct ev_contact_set *ev)
{
    if (!ev) return 0;
    return EV_CONTACT_SET_FIXED_LEN + (size_t)ev->address_len +
           (size_t)ev->name_len;
}

static inline bool
ev_contact_set_serialize(const struct ev_contact_set *ev,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ev || !out || !out_len) return false;
    if (ev->address_len == 0 || ev->address_len > EV_CONTACT_ADDRESS_MAX)
        return false;
    if (ev->name_len > EV_CONTACT_NAME_MAX) return false;
    if (!ev->address) return false;
    if (ev->name_len && !ev->name) return false;
    size_t need = ev_contact_set_serialized_len(ev);
    if (out_cap < need) return false;

    out[0] = ev->address_len;
    out[1] = ev->name_len;
    memset(out + 2, 0, 6);
    memcpy(out + EV_CONTACT_SET_FIXED_LEN, ev->address, ev->address_len);
    if (ev->name_len)
        memcpy(out + EV_CONTACT_SET_FIXED_LEN + ev->address_len,
               ev->name, ev->name_len);
    *out_len = need;
    return true;
}

static inline bool
ev_contact_set_parse(const void *payload, size_t len,
                     struct ev_contact_set *out)
{
    if (!payload || !out || len < EV_CONTACT_SET_FIXED_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    uint8_t address_len = buf[0];
    uint8_t name_len = buf[1];
    if (address_len == 0 || address_len > EV_CONTACT_ADDRESS_MAX)
        return false;
    if (name_len > EV_CONTACT_NAME_MAX)
        return false;
    size_t need = EV_CONTACT_SET_FIXED_LEN + (size_t)address_len +
                  (size_t)name_len;
    if (len != need) return false;

    memset(out, 0, sizeof(*out));
    out->address_len = address_len;
    out->name_len = name_len;
    out->address = (const char *)(buf + EV_CONTACT_SET_FIXED_LEN);
    out->name = name_len
              ? (const char *)(buf + EV_CONTACT_SET_FIXED_LEN + address_len)
              : NULL;
    return true;
}

static inline bool
ev_contact_touched_serialize(const struct ev_contact_touched *ev,
                             uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ev || !out || !out_len) return false;
    if (ev->address_len == 0 || ev->address_len > EV_CONTACT_ADDRESS_MAX)
        return false;
    if (!ev->address) return false;
    size_t need = EV_CONTACT_TOUCHED_LEN + (size_t)ev->address_len;
    if (out_cap < need) return false;

    out[0] = ev->address_len;
    memset(out + 1, 0, 3);
    ev_put_u32_le(out + 4, ev->last_used_unix);
    memcpy(out + EV_CONTACT_TOUCHED_LEN, ev->address, ev->address_len);
    *out_len = need;
    return true;
}

static inline bool
ev_contact_touched_parse(const void *payload, size_t len,
                         struct ev_contact_touched *out)
{
    if (!payload || !out || len < EV_CONTACT_TOUCHED_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    uint8_t address_len = buf[0];
    if (address_len == 0 || address_len > EV_CONTACT_ADDRESS_MAX)
        return false;
    if (len != EV_CONTACT_TOUCHED_LEN + (size_t)address_len)
        return false;

    memset(out, 0, sizeof(*out));
    out->address_len = address_len;
    out->last_used_unix = ev_get_u32_le(buf + 4);
    out->address = (const char *)(buf + EV_CONTACT_TOUCHED_LEN);
    return true;
}

static inline size_t
ev_contact_delete_serialized_len(const struct ev_contact_delete *ev)
{
    if (!ev) return 0;
    return EV_CONTACT_DELETE_FIXED_LEN + (size_t)ev->address_len;
}

static inline bool
ev_contact_delete_serialize(const struct ev_contact_delete *ev,
                            uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ev || !out || !out_len) return false;
    if (ev->address_len == 0 || ev->address_len > EV_CONTACT_ADDRESS_MAX)
        return false;
    if (!ev->address) return false;
    size_t need = ev_contact_delete_serialized_len(ev);
    if (out_cap < need) return false;

    out[0] = ev->address_len;
    memset(out + 1, 0, 7);
    memcpy(out + EV_CONTACT_DELETE_FIXED_LEN, ev->address, ev->address_len);
    *out_len = need;
    return true;
}

static inline bool
ev_contact_delete_parse(const void *payload, size_t len,
                        struct ev_contact_delete *out)
{
    if (!payload || !out || len < EV_CONTACT_DELETE_FIXED_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    uint8_t address_len = buf[0];
    if (address_len == 0 || address_len > EV_CONTACT_ADDRESS_MAX)
        return false;
    if (len != EV_CONTACT_DELETE_FIXED_LEN + (size_t)address_len)
        return false;

    memset(out, 0, sizeof(*out));
    out->address_len = address_len;
    out->address = (const char *)(buf + EV_CONTACT_DELETE_FIXED_LEN);
    return true;
}

static inline size_t
ev_onion_announcement_serialized_len(
    const struct ev_onion_announcement *ev)
{
    if (!ev) return 0;
    return EV_ONION_ANNOUNCEMENT_FIXED_LEN + (size_t)ev->onion_addr_len +
           (size_t)ev->script_hex_len;
}

static inline bool
ev_onion_announcement_serialize(const struct ev_onion_announcement *ev,
                                uint8_t *out, size_t out_cap,
                                size_t *out_len)
{
    if (!ev || !out || !out_len) return false;
    if (ev->onion_addr_len == 0 ||
        ev->onion_addr_len > EV_ONION_ADDRESS_MAX)
        return false;
    if (ev->script_hex_len > EV_ONION_SCRIPT_HEX_MAX)
        return false;
    if (!ev->onion_address) return false;
    if (ev->script_hex_len && !ev->script_hex) return false;
    size_t need = ev_onion_announcement_serialized_len(ev);
    if (out_cap < need) return false;

    ev_put_u32_le(out + 0, ev->announced_at_unix);
    out[4] = ev->onion_addr_len;
    out[5] = ev->script_hex_len;
    out[6] = 0u;
    out[7] = 0u;
    memcpy(out + EV_ONION_ANNOUNCEMENT_FIXED_LEN, ev->onion_address,
           ev->onion_addr_len);
    if (ev->script_hex_len)
        memcpy(out + EV_ONION_ANNOUNCEMENT_FIXED_LEN + ev->onion_addr_len,
               ev->script_hex, ev->script_hex_len);
    *out_len = need;
    return true;
}

static inline bool
ev_onion_announcement_parse(const void *payload, size_t len,
                            struct ev_onion_announcement *out)
{
    if (!payload || !out || len < EV_ONION_ANNOUNCEMENT_FIXED_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    uint8_t onion_addr_len = buf[4];
    uint8_t script_hex_len = buf[5];
    if (onion_addr_len == 0 || onion_addr_len > EV_ONION_ADDRESS_MAX)
        return false;
    if (script_hex_len > EV_ONION_SCRIPT_HEX_MAX)
        return false;
    size_t need = EV_ONION_ANNOUNCEMENT_FIXED_LEN +
                  (size_t)onion_addr_len + (size_t)script_hex_len;
    if (len != need) return false;

    memset(out, 0, sizeof(*out));
    out->announced_at_unix = ev_get_u32_le(buf + 0);
    out->onion_addr_len = onion_addr_len;
    out->script_hex_len = script_hex_len;
    out->onion_address =
        (const char *)(buf + EV_ONION_ANNOUNCEMENT_FIXED_LEN);
    out->script_hex = script_hex_len
                    ? (const char *)(buf + EV_ONION_ANNOUNCEMENT_FIXED_LEN +
                                     onion_addr_len)
                    : NULL;
    return true;
}

static inline bool
ev_hodl_snapshot_serialize(const struct ev_hodl_snapshot *ev,
                           uint8_t out[EV_HODL_SNAPSHOT_LEN])
{
    if (!ev || !out) return false;
    ev_put_u32_le(out + 0, (uint32_t)ev->height);
    ev_put_u32_le(out + 4, ev->time_unix);
    ev_put_u64_le(out + 8, (uint64_t)ev->total_zat);
    ev_put_u64_le(out + 16, (uint64_t)ev->older_1y_zat);
    ev_put_double_le(out + 24, ev->older_1y_pct);
    return true;
}

static inline bool
ev_hodl_snapshot_parse(const void *payload, size_t len,
                       struct ev_hodl_snapshot *out)
{
    if (!payload || !out || len != EV_HODL_SNAPSHOT_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    memset(out, 0, sizeof(*out));
    out->height = (int32_t)ev_get_u32_le(buf + 0);
    out->time_unix = ev_get_u32_le(buf + 4);
    out->total_zat = (int64_t)ev_get_u64_le(buf + 8);
    out->older_1y_zat = (int64_t)ev_get_u64_le(buf + 16);
    out->older_1y_pct = ev_get_double_le(buf + 24);
    return true;
}

/* ── EV_PEER_SESSION_CLOSED ─────────────────────────────────────── */

static inline bool
ev_peer_session_closed_serialize(const struct ev_peer_session_closed *ev,
                                 uint8_t buf[EV_PEER_SESSION_CLOSED_LEN])
{
    if (!ev || !buf) return false;
    memcpy(buf, ev->ip_v4_or_v6, 16);
    ev_put_u16_le(buf + 16, ev->port);
    buf[18] = ev->reason;
    buf[19] = 0u;
    ev_put_u32_le(buf + 20, ev->duration_secs);
    ev_put_u64_le(buf + 24, ev->bytes_in);
    ev_put_u64_le(buf + 32, ev->bytes_out);
    ev_put_u64_le(buf + 40, ev->headers_delivered);
    ev_put_u64_le(buf + 48, ev->blocks_delivered);
    ev_put_u32_le(buf + 56, ev->bandwidth_score);
    ev_put_u64_le(buf + 60, (uint64_t)ev->avg_latency_us);
    ev_put_u64_le(buf + 68, (uint64_t)ev->last_useful_time);
    return true;
}

static inline bool
ev_peer_session_closed_parse(const void *payload, size_t len,
                             struct ev_peer_session_closed *out)
{
    if (!payload || !out || len != EV_PEER_SESSION_CLOSED_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    memset(out, 0, sizeof(*out));
    memcpy(out->ip_v4_or_v6, buf, 16);
    out->port = ev_get_u16_le(buf + 16);
    out->reason = buf[18];
    out->duration_secs = ev_get_u32_le(buf + 20);
    out->bytes_in = ev_get_u64_le(buf + 24);
    out->bytes_out = ev_get_u64_le(buf + 32);
    out->headers_delivered = ev_get_u64_le(buf + 40);
    out->blocks_delivered = ev_get_u64_le(buf + 48);
    out->bandwidth_score = ev_get_u32_le(buf + 56);
    out->avg_latency_us = (int64_t)ev_get_u64_le(buf + 60);
    out->last_useful_time = (int64_t)ev_get_u64_le(buf + 68);
    return true;
}

/* ── EV_NET_FORK_OBSERVED ───────────────────────────────────────── */

static inline size_t
ev_net_fork_observed_serialized_len(const struct ev_net_fork_observed *ev)
{
    if (!ev) return 0;
    return EV_NET_FORK_OBSERVED_FIXED_LEN + (size_t)ev->hash_a_len +
           (size_t)ev->hash_b_len;
}

static inline bool
ev_net_fork_observed_serialize(const struct ev_net_fork_observed *ev,
                               uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ev || !out || !out_len) return false;
    if (ev->hash_a_len > EV_NET_FORK_TIP_HEX_MAX ||
        ev->hash_b_len > EV_NET_FORK_TIP_HEX_MAX)
        return false;
    size_t need = ev_net_fork_observed_serialized_len(ev);
    if (out_cap < need) return false;
    ev_put_u64_le(out + 0, (uint64_t)ev->height);
    ev_put_u64_le(out + 8, (uint64_t)ev->observed_unix);
    ev_put_u32_le(out + 16, ev->num_clusters);
    ev_put_u32_le(out + 20, ev->count_a);
    ev_put_u32_le(out + 24, ev->count_b);
    out[28] = ev->hash_a_len;
    out[29] = ev->hash_b_len;
    out[30] = 0u;
    out[31] = 0u;
    if (ev->hash_a_len)
        memcpy(out + EV_NET_FORK_OBSERVED_FIXED_LEN, ev->tip_hash_a,
               ev->hash_a_len);
    if (ev->hash_b_len)
        memcpy(out + EV_NET_FORK_OBSERVED_FIXED_LEN + ev->hash_a_len,
               ev->tip_hash_b, ev->hash_b_len);
    *out_len = need;
    return true;
}

static inline bool
ev_net_fork_observed_parse(const void *payload, size_t len,
                           struct ev_net_fork_observed *out)
{
    if (!payload || !out || len < EV_NET_FORK_OBSERVED_FIXED_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    uint8_t hash_a_len = buf[28];
    uint8_t hash_b_len = buf[29];
    if (hash_a_len > EV_NET_FORK_TIP_HEX_MAX ||
        hash_b_len > EV_NET_FORK_TIP_HEX_MAX)
        return false;
    if (len != EV_NET_FORK_OBSERVED_FIXED_LEN + (size_t)hash_a_len +
               (size_t)hash_b_len)
        return false;
    memset(out, 0, sizeof(*out));
    out->height = (int64_t)ev_get_u64_le(buf + 0);
    out->observed_unix = (int64_t)ev_get_u64_le(buf + 8);
    out->num_clusters = ev_get_u32_le(buf + 16);
    out->count_a = ev_get_u32_le(buf + 20);
    out->count_b = ev_get_u32_le(buf + 24);
    out->hash_a_len = hash_a_len;
    out->hash_b_len = hash_b_len;
    if (hash_a_len)
        memcpy(out->tip_hash_a, buf + EV_NET_FORK_OBSERVED_FIXED_LEN,
               hash_a_len);
    if (hash_b_len)
        memcpy(out->tip_hash_b,
               buf + EV_NET_FORK_OBSERVED_FIXED_LEN + hash_a_len, hash_b_len);
    return true;
}

/* ── EV_NODE_CENSUS_OBSERVED ────────────────────────────────────── */

static inline size_t
ev_node_census_observed_serialized_len(const struct ev_node_census_observed *ev)
{
    if (!ev) return 0;
    return EV_NODE_CENSUS_OBSERVED_FIXED_LEN + (size_t)ev->ua_len;
}

static inline bool
ev_node_census_observed_serialize(const struct ev_node_census_observed *ev,
                                  uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ev || !out || !out_len) return false;
    if (ev->ua_len > EV_CENSUS_UA_MAX) return false;
    size_t need = ev_node_census_observed_serialized_len(ev);
    if (out_cap < need) return false;
    memcpy(out + 0, ev->ip_v4_or_v6, 16);
    ev_put_u16_le(out + 16, ev->port);
    out[18] = ev->source;
    out[19] = ev->success ? 1u : 0u;
    out[20] = ev->ua_overflow ? 1u : 0u;
    out[21] = 0u;
    ev_put_u32_le(out + 22, (uint32_t)ev->protocol_version);
    ev_put_u64_le(out + 26, ev->services);
    ev_put_u64_le(out + 34, (uint64_t)ev->reported_height);
    ev_put_u64_le(out + 42, (uint64_t)ev->observed_unix);
    ev_put_u16_le(out + 50, ev->ua_len);
    if (ev->ua_len)
        memcpy(out + EV_NODE_CENSUS_OBSERVED_FIXED_LEN, ev->user_agent,
               ev->ua_len);
    *out_len = need;
    return true;
}

static inline bool
ev_node_census_observed_parse(const void *payload, size_t len,
                              struct ev_node_census_observed *out)
{
    if (!payload || !out || len < EV_NODE_CENSUS_OBSERVED_FIXED_LEN)
        return false;
    const uint8_t *buf = (const uint8_t *)payload;
    uint16_t ua_len = ev_get_u16_le(buf + 50);
    if (ua_len > EV_CENSUS_UA_MAX)
        return false;
    if (len != EV_NODE_CENSUS_OBSERVED_FIXED_LEN + (size_t)ua_len)
        return false;
    memset(out, 0, sizeof(*out));
    memcpy(out->ip_v4_or_v6, buf + 0, 16);
    out->port = ev_get_u16_le(buf + 16);
    out->source = buf[18];
    out->success = buf[19] ? 1u : 0u;
    out->ua_overflow = buf[20] ? 1u : 0u;
    out->reserved = 0u;
    out->protocol_version = (int32_t)ev_get_u32_le(buf + 22);
    out->services = ev_get_u64_le(buf + 26);
    out->reported_height = (int64_t)ev_get_u64_le(buf + 34);
    out->observed_unix = (int64_t)ev_get_u64_le(buf + 42);
    out->ua_len = ua_len;
    if (ua_len)
        memcpy(out->user_agent, buf + EV_NODE_CENSUS_OBSERVED_FIXED_LEN,
               ua_len);
    return true;
}

/* ── EV_UTXO_ADD / EV_UTXO_SPEND codec (reserved wire slots) ───────────────
 *
 * The event-log-fed UTXO projection these fed was removed in Program H1 (the
 * kernel coins store is the one UTXO ledger). The wire slots (event_log.h tags
 * 5/6) and this codec are RETAINED: the tags are frozen so old event logs stay
 * readable, and the serialiser is still used by the rebuild_recent tool and the
 * event-log unit tests. No production emitter or consumer remains.
 *
 * Frozen wire formats. Extending requires a new event_log_type id, not
 * an in-place change.
 *
 *   EV_UTXO_ADD (variable length, 56 + script_len bytes):
 *      [ 32B  txid                 ]
 *      [  4B  vout (LE)            ]
 *      [  8B  value, zatoshis (LE) ]
 *      [  4B  height (LE)          ]
 *      [  1B  is_coinbase (0/1)    ]
 *      [  3B  reserved (zero)      ]
 *      [  4B  script_len (LE)      ]
 *      [ NB   script bytes         ]
 *
 *   EV_UTXO_SPEND (fixed 36 bytes):
 *      [ 32B  prevout_txid         ]
 *      [  4B  prevout_vout (LE)    ]
 */

/* Header portion (everything but the trailing script). */
#define EV_UTXO_ADD_HDR_WIRE_LEN 56u
#define EV_UTXO_SPEND_WIRE_LEN   36u

struct ev_utxo_add_hdr {
    uint8_t  txid[32];
    uint32_t vout;
    int64_t  value;
    uint32_t height;
    uint8_t  is_coinbase;   /* 0 or 1 */
    uint8_t  reserved[3];   /* zero on emit; ignored on parse */
    uint32_t script_len;
};

struct ev_utxo_spend {
    uint8_t  txid[32];
    uint32_t vout;
};

/* Total wire length of an EV_UTXO_ADD payload given its header. */
static inline size_t
ev_utxo_add_serialized_len(const struct ev_utxo_add_hdr *hdr)
{
    if (!hdr) return 0;
    return (size_t)EV_UTXO_ADD_HDR_WIRE_LEN + (size_t)hdr->script_len;
}

/* Serialise an EV_UTXO_ADD payload into `out`. `out_cap` must hold
 * EV_UTXO_ADD_HDR_WIRE_LEN + hdr->script_len bytes. Writes the produced
 * length into *out_len. Returns false on truncation / NULL args /
 * (script_len > 0 && script_bytes == NULL).
 *
 * The `reserved` field in `hdr` is ignored — we always emit zero bytes
 * regardless of what's in the struct, so the wire form is deterministic. */
static inline bool
ev_utxo_add_serialize(const struct ev_utxo_add_hdr *hdr,
                      const uint8_t *script_bytes,
                      uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!hdr || !out || !out_len) return false;
    if (hdr->script_len > 0 && !script_bytes) return false;
    size_t need = ev_utxo_add_serialized_len(hdr);
    if (out_cap < need) return false;

    memcpy(out + 0, hdr->txid, 32);
    ev_put_u32_le(out + 32, hdr->vout);
    ev_put_u64_le(out + 36, (uint64_t)hdr->value);
    ev_put_u32_le(out + 44, hdr->height);
    out[48] = hdr->is_coinbase ? 1u : 0u;
    out[49] = 0u;
    out[50] = 0u;
    out[51] = 0u;
    ev_put_u32_le(out + 52, hdr->script_len);
    if (hdr->script_len > 0)
        memcpy(out + EV_UTXO_ADD_HDR_WIRE_LEN, script_bytes, hdr->script_len);

    *out_len = need;
    return true;
}

/* Parse an EV_UTXO_ADD payload. On success fills `hdr`; *script_out
 * (if non-NULL) is set to point INTO `payload` (zero-copy; valid for
 * the lifetime of `payload`). Returns false on truncation, bogus
 * script_len, or NULL `payload`/`hdr`. */
static inline bool
ev_utxo_add_parse(const uint8_t *payload, size_t payload_len,
                  struct ev_utxo_add_hdr *hdr,
                  const uint8_t **script_out,
                  size_t *script_len_out)
{
    if (!payload || !hdr) return false;
    if (payload_len < EV_UTXO_ADD_HDR_WIRE_LEN) return false;

    memcpy(hdr->txid, payload + 0, 32);
    hdr->vout        = ev_get_u32_le(payload + 32);
    hdr->value       = (int64_t)ev_get_u64_le(payload + 36);
    hdr->height      = ev_get_u32_le(payload + 44);
    hdr->is_coinbase = payload[48] ? 1u : 0u;
    hdr->reserved[0] = 0u;
    hdr->reserved[1] = 0u;
    hdr->reserved[2] = 0u;
    hdr->script_len  = ev_get_u32_le(payload + 52);

    size_t need = (size_t)EV_UTXO_ADD_HDR_WIRE_LEN + (size_t)hdr->script_len;
    if (payload_len < need) return false;

    if (script_out) {
        *script_out = (hdr->script_len > 0)
                    ? (payload + EV_UTXO_ADD_HDR_WIRE_LEN)
                    : NULL;
    }
    if (script_len_out)
        *script_len_out = hdr->script_len;
    return true;
}

static inline bool
ev_utxo_spend_serialize(const struct ev_utxo_spend *spend,
                        uint8_t out[EV_UTXO_SPEND_WIRE_LEN])
{
    if (!spend || !out) return false;
    memcpy(out + 0, spend->txid, 32);
    ev_put_u32_le(out + 32, spend->vout);
    return true;
}

static inline bool
ev_utxo_spend_parse(const void *payload, size_t payload_len,
                    struct ev_utxo_spend *spend_out)
{
    if (!payload || !spend_out) return false;
    if (payload_len != EV_UTXO_SPEND_WIRE_LEN) return false;
    const uint8_t *buf = (const uint8_t *)payload;
    memcpy(spend_out->txid, buf + 0, 32);
    spend_out->vout = ev_get_u32_le(buf + 32);
    return true;
}

/* ── EV_BLOCK_HEADER ─────────────────────────────────────────────────
 *
 * Per-block-index entry. Emitted alongside the persisted block-index write.
 * The block_index_projection consumes these to materialize a SQLite-backed
 * replacement for the LevelDB `b` keyspace.
 *
 * Wire layout (little-endian, no padding):
 *   bytes  0..31    hash                  (block hash)
 *   bytes 32..63    hashPrev              (previous block hash)
 *   bytes 64..67    height                (int32 LE)
 *   bytes 68..71    nStatus               (uint32 LE)
 *   bytes 72..75    nFile                 (int32 LE)
 *   bytes 76..79    nDataPos              (uint32 LE)
 *   bytes 80..83    nUndoPos              (uint32 LE)
 *   bytes 84..87    nTime                 (uint32 LE)
 *   bytes 88..91    nBits                 (uint32 LE)
 *   bytes 92..123   nNonce                (32 bytes)
 *   bytes 124..155  hashMerkleRoot        (32 bytes)
 *   bytes 156..187  hashFinalSaplingRoot  (32 bytes)
 *   bytes 188..191  nVersion              (int32 LE)
 *   bytes 192..195  nTx                   (uint32 LE)
 *   bytes 196..197  nSolutionSize         (uint16 LE)
 *   bytes 198..199  reserved              (2 bytes, MBZ)
 *   bytes 200..     nSolution             (nSolutionSize bytes)
 *
 * Total fixed prefix: 200 bytes. nSolution follows. */
#define EV_BLOCK_HEADER_FIXED_BYTES  200u
#define EV_BLOCK_HEADER_MAX_SOLUTION 1344u   /* Equihash 200,9 = 1344 B */

struct ev_block_header {
    uint8_t  hash[32];
    uint8_t  hashPrev[32];
    int32_t  height;
    uint32_t nStatus;
    int32_t  nFile;
    uint32_t nDataPos;
    uint32_t nUndoPos;
    uint32_t nTime;
    uint32_t nBits;
    uint8_t  nNonce[32];
    uint8_t  hashMerkleRoot[32];
    uint8_t  hashFinalSaplingRoot[32];
    int32_t  nVersion;
    uint32_t nTx;
    uint16_t nSolutionSize;
    uint8_t  reserved[2];
    /* nSolution bytes follow on the wire (nSolutionSize bytes). In the
     * in-memory struct, the caller passes the solution pointer
     * separately to ev_block_header_serialize() / receives it back from
     * ev_block_header_parse(). */
};

/* Returns the on-disk size of the serialization for the given solution
 * size. Pass `nSolutionSize` from the struct. */
static inline size_t ev_block_header_wire_size(uint16_t nSolutionSize)
{
    return (size_t)EV_BLOCK_HEADER_FIXED_BYTES + (size_t)nSolutionSize;
}

/* Serialize a header into `out` (must have at least
 * ev_block_header_wire_size(h->nSolutionSize) bytes). The trailing
 * solution comes from `solution` (may be NULL iff nSolutionSize == 0).
 * Returns true on success, false on bad input. */
bool ev_block_header_serialize(const struct ev_block_header *h,
                               const uint8_t *solution,
                               uint8_t *out, size_t out_cap,
                               size_t *out_written);

/* Parse a serialized header from `in`. The fixed-size fields populate
 * `*h_out`. The pointer `*solution_out` is set to the trailing solution
 * bytes inside `in` (no copy) — valid only while `in` remains alive.
 * Returns true on success, false on truncation / size mismatch. */
bool ev_block_header_parse(const uint8_t *in, size_t in_len,
                           struct ev_block_header *h_out,
                           const uint8_t **solution_out);

/* ── EV_BLOCK_STATUS ─────────────────────────────────────────────────
 *
 * Lightweight status-only update for a block_index entry that ALREADY has a
 * durable EV_BLOCK_HEADER row from first admit. body_persist / script_validate
 * bump BLOCK_HAVE_DATA / BLOCK_VALID_SCRIPTS (+ nFile/nDataPos/nUndoPos/nTx)
 * without ever changing the immutable header fields (hash, hashPrev, version,
 * merkle/sapling roots, time, bits, nonce, Equihash solution) — carrying only
 * the mutable fields avoids re-serializing the full ~1.5KB header + solution
 * on every status bump. block_index_projection's catch_up applies this
 * against the row the prior EV_BLOCK_HEADER created (patches the mutable
 * fields of the stored blob and re-serializes it there, off the fold's hot
 * path — see storage/block_index_projection.c).
 *
 * Wire layout (little-endian, no padding), fixed 52 bytes:
 *   bytes  0..31   hash       (block hash — projection lookup key)
 *   bytes 32..35   nStatus    (uint32 LE)
 *   bytes 36..39   nFile      (int32 LE)
 *   bytes 40..43   nDataPos   (uint32 LE)
 *   bytes 44..47   nUndoPos   (uint32 LE)
 *   bytes 48..51   nTx        (uint32 LE)
 */
#define EV_BLOCK_STATUS_WIRE_LEN 52u

struct ev_block_status {
    uint8_t  hash[32];
    uint32_t nStatus;
    int32_t  nFile;
    uint32_t nDataPos;
    uint32_t nUndoPos;
    uint32_t nTx;
};

static inline bool
ev_block_status_serialize(const struct ev_block_status *s,
                          uint8_t out[EV_BLOCK_STATUS_WIRE_LEN])
{
    if (!s || !out) return false;
    memcpy(out + 0, s->hash, 32);
    ev_put_u32_le(out + 32, s->nStatus);
    ev_put_u32_le(out + 36, (uint32_t)s->nFile);
    ev_put_u32_le(out + 40, s->nDataPos);
    ev_put_u32_le(out + 44, s->nUndoPos);
    ev_put_u32_le(out + 48, s->nTx);
    return true;
}

static inline bool
ev_block_status_parse(const void *payload, size_t payload_len,
                      struct ev_block_status *out)
{
    if (!payload || !out) return false;
    if (payload_len != EV_BLOCK_STATUS_WIRE_LEN) return false;
    const uint8_t *buf = (const uint8_t *)payload;
    memcpy(out->hash, buf + 0, 32);
    out->nStatus  =           ev_get_u32_le(buf + 32);
    out->nFile    = (int32_t) ev_get_u32_le(buf + 36);
    out->nDataPos =           ev_get_u32_le(buf + 40);
    out->nUndoPos =           ev_get_u32_le(buf + 44);
    out->nTx      =           ev_get_u32_le(buf + 48);
    return true;
}

/* ── ZNAM events for znam_projection ───────────────────────────────
 *
 * Frozen wire formats. Variable-length strings carry an explicit u8
 * length prefix so the projection can validate every byte. All names
 * are bounded by ZNAM_NAME_MAX (63). Owner addresses are text (P2PKH
 * t-address style strings <= 64 chars). Target / value strings are
 * bounded by ZNAM_VALUE_MAX (128) and ZNAM_TEXT_VAL_MAX (128).
 *
 *   EV_ZNAM_REGISTER (variable):
 *     [ 1B  name_len               ]
 *     [ NB  name                   ]
 *     [ 1B  owner_len              ]
 *     [ NB  owner_address          ]
 *     [ 1B  target_type            ]
 *     [ 1B  target_value_len       ]
 *     [ NB  target_value           ]
 *     [ 32B reg_txid               ]
 *     [  4B reg_height (LE, i32)   ]
 *     [  4B registered_unix (LE)   ]
 *     [  4B expiry_height (LE,i32) ]
 *
 *   EV_ZNAM_UPDATE (variable):
 *     [ 1B  name_len               ]
 *     [ NB  name                   ]
 *     [ 1B  action_type            ]   // 0=addr_record,1=text_record,2=primary
 *     [ 1B  key_or_coin_type       ]   // coin_type for action 0/2; ignored if 1
 *     [ 1B  key_len                ]   // text_record key len; 0 for action 0/2
 *     [ NB  key                    ]
 *     [ 1B  value_len              ]
 *     [ NB  value                  ]
 *     [ 32B update_txid            ]
 *
 *   EV_ZNAM_TRANSFER (variable):
 *     [ 1B  name_len               ]
 *     [ NB  name                   ]
 *     [ 1B  new_owner_len          ]
 *     [ NB  new_owner              ]
 *     [ 32B update_txid            ]
 *
 *   EV_ZNAM_RENEW (variable):
 *     [ 1B  name_len               ]
 *     [ NB  name                   ]
 *     [  4B new_expiry_height(LE)  ]
 *     [ 32B update_txid            ]
 *
 *   EV_ZNAM_EXPIRE (variable):
 *     [ 1B  name_len               ]
 *     [ NB  name                   ]
 *     [  4B expired_at_height(LE)  ]
 */

#define EV_ZNAM_NAME_MAX     63u
#define EV_ZNAM_OWNER_MAX    64u
#define EV_ZNAM_VALUE_MAX   128u
#define EV_ZNAM_KEY_MAX      32u

#define EV_ZNAM_UPDATE_ACTION_ADDR        0u
#define EV_ZNAM_UPDATE_ACTION_TEXT        1u
#define EV_ZNAM_UPDATE_ACTION_PRIMARY     2u

struct ev_znam_register {
    uint8_t  name_len;
    char     name[EV_ZNAM_NAME_MAX + 1];
    uint8_t  owner_len;
    char     owner_address[EV_ZNAM_OWNER_MAX + 1];
    uint8_t  target_type;
    uint8_t  target_value_len;
    char     target_value[EV_ZNAM_VALUE_MAX + 1];
    uint8_t  reg_txid[32];
    int32_t  reg_height;
    uint32_t registered_unix;
    int32_t  expiry_height;
};

struct ev_znam_update {
    uint8_t  name_len;
    char     name[EV_ZNAM_NAME_MAX + 1];
    uint8_t  action_type;            /* 0=addr,1=text,2=primary */
    uint8_t  key_or_coin_type;       /* coin_type for action 0/2, ignored if 1 */
    uint8_t  key_len;
    char     key[EV_ZNAM_KEY_MAX + 1];
    uint8_t  value_len;
    char     value[EV_ZNAM_VALUE_MAX + 1];
    uint8_t  update_txid[32];
};

struct ev_znam_transfer {
    uint8_t  name_len;
    char     name[EV_ZNAM_NAME_MAX + 1];
    uint8_t  new_owner_len;
    char     new_owner[EV_ZNAM_OWNER_MAX + 1];
    uint8_t  update_txid[32];
};

struct ev_znam_renew {
    uint8_t  name_len;
    char     name[EV_ZNAM_NAME_MAX + 1];
    int32_t  new_expiry_height;
    uint8_t  update_txid[32];
};

struct ev_znam_expire {
    uint8_t  name_len;
    char     name[EV_ZNAM_NAME_MAX + 1];
    int32_t  expired_at_height;
};

/* ── EV_ZNAM_REGISTER ──────────────────────────────────────────── */

static inline size_t
ev_znam_register_serialized_len(const struct ev_znam_register *ev)
{
    if (!ev) return 0;
    return (size_t)1 + ev->name_len + 1 + ev->owner_len + 1 + 1 +
           ev->target_value_len + 32 + 4 + 4 + 4;
}

static inline bool
ev_znam_register_serialize(const struct ev_znam_register *ev,
                           uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ev || !out || !out_len) return false;
    if (ev->name_len == 0 || ev->name_len > EV_ZNAM_NAME_MAX) return false;
    if (ev->owner_len == 0 || ev->owner_len > EV_ZNAM_OWNER_MAX) return false;
    if (ev->target_value_len > EV_ZNAM_VALUE_MAX) return false;
    size_t need = ev_znam_register_serialized_len(ev);
    if (out_cap < need) return false;
    size_t off = 0;
    out[off++] = ev->name_len;
    memcpy(out + off, ev->name, ev->name_len); off += ev->name_len;
    out[off++] = ev->owner_len;
    memcpy(out + off, ev->owner_address, ev->owner_len); off += ev->owner_len;
    out[off++] = ev->target_type;
    out[off++] = ev->target_value_len;
    if (ev->target_value_len)
        memcpy(out + off, ev->target_value, ev->target_value_len);
    off += ev->target_value_len;
    memcpy(out + off, ev->reg_txid, 32); off += 32;
    ev_put_u32_le(out + off, (uint32_t)ev->reg_height); off += 4;
    ev_put_u32_le(out + off, ev->registered_unix); off += 4;
    ev_put_u32_le(out + off, (uint32_t)ev->expiry_height); off += 4;
    *out_len = off;
    return true;
}

static inline bool
ev_znam_register_parse(const void *payload, size_t len,
                       struct ev_znam_register *out)
{
    if (!payload || !out) return false;
    if (len < 1) return false;
    const uint8_t *buf = (const uint8_t *)payload;
    size_t off = 0;
    memset(out, 0, sizeof(*out));
    out->name_len = buf[off++];
    if (out->name_len == 0 || out->name_len > EV_ZNAM_NAME_MAX) return false;
    if (off + out->name_len + 1 > len) return false;
    memcpy(out->name, buf + off, out->name_len); off += out->name_len;
    out->owner_len = buf[off++];
    if (out->owner_len == 0 || out->owner_len > EV_ZNAM_OWNER_MAX) return false;
    if (off + out->owner_len + 2 > len) return false;
    memcpy(out->owner_address, buf + off, out->owner_len); off += out->owner_len;
    out->target_type = buf[off++];
    out->target_value_len = buf[off++];
    if (out->target_value_len > EV_ZNAM_VALUE_MAX) return false;
    if (off + out->target_value_len + 32 + 12 > len) return false;
    if (out->target_value_len)
        memcpy(out->target_value, buf + off, out->target_value_len);
    off += out->target_value_len;
    memcpy(out->reg_txid, buf + off, 32); off += 32;
    out->reg_height     = (int32_t)ev_get_u32_le(buf + off); off += 4;
    out->registered_unix = ev_get_u32_le(buf + off); off += 4;
    out->expiry_height  = (int32_t)ev_get_u32_le(buf + off); off += 4;
    if (off != len) return false;
    return true;
}

/* ── EV_ZNAM_UPDATE ─────────────────────────────────────────────── */

static inline size_t
ev_znam_update_serialized_len(const struct ev_znam_update *ev)
{
    if (!ev) return 0;
    return (size_t)1 + ev->name_len + 1 + 1 + 1 + ev->key_len + 1 +
           ev->value_len + 32;
}

static inline bool
ev_znam_update_serialize(const struct ev_znam_update *ev,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ev || !out || !out_len) return false;
    if (ev->name_len == 0 || ev->name_len > EV_ZNAM_NAME_MAX) return false;
    if (ev->key_len > EV_ZNAM_KEY_MAX) return false;
    if (ev->value_len > EV_ZNAM_VALUE_MAX) return false;
    size_t need = ev_znam_update_serialized_len(ev);
    if (out_cap < need) return false;
    size_t off = 0;
    out[off++] = ev->name_len;
    memcpy(out + off, ev->name, ev->name_len); off += ev->name_len;
    out[off++] = ev->action_type;
    out[off++] = ev->key_or_coin_type;
    out[off++] = ev->key_len;
    if (ev->key_len)
        memcpy(out + off, ev->key, ev->key_len);
    off += ev->key_len;
    out[off++] = ev->value_len;
    if (ev->value_len)
        memcpy(out + off, ev->value, ev->value_len);
    off += ev->value_len;
    memcpy(out + off, ev->update_txid, 32); off += 32;
    *out_len = off;
    return true;
}

static inline bool
ev_znam_update_parse(const void *payload, size_t len,
                     struct ev_znam_update *out)
{
    if (!payload || !out) return false;
    if (len < 1) return false;
    const uint8_t *buf = (const uint8_t *)payload;
    size_t off = 0;
    memset(out, 0, sizeof(*out));
    out->name_len = buf[off++];
    if (out->name_len == 0 || out->name_len > EV_ZNAM_NAME_MAX) return false;
    if (off + out->name_len + 3 > len) return false;
    memcpy(out->name, buf + off, out->name_len); off += out->name_len;
    out->action_type      = buf[off++];
    out->key_or_coin_type = buf[off++];
    out->key_len          = buf[off++];
    if (out->key_len > EV_ZNAM_KEY_MAX) return false;
    if (off + out->key_len + 1 > len) return false;
    if (out->key_len)
        memcpy(out->key, buf + off, out->key_len);
    off += out->key_len;
    out->value_len = buf[off++];
    if (out->value_len > EV_ZNAM_VALUE_MAX) return false;
    if (off + out->value_len + 32 > len) return false;
    if (out->value_len)
        memcpy(out->value, buf + off, out->value_len);
    off += out->value_len;
    memcpy(out->update_txid, buf + off, 32); off += 32;
    if (off != len) return false;
    return true;
}

/* ── EV_ZNAM_TRANSFER ──────────────────────────────────────────── */

static inline size_t
ev_znam_transfer_serialized_len(const struct ev_znam_transfer *ev)
{
    if (!ev) return 0;
    return (size_t)1 + ev->name_len + 1 + ev->new_owner_len + 32;
}

static inline bool
ev_znam_transfer_serialize(const struct ev_znam_transfer *ev,
                           uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ev || !out || !out_len) return false;
    if (ev->name_len == 0 || ev->name_len > EV_ZNAM_NAME_MAX) return false;
    if (ev->new_owner_len == 0 || ev->new_owner_len > EV_ZNAM_OWNER_MAX)
        return false;
    size_t need = ev_znam_transfer_serialized_len(ev);
    if (out_cap < need) return false;
    size_t off = 0;
    out[off++] = ev->name_len;
    memcpy(out + off, ev->name, ev->name_len); off += ev->name_len;
    out[off++] = ev->new_owner_len;
    memcpy(out + off, ev->new_owner, ev->new_owner_len); off += ev->new_owner_len;
    memcpy(out + off, ev->update_txid, 32); off += 32;
    *out_len = off;
    return true;
}

static inline bool
ev_znam_transfer_parse(const void *payload, size_t len,
                       struct ev_znam_transfer *out)
{
    if (!payload || !out) return false;
    if (len < 1) return false;
    const uint8_t *buf = (const uint8_t *)payload;
    size_t off = 0;
    memset(out, 0, sizeof(*out));
    out->name_len = buf[off++];
    if (out->name_len == 0 || out->name_len > EV_ZNAM_NAME_MAX) return false;
    if (off + out->name_len + 1 > len) return false;
    memcpy(out->name, buf + off, out->name_len); off += out->name_len;
    out->new_owner_len = buf[off++];
    if (out->new_owner_len == 0 || out->new_owner_len > EV_ZNAM_OWNER_MAX)
        return false;
    if (off + out->new_owner_len + 32 > len) return false;
    memcpy(out->new_owner, buf + off, out->new_owner_len);
    off += out->new_owner_len;
    memcpy(out->update_txid, buf + off, 32); off += 32;
    if (off != len) return false;
    return true;
}

/* ── EV_ZNAM_RENEW ─────────────────────────────────────────────── */

static inline size_t
ev_znam_renew_serialized_len(const struct ev_znam_renew *ev)
{
    if (!ev) return 0;
    return (size_t)1 + ev->name_len + 4 + 32;
}

static inline bool
ev_znam_renew_serialize(const struct ev_znam_renew *ev,
                        uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ev || !out || !out_len) return false;
    if (ev->name_len == 0 || ev->name_len > EV_ZNAM_NAME_MAX) return false;
    size_t need = ev_znam_renew_serialized_len(ev);
    if (out_cap < need) return false;
    size_t off = 0;
    out[off++] = ev->name_len;
    memcpy(out + off, ev->name, ev->name_len); off += ev->name_len;
    ev_put_u32_le(out + off, (uint32_t)ev->new_expiry_height); off += 4;
    memcpy(out + off, ev->update_txid, 32); off += 32;
    *out_len = off;
    return true;
}

static inline bool
ev_znam_renew_parse(const void *payload, size_t len,
                    struct ev_znam_renew *out)
{
    if (!payload || !out) return false;
    if (len < 1) return false;
    const uint8_t *buf = (const uint8_t *)payload;
    size_t off = 0;
    memset(out, 0, sizeof(*out));
    out->name_len = buf[off++];
    if (out->name_len == 0 || out->name_len > EV_ZNAM_NAME_MAX) return false;
    if (off + out->name_len + 4 + 32 != len) return false;
    memcpy(out->name, buf + off, out->name_len); off += out->name_len;
    out->new_expiry_height = (int32_t)ev_get_u32_le(buf + off); off += 4;
    memcpy(out->update_txid, buf + off, 32); off += 32;
    return true;
}

/* ── EV_ZNAM_EXPIRE ────────────────────────────────────────────── */

static inline size_t
ev_znam_expire_serialized_len(const struct ev_znam_expire *ev)
{
    if (!ev) return 0;
    return (size_t)1 + ev->name_len + 4;
}

static inline bool
ev_znam_expire_serialize(const struct ev_znam_expire *ev,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!ev || !out || !out_len) return false;
    if (ev->name_len == 0 || ev->name_len > EV_ZNAM_NAME_MAX) return false;
    size_t need = ev_znam_expire_serialized_len(ev);
    if (out_cap < need) return false;
    size_t off = 0;
    out[off++] = ev->name_len;
    memcpy(out + off, ev->name, ev->name_len); off += ev->name_len;
    ev_put_u32_le(out + off, (uint32_t)ev->expired_at_height); off += 4;
    *out_len = off;
    return true;
}

static inline bool
ev_znam_expire_parse(const void *payload, size_t len,
                     struct ev_znam_expire *out)
{
    if (!payload || !out) return false;
    if (len < 1) return false;
    const uint8_t *buf = (const uint8_t *)payload;
    size_t off = 0;
    memset(out, 0, sizeof(*out));
    out->name_len = buf[off++];
    if (out->name_len == 0 || out->name_len > EV_ZNAM_NAME_MAX) return false;
    if (off + out->name_len + 4 != len) return false;
    memcpy(out->name, buf + off, out->name_len); off += out->name_len;
    out->expired_at_height = (int32_t)ev_get_u32_le(buf + off); off += 4;
    return true;
}

#endif /* ZCL_STORAGE_EVENT_LOG_PAYLOADS_H */
