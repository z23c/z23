/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Messaging (ZMSG) — P2P + on-chain messaging.
 *
 * Two modes:
 *   Off-chain: direct P2P messages between connected nodes (instant, free).
 *              PLAINTEXT on the wire — zmsg_serialize writes a plain
 *              length-prefixed struct and rpc_msg_send hands the body
 *              straight to the socket; transport encryption is not yet
 *              implemented.
 *   On-chain:  rides inside the 512-byte encrypted Sapling memo field of a
 *              shielded transaction (permanent, paid) — the memo encryption
 *              is real (Sapling note encryption), the payload itself is not
 *              separately encrypted.
 *
 * P2P messages:
 *   zmsg    — plaintext message delivery
 *   zmsgack — delivery acknowledgment */

#ifndef ZCL_NET_ZMSG_H
#define ZCL_NET_ZMSG_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* P2P message commands */
#define MSG_ZMSG     "zmsg"
#define MSG_ZMSG_ACK "zmsgack"

/* Limits */
#define ZMSG_MAX_BODY    4096
#define ZMSG_MAX_ADDR    128
#define ZMSG_MAX_STORED  1000

/* Direction */
#define ZMSG_INBOUND  0
#define ZMSG_OUTBOUND 1

/* Channel */
#define ZMSG_CHANNEL_ONCHAIN 0
#define ZMSG_CHANNEL_P2P     1

/* On-chain memo magic */
#define ZMSG_MEMO_MAGIC_0  0x5A  /* 'Z' */
#define ZMSG_MEMO_MAGIC_1  0x4D  /* 'M' */

/* ── On-chain ZMSG memo wire format (v1) ────────────────────────────
 *
 * An on-chain ZMSG rides inside the 512-byte encrypted Sapling memo of a
 * shielded output (consensus treats the memo as opaque free-form bytes, so
 * this format changes NO consensus predicate). Fixed 38-byte header; the
 * reply-to field is always present (all-zero when unused) so decode needs no
 * variable-offset arithmetic. Layout, all integers little-endian:
 *
 *   Offset  Size  Field         Notes
 *   0       1     magic0        = 0x5A ('Z')
 *   1       1     magic1        = 0x4D ('M')
 *   2       1     version       = 0x01 (ZMSG_MEMO_VERSION)
 *   3       1     flags         bit0 = HAS_REPLY_TO; bits 1-7 reserved (0)
 *   4       2     payload_len   count of UTF-8 payload bytes, <= 474
 *   6       32    reply_to      parent msg_id; all-zero when HAS_REPLY_TO clear
 *   38      N     payload       UTF-8 message body (N = payload_len)
 *   38+N    ...   padding       0xF6 to fill the 512-byte memo (Sapling convention)
 *
 * Max payload = 512 - 38 = 474 bytes. Decode is strict: it rejects a wrong
 * magic, an unknown version, any reserved flag bit, or a payload_len past the
 * 474-byte ceiling. See docs/ZMSG_ONCHAIN.md for the full spec. */

#define ZMSG_MEMO_LEN            512
#define ZMSG_MEMO_VERSION        0x01
#define ZMSG_MEMO_HEADER_LEN     38
#define ZMSG_MEMO_MAX_PAYLOAD    (ZMSG_MEMO_LEN - ZMSG_MEMO_HEADER_LEN)  /* 474 */
#define ZMSG_MEMO_PAD_BYTE       0xF6
#define ZMSG_MEMO_FLAG_HAS_REPLY_TO 0x01
#define ZMSG_MEMO_FLAGS_KNOWN    ZMSG_MEMO_FLAG_HAS_REPLY_TO

/* Dust-tier value (zatoshis) carried by the shielded output of an on-chain
 * ZMSG. The message rides in the memo; the value is incidental. */
#define ZMSG_ONCHAIN_DUST_ZAT    1000

/* Decoded view of an on-chain ZMSG memo. payload is NOT NUL-terminated;
 * payload_len is authoritative. */
struct zmsg_memo {
    uint8_t  version;
    uint8_t  flags;
    bool     has_reply_to;
    uint8_t  reply_to[32];
    uint16_t payload_len;
    uint8_t  payload[ZMSG_MEMO_MAX_PAYLOAD];
};

/* Encode a ZMSG into the 512-byte Sapling memo buffer `out` (0xF6-padded).
 * `payload`/`payload_len` is the UTF-8 body (payload_len <= ZMSG_MEMO_MAX_PAYLOAD;
 * may be NULL only when payload_len == 0). `reply_to` is a 32-byte parent
 * msg_id, or NULL for a fresh (non-reply) message. Returns false (and logs) on
 * a NULL out or an over-long payload; on failure `out` is left unmodified. */
bool zmsg_memo_encode(uint8_t out[ZMSG_MEMO_LEN],
                      const uint8_t *payload, size_t payload_len,
                      const uint8_t reply_to[32]);

/* Parse a 512-byte Sapling memo as a ZMSG. Returns true only when the magic,
 * version, flags, and payload_len all validate; false (no log — a non-ZMSG
 * memo is the common, benign case) otherwise. `out` is zeroed first. Caller
 * must pass non-NULL memo and out. */
bool zmsg_memo_decode(const uint8_t memo[ZMSG_MEMO_LEN], struct zmsg_memo *out);

/* ── P2P Message Struct ─────────────────────────────────────────── */

struct zmsg_message {
    uint8_t  msg_id[32];        /* SHA3(timestamp || sender || body) */
    int      direction;         /* ZMSG_INBOUND / ZMSG_OUTBOUND */
    int      channel;           /* ZMSG_CHANNEL_* */
    char     sender[ZMSG_MAX_ADDR];
    char     recipient[ZMSG_MAX_ADDR];
    char     body[ZMSG_MAX_BODY];
    int64_t  timestamp;
    uint8_t  txid[32];          /* non-zero for on-chain */
    bool     read;
};

/* ── Serialization ──────────────────────────────────────────────── */

struct byte_stream;

/* Write msg onto stream s in wire form (msg_id, timestamp, then
 * length-prefixed sender/recipient/body). Caller must pass non-NULL
 * msg and s; neither is null-checked. sender/recipient are capped at
 * 127 bytes and body at ZMSG_MAX_BODY on the wire. Returns true only
 * if every field was written. */
bool zmsg_serialize(const struct zmsg_message *msg, struct byte_stream *s);

/* Read a message from stream s into msg (zeroed first). Caller must
 * pass non-NULL msg and s; neither is null-checked. Peer-controlled
 * length prefixes are bounds-checked against the fixed-size fields.
 * Returns true only if every field was read and in range; false on a
 * short/over-long stream. */
bool zmsg_deserialize(struct zmsg_message *msg, struct byte_stream *s);

/* Compute msg_id from message contents */
void zmsg_compute_id(const struct zmsg_message *msg, uint8_t out[32]);

/* ── In-Memory Message Store ────────────────────────────────────── */

/* Add a message to the store. Returns true if new. */
bool zmsg_store_add(const struct zmsg_message *msg);

/* Get messages. Returns count written to out (up to max). */
int zmsg_store_list(struct zmsg_message *out, size_t max,
                    bool unread_only);

/* Snapshot one inbox window and its uncapped total under the same mutex.
 * Rows are newest-first and use the same unread predicate as
 * zmsg_store_list(). `written_out` and `total_out` are zeroed before any
 * refusal; out may be NULL only when max is zero. The total is exact for the
 * same instant as the copied rows, so concurrent delivery/read changes cannot
 * make pagination metadata disagree with its window. */
bool zmsg_store_inbox_window(struct zmsg_message *out, size_t max,
                             bool unread_only, size_t *written_out,
                             int64_t *total_out);

/* Mark a message as read by msg_id. */
bool zmsg_store_mark_read(const uint8_t msg_id[32]);

/* Get message count. */
int zmsg_store_count(void);

/* Count only unread messages — the same predicate zmsg_store_list applies
 * with unread_only=true, so an inbox window can be measured against it. */
int zmsg_store_count_unread(void);

/* ── SQLite Persistence ─────────────────────────────────────────── */

struct node_db;

bool db_zmsg_save(struct node_db *ndb, const struct zmsg_message *msg);
int db_zmsg_list(struct node_db *ndb, struct zmsg_message *out,
                 size_t max, bool unread_only);
/* Uncapped total behind the db_zmsg_list window under the same unread
 * filter. -1 only when the store is unreadable. Documented alongside the
 * model in models/zmsg.h. */
int db_zmsg_count(struct node_db *ndb, bool unread_only);
bool db_zmsg_inbox_window(struct node_db *ndb, struct zmsg_message *out,
                          size_t max, bool unread_only, size_t *rows_out,
                          int64_t *total_out);
bool db_zmsg_mark_read(struct node_db *ndb, const uint8_t msg_id[32]);

#endif
