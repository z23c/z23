/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Messaging (ZMSG) — P2P messaging implementation. */

#include "net/zmsg.h"
#include "core/serialize.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"
#include <string.h>
#include <pthread.h>

/* ── Serialization ──────────────────────────────────────────────── */

bool zmsg_serialize(const struct zmsg_message *msg, struct byte_stream *s)
{
    bool ok = true;
    ok &= stream_write(s, msg->msg_id, 32);
    ok &= stream_write_i64_le(s, msg->timestamp);

    /* sender: length-prefixed string */
    size_t slen = strlen(msg->sender);
    ok &= stream_write_u8(s, (uint8_t)(slen > 127 ? 127 : slen));
    ok &= stream_write(s, msg->sender, slen > 127 ? 127 : slen);

    /* recipient */
    size_t rlen = strlen(msg->recipient);
    ok &= stream_write_u8(s, (uint8_t)(rlen > 127 ? 127 : rlen));
    ok &= stream_write(s, msg->recipient, rlen > 127 ? 127 : rlen);

    /* body: 2-byte length prefix */
    size_t blen = strlen(msg->body);
    if (blen > ZMSG_MAX_BODY) blen = ZMSG_MAX_BODY;
    ok &= stream_write_u16_le(s, (uint16_t)blen);
    ok &= stream_write(s, msg->body, blen);

    return ok;
}

bool zmsg_deserialize(struct zmsg_message *msg, struct byte_stream *s)
{
    memset(msg, 0, sizeof(*msg));
    bool ok = true;

    ok &= stream_read(s, msg->msg_id, 32);
    ok &= stream_read_i64_le(s, &msg->timestamp);

    /* all three length prefixes are peer-controlled. Reject any
     * value that would let stream_read overflow the fixed-size field OR
     * push the trailing NUL write past the buffer. Serialize caps
     * sender/recipient at 127 and body at ZMSG_MAX_BODY (4096), so a
     * conformant peer's payload always passes these bounds. */
    uint8_t slen = 0;
    ok &= stream_read_u8(s, &slen);
    if (!ok) LOG_FAIL("zmsg", "deserialize: read sender length failed");
    if (slen >= ZMSG_MAX_ADDR)
        LOG_FAIL("zmsg", "deserialize: sender length out of range "
                 "(slen=%u, max=%d)", slen, ZMSG_MAX_ADDR - 1);
    ok &= stream_read(s, msg->sender, slen);
    msg->sender[slen] = '\0';

    uint8_t rlen = 0;
    ok &= stream_read_u8(s, &rlen);
    if (!ok) LOG_FAIL("zmsg", "deserialize: read recipient length failed");
    if (rlen >= ZMSG_MAX_ADDR)
        LOG_FAIL("zmsg", "deserialize: recipient length out of range "
                 "(rlen=%u, max=%d)", rlen, ZMSG_MAX_ADDR - 1);
    ok &= stream_read(s, msg->recipient, rlen);
    msg->recipient[rlen] = '\0';

    uint16_t blen = 0;
    ok &= stream_read_u16_le(s, &blen);
    if (!ok || blen >= ZMSG_MAX_BODY)
        LOG_FAIL("zmsg", "deserialize: body length invalid "
                 "(blen=%u, max=%d)", blen, ZMSG_MAX_BODY - 1);
    ok &= stream_read(s, msg->body, blen);
    msg->body[blen] = '\0';

    return ok;
}

/* ── On-chain memo codec (v1) ───────────────────────────────────── */

bool zmsg_memo_encode(uint8_t out[ZMSG_MEMO_LEN],
                      const uint8_t *payload, size_t payload_len,
                      const uint8_t reply_to[32])
{
    if (!out) LOG_FAIL("zmsg", "memo_encode: out is NULL");
    if (payload_len > ZMSG_MEMO_MAX_PAYLOAD)
        LOG_FAIL("zmsg", "memo_encode: payload_len %zu exceeds max %d",
                 payload_len, ZMSG_MEMO_MAX_PAYLOAD);
    if (payload_len > 0 && !payload)
        LOG_FAIL("zmsg", "memo_encode: payload NULL but payload_len=%zu",
                 payload_len);

    memset(out, ZMSG_MEMO_PAD_BYTE, ZMSG_MEMO_LEN);
    out[0] = ZMSG_MEMO_MAGIC_0;
    out[1] = ZMSG_MEMO_MAGIC_1;
    out[2] = ZMSG_MEMO_VERSION;
    out[3] = reply_to ? ZMSG_MEMO_FLAG_HAS_REPLY_TO : 0;
    out[4] = (uint8_t)(payload_len & 0xFF);
    out[5] = (uint8_t)((payload_len >> 8) & 0xFF);
    if (reply_to)
        memcpy(out + 6, reply_to, 32);
    else
        memset(out + 6, 0, 32);
    if (payload_len > 0)
        memcpy(out + ZMSG_MEMO_HEADER_LEN, payload, payload_len);
    return true;
}

bool zmsg_memo_decode(const uint8_t memo[ZMSG_MEMO_LEN], struct zmsg_memo *out)
{
    if (!memo || !out) LOG_FAIL("zmsg", "memo_decode: NULL arg");
    memset(out, 0, sizeof(*out));

    /* Not a ZMSG memo is the common, benign case (every non-ZMSG shielded
     * note passes through here) — return false quietly, do NOT log-spam. */
    if (memo[0] != ZMSG_MEMO_MAGIC_0 || memo[1] != ZMSG_MEMO_MAGIC_1)
        return false;
    if (memo[2] != ZMSG_MEMO_VERSION)
        return false;
    uint8_t flags = memo[3];
    if (flags & ~(uint8_t)ZMSG_MEMO_FLAGS_KNOWN)
        return false;                       /* reserved flag bit set */
    uint16_t plen = (uint16_t)memo[4] | ((uint16_t)memo[5] << 8);
    if (plen > ZMSG_MEMO_MAX_PAYLOAD)
        return false;                       /* payload runs past the memo */

    out->version = memo[2];
    out->flags = flags;
    out->has_reply_to = (flags & ZMSG_MEMO_FLAG_HAS_REPLY_TO) != 0;
    memcpy(out->reply_to, memo + 6, 32);
    out->payload_len = plen;
    if (plen > 0)
        memcpy(out->payload, memo + ZMSG_MEMO_HEADER_LEN, plen);
    return true;
}

void zmsg_compute_id(const struct zmsg_message *msg, uint8_t out[32])
{
    if (!msg || !out) return;
    struct sha3_256_ctx sha3;
    sha3_256_init(&sha3);
    sha3_256_write(&sha3, (const unsigned char *)&msg->timestamp, 8);
    sha3_256_write(&sha3, (const unsigned char *)msg->sender,
                   strlen(msg->sender));
    sha3_256_write(&sha3, (const unsigned char *)msg->body,
                   strlen(msg->body));
    sha3_256_finalize(&sha3, out);
}

/* ── In-Memory Store ────────────────────────────────────────────── */

static struct zmsg_message g_messages[ZMSG_MAX_STORED];
static int g_msg_count = 0;
static pthread_mutex_t g_zmsg_mutex = PTHREAD_MUTEX_INITIALIZER;

bool zmsg_store_add(const struct zmsg_message *msg)
{
    if (!msg) LOG_FAIL("zmsg", "store_add: msg is NULL");
    pthread_mutex_lock(&g_zmsg_mutex);

    /* Check for duplicate */
    for (int i = 0; i < g_msg_count; i++) {
        if (memcmp(g_messages[i].msg_id, msg->msg_id, 32) == 0) {
            pthread_mutex_unlock(&g_zmsg_mutex);
            return false;
        }
    }

    if (g_msg_count >= ZMSG_MAX_STORED) {
        /* Evict oldest */
        memmove(&g_messages[0], &g_messages[1],
                (ZMSG_MAX_STORED - 1) * sizeof(struct zmsg_message));
        g_msg_count = ZMSG_MAX_STORED - 1;
    }

    g_messages[g_msg_count] = *msg;
    g_msg_count++;
    pthread_mutex_unlock(&g_zmsg_mutex);
    return true;
}

int zmsg_store_list(struct zmsg_message *out, size_t max,
                    bool unread_only)
{
    if (!out) LOG_ERR("zmsg", "store_list: out is NULL");
    pthread_mutex_lock(&g_zmsg_mutex);
    int count = 0;
    /* Return newest first */
    for (int i = g_msg_count - 1; i >= 0 && (size_t)count < max; i--) {
        if (unread_only && g_messages[i].read) continue;
        out[count++] = g_messages[i];
    }
    pthread_mutex_unlock(&g_zmsg_mutex);
    return count;
}

bool zmsg_store_mark_read(const uint8_t msg_id[32])
{
    pthread_mutex_lock(&g_zmsg_mutex);
    for (int i = 0; i < g_msg_count; i++) {
        if (memcmp(g_messages[i].msg_id, msg_id, 32) == 0) {
            g_messages[i].read = true;
            pthread_mutex_unlock(&g_zmsg_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&g_zmsg_mutex);
    return false;
}

int zmsg_store_count(void)
{
    pthread_mutex_lock(&g_zmsg_mutex);
    int c = g_msg_count;
    pthread_mutex_unlock(&g_zmsg_mutex);
    return c;
}

int zmsg_store_count_unread(void)
{
    pthread_mutex_lock(&g_zmsg_mutex);
    int c = 0;
    for (int i = 0; i < g_msg_count; i++)
        if (!g_messages[i].read)
            c++;
    pthread_mutex_unlock(&g_zmsg_mutex);
    return c;
}
