/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZDESC — onion-service descriptor body codec. See zid/zdesc.h for the
 * frozen wire, the size argument (942-byte doc vs a 223-byte OP_RETURN
 * cap), and the period contract. Pure: no allocation, no store, no
 * network, no chain. */

#include "zid/zdesc.h"

#include "base/serialize_le.h"
#include "zid/zid.h"
#include "base/log_macros.h"

#include <string.h>

#define ZDESC_LOG "zid.desc"

bool zdesc_onion_valid(const char *host)
{
    if (!host)
        return false;
    if (strlen(host) != (size_t)ZDESC_ONION_LEN)
        return false;
    if (strcmp(host + 56, ".onion") != 0)
        return false;
    for (size_t i = 0; i < 56; i++) {
        char c = host[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')))
            return false;
    }
    return true;
}

size_t zdesc_encode_body(uint8_t *out, size_t out_len,
                         const struct zdesc *desc)
{
    if (!out || !desc)
        LOG_RETURN(0, ZDESC_LOG, "encode: NULL argument (out=%p desc=%p)",
                   (void *)out, (const void *)desc);
    if (!zdesc_onion_valid(desc->onion))
        LOG_RETURN(0, ZDESC_LOG,
                   "encode: service hostname is not a v3 onion "
                   "(56 base32 a-z2-7 chars + \".onion\")");
    if (desc->intro_count > ZDESC_INTRO_MAX)
        LOG_RETURN(0, ZDESC_LOG, "encode: intro_count %u exceeds max %d",
                   desc->intro_count, ZDESC_INTRO_MAX);
    for (uint8_t i = 0; i < desc->intro_count; i++) {
        if (!zdesc_onion_valid(desc->intro[i].onion))
            LOG_RETURN(0, ZDESC_LOG,
                       "encode: introduction point %u hostname is not a v3 "
                       "onion", i);
    }

    size_t total = (size_t)ZDESC_BODY_MIN +
                   (size_t)desc->intro_count * (size_t)ZDESC_INTRO_WIRE;
    if (out_len < total)
        LOG_RETURN(0, ZDESC_LOG, "encode: out_len %zu too small (need %zu)",
                   out_len, total);

    size_t n = 0;
    memcpy(out + n, "ZIDD", 4);
    n += 4;
    memcpy(out + n, desc->onion, ZDESC_ONION_LEN);
    n += ZDESC_ONION_LEN;
    zcl_write_u64_le(out + n, desc->not_before);
    n += 8;
    out[n++] = desc->intro_count;
    for (uint8_t i = 0; i < desc->intro_count; i++) {
        memcpy(out + n, desc->intro[i].onion, ZDESC_ONION_LEN);
        n += ZDESC_ONION_LEN;
        memcpy(out + n, desc->intro[i].auth_key, 32);
        n += 32;
    }
    return n;
}

bool zdesc_decode_body(struct zdesc *desc, const uint8_t *body,
                       uint16_t body_len)
{
    if (!desc || !body)
        LOG_FAIL(ZDESC_LOG, "decode: NULL argument (desc=%p body=%p)",
                 (void *)desc, (const void *)body);
    if (body_len < ZDESC_BODY_MIN)
        LOG_FAIL(ZDESC_LOG, "decode: body_len %u below minimum %d", body_len,
                 ZDESC_BODY_MIN);
    if (body_len > ZDESC_BODY_MAX)
        LOG_FAIL(ZDESC_LOG, "decode: body_len %u exceeds max %d", body_len,
                 ZDESC_BODY_MAX);
    if (memcmp(body, "ZIDD", 4) != 0)
        LOG_FAIL(ZDESC_LOG, "decode: bad tag (want ZIDD)");

    uint8_t count = body[4 + ZDESC_ONION_LEN + 8];
    if (count > ZDESC_INTRO_MAX)
        LOG_FAIL(ZDESC_LOG, "decode: intro_count %u exceeds max %d", count,
                 ZDESC_INTRO_MAX);
    size_t want = (size_t)ZDESC_BODY_MIN +
                  (size_t)count * (size_t)ZDESC_INTRO_WIRE;
    if ((size_t)body_len != want)
        LOG_FAIL(ZDESC_LOG,
                 "decode: body_len %u does not match intro_count %u "
                 "(want exactly %zu — no trailing bytes)",
                 body_len, count, want);

    memset(desc, 0, sizeof(*desc));
    memcpy(desc->onion, body + 4, ZDESC_ONION_LEN);
    desc->not_before = zcl_read_u64_le(body + 4 + ZDESC_ONION_LEN);
    desc->intro_count = count;
    size_t at = ZDESC_BODY_MIN;
    for (uint8_t i = 0; i < count; i++) {
        memcpy(desc->intro[i].onion, body + at, ZDESC_ONION_LEN);
        memcpy(desc->intro[i].auth_key, body + at + ZDESC_ONION_LEN, 32);
        at += ZDESC_INTRO_WIRE;
    }

    /* Trailing NULs come from the memset; now prove the bytes are a
     * real v3 hostname. A control byte or a wrong alphabet is a reject,
     * not a silent sanitize (same discipline as zid_release_decode_body). */
    if (!zdesc_onion_valid(desc->onion))
        LOG_FAIL(ZDESC_LOG, "decode: service hostname is not a v3 onion");
    for (uint8_t i = 0; i < count; i++) {
        if (!zdesc_onion_valid(desc->intro[i].onion))
            LOG_FAIL(ZDESC_LOG,
                     "decode: introduction point %u hostname is not a v3 "
                     "onion", i);
    }
    return true;
}

bool zdesc_sign(struct zid_doc *doc, const struct zdesc *desc, uint64_t seq,
                uint64_t expiry, const uint8_t seed[32])
{
    if (!doc || !desc || !seed)
        LOG_FAIL(ZDESC_LOG, "sign: NULL argument");
    if (expiry <= desc->not_before)
        LOG_FAIL(ZDESC_LOG,
                 "sign: expiry %llu is not after not_before %llu — the "
                 "validity window never opens",
                 (unsigned long long)expiry,
                 (unsigned long long)desc->not_before);
    uint8_t body[ZDESC_BODY_MAX];
    size_t body_len = zdesc_encode_body(body, sizeof(body), desc);
    if (body_len == 0)
        LOG_FAIL(ZDESC_LOG, "sign: body encode failed");
    if (!zid_doc_sign(doc, body, (uint16_t)body_len, seq, expiry, seed))
        LOG_FAIL(ZDESC_LOG, "sign: doc sign failed");
    return true;
}

bool zdesc_verify(const struct zid_doc *doc, struct zdesc *desc_out,
                  uint64_t now_unix)
{
    if (!doc)
        LOG_FAIL(ZDESC_LOG, "verify: NULL doc");
    if (!zid_doc_verify(doc, now_unix))
        LOG_FAIL(ZDESC_LOG, "verify: doc verify failed (signature or expiry)");
    struct zdesc desc;
    if (!zdesc_decode_body(&desc, doc->body, doc->body_len))
        LOG_FAIL(ZDESC_LOG, "verify: body is not a valid ZIDD descriptor");
    if (now_unix < desc.not_before)
        LOG_FAIL(ZDESC_LOG,
                 "verify: descriptor not yet valid (now %llu < not_before "
                 "%llu)", (unsigned long long)now_unix,
                 (unsigned long long)desc.not_before);
    if (desc_out)
        *desc_out = desc;
    return true;
}

uint64_t zdesc_period_at(uint64_t now_unix)
{
    return now_unix / (uint64_t)ZDESC_PERIOD_SECONDS;
}

uint64_t zdesc_period_prev(uint64_t period)
{
    return period == 0 ? 0 : period - 1;
}

void zdesc_record_key(uint8_t out[32], const uint8_t master_pubkey[32],
                      uint64_t period)
{
    zid_blinded_key(out, master_pubkey, period);
}
