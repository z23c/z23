/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The row: its canonical bytes, its hash, its signature.
 *
 * There is exactly ONE encoding of a row. That is not tidiness — a
 * signature over bytes that could have been written two ways is a
 * signature over nothing in particular, so every degree of freedom is
 * closed here rather than left to a caller: pairs are ascending by key with
 * no repeats, the note carries no NUL and no control byte, unused bytes do
 * not exist because there is no padding, and a field outside its bound
 * refuses rather than being clamped.
 *
 * Decode is written as the exact inverse and is the ONLY way bytes from
 * another machine become a row. It never trusts a length it has not
 * checked against what is actually there.
 */

#include "fleetledger/fleet_ledger.h"

#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "sha3/sha3.h"

#include <string.h>

/* The domain tag is INSIDE every hash and every signature. A row's bytes
 * therefore mean something only in this protocol: they cannot be replayed
 * as a signature over some other structure that happens to share a prefix. */
static void domain_write(struct sha3_256_ctx *ctx)
{
    sha3_256_write(ctx, (const unsigned char *)ZCL_FLEET_DOMAIN,
                   sizeof(ZCL_FLEET_DOMAIN)); /* includes the NUL */
}

void zcl_fleet_row_hash(const uint8_t *encoded, size_t len,
                        uint8_t out[ZCL_FLEET_HASH_BYTES])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    domain_write(&ctx);
    if (encoded && len)
        sha3_256_write(&ctx, (const unsigned char *)encoded, len);
    sha3_256_finalize(&ctx, (unsigned char *)out);
}

/* A note is a task id, a lane name, a unit name — something a person reads.
 * Control bytes in it would let a row rewrite a terminal that prints it, so
 * they are refused at the boundary rather than escaped at every printer. */
static bool note_bytes_ok(const char *note, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)note[i];
        if (c < 0x20u || c == 0x7fu)
            return false;
    }
    return true;
}

enum zcl_fleet_status zcl_fleet_row_validate(const struct zcl_fleet_row *row)
{
    if (!row)
        return ZCL_FLEET_ARGUMENT;
    if (row->seq == 0)
        return ZCL_FLEET_SEQUENCE;
    if (!zcl_fleet_kind_name(row->kind))
        return ZCL_FLEET_KIND_UNKNOWN;
    if (!zcl_fleet_subject_name(row->kind, row->subject))
        return row->kind == ZCL_FLEET_KIND_VITALS ? ZCL_FLEET_VITAL_UNKNOWN
                                                  : ZCL_FLEET_SUBJECT_UNKNOWN;
    if (row->pair_count > ZCL_FLEET_PAIRS_MAX)
        return ZCL_FLEET_MALFORMED;
    if (row->note_len > ZCL_FLEET_NOTE_MAX)
        return ZCL_FLEET_MALFORMED;
    if (!note_bytes_ok(row->note, row->note_len))
        return ZCL_FLEET_MALFORMED;
    /* Ascending with no repeats: one canonical order, and a key can never
     * appear twice so a sum can never double-count one row. */
    for (size_t i = 0; i < row->pair_count; i++) {
        uint8_t key = row->pair[i].key;
        if (!zcl_fleet_pair_name(key))
            return ZCL_FLEET_PAIR_UNKNOWN;
        if (i > 0 && key <= row->pair[i - 1].key)
            return ZCL_FLEET_MALFORMED;
    }
    return ZCL_FLEET_OK;
}

static size_t row_body_bytes(const struct zcl_fleet_row *row)
{
    return ZCL_FLEET_ROW_HEAD_BYTES +
           (size_t)row->pair_count * ZCL_FLEET_ROW_PAIR_BYTES +
           (size_t)row->note_len;
}

/* Everything but the signature: what the signature is OVER, and the prefix
 * every encoded row starts with. */
static size_t row_write_body(const struct zcl_fleet_row *row, uint8_t *out)
{
    size_t n = 0;
    out[n++] = (uint8_t)ZCL_FLEET_ROW_VERSION;
    out[n++] = row->kind;
    out[n++] = (uint8_t)(row->subject >> 8);
    out[n++] = (uint8_t)(row->subject & 0xffu);
    out[n++] = row->pair_count;
    out[n++] = row->note_len;
    zcl_write_u64_be(out + n, row->seq);
    n += 8;
    zcl_write_u64_be(out + n, (uint64_t)row->ts_unix);
    n += 8;
    memcpy(out + n, row->box_id, ZCL_FLEET_ID_BYTES);
    n += ZCL_FLEET_ID_BYTES;
    memcpy(out + n, row->prev_hash, ZCL_FLEET_HASH_BYTES);
    n += ZCL_FLEET_HASH_BYTES;
    for (size_t i = 0; i < row->pair_count; i++) {
        out[n++] = row->pair[i].key;
        zcl_write_u64_be(out + n, (uint64_t)row->pair[i].value);
        n += 8;
    }
    if (row->note_len)
        memcpy(out + n, row->note, row->note_len);
    n += row->note_len;
    return n;
}

size_t zcl_fleet_row_encode(const struct zcl_fleet_row *row, uint8_t *out,
                            size_t cap)
{
    if (!row || !out || zcl_fleet_row_validate(row) != ZCL_FLEET_OK)
        return 0;
    size_t body = row_body_bytes(row);
    if (cap < body + ZCL_FLEET_SIG_BYTES)
        return 0;
    size_t n = row_write_body(row, out);
    memcpy(out + n, row->sig, ZCL_FLEET_SIG_BYTES);
    return n + ZCL_FLEET_SIG_BYTES;
}

enum zcl_fleet_status zcl_fleet_row_decode(const uint8_t *in, size_t len,
                                           struct zcl_fleet_row *out,
                                           size_t *consumed)
{
    if (!in || !out)
        return ZCL_FLEET_ARGUMENT;
    if (len < ZCL_FLEET_ROW_HEAD_BYTES + ZCL_FLEET_SIG_BYTES)
        return ZCL_FLEET_MALFORMED;
    if (in[0] != (uint8_t)ZCL_FLEET_ROW_VERSION)
        return ZCL_FLEET_MALFORMED;

    memset(out, 0, sizeof(*out));
    out->kind = in[1];
    out->subject = (uint16_t)(((uint16_t)in[2] << 8) | (uint16_t)in[3]);
    out->pair_count = in[4];
    out->note_len = in[5];
    if (out->pair_count > ZCL_FLEET_PAIRS_MAX ||
        out->note_len > ZCL_FLEET_NOTE_MAX)
        return ZCL_FLEET_MALFORMED;

    /* The length is derived from the counts and checked against what is
     * actually in the buffer BEFORE any of it is read. */
    size_t body = ZCL_FLEET_ROW_HEAD_BYTES +
                  (size_t)out->pair_count * ZCL_FLEET_ROW_PAIR_BYTES +
                  (size_t)out->note_len;
    if (len < body + ZCL_FLEET_SIG_BYTES)
        return ZCL_FLEET_MALFORMED;

    size_t n = 6;
    out->seq = zcl_read_u64_be(in + n);
    n += 8;
    out->ts_unix = (int64_t)zcl_read_u64_be(in + n);
    n += 8;
    memcpy(out->box_id, in + n, ZCL_FLEET_ID_BYTES);
    n += ZCL_FLEET_ID_BYTES;
    memcpy(out->prev_hash, in + n, ZCL_FLEET_HASH_BYTES);
    n += ZCL_FLEET_HASH_BYTES;
    for (size_t i = 0; i < out->pair_count; i++) {
        out->pair[i].key = in[n++];
        out->pair[i].value = (int64_t)zcl_read_u64_be(in + n);
        n += 8;
    }
    if (out->note_len)
        memcpy(out->note, in + n, out->note_len);
    n += out->note_len;
    memcpy(out->sig, in + n, ZCL_FLEET_SIG_BYTES);

    enum zcl_fleet_status shape = zcl_fleet_row_validate(out);
    if (shape != ZCL_FLEET_OK)
        return shape;
    if (consumed)
        *consumed = body + ZCL_FLEET_SIG_BYTES;
    return ZCL_FLEET_OK;
}

/* The message a signature covers: the domain tag, then the body. The tag is
 * separate from the body rather than a prefix inside it, so no row content
 * can ever be arranged to look like the tag. */
static size_t sign_message(const struct zcl_fleet_row *row,
                           uint8_t out[sizeof(ZCL_FLEET_DOMAIN) +
                                       ZCL_FLEET_ROW_MAX_BYTES])
{
    memcpy(out, ZCL_FLEET_DOMAIN, sizeof(ZCL_FLEET_DOMAIN));
    size_t n = sizeof(ZCL_FLEET_DOMAIN);
    n += row_write_body(row, out + n);
    return n;
}

enum zcl_fleet_status zcl_fleet_row_sign(
    struct zcl_fleet_row *row, const uint8_t seed[ZCL_FLEET_SEED_BYTES])
{
    if (!row || !seed)
        return ZCL_FLEET_ARGUMENT;
    enum zcl_fleet_status shape = zcl_fleet_row_validate(row);
    if (shape != ZCL_FLEET_OK)
        return shape;

    /* The row says who wrote it; this proves the seed agrees. A row signed
     * by a key that is not its box_id would verify nowhere and would be
     * discovered only by the peer that received it. */
    uint8_t pk[32];
    uint8_t sk[32];
    zcl_ed25519_keypair(pk, sk, seed);
    if (memcmp(pk, row->box_id, ZCL_FLEET_ID_BYTES) != 0) {
        memset(sk, 0, sizeof sk);
        return ZCL_FLEET_SIG_INVALID;
    }

    uint8_t msg[sizeof(ZCL_FLEET_DOMAIN) + ZCL_FLEET_ROW_MAX_BYTES];
    size_t msg_len = sign_message(row, msg);
    zcl_ed25519_sign(row->sig, msg, msg_len, sk, pk);
    memset(sk, 0, sizeof sk);
    return ZCL_FLEET_OK;
}

enum zcl_fleet_status zcl_fleet_row_verify(const struct zcl_fleet_row *row)
{
    if (!row)
        return ZCL_FLEET_ARGUMENT;
    enum zcl_fleet_status shape = zcl_fleet_row_validate(row);
    if (shape != ZCL_FLEET_OK)
        return shape;
    uint8_t msg[sizeof(ZCL_FLEET_DOMAIN) + ZCL_FLEET_ROW_MAX_BYTES];
    size_t msg_len = sign_message(row, msg);
    if (!ed25519_verify(row->sig, msg, msg_len, row->box_id))
        return ZCL_FLEET_SIG_INVALID;
    return ZCL_FLEET_OK;
}

uint32_t zcl_fleet_day_of(int64_t ts_unix)
{
    /* UTC day number since the epoch. A negative timestamp is not a time
     * this ledger records, so it lands in day 0 rather than wrapping. */
    if (ts_unix <= 0)
        return 0;
    return (uint32_t)(ts_unix / 86400);
}
