/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The fleet carriage lane's frame codecs: the pull question, the
 * answer head and the framed answer records, with the check that a whole
 * answer adds up before any of it is used. Pure byte work, moved out of
 * boot_fleet_board_fleet.c so the stream lane keeps to its size limit.
 */

#include "boot_fleet_board_frame_internal.h"

#include "base/serialize_le.h"
#include "models/fleet_board_post.h"

#include <string.h>

size_t board_pull_encode(int64_t after,
                         uint8_t out[FLEET_BOARD_FLEET_PULL_BYTES])
{
    out[0] = (uint8_t)FLEET_BOARD_FLEET_MSG_PULL;
    out[1] = (uint8_t)FLEET_BOARD_FLEET_VERSION;
    zcl_write_u64_be(out + 2, (uint64_t)after);
    return FLEET_BOARD_FLEET_PULL_BYTES;
}

bool board_pull_decode(const uint8_t *in, size_t len, int64_t *after_out)
{
    if (!in || len != FLEET_BOARD_FLEET_PULL_BYTES ||
        in[0] != (uint8_t)FLEET_BOARD_FLEET_MSG_PULL ||
        in[1] != (uint8_t)FLEET_BOARD_FLEET_VERSION)
        return false;
    uint64_t after = zcl_read_u64_be(in + 2);
    if (after > (uint64_t)INT64_MAX)
        return false;
    *after_out = (int64_t)after;
    return true;
}

void board_answer_head_encode(
    const uint8_t epoch[FLEET_BOARD_FLEET_EPOCH_BYTES], int64_t scanned,
    uint8_t *out)
{
    out[0] = (uint8_t)FLEET_BOARD_FLEET_MSG_ANSWER;
    out[1] = (uint8_t)FLEET_BOARD_FLEET_VERSION;
    memcpy(out + 2, epoch, FLEET_BOARD_FLEET_EPOCH_BYTES);
    zcl_write_u64_be(out + 2 + FLEET_BOARD_FLEET_EPOCH_BYTES,
                     (uint64_t)scanned);
}

bool board_answer_head_decode(const uint8_t *in, size_t len,
                              struct board_answer_head *out)
{
    if (!in || len < FLEET_BOARD_FLEET_ANSWER_HEAD ||
        in[0] != (uint8_t)FLEET_BOARD_FLEET_MSG_ANSWER ||
        in[1] != (uint8_t)FLEET_BOARD_FLEET_VERSION)
        return false;
    memcpy(out->epoch, in + 2, FLEET_BOARD_FLEET_EPOCH_BYTES);
    uint64_t scanned = zcl_read_u64_be(in + 2 + FLEET_BOARD_FLEET_EPOCH_BYTES);
    if (scanned > (uint64_t)INT64_MAX)
        return false;
    out->scanned = (int64_t)scanned;
    return true;
}

bool board_answer_visit(const struct db_fleet_board_post *row, void *ctx)
{
    struct board_answer *a = ctx;
    const size_t head = FLEET_BOARD_FLEET_RECORD_HEAD;
    if (a->count >= FLEET_BOARD_FLEET_ANSWER_POSTS_MAX ||
        a->cap - a->len <= head)
        return false;
    uint8_t *at = a->buf + a->len;
    size_t wire_len = 0;
    if (fleet_board_post_encode(&row->post, at + head, a->cap - a->len - head,
                                &wire_len) != FLEET_BOARD_OK)
        return false;
    zcl_write_u64_be(at, (uint64_t)row->arrival);
    memcpy(at + 8, row->post.id, 32);
    zcl_write_u32_be(at + 40, (uint32_t)wire_len);
    a->len += head + wire_len;
    a->count++;
    return true;
}

bool board_record_next(const uint8_t *buf, size_t len, size_t *off,
                       struct board_record *rec)
{
    const size_t head = FLEET_BOARD_FLEET_RECORD_HEAD;
    if (*off >= len || len - *off < head)
        return false;
    const uint8_t *at = buf + *off;
    uint64_t arrival = zcl_read_u64_be(at);
    uint32_t wire_len = zcl_read_u32_be(at + 40);
    if (arrival > (uint64_t)INT64_MAX || wire_len == 0 ||
        wire_len > len - *off - head)
        return false;
    rec->arrival = (int64_t)arrival;
    memcpy(rec->id, at + 8, 32);
    rec->wire = at + head;
    rec->wire_len = wire_len;
    *off += head + wire_len;
    return true;
}

bool board_answer_valid(const uint8_t *buf, size_t len,
                        const struct board_answer_head *h, int64_t asked_after,
                        bool roster)
{
    if (h->scanned < asked_after)
        return false;
    size_t off = FLEET_BOARD_FLEET_ANSWER_HEAD;
    int64_t prev = asked_after;
    bool may_pin = roster;
    struct board_record rec;
    while (board_record_next(buf, len, &off, &rec)) {
        bool pinned = may_pin && rec.arrival == FLEET_BOARD_ROSTER_PINNED_ARRIVAL;
        may_pin = false;
        if (pinned)
            continue;
        if (rec.arrival <= prev || rec.arrival > h->scanned)
            return false;
        prev = rec.arrival;
    }
    return off == len;
}
