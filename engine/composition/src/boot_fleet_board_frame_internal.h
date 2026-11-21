/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The fleet carriage lane's frame codecs (the pull question, the
 * answer head, the framed answer records, the push and its receipt), shared
 * by boot_fleet_board_fleet.c, boot_fleet_board_push.c and
 * boot_fleet_board_frame.c. Pure byte work: no lock, no store read, no
 * stream. */

#ifndef ZCL_BOOT_FLEET_BOARD_FRAME_INTERNAL_H
#define ZCL_BOOT_FLEET_BOARD_FRAME_INTERNAL_H

#include "config/boot_fleet_board.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

size_t board_pull_encode(int64_t after,
                         uint8_t out[FLEET_BOARD_FLEET_PULL_BYTES]);
bool board_pull_decode(const uint8_t *in, size_t len, int64_t *after_out);

/* The answer head: which process answered, and how far its page reached. */
struct board_answer_head {
    uint8_t epoch[FLEET_BOARD_FLEET_EPOCH_BYTES];
    int64_t scanned;
};

void board_answer_head_encode(
    const uint8_t epoch[FLEET_BOARD_FLEET_EPOCH_BYTES], int64_t scanned,
    uint8_t *out);
bool board_answer_head_decode(const uint8_t *in, size_t len,
                              struct board_answer_head *out);

/* One answer page being composed into a caller's buffer. */
struct board_answer {
    uint8_t *buf;
    size_t cap;
    size_t len;
    unsigned count;
};

struct db_fleet_board_post;
/* Append one record, or stop the page when it would not fit: the next
 * pull starts at exactly this row, so nothing is skipped. The visitor shape
 * db_fleet_board_fleet_after walks with; `ctx` is a struct board_answer. */
bool board_answer_visit(const struct db_fleet_board_post *row, void *ctx);

struct board_record {
    int64_t arrival;
    uint8_t id[32];
    const uint8_t *wire;
    size_t wire_len;
    bool roster_only; /* the answer's: this box is not armed yet */
};

/* The next framed record, or false at the end or at a frame that does not
 * add up. */
bool board_record_next(const uint8_t *buf, size_t len, size_t *off,
                       struct board_record *rec);

/* The whole answer adds up before any of it is used: every record framed,
 * arrivals strictly rising from where the pull asked, none past the point
 * the page says it reached. A roster answer may lead with one pinned record,
 * which stands outside the numbering. One bad frame voids the answer; nothing
 * in it is guessed at and no cursor moves. */
bool board_answer_valid(const uint8_t *buf, size_t len,
                        const struct board_answer_head *h, int64_t asked_after,
                        bool roster);

/* ── the push (config/boot_fleet_board.h, "PUSH") ──────────────────────── */

/* One pushed record: the id the pusher names and the post wire it sent. No
 * arrival number: a push moves no cursor. */
struct board_push_record {
    uint8_t id[32];
    const uint8_t *wire;
    size_t wire_len;
};

/* Start a push payload of no records in `out`. */
void board_push_begin(uint8_t out[FLEET_BOARD_PUSH_HEAD]);
/* Append one post to a payload begun above, whose length is `*len` and whose
 * buffer holds FLEET_BOARD_PUSH_MAX bytes. False, and nothing changed, when
 * the payload already holds FLEET_BOARD_PUSH_POSTS_MAX records or the post
 * would not fit. */
bool board_push_append_post(uint8_t *buf, size_t *len,
                            const struct fleet_board_post *post);
/* The whole payload adds up before any of it is used: the type, the version,
 * 1..FLEET_BOARD_PUSH_POSTS_MAX records each framed inside the payload, and
 * nothing after the last one, in at most FLEET_BOARD_PUSH_MAX bytes. Framing
 * only: no record is decoded and no signature is checked. */
bool board_push_valid(const uint8_t *buf, size_t len, unsigned *n_out);
/* The next framed record of a payload board_push_valid accepted. */
bool board_push_record_next(const uint8_t *buf, size_t len, size_t *off,
                            struct board_push_record *rec);

/* The receipt a receiver puts on the CLOSE of a push stream: the push's own
 * verdict (FLEET_BOARD_PUSH_CODE_*), the receiver's commit time in Unix
 * milliseconds, and each record's verdict (FLEET_BOARD_PUSH_RECORD_*) with
 * the board result behind it. */
struct board_push_receipt {
    uint8_t code;
    uint8_t n;
    int64_t commit_ms;
    struct {
        uint8_t id[32];
        uint8_t verdict;
        uint8_t result;
    } rec[FLEET_BOARD_PUSH_POSTS_MAX];
};

size_t board_push_receipt_encode(const struct board_push_receipt *r,
                                 uint8_t out[FLEET_BOARD_PUSH_RECEIPT_MAX]);
/* Exact: a receipt whose length does not match its count, or whose code or
 * verdict is out of range, is refused whole. */
bool board_push_receipt_decode(const uint8_t *in, size_t len,
                               struct board_push_receipt *out);

#endif /* ZCL_BOOT_FLEET_BOARD_FRAME_INTERNAL_H */
