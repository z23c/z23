/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The fleet carriage lane's frame codecs (the pull question, the
 * answer head and the framed answer records), shared by
 * boot_fleet_board_fleet.c and boot_fleet_board_frame.c. Pure byte work: no
 * lock, no store read, no stream. */

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

#endif /* ZCL_BOOT_FLEET_BOARD_FRAME_INTERNAL_H */
