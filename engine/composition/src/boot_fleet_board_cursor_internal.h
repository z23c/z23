/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The fleet carriage lane's per-peer pull cursor and its file, shared
 * by boot_fleet_board_fleet.c and boot_fleet_board_cursor.c. */

#ifndef ZCL_BOOT_FLEET_BOARD_CURSOR_INTERNAL_H
#define ZCL_BOOT_FLEET_BOARD_CURSOR_INTERNAL_H

#include "config/boot_fleet_board.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Everything this box knows about one peer's board, in that peer's own
 * arrival numbers, which mean something only inside the answering process
 * named by `epoch`.
 *
 * `next`: every row the peer could serve at or below it is settled here —
 * stored, refused for good, or at or above `carry_min`.
 * `carry_min`: the lowest arrival refused for a reason that can clear (a
 * role not granted yet, a clock ahead of ours, a quota or a busy store);
 * 0 when there is none. `next` never waits on such a row, so one post
 * this box may never accept cannot hold back the rest of the board.
 * A sweep re-reads (`sweep_pos`, `sweep_end`] page by page, offering every
 * row this box still does not hold; whatever is refused again lands in
 * `carry_min` for the next sweep. So a refused row is offered again until
 * it is stored, refused for good, or no longer served, and no row is ever
 * passed over. */
struct board_cursor { // hardening-ok: one peer's sync position; it parses no bytes
    bool used;
    bool epoch_known;
    bool sweep_active;
    bool sweep_turn;
    uint8_t peer_box_id[32];
    uint8_t epoch[FLEET_BOARD_FLEET_EPOCH_BYTES];
    int64_t next;
    int64_t carry_min;
    int64_t sweep_pos;
    int64_t sweep_end;
    /* Memory only, never written: when this slot was last asked about, so a
     * full table gives up the idlest peer (0: loaded and not seen yet). */
    uint64_t seen;
};

void board_cursor_write(const char *path, const struct board_cursor *rows,
                        size_t n);
/* The slot for a peer, made if `create`: when all `n` are taken the idlest is
 * evicted, which costs that peer one re-pull, never a lost row. */
struct board_cursor *board_cursor_find(struct board_cursor *rows, size_t n,
                                       const uint8_t box_id[32], bool create);
/* After a load: re-offer every row up to each `next` this box does not hold,
 * since the cursor file is synced and the row store may not have been. */
void board_cursor_arm_sweeps(struct board_cursor *rows, size_t n);
size_t board_cursor_read(const char *path, struct board_cursor *out,
                         size_t cap);

#endif /* ZCL_BOOT_FLEET_BOARD_CURSOR_INTERNAL_H */
