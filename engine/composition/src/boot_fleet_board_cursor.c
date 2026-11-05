/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The fleet carriage lane's durable pull cursors: one fixed-width
 * record per peer, read once per process and written after each answer. A file
 * that does not add up is refused whole and the pull starts again from the
 * beginning, which dedupe by post id keeps correct.
 */

#include "boot_fleet_board_cursor_internal.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "util/log_macros.h"

#include <stdlib.h>
#include <string.h>

/* One durable cursor record. Fixed width so a short or long file is
 * refused whole and the pull starts again from the beginning, which
 * dedupe by post id keeps correct. */
#define BOARD_CURSOR_REC (4u + 32u + FLEET_BOARD_FLEET_EPOCH_BYTES + 32u)
#define BOARD_CURSOR_MAGIC "FBc1"

static void board_cursor_pack(const struct board_cursor *c, uint8_t *out)
{
    out[0] = c->epoch_known ? 1u : 0u;
    out[1] = c->sweep_active ? 1u : 0u;
    out[2] = c->sweep_turn ? 1u : 0u;
    out[3] = 0;
    memcpy(out + 4, c->peer_box_id, 32);
    memcpy(out + 36, c->epoch, FLEET_BOARD_FLEET_EPOCH_BYTES);
    zcl_write_u64_be(out + 36 + FLEET_BOARD_FLEET_EPOCH_BYTES,
                     (uint64_t)c->next);
    zcl_write_u64_be(out + 44 + FLEET_BOARD_FLEET_EPOCH_BYTES,
                     (uint64_t)c->carry_min);
    zcl_write_u64_be(out + 52 + FLEET_BOARD_FLEET_EPOCH_BYTES,
                     (uint64_t)c->sweep_pos);
    zcl_write_u64_be(out + 60 + FLEET_BOARD_FLEET_EPOCH_BYTES,
                     (uint64_t)c->sweep_end);
}

static bool board_cursor_unpack(const uint8_t *in, struct board_cursor *out)
{
    uint64_t next = zcl_read_u64_be(in + 36 + FLEET_BOARD_FLEET_EPOCH_BYTES);
    uint64_t carry = zcl_read_u64_be(in + 44 + FLEET_BOARD_FLEET_EPOCH_BYTES);
    uint64_t spos = zcl_read_u64_be(in + 52 + FLEET_BOARD_FLEET_EPOCH_BYTES);
    uint64_t send = zcl_read_u64_be(in + 60 + FLEET_BOARD_FLEET_EPOCH_BYTES);
    if (next > (uint64_t)INT64_MAX || carry > (uint64_t)INT64_MAX ||
        spos > (uint64_t)INT64_MAX || send > (uint64_t)INT64_MAX)
        return false;
    memset(out, 0, sizeof *out);
    out->used = true;
    out->epoch_known = in[0] != 0;
    out->sweep_active = in[1] != 0;
    out->sweep_turn = in[2] != 0;
    memcpy(out->peer_box_id, in + 4, 32);
    memcpy(out->epoch, in + 36, FLEET_BOARD_FLEET_EPOCH_BYTES);
    out->next = (int64_t)next;
    out->carry_min = (int64_t)carry;
    out->sweep_pos = (int64_t)spos;
    out->sweep_end = (int64_t)send;
    return true;
}

void board_cursor_write(const char *path, const struct board_cursor *rows,
                        size_t n)
{
    uint8_t *buf = NULL;
    struct platform_private_file file;
    size_t bytes = 8u + n * BOARD_CURSOR_REC;
    buf = zcl_malloc(bytes, "fleet-board-cursors");
    if (!buf)
        return;
    memcpy(buf, BOARD_CURSOR_MAGIC, 4);
    zcl_write_u32_be(buf + 4, (uint32_t)n);
    for (size_t i = 0; i < n; i++)
        board_cursor_pack(&rows[i], buf + 8u + i * BOARD_CURSOR_REC);
    platform_private_file_init(&file);
    if (platform_private_file_open_locked_create(path, &file)) {
        bool ok = platform_private_file_truncate(&file, 0) &&
                  platform_private_file_write_at(&file, buf, bytes, 0) &&
                  platform_private_file_authority_flush(&file);
        platform_private_file_close(&file);
        if (!ok)
            LOG_WARN("fleet.board",
                     "fleet pull cursor was not saved: path=%s", path);
    }
    free(buf);
}

size_t board_cursor_read(const char *path, struct board_cursor *out,
                         size_t cap)
{
    struct platform_positioned_file file;
    uint8_t head[8];
    uint8_t *buf = NULL;
    uint64_t size = 0;
    uint32_t count = 0;
    size_t n = 0;
    bool ok = false;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return 0;
    ok = platform_positioned_file_size(&file, &size) && size >= 8 &&
         platform_positioned_file_read(&file, head, 8, 0) == 8;
    if (ok) {
        count = zcl_read_u32_be(head + 4);
        ok = memcmp(head, BOARD_CURSOR_MAGIC, 4) == 0 && count <= cap &&
             size == 8u + (uint64_t)count * BOARD_CURSOR_REC;
    }
    if (ok && count > 0) {
        buf = zcl_malloc((size_t)count * BOARD_CURSOR_REC,
                         "fleet-board-cursors");
        ok = buf && platform_positioned_file_read(
                        &file, buf, (size_t)count * BOARD_CURSOR_REC, 8) ==
                        (int64_t)((size_t)count * BOARD_CURSOR_REC);
    }
    platform_positioned_file_close(&file);
    if (!ok) {
        free(buf);
        LOG_WARN("fleet.board",
                 "fleet pull cursor file was unreadable; pulls start again");
        return 0;
    }
    for (uint32_t i = 0; i < count; i++) {
        if (board_cursor_unpack(buf + (size_t)i * BOARD_CURSOR_REC, &out[n]))
            n++;
    }
    free(buf);
    return n;
}


/* The seen stamp that makes a row the newest: one past the largest held. */
static void board_cursor_touch(struct board_cursor *rows, size_t n,
                               struct board_cursor *c)
{
    uint64_t top = 0;
    for (size_t i = 0; i < n; i++) {
        if (rows[i].seen > top)
            top = rows[i].seen;
    }
    c->seen = top + 1u;
}

struct board_cursor *board_cursor_find(struct board_cursor *rows, size_t n,
                                       const uint8_t box_id[32], bool create)
{
    struct board_cursor *pick = NULL;
    for (size_t i = 0; i < n; i++) {
        if (rows[i].used && memcmp(rows[i].peer_box_id, box_id, 32) == 0) {
            board_cursor_touch(rows, n, &rows[i]);
            return &rows[i];
        }
        /* A free slot beats any used one; among used, the idlest. */
        if (!pick || (pick->used && (!rows[i].used || rows[i].seen < pick->seen)))
            pick = &rows[i];
    }
    if (!create || !pick)
        return NULL;
    memset(pick, 0, sizeof *pick);
    pick->used = true;
    memcpy(pick->peer_box_id, box_id, 32);
    board_cursor_touch(rows, n, pick);
    return pick;
}

void board_cursor_arm_sweeps(struct board_cursor *rows, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (!rows[i].used || rows[i].next <= 0)
            continue;
        rows[i].sweep_active = true;
        rows[i].sweep_pos = 0;
        rows[i].sweep_end = rows[i].next;
    }
}
