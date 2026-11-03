/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * undo_rev_index — see services/undo_rev_index.h. Interface-only stub: the
 * locator finds nothing until the scan lands. */

#include "services/undo_rev_index.h"

#include <string.h>

bool undo_rev_locator_init(struct undo_rev_locator *loc, const char *datadir,
                           const unsigned char magic[UNDO_REV_MAGIC_SIZE])
{
    if (!loc || !datadir || !magic)
        return false;
    memset(loc, 0, sizeof(*loc));
    loc->cursor_file = -1;
    return true;
}

void undo_rev_locator_free(struct undo_rev_locator *loc)
{
    (void)loc;
}

enum undo_rev_status undo_rev_locator_read(struct undo_rev_locator *loc,
                                           const struct uint256 *parent,
                                           int hint_file,
                                           struct block_undo *out)
{
    (void)loc; (void)parent; (void)hint_file;
    if (out)
        block_undo_init(out);
    return UNDO_REV_NOT_FOUND;
}

enum undo_rev_status undo_rev_shared_read(
    const char *datadir, const unsigned char magic[UNDO_REV_MAGIC_SIZE],
    const struct uint256 *parent, int hint_file, struct block_undo *out)
{
    (void)datadir; (void)magic; (void)parent; (void)hint_file;
    if (out)
        block_undo_init(out);
    return UNDO_REV_NOT_FOUND;
}
