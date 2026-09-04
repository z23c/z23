/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: The racy-clean rule for codeindex Merkle leaves — when a file's
 * stat key is evidence that its bytes did not move, and when it is not.
 */

#include "codeindex_priv.h"

#include "platform/clock.h"

/* The whole second a build pass begins in.
 *
 * Floored deliberately. A filesystem stamps mtime from a coarse tick, so a
 * file written just after this read can carry a stamp slightly EARLIER than a
 * finer reading of the clock; flooring to the second makes that impossible.
 * Flooring can only widen the set of leaves a later pass re-reads, so it can
 * cost reads but can never hide a write. */
uint64_t ci_merkle_capture_second(void)
{
    int64_t ms = clock_now_wall_ms();
    return ms > 0 ? (uint64_t)ms / 1000u : 0;
}

/* The mtime nanoseconds a pass that began in `captured_sec` may record for a
 * leaf it just read.
 *
 * A (dev,ino,size,mtime,ctime) key is evidence only for a file that has
 * settled. While the clock is still inside the second a file was written in,
 * a rewrite of the same number of bytes can land in the same coarse timestamp
 * tick and move no field of that key at all — the classic racy-clean case,
 * and the ordinary case for a tree materialized onto tmpfs and edited
 * milliseconds later. Such a leaf is therefore recorded with a nanosecond
 * value no live stat can equal, which makes the next pass re-read its bytes
 * instead of trusting a key that proves nothing. If the bytes did not in fact
 * move, that pass's digest comparison keeps the leaf clean and no ancestor is
 * rehashed: the rule costs one read, never a false change. */
uint64_t ci_merkle_settled_mtime_nsec(uint64_t mtime_sec, uint64_t mtime_nsec,
                                      uint64_t captured_sec)
{
    return mtime_sec < captured_sec ? mtime_nsec : UINT64_MAX;
}
