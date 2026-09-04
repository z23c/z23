/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Size-bounded rotation for an append-only text log the node does not own the
 * writer of.
 *
 * WHY COPY-AND-TRUNCATE RATHER THAN RENAME. The obvious rotation is
 * rename(log, log.1) and let the writer create a new file. That does not work
 * for the logs this node actually has to bound. The embedded Tor writes
 * tor.log through a file descriptor it opened once at startup with O_APPEND
 * and never reopens (there is no SIGHUP path into an embedded Tor); after a
 * rename that descriptor still points at tor.log.1, which then grows forever
 * while tor.log never reappears. Renaming would convert an unbounded log into
 * an unbounded log with a confusing name.
 *
 * Truncating the file the writer already holds open is correct precisely
 * BECAUSE the writer opened it O_APPEND: every write seeks to the current end
 * as part of the write, so after a truncation the next line lands at offset 0
 * and no sparse hole is created. A writer that used a plain offset-tracking
 * descriptor would instead leave a hole, so this function is only for
 * append-mode writers — see the note in each caller.
 *
 * One previous generation is kept, at "<path>.1", replaced on each rotation.
 * That is deliberate: the value of an operational log falls off a cliff with
 * age, and two files with a hard bound each is a bound; N files is not.
 */

#ifndef ZCL_LOG_ROTATE_H
#define ZCL_LOG_ROTATE_H

#include <stdbool.h>
#include <stdint.h>

/* Rotate `path` if it is larger than `max_bytes`: copy its current contents
 * to "<path>.1" (replacing any previous generation), then truncate `path` to
 * zero. `max_bytes` <= 0 disables rotation.
 *
 * Returns true only when a rotation actually happened, and then writes the
 * number of bytes retired into `*out_rotated_bytes` when it is non-NULL. A
 * missing file, an under-bound file, and an unreadable file all return false
 * without touching anything: bounding a log must never be able to lose one.
 *
 * SAFE ONLY FOR O_APPEND WRITERS. See the header comment. */
bool log_rotate_if_over(const char *path, int64_t max_bytes,
                        int64_t *out_rotated_bytes);

/* Current size of `path` in bytes, or -1 when it cannot be measured. Exposed
 * so a caller can report a log's size in typed status without a second seam. */
int64_t log_rotate_file_size(const char *path);

#endif
