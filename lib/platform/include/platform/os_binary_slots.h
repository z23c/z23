/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Crash-durable binary A/B slot state and executable selection.
 *
 * The launch decision happens before the node exists, so it cannot rely on
 * SQLite, the blocker registry, or a shell.  This platform seam owns the one
 * durable boot-failure counter format and pins the selected executable inode
 * before returning it to the caller for fexecve(3).
 */
#ifndef ZCL_PLATFORM_OS_BINARY_SLOTS_H
#define ZCL_PLATFORM_OS_BINARY_SLOTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define OS_BINARY_SLOTS_STREAK_BASENAME "boot-fail-streak"
#define OS_BINARY_SLOTS_LASTGOOD_BASENAME "last-good"
#define OS_BINARY_SLOTS_PATH_MAX 1024
#define OS_BINARY_SLOTS_ERROR_MAX 256

struct os_binary_slots_launch {
    int executable_fd;             /* pinned O_NOFOLLOW regular executable */
    bool fallback_active;
    bool streak_corrupt;           /* malformed/empty/overflow was preserved */
    bool streak_written;
    uint32_t streak_before;
    uint32_t streak_after;
    char target_path[OS_BINARY_SLOTS_PATH_MAX];
    char error[OS_BINARY_SLOTS_ERROR_MAX];
};

/* Create every missing component of slots_dir with mode 0700, refusing '.',
 * '..', symlinks, and non-directories at every path component. */
bool os_binary_slots_ensure_directory(const char *slots_dir,
                                      char *error, size_t error_size);

/* Parse a strict decimal fallback threshold in 1..UINT32_MAX. */
bool os_binary_slots_parse_threshold(const char *text, uint32_t *out);

/* Under the slots-dir lock, strictly parse the streak, select and pin either
 * current_path or last-good, and durably increment a valid counter before
 * returning.  A malformed/empty/overflow counter is never rewritten.  When
 * last-good is executable it is selected fail-closed; otherwise the sole
 * executable current candidate is selected with streak_corrupt=true.
 * Caller owns out->executable_fd and must close it or call close_launch(). */
bool os_binary_slots_prepare_launch(const char *slots_dir,
                                    const char *current_path,
                                    uint32_t fallback_threshold,
                                    struct os_binary_slots_launch *out);

void os_binary_slots_close_launch(struct os_binary_slots_launch *launch);

/* Crash-durable counter operations used by the running node.  Increment is
 * strict: corrupt/empty/overflow state is preserved and returns false. */
bool os_binary_slots_reset_streak_file(const char *streak_file,
                                       char *error, size_t error_size);
bool os_binary_slots_increment_streak_file(const char *streak_file,
                                           char *error, size_t error_size);

#ifdef ZCL_TESTING
/* One-shot failure injection after file fsync but before rename. */
void os_binary_slots_test_fail_before_rename_once(void);
#endif

#endif /* ZCL_PLATFORM_OS_BINARY_SLOTS_H */
