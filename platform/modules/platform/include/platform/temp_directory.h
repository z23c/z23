/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * One race-free scratch-directory create, on both platform arms.
 *
 * mkdtemp(3) is a POSIX-only symbol: the mingw CRT does not declare or
 * export it, so a caller that reaches for it is an implicit declaration
 * under -Werror and an int-to-pointer result that sails straight past the
 * usual `if (!mkdtemp(buf))` guard. This is the portable primitive those
 * callers use instead. */
#ifndef ZCL_PLATFORM_TEMP_DIRECTORY_H
#define ZCL_PLATFORM_TEMP_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>

/* Upper bound, terminator included, on a path this module will produce.
 * Sized for a Windows GetTempPathW() answer (MAX_PATH wide characters) plus
 * the caller's prefix and the random leaf, so a caller declares one buffer
 * and never has to ask the platform how long the answer will be. */
#define PLATFORM_TEMP_PATH_MAX 512u

/* Longest name_prefix accepted. A longer one is EINVAL, never truncated. */
#define PLATFORM_TEMP_PREFIX_MAX 64u

/* Create a fresh, owner-private directory under the OS temporary directory
 * — $TMPDIR (absolute only) or /tmp on POSIX, GetTempPathW() on Windows —
 * named <name_prefix><18 random hex digits>, and write its path to out_path.
 *
 * The create is EXCLUSIVE on both arms: it goes through
 * platform_private_directory_create(), whose mkdir(2) and CreateDirectoryW()
 * both fail rather than adopt a directory that already exists. There is
 * therefore no generate-name / test-for-existence / create window for
 * another process to win — the create itself is the test — and the caller
 * can never be handed a directory somebody else already owns. A name
 * collision is reported as EEXIST and retried with fresh randomness a
 * bounded number of times.
 *
 * name_prefix must be non-empty, at most PLATFORM_TEMP_PREFIX_MAX bytes and
 * free of path separators. On any failure out_path is set to the empty
 * string, errno describes the failure, and no directory is left behind. On
 * success the caller owns the directory and is responsible for removing it.
 */
bool platform_temp_directory_create(const char *name_prefix, char *out_path,
                                    size_t out_cap);

#endif
