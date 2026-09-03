/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows-only internal helper shared by disk_space.c,
 * file_metadata.c and positioned_file.c — converts a UTF-8 pathname into the
 * wide \\?\-extended form CreateFileW/GetDiskFreeSpaceExW want, covering
 * drive-absolute, UNC, and already-extended inputs. Compiles to nothing on
 * POSIX, where the same paths are handed to open()/statvfs() unchanged.
 *
 * The separator rewrite is load-bearing, not cosmetic. The \\?\ prefix turns
 * OFF every Win32 path parse — including the forward-slash-to-backslash
 * rewrite — so a '/' left in the string reaches the object manager as an
 * ordinary filename character and the open fails with ERROR_INVALID_NAME.
 * That is neither ERROR_FILE_NOT_FOUND nor ERROR_PATH_NOT_FOUND, so the
 * callers' missing-vs-refused split reports a file that plainly exists as
 * refused/unreadable. In-tree callers do join with '/' (util/boot_status.c,
 * platform/state_root.c, the native zcode workspace paths), so the rewrite
 * has to happen HERE, before the prefix goes on.
 *
 * The implementation now lives in the public platform/windows_path.h so
 * higher layers can use the same UTF-8 and long-path boundary. This internal
 * include remains as a compatibility route for existing platform sources. */
#ifndef ZCL_PLATFORM_WINDOWS_PATH_INTERNAL_H
#define ZCL_PLATFORM_WINDOWS_PATH_INTERNAL_H

/* Compatibility include for the existing platform implementations. New
 * consumers use the public header directly. */
#include "platform/windows_path.h"

#endif
