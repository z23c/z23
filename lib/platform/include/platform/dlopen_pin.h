/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: produce a dlopen()-able path that pins the exact bytes behind an
 * open file descriptor, isolating the OS-specific mechanism from the rest of
 * the tree.
 *
 * Linux resolves the descriptor through /proc/self/fd/<fd>, so no copy is made.
 * macOS lacks a per-fd path that gives dyld a unique object identity; reusing
 * /dev/fd/N while an older handle is mapped returns dyld's cached object.
 * Instead, the fd contents are copied to a unique temp file named after the
 * artifact hash plus pid/counter, and that temp path is returned. The original
 * fd stays open to pin the source identity. */
#ifndef ZCL_PLATFORM_DLOPEN_PIN_H
#define ZCL_PLATFORM_DLOPEN_PIN_H

#include <stdbool.h>
#include <stddef.h>

/* Return a dlopen()-able pinned path for the bytes behind fd.
 *
 * artifact_sha256 is the caller's SHA-256 over the artifact bytes (64 hex
 * digits, NUL-terminated). It is required on macOS so the temp copy name is
 * deterministic per artifact; it is ignored on Linux.
 *
 * On success, writes the path (NUL-terminated) into `path` and returns true.
 * On failure, `path` is set to the empty string and the function returns false.
 *
 * The returned path remains meaningful only while fd remains open. */
bool platform_dlopen_pin_path(int fd, const char *artifact_sha256,
                              char *path, size_t path_size);

/* Release any platform-owned copy created for `path`.
 *
 * Safe to call on any value returned by platform_dlopen_pin_path(); it is a
 * no-op on platforms (Linux) that pin by descriptor rather than by temp copy.
 * It must NOT be called for a successfully-loaded mapping on macOS, because
 * dyld may need the file for lazy binding. */
void platform_dlopen_pin_path_cleanup(const char *path);

#endif /* ZCL_PLATFORM_DLOPEN_PIN_H */
