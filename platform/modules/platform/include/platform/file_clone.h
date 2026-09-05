/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: descriptor-bound copy-on-write cloning for immutable build inputs,
 * with a typed portable-copy fallback when the host cannot clone. */
#ifndef ZCL_PLATFORM_FILE_CLONE_H
#define ZCL_PLATFORM_FILE_CLONE_H

enum platform_file_clone_result {
    PLATFORM_FILE_CLONE_CLONED = 0,
    PLATFORM_FILE_CLONE_UNAVAILABLE,
    PLATFORM_FILE_CLONE_REFUSED,
};

/* Clone all bytes from an already-open readable regular source into an
 * already-open writable, non-append, empty, distinct regular destination
 * inode. On Linux, O_PATH descriptors are not readable/writable handles and
 * are refused.
 * Neither descriptor is closed and neither file offset is changed. UNAVAILABLE
 * leaves the destination empty so the caller may use its existing byte-copy
 * path. REFUSED means the descriptor contract was invalid or a hard I/O
 * failure occurred; callers must not treat it as successful cloning.
 * Unsupported platforms return UNAVAILABLE. */
enum platform_file_clone_result platform_file_clone_fd(int source_fd,
                                                        int destination_fd);

#endif
