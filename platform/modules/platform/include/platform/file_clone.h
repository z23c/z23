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
 * already-open writable, non-append, empty, distinct regular destination.
 * On Linux, O_PATH descriptors are not readable/writable handles and are
 * refused, and FICLONE fills the existing destination inode. Darwin has no
 * equivalent ioctl: APFS clonefile creates a new inode inside a private
 * directory, that clone is given the destination mode, and it replaces the
 * destination path only while that path is still the caller's empty file.
 * The caller's destination descriptor number is then retargeted onto it.
 * Callers that fstat, pread, fchmod, futimens, or rename that path see the
 * clone.
 * Neither descriptor number is closed and neither file offset is changed.
 * UNAVAILABLE leaves the destination inode and path untouched so the caller
 * may use its existing byte-copy path. REFUSED means the descriptor contract
 * was invalid or a hard I/O failure occurred; callers must not treat it as
 * successful cloning. Unsupported platforms return UNAVAILABLE. */
enum platform_file_clone_result platform_file_clone_fd(int source_fd,
                                                        int destination_fd);

#endif
