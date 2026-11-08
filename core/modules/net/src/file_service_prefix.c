/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Verify the contiguous reusable prefix before history chunk writes. */
#if !defined(_WIN32)
#include "file_service_priv.h"
#include "net/file_service.h"
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

enum fs_prefix_decision fs_prefix_decide(enum fs_resume_cause cause, uint32_t verified,
                                                 uint32_t minimum, bool cancelled)
{
    if (cause == FS_RESUME_STOPPED) return FS_PREFIX_STOPPED;
    if (verified < minimum) return FS_PREFIX_ERROR;
    if (cancelled) return FS_PREFIX_STOPPED;
    return FS_PREFIX_READY;
}

/* Resume support: how many leading chunks already sit on disk intact. */
uint32_t fs_sync_resume_scan(const char *datadir,
                                    const struct file_chunk *chunks,
                                    uint32_t num_chunks, struct fs_receive_op *op,
                                    enum fs_resume_cause *cause)
{
    *cause = FS_RESUME_SCANNED;
    uint32_t skip_chunks = 0;
    {
        uint32_t verified = 0, checked = 0;
        for (uint32_t j = 0; j < num_chunks; j++) {
            if (fs_receive_cancelled(op)) { *cause = FS_RESUME_STOPPED; break; }
            /* Check if file is large enough for this chunk */
            int fd2 = fs_chunk_open(datadir, chunks[j].file_index, O_RDONLY);
            struct stat st;
            if (fd2 < 0) { *cause = FS_RESUME_FAILED; break; }
            if (fstat(fd2, &st) != 0 || st.st_size < 0 ||
                (uint64_t)st.st_size < chunks[j].offset + chunks[j].size) {
                close(fd2); *cause = FS_RESUME_FAILED; break;
            }

            /* Every reused chunk must match the current manifest. */
            enum fs_chunk_check checked_chunk = fs_verify_local_chunk(fd2, &chunks[j], op);
            close(fd2);
            if (checked_chunk != FS_CHUNK_VALID) {
                *cause = checked_chunk == FS_CHUNK_STOPPED ? FS_RESUME_STOPPED : FS_RESUME_FAILED;
                if (checked_chunk == FS_CHUNK_FAILED)
                    fprintf(stderr, "file_service: resume verification failed at chunk %u\n", j);
                break;
            }
            checked++;
            verified++;
        }
        skip_chunks = verified;
        if (skip_chunks > 0) {
            printf("file_service: resuming — %u/%u chunks on disk "
                   "(%u SHA3-verified)\n", skip_chunks, num_chunks, checked);
        }
    }
    return skip_chunks;
}

#ifdef ZCL_TESTING
uint32_t fs_test_resume(const char *, const struct file_chunk *, uint32_t);
uint32_t fs_test_resume(const char *dir, const struct file_chunk *chunks, uint32_t count)
{
    enum fs_resume_cause cause;
    return fs_sync_resume_scan(dir, chunks, count, NULL, &cause);
}
int fs_test_prefix_scan_decision(const char *, const struct file_chunk *, uint32_t,
                                 struct fs_receive_op *, bool);
int fs_test_prefix_scan_decision(const char *dir, const struct file_chunk *chunks, uint32_t count,
                                 struct fs_receive_op *op, bool cancel_after_scan)
{
    if (!dir || !chunks || !op || !op->has_expected) return -1;
    enum fs_resume_cause cause;
    uint32_t verified = fs_sync_resume_scan(dir, chunks, count, op, &cause);
    if (cancel_after_scan) fs_receive_cancel(op);
    return (int)fs_prefix_decide(cause, verified, op->min_verified_chunks, fs_receive_cancelled(op));
}
#endif
#endif /* !_WIN32 */
