/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove the Windows arm of os_proc_open_self_exe() exists, opens the
 * running image, hands back a FILE* the caller's fclose owns outright, and
 * publishes the HONEST identity rung for a pathname reopen.
 *
 * Why a cross-link is load-bearing here and not ceremony: gcc and clang on a
 * POSIX host accept a syntax error inside a `#if defined(_WIN32)` arm without
 * a murmur, because they never preprocess into it. Only the mingw driver that
 * builds this program reads that code at all. Before this row existed the
 * Windows arm of that function was `errno = ENOTSUP; return NULL;` -- there
 * was nothing to compile and therefore nothing this could have caught.
 *
 * The handle-leak loop is the specific defect the implementation's ownership
 * chain is written to avoid: _open_osfhandle adopts the HANDLE and _fdopen
 * adopts the fd, so a wrong undo on either failure arm leaks one OS handle
 * per attempt on exactly the box an operator is already trying to diagnose. */
#include "platform/os_proc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#if defined(_WIN32)

#define SELF_IMAGE_CYCLES 256
/* Handle counts on Windows are process-wide and other machinery in the CRT
 * may legitimately move them by a handful across the loop. A LEAK moves them
 * by SELF_IMAGE_CYCLES, so this slack separates the two without inventing a
 * flake. */
#define SELF_IMAGE_HANDLE_SLACK 8

static bool read_running_image_header(void)
{
    FILE *image = os_proc_open_self_exe();
    if (!image)
        return false;
    unsigned char header[64];
    size_t got = fread(header, 1, sizeof(header), image);
    /* fclose, not _close/CloseHandle: the whole point of routing the handle
     * through _open_osfhandle+_fdopen is that every caller in the tree
     * (binary_staleness_service, canary_sentinel_watch, binary_ab_fallback,
     * anchor_controller) closes this the same way it closes the Linux one. */
    if (fclose(image) != 0)
        return false;
    /* A PE image starts "MZ". Anything else means the pathname reopen
     * resolved to something that is not an executable at all. */
    return got == sizeof(header) && header[0] == 'M' && header[1] == 'Z';
}

int main(void)
{
    /* The rung must be the honest one. RESOLVED_PATH and not RUNNING_IMAGE:
     * GetModuleFileNameW returns a PEB-cached STRING, so the reopen is by
     * name and a rename-then-install deploy -- the standard Windows update
     * idiom, since a running image can be renamed but never overwritten in
     * place -- races it. If someone ever widens this to RUNNING_IMAGE
     * without adding a mechanism that actually pins the loader's file
     * object, this line is what refuses. */
    if (os_proc_self_exe_identity() != OS_PROC_IMAGE_IDENTITY_RESOLVED_PATH)
        return 1;

    if (!read_running_image_header())
        return 1;

    size_t before = 0;
    if (!os_proc_open_fd_count(&before))
        return 1;
    for (int i = 0; i < SELF_IMAGE_CYCLES; i++) {
        if (!read_running_image_header())
            return 1;
    }
    size_t after = 0;
    if (!os_proc_open_fd_count(&after))
        return 1;
    if (after > before + SELF_IMAGE_HANDLE_SLACK)
        return 1;

    puts("os_proc_self_image_acceptance: PASS");
    return 0;
}

#else
int main(void) { return 77; }
#endif
