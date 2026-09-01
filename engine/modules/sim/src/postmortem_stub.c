/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the Windows build of sim/postmortem.h — every entry point refuses
 * with -ENOTSUP, an empty path, or NULL, because the crash capsule this
 * library promises has no Windows implementation yet.
 *
 * WHY A SEPARATE TRANSLATION UNIT, AND WHY IT CANNOT COLLIDE. postmortem.c
 * compiles its body only under !defined(_WIN32); this file compiles its body
 * only under defined(_WIN32). The two arms are mutually exclusive by
 * construction, so no symbol here is ever defined twice no matter how the
 * sources are gathered — on a POSIX host this unit contributes nothing but
 * the declarations of the header above the guard. The alternative pattern,
 * a Makefile source-swap (see os_sandbox_linux.c / os_sandbox_stub.c and
 * Makefile's LIB_SRCS filter-out), leaves both files defining the same
 * symbols and relies on the build never compiling both; the guard is the
 * cheaper guarantee.
 *
 * THESE ARE REFUSALS, NOT DEGRADED SUCCESSES. A caller that asks for a crash
 * capsule is told the surface is unavailable; it is never handed an empty
 * capsule, a truncated one, or a success that produced no evidence. The real
 * capture path is an async-signal-safe POSIX crash hook (sigaction, a
 * signal-safe write loop, a ucontext register dump) and the inventory path is
 * dirent-based, so nothing here can be a partial port — the honest answer is
 * ENOTSUP until a Windows capture path exists and its acceptance passes. */

#include "sim/postmortem.h"

#if defined(_WIN32)

#include <errno.h>

int postmortem_capture_write(const struct postmortem_capture_opts *opts,
                             char *capsule_path_out,
                             size_t capsule_path_cap)
{
    (void)opts;
    if (capsule_path_out && capsule_path_cap) capsule_path_out[0] = '\0';
    return -ENOTSUP;
}

int postmortem_install(seed_tape_t *tape, const char *dir)
{
    (void)tape;
    (void)dir;
    return -ENOTSUP;
}

void postmortem_uninstall(void) {}

int postmortem_list(const char *dir, struct postmortem_summary *out,
                    size_t out_cap, size_t *count_out)
{
    (void)dir;
    (void)out;
    (void)out_cap;
    if (count_out) *count_out = 0;
    return -ENOTSUP;
}

seed_tape_t *postmortem_load(const char *path)
{
    (void)path;
    return NULL;
}

bool postmortem_capsule_validate(const char *capsule_path)
{
    (void)capsule_path;
    return false;
}

seed_tape_t *postmortem_capsule_load_tape(const char *capsule_path)
{
    (void)capsule_path;
    return NULL;
}

int postmortem_capsule_compress(const char *capsule_path,
                                char *compressed_path_out,
                                size_t compressed_path_cap)
{
    (void)capsule_path;
    if (compressed_path_out && compressed_path_cap)
        compressed_path_out[0] = '\0';
    return -ENOTSUP;
}

int postmortem_capsule_compress_unpacked(const char *dir,
                                         size_t *compressed_out)
{
    (void)dir;
    if (compressed_out) *compressed_out = 0;
    return -ENOTSUP;
}

int postmortem_capsule_list(const char *dir,
                            struct postmortem_capsule_entry *entries,
                            size_t entry_cap, size_t *count_out)
{
    (void)dir;
    (void)entries;
    (void)entry_cap;
    if (count_out) *count_out = 0;
    return -ENOTSUP;
}

int postmortem_capsule_prune(const char *dir, int64_t now_unix,
                             int64_t max_age_seconds, size_t keep_latest,
                             size_t *pruned_out)
{
    (void)dir;
    (void)now_unix;
    (void)max_age_seconds;
    (void)keep_latest;
    if (pruned_out) *pruned_out = 0;
    return -ENOTSUP;
}

#endif /* defined(_WIN32) */
