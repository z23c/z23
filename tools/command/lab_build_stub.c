/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Non-Linux build of the one-file lab. Every entry point refuses with
 * LAB_E_UNSUPPORTED or reports that nothing ran; the compile and confined run
 * live in lab_build.c and lab_exec.c. */
#include "command/lab.h"

#include <string.h>

#if !defined(__linux__)

size_t lab_compile_count(void)
{
    return 0;
}

size_t lab_run_count(void)
{
    return 0;
}

enum lab_err lab_dirs_open(struct lab_dirs *d)
{
    memset(d, 0, sizeof(*d));
    return LAB_E_UNSUPPORTED;
}

enum lab_err lab_toolchain_find(struct lab_toolchain *tc)
{
    memset(tc, 0, sizeof(*tc));
    return LAB_E_NO_COMPILER;
}

enum lab_err lab_source_load(const char *path, struct lab_source *src)
{
    (void)path;
    memset(src, 0, sizeof(*src));
    return LAB_E_BAD_FILE;
}

void lab_source_free(struct lab_source *src)
{
    (void)src;
}

void lab_compile_source(const struct lab_dirs *d, const struct lab_toolchain *tc,
                        const struct lab_source *src, const char *name,
                        bool sanitize, struct lab_compile *out)
{
    (void)d;
    (void)tc;
    (void)src;
    (void)name;
    (void)sanitize;
    memset(out, 0, sizeof(*out));
    out->unconfined = true;
}

void lab_compile_release(const struct lab_dirs *d, const struct lab_toolchain *tc,
                         const struct lab_source *src, const char *name,
                         struct lab_compile *out)
{
    (void)d;
    (void)tc;
    (void)src;
    (void)name;
    memset(out, 0, sizeof(*out));
    out->unconfined = true;
}

void lab_compile_cleanup(const struct lab_dirs *d, const char *name)
{
    (void)d;
    (void)name;
}

void lab_run_binary(const struct lab_dirs *d, const char *binary,
                    bool sanitized, const struct lab_inputs *in,
                    struct lab_proc *out)
{
    (void)d;
    (void)binary;
    (void)sanitized;
    (void)in;
    out->launch = LAB_LAUNCH_UNSUPPORTED;
}

#endif
