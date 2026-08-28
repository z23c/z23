/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Refuse unqualified codeindex rebuild operations on Windows. */
#if defined(_WIN32)

#include "codeindex_priv.h"
#include "codeindex/codeindex_build.h"

#include <stdio.h>
#include <string.h>

static bool ci_windows_refused(void)
{
    fprintf(stderr,
            "REFUSED: codeindex rebuild is unavailable on Windows until its "
            "transaction uses retained directory-relative child operations\n");
    return false;
}

bool ci_path_is_registry(const char *relpath)
{
    if (!relpath || !relpath[0]) return false;
    size_t length = strlen(relpath);
    return length >= 4 && strcmp(relpath + length - 4, ".def") == 0;
}

bool ci_enumerate_sources(const char *root, ci_enum_cb cb, void *user)
{
    (void)root;
    (void)cb;
    (void)user;
    return ci_windows_refused();
}

bool ci_source_roots_sha3(const char *root, uint8_t exact_out[32],
                          uint8_t stat_out[32])
{
    (void)root;
    (void)exact_out;
    (void)stat_out;
    return ci_windows_refused();
}

bool ci_source_stat_root_sha3(const char *root, uint8_t out[32])
{
    (void)root;
    (void)out;
    return ci_windows_refused();
}

bool ci_codeindex_refresh(struct codeindex *ci)
{
    (void)ci;
    return ci_windows_refused();
}

bool codeindex_rebuild(struct codeindex *ci)
{
    (void)ci;
    return ci_windows_refused();
}

#ifdef ZCL_TESTING
void ci_test_note_exact_bytes(uint64_t bytes) { (void)bytes; }
void codeindex_test_reset_exact_bytes_read(void) { }
uint64_t codeindex_test_exact_bytes_read(void) { return 0; }
void codeindex_test_set_crash_point(enum codeindex_test_crash_point point)
{
    (void)point;
}
void codeindex_test_set_stage_tamper(
    enum codeindex_test_stage_tamper tamper, const char *victim_path)
{
    (void)tamper;
    (void)victim_path;
}
#endif

#else
typedef int codeindex_build_windows_not_built;
#endif
