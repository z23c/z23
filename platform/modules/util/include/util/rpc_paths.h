/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared helper for building the six default datadir / conf / cookie
 * paths that zcl-nodectl (and, in the future, any other operator tool)
 * uses when neither the caller nor an environment variable overrides
 * them.
 *
 * Keeping this in a header (static inline) means the same code is
 * compiled into both tools/zcl-nodectl and the test binary without
 * linker gymnastics — the zcl-nodectl Makefile rule compiles a single
 * .c file in isolation, so an external .c dependency would require
 * extra plumbing just to share six lines of snprintf.
 *
 * Replaces previous hardcoded home-directory defaults with
 * $HOME-derived paths.
 */
#ifndef ZCL_UTIL_RPC_PATHS_H
#define ZCL_UTIL_RPC_PATHS_H

#include <stddef.h>
#include <stdio.h>

static inline void zcl_nodectl_build_default_paths(
    const char *home,
    char *legacy_dd, size_t legacy_dd_sz,
    char *legacy_conf, size_t legacy_conf_sz,
    char *legacy_cookie, size_t legacy_cookie_sz,
    char *c23_dd, size_t c23_dd_sz,
    char *c23_conf, size_t c23_conf_sz,
    char *c23_cookie, size_t c23_cookie_sz)
{
    const char *h = (home && *home) ? home : ".";
    snprintf(legacy_dd, legacy_dd_sz, "%s/.zclassic", h);
    snprintf(legacy_conf, legacy_conf_sz, "%s/.zclassic/zclassic.conf", h);
    snprintf(legacy_cookie, legacy_cookie_sz, "%s/.zclassic/.cookie", h);
    snprintf(c23_dd, c23_dd_sz, "%s/.zclassic-c23", h);
    snprintf(c23_conf, c23_conf_sz, "%s/.zclassic-c23/zclassic.conf", h);
    snprintf(c23_cookie, c23_cookie_sz, "%s/.zclassic-c23/.cookie", h);
}

#endif /* ZCL_UTIL_RPC_PATHS_H */
