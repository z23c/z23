// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// Shared declarations for the check-platform-header-guards gate port.
// gate_platform_header_guards_scan.c holds the per-file conditional-depth
// scanner; gate_platform_header_guards.c holds the table, the build-derived
// exemption parse, and the grading driver.

#ifndef GATE_PLATFORM_HEADER_GUARDS_PRIV_H
#define GATE_PLATFORM_HEADER_GUARDS_PRIV_H

#include <stdio.h>

enum { PHG_LINE = 4096, PHG_PATH = 1024 };

// One angle-bracket include with the macro context live at that point.
// act: space-fenced macro tokens of the active branch of every open frame.
// raw: the squeezed conditions of every non-else frame, space separated.
struct phg_inc {
    const char *file;   // repo-relative path
    char hdr[256];
    long ln;
    char act[1024];
    char raw[1024];
};

typedef int (*phg_inc_fn)(const struct phg_inc *inc, void *ctx);

// Scan one file; fn is called for every angle-bracket include.
// Returns 0 ok, 1 file missing, 2 error (fail closed).
int phg_scan_file(const char *path, const char *rel, phg_inc_fn fn,
                  void *ctx);

// Full scan of root. mode: "" grade, "list", "quiet" (grade, no banner).
// Returns 0 clean, 1 findings, 2 hollow/unparseable.
int phg_run_scan(const char *root, int src_floor, int cand_floor,
                 int inc_floor, int seen_floor, int wincat_floor,
                 const char *mode, FILE *out, FILE *err);

#endif
