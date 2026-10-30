/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private declarations shared by the check-standalone-tools-link
 * gate files (scan, x11 probe, build phase, selftest).
 */
#ifndef GATE_STANDALONE_TOOLS_LINK_PRIV_H
#define GATE_STANDALONE_TOOLS_LINK_PRIV_H

#include <stdio.h>
#include <sys/types.h>

enum { STL_NAME = 128, STL_MAX = 1024, STL_LINE = 8192, STL_PATH = 1024,
       STL_TEXT = 16384, STL_TOK = 192, STL_TOKS = 1024,
       STL_TGT = STL_NAME + 16 };

extern const char k_stl_gate[];

struct stl_names { char n[STL_MAX][STL_NAME]; int count; };

/* One physical line at a time, with long lines delivered in chunks. */
struct stl_rd { FILE *f; int mid, head; char buf[STL_LINE]; };

int stl_rd_next(struct stl_rd *r);
int stl_names_add(struct stl_names *t, const char *s, size_t n);
int stl_names_has(const struct stl_names *t, const char *s);
int stl_scan_makefile(const char *path, struct stl_names *tools);
int stl_load_fuzz(const char *mk, struct stl_names *fuzz);
int stl_windows_covers(const char *catalog, const char *row, const char *src);

int stl_wait(pid_t pid);
int stl_mkdtemp(char *dir, size_t cap, const char *tag);
int stl_nonempty(const char *path);
void stl_copy_to(FILE *out, const char *path);
int stl_x11_linkable(void);
int stl_x11_link_check(const char *dir);

/* 0 = clean or WARN, 1 = violations in FAIL mode, 2 = broken gate. */
int stl_build_phase(char (*targets)[STL_TGT], int nt, int build_only,
                    const char *mode, int host_linux);

#endif
