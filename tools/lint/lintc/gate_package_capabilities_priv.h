/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for check-package-capabilities
 * (gate_package_capabilities.c, gate_package_capabilities_parse.c and
 * gate_package_capabilities_selftest.c) — the C23 port of
 * tools/lint/check_package_capabilities.sh.
 */
#ifndef GATE_PACKAGE_CAPABILITIES_PRIV_H
#define GATE_PACKAGE_CAPABILITIES_PRIV_H
#include <stdio.h>
#include "lintc.h"

enum {
    PC_PATHLEN = 192, PC_NAMELEN = 128, PC_DIRLEN = 160,
    PC_MAXPATH = 2048, PC_MAXPKG = 64,
    PC_MAXSRC = 128, PC_SRCLEN = PC_PATHLEN,
    PC_MAXARR = 64, PC_ARRLEN = 40, PC_MAXCAPS = 12,
    PC_JSONBUF = 1 << 16, PC_RENDERBUF = 4096,
    PC_REPORTBUF = 1 << 18,
};

/* A path's realized capability classes: at most PC_MAXCAPS distinct CAP_*
 * tokens (real files reach a handful at most). */
struct pc_capset { char v[PC_MAXCAPS][PC_ARRLEN]; int n; };
int pc_capset_has(const struct pc_capset *s, const char *name);
int pc_capset_add(struct pc_capset *s, const char *name);

/* one shipped-source-or-module row: a path and the capability classes any
 * ZCL_MODULE_CAPABILITY row grants it (CAP_NONE dropped, union across every
 * modules file that names this exact path — a package can cross platforms
 * and must declare the union of its portable and platform-exact reach). */
struct pc_pathcaps { char path[PC_PATHLEN]; struct pc_capset caps; };
struct pc_modtable { struct pc_pathcaps rows[PC_MAXPATH]; int n; };

struct pc_pkg { char name[PC_NAMELEN]; char dir[PC_DIRLEN]; };

/* ── gate_package_capabilities_parse.c ──────────────────────────────────── */
int pc_load_classes(const char *path, struct sr_set *out, int *n_lines);
int pc_load_module_rows(const char *const *paths, int npaths,
                        struct pc_modtable *out, int *n_rows);
int pc_load_registry(const char *const *paths, int npaths, struct pc_pkg *out,
                     int cap, int *n_out);
/* 0 = key present (out and n hold its elements, possibly zero of them),
 * 1 = key absent, 2 = die()'d (overflow/read error). */
int pc_json_array(const char *manifest, const char *key,
                  char out[][PC_ARRLEN], int cap, int *n);
/* Sources a package SHIPS, repo-root-relative, in files[] order when the
 * manifest declares files[] (honoured exactly, .c entries only), else
 * dir/src and dir/tests .c files in sorted order. */
int pc_pkg_sources(const char *root, const char *dir, char out[][PC_SRCLEN],
                   int cap, int *n);
struct pc_pathcaps *pc_modtable_find(struct pc_modtable *t, const char *path);

/* ── gate_package_capabilities.c ─────────────────────────────────────────── */
int pc_check_root(const char *root, FILE *out);
int pc_append(char *out, size_t cap, size_t *used, const char *fmt, ...);
void pc_render(const struct sr_set *s, char *out, size_t cap, int json_style);

#endif
