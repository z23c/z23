/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private interface of check_package_anatomy. Shared by
 * gate_package_anatomy.c (rules, verdict, entry points),
 * gate_package_anatomy_hdr.c (R4-R6 public-header scan) and
 * gate_package_anatomy_kat.c (declared KATs) and gate_package_anatomy_selftest.c
 * (the fixture builder reuses pka_upper). Nothing else includes it.
 */
#ifndef Z23_LINTC_GATE_PACKAGE_ANATOMY_PRIV_H
#define Z23_LINTC_GATE_PACKAGE_ANATOMY_PRIV_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"

enum { PKA_PKGS = 512, PKA_FILES = 2048, PKA_PATH = 1024,
       PKA_LINE = CSTRIP_LINE_MAX, PKA_MLINE = 4096,
       PKA_MANIFEST = 65536, PKA_FAILS = 512, PKA_FAIL = 1200,
       PKA_DECL = 2048, PKA_CC = 16, PKA_CCLEN = 256 };

struct pka_ctx {
    char fail[PKA_FAILS][PKA_FAIL];
    int nfail;
};

struct pka_fl {
    char p[PKA_FILES][PKA_PATH];
    int n;
};

struct pka_decl {
    char v[PKA_DECL][PKA_PATH];
    int comma[PKA_DECL];
    int n;
};

extern const char k_pka_gate[];
extern struct pka_fl g_pka_fl;

/* Record one violation row; 0 ok, 2 fatal (row overflow / too many). */
int pka_fail(struct pka_ctx *cf, const char *fmt, ...);

#define PKA_FAIL(...) do { \
    int q_ = pka_fail(cf, __VA_ARGS__); \
    if (q_) return q_; \
} while (0)

/* Character and text helpers defined in gate_package_anatomy.c. */
size_t pka_ws(const char *s, size_t i);
int pka_idch(char c);
void pka_upper(const char *in, char *out, size_t cap);

/* R4-R6: public header guard, macros and inline definitions. */
int pka_r4(const char *dir, const char *pkg, struct pka_ctx *cf);

/* Declared KATs; 0 ok, 1 a KAT failed, 2 fatal. */
int pka_run_kats(void);

#endif
