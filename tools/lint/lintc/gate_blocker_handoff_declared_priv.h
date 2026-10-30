/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declarations for the check_blocker_handoff_declared gate port:
 * gate_blocker_handoff_declared.c (tables, classification, report) and
 * gate_blocker_handoff_declared_scan.c (file walk and the three source
 * passes). The selftest lives in
 * gate_blocker_handoff_declared_selftest.c.
 */
#ifndef GATE_BLOCKER_HANDOFF_DECLARED_PRIV_H
#define GATE_BLOCKER_HANDOFF_DECLARED_PRIV_H

#include <stdio.h>
#include <stddef.h>

enum {
    BH_FILES = 8192,      /* scanned .c/.h paths */
    BH_PATH = 512,
    BH_SCRATCH = 2u << 20, /* one source file slurped whole */
    BH_LINES = 16384,     /* lines in the slurped file */
    BH_LLINE = 4096,      /* one physical line */
    BH_JOIN = 65536,      /* one backslash-joined #define (longest: ~10.8 KB) */
    BH_RBUF = 16384,      /* a joined multi-line call */
    BH_ARGS = 4096,       /* the argument text of one call */
    BH_SITES = 8192,      /* raise sites */
    BH_VAL = 176,         /* literal / id / expr text of a raise site */
    BH_MACRO = 2048,      /* BLOCKER_ID macro table rows */
    BH_IDLEN = 160,
    BH_MARKLEN = 256,     /* per-file blocker-id marker patterns, space-joined */
    BH_PAT = 512,         /* remedy / decision table rows */
    BH_HEAD = 128,        /* head of the second table argument */
    BH_EE = 1024,         /* ids raisable with an empty escape */
    BH_LOC = BH_PATH + 16,
    BH_BASE = 512,        /* baseline entries */
    BH_LST = 256          /* tolerated / violation / stale lists */
};

/* One raise site, the port of one awk output row. fnk is 1..5 indexing the
 * raise-form table; kind is 'l' literal, 'i' identifier, 'e' expression;
 * has_esc is 0/1 and is 1 only for blocker_init sites whose record variable
 * is later assigned a non-empty escape action in the same function. */
struct bh_site {
    int fidx;
    int line;
    char fnk;
    char kind;
    char has_esc;
    char val[BH_VAL];
};

extern char bh_files[BH_FILES][BH_PATH];
extern int bh_nfiles;
extern struct bh_site bh_sites[BH_SITES];
extern int bh_nsites;
extern char bh_macros[BH_MACRO][2][BH_IDLEN];
extern int bh_nmacros;
extern char bh_fmark[BH_FILES][BH_MARKLEN];
extern size_t bh_got;          /* bytes of the currently slurped file */
extern char bh_scratch[BH_SCRATCH];

void bh_reset(void);
int bh_set_root(const char *root);
int bh_collect_files(const char *roots_spec);
int bh_scan_all(void);
int bh_path(char *out, size_t cap, const char *rel);
int bhd_run_gate(const char *root, FILE *out, FILE *err);

#endif
