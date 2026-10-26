/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for check-split-preserved
 * (gate_split_preserved.c, gate_split_preserved_check.c and
 * gate_split_preserved_selftest.c): the lexical facts of one C file, and the
 * comparison of a base text with a new text.
 */
#ifndef GATE_SPLIT_PRESERVED_PRIV_H
#define GATE_SPLIT_PRESERVED_PRIV_H
#include <stddef.h>
#include <stdio.h>

/* One fact. key is the compared text; for a LOG call it is "FUNC\tCALL". func
 * names the enclosing function ("" outside one). miss is set by sp_diff. */
struct sp_ent {
    char *key;
    char *func;
    unsigned line;
    size_t off;
    int miss;
};

struct sp_list {
    struct sp_ent *v;
    size_t n, cap;
    int err;
};

/* A function definition: its name and the byte range from the line after the
 * previous declaration to its closing brace. */
struct sp_span {
    char *name;
    size_t from, to;
};

struct sp_file {
    struct sp_list cm;  /* comment lines, trimmed */
    struct sp_list lg;  /* LOG_*( calls with their function */
    struct sp_list inc; /* #include and __has_include lines */
    struct sp_span *span;
    size_t nspan, capspan;
    char *hdr[5];       /* the first five lines, for the licence check */
    char *code;         /* the text with every comment blanked */
    unsigned char *lit; /* 1 for each byte of a string or char literal */
    size_t n;
    int err;
};

/* Fills f from text; returns 0, or 1 when memory ran out. */
int sp_analyze(struct sp_file *f, const char *text, size_t n);
void sp_free(struct sp_file *f);

/* Whether the header named by an added #include exists in the tree. */
typedef int (*sp_exists_fn)(const char *header);

/* Compares cur against base for path, writing one "FAIL path:LINE: ..." line
 * per finding to out. dedup selects the duplicate-removal rules. Returns 0
 * clean, 1 findings, 2 memory ran out. */
int sp_compare(const char *path, const char *base, size_t base_len,
               const char *cur, size_t cur_len, int dedup,
               sp_exists_fn exists, FILE *out);

#endif
