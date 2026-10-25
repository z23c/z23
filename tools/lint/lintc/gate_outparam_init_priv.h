/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private interface shared by the check-outparam-init-before-return
 * gate files (driver, line lexer, out-parameter scan, publish/free scan and
 * selftest) — not listed in lintc.h, which declares only shared helpers and
 * gate entry points.
 */
#ifndef GATE_OUTPARAM_INIT_PRIV_H
#define GATE_OUTPARAM_INIT_PRIV_H

#include <stddef.h>

enum { OP_NAME = 128, OP_PATH = 160, OP_KEY = 3 * OP_NAME + 4 };

/* Growable NUL-terminated text. */
struct op_buf {
    char *p;
    size_t n, cap;
};
int op_buf_put(struct op_buf *b, const char *s, size_t n);
void op_buf_clear(struct op_buf *b);
void op_buf_free(struct op_buf *b);
const char *op_buf_str(const struct op_buf *b);

/* Insertion-ordered string set with a fixed capacity; adding past it is an
 * error (fail closed), never a silent drop. */
struct op_hset {
    char (*nm)[OP_NAME];
    int *slot;
    int n, cap, nslot;
};
int op_hset_init(struct op_hset *h, int cap);
void op_hset_free(struct op_hset *h);
void op_hset_clear(struct op_hset *h);
int op_hset_add(struct op_hset *h, const char *s);
int op_hset_has(const struct op_hset *h, const char *s);

/* ASCII character classes and small text predicates (locale independent). */
int op_idc(int c);
int op_id1(int c);
size_t op_skipws(const char *s, size_t i);
int op_word_before_ok(const char *s, size_t i);
int op_has_word(const char *s, const char *w);
int op_ends_semi(const char *s);
int op_nonblank(const char *s);
size_t op_trim(char *s);
int op_decl_name(const char *p, char *out, size_t cap);

/* The three awk programs the shell gate ran, as one line lexer: the
 * out-parameter scan, the publisher finder and the publish/free analyzer. */
enum op_mode { OP_MODE_SCAN, OP_MODE_PUB, OP_MODE_FREE };

struct op_fn;
typedef int (*op_emit_fn)(struct op_fn *f, void *ctx);

struct op_fn {
    enum op_mode mode;
    op_emit_fn emit;
    void *ctx;
    struct op_hset *objs; /* OP_MODE_PUB: file-scope pointer names, per file */
    int depth, incomment;
    long lineno;
    struct op_buf sig, work, full, arena;
    size_t *off;
    long *ln;
    size_t nbody, bodycap;
    char fnname[OP_NAME];
    const char *file;
};

void op_fn_init(struct op_fn *f, enum op_mode mode, op_emit_fn emit,
                void *ctx, struct op_hset *objs);
void op_fn_free(struct op_fn *f);
void op_fn_begin(struct op_fn *f, const char *file);
int op_fn_line(struct op_fn *f, const char *raw, size_t len);
/* Brace depth the file ended at; nonzero means the scanner lost balance. */
int op_fn_end(const struct op_fn *f);
const char *op_body(const struct op_fn *f, size_t j); /* 1-based */
long op_body_lineno(const struct op_fn *f, size_t j);
/* Reads one tracked file through the lexer; false on any read failure. */
int op_fn_file(struct op_fn *f, const char *path, int *final_depth);
/* Splits the parameter list of the current signature into a scratch copy
 * (NUL-separated); returns the part count, 0 for none. */
int op_params(const char *sig, struct op_buf *out);
const char *op_param_at(const struct op_buf *b, int idx);

/* Out-parameter scan (leg 1). */
struct op_finding {
    char key[OP_KEY];
    char file[OP_PATH];
    long exit_line, init_line;
    char tag;
};
struct op_scan {
    const struct op_hset *frees;
    struct op_finding *find;
    int nfind, capfind;
    long nfuncs, nparams;
    struct op_buf parms, region;
};
int op_scan_emit(struct op_fn *f, void *ctx);
void op_scan_free(struct op_scan *s);

/* Publisher finder and publish/free analyzer (leg 2). */
struct op_pubhit {
    char file[OP_PATH];
    char fn[OP_NAME], setter[OP_NAME], obj[OP_NAME];
    long pub_line, free_line;
};
enum { OP_PUBMAX = 256 };
/* One publish: setter(&obj) at body line j. */
struct op_pubat {
    char setter[OP_NAME], obj[OP_NAME];
    size_t j;
};
/* A named event (an unpublish or a module teardown) at body line j. */
struct op_pubmark {
    char name[OP_NAME];
    size_t j;
};
struct op_pub {
    struct op_hset *found;       /* publisher names the finder derived */
    const struct op_hset *known; /* publisher names the analyzer reads */
    struct op_pubhit *hit;
    int nhit, caphit;
    long nfuncs;
    struct op_buf parms;
    struct op_pubat at[OP_PUBMAX];
    struct op_pubmark clr[OP_PUBMAX], tear[OP_PUBMAX];
    int nat, nclr, ntear;
};
int op_pubfind_emit(struct op_fn *f, void *ctx);
int op_pubfree_emit(struct op_fn *f, void *ctx);
void op_pub_free(struct op_pub *p);

/* Selftest drivers use these in-memory feeds. */
int op_feed_text(struct op_fn *f, const char *name, const char *text,
                 int *final_depth);

#endif
