/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fp_priv — shared internals of cognition/modules/fingerprint. Not a public surface.
 *
 * The scan keeps every source file's CLEANED text (comments and literals
 * blanked to spaces, newlines preserved) so that a byte offset in the
 * cleaned text is also a byte offset in the original and a line number is a
 * count of newlines before it. Every symbol record is therefore a pair of
 * offsets into one buffer rather than a copied string, which is what keeps a
 * whole-tree scan bounded.
 */

#ifndef ZCL_FP_PRIV_H
#define ZCL_FP_PRIV_H

#include "fingerprint/fingerprint.h"

#include <stdio.h>

enum fp_sym_kind {
    FP_SYM_FUNC = 0,   /* a function DEFINITION, with a body */
    FP_SYM_PROTO,      /* a function prototype in a header */
    FP_SYM_MACRO,      /* a #define */
    FP_SYM_OBJ,        /* a file-scope object */
    FP_SYM_ENUMCONST,  /* an enumeration constant */
    FP_SYM_TYPE        /* struct/union/enum/typedef tag */
};

struct fp_sym {
    char name[FP_MAX_NAME];
    unsigned char kind;
    bool is_static;
    bool const_object;   /* file-scope object safe to read (see fp_purity) */
    int  file;
    int  line;
    uint32_t decl_off;   /* declarator text: return type + name + params */
    uint32_t decl_len;
    uint32_t body_off;   /* function body, or macro replacement text */
    uint32_t body_len;
    int  next;           /* hash chain */
    signed char verdict; /* cached fp_verdict, -1 unknown, -2 in progress */
    char cause[FP_MAX_NAME]; /* identifier that caused a cached rejection */
};

struct fp_file {
    char  path[FP_MAX_PATH];
    char  group[64];
    char  include[FP_MAX_PATH];
    char *text;
    size_t len;
    bool  is_header;
    /* This unit defines main(). Including it into a probe translation unit
     * would collide with the generated driver's own main() at link time and
     * take the whole link down, so a file-local function living here has no
     * reachable definition at all. Decided once, at scan time, rather than
     * discovered as a link failure that costs a whole round. */
    bool  defines_main;
    /* This unit exports an external symbol that some OTHER unit also
     * exports. In a tree that links, that only happens between mutually
     * exclusive `#if` variants — foo_posix.c and foo_win32.c — and the
     * scanner does not run the preprocessor, so it sees both. Including both
     * into two probe TUs would define the symbol twice and fail the whole
     * link, and a link failure costs a round and blames the wrong probes.
     * Refused up front instead, and counted. */
    bool  dup_export;
};

struct fp_index {
    char root[FP_MAX_PATH];
    struct fp_file *files;
    size_t nfiles;
    struct fp_sym *syms;
    size_t nsyms;
    size_t syms_cap;
    int   *bucket;
    size_t nbuckets;
    size_t nfuncs;
    /* The identifier that caused the most recent rejection. Reporting WHY a
     * function was refused by name is what makes the exclusion buckets
     * actionable — the commonest unresolved call target is the next
     * allowlist entry, or the next real impurity. */
    char cause[FP_MAX_NAME];
    /* Whether a file-local function may be reached by including its defining
     * unit. On by default; turned off only to measure the difference. */
    bool allow_source_route;
    struct fp_cause {
        char name[FP_MAX_NAME];
        unsigned char verdict;
        size_t count;
    } *causes;
    size_t ncauses;
    size_t causes_cap;
};

/* fp_index.c */
uint64_t fp_hash_str(const char *s);
int  fp_sym_lookup(const struct fp_index *ix, const char *name, size_t len,
                   enum fp_sym_kind kind);
int  fp_line_of(const struct fp_file *f, uint32_t off);
bool fp_ident_start(int c);
bool fp_ident_char(int c);

/* fp_purity.c */
enum fp_verdict fp_purity_of(struct fp_index *ix, int sym);

/* fp_sig.c */
enum fp_verdict fp_signature_of(struct fp_index *ix, int sym,
                                struct fp_candidate *out);

#endif /* ZCL_FP_PRIV_H */
