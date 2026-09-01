/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal seams of the writer census (controllers/fact_writers.h is the public
 * surface). Three translation units share these:
 *
 *   fact_writers_manifest.c  expands controllers/fact_store_writers.def into the
 *                            store + write-entry-point row tables and hands them
 *                            out read-only. It is the ONLY file that includes
 *                            the .def, so a manifest row's function address is
 *                            taken exactly once.
 *   fact_writers_text.c      the source-text primitives: whole-file + line
 *                            cache, the string-valued macro table, adjacent
 *                            string-literal joining, call-argument extraction,
 *                            key resolution and plausibility.
 *   fact_writers.c           the census itself — the three derivations, the
 *                            accumulator, and report assembly.
 *   fact_writers_coverage.c  the other direction: declared keyed-write entry
 *                            points that no manifest row claims.
 *
 * Nothing here is a fact about the node; every function reads the tree.
 */

#ifndef ZCL_CONTROLLERS_FACT_WRITERS_PRIV_H
#define ZCL_CONTROLLERS_FACT_WRITERS_PRIV_H

#include "controllers/fact_writers.h"

#include <stdbool.h>
#include <stddef.h>

#define FW_DOMAIN "factwriters"

enum { FW_MACRO_NAME_MAX = 80, FW_LINE_JOIN = 6, FW_SQL_WINDOW = 6 };

/* ── the manifest rows (fact_writers_manifest.c) ─────────────────────────── */

struct fw_store_row {
    const char *store;
    const char *table;
    const char *key_column;
    const char *api_headers;   /* ':'-separated repo-relative paths */
};

/* The one purpose of storing an entry point's address is to make a manifest row
 * naming a nonexistent function fail the compile and the link. The signatures
 * differ per store, so the census holds them at the one function-pointer type
 * ISO C lets every other one be cast to and from without loss. */
typedef void (*fact_write_entry_fn)(void);

struct fw_api_row {
    const char *store;
    const char *fn;
    fact_write_entry_fn addr;
    int key_arg;               /* 0-based position of the key argument */
};

const struct fw_store_row *fw_store_rows(size_t *count);
const struct fw_api_row *fw_api_rows(size_t *count);
/* Is `fn` already a declared write entry point of `store`? */
bool fw_api_claimed(const char *store, const char *fn);

/* ── source-text primitives (fact_writers_text.c) ────────────────────────── */

bool fw_ident_char(char c);
/* Word-boundary substring search from `from`; the offset, or -1 when absent. */
long fw_find_word(const char *hay, const char *needle, long from);
void fw_trim(char *s);
/* A line whose first visible characters open or continue a comment. */
bool fw_comment_line(const char *line);

/* One loaded file: whole content plus a line-start index. */
struct fw_file {
    char *buf;
    size_t len;
    size_t *line_off;
    size_t nlines;
};

/* Load <root>/<rel>. false when absent/oversized — not an error for a census.
 * The unindexed form is for whole-buffer predicates/harvests; callers that
 * need random line access must index it (or use the combined loader). */
bool fw_file_load_unindexed(const char *root, const char *rel,
                            struct fw_file *out);
bool fw_file_index_lines(struct fw_file *file);
bool fw_file_load(const char *root, const char *rel, struct fw_file *out);
void fw_file_free(struct fw_file *f);
/* Copy line `lineno` (1-based) into dst[cap], sans newline. "" when absent. */
void fw_file_line(const struct fw_file *f, size_t lineno, char *dst, size_t cap);

/* String-valued `#define`s harvested from the tree. */
struct fw_macro {
    char name[FW_MACRO_NAME_MAX];
    char value[FACT_KEY_MAX];
};

struct fw_macros {
    struct fw_macro *v;
    size_t n, cap;
};

const char *fw_macro_lookup(const struct fw_macros *m, const char *name);
bool fw_collect_macros(const struct fw_file *f, struct fw_macros *m);

/* Concatenate the adjacent string-literal pieces starting at `p` (the opening
 * quote), resolving an interleaved string-valued macro identifier. Returns the
 * byte after the last consumed piece. */
const char *fw_join_literals(const char *p, const struct fw_macros *m,
                             char *out, size_t cap);

/* Join up to FW_LINE_JOIN raw lines from `lineno` so a call split over lines is
 * one string; stops once parenthesis depth returns to zero. */
void fw_join_call(const struct fw_file *f, size_t lineno, char *out, size_t cap);
/* Argument `idx` (0-based) of the first `fn(` call in `text`. */
bool fw_call_arg(const char *text, const char *fn, int idx,
                 char *out, size_t cap);
/* Resolve an argument's source text to the key string it denotes. */
bool fw_resolve_key(const char *argtext, const struct fw_macros *m,
                    char *out, size_t cap);
/* Reject what cannot name a durable slot: a bind placeholder, a LIKE pattern,
 * a statement fragment. This is what keeps a wildcard out of the fact set. */
bool fw_key_plausible(const char *key);
/* Index of the first `const char *` parameter in a joined declaration, or -1. */
int fw_key_param_index(const char *decl);

#endif /* ZCL_CONTROLLERS_FACT_WRITERS_PRIV_H */
