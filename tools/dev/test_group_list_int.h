/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared state and helpers of the test-group list TUs
 *          (test_group_list*.c). Nothing outside them includes this. */

#ifndef ZCL_TEST_GROUP_LIST_INT_H
#define ZCL_TEST_GROUP_LIST_INT_H

#include "test_group_list.h"

#include <stdbool.h>
#include <stddef.h>

/* Owned list of owned strings. */
struct tgl_strs {
    char **v;
    size_t n;
    size_t cap;
};

struct tgl_family {
    char *token;
    char *glob;
};

struct tgl_ctx {
    const struct tgl_sources *src;
    FILE *out;
    FILE *err;
    struct tgl_strs reg;      /* registered full names, catalog order */
    const char **sorted;      /* the same names, byte order, for lookup */
    struct tgl_family *fam;
    size_t nfam;
    bool fam_loaded;
};

bool tgl_strs_push(struct tgl_strs *s, const char *str, size_t len);
void tgl_strs_free(struct tgl_strs *s);
bool tgl_strs_has(const struct tgl_strs *s, const char *str);

/* Whole file in a NUL-terminated malloc buffer; NULL when unreadable. */
char *tgl_read_file(const char *path, size_t *len);
/* Split `text` in place at newlines (the final newline ends no extra line). */
/* Returns the line count; *lines is a malloc array of pointers into text. */
size_t tgl_split_lines(char *text, char ***lines);
/* stdout flushed, then the diagnostic stream. */
FILE *tgl_errf(const struct tgl_ctx *c);
/* The registered name `name`, or NULL. */
const char *tgl_find(const struct tgl_ctx *c, const char *name);

/* The pair-th double-quoted string of a line (awk -F'"' $2, $4), malloc. */
char *tgl_quoted_field(const char *line, int pair);
bool tgl_ident_char(int c);
bool tgl_blank(const char *s);
const char *tgl_skip_space(const char *s);

/* Registry. */
bool tgl_load_registry(struct tgl_ctx *c);
void tgl_ctx_free(struct tgl_ctx *c);
bool tgl_is_registered(const struct tgl_ctx *c, const char *name);
/* True and the one canonical full name when `needle` resolves exactly. */
bool tgl_resolve_exact(const struct tgl_ctx *c, const char *needle,
                       const char **hit);
bool tgl_load_families(struct tgl_ctx *c);
bool tgl_token_selects(struct tgl_ctx *c, const char *token, const char *full);

/* Splits an operand list on blanks. */
bool tgl_words(const char *text, struct tgl_strs *out);

/* test_group_list_umbrella.c */
int tgl_resolve_proof(struct tgl_ctx *c, const struct tgl_strs *ids);

/* test_group_list_rules.c */
int tgl_check_impact_rules(struct tgl_ctx *c, const char *rules);

/* test_group_list_report.c */
int tgl_report(struct tgl_ctx *c);
/* The gated names, or false after the FATAL diagnostic when there are none. */
bool tgl_gated_or_refuse(struct tgl_ctx *c, struct tgl_strs *gated);
bool tgl_params_gated(const struct tgl_ctx *c, struct tgl_strs *out);

#endif /* ZCL_TEST_GROUP_LIST_INT_H */
