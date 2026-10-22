/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private declarations shared by the check-api-reference-generated
 * gate and its selftest.
 */
#ifndef GATE_API_REFERENCE_GENERATED_PRIV_H
#define GATE_API_REFERENCE_GENERATED_PRIV_H

#include <stddef.h>
#include <limits.h>
#include <stdio.h>

enum { ARG_DEF_MAX = 256, ARG_DEF_PATH = 160 };

struct arg_defs {
    char path[ARG_DEF_MAX][ARG_DEF_PATH]; /* sorted, unique */
    size_t n;
};

/* Both streams may be the same FILE. */
struct arg_io {
    FILE *out;
    FILE *err;
};

struct arg_scratch {
    char dir[PATH_MAX];
    char bin[PATH_MAX + 32];
    char expected[PATH_MAX + 32];
    char entries[24];
};

extern const char arg_gen_src[];
extern const char arg_template[];
extern const char arg_doc[];
extern const char arg_tmp_default[];

/* The .def files tools/gen_api_reference.c includes; 0 or a nonzero exit code. */
int arg_def_list(struct arg_defs *d);
/* Creates the scratch directory under TMPDIR; 0, or -1 with s->dir empty. */
int arg_open_scratch(struct arg_scratch *s);
/* The gate over the current directory: 0 clean, 1 drift, 2 fatal. */
int arg_gate(const struct arg_io *io);
/* The whole file as a NUL-terminated heap buffer (caller frees), or NULL. */
char *arg_slurp(const char *path);
/* Checks the generated reference against the template and .def sources; 0 clean, 1 failed, 2 fatal. */
int arg_verify(const struct arg_io *io, const struct arg_defs *d, char *entries, size_t cap);
/* Writes up to limit lines of data (0: all), each indented four spaces. */
void arg_indent(FILE *out, const char *data, size_t limit);

#endif
