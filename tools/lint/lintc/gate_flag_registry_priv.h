/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gate_flag_registry_priv — the seam between gate_flag_registry.c (the
 * flags.def parser, read-site scanner, and check-flag-registry gate body)
 * and gate_flag_registry_first_use.c (the first-use pointer check: does
 * the <path>:<line> a row cites actually read that flag's name).
 * NOT a public header: nothing outside tools/lint/lintc/ includes this.
 */

#ifndef ZCL_LINTC_GATE_FLAG_REGISTRY_PRIV_H
#define ZCL_LINTC_GATE_FLAG_REGISTRY_PRIV_H

#include <stdio.h>

enum {
    FR_NAME = 96,
    FR_FU_PATH = 256,
};

struct fr_row {
    char name[FR_NAME];
    char kind[24];
    char def[64];
    char exp[64];
    char fu_path[FR_FU_PATH];
    int fu_line;
    int fu_present;
    int used;
};

/* gate_flag_registry_first_use.c: parses the "first use <path>:<line>"
 * clause out of a row's why_ string (returns 0 with *line left untouched
 * when the string carries no such clause — e.g. "first use Makefile
 * deploy: recipe", which is prose, not a pointer), and verifies every
 * fu_present row's cited line actually reads the flag's name. */
int fru_parse_pointer(const char *why, char *path, size_t pathcap, int *line);
int fru_check_rows(const struct fr_row *rows, int n, FILE *out, int *verified);

#endif
