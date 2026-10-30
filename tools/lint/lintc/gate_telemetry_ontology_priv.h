/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for the check-telemetry-ontology gate port
 * (gate_telemetry_ontology.c plus its _onto and _scan parts). Ported from
 * tools/lint/check_telemetry_ontology.sh (deleted). All gate state lives in
 * one static struct so the selftest can re-run the gate repeatedly with no
 * heap allocation; every fixed array is capacity-checked and an overflow is
 * a loud exit 2, never a silent truncation.
 */
#ifndef GATE_TELEMETRY_ONTOLOGY_PRIV_H
#define GATE_TELEMETRY_ONTOLOGY_PRIV_H
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include "lintc.h"

#define TO_GATE "check_telemetry_ontology"

enum {
    TO_MAX_ONTO = 3000,
    TO_KEY = 256,
    TO_MAX_DOM = 64,
    TO_DOM = 64,
    TO_MAX_ROWS = 128,
    TO_ROWKEY = 320,
    TO_PREFIX = 160,
    TO_SUB = 48,
    TO_MAX_TBL = 32,
    TO_PATH = 512,
    TO_MAX_FILL = 256,
    TO_MAX_VIOL = 512,
    TO_VIOL = 320,
    TO_LINE = 2048,
    TO_BUF = 2048,
    TO_MAX_CHECKED = 128,
};

struct to_viol {
    char line[TO_MAX_VIOL][TO_VIOL];
    int n;
};

struct to_state {
    FILE *out, *err;
    const char *manifest_path, *extra_path, *onto_path, *domains_path;
    const char *fields_dir, *tu_path, *fill_count_path, *fill_roots, *mode;
    char onto_key[TO_MAX_ONTO][TO_KEY];
    int onto_n, onto_count, judged, questions;
    char reg_dom[TO_MAX_DOM][TO_DOM];
    int reg_n;
    char pasted_dom[TO_MAX_DOM][TO_DOM];
    int pasted_n;
    char dom_def[TO_MAX_DOM][TO_PATH];
    int dom_def_n;
    int dom_table_rows;
    struct to_viol mispaired, half_reg, content_bad;
    char checked[TO_MAX_CHECKED][TO_PATH];
    int checked_n;
    char m_key[TO_MAX_ROWS][TO_ROWKEY];
    char m_prefix[TO_MAX_ROWS][TO_PREFIX];
    char m_sub[TO_MAX_ROWS][TO_SUB];
    int m_n;
    char f_file[TO_MAX_ROWS][TO_PATH];
    char f_fn[TO_MAX_ROWS][TO_DOM];
    int f_n;
    char t_dom[TO_MAX_TBL][TO_DOM];
    char t_def[TO_MAX_TBL][TO_PATH];
    int t_min[TO_MAX_TBL], t_n;
    char fill_file[TO_MAX_FILL][TO_PATH];
    int fill_n;
    struct to_viol unmapped, unannotated, unresolved, shrunk, handwritten,
        wrong_domain;
    int extracted, table_leaves, fill_scanned;
    int failed_content, failed_fill;
};

int to_check(FILE *out, FILE *err);
int to_each_line(const char *path, FILE *err,
                 int (*cb)(void *, const char *, size_t), void *ctx);
int to_viol_add(struct to_viol *v, FILE *err, const char *fmt, ...);
int to_viol_has(const struct to_viol *v, const char *needle);
void to_viol_print(FILE *f, const struct to_viol *v);
int to_readable(const char *path);
/* onto part */
int to_phase_onto(struct to_state *st);
int to_onto_has(const struct to_state *st, const char *key);
int to_onto_add(struct to_state *st, const char *key);
int to_leaf_gm(const char *line, char *g, char *m);
int to_table_domain(const char *path, char *out, size_t cap, FILE *err);
int to_content_scan(struct to_state *st, struct to_viol *dst,
                    const char *path, int leaf);
int to_checked_has(const struct to_state *st, const char *path);
int to_list_add(char (*list)[TO_PATH], int *n, int cap, const char *what,
                FILE *err, const char *path);
int to_mark_checked(struct to_state *st, const char *path);
/* scan part */
int to_phase_manifest(struct to_state *st);
int to_phase_scan(struct to_state *st);
int to_phase_tables(struct to_state *st);
int to_verdict(struct to_state *st);

#endif
