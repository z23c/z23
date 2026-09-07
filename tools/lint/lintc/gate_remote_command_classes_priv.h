/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for the check-remote-command-classes C23
 * lint family (gate_remote_command_classes.c, its _parse.c sibling, and its
 * _selftest.c sibling). Private to this family — never included outside
 * tools/lint/lintc/.
 */
#ifndef GATE_REMOTE_COMMAND_CLASSES_PRIV_H
#define GATE_REMOTE_COMMAND_CLASSES_PRIV_H

#include <stdio.h>

enum { RCC_LEAF = 256, RCC_CLASS = 64, RCC_REASON = 2048 };

/* A growable, order-preserving set of NUL-terminated strings, owned. */
struct rcc_list {
    char **v;
    size_t n, cap;
};

/* One parsed REMOTE_COMMAND_CLASS(...) row, in file order. leaf/cls default
 * to "?" and reason to "" when the row does not parse — never silently
 * dropped, matching the retired awk helper's emit(). */
struct rcc_row {
    char leaf[RCC_LEAF];
    char cls[RCC_CLASS];
    char reason[RCC_REASON];
    int wellformed; /* quote_count(buf) == 4 */
};

struct rcc_rows {
    struct rcc_row *v;
    size_t n, cap;
};

int rcc_push(struct rcc_list *l, const char *s, size_t n);
int rcc_add_uniq(struct rcc_list *l, const char *s, size_t n);
int rcc_has(const struct rcc_list *l, const char *s);
void rcc_free(struct rcc_list *l);
void rcc_sort(struct rcc_list *l);

int rcc_row_push(struct rcc_rows *r, const struct rcc_row *row);
void rcc_rows_free(struct rcc_rows *r);

/* source A: typed command registry (replaces the retired command-leaf awk helper).
 * *nfiles is set to the number of *.def files walked (the shell's
 * `find ... | wc -l`), independent of how many leaves they yielded. */
int rcc_leaf_dir(const char *def_dir, struct rcc_list *leaves, int *nfiles);

/* source B: flat AGENT_CONTRACT(...) method table. */
int rcc_agent_defs(const char *agent_def, struct rcc_list *methods);

/* source C: the class table (replaces the retired class-table awk helper). */
int rcc_table_rows(const char *table_path, struct rcc_rows *rows);

/* Re-invokes the gate against the given three sources and two floors — the
 * selftest's hook onto the same run_gate() the production path uses. */
int rcc_run_gate_for_selftest(const char *def_dir, const char *agent_def,
                              const char *table, int typed_floor,
                              int agent_floor, FILE *out, FILE *err);

#endif
