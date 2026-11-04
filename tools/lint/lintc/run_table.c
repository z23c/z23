/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the gate command table of `z23-lint run`, compiled in from
 * gate_commands.def (the one source of truth; check-lint-gate-wiring and
 * check-doc-claims read the same lines from the scanned root). The first row
 * for a name wins.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>

#include "run_priv.h"

#define LINT_ROW(name, cmd) { name, cmd },
static const struct {
    const char *name;
    const char *cmd;
} k_rows[] = {
#include "gate_commands.def"
};
#undef LINT_ROW

const struct lr_table_row *lr_table_find(const struct lr_table *t, const char *gate)
{
    for (int i = 0; i < t->n; i++) {
        if (strcmp(t->rows[i].name, gate) == 0)
            return &t->rows[i];
    }
    return NULL;
}

int lr_table_load(struct lr_table *t)
{
    t->n = 0;
    for (size_t i = 0; i < sizeof k_rows / sizeof k_rows[0]; i++) {
        struct lr_table_row *row = &t->rows[t->n];
        if (strlen(k_rows[i].name) >= sizeof row->name
            || strlen(k_rows[i].cmd) >= sizeof row->cmd)
            return 1;
        (void)snprintf(row->name, sizeof row->name, "%s", k_rows[i].name);
        (void)snprintf(row->cmd, sizeof row->cmd, "%s", k_rows[i].cmd);
        if (lr_table_find(t, row->name))
            continue;
        if (++t->n >= LR_TABLE_ROWS)
            return 1;
    }
    return 0;
}
