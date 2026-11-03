/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: read run_lint.sh's gate_command() table for `z23-lint run`, so the
 * C driver and the shell driver share one source of truth while both exist.
 * A row is `<ws>check-NAME)<ws>echo '<command>' ;` with the command in single
 * quotes; the first row for a name wins, as in the shell case statement.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "run_priv.h"

static const char *skip_blank(const char *p)
{
    while (*p == ' ' || *p == '\t')
        p++;
    return p;
}

static int name_char(int c)
{
    return islower(c) || isdigit(c) || c == '-';
}

/* Copy the gate name at P into ROW; the pointer after it, NULL if too long. */
static const char *take_name(const char *p, struct lr_table_row *row)
{
    size_t n = 0;
    while (name_char((unsigned char)p[n])) {
        if (n + 1 >= sizeof row->name)
            return NULL;
        row->name[n] = p[n];
        n++;
    }
    row->name[n] = '\0';
    return p + n;
}

/* Past `echo` and its blanks; NULL when the word is not `echo `. */
static const char *take_echo(const char *p)
{
    if (strncmp(p, "echo", 4) != 0 || (p[4] != ' ' && p[4] != '\t'))
        return NULL;
    return skip_blank(p + 4);
}

/* Copy the single-quoted text at P into ROW's command. */
static int take_command(const char *p, struct lr_table_row *row)
{
    const char *end;
    if (*p++ != '\'')
        return 0;
    end = strchr(p, '\'');
    if (!end || (size_t)(end - p) >= sizeof row->cmd)
        return 0;
    memcpy(row->cmd, p, (size_t)(end - p));
    row->cmd[end - p] = '\0';
    return 1;
}

/* Parse one source line into NAME and CMD; 1 if it is a table row. */
static int parse_row(const char *line, struct lr_table_row *row)
{
    const char *p = skip_blank(line);
    if (p == line || strncmp(p, "check-", 6) != 0)
        return 0;
    p = take_name(p, row);
    if (!p || *p++ != ')')
        return 0;
    p = take_echo(skip_blank(p));
    return p && take_command(p, row);
}

const struct lr_table_row *lr_table_find(const struct lr_table *t, const char *gate)
{
    for (int i = 0; i < t->n; i++) {
        if (strcmp(t->rows[i].name, gate) == 0)
            return &t->rows[i];
    }
    return NULL;
}

int lr_table_load(struct lr_table *t, const char *path)
{
    FILE *f = fopen(path, "r");
    char line[LR_CMD + 256];
    t->n = 0;
    if (!f)
        return 1;
    while (fgets(line, sizeof line, f)) {
        struct lr_table_row *row = &t->rows[t->n];
        if (!parse_row(line, row) || lr_table_find(t, row->name))
            continue;
        if (++t->n >= LR_TABLE_ROWS) {
            (void)fclose(f);
            return 1;
        }
    }
    (void)fclose(f);
    return 0;
}
