/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the canonical lint command of every gate gates.def marks
 * LINT_CMD_PLAIN or LINT_CMD_PAIR, so z23-lint run asks for these
 * instead of carrying one identical case line per gate.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "lintc.h"

#define LINT_GATE(name, base, cmd, ...) { name, cmd },
static const struct {
    const char *name;
    int cmd;
} k_cmds[] = {
#include "gates.def"
};
#undef LINT_GATE

int lint_gate_command(const char *gate, char *out, size_t cap)
{
    for (size_t i = 0; i < sizeof k_cmds / sizeof k_cmds[0]; i++) {
        if (strcmp(gate, k_cmds[i].name) != 0 || k_cmds[i].cmd == LINT_CMD_NONE)
            continue;
        int n = k_cmds[i].cmd == LINT_CMD_PAIR
            ? snprintf(out, cap, "./build/bin/z23-lint %s --selftest && ./build/bin/z23-lint %s",
                       gate, gate)
            : snprintf(out, cap, "./build/bin/z23-lint %s", gate);
        return n < 0 || (size_t)n >= cap ? 2 : 0;
    }
    return 1;
}

static int lint_row_name(const char **input, char *name, size_t cap)
{
    const char *p = *input;
    size_t n = 0;
    for (; *p && *p != '"'; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-'))
            return 2;
        if (n + 1 >= cap) return 2;
        name[n++] = *p;
    }
    name[n] = '\0';
    if (n <= 6 || strncmp(name, "check-", 6) != 0) return 2;
    if (strncmp(p, "\", \"", 4) != 0) return 2;
    *input = p + 4;
    return 0;
}

static int lint_row_command(const char *p, char *cmd, size_t cap)
{
    size_t n = 0;
    for (; *p && !(p[0] == '"' && p[1] == ')'); p++) {
        if (*p == '\\') {
            if (p[1] != '"' && p[1] != '\\') return 2;
            p++;
        }
        if (n + 1 >= cap) return 2;
        cmd[n++] = *p;
    }
    cmd[n] = '\0';
    if (p[0] != '"' || p[1] != ')') return 2;
    p += 2;
    while (*p && isspace((unsigned char)*p)) p++;
    return *p ? 2 : 0;
}

/* The table permits only blank lines, // comments and canonical rows. One
 * scanner behind both row kinds: OPEN names the row word ("LINT_ROW(\"" or
 * "LINT_ROW_FILES(\""); the same 0/1/2 contract as lint_cmdrow_parse. */
static int lint_row_scan(const char *line, const char *open, char *name,
                         size_t ncap, char *str, size_t scap)
{
    const char *p = line;
    while (isspace((unsigned char)*p)) p++;
    if (!*p) return 1;
    if (p[0] == '/' && p[1] == '/') {
        size_t n = strlen(p);
        if (n && p[n - 1] == '\n') n--;
        if (n && p[n - 1] == '\r') n--;
        return n && p[n - 1] == '\\' ? 2 : 1;
    }
    if (strncmp(p, open, strlen(open)) != 0) return 2;
    p += strlen(open);
    return lint_row_name(&p, name, ncap) ? 2 : lint_row_command(p, str, scap);
}

/* One line of gate_commands.def text (the driver's command table): 0 a
 * LINT_ROW("name", "command") row with the command in CMD, 3 a
 * LINT_ROW_FILES("name", "sources") marker row with the sources in CMD,
 * 1 not a row (blank or // comment), 2 malformed or too long. */
int lint_cmdrow_parse(const char *line, char *name, size_t ncap, char *cmd,
                      size_t ccap)
{
    int rc = lint_row_scan(line, "LINT_ROW(\"", name, ncap, cmd, ccap);
    if (rc != 2)
        return rc;
    return lint_row_scan(line, "LINT_ROW_FILES(\"", name, ncap, cmd, ccap) == 0
               ? 3
               : 2;
}
