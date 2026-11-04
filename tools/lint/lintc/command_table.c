/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the canonical lint command of every gate gates.def marks
 * LINT_CMD_PLAIN or LINT_CMD_PAIR, so z23-lint run asks for these
 * instead of carrying one identical case line per gate.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include "lintc.h"

#define LINT_GATE(name, base, cmd) { name, cmd },
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

/* Parse one `LINT_ROW("name", "command")` line of gate_commands.def text:
 * the name and the unescaped command (`\"` and `\\`). 0 if LINE is a row,
 * 1 if it is not one, 2 if a field does not fit. */
int lint_cmdrow_parse(const char *line, char *name, size_t ncap, char *cmd,
                      size_t ccap)
{
    static const char k_open[] = "LINT_ROW(\"";
    const char *p = line;
    size_t n = 0;
    if (strncmp(p, k_open, sizeof k_open - 1) != 0)
        return 1;
    p += sizeof k_open - 1;
    for (; *p && *p != '"'; p++) {
        if (n + 1 >= ncap)
            return 2;
        name[n++] = *p;
    }
    name[n] = '\0';
    if (strncmp(p, "\", \"", 4) != 0)
        return 1;
    p += 4;
    n = 0;
    for (; *p && !(p[0] == '"' && p[1] == ')'); p++) {
        if (*p == '\\' && (p[1] == '"' || p[1] == '\\'))
            p++;
        if (n + 1 >= ccap)
            return 2;
        cmd[n++] = *p;
    }
    cmd[n] = '\0';
    return p[0] == '"' && p[1] == ')' ? 0 : 1;
}
