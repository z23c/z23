/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the canonical lint command of every gate gates.def marks
 * LINT_CMD_PLAIN or LINT_CMD_PAIR, so run_lint.sh asks z23-lint for these
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
