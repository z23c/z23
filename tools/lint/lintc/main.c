/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the split C23 lint runtime's gate table and CLI entry point
 * (z23-lint <gate-name> [--selftest] | z23-lint <gate-name> [args...] | --list).
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "premise.h"

#define LINT_GATE(name, base) { name, base##_run, base##_selftest },
static const struct lint_gate k_gates[] = {
#include "gates.def"
};
#undef LINT_GATE

/* Premise-selection subcommands; they are tools, not gates, so --list and
 * the gate table never name them. */
static const struct {
    const char *name;
    int (*main)(int argc, char **argv);
} k_tools[] = {
    { "select", lint_select_main },
    { "unit-exec", lint_unit_exec_main },
    { "premise", lint_premise_main },
};

/* The premise-selection tool named by argv[1], or NULL. */
static int (*find_tool(const char *name))(int, char **)
{
    for (size_t i = 0; i < sizeof k_tools / sizeof k_tools[0]; i++) {
        if (strcmp(name, k_tools[i].name) == 0)
            return k_tools[i].main;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    g_lint_argv0 = argc > 0 ? argv[0] : NULL;
    if (argc >= 2 && strcmp(argv[1], "--list") == 0) {
        for (size_t i = 0; i < sizeof k_gates / sizeof k_gates[0]; i++)
            printf("%s\n", k_gates[i].name);
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "--families") == 0)
        return lint_families_ledger();
    if (argc < 2)
        return die("z23-lint: usage: z23-lint <gate-name> [--selftest] | z23-lint <gate-name> [args...] | --list | --families\n",
                   "");
    int (*tool)(int, char **) = find_tool(argv[1]);
    if (tool)
        return tool(argc - 2, argv + 2);
    const struct lint_gate *g = NULL;
    for (size_t i = 0; i < sizeof k_gates / sizeof k_gates[0]; i++) {
        if (strcmp(argv[1], k_gates[i].name) == 0)
            g = &k_gates[i];
    }
    if (!g)
        return die("z23-lint: unknown gate: %s\n", argv[1]);
    if (argc >= 3 && strcmp(argv[2], "--selftest") == 0)
        return g->selftest();
    return g->run(argc - 2, argv + 2);
}
