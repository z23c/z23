/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the split C23 lint runtime's gate table and CLI entry point
 * (z23-lint <gate-name> [--selftest] | z23-lint <gate-name> [args...] | --list | --gate-command <gate>).
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "platform/logical_cpu.h"
#include "lintc.h"
#include "lintc_commands.h"
#include "premise.h"
#include "gate_lib_module_order_graph.h"

#define LINT_GATE(name, base, cmd) { name, base##_run, base##_selftest },
static const struct lint_gate k_gates[] = {
#include "gates.def"
};
#undef LINT_GATE

const struct lint_gate *lint_gate_table(size_t *n)
{
    *n = sizeof k_gates / sizeof k_gates[0];
    return k_gates;
}

/* Expose the same checked CPU, memory and optional-cap policy as native
 * Make-spawning callers, without introducing another sizing authority. */
static int build_jobs_main(int argc, char **argv)
{
    (void)argv;
    if (argc != 0) return die("z23-lint: usage: z23-lint build-jobs\n", "");
    char jobs[16];
    if (!platform_build_jobs_arg(jobs))
        return die("z23-lint: invalid ZCL_BUILD_MAX_JOBS or job count\n", "");
    if (printf("%s\n", jobs) < 0 || fflush(stdout) != 0)
        return die("z23-lint: build-jobs output failed\n", "");
    return 0;
}

/* Tool, not a gate. Withholds --changed-files when the gate source differs
 * from the base. The harness links fast_narrow.c without this entry point,
 * so the gate table stays out of that binary. */
static int lint_fast_scan_args(int argc, char **argv, const char **gate,
                               const char **changed)
{
    *gate = NULL;
    *changed = NULL;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "--gate=", 7) == 0 && argv[i][7] != '\0')
            *gate = argv[i] + 7;
        else if (strncmp(argv[i], "--changed-files=", 16) == 0 && argv[i][16] != '\0')
            *changed = argv[i] + 16;
        else
            return 2;
    }
    if (!*gate || !*changed)
        return 2;
    return 0;
}

static const struct lint_gate *lint_fast_find(const char *name)
{
    size_t n = 0;
    const struct lint_gate *tab = lint_gate_table(&n);
    for (size_t i = 0; i < n; i++) {
        if (strcmp(tab[i].name, name) == 0)
            return &tab[i];
    }
    return NULL;
}

static int lint_fast_scan_main(int argc, char **argv)
{
    const char *gate = NULL;
    const char *changed = NULL;
    const struct lint_gate *g;
    char flag[PATH_MAX];
    char *args[4];
    int ac = 0;
    if (lint_fast_scan_args(argc, argv, &gate, &changed) != 0)
        return die("z23-lint: usage: z23-lint fast-scan --gate=NAME --changed-files=PATH\n", "");
    g = lint_fast_find(gate);
    if (!g)
        return die("z23-lint: unknown gate: %s\n", gate);
    if (strcmp(gate, "check-fortify-masked-decls") == 0)
        args[ac++] = (char *)"--verify";
    if (lint_fast_gate_narrow(gate, 1)) {
        if (snprintf(flag, sizeof flag, "--changed-files=%s", changed) >= (int)sizeof flag)
            return 2;
        args[ac++] = flag;
    }
    args[ac] = NULL;
    return g->run(ac, args);
}

/* Subcommands (premise selection, module-linkgraph); they are tools, not
 * gates, so --list and the gate table never name them. */
static const struct {
    const char *name;
    int (*main)(int argc, char **argv);
} k_tools[] = {
    { "build-jobs", build_jobs_main },
    { "select", lint_select_main },
    { "unit-exec", lint_unit_exec_main },
    { "premise", lint_premise_main },
    { "precheck", lint_precheck_main },
    { "module-linkgraph", lmg_main },
    { "run", lint_run_main },
    { "epoch-probes", lint_epoch_probes_main },
    { "fast-scan", lint_fast_scan_main },
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

static int list_main(void)
{
    for (size_t i = 0; i < sizeof k_gates / sizeof k_gates[0]; i++)
        printf("%s\n", k_gates[i].name);
    return 0;
}

/* z23-lint --gate-command GATE: print the canonical lint command of a gate
 * gates.def owns; exit 1 (nothing printed) for any other gate. */
static int gate_command_main(int argc, char **argv)
{
    char cmd[512];
    if (argc != 3)
        return die("z23-lint: usage: z23-lint --gate-command <gate-name>\n", "");
    int rc = lint_gate_command(argv[2], cmd, sizeof cmd);
    if (rc == 0)
        puts(cmd);
    return rc;
}

int main(int argc, char **argv)
{
    g_lint_argv0 = argc > 0 ? argv[0] : NULL;
    if (argc >= 2 && strcmp(argv[1], "--list") == 0)
        return list_main();
    if (argc >= 2 && strcmp(argv[1], "--gate-command") == 0)
        return gate_command_main(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "--families") == 0)
        return lint_families_ledger();
    if (argc < 2)
        return die("z23-lint: usage: z23-lint <gate-name> [--selftest] | z23-lint <gate-name> [args...] | --list | --families | --gate-command <gate-name>\n",
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
