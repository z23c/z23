/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: `z23-lint run` — the C23 lint driver (shadow of tools/lint/run_lint.sh).
 *
 *   z23-lint run [--jobs N] [--bin-dir DIR] [--list] [--print-command GATE] GATE...
 *
 * Runs each gate's command from run_lint.sh's gate_command() table (the one
 * source of truth while both drivers exist; a gate absent there asks
 * gates.def) with fork/execvp and no shell, up to --jobs at a time, and
 * prints the run_lint.sh verdict lines, `lint timing` table and FAIL logs.
 * tools/scripts/check_*.sh wrappers that only exec z23-lint run as
 * `z23-lint <gate>` directly. Env as run_lint.sh: ZCL_LINT_JOBS,
 * ZCL_LINT_BUDGET_SEC, ZCL_LINT_TIMING_DIR, ZCL_LINT_VERBOSE,
 * ZCL_LINT_INVENTORY_TOOL, ZCL_HOST_JOBS (nested sweep worker counts).
 * Exit: 0 every gate passed, 1 a gate failed (all still run), 2 misuse.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lintc.h"
#include "run_priv.h"

enum { DEFAULT_JOBS = 8, DEFAULT_BUDGET = 75, DEFAULT_HOST = 8 };

static struct lr_table g_table;

/* Same sets as run_lint.sh: SERIAL_PROLOGUE, SERIAL_EPILOGUE, LONG_POLE_FIRST. */
static const char k_serial_pro[] = " check-git-hooks-installed check-build-epoch-integrity ";
static const char k_serial_epi[] = " check-codeindex-coverage check-cookbook ";
static const char k_poles[] =
    " check-windows-cross-syntax check-standalone-tools-link check-clang-portability"
    " check-vcs-no-sha1 check-windows-acceptance check-outparam-init-before-return ";

static int resolve_default(void *ctx, const char *gate, char *cmd, size_t cap)
{
    const struct lr_table_row *row = lr_table_find(ctx, gate);
    if (!row)
        return lint_gate_command(gate, cmd, cap);
    int n = snprintf(cmd, cap, "%s", row->cmd);
    return n < 0 || (size_t)n >= cap ? 2 : 0;
}

static bool all_digits(const char *s)
{
    if (!*s)
        return false;
    for (; *s; s++) {
        if (!isdigit((unsigned char)*s))
            return false;
    }
    return true;
}

static int env_int(const char *name, int dflt)
{
    const char *v = getenv(name);
    return (v && all_digits(v) && strlen(v) < 9) ? atoi(v) : dflt;
}

/* `${NAME:-value}`: set only when unset or empty. */
static void env_default(const char *name, const char *value)
{
    const char *v = getenv(name);
    if (!v || !*v)
        (void)setenv(name, value, 1);
}

static bool wants(char *const *gates, int n, const char *name)
{
    for (int i = 0; i < n; i++) {
        if (strcmp(gates[i], name) == 0)
            return true;
    }
    return false;
}

static int clamp(int v, int lo, int hi)
{
    return v < lo ? lo : (v > hi ? hi : v);
}

/* The driver already spends the host across gates; nested sweeps get a
 * bounded share (3/8 and 5/8 of the host), everything else one worker. */
static void setup_env(char *const *gates, int n, const char *bin_dir)
{
    long host = sysconf(_SC_NPROCESSORS_ONLN);
    char buf[24];
    int sweep = env_int("ZCL_HOST_JOBS", host > 0 ? (int)host : DEFAULT_HOST);
    if (wants(gates, n, "check-clang-portability")
        || wants(gates, n, "check-windows-cross-syntax")) {
        (void)snprintf(buf, sizeof buf, "%d", clamp(sweep * 3 / 8, 4, 12));
        env_default("ZCL_CC_JOBS", buf);
        (void)snprintf(buf, sizeof buf, "%d", clamp(sweep * 5 / 8, 6, 20));
        env_default("ZCL_WIN_CROSS_JOBS", buf);
    } else {
        env_default("ZCL_CC_JOBS", "1");
    }
    env_default("ZCL_TOOLS_LINK_JOBS", "1");
    env_default("ZCL_FUZZ_REPLAY_JOBS", "1");
    (void)setenv("ZCL_LINT_PRODUCTION_SCAN", "1", 1);
    (void)setenv("ZCL_LINT_BIN_DIR", bin_dir, 1);
}

/* Generate the capability inventory once before concurrent readers. */
static int pregen_inventory(const char *tool, char *const *gates, int n)
{
    char cmd[LR_PATH + 64], err[LR_ERR];
    struct lr_plan plan;
    if (!wants(gates, n, "check-capability-inventory-generated")
        && !wants(gates, n, "check-kpi-floor")
        && !wants(gates, n, "check-generated-artifact-contradictions"))
        return 0;
    (void)fputs("z23-lint run: generating build/gen/CAPABILITY_INVENTORY.jsonl before the gate pool\n", stderr);
    if (tool && *tool) {
        (void)lr_mkdir_p("build/gen");
        (void)snprintf(cmd, sizeof cmd, "\"%s\" build/gen/CAPABILITY_INVENTORY.jsonl .", tool);
    } else {
        (void)snprintf(cmd, sizeof cmd, "make -s --no-print-directory docs-capability-inventory");
    }
    if (lr_parse_command(cmd, NULL, &plan, err, sizeof err) != 0)
        return 1;
    (void)fflush(NULL);
    int saved = dup(STDOUT_FILENO);
    (void)dup2(STDERR_FILENO, STDOUT_FILENO);
    int rc = lr_run_plan(&plan);
    (void)dup2(saved, STDOUT_FILENO);
    (void)close(saved);
    return rc;
}

/* Table gates absent from this run are named (non-fatal), as run_lint.sh does. */
static void note_unrequested(char *const *gates, int n)
{
    for (int i = 0; i < g_table.n; i++) {
        if (!wants(gates, n, g_table.rows[i].name))
            (void)fprintf(stderr, "z23-lint run: note \xe2\x80\x94 table gate '%s' not in "
                          "this run's gate list\n", g_table.rows[i].name);
    }
}

static int name_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int list_gates(void)
{
    const char *names[LR_TABLE_ROWS];
    for (int i = 0; i < g_table.n; i++)
        names[i] = g_table.rows[i].name;
    qsort(names, (size_t)g_table.n, sizeof names[0], name_cmp);
    for (int i = 0; i < g_table.n; i++)
        puts(names[i]);
    return 0;
}

static int print_command(const char *gate)
{
    char cmd[LR_CMD];
    if (resolve_default(&g_table, gate, cmd, sizeof cmd) != 0)
        return 1;
    puts(cmd);
    return 0;
}

static int usage(int rc)
{
    (void)fputs("usage: z23-lint run [--jobs N] [--bin-dir DIR] [--list] "
                "[--print-command GATE] GATE...\n", rc ? stderr : stdout);
    return rc;
}

struct run_args {
    int jobs;
    const char *bin_dir;
    char *gates[LR_MAX_GATES];
    int n;
    int mode;               /* 0 run, 1 list, 2 print-command, 3 help */
    const char *print_gate;
};

static const char k_nomatch[] = "";

/* Value of `--opt V` or `--opt=V` at argv[*i]; NULL when missing. */
static const char *opt_value(int argc, char **argv, int *i, const char *opt)
{
    size_t n = strlen(opt);
    if (strcmp(argv[*i], opt) == 0)
        return *i + 1 < argc ? argv[++*i] : NULL;
    if (strncmp(argv[*i], opt, n) == 0 && argv[*i][n] == '=')
        return argv[*i] + n + 1;
    return k_nomatch;
}

static int parse_jobs(struct run_args *a, const char *v)
{
    if (!v || !all_digits(v) || strlen(v) > 6 || atoi(v) < 1) {
        (void)fprintf(stderr, "z23-lint run: --jobs must be a positive integer (got '%s')\n",
                      v ? v : "");
        return 2;
    }
    a->jobs = clamp(atoi(v), 1, LR_MAX_JOBS);
    return 0;
}

static int parse_one(struct run_args *a, int argc, char **argv, int *i)
{
    const char *v;
    if ((v = opt_value(argc, argv, i, "--jobs")) != k_nomatch)
        return parse_jobs(a, v);
    if ((v = opt_value(argc, argv, i, "--bin-dir")) != k_nomatch) {
        a->bin_dir = v;
        return v ? 0 : 2;
    }
    if (strcmp(argv[*i], "--list") == 0)
        a->mode = 1;
    else if (strcmp(argv[*i], "--help") == 0 || strcmp(argv[*i], "-h") == 0)
        a->mode = 3;
    else if (strcmp(argv[*i], "--print-command") == 0 && *i + 1 < argc) {
        a->print_gate = argv[++*i];
        a->mode = 2;
    } else if (strncmp(argv[*i], "check-", 6) == 0 && a->n < LR_MAX_GATES)
        a->gates[a->n++] = argv[*i];
    else {
        (void)fprintf(stderr, "z23-lint run: unknown argument '%s'\n", argv[*i]);
        return 2;
    }
    return 0;
}

static int parse_args(struct run_args *a, int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        int rc = parse_one(a, argc, argv, &i);
        if (rc != 0)
            return rc;
    }
    return 0;
}

static int start_run(const struct run_args *a)
{
    char state[PATH_MAX + 32], lint_bin[LR_PATH], cwd[PATH_MAX];
    const char *dir = getenv("ZCL_LINT_TIMING_DIR");
    struct lr_opts o;
    const char *inv = getenv("ZCL_LINT_INVENTORY_TOOL");
    char inv_copy[LR_PATH] = "";
    if (!getcwd(cwd, sizeof cwd))
        return 2;
    if (inv)
        (void)snprintf(inv_copy, sizeof inv_copy, "%s", inv);
    (void)unsetenv("ZCL_LINT_INVENTORY_TOOL");
    (void)snprintf(state, sizeof state, "%s", dir && *dir ? dir : "");
    if (!*state)
        (void)snprintf(state, sizeof state, "%s/.cache/lint-timing", cwd);
    (void)snprintf(lint_bin, sizeof lint_bin, "%s/z23-lint", a->bin_dir);
    o = (struct lr_opts){ a->jobs, state, lint_bin, a->bin_dir,
                          env_int("ZCL_LINT_BUDGET_SEC", DEFAULT_BUDGET),
                          getenv("ZCL_LINT_VERBOSE") && !strcmp(getenv("ZCL_LINT_VERBOSE"), "1"),
                          stdout, stderr, resolve_default, &g_table,
                          k_serial_pro, k_serial_epi, k_poles };
    setup_env(a->gates, a->n, a->bin_dir);
    note_unrequested(a->gates, a->n);
    if (pregen_inventory(inv_copy, a->gates, a->n) != 0)
        return 1;
    return lr_execute(&o, a->gates, a->n);
}

int lint_run_main(int argc, char **argv)
{
    struct run_args a = { env_int("ZCL_LINT_JOBS", DEFAULT_JOBS), "build/bin", { 0 }, 0, 0, NULL };
    int rc = parse_args(&a, argc, argv);
    if (rc != 0)
        return rc;
    a.jobs = clamp(a.jobs, 1, LR_MAX_JOBS);
    if (a.mode == 3)
        return usage(0);
    if (lr_table_load(&g_table, "tools/lint/run_lint.sh") != 0) {
        (void)fputs("z23-lint run: cannot read the gate table tools/lint/run_lint.sh "
                    "(run from the repository root)\n", stderr);
        return 2;
    }
    if (a.mode == 1)
        return list_gates();
    if (a.mode == 2)
        return print_command(a.print_gate);
    if (a.n == 0) {
        (void)fputs("z23-lint run: no gates given\n", stderr);
        return 2;
    }
    return start_run(&a);
}
