/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for `z23-lint run`, the C23 lint driver
 * (run_main.c, run_table.c, run_cmd.c, run_exec.c, run_pool.c, run_report.c).
 */
#ifndef LINTC_RUN_PRIV_H
#define LINTC_RUN_PRIV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

enum {
    LR_MAX_STEPS = 16, LR_MAX_ARGV = 64, LR_MAX_ENV = 8, LR_POOL = 8192,
    LR_CMD = 2048, LR_MAX_GATES = 512, LR_NAME = 96, LR_PATH = 1024,
    LR_ERR = 160, LR_MAX_JOBS = 32, LR_TABLE_ROWS = 256,
};

/* The table command that is not an argv: the core-seal pipeline. */
#define LR_CORE_SEAL "__core_seal__"

/* One simple command: leading NAME=value words, then argv. */
struct lr_step {
    char *argv[LR_MAX_ARGV + 1];
    int argc;
    char *env[LR_MAX_ENV];
    int nenv;
};

/* A gate command parsed without a shell: steps joined by `&&`. */
struct lr_plan {
    struct lr_step steps[LR_MAX_STEPS];
    int nsteps;
    char pool[LR_POOL];
    size_t used;
};

/* Parse CMD into PLAN (quotes, $VAR/${VAR}, NAME=v prefixes, `&&`). A
 * tools/scripts/check_*.sh wrapper that only execs z23-lint becomes a direct
 * LINT_BIN <gate> step. Anything else a shell would interpret (| ; < > ( ) `
 * $( ) is refused. 0 ok; 1 with ERR set. */
int lr_parse_command(const char *cmd, const char *lint_bin,
                     struct lr_plan *plan, char *err, size_t errcap);

/* Run PLAN's steps in order, stopping at the first non-zero. A step killed by
 * signal N is 128+N, a failed exec 127. Returns the last step's status. */
int lr_run_plan(const struct lr_plan *plan);

/* The check-core-seal pipeline (git ls-files | core_seal check MANIFEST). */
int lr_core_seal(const char *bin_dir);

struct lr_table_row {
    char name[LR_NAME];
    char cmd[LR_CMD];
};

struct lr_table {
    struct lr_table_row rows[LR_TABLE_ROWS];
    int n;
};

/* Fill T from the compiled gate_commands.def rows (first row per name wins). */
int lr_table_load(struct lr_table *t);
const struct lr_table_row *lr_table_find(const struct lr_table *t,
                                         const char *gate);

/* Resolve GATE to its command text; 0 ok, non-zero no entry. */
typedef int (*lr_resolve_fn)(void *ctx, const char *gate, char *cmd, size_t cap);

struct lr_opts {
    int jobs;
    const char *state_dir;    /* artifact dir (.cache/lint-timing) */
    const char *lint_bin;     /* wrapper rewrite target, NULL = none */
    const char *bin_dir;      /* for the core-seal pipeline */
    int budget_sec;
    bool verbose;
    FILE *out;                /* PASS/FAIL lines and the timing table */
    FILE *err;                /* failure summary and FAIL logs */
    lr_resolve_fn resolve;
    void *rctx;
    const char *serial_pro;   /* " name name " lists */
    const char *serial_epi;
    const char *poles;
};

struct lr_gate {
    char name[LR_NAME];
    char cmd[LR_CMD];
    long long ms;
    int rc;
    bool have_rc;
    pid_t pid;
    long long t0;
};

struct lr_run {
    const struct lr_opts *o;
    struct lr_gate g[LR_MAX_GATES];
    int n;
    char gates_dir[LR_PATH];
};

/* Run every gate (parallel pool between the serial lists); print the
 * verdict lines, timing table and failure logs. 0 all passed, 1 any
 * failed, 2 driver misuse. */
int lr_execute(const struct lr_opts *o, char *const *gates, int n);

long long lr_now_ms(void);
/* Pool and worker (run_pool.c). */
int lr_pool(struct lr_run *r, const int *order, int cnt, int jobs);
/* Reporting (run_report.c). */
int lr_report(struct lr_run *r, long long wall_ms);
/* Artifact dirs (run_report.c). */
int lr_make_dirs(struct lr_run *r);
void lr_prune_old_runs(const char *state_dir);
int lr_mkdir_p(const char *path);

#endif
