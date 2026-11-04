/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the schedule of `z23-lint run`. Resolve every requested gate
 * (a gate with no command is a loud exit 2, never a silent skip), run the
 * serial-prologue gates one by one, then the parallel pool with the
 * long-pole gates first, then the serial-epilogue gates, and report. The
 * ordering changes no gate's command or verdict, only which one waits.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "run_priv.h"

static struct lr_run g_run;     /* ~1 MB of gate commands: not for the stack */

/* True when " NAME " occurs in the space-separated LIST. */
static bool in_list(const char *list, const char *name)
{
    char key[LR_NAME + 2];
    if (!list)
        return false;
    (void)snprintf(key, sizeof key, " %s ", name);
    return strstr(list, key) != NULL;
}

static int resolve_all(struct lr_run *r, char *const *gates)
{
    const struct lr_opts *o = r->o;
    int missing = 0;
    for (int i = 0; i < r->n; i++) {
        struct lr_gate *g = &r->g[i];
        (void)snprintf(g->name, sizeof g->name, "%s", gates[i]);
        if (o->resolve(o->rctx, g->name, g->cmd, sizeof g->cmd) != 0) {
            (void)fprintf(o->err, "z23-lint run: FATAL \xe2\x80\x94 gate '%s' has no "
                          "invocation-table entry.\n  Add its exact recipe command as "
                          "a LINT_ROW in tools/lint/lintc/gate_commands.def\n", g->name);
            missing = 1;
        }
    }
    return missing;
}

/* Every long-pole name must resolve, or the ordering would silently stop
 * ordering anything. */
static int check_poles(const struct lr_opts *o)
{
    char buf[LR_PATH], cmd[LR_CMD], *save = NULL;
    (void)snprintf(buf, sizeof buf, "%s", o->poles ? o->poles : "");
    for (char *t = strtok_r(buf, " \t\n", &save); t; t = strtok_r(NULL, " \t\n", &save)) {
        if (o->resolve(o->rctx, t, cmd, sizeof cmd) != 0) {
            (void)fprintf(o->err, "z23-lint run: FATAL \xe2\x80\x94 long-pole list names '%s', "
                          "which has no command\n", t);
            return 1;
        }
    }
    return 0;
}

/* Parallel gates in dispatch order: poles in pole order, then the rest. */
static int order_parallel(const struct lr_run *r, const int *par, int npar, int *out)
{
    char buf[LR_PATH], *save = NULL;
    int n = 0;
    (void)snprintf(buf, sizeof buf, "%s", r->o->poles ? r->o->poles : "");
    for (char *t = strtok_r(buf, " \t\n", &save); t; t = strtok_r(NULL, " \t\n", &save)) {
        for (int k = 0; k < npar; k++) {
            if (strcmp(r->g[par[k]].name, t) == 0)
                out[n++] = par[k];
        }
    }
    for (int k = 0; k < npar; k++) {
        if (!in_list(r->o->poles, r->g[par[k]].name))
            out[n++] = par[k];
    }
    return n;
}

struct lr_lanes {
    int pro[LR_MAX_GATES], npro;
    int par[LR_MAX_GATES], npar;
    int epi[LR_MAX_GATES], nepi;
    int ord[LR_MAX_GATES];
};

static void classify(const struct lr_run *r, struct lr_lanes *ln)
{
    for (int i = 0; i < r->n; i++) {
        const char *name = r->g[i].name;
        if (in_list(r->o->serial_pro, name))
            ln->pro[ln->npro++] = i;
        else if (in_list(r->o->serial_epi, name))
            ln->epi[ln->nepi++] = i;
        else
            ln->par[ln->npar++] = i;
    }
}

static int run_lanes(struct lr_run *r, struct lr_lanes *ln)
{
    int nord = order_parallel(r, ln->par, ln->npar, ln->ord);
    if (nord != ln->npar) {
        (void)fprintf(r->o->err, "z23-lint run: FATAL \xe2\x80\x94 long-pole ordering produced "
                      "%d gates from %d\n", nord, ln->npar);
        return 2;
    }
    if (lr_pool(r, ln->pro, ln->npro, 1) != 0
        || lr_pool(r, ln->ord, nord, r->o->jobs) != 0
        || lr_pool(r, ln->epi, ln->nepi, 1) != 0)
        return 1;
    return 0;
}

int lr_execute(const struct lr_opts *o, char *const *gates, int n)
{
    struct lr_run *r = &g_run;
    static struct lr_lanes ln;
    long long start;
    int rc;
    if (n < 1 || n > LR_MAX_GATES)
        return 2;
    memset(r, 0, sizeof *r);
    memset(&ln, 0, sizeof ln);
    r->o = o;
    r->n = n;
    if (resolve_all(r, gates) != 0 || check_poles(o) != 0 || lr_make_dirs(r) != 0)
        return 2;
    (void)setenv("ZCL_LINT_GATES_DIR_X", r->gates_dir, 1);
    classify(r, &ln);
    start = lr_now_ms();
    rc = run_lanes(r, &ln);
    if (rc == 2)
        return 2;
    return lr_report(r, lr_now_ms() - start) | rc;
}
