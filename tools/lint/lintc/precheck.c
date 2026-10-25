/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: `z23-lint precheck` — which lint gates does this tree newly break?
 * Each selected gate runs here (the cwd) and in --base=DIR, every run in a
 * forked child whose stdout and stderr go to /dev/null. One line per gate
 * that passes in DIR and fails here: `NEW <gate> rc=<n>`.
 *
 *   z23-lint precheck --base=DIR [--jobs=N] [--gates=a,b]
 *
 * At most N children run at once (default 8, accepted 1..32). A child killed
 * by a signal counts as rc=124. Exit 0 = no new failure, 1 = new failure(s),
 * 2 = usage or setup error.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "lintc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

enum { PC_MAX_GATES = 512, PC_MAX_JOBS = 32, PC_DEFAULT_JOBS = 8,
       PC_TIMEOUT_S = 180, PC_LIST = 4096, PC_RC_SIGNAL = 124,
       PC_RC_SETUP = 125 };

struct pc_opts {
    const char *base;
    int jobs;
    bool have_list;
    char list[PC_LIST];
    size_t n_sel;
    size_t sel[PC_MAX_GATES];
};

struct pc_slot {
    pid_t pid;
    size_t item;
};

static const char k_pc_usage[] =
    "z23-lint: usage: z23-lint precheck --base=DIR [--jobs=N] [--gates=a,b]\n";

static bool pc_parse_jobs(const char *s, int *out)
{
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 1 || v > PC_MAX_JOBS)
        return false;
    *out = (int)v;
    return true;
}

static int pc_parse_arg(struct pc_opts *o, const char *arg)
{
    if (strncmp(arg, "--base=", 7) == 0 && arg[7] != '\0') {
        o->base = arg + 7;
        return 0;
    }
    if (strncmp(arg, "--jobs=", 7) == 0 && pc_parse_jobs(arg + 7, &o->jobs))
        return 0;
    if (strncmp(arg, "--gates=", 8) == 0 && arg[8] != '\0') {
        if (strlen(arg + 8) >= sizeof o->list)
            return 2;
        (void)snprintf(o->list, sizeof o->list, "%s", arg + 8);
        o->have_list = true;
        return 0;
    }
    return 2;
}

static int pc_parse(struct pc_opts *o, int argc, char **argv)
{
    o->jobs = PC_DEFAULT_JOBS;
    for (int i = 0; i < argc; i++) {
        if (pc_parse_arg(o, argv[i]) != 0)
            return 2;
    }
    return o->base ? 0 : 2;
}

static int pc_select_one(struct pc_opts *o, const struct lint_gate *tab,
                         size_t n, const char *name)
{
    for (size_t i = 0; i < n; i++) {
        if (strcmp(tab[i].name, name) != 0)
            continue;
        if (o->n_sel >= PC_MAX_GATES)
            return 2;
        o->sel[o->n_sel++] = i;
        return 0;
    }
    fprintf(stderr, "precheck: unknown gate %s\n", name);
    return 2;
}

/* The gates to run: the --gates subset in the order given, else the table. */
static int pc_select(struct pc_opts *o, const struct lint_gate *tab, size_t n)
{
    if (!o->have_list) {
        if (n > PC_MAX_GATES)
            return 2;
        for (size_t i = 0; i < n; i++)
            o->sel[o->n_sel++] = i;
        return 0;
    }
    char *save = NULL;
    for (char *tok = strtok_r(o->list, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        if (pc_select_one(o, tab, n, tok) != 0)
            return 2;
    }
    return o->n_sel > 0 ? 0 : 2;
}

[[noreturn]] static void pc_child(const struct lint_gate *g, const char *dir)
{
    char *av[2] = { (char *)g->name, NULL };
    int fd = open("/dev/null", O_RDWR);
    if (fd < 0 || chdir(dir) != 0 || dup2(fd, STDOUT_FILENO) < 0
        || dup2(fd, STDERR_FILENO) < 0)
        _exit(PC_RC_SETUP);
    (void)alarm(PC_TIMEOUT_S);
    _exit(g->run(1, av) & 0xff);
}

static int pc_spawn(const struct lint_gate *g, const char *dir, pid_t *pid)
{
    fflush(NULL);
    *pid = fork();
    if (*pid < 0)
        return -1;
    if (*pid == 0)
        pc_child(g, dir);
    return 0;
}

/* Start work item *next: even items run the gate here, odd items in base. */
static int pc_start_next(const struct lint_gate *tab, const struct pc_opts *o,
                         struct pc_slot *slots, size_t *live, size_t *next)
{
    const struct lint_gate *g = &tab[o->sel[*next / 2]];
    const char *dir = (*next % 2 == 0) ? "." : o->base;
    if (pc_spawn(g, dir, &slots[*live].pid) != 0)
        return -1;
    slots[*live].item = *next;
    (*live)++;
    (*next)++;
    return 0;
}

static int pc_status_rc(int st)
{
    if (WIFSIGNALED(st))
        return PC_RC_SIGNAL;
    return WIFEXITED(st) ? WEXITSTATUS(st) : PC_RC_SIGNAL;
}

/* Reap one child and record its rc under its work item. */
static int pc_reap(struct pc_slot *slots, size_t *live, int *rc)
{
    int st = 0;
    pid_t done;
    do
        done = waitpid(-1, &st, 0);
    while (done < 0 && errno == EINTR);
    if (done < 0)
        return -1;
    for (size_t i = 0; i < *live; i++) {
        if (slots[i].pid != done)
            continue;
        rc[slots[i].item] = pc_status_rc(st);
        slots[i] = slots[--*live];
        return 0;
    }
    return -1;
}

/* Runs every work item with at most o->jobs children live. rc[2k] is gate k
 * here and rc[2k+1] is gate k in base. A spawn failure stops new work and
 * drains the children already running before the error is returned. */
static int pc_run_all(const struct lint_gate *tab, const struct pc_opts *o,
                      int *rc)
{
    struct pc_slot slots[PC_MAX_JOBS];
    size_t live = 0, next = 0, total = 2 * o->n_sel;
    bool err = false;
    while (next < total || live > 0) {
        while (!err && next < total && live < (size_t)o->jobs) {
            if (pc_start_next(tab, o, slots, &live, &next) != 0) {
                err = true;
                next = total;
            }
        }
        if (live > 0 && pc_reap(slots, &live, rc) != 0)
            return -1;
    }
    return err ? -1 : 0;
}

static int pc_report(const struct lint_gate *tab, const struct pc_opts *o,
                     const int *rc)
{
    size_t fails = 0;
    for (size_t k = 0; k < o->n_sel; k++) {
        if (rc[2 * k + 1] != 0 || rc[2 * k] == 0)
            continue;
        printf("NEW %s rc=%d\n", tab[o->sel[k]].name, rc[2 * k]);
        fails++;
    }
    printf("precheck: %zu new failure(s) of %zu gates\n", fails, o->n_sel);
    return fails > 0 ? 1 : 0;
}

int lint_precheck_main(int argc, char **argv)
{
    struct pc_opts o;
    size_t n = 0;
    memset(&o, 0, sizeof o);
    const struct lint_gate *tab = lint_gate_table(&n);
    if (pc_parse(&o, argc, argv) != 0 || pc_select(&o, tab, n) != 0) {
        fputs(k_pc_usage, stderr);
        return 2;
    }
    int rc[2 * PC_MAX_GATES];
    if (pc_run_all(tab, &o, rc) != 0) {
        fputs("precheck: a gate child could not be started or reaped\n",
              stderr);
        return 2;
    }
    return pc_report(tab, &o, rc);
}
