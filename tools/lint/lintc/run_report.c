/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the artifacts and report of `z23-lint run`: the per-run gates dir,
 * old-run pruning, the lint timing table, the zcl.lint_timing.v1 last-run.json
 * and the failure summary with each failed gate's log, in the formats
 * run_lint.sh prints (the land queue and fleet readers parse them).
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "run_priv.h"

enum { PRUNE_AGE_S = 120 * 60 };

int lr_mkdir_p(const char *path)
{
    char buf[LR_PATH];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof buf)
        return 1;
    memcpy(buf, path, n + 1);
    for (size_t i = 1; i < n; i++) {
        if (buf[i] != '/')
            continue;
        buf[i] = '\0';
        if (mkdir(buf, 0755) != 0 && errno != EEXIST)
            return 1;
        buf[i] = '/';
    }
    return (mkdir(buf, 0755) != 0 && errno != EEXIST) ? 1 : 0;
}

static int rm_cb(const char *p, const struct stat *sb, int flag, struct FTW *w)
{
    (void)sb;
    (void)flag;
    (void)w;
    (void)remove(p);
    return 0;
}

static void rm_rf(const char *path)
{
    (void)nftw(path, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
}

/* Old run dirs go by age, never "everything that is here": a live run's dir
 * must survive another run starting. */
void lr_prune_old_runs(const char *state_dir)
{
    char dir[LR_PATH], path[LR_PATH + 300];
    struct dirent *e;
    struct stat st;
    (void)snprintf(dir, sizeof dir, "%s/gates", state_dir);
    DIR *d = opendir(dir);
    if (!d)
        return;
    time_t now = time(NULL); // platform-ok: z23-lint links no platform library; artifact age only
    while ((e = readdir(d)) != NULL) {
        (void)snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        if (strncmp(e->d_name, "run.", 4) == 0 && lstat(path, &st) == 0
            && S_ISDIR(st.st_mode) && now - st.st_mtime > PRUNE_AGE_S)
            rm_rf(path);
    }
    (void)closedir(d);
}

int lr_make_dirs(struct lr_run *r)
{
    char list[LR_PATH + 32];
    (void)snprintf(r->gates_dir, sizeof r->gates_dir, "%s/gates/run.%ld",
                   r->o->state_dir, (long)getpid());
    rm_rf(r->gates_dir);
    if (lr_mkdir_p(r->gates_dir) != 0)
        return 1;
    (void)snprintf(list, sizeof list, "%s/requested.list", r->gates_dir);
    FILE *f = fopen(list, "w");
    if (!f)
        return 1;
    for (int i = 0; i < r->n; i++)
        (void)fprintf(f, "%s\n", r->g[i].name);
    (void)fclose(f);
    lr_prune_old_runs(r->o->state_dir);
    return 0;
}

/* ---- report ------------------------------------------------------------ */

/* Slowest first; equal times name-descending, as `sort -nr` orders them. */
static int rank_cmp(const void *pa, const void *pb)
{
    const struct lr_gate *a = *(const struct lr_gate *const *)pa;
    const struct lr_gate *b = *(const struct lr_gate *const *)pb;
    if (a->ms != b->ms)
        return a->ms < b->ms ? 1 : -1;
    return strcmp(b->name, a->name);
}

static int rank_gates(struct lr_run *r, const struct lr_gate **rank)
{
    int n = 0;
    for (int i = 0; i < r->n; i++) {
        if (r->g[i].have_rc)
            rank[n++] = &r->g[i];
    }
    qsort(rank, (size_t)n, sizeof *rank, rank_cmp);
    return n;
}

static void print_timing(const struct lr_run *r, const struct lr_gate **rank,
                         int nrank, long long wall_ms)
{
    int show = r->o->verbose ? r->n : 10;
    FILE *o = r->o->out;
    (void)fprintf(o, "\xe2\x94\x80\xe2\x94\x80 lint timing: %d gates, wall %lld ms, jobs %d \xe2\x94\x80\xe2\x94\x80\n",
                  r->n, wall_ms, r->o->jobs);
    for (int i = 0; i < nrank && i < show; i++)
        (void)fprintf(o, "  %7lld ms  %s\n", rank[i]->ms, rank[i]->name);
    if (show < r->n)
        (void)fprintf(o, "  \xe2\x80\xa6 (ZCL_LINT_VERBOSE=1 for the full table)\n");
    (void)fflush(o);
}

static void write_json_gates(FILE *f, const struct lr_run *r,
                             const struct lr_gate **rank, int nrank)
{
    (void)r;
    for (int i = 0; i < nrank; i++)
        (void)fprintf(f, "%s    {\"name\":\"%s\",\"ms\":%lld,\"rc\":%d}",
                      i ? ",\n" : "", rank[i]->name, rank[i]->ms, rank[i]->rc);
}

static void write_last_run(const struct lr_run *r, const struct lr_gate **rank,
                           int nrank, long long wall_ms, int failed)
{
    char tmp[LR_PATH], fin[LR_PATH], stamp[40];
    time_t now = time(NULL); // platform-ok: z23-lint links no platform library; generated_at_utc field only
    struct tm tm;
    (void)gmtime_r(&now, &tm);
    (void)strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%SZ", &tm);
    (void)snprintf(tmp, sizeof tmp, "%s/last-run.json.%ld.tmp", r->o->state_dir, (long)getpid());
    (void)snprintf(fin, sizeof fin, "%s/last-run.json", r->o->state_dir);
    FILE *f = fopen(tmp, "w");
    if (!f)
        return;
    (void)fprintf(f, "{\n  \"schema\":\"zcl.lint_timing.v1\",\n  \"generated_at_utc\":\"%s\",\n"
                     "  \"wall_ms\":%lld,\n  \"jobs\":%d,\n  \"budget_sec\":%d,\n"
                     "  \"gate_count\":%d,\n  \"failed_count\":%d,\n  \"gates\":[\n",
                  stamp, wall_ms, r->o->jobs, r->o->budget_sec, r->n, failed);
    write_json_gates(f, r, rank, nrank);
    (void)fprintf(f, "\n  ]\n}\n");
    if (fclose(f) == 0)
        (void)rename(tmp, fin);
}

static void cat_log(const struct lr_run *r, const struct lr_gate *g, long *bytes)
{
    char path[LR_PATH + LR_NAME + 16], buf[4096];
    size_t n;
    FILE *f;
    *bytes = 0;
    (void)snprintf(path, sizeof path, "%s/%s.log", r->gates_dir, g->name);
    f = fopen(path, "r");
    if (!f)
        return;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        (void)fwrite(buf, 1, n, r->o->err);
        *bytes += (long)n;
    }
    (void)fclose(f);
}

static void silent_failure(FILE *e, const struct lr_gate *g)
{
    (void)fprintf(e, "  (this gate produced NO output at all)\n\n"
        "  The gate exited %d without printing a diagnosis, so the\n"
        "  failure is real but self-reported nothing. That is a defect in\n"
        "  the gate, on top of whatever it was failing on: a gate must say\n"
        "  why it refused. Most often it is a script under 'set -e' whose\n"
        "  checks are bare boolean assertions, dying on a missing build\n"
        "  artifact, tool, or fixture before it prints anything.\n\n"
        "  Reproduce it directly (this driver captured nothing more):\n"
        "      %s\n  and to see the exact assertion that failed:\n"
        "      bash -x -c '%s'\n", g->rc, g->cmd, g->cmd);
}

/* N box-drawing horizontal rules (U+2500). */
static void put_rule(FILE *f, int n)
{
    for (int i = 0; i < n; i++)
        (void)fputs("\xe2\x94\x80", f);
}

static void print_fail_log(const struct lr_run *r, const struct lr_gate *g)
{
    long bytes;
    (void)fputs("\n", r->o->err);
    put_rule(r->o->err, 4);
    (void)fprintf(r->o->err, " FAIL log: %s ", g->name);
    put_rule(r->o->err, 28);
    (void)fputs("\n", r->o->err);
    cat_log(r, g, &bytes);
    if (bytes == 0)
        silent_failure(r->o->err, g);
}

static bool gate_failed(const struct lr_gate *g)
{
    return !g->have_rc || g->rc != 0;
}

static void print_failures(const struct lr_run *r, int failed)
{
    FILE *e = r->o->err;
    (void)fprintf(e, "\n\xe2\x95\x90\xe2\x95\x90 LINT: %d of %d gates FAILED \xe2\x95\x90\xe2\x95\x90\n",
                  failed, r->n);
    for (int i = 0; i < r->n; i++) {
        if (gate_failed(&r->g[i]))
            (void)fprintf(e, "  \xe2\x9c\x97 %s%s\n", r->g[i].name,
                          r->g[i].have_rc ? "" : " (worker crash \xe2\x80\x94 no rc artifact)");
    }
    for (int i = 0; i < r->n; i++) {
        if (gate_failed(&r->g[i]))
            print_fail_log(r, &r->g[i]);
    }
    (void)fflush(e);
}

int lr_report(struct lr_run *r, long long wall_ms)
{
    const struct lr_gate *rank[LR_MAX_GATES];
    int failed = 0;
    for (int i = 0; i < r->n; i++)
        failed += gate_failed(&r->g[i]) ? 1 : 0;
    int nrank = rank_gates(r, rank);
    print_timing(r, rank, nrank, wall_ms);
    write_last_run(r, rank, nrank, wall_ms, failed);
    if (wall_ms > (long long)r->o->budget_sec * 1000)
        (void)fprintf(r->o->err, "z23-lint run: NOTE \xe2\x80\x94 wall %lld ms exceeds the %ds soft "
                      "budget (ZCL_LINT_BUDGET_SEC; see the budget comment above the lint target)\n",
                      wall_ms, r->o->budget_sec);
    if (failed > 0)
        print_failures(r, failed);
    return failed > 0 ? 1 : 0;
}
