/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: `z23-lint precheck` — which lint gates does this tree newly break?
 * Each selected gate runs here (the cwd) and in --base=DIR, every run in a
 * forked child. The run here keeps its output in a temp file so the first
 * non-empty line (at most 200 bytes) can be reported; the base run's output
 * goes to /dev/null. One line per gate that passes in DIR and fails here:
 * `NEW <gate> rc=<n>`.
 *
 *   z23-lint precheck [--base=DIR] [--jobs=N] [--gates=a,b] [--skip=a,b]
 *                     [--json]
 *
 * A gate that passes in DIR and fails here, but whose output contains
 * "cannot execute a child", "missing executable" or "is not built" needs a
 * build this tree lacks: it is UNBUILT (line `UNBUILT <gate>`), not NEW, and
 * does not fail the run. --skip=a,b leaves those gates out (neither tree runs
 * them; they are not counted in the summary); a name outside the gate table is
 * a usage error. --json replaces the text with one object per gate
 *   {"gate","lane_rc","base_rc","verdict","first_line"}
 * (verdict NEW|PREEXISTING|FIXED|UNBUILT|SKIPPED|PASS; an rc of -1 means the
 * gate did not run) and a final {"summary":{"gates","new","unbuilt",
 * "skipped"}} object. The default text output is `NEW`/`UNBUILT` lines and
 * `precheck: N new failure(s) of M gates`.
 *
 * Without --base, the base is a shared detached worktree at
 * merge-base(HEAD, origin/main) of the current tree, kept under
 * $ZCL_PRECHECK_CACHE (default $HOME/.cache/development-scratch/z23/precheck)
 * and serialized by a flock (precheck_base.c). Its gate results are cached by
 * sha in base-native-<sha>.txt, so a later call does not rerun them. A missing
 * origin/main or a git failure exits 2. An explicit --base=DIR runs and
 * caches nothing extra: the base is simply DIR.
 *
 * At most N children run at once (default 8, accepted 1..32). A child killed
 * by a signal counts as rc=124. Exit 0 = no new failure, 1 = new failure(s),
 * 2 = usage or setup error.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "lintc.h"
#include "precheck_base.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

enum { PC_MAX_GATES = 512, PC_MAX_JOBS = 32, PC_DEFAULT_JOBS = 8,
       PC_TIMEOUT_S = 180, PC_LIST = 4096, PC_RC_SIGNAL = 124,
       PC_RC_SETUP = 125, PC_LINE = 201, PC_READ_CAP = 65536 };

struct pc_opts {
    const char *base;
    int jobs;
    bool json;
    bool have_list;
    bool have_skip;
    char list[PC_LIST];
    char skip_list[PC_LIST];
    size_t n_sel;
    size_t sel[PC_MAX_GATES];
    bool skipped[PC_MAX_GATES];   /* by selected index */
};

struct pc_slot {
    pid_t pid;
    size_t item;
    FILE *cap;                    /* the lane run's output, else NULL */
};

/* What the lane runs printed: the first non-empty line, and whether any line
 * says the tree lacks a build the gate needs. */
struct pc_cap {
    char line[PC_MAX_GATES][PC_LINE];
    bool unbuilt[PC_MAX_GATES];
};

enum pc_verdict { PCV_PASS, PCV_NEW, PCV_PREEXISTING, PCV_FIXED, PCV_UNBUILT,
                  PCV_SKIPPED };

static const char *const k_pc_verdict[] = {
    "PASS", "NEW", "PREEXISTING", "FIXED", "UNBUILT", "SKIPPED"
};

static const char *const k_pc_unbuilt[] = {
    "cannot execute a child", "missing executable", "is not built"
};

static const char k_pc_usage[] =
    "z23-lint: usage: z23-lint precheck [--base=DIR] [--jobs=N] "
    "[--gates=a,b] [--skip=a,b] [--json]\n";

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

/* Copies a non-empty comma list into dst (PC_LIST bytes). */
static bool pc_parse_list(char *dst, const char *src)
{
    if (src[0] == '\0' || strlen(src) >= PC_LIST)
        return false;
    (void)snprintf(dst, PC_LIST, "%s", src);
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
    if (strncmp(arg, "--gates=", 8) == 0 && pc_parse_list(o->list, arg + 8)) {
        o->have_list = true;
        return 0;
    }
    if (strncmp(arg, "--skip=", 7) == 0 && pc_parse_list(o->skip_list, arg + 7)) {
        o->have_skip = true;
        return 0;
    }
    if (strcmp(arg, "--json") == 0) {
        o->json = true;
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
    return 0;
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

/* Marks each --skip gate in o->skipped; a name outside the table is an error. */
static int pc_mark_skips(struct pc_opts *o, const struct lint_gate *tab,
                         size_t n)
{
    char *save = NULL;
    if (!o->have_skip)
        return 0;
    for (char *tok = strtok_r(o->skip_list, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        size_t i = 0;
        while (i < n && strcmp(tab[i].name, tok) != 0)
            i++;
        if (i == n) {
            fprintf(stderr, "precheck: unknown gate %s\n", tok);
            return 2;
        }
        for (size_t k = 0; k < o->n_sel; k++) {
            if (o->sel[k] == i)
                o->skipped[k] = true;
        }
    }
    return 0;
}

[[noreturn]] static void pc_child(const struct lint_gate *g, const char *dir,
                                  FILE *cap)
{
    /* Same argv as `z23-lint GATE`: main.c runs g->run(argc-2, argv+2), so
     * a plain invocation has argc 0 and argv[0] NULL. */
    char *av[2] = { (char *)g->name, NULL };
    int fd = cap ? fileno(cap) : open("/dev/null", O_RDWR);
    if (fd < 0 || chdir(dir) != 0 || dup2(fd, STDOUT_FILENO) < 0
        || dup2(fd, STDERR_FILENO) < 0)
        _exit(PC_RC_SETUP);
    /* Gates that resolve the repo through cic_repo_root would otherwise lint
     * the binary's own tree in both runs; cic_invoke children inherit this. */
    char root[PATH_MAX];
    if (!getcwd(root, sizeof root) || setenv("ZCL_LINT_REPO_ROOT", root, 1) != 0)
        _exit(PC_RC_SETUP);
    (void)alarm(PC_TIMEOUT_S);
    int rc = g->run(0, av + 1) & 0xff;
    fflush(NULL);
    _exit(rc);
}

static int pc_spawn(const struct lint_gate *g, const char *dir, FILE *cap,
                    pid_t *pid)
{
    fflush(NULL);
    *pid = fork();
    if (*pid < 0)
        return -1;
    if (*pid == 0)
        pc_child(g, dir, cap);
    return 0;
}

/* A work item that needs no child: a skipped gate, or a base rc already cached. */
static bool pc_item_idle(const struct pc_opts *o, const int *rc, size_t item)
{
    return o->skipped[item / 2] || (item % 2 == 1 && rc[item] >= 0);
}

/* Start work item *next: even items run the gate here (output kept in a temp
 * file), odd items in base (output discarded). */
static int pc_start_next(const struct lint_gate *tab, const struct pc_opts *o,
                         const int *rc, struct pc_slot *slots, size_t *live,
                         size_t *next)
{
    while (*next < 2 * o->n_sel && pc_item_idle(o, rc, *next))
        (*next)++;
    if (*next >= 2 * o->n_sel)
        return 0;
    const struct lint_gate *g = &tab[o->sel[*next / 2]];
    const char *dir = (*next % 2 == 0) ? "." : o->base;
    FILE *cap = (*next % 2 == 0) ? tmpfile() : NULL;
    if (pc_spawn(g, dir, cap, &slots[*live].pid) != 0) {
        if (cap)
            fclose(cap);
        return -1;
    }
    slots[*live].item = *next;
    slots[*live].cap = cap;
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

/* Reads a lane run's output: its first non-empty line (at most 200 bytes) into
 * c->line[k] and whether any line says the tree lacks a build. */
static void pc_read_cap(FILE *f, struct pc_cap *c, size_t k)
{
    char buf[512];
    size_t seen = 0;
    c->line[k][0] = '\0';
    if (fseek(f, 0, SEEK_SET) != 0)
        return;
    while (seen < PC_READ_CAP && fgets(buf, sizeof buf, f)) {
        seen += strlen(buf);
        for (size_t i = 0; i < sizeof k_pc_unbuilt / sizeof k_pc_unbuilt[0]; i++)
            c->unbuilt[k] = c->unbuilt[k] || strstr(buf, k_pc_unbuilt[i]);
        size_t n = strlen(buf);
        while (n > 0 && strchr(" \t\r\n", buf[n - 1]))
            buf[--n] = '\0';
        size_t lead = strspn(buf, " \t");
        if (c->line[k][0] == '\0' && buf[lead] != '\0')
            (void)snprintf(c->line[k], PC_LINE, "%s", buf + lead);
    }
}

/* Reap one child and record its rc (and, for a lane run, its output). */
static int pc_reap(struct pc_slot *slots, size_t *live, int *rc,
                   struct pc_cap *c)
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
        if (slots[i].cap) {
            pc_read_cap(slots[i].cap, c, slots[i].item / 2);
            fclose(slots[i].cap);
        }
        slots[i] = slots[--*live];
        return 0;
    }
    return -1;
}

/* Runs every work item with at most o->jobs children live. rc[2k] is gate k
 * here and rc[2k+1] is gate k in base. A spawn failure stops new work and
 * drains the children already running before the error is returned. */
static int pc_run_all(const struct lint_gate *tab, const struct pc_opts *o,
                      int *rc, struct pc_cap *c)
{
    struct pc_slot slots[PC_MAX_JOBS];
    size_t live = 0, next = 0, total = 2 * o->n_sel;
    bool err = false;
    while (next < total || live > 0) {
        while (!err && next < total && live < (size_t)o->jobs) {
            if (pc_start_next(tab, o, rc, slots, &live, &next) != 0) {
                err = true;
                next = total;
            }
        }
        if (live > 0 && pc_reap(slots, &live, rc, c) != 0)
            return -1;
    }
    return err ? -1 : 0;
}

static enum pc_verdict pc_verdict(const struct pc_opts *o, const int *rc,
                                  const struct pc_cap *c, size_t k)
{
    int lane = rc[2 * k], base = rc[2 * k + 1];
    if (o->skipped[k])
        return PCV_SKIPPED;
    if (lane == 0)
        return base == 0 ? PCV_PASS : PCV_FIXED;
    if (base != 0)
        return PCV_PREEXISTING;
    return c->unbuilt[k] ? PCV_UNBUILT : PCV_NEW;
}

static void pc_json_str(const char *s)
{
    putchar('"');
    for (; *s; s++) {
        unsigned char ch = (unsigned char)*s;
        if (ch == '"' || ch == '\\')
            printf("\\%c", ch);
        else if (ch < 0x20 || ch >= 0x7f)
            printf("\\u%04x", (unsigned)ch);
        else
            putchar(ch);
    }
    putchar('"');
}

static void pc_json_gate(const char *name, const int *rc, size_t k,
                         enum pc_verdict v, const char *line)
{
    fputs("{\"gate\":", stdout);
    pc_json_str(name);
    printf(",\"lane_rc\":%d,\"base_rc\":%d,\"verdict\":\"%s\",\"first_line\":",
           rc[2 * k], rc[2 * k + 1], k_pc_verdict[v]);
    pc_json_str(line);
    puts("}");
}

static int pc_report(const struct lint_gate *tab, const struct pc_opts *o,
                     const int *rc, const struct pc_cap *c)
{
    size_t fails = 0, unbuilt = 0, skipped = 0;
    for (size_t k = 0; k < o->n_sel; k++) {
        const char *name = tab[o->sel[k]].name;
        enum pc_verdict v = pc_verdict(o, rc, c, k);
        fails += v == PCV_NEW;
        unbuilt += v == PCV_UNBUILT;
        skipped += v == PCV_SKIPPED;
        if (o->json)
            pc_json_gate(name, rc, k, v, c->line[k]);
        else if (v == PCV_NEW)
            printf("NEW %s rc=%d\n", name, rc[2 * k]);
        else if (v == PCV_UNBUILT)
            printf("UNBUILT %s\n", name);
    }
    if (o->json)
        printf("{\"summary\":{\"gates\":%zu,\"new\":%zu,\"unbuilt\":%zu,"
               "\"skipped\":%zu}}\n", o->n_sel - skipped, fails, unbuilt, skipped);
    else
        printf("precheck: %zu new failure(s) of %zu gates\n", fails,
               o->n_sel - skipped);
    return fails > 0 ? 1 : 0;
}

/* Auto base: open the shared tree and take the cached rc of each selected
 * gate (rc[2k+1] stays -1 for a gate to run). */
static int pc_auto_open(struct pc_opts *o, const struct lint_gate *tab,
                        struct precheck_base *pb, int *rc)
{
    char why[160];
    if (precheck_base_open(pb, why, sizeof why) != 0) {
        fprintf(stderr, "precheck: %s\n", why);
        return 2;
    }
    o->base = pb->tree;
    for (size_t k = 0; k < o->n_sel; k++) {
        int cached = 0;
        if (precheck_base_lookup(pb, tab[o->sel[k]].name, &cached) == 0)
            rc[2 * k + 1] = cached;
    }
    return 0;
}

/* Cache the base rcs just measured; a signal or setup rc is not a result. */
static void pc_auto_save(const struct lint_gate *tab, const struct pc_opts *o,
                         const struct precheck_base *pb, const int *rc)
{
    const char *names[PC_MAX_GATES];
    int rcs[PC_MAX_GATES];
    size_t n = 0;
    for (size_t k = 0; k < o->n_sel; k++) {
        if (rc[2 * k + 1] < 0 || rc[2 * k + 1] >= PC_RC_SIGNAL)
            continue;
        names[n] = tab[o->sel[k]].name;
        rcs[n++] = rc[2 * k + 1];
    }
    if (precheck_base_store(pb, names, rcs, n) != 0)
        fputs("precheck: warning: could not cache the base results\n", stderr);
}

static int pc_run_report(const struct lint_gate *tab, struct pc_opts *o)
{
    struct precheck_base pb;
    int rc[2 * PC_MAX_GATES];
    struct pc_cap cap;
    bool autob = o->base == NULL;
    memset(&cap, 0, sizeof cap);
    for (size_t i = 0; i < 2 * o->n_sel; i++)
        rc[i] = -1;
    if (autob && pc_auto_open(o, tab, &pb, rc) != 0)
        return 2;
    int run = pc_run_all(tab, o, rc, &cap);
    if (autob && run == 0)
        pc_auto_save(tab, o, &pb, rc);
    if (autob)
        precheck_base_close(&pb);
    if (run != 0) {
        fputs("precheck: a gate child could not be started or reaped\n",
              stderr);
        return 2;
    }
    return pc_report(tab, o, rc, &cap);
}

int lint_precheck_main(int argc, char **argv)
{
    struct pc_opts o;
    size_t n = 0;
    memset(&o, 0, sizeof o);
    const struct lint_gate *tab = lint_gate_table(&n);
    if (pc_parse(&o, argc, argv) != 0 || pc_select(&o, tab, n) != 0
        || pc_mark_skips(&o, tab, n) != 0) {
        fputs(k_pc_usage, stderr);
        return 2;
    }
    return pc_run_report(tab, &o);
}
