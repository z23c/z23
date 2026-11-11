/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the gate worker pool of `z23-lint run`. Each gate runs in its own
 * forked worker whose stdout and stderr are the gate's log file; the parent
 * keeps up to JOBS workers alive in dispatch order (the xargs -P contract of
 * the former shell driver), times each from fork to reap, writes the .ms/.rc artifacts,
 * and prints one PASS/FAIL line per finished gate.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "run_priv.h"

long long lr_now_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts); // platform-ok: z23-lint links no platform library; gate wall time for the verdict line only
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* In the worker: point fd 0/1/2 at /dev/null and the log, then run. */
static int worker_body(const struct lr_run *r, const struct lr_gate *g)
{
    char log[LR_PATH + LR_NAME + 16];
    struct lr_plan plan;
    char err[LR_ERR];
    int fd, nul;
    (void)snprintf(log, sizeof log, "%s/%s.log", r->gates_dir, g->name);
    fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    nul = open("/dev/null", O_RDONLY);
    if (fd < 0 || nul < 0)
        return 126;
    (void)dup2(nul, STDIN_FILENO);
    (void)dup2(fd, STDOUT_FILENO);
    (void)dup2(fd, STDERR_FILENO);
    (void)close(nul);
    (void)close(fd);
    if (strcmp(g->cmd, LR_CORE_SEAL) == 0)
        return lr_core_seal(r->o->bin_dir ? r->o->bin_dir : "build/bin");
    if (lr_parse_command(g->cmd, r->o->lint_bin, &plan, err, sizeof err) != 0) {
        (void)fprintf(stderr, "z23-lint run: cannot run %s: %s\n  command: %s\n",
                      g->name, err, g->cmd);
        return 2;
    }
    return lr_run_plan(&plan);
}

static pid_t spawn_worker(struct lr_run *r, int i)
{
    struct lr_gate *g = &r->g[i];
    (void)fflush(NULL);
    g->t0 = lr_now_ms();
    pid_t pid = fork();
    if (pid == 0) {
        int rc = worker_body(r, g);
        (void)fflush(NULL);
        _exit(rc);
    }
    g->pid = pid < 0 ? 0 : pid;
    return pid;
}

static void write_num(const struct lr_run *r, const char *name, const char *ext,
                      long long v)
{
    char path[LR_PATH + LR_NAME + 16];
    (void)snprintf(path, sizeof path, "%s/%s.%s", r->gates_dir, name, ext);
    FILE *f = fopen(path, "w");
    if (!f)
        return;
    (void)fprintf(f, "%lld\n", v);
    (void)fclose(f);
}

static void print_verdict(const struct lr_run *r, const struct lr_gate *g)
{
    if (g->rc == 0)
        (void)fprintf(r->o->out, "PASS %-42s %7lld ms\n", g->name, g->ms);
    else
        (void)fprintf(r->o->out, "FAIL %-42s %7lld ms (rc=%d)\n", g->name, g->ms, g->rc);
    (void)fflush(r->o->out);
}

/* A worker that did not exit normally leaves no .rc artifact: the driver's
 * own failure, reported as a worker crash, never as a gate verdict. */
static void finish_gate(struct lr_run *r, int i, int status)
{
    struct lr_gate *g = &r->g[i];
    g->ms = lr_now_ms() - g->t0;
    g->pid = 0;
    if (!WIFEXITED(status))
        return;
    g->rc = WEXITSTATUS(status);
    g->have_rc = true;
    write_num(r, g->name, "ms", g->ms);
    write_num(r, g->name, "rc", g->rc);
    print_verdict(r, g);
}

static int reap_gate(struct lr_run *r, int i, int options)
{
    struct lr_gate *g = &r->g[i];
    int status = 0;
    pid_t pid;
    do {
        pid = waitpid(g->pid, &status, options);
    } while (pid < 0 && errno == EINTR);
    if (pid < 0) {
        (void)fprintf(r->o->err, "z23-lint run: cannot wait for gate %s: %s\n",
                      g->name, strerror(errno));
        /* Its status is unavailable. Never signal a possibly reused PID. */
        g->pid = 0;
        return -1;
    }
    if (pid == 0)
        return 0;
    finish_gate(r, i, status);
    return 1;
}

/* Only these worker PIDs belong to this pool. A process-wide wait can steal
 * another caller's child and release a slot whose worker is still running. */
static int reap_ready(struct lr_run *r, const int *order, int cnt)
{
    bool active = false;
    for (int k = 0; k < cnt; k++) {
        struct lr_gate *g = &r->g[order[k]];
        if (g->pid <= 0)
            continue;
        active = true;
        int ready = reap_gate(r, order[k], WNOHANG);
        if (ready != 0)
            return ready;
    }
    return active ? 0 : -1;
}

static int reap_one(struct lr_run *r, const int *order, int cnt)
{
    for (;;) {
        int ready = reap_ready(r, order, cnt);
        if (ready != 0)
            return ready < 0 ? -1 : 0;
        /* Waiting on the first PID would stall slot refill behind a slow
         * gate. Rescan all owned workers without busy-spinning instead. */
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 5000000 };
        while (nanosleep(&pause, &pause) != 0) {
            if (errno != EINTR)
                return -1;
        }
    }
}

/* A driver failure stops dispatch, but already launched gates still own
 * their logs and inputs. Wait for them before returning the run's scope. */
static void drain_workers(struct lr_run *r, const int *order, int cnt)
{
    for (int k = 0; k < cnt; k++) {
        if (r->g[order[k]].pid > 0)
            (void)reap_gate(r, order[k], 0);
    }
}

int lr_pool(struct lr_run *r, const int *order, int cnt, int jobs)
{
    int next = 0, running = 0;
    while (next < cnt || running > 0) {
        while (running < jobs && next < cnt) {
            if (spawn_worker(r, order[next++]) > 0)
                running++;
        }
        if (running > 0 && reap_one(r, order, cnt) != 0) {
            drain_workers(r, order, cnt);
            return 1;
        }
        if (running > 0)
            running--;
    }
    return 0;
}
