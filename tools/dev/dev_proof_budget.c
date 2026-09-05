/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Budget each proof step from this checkout's own measurements and
 * kill only a step that has genuinely stopped.
 *
 * The wall this replaces was a single constant applied to every step. Under
 * load the test dimension took 19 minutes against a 15-minute cap, the proof
 * reported `child_proof_failed_exit_124`, and the tests it had just killed
 * would have gone green four minutes later. A flat cap is wrong in both
 * directions: it murders healthy slow work, and it lets a genuinely hung step
 * hold the queue for the whole cap.
 *
 * So a step is planned, not timed out. Its budget comes from what it is about
 * to do — for the test dimension, the groups the impact plan selected, each
 * carrying the wall time this checkout last measured for it. While it runs,
 * the thing watched is its LOG, not the clock: a step that is still writing is
 * alive. It is killed only when it has been silent for longer than the
 * no-progress window AND its budget is already spent, or when it crosses the
 * hard ceiling no matter how loud it is. */

#include "dev_proof_budget.h"

#include "base/safe_alloc.h"
#include "platform/private_directory.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define TIMING_ROWS_MAX 1024u
#define TIMING_LINE_MAX 512u

struct timing_row {
    char key[PROOF_TIMING_KEY_MAX];
    int64_t samples[PROOF_HISTORY_MAX];
    size_t count;
};

struct timing_table {
    struct timing_row rows[TIMING_ROWS_MAX];
    size_t count;
};

const char *zcl_dev_proof_kill_cause_name(enum zcl_dev_proof_kill_cause cause)
{
    switch (cause) {
    case ZCL_DEV_PROOF_KILL_NONE: return "none";
    case ZCL_DEV_PROOF_KILL_NO_PROGRESS: return "no_progress";
    case ZCL_DEV_PROOF_KILL_HARD_CEILING: return "hard_ceiling";
    }
    return "unknown";
}

int64_t zcl_dev_proof_ceiling_ms(void)
{
    const char *text = getenv("ZCL_PROOF_TIMEOUT_MS");
    if (!text || !*text) return PROOF_TIMEOUT_MS;
    char *end = NULL;
    errno = 0;
    long long value = strtoll(text, &end, 10);
    if (errno || !end || *end || value <= 0) return PROOF_TIMEOUT_MS;
    /* Raise only. A machine may say a step deserves longer than an hour; no
     * machine gets to make the ceiling shorter than the shipped one. */
    if (value < PROOF_TIMEOUT_MS) return PROOF_TIMEOUT_MS;
    if (value > PROOF_TIMEOUT_MAX_MS) return PROOF_TIMEOUT_MAX_MS;
    return (int64_t)value;
}

struct zcl_dev_proof_budget zcl_dev_proof_budget_make(int64_t planned_ms,
                                                      int64_t floor_ms)
{
    struct zcl_dev_proof_budget budget;
    budget.ceiling_ms = zcl_dev_proof_ceiling_ms();
    budget.no_progress_ms = PROOF_NO_PROGRESS_MS;
    if (floor_ms < 0) floor_ms = 0;
    budget.budget_ms = planned_ms < floor_ms ? floor_ms : planned_ms;
    if (budget.budget_ms > budget.ceiling_ms)
        budget.budget_ms = budget.ceiling_ms;
    return budget;
}

enum zcl_dev_proof_kill_cause zcl_dev_proof_budget_verdict(
    const struct zcl_dev_proof_budget *budget, int64_t elapsed_ms,
    int64_t last_progress_age_ms)
{
    if (!budget) return ZCL_DEV_PROOF_KILL_NONE;
    if (budget->ceiling_ms > 0 && elapsed_ms >= budget->ceiling_ms)
        return ZCL_DEV_PROOF_KILL_HARD_CEILING;
    if (elapsed_ms >= budget->budget_ms &&
        last_progress_age_ms >= budget->no_progress_ms)
        return ZCL_DEV_PROOF_KILL_NO_PROGRESS;
    return ZCL_DEV_PROOF_KILL_NONE;
}

/* ── The rolling table ─────────────────────────────────────────────────── */

static bool timing_paths(const char *state_dir, char dir[PATH_MAX],
                         char table[PATH_MAX])
{
    if (!state_dir || !*state_dir) return false;
    return snprintf(dir, PATH_MAX, "%s/timing", state_dir) < PATH_MAX &&
           snprintf(table, PATH_MAX, "%s/timing/table.tsv", state_dir) <
               PATH_MAX;
}

static void timing_load(const char *table_path, struct timing_table *out)
{
    out->count = 0;
    FILE *f = fopen(table_path, "r");
    if (!f) return;
    char line[TIMING_LINE_MAX];
    while (out->count < TIMING_ROWS_MAX && fgets(line, sizeof(line), f)) {
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';
        size_t key_len = strlen(line);
        if (key_len == 0 || key_len >= PROOF_TIMING_KEY_MAX) continue;
        struct timing_row *row = &out->rows[out->count];
        memset(row, 0, sizeof(*row));
        memcpy(row->key, line, key_len + 1);
        const char *scan = tab + 1;
        while (row->count < PROOF_HISTORY_MAX) {
            char *end = NULL;
            errno = 0;
            long long value = strtoll(scan, &end, 10);
            if (errno || end == scan || value < 0) break;
            row->samples[row->count++] = (int64_t)value;
            scan = end;
        }
        if (row->count) out->count++;
    }
    fclose(f);
}

static bool timing_store(const char *dir_path, const char *table_path,
                         const struct timing_table *table)
{
    if (!platform_private_directory_ensure(dir_path)) return false;
    char temporary[PATH_MAX];
    if (snprintf(temporary, sizeof(temporary), "%s.tmp", table_path) >=
        (int)sizeof(temporary))
        return false;
    FILE *f = fopen(temporary, "w");
    if (!f) return false;
    bool ok = true;
    for (size_t i = 0; i < table->count && ok; i++) {
        const struct timing_row *row = &table->rows[i];
        if (fprintf(f, "%s", row->key) < 0) ok = false;
        for (size_t s = 0; s < row->count && ok; s++)
            if (fprintf(f, "%c%lld", s == 0 ? '\t' : ' ',
                        (long long)row->samples[s]) < 0)
                ok = false;
        if (ok && fputc('\n', f) == EOF) ok = false;
    }
    if (fflush(f) != 0) ok = false;
    if (fclose(f) != 0) ok = false;
    if (!ok || rename(temporary, table_path) != 0) {
        (void)remove(temporary);
        return false;
    }
    return true;
}

static struct timing_row *timing_find(struct timing_table *table,
                                      const char *key)
{
    for (size_t i = 0; i < table->count; i++)
        if (strcmp(table->rows[i].key, key) == 0) return &table->rows[i];
    return NULL;
}

static bool timing_key_ok(const char *key)
{
    if (!key || !*key || strlen(key) >= PROOF_TIMING_KEY_MAX) return false;
    for (const char *p = key; *p; p++)
        if (*p == '\t' || *p == '\n' || *p == ' ') return false;
    return true;
}

static void timing_row_append(struct timing_row *row, int64_t observed_ms)
{
    if (row->count == PROOF_HISTORY_MAX) {
        memmove(row->samples, row->samples + 1,
                sizeof(row->samples[0]) * (PROOF_HISTORY_MAX - 1));
        row->count = PROOF_HISTORY_MAX - 1;
    }
    row->samples[row->count++] = observed_ms;
}

bool zcl_dev_proof_timing_note(const char *state_dir, const char *key,
                               int64_t observed_ms)
{
    char dir[PATH_MAX], table_path[PATH_MAX];
    if (!timing_key_ok(key) || observed_ms < 0 ||
        !timing_paths(state_dir, dir, table_path))
        return false;
    struct timing_table *table =
        zcl_calloc(1, sizeof(*table), "dev_proof_timing_table");
    if (!table) return false;
    timing_load(table_path, table);
    struct timing_row *row = timing_find(table, key);
    if (!row) {
        if (table->count == TIMING_ROWS_MAX) {
            free(table);
            return false;
        }
        row = &table->rows[table->count++];
        memset(row, 0, sizeof(*row));
        (void)snprintf(row->key, sizeof(row->key), "%s", key);
    }
    timing_row_append(row, observed_ms);
    bool ok = timing_store(dir, table_path, table);
    free(table);
    return ok;
}

/* What history argues a key deserves: twice its worst recent run plus a
 * minute of headroom. A group this checkout measures in seconds ends up with
 * far less than the compiled default; a genuinely slow group ends up with far
 * more. */
static int64_t allowance_from_samples(const struct timing_row *row)
{
    int64_t worst = 0;
    for (size_t i = 0; i < row->count; i++)
        if (row->samples[i] > worst) worst = row->samples[i];
    return worst * 2 + 60000;
}

int64_t zcl_dev_proof_timing_allowance_ms(const char *state_dir,
                                          const char *key, int64_t fallback_ms)
{
    char dir[PATH_MAX], table_path[PATH_MAX];
    if (!timing_key_ok(key) || !timing_paths(state_dir, dir, table_path))
        return fallback_ms;
    struct timing_table *table =
        zcl_calloc(1, sizeof(*table), "dev_proof_timing_table");
    if (!table) return fallback_ms;
    timing_load(table_path, table);
    const struct timing_row *row = timing_find(table, key);
    int64_t allowance = !row || row->count == 0 ? fallback_ms
                                                : allowance_from_samples(row);
    free(table);
    return allowance;
}

/* ── Reading the harness's own banners ─────────────────────────────────── */

bool zcl_dev_proof_timing_parse_group_line(const char *line, char *group,
                                           size_t group_size, int64_t *ms)
{
    static const char marker[] = "==================== ";
    if (!line || !group || !group_size || !ms) return false;
    if (strncmp(line, marker, sizeof(marker) - 1) != 0) return false;
    const char *name = line + sizeof(marker) - 1;
    const char *open = strstr(name, " (");
    if (!open || open == name) return false;
    size_t name_len = (size_t)(open - name);
    if (name_len >= group_size) return false;
    const char *status = open + 2;
    /* Only a passing group is evidence of how long the work takes. */
    if (strncmp(status, "PASS", 4) != 0) return false;
    const char *close = strstr(status, ") ====");
    if (!close) return false;
    /* The seconds are the last comma-separated field before the paren; a
     * skip note can sit between the status and the time. */
    const char *seconds = NULL;
    for (const char *p = status; p < close; p++)
        if (*p == ',') seconds = p + 1;
    if (!seconds) return false;
    while (seconds < close && *seconds == ' ') seconds++;
    char *end = NULL;
    errno = 0;
    long long value = strtoll(seconds, &end, 10);
    if (errno || end == seconds || value < 0 || end >= close || *end != 's')
        return false;
    if (end + 1 != close) return false;
    memcpy(group, name, name_len);
    group[name_len] = '\0';
    *ms = (int64_t)value * 1000;
    return true;
}

size_t zcl_dev_proof_timing_ingest_test_log(const char *state_dir,
                                            const char *log_path)
{
    char dir[PATH_MAX], table_path[PATH_MAX];
    if (!log_path || !timing_paths(state_dir, dir, table_path)) return 0;
    FILE *f = fopen(log_path, "r");
    if (!f) return 0;
    struct timing_table *table =
        zcl_calloc(1, sizeof(*table), "dev_proof_timing_table");
    if (!table) {
        fclose(f);
        return 0;
    }
    timing_load(table_path, table);
    char line[TIMING_LINE_MAX];
    char group[PROOF_TIMING_KEY_MAX];
    size_t noted = 0;
    int64_t observed = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!zcl_dev_proof_timing_parse_group_line(line, group, sizeof(group),
                                                   &observed))
            continue;
        if (!timing_key_ok(group)) continue;
        struct timing_row *row = timing_find(table, group);
        if (!row) {
            if (table->count == TIMING_ROWS_MAX) continue;
            row = &table->rows[table->count++];
            memset(row, 0, sizeof(*row));
            (void)snprintf(row->key, sizeof(row->key), "%s", group);
        }
        timing_row_append(row, observed);
        noted++;
    }
    fclose(f);
    bool stored = noted && timing_store(dir, table_path, table);
    free(table);
    return stored ? noted : 0;
}

/* ── Budgets ───────────────────────────────────────────────────────────── */

struct zcl_dev_proof_budget zcl_dev_proof_test_budget(const char *state_dir,
                                                      const char *groups_csv,
                                                      uint32_t groups)
{
    char dir[PATH_MAX], table_path[PATH_MAX];
    struct timing_table *table = NULL;
    if (timing_paths(state_dir, dir, table_path) &&
        (table = zcl_calloc(1, sizeof(*table),
                            "dev_proof_timing_table")) != NULL)
        timing_load(table_path, table);
    int64_t planned = 0;
    uint32_t counted = 0;
    if (groups_csv && *groups_csv) {
        const char *scan = groups_csv;
        while (*scan) {
            const char *end = strchr(scan, ',');
            size_t len = end ? (size_t)(end - scan) : strlen(scan);
            char key[PROOF_TIMING_KEY_MAX];
            if (len && len < sizeof(key)) {
                memcpy(key, scan, len);
                key[len] = '\0';
                const struct timing_row *row =
                    table ? timing_find(table, key) : NULL;
                planned += row && row->count ? allowance_from_samples(row)
                                             : PROOF_TEST_GROUP_DEFAULT_MS;
                counted++;
            }
            if (!end) break;
            scan = end + 1;
        }
    }
    free(table);
    /* A selector we could not read is never a reason to shrink the budget. */
    if (counted < groups)
        planned += (int64_t)(groups - counted) * PROOF_TEST_GROUP_DEFAULT_MS;
    return zcl_dev_proof_budget_make(planned + PROOF_TEST_FLOOR_MS,
                                     PROOF_TEST_FLOOR_MS);
}

struct zcl_dev_proof_budget zcl_dev_proof_step_budget(const char *state_dir,
                                                      const char *key,
                                                      int64_t fallback_ms)
{
    int64_t planned =
        zcl_dev_proof_timing_allowance_ms(state_dir, key, fallback_ms);
    return zcl_dev_proof_budget_make(planned + PROOF_STEP_FLOOR_MS,
                                     PROOF_STEP_FLOOR_MS);
}

/* ── The record a person reads afterwards ──────────────────────────────── */

bool zcl_dev_proof_phase_note(const char *phases_path, const char *field,
                              const char *value)
{
    if (!phases_path || !field || !value) return false;
    FILE *f = fopen(phases_path, "a");
    if (!f) return false;
    int written = fprintf(f, "%s=%s\n", field, value);
    bool ok = written > 0 && fflush(f) == 0;
    return fclose(f) == 0 && ok;
}

bool zcl_dev_proof_phase_record(const char *phases_path, const char *step,
                                const struct zcl_dev_proof_step_report *report)
{
    if (!phases_path || !step || !report) return false;
    FILE *f = fopen(phases_path, "a");
    if (!f) return false;
    int written = fprintf(
        f,
        "step=%s budget_ms=%lld elapsed_ms=%lld last_progress_age_ms=%lld "
        "cause=%s exit=%d\n",
        step, (long long)report->budget_ms, (long long)report->elapsed_ms,
        (long long)report->last_progress_age_ms,
        zcl_dev_proof_kill_cause_name(report->cause), report->rc);
    bool ok = written > 0 && fflush(f) == 0;
    return fclose(f) == 0 && ok;
}

/* ── Running one step under the watch ──────────────────────────────────── */

#if !defined(_WIN32)

static bool log_progress_mark(const char *path, int64_t *size, int64_t *mtime)
{
    struct stat st;
    if (stat(path, &st) != 0) return false;
    bool moved = (int64_t)st.st_size != *size ||
                 (int64_t)st.st_mtime != *mtime;
    *size = (int64_t)st.st_size;
    *mtime = (int64_t)st.st_mtime;
    return moved;
}

bool zcl_dev_proof_step_start(struct zcl_dev_proof_step *step, const char *root,
                              const char *log_path, const char *const argv[],
                              const struct zcl_dev_proof_budget *budget)
{
    if (!step || !root || !log_path || !argv || !budget) return false;
    memset(step, 0, sizeof(*step));
    if (snprintf(step->log_path, sizeof(step->log_path), "%s", log_path) >=
        (int)sizeof(step->log_path))
        return false;
    step->budget = *budget;
    step->report.budget_ms = budget->budget_ms;
    step->seen_size = -1;
    step->seen_mtime = -1;
    pid_t child = fork();
    if (child < 0) {
        step->report.rc = -1;
        step->finished = true;
        return false;
    }
    if (child == 0) {
        if (setsid() < 0 || chdir(root) != 0) _exit(127);
        struct rlimit stack = {.rlim_cur = RLIM_INFINITY,
                               .rlim_max = RLIM_INFINITY};
        (void)setrlimit(RLIMIT_STACK, &stack);
        int fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0 ||
            dup2(fd, STDERR_FILENO) < 0)
            _exit(127);
        if (fd > STDERR_FILENO) close(fd);
#if defined(__APPLE__)
        /* A pathname sandbox cannot revoke inherited open-file authority.
         * Keep only the log streams and inert stdin before executing any
         * generation code. Census the real descriptors, not the current
         * descriptor limit, which may have been lowered since they opened. */
        int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (input < 0 || dup2(input, STDIN_FILENO) < 0) {
            (void)dprintf(STDERR_FILENO,
                          "proof step: inert stdin setup failed: %s\n",
                          strerror(errno));
            _exit(127);
        }
        if (input > STDERR_FILENO) close(input);
        if (!os_proc_close_inherited_fds()) {
            (void)dprintf(STDERR_FILENO,
                          "proof step: descriptor confinement failed: %s\n",
                          strerror(errno));
            _exit(127);
        }
#endif
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    step->child = (int64_t)child;
    step->started = true;
    step->started_us = platform_time_monotonic_us();
    step->last_progress_us = step->started_us;
    return true;
}

bool zcl_dev_proof_step_poll(struct zcl_dev_proof_step *step)
{
    if (!step || !step->started) return true;
    if (step->finished) return true;
    int status = 0;
    pid_t child = (pid_t)step->child;
    pid_t got = waitpid(child, &status, WNOHANG);
    if (got == child) {
        int64_t now_us = platform_time_monotonic_us();
        (void)log_progress_mark(step->log_path, &step->seen_size,
                                &step->seen_mtime);
        step->report.elapsed_ms = (now_us - step->started_us) / 1000;
        step->report.last_progress_age_ms = 0;
        if (WIFEXITED(status)) step->report.rc = WEXITSTATUS(status);
        else
            step->report.rc =
                WIFSIGNALED(status) ? 128 + WTERMSIG(status) : -1;
        step->finished = true;
        return true;
    }
    if (got < 0 && errno != EINTR) {
        step->report.rc = -1;
        step->finished = true;
        return true;
    }
    int64_t now_us = platform_time_monotonic_us();
    if (log_progress_mark(step->log_path, &step->seen_size, &step->seen_mtime))
        step->last_progress_us = now_us;
    step->report.elapsed_ms = (now_us - step->started_us) / 1000;
    step->report.last_progress_age_ms =
        (now_us - step->last_progress_us) / 1000;
    enum zcl_dev_proof_kill_cause cause = zcl_dev_proof_budget_verdict(
        &step->budget, step->report.elapsed_ms,
        step->report.last_progress_age_ms);
    if (cause == ZCL_DEV_PROOF_KILL_NONE) return false;
    step->report.cause = cause;
    (void)kill(-child, SIGTERM);
    platform_sleep_ms(100);
    (void)kill(-child, SIGKILL);
    (void)waitpid(child, &status, 0);
    step->report.rc = 124;
    step->finished = true;
    return true;
}

size_t zcl_dev_proof_steps_wait(struct zcl_dev_proof_step *steps, size_t count)
{
    if (!steps) return 0;
    for (;;) {
        bool pending = false;
        for (size_t i = 0; i < count; i++) {
            if (!steps[i].started || steps[i].finished) continue;
            if (!zcl_dev_proof_step_poll(&steps[i])) pending = true;
        }
        if (!pending) break;
        platform_sleep_ms(20);
    }
    /* Fail closed on the first step that did not succeed, in the order the
     * caller listed them, so a concurrent proof reports the same failure a
     * sequential one would have. */
    for (size_t i = 0; i < count; i++)
        if (steps[i].started && steps[i].report.rc != 0) return i;
    return count;
}

int zcl_dev_proof_run_watched(const char *root, const char *log_path,
                              const char *const argv[],
                              const struct zcl_dev_proof_budget *budget,
                              struct zcl_dev_proof_step_report *report)
{
    struct zcl_dev_proof_step step;
    if (!zcl_dev_proof_step_start(&step, root, log_path, argv, budget)) {
        if (report) {
            memset(report, 0, sizeof(*report));
            report->budget_ms = budget ? budget->budget_ms : 0;
            report->rc = -1;
        }
        return -1;
    }
    (void)zcl_dev_proof_steps_wait(&step, 1);
    if (report) *report = step.report;
    return step.report.rc;
}

#endif /* !_WIN32 */
