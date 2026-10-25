/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: shared helpers of the dev.cx leaves (dev.cx.next, dev.cx.check):
 *          a string set, bounded whole-file reads, a no-shell process run and
 *          the baseline row parser. The complexity metric itself stays in
 *          tools/lint/lintc/gate_function_complexity.c; dev.cx.check runs the
 *          lane's own build/bin/z23-lint and never reimplements it. */

#ifndef ZCL_NATIVE_DEV_CX_H
#define ZCL_NATIVE_DEV_CX_H

#include <stdbool.h>
#include <stddef.h>

/* Where the pinned rows live, relative to a checkout or worktree root. */
#define ZCL_CX_BASELINE_REL "tools/lint/cyclomatic_complexity_baseline.txt"
/* The cap the gate enforces (gate_function_complexity.c CYC_MAX). */
#define ZCL_CX_CAP 15
#define ZCL_CX_PATH_MAX 4096
#define ZCL_CX_NAME_MAX 128
#define ZCL_CX_FILE_MAX 512

struct cx_set {
    char **v;
    size_t n, cap;
};

/* A baseline row `file:function:score`. */
struct cx_row {
    char file[ZCL_CX_FILE_MAX];
    char fn[ZCL_CX_NAME_MAX];
    int score;
};

bool cx_set_add(struct cx_set *s, const char *text, size_t len);
bool cx_set_has(const struct cx_set *s, const char *text);
void cx_set_free(struct cx_set *s);
/* Adds every non-empty line of text (CR trimmed). */
bool cx_set_add_lines(struct cx_set *s, const char *text);

/* Whole file, NUL-terminated, malloc'd; NULL on any read error. */
char *cx_read_file(const char *path, size_t *len);
bool cx_write_file(const char *path, const char *data, size_t len);

/* argv without a shell in dir (NULL = here). Returns the child's exit status,
 * -1 when it could not be started or timed out. merged folds stderr in. */
int cx_run(const char *dir, const char *const argv[], char *buf, size_t cap,
           int timeout_ms, bool merged);

/* Parses one row (len bytes, no newline); false for comments and junk. */
bool cx_row_parse(const char *line, size_t len, struct cx_row *out);


/* Every path any worktree of the repository at root changes against
 * origin/main: committed (merge-base diff of its HEAD), staged, unstaged and
 * untracked. Worktrees are scanned in parallel; one that cannot be compared
 * fails the whole call (why names it): an unknown is never read as clean. */
bool cx_changed_files(const char *root, struct cx_set *out, char *why,
                      size_t why_cap);

#endif
