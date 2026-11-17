/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: decide when a per-file lint gate may scan only the changed-file
 * set. The per-file-deterministic marker rows live in gate_commands.def
 * (LINT_ROW_FILES), compiled in below, next to the command they qualify.
 * The land proof and `make lint` never call this; a narrowed pass is
 * not a whole-tree proof. `z23-lint fast-scan` is a tool, not a gate.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "lintc.h"
#include "precheck_base.h"
#include "run_priv.h"

/* The per-file-deterministic marker rows of gate_commands.def: the run
 * driver narrows exactly these gates, never a gate without a row. */
#define LINT_ROW(name, cmd)
#define LINT_ROW_FILES(name, files) { name, files },
static const struct {
    const char *name;
    const char *files;
} k_fast_file_rows[] = {
#include "gate_commands.def"
};
#undef LINT_ROW
#undef LINT_ROW_FILES

const char *lint_fast_files_decl(const char *gate)
{
    if (!gate)
        return NULL;
    for (size_t i = 0; i < sizeof k_fast_file_rows / sizeof k_fast_file_rows[0]; i++)
        if (strcmp(k_fast_file_rows[i].name, gate) == 0)
            return k_fast_file_rows[i].files;
    return NULL;
}

int lint_fast_should_narrow(int per_file, int set_supplied, int source_matches)
{
    return per_file && set_supplied && source_matches;
}

int lint_examined_print(int n, int floor)
{
    int k;
    if (floor < 0)
        k = printf("examined-files: %d\nscan-floor: whole\n", n);
    else
        k = printf("examined-files: %d\nscan-floor: %d\n", n, floor);
    return k < 0 ? -1 : 0;
}

static int lint_changed_has(const struct lint_changed *c, const char *s)
{
    for (int i = 0; i < c->n; i++) {
        if (strcmp(c->path[i], s) == 0)
            return 1;
    }
    return 0;
}

void lint_changed_free(struct lint_changed *c)
{
    if (!c)
        return;
    for (int i = 0; i < c->n; i++)
        free(c->path[i]);
    free(c->path);
    c->path = NULL;
    c->n = 0;
    c->active = 0;
}

/* Takes ownership of s. Empty and duplicate lines are dropped. */
static int lint_changed_add(struct lint_changed *c, char *s)
{
    char **np;
    if (s[0] == '\0' || lint_changed_has(c, s)) {
        free(s);
        return 0;
    }
    np = realloc(c->path, (size_t)(c->n + 1) * sizeof(*np)); // raw-alloc-ok:lint-runtime
    if (!np) {
        free(s);
        return 2;
    }
    c->path = np;
    c->path[c->n++] = s;
    return 0;
}

static int lint_changed_load(struct lint_changed *c, const char *path)
{
    FILE *f = fopen(path, "r");
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    if (!f) {
        fprintf(stderr, "z23-lint: cannot open changed-file list\n");
        return 2;
    }
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        char *copy;
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        if (line[0] == '\0')
            continue;
        /* Git quotes paths this newline format cannot represent literally.
         * Discard even earlier entries: a partial set is not a safe scan. */
        if (line[0] == '"') {
            fprintf(stderr, "z23-lint: quoted changed-file path; using whole-tree scan\n");
            lint_changed_free(c);
            break;
        }
        if (strlen(line) >= 4096) {
            rc = 2;
            break;
        }
        copy = malloc(strlen(line) + 1); // raw-alloc-ok:lint-runtime
        if (!copy) {
            rc = 2;
            break;
        }
        memcpy(copy, line, strlen(line) + 1);
        rc = lint_changed_add(c, copy);
    }
    if (ferror(f))
        rc = 2;
    free(line);
    if (fclose(f) != 0)
        rc = 2;
    return rc;
}

static int lint_changed_take(int *argc, char ***argv, const char **file)
{
    int w = 0;
    *file = NULL;
    for (int i = 0; i < *argc; i++) {
        const char *a = (*argv)[i];
        if (a && strncmp(a, "--changed-files=", 16) == 0) {
            if (*file || a[16] == '\0')
                return 2;
            *file = a + 16;
            continue;
        }
        (*argv)[w++] = (*argv)[i];
    }
    *argc = w;
    return 0;
}

int lint_changed_bind(int *argc, char ***argv, struct lint_changed *out)
{
    const char *file = NULL;
    int rc;
    memset(out, 0, sizeof *out);
    if (!argc || !argv || *argc <= 0)
        return 0;
    rc = lint_changed_take(argc, argv, &file);
    if (rc)
        return rc;
    if (!file)
        return 0;
    out->active = 1;
    rc = lint_changed_load(out, file);
    if (rc)
        lint_changed_free(out);
    return rc;
}

int lint_fast_append_changed(char *cmd, size_t cap, const char *path)
{
    char quoted[8192];
    size_t n;
    int k;
    if (!cmd || !path || !path[0] || sh_single_quote(path, quoted, sizeof quoted))
        return 2;
    n = strlen(cmd);
    if (n >= cap)
        return 2;
    k = snprintf(cmd + n, cap - n, " --changed-files=%s", quoted);
    if (k < 0 || (size_t)k >= cap - n)
        return 2;
    return 0;
}

static int lint_fast_tip(char *tip, size_t cap)
{
    const char *rev[] = {
        "rev-parse", "--verify", "-q", "refs/remotes/origin/main^{commit}", NULL
    };
    int rc = precheck_base_git(NULL, rev, tip, cap);
    return rc == 0 && tip[0] != '\0';
}

static int lint_fast_base(char *sha, size_t cap)
{
    char tip[80];
    const char *mb[] = { "merge-base", "HEAD", tip, NULL };
    int rc;
    if (!lint_fast_tip(tip, sizeof tip))
        return 0;
    rc = precheck_base_git(NULL, mb, sha, cap);
    return rc == 0 && sha[0] != '\0';
}

static int lint_fast_diff_quiet(const char *sha, const char *const *files)
{
    const char *args[9];
    int n = 0;
    args[n++] = "diff";
    args[n++] = "--quiet";
    args[n++] = sha;
    args[n++] = "--";
    for (int i = 0; files[i] != NULL && n < 8; i++)
        args[n++] = files[i];
    args[n] = NULL;
    return precheck_base_git(NULL, args, NULL, 0) == 0;
}

/* Split the declared space-separated sources into OUT (NULL-terminated) inside
 * BUF. Returns the count, 0 when the row is empty or overflows either. */
static int lint_fast_split_sources(const char *files, char *buf, size_t cap,
                                   const char *out[9])
{
    size_t w = 0;
    int n = 0;
    const char *p = files;
    while (*p) {
        const char *q = p;
        size_t len;
        while (*q && *q != ' ')
            q++;
        len = (size_t)(q - p);
        if (len == 0) {
            p++;
            continue;
        }
        if (w + len + 1 >= cap || n >= 8)
            return 0;
        memcpy(buf + w, p, len);
        buf[w + len] = '\0';
        out[n++] = buf + w;
        w += len + 1;
        p = q;
    }
    out[n] = NULL;
    return n;
}

int lint_fast_gate_narrow(const char *name, int set_supplied)
{
    char sha[80], buf[512];
    const char *src[9];
    const char *decl;
    if (!name || !set_supplied)
        return 0;
    decl = lint_fast_files_decl(name);
    if (!decl)
        return 0;
    if (!lint_fast_base(sha, sizeof sha))
        return 0;
    if (lint_fast_split_sources(decl, buf, sizeof buf, src) == 0)
        return 0;
    return lint_fast_should_narrow(1, 1, lint_fast_diff_quiet(sha, src));
}

/* The run driver's --base scope: git's stdout for ARGS appended to FD. */
static int lint_scope_git_to_fd(const char *const *args, int fd)
{
    int st = 0;
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (dup2(fd, STDOUT_FILENO) < 0)
            _exit(127);
        execvp("git", (char *const *)args);
        _exit(127);
    }
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

int lint_changed_scope_from_base(const char *base, char *out, size_t cap)
{
    const char *diff[] = { "git", "diff", "--name-only", base, NULL };
    static const char *const k_untracked[] = {
        "git", "ls-files", "--others", "--exclude-standard", NULL
    };
    char path[PATH_MAX], cwd[PATH_MAX];
    int fd, rc, n;
    if (!base || !base[0] || lr_mkdir_p("build/scratch") != 0)
        return 2;
    /* Absolute: the scope file is handed to gates and readers that may not
     * share the driver's working directory. */
    if (!getcwd(cwd, sizeof cwd))
        return 2;
    n = snprintf(path, sizeof path, "%s/build/scratch/lint-changed-%ld.txt",
                 cwd, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof path)
        return 2;
    fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0)
        return 2;
    rc = lint_scope_git_to_fd(diff, fd);
    if (rc == 0)
        rc = lint_scope_git_to_fd(k_untracked, fd);
    if (close(fd) != 0)
        rc = -1;
    if (rc != 0) {
        (void)unlink(path);
        return 2;
    }
    if (snprintf(out, cap, "%s", path) >= (int)cap)
        return 2;
    return 0;
}


