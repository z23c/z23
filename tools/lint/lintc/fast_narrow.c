/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: decide when a per-file lint gate may scan only the changed-file
 * set. The land proof and `make lint` never call this; a narrowed pass is
 * not a whole-tree proof. `z23-lint fast-scan` is a tool, not a gate.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lintc.h"
#include "precheck_base.h"

static const char *const k_fast_nak[] = {
    "tools/lint/lintc/gate_git_scan_a.c",
    NULL
};
static const char *const k_fast_fmd[] = {
    "tools/lint/lintc/gate_fortify_masked_decls.c",
    NULL
};
static const char *const k_fast_crs[] = {
    "tools/lint/lintc/gate_raw_sqlite.c",
    "tools/lint/lintc/gate_raw_sqlite_ctx.c",
    "tools/lint/lintc/gate_raw_sqlite_exec.c",
    "tools/lint/lintc/gate_raw_sqlite_priv.h",
    NULL
};

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
    size_t n;
    int k;
    if (!cmd || !path || !path[0] || strchr(path, ' ') || strchr(path, '\n')
        || strchr(path, '\t'))
        return 2;
    n = strlen(cmd);
    if (n >= cap)
        return 2;
    k = snprintf(cmd + n, cap - n, " --changed-files=%s", path);
    if (k < 0 || (size_t)k >= cap - n)
        return 2;
    return 0;
}

static const char *const *lint_fast_sources(const char *name)
{
    if (strcmp(name, "check-no-api-keys") == 0)
        return k_fast_nak;
    if (strcmp(name, "check-fortify-masked-decls") == 0)
        return k_fast_fmd;
    if (strcmp(name, "check-raw-sqlite") == 0)
        return k_fast_crs;
    return NULL;
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

int lint_fast_gate_narrow(const char *name, int set_supplied)
{
    const char *const *src;
    char sha[80];
    if (!name || !set_supplied)
        return 0;
    src = lint_fast_sources(name);
    if (!src)
        return 0;
    if (!lint_fast_base(sha, sizeof sha))
        return 0;
    return lint_fast_should_narrow(1, 1, lint_fast_diff_quiet(sha, src));
}


