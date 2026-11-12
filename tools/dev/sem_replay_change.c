/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-sem-replay: the files a commit changes, and its change kind.
 *
 * Kinds, first match wins: build-system (a build input the compile epoch
 * hashes: the Makefile, a .mk, the epoch scripts, the zcc wrapper),
 * new-file (a C text file added), macro (a changed header, registry or .inc
 * adds or removes a preprocessor directive line), header (a header,
 * registry or .inc changed), body-only (only .c files changed among the C
 * text). The step also marks a commit build-system when its build moved to
 * a new compile epoch. */
#include "sem_replay_change.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const k_build_inputs[] = {
    "Makefile",
    "tools/dev/build-epoch-key.sh",
    "tools/dev/compile-epoch-object.sh",
    "tools/dev/build-epoch-session.sh",
    "tools/dev/build-epoch-open-file-identity.sh",
    "tools/dev/publish_build_alias.c",
    "tools/dev/publish_build_alias.h",
    "tools/dev/zcc-bootstrap-inputs.list",
    "tools/zcc.c",
};

static bool ends_with(const char *s, const char *suffix)
{
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && strcmp(s + n - m, suffix) == 0;
}

static bool is_build_input(const char *f)
{
    for (size_t i = 0; i < sizeof(k_build_inputs) / sizeof(k_build_inputs[0]); i++)
        if (strcmp(f, k_build_inputs[i]) == 0)
            return true;
    return ends_with(f, ".mk");
}

static bool is_header_text(const char *f)
{
    return ends_with(f, ".h") || ends_with(f, ".def") || ends_with(f, ".inc");
}

static bool git_text(const char *repo, char *const argv[], char **out,
                     size_t *len)
{
    int rc = sr_capture(argv, repo, NULL, out, len);
    if (rc != 0)
        fprintf(stderr, "sem-replay: git %s exited %d\n", argv[1], rc);
    return rc == 0;
}

/* The replay's fixed output contract supports one complete SHA-1 object ID. */
static bool oid_record(const char *text, size_t len, char out[64])
{
    out[0] = '\0';
    if (memchr(text, '\0', len))
        return false;
    if (len && text[len - 1] == '\n') {
        len--;
        if (len && text[len - 1] == '\r')
            len--;
    }
    if (len != 40)
        return false;
    for (size_t i = 0; i < len; i++)
        if (!memchr("0123456789abcdefABCDEF", text[i], 22))
            return false;
    memcpy(out, text, len);
    out[len] = '\0';
    return true;
}

static bool first_line(const char *repo, char *const argv[], char out[64])
{
    out[0] = '\0';
    char *text = NULL;
    size_t len = 0;
    bool ok = git_text(repo, argv, &text, &len) && len > 0;
    if (ok) {
        ok = oid_record(text, len, out);
        if (!ok)
            fprintf(stderr, "sem-replay: invalid or unsupported object ID response\n");
    }
    free(text);
    return ok;
}

bool sr_git_parent(const char *repo, const char *commit, char out[64])
{
    char rev[128];
    snprintf(rev, sizeof(rev), "%s^", commit);
    char *argv[] = {"git", "rev-parse", "--verify", rev, NULL};
    return first_line(repo, argv, out);
}

bool sr_git_head(const char *repo, char out[64])
{
    char *argv[] = {"git", "rev-parse", "HEAD", NULL};
    return first_line(repo, argv, out);
}

bool sr_git_checkout(const char *repo, const char *rev, const char *log)
{
    char head[64];
    if (sr_git_head(repo, head) && strcmp(head, rev) == 0)
        return true;
    char *argv[] = {"git", "-c", "advice.detachedHead=false", "checkout",
                    "-q", "--detach", (char *)rev, NULL};
    int rc = sr_run(argv, repo, log, NULL, NULL);
    if (rc != 0)
        fprintf(stderr, "sem-replay: git checkout %s exited %d\n", rev, rc);
    return rc == 0;
}

bool sr_git_blob(const char *repo, const char *rev, const char *path,
                 const char *dest)
{
    char spec[4200];
    snprintf(spec, sizeof(spec), "%s:%s", rev, path);
    char *argv[] = {"git", "cat-file", "blob", spec, NULL};
    char *text = NULL;
    size_t len = 0;
    bool ok = git_text(repo, argv, &text, &len) && sr_mkparent(dest) &&
              sr_write_file(dest, text ? text : "", len);
    free(text);
    return ok;
}

/* One "<status>\t<path>" line of git diff --name-status. */
static bool change_line(struct sr_change *c, const char *line, size_t len)
{
    const char *tab = memchr(line, '\t', len);
    if (tab == NULL || len < 3)
        return true;
    size_t pl = len - (size_t)(tab + 1 - line);
    const char *path = tab + 1;
    bool ok = sr_strv_pushn(&c->files, path, pl);
    if (ok && line[0] == 'A')
        ok = sr_strv_pushn(&c->added, path, pl);
    if (ok && line[0] == 'D')
        ok = sr_strv_pushn(&c->deleted, path, pl);
    if (ok && line[0] != 'D' && pl > 2 && memcmp(path + pl - 2, ".c", 2) == 0)
        ok = sr_strv_pushn(&c->c_files, path, pl);
    return ok;
}

static bool any_of(const struct sr_strv *s, bool (*pred)(const char *))
{
    for (size_t i = 0; i < s->n; i++)
        if (pred(s->v[i]))
            return true;
    return false;
}

static bool is_c_text(const char *f)
{
    return ends_with(f, ".c") || is_header_text(f);
}

/* A +/- line of a unified diff that adds or removes a directive. */
static bool directive_line(const char *p, size_t len)
{
    if (len < 2 || (p[0] != '+' && p[0] != '-') || (len >= 3 && p[1] == p[0] && p[2] == p[0]))
        return false;
    size_t i = 1;
    while (i < len && (p[i] == ' ' || p[i] == '\t'))
        i++;
    return i < len && p[i] == '#';
}

/* argv of `git diff -U0 parent commit -- <changed header text>...`, NULL
 * terminated; false when the change has no header text. */
static bool header_diff_cmd(const char *parent, const char *commit,
                            const struct sr_change *c, struct sr_strv *cmd)
{
    bool ok = sr_strv_push(cmd, "git") && sr_strv_push(cmd, "diff") &&
              sr_strv_push(cmd, "-U0") && sr_strv_push(cmd, parent) &&
              sr_strv_push(cmd, commit) && sr_strv_push(cmd, "--");
    size_t headers = 0;
    for (size_t i = 0; ok && i < c->files.n; i++)
        if (is_header_text(c->files.v[i]) && ++headers)
            ok = sr_strv_push(cmd, c->files.v[i]);
    ok = ok && headers > 0 && sr_strv_pushn(cmd, "", 0);
    if (ok) {
        free(cmd->v[cmd->n - 1]);
        cmd->v[cmd->n - 1] = NULL;
    }
    return ok;
}

static bool any_directive(const char *text, size_t len)
{
    for (const char *p = text; p && p < text + len;) {
        const char *nl = memchr(p, '\n', (size_t)(text + len - p));
        size_t ll = nl ? (size_t)(nl - p) : (size_t)(text + len - p);
        if (directive_line(p, ll))
            return true;
        p += ll + 1;
    }
    return false;
}

static bool macro_changed(const char *repo, const char *parent,
                          const char *commit, const struct sr_change *c)
{
    struct sr_strv cmd = {0};
    char *text = NULL;
    size_t len = 0;
    bool hit = header_diff_cmd(parent, commit, c, &cmd) &&
               git_text(repo, cmd.v, &text, &len) && text != NULL &&
               any_directive(text, len);
    free(text);
    sr_strv_free(&cmd);
    return hit;
}

static const char *classify(const char *repo, const char *parent,
                            const char *commit, const struct sr_change *c)
{
    if (any_of(&c->files, is_build_input))
        return "build-system";
    if (any_of(&c->added, is_c_text))
        return "new-file";
    if (macro_changed(repo, parent, commit, c))
        return "macro";
    if (any_of(&c->files, is_header_text))
        return "header";
    return "body-only";
}

bool sr_change_load(const char *repo, const char *parent, const char *commit,
                    struct sr_change *out)
{
    memset(out, 0, sizeof(*out));
    char *argv[] = {"git", "diff", "--no-renames", "--name-status",
                    (char *)parent, (char *)commit, NULL};
    char *text = NULL;
    size_t len = 0;
    bool ok = git_text(repo, argv, &text, &len);
    for (char *p = text; ok && p && p < text + len;) {
        char *nl = memchr(p, '\n', (size_t)(text + len - p));
        size_t ll = nl ? (size_t)(nl - p) : (size_t)(text + len - p);
        ok = change_line(out, p, ll);
        p += ll + 1;
    }
    free(text);
    for (size_t i = 0; ok && i < out->files.n; i++) {
        const char *f = out->files.v[i];
        out->n_c += ends_with(f, ".c");
        out->n_h += is_header_text(f);
        out->n_other += !is_c_text(f);
    }
    sr_strv_sort_unique(&out->files);
    sr_strv_sort_unique(&out->added);
    sr_strv_sort_unique(&out->deleted);
    sr_strv_sort_unique(&out->c_files);
    if (ok)
        out->kind = classify(repo, parent, commit, out);
    return ok;
}

void sr_change_free(struct sr_change *c)
{
    sr_strv_free(&c->files);
    sr_strv_free(&c->added);
    sr_strv_free(&c->deleted);
    sr_strv_free(&c->c_files);
}
