/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — model ActiveRecord save lifecycle
 * (check-model-ar-lifecycle). .git probe first; lint_git_index_foreach
 * only when .git exists.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { MAL_MAX = 4096, MAL_LINE = 8192, MAL_HIT = 256, MAL_FN = 256,
       MAL_NAME = 80, MAL_BODY = 16384, MAL_SAVE = 32 };

struct mal_set { char p[MAL_MAX][RS_PATH]; int n; };
struct mal_idx { struct mal_set *s; const char (*rooms)[RS_PATH]; int nr; };
struct mal_help { char n[MAL_FN][MAL_NAME]; int c; };
struct mal_save {
    char n[MAL_SAVE][MAL_NAME];
    char body[MAL_SAVE][MAL_BODY];
    int line[MAL_SAVE];
    int c;
};

static const char k_mal_call[] =
    "(^|[^[:alnum:]_])ar_run_(before|after)_save[[:space:]]*\\(";
static const char k_mal_ok[] = "ar-lifecycle-ok:[A-Za-z][A-Za-z0-9_-]*";

static int mal_add(struct mal_set *s, const char *path)
{
    size_t n;
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 0;
    n = strlen(path);
    if (s->n >= MAL_MAX || n >= RS_PATH)
        return die("z23-lint: model-ar-lifecycle overflow\n", "");
    memcpy(s->p[s->n++], path, n + 1);
    return 0;
}

static int mal_in_room_src(const char *path, const char (*rooms)[RS_PATH],
                           int nr)
{
    const char *base = strrchr(path, '/');
    char want[RS_PATH];
    int i;
    size_t n = strlen(path);
    if (n < 2 || path[n - 2] != '.' || path[n - 1] != 'c')
        return 0;
    base = base ? base + 1 : path;
    for (i = 0; i < nr; i++) {
        if (ovf(snprintf(want, sizeof want, "%s/src/%s", rooms[i], base),
                sizeof want))
            return 0;
        if (strcmp(path, want) == 0)
            return 1;
    }
    return 0;
}

static int mal_on_idx(const char *path, int stage, void *ctx)
{
    struct mal_idx *c = ctx;
    (void)stage;
    if (lint_path_is_excluded(path) || !mal_in_room_src(path, c->rooms, c->nr))
        return 0;
    return mal_add(c->s, path);
}

static int mal_collect(struct mal_set *s, const char (*rooms)[RS_PATH], int nr)
{
    struct mal_idx ix = { .s = s, .rooms = rooms, .nr = nr };
    struct stat st;
    char bad[8] = {0};
    int rc = 0, i;
    s->n = 0;
    if (stat(".git", &st) == 0) {
        rc = lint_git_index_foreach(mal_on_idx, &ix, bad);
        if (rc)
            fprintf(stderr,
                    "check_model_ar_lifecycle: UNPROVEN — git index%s%s\n",
                    bad[0] ? " extension " : "", bad);
        return rc;
    }
    for (i = 0; rc == 0 && i < nr; i++) {
        char src[RS_PATH];
        struct dirent **names = NULL;
        int n, j;
        if (ovf(snprintf(src, sizeof src, "%s/src", rooms[i]), sizeof src))
            return 2;
        n = scandir(src, &names, NULL, alphasort);
        if (n < 0)
            continue;
        for (j = 0; j < n; j++) {
            char path[4096];
            size_t kn = strlen(names[j]->d_name);
            if (rc == 0 && kn >= 2
                && strcmp(names[j]->d_name + kn - 2, ".c") == 0
                && !ovf(snprintf(path, sizeof path, "%s/%s", src,
                                 names[j]->d_name), sizeof path)
                && !lint_path_is_excluded(path))
                rc = mal_add(s, path);
            free(names[j]);
        }
        free(names);
    }
    return rc;
}

static int mal_is_cmt(const char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    return s[0] == '/' && (s[1] == '/' || s[1] == '*');
}

static int mal_direct(const char *path, const regex_t *call, const regex_t *ok,
                      char viol[][RS_PATH], int *nv)
{
    FILE *f = fopen(path, "r");
    char buf[MAL_LINE];
    int lineno = 0;
    if (!f) {
        fprintf(stderr, "check_model_ar_lifecycle: UNPROVEN — cannot read %s\n",
                path);
        return 2;
    }
    while (fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        lineno++;
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (mal_is_cmt(buf))
            continue;
        if (regexec(call, buf, 0, NULL, 0) != 0)
            continue;
        if (regexec(ok, buf, 0, NULL, 0) == 0)
            continue;
        if (*nv < MAL_HIT
            && !ovf(snprintf(viol[*nv], RS_PATH, "%s:%d:%s", path, lineno,
                             buf), RS_PATH))
            (*nv)++;
    }
    fclose(f);
    return 0;
}

static const char *mal_skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t')
        p++;
    return p;
}

static int mal_is_ident0(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

static int mal_is_ident(char c)
{
    return mal_is_ident0(c) || (c >= '0' && c <= '9');
}

static int mal_copy_ident(const char **pp, char *name, size_t cap)
{
    const char *p = *pp;
    size_t n = 0;
    if (!mal_is_ident0(*p))
        return 0;
    while (mal_is_ident(*p)) {
        if (n + 1 < cap)
            name[n++] = *p;
        p++;
    }
    name[n] = '\0';
    *pp = p;
    return 1;
}

static int mal_bool_sig(const char *line, char *name, size_t cap)
{
    const char *p = mal_skip_ws(line);
    if (strncmp(p, "static", 6) == 0 && (p[6] == ' ' || p[6] == '\t'))
        p = mal_skip_ws(p + 6);
    if (strncmp(p, "bool", 4) != 0 || (p[4] != ' ' && p[4] != '\t'))
        return 0;
    p = mal_skip_ws(p + 4);
    if (!mal_copy_ident(&p, name, cap))
        return 0;
    p = mal_skip_ws(p);
    return *p == '(';
}

static int mal_is_save(const char *name)
{
    size_t n;
    if (strncmp(name, "db_", 3) != 0)
        return 0;
    n = strlen(name);
    return n > 8 && strcmp(name + n - 5, "_save") == 0;
}

static int mal_has_ar(const char *body)
{
    return strstr(body, "AR_BEGIN_SAVE") || strstr(body, "AR_ADHOC_SAVE")
        || strstr(body, "AR_CACHED_SAVE") || strstr(body, "ar-lifecycle-ok:");
}

static int mal_brace_delta(const char *s)
{
    int d = 0;
    for (; *s; s++) {
        if (*s == '{')
            d++;
        else if (*s == '}')
            d--;
    }
    return d;
}

static int mal_calls_help(const char *body, const struct mal_help *h)
{
    int i;
    for (i = 0; i < h->c; i++) {
        const char *p = body;
        size_t n = strlen(h->n[i]);
        while ((p = strstr(p, h->n[i])) != NULL) {
            int ok_before = p == body
                || !((p[-1] >= 'A' && p[-1] <= 'Z')
                     || (p[-1] >= 'a' && p[-1] <= 'z')
                     || (p[-1] >= '0' && p[-1] <= '9') || p[-1] == '_');
            const char *q = p + n;
            while (*q == ' ' || *q == '\t')
                q++;
            if (ok_before && *q == '(')
                return 1;
            p += n;
        }
    }
    return 0;
}

static int mal_finish(struct mal_help *h, struct mal_save *sv, const char *name,
                      int line, const char *body)
{
    int ar = mal_has_ar(body);
    if (ar) {
        if (h->c >= MAL_FN)
            return die("z23-lint: model-ar-lifecycle overflow\n", "");
        snprintf(h->n[h->c++], MAL_NAME, "%s", name);
    }
    if (!mal_is_save(name))
        return 0;
    if (sv->c >= MAL_SAVE)
        return die("z23-lint: model-ar-lifecycle overflow\n", "");
    snprintf(sv->n[sv->c], MAL_NAME, "%s", name);
    sv->line[sv->c] = line;
    snprintf(sv->body[sv->c], MAL_BODY, "%s", body);
    sv->c++;
    return 0;
}

static int mal_parse_file(const char *path, struct mal_help *h,
                          struct mal_save *sv)
{
    FILE *f = fopen(path, "r");
    char buf[MAL_LINE], name[MAL_NAME], body[MAL_BODY];
    int in_fn = 0, saw = 0, depth = 0, line = 0, fn_line = 0, rc = 0;
    h->c = 0;
    sv->c = 0;
    body[0] = '\0';
    if (!f) {
        fprintf(stderr, "check_model_ar_lifecycle: UNPROVEN — cannot read %s\n",
                path);
        return 2;
    }
    while (rc == 0 && fgets(buf, (int)sizeof buf, f)) {
        line++;
        if (!in_fn) {
            if (!mal_bool_sig(buf, name, sizeof name))
                continue;
            in_fn = 1;
            saw = 0;
            depth = 0;
            fn_line = line;
            body[0] = '\0';
        }
        if (in_fn) {
            if (strlen(body) + strlen(buf) + 1 < sizeof body)
                strcat(body, buf);
            if (strchr(buf, '{'))
                saw = 1;
            if (saw)
                depth += mal_brace_delta(buf);
            if (saw && depth == 0) {
                rc = mal_finish(h, sv, name, fn_line, body);
                in_fn = 0;
            }
        }
    }
    fclose(f);
    if (rc == 0 && in_fn) {
        fprintf(stderr, "FATAL: unmatched function braces in %s at line %d\n",
                path, fn_line);
        return 2;
    }
    return rc;
}

static int mal_grade_saves(const char *path, const struct mal_help *h,
                           const struct mal_save *sv, char viol[][RS_PATH],
                           int *nv)
{
    int i;
    for (i = 0; i < sv->c; i++) {
        if (mal_has_ar(sv->body[i]))
            continue;
        if (mal_calls_help(sv->body[i], h))
            continue;
        if (*nv < MAL_HIT
            && !ovf(snprintf(viol[*nv], RS_PATH,
                             "%s:%d: %s does not reach AR_BEGIN_SAVE / "
                             "AR_ADHOC_SAVE / AR_CACHED_SAVE",
                             path, sv->line[i], sv->n[i]), RS_PATH))
            (*nv)++;
    }
    return 0;
}

static int mal_run(void)
{
    static struct mal_set files;
    static char viol[MAL_HIT][RS_PATH];
    char rooms[RS_MAX][RS_PATH];
    regex_t call, ok;
    int nr = 0, nv = 0, rc, i;
    rc = repo_shape_room_dirs("models", rooms, RS_MAX, &nr);
    if (rc)
        return rc;
    rc = mal_collect(&files, rooms, nr);
    if (rc)
        return rc;
    if (files.n < 20) {
        printf("FAIL: check_model_ar_lifecycle scanned only %d model file(s)\n"
               "      expected physical */models/src/*.c rooms; gate would be "
               "hollow\n", files.n);
        return 2;
    }
    if (reg_fail(&call, regcomp(&call, k_mal_call, REG_EXTENDED))
        || reg_fail(&ok, regcomp(&ok, k_mal_ok, REG_EXTENDED)))
        return 2;
    for (i = 0; rc == 0 && i < files.n; i++)
        rc = mal_direct(files.p[i], &call, &ok, viol, &nv);
    drop2(&call, &ok);
    for (i = 0; rc == 0 && i < files.n; i++) {
        static struct mal_help h;
        static struct mal_save sv;
        rc = mal_parse_file(files.p[i], &h, &sv);
        if (rc == 0)
            rc = mal_grade_saves(files.p[i], &h, &sv, viol, &nv);
    }
    if (rc)
        return rc;
    if (!nv) {
        fputs("check_model_ar_lifecycle: clean — model saves use AR lifecycle "
              "macros\n", stdout);
        return 0;
    }
    fputs("FAIL: model sources call AR save callbacks directly:\n", stdout);
    for (i = 0; i < nv; i++)
        printf("  %s\n", viol[i]);
    fputs("\nUse AR_BEGIN_SAVE / AR_ADHOC_SAVE / AR_FINISH_SAVE so validation "
          "and\nbefore/after-save hooks remain in one defensive lifecycle.\n",
          stdout);
    return 1;
}

int check_model_ar_lifecycle_selftest(void)
{
    int rc = mal_run();
    if (rc != 0) {
        fprintf(stderr, "check_model_ar_lifecycle selftest: FAIL — clean tree "
                        "rc=%d want=0\n", rc);
        return 1;
    }
    fputs("check_model_ar_lifecycle selftest: PASS — clean tree model saves "
          "use AR lifecycle macros\n", stdout);
    return 0;
}

int check_model_ar_lifecycle_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return mal_run();
}
