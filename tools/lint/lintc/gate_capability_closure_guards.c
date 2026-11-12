/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: compiled-out detection of the capability-closure gate. A declared
 * capability whose code a guard macro keeps out of this build's compile line
 * proves nothing either way: the gate reports it UNOBSERVED, naming the macros,
 * and never as a pass or a violation. The macros come from the Makefile's real
 * CFLAGS, never from file names or HAVE_* conventions.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "base/safe_alloc.h"
#include "gate_capability_closure_priv.h"
#include "lintc_proc.h"

/* make -s print-CFLAGS in root with an empty MAKEFLAGS; the text, or NULL when
 * make failed. The repository's own query reuses the source record the parent
 * make already verified. */
static char *ccg_make_cflags(const struct ccg_cfg *cfg, const char *root)
{
    static const char *const set[] = { "MAKEFLAGS=", NULL };
    char rec[CCD_PATH + 32];
    char *argv[7] = { (char *)"sh", (char *)"-c", (char *)"cd \"$0\" && exec make -s \"$@\"", (char *)root,
                      (char *)"print-CFLAGS" };
    struct lcp_spec sp = { .argv = argv, .setenv = set, .mode = LCP_OUT, .grace_ms = CCD_GRACE_MS };
    struct lcp_buf out = { 0 };
    int code = 1;
    char *text = NULL;
    if (cfg->record && cfg->repo && strcmp(root, cfg->repo) == 0
        && snprintf(rec, sizeof rec, "BUILD_SOURCE_RECORD=%s", cfg->record) < (int)sizeof rec)
        argv[5] = rec;
    if (lcp_run(&sp, &out, &code) == 0 && code == 0)
        text = zcl_strdup(out.data ? out.data : "", "ccg_cflags");
    lcp_buf_free(&out);
    return text;
}

/* -D<name>[=value] defines a macro; a later -U<name> removes it again. */
static int ccg_macro_tok(struct ccg_macros *m, const char *tok)
{
    char name[256];
    size_t n;
    if (tok[0] != '-' || (tok[1] != 'D' && tok[1] != 'U'))
        return 0;
    n = tok[1] == 'D' ? strcspn(tok + 2, "=") : strlen(tok + 2);
    if (n == 0 || n >= sizeof name)
        return 0;
    snprintf(name, sizeof name, "%.*s", (int)n, tok + 2);
    return ccd_map_put(&m->def, name, tok[1] == 'D' ? "1" : "");
}

int ccg_macros_load(const struct ccg_cfg *cfg, const char *root, struct ccg_macros *m)
{
    char *text = cfg->cflags ? zcl_strdup(cfg->cflags, "ccg_cflags") : ccg_make_cflags(cfg, root), *save = NULL;
    int bad = 0;
    if (!text && !(cfg->repo && strcmp(root, cfg->repo) == 0))
        text = zcl_strdup("", "ccg_cflags");
    if (!text) {
        fputs("check_capability_closure: FATAL \xe2\x80\x94 cannot read current CFLAGS\n", cfg->err);
        return 1;
    }
    for (char *tok = strtok_r(text, " \t\n", &save); tok && !bad; tok = strtok_r(NULL, " \t\n", &save))
        bad = ccg_macro_tok(m, tok);
    free(text);
    m->loaded = !bad;
    return bad;
}

/* The first line that is neither blank nor a comment, or NULL. */
static char *ccg_first_line(const char *file)
{
    char *line = NULL, *found = NULL;
    size_t cap = 0;
    int in_comment = 0;
    FILE *f = fopen(file, "r");
    for (ssize_t n; f && !found && (n = getline(&line, &cap, f)) >= 0;) {
        char *l = line + strspn(line, " \t");
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (in_comment)
            in_comment = strstr(line, "*/") == NULL;
        else if (*l && strncmp(l, "/*", 2) == 0)
            in_comment = strstr(l, "*/") == NULL;
        else if (*l && strncmp(l, "//", 2) != 0)
            found = zcl_strdup(l, "ccg_first_line");
    }
    if (f)
        fclose(f);
    free(line);
    return found;
}

int ccg_ident(int c, int first)
{
    return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (!first && c >= '0' && c <= '9');
}

/* Not a guard name: the directive words if, ifdef and defined. An #ifndef line
 * keeps its directive as a name, as the script did. */
static int ccg_directive_word(const char *p, size_t n)
{
    return (n == 2 && strncmp(p, "if", 2) == 0) || (n == 5 && strncmp(p, "ifdef", 5) == 0)
           || (n == 7 && strncmp(p, "defined", 7) == 0);
}

/* Every identifier of the line but the directive words, comma-joined, or NULL
 * when there is none. */
static char *ccg_guard_names(const char *line)
{
    size_t cap = strlen(line) + 1, len = 0;
    char *joined = zcl_malloc(cap, "ccg_guard_names");
    for (const char *p = line; joined && *p;) {
        size_t n = 0;
        while (*p && !ccg_ident((unsigned char)*p, 1))
            p++;
        while (ccg_ident((unsigned char)p[n], 0))
            n++;
        if (n && !ccg_directive_word(p, n))
            len += (size_t)snprintf(joined + len, cap - len, "%s%.*s", len ? "," : "", (int)n, p);
        p += n;
    }
    if (joined && len == 0) {
        free(joined);
        joined = NULL;
    }
    return joined;
}

static int ccg_any_defined(const struct ccg_macros *m, const char *names)
{
    char name[CCD_PATH];
    for (const char *p = names; *p;) {
        size_t n = strcspn(p, ",");
        const char *v;
        snprintf(name, sizeof name, "%.*s", (int)n, p);
        v = ccd_map_get(&m->def, name);
        if (v && v[0])
            return 1;
        p += n + (p[n] == ',');
    }
    return 0;
}

char *ccg_compiled_out(const struct ccg_macros *m, const char *root, const char *path)
{
    char full[CCD_PATH], *line, *names = NULL;
    if (snprintf(full, sizeof full, "%s/%s", root, path) >= (int)sizeof full || !(line = ccg_first_line(full)))
        return NULL;
    if (strncmp(line, "#if", 3) == 0)
        names = ccg_guard_names(line);
    free(line);
    if (names && ccg_any_defined(m, names)) {
        free(names);
        names = NULL;
    }
    return names;
}
