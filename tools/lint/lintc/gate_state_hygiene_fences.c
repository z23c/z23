/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — local-state hygiene fences of the C23 lint
 * runtime (check-json-value-init, check-one-write-path).
 */

/*
 * Gates: check-json-value-init, check-one-write-path
 * Local-state hygiene fences. json_set_* and json_free release PREVIOUS
 * contents first, so an uninitialised struct json_value local frees
 * stack garbage (zid_domain_dump_state_json crashed a serving node
 * every ~15 minutes). Whole-repo each_zpath(k_ls_all) .c files, no
 * exclusion, zero baseline. check-one-write-path is the E6 shrink-only
 * consensus-writer ratchet: walk_src per root core/engine/contexts/
 * cognition/platform/tools against an intentionally empty baseline.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "lint_narrow_hook.h"

/* A handful of bare json_value locals per file is plenty; overflow is fatal. */
enum { JVI_PEND = 32, JVI_NAME = 64, JVI_LINE = 8192 };
enum { OWP_MAX = 256, OWP_KEY = 2048, OWP_FLOOR = 200 };
enum { OWP_ROOT_MAX = 16, OWP_ROOT_BUF = 4096 };

struct jvi_slot { char n[JVI_NAME]; int line; };
struct jvi_pend { struct jvi_slot e[JVI_PEND]; int n; };
struct jvi_acc { int hits; int emit; int files; };

struct owp_re { regex_t a, b, mark; };
struct owp_acc {
    const struct owp_re *re;
    char base[OWP_MAX][OWP_KEY];
    char hit[OWP_MAX][OWP_KEY];
    int nbase, nhit, nfiles;
};

static int sh_want(const char *tag, int got, int w, const char *s)
{
    if (got == w)
        return 0;
    fprintf(stderr, "%s selftest: want %d got %d: %s\n", tag, w, got, s);
    return 1;
}

static int jvi_ident(unsigned char c)
{ return lintc_ident_start(c) || (c >= '0' && c <= '9'); }

static const char *jvi_skip_ht(const char *p)
{ while (*p == ' ' || *p == '\t') p++; return p; }

static const char *jvi_kw(const char *p, const char *kw)
{
    size_t n = strlen(kw);
    if (strncmp(p, kw, n) != 0)
        return NULL;
    p += n;
    if (*p != ' ' && *p != '\t')
        return NULL;
    return jvi_skip_ht(p);
}

static int jvi_read_ident(const char **pp, char *name, size_t cap)
{
    const char *p = *pp;
    if (!lintc_ident_start((unsigned char)*p))
        return 0;
    size_t n = 0;
    name[n++] = *p++;
    while (jvi_ident((unsigned char)*p)) {
        if (n + 1 >= cap)
            return 0;
        name[n++] = *p++;
    }
    name[n] = '\0';
    *pp = p;
    return 1;
}

static int jvi_is_bare_decl(const char *line, char *name, size_t cap)
{
    const char *p = jvi_kw(jvi_skip_ht(line), "struct");
    if (!p)
        return 0;
    p = jvi_kw(p, "json_value");
    if (!p || !jvi_read_ident(&p, name, cap))
        return 0;
    p = jvi_skip_ht(p);
    if (*p != ';')
        return 0;
    return *jvi_skip_ht(p + 1) == '\0';
}

/* Two EREs, ported literally: [^A-Za-z_0-9]NAME[^A-Za-z_0-9] OR
 * [^A-Za-z_0-9]NAME$ — no start-of-line alternative. */
static int jvi_mentions_name(const char *line, const char *name)
{
    size_t nlen = strlen(name);
    for (size_t i = 0; line[i]; i++) {
        if (jvi_ident((unsigned char)line[i]))
            continue;
        if (strncmp(line + i + 1, name, nlen) != 0)
            continue;
        unsigned char after = (unsigned char)line[i + 1 + nlen];
        if (after == '\0' || !jvi_ident(after))
            return 1;
    }
    return 0;
}

/* comma=1: json_set_*([ \t]*&NAME[,)]  comma=0: fn([ \t]*&NAME[ \t]*) */
static int jvi_call_amp(const char *line, const char *fn, const char *name,
                        int comma)
{
    size_t fl = strlen(fn), nl = strlen(name);
    for (const char *p = line; *p; p++) {
        const char *q;
        if (strncmp(p, fn, fl) != 0 || p[fl] != '(')
            continue;
        q = jvi_skip_ht(p + fl + 1);
        if (*q != '&' || strncmp(q + 1, name, nl) != 0)
            continue;
        q += 1 + nl;
        if (comma) {
            if (*q == ',' || *q == ')')
                return 1;
            continue;
        }
        q = jvi_skip_ht(q);
        if (*q == ')')
            return 1;
    }
    return 0;
}

static int jvi_is_json_init_call(const char *line, const char *name)
{ return jvi_call_amp(line, "json_init", name, 0); }

static int jvi_is_flagged_call(const char *line, const char *name)
{
    static const char *const setfn[] = {
        "json_set_object", "json_set_array", "json_set_str", "json_set_int",
        "json_set_bool", "json_set_real", "json_set_null"
    };
    for (size_t i = 0; i < sizeof setfn / sizeof setfn[0]; i++) {
        if (jvi_call_amp(line, setfn[i], name, 1))
            return 1;
    }
    return jvi_call_amp(line, "json_free", name, 0);
}

static int jvi_pend_add(struct jvi_pend *p, const char *name, int line)
{
    for (int i = 0; i < p->n; i++) {
        if (strcmp(p->e[i].n, name) == 0) {
            p->e[i].line = line;
            return 0;
        }
    }
    if (p->n >= JVI_PEND || strlen(name) >= JVI_NAME)
        return die("z23-lint: json_value pending-name overflow\n", "");
    memcpy(p->e[p->n].n, name, strlen(name) + 1);
    p->e[p->n].line = line;
    p->n++;
    return 0;
}

static void jvi_pend_del(struct jvi_pend *p, int i)
{ p->e[i] = p->e[p->n - 1]; p->n--; }

static int jvi_hit(struct jvi_acc *a, const char *path, int line,
                   const char *name, const char *text)
{
    a->hits++;
    if (!a->emit)
        return 0;
    if (printf("%s:%d: %s -> %s\n", path, line, name, text) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int jvi_scan_line(struct jvi_acc *a, struct jvi_pend *p,
                         const char *path, int lineno, const char *line)
{
    char name[JVI_NAME];
    if (jvi_is_bare_decl(line, name, sizeof name))
        return jvi_pend_add(p, name, lineno);
    int rc = 0;
    for (int i = 0; rc == 0 && i < p->n; ) {
        const char *nm = p->e[i].n;
        if (!jvi_mentions_name(line, nm)) {
            i++;
            continue;
        }
        if (!jvi_is_json_init_call(line, nm) && jvi_is_flagged_call(line, nm))
            rc = jvi_hit(a, path, p->e[i].line, nm, line);
        jvi_pend_del(p, i);
    }
    return rc;
}

/* In-memory buffer scan (selftest fixtures are string literals, not temp files). */
static int jvi_scan_text(struct jvi_acc *a, const char *path, const char *text)
{
    struct jvi_pend pend = {0};
    int lineno = 1, rc = 0;
    const char *p = text;
    while (rc == 0 && *p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char buf[JVI_LINE];
        if (n >= sizeof buf)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(buf, p, n);
        buf[n] = '\0';
        rc = jvi_scan_line(a, &pend, path, lineno, buf);
        lineno++;
        if (!nl)
            break;
        p = nl + 1;
    }
    return rc;
}

static int jvi_scan_file(struct jvi_acc *a, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    struct jvi_pend pend = {0};
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        rc = jvi_scan_line(a, &pend, path, lineno, line);
    }
    return fin(f, line, path, rc);
}

static int jvi_on_path(const char *path, void *ctx)
{
    size_t n = strlen(path);
    if (n < 2 || path[n - 2] != '.' || path[n - 1] != 'c')
        return 0;
    struct jvi_acc *a = ctx;
    a->files++;
    return jvi_scan_file(a, path);
}

/* jvi_path_form/jvi_repo bodies live in the shared narrowing hooks
 * (lint_narrow_hook.h). */
static const char *jvi_path_form(const char *path, const char *repo)
{
    return lint_narrow_repo_form_opt(path, repo);
}

static int jvi_repo(const struct lint_changed *ch, char out[4096],
                    const char **repo)
{
    return lint_narrow_repo_opt(ch, out, repo);
}

struct jvi_selected {
    const struct lint_changed *ch;
    const char *repo;
    struct jvi_acc *acc;
    char last[RS_PATH];
};

static int jvi_changed_has(const struct jvi_selected *sel, const char *path)
{
    for (int i = 0; i < sel->ch->n; i++)
        if (strcmp(jvi_path_form(sel->ch->path[i], sel->repo), path) == 0)
            return 1;
    return 0;
}

static int jvi_selected_index(const char *path, int stage, void *vctx)
{
    struct jvi_selected *sel = vctx;
    (void)stage;
    if (!jvi_changed_has(sel, path) || strcmp(sel->last, path) == 0)
        return 0;
    int rc = jvi_on_path(path, sel->acc);
    if (rc == 0 && ovf(snprintf(sel->last, sizeof sel->last, "%s", path),
                       sizeof sel->last))
        return 2;
    return rc;
}

static int jvi_select(const struct lint_changed *ch, struct jvi_acc *a)
{
    char repo_buf[4096];
    const char *repo;
    if (jvi_repo(ch, repo_buf, &repo) != 0)
        return 2;
    struct jvi_selected sel = { .ch = ch, .repo = repo, .acc = a, .last = {0} };
    char bad[8] = {0};
    a->files = 0;
    if (lint_git_index_foreach(jvi_selected_index, &sel, bad) != 0) {
        fprintf(stderr, "check_json_value_init: UNPROVEN — git index%s%s\n",
                bad[0] ? " extension " : "", bad);
        return 2;
    }
    return lint_examined_print(a->files, 0) < 0 ? 2 : 0;
}

static int jvi_fail_msg(void)
{
    if (puts("FAIL: struct json_value used before it was initialised") == EOF
        || puts("  json_set_*() and json_free() release the value's PREVIOUS contents") == EOF
        || puts("  first, so on an uninitialised local they free/walk stack garbage.") == EOF
        || puts("  Declare it 'struct json_value x = {0};' or call json_init(&x) first") == EOF
        || puts("  (contract: platform/modules/json/include/json/json.h).") == EOF)
        return die("z23-lint: write failed\n", "");
    return 1;
}

int check_json_value_init_run(int argc, char **argv)
{
    struct lint_changed changed;
    if (lint_changed_bind(&argc, &argv, &changed) != 0)
        return 2;
    /* gate_commands.def still forwards the shell original's hyphenated flag. */
    if (argc >= 1 && strcmp(argv[0], "--self-test") == 0) {
        lint_changed_free(&changed);
        return check_json_value_init_selftest();
    }
    struct jvi_acc a = { .emit = 1 };
    int rc = changed.active ? jvi_select(&changed, &a)
                            : each_zpath(k_ls_all, jvi_on_path, &a);
    lint_changed_free(&changed);
    if (rc)
        return rc;
    if (a.hits)
        return jvi_fail_msg();
    if (puts("OK: check_json_value_init - every struct json_value local is initialised before use")
        == EOF)
        return die("z23-lint: write failed\n", "");
    return 0;
}

static int jvi_st_a(void)
{
    struct jvi_acc a = {0};
    static const char t[] =
        "void f(void) {\n"
        "    struct json_value arr;\n"
        "    json_set_array(&arr);\n"
        "}\n";
    if (jvi_scan_text(&a, "bad.c", t))
        return 1;
    return sh_want("check_json_value_init", a.hits, 1, "bare decl then json_set_array");
}

static int jvi_st_b(void)
{
    struct jvi_acc a = {0};
    static const char t[] =
        "void g(void) {\n"
        "    struct json_value arr = {0};\n"
        "    json_set_array(&arr);\n"
        "}\n";
    if (jvi_scan_text(&a, "good.c", t))
        return 1;
    return sh_want("check_json_value_init", a.hits, 0, "= {0} then json_set_array");
}

static int jvi_st_c(void)
{
    struct jvi_acc a = {0};
    static const char t[] =
        "void g(void) {\n"
        "    struct json_value obj;\n"
        "    json_init(&obj); json_set_object(&obj);\n"
        "}\n";
    if (jvi_scan_text(&a, "good.c", t))
        return 1;
    return sh_want("check_json_value_init", a.hits, 0,
                   "json_init then json_set_object on one line");
}

static int jvi_st_select(const char *root, const char *path, int want_rc,
                         int want_hits, int want_files)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd) || chdir(root) != 0)
        return 1;
    char *paths[] = { (char *)path };
    struct lint_changed one = { paths, 1, 1 };
    struct jvi_acc a = {0};
    int rc = jvi_select(&one, &a);
    if (chdir(cwd) != 0)
        return 1;
    int bad = rc != want_rc || a.hits != want_hits || a.files != want_files;
    if (bad)
        fprintf(stderr, "json narrowed case failed: %s rc=%d hits=%d files=%d\n",
                path, rc, a.hits, a.files);
    return bad;
}

static int jvi_st_git(const char *root)
{
    char quoted[8192], cmd[8192], out[1024];
    if (sh_single_quote(root, quoted, sizeof quoted) != 0 ||
        ovf(snprintf(cmd, sizeof cmd,
            "GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null "
            "git -C %s init -q . && git -C %s add -f -- .", quoted, quoted),
            sizeof cmd))
        return 1;
    int code = 0;
    return capture_cmd(cmd, out, sizeof out, &code) != 0 || code != 0;
}

static int jvi_st_conflict(const char *root)
{
    char quoted[8192], info[1024], cmd[8192];
    if (sh_single_quote(root, quoted, sizeof quoted) != 0)
        return 1;
    if (ovf(snprintf(cmd, sizeof cmd, "git -C %s ls-files -s -- engine/x/bad.c",
                     quoted), sizeof cmd))
        return 1;
    int code = 0;
    if (capture_cmd(cmd, info, sizeof info, &code) != 0 || code != 0 ||
        strlen(info) < 50 || memcmp(info, "100644 ", 7) != 0 ||
        info[47] != ' ' || info[48] != '0' || info[49] != '\t')
        return 1;
    char hash[41];
    memcpy(hash, info + 7, 40);
    hash[40] = '\0';
    if (ovf(snprintf(cmd, sizeof cmd,
        "git -C %s update-index --force-remove -- engine/x/bad.c && "
        "printf '100644 %s 1\\tengine/x/bad.c\\n100644 %s 2\\tengine/x/bad.c\\n"
        "100644 %s 3\\tengine/x/bad.c\\n' | git -C %s update-index --index-info",
        quoted, hash, hash, hash, quoted), sizeof cmd))
        return 1;
    return capture_cmd(cmd, info, sizeof info, &code) != 0 || code != 0;
}

static const char *const k_jvi_git_env[] = {
    "GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE", "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", NULL
};
struct jvi_st_env { char *value[6]; };

/* The save/clear/restore bodies live in the shared narrowing hooks
 * (lint_narrow_hook.h); the selftest keeps calling the jvi_* names. */
static int jvi_st_env_save(struct jvi_st_env *env)
{
    return lint_narrow_env_save(k_jvi_git_env, env->value,
                                (int)(sizeof env->value / sizeof env->value[0]));
}

static int jvi_st_env_clear(struct jvi_st_env *env)
{
    (void)env;
    return lint_narrow_env_clear(k_jvi_git_env,
                                 (int)(sizeof env->value / sizeof env->value[0]));
}

static int jvi_st_env_restore(struct jvi_st_env *env)
{
    return lint_narrow_env_restore(k_jvi_git_env, env->value,
                                   (int)(sizeof env->value /
                                         sizeof env->value[0]));
}

static int jvi_st_narrow(void)
{
    static const char bad_src[] =
        "void f(void) {\n    struct json_value arr;\n    json_set_array(&arr);\n}\n";
    static const char good_src[] = "int f(void) { return 0; }\n";
    char root[4096], bad_path[4096], good_path[4096], missing_path[4096];
    if (lint_mkdtemp(root, sizeof root, "jvi-narrow") != 0 ||
        ovf(snprintf(bad_path, sizeof bad_path, "%s/engine/x/bad.c", root),
            sizeof bad_path) ||
        ovf(snprintf(good_path, sizeof good_path, "%s/engine/x/good.c", root),
            sizeof good_path) ||
        ovf(snprintf(missing_path, sizeof missing_path, "%s/engine/x/missing.c", root),
            sizeof missing_path) ||
        csr_write(bad_path, bad_src) || csr_write(good_path, good_src) ||
        csr_write(missing_path, good_src))
        return 1;
    struct jvi_st_env env;
    if (jvi_st_env_save(&env)) {
        (void)rap_rm_rf(root);
        return 1;
    }
    int bad = jvi_st_env_clear(&env);
    if (!bad) {
        bad = jvi_st_git(root);
        bad |= jvi_st_select(root, "engine/x/bad.c", 0, 1, 1);
        bad |= jvi_st_select(root, "engine/x/good.c", 0, 0, 1);
        bad |= jvi_st_select(root, "docs/README.md", 0, 0, 0);
        bad |= unlink(missing_path) != 0;
        bad |= jvi_st_select(root, "engine/x/missing.c", 2, 0, 1);
        if (!bad)
            bad |= jvi_st_conflict(root);
        bad |= jvi_st_select(root, "engine/x/bad.c", 0, 1, 1);
    }
    bad |= rap_rm_rf(root);
    bad |= jvi_st_env_restore(&env);
    return bad;
}

int check_json_value_init_selftest(void)
{
    int bad = jvi_st_a() | jvi_st_b() | jvi_st_c() | jvi_st_narrow();
    return st_ok(bad,
                 "OK: check_json_value_init self-test (detects the bad shape, passes both good shapes)\n");
}

static const char *const k_owp_roots[] = {
    "core", "engine", "contexts", "cognition", "platform", "tools"
};

static int owp_skip_path(const char *path)
{
    if (lint_path_is_excluded(path) || strstr(path, "/test/"))
        return 1;
    return strncmp(path, "tools/scripts/", 14) == 0
        || strncmp(path, "tools/lint/", 11) == 0;
}

static int owp_collapse(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    int in_sp = 0;
    for (const char *p = in; *p; p++) {
        if (isspace((unsigned char)*p)) {
            if (in_sp)
                continue;
            if (o + 1 >= cap)
                return die("z23-lint: derived buffer overflow\n", "");
            out[o++] = ' ';
            in_sp = 1;
            continue;
        }
        if (o + 1 >= cap)
            return die("z23-lint: derived buffer overflow\n", "");
        out[o++] = *p;
        in_sp = 0;
    }
    out[o] = '\0';
    return 0;
}

static int owp_is_comment(const char *content)
{
    const char *t = content;
    while (*t && isspace((unsigned char)*t))
        t++;
    if (t[0] == '*')
        return 1;
    return t[0] == '/' && (t[1] == '/' || t[1] == '*');
}

static const char *owp_after_colons(const char *key)
{
    const char *p = strchr(key, ':');
    if (!p)
        return key;
    p = strchr(p + 1, ':');
    return p ? p + 1 : key;
}

static int owp_compile(struct owp_re *r)
{
    int rc = compile_pat(&r->a, REG_EXTENDED,
                         "active_chain_set_tip[[:space:]]*\\(|",
                         "coins_view_sqlite_batch_write(_ex)?[[:space:]]*\\(|",
                         "coins_view_cache_flush[[:space:]]*\\(", "");
    if (rc)
        return rc;
    /* connect_tip/disconnect_tip/process_new_block were in the shell
     * pattern this ported (./build/bin/z23-lint check-one-write-path) but
     * are themselves deleted engine entry points (see the stale[] list
     * in check_deleted_engine_names_file) — a .sh file was never walked
     * by that gate, but this .c file is, so naming them here trips it.
     * Dropped: none of the three exist as a live production call, so
     * this drops no real coverage. */
    rc = compile_pat(&r->b, REG_EXTENDED,
                     "utxo_projection_set_author[[:space:]]*\\(", "", "", "");
    if (rc) {
        regfree(&r->a);
        return rc;
    }
    rc = compile_pat(&r->mark, REG_EXTENDED,
                     "//[[:space:]]*one-write-path-ok:",
                     "[A-Za-z][A-Za-z0-9_-]*", "", "");
    if (rc) {
        regfree(&r->a);
        regfree(&r->b);
        return rc;
    }
    return 0;
}

static void owp_free(struct owp_re *r)
{ drop3(&r->a, &r->b, &r->mark); }

static int owp_pat_hit(const struct owp_re *r, const char *line)
{
    return regexec(&r->a, line, 0, NULL, 0) == 0
        || regexec(&r->b, line, 0, NULL, 0) == 0;
}

static int owp_make_key(const char *path, int lineno, const char *line,
                        char *key, size_t cap)
{
    char raw[OWP_KEY];
    if (ovf(snprintf(raw, sizeof raw, "%s:%d:%s", path, lineno, line),
            sizeof raw))
        return 2;
    return owp_collapse(raw, key, cap);
}

static int owp_base_has(const struct owp_acc *a, const char *key)
{
    for (int i = 0; i < a->nbase; i++) {
        if (strcmp(a->base[i], key) == 0)
            return 1;
    }
    return 0;
}

static int owp_add_hit(struct owp_acc *a, const char *key)
{
    if (a->nhit >= OWP_MAX || strlen(key) >= OWP_KEY)
        return die("z23-lint: one-write-path hit overflow\n", "");
    memcpy(a->hit[a->nhit], key, strlen(key) + 1);
    a->nhit++;
    return 0;
}

static int owp_consider(struct owp_acc *a, const char *path, int lineno,
                        const char *line)
{
    char key[OWP_KEY];
    int rc = owp_make_key(path, lineno, line, key, sizeof key);
    const char *content;
    if (rc)
        return rc;
    content = owp_after_colons(key);
    if (owp_is_comment(content))
        return 0;
    if (regexec(&a->re->mark, content, 0, NULL, 0) == 0)
        return 0;
    if (owp_base_has(a, key))
        return 0;
    return owp_add_hit(a, key);
}

static int owp_scan_text(struct owp_acc *a, const char *path, const char *text)
{
    int lineno = 1, rc = 0;
    const char *p = text;
    while (rc == 0 && *p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char buf[JVI_LINE];
        if (n >= sizeof buf)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(buf, p, n);
        buf[n] = '\0';
        if (owp_pat_hit(a->re, buf))
            rc = owp_consider(a, path, lineno, buf);
        lineno++;
        if (!nl)
            break;
        p = nl + 1;
    }
    return rc;
}

static int owp_scan_file(const char *path, struct owp_acc *a)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if (owp_pat_hit(a->re, line))
            rc = owp_consider(a, path, lineno, line);
    }
    return fin(f, line, path, rc);
}

static int owp_on_file(const char *path, void *ctx)
{
    struct owp_acc *a = ctx;
    if (owp_skip_path(path))
        return 0;
    a->nfiles++;
    return owp_scan_file(path, a);
}

static int owp_walk_roots(struct owp_acc *a, const char *const *roots, size_t n)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < n; i++)
        rc = walk_src(roots[i], 1, owp_on_file, a);
    return rc;
}

static int owp_walk(struct owp_acc *a)
{
    return owp_walk_roots(a, k_owp_roots,
                          sizeof k_owp_roots / sizeof k_owp_roots[0]);
}

/* ZCL_OWP_SCAN_ROOTS (space-separated) lets the meta-gate selftest point
 * this scan at a guaranteed-empty dir and prove the floor trips exit 2
 * instead of a hollow "clean" — same contract as the shell gate this
 * replaced. env is mutated in place (word-split like shell $SCAN_ROOTS);
 * caller owns buf's lifetime for as long as *out entries are read. */
static int owp_split_roots(char *env, const char *out[], size_t maxn,
                           size_t *nout)
{
    size_t n = 0;
    char *p = env;
    while (*p) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        if (n >= maxn)
            return 1;
        out[n++] = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        if (*p) {
            *p = '\0';
            p++;
        }
    }
    *nout = n;
    return 0;
}

static int owp_base_skip(const char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    return *s == '\0' || *s == '#';
}

static int owp_load_base(struct owp_acc *a)
{
    FILE *f = fopen("tools/scripts/one_write_path_baseline.txt", "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if (owp_base_skip(line))
            continue;
        if (a->nbase >= OWP_MAX || (size_t)n >= OWP_KEY) {
            rc = die("z23-lint: one-write-path baseline overflow\n", "");
            break;
        }
        memcpy(a->base[a->nbase], line, (size_t)n + 1);
        a->nbase++;
    }
    return fin(f, line, "tools/scripts/one_write_path_baseline.txt", rc);
}

static int owp_report(const struct owp_acc *a)
{
    int i;
    if (a->nhit == 0) {
        if (printf("check_one_write_path: clean — %d grandfathered write surface(s), no new ones\n",
                   a->nbase) < 0)
            return die("z23-lint: write failed\n", "");
        return 0;
    }
    if (puts("") == EOF
        || printf("check_one_write_path: %d NEW chain-state write surface(s)\n",
                  a->nhit) < 0
        || puts("") == EOF)
        return die("z23-lint: write failed\n", "");
    for (i = 0; i < a->nhit; i++) {
        if (printf("  %s\n", a->hit[i]) < 0)
            return die("z23-lint: write failed\n", "");
    }
    if (puts("") == EOF
        || puts("Consensus chain writes must collapse to the reducer/log path. Move the") == EOF
        || puts("write behind the existing reducer/stage path, delete the legacy writer,") == EOF
        || puts("or add a tightly-scoped '// one-write-path-ok:<tag>' marker only for a") == EOF
        || puts("non-authoritative compatibility wrapper.") == EOF)
        return die("z23-lint: write failed\n", "");
    return 1;
}

/* ZCL_OWP_SCAN_ROOTS override, when set and non-empty, replaces the
 * default root list AND drops the floor to 1 (a test-fed empty dir has
 * no 200-file production floor to meet) — the same SCAN_FLOOR_OVERRIDE
 * contract ./build/bin/z23-lint check-one-write-path used. */
static int owp_scan(struct owp_acc *a, int *floor_out)
{
    const char *env = getenv("ZCL_OWP_SCAN_ROOTS");
    if (!env || !env[0]) {
        *floor_out = OWP_FLOOR;
        return owp_walk(a);
    }
    static char buf[OWP_ROOT_BUF];
    if (snprintf(buf, sizeof buf, "%s", env) >= (int)sizeof buf)
        return die("z23-lint: ZCL_OWP_SCAN_ROOTS overflow\n", "");
    const char *roots[OWP_ROOT_MAX];
    size_t nroots = 0;
    if (owp_split_roots(buf, roots, OWP_ROOT_MAX, &nroots))
        return die("z23-lint: ZCL_OWP_SCAN_ROOTS names too many roots\n", "");
    *floor_out = 1;
    return owp_walk_roots(a, roots, nroots);
}

int check_one_write_path_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    struct owp_re r;
    int rc = owp_compile(&r);
    static struct owp_acc a;
    if (rc)
        return rc;
    memset(&a, 0, sizeof a);
    a.re = &r;
    rc = owp_load_base(&a);
    int floor = OWP_FLOOR;
    if (rc == 0)
        rc = owp_scan(&a, &floor);
    if (rc == 0)
        rc = gate_require_scanned(a.nfiles, floor, "check_one_write_path",
                                  "roots: core engine contexts cognition platform tools");
    if (rc == 0)
        rc = owp_report(&a);
    owp_free(&r);
    return rc;
}

static int owp_st_feed(struct owp_re *r, const char *line, const char *bkey,
                       int *nhit)
{
    static struct owp_acc a;
    memset(&a, 0, sizeof a);
    a.re = r;
    if (bkey) {
        if (strlen(bkey) >= OWP_KEY)
            return 1;
        memcpy(a.base[0], bkey, strlen(bkey) + 1);
        a.nbase = 1;
    }
    if (owp_scan_text(&a, "t.c", line))
        return 1;
    *nhit = a.nhit;
    return 0;
}

static int owp_st_a(struct owp_re *r)
{
    int n = 0;
    return owp_st_feed(r, "utxo_projection_set_author();\n", NULL, &n)
        || sh_want("check_one_write_path", n, 1, "bare utxo_projection_set_author is new");
}

static int owp_st_b(struct owp_re *r)
{
    int n = 0;
    return owp_st_feed(r, "utxo_projection_set_author(); // one-write-path-ok:test-tag\n", NULL, &n)
        || sh_want("check_one_write_path", n, 0, "inline marker suppresses");
}

static int owp_st_c(struct owp_re *r)
{
    int n = 0;
    return owp_st_feed(r, "    // utxo_projection_set_author();\n", NULL, &n)
        || sh_want("check_one_write_path", n, 0, "comment line is skipped");
}

static int owp_st_d(struct owp_re *r)
{
    int n = 0;
    return owp_st_feed(r, "utxo_projection_set_author();\n", "t.c:1:utxo_projection_set_author();", &n)
        || sh_want("check_one_write_path", n, 0, "baseline key is not re-flagged");
}

static int owp_st_e(void)
{
    int rc = gate_require_scanned(0, OWP_FLOOR, "check_one_write_path",
                                  "selftest hollow floor");
    return sh_want("check_one_write_path", rc != 0, 1,
                   "empty scan set refuses loud");
}

int check_one_write_path_selftest(void)
{
    struct owp_re r;
    int cr = owp_compile(&r);
    int bad;
    if (cr)
        return cr;
    bad = owp_st_a(&r) | owp_st_b(&r) | owp_st_c(&r) | owp_st_d(&r) | owp_st_e();
    owp_free(&r);
    return st_ok(bad, "OK: check_one_write_path selftest\n");
}
