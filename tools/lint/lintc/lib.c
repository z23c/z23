/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-lint — C23 replacements for tools/lint shell gates.
 * Invoke: z23-lint <gate-name> [--selftest] | z23-lint <gate-name> [args...] | --list
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"

const char k_ls_all[] = "git ls-files -z";
int die(const char *msg, const char *arg)
{
    fprintf(stderr, msg, arg);
    return 2;
}

int fin(FILE *f, char *line, const char *path, int rc)
{
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    free(line);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

int reg_fail(regex_t *re, int err)
{
    char msg[128];
    if (err == 0)
        return 0;
    (void)regerror(err, re, msg, sizeof msg);
    return die("z23-lint: regcomp failed: %s\n", msg);
}

int cmd_done(const char *cmd, int st, int allow_exit1)
{
    if (st == 0)
        return 0;
    if (allow_exit1 && st != -1 && WIFEXITED(st) && WEXITSTATUS(st) == 1)
        return 0;
    return die("z23-lint: command failed (%s)\n", cmd);
}

int each_zpath_st(const char *cmd, int allow_exit1,
                         int (*fn)(const char *, void *), void *ctx)
{
    FILE *pipe = popen(cmd, "r");
    if (!pipe)
        return die("z23-lint: popen failed (%s)\n", cmd);
    char *buf = NULL;
    size_t cap = 0;
    int rc = 0;
    ssize_t n;
    while ((n = getdelim(&buf, &cap, '\0', pipe)) >= 0) {
        if (n <= 0 || buf[0] == '\0')
            continue;
        rc = fn(buf, ctx);
        if (rc != 0)
            break;
    }
    if (rc == 0 && ferror(pipe))
        rc = die("z23-lint: read failed (%s)\n", cmd);
    free(buf);
    int st = pclose(pipe);
    if (rc != 0)
        return rc;
    return cmd_done(cmd, st, allow_exit1);
}

int each_zpath(const char *cmd, int (*fn)(const char *, void *), void *ctx)
{
    return each_zpath_st(cmd, 0, fn, ctx);
}
int replay(FILE *out)
{
    if (fseek(out, 0, SEEK_SET) != 0)
        return die("z23-lint: fseek failed\n", "");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, out)) >= 0) {
        if (fwrite(line, 1, (size_t)n, stderr) != (size_t)n) {
            free(line);
            return die("z23-lint: write failed\n", "");
        }
    }
    int err = ferror(out);
    free(line);
    return err ? die("z23-lint: read failed\n", "") : 0;
}

int st_ok(int bad, const char *msg)
{
    if (bad)
        return 1;
    fputs(msg, stdout);
    return 0;
}

int want(const char *tag, const regex_t *re, const char *s, int w)
{
    if ((regexec(re, s, 0, NULL, 0) == 0) != w) {
        fprintf(stderr, "%s selftest: want %d: %s\n", tag, w, s);
        return 1;
    }
    return 0;
}

void drop2(regex_t *a, regex_t *b) { regfree(a); regfree(b); }

int walk_src(const char *dir, int hdrs,
                    int (*scan)(const char *, void *), void *ctx)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char path[4096];
            struct stat st;
            size_t nl = strlen(name);
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", dir);
            else if (lstat(path, &st) != 0)
                rc = die("z23-lint: cannot stat %s\n", path);
            else if (S_ISDIR(st.st_mode))
                rc = walk_src(path, hdrs, scan, ctx);
            else if (S_ISREG(st.st_mode) && nl >= 2
                     && ((hdrs == 2 && nl >= 4 && memcmp(name + nl - 4, ".def", 4) == 0)
                         || (hdrs != 2 && name[nl - 2] == '.'
                             && (name[nl - 1] == 'c' || (hdrs && name[nl - 1] == 'h')))))
                rc = scan(path, ctx);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

int compile_pat(regex_t *re, int flags, const char *a, const char *b,
                       const char *c, const char *d)
{
    char pat[160];
    int n = snprintf(pat, sizeof pat, "%s%s%s%s", a, b, c, d);
    if (n < 0 || (size_t)n >= sizeof pat)
        return die("z23-lint: pattern buffer overflow\n", "");
    return reg_fail(re, regcomp(re, pat, flags));
}

int pair_comp(regex_t *a, int fa, const char *a0, const char *a1,
                     const char *a2, const char *a3, regex_t *b, int fb,
                     const char *b0, const char *b1, const char *b2, const char *b3)
{
    int cr = compile_pat(a, fa, a0, a1, a2, a3);
    if (cr)
        return cr;
    cr = compile_pat(b, fb, b0, b1, b2, b3);
    if (cr)
        regfree(a);
    return cr;
}

int miss(const char *path, FILE *out, const char *fmt)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        if (errno != ENOENT)
            return die("z23-lint: cannot stat %s\n", path);
    } else if (S_ISREG(st.st_mode))
        return 0;
    fprintf(out, fmt, path);
    return 1;
}

int scan_re(const char *path, const regex_t *re, int *hits, int show)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        if (regexec(re, line, 0, NULL, 0) != 0)
            continue;
        (*hits)++;
        if (!show)
            break;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (fprintf(stdout, "%s:%d:%s\n", path, lineno, line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    }
    return fin(f, line, path, rc);
}

void drop3(regex_t *a, regex_t *b, regex_t *c)
{
    drop2(a, b);
    regfree(c);
}

/* C scan_exclusions/repo_shape/gate_lib bits. Non-parity: no ZCL_GATE_SCAN_LOG. */
const char k_planted[] = "tools/lint/fixtures/planted";
static regex_t g_excl_re;
int g_excl_ok, g_n_ctx, g_n_shapes, g_n_libs, g_n_mods, g_n_auth, g_rs_ready;
char g_ctx[RS_MAX][RS_NAME], g_shapes[RS_SHAPE][RS_NAME];
char g_libs[RS_MAX][RS_NAME], g_mods[RS_MAX][RS_PATH], g_auth[RS_AUTH][RS_PATH];
const char *const k_domain[] = {
    "contexts/wallet/domain", "platform/domain/encoding"
};

int ovf(int n, size_t cap)
{ return (n < 0 || (size_t)n >= cap) ? die("z23-lint: derived buffer overflow\n", "") : 0; }
int rs_ovf(void) { return die("z23-lint: repo-shape overflow\n", ""); }
static const char *rs_root(void)
{ const char *e = getenv("ZCL_REPO_SHAPE_ROOT"); return (e && e[0]) ? e : "."; }
int lint_prod_scan(void)
{ const char *e = getenv("ZCL_LINT_PRODUCTION_SCAN"); return e && strcmp(e, "1") == 0; }

int excl_ensure(void)
{
    if (g_excl_ok) return 0;
    char pat[256];
    int n = snprintf(pat, sizeof pat, "%s|%s%s%s%s%s",
                     "(^|/)_[^/]*fixture[^/]*\\.[ch]$", "(^|/)", k_planted,
                     "/|(^|/)build/|(^|/)vendor/|(^|/)\\.claude/",
                     "|(^|/)test-tmp/", "");
    if (ovf(n, sizeof pat)) return 2;
    int err = reg_fail(&g_excl_re, regcomp(&g_excl_re, pat, REG_EXTENDED));
    return err ? err : (g_excl_ok = 1, 0);
}

int lint_path_is_excluded(const char *path)
{ return lint_prod_scan() && !excl_ensure() && regexec(&g_excl_re, path, 0, NULL, 0) == 0; }

int lint_filter_excluded(const char *in, char *out, size_t cap)
{
    if (!lint_prod_scan())
        return ovf(snprintf(out, cap, "%s", in), cap);
    if (excl_ensure()) return 2;
    size_t used = 0;
    out[0] = '\0';
    for (const char *p = in; *p; ) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[4096];
        if (n >= sizeof line) return die("z23-lint: derived buffer overflow\n", "");
        memcpy(line, p, n);
        line[n] = '\0';
        if (regexec(&g_excl_re, line, 0, NULL, 0) != 0) {
            int k = snprintf(out + used, cap - used, "%s%s", line, nl ? "\n" : "");
            if (ovf(k, cap - used)) return 2;
            used += (size_t)k;
        }
        p = nl ? nl + 1 : p + n;
        if (!nl) break;
    }
    return 0;
}

int lint_annotate_stray(const char *path, FILE *out)
{
    char cmd[4096];
    if (ovf(snprintf(cmd, sizeof cmd, "git ls-files --error-unmatch -- %s", path),
            sizeof cmd))
        return 2;
    FILE *p = popen(cmd, "r");
    if (!p) return die("z23-lint: popen failed (%s)\n", cmd);
    char *buf = NULL;
    size_t cap = 0;
    while (getline(&buf, &cap, p) >= 0) { }
    free(buf);
    int st = pclose(p);
    if (st == 0)
        return fputs(path, out) < 0 ? die("z23-lint: write failed\n", "") : 0;
    return fprintf(out, "%s [untracked stray file -- not a code violation; "
                   "likely left by a crashed agent/worktree, delete it]", path) < 0
               ? die("z23-lint: write failed\n", "") : 0;
}

int gate_require_scanned(int count, int floor, const char *name,
                                const char *hint)
{
    if (count >= floor) return 0;
    fprintf(stderr, "%s: FATAL — scan set is '%d' (< floor %d).\n", name, count, floor);
    fputs("  The scan producer (find/glob/grep) returned too little; a\n"
          "  scanned dir/file was likely renamed, moved, or deleted.\n"
          "  Refusing to report 'clean' off a hollow (empty) scan.\n", stderr);
    if (hint && hint[0]) fprintf(stderr, "  %s\n", hint);
    return 2;
}

int gate_count_and_report(const char *matches, int *out_count)
{
    *out_count = 0;
    if (!matches) return 0;
    int any = 0;
    for (const char *s = matches; *s; s++)
        if (!isspace((unsigned char)*s)) { any = 1; break; }
    if (!any) return 0;
    for (const char *p = matches; *p; ) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n > 0) {
            (*out_count)++;
            if (fwrite(p, 1, n, stderr) != n || fputc('\n', stderr) == EOF)
                return die("z23-lint: write failed\n", "");
        }
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

static int rs_continues(const char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' '
                 || s[n - 1] == '\t'))
        n--;
    return n && s[n - 1] == '\\';
}

static int rs_emit(char *line, char dst[][RS_NAME], int max, int *n)
{
    char *hash = strchr(line, '#');
    if (hash) *hash = '\0';
    for (char *q = line; *q; q++) if (*q == '\\') *q = ' ';
    *n = 0;
    for (char *p = line; *p; ) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (!*p) break;
        char *s = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
        char save = *p;
        *p = '\0';
        if (*n >= max || strlen(s) >= RS_NAME) return rs_ovf();
        memcpy(dst[*n], s, strlen(s) + 1);
        (*n)++;
        *p = save;
        if (save) p++;
    }
    return 0;
}

static int rs_make_list(const char *variable, char dst[][RS_NAME], int max, int *n)
{
    const char *mk = getenv("ZCL_REPO_SHAPE_MAKEFILE");
    char path[4096];
    if (!mk || !mk[0]) {
        if (ovf(snprintf(path, sizeof path, "%s/Makefile", rs_root()), sizeof path))
            return 2;
        mk = path;
    }
    FILE *f = fopen(mk, "r");
    if (!f) return die("z23-lint: cannot open %s\n", mk);
    char *line = NULL, assembled[8192];
    size_t cap = 0, alen = strlen(variable);
    int found = 0, rc = 0;
    assembled[0] = '\0';
    while (getline(&line, &cap, f) >= 0) {
        if (!found) {
            if (strncmp(line, variable, alen) != 0) continue;
            const char *p = line + alen;
            while (*p == ' ' || *p == '\t') p++;
            if (*p != '=') continue;
            found = 1;
            if (ovf(snprintf(assembled, sizeof assembled, "%s", p + 1), sizeof assembled)) {
                rc = 2; break;
            }
            if (!rs_continues(line)) break;
            continue;
        }
        size_t used = strlen(assembled);
        int k = snprintf(assembled + used, sizeof assembled - used, " %s", line);
        if (ovf(k, sizeof assembled - used)) { rc = 2; break; }
        if (!rs_continues(line)) break;
    }
    if (rc == 0) rc = found ? rs_emit(assembled, dst, max, n) : (*n = 0, 0);
    return fin(f, line, mk, rc);
}

static int rs_cmp_name(const void *a, const void *b) { return strcmp(a, b); }

static int rs_uniq(void *arr, int n, size_t stride)
{
    if (n <= 1) return n;
    qsort(arr, (size_t)n, stride, rs_cmp_name);
    int w = 1;
    char *base = arr;
    for (int i = 1; i < n; i++) {
        if (strcmp(base + (size_t)i * stride, base + (size_t)(w - 1) * stride) != 0) {
            if (w != i)
                memcpy(base + (size_t)w * stride, base + (size_t)i * stride, stride);
            w++;
        }
    }
    return w;
}

static const char *rs_env_or(const char *env, char *buf, size_t cap, const char *fmt)
{
    const char *e = getenv(env);
    if (e && e[0]) return e;
    return ovf(snprintf(buf, cap, fmt, rs_root()), cap) ? NULL : buf;
}

static int rs_lib_modules(void)
{
    char path[4096];
    const char *md = rs_env_or("ZCL_REPO_SHAPE_MODULE_DEF", path, sizeof path,
                               "%s/engine/composition/lib_module_order.def");
    if (!md) return 2;
    FILE *f = fopen(md, "r");
    if (!f) return die("z23-lint: cannot open %s\n", md);
    char *line = NULL;
    size_t cap = 0;
    g_n_libs = 0;
    int rc = 0;
    while (getline(&line, &cap, f) >= 0) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "LIB_MODULE(\"", 12) != 0) continue;
        p += 12;
        char *e = p;
        while ((*e >= 'A' && *e <= 'Z') || (*e >= 'a' && *e <= 'z')
               || (*e >= '0' && *e <= '9') || *e == '_')
            e++;
        if (*e != '"' || e[1] != ')' ) continue;
        size_t n = (size_t)(e - p);
        if (g_n_libs >= RS_MAX || n >= RS_NAME) { rc = rs_ovf(); break; }
        memcpy(g_libs[g_n_libs], p, n);
        g_libs[g_n_libs][n] = '\0';
        g_n_libs++;
    }
    rc = fin(f, line, md, rc);
    if (rc) return rc;
    g_n_libs = rs_uniq(g_libs, g_n_libs, RS_NAME);
    return 0;
}

static int rs_is_module_dir(const char *rel)
{
    const char *slash = strrchr(rel, '/');
    if (!slash || slash == rel || slash[1] == '\0') return 0;
    if (slash >= rel + 8 && strncmp(slash - 8, "/modules", 8) == 0) return 1;
    return strncmp(rel, "modules/", 8) == 0 && strchr(rel + 8, '/') == NULL;
}

static int rs_mod_walk(const char *dir, int depth)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return (errno == ENOENT || errno == EACCES) ? 0
            : die("z23-lint: cannot scan %s\n", dir);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") && strcmp(name, "..")) {
            char path[4096];
            struct stat st;
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (ovf(k, sizeof path)) rc = 2;
            else if (lstat(path, &st) != 0)
                rc = (errno == ENOENT || errno == EACCES) ? 0
                    : die("z23-lint: cannot stat %s\n", path);
            else if (S_ISDIR(st.st_mode)) {
                int nd = depth + 1;
                if (nd >= 2 && nd <= 4) {
                    const char *root = rs_root();
                    size_t rl = strlen(root);
                    const char *rel = (strncmp(path, root, rl) == 0 && path[rl] == '/')
                        ? path + rl + 1 : path;
                    if (rs_is_module_dir(rel)) {
                        if (g_n_mods >= RS_MAX || strlen(rel) >= RS_PATH) rc = rs_ovf();
                        else { memcpy(g_mods[g_n_mods], rel, strlen(rel) + 1); g_n_mods++; }
                    }
                }
                if (rc == 0 && nd < 4) rc = rs_mod_walk(path, nd);
            }
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int rs_isdir(const char *rel)
{
    char path[4096];
    struct stat st;
    if (ovf(snprintf(path, sizeof path, "%s/%s", rs_root(), rel), sizeof path))
        return 0;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int rs_put(char out[][RS_PATH], int max, int *n, const char *base,
                  const char *leaf)
{
    char path[RS_PATH];
    int k = (leaf && leaf[0]) ? snprintf(path, sizeof path, "%s/%s", base, leaf)
                              : snprintf(path, sizeof path, "%s", base);
    if (ovf(k, sizeof path)) return 2;
    if (!rs_isdir(path)) return 0;
    if (*n >= max) return rs_ovf();
    memcpy(out[*n], path, strlen(path) + 1);
    (*n)++;
    return 0;
}

int rs_init(void)
{
    if (g_rs_ready) return 0;
    char mk[4096], md[4096];
    const char *mkp = rs_env_or("ZCL_REPO_SHAPE_MAKEFILE", mk, sizeof mk, "%s/Makefile");
    const char *mdp = rs_env_or("ZCL_REPO_SHAPE_MODULE_DEF", md, sizeof md,
                                "%s/engine/composition/lib_module_order.def");
    if (!mkp || !mdp) return 2;
    FILE *fm = fopen(mkp, "r"), *fd = fopen(mdp, "r");
    if (!fm || !fd) {
        if (fm) fclose(fm);
        if (fd) fclose(fd);
        fputs("repo-shape: FATAL — architecture declarations are unreadable\n", stderr);
        return 2;
    }
    fclose(fm); fclose(fd);
    int rc = rs_make_list("PRODUCT_CONTEXTS", g_ctx, RS_MAX, &g_n_ctx);
    if (rc == 0) rc = rs_make_list("APP_DIRS", g_shapes, RS_SHAPE, &g_n_shapes);
    if (rc == 0) rc = rs_lib_modules();
    if (rc == 0)
        rc = gate_require_scanned(g_n_ctx, 1, "repo-shape",
                                  "PRODUCT_CONTEXTS parse came back empty");
    if (rc == 0)
        rc = gate_require_scanned(g_n_shapes, 1, "repo-shape",
                                  "APP_DIRS parse came back empty");
    if (rc == 0)
        rc = gate_require_scanned(g_n_libs, 1, "repo-shape",
                                  "module declaration parse came back empty");
    g_n_mods = 0;
    static const char *const auth[] = {
        "core", "engine", "cognition", "platform", "contexts"
    };
    for (size_t i = 0; rc == 0 && i < sizeof auth / sizeof auth[0]; i++) {
        char start[4096];
        if (ovf(snprintf(start, sizeof start, "%s/%s", rs_root(), auth[i]), sizeof start))
            return 2;
        rc = rs_mod_walk(start, 0);
    }
    if (rc) return rc;
    g_n_mods = rs_uniq(g_mods, g_n_mods, RS_PATH);
    rc = gate_require_scanned(g_n_mods, g_n_libs, "repo-shape",
                              "physical module directory set is incomplete");
    if (rc) return rc;
    memcpy(g_auth[0], "engine", 7);
    memcpy(g_auth[1], "cognition", 10);
    g_n_auth = 2;
    for (int i = 0; i < g_n_ctx; i++) {
        if (g_n_auth >= RS_AUTH) return rs_ovf();
        if (ovf(snprintf(g_auth[g_n_auth], RS_PATH, "contexts/%s", g_ctx[i]), RS_PATH))
            return 2;
        g_n_auth++;
    }
    g_rs_ready = 1;
    return 0;
}

int repo_shape_dirs(const char *family, const char *leaf,
                           char out[][RS_PATH], int max, int *n)
{
    int rc = rs_init();
    if (rc) return rc;
    *n = 0;
    if (strcmp(family, "app") == 0) {
        for (int a = 0; rc == 0 && a < g_n_auth; a++)
            for (int s = 0; rc == 0 && s < g_n_shapes; s++) {
                char base[RS_PATH];
                if (ovf(snprintf(base, sizeof base, "%s/%s", g_auth[a], g_shapes[s]),
                        sizeof base))
                    return 2;
                rc = rs_put(out, max, n, base, leaf);
            }
        return rc;
    }
    if (strcmp(family, "lib") == 0) {
        for (int i = 0; rc == 0 && i < g_n_mods; i++)
            rc = rs_put(out, max, n, g_mods[i], leaf);
        return rc;
    }
    if (strcmp(family, "domain") == 0) {
        for (size_t i = 0; rc == 0 && i < sizeof k_domain / sizeof k_domain[0]; i++)
            rc = rs_put(out, max, n, k_domain[i], leaf);
        return rc;
    }
    fprintf(stderr, "repo_shape_dirs: FATAL — unknown family '%s'\n", family);
    return 2;
}

int repo_shape_room_dirs(const char *shape, char out[][RS_PATH], int max,
                                int *n)
{
    int rc = rs_init();
    if (rc) return rc;
    *n = 0;
    for (int i = 0; rc == 0 && i < g_n_auth; i++)
        rc = rs_put(out, max, n, g_auth[i], shape);
    if (rc) return rc;
    if (*n == 0) {
        fprintf(stderr, "repo_shape_room_dirs: FATAL — no '%s' room exists\n", shape);
        return 2;
    }
    return 0;
}
const char *clock_mode(void)
{ const char *m = getenv("ZCL_LINT_MODE"); return (m && m[0]) ? m : "FAIL"; }
int clock_grade(int v, const char *mode)
{ return (v > 0 && strcmp(mode, "FAIL") == 0) ? 1 : 0; }
int sr_has(const struct sr_set *s, const char *name)
{ for (int i = 0; i < s->count; i++) if (!strcmp(s->n[i], name)) return 1; return 0; }

int sr_add(struct sr_set *s, const char *name)
{
    size_t n = strlen(name);
    if (sr_has(s, name)) return 0;
    if (s->count >= SR_ALLOW || n >= SR_NAME) return die("z23-lint: stray-root overflow\n", "");
    memcpy(s->n[s->count++], name, n + 1);
    return 0;
}

int sr_load(struct sr_set *s, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        char *h = strchr(line, '#'), *p = line;
        if (h) *h = '\0';
        while (*p && isspace((unsigned char)*p)) p++;
        size_t n = strlen(p);
        while (n && isspace((unsigned char)p[n - 1])) p[--n] = '\0';
        if (n) rc = sr_add(s, p);
    }
    return fin(f, line, path, rc);
}

int capture_cmd(const char *cmd, char *out, size_t cap, int *code)
{
    FILE *p = popen(cmd, "r");
    if (!p)
        return die("z23-lint: popen failed (%s)\n", cmd);
    size_t used = 0;
    out[0] = '\0';
    int rc = 0;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, p)) > 0) {
        if (used + n >= cap) {
            rc = die("z23-lint: derived buffer overflow\n", "");
            break;
        }
        memcpy(out + used, buf, n);
        used += n;
        out[used] = '\0';
    }
    if (rc == 0 && ferror(p))
        rc = die("z23-lint: read failed (%s)\n", cmd);
    int st = pclose(p);
    if (rc)
        return rc;
    while (used && out[used - 1] == '\n')
        out[--used] = '\0';
    if (st == -1)
        *code = 127;
    else if (WIFEXITED(st))
        *code = WEXITSTATUS(st);
    else
        *code = 127;
    return 0;
}

int csr_mkdirs(const char *path)
{
    char buf[4096];
    if (ovf(snprintf(buf, sizeof buf, "%s", path), sizeof buf))
        return 2;
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            return die("z23-lint: mkdir failed: %s\n", buf);
        *p = '/';
    }
    if (mkdir(buf, 0700) != 0 && errno != EEXIST)
        return die("z23-lint: mkdir failed: %s\n", buf);
    return 0;
}

int csr_write(const char *path, const char *text)
{
    char dir[4096];
    const char *slash = strrchr(path, '/');
    if (!slash)
        return die("z23-lint: path too long: %s\n", path);
    size_t n = (size_t)(slash - path);
    if (n >= sizeof dir)
        return die("z23-lint: path too long: %s\n", path);
    memcpy(dir, path, n);
    dir[n] = '\0';
    int rc = csr_mkdirs(dir);
    if (rc)
        return rc;
    FILE *f = fopen(path, "w");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    size_t len = strlen(text);
    rc = fwrite(text, 1, len, f) != len;
    if (fclose(f) != 0 && rc == 0)
        return die("z23-lint: fclose failed: %s\n", path);
    return rc ? die("z23-lint: write failed\n", "") : 0;
}

int csr_slurp(FILE *f, char *buf, size_t cap)
{
    rewind(f);
    size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    return ferror(f) ? die("z23-lint: read failed\n", "") : 0;
}

int psp_st_reset(FILE *out)
{
    rewind(out);
    return ftruncate(fileno(out), 0) != 0;
}

int rap_rm_rf(const char *root)
{
    char cmd[8192], dump[64];
    int code = 0;
    if (strchr(root, '\''))
        return die("z23-lint: path too long: %s\n", root);
    if (ovf(snprintf(cmd, sizeof cmd, "rm -rf -- '%s'", root), sizeof cmd))
        return 2;
    return capture_cmd(cmd, dump, sizeof dump, &code);
}

int sh_single_quote(const char *in, char *out, size_t cap)
{
    size_t used = 0;
    if (cap < 3)
        return die("z23-lint: derived buffer overflow\n", "");
    out[used++] = '\'';
    for (const char *p = in; *p; p++) {
        if (*p == '\'') {
            if (used + 4 >= cap)
                return die("z23-lint: derived buffer overflow\n", "");
            out[used++] = '\'';
            out[used++] = '\\';
            out[used++] = '\'';
            out[used++] = '\'';
        } else {
            if (used + 2 > cap)
                return die("z23-lint: derived buffer overflow\n", "");
            out[used++] = *p;
        }
    }
    if (used + 2 > cap)
        return die("z23-lint: derived buffer overflow\n", "");
    out[used++] = '\'';
    out[used] = '\0';
    return 0;
}

/* The program's own absolute path, derived from argv[0] exactly the way the
 * shell gates derive SCRIPT_DIR — `cd "$(dirname "$0")" && pwd` — by entering
 * the directory and reading the working directory back. Every caller reaches
 * this binary through the tools/lint shim, which always passes a path with a
 * directory part; a bare name (found via PATH) is refused. No /proc read. */
const char *g_lint_argv0;

int lint_self_exe(char *buf, size_t cap)
{
    const char *a0 = g_lint_argv0;
    const char *slash = a0 ? strrchr(a0, '/') : NULL;
    char dir[4096], here[4096], there[4096];
    if (!slash || cap == 0)
        return die("z23-lint: cannot resolve executable path\n", "");
    size_t dlen = slash == a0 ? 1 : (size_t)(slash - a0);
    if (dlen >= sizeof dir || !getcwd(here, sizeof here))
        return die("z23-lint: cannot resolve executable path\n", "");
    memcpy(dir, a0, dlen);
    dir[dlen] = '\0';
    int ok = chdir(dir) == 0 && getcwd(there, sizeof there) != NULL;
    if (chdir(here) != 0)
        return die("z23-lint: cannot restore working directory\n", "");
    if (!ok)
        return die("z23-lint: cannot resolve executable path\n", "");
    int n = snprintf(buf, cap, "%s/%s", there, slash + 1);
    if (n < 0 || (size_t)n >= cap)
        return die("z23-lint: cannot resolve executable path\n", "");
    return 0;
}

const char *env_or(const char *name, const char *fallback)
{
    const char *e = getenv(name);
    return (e && e[0]) ? e : fallback;
}

int cic_repo_root(char *buf, size_t cap)
{
    if (lint_self_exe(buf, cap))
        return 2;
    /* $ROOT/build/bin/z23-lint → $ROOT (executable dir, then two parents). */
    for (int i = 0; i < 3; i++) {
        char *slash = strrchr(buf, '/');
        if (!slash || slash == buf)
            return die("z23-lint: cannot resolve executable path\n", "");
        *slash = '\0';
    }
    return 0;
}

int cic_invoke(const char *gate, int merge_err, char *out, size_t cap,
                      int *code)
{
    char exe[4096], quoted[8192], cmd[8192];
    if (lint_self_exe(exe, sizeof exe)
        || sh_single_quote(exe, quoted, sizeof quoted)
        || ovf(snprintf(cmd, sizeof cmd, "%s %s%s", quoted, gate,
                        merge_err ? " 2>&1" : ""), sizeof cmd))
        return 2;
    return capture_cmd(cmd, out, cap, code);
}
