/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the per-translation-unit result cache for the
 * check-clang-portability gate port. Ported from tools/lint/tu_result_cache.sh
 * (deleted): the include-set digest, salt derivation, the parent-side plan
 * pass that replays hits into the gate's own artifact paths, and the worker
 * compile that stores each miss. Fail-safe, never fail-open.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_clang_portability_priv.h"

static const char k_cpc_gate[] = "check-clang-portability";

/* Growable set of heap strings. The include walk is unbounded (the tree holds
 * thousands of headers), so nothing in the digest may cap or truncate it:
 * a silent cap would switch the cache off on every real run. */
struct cp_vec {
    char **v;
    size_t n, cap;
};

static int cp_vec_add(struct cp_vec *s, const char *p)
{
    if (s->n == s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 1024;
        char **nv = realloc(s->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv)
            return -1;
        s->v = nv;
        s->cap = nc;
    }
    char *d = strdup(p);
    if (!d)
        return -1;
    s->v[s->n++] = d;
    return 0;
}

static void cp_vec_sort_uniq(struct cp_vec *s)
{
    if (s->n > 1)
        qsort(s->v, s->n, sizeof *s->v, lintc_strcmp_ptr);
    size_t w = 0;
    for (size_t i = 0; i < s->n; i++) {
        if (w && !strcmp(s->v[w - 1], s->v[i]))
            free(s->v[i]);
        else
            s->v[w++] = s->v[i];
    }
    s->n = w;
}

static int cp_ext_is(const char *name, const char *ext)
{
    size_t l = strlen(name), e = strlen(ext);
    return l > e && !strcmp(name + l - e, ext);
}

static int cp_hdr_ext(const char *name)
{
    return cp_ext_is(name, ".h") || cp_ext_is(name, ".inc") ||
           cp_ext_is(name, ".def");
}

static int cp_name_ok(const char *p)
{
    for (const unsigned char *u = (const unsigned char *)p; *u; u++)
        if (isspace(*u) || *u == '\\')
            return 0;
    return 1;
}


struct cp_walk {
    const char *root;
    struct cp_vec all;
};

/* Prune list mirrors tu_result_cache.sh: root-relative paths only. */
static int cp_pruned(const struct cp_walk *w, const char *sub)
{
    static const char *const bad[] = { ".git", "build", "test-tmp", ".claude",
                                       ".cache", "vendor/tor" };
    size_t rl = strlen(w->root);
    if (strncmp(sub, w->root, rl) != 0 || sub[rl] != '/')
        return 0;
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        if (!strcmp(sub + rl + 1, bad[i]))
            return 1;
    return 0;
}

static int cp_walk_dir(struct cp_walk *w, const char *dir);

static int cp_walk_entry(struct cp_walk *w, const char *dir, const char *name)
{
    char sub[CP_PATH];
    struct stat st;
    if (ovf(snprintf(sub, sizeof sub, "%s/%s", dir, name), sizeof sub))
        return -1;
    if (lstat(sub, &st) != 0)
        return 0;
    if (S_ISDIR(st.st_mode))
        return cp_pruned(w, sub) ? 0 : cp_walk_dir(w, sub);
    if (S_ISREG(st.st_mode) && (cp_hdr_ext(name) || cp_ext_is(name, ".c")))
        return cp_vec_add(&w->all, sub);
    return 0;
}

static int cp_walk_dir(struct cp_walk *w, const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    struct dirent *e;
    int rc = 0;
    while (rc == 0 && (e = readdir(d)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
            rc = cp_walk_entry(w, dir, e->d_name);
    closedir(d);
    return rc;
}

/* One line's first `#include "...c"` target basename, if any. */
static int cp_inc_line(const regex_t *re, const char *line, struct cp_vec *names)
{
    regmatch_t m[1];
    char tok[CP_PATH];
    if (regexec(re, line, 1, m, 0) != 0)
        return 0;
    size_t l = (size_t)(m[0].rm_eo - m[0].rm_so);
    if (l >= sizeof tok)
        return 0;
    memcpy(tok, line + m[0].rm_so, l);
    tok[l] = '\0';
    char *q1 = strchr(tok, '"');
    char *q2 = strrchr(tok, '"');
    if (!q1 || q2 == q1)
        return 0;
    *q2 = '\0';
    const char *sl = strrchr(q1 + 1, '/');
    return cp_vec_add(names, sl ? sl + 1 : q1 + 1);
}

/* Sorted basenames of *.c files that some file textually #includes. */
static int cp_included_c(const struct cp_vec *all, struct cp_vec *names)
{
    regex_t re;
    if (cp_regcomp(&re, "#[[:space:]]*include[[:space:]]*\"[^\"]*\\.c\"",
                   REG_EXTENDED))
        return -1;
    char line[CP_LINE];
    int rc = 0;
    for (size_t i = 0; i < all->n && rc == 0; i++) {
        FILE *f = fopen(all->v[i], "r");
        if (!f)
            continue;
        while (rc == 0 && fgets(line, sizeof line, f))
            rc = cp_inc_line(&re, line, names);
        fclose(f);
    }
    regfree(&re);
    cp_vec_sort_uniq(names);
    return rc;
}

/* Every header by extension plus every .c some file includes (matched by
 * basename: a deliberate superset that can only over-invalidate). */
static int cp_digest_list(const struct cp_vec *all, struct cp_vec *list)
{
    struct cp_vec names = { 0 };
    int rc = cp_included_c(all, &names);
    for (size_t i = 0; i < all->n && rc == 0; i++) {
        const char *p = all->v[i];
        const char *sl = strrchr(p, '/');
        const char *base = sl ? sl + 1 : p;
        if (!cp_name_ok(p))
            rc = 1;
        else if (cp_hdr_ext(p) ||
                 bsearch(&base, names.v, names.n, sizeof *names.v, lintc_strcmp_ptr))
            rc = cp_vec_add(list, p);
    }
    lintc_strv_free(names.v, names.n);
    cp_vec_sort_uniq(list);
    return rc;
}

/* The sorted include set under root, after the selftest's vanish hook. */
static int cp_digest_collect(const char *root, const char *vanish,
                             struct cp_vec *list)
{
    struct cp_walk w = { .root = root };
    int rc = cp_walk_dir(&w, root);
    if (rc == 0 && w.all.n == 0)
        rc = 1;
    if (rc == 0)
        rc = cp_digest_list(&w.all, list);
    lintc_strv_free(w.all.v, w.all.n);
    if (rc == 0 && list->n == 0)
        rc = 1;
    if (rc == 0 && vanish && unlink(vanish) != 0)
        rc = 1;
    return rc;
}

/* "path\tsha" per file. A path that vanished since the walk is dropped; any
 * other read error refuses the digest, naming the file. */
static int cp_digest_lines(const struct cp_vec *list, const char *tmp,
                           size_t *nlines)
{
    FILE *f = fopen(tmp, "wb");
    if (!f)
        return 1;
    int rc = 0;
    *nlines = 0;
    for (size_t i = 0; i < list->n && rc == 0; i++) {
        char h[CP_SHA];
        int r = cp_sha256_file(list->v[i], h);
        if (r == 1)
            continue;
        if (r != 0) {
            fprintf(stderr, "tu_cache_include_digest: cannot read '%s': %s\n",
                    list->v[i], strerror(errno));
            rc = 1;
        } else {
            fprintf(f, "%s\t%s\n", list->v[i], h);
            (*nlines)++;
        }
    }
    if (fclose(f) != 0)
        rc = 1;
    return rc;
}

int cp_include_digest(const char *scratch, const char *root, const char *vanish,
                      char out[CP_SHA])
{
    struct cp_vec list = { 0 };
    char tmp[CP_PATH];
    size_t nl = 0;
    int rc = cp_digest_collect(root, vanish, &list);
    if (rc == 0 && ovf(snprintf(tmp, sizeof tmp, "%s/digest-lines.txt", scratch),
                       sizeof tmp))
        rc = 1;
    if (rc == 0)
        rc = cp_digest_lines(&list, tmp, &nl);
    lintc_strv_free(list.v, list.n);
    if (rc == 0 && (nl == 0 || cp_sha256_file(tmp, out) != 0))
        rc = 1;
    return rc ? 1 : 0;
}

/* ── cache setup / plan / store ──────────────────────────────────────── */

static void cp_cache_off(struct cp_ctx *c, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->cache_off, sizeof c->cache_off, fmt, ap);
    va_end(ap);
    c->cache_on = 0;
}

static int cp_cache_env_disabled(const char *cachedir)
{
    const char *force = getenv("ZCL_TU_CACHE_SELFTEST_FORCE");
    if (cachedir && *cachedir && force && !strcmp(force, "1"))
        return 0;
    const char *e = getenv("ZCL_LINT_TU_CACHE");
    return e && !strcmp(e, "0");
}

/* The salt of everything that decides a cached verdict. 0 ok, 1 cache off
 * (reason recorded), 2 hard failure. */
static int cp_cache_salt(struct cp_ctx *c, const char *root, char salt[CP_SHA])
{
    char capture[CP_PATH], ccid[CP_LINE], digest[CP_SHA], flags_sha[CP_SHA];
    char libsha[CP_SHA], pre[CP_LINE * 3];
    ccid[0] = '\0';
    if (cps_snp(capture, "%s/ccid.txt", c->work))
        return 2;
    cp_version_line(c, capture, ccid, sizeof ccid);
    if (!ccid[0]) {
        cp_cache_off(c, "'%s' printed no version line", c->cc);
        return 1;
    }
    if (cp_include_digest(c->work, root, NULL, digest) != 0) {
        cp_cache_off(c, "could not digest the include set under '%s'", root);
        return 1;
    }
    if (cp_sha256_file(c->flags_nul, flags_sha) != 0) {
        cp_cache_off(c, "could not hash '%s'", c->flags_nul);
        return 1;
    }
    /* The gate and the cache library are this one binary: a rebuilt gate
     * (changed flags logic, diagnostics handling) must void older entries. */
    char exe[CP_PATH];
    if (lint_self_exe(exe, sizeof exe) != 0 || cp_sha256_file(exe, libsha) != 0) {
        cp_cache_off(c, "could not hash the gate binary");
        return 1;
    }
    if (cps_snp(pre, "tu-result-cache/v2\n%s\n%s\n%s\n%s\n%s\n%s\n",
                k_cpc_gate, libsha, libsha, ccid, flags_sha, digest))
        return 2;
    cp_sha256_data(pre, strlen(pre), salt);
    return 0;
}

static int cp_cache_gateroot(const struct cp_ctx *c, const char *cachedir,
                             char out[CP_PATH])
{
    const char *e = getenv("ZCL_LINT_TU_CACHE_DIR");
    if (cachedir && *cachedir)
        return ovf(snprintf(out, CP_PATH, "%s/%s", cachedir, k_cpc_gate), CP_PATH);
    if (e && *e)
        return ovf(snprintf(out, CP_PATH, "%s/%s", e, k_cpc_gate), CP_PATH);
    return ovf(snprintf(out, CP_PATH, "%s/.cache/lint-tu/%s", c->root, k_cpc_gate),
               CP_PATH);
}

int cp_cache_setup(struct cp_ctx *c, const char *cachedir, const char *root)
{
    char salt[CP_SHA], gateroot[CP_PATH];
    c->cache_on = 0;
    c->cache_off[0] = '\0';
    if (cp_cache_env_disabled(cachedir)) {
        cp_cache_off(c, "ZCL_LINT_TU_CACHE=0");
        return 0;
    }
    int rc = cp_cache_salt(c, root, salt);
    if (rc)
        return rc == 1 ? 0 : rc;
    if (cp_cache_gateroot(c, cachedir, gateroot) ||
        cps_snp(c->cache_dir, "%s/%s", gateroot, salt) ||
        cps_snp(c->events, "%s/tu-cache.events", c->work))
        return 2;
    if (cp_mkdirs(c->cache_dir) != 0) {
        cp_cache_off(c, "cannot create '%s'", c->cache_dir);
        return 0;
    }
    cp_touch(c->cache_dir);
    FILE *f = fopen(c->events, "w");
    if (!f) {
        cp_cache_off(c, "cannot write '%s'", c->events);
        return 0;
    }
    fclose(f);
    c->cache_on = 1;
    return 0;
}

static int cp_entry_read(const char *ent, int *rc, int *haslog)
{
    char line[64];
    FILE *f = fopen(ent, "r");
    if (!f)
        return 1;
    int ok = fgets(line, sizeof line, f) != NULL;
    fclose(f);
    if (!ok)
        return 1;
    char a[32], b[32];
    if (sscanf(line, "%31s %31s", a, b) != 2)
        return 1;
    if (!a[0] || strspn(a, "0123456789") != strlen(a))
        return 1;
    if (strcmp(b, "0") != 0 && strcmp(b, "1") != 0)
        return 1;
    *rc = atoi(a);
    *haslog = atoi(b);
    return 0;
}

static int cp_hit_replay(struct cp_ctx *c, const char *src, const char *ent,
                         int rc, int haslog)
{
    char key[CP_PATH], log[CP_PATH], rcf[CP_PATH];
    cp_key(src, key, sizeof key);
    if (ovf(snprintf(log, sizeof log, "%s/%s.log", c->out_dir, key), sizeof log))
        return 2;
    if (ovf(snprintf(rcf, sizeof rcf, "%s/%s.rc", c->out_dir, key), sizeof rcf))
        return 2;
    FILE *rf = fopen(rcf, "w");
    if (!rf)
        return 2;
    fprintf(rf, "%d\n", rc);
    fclose(rf);
    FILE *lf = fopen(log, "wb");
    if (!lf)
        return 2;
    if (haslog) {
        FILE *e = fopen(ent, "r");
        char skip[128];
        if (!e || !fgets(skip, sizeof skip, e)) {
            if (e)
                fclose(e);
            fclose(lf);
            return 2;
        }
        char buf[8192];
        size_t n;
        while ((n = fread(buf, 1, sizeof buf, e)) > 0)
            fwrite(buf, 1, n, lf);
        fclose(e);
    }
    fclose(lf);
    return 0;
}

/* Cache off or unusable: every source is a miss and gets compiled. */
static int cp_all_miss(struct cp_ctx *c)
{
    memcpy(c->miss, c->srcs, (size_t)c->nsrc * sizeof c->srcs[0]);
    c->nmiss = c->nsrc;
    return 0;
}

int cp_cache_plan(struct cp_ctx *c)
{
    c->nmiss = 0;
    if (!c->cache_on)
        return cp_all_miss(c);
    int hashed = 0, hits = 0;
    for (int i = 0; i < c->nsrc; i++) {
        char sha[CP_SHA];
        if (cp_sha256_file(c->srcs[i], sha) != 0)
            break;
        hashed++;
    }
    if (hashed != c->nsrc) {
        char reason[128];
        snprintf(reason, sizeof reason, "hashed %d of %d source(s)", hashed,
                 c->nsrc);
        cp_cache_off(c, "%s", reason);
        return cp_all_miss(c);
    }
    for (int i = 0; i < c->nsrc; i++) {
        char sha[CP_SHA], ent[CP_PATH * 2];
        cp_sha256_file(c->srcs[i], sha);
        if (ovf(snprintf(ent, sizeof ent, "%s/%s.%s", c->cache_dir,
                         c->srcs[i], sha), sizeof ent)) {
            fprintf(stderr, "%s: cache entry path exceeds %d\n", k_cpc_gate,
                    CP_PATH * 2);
            return 2;
        }
        int rc, haslog;
        if (cp_entry_read(ent, &rc, &haslog) == 0) {
            if (cp_hit_replay(c, c->srcs[i], ent, rc, haslog) != 0)
                return 2;
            hits++;
        } else {
            if (c->nmiss >= CP_MAXSRC) {
                fprintf(stderr, "%s: miss list exceeds %d\n", k_cpc_gate,
                        CP_MAXSRC);
                return 2;
            }
            memcpy(c->miss[c->nmiss++], c->srcs[i], CP_PATH);
        }
    }
    cp_appendf(c->events, "H %d\nM %d\n", hits, c->nmiss);
    return 0;
}

static int cp_store(struct cp_ctx *c, const char *src, int rc,
                    const char *log)
{
    char sha[CP_SHA], ent[CP_PATH * 2], tmp[CP_PATH * 2];
    if (cp_sha256_file(src, sha) != 0)
        return 1;
    if (ovf(snprintf(ent, sizeof ent, "%s/%s.%s", c->cache_dir, src, sha),
            sizeof ent))
        return 1;
    char dir[CP_PATH * 2];
    if (ovf(snprintf(dir, sizeof dir, "%s", ent), sizeof dir))
        return 1;
    char *slash = strrchr(dir, '/');
    if (slash)
        *slash = '\0';
    if (cp_mkdirs(dir) != 0)
        return 1;
    if (ovf(snprintf(tmp, sizeof tmp, "%s/.tmp.%d", dir, (int)getpid()),
            sizeof tmp))
        return 1;
    FILE *f = fopen(tmp, "wb");
    if (!f)
        return 1;
    fprintf(f, "%d ", rc);
    struct stat st;
    int haslog = stat(log, &st) == 0 && st.st_size > 0;
    fprintf(f, "%d\n", haslog);
    if (haslog) {
        FILE *l = fopen(log, "rb");
        char buf[8192];
        size_t n;
        if (l) {
            while ((n = fread(buf, 1, sizeof buf, l)) > 0)
                fwrite(buf, 1, n, f);
            fclose(l);
        }
    }
    fclose(f);
    if (rename(tmp, ent) != 0) {
        unlink(tmp);
        return 1;
    }
    cp_appendf(c->events, "s\n");
    return 0;
}

/* Compile one TU into its log and status artifacts and store the result.
 * 0 ok, 2 on a failure to name the artifacts. */
static int cp_compile_core(struct cp_ctx *c, const char *src)
{
    char *tail[CP_MAXARGS + 3];
    int a = 0;
    for (int i = 0; i < c->nflags; i++)
        tail[a++] = c->flags[i];
    static char ident[] = "-DZCL_SOURCE_IDENTITY_BATCH_INPUT_ID=\""
        "0000000000000000000000000000000000000000000000000000000000000000\"";
    if (!strcmp(src, "tools/dev/source_identity_batch.c"))
        tail[a++] = ident;
    tail[a++] = (char *)src;
    tail[a] = NULL;
    char key[CP_PATH], log[CP_PATH], rcf[CP_PATH];
    cp_key(src, key, sizeof key);
    if (cps_snp(log, "%s/%s.log", c->out_dir, key) ||
        cps_snp(rcf, "%s/%s.rc", c->out_dir, key))
        return 2;
    int rc = 0;
    if (cp_cc_spawn(c, tail, log, log, &rc) != 0)
        rc = 127;
    FILE *f = fopen(rcf, "w");
    if (f) {
        fprintf(f, "%d\n", rc);
        fclose(f);
    }
    if (c->cache_on)
        cp_store(c, src, rc, log);
    return 0;
}

/* A worker process: never returns, never flushes the parent's buffers. */
static void cp_child_compile(struct cp_ctx *c, const char *src)
{
    _exit(cp_compile_core(c, src));
}

int cp_compile_misses(struct cp_ctx *c)
{
    int running = 0;
    for (int i = 0; i < c->nmiss; i++) {
        while (running >= c->jobs) {
            int st;
            pid_t p;
            do
                p = wait(&st);
            while (p < 0 && errno == EINTR);
            if (p > 0)
                running--;
        }
        pid_t pid = fork();
        if (pid == 0)
            cp_child_compile(c, c->miss[i]);
        if (pid > 0)
            running++;
    }
    while (running > 0) {
        int st;
        pid_t p;
        do
            p = wait(&st);
        while (p < 0 && errno == EINTR);
        if (p > 0)
            running--;
    }
    return 0;
}

int cp_compile_one(struct cp_ctx *c, const char *src)
{
    return cp_compile_core(c, src);
}

int cp_cache_summary(const struct cp_ctx *c)
{
    if (!c->cache_on) {
        printf("  tu-cache: 0 hit, 0 miss, 0 stored (off: %s)\n",
               c->cache_off[0] ? c->cache_off : "not enabled");
        return 0;
    }
    int h = 0, m = 0, s = 0;
    FILE *f = fopen(c->events, "r");
    if (f) {
        char line[64];
        while (fgets(line, sizeof line, f)) {
            if (line[0] == 'H')
                h += atoi(line + 1);
            else if (line[0] == 'M')
                m += atoi(line + 1);
            else if (line[0] == 's')
                s++;
        }
        fclose(f);
    }
    printf("  tu-cache: %d hit, %d miss, %d stored\n", h, m, s);
    return 0;
}
