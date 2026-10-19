/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: data layer of the capability-closure gate in C23. Epoch discovery,
 * the nm record parser and batched runner, the capability_symbols.def and
 * module_capabilities.def loaders with source-owned sidecars, and the
 * capability-set helpers. Output strings and table semantics are those of the
 * shell gate this replaced.
 */
#define _XOPEN_SOURCE 700
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "gate_capability_closure_priv.h"
#include "lintc.h"
#include "lintc_proc.h"

static void *ccd_grow(void *p, size_t *cap, size_t need, size_t elem)
{
    if (!elem || need > SIZE_MAX / elem)
        return NULL;
    size_t limit = SIZE_MAX / elem;
    size_t c = *cap ? *cap : (limit < 16 ? limit : 16);
    if (c > limit)
        return NULL;
    while (c < need)
        c = c > limit / 2 ? need : c * 2;
    void *q = realloc(p, c * elem); // raw-alloc-ok:lint-runtime
    if (q)
        *cap = c;
    return q;
}

static size_t ccd_lower(const struct ccd_map *m, const char *key, int *hit)
{
    size_t lo = 0, hi = m->n, mid = 0;
    for (*hit = 0; lo < hi && !*hit;) {
        mid = lo + (hi - lo) / 2;
        int c = strcmp(m->ent[mid].key, key);
        *hit = c == 0;
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return *hit ? mid : lo;
}

int ccd_map_put(struct ccd_map *m, const char *key, const char *val)
{
    int hit;
    size_t at = ccd_lower(m, key, &hit);
    char *v = strndup(val, strlen(val));
    if (!v)
        return -1;
    if (hit) {
        free(m->ent[at].val);
        m->ent[at].val = v;
        return 0;
    }
    if (m->n == SIZE_MAX) {
        free(v);
        return -1;
    }
    struct ccd_ent *e = m->n < m->cap ? m->ent : ccd_grow(m->ent, &m->cap, m->n + 1, sizeof *e);
    /* Publish a moved allocation before the next fallible operation. n still
     * names only complete entries, so cleanup stays valid if strdup fails. */
    if (e)
        m->ent = e;
    char *k = e ? strndup(key, strlen(key)) : NULL;
    if (!k) {
        free(v);
        return -1;
    }
    memmove(e + at + 1, e + at, (m->n++ - at) * sizeof *e);
    e[at] = (struct ccd_ent){ k, v };
    return 0;
}

const char *ccd_map_get(const struct ccd_map *m, const char *key)
{
    int hit;
    size_t at = ccd_lower(m, key, &hit);
    return hit ? m->ent[at].val : NULL;
}

void ccd_map_free(struct ccd_map *m)
{
    for (size_t i = 0; i < m->n; i++) {
        free(m->ent[i].key);
        free(m->ent[i].val);
    }
    free(m->ent);
    *m = (struct ccd_map){ 0 };
}

static const struct { char os; const char *path; } k_ccd_skip[] = {
    { 'L', "platform/modules/platform/src/os_sandbox_stub.c" },
    { 'D', "platform/modules/platform/src/os_sandbox_linux.c" },
    { 'D', "platform/modules/platform/src/os_sandbox_landlock_linux.c" },
    { 'D', "platform/modules/platform/src/os_sandbox_package_linux.c" },
    { 'D', "platform/modules/platform/src/os_sandbox_terminal_worker.c" },
    { 'D', "platform/modules/util/src/self_backtrace.c" },
    { 'D', "tools/dev/wallet_gui_load.c" },
    { 'W', "platform/modules/platform/src/os_sandbox_linux.c" },
    { 'W', "platform/modules/platform/src/os_sandbox_landlock_linux.c" },
    { 'W', "platform/modules/platform/src/os_sandbox_package_linux.c" },
    { 'W', "platform/modules/platform/src/os_sandbox_terminal_worker.c" },
    { 'W', "contexts/commons/modules/vcs/src/vcs_devloop.c" },
    { 'W', "tools/package_verify.c" },
};

int ccd_coverage_applicable(enum ccd_os os, const char *path)
{
    for (size_t i = 0; i < sizeof k_ccd_skip / sizeof *k_ccd_skip; i++)
        if (k_ccd_skip[i].os == "LDWO"[os] && strcmp(k_ccd_skip[i].path, path) == 0)
            return 0;
    return 1;
}

/* One epochs entry. 0 when it is skipped or considered, -1 on path overflow
 * (never skipped silently), -2 (errno set) when it cannot be stat'ed. */
static int ccd_epoch_consider(const char *base, const char *name, char *best, size_t best_cap, struct stat *bst)
{
    char path[CCD_PATH];
    struct stat st;
    if (name[0] == '.')
        return 0;
    if (snprintf(path, sizeof path, "%s/%s", base, name) >= (int)sizeof path)
        return -1;
    if (stat(path, &st) != 0)
        return -2;
    if (!S_ISDIR(st.st_mode))
        return 0;
    if (!best[0] || st.st_mtime > bst->st_mtime
        || (st.st_mtime == bst->st_mtime && strcmp(name, best) < 0)) {
        snprintf(best, best_cap, "%s", name);
        *bst = st;
    }
    return 0;
}

int ccd_find_epoch(const char *root, char *out, size_t cap)
{
    char base[CCD_PATH], best[256] = "";
    struct stat bst = { 0 };
    DIR *d;
    int rc = 0;
    if (snprintf(base, sizeof base, "%s/build/dev-obj/epochs", root) >= (int)sizeof base)
        return -1;
    if (!(d = opendir(base)))
        return errno == ENOENT ? 0 : -2;      /* only a missing epochs dir means "none" */
    for (;;) {
        errno = 0;                             /* cleared before EVERY readdir, as ccd_walk does */
        struct dirent *e = readdir(d);
        if (!e) {
            if (errno)
                rc = -2;
            break;
        }
        if ((rc = ccd_epoch_consider(base, e->d_name, best, sizeof best, &bst)) != 0)
            break;
    }
    int saved = errno;
    closedir(d);
    errno = saved;
    if (rc != 0)
        return rc;
    return best[0] ? (snprintf(out, cap, "%s/%s", base, best) >= (int)cap ? -1 : 1) : 0;
}

/* The colon that ends the path; a leading Windows drive colon is skipped. */
static const char *ccd_path_colon(const char *line)
{
    const char *c = strchr(line, ':');
    if (c == line + 1 && isalpha((unsigned char)line[0]) && (line[2] == '/' || line[2] == '\\'))
        c = strchr(line + 2, ':');
    return c;
}

static size_t ccd_tokens(char *rest, char *tok[3])
{
    size_t m = 0;
    for (char *p = strtok(rest, " \t"); p; p = strtok(NULL, " \t"))
        if (m == 3)
            return 4;
        else
            tok[m++] = p;
    return m;
}

/* Mach-O: drop the leading underscore and a trailing $VARIANT. */
static void ccd_undecorate(char **name)
{
    char *d;
    if ((*name)[0] == '_')
        (*name)++;
    d = strrchr(*name, '$');
    if (!d || !d[1])
        return;
    for (const char *p = d + 1; *p; p++)
        if (!strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_", *p))
            return;
    *d = '\0';
}

static int ccd_nm_push(struct ccd_nm *o, const char *path, size_t pl, const char *type, const char *name)
{
    size_t tl = strlen(type), nl = strlen(name);
    if (pl > SIZE_MAX - tl || pl + tl > SIZE_MAX - nl ||
        pl + tl + nl > SIZE_MAX - 3 || o->n == SIZE_MAX)
        return -1;
    struct ccd_nmrow *r = o->n < o->cap ? o->row : ccd_grow(o->row, &o->cap, o->n + 1, sizeof *r);
    /* A failed row allocation must leave the container owner up to date. */
    if (r)
        o->row = r;
    char *b = r ? malloc(pl + tl + nl + 3) : NULL; // raw-alloc-ok:lint-runtime
    if (!b)
        return -1;
    memcpy(b, path, pl);
    b[pl] = '\0';
    memcpy(b + pl + 1, type, tl + 1);
    memcpy(b + pl + tl + 2, name, nl + 1);
    o->row[o->n++] = (struct ccd_nmrow){ b, b + pl + 1, b + pl + tl + 2 };
    return 0;
}

static int ccd_parse_line(char *line, int strip, struct ccd_nm *o)
{
    const char *colon = ccd_path_colon(line);
    char *tok[3], *name;
    size_t pl, m;
    if (!colon)
        return 0;
    pl = (size_t)(colon - line);
    m = ccd_tokens((char *)colon + 1, tok);
    if (m != 2 && m != 3)
        return 0;
    name = tok[m - 1];
    if (strip)
        ccd_undecorate(&name);
    return ccd_nm_push(o, line, pl, tok[m - 2], name);
}

int ccd_parse_nm(const char *text, int strip, struct ccd_nm *out)
{
    char *copy = strndup(text, strlen(text)), *save = NULL;
    int rc = copy ? 0 : -1;
    for (char *l = copy ? strtok_r(copy, "\n", &save) : NULL; l && rc == 0; l = strtok_r(NULL, "\n", &save))
        rc = ccd_parse_line(l, strip, out);
    free(copy);
    return rc;
}

int ccd_nm_failed(const struct ccd_nm *nm)
{
    return nm->rc != 0 || nm->errlen != 0;
}

void ccd_nm_free(struct ccd_nm *nm)
{
    for (size_t i = 0; i < nm->n; i++)
        free(nm->row[i].path);
    free(nm->row);
    free(nm->err);
    *nm = (struct ccd_nm){ 0 };
}

static char *ccd_slurp(const char *path)
{
    FILE *f = fopen(path, "r");
    long n = f && fseek(f, 0, SEEK_END) == 0 ? ftell(f) : -1;
    char *p = n >= 0 && fseek(f, 0, SEEK_SET) == 0 ? malloc((size_t)n + 1) : NULL; // raw-alloc-ok:lint-runtime
    if (p && fread(p, 1, (size_t)n, f) == (size_t)n)
        p[n] = '\0';
    else {
        free(p);
        p = NULL;
    }
    if (f)
        fclose(f);
    return p;
}

static int ccd_collect_err(const char *path, struct ccd_nm *o)
{
    char *t = ccd_slurp(path), *p = NULL;
    size_t n = t ? strlen(t) : 0;
    if (n && (p = realloc(o->err, o->errlen + n + 1))) { // raw-alloc-ok:lint-runtime
        memcpy(p + o->errlen, t, n + 1);
        o->err = p;
        o->errlen += n;
    }
    free(t);
    return !t || (n && !p) ? -1 : 0;
}

/* nm stderr goes to the file named by $0 of a one-line sh: lcp_run offers no
 * mode that captures stdout and stderr apart. */
static int ccd_errfile(char *path, size_t cap)
{
    const char *tmp = getenv("TMPDIR");
    int fd;
    snprintf(path, cap, "%s/cap-closure-nm.XXXXXX", tmp && tmp[0] == '/' ? tmp : P_tmpdir);
    if ((fd = mkstemp(path)) < 0)
        return -1;
    return close(fd);
}

static void ccd_nm_argv(char **argv, char *errpath, char *const *objs, size_t n, int defined_only)
{
    char *const head[] = { (char *)"sh", (char *)"-c", (char *)"exec nm \"$@\" 2>\"$0\"", errpath,
                           (char *)"--print-file-name", (char *)"-U" };
    size_t k = defined_only ? 6 : 5;
    memcpy(argv, head, k * sizeof *argv);
    memcpy(argv + k, objs, n * sizeof *argv);
    argv[k + n] = NULL;
}

static int ccd_exit(int rc, int code, int lost)
{
    return rc < 0 ? 127 : rc > 0 ? 0 : code ? code : lost ? 1 : 0;
}

static int ccd_nm_take(const struct lcp_buf *out, const char *errpath, int strip, struct ccd_nm *o)
{
    if (out->data && ccd_parse_nm(out->data, strip, o) != 0)
        return -1;
    return ccd_collect_err(errpath, o);
}

static int ccd_nm_batch(char *const *objs, size_t n, int defined_only, int strip, struct ccd_nm *o)
{
    char errpath[CCD_PATH], *argv[CCD_NM_BATCH + 8];
    struct lcp_spec s = { .argv = argv, .mode = LCP_OUT, .grace_ms = CCD_GRACE_MS };
    struct lcp_buf out = { 0 };
    int code = 0, rc, bad;
    if (ccd_errfile(errpath, sizeof errpath) != 0)
        return -1;
    ccd_nm_argv(argv, errpath, objs, n, defined_only);
    rc = lcp_run(&s, &out, &code);
    if (!o->rc)
        o->rc = ccd_exit(rc, code, out.lost);
    bad = rc == 0 && ccd_nm_take(&out, errpath, strip, o);
    lcp_buf_free(&out);
    unlink(errpath);
    return bad ? -1 : rc > 0;
}

int ccd_run_nm(char *const *objs, size_t n, int defined_only, size_t batch, int strip, struct ccd_nm *out)
{
    if (batch == 0 || batch > CCD_NM_BATCH)
        batch = CCD_NM_BATCH;
    for (size_t at = 0, cnt; at < n; at += cnt) {
        size_t bytes = 0;
        for (cnt = 0; at + cnt < n && cnt < batch && bytes < CCD_NM_BYTES; cnt++)
            bytes += strlen(objs[at + cnt]) + 1;
        int rc = ccd_nm_batch(objs + at, cnt, defined_only, strip, out);
        if (rc != 0)
            return rc;
    }
    return 0;
}

typedef int (*ccd_rec_fn)(void *ctx, const char *key, const char *cls);

/* One joined record: the first quoted argument and the class text after the
 * first comma, with trailing space and one trailing comma removed. buf is
 * edited in place. */
/* End of the class text: trailing space, one comma and the space before it removed. */
static char *ccd_class_end(const char *c, char *end)
{
    while (end > c && isspace((unsigned char)end[-1]))
        end--;
    if (end > c && end[-1] == ',')
        end--;
    while (end > c && isspace((unsigned char)end[-1]))
        end--;
    return end;
}

static int ccd_record(const regex_t *re, char *buf, ccd_rec_fn fn, void *ctx)
{
    regmatch_t m;
    if (regexec(re, buf, 1, &m, 0) != 0)
        return 0;
    char *s = buf + m.rm_so, *end = buf + m.rm_eo, *q = strchr(s, '"'), *e = q + 1, *c = strchr(s, ',');
    while (*e != '"')
        e += *e == '\\' ? 2 : 1;
    if (!c || c >= end || e == q + 1)
        return 0;
    for (c++; c < end && isspace((unsigned char)*c); c++)
        ;
    end = ccd_class_end(c, end);
    if (end == c)
        return 0;
    *e = '\0';
    *end = '\0';
    return fn(ctx, q + 1, c);
}

/* Each marker line plus the lines up to the next marker is one record, so a
 * call wrapped across lines still parses. */
static int ccd_scan(char *text, const char *marker, const regex_t *re, ccd_rec_fn fn, void *ctx)
{
    char *buf = NULL, *save = NULL;
    size_t len = 0, cap = 0;
    int rc = 0;
    for (char *l = strtok_r(text, "\n", &save);; l = strtok_r(NULL, "\n", &save)) {
        int start = l && strstr(l, marker);
        if ((start || !l) && len) {
            rc = ccd_record(re, buf, fn, ctx);
            len = 0;
        }
        if (!l || rc != 0)
            break;
        if (!start && !len)
            continue;
        size_t ln = strlen(l);
        char *nb = len + ln + 2 > cap ? ccd_grow(buf, &cap, len + ln + 2, 1) : buf;
        if (!nb) {
            rc = -1;
            break;
        }
        buf = nb;
        buf[len] = ' ';
        memcpy(buf + (len ? len + 1 : 0), l, ln + 1);
        len += ln + (len != 0);
    }
    free(buf);
    return rc;
}

static const char k_ccd_sym_re[] = "ZCL_CAPABILITY_SYMBOL\\([[:space:]]*\"([^\"\\\\]|\\\\.)*\""
                                   "[[:space:]]*,[[:space:]]*CAP_[A-Z_]+";
static const char k_ccd_mod_re[] = "ZCL_MODULE_CAPABILITY\\([[:space:]]*\"([^\"\\\\]|\\\\.)*\""
                                   "[[:space:]]*,[[:space:]]*[A-Z_|]+[[:space:]]*,";

/* 0 after fn saw every record, 1 when the file cannot be read, else fn's or -1. */
static int ccd_def_each(const char *file, int modules, ccd_rec_fn fn, void *ctx)
{
    regex_t re;
    char *text = ccd_slurp(file);
    if (!text)
        return 1;
    int rc = regcomp(&re, modules ? k_ccd_mod_re : k_ccd_sym_re, REG_EXTENDED) ? -1 : 0;
    if (rc == 0) {
        rc = ccd_scan(text, modules ? "ZCL_MODULE_CAPABILITY(" : "ZCL_CAPABILITY_SYMBOL(", &re, fn, ctx);
        regfree(&re);
    }
    free(text);
    return rc;
}

struct ccd_symctx { struct ccd_map *map; size_t count; int aliases; };

static int ccd_sym_row(void *ctx, const char *sym, const char *cls)
{
    static const char *const pre[] = { "__imp_", "__imp__", "__mingw_" };
    struct ccd_symctx *c = ctx;
    char key[CCD_PATH];
    if (!c->aliases) {
        c->count++;
        return ccd_map_put(c->map, sym, cls);
    }
    for (size_t j = 0; j < 3; j++)
        if (snprintf(key, sizeof key, "%s%s", pre[j], sym) >= (int)sizeof key
            || ccd_map_put(c->map, key, cls) != 0)
            return -1;
    return 0;
}

int ccd_symbols_load(const char *file, int windows, struct ccd_map *sym, size_t *count)
{
    struct ccd_symctx c = { sym, 0, 0 };
    int rc = ccd_def_each(file, 0, ccd_sym_row, &c);
    *count = c.count;
    c.aliases = 1;
    return rc == 0 && windows ? ccd_def_each(file, 0, ccd_sym_row, &c) : rc;
}

/* Next "|"-separated token of p: its length, with *next past the separator. */
static size_t ccd_tok(const char *p, const char **next)
{
    const char *bar = strchr(p, '|');
    size_t n = bar ? (size_t)(bar - p) : strlen(p);
    *next = p + n + (bar != NULL);
    return n;
}

int ccd_grants(const char *raw, const char *want)
{
    const char *next;
    for (const char *p = raw; *p; p = next) {
        size_t n = ccd_tok(p, &next);
        if (n == strlen(want) && memcmp(p, want, n) == 0)
            return 1;
    }
    return 0;
}

char *ccd_union_caps(const char *out, const char *add)
{
    size_t ol = strlen(out);
    char *r = malloc(ol + strlen(add) + 2); // raw-alloc-ok:lint-runtime
    const char *next;
    if (r)
        memcpy(r, out, ol + 1);
    for (const char *p = add; r && *p; p = next) {
        size_t n = ccd_tok(p, &next);
        char *tok = strndup(p, n);
        if (!tok) {
            free(r);
            return NULL;
        }
        if (n && strcmp(tok, "CAP_NONE") != 0 && !ccd_grants(r, tok)) {
            snprintf(r + ol, n + 2, "%s%s", ol ? "|" : "", tok);
            ol += n + (ol != 0);
        }
        free(tok);
    }
    return r;
}

struct ccd_modctx { struct ccd_mods *m; int merge; size_t n; char path[CCD_PATH]; char *cls; };

/* Sets the exact class of path and merges it into the union (merge) or
 * replaces the union with it. */
static int ccd_mod_set(struct ccd_mods *m, const char *path, const char *cls, int merge)
{
    const char *old = merge ? ccd_map_get(&m->uni, path) : NULL;
    char *u = ccd_union_caps(old ? old : "", cls);
    int rc = !u || ccd_map_put(&m->raw, path, cls) || ccd_map_put(&m->uni, path, u) ? -1 : 0;
    free(u);
    return rc;
}

static int ccd_mod_row(void *ctx, const char *path, const char *cls)
{
    struct ccd_modctx *c = ctx;
    c->n++;
    if (!c->merge && c->n == 1) {
        snprintf(c->path, sizeof c->path, "%s", path);
        /* Preserve every valid class token, including grants after byte255. */
        c->cls = strndup(cls, strlen(cls));
        if (!c->cls)
            return -1;
    }
    return c->merge ? ccd_mod_set(c->m, path, cls, 1) : 0;
}

static int ccd_is_file(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int ccd_sidecar_fail(struct ccd_mods *m, const char *sidecar, const char *why)
{
    snprintf(m->error, sizeof m->error,
             "check_capability_closure: FATAL \xe2\x80\x94 invalid source-owned capability sidecar: %s%s",
             sidecar, why);
    return 1;
}

/* A sidecar names exactly its sibling .c file, once, and no central row. */
static int ccd_sidecar(struct ccd_mods *m, const char *root, const char *sc)
{
    static const char k_suffix[] = ".capabilities.def";
    struct ccd_modctx one = { .m = m };
    struct stat st;
    size_t rl = strlen(root) + 1, el = strlen(sc) - rl - (sizeof k_suffix - 1);
    int rc;
    if (lstat(sc, &st) != 0 || !S_ISREG(st.st_mode))
        return ccd_sidecar_fail(m, sc, "");
    rc = ccd_def_each(sc, 1, ccd_mod_row, &one);
    if (rc == 0) {
        if (one.n != 1 || strlen(one.path) != el || memcmp(one.path, sc + rl, el) != 0)
            rc = ccd_sidecar_fail(m, sc, "");
        else if (ccd_map_get(&m->raw, one.path))
            rc = ccd_sidecar_fail(m, sc, " (duplicate central row)");
        else
            rc = ccd_mod_set(m, one.path, one.cls, 0);
    }
    free(one.cls);
    return rc;
}

struct ccd_list { char **s; size_t n, cap; };

static int ccd_list_add(struct ccd_list *l, const char *path)
{
    if (l->n == SIZE_MAX)
        return -1;
    char **s = ccd_grow(l->s, &l->cap, l->n + 1, sizeof *s);
    if (!s)
        return -1;
    l->s = s;
    s[l->n] = strndup(path, strlen(path));
    if (!s[l->n])
        return -1;
    l->n++;
    return 0;
}

static int ccd_is_sidecar_name(const char *name)
{
    static const char k_name[] = ".c.capabilities.def";
    size_t nl = strlen(name);
    return nl >= sizeof k_name - 1 && strcmp(name + nl - (sizeof k_name - 1), k_name) == 0;
}

#ifdef ZCL_TESTING
struct ccd_scan_test ccd_scan_test;

/* Inject only at the named owned fixture directory or leaf. */
static int ccd_scan_fault(enum ccd_scan_fault fault, const char *path)
{
    return ccd_scan_test.fault == fault && ccd_scan_test.path &&
        strcmp(ccd_scan_test.path, path) == 0;
}

static DIR *ccd_scan_open(const char *path)
{
    if (ccd_scan_fault(CCD_SCAN_OPEN, path)) { errno = EACCES; return NULL; }
    DIR *d = opendir(path);
    ccd_scan_test.opened += d != NULL;
    return d;
}

static struct dirent *ccd_scan_read(DIR *d, const char *path)
{
    struct dirent *entry = readdir(d);
    if (!entry && !errno && ccd_scan_fault(CCD_SCAN_READ, path)) errno = EIO;
    if (entry && ccd_scan_fault(CCD_SCAN_DIRTY, path)) errno = ENOENT;
    return entry;
}

static int ccd_scan_close(DIR *d, const char *path)
{
    int result = closedir(d);
    ccd_scan_test.closed++;
    if (result == 0 && ccd_scan_fault(CCD_SCAN_CLOSE, path)) { errno = EIO; return -1; }
    return result;
}

static int ccd_scan_stat(const char *path, struct stat *st)
{
    if (ccd_scan_fault(CCD_SCAN_STAT, path)) { errno = EIO; return -1; }
    return stat(path, st);
}

static int ccd_scan_lstat(const char *path, struct stat *st)
{
    if (ccd_scan_fault(CCD_SCAN_LSTAT, path)) { errno = EIO; return -1; }
    return lstat(path, st);
}
#else
#define ccd_scan_open opendir
#define ccd_scan_read(d, path) readdir(d)
#define ccd_scan_close(d, path) closedir(d)
#define ccd_scan_stat stat
#define ccd_scan_lstat lstat
#endif

static int ccd_walk(const char *dir, struct ccd_list *l);

/* Every non-dot entry must have a complete path and a readable file type. */
static int ccd_walk_entry(const char *dir, const char *name, struct ccd_list *l)
{
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return 0;
    char path[CCD_PATH];
    struct stat st;
    int n = snprintf(path, sizeof path, "%s/%s", dir, name);
    if (n < 0 || n >= (int)sizeof path || ccd_scan_lstat(path, &st) != 0) return 1;
    int rc = ccd_is_sidecar_name(name) ? ccd_list_add(l, path) : 0;
    if (rc == 0 && S_ISDIR(st.st_mode)) rc = ccd_walk(path, l);
    return rc;
}

/* Errors never stand for EOF or an empty optional root. Close every opened
 * directory even after recursion, allocation or enumeration refuses. */
static int ccd_walk(const char *dir, struct ccd_list *l)
{
    DIR *d = ccd_scan_open(dir);
    if (!d) return 1;
    int rc = 0;
    while (rc == 0) {
        errno = 0;
        struct dirent *entry = ccd_scan_read(d, dir);
        if (!entry) { rc = errno ? 1 : 0; break; }
        rc = ccd_walk_entry(dir, entry->d_name, l);
    }
    if (ccd_scan_close(d, dir) != 0 && rc == 0) rc = 1;
    return rc;
}

static int ccd_cmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int ccd_sidecars(struct ccd_mods *m, const char *root)
{
    static const char *const dirs[] = { "core", "engine", "contexts", "cognition", "platform", "tools" };
    struct ccd_list l = { 0 };
    struct stat st;
    char dir[CCD_PATH];
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < 6; i++) {
        int n = snprintf(dir, sizeof dir, "%s/%s", root, dirs[i]);
        if (n < 0 || n >= (int)sizeof dir) { rc = 1; break; }
        if (ccd_scan_stat(dir, &st) != 0) {
            if (errno == ENOENT) continue; /* an optional source root is absent */
            rc = 1;
            break;
        }
        /* Preserve the shell's intentional -d filter for non-directories. */
        if (S_ISDIR(st.st_mode)) rc = ccd_walk(dir, &l);
    }
    if (rc == 0 && l.n > 1) qsort(l.s, l.n, sizeof *l.s, ccd_cmp);
    for (size_t i = 0; i < l.n; i++) {
        rc = rc == 0 ? ccd_sidecar(m, root, l.s[i]) : rc;
        free(l.s[i]);
    }
    free(l.s);
    return rc;
}

int ccd_modules_load(const char *file, const char *platform_file, const char *root, struct ccd_mods *m)
{
    struct ccd_modctx c = { .m = m, .merge = 1 };
    int rc;
    memset(m, 0, sizeof *m);
    if (!ccd_is_file(file))
        return 1;
    if ((rc = ccd_def_each(file, 1, ccd_mod_row, &c)) != 0 || (rc = ccd_sidecars(m, root)) != 0)
        return rc;
    c.n = 0;
    if (platform_file && ccd_is_file(platform_file) && (rc = ccd_def_each(platform_file, 1, ccd_mod_row, &c)) != 0)
        return rc;
    m->count = m->raw.n;
    m->platform_count = c.n;
    return 0;
}

void ccd_mods_free(struct ccd_mods *m)
{
    ccd_map_free(&m->raw);
    ccd_map_free(&m->uni);
}

int capability_closure_data_run(int argc, char **argv)
{
    return die("z23-lint: capability-closure-data has a selftest only: %s\n", argc > 0 ? argv[0] : "use --selftest");
}
