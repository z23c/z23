/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — dumpstate never blocks behind the reducer
 * (check-dumper-never-blocks). Tracked files via lint_git_index_foreach;
 * filesystem walk when .git is absent.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
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

enum { DNB_MAX = 4096, DNB_PRIM = 32, DNB_LINE = 8192, DNB_KEY = RS_PATH + 96 };

struct dnb_set { char p[DNB_MAX][RS_PATH]; int n; };
struct dnb_prim { char name[64]; char ere[256]; regex_t re; };
struct dnb_base { char k[DNB_MAX][DNB_KEY]; int n; };

static const char k_dnb_man[] = "tools/scripts/dumper_blocking_primitives.tsv";
static const char k_dnb_base[] = "tools/scripts/dumper_blocking_baseline.tsv";
static const char k_dnb_fn[] =
    "^(static[[:space:]]+)?(bool|void|int)[[:space:]]+"
    "[A-Za-z_][A-Za-z0-9_]*_dump_state_(json|fill)[[:space:]]*[(]";

static int dnb_add(struct dnb_set *s, const char *path)
{
    size_t n;
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 0;
    n = strlen(path);
    if (s->n >= DNB_MAX || n >= RS_PATH)
        return die("z23-lint: dumper-never-blocks overflow\n", "");
    memcpy(s->p[s->n++], path, n + 1);
    return 0;
}

static int dnb_is_c(const char *path)
{
    size_t n = strlen(path);
    return n >= 2 && path[n - 2] == '.' && path[n - 1] == 'c'
        && strstr(path, "/test/") == NULL && !lint_path_is_excluded(path);
}

static int dnb_under(const char *path, const char *root)
{
    size_t n = strlen(root);
    return strncmp(path, root, n) == 0 && (path[n] == '/' || path[n] == '\0');
}

struct dnb_idx { struct dnb_set *s; const char (*roots)[RS_PATH]; int nr; };

static int dnb_on_idx(const char *path, int stage, void *ctx)
{
    struct dnb_idx *c = ctx;
    int i;
    (void)stage;
    if (!dnb_is_c(path))
        return 0;
    for (i = 0; i < c->nr; i++)
        if (dnb_under(path, c->roots[i]))
            return dnb_add(c->s, path);
    return 0;
}

static int dnb_on_walk(const char *path, void *ctx)
{
    return dnb_is_c(path) ? dnb_add(ctx, path) : 0;
}

static int dnb_split_roots(const char *s, char out[][RS_PATH], int max, int *n)
{
    char buf[4096], *p;
    *n = 0;
    if (ovf(snprintf(buf, sizeof buf, "%s", s), sizeof buf))
        return 2;
    p = buf;
    while (*p) {
        char *t, save;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        if (*n >= max)
            return die("z23-lint: dumper-never-blocks overflow\n", "");
        t = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        save = *p;
        *p = '\0';
        if (ovf(snprintf(out[*n], RS_PATH, "%s", t), RS_PATH))
            return 2;
        (*n)++;
        if (!save)
            break;
        *p++ = save;
    }
    return 0;
}

static int dnb_unreadable(const char *path)
{
    fprintf(stderr, "check_dumper_never_blocks: UNPROVEN — cannot read %s\n",
            path);
    return 2;
}
static int dnb_walk_roots(struct dnb_set *s, const char (*roots)[RS_PATH],
                          int nr)
{
    int rc, i;
    for (i = 0; i < nr; i++) {
        rc = walk_src(roots[i], 0, dnb_on_walk, s);
        if (rc)
            return rc;
    }
    return 0;
}
static int dnb_collect(struct dnb_set *s, const char (*roots)[RS_PATH], int nr)
{
    struct dnb_idx ix = { .s = s, .roots = roots, .nr = nr };
    struct stat st;
    char bad[8] = {0};
    const char *ov = getenv("ZCL_DUMPER_BLOCKING_SCAN_ROOTS");
    int rc;
    s->n = 0;
    if (ov && ov[0])
        return dnb_walk_roots(s, roots, nr);
    if (stat(".git", &st) != 0)
        return dnb_walk_roots(s, roots, nr);
    rc = lint_git_index_foreach(dnb_on_idx, &ix, bad);
    if (rc)
        return die("check_dumper_never_blocks: UNPROVEN — git index\n", "");
    return 0;
}

static int dnb_bhas(const struct dnb_base *b, const char *k)
{
    int i;
    for (i = 0; i < b->n; i++)
        if (strcmp(b->k[i], k) == 0)
            return 1;
    return 0;
}

static int dnb_badd(struct dnb_base *b, const char *k)
{
    size_t n;
    if (dnb_bhas(b, k))
        return 0;
    n = strlen(k);
    if (b->n >= DNB_MAX || n >= DNB_KEY)
        return die("z23-lint: dumper-never-blocks overflow\n", "");
    memcpy(b->k[b->n++], k, n + 1);
    return 0;
}

static void dnb_posix_ere(const char *in, char *out, size_t cap)
{
    char tmp[256];
    size_t n = 0;
    const char *p = in;
    while (*p && n + 24 < sizeof tmp) {
        if (p[0] == '\\' && p[1] == 'b') {
            int left = p[2] && (isalnum((unsigned char)p[2]) || p[2] == '_');
            const char *r = left ? "([^[:alnum:]_]|^)" : "([^[:alnum:]_]|$)";
            size_t rl = strlen(r);
            memcpy(tmp + n, r, rl);
            n += rl;
            p += 2;
        } else if (p[0] == '\\' && (p[1] == '(' || p[1] == ')')) {
            tmp[n++] = '[';
            tmp[n++] = p[1];
            tmp[n++] = ']';
            p += 2;
        } else {
            tmp[n++] = *p++;
        }
    }
    tmp[n] = '\0';
    snprintf(out, cap, "%s", tmp);
}

static int dnb_load_man(struct dnb_prim *p, int *n, const char *path)
{
    FILE *f = fopen(path, "r");
    char buf[DNB_LINE];
    *n = 0;
    if (!f) {
        fprintf(stderr, "check_dumper_never_blocks: FATAL — manifest missing: "
                        "%s\n", path);
        return 2;
    }
    while (fgets(buf, (int)sizeof buf, f)) {
        char *tab, *nl, ere[256];
        size_t nlen = strlen(buf);
        if (nlen && buf[nlen - 1] == '\n')
            buf[--nlen] = '\0';
        if (buf[0] == '\0' || buf[0] == '#')
            continue;
        tab = strchr(buf, '\t');
        if (!tab || strchr(tab + 1, '\t')) {
            fprintf(stderr, "check_dumper_never_blocks: FATAL — malformed "
                            "manifest row: %s\n", buf);
            fclose(f);
            return 2;
        }
        *tab = '\0';
        nl = tab + 1;
        if (*n >= DNB_PRIM) {
            fclose(f);
            return die("z23-lint: dumper-never-blocks overflow\n", "");
        }
        snprintf(p[*n].name, sizeof p[*n].name, "%s", buf);
        dnb_posix_ere(nl, ere, sizeof ere);
        snprintf(p[*n].ere, sizeof p[*n].ere, "%s", ere);
        if (reg_fail(&p[*n].re, regcomp(&p[*n].re, ere, REG_EXTENDED))) {
            fclose(f);
            return 2;
        }
        (*n)++;
    }
    fclose(f);
    if (*n == 0) {
        fprintf(stderr, "check_dumper_never_blocks: FATAL — manifest contains "
                        "no primitives\n");
        return 2;
    }
    return 0;
}

static int dnb_load_base(struct dnb_base *b, const char *path)
{
    FILE *f = fopen(path, "r");
    char buf[DNB_LINE];
    b->n = 0;
    if (!f)
        return 0;
    while (fgets(buf, (int)sizeof buf, f)) {
        char *tab;
        size_t n = strlen(buf);
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (buf[0] == '\0' || buf[0] == '#')
            continue;
        tab = strchr(buf, '\t');
        if (!tab)
            continue;
        if (dnb_badd(b, buf)) {
            fclose(f);
            return 2;
        }
    }
    fclose(f);
    return 0;
}

static int dnb_is_sig(const regex_t *fn, const char *line)
{
    return regexec(fn, line, 0, NULL, 0) == 0;
}

static int dnb_hit_line(const char *buf, const char *path, int lineno,
                        struct dnb_prim *prim, int np, struct dnb_base *base,
                        struct dnb_base *seen, char viol[][DNB_KEY], int *nv)
{
    int i, rc = 0;
    for (i = 0; rc == 0 && i < np; i++) {
        char key[DNB_KEY];
        if (regexec(&prim[i].re, buf, 0, NULL, 0) != 0)
            continue;
        if (ovf(snprintf(key, sizeof key, "%s\t%s", prim[i].name, path),
                sizeof key))
            return 2;
        if (dnb_bhas(seen, key))
            continue;
        rc = dnb_badd(seen, key);
        if (rc || dnb_bhas(base, key))
            continue;
        if (*nv < DNB_MAX
            && !ovf(snprintf(viol[*nv], DNB_KEY,
                             "%s in %s (dump body line ~%d)",
                             prim[i].name, path, lineno), DNB_KEY))
            (*nv)++;
    }
    return rc;
}
static int dnb_scan_file(const char *path, const regex_t *fn,
                         struct dnb_prim *prim, int np, struct dnb_base *base,
                         struct dnb_base *seen, char viol[][DNB_KEY], int *nv,
                         int *nbodies)
{
    FILE *f = fopen(path, "r");
    char buf[DNB_LINE];
    int cap = 0, lineno = 0, rc = 0, had = 0;
    if (!f)
        return dnb_unreadable(path);
    while (rc == 0 && fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        lineno++;
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (dnb_is_sig(fn, buf))
            cap = 1;
        if (!cap)
            continue;
        had = 1;
        rc = dnb_hit_line(buf, path, lineno, prim, np, base, seen, viol, nv);
        if (buf[0] == '}')
            cap = 0;
    }
    if (had)
        (*nbodies)++;
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int dnb_keep_dumpers(struct dnb_set *tus, const regex_t *fn)
{
    int j, w = 0;
    for (j = 0; j < tus->n; j++) {
        FILE *tf = fopen(tus->p[j], "r");
        char lb[DNB_LINE];
        int hit = 0;
        if (!tf)
            return dnb_unreadable(tus->p[j]);
        while (fgets(lb, (int)sizeof lb, tf))
            if (dnb_is_sig(fn, lb)) {
                hit = 1;
                break;
            }
        fclose(tf);
        if (hit) {
            if (w != j)
                memcpy(tus->p[w], tus->p[j], RS_PATH);
            w++;
        }
    }
    tus->n = w;
    return 0;
}
static int dnb_verdict(int np, int nt, int nb, int nv, int ns,
                       char viol[][DNB_KEY], char stale[][DNB_KEY])
{
    int i;
    if (!nv && !ns) {
        printf("check_dumper_never_blocks: clean — %d primitive(s), %d dumper "
               "TU(s), %d reviewed debt row(s), no new blocking dumpers\n",
               np, nt, nb);
        return 0;
    }
    if (nv) {
        fputs("check_dumper_never_blocks: FAIL — dumper reaches a "
              "blocking primitive\n", stdout);
        for (i = 0; i < nv; i++)
            printf("  %s\n", viol[i]);
        fputs("  A *_dump_state_json must never take "
              "progress_store_tx_lock blocking\n"
              "  or run COUNT(*). Publish the value through the snapshot "
              "plane\n  (util/subsystem_snapshot.h / jobs/stage_log_rows.h) "
              "and read it\n  lock-free; use progress_store_tx_trylock only "
              "for cold single-row\n  detail, emitting "
              "{\"snapshot_status\":\"progress_store_busy\"}.\n", stdout);
    }
    if (ns) {
        fputs("check_dumper_never_blocks: FAIL — stale baseline row(s) "
              "(shrink the baseline)\n", stdout);
        for (i = 0; i < ns; i++)
            printf("  %s\n", stale[i]);
    }
    return 1;
}
static int dnb_check_roots(const char (*roots)[RS_PATH], int nr)
{
    int i;
    for (i = 0; i < nr; i++) {
        struct stat st;
        if (stat(roots[i], &st) != 0 || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "check_dumper_never_blocks: FATAL — scan root "
                            "missing: %s\n", roots[i]);
            return 2;
        }
    }
    return 0;
}
static int dnb_load(struct dnb_prim *prim, int *np, struct dnb_base *base,
                    regex_t *fn)
{
    const char *man = env_or("ZCL_DUMPER_BLOCKING_MANIFEST", k_dnb_man);
    const char *bp = env_or("ZCL_DUMPER_BLOCKING_BASELINE", k_dnb_base);
    FILE *bf;
    int rc = dnb_load_man(prim, np, man);
    if (rc)
        return rc;
    bf = fopen(bp, "a");
    if (bf)
        fclose(bf);
    rc = dnb_load_base(base, bp);
    if (rc)
        return rc;
    return reg_fail(fn, regcomp(fn, k_dnb_fn, REG_EXTENDED)) ? 2 : 0;
}
static int dnb_scan_all(struct dnb_set *tus, regex_t *fn, struct dnb_prim *prim,
                        int np, struct dnb_base *base, struct dnb_base *seen,
                        char viol[][DNB_KEY], int *nv, int *nbodies)
{
    int i, rc = 0;
    for (i = 0; rc == 0 && i < tus->n; i++)
        rc = dnb_scan_file(tus->p[i], fn, prim, np, base, seen, viol, nv,
                           nbodies);
    return rc;
}
static void dnb_stale(const struct dnb_base *base, const struct dnb_base *seen,
                      char stale[][DNB_KEY], int *ns)
{
    int i;
    *ns = 0;
    for (i = 0; i < base->n; i++) {
        if (dnb_bhas(seen, base->k[i]) || *ns >= DNB_MAX)
            continue;
        snprintf(stale[(*ns)++], DNB_KEY, "%s", base->k[i]);
    }
}
static int dnb_run(void)
{
    static struct dnb_set tus;
    static struct dnb_prim prim[DNB_PRIM];
    static struct dnb_base base, seen;
    static char viol[DNB_MAX][DNB_KEY], stale[DNB_MAX][DNB_KEY];
    char roots[16][RS_PATH];
    const char *rt = env_or("ZCL_DUMPER_BLOCKING_SCAN_ROOTS",
                            "core engine contexts cognition platform");
    regex_t fn;
    int nr = 0, np = 0, nv = 0, ns = 0, nbodies = 0, rc, i;
    rc = dnb_split_roots(rt, roots, 16, &nr);
    if (rc)
        return rc;
    rc = dnb_check_roots(roots, nr);
    if (rc)
        return rc;
    rc = dnb_load(prim, &np, &base, &fn);
    if (rc)
        return rc;
    rc = dnb_collect(&tus, roots, nr);
    if (rc == 0)
        rc = dnb_keep_dumpers(&tus, &fn);
    if (rc == 0)
        rc = gate_require_scanned(tus.n, 1, "check_dumper_never_blocks",
                                  "no *_dump_state_json / *_dump_state_fill "
                                  "definitions found — was a shape dir "
                                  "renamed/moved?");
    seen.n = 0;
    if (rc == 0)
        rc = dnb_scan_all(&tus, &fn, prim, np, &base, &seen, viol, &nv,
                          &nbodies);
    regfree(&fn);
    for (i = 0; i < np; i++)
        regfree(&prim[i].re);
    if (rc)
        return rc;
    rc = gate_require_scanned(nbodies, 1, "check_dumper_never_blocks",
                              "extracted zero dumper bodies — the "
                              "*_dump_state_json extractor drifted.");
    if (rc)
        return rc;
    dnb_stale(&base, &seen, stale, &ns);
    return dnb_verdict(np, tus.n, base.n, nv, ns, viol, stale);
}

static int dnb_quiet(void)
{
    int nfd, oldo, olde, rc;
    fflush(stdout);
    fflush(stderr);
    nfd = open("/dev/null", O_WRONLY);
    if (nfd < 0)
        return 2;
    oldo = dup(1);
    olde = dup(2);
    dup2(nfd, 1);
    dup2(nfd, 2);
    close(nfd);
    rc = dnb_run();
    fflush(stdout);
    fflush(stderr);
    dup2(oldo, 1);
    dup2(olde, 2);
    close(oldo);
    close(olde);
    return rc;
}

static int dnb_st_want(int got, int want, const char *msg)
{
    if (got == want) {
        printf("  ok  %s (rc=%d)\n", msg, want);
        return 0;
    }
    fprintf(stderr, "check_dumper_never_blocks --selftest: FAIL — %s: rc=%d "
                    "want=%d\n", msg, got, want);
    return 1;
}
static int dnb_st_write(const char *dir, const char *name, const char *text)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/%s", dir, name), sizeof path))
        return 2;
    return csr_write(path, text);
}
static int dnb_st_one(const char *dir, const char *name, const char *text,
                      const char *label, int want)
{
    if (name && dnb_st_write(dir, name, text))
        return 2;
    return dnb_st_want(dnb_quiet(), want, label);
}
static int dnb_st_rm(const char *dir, const char *name)
{
    char p[4608];
    if (!ovf(snprintf(p, sizeof p, "%s/%s", dir, name), sizeof p))
        unlink(p);
    return 0;
}
static int dnb_st_prep(char *tmp, char *root, char *empty, char *basep,
                       size_t cap)
{
    if (!mkdtemp(tmp))
        return die("z23-lint: mkdtemp failed\n", "");
    if (ovf(snprintf(root, cap, "%s/scanroot", tmp), cap))
        return 2;
    if (ovf(snprintf(empty, cap, "%s/emptyroot", tmp), cap))
        return 2;
    if (ovf(snprintf(basep, cap, "%s/empty_baseline.tsv", tmp), cap))
        return 2;
    if (csr_mkdirs(root) || csr_mkdirs(empty) || csr_write(basep, ""))
        return 2;
    if (setenv("ZCL_DUMPER_BLOCKING_SCAN_ROOTS", root, 1)
        || setenv("ZCL_DUMPER_BLOCKING_BASELINE", basep, 1))
        return 2;
    return 0;
}
int check_dumper_never_blocks_selftest(void)
{
    char tmp[] = "/tmp/zcl-dnb-XXXXXX";
    char root[4096], empty[4096], basep[4096];
    int bad = 0, rc;
    if (dnb_st_prep(tmp, root, empty, basep, sizeof root)) {
        rap_rm_rf(tmp);
        return 2;
    }
    rc = dnb_st_one(root, "clean_dumper.c",
                    "bool clean_dump_state_json(struct json_value *out, "
                    "const char *key)\n{\n    (void)key;\n    if "
                    "(!progress_store_tx_trylock()) { return true; }\n    "
                    "return true;\n}\n",
                    "1 clean sandbox", 0);
    if (rc == 2)
        return rap_rm_rf(tmp), 2;
    bad |= rc;
    rc = dnb_st_one(root, "fill_provider.c",
                    "bool runtime_dump_state_fill(struct runtime_snapshot "
                    "*snap)\n{\n    progress_store_tx_lock();\n    return "
                    "true;\n}\n",
                    "2 blocking call inside *_dump_state_fill", 1);
    if (rc == 2)
        return rap_rm_rf(tmp), 2;
    bad |= rc;
    rc = dnb_st_one(root, "fill_provider.c",
                    "static void helper_that_may_block(void)\n{\n    "
                    "progress_store_tx_lock();\n}\n\nbool "
                    "runtime_dump_state_fill(struct runtime_snapshot *snap)"
                    "\n{\n    (void)snap;\n    return true;\n}\n",
                    "3 same call outside any dump body", 0);
    if (rc == 2)
        return rap_rm_rf(tmp), 2;
    bad |= rc;
    dnb_st_rm(root, "fill_provider.c");
    rc = dnb_st_one(root, "json_dumper.c",
                    "bool legacy_dump_state_json(struct json_value *out, "
                    "const char *key)\n{\n    (void)key;\n    (void)out;\n    "
                    "stage_log_row_count(\"x\");\n    return true;\n}\n",
                    "4 blocking call inside *_dump_state_json", 1);
    if (rc == 2)
        return rap_rm_rf(tmp), 2;
    bad |= rc;
    dnb_st_rm(root, "json_dumper.c");
    if (setenv("ZCL_DUMPER_BLOCKING_SCAN_ROOTS", empty, 1))
        return rap_rm_rf(tmp), 2;
    rc = dnb_st_one(NULL, NULL, NULL, "5 empty scan root is FATAL", 2);
    if (rc == 2)
        return rap_rm_rf(tmp), 2;
    bad |= rc;
    unsetenv("ZCL_DUMPER_BLOCKING_SCAN_ROOTS");
    unsetenv("ZCL_DUMPER_BLOCKING_BASELINE");
    rc = dnb_st_one(NULL, NULL, NULL, "6 real tree", 0);
    if (rc == 2)
        return rap_rm_rf(tmp), 2;
    bad |= rc;
    rap_rm_rf(tmp);
    if (bad) {
        fputs("check_dumper_never_blocks: --selftest FAILED\n", stderr);
        return 1;
    }
    fputs("check_dumper_never_blocks: --selftest passed (6 cases)\n", stdout);
    return 0;
}

int check_dumper_never_blocks_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return dnb_run();
}
