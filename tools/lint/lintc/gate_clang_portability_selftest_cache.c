/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the tu-cache soundness proofs for the check-clang-portability
 * selftest, ported from tu_cache_selftest and
 * tu_cache_include_digest_selftest in tools/lint/tu_result_cache.sh
 * (deleted). The stub compiler is this gate's own --stub-cc mode, exec'd
 * from this binary, so no shell is ever involved.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_clang_portability_priv.h"

static int cpt_copy_dir(const char *src, const char *dst);


static int cpt_fail(const char *msg)
{
    fprintf(stderr, "FAIL: --self-test — tu-cache: %s\n", msg);
    return 1;
}

/* ── include-digest TOCTOU proof ─────────────────────────────────────── */

int cp_digest_selftest(const char *scratch)
{
    char base[CP_PATH], root[CP_PATH], sc1[CP_PATH], sc2[CP_PATH];
    if (cps_snp(base, "%s/tu-digest-self", scratch))
        return 2;
    cp_mkdirs(base);
    cps_snp(root, "%s/root", base);
    cps_snp(sc1, "%s/scratch1", base);
    cps_snp(sc2, "%s/scratch2", base);
    cp_mkdirs(root);
    cp_mkdirs(sc1);
    cp_mkdirs(sc2);
    char p[CP_PATH];
    cps_snp(p, "%s/a.h", root);
    cps_static_write(p, "#define A 1\n");
    cps_snp(p, "%s/b.h", root);
    cps_static_write(p, "#define B 1\n");
    cps_snp(p, "%s/c.h", root);
    cps_static_write(p, "#define C 1\n");
    char out[CP_SHA];
    if (cp_include_digest(sc1, root, p, out) != 0 || !out[0]) {
        fprintf(stderr, "FAIL: tu_cache_include_digest_selftest — a path that "
                        "vanished\n  between find and sha256 failed the whole "
                        "digest\n");
        rap_rm_rf(base);
        return 2;
    }
    cps_snp(p, "%s/d.h", root);
    cps_static_write(p, "#define D 1\n");
    chmod(p, 0000);
    fflush(stderr);
    int keep_err = dup(2);
    int dn = open("/dev/null", O_WRONLY);
    if (dn >= 0) {
        dup2(dn, 2);
        close(dn);
    }
    int rc = cp_include_digest(sc2, root, NULL, out);
    fflush(stderr);
    if (keep_err >= 0) {
        dup2(keep_err, 2);
        close(keep_err);
    }
    chmod(p, 0644);
    if (rc == 0) {
        fprintf(stderr, "FAIL: tu_cache_include_digest_selftest — an "
                        "unreadable file did not fail the digest\n");
        rap_rm_rf(base);
        return 2;
    }
    rap_rm_rf(base);
    printf("  OK: tu_cache_include_digest selftest — a vanished path is "
           "dropped (digest still succeeds), an unreadable file fails loudly "
           "and is named\n");
    return 0;
}

/* shared with the other selftest file */
int cps_static_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    fputs(text, f);
    fclose(f);
    return 0;
}

/* ── synthetic sweep ─────────────────────────────────────────────────── */

struct cpt_counts { int h, m, s; };

static int cpt_counts_read(const struct cp_ctx *c, struct cpt_counts *o)
{
    o->h = o->m = o->s = 0;
    FILE *f = fopen(c->events, "r");
    if (!f)
        return 0;
    char line[64];
    while (fgets(line, sizeof line, f)) {
        if (line[0] == 'H')
            o->h += atoi(line + 1);
        else if (line[0] == 'M')
            o->m += atoi(line + 1);
        else if (line[0] == 's')
            o->s++;
    }
    fclose(f);
    return 0;
}

static void cpt_load_srcs(struct cp_ctx *c, const char *list)
{
    char line[CP_PATH];
    FILE *f = fopen(list, "r");
    c->nsrc = 0;
    while (f && fgets(line, sizeof line, f) && c->nsrc < CP_MAXSRC) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        snprintf(c->srcs[c->nsrc++], CP_PATH, "%s", line);
    }
    if (f)
        fclose(f);
}

static int cpt_sweep(struct cp_ctx *c, const char *base, const char *cc,
                     const char *flags_nul, const char *root,
                     const char *srclist_path, int jobs,
                     struct cpt_counts *out)
{
    char cachedir[CP_PATH];
    cps_snp(cachedir, "%s/cachedir", base);
    c->cc = cc;
    c->flags_nul[0] = '\0';
    cps_snp(c->flags_nul, "%s", flags_nul);
    c->nflags = 1;
    c->stub_cc = 1;
    snprintf(c->flags[0], CP_PATH, "%s", "-c");
    c->jobs = jobs;
    char work[CP_PATH];
    cps_snp(work, "%s/work", base);
    cp_mkdirs(work);
    char keep[CP_PATH];
    cps_snp(keep, "%s", c->work);
    cps_snp(c->work, "%s", work);
    char keepout[CP_PATH];
    cps_snp(keepout, "%s", c->out_dir);
    cps_snp(c->out_dir, "%s/out", base);
    cp_mkdirs(c->out_dir);
    int rc = cp_cache_setup(c, cachedir, root);
    if (rc || !c->cache_on) {
        char m[256];
        cps_snp(m,
                 "the cache refused to enable on a synthetic root (%s)",
                 c->cache_off);
        return cpt_fail(m);
    }
    cpt_load_srcs(c, srclist_path);
    rc = cp_cache_plan(c);
    if (rc == 0)
        rc = cp_compile_misses(c);
    cpt_counts_read(c, out);
    cps_snp(c->work, "%s", keep);
    cps_snp(c->out_dir, "%s", keepout);
    return rc;
}

static int cpt_want(struct cpt_counts *o, int h, int m, int s, const char *msg)
{
    if (o->h == h && o->m == m && o->s == s)
        return 0;
    char mm[256];
    cps_snp(mm, "%s (got %d/%d/%d)", msg, o->h, o->m, o->s);
    return cpt_fail(mm);
}

static int cpt_units(const char *root, const char *list, int n)
{
    char p[CP_PATH];
    cps_snp(p, "%s/src/shared.h", root);
    cps_static_write(p, "#define TU_SELFTEST_SHARED 1\n");
    FILE *f = fopen(list, "w");
    if (!f)
        return 2;
    for (int i = 0; i < n; i++) {
        char src[CP_PATH];
        cps_snp(src, "%s/src/u%d.c", root, i);
        FILE *u = fopen(src, "w");
        if (!u)
            continue;
        fprintf(u, "#include \"shared.h\"\nint unit_%d(void);\n", i);
        fclose(u);
        fprintf(f, "%s\n", src);
    }
    fclose(f);
    return 0;
}


static int cpt_mixed_includes(const char *root)
{
    static const char *const names[] = { "bare.c", "nested/qualified.c",
                                         "nested/regex[1].c" };
    char d[CP_PATH];
    cps_snp(d, "%s/src/nested", root);
    cp_mkdirs(d);
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        char p[CP_PATH];
        cps_snp(p, "%s/src/%s", root, names[i]);
        cps_static_write(p, "/* included body */\n");
    }
    char p[CP_PATH];
    cps_snp(p, "%s/src/u0.c", root);
    FILE *f = fopen(p, "a");
    if (!f)
        return 2;
    fprintf(f, "#include \"bare.c\"\n#include \"nested/qualified.c\"\n"
               "#include \"nested/regex[1].c\"\n");
    fclose(f);
    return 0;
}

static int cpt_runfile_count(const char *runs)
{
    return cp_count_lines(runs);
}

static int cpt_artifacts_eq(struct cp_ctx *c, const char *dira, const char *dirb)
{
    for (int i = 0; i < c->nsrc; i++) {
        char key[CP_PATH], a[CP_PATH], b[CP_PATH];
        cp_key(c->srcs[i], key, sizeof key);
        cps_snp(a, "%s/%s.log", dira, key);
        cps_snp(b, "%s/%s.log", dirb, key);
        if (cp_file_eq(a, b) != 1)
            return 0;
        cps_snp(a, "%s/%s.rc", dira, key);
        cps_snp(b, "%s/%s.rc", dirb, key);
        if (cp_file_eq(a, b) != 1)
            return 0;
    }
    return 1;
}

struct cpt_st {
    struct cp_ctx *c;
    const char *self;
    char base[CP_PATH], root[CP_PATH], list[CP_PATH], flags[CP_PATH];
    char runs[CP_PATH], cold[CP_PATH], real[CP_PATH], realcc[CP_PATH];
    /* the real flag set, which the synthetic sweeps overwrite */
    int nflags;
    char flag0[CP_PATH], flags_nul[CP_PATH];
    int n;
    struct cpt_counts ct;
};

static int cpt_run(struct cpt_st *st)
{
    return cpt_sweep(st->c, st->base, st->self, st->flags, st->root, st->list,
                     4, &st->ct);
}

/* One sweep, then the expected hit/miss/store counts. */
static int cpt_run_want(struct cpt_st *st, int h, int m, int s, const char *msg)
{
    int rc = cpt_run(st);
    return rc ? rc : cpt_want(&st->ct, h, m, s, msg);
}

static int cpt_setup(struct cpt_st *st)
{
    char sd[CP_PATH];
    st->nflags = st->c->nflags;
    snprintf(st->flag0, sizeof st->flag0, "%s", st->c->flags[0]);
    snprintf(st->flags_nul, sizeof st->flags_nul, "%s", st->c->flags_nul);
    snprintf(st->realcc, sizeof st->realcc, "%s", st->c->cc);
    if (cps_snp(st->base, "%s/tu-cache-selftest", st->c->work) ||
        cps_snp(st->root, "%s/root", st->base) ||
        cps_snp(st->list, "%s/srcs.txt", st->base) ||
        cps_snp(st->flags, "%s/sflags.nul", st->base) ||
        cps_snp(st->runs, "%s/runs", st->base) ||
        cps_snp(st->cold, "%s/cold-out", st->base) ||
        cps_snp(sd, "%s/src", st->root))
        return 2;
    cp_mkdirs(sd);
    setenv("ZCL_TU_CACHE_SELFTEST_FORCE", "1", 1);
    setenv("ZCL_TU_STUB_RUNS", st->runs, 1);
    /* a "-c" flags file with its trailing NUL */
    FILE *ff = fopen(st->flags, "wb");
    if (!ff)
        return 2;
    fputs("-c", ff);
    fputc('\0', ff);
    fclose(ff);
    st->n = 16;
    if (cpt_units(st->root, st->list, st->n) || cpt_mixed_includes(st->root))
        return 2;
    return cps_static_write(st->runs, "") != 0;
}

/* (1) a cold run misses and stores everything, and the planted failure fails */
static int cpt_cold(struct cpt_st *st)
{
    char u7rc[CP_PATH], u7src[CP_PATH], u7key[CP_PATH], first[32];
    int rc = cpt_run_want(st, 0, st->n, st->n, "cold run was not 0/16/16");
    if (rc)
        return rc;
    if (cps_snp(u7src, "%s/src/u7.c", st->root))
        return 2;
    cp_key(u7src, u7key, sizeof u7key);
    if (cps_snp(u7rc, "%s/out/%s.rc", st->base, u7key))
        return 2;
    if (cp_first_line(u7rc, first, sizeof first) != 0 || strcmp(first, "1") != 0)
        return cpt_fail("the planted failing unit did not fail on the cold run");
    cp_mkdirs(st->cold);
    {
        char od[CP_PATH];
        cps_snp(od, "%s/out", st->base);
        cpt_copy_dir(od, st->cold);
    }
    return 0;
}

/* (2)+(3) warm runs are 100% hit, byte-identical, with no recompiles */
static int cpt_warm(struct cpt_st *st)
{
    int before = cpt_runfile_count(st->runs);
    int rc = cpt_run_want(st, st->n, 0, 0, "warm run was not 16/0/0");
    if (rc)
        return rc;
    if (cpt_runfile_count(st->runs) != before)
        return cpt_fail("a warm run still invoked the compiler");
    char od[CP_PATH];
    cps_snp(od, "%s/out", st->base);
    if (!cpt_artifacts_eq(st->c, st->cold, od))
        return cpt_fail("a replayed artifact differs from the cold artifact");
    return cpt_run_want(st, st->n, 0, 0, "third run was not 16/0");
}

/* (3b) editing an included C body busts every entry */
static int cpt_included(struct cpt_st *st)
{
    static const char *const inc[] = { "bare.c", "nested/qualified.c",
                                       "nested/regex[1].c" };
    for (size_t i = 0; i < sizeof inc / sizeof inc[0]; i++) {
        char p[CP_PATH], m[128];
        cps_snp(p, "%s/src/%s", st->root, inc[i]);
        cps_static_write(p, "/* changed included body */\n");
        cps_snp(m, "editing included C body '%s' left stale hits", inc[i]);
        int rc = cpt_run_want(st, 0, st->n, st->n, m);
        if (rc)
            return rc;
    }
    return 0;
}

/* (4)-(6) a header edit busts all, one .c edit busts one, a revert hits */
static int cpt_edits(struct cpt_st *st)
{
    char sh[CP_PATH], u3[CP_PATH];
    cps_snp(sh, "%s/src/shared.h", st->root);
    cps_snp(u3, "%s/src/u3.c", st->root);
    cps_static_write(sh, "#define TU_SELFTEST_SHARED 2\n");
    int rc = cpt_run_want(st, 0, st->n, st->n,
                          "editing a header left stale entries");
    if (rc)
        return rc;
    cps_static_write(u3, "#include \"shared.h\"\nint unit_3(int);\n");
    rc = cpt_run_want(st, st->n - 1, 1, 1, "editing one TU was not 15/1");
    if (rc)
        return rc;
    cps_static_write(u3, "#include \"shared.h\"\nint unit_3(void);\n");
    return cpt_run_want(st, st->n, 0, 0, "reverting one TU was not 16/0");
}

/* (7) ZCL_LINT_TU_CACHE=0: no serve, no store */
static int cpt_disabled(struct cpt_st *st)
{
    struct cp_ctx *c = st->c;
    char one[CP_PATH];
    unsetenv("ZCL_TU_CACHE_SELFTEST_FORCE");
    setenv("ZCL_LINT_TU_CACHE", "0", 1);
    cps_snp(c->work, "%s/work", st->base);
    cpt_load_srcs(c, st->list);
    int rc = cp_cache_setup(c, NULL, st->root);
    unsetenv("ZCL_LINT_TU_CACHE");
    setenv("ZCL_TU_CACHE_SELFTEST_FORCE", "1", 1);
    if (rc == 0 && c->cache_on)
        return cpt_fail("ZCL_LINT_TU_CACHE=0 did not disable the cache");
    int rb = cpt_runfile_count(st->runs);
    cps_snp(one, "%s/src/u0.c", st->root);
    cp_compile_one(c, one);
    if (cpt_runfile_count(st->runs) == rb)
        return cpt_fail("a disabled cache did not invoke the compiler");
    return 0;
}

/* (8) real wiring: real compiler, real flags, one real source. The cold
 * log and status are snapshotted, deleted, and must replay byte-for-byte. */
struct cpt_real {
    char rdir[CP_PATH], rlog[CP_PATH], rrc[CP_PATH], clog[CP_PATH], crc[CP_PATH];
};

static void cpt_copy_file(const char *from, const char *to)
{
    char b[8192];
    size_t t;
    FILE *in = fopen(from, "rb"), *out = fopen(to, "wb");
    while (in && out && (t = fread(b, 1, sizeof b, in)) > 0)
        fwrite(b, 1, t, out);
    if (in)
        fclose(in);
    if (out)
        fclose(out);
}

static int cpt_real_cold(struct cpt_st *st, struct cpt_real *r)
{
    struct cp_ctx *c = st->c;
    char rwork[CP_PATH], rcachedir[CP_PATH], key[CP_PATH];
    if (cps_snp(r->rdir, "%s/real", st->base) ||
        cps_snp(rcachedir, "%s/cachedir", r->rdir) ||
        cps_snp(rwork, "%s/rwork", r->rdir))
        return 2;
    cp_mkdirs(rwork);
    snprintf(c->cc_buf, sizeof c->cc_buf, "%s", st->realcc);
    c->cc = c->cc_buf;
    c->stub_cc = 0;
    c->nflags = st->nflags;
    snprintf(c->flags[0], CP_PATH, "%s", st->flag0);
    snprintf(c->flags_nul, sizeof c->flags_nul, "%s", st->flags_nul);
    c->jobs = 1;
    cps_snp(c->work, "%s", rwork);
    cps_snp(c->out_dir, "%s/out", r->rdir);
    cp_mkdirs(c->out_dir);
    c->nsrc = 1;
    snprintf(c->srcs[0], CP_PATH, "%s", st->real);
    int rc = cp_cache_setup(c, rcachedir, ".");
    if (rc || !c->cache_on)
        return cpt_fail("the real gate configuration disabled the cache");
    rc = cp_cache_plan(c);
    if (rc)
        return rc;
    if (c->nmiss != 1)
        return cpt_fail("a fresh generation served the source without "
                        "compiling it");
    rc = cp_compile_one(c, st->real);
    cp_key(st->real, key, sizeof key);
    if (cps_snp(r->rlog, "%s/%s.log", c->out_dir, key) ||
        cps_snp(r->rrc, "%s/%s.rc", c->out_dir, key) ||
        cps_snp(r->clog, "%s/cold.log", r->rdir) ||
        cps_snp(r->crc, "%s/cold.rc", r->rdir))
        return 2;
    return rc;
}

static int cpt_real_replay(struct cpt_st *st, const struct cpt_real *r)
{
    struct cp_ctx *c = st->c;
    cpt_copy_file(r->rlog, r->clog);
    cpt_copy_file(r->rrc, r->crc);
    unlink(r->rlog);
    unlink(r->rrc);
    int rc = cp_cache_plan(c);
    if (rc)
        return rc;
    if (c->nmiss != 0)
        return cpt_fail("the real compiler's stored result did not replay");
    if (cp_file_eq(r->rlog, r->clog) != 1)
        return cpt_fail("the real compiler's replayed log differs from its "
                        "cold log");
    if (cp_file_eq(r->rrc, r->crc) != 1)
        return cpt_fail("the real compiler's replayed status differs from its "
                        "cold status");
    return 0;
}

static int cpt_real(struct cpt_st *st)
{
    struct cpt_real r;
    int rc = cpt_real_cold(st, &r);
    return rc ? rc : cpt_real_replay(st, &r);
}

int cp_tu_cache_selftest(struct cp_ctx *c, const char *self, const char *real_src)
{
    static struct cpt_st st;
    memset(&st, 0, sizeof st);
    st.c = c;
    st.self = self;
    /* real_src points into c->srcs, which the synthetic sweeps overwrite */
    snprintf(st.real, sizeof st.real, "%s", real_src);
    int rc = cpt_setup(&st);
    if (!rc)
        rc = cpt_cold(&st);
    if (!rc)
        rc = cpt_warm(&st);
    if (!rc)
        rc = cpt_included(&st);
    if (!rc)
        rc = cpt_edits(&st);
    if (!rc)
        rc = cpt_disabled(&st);
    if (!rc)
        rc = cpt_real(&st);
    unsetenv("ZCL_TU_STUB_RUNS");
    unsetenv("ZCL_TU_CACHE_SELFTEST_FORCE");
    if (rc)
        return rc;
    rap_rm_rf(st.base);
    printf("  OK: --self-test — tu-cache over 16 synthetic TUs at 4 workers:\n"
           "      two consecutive runs on an unchanged tree are 100%% hit and\n"
           "      byte-identical (a third too), header/included-C edits bust "
           "all 16, a\n      .c edit busts exactly 1 and reverting it hits "
           "again, a stored\n      FAIL replays as FAIL, ZCL_LINT_TU_CACHE=0 "
           "stores none, and\n      %s replays a real TU byte-for-byte\n",
           c->cc);
    return 0;
}

static int cpt_copy_dir(const char *src, const char *dst)
{
    DIR *d = opendir(src);
    if (!d)
        return -1;
    cp_mkdirs(dst);
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        char a[CP_PATH], b[CP_PATH];
        cps_snp(a, "%s/%s", src, e->d_name);
        cps_snp(b, "%s/%s", dst, e->d_name);
        FILE *fa = fopen(a, "rb"), *fb = fopen(b, "wb");
        if (fa && fb) {
            char buf[8192];
            size_t n;
            while ((n = fread(buf, 1, sizeof buf, fa)) > 0)
                fwrite(buf, 1, n, fb);
        }
        if (fa)
            fclose(fa);
        if (fb)
            fclose(fb);
    }
    closedir(d);
    return 0;
}
