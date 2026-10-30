/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-published-platforms — every platform the install path
 * CLAIMS must be one the release process actually produces. Ported from
 * the former shell script check_published_platforms (deleted). Selftest:
 * gate_published_platforms_selftest.c.
 *
 * THE FAILURE THIS PREVENTS, precisely. A stranger runs
 * curl https://z23.sh | sh. The shim names their machine, looks it up in its
 * published table, and either refuses by name or fetches
 * <origin>/bootstrap/<triple>/z23-bootstrap. A name in that table with nothing
 * behind it does not degrade gracefully: it converts an honest, informative
 * refusal into a 404 — or worse, into a digest check against a digest nobody
 * ever wrote — on someone else's computer. Widening the claim is a one-word
 * edit; producing the artifact is a toolchain, a second-stage installer and a
 * service lifecycle. Nothing in the source stops the one-word edit, so this
 * does.
 *
 * FOUR CLAIMS, FOUR AUTHORITIES:
 *   platform/packaging/install/install.sh        PUBLISHED_PLATFORMS + BOOT_*
 *   platform/packaging/install/install.ps1       $BootPins keys
 *   platform/modules/install/src/front_door_platform.c  FD_PUBLISHED
 *   platform/packaging/release/build_release.sh  what is actually produced
 *
 * The cutter is the authority and it is ASKED (--print-bootstrap-platforms,
 * --print-runtime-platforms) via lcp_run of bash — never system(), popen()
 * or a shell string — so this gate holds no second copy of the answer that
 * could drift from the first. The claim sets may legitimately DIFFER from each
 * other and from the produced sets (subset, not equality): narrowing a claim
 * is always allowed, widening one is never allowed silently.
 *
 * Checks: (1) install.sh claims ⊆ produced bootstrap; (2) each claim has a
 * digest-selecting case arm and its BOOT_ row; (3) reverse of 2 — no arm for
 * an unpublished platform; (4) install.ps1 claims ⊆ produced bootstrap;
 * (5) FD_PUBLISHED ⊆ produced runtime; (6) every checked-in digest is the
 * all-zero sentinel (real digests belong only in the copies the cutter
 * publishes); (7) reachability — no produced platform's cpu may be a fold
 * SOURCE in install.sh's uname -m rewrite, or no machine can ever match the
 * artifact built for it (the frozen darwin-arm64 regression).
 *
 * Exit 0 pass, 1 violation, 2 usage or internal error. Unreadable inputs and
 * parse overflow are errors (2), never skips. Environment overrides
 * ZCL_PP_INSTALL_SH / ZCL_PP_INSTALL_PS1 / ZCL_PP_FRONT_DOOR_C / ZCL_PP_CUTTER
 * exist so the selftest can point the same checks at mutated fixtures.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <regex.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_proc.h"
#include "lintc_sig.h"

static const char k_ppp_gate[] = "check-published-platforms";
#define PPP_Z64 "0000000000000000000000000000000000000000000000000000000000000000"

enum { PPP_N = 64, PPP_NAME = 64, PPP_LINE = 1024, PPP_ROWS = 32,
       PPP_ROW = 300, PPP_CAP = 4096, PPP_BIG = 8192, PPP_VAR = 96 };

static const char k_ppp_pat_pub[] =
    "^PUBLISHED_PLATFORMS=\"(.*)\"[[:space:]]*$";
static const char k_ppp_pat_arm[] =
    "^[[:space:]]*([a-z0-9][a-z0-9_.-]*)\\)[[:space:]]*WANT=";
static const char k_ppp_pat_boot[] = "^BOOT_[A-Z0-9_]*=";
static const char k_ppp_pat_zero[] = "^BOOT_ZERO=0{64}$";
static const char k_ppp_pat_fold[] =
    "^case \"\\$\\(uname -m\\)\" in (.*) esac$";
static const char k_ppp_pat_ps1[] =
    "^[[:space:]]*['\"]([a-z0-9][a-z0-9_.-]*)['\"][[:space:]]*=[[:space:]]*"
    "[\"'][0-9a-f]{64}['\"]";
static const char k_ppp_pat_fd[] =
    "^#define[[:space:]]+FD_PUBLISHED[[:space:]]+\"(.*)\".*$";

struct ppp_set { char v[PPP_N][PPP_NAME]; int n; };

struct ppp_sh {
    regex_t re_pub, re_arm, re_boot, re_zero, re_fold;
    struct ppp_set pub, arms, fold;
    char boots[PPP_ROWS][PPP_ROW];
    int nboots, has_zero, err;
};

struct ppp_ps1 {
    regex_t re;
    struct ppp_set win;
    char rows[PPP_ROWS][PPP_ROW];
    int nrows, err;
};

struct ppp_fd {
    regex_t re;
    struct ppp_set rt;
    int err;
};

struct ppp_all {
    struct ppp_sh sh;
    struct ppp_ps1 ps1;
    struct ppp_fd fd;
    struct ppp_set boot, rt;
    FILE *err;
    int bad;
};

/* ── small set and string helpers ─────────────────────────────────────── */

static int ppp_add(struct ppp_set *s, const char *name)
{
    if (s->n >= PPP_N) {
        fprintf(stderr, "%s: platform set exceeds %d\n", k_ppp_gate, PPP_N);
        return 2;
    }
    if (strlen(name) >= PPP_NAME) {
        fprintf(stderr, "%s: platform name exceeds %d\n", k_ppp_gate,
                PPP_NAME);
        return 2;
    }
    strcpy(s->v[s->n], name);
    s->n++;
    return 0;
}

static int ppp_in(const struct ppp_set *s, const char *want)
{
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->v[i], want) == 0)
            return 1;
    return 0;
}

static int ppp_split(char *s, const char *delim, struct ppp_set *set)
{
    char *save = NULL;
    for (char *t = strtok_r(s, delim, &save); t; t = strtok_r(NULL, delim,
         &save)) {
        int rc = ppp_add(set, t);
        if (rc)
            return rc;
    }
    return 0;
}

static int ppp_cpy(char *dst, size_t cap, const char *line,
                   const regmatch_t *m)
{
    size_t n = (size_t)(m->rm_eo - m->rm_so);
    if (n >= cap)
        return 2;
    memcpy(dst, line + m->rm_so, n);
    dst[n] = '\0';
    return 0;
}

/* join_trail=1 mirrors tr '\n' ' ': every item followed by one space. */
static int ppp_join(const struct ppp_set *s, char *buf, size_t cap,
                    int join_trail)
{
    size_t o = 0;
    buf[0] = '\0';
    for (int i = 0; i < s->n; i++) {
        size_t l = strlen(s->v[i]);
        int sep = join_trail || i > 0;
        if (o + l + (size_t)sep + 1 > cap)
            return 2;
        if (sep && !join_trail)
            buf[o++] = ' ';
        memcpy(buf + o, s->v[i], l);
        o += l;
        if (join_trail)
            buf[o++] = ' ';
    }
    buf[o] = '\0';
    return 0;
}

static void ppp_fail(struct ppp_all *a, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(a->err, "%s: FAIL: ", k_ppp_gate);
    vfprintf(a->err, fmt, ap);
    fputc('\n', a->err);
    va_end(ap);
    a->bad = 1;
}

/* ── the cpu fold table, read from the shim (never restated here) ─────── */

static void ppp_strip_quotes(char *v)
{
    size_t n = strlen(v);
    if (n >= 2 && v[0] == '"' && v[n - 1] == '"') {
        memmove(v, v + 1, n - 2);
        v[n - 2] = '\0';
    }
}

static int ppp_fold_pats(struct ppp_set *fold, const char *pat,
                         const char *value)
{
    char tok[PPP_NAME];
    size_t o = 0;
    for (const char *p = pat; ; p++) {
        if (*p != '\0' && *p != ' ' && *p != '|') {
            if (o + 1 >= sizeof tok)
                continue;
            tok[o++] = *p;
            continue;
        }
        tok[o] = '\0';
        o = 0;
        int skip = tok[0] == '\0' || strcmp(tok, "*") == 0 ||
                   strcmp(tok, value) == 0;
        int rc = skip ? 0 : ppp_add(fold, tok);
        if (rc)
            return rc;
        if (*p == '\0')
            return 0;
    }
}

/* Selftest hook: the last token being skipped ("*", the install.sh fallback
 * arm) must still stop at the terminator and never read the bytes after it.
 * Returns the number of folds recorded (0 expected). */
int ppp_fold_tail_probe(void)
{
    struct ppp_set fold = { .n = 0 };
    char pat[16] = " *\0zz|yy";
    if (ppp_fold_pats(&fold, pat, "x") != 0)
        return -1;
    return fold.n;
}

/* One arm of the uname -m case: an arm is a FOLD when the value it assigns
 * is not the alternative itself (amd64 folds, x86_64 is the identity). */
static int ppp_fold_arm(struct ppp_set *fold, const char *arm)
{
    const char *close = strchr(arm, ')');
    const char *cpu = strstr(arm, "cpu=");
    if (!close || !cpu || cpu < close)
        return 0;
    char value[PPP_NAME];
    size_t i = 0;
    cpu += 4;
    while (cpu[i] != '\0' && cpu[i] != ' ' && i + 1 < sizeof value) {
        value[i] = cpu[i];
        i++;
    }
    value[i] = '\0';
    ppp_strip_quotes(value);
    char pat[PPP_LINE];
    size_t n = (size_t)(close - arm);
    if (n >= sizeof pat) {
        fprintf(stderr, "%s: fold arm exceeds %d\n", k_ppp_gate, PPP_LINE);
        return 2;
    }
    memcpy(pat, arm, n);
    pat[n] = '\0';
    return ppp_fold_pats(fold, pat, value);
}

static int ppp_fold_add(struct ppp_set *fold, const char *inner)
{
    char buf[PPP_LINE];
    if (strlen(inner) >= sizeof buf) {
        fprintf(stderr, "%s: fold case line exceeds %d\n", k_ppp_gate,
                PPP_LINE);
        return 2;
    }
    strcpy(buf, inner);
    char *save = NULL;
    for (char *arm = strtok_r(buf, ";", &save); arm; arm = strtok_r(NULL,
         ";", &save)) {
        int rc = ppp_fold_arm(fold, arm);
        if (rc)
            return rc;
    }
    return 0;
}

/* ── parsing the three claim files ────────────────────────────────────── */

static int ppp_sh_bootline(struct ppp_sh *s, const char *buf)
{
    regmatch_t m[2];
    if (regexec(&s->re_boot, buf, 2, m, 0) != 0)
        return 0;
    if (strncmp(buf, "BOOT_ZERO=", 10) == 0) {
        if (regexec(&s->re_zero, buf, 0, NULL, 0) == 0)
            s->has_zero = 1;
        return 0;
    }
    if (s->nboots >= PPP_ROWS || strlen(buf) >= PPP_ROW) {
        fprintf(stderr, "%s: BOOT_ rows exceed %d\n", k_ppp_gate, PPP_ROWS);
        s->err = 1;
        return 2;
    }
    strcpy(s->boots[s->nboots], buf);
    s->nboots++;
    return 0;
}

static int ppp_sh_line(void *ctx, const char *line, size_t len)
{
    struct ppp_sh *s = ctx;
    regmatch_t m[2];
    char buf[PPP_LINE], inner[PPP_LINE];
    size_t n = len;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    if (n >= sizeof buf) {
        fprintf(stderr, "%s: install.sh line exceeds %d\n", k_ppp_gate,
                PPP_LINE);
        return 2;
    }
    memcpy(buf, line, n);
    buf[n] = '\0';
    if (regexec(&s->re_pub, buf, 2, m, 0) == 0
        && ppp_cpy(inner, sizeof inner, buf, &m[1]) == 0) {
        if (ppp_split(inner, " \t", &s->pub)) {
            s->err = 1;
            return 2;
        }
    }
    if (regexec(&s->re_arm, buf, 2, m, 0) == 0
        && ppp_cpy(inner, sizeof inner, buf, &m[1]) == 0) {
        if (ppp_add(&s->arms, inner)) {
            s->err = 1;
            return 2;
        }
    }
    if (regexec(&s->re_fold, buf, 2, m, 0) == 0
        && ppp_cpy(inner, sizeof inner, buf, &m[1]) == 0) {
        if (ppp_fold_add(&s->fold, inner)) {
            s->err = 1;
            return 2;
        }
    }
    if (ppp_sh_bootline(s, buf)) {
        s->err = 1;
        return 2;
    }
    return 0;
}

static int ppp_compile(regex_t *re, const char *pat)
{
    int rc = regcomp(re, pat, REG_EXTENDED);
    return rc ? reg_fail(re, rc) : 0;
}

static int ppp_parse_sh(const char *path, struct ppp_sh *s)
{
    memset(s, 0, sizeof *s);
    if (ppp_compile(&s->re_pub, k_ppp_pat_pub)
        || ppp_compile(&s->re_arm, k_ppp_pat_arm)
        || ppp_compile(&s->re_boot, k_ppp_pat_boot)
        || ppp_compile(&s->re_zero, k_ppp_pat_zero)
        || ppp_compile(&s->re_fold, k_ppp_pat_fold)) {
        regfree(&s->re_pub); regfree(&s->re_arm); regfree(&s->re_boot);
        regfree(&s->re_zero); regfree(&s->re_fold);
        return 2;
    }
    int rc = lc_each_line(path, ppp_sh_line, s, 1);
    regfree(&s->re_pub); regfree(&s->re_arm); regfree(&s->re_boot);
    regfree(&s->re_zero); regfree(&s->re_fold);
    if (s->err)
        return 2;
    return rc == 0 ? 0 : 2;
}

static int ppp_ps1_line(void *ctx, const char *line, size_t len)
{
    struct ppp_ps1 *s = ctx;
    regmatch_t m[2];
    char buf[PPP_ROW], name[PPP_NAME];
    size_t n = len;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    if (n >= sizeof buf) {
        fprintf(stderr, "%s: install.ps1 line exceeds %d\n", k_ppp_gate,
                PPP_ROW);
        return 2;
    }
    memcpy(buf, line, n);
    buf[n] = '\0';
    if (regexec(&s->re, buf, 2, m, 0) != 0)
        return 0;
    if (ppp_cpy(name, sizeof name, buf, &m[1]) || ppp_add(&s->win, name)) {
        s->err = 1;
        return 2;
    }
    if (s->nrows >= PPP_ROWS) {
        fprintf(stderr, "%s: BootPins rows exceed %d\n", k_ppp_gate,
                PPP_ROWS);
        s->err = 1;
        return 2;
    }
    strcpy(s->rows[s->nrows], buf);
    s->nrows++;
    return 0;
}

/* Shared tail of the ps1 and front-door scans: compile pat into *re, feed
 * every line of path to cb with ctx, and fold the line walk and the
 * callback's own error flag into 0 or 2. */
static int ppp_scan(const char *path, regex_t *re, const char *pat,
                    int (*cb)(void *, const char *, size_t), void *ctx,
                    const int *err)
{
    if (ppp_compile(re, pat))
        return 2;
    int rc = lc_each_line(path, cb, ctx, 1);
    regfree(re);
    if (*err)
        return 2;
    return rc == 0 ? 0 : 2;
}

static int ppp_parse_ps1(const char *path, struct ppp_ps1 *s)
{
    memset(s, 0, sizeof *s);
    return ppp_scan(path, &s->re, k_ppp_pat_ps1, ppp_ps1_line, s, &s->err);
}

static int ppp_fd_line(void *ctx, const char *line, size_t len)
{
    struct ppp_fd *s = ctx;
    regmatch_t m[2];
    char buf[PPP_LINE], inner[PPP_LINE];
    size_t n = len;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    if (n >= sizeof buf) {
        fprintf(stderr, "%s: front_door_platform.c line exceeds %d\n",
                k_ppp_gate, PPP_LINE);
        return 2;
    }
    memcpy(buf, line, n);
    buf[n] = '\0';
    if (regexec(&s->re, buf, 2, m, 0) == 0
        && ppp_cpy(inner, sizeof inner, buf, &m[1]) == 0) {
        if (ppp_split(inner, " \t", &s->rt)) {
            s->err = 1;
            return 2;
        }
    }
    return 0;
}

static int ppp_parse_fd(const char *path, struct ppp_fd *s)
{
    memset(s, 0, sizeof *s);
    return ppp_scan(path, &s->re, k_ppp_pat_fd, ppp_fd_line, s, &s->err);
}

/* ── asking the cutter (lcp_run of bash, stdout captured) ─────────────── */

static int ppp_cutter(const char *cutter, const char *flag,
                      struct ppp_set *out)
{
    static int installed;
    char *const argv[] = { (char *)"bash", (char *)cutter, (char *)flag,
                           NULL };
    struct lcp_spec spec = { .argv = argv, .mode = LCP_OUT_ERRPASS,
                             .grace_ms = 500 };
    struct lcp_buf cap = { 0 };
    int code = 127, rc, sig;
    char buf[PPP_CAP];

    if (!installed && lsc_install() != 0)
        return 2;
    installed = 1;
    fflush(stdout);
    fflush(stderr);
    rc = lcp_run(&spec, &cap, &code);
    lsc_unblock();
    sig = lsc_pending();
    if (sig) {
        lcp_buf_free(&cap);
        lsc_finish(sig);
        return 2;
    }
    if (rc != 0 || cap.lost) {
        lcp_buf_free(&cap);
        return 2;
    }
    if (cap.len + 1 >= sizeof buf) {
        fprintf(stderr, "%s: cutter output exceeds %d\n", k_ppp_gate,
                PPP_CAP);
        lcp_buf_free(&cap);
        return 2;
    }
    if (cap.len > 0)
        memcpy(buf, cap.data, cap.len);
    buf[cap.len] = '\0';
    lcp_buf_free(&cap);
    if (code != 0)
        return 1;
    return ppp_split(buf, " \t\r\n", out);
}

/* ── the checks ───────────────────────────────────────────────────────── */

static int ppp_var_row(struct ppp_all *a, const char *plat)
{
    char var[PPP_VAR];
    size_t o = 5;
    memcpy(var, "BOOT_", 5);
    for (const char *p = plat; *p != '\0'; p++)
        var[o++] = (*p == '-') ? '_' : (char)toupper((unsigned char)*p);
    var[o] = '\0';
    for (int i = 0; i < a->sh.nboots; i++)
        if (strncmp(a->sh.boots[i], var, o) == 0 && a->sh.boots[i][o] == '=')
            return 0;
    ppp_fail(a, "install.sh publishes %s but has no %s= row", plat, var);
    return 0;
}

static int ppp_claims_subset(struct ppp_all *a, const char *prod)
{
    for (int i = 0; i < a->sh.pub.n; i++) {
        const char *p = a->sh.pub.v[i];
        if (!ppp_in(&a->boot, p))
            ppp_fail(a, "install.sh publishes %s, but the release cutter "
                    "produces no z23-bootstrap for it (produced: %s)", p,
                    prod);
        if (!ppp_in(&a->sh.arms, p))
            ppp_fail(a, "install.sh publishes %s but has no case arm "
                    "selecting a digest for it", p);
        (void)ppp_var_row(a, p);
    }
    return 0;
}

static int ppp_check_posix_claims(struct ppp_all *a)
{
    char prod[PPP_BIG];
    int rc = ppp_join(&a->boot, prod, sizeof prod, 0);
    if (rc)
        return 2;
    rc = ppp_claims_subset(a, prod);
    if (rc)
        return rc;
    for (int i = 0; i < a->sh.arms.n; i++)
        if (!ppp_in(&a->sh.pub, a->sh.arms.v[i]))
            ppp_fail(a, "install.sh has a case arm for %s, which "
                    "PUBLISHED_PLATFORMS does not name", a->sh.arms.v[i]);
    return 0;
}

static int ppp_check_win_rt(struct ppp_all *a)
{
    char prod[PPP_BIG];
    for (int i = 0; i < a->ps1.win.n; i++)
        if (!ppp_in(&a->boot, a->ps1.win.v[i]))
            ppp_fail(a, "install.ps1 publishes %s, but the release cutter "
                    "produces no z23-bootstrap for it", a->ps1.win.v[i]);
    int rc = ppp_join(&a->rt, prod, sizeof prod, 0);
    if (rc)
        return 2;
    for (int i = 0; i < a->fd.rt.n; i++)
        if (!ppp_in(&a->rt, a->fd.rt.v[i]))
            ppp_fail(a, "FD_PUBLISHED names %s, but the release cutter "
                    "packages no runtime for it (packaged: %s)",
                    a->fd.rt.v[i], prod);
    return 0;
}

static int ppp_check_sentinel(struct ppp_all *a)
{
    for (int i = 0; i < a->sh.nboots; i++) {
        const char *l = a->sh.boots[i];
        /* Neither accepted tail contains '=', so "ends with =X" is the same
         * as "the text from the last '=' equals =X". */
        const char *eq = strrchr(l, '=');
        if (!eq || (strcmp(eq, "=\"$BOOT_ZERO\"") != 0
                    && strcmp(eq, "=" PPP_Z64) != 0))
            ppp_fail(a, "install.sh has a non-sentinel baked digest checked "
                    "in: %s", l);
    }
    if (!a->sh.has_zero)
        ppp_fail(a, "install.sh has no all-zero BOOT_ZERO sentinel to "
                "compare against");
    for (int i = 0; i < a->ps1.nrows; i++)
        if (strstr(a->ps1.rows[i], PPP_Z64) == NULL)
            ppp_fail(a, "install.ps1 has a non-sentinel baked digest checked "
                    "in: %s", a->ps1.rows[i]);
    return 0;
}

static int ppp_reach_one(struct ppp_all *a, const char *plat)
{
    const char *cpu = strchr(plat, '-');
    if (cpu == NULL || cpu[1] == '\0')
        return 0;
    cpu++;
    if (!ppp_in(&a->sh.fold, cpu))
        return 0;
    ppp_fail(a, "the cutter produces %s, but install.sh rewrites the cpu "
            "'%s' before looking a platform up, so no machine can ever "
            "match it", plat, cpu);
    return 0;
}

static int ppp_check_reach(struct ppp_all *a)
{
    for (int i = 0; i < a->boot.n; i++) {
        int rc = ppp_reach_one(a, a->boot.v[i]);
        if (rc)
            return rc;
    }
    for (int i = 0; i < a->rt.n; i++) {
        int rc = ppp_reach_one(a, a->rt.v[i]);
        if (rc)
            return rc;
    }
    return 0;
}

/* ── assembly ─────────────────────────────────────────────────────────── */

static int ppp_require_file(const char *path, FILE *err)
{
    struct stat st;
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
        return 0;
    fprintf(err, "%s: FAIL: missing %s\n", k_ppp_gate, path);
    return 1;
}

static int ppp_inputs_ok(const char *sh, const char *ps1, const char *fdc,
                         const char *cutter, FILE *err)
{
    if (ppp_require_file(sh, err))
        return 1;
    if (ppp_require_file(ps1, err))
        return 1;
    if (ppp_require_file(fdc, err))
        return 1;
    return ppp_require_file(cutter, err);
}

/* An empty answer from the cutter is a broken cutter, not "nothing is
 * produced": fail rather than vacuously pass everything. */
static int ppp_produced(const char *cutter, struct ppp_set *boot,
                        struct ppp_set *rt, FILE *err)
{
    int rc = ppp_cutter(cutter, "--print-bootstrap-platforms", boot);
    if (rc == 1) {
        fprintf(err, "%s: FAIL: %s --print-bootstrap-platforms failed\n",
                k_ppp_gate, cutter);
        return 1;
    }
    if (rc)
        return 2;
    rc = ppp_cutter(cutter, "--print-runtime-platforms", rt);
    if (rc == 1) {
        fprintf(err, "%s: FAIL: %s --print-runtime-platforms failed\n",
                k_ppp_gate, cutter);
        return 1;
    }
    if (rc)
        return 2;
    if (boot->n == 0) {
        fprintf(err, "%s: FAIL: the cutter names no bootstrap platform at "
                "all\n", k_ppp_gate);
        return 1;
    }
    if (rt->n == 0) {
        fprintf(err, "%s: FAIL: the cutter names no runtime platform at "
                "all\n", k_ppp_gate);
        return 1;
    }
    return 0;
}

/* Shared with the selftest: 0 pass, 1 violation, 2 internal error. */
int ppp_check(const char *sh, const char *ps1, const char *fdc,
              const char *cutter, FILE *out, FILE *err)
{
    (void)out;
    if (ppp_inputs_ok(sh, ps1, fdc, cutter, err))
        return 1;
    struct ppp_all a;
    memset(&a, 0, sizeof a);
    a.err = err;
    int rc = ppp_produced(cutter, &a.boot, &a.rt, err);
    if (rc)
        return rc;
    rc = ppp_parse_sh(sh, &a.sh);
    if (rc == 0)
        rc = ppp_parse_ps1(ps1, &a.ps1);
    if (rc == 0)
        rc = ppp_parse_fd(fdc, &a.fd);
    if (rc)
        return rc;
    rc = ppp_check_posix_claims(&a);
    if (rc == 0)
        rc = ppp_check_win_rt(&a);
    if (rc == 0)
        rc = ppp_check_sentinel(&a);
    if (rc == 0)
        rc = ppp_check_reach(&a);
    if (rc)
        return rc;
    return a.bad ? 1 : 0;
}

/* Rebuilds the bracketed claim lists for the PASS note (trailing space, as
 * the shell original's tr produced). which: 0 sh, 1 ps1, 2 fd. */
static int ppp_note_one(const char *path, int which, char *buf, size_t cap)
{
    int rc = 2;
    if (which == 0) {
        struct ppp_sh s;
        rc = ppp_parse_sh(path, &s);
        if (rc == 0)
            rc = ppp_join(&s.pub, buf, cap, 1);
    } else if (which == 1) {
        struct ppp_ps1 s;
        rc = ppp_parse_ps1(path, &s);
        if (rc == 0)
            rc = ppp_join(&s.win, buf, cap, 1);
    } else {
        struct ppp_fd s;
        rc = ppp_parse_fd(path, &s);
        if (rc == 0)
            rc = ppp_join(&s.rt, buf, cap, 1);
    }
    return rc;
}

static int ppp_pass_note(const char *sh, const char *ps1, const char *fdc)
{
    char a[PPP_BIG], b[PPP_BIG], c[PPP_BIG];
    int rc = ppp_note_one(sh, 0, a, sizeof a);
    if (rc == 0)
        rc = ppp_note_one(ps1, 1, b, sizeof b);
    if (rc == 0)
        rc = ppp_note_one(fdc, 2, c, sizeof c);
    if (rc)
        return 2;
    printf("%s: PASS — install.sh publishes [%s], install.ps1 publishes "
           "[%s], FD_PUBLISHED runtimes [%s]; every one is produced by "
           "platform/packaging/release/build_release.sh, and every "
           "checked-in digest is the sentinel.\n", k_ppp_gate, a, b, c);
    return 0;
}

int check_published_platforms_run(int argc, char **argv)
{
    if (argc >= 1) {
        fprintf(stderr, "%s: unknown argument: %s\n", k_ppp_gate, argv[0]);
        return 2;
    }
    const char *sh = env_or("ZCL_PP_INSTALL_SH",
                            "platform/packaging/install/install.sh");
    const char *ps1 = env_or("ZCL_PP_INSTALL_PS1",
                             "platform/packaging/install/install.ps1");
    const char *fdc = env_or("ZCL_PP_FRONT_DOOR_C",
                             "platform/modules/install/src/"
                             "front_door_platform.c");
    const char *cutter = env_or("ZCL_PP_CUTTER",
                                "platform/packaging/release/"
                                "build_release.sh");
    int rc = ppp_check(sh, ps1, fdc, cutter, stdout, stderr);
    if (rc == 0)
        return ppp_pass_note(sh, ps1, fdc);
    if (rc == 1) {
        fprintf(stderr, "%s: a front door claims a platform the release "
                "process does not produce.\n", k_ppp_gate);
        fprintf(stderr, "  Fix the claim, or produce the artifact — never "
                "the other way round.\n");
        fprintf(stderr, "  See docs/work/BOOTSTRAP_PLAN.md, \"Platform "
                "work\".\n");
        return 1;
    }
    return rc;
}
