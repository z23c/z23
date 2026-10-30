/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-fortify-masked-decls — a .c file may not call a
 * POSIX/GNU function whose declaration reaches it ONLY through a fortify
 * inline (i.e. only when optimisation is on), unless the file sets a
 * feature-test macro before its first #include. Ported from
 * tools/lint/check_fortify_masked_decls.sh (deleted). Selftest:
 * gate_fortify_masked_decls_selftest.c.
 *
 * WHY (bug class found live 2026-08-30). The build compiles with
 * -std=c23 -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2. Under glibc some
 * declarations (realpath et al.) arrive ONLY via the fortify inline, which
 * glibc activates only under optimisation. Such files compile purely as a
 * side effect of -O1+, and in C23 an implicit declaration is a hard error:
 * they break at -O0, under -U_FORTIFY_SOURCE, and on any non-glibc libc.
 *
 * The gate MEASURES the masked set instead of hardcoding it: for each
 * candidate it compiles a tiny TU with the project's real flags at -O0 and
 * at -O2 (fork + execvp, never a shell string); MASKED means fails at -O0
 * and succeeds at -O2. A control probe must compile or the gate refuses
 * (exit 2) rather than passing vacuously. Comments and string bodies are
 * blanked in-process with the shared cstrip_line (lib.c), so prose naming
 * a function does not trip the scan.
 *
 * The baseline is empty by design: if this gate fails, add the feature-test
 * guard, never a baseline row.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"

static const char k_fmd_gate[] = "check-fortify-masked-decls";

/* Candidates: POSIX/GNU functions glibc guards behind a feature-test macro
 * AND also gives a fortify inline, plus near neighbours. Being on this list
 * asserts nothing; only the -O0/-O2 measurement decides. */
static const char *const k_fmd_candidates[] = {
    "realpath", "ptsname_r", "getwd", "gethostname", "mktemp", "getcwd",
    "readlink", "readlinkat", "stpcpy", "stpncpy", "mempcpy", "strcasestr",
    "memmem", "strsep", "strdup", "strndup", "asprintf", "vasprintf",
    "getline", "getdelim", "usleep", "random", "srandom", "initstate",
    "setstate", "lockf", "pread", "pwrite", "ftruncate", "truncate",
    "fchdir", "symlink", "chroot", "wcpcpy", "wcpncpy",
};

enum { FMD_CC_MAX = 32, FMD_CC_BUF = 1024, FMD_MAX_MASKED = 64,
       FMD_NAME = 32, FMD_PATH = 1024, FMD_HITS = 512,
       FMD_OFF_CAP = 64 };

/* $CC in this tree is routinely a COMMAND LINE ("<path>/zcc cc"); it is
 * word-split on whitespace, exactly like the script's `read -r -a`. */
struct fmd_cc {
    char *argv[FMD_CC_MAX + 1];
    int argc;
    char buf[FMD_CC_BUF];
    char shown[FMD_CC_BUF];
};

/* Comment/string stripper state (strings=1: literal bodies are removed so a
 * masked function NAMED inside a literal is not a call). */

struct fmd_meas {
    struct fmd_cc cc;
    char masked[FMD_MAX_MASKED][FMD_NAME];
    int nmasked;
    regex_t re_inc, re_def;
    int re_ok;
};

/* One tracked file under scan. */
struct fmd_scan1 {
    const struct fmd_meas *m;
    struct cstrip st;
    int hit[FMD_MAX_MASKED];
    char hits[FMD_HITS];
    int any, inc_seen, guarded;
};

struct fmd_off { char path[FMD_PATH]; char hits[FMD_HITS]; };

struct fmd_run_ctx {
    const struct fmd_meas *m;
    const char *root;
    struct fmd_off *offs;
    size_t n, cap;
    int err;
};

/* ---------------------------------------------------------------- helpers */

static void fmd_cc_init(struct fmd_cc *cc)
{
    const char *e = getenv("CC");
    if (!e || !*e)
        e = "cc";
    if (ovf(snprintf(cc->buf, sizeof cc->buf, "%s", e), sizeof cc->buf))
        cc->buf[0] = '\0';
    cc->argc = 0;
    char *p = cc->buf;
    while (cc->argc < FMD_CC_MAX) {
        while (*p == ' ' || *p == '\t' || *p == '\n')
            p++;
        if (!*p)
            break;
        cc->argv[cc->argc++] = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n')
            p++;
        if (*p)
            *p++ = '\0';
    }
    cc->argv[cc->argc] = NULL;
    size_t o = 0;
    for (int i = 0; i < cc->argc; i++) {
        if (i && o + 1 < sizeof cc->shown)
            cc->shown[o++] = ' ';
        size_t l = strlen(cc->argv[i]);
        if (o + l + 1 >= sizeof cc->shown)
            break;
        memcpy(cc->shown + o, cc->argv[i], l);
        o += l;
    }
    cc->shown[o] = '\0';
}

static int fmd_write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    if (fputs(text, f) == EOF) {
        fclose(f);
        return -1;
    }
    return fclose(f) == 0 ? 0 : -1;
}

/* Runs the compiler (fork + execvp, no shell) with all output discarded.
 * Returns 0 compiled, 1 compile failed, -1 internal (fork/exec) error. */
static int fmd_compile(const char *src, const char *obj, const char *opt,
                       const struct fmd_cc *cc)
{
    char *av[FMD_CC_MAX + 10];
    int n = 0;
    for (int i = 0; i < cc->argc; i++)
        av[n++] = cc->argv[i];
    av[n++] = (char *)"-std=c23";
    av[n++] = (char *)"-D_POSIX_C_SOURCE=200809L";
    av[n++] = (char *)"-D_FORTIFY_SOURCE=2";
    av[n++] = (char *)opt;
    av[n++] = (char *)"-c";
    av[n++] = (char *)src;
    av[n++] = (char *)"-o";
    av[n++] = (char *)obj;
    av[n] = NULL;
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) {
            dup2(dn, STDOUT_FILENO);
            dup2(dn, STDERR_FILENO);
        }
        int zi = open("/dev/null", O_RDONLY);
        if (zi >= 0)
            dup2(zi, STDIN_FILENO);
        execvp(av[0], av);
        _exit(127);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : 1;
}

/* True when code contains `name` as a whole word followed by optional
 * whitespace and '('. */
static int fmd_name_called(const char *code, const char *name)
{
    size_t nl = strlen(name);
    const char *p = code;
    while ((p = strstr(p, name)) != NULL) {
        if (p > code && (isalnum((unsigned char)p[-1]) || p[-1] == '_')) {
            p++;
            continue;
        }
        const char *q = p + nl;
        while (*q == ' ' || *q == '\t')
            q++;
        if (*q == '(')
            return 1;
        p++;
    }
    return 0;
}

/* ------------------------------------------------------------ measurement */

int fmd_meas_create(const char *work, struct fmd_meas **out)
{
    *out = NULL;
    struct fmd_meas *m = calloc(1, sizeof *m);
    if (!m)
        return 2;
    memset(m, 0, sizeof *m);
    fmd_cc_init(&m->cc);
    char ctl[FMD_PATH], obj[FMD_PATH];
    if (ovf(snprintf(ctl, sizeof ctl, "%s/control.c", work), sizeof ctl) ||
        ovf(snprintf(obj, sizeof obj, "%s/control.o", work), sizeof obj)) {
        free(m);
        return 2;
    }
    if (fmd_write_file(ctl,
            "#include <stdlib.h>\nint main(void){return 0;}\n") != 0) {
        free(m);
        return 2;
    }
    if (fmd_compile(ctl, obj, "-O0", &m->cc) != 0) {
        fprintf(stderr,
                "%s: FAIL — the control probe does not compile with\n"
                "  CC=\"%s\" -std=c23 -D_POSIX_C_SOURCE=200809L "
                "-D_FORTIFY_SOURCE=2 -O0\n"
                "  The gate cannot measure anything, so it refuses rather "
                "than passing vacuously.\n", k_fmd_gate, m->cc.shown);
        free(m);
        return 2;
    }
    for (size_t i = 0; i < sizeof k_fmd_candidates /
                            sizeof k_fmd_candidates[0]; i++) {
        const char *fn = k_fmd_candidates[i];
        char src[FMD_PATH], pobj[FMD_PATH], text[640];
        if (ovf(snprintf(src, sizeof src, "%s/probe.c", work), sizeof src) ||
            ovf(snprintf(pobj, sizeof pobj, "%s/probe.o", work),
                sizeof pobj) ||
            ovf(snprintf(text, sizeof text,
                         "#include <stdlib.h>\n#include <stdio.h>\n"
                         "#include <string.h>\n#include <unistd.h>\n"
                         "#include <wchar.h>\n"
                         "void *zcl_probe_sink;\n"
                         "void zcl_probe(void) { zcl_probe_sink = "
                         "(void *)&%s; }\n", fn),
                sizeof text)) {
            free(m);
            return 2;
        }
        if (fmd_write_file(src, text) != 0) {
            free(m);
            return 2;
        }
        int rc0 = fmd_compile(src, pobj, "-O0", &m->cc);
        int rc2 = fmd_compile(src, pobj, "-O2", &m->cc);
        if (rc0 < 0 || rc2 < 0) {
            free(m);
            return 2;
        }
        if (rc0 != 0 && rc2 == 0 && m->nmasked < FMD_MAX_MASKED) {
            snprintf(m->masked[m->nmasked], FMD_NAME, "%s", fn);
            m->nmasked++;
        }
    }
    int e1 = regcomp(&m->re_inc,
                     "^[[:space:]]*#[[:space:]]*include", REG_EXTENDED);
    int e2 = regcomp(&m->re_def,
                     "^[[:space:]]*#[[:space:]]*define[[:space:]]+"
                     "(_DEFAULT_SOURCE|_GNU_SOURCE|_XOPEN_SOURCE|_BSD_SOURCE)",
                     REG_EXTENDED);
    if (e1 || e2) {
        if (e1 == 0)
            regfree(&m->re_inc);
        if (e2 == 0)
            regfree(&m->re_def);
        free(m);
        return 2;
    }
    m->re_ok = 1;
    *out = m;
    return 0;
}

void fmd_meas_free(struct fmd_meas *m)
{
    if (!m)
        return;
    if (m->re_ok) {
        regfree(&m->re_inc);
        regfree(&m->re_def);
    }
    free(m);
}

int fmd_meas_nmasked(const struct fmd_meas *m) { return m->nmasked; }

const char *fmd_meas_masked_first(const struct fmd_meas *m)
{
    return m->nmasked > 0 ? m->masked[0] : "";
}

/* Darwin and other non-glibc hosts can truthfully measure an empty set; the
 * lexical scanner still needs a discriminating name to test against. */
void fmd_meas_force_synthetic(struct fmd_meas *m)
{
    m->nmasked = 1;
    snprintf(m->masked[0], FMD_NAME, "%s", "zcl_synthetic_masked_decl");
}

void fmd_meas_masked_str(const struct fmd_meas *m, char *out, size_t cap)
{
    size_t o = 0;
    out[0] = '\0';
    for (int i = 0; i < m->nmasked; i++) {
        if (i && o + 1 < cap)
            out[o++] = ' ';
        size_t l = strlen(m->masked[i]);
        if (o + l + 1 >= cap)
            break;
        memcpy(out + o, m->masked[i], l);
        o += l;
        out[o] = '\0';
    }
}

/* -------------------------------------------------------------- scanning */

static int fmd_scan_cb(void *vp, const char *line, size_t len)
{
    struct fmd_scan1 *s = vp;
    const struct fmd_meas *m = s->m;
    size_t n = len;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    static char raw[CSTRIP_LINE_MAX], code[CSTRIP_LINE_MAX];
    if (n >= sizeof raw)
        return 2;
    memcpy(raw, line, n);
    raw[n] = '\0';
    if (!cstrip_line(&s->st, raw, n, code, sizeof code))
        return 2;
    for (int i = 0; i < m->nmasked; i++) {
        if (s->hit[i])
            continue;
        if (fmd_name_called(code, m->masked[i])) {
            s->hit[i] = 1;
            s->any = 1;
            size_t l = strlen(s->hits), nl = strlen(m->masked[i]);
            if (l + 1 + nl + 1 < sizeof s->hits) {
                s->hits[l] = ' ';
                memcpy(s->hits + l + 1, m->masked[i], nl + 1);
            }
        }
    }
    if (!s->inc_seen && !s->guarded &&
        regexec(&m->re_def, raw, 0, NULL, 0) == 0)
        s->guarded = 1;
    if (regexec(&m->re_inc, raw, 0, NULL, 0) == 0)
        s->inc_seen = 1;
    return 0;
}

/* Scans one file. Returns 0 clean, 1 offender (hits filled), 2 error. */
int fmd_scan_file(const char *path, const struct fmd_meas *m, char *hits,
                  size_t cap)
{
    struct fmd_scan1 *s = calloc(1, sizeof *s);
    if (!s)
        return 2;
    memset(s, 0, sizeof *s);
    s->m = m;
    int rc = lc_each_line(path, fmd_scan_cb, s, 1);
    int out = 2;
    if (rc != 0) {
        fprintf(stderr, "%s: cannot read %s — refusing to report it clean\n",
                k_fmd_gate, path);
    } else if (s->any && !s->guarded) {
        if (hits)
            snprintf(hits, cap, "%s", s->hits);
        out = 1;
    } else {
        out = 0;
    }
    free(s);
    return out;
}

/* -------------------------------------------------------------- the gate */

static int fmd_off_add(struct fmd_run_ctx *c, const char *path,
                       const char *hits)
{
    if (c->n == c->cap) {
        size_t ncap = c->cap ? c->cap * 2 : FMD_OFF_CAP;
        struct fmd_off *no = malloc(ncap * sizeof *no);
        if (!no)
            return -1;
        if (c->n)
            memcpy(no, c->offs, c->n * sizeof *no);
        free(c->offs);
        c->offs = no;
        c->cap = ncap;
    }
    snprintf(c->offs[c->n].path, FMD_PATH, "%s", path);
    snprintf(c->offs[c->n].hits, FMD_HITS, "%s", hits);
    c->n++;
    return 0;
}

static int fmd_index_cb(const char *path, int stage, void *vp)
{
    (void)stage;
    struct fmd_run_ctx *c = vp;
    size_t l = strlen(path);
    if (l < 3 || strcmp(path + l - 2, ".c") != 0)
        return 0;
    char full[FMD_PATH];
    if (ovf(snprintf(full, sizeof full, "%s/%s", c->root, path),
            sizeof full)) {
        c->err = 1;
        return 1;
    }
    struct stat sb;
    if (stat(full, &sb) != 0 || !S_ISREG(sb.st_mode))
        return 0; /* the script's `[ -f "$f" ] || continue` */
    char hits[FMD_HITS];
    int rc = fmd_scan_file(full, c->m, hits, sizeof hits);
    if (rc == 2) {
        c->err = 1;
        return 1;
    }
    if (rc == 1 && fmd_off_add(c, path, hits) != 0) {
        c->err = 1;
        return 1;
    }
    return 0;
}

static void fmd_report_fail(const struct fmd_run_ctx *c, const char *mset,
                            const char *cc)
{
    fprintf(stderr, "%s: FAILED\n\n", k_fmd_gate);
    fputs("These files call a function this toolchain declares ONLY through "
          "the\nfortify inline, which glibc enables only when optimisation "
          "is on:\n\n", stderr);
    for (size_t i = 0; i < c->n; i++)
        fprintf(stderr, "  %s calls:%s\n", c->offs[i].path, c->offs[i].hits);
    fprintf(stderr,
            "\nMeasured masked set on CC=\"%s\":%s\n\n"
            "Each one compiles today by accident of -O2 and is a hard C23 "
            "error at\n-O0, under -U_FORTIFY_SOURCE, and on any non-glibc "
            "libc. Fix by adding\nthis BEFORE the file's first #include "
            "(after them it does nothing --\nfeature-test macros are read "
            "when <features.h> is first pulled in):\n\n"
            "    #if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)\n"
            "    #define _DEFAULT_SOURCE\n"
            "    #endif\n\n"
            "The baseline for this gate is empty by design. Add the guard, "
            "not a row.\n", cc, mset);
}

int check_fortify_masked_decls_run(int argc, char **argv)
{
    const char *root = (argc >= 1 && argv[0] && argv[0][0]) ? argv[0] : ".";
    char work[] = "/tmp/fortify-masked-decls.XXXXXX";
    if (!mkdtemp(work)) {
        fprintf(stderr, "%s: cannot create work dir\n", k_fmd_gate);
        return 2;
    }
    struct fmd_meas *m = NULL;
    int rc = fmd_meas_create(work, &m);
    rap_rm_rf(work);
    if (rc)
        return 2;
    char mset[FMD_CC_BUF];
    fmd_meas_masked_str(m, mset, sizeof mset);
    if (m->nmasked == 0) {
        printf("%s: PASSED — this toolchain masks no candidate\n"
               "  declaration behind optimisation (control probe compiled, "
               "so the\n  measurement ran). CC=\"%s\"\n",
               k_fmd_gate, m->cc.shown);
        fmd_meas_free(m);
        return 0;
    }
    struct fmd_run_ctx c;
    memset(&c, 0, sizeof c);
    c.m = m;
    c.root = root;
    char bad[8] = {0};
    int grc = lint_git_index_foreach(fmd_index_cb, &c, bad);
    if (c.err || grc) {
        free(c.offs);
        fmd_meas_free(m);
        fprintf(stderr, "%s: index scan failed\n", k_fmd_gate);
        return 2;
    }
    if (c.n > 0) {
        fmd_report_fail(&c, mset, m->cc.shown);
        free(c.offs);
        fmd_meas_free(m);
        return 1;
    }
    free(c.offs);
    fmd_meas_free(m);
    printf("%s: PASSED (masked set:%s; no unguarded caller)\n", k_fmd_gate,
           mset);
    return 0;
}
