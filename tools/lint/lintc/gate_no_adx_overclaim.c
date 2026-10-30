/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-no-adx-overclaim — a lib/ source may not advertise
 * ADCX/ADOX carry chains that its own compiled object does not contain.
 * Ported from tools/lint/check_no_adx_overclaim.sh (deleted). Selftest:
 * gate_no_adx_overclaim_selftest.c.
 *
 * The population is every source under core engine contexts cognition
 * platform that either carries target(...adx...) in a __attribute__ or
 * includes the shared "mont_adx.h" header (which carries the chains without
 * needing the attribute). For each such file the gate greps claim lines
 * (ADCX/ADOX named, minus lines that explicitly deny the claim), compiles
 * the file standalone with the canonical print-includes -I set, disassembles
 * the object with objdump, and counts emitted adcx/adox instructions. A
 * claim with zero emitted instructions is an overclaim: report to stderr and
 * count a violation. Fail closed: unreadable population, hollow or ambiguous
 * include records, compile failure, or disassembly failure are exit 2.
 *
 * Mode: WARN or FAIL via ZCL_LINT_MODE, default FAIL; violations exit 1 only
 * in FAIL mode. Off x86-64 the ADX instructions cannot exist in the ISA, so
 * a zero count there is the portability tautology and passes.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "lintc.h"

static const char k_ao_gate[] = "check_no_adx_overclaim";

enum { AO_PATH = 1024, AO_TEXT = 65536,
       AO_FILES = 96,
       AO_IFLAGS = 256, AO_IWORD = 160,
       AO_CLAIMS = 64, AO_CLAIM = 512,
       AO_ARGS = 192, AO_ENV = 512, AO_LINE = 16384 };

struct ao_incset { char flag[AO_IFLAGS][AO_IWORD]; int n; };
struct ao_fset { char name[AO_FILES][AO_PATH]; int n; };
struct ao_claims { char row[AO_CLAIMS][AO_CLAIM]; int n; };

extern char **environ;

/* Child side of ao_spawn: point the std streams at logfile or the pipe. */
static void ao_child_redirect(const char *logfile, int use_pipe,
                              const int fds[2])
{
    if (logfile) {
        int fd = open(logfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0)
            _exit(126);
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd > 2)
            close(fd);
    } else if (use_pipe) {
        close(fds[0]);
        dup2(fds[1], 1);
        close(fds[1]);
    }
}

/* Child side of ao_spawn: exec av, under envp when given. Never returns. */
static void ao_child_exec(char *const av[], char *const envp[])
{
    if (envp)
        environ = (char **)envp; /* execvp searches PATH with this */
    execvp(av[0], av);
    _exit(127);
}

/* Reads the child's stdout pipe into out until cap bytes or EOF. */
static size_t ao_drain(int fd, char *out, size_t cap)
{
    size_t len = 0;
    ssize_t r;
    while (len < cap && (r = read(fd, out + len, cap - len)) > 0)
        len += (size_t)r;
    return len;
}

/* Runs av (execvp, or execvp under envp when given) capturing stdout into out
 * (cap bytes, NUL-terminated via olen) and optionally redirecting both std
 * streams to logfile. *code is the child exit status, 127 on exec failure,
 * 128 on a fatal signal. Returns 0 on success, 2 on a spawn failure. */
static int ao_spawn(char *const av[], char *const envp[], char *out,
                    size_t cap, size_t *olen, const char *logfile, int *code)
{
    int fds[2] = { -1, -1 };
    int use_pipe = out != NULL;
    if (use_pipe && pipe(fds) != 0)
        return 2;
    pid_t pid = fork();
    if (pid < 0)
        return 2;
    if (pid == 0) {
        ao_child_redirect(logfile, use_pipe, fds);
        ao_child_exec(av, envp);
    }
    size_t len = 0;
    if (use_pipe) {
        close(fds[1]);
        len = ao_drain(fds[0], out, cap);
        close(fds[0]);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR)
            return 2;
    }
    if (olen)
        *olen = len;
    *code = WIFEXITED(st) ? WEXITSTATUS(st) : 128;
    return 0;
}

/* A child that exits 127 (exec failed) or 128 (fatal signal) could not
 * run at all; say so, so the fail-closed exit 2 is not silent. */
static void ao_report_spawn(const char *tool, int code)
{
    if (code == 127 || code == 128)
        fprintf(stderr, "%s: FATAL — cannot run %s (exit %d)\n", k_ao_gate,
                tool, code);
}

/* 0 = tool present, 1 = missing (exec failed), 2 = internal error. */
static int ao_tool_ok(const char *tool)
{
    static char av0[AO_PATH];
    if (ovf(snprintf(av0, sizeof av0, "%s", tool), sizeof av0))
        return 2;
    char *av[3] = { av0, (char *)"--version", NULL };
    int code = 0;
    if (ao_spawn(av, NULL, NULL, 0, NULL, "/dev/null", &code))
        return 2;
    return code == 127 ? 1 : 0;
}

static int ao_add_lines(const char *buf, struct ao_fset *fs)
{
    const char *p = buf;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n >= AO_PATH) {
            fprintf(stderr, "%s: git grep path exceeds %d\n", k_ao_gate,
                    AO_PATH);
            return 2;
        }
        if (fs->n >= AO_FILES) {
            fprintf(stderr, "%s: population exceeds %d files\n", k_ao_gate,
                    AO_FILES);
            return 2;
        }
        memcpy(fs->name[fs->n], p, n);
        fs->name[fs->n][n] = '\0';
        fs->n++;
        p = nl ? nl + 1 : p + n;
    }
    return 0;
}

static void ao_sort_dedupe(struct ao_fset *fs)
{
    for (int i = 1; i < fs->n; i++) {
        char tmp[AO_PATH];
        strcpy(tmp, fs->name[i]);
        int j = i - 1;
        while (j >= 0 && strcmp(fs->name[j], tmp) > 0) {
            strcpy(fs->name[j + 1], fs->name[j]);
            j--;
        }
        strcpy(fs->name[j + 1], tmp);
    }
    int w = 0;
    for (int i = 0; i < fs->n; i++)
        if (w == 0 || strcmp(fs->name[w - 1], fs->name[i]) != 0)
            strcpy(fs->name[w++], fs->name[i]);
    fs->n = w;
}

/* Both git greps over the scanned roots; exit 0 = matched, 1 = no match,
 * anything above is fatal and fails closed. */
static int ao_population(struct ao_fset *fs)
{
    static char buf[AO_TEXT];
    static const char *const pats[2] = {
        "__attribute__\\(\\(target\\(\"[^\"]*adx",
        "#[[:space:]]*include[[:space:]]+\"mont_adx\\.h\"",
    };
    fs->n = 0;
    for (int pass = 0; pass < 2; pass++) {
        char *av[12] = { (char *)"git",       (char *)"grep",
                         (char *)"-l",        (char *)"-E",
                         (char *)pats[pass],  (char *)"--",
                         (char *)"core",      (char *)"engine",
                         (char *)"contexts",  (char *)"cognition",
                         (char *)"platform",  NULL };
        size_t len = 0;
        int code = 0;
        if (ao_spawn(av, NULL, buf, AO_TEXT - 1, &len, NULL, &code))
            return 2;
        ao_report_spawn("git", code);
        if (code > 1)
            return 2;
        buf[len] = '\0';
        if (ao_add_lines(buf, fs))
            return 2;
    }
    ao_sort_dedupe(fs);
    return 0;
}

static int ao_token_is_inc(const char *tok)
{
    size_t n = strlen(tok);
    return n > 2 && tok[0] == '-' && tok[1] == 'I';
}

/* 1 when every whitespace field of line is an -I flag (fields copied to tmp,
 * count in nf), 0 when not, 2 on overflow. Mirrors the shell helper. */
static int ao_try_candidate(char *line, char tmp[][AO_IWORD], int *nf)
{
    int n = 0;
    char *save = NULL;
    for (char *tok = strtok_r(line, " \t", &save); tok;
         tok = strtok_r(NULL, " \t", &save)) {
        if (!ao_token_is_inc(tok))
            return 0;
        if (n >= AO_IFLAGS || strlen(tok) >= AO_IWORD) {
            fprintf(stderr, "%s: include flag exceeds %d bytes or %d flags\n",
                    k_ao_gate, AO_IWORD, AO_IFLAGS);
            return 2;
        }
        strcpy(tmp[n++], tok);
    }
    *nf = n;
    return n > 0 ? 1 : 0;
}

/* Selects the single line of text made entirely of -I flags. Returns 0 with
 * the flags in set, 1 when zero or several such lines exist, 2 on overflow.
 * Exposed non-static for the selftest. */
int ao_extract_includes(const char *text, struct ao_incset *set)
{
    static char tmp[AO_IFLAGS][AO_IWORD], cand[AO_IFLAGS][AO_IWORD];
    int cands = 0, cand_n = 0;
    set->n = 0;
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        char line[AO_LINE];
        if (n >= sizeof line) {
            fprintf(stderr, "%s: include record line exceeds %d\n", k_ao_gate,
                    AO_LINE - 1);
            return 2;
        }
        memcpy(line, p, n);
        line[n] = '\0';
        int nf = 0;
        int rc = ao_try_candidate(line, tmp, &nf);
        if (rc == 2)
            return 2;
        if (rc == 1) {
            memcpy(cand, tmp, sizeof tmp);
            cand_n = nf;
            cands++;
        }
        p = nl ? nl + 1 : p + n;
    }
    if (cands != 1)
        return 1;
    memcpy(set->flag, cand, sizeof cand);
    set->n = cand_n;
    return 0;
}

/* environ without MAKEFLAGS, so the make runs without inherited flags. */
static int ao_envp_nomakeflags(char *envp[])
{
    int n = 0;
    for (char **e = environ; *e; e++) {
        if (strncmp(*e, "MAKEFLAGS=", 10) == 0)
            continue;
        if (n >= AO_ENV - 1) {
            fprintf(stderr, "%s: environment exceeds %d entries\n", k_ao_gate,
                    AO_ENV - 1);
            return 2;
        }
        envp[n++] = *e;
    }
    envp[n] = NULL;
    return 0;
}

static int ao_get_includes(struct ao_incset *set)
{
    static char buf[AO_TEXT];
    char *envp[AO_ENV];
    char *av[5] = { (char *)"make", (char *)"--no-print-directory",
                    (char *)"-s", (char *)"print-includes", NULL };
    size_t len = 0;
    int code = 0;
    if (ao_envp_nomakeflags(envp))
        return 2;
    if (ao_spawn(av, envp, buf, AO_TEXT - 1, &len, NULL, &code))
        return 2;
    ao_report_spawn("make", code);
    if (code != 0)
        return 2;
    buf[len] = '\0';
    int rc = ao_extract_includes(buf, set);
    if (rc == 1) {
        fprintf(stderr,
                "%s: FATAL — print-includes did not emit exactly one canonical -I record.\n",
                k_ao_gate);
        return 2;
    }
    return rc;
}

static int ao_is_x86(void)
{
    struct utsname u;
    if (uname(&u) != 0)
        return 0;
    return strcmp(u.machine, "x86_64") == 0;
}

static int ao_mkdtemp(char *out, size_t cap)
{
    if (ovf(snprintf(out, cap, "%s/z23-lint-no-adx.XXXXXX",
                     env_or("TMPDIR", "/tmp")), cap))
        return 2;
    if (!mkdtemp(out))
        return 2;
    return 0;
}

struct ao_claimctx {
    struct ao_claims *c;
    const regex_t *claim;
    const regex_t *deny;
    int lineno;
};

static int ao_claims_cb(void *ctx, const char *line, size_t len)
{
    struct ao_claimctx *x = ctx;
    x->lineno++;
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len >= AO_CLAIM) {
        fprintf(stderr, "%s: claim line exceeds %d bytes\n", k_ao_gate,
                AO_CLAIM - 1);
        return 2;
    }
    char buf[AO_CLAIM];
    memcpy(buf, line, len);
    buf[len] = '\0';
    if (regexec(x->claim, buf, 0, NULL, 0) != 0)
        return 0;
    if (regexec(x->deny, buf, 0, NULL, 0) == 0)
        return 0;
    if (x->c->n >= AO_CLAIMS) {
        fprintf(stderr, "%s: claim lines exceed %d\n", k_ao_gate, AO_CLAIMS);
        return 2;
    }
    if (ovf(snprintf(x->c->row[x->c->n], AO_CLAIM, "%d:%s", x->lineno, buf),
             AO_CLAIM))
        return 2;
    x->c->n++;
    return 0;
}

/* Claim lines: the file names ADCX/ADOX outside an explicit denial. */
static int ao_claims(const char *path, struct ao_claims *c)
{
    regex_t claim, deny;
    int rc = compile_pat(&claim, REG_EXTENDED, "ADCX|ADOX|adcx|adox", "", "", "");
    if (rc)
        return 2;
    rc = compile_pat(&deny, REG_EXTENDED | REG_ICASE,
                     "not |never|no ADCX|no adcx|without |",
                     "zero carry-in|literal 0|overclaim", "", "");
    if (rc) {
        regfree(&claim);
        return 2;
    }
    struct ao_claimctx x = { c, &claim, &deny, 0 };
    c->n = 0;
    rc = lc_each_line(path, ao_claims_cb, &x, 1);
    drop2(&claim, &deny);
    return rc ? 2 : 0;
}

static void ao_cat_indented(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    char line[512];
    while (fgets(line, sizeof line, f))
        fprintf(stderr, "    %s", line);
    fclose(f);
}

static int ao_compile(const char *cc, const char *file, const char *obj,
                      const struct ao_incset *incs, int x86,
                      const char *logpath)
{
    static char *av[AO_ARGS];
    static char ccbuf[AO_PATH];
    if (ovf(snprintf(ccbuf, sizeof ccbuf, "%s", cc), sizeof ccbuf))
        return 2;
    int n = 0;
    av[n++] = ccbuf;
    av[n++] = (char *)"-std=c23";
    av[n++] = (char *)"-O3";
    if (x86)
        av[n++] = (char *)"-march=x86-64-v3";
    for (int i = 0; i < incs->n; i++) {
        if (n >= AO_ARGS - 5) {
            fprintf(stderr, "%s: compile argv exceeds %d entries\n", k_ao_gate,
                    AO_ARGS);
            return 2;
        }
        av[n++] = (char *)incs->flag[i];
    }
    av[n++] = (char *)"-c";
    av[n++] = (char *)"-o";
    av[n++] = (char *)obj;
    av[n++] = (char *)file;
    av[n] = NULL;
    int code = 0;
    if (ao_spawn(av, NULL, NULL, 0, NULL, logpath, &code))
        return 2;
    if (code != 0) {
        fprintf(stderr, "%s: FATAL — could not compile %s to measure it.\n",
                k_ao_gate, file);
        ao_cat_indented(logpath);
        return 2;
    }
    return 0;
}

/* Counts disassembly lines of the form ADDR: adcx|adox. */
static int ao_count_adx(const char *obj, int *count)
{
    static char buf[AO_TEXT];
    char *av[5] = { (char *)"objdump", (char *)"-d",
                    (char *)"--no-show-raw-insn", (char *)obj, NULL };
    regex_t re;
    int rc = compile_pat(&re, REG_EXTENDED, "^[[:space:]]+[0-9a-f]+:",
                         "[[:space:]]+(adcx|adox)[[:space:]]", "", "");
    if (rc)
        return 2;
    size_t len = 0;
    int code = 0;
    rc = ao_spawn(av, NULL, buf, AO_TEXT - 1, &len, NULL, &code);
    if (rc == 0)
        ao_report_spawn("objdump", code);
    if (rc == 0 && code != 0)
        rc = 2;
    if (rc == 0) {
        buf[len] = '\0';
        *count = 0;
        char *p = buf;
        while (*p) {
            char *nl = strchr(p, '\n');
            if (nl)
                *nl = '\0';
            if (regexec(&re, p, 0, NULL, 0) == 0)
                (*count)++;
            if (!nl)
                break;
            p = nl + 1;
        }
    }
    regfree(&re);
    return rc;
}

static int ao_obj_path(char *out, size_t cap, const char *tmpdir,
                       const char *file)
{
    const char *b = strrchr(file, '/');
    b = b ? b + 1 : file;
    size_t n = strlen(b);
    if (n > 2 && strcmp(b + n - 2, ".c") == 0)
        n -= 2;
    if (ovf(snprintf(out, cap, "%s/%.*s.o", tmpdir, (int)n, b), cap))
        return 2;
    return 0;
}

static void ao_report(const char *file, const struct ao_claims *c)
{
    fprintf(stderr, "%s: names ADCX/ADOX but the compiled object contains none\n",
            file);
    for (int i = 0; i < c->n; i++)
        fprintf(stderr, "    %s\n", c->row[i]);
    fprintf(stderr,
            "    -> pin the two carry chains in inline asm (core/modules/sapling/src/mont_adx.h),\n"
            "       or report the tier honestly as \"BMI2 MULX\"\n");
}

/* Grades one file: claims, compile, disassemble, verdict. *viol increments
 * on an overclaim. Returns 0 ok, 2 fail-closed. */
static int ao_grade_file(const char *cc, const char *file, const char *tmpdir,
                         const char *logpath, const struct ao_incset *incs,
                         int x86, int *viol)
{
    struct ao_claims c;
    int rc = ao_claims(file, &c);
    if (rc)
        return 2;
    if (c.n == 0)
        return 0;
    char obj[AO_PATH];
    if (ao_obj_path(obj, sizeof obj, tmpdir, file))
        return 2;
    rc = ao_compile(cc, file, obj, incs, x86, logpath);
    if (rc)
        return 2;
    int emitted = 0;
    rc = ao_count_adx(obj, &emitted);
    if (rc)
        return 2;
    if (emitted > 0)
        return 0;
    if (!x86)
        return 0;
    ao_report(file, &c);
    (*viol)++;
    return 0;
}

/* Both measuring tools must exist: no compiler or no objdump is fail-closed. */
static int ao_tools_present(const char *cc)
{
    int rc = ao_tool_ok(cc);
    if (rc == 1) {
        fprintf(stderr,
                "%s: FATAL — no C compiler ('%s') to measure with.\n",
                k_ao_gate, cc);
        return 2;
    }
    if (rc)
        return 2;
    rc = ao_tool_ok("objdump");
    if (rc == 1) {
        fprintf(stderr,
                "%s: FATAL — objdump not found; cannot read emitted code.\n",
                k_ao_gate);
        return 2;
    }
    return rc ? 2 : 0;
}

/* Population and canonical include set, both fail-closed on a hollow scan. */
static int ao_scan_inputs(struct ao_fset *fs, struct ao_incset *incs)
{
    if (ao_population(fs))
        return 2;
    if (gate_require_scanned(fs->n, 2, k_ao_gate,
            "expected at least core/modules/sapling/src/bn254_accel.c and "
            "core/modules/sapling/src/fr_avx512.c"))
        return 2;
    if (ao_get_includes(incs))
        return 2;
    return gate_require_scanned(incs->n, 20, k_ao_gate,
            "canonical build include set came back hollow") ? 2 : 0;
}

/* Grades every population file in order; stops at the first fail-closed. */
static int ao_grade_all(const char *cc, const struct ao_fset *fs,
                        const struct ao_incset *incs, int *viol)
{
    char tmpdir[AO_PATH], logpath[AO_PATH + 16];
    if (ao_mkdtemp(tmpdir, sizeof tmpdir))
        return 2;
    if (ovf(snprintf(logpath, sizeof logpath, "%s/cc.log", tmpdir),
             sizeof logpath)) {
        rap_rm_rf(tmpdir);
        return 2;
    }
    int x86 = ao_is_x86();
    int rc = 0;
    for (int i = 0; i < fs->n && rc == 0; i++)
        rc = ao_grade_file(cc, fs->name[i], tmpdir, logpath, incs, x86, viol);
    rap_rm_rf(tmpdir);
    return rc ? 2 : 0;
}

int check_no_adx_overclaim_run(int argc, char **argv)
{
    (void)argv;
    if (argc != 0) {
        fprintf(stderr, "usage: %s [--selftest]\n", k_ao_gate);
        return 2;
    }
    const char *mode = env_or("ZCL_LINT_MODE", "FAIL");
    const char *cc = env_or("CC", "cc");
    struct ao_fset fs;
    struct ao_incset incs;
    int viol = 0;
    if (ao_tools_present(cc) || ao_scan_inputs(&fs, &incs))
        return 2;
    if (ao_grade_all(cc, &fs, &incs, &viol))
        return 2;
    printf("[%s] scanned %d ADX-claiming file(s), %d violation(s) (mode: %s)\n",
           k_ao_gate, fs.n, viol, mode);
    printf("[%s] target(\"bmi2,adx\") buys MULX; ADCX/ADOX only\n", k_ao_gate);
    printf("[%s] materialise when a carry is threaded forward,\n", k_ao_gate);
    printf("[%s] and this gate reads the object file to check.\n", k_ao_gate);
    if (viol > 0 && strcmp(mode, "FAIL") == 0)
        return 1;
    return 0;
}
