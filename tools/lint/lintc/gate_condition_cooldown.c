/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-condition-cooldown — Gate E14: an external/network-
 * dependent CRITICAL condition must not permanently latch. Ported from
 * the retired shell script (check_condition_cooldown). Selftest:
 * gate_condition_cooldown_selftest.c.
 *
 * A CRITICAL condition whose detect() depends on peer/network state
 * (connman_max_peer_height, connman_get_node_count, sync_monitor_connman,
 * sync_monitor_max_peer_height, legacy_chain_rpc_*) must set
 * `.cooldown_secs > 0` or wire a `.progressing` callback (TL-1). Without
 * either, condition.c latches permanently at max_attempts (the 2026-07-13
 * 27h-page bug class). Scope: each *.c directly under the scan dir
 * (ZCL_CONDITION_COOLDOWN_SCAN_DIR, default engine/conditions/src) that
 * defines a `static struct condition <var> = {` registration literal.
 * Exit 0 clean; 2 on a violation (offenders named on stderr) or a hollow
 * scan. Recursion guard: running the gate entry with
 * ZCL_CONDITION_COOLDOWN_SELFTEST=1 in the environment is refused.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "lintc.h"
#include "lintc_text.h"

enum { CCD_FILES = 512, CCD_PATH = 1024, CCD_LINE = 4096,
       CCD_NAME = CCD_LINE, CCD_VIOL = 64, CCD_VROW = 5200,
       CCD_DEFBUF = CCD_LINE };

static const char k_ccd_gate[] = "check_condition_cooldown";
static const char k_ccd_default_dir[] = "engine/conditions/src";

enum { R_STRUCT, R_SEV, R_NET, R_PROG, R_COOL, R_LIT, R_MAC, R_COUNT };

static const char *const k_ccd_pat[R_COUNT] = {
    "^static struct condition [A-Za-z_][A-Za-z0-9_]* = \\{[[:space:]]*$",
    "\\.severity[[:space:]]*=[[:space:]]*COND_CRITICAL([^A-Za-z0-9_]|$)",
    "connman_max_peer_height\\(|connman_get_node_count\\("
    "|sync_monitor_connman\\(|sync_monitor_max_peer_height\\("
    "|legacy_chain_rpc_[A-Za-z_]*\\(",
    "\\.progressing[[:space:]]*=[[:space:]]*[A-Za-z_]",
    "\\.cooldown_secs[[:space:]]*=[[:space:]]*[0-9]+",
    "\\.name[[:space:]]*=[[:space:]]*\"[^\"]*\"",
    "\\.name[[:space:]]*=[[:space:]]*[A-Za-z_][A-Za-z0-9_]*",
};

static regex_t g_ccd_re[R_COUNT];
static int g_ccd_re_ok;

/* Collected facts about one scanned file (all patterns, single pass). */
struct ccd_file {
    int has_struct; /* registers a condition literal */
    int sev;        /* .severity = COND_CRITICAL */
    int net;        /* calls a peer/network/oracle primitive */
    int prog;       /* .progressing = <ident> (TL-1 exemption) */
    int got_cool;   /* a .cooldown_secs = <N> line was seen */
    long cool;      /* the N of the first such line */
    int seen_lit, got_lit; /* first .name = "..." seen / non-empty */
    char lit[CCD_NAME];
    int seen_mac, got_mac; /* first .name = MACRO seen / usable */
    char mac[CCD_NAME];
};

static int ccd_re_ensure(void)
{
    if (g_ccd_re_ok)
        return 0;
    for (int i = 0; i < R_COUNT; i++) {
        int e = regcomp(&g_ccd_re[i], k_ccd_pat[i], REG_EXTENDED);
        if (e)
            return reg_fail(&g_ccd_re[i], e);
    }
    g_ccd_re_ok = 1;
    return 0;
}

static int ccd_is_digit(int c) { return c >= '0' && c <= '9'; }

/* One regex probe: 1 match, 0 REG_NOMATCH, -1 (message printed) on any
 * other regexec failure, so a broken regex never reads as "no match". */
static int ccd_rx(int idx, const char *buf, regmatch_t *m)
{
    int e = regexec(&g_ccd_re[idx], buf, m ? 1 : 0, m, 0);
    if (e == 0)
        return 1;
    if (e == REG_NOMATCH)
        return 0;
    char msg[160];
    regerror(e, &g_ccd_re[idx], msg, sizeof msg);
    fprintf(stderr, "%s: regexec failed on pattern %d: %s\n", k_ccd_gate,
            idx, msg);
    return -1;
}

/* First `.cooldown_secs = <N>`: digits end at rm_eo, walk back. */
static int ccd_take_cool(struct ccd_file *f, const char *buf)
{
    regmatch_t m;
    if (f->got_cool)
        return 0;
    int r = ccd_rx(R_COOL, buf, &m);
    if (r <= 0)
        return r < 0 ? 2 : 0;
    int s = (int)m.rm_eo;
    while (s > (int)m.rm_so && ccd_is_digit(buf[s - 1]))
        s--;
    f->cool = strtol(buf + s, NULL, 10);
    f->got_cool = 1;
    return 0;
}

/* First `.name = "..."` (like the old `head -1`): later lines are ignored
 * even when this one is empty, in which case the name falls back. */
static int ccd_take_lit(struct ccd_file *f, const char *buf)
{
    regmatch_t m;
    if (f->seen_lit)
        return 0;
    int r = ccd_rx(R_LIT, buf, &m);
    if (r <= 0)
        return r < 0 ? 2 : 0;
    f->seen_lit = 1;
    const char *p = strchr(buf + m.rm_so, '"');
    if (!p)
        return 0;
    p++;
    const char *q = strchr(p, '"');
    if (!q || q == p)
        return 0;
    memcpy(f->lit, p, (size_t)(q - p));
    f->lit[q - p] = '\0';
    f->got_lit = 1;
    return 0;
}

/* First `.name = MACRO`: identifier ends at rm_eo, walk back. */
static int ccd_take_mac(struct ccd_file *f, const char *buf)
{
    regmatch_t m;
    if (f->seen_mac)
        return 0;
    int r = ccd_rx(R_MAC, buf, &m);
    if (r <= 0)
        return r < 0 ? 2 : 0;
    f->seen_mac = 1;
    int e = (int)m.rm_eo, s = e;
    while (s > (int)m.rm_so && lintc_ident_char(buf[s - 1]))
        s--;
    if (e - s <= 0)
        return 0;
    memcpy(f->mac, buf + s, (size_t)(e - s));
    f->mac[e - s] = '\0';
    f->got_mac = 1;
    return 0;
}

struct ccd_ctx { struct ccd_file *f; const char *path; };

/* The four flag probes, in enum order R_STRUCT..R_PROG. */
static int ccd_flags(struct ccd_file *f, const char *buf)
{
    int *const flag[] = { &f->has_struct, &f->sev, &f->net, &f->prog };
    for (int i = 0; i < 4; i++) {
        int r = ccd_rx(i, buf, NULL);
        if (r < 0)
            return 2;
        if (r)
            *flag[i] = 1;
    }
    return 0;
}

/* lc_each_line callback: accumulate every fact about one line. */
static int ccd_file_line(void *ctx, const char *line, size_t len)
{
    struct ccd_ctx *c = ctx;
    struct ccd_file *f = c->f;
    char buf[CCD_LINE];
    size_t n = len;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    if (n >= sizeof buf) {
        fprintf(stderr, "%s: line of %s exceeds %d bytes\n", k_ccd_gate,
                c->path, CCD_LINE);
        return 2;
    }
    memcpy(buf, line, n);
    buf[n] = '\0';
    if (ccd_flags(f, buf) || ccd_take_cool(f, buf) ||
        ccd_take_lit(f, buf) || ccd_take_mac(f, buf))
        return 2;
    return 0;
}

static int ccd_scan_file(const char *path, struct ccd_file *f, FILE *err)
{
    memset(f, 0, sizeof *f);
    struct ccd_ctx c = { f, path };
    int rc = lc_each_line(path, ccd_file_line, &c, 1);
    if (rc == 0)
        return 0;
    fprintf(err, "%s: FATAL — cannot read %s (exit %d); refusing to "
            "report 'clean' off a broken scan\n", k_ccd_gate, path, rc);
    return 2;
}

struct ccd_def { const char *macro; char *out; size_t cap; int found; };

/* Returns the text after `#define MACRO ` when it starts a quote, else NULL. */
static const char *ccd_define_value(const char *buf, const char *macro)
{
    const char *p = strstr(buf, "#define");
    if (!p)
        return NULL;
    p += 7;
    while (*p == ' ' || *p == '\t')
        p++;
    size_t ml = strlen(macro);
    if (strncmp(p, macro, ml) != 0)
        return NULL;
    p += ml;
    if (*p != ' ' && *p != '\t')
        return NULL;
    while (*p == ' ' || *p == '\t')
        p++;
    return *p == '"' ? p + 1 : NULL;
}

/* lc_each_line callback: resolve `#define MACRO "value"` in the file. */
static int ccd_def_line(void *v, const char *line, size_t len)
{
    struct ccd_def *d = v;
    if (d->found)
        return 0;
    char buf[CCD_DEFBUF];
    size_t n = len;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    if (n >= sizeof buf) {
        fprintf(stderr, "%s: line exceeds %d bytes while resolving a name\n",
                k_ccd_gate, CCD_DEFBUF);
        return 2;
    }
    memcpy(buf, line, n);
    buf[n] = '\0';
    const char *p = ccd_define_value(buf, d->macro);
    if (!p)
        return 0;
    const char *q = strchr(p, '"');
    if (!q || (size_t)(q - p) >= d->cap)
        return 0;
    memcpy(d->out, p, (size_t)(q - p));
    d->out[q - p] = '\0';
    d->found = 1;
    return 0;
}

/* Copies src into out; 2 (message printed) when it does not fit. */
static int ccd_put(char *out, size_t cap, const char *src)
{
    if (ovf(snprintf(out, cap, "%s", src), cap)) {
        fprintf(stderr, "%s: condition name too long\n", k_ccd_gate);
        return 2;
    }
    return 0;
}

/* The filename stem (basename without .c), the last-resort name. */
static int ccd_stem(const char *path, char *out, size_t cap)
{
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    size_t n = strlen(b);
    if (n > 2 && strcmp(b + n - 2, ".c") == 0)
        n -= 2;
    if (n >= cap) {
        fprintf(stderr, "%s: file name too long: %s\n", k_ccd_gate, path);
        return 2;
    }
    memcpy(out, b, n);
    out[n] = '\0';
    return 0;
}

/* The condition's reported name: non-empty literal, else a macro resolved
 * to a non-empty value, else the file stem (as the old script did). */
static int ccd_name_for(const struct ccd_file *f, const char *path,
                        char *out, size_t cap)
{
    if (f->got_lit)
        return ccd_put(out, cap, f->lit);
    if (f->got_mac) {
        char val[CCD_NAME];
        val[0] = '\0';
        struct ccd_def d = { f->mac, val, sizeof val, 0 };
        if (lc_each_line(path, ccd_def_line, &d, 1) != 0)
            return 2;
        if (d.found && val[0])
            return ccd_put(out, cap, val);
    }
    return ccd_stem(path, out, cap);
}

/* Byte order, not locale order: a determinism choice for the file list. */
static int ccd_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* One directory entry: 0 skipped (not a regular *.c), 1 stored, 2 error. */
static int ccd_entry(const char *dir, const char *name,
                     char files[][CCD_PATH], int n, int cap)
{
    size_t ln = strlen(name);
    if (ln < 2 || strcmp(name + ln - 2, ".c") != 0)
        return 0;
    char path[CCD_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", dir, name), sizeof path)) {
        fprintf(stderr, "%s: path too long: %s/%s\n", k_ccd_gate, dir, name);
        return 2;
    }
    struct stat st;
    if (lstat(path, &st) != 0) {
        fprintf(stderr, "%s: cannot stat %s\n", k_ccd_gate, path);
        return 2;
    }
    if (!S_ISREG(st.st_mode))
        return 0;
    if (n >= cap) {
        fprintf(stderr, "%s: file list exceeds %d\n", k_ccd_gate, cap);
        return 2;
    }
    memcpy(files[n], path, strlen(path) + 1);
    return 1;
}

/* Lists the regular *.c files directly under dir, sorted. An unopenable
 * dir yields zero files, so the scan floor fails loud downstream. */
static int ccd_list(const char *dir, char files[][CCD_PATH], int *out_n,
                    int cap)
{
    DIR *d = opendir(dir);
    int n = 0;
    *out_n = 0;
    if (!d)
        return 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        int r = ccd_entry(dir, e->d_name, files, n, cap);
        if (r == 2) {
            closedir(d);
            return 2;
        }
        n += r;
    }
    closedir(d);
    qsort(files, (size_t)n, CCD_PATH, ccd_cmp);
    *out_n = n;
    return 0;
}

static int ccd_is_violation(const struct ccd_file *f)
{
    if (!f->has_struct || !f->sev || !f->net || f->prog)
        return 0;
    return !(f->got_cool && f->cool > 0);
}

/* One gate pass over dir: prints the verdict and returns the exit code. */
int ccd_scan_dir(const char *dir, FILE *out, FILE *err)
{
    if (ccd_re_ensure())
        return 2;
    static char files[CCD_FILES][CCD_PATH];
    int n = 0;
    int rc = ccd_list(dir, files, &n, CCD_FILES);
    if (rc)
        return rc;
    char hint[512];
    if (ovf(snprintf(hint, sizeof hint,
                     "no *.c under %s — scan dir renamed/moved/emptied?",
                     dir), sizeof hint))
        return 2;
    rc = gate_require_scanned(n, 1, k_ccd_gate, hint);
    if (rc)
        return rc;
    static char viol[CCD_VIOL][CCD_VROW];
    int nviol = 0;
    for (int i = 0; i < n; i++) {
        struct ccd_file f;
        rc = ccd_scan_file(files[i], &f, err);
        if (rc)
            return rc;
        if (!ccd_is_violation(&f))
            continue;
        char name[CCD_NAME];
        if (ccd_name_for(&f, files[i], name, sizeof name))
            return 2;
        if (nviol >= CCD_VIOL) {
            fprintf(stderr, "%s: violations exceed %d\n", k_ccd_gate,
                    CCD_VIOL);
            return 2;
        }
        if (ovf(snprintf(viol[nviol], CCD_VROW, "%s: %s", files[i], name),
                CCD_VROW))
            return 2;
        nviol++;
    }
    if (nviol == 0) {
        fprintf(out, "%s: OK — every network/oracle-dependent CRITICAL "
                "condition in %s sets cooldown_secs > 0 or .progressing\n",
                k_ccd_gate, dir);
        return 0;
    }
    fprintf(err,
            "FAIL: CRITICAL condition(s) depend on external/network state but\n"
            "      never re-arm — they will PERMANENTLY LATCH at max_attempts\n"
            "      instead of retrying (the 2026-07-13 27h-page bug class):\n"
            "\n");
    for (int i = 0; i < nviol; i++)
        fprintf(err, "  %s\n", viol[i]);
    fprintf(err,
            "\n"
            "      Fix: add `.cooldown_secs = <secs>` (see sync_violation_lag.c\n"
            "      for the canonical shape) so condition.c re-arms the remedy on\n"
            "      a bounded backoff, OR wire a `.progressing` callback (TL-1,\n"
            "      framework/condition.h) if the condition already has a durable-\n"
            "      progress signal that resets the attempt budget instead.\n");
    return 2;
}

/* The full gate entry: recursion refusal, then the scan-dir pass. */
int ccd_run(FILE *out, FILE *err)
{
    const char *st = getenv("ZCL_CONDITION_COOLDOWN_SELFTEST");
    if (st && strcmp(st, "1") == 0) {
        fprintf(err, "FAIL: check_condition_cooldown self-test recursion "
                "refused\n");
        return 2;
    }
    const char *dir = getenv("ZCL_CONDITION_COOLDOWN_SCAN_DIR");
    if (!dir || !*dir)
        dir = k_ccd_default_dir;
    return ccd_scan_dir(dir, out, err);
}

int check_condition_cooldown_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return ccd_run(stdout, stderr);
}
