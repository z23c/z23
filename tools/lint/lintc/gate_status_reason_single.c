/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check_status_reason_single — stop a third inline copy of
 * the operator-needed ladder from growing back. Ported from
 * tools/lint/check_status_reason_single.sh (deleted). Mode: shrink-only
 * ratchet (ZCL_LINT_MODE: FAIL default | WARN | UPDATE). The planted-
 * violation selftest is gate_status_reason_single_selftest.c.
 *
 * WHAT IS COUNTED, per scanned *.c file: an inline operator-verdict ladder,
 * matched by SHAPE and NOT by any name. A match needs BOTH halves:
 *   1. STRUCTURE: inside one function body, a locally declared
 *      `bool <IDENT> = false;` (or true) re-assigned on LADDER_ASSIGN_MIN
 *      (3) or more later lines, in a body with LADDER_ELSEIF_MIN (2) or
 *      more `else if (` branches.
 *   2. ROLE: the same body either publishes a boolean to an operator-facing
 *      JSON document (json_push_kv_bool) or contains a literal from the
 *      closed status vocabulary ("blocked" / "catching_up" / "degraded").
 *
 * Function bodies are delimited by a `{` alone at column 0 and a `}` at
 * column 0, exactly as the awk pass of the shell original. Assignments are
 * found by splitting each line on `{` and `;` and testing every fragment,
 * so the same-line brace style counts too. No allow-comment escape hatch
 * exists; the shrink-only baseline file is the only route.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_status_reason_single_priv.h"

enum { SRS_MAXFILES = 4096, SRS_PATH = 1024, SRS_LINE = 8192,
       SRS_NAMES = 64, SRS_NAME = 128, SRS_MAXROWS = 256,
       SRS_BASE = 128, SRS_VIOL = SRS_MAXROWS + SRS_BASE + 1,
       SRS_ROW = SRS_PATH + 256, SRS_GITBUF = 1 << 20 };
static const int k_srs_assign_min = 3;
static const int k_srs_elseif_min = 2;
static const int k_srs_ratchet_ceiling = 1;
static const char k_srs_gate[] = "check_status_reason_single";
static const char k_srs_default_baseline[] = "tools/lint/status_reason_baseline.txt";

struct srs_row { char path[SRS_PATH]; int debt; };
struct srs_rows { struct srs_row r[SRS_MAXROWS]; int n; };
struct srs_base { char path[SRS_PATH]; char raw[SRS_NAME]; int val; int hit; };
struct srs_baselist { struct srs_base b[SRS_BASE]; int n; };
struct srs_bodystate {
    int infunc, elseifs, haspub, hasvocab, ndecl;
    char names[SRS_NAMES][SRS_NAME];
    int assigns[SRS_NAMES];
};
struct srs_fctx { struct srs_bodystate b; int count; };
struct srs_cfg { const char *mode, *basep, *glob; int ceiling, floor; };
struct srs_run {
    struct srs_cfg cfg;
    size_t nfiles;
    int baseline_sum, total, nviol, nstale, ntol;
    struct srs_rows rs;
    struct srs_baselist bl;
    char viol[SRS_VIOL][SRS_ROW];
    char stale[SRS_BASE][SRS_ROW];
    char files[SRS_MAXFILES][SRS_PATH];
};
static struct srs_run g_srs;

static int srs_ws(char c) { return c == ' ' || c == '\t'; }

static void srs_reset_body(struct srs_bodystate *b)
{
    b->elseifs = 0;
    b->haspub = 0;
    b->hasvocab = 0;
    b->ndecl = 0;
}

static void srs_close_body(struct srs_fctx *f)
{
    if (!f->b.infunc)
        return;
    if ((f->b.haspub || f->b.hasvocab) && f->b.elseifs >= k_srs_elseif_min)
        for (int i = 0; i < f->b.ndecl; i++)
            if (f->b.assigns[i] >= k_srs_assign_min)
                f->count++;
    f->b.infunc = 0;
    srs_reset_body(&f->b);
}

/* Copies src into dst, failing closed when it does not fit. */
static int srs_copy(char *dst, size_t cap, const char *src)
{
    return ovf(snprintf(dst, cap, "%s", src), cap);
}

static size_t srs_skip_ws(const char *s, size_t i)
{
    while (srs_ws(s[i]))
        i++;
    return i;
}

/* Copies the C identifier starting at s[i] into name. Returns the index
 * after it; equal to i when there is no identifier there. */
static size_t srs_ident(const char *s, size_t i, char *name, size_t cap)
{
    size_t j = 0, k = i;
    name[0] = '\0';
    if (!(isalpha((unsigned char)s[k]) || s[k] == '_'))
        return i;
    while (isalnum((unsigned char)s[k]) || s[k] == '_') {
        if (j + 1 < cap)
            name[j++] = s[k];
        k++;
    }
    name[j] = '\0';
    return k;
}

/* Matches `bool <ident> = (false|true);` with nothing after it, the
 * ladder accumulator, after one or more leading blanks. */
static int srs_decl_name(const char *s, char *name, size_t cap)
{
    size_t i = srs_skip_ws(s, 0);
    if (i == 0 || strncmp(s + i, "bool", 4) != 0)
        return 0;
    size_t j = srs_skip_ws(s, i + 4);
    if (j == i + 4)
        return 0;
    size_t e = srs_ident(s, j, name, cap);
    if (e == j)
        return 0;
    i = srs_skip_ws(s, e);
    if (s[i] != '=')
        return 0;
    i = srs_skip_ws(s, i + 1);
    if (strncmp(s + i, "false", 5) == 0)
        i += 5;
    else if (strncmp(s + i, "true", 4) == 0)
        i += 4;
    else
        return 0;
    i = srs_skip_ws(s, i);
    if (s[i] != ';')
        return 0;
    return s[srs_skip_ws(s, i + 1)] == '\0';
}

/* A fragment of the form `ident = <rest>` where rest is non-empty and
 * does not start with '=' (the awk pattern `=[ \t]*[^=]`, whose blank
 * run may backtrack onto one blank, so `x = ` counts). */
static int srs_frag_assign(const char *t, char *name, size_t cap)
{
    size_t i = srs_skip_ws(t, 0);
    size_t e = srs_ident(t, i, name, cap);
    if (e == i)
        return 0;
    i = srs_skip_ws(t, e);
    if (t[i] != '=')
        return 0;
    i++;
    return t[i] != '\0' && t[i] != '=';
}

static int srs_decl_find(const struct srs_bodystate *b, const char *name)
{
    for (int i = 0; i < b->ndecl; i++)
        if (strcmp(b->names[i], name) == 0)
            return i;
    return -1;
}

static int srs_has_elseif(const char *s)
{
    const char *p = s;
    while ((p = strstr(p, "else")) != NULL) {
        size_t i = (size_t)(p - s) + 4;
        size_t k = srs_skip_ws(s, i);
        if (k > i && strncmp(s + k, "if", 2) == 0 &&
            s[srs_skip_ws(s, k + 2)] == '(')
            return 1;
        p++;
    }
    return 0;
}

/* True when tok occurs in s followed by blanks and '('. Every occurrence
 * is tried, not only the first. */
static int srs_tok_paren(const char *s, const char *tok)
{
    size_t tl = strlen(tok);
    const char *p = s;
    while ((p = strstr(p, tok)) != NULL) {
        size_t i = srs_skip_ws(s, (size_t)(p - s) + tl);
        if (s[i] == '(')
            return 1;
        p++;
    }
    return 0;
}

static int srs_has_vocab(const char *s)
{
    return strstr(s, "\"blocked\"") != NULL ||
           strstr(s, "\"catching_up\"") != NULL ||
           strstr(s, "\"degraded\"") != NULL;
}

static int srs_is_open_line(const char *s)
{
    if (s[0] != '{')
        return 0;
    return s[srs_skip_ws(s, 1)] == '\0';
}

/* A locally declared bool seeded with a literal starts a ladder candidate. */
static int srs_note_decl(struct srs_bodystate *b, const char *buf)
{
    char nm[SRS_NAME];
    if (srs_decl_name(buf, nm, sizeof nm) && b->ndecl < SRS_NAMES &&
        srs_decl_find(b, nm) < 0) {
        if (srs_copy(b->names[b->ndecl], SRS_NAME, nm))
            return 2;
        b->assigns[b->ndecl] = 0;
        b->ndecl++;
    }
    return 0;
}

/* Counts plain assignments to declared bools, fragment by fragment. */
static void srs_note_frags(struct srs_bodystate *b, const char *buf, size_t n)
{
    char nm[SRS_NAME];
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && buf[j] != '{' && buf[j] != ';')
            j++;
        if (j > i) {
            char frag[SRS_LINE];
            memcpy(frag, buf + i, j - i);
            frag[j - i] = '\0';
            int k;
            if (srs_frag_assign(frag, nm, sizeof nm) &&
                (k = srs_decl_find(b, nm)) >= 0)
                b->assigns[k]++;
        }
        i = j + 1;
    }
}

static void srs_note_flags(struct srs_bodystate *b, const char *buf)
{
    if (srs_has_elseif(buf))
        b->elseifs++;
    if (srs_tok_paren(buf, "json_push_kv_bool"))
        b->haspub = 1;
    if (srs_has_vocab(buf))
        b->hasvocab = 1;
}

/* lc_each_line callback: mirrors the awk pass of the shell original. */
static int srs_scan_line(void *ctx, const char *line, size_t len)
{
    struct srs_fctx *f = ctx;
    char buf[SRS_LINE];
    size_t n = len;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    if (n >= sizeof buf) {
        fprintf(stderr, "%s: line exceeds %d bytes\n", k_srs_gate,
                (int)sizeof buf);
        return 2;
    }
    memcpy(buf, line, n);
    buf[n] = '\0';
    if (srs_is_open_line(buf)) {
        srs_close_body(f);
        f->b.infunc = 1;
        srs_reset_body(&f->b);
        return 0;
    }
    if (buf[0] == '}') {
        srs_close_body(f);
        return 0;
    }
    if (!f->b.infunc)
        return 0;
    if (srs_note_decl(&f->b, buf))
        return 2;
    srs_note_frags(&f->b, buf, n);
    srs_note_flags(&f->b, buf);
    return 0;
}

/* Counts the ladders in one file. 0 ok (count set), 2 error. */
int srs_scan_file(const char *path, int *count)
{
    struct srs_fctx f;
    memset(&f, 0, sizeof f);
    int rc = lc_each_line(path, srs_scan_line, &f, 1);
    if (rc != 0) {
        fprintf(stderr, "%s: could not scan %s\n", k_srs_gate, path);
        return 2;
    }
    srs_close_body(&f);
    *count = f.count;
    return 0;
}

static int srs_scan_all(char files[][SRS_PATH], size_t n, struct srs_rows *rs)
{
    rs->n = 0;
    for (size_t i = 0; i < n; i++) {
        int debt = 0;
        if (srs_scan_file(files[i], &debt))
            return 2;
        if (debt <= 0)
            continue;
        if (rs->n >= SRS_MAXROWS) {
            fprintf(stderr, "%s: hit rows exceed %d\n", k_srs_gate,
                    SRS_MAXROWS);
            return 2;
        }
        if (srs_copy(rs->r[rs->n].path, SRS_PATH, files[i]))
            return 2;
        rs->r[rs->n].debt = debt;
        rs->n++;
    }
    return 0;
}

static void srs_trim(char *s)
{
    size_t n = strlen(s), a = 0;
    while (a < n && srs_ws(s[a]))
        a++;
    while (n > a && (srs_ws(s[n - 1]) || s[n - 1] == '\n' || s[n - 1] == '\r'))
        n--;
    memmove(s, s + a, n - a);
    s[n - a] = '\0';
}

/* Parses one "<path> <count>" baseline row. The count token is kept raw
 * so a non-numeric value fails closed with its own message. */
static int srs_base_row(struct srs_baselist *bl, char *line)
{
    size_t b = strlen(line), a = 0, e = b;
    while (a < b && !srs_ws(line[a]))
        a++;
    while (e > 0 && !srs_ws(line[e - 1]))
        e--;
    if (e < a)
        e = a;
    struct srs_base *row = &bl->b[bl->n];
    if (ovf(snprintf(row->path, SRS_PATH, "%.*s", (int)a, line), SRS_PATH))
        return 2;
    if (srs_copy(row->raw, sizeof row->raw, line + e))
        return 2;
    row->val = atoi(row->raw);
    row->hit = 0;
    bl->n++;
    return 0;
}

/* Loads a "<path> <count>" baseline: comment/blank lines skipped. A missing
 * baseline is empty. */
static int srs_base_load(const char *path, struct srs_baselist *bl)
{
    bl->n = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[SRS_PATH * 2];
    int rc = 0;
    while (rc == 0 && fgets(line, sizeof line, f)) {
        char *h = strchr(line, '#');
        if (h)
            *h = '\0';
        srs_trim(line);
        if (!line[0])
            continue;
        if (bl->n >= SRS_BASE)
            break;
        rc = srs_base_row(bl, line);
    }
    fclose(f);
    return rc;
}

static int srs_base_find(const struct srs_baselist *bl, const char *path)
{
    for (int i = 0; i < bl->n; i++)
        if (strcmp(bl->b[i].path, path) == 0)
            return i;
    return -1;
}

static int srs_digits(const char *s)
{
    if (!*s)
        return 0;
    for (; *s; s++)
        if (!isdigit((unsigned char)*s))
            return 0;
    return 1;
}

static int srs_excluded(const char *p)
{
    static const char *const ex[] = { "operator_needed_policy.c",
                                      "test_operator_needed_policy.c" };
    for (size_t i = 0; i < 2; i++) {
        size_t l = strlen(ex[i]);
        size_t n = strlen(p);
        if (n < l)
            continue;
        if (strcmp(p + n - l, ex[i]) == 0 &&
            (n == l || p[n - l - 1] == '/'))
            return 1;
    }
    return 0;
}

static int srs_add_file(char files[][SRS_PATH], size_t *n, const char *p)
{
    if (*n >= SRS_MAXFILES) {
        fprintf(stderr, "%s: scan set exceeds %d files\n", k_srs_gate,
                SRS_MAXFILES);
        return 2;
    }
    if (strlen(p) >= SRS_PATH) {
        fprintf(stderr, "%s: path exceeds %d bytes: %s\n", k_srs_gate,
                SRS_PATH, p);
        return 2;
    }
    if (srs_copy(files[*n], SRS_PATH, p))
        return 2;
    (*n)++;
    return 0;
}

/* Reads `git ls-files core engine ...` over a pipe and returns its bytes
 * in buf (NUL-terminated). 0 ok, 2 error. A failed git leaves an empty
 * set, which the floor refuses. */
static int srs_git_read(char *buf, size_t cap, size_t *len)
{
    int fd[2];
    *len = 0;
    buf[0] = '\0';
    if (pipe(fd) != 0)
        return 0;
    pid_t pid = fork();
    if (pid < 0) {
        close(fd[0]);
        close(fd[1]);
        return 0;
    }
    if (pid == 0) {
        close(fd[0]);
        dup2(fd[1], STDOUT_FILENO);
        close(fd[1]);
        char *const av[] = { (char *)"git", (char *)"ls-files",
                             (char *)"core", (char *)"engine",
                             (char *)"contexts", (char *)"cognition",
                             (char *)"platform", NULL };
        execvp(av[0], av);
        _exit(127);
    }
    close(fd[1]);
    ssize_t r;
    while (*len < cap - 1 &&
           (r = read(fd[0], buf + *len, cap - 1 - *len)) > 0)
        *len += (size_t)r;
    close(fd[0]);
    if (*len >= cap - 1) {
        fprintf(stderr, "%s: git ls-files output exceeds %zu bytes\n",
                k_srs_gate, cap - 1);
        return 2;
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0)
        if (errno != EINTR)
            return 2;
    buf[*len] = '\0';
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
        *len = 0;
    return 0;
}

/* The .c files of the five production authorities, minus the policy pair. */
static int srs_git_files(char files[][SRS_PATH], size_t *n)
{
    static char buf[SRS_GITBUF];
    size_t len = 0;
    *n = 0;
    if (srs_git_read(buf, sizeof buf, &len))
        return 2;
    char *save = NULL;
    for (char *p = strtok_r(buf, "\n", &save); p;
         p = strtok_r(NULL, "\n", &save)) {
        size_t l = strlen(p);
        if (l < 2 || strcmp(p + l - 2, ".c") != 0 || srs_excluded(p))
            continue;
        if (srs_add_file(files, n, p))
            return 2;
    }
    return 0;
}

/* Sandbox path: a literal glob (a dir plus a *.c pattern) over a temp tree. */
static int srs_glob_files(const char *pat, char files[][SRS_PATH], size_t *n)
{
    *n = 0;
    char dir[SRS_PATH];
    if (srs_copy(dir, sizeof dir, pat))
        return 2;
    char *slash = strrchr(dir, '/');
    const char *d = ".";
    if (slash) {
        *slash = '\0';
        d = dir;
    }
    DIR *dp = opendir(d);
    if (!dp)
        return 0;
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        char full[SRS_PATH * 2];
        if (ovf(snprintf(full, sizeof full, "%s/%s", d, de->d_name),
                sizeof full)) {
            closedir(dp);
            return 2;
        }
        if (fnmatch(pat, full, 0) == 0 && srs_add_file(files, n, full)) {
            closedir(dp);
            return 2;
        }
    }
    closedir(dp);
    return 0;
}

static int srs_cmp_str(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int srs_cmp_row(const void *a, const void *b)
{
    return strcmp(((const struct srs_row *)a)->path,
                  ((const struct srs_row *)b)->path);
}

/* Classifies one measured row against its baseline pin. */
static void srs_classify_row(struct srs_run *r, const struct srs_row *row)
{
    int k = srs_base_find(&r->bl, row->path);
    if (k < 0) {
        viol_put(r->viol[r->nviol++], SRS_ROW,
                 "%s — %d inline ladder(s) found, not in the baseline "
                 "(a new file may carry ZERO)", row->path, row->debt);
        return;
    }
    r->bl.b[k].hit = 1;
    if (row->debt <= r->bl.b[k].val) {
        r->ntol++;
        return;
    }
    viol_put(r->viol[r->nviol++], SRS_ROW,
             "%s — %d inline ladder(s) found, baseline allows %d",
             row->path, row->debt, r->bl.b[k].val);
}

/* Measures every row against the baseline and lists the stale pins. */
static void srs_evaluate(struct srs_run *r)
{
    r->total = 0;
    r->nviol = 0;
    r->ntol = 0;
    r->nstale = 0;
    for (int i = 0; i < r->rs.n; i++) {
        r->total += r->rs.r[i].debt;
        srs_classify_row(r, &r->rs.r[i]);
    }
    for (int i = 0; i < r->bl.n; i++)
        if (!r->bl.b[i].hit)
            viol_put(r->stale[r->nstale++], SRS_ROW,
                     "%s (baseline says %d, actual 0)", r->bl.b[i].path,
                     r->bl.b[i].val);
}

/* The baseline file's recorded sum may never exceed the ceiling. */
static void srs_ceiling_check(struct srs_run *r, FILE *out)
{
    if (r->baseline_sum <= r->cfg.ceiling)
        return;
    fprintf(out, "\n[%s] baseline sum (%d) exceeds the ratchet ceiling "
            "(%d)\n", k_srs_gate, r->baseline_sum, r->cfg.ceiling);
    fprintf(out, "        in %s — the baseline was edited upward. Lower it "
            "back, or\n", r->cfg.basep);
    fprintf(out, "        lower RATCHET_CEILING in this script if the "
            "tolerated set has\n");
    fprintf(out, "        genuinely grown (a change that belongs in code "
            "review, not a\n");
    fprintf(out, "        quiet data-file edit).\n");
    viol_put(r->viol[r->nviol++], SRS_ROW,
             "%s — baseline sum %d exceeds ceiling %d", r->cfg.basep,
             r->baseline_sum, r->cfg.ceiling);
}

static int srs_write_baseline(const char *path, const struct srs_rows *rs)
{
    struct srs_rows sorted = *rs;
    qsort(sorted.r, (size_t)sorted.n, sizeof sorted.r[0], srs_cmp_row);
    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "%s: cannot write %s\n", k_srs_gate, path);
        return 2;
    }
    fprintf(f, "# %s baseline — files still carrying an inline operator-verdict\n", k_srs_gate);
    fprintf(f, "# ladder instead of selecting an enum node_status_reason and reading\n");
    fprintf(f, "# the verdict back from controllers/operator_needed_policy.def.\n");
    fprintf(f, "#\n");
    fprintf(f, "# Format: <path> <count>.  COUNTS MAY ONLY SHRINK.\n");
    fprintf(f, "#\n");
    fprintf(f, "# Regenerate: ZCL_LINT_MODE=UPDATE ./build/bin/z23-lint check-status-reason-single\n");
    for (int i = 0; i < sorted.n; i++)
        fprintf(f, "%s %d\n", sorted.r[i].path, sorted.r[i].debt);
    fclose(f);
    return 0;
}

/* Reads the gate knobs from the environment, with the shell defaults. */
static void srs_cfg_load(struct srs_cfg *c)
{
    c->mode = env_or("ZCL_LINT_MODE", "FAIL");
    c->basep = env_or("ZCL_STATUS_REASON_GATE_BASELINE", k_srs_default_baseline);
    c->glob = env_or("ZCL_STATUS_REASON_GATE_SCAN_GLOB", NULL);
    const char *ce = env_or("ZCL_STATUS_REASON_GATE_CEILING", NULL);
    c->ceiling = ce ? atoi(ce) : k_srs_ratchet_ceiling;
    c->floor = atoi(env_or("ZCL_STATUS_REASON_GATE_FILE_FLOOR",
                           c->glob ? "1" : "1500"));
}

/* Collects the scan set and refuses a hollow one. */
static int srs_collect(struct srs_run *r)
{
    int rc = r->cfg.glob
        ? srs_glob_files(r->cfg.glob, r->files, &r->nfiles)
        : srs_git_files(r->files, &r->nfiles);
    if (rc)
        return 2;
    if (gate_require_scanned((int)r->nfiles, r->cfg.floor, k_srs_gate,
                             "no *.c files found under the five production "
                             "authorities"))
        return 2;
    return 0;
}

/* Loads the baseline and sums it; a non-numeric count is fatal. */
static int srs_load_baseline(struct srs_run *r, FILE *err)
{
    if (srs_base_load(r->cfg.basep, &r->bl))
        return 2;
    r->baseline_sum = 0;
    for (int i = 0; i < r->bl.n; i++) {
        if (!srs_digits(r->bl.b[i].raw)) {
            fprintf(err, "[%s] FATAL — baseline row '%s' has a non-numeric "
                    "count '%s' in %s\n", k_srs_gate, r->bl.b[i].path,
                    r->bl.b[i].raw, r->cfg.basep);
            return 2;
        }
        r->baseline_sum += r->bl.b[i].val;
    }
    return 0;
}

/* Prints the violation and stale sections. Returns 1 when either exists. */
static int srs_print_findings(const struct srs_run *r, FILE *out)
{
    int fail = 0;
    if (r->nviol > 0) {
        fail = 1;
        fprintf(out, "\n[%s] %d violation(s) — a new or grown inline\n",
                k_srs_gate, r->nviol);
        fprintf(out, "        operator-verdict ladder:\n");
        for (int i = 0; i < r->nviol; i++)
            fprintf(out, "  %s\n", r->viol[i]);
        fprintf(out, "\n");
        fprintf(out, "  One table decides this. Select an enum node_status_reason over your\n");
        fprintf(out, "  own snapshot, then read status/summary/operator_needed back:\n");
        fprintf(out, "    #include \"controllers/operator_needed_policy.h\"\n");
        fprintf(out, "    node_status_reason_status() / _summary() / _operator_needed()\n");
        fprintf(out, "  Add a row to controllers/operator_needed_policy.def for a new reason.\n");
        fprintf(out, "  Never pass a literal that switches a rung off — a shared function\n");
        fprintf(out, "  called with a conjunct-disabling literal is still two ledgers.\n");
        fprintf(out, "  Raising a number in %s is NOT a fix; counts may only shrink.\n",
                r->cfg.basep);
    }
    if (r->nstale > 0) {
        fail = 1;
        fprintf(out, "\n[%s] %d STALE baseline row(s) — the file no longer "
                "carries\n", k_srs_gate, r->nstale);
        fprintf(out, "        an inline ladder. Delete them from %s:\n", r->cfg.basep);
        for (int i = 0; i < r->nstale; i++)
            fprintf(out, "  %s\n", r->stale[i]);
    }
    return fail;
}

static void srs_sort_findings(struct srs_run *r)
{
    qsort(r->viol, (size_t)r->nviol, SRS_ROW, srs_cmp_str);
    qsort(r->stale, (size_t)r->nstale, SRS_ROW, srs_cmp_str);
}

/* The whole gate, parameterized by the sink streams (selftest re-entry). */
int srs_run_core(FILE *out, FILE *err)
{
    struct srs_run *r = &g_srs;
    srs_cfg_load(&r->cfg);
    if (srs_collect(r))
        return 2;
    if (srs_scan_all(r->files, r->nfiles, &r->rs))
        return 2;
    if (srs_load_baseline(r, err))
        return 2;
    srs_evaluate(r);
    srs_ceiling_check(r, out);
    if (strcmp(r->cfg.mode, "UPDATE") == 0) {
        if (srs_write_baseline(r->cfg.basep, &r->rs))
            return 2;
        fprintf(out, "[%s] baseline UPDATED: %s\n", k_srs_gate, r->cfg.basep);
        return 0;
    }
    srs_sort_findings(r);
    int fail = srs_print_findings(r, out);
    if (fail && strcmp(r->cfg.mode, "FAIL") == 0)
        return 1;
    fprintf(out, "[%s] PASS (%zu *.c files scanned, %d carrying a ladder, %d "
            "total, %d baselined file(s) summing to %d/%d, %d tolerated, "
            "no allow-comment mechanism exists)\n", k_srs_gate, r->nfiles,
            r->rs.n, r->total, r->bl.n, r->baseline_sum, r->cfg.ceiling,
            r->ntol);
    return 0;
}

int check_status_reason_single_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return srs_run_core(stdout, stderr);
}
