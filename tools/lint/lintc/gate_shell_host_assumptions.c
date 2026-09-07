/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-shell-host-assumptions lint gate of the
 * C23 lint runtime. Replaces tools/lint/check_shell_host_assumptions.sh:
 * a shrink-only rail for shell commands whose spellings silently assume
 * Linux/GNU (bare `ss`, `nproc`, `stat -c`, `sed -i`). Every tracked *.sh
 * file's raw lexical text (comments, quotes and heredoc bodies included,
 * exactly like the shell gate) is scanned; per-(kind,path) hit counts are
 * checked against a per-kind hard ceiling and a shrink-only baseline file.
 * Production scan probes for a .git directory and reads it natively via
 * lint_git_index_foreach; a tree with no .git (git archive HEAD, or the
 * make_lint_gates fixture) falls back to a plain filesystem walk — never
 * spawns a process either way.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_shell_host_assumptions_priv.h"

enum {
    SHL_FILES_MAX = 2048, SHL_LOGICAL_MAX = 16384, SHL_VIOL_MAX = 512,
    SHL_VIOL_LINE = 640
};

const char k_gate[] = "check-shell-host-assumptions";
static const char k_self[] = "tools/lint/check_shell_host_assumptions.sh";

/* ── generic helpers ──────────────────────────────────────────────────── */

static int shl_fail(const char *msg)
{
    fprintf(stderr, "[%s] FATAL — %s\n", k_gate, msg);
    return 2;
}

static int shl_fail_fmt(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    return shl_fail(buf);
}

static int shl_has_sh_suffix(const char *path)
{
    size_t n = strlen(path);
    return n >= 3 && !strcmp(path + n - 3, ".sh");
}

static int shl_has_git(const char *root)
{
    char p[SHL_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/.git", root), sizeof p)) return 0;
    struct stat st;
    return stat(p, &st) == 0;
}

/* ── (kind,path)->count table, shared shape for the observed scan and
 * the loaded baseline. ──────────────────────────────────────────────── */

int shl_table_find(const struct shl_table *t, const char *kind, const char *path)
{
    for (int i = 0; i < t->n; i++)
        if (!strcmp(t->r[i].kind, kind) && !strcmp(t->r[i].path, path)) return i;
    return -1;
}

static int shl_table_set(struct shl_table *t, const char *kind, const char *path, int count)
{
    if (t->n >= SHL_ROWS_MAX) return die("z23-lint: scan-set overflow\n", "");
    int idx = t->n++;
    if (ovf(snprintf(t->r[idx].kind, sizeof t->r[idx].kind, "%s", kind), sizeof t->r[idx].kind)
        || ovf(snprintf(t->r[idx].path, sizeof t->r[idx].path, "%s", path), sizeof t->r[idx].path))
        return 2;
    t->r[idx].count = count;
    return 0;
}

static int shl_table_bump(struct shl_table *t, const char *kind, const char *path)
{
    int idx = shl_table_find(t, kind, path);
    if (idx < 0) {
        if (shl_table_set(t, kind, path, 0)) return 2;
        idx = t->n - 1;
    }
    t->r[idx].count++;
    return 0;
}

static int shl_total_for(const struct shl_table *t, const char *kind)
{
    int s = 0;
    for (int i = 0; i < t->n; i++)
        if (!strcmp(t->r[i].kind, kind)) s += t->r[i].count;
    return s;
}

/* ── file collection: tracked *.sh (index or walk), or a fixture dir
 * walk under ZCL_SHELL_HOST_SCAN_DIR. Each entry carries the path used
 * to open it (abs) and the path used as its table/baseline key
 * (report) — the shell gate's own $ROOT/ stripping rule, applied at
 * collection time instead of after the fact. ─────────────────────────── */

struct shl_file { char abs[SHL_PATH]; char report[SHL_PATH]; };
struct shl_files { struct shl_file f[SHL_FILES_MAX]; int n; };

static int shl_files_add(struct shl_files *fs, const char *abs, const char *report)
{
    if (fs->n >= SHL_FILES_MAX) return die("z23-lint: scan-set overflow\n", "");
    if (ovf(snprintf(fs->f[fs->n].abs, SHL_PATH, "%s", abs), SHL_PATH)
        || ovf(snprintf(fs->f[fs->n].report, SHL_PATH, "%s", report), SHL_PATH))
        return 2;
    fs->n++;
    return 0;
}

struct shl_idx_ctx { struct shl_files *fs; const char *root; int rc; };

static int shl_idx_cb(const char *path, int stage, void *ctxp)
{
    if (stage != 0) return 0;
    struct shl_idx_ctx *c = ctxp;
    if (!shl_has_sh_suffix(path) || !strcmp(path, k_self)) return 0;
    char abs[SHL_PATH];
    if (ovf(snprintf(abs, sizeof abs, "%s/%s", c->root, path), sizeof abs)) {
        c->rc = 2;
        return 1;
    }
    c->rc = shl_files_add(c->fs, abs, path);
    return c->rc ? 1 : 0;
}

static int shl_collect_index(struct shl_files *fs, const char *root)
{
    struct shl_idx_ctx c = { fs, root, 0 };
    char badext[5] = "";
    int rc = lint_git_index_foreach(shl_idx_cb, &c, badext);
    if (rc == 2 || c.rc == 2 || badext[0]) {
        fprintf(stderr,
            "[%s] UNPROVEN — the git index carries a mandatory extension\n"
            "  this native reader does not interpret; refusing to grade.\n", k_gate);
        return 2;
    }
    return 0;
}

static int shl_skip_dir(const char *name)
{
    return !strcmp(name, ".git") || !strcmp(name, "build") || !strcmp(name, "vendor")
        || !strcmp(name, ".claude") || !strcmp(name, "test-tmp");
}

static int shl_walk(const char *base, const char *rel, struct shl_files *fs,
                    int apply_skip, int prefix_report, int skip_self);

static int shl_walk_add_if_match(const char *base, const char *relpath,
                                 const char *abspath, struct shl_files *fs,
                                 int prefix_report, int skip_self)
{
    if (!shl_has_sh_suffix(relpath)) return 0;
    if (skip_self && !strcmp(relpath, k_self)) return 0;
    char report[SHL_PATH];
    if (prefix_report) {
        if (ovf(snprintf(report, sizeof report, "%s/%s", base, relpath), sizeof report))
            return 2;
    } else if (ovf(snprintf(report, sizeof report, "%s", relpath), sizeof report))
        return 2;
    return shl_files_add(fs, abspath, report);
}

static int shl_walk_entry(const char *base, const char *dir, const char *rel,
                          const char *nm, struct shl_files *fs, int apply_skip,
                          int prefix_report, int skip_self)
{
    char relpath[SHL_PATH], abspath[4096];
    if (ovf(snprintf(relpath, sizeof relpath, "%s%s%s", rel, rel[0] ? "/" : "", nm),
            sizeof relpath)
        || ovf(snprintf(abspath, sizeof abspath, "%s/%s", dir, nm), sizeof abspath))
        return 2;
    struct stat st;
    if (lstat(abspath, &st) != 0)
        return die("z23-lint: cannot stat %s\n", abspath);
    if (S_ISDIR(st.st_mode))
        return shl_walk(base, relpath, fs, apply_skip, prefix_report, skip_self);
    if (S_ISREG(st.st_mode))
        return shl_walk_add_if_match(base, relpath, abspath, fs, prefix_report, skip_self);
    return 0;
}

static int shl_walk(const char *base, const char *rel, struct shl_files *fs,
                    int apply_skip, int prefix_report, int skip_self)
{
    char dir[4096];
    if (ovf(snprintf(dir, sizeof dir, "%s%s%s", base, rel[0] ? "/" : "", rel), sizeof dir))
        return 2;
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        if (rc == 0) {
            const char *nm = names[i]->d_name;
            if (strcmp(nm, ".") != 0 && strcmp(nm, "..") != 0
                && (!apply_skip || !shl_skip_dir(nm)))
                rc = shl_walk_entry(base, dir, rel, nm, fs, apply_skip, prefix_report, skip_self);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int shl_collect_files(const char *root, const char *scan_dir, struct shl_files *fs)
{
    fs->n = 0;
    if (scan_dir && scan_dir[0])
        return shl_walk(scan_dir, "", fs, 0, 1, 0);
    if (shl_has_git(root))
        return shl_collect_index(fs, root);
    return shl_walk(root, "", fs, 1, 0, 1);
}

/* ── lexical classifier: joins backslash-continued physical lines into
 * one logical line (exactly like the shell gate's awk driver), defangs
 * quote characters, then finds every non-overlapping hit of the four
 * host-assumption shapes. Each shape scans its OWN copy of the defanged
 * line (the shell gate's awk passed `text` to emit_matches by value, so
 * one shape's consumed matches never affect another's). ──────────────── */

struct shl_pats { regex_t ss, nproc, stat_p, sed_p; };

static int shl_pats_compile(struct shl_pats *p)
{
    if (compile_pat(&p->ss, REG_EXTENDED,
                    "(^|[[:space:];&|()/])ss([[:space:];&|()]|$)", "", "", ""))
        return 2;
    if (compile_pat(&p->nproc, REG_EXTENDED,
                    "(^|[[:space:];&|()/])nproc([[:space:];&|()]|$)", "", "", "")) {
        regfree(&p->ss);
        return 2;
    }
    if (compile_pat(&p->stat_p, REG_EXTENDED,
                    "(^|[[:space:];&|()/])stat[[:space:]]+([^;&|()[:space:]]+[[:space:]]+)*"
                    "-[A-Za-z]*c[^;&|()[:space:]]*", "", "", "")) {
        drop2(&p->ss, &p->nproc);
        return 2;
    }
    if (compile_pat(&p->sed_p, REG_EXTENDED,
                    "(^|[[:space:];&|()/])sed[[:space:]]+([^;&|()[:space:]]+[[:space:]]+)*"
                    "-[A-Za-z]*i[^;&|()[:space:]]*", "", "", "")) {
        drop3(&p->ss, &p->nproc, &p->stat_p);
        return 2;
    }
    return 0;
}

static void shl_pats_free(struct shl_pats *p)
{ drop3(&p->ss, &p->nproc, &p->stat_p); regfree(&p->sed_p); }

static int shl_emit_kind(const regex_t *re, const char *kind, const char *path,
                         const char *base, struct shl_table *t)
{
    char text[SHL_LOGICAL_MAX];
    if (ovf(snprintf(text, sizeof text, "%s", base), sizeof text)) return 2;
    regmatch_t mt;
    while (regexec(re, text, 1, &mt, 0) == 0) {
        if (shl_table_bump(t, kind, path)) return 2;
        size_t so = (size_t)mt.rm_so, eo = (size_t)mt.rm_eo, len = strlen(text);
        char tmp[SHL_LOGICAL_MAX];
        size_t k = so;
        memcpy(tmp, text, so);
        tmp[k++] = ' ';
        memcpy(tmp + k, text + eo, len - eo + 1);
        memcpy(text, tmp, k + (len - eo + 1));
    }
    return 0;
}

static int shl_classify(const char *logical, const char *path,
                        const struct shl_pats *P, struct shl_table *t)
{
    char base[SHL_LOGICAL_MAX];
    if (ovf(snprintf(base, sizeof base, "%s", logical), sizeof base)) return 2;
    for (char *p = base; *p; p++)
        if (*p == '"' || *p == '\'') *p = ' ';
    if (shl_emit_kind(&P->ss, "ss", path, base, t)) return 2;
    if (shl_emit_kind(&P->nproc, "nproc", path, base, t)) return 2;
    if (shl_emit_kind(&P->stat_p, "stat", path, base, t)) return 2;
    if (shl_emit_kind(&P->sed_p, "sed", path, base, t)) return 2;
    return 0;
}

static int shl_line_continues(const char *line)
{
    size_t n = strlen(line);
    while (n && (line[n - 1] == ' ' || line[n - 1] == '\t')) n--;
    return n > 0 && line[n - 1] == '\\';
}

static void shl_strip_continuation(char *code)
{
    size_t n = strlen(code);
    while (n && (code[n - 1] == ' ' || code[n - 1] == '\t')) n--;
    if (n) n--;
    code[n] = '\0';
}

static int shl_append_logical(char *buf, size_t cap, const char *code)
{
    size_t have = strlen(buf), add = strlen(code);
    if (have + 1 + add + 1 > cap) return die("z23-lint: derived buffer overflow\n", "");
    buf[have] = ' ';
    memcpy(buf + have + 1, code, add + 1);
    return 0;
}

static int shl_scan_open_file(FILE *f, const char *path, const struct shl_pats *P,
                              struct shl_table *t)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    char logical[SHL_LOGICAL_MAX];
    logical[0] = '\0';
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';
        int cont = shl_line_continues(line);
        if (cont) shl_strip_continuation(line);
        rc = shl_append_logical(logical, sizeof logical, line);
        if (rc == 0 && !cont) {
            rc = shl_classify(logical, path, P, t);
            logical[0] = '\0';
        }
    }
    if (rc == 0 && logical[0])
        rc = shl_classify(logical, path, P, t);
    return fin(f, line, path, rc);
}

static int shl_scan_file(const char *abs, const char *report, const struct shl_pats *P,
                         struct shl_table *t, const char *inject_path)
{
    if (inject_path && inject_path[0] && !strcmp(abs, inject_path))
        return shl_fail("shell assumption scanner failed");
    FILE *f = fopen(abs, "r");
    if (!f) {
        fprintf(stderr, "[%s] UNPROVEN — cannot open %s\n", k_gate, abs);
        return 2;
    }
    return shl_scan_open_file(f, report, P, t);
}

/* ── baseline: `<kind> TAB <tracked path> TAB <count>` rows, `#`
 * comments and blanks skipped, shrink-only. ──────────────────────────── */

static int shl_baseline_row(char *line, struct shl_table *allowed)
{
    char *t1 = strchr(line, '\t');
    if (!t1) return shl_fail_fmt("malformed baseline row: %s", line);
    *t1 = '\0';
    char *kind = line;
    char *t2 = strchr(t1 + 1, '\t');
    if (!t2) return shl_fail_fmt("malformed baseline row: %s", line);
    *t2 = '\0';
    char *path = t1 + 1;
    char *count_s = t2 + 1;
    if (!count_s[0]) return shl_fail_fmt("baseline count is not numeric: %s %s %s", kind, path, count_s);
    for (const char *p = count_s; *p; p++)
        if (!isdigit((unsigned char)*p))
            return shl_fail_fmt("baseline count is not numeric: %s %s %s", kind, path, count_s);
    if (shl_table_find(allowed, kind, path) >= 0)
        return shl_fail_fmt("duplicate baseline row: %s %s", kind, path);
    return shl_table_set(allowed, kind, path, atoi(count_s));
}

int shl_load_baseline(const char *path, struct shl_table *allowed, int *present)
{
    allowed->n = 0;
    *present = 0;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    *present = 1;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;
        rc = shl_baseline_row(line, allowed);
    }
    return fin(f, line, path, rc);
}

/* ── violation collection: a shared array of already-formatted lines,
 * sorted LC_ALL=C (byte order, i.e. strcmp) before printing so the
 * report is deterministic regardless of scan order. ──────────────────── */

struct shl_violset { char v[SHL_VIOL_MAX][SHL_VIOL_LINE]; int n; };

static int shl_viol_add(struct shl_violset *vs, const char *fmt, ...)
{
    if (vs->n >= SHL_VIOL_MAX) return die("z23-lint: scan-set overflow\n", "");
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(vs->v[vs->n], SHL_VIOL_LINE, fmt, ap);
    va_end(ap);
    if (ovf(k, SHL_VIOL_LINE)) return 2;
    vs->n++;
    return 0;
}

static int shl_viol_cmp(const void *a, const void *b)
{ return strcmp((const char *)a, (const char *)b); }

static int shl_ceiling_for(const char *kind, int ss_c, int nproc_c, int stat_c, int sed_c)
{
    if (!strcmp(kind, "ss")) return ss_c;
    if (!strcmp(kind, "nproc")) return nproc_c;
    if (!strcmp(kind, "stat")) return stat_c;
    return sed_c;
}

static int shl_check_ceilings(const struct shl_table *actual, int ss_c, int nproc_c,
                              int stat_c, int sed_c, struct shl_violset *vs)
{
    static const char *const kinds[] = { "ss", "nproc", "stat", "sed" };
    for (int i = 0; i < 4; i++) {
        int total = shl_total_for(actual, kinds[i]);
        int ceil = shl_ceiling_for(kinds[i], ss_c, nproc_c, stat_c, sed_c);
        if (total > ceil
            && shl_viol_add(vs, "%s total %d exceeds ceiling %d", kinds[i], total, ceil))
            return 2;
    }
    return 0;
}

static int shl_check_actual_row(const struct shl_row *row, const struct shl_table *allowed,
                                int bootstrap, int update_mode, struct shl_violset *vs)
{
    int idx = shl_table_find(allowed, row->kind, row->path);
    if (idx < 0) {
        if (!bootstrap)
            return shl_viol_add(vs, "%s %s count=%d is new", row->kind, row->path, row->count);
        return 0;
    }
    int base_count = allowed->r[idx].count;
    if (row->count > base_count)
        return shl_viol_add(vs, "%s %s actual=%d baseline=%d grew",
                            row->kind, row->path, row->count, base_count);
    if (!update_mode && row->count != base_count)
        return shl_viol_add(vs, "%s %s actual=%d baseline=%d",
                            row->kind, row->path, row->count, base_count);
    return 0;
}

static int shl_check_stale(const struct shl_table *allowed, const struct shl_table *actual,
                           struct shl_violset *vs)
{
    for (int i = 0; i < allowed->n; i++)
        if (shl_table_find(actual, allowed->r[i].kind, allowed->r[i].path) < 0
            && shl_viol_add(vs, "%s %s actual=0 baseline=%d (stale row)",
                            allowed->r[i].kind, allowed->r[i].path, allowed->r[i].count))
            return 2;
    return 0;
}

static int shl_compare(const struct shl_table *actual, const struct shl_table *allowed,
                       int bootstrap, int update_mode, struct shl_violset *vs)
{
    for (int i = 0; i < actual->n; i++)
        if (shl_check_actual_row(&actual->r[i], allowed, bootstrap, update_mode, vs))
            return 2;
    if (!update_mode && shl_check_stale(allowed, actual, vs))
        return 2;
    return 0;
}

static int shl_report_violations(struct shl_violset *vs)
{
    qsort(vs->v, (size_t)vs->n, SHL_VIOL_LINE, shl_viol_cmp);
    fprintf(stderr, "[%s] FAIL — shell host-assumption debt changed:\n", k_gate);
    for (int i = 0; i < vs->n; i++)
        fprintf(stderr, "  %s\n", vs->v[i]);
    fprintf(stderr, "Fix the command with a portable helper/fallback, then shrink with:\n");
    fprintf(stderr, "  ZCL_LINT_MODE=UPDATE tools/lint/check_shell_host_assumptions.sh\n");
    return 1;
}

static int shl_row_cmp(const void *a, const void *b)
{
    const struct shl_row *ra = a, *rb = b;
    int k = strcmp(ra->kind, rb->kind);
    return k ? k : strcmp(ra->path, rb->path);
}

static int shl_write_baseline(const char *path, struct shl_table *actual)
{
    qsort(actual->r, (size_t)actual->n, sizeof actual->r[0], shl_row_cmp);
    char tmp[SHL_PATH];
    if (ovf(snprintf(tmp, sizeof tmp, "%s.tmp", path), sizeof tmp)) return 2;
    FILE *f = fopen(tmp, "w");
    if (!f) return die("z23-lint: cannot open %s\n", tmp);
    int rc = 0;
    if (fprintf(f, "# %s shrink-only baseline\n"
                  "# Format: <kind> TAB <tracked path> TAB <count>. Counts may only shrink.\n",
               k_gate) < 0)
        rc = die("z23-lint: write failed\n", "");
    for (int i = 0; rc == 0 && i < actual->n; i++)
        if (fprintf(f, "%s\t%s\t%d\n", actual->r[i].kind, actual->r[i].path,
                   actual->r[i].count) < 0)
            rc = die("z23-lint: write failed\n", "");
    if (fclose(f) != 0 && rc == 0) rc = die("z23-lint: fclose failed: %s\n", tmp);
    if (rc == 0 && rename(tmp, path) != 0) rc = die("z23-lint: rename failed: %s\n", path);
    return rc;
}

/* ── entry point ──────────────────────────────────────────────────────── */

struct shl_cfg {
    const char *root, *scan_dir, *baseline, *inject_path;
    int file_floor, ss_c, nproc_c, stat_c, sed_c, inject_fail, inject_tracked, bootstrap, update_mode;
};

static void shl_cfg_load(struct shl_cfg *c)
{
    c->root = ".";
    c->scan_dir = getenv("ZCL_SHELL_HOST_SCAN_DIR");
    c->inject_path = getenv("ZCL_SHELL_HOST_INJECT_SCAN_PATH");
    c->file_floor = atoi(env_or("ZCL_SHELL_HOST_FILE_FLOOR", "400"));
    c->ss_c = atoi(env_or("ZCL_SHELL_HOST_SS_CEILING", "63"));
    c->nproc_c = atoi(env_or("ZCL_SHELL_HOST_NPROC_CEILING", "36"));
    c->stat_c = atoi(env_or("ZCL_SHELL_HOST_STAT_CEILING", "108"));
    c->sed_c = atoi(env_or("ZCL_SHELL_HOST_SED_CEILING", "22"));
    const char *inj = getenv("ZCL_SHELL_HOST_INJECT_SCAN_FAILURE");
    c->inject_fail = inj && !strcmp(inj, "1");
    const char *injt = getenv("ZCL_SHELL_HOST_INJECT_TRACKED_BASELINE");
    c->inject_tracked = injt && !strcmp(injt, "1");
    const char *bs = getenv("ZCL_SHELL_HOST_BOOTSTRAP");
    c->bootstrap = bs && !strcmp(bs, "1");
    const char *mode = getenv("ZCL_LINT_MODE");
    c->update_mode = mode && !strcmp(mode, "UPDATE");
    static char blbuf[SHL_PATH];
    const char *bl = getenv("ZCL_SHELL_HOST_BASELINE");
    if (bl && bl[0]) c->baseline = bl;
    else {
        snprintf(blbuf, sizeof blbuf, "%s/tools/lint/shell_host_assumptions_baseline.txt",
                c->root);
        c->baseline = blbuf;
    }
}

static int shl_scan_all(const struct shl_files *fs, const struct shl_pats *P,
                        struct shl_table *actual, const char *inject_path)
{
    for (int i = 0; i < fs->n; i++)
        if (shl_scan_file(fs->f[i].abs, fs->f[i].report, P, actual, inject_path))
            return 2;
    return 0;
}

static int shl_resolve_baseline(const struct shl_cfg *cfg, struct shl_table *allowed,
                                int *bootstrap_out)
{
    int present = 0;
    if (shl_load_baseline(cfg->baseline, allowed, &present)) return 2;
    *bootstrap_out = 0;
    if (present) return 0;
    if (cfg->inject_tracked)
        return shl_fail_fmt("tracked baseline is missing from the worktree: %s", cfg->baseline);
    if (cfg->update_mode && cfg->bootstrap) {
        *bootstrap_out = 1;
        return 0;
    }
    return shl_fail_fmt("baseline is missing: %s", cfg->baseline);
}

int check_shell_host_assumptions_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    struct shl_cfg cfg;
    shl_cfg_load(&cfg);

    static struct shl_files fs;
    if (shl_collect_files(cfg.root, cfg.scan_dir, &fs)) return 2;
    if (fs.n < cfg.file_floor)
        return shl_fail_fmt("shell scan found %d file(s), floor is %d", fs.n, cfg.file_floor);

    if (cfg.inject_fail) return shl_fail("shell assumption scanner failed");

    struct shl_pats P;
    if (shl_pats_compile(&P)) return 2;

    static struct shl_table actual;
    actual.n = 0;
    int rc = shl_scan_all(&fs, &P, &actual, cfg.inject_path);
    shl_pats_free(&P);
    if (rc) return 2;

    static struct shl_violset vs;
    vs.n = 0;
    if (shl_check_ceilings(&actual, cfg.ss_c, cfg.nproc_c, cfg.stat_c, cfg.sed_c, &vs))
        return 2;

    static struct shl_table allowed;
    int bootstrap = 0;
    if (shl_resolve_baseline(&cfg, &allowed, &bootstrap)) return 2;

    if (shl_compare(&actual, &allowed, bootstrap, cfg.update_mode, &vs)) return 2;

    if (vs.n > 0) return shl_report_violations(&vs);

    if (cfg.update_mode) {
        if (shl_write_baseline(cfg.baseline, &actual)) return 2;
        if (printf("[%s] baseline UPDATED: %s\n", k_gate, cfg.baseline) < 0)
            return die("z23-lint: write failed\n", "");
        return 0;
    }

    int total = shl_total_for(&actual, "ss") + shl_total_for(&actual, "nproc")
        + shl_total_for(&actual, "stat") + shl_total_for(&actual, "sed");
    if (printf("[%s] PASS files=%d sites=%d ss=%d nproc=%d stat=%d sed=%d\n",
              k_gate, fs.n, total, shl_total_for(&actual, "ss"),
              shl_total_for(&actual, "nproc"), shl_total_for(&actual, "stat"),
              shl_total_for(&actual, "sed")) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

