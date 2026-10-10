/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — no new coordination shell (check-no-new-coordination-shell).
 * The project goal is NO shell on the coordination path. The coordination
 * path is TOP-LEVEL ONLY: a tracked path is on it when it is exactly
 * tools/dev/<name>.sh or tools/scripts/<name>.sh (no further '/' in <name>),
 * or one of tools/agent_test_runner.sh, tools/agent_fast_ci.sh,
 * tools/deploy_guard.sh. Anything under a subdirectory (for example
 * tools/dev/fixtures and below) is test data and is NOT on the path.
 *
 * Every tracked coordination-path script must be listed in
 * tools/lint/coordination_shell_baseline.txt (one repo-relative path per
 * line, LC_ALL=C sorted, '#' comment lines allowed). A script that is not
 * listed FAILS and must be written in C23 as a native command instead. A
 * listed path that is no longer tracked FAILS as STALE (remove it). An
 * unsorted or duplicate list FAILS. A missing list is read as empty, so every
 * coordination-path script then fails as NEW.
 *
 * The list is HAND-EDITED and can only lose lines: there is NO update and NO
 * write-baseline mode, and this gate never writes the list. Any argument
 * passed to the run mode is refused for that reason.
 *
 * Tracked files via lint_git_index_foreach when .git exists; otherwise the
 * filesystem walk fallback (a non-recursive scandir of tools/dev and
 * tools/scripts, plus a stat of the three named files) — same idiom as
 * gate_no_new_repair_rung.c. The index path is exercised by the real-tree run
 * and the walk path by the selftest, because no selftest in this tree builds a
 * throwaway git repository for lint_git_index_foreach to read. The index
 * iterator calls back once per stage, so each path is added to the set once.
 * Selftest sandboxes a throwaway fixture tree under getenv("TMPDIR") else
 * ./test-tmp (never /tmp itself). Its cases: a clean list passes; a new
 * top-level script fails; a stale entry fails; an unsorted list fails; a
 * subdirectory script is not flagged; malformed entries (absolute, "..",
 * subdirectory, outside the two directories, trailing whitespace) fail as
 * MALFORMED; a missing list reports the missing file; an unreadable list
 * fails with rc 2.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { NCS_MAX = 1024, NCS_LINE = 8192 };

struct ncs_set { char p[NCS_MAX][RS_PATH]; int n; };
struct ncs_ctx { struct ncs_set *s; const char *base; };

static const char k_ncs_base[] = "tools/lint/coordination_shell_baseline.txt";
static const char *const k_ncs_named[] = {
    "tools/agent_test_runner.sh", "tools/agent_fast_ci.sh",
    "tools/deploy_guard.sh"
};
enum { NCS_NNAMED = (int)(sizeof k_ncs_named / sizeof k_ncs_named[0]) };
static const char *const k_ncs_dirs[] = { "tools/dev", "tools/scripts" };
enum { NCS_NDIRS = (int)(sizeof k_ncs_dirs / sizeof k_ncs_dirs[0]) };

/* ── the set ──────────────────────────────────────────────────────────── */

static int ncs_add(struct ncs_set *s, const char *path)
{
    size_t n = strlen(path);
    if (s->n >= NCS_MAX || n >= RS_PATH)
        return die("z23-lint: no-new-coordination-shell overflow\n", "");
    memcpy(s->p[s->n++], path, n + 1);
    return 0;
}

static int ncs_has(const struct ncs_set *s, const char *path)
{
    for (int i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 1;
    return 0;
}

static int ncs_cmp(const void *a, const void *b)
{
    return strcmp(a, b);
}

/* ── which paths are on the coordination path ─────────────────────────── */

/* The path with `base` stripped, or NULL when `path` is not under `base`. */
static const char *ncs_rel(const char *base, const char *path)
{
    size_t k = strlen(base);
    return strncmp(path, base, k) == 0 ? path + k : NULL;
}

/* A TOP-LEVEL script directly under `dir` (no '/' in the name): "<dir>/" then
 * one segment of at least one byte, then ".sh". */
static int ncs_top_script(const char *rel, const char *dir)
{
    size_t k = strlen(dir), n = strlen(rel);
    if (n < k + 5 || strncmp(rel, dir, k) != 0 || rel[k] != '/')
        return 0;
    if (strchr(rel + k + 1, '/'))
        return 0;
    return strcmp(rel + n - 3, ".sh") == 0;
}

static int ncs_named(const char *rel)
{
    for (int i = 0; i < NCS_NNAMED; i++)
        if (strcmp(rel, k_ncs_named[i]) == 0)
            return 1;
    return 0;
}

static int ncs_is_coord(const char *rel)
{
    for (int i = 0; i < NCS_NDIRS; i++)
        if (ncs_top_script(rel, k_ncs_dirs[i]))
            return 1;
    return ncs_named(rel);
}

static int ncs_visit(const char *path, void *ctxv)
{
    struct ncs_ctx *c = ctxv;
    const char *rel = ncs_rel(c->base, path);
    if (!rel || !ncs_is_coord(rel) || lint_path_is_excluded(path))
        return 0;
    if (ncs_has(c->s, rel))
        return 0;
    return ncs_add(c->s, rel);
}

static int ncs_on_idx(const char *path, int stage, void *ctx)
{
    (void)stage;
    return ncs_visit(path, ctx);
}

/* ── collecting the tracked coordination-path set ─────────────────────── */

/* One directory, NOT recursive: the coordination path is top-level only.
 * walk_src() cannot be used here because its matcher yields only .c (and
 * .h) names, never .sh. */
static int ncs_walk_one(struct ncs_ctx *c, const char *path, const char *name)
{
    char file[4096];
    struct stat st;
    if (ovf(snprintf(file, sizeof file, "%s/%s", path, name), sizeof file))
        return 2;
    if (stat(file, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    return ncs_visit(file, c);
}

static int ncs_walk_dir(struct ncs_ctx *c, const char *dir)
{
    char path[4096];
    struct dirent **names = NULL;
    if (ovf(snprintf(path, sizeof path, "%s%s", c->base, dir), sizeof path))
        return 2;
    int n = scandir(path, &names, NULL, alphasort);
    if (n < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", path);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        if (rc == 0)
            rc = ncs_walk_one(c, path, names[i]->d_name);
        free(names[i]);
    }
    free(names);
    return rc;
}

static int ncs_walk_named(struct ncs_ctx *c)
{
    char path[4096];
    struct stat st;
    for (int i = 0; i < NCS_NNAMED; i++) {
        if (ovf(snprintf(path, sizeof path, "%s%s", c->base,
                         k_ncs_named[i]), sizeof path))
            return 2;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        int rc = ncs_visit(path, c);
        if (rc)
            return rc;
    }
    return 0;
}

static int ncs_walk_all(struct ncs_ctx *c)
{
    for (int i = 0; i < NCS_NDIRS; i++) {
        int rc = ncs_walk_dir(c, k_ncs_dirs[i]);
        if (rc)
            return rc;
    }
    return ncs_walk_named(c);
}

static int ncs_collect(struct ncs_set *s, const char *base, int use_git)
{
    struct ncs_ctx c = { .s = s, .base = base };
    struct stat st;
    char bad[8] = {0};
    int rc;
    s->n = 0;
    if (use_git && stat(".git", &st) == 0) {
        rc = lint_git_index_foreach(ncs_on_idx, &c, bad);
        if (rc)
            fprintf(stderr,
                    "check-no-new-coordination-shell: UNPROVEN — git index%s%s\n",
                    bad[0] ? " extension " : "", bad);
    } else {
        rc = ncs_walk_all(&c);
    }
    if (rc == 0)
        qsort(s->p, (size_t)s->n, RS_PATH, ncs_cmp);
    return rc;
}

/* ── the list ─────────────────────────────────────────────────────────── */

/* Load-time state for one list file. bad is set by any MALFORMED, comment or
 * unsorted line; the scan keeps going so every bad line is named. */
struct ncs_lst { struct ncs_set *b; const char *path; FILE *err; int line; int seen; int bad; };

/* Names the entry (at most its first 80 bytes), the line, and why. */
static void ncs_malformed(struct ncs_lst *L, const char *text, const char *why)
{
    fprintf(L->err, "check-no-new-coordination-shell: MALFORMED list entry "
                    "%.80s: %s (line %d)\n", text, why, L->line);
    L->bad = 1;
}

/* A CR anywhere, or a space or tab at either end, is not a clean path. */
static int ncs_has_edge_ws(const char *s)
{
    size_t n = strlen(s);
    if (strchr(s, '\r') != NULL)
        return 1;
    return n > 0 && (s[0] == ' ' || s[0] == '\t' || s[n - 1] == ' '
                     || s[n - 1] == '\t');
}

/* One non-blank, non-comment line: clean edges, then the coordination-path
 * shape, then strictly ascending order. */
static int ncs_load_entry(struct ncs_lst *L, const char *buf)
{
    if (ncs_has_edge_ws(buf)) {
        ncs_malformed(L, buf, "leading, trailing or CR whitespace");
        return 0;
    }
    if (!ncs_is_coord(buf)) {
        ncs_malformed(L, buf, "not a top-level coordination-path script name");
        return 0;
    }
    if (L->b->n > 0 && strcmp(L->b->p[L->b->n - 1], buf) >= 0) {
        fprintf(L->err, "check-no-new-coordination-shell: %s is unsorted or "
                        "holds a duplicate near \"%.80s\" (line %d); keep one "
                        "path per line, sorted with LC_ALL=C sort, no "
                        "duplicates\n", L->path, buf, L->line);
        L->bad = 1;
        return 0;
    }
    return ncs_add(L->b, buf);
}

/* A blank line is a no-op. A '#' line is a comment only before the first
 * path line. Anything else is an entry. */
static int ncs_load_one(struct ncs_lst *L, const char *buf)
{
    if (buf[0] == '\0')
        return 0;
    if (buf[0] == '#') {
        if (L->seen) {
            fprintf(L->err, "check-no-new-coordination-shell: MALFORMED list "
                            "line %d: a '#' comment after the first path line; "
                            "comments belong in the header\n", L->line);
            L->bad = 1;
        }
        return 0;
    }
    L->seen = 1;
    return ncs_load_entry(L, buf);
}

/* fgets() filled the buffer with no newline: the line is too long. Name it by
 * its first 80 bytes, then consume the rest of it. */
static void ncs_too_long(struct ncs_lst *L, FILE *f, char *buf, size_t cap)
{
    fprintf(L->err, "check-no-new-coordination-shell: MALFORMED list line %d: "
                    "longer than the %zu-byte line buffer; first 80 bytes: "
                    "%.80s\n", L->line, cap, buf);
    L->bad = 1;
    while (strchr(buf, '\n') == NULL && fgets(buf, (int)cap, f) != NULL)
        ;
}

/* Returns 0 for a clean list, 1 when any line is MALFORMED or unsorted (every
 * such line is named), 2 when the file cannot be read or the set overflows. A
 * missing file is an empty list, announced on err, so every script reads NEW. */
static int ncs_load_list(struct ncs_set *b, const char *path, FILE *err)
{
    struct ncs_lst L = { .b = b, .path = path, .err = err };
    char buf[NCS_LINE];
    int rc = 0;
    b->n = 0;
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno != ENOENT) {
            fprintf(err, "check-no-new-coordination-shell: cannot read %s\n",
                    path);
            return 2;
        }
        fprintf(err, "check-no-new-coordination-shell: list file %s is "
                     "missing; every coordination-path script is NEW\n", path);
        return 0;
    }
    while (rc == 0 && fgets(buf, (int)sizeof buf, f)) {
        size_t n;
        L.line++;
        if (strchr(buf, '\n') == NULL && !feof(f)) {
            ncs_too_long(&L, f, buf, sizeof buf);
            continue;
        }
        n = strlen(buf);
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        rc = ncs_load_one(&L, buf);
    }
    if (ferror(f)) {
        fclose(f);
        fprintf(err, "check-no-new-coordination-shell: cannot read %s\n", path);
        return 2;
    }
    fclose(f);
    return rc ? rc : L.bad;
}

/* ── comparison and report ────────────────────────────────────────────── */

static int ncs_report_new(FILE *err, const struct ncs_set *listed,
                          const struct ncs_set *found)
{
    int bad = 0;
    for (int i = 0; i < found->n; i++) {
        if (ncs_has(listed, found->p[i]))
            continue;
        if (!bad)
            fputs("check-no-new-coordination-shell: NEW coordination-path "
                  "script(s) not on the list:\n", err);
        fprintf(err, "  %s\n", found->p[i]);
        bad = 1;
    }
    if (bad)
        fputs("\nwrite it in C23 as a native command instead (the project "
              "goal: no shell on the coordination path)\n", err);
    return bad;
}

static int ncs_report_stale(FILE *err, const struct ncs_set *listed,
                            const struct ncs_set *found)
{
    int bad = 0;
    for (int i = 0; i < listed->n; i++) {
        if (ncs_has(found, listed->p[i]))
            continue;
        fprintf(err, "check-no-new-coordination-shell: STALE list entry %s is "
                     "no longer a tracked coordination-path file; remove it "
                     "from the list (the list only shrinks)\n",
                listed->p[i]);
        bad = 1;
    }
    return bad;
}

static int ncs_run_cfg(const char *base, const char *list_path, int use_git,
                       FILE *out, FILE *err)
{
    static struct ncs_set found, listed;
    int rc = ncs_load_list(&listed, list_path, err);
    if (rc)
        return rc;
    rc = ncs_collect(&found, base, use_git);
    if (rc)
        return rc;
    int bad_new = ncs_report_new(err, &listed, &found);
    int bad_stale = ncs_report_stale(err, &listed, &found);
    if (bad_new || bad_stale)
        return 1;
    fprintf(out, "check-no-new-coordination-shell: clean — %d "
                 "coordination-path script(s), all listed in %s\n",
            found.n, list_path);
    return 0;
}

/* ── selftest ─────────────────────────────────────────────────────────── */

/* Plant "<base><rel>" with a trivial shell body. Split out of ncs_st_case()
 * to keep its own complexity low. */
static int ncs_st_plant(const char *base, const char *rel)
{
    char p[4096];
    if (ovf(snprintf(p, sizeof p, "%s%s", base, rel), sizeof p))
        return 1;
    return csr_write(p, "#!/bin/sh\n");
}

/* Lay out <root>/<name>/: the base directory, the list file path, the planted
 * scripts, and the list body. Returns nonzero on any failure. */
static int ncs_st_setup(const char *root, const char *name,
                        const char *const *rels, int nrels,
                        const char *list_body, char *base, size_t bcap,
                        char *list, size_t lcap)
{
    if (ovf(snprintf(base, bcap, "%s/%s/", root, name), bcap)
        || ovf(snprintf(list, lcap, "%s/%s/list.txt", root, name), lcap)
        || csr_write(list, list_body))
        return 1;
    for (int i = 0; i < nrels; i++)
        if (ncs_st_plant(base, rels[i]))
            return 1;
    return 0;
}

/* Run the gate in walk mode and capture its stdout, stderr and return code.
 * Split out of ncs_st_case() to keep its own complexity low. */
static int ncs_st_capture(const char *base, const char *list, char *obuf,
                          size_t ocap, char *ebuf, size_t ecap, int *rc)
{
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out) fclose(out);
        if (err) fclose(err);
        return 1;
    }
    *rc = ncs_run_cfg(base, list, 0, out, err);
    int bad = csr_slurp(out, obuf, ocap) || csr_slurp(err, ebuf, ecap);
    fclose(out);
    fclose(err);
    return bad;
}

static int ncs_st_match(const char *obuf, const char *ebuf,
                        const char *needle)
{
    return !needle || strstr(obuf, needle) != NULL
           || strstr(ebuf, needle) != NULL;
}

/* Run the gate in walk mode against base and list, and check its return code
 * and a needle in its output. Shared by every case builder. */
static int ncs_st_run(const char *name, const char *base, const char *list,
                      int want_rc, const char *needle)
{
    char obuf[4096], ebuf[4096];
    int rc = 0;
    if (ncs_st_capture(base, list, obuf, sizeof obuf, ebuf, sizeof ebuf, &rc))
        return 1;
    int ok = rc == want_rc && ncs_st_match(obuf, ebuf, needle);
    if (!ok)
        fprintf(stderr, "check_no_new_coordination_shell selftest: %s: want "
                        "rc %d needle '%s'; got rc %d, stdout:\n%s\nstderr:\n%s\n",
                name, want_rc, needle ? needle : "(none)", rc, obuf, ebuf);
    return ok ? 0 : 1;
}

/* Build <root>/<name>/ with the given scripts and list body, then run the gate
 * against it. Every path it creates lives under <root>, which the caller
 * removes once for every case. */
static int ncs_st_case(const char *root, const char *name,
                       const char *const *rels, int nrels,
                       const char *list_body, int want_rc, const char *needle)
{
    char base[4096], list[4096];
    if (ncs_st_setup(root, name, rels, nrels, list_body, base, sizeof base,
                     list, sizeof list))
        return 1;
    return ncs_st_run(name, base, list, want_rc, needle);
}

/* R2 provocations, with no new seam. The list file is removed: a missing list
 * reads every script as NEW (rc 1, "is missing"). Or it is replaced by a
 * directory: fopen succeeds, fgets fails, and the gate reports "cannot read"
 * with rc 2. */
static int ncs_st_list_gone(const char *root, const char *name, int as_dir,
                            int want_rc, const char *needle)
{
    static const char *const one[] = { "tools/dev/a.sh" };
    char base[4096], list[4096];
    if (ncs_st_setup(root, name, one, 1, "", base, sizeof base, list,
                     sizeof list))
        return 1;
    if (unlink(list) != 0)
        return 1;
    if (as_dir && mkdir(list, 0700) != 0)
        return 1;
    return ncs_st_run(name, base, list, want_rc, needle);
}

static const char *const k_ncs_one[] = { "tools/dev/a.sh" };
static const char *const k_ncs_new[] = { "tools/dev/a.sh", "tools/scripts/new.sh" };
static const char *const k_ncs_two[] = { "tools/dev/a.sh", "tools/dev/b.sh" };
static const char *const k_ncs_sub[] = { "tools/dev/fixtures/x.sh" };

/* Save ZCL_LINT_PRODUCTION_SCAN and clear it for the scan. Under `make` that
 * variable makes lint_path_is_excluded() hide every path under test-tmp/, so
 * the sandbox would read as empty; selftests must see the unfiltered tree
 * (same precedent as gate_no_bare_tmp_fixture.c). */
static int ncs_env_save(char *buf, size_t cap, int *had)
{
    const char *old = getenv("ZCL_LINT_PRODUCTION_SCAN");
    *had = old != NULL;
    if (!old)
        return 0;
    return ovf(snprintf(buf, cap, "%s", old), cap);
}

static void ncs_env_restore(const char *buf, int had)
{
    if (had)
        (void)setenv("ZCL_LINT_PRODUCTION_SCAN", buf, 1);
    else
        (void)unsetenv("ZCL_LINT_PRODUCTION_SCAN");
}

static int ncs_st_cases(const char *root)
{
    int bad = 0;
    bad |= ncs_st_case(root, "clean", k_ncs_one, 1,
                       "# header\ntools/dev/a.sh\n", 0, "clean");
    bad |= ncs_st_case(root, "new", k_ncs_new, 2, "tools/dev/a.sh\n", 1,
                       "tools/scripts/new.sh");
    bad |= ncs_st_case(root, "stale", k_ncs_one, 1,
                       "tools/dev/a.sh\ntools/dev/gone.sh\n", 1,
                       "tools/dev/gone.sh");
    bad |= ncs_st_case(root, "unsorted", k_ncs_two, 2,
                       "tools/dev/b.sh\ntools/dev/a.sh\n", 1, "unsorted");
    bad |= ncs_st_case(root, "subdir", k_ncs_sub, 1, "", 0, "clean");
    bad |= ncs_st_case(root, "absolute", k_ncs_one, 1, "/tools/dev/a.sh\n", 1,
                       "MALFORMED list entry /tools/dev/a.sh");
    bad |= ncs_st_case(root, "dotdot", k_ncs_one, 1, "tools/dev/../x.sh\n", 1,
                       "MALFORMED list entry tools/dev/../x.sh");
    bad |= ncs_st_case(root, "subentry", k_ncs_one, 1, "tools/dev/x/y.sh\n", 1,
                       "MALFORMED list entry tools/dev/x/y.sh");
    bad |= ncs_st_case(root, "outside", k_ncs_one, 1, "tools/other.sh\n", 1,
                       "MALFORMED list entry tools/other.sh");
    bad |= ncs_st_case(root, "trailws", k_ncs_one, 1, "tools/dev/a.sh \n", 1,
                       "leading, trailing or CR whitespace");
    bad |= ncs_st_list_gone(root, "missing", 0, 1, "is missing");
    bad |= ncs_st_list_gone(root, "readerr", 1, 2, "cannot read");
    return bad;
}

int check_no_new_coordination_shell_selftest(void)
{
    char old_prod[64];
    int had_prod = 0;
    if (ncs_env_save(old_prod, sizeof old_prod, &had_prod))
        return 2;
    (void)unsetenv("ZCL_LINT_PRODUCTION_SCAN");
    const char *td = env_or("TMPDIR", "test-tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-ncs-XXXXXX", td),
            sizeof tmpl)) {
        ncs_env_restore(old_prod, had_prod);
        return 2;
    }
    int made_td = mkdir(td, 0700) == 0;
    char *root = mkdtemp(tmpl);
    if (!root) {
        ncs_env_restore(old_prod, had_prod);
        if (made_td)
            (void)rmdir(td);
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    }
    int bad = ncs_st_cases(root);
    if (rap_rm_rf(root) != 0) {
        fprintf(stderr, "check_no_new_coordination_shell selftest: cannot "
                        "remove sandbox %s\n", root);
        bad = 1;
    }
    /* Remove the TMPDIR-or-test-tmp root only if this selftest created it;
     * rmdir refuses a non-empty directory, which is not ours to remove. */
    if (made_td && rmdir(td) != 0 && errno != ENOTEMPTY) {
        fprintf(stderr, "check_no_new_coordination_shell selftest: cannot "
                        "remove %s\n", td);
        bad = 1;
    }
    ncs_env_restore(old_prod, had_prod);
    return st_ok(bad, "check_no_new_coordination_shell selftest: OK\n");
}

/* ── run ──────────────────────────────────────────────────────────────── */

int check_no_new_coordination_shell_run(int argc, char **argv)
{
    (void)argv;
    if (argc >= 1) {
        fprintf(stderr, "check-no-new-coordination-shell: takes no arguments; "
                        "there is no write-baseline mode. Edit %s by hand (it "
                        "can only lose lines).\n", k_ncs_base);
        return 2;
    }
    return ncs_run_cfg("", k_ncs_base, 1, stdout, stderr);
}
