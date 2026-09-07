/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — progress-honesty fences of the C23 lint runtime
 * (check-no-silent-ready, check-stage-advances-or-blocks). HARD fences for
 * FRAMEWORK.md's Prime Directive: advance the tip OR name a typed stall;
 * never report READY or spin forward while behind. Placement ruling
 * (2026-09-06): new ports land in their own files. This pair shares one
 * subject. Consumer 1 repairs `mapfile -t files < <(grep -rlE ... || true)`:
 * a scan-time open/read failure is UNPROVEN exit 2 naming the file.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { PH_MAX = 256, PH_PATH = 512, PH_MSG = 640, PH_CAP = 4096 };

static FILE *ph_out, *ph_err;
static const char *ph_ready_root_ov, *ph_ready_auth_ov, *ph_jobs_dir_ov;
static int ph_jobs_step_floor_ov = -1;

static void ph_io_prod(void) { ph_out = stdout; ph_err = stderr; }
static void ph_clear_ov(void)
{
    ph_ready_root_ov = NULL; ph_ready_auth_ov = NULL; ph_jobs_dir_ov = NULL;
    ph_jobs_step_floor_ov = -1; ph_io_prod();
}
static const char *ph_ready_root(void)
{ return ph_ready_root_ov ? ph_ready_root_ov : "engine/services/src"; }
static const char *ph_ready_auth(void)
{
    return ph_ready_auth_ov ? ph_ready_auth_ov
        : "engine/services/src/chain_activation_service.c";
}
static const char *ph_jobs_dir(void)
{
    if (ph_jobs_dir_ov && ph_jobs_dir_ov[0]) return ph_jobs_dir_ov;
    return env_or("ZCL_JOBS_DIR", "engine/jobs/src");
}
static int ph_jobs_step_floor(void)
{
    if (ph_jobs_step_floor_ov >= 0) return ph_jobs_step_floor_ov;
    const char *e = getenv("ZCL_JOBS_DIR");
    return (e && e[0]) ? 0 : 8;
}
static int ph_puts(FILE *f, const char *s)
{ return fputs(s, f) < 0 ? die("z23-lint: write failed\n", "") : 0; }
static int ph_cannot_open(const char *path)
{
    fprintf(ph_err ? ph_err : stderr, "z23-lint: cannot open %s\n", path);
    return 2;
}
static int ph_isdir(const char *path)
{ struct stat st; return stat(path, &st) == 0 && S_ISDIR(st.st_mode); }
static int ph_hit(const regex_t *re, const char *s)
{ return regexec(re, s, 0, NULL, 0) == 0; }
static int ph_has(const char *buf, const char *need)
{ return buf && need && strstr(buf, need) != NULL; }

static char *ph_mkdtemp(char *tmpl, size_t cap)
{
    const char *td = env_or("TMPDIR", "/tmp");
    if (ovf(snprintf(tmpl, cap, "%s/z23-lint-ph.XXXXXX", td), cap)) return NULL;
    char *tmp = mkdtemp(tmpl);
    return tmp ? tmp : (die("z23-lint: mkdir failed: %s\n", td), NULL);
}

static int ph_cap(int (*eval)(void), char *ob, size_t oc, char *eb, size_t ec,
                  int *rc)
{
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out) fclose(out);
        if (err) fclose(err);
        return die("z23-lint: tmpfile failed\n", "");
    }
    ph_out = out; ph_err = err; *rc = eval();
    int bad = csr_slurp(out, ob, oc) || csr_slurp(err, eb, ec);
    fclose(out); fclose(err); ph_io_prod();
    return bad ? 2 : 0;
}

/* ── check-no-silent-ready ─────────────────────────────────────────── */

struct ph_rf { char path[PH_PATH]; int unguarded, blocker; };
struct ph_ready {
    regex_t ready, ov, block;
    struct ph_rf file[PH_MAX];
    int n;
};
static int ph_cmp_rf(const void *a, const void *b)
{
    return strcmp(((const struct ph_rf *)a)->path,
                  ((const struct ph_rf *)b)->path);
}

static int ph_ready_comp(struct ph_ready *a)
{
    int rc = compile_pat(&a->ready, REG_EXTENDED,
        "activation_set_state[[:space:]]*\\([^;]*ACTIVATION_READY", "", "", "");
    if (rc) return rc;
    rc = compile_pat(&a->ov, REG_EXTENDED,
        "//[[:space:]]*no-silent-ready-ok:[A-Za-z][A-Za-z0-9_-]*", "", "", "");
    if (rc) { regfree(&a->ready); return rc; }
    rc = compile_pat(&a->block, REG_EXTENDED,
        "blocker_set[[:space:]]*\\(|_set_behind_blocker[[:space:]]*\\(",
        "", "", "");
    if (rc) drop2(&a->ready, &a->ov);
    return rc;
}

static int ph_ready_read(const char *path, const struct ph_ready *a,
                         int *any, int *unguarded, int *blocker)
{
    FILE *f = fopen(path, "r");
    if (!f) return ph_cannot_open(path);
    char *line = NULL; size_t cap = 0;
    while (getline(&line, &cap, f) >= 0) {
        if (ph_hit(&a->ready, line)) {
            (*any)++;
            if (!ph_hit(&a->ov, line)) (*unguarded)++;
        }
        if (ph_hit(&a->block, line)) *blocker = 1;
    }
    return fin(f, line, path, 0);
}

static int ph_ready_on_file(const char *path, void *ctx)
{
    struct ph_ready *a = ctx;
    if (lint_path_is_excluded(path)) return 0;
    if (a->n >= PH_MAX) return die("z23-lint: derived buffer overflow\n", "");
    int any = 0, unguarded = 0, blocker = 0;
    int rc = ph_ready_read(path, a, &any, &unguarded, &blocker);
    if (rc || !any) return rc;
    if (ovf(snprintf(a->file[a->n].path, sizeof a->file[0].path, "%s", path),
            sizeof a->file[0].path))
        return 2;
    a->file[a->n].unguarded = unguarded;
    a->file[a->n].blocker = blocker;
    a->n++;
    return 0;
}

static int ph_ready_preflight(const struct ph_ready *a)
{
    if (a->n == 0) {
        int rc = ph_puts(ph_err,
            "check_no_silent_ready: BROKEN — found 0 ACTIVATION_READY authorities.\n"
            "  The setter (activation_set_state) or enum (ACTIVATION_READY) was likely\n"
            "  renamed; update the producer grep in this gate. Refusing to report clean.\n");
        return rc ? rc : 2;
    }
    int found = 0;
    for (int i = 0; i < a->n; i++)
        if (strcmp(a->file[i].path, ph_ready_auth()) == 0) found = 1;
    if (found) return 0;
    fprintf(ph_err,
            "check_no_silent_ready: BROKEN — the known authority (%s)\n"
            "  is not in the discovered set; the authority moved or the setter/enum was\n"
            "  renamed. Update EXPECTED_AUTHORITY/producer in this gate deliberately.\n",
            ph_ready_auth());
    return 2;
}

static int ph_ready_note(char viol[][PH_MSG], int *nviol, const char *path)
{
    if (*nviol >= PH_MAX) return die("z23-lint: derived buffer overflow\n", "");
    if (ovf(snprintf(viol[*nviol], PH_MSG,
            "%s: transitions to ACTIVATION_READY but never names a typed blocker "
            "(blocker_set / *_set_behind_blocker) — the silent-ready hole: it can "
            "report 'ready' while behind the most-work header chain with no "
            "actionable reason and no operator sink", path), PH_MSG))
        return 2;
    (*nviol)++;
    return 0;
}

static int ph_ready_report(const struct ph_ready *a)
{
    char viol[PH_MAX][PH_MSG];
    int nviol = 0;
    for (int i = 0; i < a->n; i++) {
        if (a->file[i].unguarded == 0 || a->file[i].blocker) continue;
        int rc = ph_ready_note(viol, &nviol, a->file[i].path);
        if (rc) return rc;
    }
    if (nviol == 0)
        return ph_puts(ph_out,
            "check_no_silent_ready: clean — every ACTIVATION_READY authority names a typed blocker on non-progress\n");
    if (fprintf(ph_out, "\ncheck_no_silent_ready: %d silent-ready violation(s)\n\n",
                nviol) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < nviol; i++)
        if (fprintf(ph_out, "  %s\n", viol[i]) < 0)
            return die("z23-lint: write failed\n", "");
    return ph_puts(ph_out,
        "\nThe block-connection authority must advance-the-tip OR name-a-typed-blocker\n"
        "every tick (FRAMEWORK.md Prime Directive). Going ACTIVATION_READY is only\n"
        "honest when local_tip == most-work valid-header tip. On the behind path,\n"
        "register a typed blocker (blocker_set / activation_set_behind_blocker) that\n"
        "names WHY, the height, and the escape action, then transition to READY.\n")
        ? 2 : 1;
}

static int ph_ready_eval(void)
{
    struct ph_ready a;
    memset(&a, 0, sizeof a);
    int rc = ph_ready_comp(&a);
    if (rc) return rc;
    rc = walk_src(ph_ready_root(), 0, ph_ready_on_file, &a);
    if (rc == 0) {
        qsort(a.file, (size_t)a.n, sizeof a.file[0], ph_cmp_rf);
        rc = ph_ready_preflight(&a);
        if (rc == 0) rc = ph_ready_report(&a);
    }
    drop3(&a.ready, &a.ov, &a.block);
    return rc;
}

int check_no_silent_ready_run(int argc, char **argv)
{ (void)argc; (void)argv; ph_clear_ov(); return ph_ready_eval(); }

static int ph_ready_st_run(const char *tmp, const char *sub, const char *body,
                           const char *auth_sub, int want_rc,
                           const char *want_out, const char *want_err)
{
    char path[PH_CAP], root[PH_CAP], auth[PH_CAP], out[PH_CAP], err[PH_CAP];
    if (ovf(snprintf(path, sizeof path,
                     "%s/%s/engine/services/src/chain_activation_service.c",
                     tmp, sub), sizeof path))
        return 1;
    if (body && csr_write(path, body)) return 1;
    if (ovf(snprintf(root, sizeof root, "%s/%s/engine/services/src", tmp, sub),
            sizeof root))
        return 1;
    if (ovf(snprintf(auth, sizeof auth, "%s/%s/%s", tmp, sub,
                     auth_sub ? auth_sub
                     : "engine/services/src/chain_activation_service.c"),
            sizeof auth))
        return 1;
    ph_ready_root_ov = root; ph_ready_auth_ov = auth;
    int rc = 0;
    int bad = ph_cap(ph_ready_eval, out, sizeof out, err, sizeof err, &rc);
    ph_clear_ov();
    if (bad || rc != want_rc) return 1;
    if (want_out && !ph_has(out, want_out)) return 1;
    if (want_err && !ph_has(err, want_err)) return 1;
    return 0;
}

static int ph_ready_st_clean(const char *tmp)
{
    return ph_ready_st_run(tmp, "clean",
        "void f(void){ activation_set_state(s, ACTIVATION_READY, r); blocker_set(b); }\n",
        NULL, 0,
        "check_no_silent_ready: clean — every ACTIVATION_READY authority names a typed blocker on non-progress",
        NULL);
}
static int ph_ready_st_empty(const char *tmp)
{
    char dir[PH_CAP], out[PH_CAP], err[PH_CAP];
    int rc = 0;
    if (ovf(snprintf(dir, sizeof dir, "%s/empty/engine/services/src", tmp),
            sizeof dir) || csr_mkdirs(dir))
        return 1;
    ph_ready_root_ov = dir;
    ph_ready_auth_ov = "engine/services/src/chain_activation_service.c";
    int bad = ph_cap(ph_ready_eval, out, sizeof out, err, sizeof err, &rc);
    ph_clear_ov();
    return bad || rc != 2
        || !ph_has(err, "check_no_silent_ready: BROKEN — found 0 ACTIVATION_READY authorities.");
}
static int ph_ready_st_wrong_auth(const char *tmp)
{
    char path[PH_CAP], root[PH_CAP], out[PH_CAP], err[PH_CAP];
    int rc = 0;
    if (ovf(snprintf(path, sizeof path, "%s/wrong/other.c", tmp), sizeof path)
        || csr_write(path,
            "void f(void){ activation_set_state(s, ACTIVATION_READY, r); blocker_set(b); }\n")
        || ovf(snprintf(root, sizeof root, "%s/wrong", tmp), sizeof root))
        return 1;
    ph_ready_root_ov = root;
    ph_ready_auth_ov = "engine/services/src/chain_activation_service.c";
    int bad = ph_cap(ph_ready_eval, out, sizeof out, err, sizeof err, &rc);
    ph_clear_ov();
    return bad || rc != 2
        || !ph_has(err, "check_no_silent_ready: BROKEN — the known authority (engine/services/src/chain_activation_service.c)");
}
static int ph_ready_st_violation(const char *tmp)
{
    return ph_ready_st_run(tmp, "viol",
        "void f(void){ activation_set_state(s, ACTIVATION_READY, r); }\n",
        NULL, 1, "transitions to ACTIVATION_READY but never names a typed blocker",
        NULL);
}
static int ph_ready_st_override(const char *tmp)
{
    return ph_ready_st_run(tmp, "ov",
        "void f(void){ activation_set_state(s, ACTIVATION_READY, r); // no-silent-ready-ok:caught_up\n}\n",
        NULL, 0,
        "check_no_silent_ready: clean — every ACTIVATION_READY authority names a typed blocker on non-progress",
        NULL);
}
static int ph_ready_st_unreadable(const char *tmp)
{
    char auth[PH_CAP], badf[PH_CAP], root[PH_CAP], out[PH_CAP], err[PH_CAP];
    int rc = 0, locked = 0;
    badf[0] = '\0';
    if (ovf(snprintf(auth, sizeof auth,
                     "%s/ur/engine/services/src/chain_activation_service.c", tmp),
            sizeof auth))
        return 1;
    if (csr_write(auth,
            "void f(void){ activation_set_state(s, ACTIVATION_READY, r); blocker_set(b); }\n"))
        return 1;
    if (ovf(snprintf(badf, sizeof badf,
                     "%s/ur/engine/services/src/unreadable.c", tmp),
            sizeof badf) || csr_write(badf, "int x;\n"))
        return 1;
    if (chmod(badf, 0) != 0) return 1;
    locked = 1;
    if (ovf(snprintf(root, sizeof root, "%s/ur/engine/services/src", tmp),
            sizeof root)) {
        (void)chmod(badf, 0600);
        return 1;
    }
    ph_ready_root_ov = root; ph_ready_auth_ov = auth;
    int bad = ph_cap(ph_ready_eval, out, sizeof out, err, sizeof err, &rc);
    ph_clear_ov();
    if (locked) (void)chmod(badf, 0600);
    return bad || rc != 2 || !ph_has(err, badf);
}

int check_no_silent_ready_selftest(void)
{
    char tmpl[PH_CAP];
    char *tmp = ph_mkdtemp(tmpl, sizeof tmpl);
    if (!tmp) return 2;
    int bad = ph_ready_st_clean(tmp) | ph_ready_st_empty(tmp)
        | ph_ready_st_wrong_auth(tmp) | ph_ready_st_violation(tmp)
        | ph_ready_st_override(tmp) | ph_ready_st_unreadable(tmp);
    ph_clear_ov();
    (void)rap_rm_rf(tmp);
    return st_ok(bad, "check_no_silent_ready selftest: OK\n");
}

/* ── check-stage-advances-or-blocks ────────────────────────────────── */

struct ph_jobs {
    regex_t step, ov, blk, cur;
    char viol[PH_MAX][PH_MSG];
    int nviol, nscan, checked;
};
static void ph_drop4(regex_t *a, regex_t *b, regex_t *c, regex_t *d)
{ regfree(a); regfree(b); regfree(c); regfree(d); }

static int ph_jobs_comp(struct ph_jobs *a)
{
    int rc = compile_pat(&a->step, REG_EXTENDED,
        "stage_create[[:space:]]*\\(|job_result_t[[:space:]]+[a-z0-9_]+_step",
        "", "", "");
    if (rc) return rc;
    rc = compile_pat(&a->ov, REG_EXTENDED,
        "//[[:space:]]*stage-advance-ok:[A-Za-z][A-Za-z0-9_-]*", "", "", "");
    if (rc) { regfree(&a->step); return rc; }
    rc = compile_pat(&a->blk, REG_EXTENDED, "JOB_BLOCKED|JOB_IDLE", "", "", "");
    if (rc) { drop2(&a->step, &a->ov); return rc; }
    rc = compile_pat(&a->cur, REG_EXTENDED,
        "cursor_out|c->cursor_in|stage_cursor", "", "", "");
    if (rc) drop3(&a->step, &a->ov, &a->blk);
    return rc;
}

static int ph_jobs_read(const char *path, const struct ph_jobs *a,
                        int *step, int *ov, int *blk, int *cur)
{
    FILE *f = fopen(path, "r");
    if (!f) return ph_cannot_open(path);
    char *line = NULL; size_t cap = 0;
    while (getline(&line, &cap, f) >= 0) {
        if (ph_hit(&a->step, line)) *step = 1;
        if (ph_hit(&a->ov, line)) *ov = 1;
        if (ph_hit(&a->blk, line)) *blk = 1;
        if (ph_hit(&a->cur, line)) *cur = 1;
    }
    return fin(f, line, path, 0);
}

static int ph_jobs_note(struct ph_jobs *a, const char *fmt, const char *path)
{
    if (a->nviol >= PH_MAX) return die("z23-lint: derived buffer overflow\n", "");
    if (ovf(snprintf(a->viol[a->nviol], PH_MSG, fmt, path), PH_MSG)) return 2;
    a->nviol++;
    return 0;
}

static int ph_jobs_on_file(const char *path, void *ctx)
{
    struct ph_jobs *a = ctx;
    if (lint_path_is_excluded(path)) return 0;
    a->nscan++;
    int step = 0, ov = 0, blk = 0, cur = 0;
    int rc = ph_jobs_read(path, a, &step, &ov, &blk, &cur);
    if (rc || !step || ov) return rc;
    a->checked++;
    if (!blk) {
        rc = ph_jobs_note(a,
            "%s: Job step never returns JOB_BLOCKED/JOB_IDLE — it can only advance, so it has no way to surface a stall",
            path);
        if (rc) return rc;
    }
    if (!cur)
        rc = ph_jobs_note(a,
            "%s: Job step references no cursor (cursor_out / c->cursor_in / stage_cursor) — it does not reason about its log position",
            path);
    return rc;
}

static int ph_jobs_missing(const char *dir)
{
    fprintf(ph_err, "check_stage_advances_or_blocks: FATAL — %s not found.\n"
                    "  The Job step dir was renamed/moved. Refusing to pass hollow.\n",
            dir);
    return 2;
}

static int ph_jobs_floors(struct ph_jobs *a, const char *dir)
{
    char hint[PH_CAP];
    if (ovf(snprintf(hint, sizeof hint, "no *.c under '%s'", dir), sizeof hint))
        return 2;
    int rc = gate_require_scanned(a->nscan, 1, "check_stage_advances_or_blocks",
                                  hint);
    if (rc) return rc;
    if (ovf(snprintf(hint, sizeof hint,
                     "matched 0/%d Job step files under '%s' — was stage_create(/_step renamed?",
                     a->checked, dir), sizeof hint))
        return 2;
    return gate_require_scanned(a->checked, ph_jobs_step_floor(),
                                "check_stage_advances_or_blocks", hint);
}

static int ph_jobs_report(const struct ph_jobs *a)
{
    if (a->nviol == 0) {
        if (fprintf(ph_out,
                    "check_stage_advances_or_blocks: clean — all %d Job step file(s) advance-or-block with a cursor reference\n",
                    a->checked) < 0)
            return die("z23-lint: write failed\n", "");
        return 0;
    }
    if (fprintf(ph_out,
                "\ncheck_stage_advances_or_blocks: %d Job-contract violation(s)\n\n",
                a->nviol) < 0)
        return die("z23-lint: write failed\n", "");
    for (int i = 0; i < a->nviol; i++)
        if (fprintf(ph_out, "  %s\n", a->viol[i]) < 0)
            return die("z23-lint: write failed\n", "");
    return ph_puts(ph_out,
        "\nA Job step (engine/jobs/src/*_stage.c) must be honest about non-progress:\n"
        "  1. Return JOB_BLOCKED or JOB_IDLE on any non-advancing path (never\n"
        "     spin forward silently).\n"
        "  2. Reference a cursor (cursor_out / c->cursor_in / stage_cursor) so\n"
        "     the stall is anchored to a log position.\n"
        "  3. For a Job that genuinely cannot block, add a file-level\n"
        "     '// stage-advance-ok:<tag>' marker (no exemptions exist today).\n")
        ? 2 : 1;
}

static int ph_jobs_eval(void)
{
    const char *dir = ph_jobs_dir();
    if (!ph_isdir(dir)) return ph_jobs_missing(dir);
    struct ph_jobs a;
    memset(&a, 0, sizeof a);
    int rc = ph_jobs_comp(&a);
    if (rc) return rc;
    rc = walk_src(dir, 0, ph_jobs_on_file, &a);
    if (rc == 0) rc = ph_jobs_floors(&a, dir);
    if (rc == 0) rc = ph_jobs_report(&a);
    ph_drop4(&a.step, &a.ov, &a.blk, &a.cur);
    return rc;
}

int check_stage_advances_or_blocks_run(int argc, char **argv)
{ (void)argc; (void)argv; ph_clear_ov(); return ph_jobs_eval(); }

static int ph_jobs_st_prep(const char *tmp, const char *sub, const char *name,
                           const char *body, char *dir, size_t dcap)
{
    char path[PH_CAP];
    if (ovf(snprintf(dir, dcap, "%s/%s", tmp, sub), dcap)) return 1;
    if (ovf(snprintf(path, sizeof path, "%s/%s", dir, name), sizeof path))
        return 1;
    return csr_write(path, body) ? 1 : 0;
}

static int ph_jobs_st_run(const char *dir, int floor, int want_rc,
                          const char *want_out)
{
    char out[PH_CAP], err[PH_CAP];
    int rc = 0;
    ph_jobs_dir_ov = dir; ph_jobs_step_floor_ov = floor;
    int bad = ph_cap(ph_jobs_eval, out, sizeof out, err, sizeof err, &rc);
    ph_clear_ov();
    if (bad || rc != want_rc) return 1;
    return (want_out && !ph_has(out, want_out)) ? 1 : 0;
}

static const char k_job_ok[] =
    "void stage_create(int x);\n"
    "job_result_t foo_step(void){ return JOB_BLOCKED; }\n"
    "void g(void){ (void)cursor_out; }\n";

static int ph_jobs_st_clean(const char *tmp)
{
    char dir[PH_CAP];
    if (ph_jobs_st_prep(tmp, "jclean", "s.c", k_job_ok, dir, sizeof dir))
        return 1;
    return ph_jobs_st_run(dir, 0, 0,
        "check_stage_advances_or_blocks: clean — all 1 Job step file(s) advance-or-block with a cursor reference");
}
static int ph_jobs_st_no_block(const char *tmp)
{
    char dir[PH_CAP];
    if (ph_jobs_st_prep(tmp, "jnb", "s.c",
            "job_result_t foo_step(void){ return JOB_ADVANCED; }\n"
            "void g(void){ (void)cursor_out; }\n", dir, sizeof dir))
        return 1;
    return ph_jobs_st_run(dir, 0, 1,
        "Job step never returns JOB_BLOCKED/JOB_IDLE — it can only advance, so it has no way to surface a stall");
}
static int ph_jobs_st_no_cursor(const char *tmp)
{
    char dir[PH_CAP];
    if (ph_jobs_st_prep(tmp, "jnc", "s.c",
            "job_result_t foo_step(void){ return JOB_BLOCKED; }\n",
            dir, sizeof dir))
        return 1;
    return ph_jobs_st_run(dir, 0, 1,
        "Job step references no cursor (cursor_out / c->cursor_in / stage_cursor) — it does not reason about its log position");
}
static int ph_jobs_st_both(const char *tmp)
{
    char dir[PH_CAP], out[PH_CAP], err[PH_CAP];
    int rc = 0;
    if (ph_jobs_st_prep(tmp, "jboth", "s.c",
            "job_result_t foo_step(void){ return JOB_ADVANCED; }\n",
            dir, sizeof dir))
        return 1;
    ph_jobs_dir_ov = dir; ph_jobs_step_floor_ov = 0;
    int bad = ph_cap(ph_jobs_eval, out, sizeof out, err, sizeof err, &rc);
    ph_clear_ov();
    return bad || rc != 1
        || !ph_has(out, "Job step never returns JOB_BLOCKED/JOB_IDLE")
        || !ph_has(out, "Job step references no cursor");
}
static int ph_jobs_st_override(const char *tmp)
{
    char dir[PH_CAP];
    if (ph_jobs_st_prep(tmp, "jov", "s.c",
            "// stage-advance-ok:cannot_block\n"
            "job_result_t foo_step(void){ return JOB_ADVANCED; }\n",
            dir, sizeof dir))
        return 1;
    return ph_jobs_st_run(dir, 0, 0,
        "check_stage_advances_or_blocks: clean — all 0 Job step file(s) advance-or-block with a cursor reference");
}
static int ph_jobs_st_nonstep(const char *tmp)
{
    char dir[PH_CAP], extra[PH_CAP];
    if (ph_jobs_st_prep(tmp, "jns", "s.c", k_job_ok, dir, sizeof dir)) return 1;
    if (ovf(snprintf(extra, sizeof extra, "%s/helper.c", dir), sizeof extra)
        || csr_write(extra, "int helper(void){ return JOB_ADVANCED; }\n"))
        return 1;
    return ph_jobs_st_run(dir, 0, 0,
        "check_stage_advances_or_blocks: clean — all 1 Job step file(s) advance-or-block with a cursor reference");
}
static int ph_jobs_st_empty(const char *tmp)
{
    char dir[PH_CAP], out[PH_CAP], err[PH_CAP];
    int rc = 0;
    if (ovf(snprintf(dir, sizeof dir, "%s/jempty", tmp), sizeof dir)
        || csr_mkdirs(dir))
        return 1;
    ph_jobs_dir_ov = dir; ph_jobs_step_floor_ov = 0;
    int bad = ph_cap(ph_jobs_eval, out, sizeof out, err, sizeof err, &rc);
    ph_clear_ov();
    return bad || rc != 2;
}
static int ph_jobs_st_floor8(const char *tmp)
{
    char dir[PH_CAP], out[PH_CAP], err[PH_CAP];
    int rc = 0;
    if (ph_jobs_st_prep(tmp, "jf8", "helper.c", "int helper(void){ return 0; }\n",
                        dir, sizeof dir))
        return 1;
    ph_jobs_dir_ov = dir; ph_jobs_step_floor_ov = 8;
    int bad = ph_cap(ph_jobs_eval, out, sizeof out, err, sizeof err, &rc);
    ph_clear_ov();
    return bad || rc != 2;
}

int check_stage_advances_or_blocks_selftest(void)
{
    char tmpl[PH_CAP];
    char *tmp = ph_mkdtemp(tmpl, sizeof tmpl);
    if (!tmp) return 2;
    int bad = ph_jobs_st_clean(tmp) | ph_jobs_st_no_block(tmp)
        | ph_jobs_st_no_cursor(tmp) | ph_jobs_st_both(tmp)
        | ph_jobs_st_override(tmp) | ph_jobs_st_nonstep(tmp)
        | ph_jobs_st_empty(tmp) | ph_jobs_st_floor8(tmp);
    ph_clear_ov();
    (void)rap_rm_rf(tmp);
    return st_ok(bad, "check_stage_advances_or_blocks selftest: OK\n");
}
