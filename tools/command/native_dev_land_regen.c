/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.land regen phase mechanics — run the three generated-doc
 *          targets in the landing worktree after a successful rebase and
 *          commit whatever they actually changed, so a submission never
 *          fails at push time for staleness a train assembler would
 *          otherwise fix by hand. Called from one site in
 *          tools/command/native_dev_land.c's dl_step_start().
 *
 * WHY THREE FIXED TARGETS, NOT A DISCOVERED SET. Exactly one make target
 * regenerates the fleet routing table across two scripts
 * (`docs-executor-routing`), one regenerates the capability census
 * (`docs-capability-inventory`), and one repairs the doc-counts block of
 * docs/CODEBASE_MAP.md (`fix-doc-counts`, the existing repair half of
 * `check-doc-counts` — see Makefile). Each writes to exactly one tracked
 * path. The table below is CLOSED and mirrors DL_REGEN_ARTIFACTS in
 * native_dev_land.c, which exists for the same reason: nothing here is
 * discovered from a diff or a directory scan, so nothing outside these
 * three paths can ever be added to a regen commit by surprise.
 *
 * WHY UNCONDITIONAL, NOT ONLY ON CONFLICT. native_dev_land.c's own
 * DL_REGEN_* machinery only regenerates these kinds of artifacts when a
 * REBASE CONFLICTS on them. A tip that rebases cleanly (the common case)
 * never touches them, and still leaves the tree exactly as stale as the
 * submitter's own checkout was — the missing case that used to cost every
 * train a hand-made "Regenerate generated docs after ..." commit. This
 * phase runs after EVERY successful rebase, conflicted or not, so a
 * submission is never the reason for that follow-up commit again.
 *
 * PROCESS RULE. Same as native_dev_land.c: `git` and `make` are the only
 * programs this file runs, always through util/spawn.h's
 * zcl_spawn_capture()/zcl_spawn_capture_merged_observed() — no popen(), no
 * system(), no shell command string.
 *
 * TEST SEAM. There is deliberately no test-only environment variable here.
 * A landing worktree is always a real checkout of this repository (it is
 * made by `git worktree add` from it), so it always has a real Makefile at
 * its root; a hermetic test rig built for a different purpose (a bare
 * "origin" plus a throwaway clone, as tests/harness/src/test_dev_land.c
 * uses for every case that does not need this phase) has none. This file
 * treats a missing Makefile as "nothing to regenerate here" rather than a
 * failure, which is both the correct behavior for an unusual worktree and,
 * for free, the isolation a fixture needs: test_dev_land.c's regen cases
 * write a small real Makefile with real (trivial) recipes into their rig
 * and get the real code path, and every other case's rig has no Makefile
 * and never touches make at all.
 */

#include "command/native_dev_land_regen.h"

#include "base/safe_alloc.h"
#include "util/spawn.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* Bounded budgets, sized like native_dev_land.c's own (DL_GIT_CAP,
 * DL_LINT_TIMEOUT_MS): a single git query never needs more than a few
 * hundred bytes, and none of these three targets is a full build. */
#define DLRG_GIT_CAP (256u * 1024u)
#define DLRG_GIT_TIMEOUT_MS (10 * 60 * 1000)
#define DLRG_MAKE_TIMEOUT_MS (10 * 60 * 1000)
#define DLRG_SUBJECT_MAX 60u

struct dlrg_artifact {
    const char *target;
    const char *path;
};

/* Closed table — see the file header WHY. */
static const struct dlrg_artifact DLRG_ARTIFACTS[] = {
    { "docs-capability-inventory", "docs/CAPABILITY_INVENTORY.jsonl" },
    { "docs-executor-routing", "docs/agent/EXECUTOR_HEURISTICS.md" },
    { "fix-doc-counts", "docs/CODEBASE_MAP.md" },
};
#define DLRG_N (sizeof(DLRG_ARTIFACTS) / sizeof(DLRG_ARTIFACTS[0]))

static bool dlrg_sha_ok(const char *s)
{
    size_t n;
    if (!s)
        return false;
    n = strlen(s);
    if (n != 40)
        return false;
    for (size_t i = 0; i < n; i++) {
        if (!isxdigit((unsigned char)s[i]))
            return false;
    }
    return true;
}

/* One git command in `wt`, capturing stdout only — mirrors
 * native_dev_land.c's dl_git(), duplicated rather than exported so this
 * file has no dependency on that file's internals. */
static int dlrg_git(const char *wt, const char *const *args, char *out,
                    size_t cap)
{
    const char *argv[24];
    size_t n = 0;
    if (out && cap)
        out[0] = '\0';
    if (!wt || !args)
        return -1;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = wt;
    for (size_t i = 0; args[i]; i++) {
        if (n + 2 > sizeof(argv) / sizeof(argv[0]))
            return -1;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    {
        char sink[2];
        return zcl_spawn_capture(argv, out ? out : sink,
                                 out ? cap : sizeof(sink),
                                 DLRG_GIT_TIMEOUT_MS);
    }
}

static void dlrg_trim(char *s)
{
    size_t n;
    if (!s)
        return;
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
                     s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = '\0';
}

static bool dlrg_rev_parse(const char *wt, const char *what, char out[80])
{
    char spec[160], buf[256];
    const char *args[] = { "rev-parse", "--verify", "--quiet", spec, NULL };
    if (!wt || !what || !out)
        return false;
    if (snprintf(spec, sizeof(spec), "%s^{commit}", what) >=
        (int)sizeof(spec))
        return false;
    if (dlrg_git(wt, args, buf, sizeof(buf)) != 0)
        return false;
    dlrg_trim(buf);
    if (!dlrg_sha_ok(buf))
        return false;
    (void)snprintf(out, 80, "%s", buf);
    return true;
}

/* Append `s` to `dst` (dst holds *used bytes already, cap total), never
 * overflowing; silently truncates once full, matching every other
 * bounded-log append in this leaf. */
static void dlrg_append(char *dst, size_t cap, size_t *used, const char *s)
{
    size_t n;
    if (!dst || !used || !s || *used >= cap)
        return;
    n = strlen(s);
    if (n > cap - *used - 1)
        n = cap - *used - 1;
    memcpy(dst + *used, s, n);
    *used += n;
    dst[*used] = '\0';
}

/* The first line naming an error or refusal, from merged stdout+stderr —
 * a smaller mirror of native_dev_land.c's dl_first_actionable(). */
static void dlrg_first_actionable(const char *text, char *out, size_t cap)
{
    static const char *const needles[] = {
        "FAIL", "fail", "error:", "Error", "ERROR", "MISMATCH", "refused",
    };
    char *copy, *save = NULL, *line;
    size_t len;
    if (out && cap)
        out[0] = '\0';
    if (!text || !out || cap == 0)
        return;
    len = strlen(text) + 1;
    copy = (char *)zcl_malloc(len, "dev.land.regen.triage");
    if (!copy)
        return;
    memcpy(copy, text, len);
    for (line = strtok_r(copy, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        for (size_t i = 0; i < sizeof(needles) / sizeof(needles[0]); i++) {
            if (strstr(line, needles[i])) {
                (void)snprintf(out, cap, "%s", line);
                free(copy);
                return;
            }
        }
    }
    free(copy);
}

/* Run one make target in `wt`, merged stdout+stderr captured and appended
 * to the caller's transcript. Returns the child's exit status, or -1 on a
 * launch failure. On a nonzero return `why` names the first actionable
 * line (or, failing that, a generic message naming the target). */
static int dlrg_make(const char *wt, const char *target, char *transcript,
                     size_t transcript_cap, size_t *used, char *why,
                     size_t why_cap)
{
    const char *argv[] = { "make", "-s", "-C", wt, target, NULL };
    char *buf;
    int rc;
    bool timed_out = false;
    buf = (char *)zcl_malloc(DLRG_GIT_CAP, "dev.land.regen.make");
    if (!buf) {
        (void)snprintf(why, why_cap,
                       "out of memory running make %s", target);
        return -1;
    }
    rc = zcl_spawn_capture_merged_observed(argv, buf, DLRG_GIT_CAP,
                                           DLRG_MAKE_TIMEOUT_MS, &timed_out);
    dlrg_append(transcript, transcript_cap, used, buf);
    if (rc != 0) {
        dlrg_first_actionable(buf, why, why_cap);
        if (!why[0])
            (void)snprintf(why, why_cap,
                           "make %s failed%s", target,
                           timed_out ? " (timed out)" : "");
    }
    free(buf);
    return rc;
}

/* "<subject>" truncated to DLRG_SUBJECT_MAX bytes, falling back to the
 * short sha when the tip's subject cannot be read at all (an unreadable
 * subject is not a reason to refuse a regen the code otherwise supports). */
static void dlrg_tip_subject(const char *wt, const char *tip_sha, char *out,
                             size_t cap)
{
    char buf[512];
    const char *args[] = { "log", "-1", "--pretty=%s", tip_sha, NULL };
    if (!out || cap == 0)
        return;
    out[0] = '\0';
    if (dlrg_git(wt, args, buf, sizeof(buf)) == 0) {
        dlrg_trim(buf);
        if (buf[0]) {
            (void)snprintf(out, cap, "%.*s", (int)DLRG_SUBJECT_MAX, buf);
            return;
        }
    }
    (void)snprintf(out, cap, "%.12s", tip_sha ? tip_sha : "");
}

/* Commit whatever changed across `changed_paths[0..changed_n)`. `why` is
 * set only on failure. Returns 1 committed, -1 failed. */
static int dlrg_commit(const char *wt, const char *tip_sha,
                       const char *const *changed_paths, size_t changed_n,
                       char *why, size_t why_cap)
{
    const char *add_args[DLRG_N + 3];
    const char *commit_args[5];
    char subject_tip[DLRG_SUBJECT_MAX + 1], subject[160];
    size_t an = 0;
    add_args[an++] = "add";
    add_args[an++] = "--";
    for (size_t i = 0; i < changed_n; i++)
        add_args[an++] = changed_paths[i];
    add_args[an] = NULL;
    dlrg_tip_subject(wt, tip_sha, subject_tip, sizeof(subject_tip));
    if (snprintf(subject, sizeof(subject), "Regenerate generated docs "
                                           "after %s",
                subject_tip) >= (int)sizeof(subject)) {
        (void)snprintf(why, why_cap, "%s",
                      "regen commit subject would not fit");
        return -1;
    }
    commit_args[0] = "commit";
    commit_args[1] = "-q";
    commit_args[2] = "-m";
    commit_args[3] = subject;
    commit_args[4] = NULL;
    /* No -S / --no-gpg-sign, matching native_dev_land.c's own dl_regen_run:
     * this repo's ambient commit.gpgsign config signs a plain `git commit`
     * in the landing worktree, and a signing flag invented here would be a
     * second, divergent way to state the same policy. */
    if (dlrg_git(wt, add_args, NULL, 0) != 0 ||
        dlrg_git(wt, commit_args, NULL, 0) != 0) {
        (void)snprintf(why, why_cap, "%s",
                      "regen commit failed after the doc generators ran");
        return -1;
    }
    return 1;
}

/* No real checkout here — see the file header's TEST SEAM note: a real
 * landing worktree always has one (it is a `git worktree` of this
 * repository), a hermetic test rig built for another purpose does not. */
static bool dlrg_has_makefile(const char *wt)
{
    struct stat st;
    char makefile[4096 + 16];
    return snprintf(makefile, sizeof(makefile), "%s/Makefile", wt) <
              (int)sizeof(makefile) &&
          stat(makefile, &st) == 0 && S_ISREG(st.st_mode);
}

/* Run every regen target in table order, appending each to `transcript`.
 * `used` carries the caller's running transcript offset forward so later
 * appends (the plan-refresh note and its own make output) land after this
 * phase's own output rather than overwriting it. Returns false on the
 * first failure, with `why` already set by dlrg_make(). */
static bool dlrg_run_targets(const char *wt, char *transcript,
                             size_t transcript_cap, size_t *used, char *why,
                             size_t why_cap)
{
    for (size_t i = 0; i < DLRG_N; i++) {
        if (dlrg_make(wt, DLRG_ARTIFACTS[i].target, transcript,
                     transcript_cap, used, why, why_cap) != 0)
            return false;
    }
    return true;
}

/* One artifact path's on-disk identity — the same fields
 * tools/dev/dev_source_identity.c folds into the build plan's
 * BASE_GENERATION mutation token (inode, size, mtime, ctime), scoped here
 * to just the paths this phase can rewrite.
 *
 * Sub-second time fields are not portable: mingw's `struct stat` carries
 * only whole-second `st_mtime`/`st_ctime` (no `st_mtim`/`st_ctim`), and
 * Darwin names the timespec pair `st_mtimespec`/`st_ctimespec`. Mirrors
 * native_dev_land.c's dl_same_copy_metadata()/dl_same_file_snapshot(),
 * which already carries this exact three-way split for the same reason:
 * this file's tools/command home is cross-compiled for Windows by
 * check-windows-cross-syntax, so it must build there even though the
 * regen phase itself only ever runs on a real landing worktree (Linux or
 * Darwin, never Windows). */
struct dlrg_snap {
    bool exists;
    ino_t ino;
    off_t size;
#if defined(_WIN32)
    time_t mtime;
    time_t ctime;
#else
    struct timespec mtim;
    struct timespec ctim;
#endif
};

static void dlrg_snap_capture(const char *wt, const char *rel,
                              struct dlrg_snap *out)
{
    char path[4096 + 16];
    struct stat st;
    memset(out, 0, sizeof(*out));
    if (!wt || !rel ||
        snprintf(path, sizeof(path), "%s/%s", wt, rel) >=
            (int)sizeof(path) ||
        stat(path, &st) != 0)
        return;
    out->exists = true;
    out->ino = st.st_ino;
    out->size = st.st_size;
#if defined(_WIN32)
    out->mtime = st.st_mtime;
    out->ctime = st.st_ctime;
#elif defined(__APPLE__)
    out->mtim.tv_sec = st.st_mtimespec.tv_sec;
    out->mtim.tv_nsec = st.st_mtimespec.tv_nsec;
    out->ctim.tv_sec = st.st_ctimespec.tv_sec;
    out->ctim.tv_nsec = st.st_ctimespec.tv_nsec;
#else
    out->mtim = st.st_mtim;
    out->ctim = st.st_ctim;
#endif
}

static void dlrg_snap_all(const char *wt, struct dlrg_snap *out)
{
    for (size_t i = 0; i < DLRG_N; i++)
        dlrg_snap_capture(wt, DLRG_ARTIFACTS[i].path, &out[i]);
}

static bool dlrg_snap_eq(const struct dlrg_snap *a, const struct dlrg_snap *b)
{
    if (a->exists != b->exists)
        return false;
    if (!a->exists)
        return true;
    if (a->ino != b->ino || a->size != b->size)
        return false;
#if defined(_WIN32)
    return a->mtime == b->mtime && a->ctime == b->ctime;
#else
    return a->mtim.tv_sec == b->mtim.tv_sec &&
          a->mtim.tv_nsec == b->mtim.tv_nsec &&
          a->ctim.tv_sec == b->ctim.tv_sec &&
          a->ctim.tv_nsec == b->ctim.tv_nsec;
#endif
}

/* How many of the table's paths changed identity (inode/size/mtime/ctime)
 * between the two snapshots — set even when the bytes a generator wrote
 * are identical to what was already there, which is exactly the case
 * `dlrg_collect_changed`'s git-diff cannot see and the build plan's
 * mutation token can. */
static size_t dlrg_snap_diff_count(const struct dlrg_snap *before,
                                   const struct dlrg_snap *after)
{
    size_t n = 0;
    for (size_t i = 0; i < DLRG_N; i++) {
        if (!dlrg_snap_eq(&before[i], &after[i]))
            n++;
    }
    return n;
}

/* Which of the table's paths actually differ from HEAD after the targets
 * ran. Writes pointers into `changed` (capacity DLRG_N) and returns how
 * many. */
static size_t dlrg_collect_changed(const char *wt, const char **changed)
{
    size_t n = 0;
    for (size_t i = 0; i < DLRG_N; i++) {
        const char *diff_args[] = { "diff", "--quiet", "--",
                                    DLRG_ARTIFACTS[i].path, NULL };
        if (dlrg_git(wt, diff_args, NULL, 0) != 0)
            changed[n++] = DLRG_ARTIFACTS[i].path;
    }
    return n;
}

static bool dlrg_args_ok(const char *wt, const char *new_head,
                         size_t new_head_cap, const char *why,
                         size_t why_cap)
{
    return wt && new_head && new_head_cap >= 41 && why && why_cap > 0;
}

/* The shared "nothing (more) to commit" tail: HEAD is reported as-is,
 * whether that is because there was no Makefile, or because the
 * generators ran and reproduced exactly what was already there. */
static int dlrg_finish_unchanged(const char *wt, char *new_head)
{
    return dlrg_rev_parse(wt, "HEAD", new_head) ? 1 : -1;
}

/* Re-seal build/dev-loop/restart.env after this phase touched the tree.
 *
 * The plan's BASE_GENERATION line is a stat-based mutation token over every
 * tracked source file (tools/dev/source-identity.sh, dev_source_identity.c)
 * and the proof checks it against the tree it is about to prove
 * (dev_proof.c's zcl_dev_source_mutation_verify). A regen target can
 * rewrite one of DLRG_ARTIFACTS with byte-identical content — git sees no
 * diff, nothing is committed — and still change that file's mtime/ctime,
 * which moves the token. If the plan was already sealed before this phase
 * ran (the common case: the landing worktree's dev-bin build seals it
 * first), the proof then refuses a tip that never actually diverged from
 * what the plan describes. Re-running $(DEV_RESTART_PLAN) reseals it from
 * the tree as it stands now; the target carries a FORCE prerequisite (see
 * Makefile), so this is always a full reseal, never a stale no-op, and it
 * is the same target the prebuild phase ensures exists — that later check
 * just finds it already fresh and does not rebuild it again. */
static bool dlrg_plan_refresh(const char *wt, size_t touched,
                              size_t committed, char *transcript,
                              size_t transcript_cap, size_t *used, char *why,
                              size_t why_cap)
{
    char line[160];
    if (touched == 0) {
        dlrg_append(transcript, transcript_cap, used,
                   "regen: restart plan unchanged\n");
        return true;
    }
    (void)snprintf(line, sizeof(line),
                  "regen: restart plan refreshed (%zu artifact(s) "
                  "rewritten, %zu committed)\n",
                  touched, committed);
    dlrg_append(transcript, transcript_cap, used, line);
    return dlrg_make(wt, "build/dev-loop/restart.env", transcript,
                     transcript_cap, used, why, why_cap) == 0;
}

int zcl_dev_land_regen_phase(const char *wt, const char *tip_sha,
                             char *new_head, size_t new_head_cap,
                             char *transcript, size_t transcript_cap,
                             char *why, size_t why_cap)
{
    const char *changed[DLRG_N];
    struct dlrg_snap before[DLRG_N], after[DLRG_N];
    size_t changed_n, used = 0, touched, committed = 0;

    if (!dlrg_args_ok(wt, new_head, new_head_cap, why, why_cap))
        return -1;
    why[0] = '\0';
    if (transcript && transcript_cap)
        transcript[0] = '\0';

    if (!dlrg_has_makefile(wt))
        return dlrg_finish_unchanged(wt, new_head);

    dlrg_snap_all(wt, before);
    if (!dlrg_run_targets(wt, transcript, transcript_cap, &used, why,
                         why_cap))
        return -1;
    dlrg_snap_all(wt, after);
    touched = dlrg_snap_diff_count(before, after);

    changed_n = dlrg_collect_changed(wt, changed);
    if (changed_n > 0) {
        if (dlrg_commit(wt, tip_sha, changed, changed_n, why, why_cap) < 0)
            return -1;
        committed = 1;
    }

    if (!dlrg_plan_refresh(wt, touched, committed, transcript,
                          transcript_cap, &used, why, why_cap))
        return -1;

    return dlrg_finish_unchanged(wt, new_head);
}
