/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the candidate fold one Muse run publishes, and the verified
 * return of the workspace to its pinned base afterwards. See header. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "services/muse_run_restore.h"
#include "services/muse_run_audit.h"
#include "base/safe_alloc.h"
#include "util/file_tree_ops.h"
#include "util/spawn.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The Windows CRT exposes neither flag. Its descriptors wrap non-inheritable
 * handles unless inheritance is requested, so a zero O_CLOEXEC keeps the
 * boundary; and the only file this opens without following is one lstat()
 * has already proven regular, so a zero O_NOFOLLOW there loses no check.
 * (Same zero fallback as engine/modules/engine/src/engine_secret.c.) */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define MRR_OTHERS_MAX 65536u
#define MRR_PATH_MAX 8192
#define MRR_UNTRACKED_MAX 4096

/* --- the fold --------------------------------------------------------------- */

/* Append "path hash" lines for every untracked path: the content half
 * of the change set that `git diff` never shows. */
static void mrr_fold_others(const char *workspace, char *acc, size_t acc_cap,
    size_t *used)
{
    const char *argv[] = { "git", "-C", workspace, "ls-files", "--others",
                           "--exclude-standard", NULL };
    char *list = zcl_malloc(MRR_OTHERS_MAX, "muse_run.others");
    int rc;
    if (!list) return;
    list[0] = '\0';
    rc = zcl_spawn_capture(argv, list, MRR_OTHERS_MAX, MR_GIT_TIMEOUT_MS);
    if (rc != 0) {
        free(list);
        return;
    }
    for (char *line = strtok(list, "\n"); line;
        line = strtok(NULL, "\n")) {
        char h[128];
        const char *path = line;
        int w;
        /* A path whose quoting will not read is not folded as a
         * best-effort guess: the identity must name what was measured or
         * name nothing, and the scope audit refuses the same row. */
        if (!muse_dequote(line)) break;
        w = snprintf(acc + *used, acc_cap - *used, "?? %s ", path);
        if (w <= 0 || (size_t)w >= acc_cap - *used) break;
        *used += (size_t)w;
        if (muse_git_line(h, sizeof(h), workspace, "hash-object", "--",
                path)) {
            w = snprintf(acc + *used, acc_cap - *used, "%s\n", h);
        } else {
            w = snprintf(acc + *used, acc_cap - *used, "missing\n");
        }
        if (w <= 0 || (size_t)w >= acc_cap - *used) break;
        *used += (size_t)w;
    }
    free(list);
}

/* Lays the fold down in a rundir tempfile, because the capture helper the
 * hash goes through is text-oriented. False when it could not be written. */
static bool mrr_fold_tempfile(const char *rundir, char *tmp, size_t tmpcap,
    const char *acc, size_t used)
{
    FILE *f;
    if (snprintf(tmp, tmpcap, "%s/.candidate.in", rundir) >= (int)tmpcap)
        return false;
    f = fopen(tmp, "wb");
    if (!f) return false;
    if (used > 0 && fwrite(acc, 1, used, f) != used) {
        fclose(f);
        (void)unlink(tmp);
        return false;
    }
    fclose(f);
    return true;
}

/* git hash-object over one file. The 40-hex token lands in out; false on
 * any git failure. The same call names the fold and checks the artifact,
 * so the two can only ever agree for the same bytes. */
static bool mrr_hash_file(const char *path, char *out, size_t cap)
{
    const char *h_argv[] = { "git", "hash-object", path, NULL };
    char hbuf[128];
    int rc;
    hbuf[0] = '\0';
    rc = zcl_spawn_capture(h_argv, hbuf, sizeof(hbuf), MR_GIT_TIMEOUT_MS);
    if (rc != 0) return false;
    hbuf[strcspn(hbuf, "\r\n")] = '\0';
    if (!muse_hex40(hbuf) || strlen(hbuf) >= cap) return false;
    (void)snprintf(out, cap, "%s", hbuf);
    return true;
}

/* One named failure out of the fold. Always leaves hex_out "none" and
 * *fold_out NULL, so no caller can read a broken fold as an empty one. */
static bool mrr_fold_failed(char *hex_out, size_t hex_cap, char **fold_out,
    char *acc, char *why, size_t why_cap, const char *what)
{
    (void)snprintf(hex_out, hex_cap, "none");
    *fold_out = NULL;
    free(acc);
    if (why && why_cap > 0) (void)snprintf(why, why_cap, "%s", what);
    return false;
}

/* The fold text and its hash; see the header. */
bool muse_candidate_fold(const char *workspace, const char *rundir,
    char *hex_out, size_t hex_cap, char **fold_out, char *why,
    size_t why_cap)
{
    const char *diff_argv[] = { "git", "-C", workspace, "diff", "HEAD",
                                "--", NULL };
    char *acc = zcl_malloc(MUSE_FOLD_MAX, "muse_run.candidate");
    char tmp[MRR_PATH_MAX];
    size_t used;
    int rc;
    (void)snprintf(hex_out, hex_cap, "none");
    *fold_out = NULL;
    if (why && why_cap > 0) why[0] = '\0';
    if (!acc)
        return mrr_fold_failed(hex_out, hex_cap, fold_out, NULL, why,
            why_cap, "the fold buffer could not be allocated");
    acc[0] = '\0';
    rc = zcl_spawn_capture(diff_argv, acc, MUSE_FOLD_MAX,
        MR_GIT_TIMEOUT_MS);
    if (rc != 0) {
        char note[MUSE_FOLD_NOTE_MAX];
        /* Name the EXIT STATUS. The one production failure of this call
         * was git exiting 128 because it could not mmap a packfile under
         * the executor child's address-space limit; a bare "git failed"
         * would have hidden which git and which failure. */
        (void)snprintf(note, sizeof(note),
            "the tracked diff could not be captured: `git -C <workspace> "
            "diff HEAD --` exited %d (stderr is not captured; a 128 here "
            "is usually git unable to map its object store under the "
            "caller's memory limit)", rc);
        return mrr_fold_failed(hex_out, hex_cap, fold_out, acc, why,
            why_cap, note);
    }
    used = strlen(acc);
    if (used + 2 < MUSE_FOLD_MAX) {
        acc[used++] = '\n';
        acc[used] = '\0';
    }
    mrr_fold_others(workspace, acc, MUSE_FOLD_MAX, &used);
    if (used < MUSE_FOLD_MAX) acc[used] = '\0';
    if (!mrr_fold_tempfile(rundir, tmp, sizeof(tmp), acc, used))
        return mrr_fold_failed(hex_out, hex_cap, fold_out, acc, why,
            why_cap, "the fold could not be written under the run dir");
    if (!mrr_hash_file(tmp, hex_out, hex_cap)) {
        (void)unlink(tmp);
        return mrr_fold_failed(hex_out, hex_cap, fold_out, acc, why,
            why_cap, "the fold could not be hashed by `git hash-object`");
    }
    (void)unlink(tmp);
    *fold_out = acc;
    return true;
}

/* --- durable bytes ------------------------------------------------------------ */

static bool mrr_fsync_path(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    bool ok;
    if (fd < 0) return false;
    ok = fsync(fd) == 0;
    close(fd);
    return ok;
}

static bool mrr_write_all(int fd, const char *p, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        p += w;
        n -= (size_t)w;
    }
    return true;
}

/* Copies src's bytes to dst through a tempfile, fsync and rename. src is
 * opened without following a symlink: only a regular file is copied. */
static bool mrr_copy_file(const char *src, const char *dst)
{
    char tmp[MRR_PATH_MAX], buf[65536];
    int in, out;
    bool ok = true;
    ssize_t n;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp-%d", dst, (int)getpid()) >=
        (int)sizeof(tmp))
        return false;
    in = open(src, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (in < 0) return false;
    out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (out < 0) {
        close(in);
        return false;
    }
    while (ok && (n = read(in, buf, sizeof(buf))) != 0) {
        if (n < 0 && errno == EINTR) continue;
        ok = n > 0 && mrr_write_all(out, buf, (size_t)n);
    }
    ok = ok && fsync(out) == 0;
    close(in);
    if (close(out) != 0) ok = false;
    if (ok && rename(tmp, dst) == 0) return true;
    (void)unlink(tmp);
    return false;
}

static bool mrr_write_durable(const char *path, const char *text, size_t n)
{
    char tmp[MRR_PATH_MAX];
    int fd;
    bool ok;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp-%d", path, (int)getpid()) >=
        (int)sizeof(tmp))
        return false;
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    ok = mrr_write_all(fd, text, n) && fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    if (ok && rename(tmp, path) == 0) return true;
    (void)unlink(tmp);
    return false;
}

/* Whole file, NUL-terminated, or NULL when unreadable or at the bound. */
static char *mrr_read_bounded(const char *path, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    char *buf;
    size_t n;
    if (!f) return NULL;
    buf = zcl_malloc(cap + 1, "muse_run.restore.read");
    if (!buf) {
        fclose(f);
        return NULL;
    }
    n = fread(buf, 1, cap + 1, f);
    fclose(f);
    if (n >= cap) {
        free(buf);
        return NULL;
    }
    buf[n] = '\0';
    *len = n;
    return buf;
}

/* --- the verification ---------------------------------------------------------- */

struct mrr_untracked {
    char path[1024];
    char hash[48];
};

struct mrr_state {
    const struct muse_restore_in *in;
    char artifact[MRR_PATH_MAX];
    char *text;          /* the artifact's verified bytes */
    size_t len;
    size_t tracked_len;  /* bytes of the `git diff HEAD` half */
    struct mrr_untracked *files;
    size_t nfiles;
    char *audit_list;    /* the scope audit's changed-path list */
    long long audit_total;
};

static const char *mrr_preconditions(const struct muse_restore_in *in)
{
    if (!in->pre_clean)
        return "not attempted: the pre-state was not measured clean, so "
               "nothing here is attributable to this run";
    if (!muse_hex40(in->base)) return "not attempted: no pinned base";
    if (!muse_hex40(in->candidate))
        return "not attempted: the change set was never named";
    if (!in->candidate_file || !in->candidate_file[0])
        return "not attempted: no candidate artifact was published";
    return NULL;
}

static const char *mrr_head_at_base(const struct muse_restore_in *in)
{
    char head[64];
    if (!muse_head_at(in->workspace, head, sizeof(head)))
        return "refused: HEAD unreadable";
    if (strcmp(head, in->base) != 0)
        return "refused: HEAD is not the pinned base";
    return NULL;
}

/* The artifact exists under the name it was published as, its bytes hash
 * to that name, it did not reach the fold bound, and it is on disk. */
static const char *mrr_verify_artifact(struct mrr_state *st)
{
    const struct muse_restore_in *in = st->in;
    char expect[128], h[64];
    (void)snprintf(expect, sizeof(expect), "candidate-%s.diff",
        in->candidate);
    if (strcmp(expect, in->candidate_file) != 0)
        return "refused: candidate artifact is not named by its hash";
    if (snprintf(st->artifact, sizeof(st->artifact), "%s/%s", in->rundir,
            in->candidate_file) >= (int)sizeof(st->artifact))
        return "refused: candidate artifact path does not fit";
    st->text = mrr_read_bounded(st->artifact, MUSE_FOLD_MAX - 2, &st->len);
    if (!st->text)
        return "refused: candidate artifact missing, unreadable, or at its "
               "size bound";
    if (!mrr_hash_file(st->artifact, h, sizeof(h)) ||
        strcmp(h, in->candidate) != 0)
        return "refused: candidate artifact bytes do not hash to its name";
    if (!mrr_fsync_path(st->artifact) || !mrr_fsync_path(in->rundir))
        return "refused: candidate artifact could not be made durable";
    return NULL;
}

/* A fresh fold of the workspace, NOW, must be byte-identical to the
 * artifact: then the artifact is a copy of exactly what is about to be
 * undone, and nothing changed since it was taken. */
static const char *mrr_verify_reproduces(struct mrr_state *st)
{
    char hex[64];
    char *fold = NULL;
    bool same;
    if (!muse_candidate_fold(st->in->workspace, st->in->rundir, hex,
            sizeof(hex), &fold, NULL, 0))
        return "refused: the workspace change set could not be re-derived";
    same = strcmp(hex, st->in->candidate) == 0 && strcmp(fold, st->text) == 0;
    free(fold);
    return same ? NULL
                : "refused: the workspace no longer matches the candidate";
}

/* The scope audit's own list of changed paths: every path restored must be
 * one it names, and a measurable empty tree needs no restore at all. */
static const char *mrr_audit(struct mrr_state *st)
{
    struct muse_audit a;
    st->audit_list = zcl_malloc(MUSE_FOLD_MAX, "muse_run.restore.audit");
    if (!st->audit_list) return "refused: out of memory";
    muse_audit_init(&a, NULL, st->audit_list, MUSE_FOLD_MAX, NULL, 0);
    if (!muse_audit_scan(st->in->workspace, &a))
        return "refused: the change set is unmeasurable";
    st->audit_total = a.total;
    return NULL;
}

/* True when the audit list holds exactly this path as one element. */
static bool mrr_audit_names(const char *list, const char *path)
{
    char esc[1100];
    size_t n;
    muse_json_escape(path, esc, sizeof(esc));
    n = strlen(esc);
    for (const char *p = strstr(list, esc); p; p = strstr(p + 1, esc)) {
        bool open = p > list && p[-1] == '"' &&
            (p - 1 == list || p[-2] == ',');
        bool close = p[n] == '"' && (p[n + 1] == ',' || p[n + 1] == '\0');
        if (open && close) return true;
    }
    return false;
}

/* One "?? <path> <hash>" line into *u; false when it does not read. */
static bool mrr_parse_other(const char *line, size_t n,
    struct mrr_untracked *u)
{
    size_t plen;
    if (n < 3 + 1 + 1 + 40 || strncmp(line, "?? ", 3) != 0) return false;
    if (line[n - 41] != ' ') return false;
    memcpy(u->hash, line + n - 40, 40);
    u->hash[40] = '\0';
    if (!muse_hex40(u->hash)) return false;
    plen = n - 41 - 3;
    if (plen == 0 || plen >= sizeof(u->path)) return false;
    memcpy(u->path, line + 3, plen);
    u->path[plen] = '\0';
    return true;
}

/* Splits the artifact at its first "?? " line: the tracked half before,
 * the untracked rows after. Every row must read. */
static const char *mrr_split(struct mrr_state *st)
{
    const char *t = st->text;
    const char *p = t;
    st->tracked_len = st->len;
    st->files = zcl_malloc(sizeof(*st->files) * MRR_UNTRACKED_MAX,
        "muse_run.restore.files");
    if (!st->files) return "refused: out of memory";
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (strncmp(p, "?? ", 3) == 0) {
            if (st->tracked_len == st->len) st->tracked_len = (size_t)(p - t);
            if (st->nfiles == MRR_UNTRACKED_MAX ||
                !mrr_parse_other(p, n, &st->files[st->nfiles]))
                return "refused: an untracked row in the candidate does not "
                       "read";
            st->nfiles++;
        } else if (st->tracked_len != st->len && n > 0) {
            return "refused: the candidate mixes rows after its untracked "
                   "half";
        }
        p = nl ? nl + 1 : p + n;
    }
    return NULL;
}

static bool mrr_path_safe(const char *path)
{
    return path[0] && path[0] != '/' && strstr(path, "..") == NULL &&
        strchr(path, '\n') == NULL;
}

/* One untracked file: named by the audit, a regular file, copied under
 * the rundir, and the copy hashes (with the workspace's own attributes
 * for that path) to the content hash the artifact recorded. */
static const char *mrr_keep_one(struct mrr_state *st, const char *dir,
    const struct mrr_untracked *u)
{
    char src[MRR_PATH_MAX], dst[MRR_PATH_MAX], opt[1200], h[64];
    struct stat sb;
    if (!mrr_path_safe(u->path) || !mrr_audit_names(st->audit_list, u->path))
        return "refused: an untracked path is not one the scope audit named";
    if (snprintf(src, sizeof(src), "%s/%s", st->in->workspace, u->path) >=
            (int)sizeof(src) ||
        snprintf(dst, sizeof(dst), "%s/%s", dir, u->hash) >=
            (int)sizeof(dst) ||
        snprintf(opt, sizeof(opt), "--path=%s", u->path) >= (int)sizeof(opt))
        return "refused: an untracked path does not fit";
    if (lstat(src, &sb) != 0 || !S_ISREG(sb.st_mode))
        return "refused: an untracked path is not a regular file";
    if (!mrr_copy_file(src, dst))
        return "refused: an untracked file could not be copied";
    if (!muse_git_line(h, sizeof(h), st->in->workspace, "hash-object", opt,
            dst) || strcmp(h, u->hash) != 0)
        return "refused: an untracked copy does not hash to the candidate";
    return NULL;
}

/* Durable copies of every untracked file BEFORE any is removed. */
static const char *mrr_keep_untracked(struct mrr_state *st)
{
    char dir[MRR_PATH_MAX];
    if (st->nfiles == 0) return NULL;
    if (snprintf(dir, sizeof(dir), "%s/candidate-%s.untracked",
            st->in->rundir, st->in->candidate) >= (int)sizeof(dir))
        return "refused: the untracked copy directory does not fit";
    if (!zcl_mkdir_p(dir, 0700).ok)
        return "refused: the untracked copy directory could not be made";
    for (size_t i = 0; i < st->nfiles; i++) {
        const char *why = mrr_keep_one(st, dir, &st->files[i]);
        if (why) return why;
    }
    return mrr_fsync_path(dir) ? NULL
                               : "refused: the untracked copies are not durable";
}

static bool mrr_git_ok(const char *const argv[])
{
    char out[4096];
    out[0] = '\0';
    return zcl_spawn_capture(argv, out, sizeof(out), MR_GIT_TIMEOUT_MS) == 0;
}

static bool mrr_has_patch(const struct mrr_state *st)
{
    for (size_t i = 0; i + 11 <= st->tracked_len; i++) {
        if ((i == 0 || st->text[i - 1] == '\n') &&
            strncmp(st->text + i, "diff --git ", 11) == 0)
            return true;
    }
    return false;
}

/* The tracked half, laid down as its own durable patch, must reverse-apply
 * cleanly before anything is changed. */
static const char *mrr_check_tracked(struct mrr_state *st, char *patch,
    size_t cap)
{
    const char *argv[] = { "git", "-C", st->in->workspace, "apply", "-R",
                           "--check", patch, NULL };
    patch[0] = '\0';
    if (!mrr_has_patch(st)) return NULL;
    if (snprintf(patch, cap, "%s/candidate-%s.tracked.patch", st->in->rundir,
            st->in->candidate) >= (int)cap)
        return "refused: the tracked patch path does not fit";
    if (!mrr_write_durable(patch, st->text, st->tracked_len))
        return "refused: the tracked patch could not be written";
    if (!mrr_git_ok(argv))
        return "refused: the tracked half does not reverse-apply";
    return NULL;
}

/* --- the restore ------------------------------------------------------------- */

static const char *mrr_undo(struct mrr_state *st, const char *patch)
{
    const char *apply[] = { "git", "-C", st->in->workspace, "apply", "-R",
                            patch, NULL };
    const char *unstage[] = { "git", "-C", st->in->workspace, "restore",
                              "--staged", "--", ":/", NULL };
    if (patch[0] && !mrr_git_ok(apply))
        return "incomplete: the tracked half did not reverse-apply";
    if (patch[0] && !mrr_git_ok(unstage))
        return "incomplete: the index could not be returned to HEAD";
    for (size_t i = 0; i < st->nfiles; i++) {
        char p[MRR_PATH_MAX];
        if (snprintf(p, sizeof(p), "%s/%s", st->in->workspace,
                st->files[i].path) >= (int)sizeof(p) ||
            unlink(p) != 0)
            return "incomplete: an untracked file could not be removed";
    }
    return NULL;
}

/* After the undo: HEAD still the base and a measured clean tree. */
static const char *mrr_settled(const struct mrr_state *st)
{
    long long left = muse_files_changed(st->in->workspace);
    const char *head = mrr_head_at_base(st->in);
    if (head) return head;
    if (left < 0) return "incomplete: the restored tree is unmeasurable";
    if (left > 0) return "incomplete: paths remain changed after restore";
    return NULL;
}

/* Every path the scope audit names must be accounted for by the artifact:
 * the tracked half's paths (a rename counted as both halves, as the audit
 * counts it) plus the untracked rows. A fold that stopped short of the
 * change set — a capture that hit its bound — fails this before anything
 * is touched. */
static const char *mrr_accounted(const struct mrr_state *st)
{
    const char *argv[] = { "git", "-C", st->in->workspace, "diff", "HEAD",
                           "--no-renames", "--name-only", "--", NULL };
    char *buf = zcl_malloc(MUSE_FOLD_MAX, "muse_run.restore.names");
    long long tracked = 0;
    bool whole;
    if (!buf) return "refused: out of memory";
    buf[0] = '\0';
    whole = zcl_spawn_capture(argv, buf, MUSE_FOLD_MAX,
        MR_GIT_TIMEOUT_MS) == 0 && strlen(buf) + 1 < MUSE_FOLD_MAX;
    for (const char *p = buf; *p; p++) {
        if (*p == '\n') tracked++;
    }
    free(buf);
    if (!whole) return "refused: the tracked path list is unmeasurable";
    if (tracked + (long long)st->nfiles != st->audit_total)
        return "refused: the candidate does not account for every changed "
               "path";
    return NULL;
}

/* Every check that must pass before a single byte is touched. */
static const char *mrr_verify(struct mrr_state *st, char *patch, size_t cap)
{
    const char *why = mrr_preconditions(st->in);
    if (!why) why = mrr_head_at_base(st->in);
    if (!why) why = mrr_verify_artifact(st);
    if (!why) why = mrr_verify_reproduces(st);
    if (!why) why = mrr_audit(st);
    if (!why) why = mrr_split(st);
    if (!why && st->audit_total > 0) why = mrr_accounted(st);
    if (!why && st->audit_total > 0) why = mrr_keep_untracked(st);
    if (!why && st->audit_total > 0) why = mrr_check_tracked(st, patch, cap);
    return why;
}

/* The undo and its settlement: everything that TOUCHES the workspace.
 * Any failure from here on leaves a half-undone tree, which is the one
 * state the caller must be able to tell apart from an untouched one. */
static const char *mrr_apply(struct mrr_state *st, const char *patch,
    bool *half_undone)
{
    const char *why;
    if (half_undone) *half_undone = true;
    why = mrr_undo(st, patch);
    if (!why) why = mrr_settled(st);
    if (!why && half_undone) *half_undone = false;
    return why;
}

bool muse_restore_workspace(const struct muse_restore_in *in, char *reason,
    size_t reason_cap, bool *half_undone)
{
    struct mrr_state st;
    char patch[MRR_PATH_MAX];
    const char *why;
    memset(&st, 0, sizeof(st));
    st.in = in;
    patch[0] = '\0';
    if (half_undone) *half_undone = false;
    why = mrr_verify(&st, patch, sizeof(patch));
    if (!why && st.audit_total == 0) {
        (void)snprintf(reason, reason_cap,
            "already clean at base %.12s", in->base);
    } else if (!why) {
        why = mrr_apply(&st, patch, half_undone);
        if (!why)
            (void)snprintf(reason, reason_cap,
                "restored to base %.12s from verified %s (%zu untracked "
                "copied)", in->base, in->candidate_file, st.nfiles);
    }
    if (why) (void)snprintf(reason, reason_cap, "%s", why);
    free(st.text);
    free(st.files);
    free(st.audit_list);
    return why == NULL;
}
