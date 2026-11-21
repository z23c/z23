/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the advisory speculative pair of `dev land speculate`: the pair the
 *          land queue will prove next, predicted while the in-flight row is
 *          still proving, with the driver's own rebase and train stacking in a
 *          scratch worktree. Reads a queue snapshot; writes nothing of the
 *          queue's.
 *
 * ── SPECULATIVE PAIR (ADVISORY) ───────────────────────────────────────────
 *
 * WHY. One host proves one candidate at a time while a second sits idle. What
 * a second host proves can never be the landed proof, but it can prove the
 * pair the queue will prove NEXT and steer scheduling with the verdict, if it
 * learns that pair while the in-flight row N is still proving.
 *
 * EXACTNESS. A landed row pushes its `local`, so when N lands origin main is
 * exactly local(N). The next row is then rebased onto exactly local(N), so
 * the pair (local(N+1) rebased on local(N), local(N)) is what the driver
 * builds. This predicts it with the driver's own code in a scratch worktree:
 * dl_rebase_pair (the head's rebase, everything dl_rebase does but the
 * landing worktree's submodule seed) and dl_train_stack_rows (the stacking
 * dl_train_prepare_first runs), over the queue minus N and the rows bound to
 * N's pair. What it guarantees is the BASE and the TREE (and which rows ride):
 * they are exactly what the driver builds. It does NOT guarantee commit ids.
 * The speculative commits are unsigned predictions, made with signing and
 * hooks off whatever the landing repository's config says (an advisory leaf
 * never signs with the owner's key), while the driver's commits are signed
 * when that repository signs; and a rebased commit carries the committer time
 * of the moment it is made. So the driver's `local` differs from this one even
 * when the tree is identical. A consumer keys on (base, tree), which is what
 * the proof binds the content to, never on `local`.
 *
 * NOT PREDICTED. The stacked lint-land (which halves a red stack), the proof
 * dependencies, a row that conflicts only because main moves for another
 * reason, and N itself failing: the pair is a prediction that holds only if
 * N lands unchanged, and it names the in-flight (local, base) it came from.
 *
 * WIDTH. The driver's train width is the lander service's
 * ZCL_LAND_TRAIN_WIDTH, which is in that process's environment and in no
 * state this one can read. The caller therefore passes train_width (1 is a
 * stated solo proof) or exports the lander's value; the reply names the width
 * assumed and its source (input or environment), and with neither no pair is
 * made up (reason width_unknown).
 *
 * WRITES. It reads a snapshot the caller took under the decision's shared
 * locks and holds no lock itself, so the driver's beats are never delayed. It
 * writes no queue, ledger, log or ref and never touches the landing worktree:
 * the rebases run in a detached scratch worktree under a private temp
 * directory, removed again; the commits it makes are unreferenced objects in
 * the landing repository. A scratch a crashed call left behind (name prefix
 * z23-land-spec-, older than the longest budget, owned by this user) is
 * removed at the start of the next call. The only durable output is
 * --bundle_out, which the caller asked for and which is created exclusively.
 * Every git spawn is held to one deadline (dl_deadline_set), and a deadline
 * that passes anywhere is reported as budget_exhausted, never as a conflict. */

#include "command/native_dev_land_internal.h"
#include "command/native_dev_land_remote_shared.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/private_directory.h"
#include "platform/temp_directory.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define DL_SPEC_CLEANUP_MS (30 * 1000)
#define DL_SPEC_SCRATCH_PREFIX "z23-land-spec-"
/* Longer than the longest budget (600 s) plus its cleanup, so a scratch this
 * old belongs to no live call. */
#define DL_SPEC_STALE_SECS (20 * 60)
#define DL_SPEC_SWEEP_MAX 8

struct dl_spec {
    const struct dl_dirs *landing;
    struct dl_spec_args args;
    struct dl_dirs d; /* the landing dirs with `wt` the scratch worktree */
    char dir[PLATFORM_TEMP_PATH_MAX];
    bool opened, flight_seen;
    struct dl_row flight, head;
    struct dl_train train;
    size_t width;
    const char *width_source;
    char reason[40], detail[512];
    char local[80], base[80], tree[80];
    bool pair;
    struct json_value bundle;
};

/* The first reason wins. A failure after the deadline passed is the budget's,
 * whatever git reported when it was killed. */
static void dl_spec_none(struct dl_spec *s, const char *reason,
                         const char *detail)
{
    if (s->reason[0])
        return;
    if (dl_budget_ms(1) == 0 && strcmp(reason, "queue_moved") != 0 &&
        strcmp(reason, "width_unknown") != 0) {
        reason = "budget_exhausted";
        detail = "the time budget ran out before the pair was built";
    }
    (void)snprintf(s->reason, sizeof(s->reason), "%s", reason);
    (void)snprintf(s->detail, sizeof(s->detail), "%s", detail);
}

static bool dl_spec_flight(struct dl_spec *s, const struct dl_row *rows,
                           size_t n)
{
    for (size_t i = 0; i < n && !s->flight_seen; i++) {
        if (strcmp(rows[i].state, "inflight") != 0)
            continue;
        s->flight = rows[i];
        s->flight_seen = true;
    }
    if (!s->flight_seen) {
        dl_spec_none(s, "nothing_in_flight",
                     "no row is in flight, so no landing is about to move "
                     "main");
        return false;
    }
    const struct dl_row *f = &s->flight;
    if ((strcmp(f->phase, "prove") != 0 && strcmp(f->phase, "push") != 0) ||
        !dl_sha_ok(f->local) || !dl_sha_ok(f->base)) {
        dl_spec_none(s, "in_flight_pair_not_final",
                     "the in-flight row has not fixed the (local, base) pair "
                     "it will push: it is still rebasing or preparing");
        return false;
    }
    return true;
}

/* The queue as it stands once the in-flight row has landed: without it and
 * without the rows bound to its pair, which land with it. */
static struct dl_row *dl_spec_after_landing(const struct dl_spec *s,
                                            const struct dl_row *rows,
                                            size_t n, size_t *count)
{
    struct dl_row *after = zcl_calloc(n ? n : 1, sizeof(*after),
                                      "dev.land.spec.rows");
    *count = 0;
    for (size_t i = 0; after && i < n; i++) {
        if (strcmp(rows[i].state, "inflight") == 0 ||
            (rows[i].proof_intent[0] &&
             strcmp(rows[i].proof_intent, s->flight.proof_intent) == 0))
            continue;
        after[(*count)++] = rows[i];
    }
    return after;
}

/* Can the driver start this row once N has landed? The train's own test of a
 * row (dl_train_joinable) minus its first-attempt rule: a retry or a
 * train_solo row is proved alone, a plain rebase onto local(N), and is as
 * predictable as a fresh one. A held, fenced, successor or already bound row
 * is not started that way. */
static bool dl_spec_startable(const struct dl_row *r)
{
    return !r->publication_hold && !r->predecessor_seq && !r->fence_peer &&
           !r->proof_intent[0] && !r->publication_signature[0] &&
           !r->pushed[0] && !r->push_diagnostic_pending;
}

static bool dl_spec_head(struct dl_spec *s, const struct dl_row *after,
                         size_t count)
{
    bool inflight = false;
    char detail[256];
    if (!dl_step_pick_row(after, count, &s->head, &inflight)) {
        dl_spec_none(s, "nothing_queued",
                     "no other row is queued behind the in-flight row");
        return false;
    }
    if (dl_spec_startable(&s->head))
        return true;
    (void)snprintf(detail, sizeof(detail),
                   "seq=%lld is next but cannot start from local(N) alone: "
                   "attempt=%lld train_solo=%lld hold=%d predecessor=%lld "
                   "fence_peer=%lld bound=%d",
                   s->head.seq, s->head.attempt, s->head.train_solo,
                   s->head.publication_hold, s->head.predecessor_seq,
                   s->head.fence_peer, s->head.proof_intent[0] != '\0');
    dl_spec_none(s, "next_row_not_joinable", detail);
    return false;
}

/* The driver's width: what the caller states, else the environment the
 * caller really has the lander's in. Never a default. */
static bool dl_spec_width(struct dl_spec *s)
{
    if (s->args.width) {
        s->width = s->args.width;
        s->width_source = "input";
        return true;
    }
    if (getenv("ZCL_LAND_TRAIN_WIDTH")) {
        s->width = dl_train_width();
        s->width_source = "environment";
        return true;
    }
    s->width_source = "none";
    dl_spec_none(s, "width_unknown",
                 "pass input.train_width (1 for a solo proof, 2..8 for a "
                 "train): the driver's width is the lander service's "
                 "ZCL_LAND_TRAIN_WIDTH, which this process does not have, "
                 "and no width is assumed");
    return false;
}

#if !defined(_WIN32)
/* One entry of the temp directory: a scratch of this leaf, owned by this
 * user, older than any live call, and not the current call's. */
static bool dl_spec_stale(const struct dl_spec *s, const char *parent,
                          const char *name, char *path, size_t cap)
{
    struct stat st;
    return strncmp(name, DL_SPEC_SCRATCH_PREFIX,
                   strlen(DL_SPEC_SCRATCH_PREFIX)) == 0 &&
           snprintf(path, cap, "%s/%s", parent, name) < (int)cap &&
           strcmp(path, s->dir) != 0 && lstat(path, &st) == 0 &&
           S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
           platform_time_wall_unix() - (int64_t)st.st_mtime >= DL_SPEC_STALE_SECS;
}

/* The stale scratch's worktree, then its directory; false when git will not
 * remove the worktree, which is then left. */
static bool dl_spec_discard(const struct dl_spec *s, const char *path)
{
    char wt[PLATFORM_TEMP_PATH_MAX + 292];
    struct stat st;
    if (snprintf(wt, sizeof(wt), "%s/wt", path) >= (int)sizeof(wt))
        return false;
    if (lstat(wt, &st) == 0) {
        /* Twice forced: a worktree add killed half-way holds an
         * "initializing" lock that a single force does not break. */
        const char *rm[] = { "worktree", "remove", "--force", "--force", wt,
                             NULL };
        if (dl_git(s->landing->wt, rm, NULL, 0, DL_GIT_TIMEOUT_MS) != 0)
            return false;
    }
    (void)platform_private_directory_remove_empty(path);
    return true;
}
#endif

/* Remove the scratch worktrees and directories a crashed call left: only
 * names this leaf makes, owned by this user, older than any live call, at
 * most DL_SPEC_SWEEP_MAX per call. A checkout git will not remove is left. */
static void dl_spec_sweep(const struct dl_spec *s)
{
#if !defined(_WIN32)
    char parent[PLATFORM_TEMP_PATH_MAX], path[PLATFORM_TEMP_PATH_MAX + 288];
    const char *slash = strrchr(s->dir, '/');
    size_t plen = slash ? (size_t)(slash - s->dir) : 0, swept = 0;
    DIR *dir;
    struct dirent *e;
    if (!plen || plen >= sizeof(parent))
        return;
    memcpy(parent, s->dir, plen);
    parent[plen] = '\0';
    dir = opendir(parent);
    dl_deadline_set(platform_time_monotonic_ms() + DL_SPEC_CLEANUP_MS);
    while (dir && swept < DL_SPEC_SWEEP_MAX && (e = readdir(dir)) != NULL)
        if (dl_spec_stale(s, parent, e->d_name, path, sizeof(path)) &&
            dl_spec_discard(s, path))
            swept++;
    if (dir)
        (void)closedir(dir);
    dl_deadline_set(0);
#else
    (void)s;
#endif
}

/* The private scratch directory, made first so a crashed call's leftovers are
 * cleared at the start of every call. */
static void dl_spec_scratch(struct dl_spec *s)
{
    if (!platform_temp_directory_create(DL_SPEC_SCRATCH_PREFIX, s->dir,
                                        sizeof(s->dir)))
        s->dir[0] = '\0';
    else
        dl_spec_sweep(s);
}

/* A detached, empty scratch worktree in the repository the landing worktree
 * belongs to: its own checkout, index and rebase state, no ref. */
static bool dl_spec_open(struct dl_spec *s)
{
    s->d = *s->landing;
    if (!s->dir[0] ||
        snprintf(s->d.wt, sizeof(s->d.wt), "%s/wt", s->dir) >=
            (int)sizeof(s->d.wt)) {
        dl_spec_none(s, "scratch_unavailable",
                     "cannot make a private scratch directory");
        return false;
    }
    const char *add[] = { "-c", "core.hooksPath=/dev/null", "worktree", "add",
                          "--quiet", "--detach", "--no-checkout", s->d.wt,
                          s->flight.local, NULL };
    s->opened = dl_git(s->landing->wt, add, NULL, 0, DL_GIT_TIMEOUT_MS) == 0;
    if (!s->opened)
        dl_spec_none(s, "scratch_unavailable",
                     "cannot add a scratch worktree beside the landing "
                     "worktree");
    return s->opened;
}

static void dl_spec_close(struct dl_spec *s)
{
    const char *rm[] = { "worktree", "remove", "--force", s->d.wt, NULL };
    if (!s->dir[0])
        return;
    dl_deadline_set(platform_time_monotonic_ms() + DL_SPEC_CLEANUP_MS);
    if (s->opened)
        (void)dl_git(s->landing->wt, rm, NULL, 0, DL_GIT_TIMEOUT_MS);
    (void)platform_private_directory_remove_empty(s->dir);
    dl_deadline_set(0);
}

/* The head's rebase onto local(N): what dl_train_rebase does for its turn.
 * A conflict is reported only when git showed unmerged paths and the budget
 * is still alive: a rebase killed at the deadline also fails the probe that
 * lists them, and a git failure with no unmerged path is no conflict. */
static bool dl_spec_rebase(struct dl_spec *s)
{
    char why[512] = "";
    dl_train_reset_pair(&s->head);
    s->head.log_path[0] = '\0';
    int rc = dl_rebase_pair(&s->d, &s->head, s->flight.local, why,
                            sizeof(why));
    if (rc == 1)
        return true;
    bool unmerged = rc == 0 && why[0] &&
                    strncmp(why, DL_CONFLICT_NO_PATHS,
                            strlen(DL_CONFLICT_NO_PATHS)) != 0;
    dl_spec_none(s, unmerged ? "rebase_conflict" : "rebase_failed",
                 why[0] ? why : "the rebase did not complete");
    return false;
}

/* A queue row, by seq, in the state it was read in with its tip unchanged. A
 * row that has left the file (terminal rows are dropped from it) is not. */
static bool dl_spec_row_same(const struct dl_row *rows, size_t n,
                             const struct dl_row *want, const char *state)
{
    for (size_t i = 0; i < n; i++)
        if (rows[i].seq == want->seq)
            return strcmp(rows[i].state, state) == 0 &&
                   strcmp(rows[i].tip, want->tip) == 0;
    return false;
}

/* The queue still holds the in-flight row, in flight on the same attempt with
 * the same (local, base), and every row of the pair as read. A row that is
 * gone, or changed, is a queue that moved. */
static bool dl_spec_current(const struct dl_spec *s)
{
    struct dl_row *rows = NULL;
    size_t n = 0;
    char qpath[4096 + 32];
    bool ok = snprintf(qpath, sizeof(qpath), "%s/queue.jsonl",
                       s->landing->land) < (int)sizeof(qpath) &&
              dl_load_rows(qpath, &rows, &n, NULL, 0);
    bool flight = false;
    for (size_t i = 0; ok && i < n; i++) {
        if (rows[i].seq != s->flight.seq)
            continue;
        flight = strcmp(rows[i].state, "inflight") == 0 &&
                 rows[i].attempt == s->flight.attempt &&
                 strcmp(rows[i].local, s->flight.local) == 0 &&
                 strcmp(rows[i].base, s->flight.base) == 0;
        break;
    }
    ok = ok && flight && dl_spec_row_same(rows, n, &s->head, "queued");
    for (size_t j = 0; ok && j < s->train.n; j++)
        ok = dl_spec_row_same(rows, n, &s->train.m[j], "queued");
    free(rows);
    return ok;
}

/* The pair: the stacked tip when the train formed, else the head's rebase;
 * its tree read back from the scratch worktree left at exactly that commit. */
static bool dl_spec_pair(struct dl_spec *s)
{
    char spec[96];
    const char *rp[] = { "rev-parse", "--verify", "--quiet", spec, NULL };
    (void)snprintf(s->local, sizeof(s->local), "%s",
                   s->train.n ? s->train.tip : s->head.local);
    (void)snprintf(s->base, sizeof(s->base), "%s", s->head.base);
    (void)snprintf(spec, sizeof(spec), "%s^{tree}", s->local);
    if (dl_train_checkout(&s->d, s->local) &&
        dl_git(s->d.wt, rp, s->tree, sizeof(s->tree), DL_GIT_TIMEOUT_MS) == 0) {
        s->tree[strcspn(s->tree, "\r\n")] = '\0';
        if (dl_sha_ok(s->tree))
            return true;
    }
    dl_spec_none(s, "rebase_failed",
                 "cannot read the tree of the predicted pair");
    return false;
}

static void dl_spec_bundle(struct dl_spec *s)
{
    static const char *const keys[] = { "bundle", "bundle_sha256", "offer" };
    char lane[64];
    struct zcl_command_reply *sub = zcl_calloc(1, sizeof(*sub),
                                               "dev.land.spec.bundle");
    json_init(&s->bundle);
    json_set_object(&s->bundle);
    if (!sub) {
        (void)json_push_kv_str(&s->bundle, "error", "out of memory");
        return;
    }
    (void)snprintf(lane, sizeof(lane), "spec-%lld", s->head.seq);
    zcl_command_reply_init(sub, "zcl.land.v1");
    if (zcl_dlr_bundle_pair(s->d.wt, s->local, s->base, s->args.bundle_out,
                            lane, sub)) {
        for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
            const char *v = json_get_str(json_get(&sub->data, keys[i]));
            if (v)
                (void)json_push_kv_str(&s->bundle, keys[i], v);
        }
    } else {
        (void)json_push_kv_str(&s->bundle, "error", sub->error.code);
        (void)json_push_kv_str(&s->bundle, "message", sub->error.message);
    }
    zcl_command_reply_free(sub);
    free(sub);
}

static void dl_spec_build(struct dl_spec *s, const struct dl_row *after,
                          size_t count)
{
    if (s->width >= 2 && dl_train_fresh(&s->head))
        (void)dl_train_stack_rows(&s->d, &s->head, &s->train, after, count,
                                  s->width, dl_rebase_pair);
    /* A stack cut short by the deadline would be a shorter train than the
     * driver forms: not a pair. */
    if (dl_budget_ms(1) == 0) {
        dl_spec_none(s, "budget_exhausted", "");
        return;
    }
    s->pair = dl_spec_pair(s);
    if (s->pair && !dl_spec_current(s)) {
        s->pair = false;
        dl_spec_none(s, "queue_moved",
                     "the in-flight row or a row of the pair changed or left "
                     "the queue while the pair was built");
    }
    if (s->pair && s->args.bundle_out)
        dl_spec_bundle(s);
}

static void dl_spec_run(struct dl_spec *s, const struct dl_row *rows, size_t n)
{
    size_t count = 0;
    struct dl_row *after = NULL;
    if (!dl_spec_flight(s, rows, n))
        return;
    after = dl_spec_after_landing(s, rows, n, &count);
    if (!after) {
        dl_spec_none(s, "rebase_failed", "out of memory");
        return;
    }
    if (dl_spec_head(s, after, count) && dl_spec_width(s) &&
        dl_spec_open(s) && dl_spec_rebase(s))
        dl_spec_build(s, after, count);
    free(after);
}

/* One row of the pair: its queue seq, its submitted tip, and its own commit in
 * the stacked history (the head's own is its rebase result). */
static void dl_spec_encode_row(struct json_value *rows,
                               const struct dl_row *row, const char *commit)
{
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    if (json_push_kv_str(&item, "tip", row->tip) &&
        json_push_kv_str(&item, "commit", commit))
        (void)json_push_kv_int(&item, "seq", row->seq);
    (void)json_push_back(rows, &item);
    json_free(&item);
}

static void dl_spec_encode_pair(const struct dl_spec *s,
                                struct json_value *out)
{
    struct json_value pair, rows;
    json_init(&pair);
    json_set_object(&pair);
    (void)json_push_kv_str(&pair, "local", s->local);
    (void)json_push_kv_str(&pair, "base", s->base);
    (void)json_push_kv_str(&pair, "tree", s->tree);
    (void)json_push_kv_bool(&pair, "unsigned", true);
    (void)json_push_kv_str(&pair, "identity",
                           "base and tree are exactly what the driver builds; "
                           "local and each commit are unsigned predictions "
                           "made with signing off, and a rebased commit "
                           "carries the time it is made, so the driver's own "
                           "commit ids differ: key on base and tree, never "
                           "on local");
    json_init(&rows);
    json_set_array(&rows);
    dl_spec_encode_row(&rows, &s->head, s->head.local);
    for (size_t j = 0; j < s->train.n; j++)
        dl_spec_encode_row(&rows, &s->train.m[j], s->train.commit[j]);
    (void)json_push_kv(&pair, "rows", &rows);
    json_free(&rows);
    (void)json_push_kv(out, "pair", &pair);
    json_free(&pair);
}

static void dl_spec_encode_flight(const struct dl_spec *s,
                                  struct json_value *out)
{
    struct json_value f;
    json_init(&f);
    json_set_object(&f);
    (void)json_push_kv_int(&f, "seq", s->flight.seq);
    (void)json_push_kv_str(&f, "phase", s->flight.phase);
    (void)json_push_kv_int(&f, "attempt", s->flight.attempt);
    (void)json_push_kv_str(&f, "local", s->flight.local);
    (void)json_push_kv_str(&f, "base", s->flight.base);
    (void)json_push_kv(out, "in_flight", &f);
    json_free(&f);
}

static void dl_spec_encode(const struct dl_spec *s, struct json_value *out)
{
    (void)json_push_kv_str(out, "schema", "zcl.land.speculative_pair.v1");
    (void)json_push_kv_str(out, "prediction",
                           "a prediction that holds only if the in-flight row "
                           "lands unchanged; discard it when the queue's "
                           "in-flight local or base differs from in_flight "
                           "below");
    (void)json_push_kv_str(out, "status", s->pair ? "pair" : "none");
    (void)json_push_kv_int(out, "train_width", (int64_t)s->width);
    (void)json_push_kv_str(out, "train_width_source",
                           s->width_source ? s->width_source : "none");
    if (s->flight_seen)
        dl_spec_encode_flight(s, out);
    if (s->pair)
        dl_spec_encode_pair(s, out);
    else {
        (void)json_push_kv_str(out, "reason", s->reason);
        (void)json_push_kv_str(out, "detail", s->detail);
    }
    if (s->bundle.type == JSON_OBJ)
        (void)json_push_kv(out, "bundle", &s->bundle);
}

void dl_train_speculate(const struct dl_dirs *d, const struct dl_row *rows,
                        size_t n, const struct dl_spec_args *args,
                        struct json_value *out)
{
    struct dl_spec *s = zcl_calloc(1, sizeof(*s), "dev.land.spec");
    if (!s) {
        (void)json_push_kv_str(out, "status", "none");
        (void)json_push_kv_str(out, "reason", "rebase_failed");
        (void)json_push_kv_str(out, "detail", "out of memory");
        return;
    }
    s->landing = d;
    s->args = *args;
    json_init(&s->bundle);
    /* Unsigned and hookless for every git child of this call, then the
     * budget: the sweep of a crashed call's scratch has its own. */
    dl_unsigned_scratch_set(true);
    dl_spec_scratch(s);
    dl_deadline_set(platform_time_monotonic_ms() +
                    (args->budget_ms > 0 ? args->budget_ms
                                         : DL_SPEC_BUDGET_MS));
    dl_spec_run(s, rows, n);
    dl_deadline_set(0);
    dl_spec_close(s);
    dl_unsigned_scratch_set(false);
    dl_spec_encode(s, out);
    json_free(&s->bundle);
    free(s);
}
