/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: opt-in land trains for dev.land: one exact proof covers up to
 *          ZCL_LAND_TRAIN_WIDTH queued rows stacked onto the head row's tip.
 *
 * ── LAND TRAINS ───────────────────────────────────────────────────────────
 *
 * WHY. Every row pays its own cold exact proof (about 5,400 CPU-seconds on
 * the shared lander) and rows prove one after another. Warm-object reuse
 * across rows stays refused, so the one lever left is fewer proofs per
 * landed row: rows per proof 1 -> up to ZCL_LAND_TRAIN_WIDTH.
 *
 * OFF BY DEFAULT. ZCL_LAND_TRAIN_WIDTH unset, "1" or anything but a single
 * digit 2..8 is today's behaviour exactly: one row, one proof, one push.
 *
 * WHAT. With width N, dl_train_intent_bind() runs where dl_start_proof used
 * to bind the proof intent. The head row is already prepared (rebase onto
 * origin main, regen, lint-land, deps). Up to N-1 joinable queued rows are
 * then stacked onto it in pick order, each rebased on the previous by the
 * ordinary dl_rebase(). A member that conflicts, or whose commits carry an
 * identity the push would refuse, is skipped: it stays queued, untouched,
 * and the train continues with the rest. Any other failure stops the
 * stacking. Regen, lint-land and the proof dependencies run again on the
 * stacked tip; if that fails the head's own commit is checked out again and
 * proved alone. The STACKED TIP is then bound as the head's proof pair and
 * every member's local, base, tree and proof_intent become that pair in one
 * queue rewrite, before the head persists it. Each member keeps its own
 * stacked commit in train_commit, which its outcome row then names.
 *
 * JOINABLE. A queued, unheld row on its first attempt with no predecessor,
 * no fence peer, no proof intent, no signature, no push in flight and no
 * train_solo mark. Held and cancelled rows are never stacked: the bind is
 * all or nothing and refuses a member that is no longer exactly the row
 * that was stacked.
 *
 * NEVER UNPROVEN. A row is published only inside the exact tree that
 * passed the proof: members carry the head's stacked tip as their own
 * local, and land through the existing reconcile path (a fresh fetch and a
 * check that this local is contained in origin main), never by a push of
 * their own. dl_train_gate() (inside dl_push_allowed) requires every bound
 * row to be live and unchanged and, once the head is signed, seals each
 * with its own bundle and signed intent: its own seq, the head's target and
 * proof digest. A composition that changed requeues the head to prove
 * alone; a pair that may already have been sent stays put, fail closed.
 *
 * RED TRAIN. A failed stacked proof says nothing about any one member, so
 * nobody fails with it. The head is requeued in place and the members are
 * released, all marked train_solo: a marked row never forms or joins a
 * train again, so each proves alone, in its original queue order, exactly
 * as without trains. No bisection.
 *
 * FENCES, HOLDS, CANCELS. A bound member cannot be cancelled or held until
 * its head's pair has landed and it records its own landing
 * (TRAIN_MEMBER_BOUND, dl_train_refuse_bound). A stale binding that no
 * live row and no landed outcome holds is cleared on the row's own turn by
 * dl_train_rebase(). Fenced rows and rows with a predecessor never join.
 *
 * STATUS. status lists each bound queued row's train_intent and
 * train_commit, and the in-flight row's train_members. */

#include "command/native_dev_land_internal.h"
#include "command/native_dev_land_regen.h"

#include "base/safe_alloc.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(ZCL_TESTING)
#include <unistd.h>
#endif

#define DL_TRAIN_MAX 8

struct dl_train {
    size_t n;
    char tip[80];
    struct dl_row m[DL_TRAIN_MAX - 1];
    char commit[DL_TRAIN_MAX - 1][80]; /* each member's commit in the stack */
};

static size_t dl_train_width(void)
{
    const char *s = getenv("ZCL_LAND_TRAIN_WIDTH");
    if (!s || s[0] < '2' || s[0] > '0' + DL_TRAIN_MAX || s[1])
        return 0;
    return (size_t)(s[0] - '0');
}

/* A row that may head a train or ride in one. */
static bool dl_train_fresh(const struct dl_row *r)
{
    return r->attempt == 1 && !r->train_solo && !r->predecessor_seq &&
           !r->fence_peer && !r->publication_hold;
}

static bool dl_train_joinable(const struct dl_row *r, const struct dl_row *head)
{
    return r->seq != head->seq && strcmp(r->state, "queued") == 0 &&
           dl_train_fresh(r) && !r->proof_intent[0] &&
           !r->publication_signature[0] && !r->pushed[0] &&
           !r->push_diagnostic_pending;
}

/* ── binding: is a queued row bound to a live train? ───────────────────── */

/* A queued row whose proof_intent is set was stacked into a train. That
 * binding is live while the head holds the same intent in flight, and
 * after the head landed until the member records its own landing. */
struct dl_train_landed_scan {
    const struct dl_row *member;
    bool found;
};

static bool dl_train_landed_visit(const struct dl_row *row, void *context)
{
    struct dl_train_landed_scan *s = context;
    if (row->seq != s->member->seq && strcmp(row->state, "landed") == 0 &&
        strcmp(row->proof_intent, s->member->proof_intent) == 0)
        s->found = true;
    return true;
}

/* Fail closed: an unreadable outcome history counts as bound. */
static bool dl_train_bound_live(const struct dl_dirs *d,
                                const struct dl_row *rows, size_t n,
                                const struct dl_row *member)
{
    char path[4096 + 32];
    struct dl_train_landed_scan scan = { member, false };
    if (strcmp(member->state, "queued") != 0 || !member->proof_intent[0])
        return false;
    for (size_t i = 0; i < n; i++)
        if (rows[i].seq != member->seq &&
            strcmp(rows[i].state, "inflight") == 0 &&
            strcmp(rows[i].proof_intent, member->proof_intent) == 0)
            return true;
    if (snprintf(path, sizeof(path), "%s/outcomes.jsonl", d->land) >=
        (int)sizeof(path))
        return true;
    return !dl_history_read(path, dl_train_landed_visit, &scan, NULL, 0) ||
           scan.found;
}

bool dl_train_refuse_bound(const struct dl_dirs *d, const struct dl_row *rows,
                           size_t n, const struct dl_row *member,
                           const char *stage, struct zcl_command_reply *reply)
{
    char evidence[256];
    if (!dl_train_bound_live(d, rows, n, member))
        return false;
    (void)snprintf(evidence, sizeof(evidence), "seq=%lld train_intent=%.120s",
                   member->seq, member->proof_intent);
    dl_fail(reply, "TRAIN_MEMBER_BOUND", stage,
            "this row rides in a train whose head is in flight or landed; "
            "the next step records it", evidence);
    (void)json_push_kv_int(&reply->data, "seq", member->seq);
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", "z23 dev land step");
    return true;
}

/* Clear a train binding the row's head no longer holds before the row's
 * own rebase: nothing downstream may read a pair this row did not prepare. */
int dl_train_rebase(const struct dl_dirs *d, struct dl_row *row,
                    const char *observed_main, char *why, size_t why_cap,
                    char *regen_note, size_t regen_note_cap)
{
    row->tree[0] = '\0';
    row->proof_intent[0] = '\0';
    row->train_commit[0] = '\0';
    dl_publication_clear(row);
    return dl_rebase(d, row, observed_main, why, why_cap, regen_note,
                     regen_note_cap);
}

/* ── queue edits ───────────────────────────────────────────────────────── */

/* Run `edit` over the live rows under queue.lock: it returns -1 to refuse,
 * 0 when nothing changed, 1 to rewrite the queue with its edits. */
static bool dl_rows_edit(const struct dl_dirs *d,
                         int (*edit)(struct dl_row *, size_t, void *),
                         void *context)
{
    struct dl_row *rows = NULL;
    size_t n = 0;
    char qpath[4096 + 32];
    int rc = -1;
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d->land) >=
        (int)sizeof(qpath))
        return false;
    int lock = dl_rows_lock(d->land);
    if (lock < 0)
        return false;
    if (dl_load_rows(qpath, &rows, &n, NULL, 0))
        rc = edit(rows, n, context);
    bool ok = rc == 0 || (rc > 0 && dl_rewrite_rows(d->land, qpath, rows, n));
    free(rows);
    dl_unlock(lock);
    return ok;
}

struct dl_train_unbind {
    const char *intent;
    long long head;
    bool solo;
    size_t count;
};

static int dl_train_unbind_edit(struct dl_row *rows, size_t n, void *context)
{
    struct dl_train_unbind *u = context;
    for (size_t i = 0; i < n; i++) {
        if (rows[i].seq == u->head || strcmp(rows[i].state, "queued") != 0 ||
            strcmp(rows[i].proof_intent, u->intent) != 0)
            continue;
        rows[i].local[0] = '\0';
        rows[i].base[0] = '\0';
        rows[i].tree[0] = '\0';
        rows[i].proof_intent[0] = '\0';
        rows[i].train_commit[0] = '\0';
        rows[i].train_solo = u->solo ? 1 : rows[i].train_solo;
        dl_publication_clear(&rows[i]);
        u->count++;
    }
    return u->count ? 1 : 0;
}

/* Release the queued rows bound to `intent`, never the head itself. */
void dl_train_unbind(const struct dl_dirs *d, const char *intent,
                     long long head, bool solo)
{
    struct dl_train_unbind u = { intent, head, solo, 0 };
    if (intent[0])
        (void)dl_rows_edit(d, dl_train_unbind_edit, &u);
}

static int dl_train_count_edit(struct dl_row *rows, size_t n, void *context)
{
    struct dl_train_unbind *u = context;
    for (size_t i = 0; i < n; i++)
        u->count += rows[i].seq != u->head &&
                    strcmp(rows[i].state, "queued") == 0 &&
                    strcmp(rows[i].proof_intent, u->intent) == 0;
    return 0;
}

/* Does any queued row ride in this row's proof pair? */
static bool dl_train_bound(const struct dl_dirs *d, const struct dl_row *row)
{
    struct dl_train_unbind u = { row->proof_intent, row->seq, false, 0 };
    return row->proof_intent[0] && dl_rows_edit(d, dl_train_count_edit, &u) &&
           u.count > 0;
}

/* ── red train: back to singles ────────────────────────────────────────── */

/* Requeue the head in place to prove alone, then release its members, all
 * marked train_solo: in that order, so no crash leaves the train pair live
 * without them. */
static void dl_train_requeue(const struct dl_dirs *d, struct dl_row *row,
                             const char *why, struct zcl_command_reply *reply)
{
    char intent[176];
    (void)snprintf(intent, sizeof(intent), "%s", row->proof_intent);
    dl_log(row, "train: ");
    dl_log(row, why);
    dl_log(row, "; every member proves alone next\n");
    row->train_solo = 1;
    row->train_commit[0] = '\0';
    (void)snprintf(row->state, sizeof(row->state), "queued");
    (void)snprintf(row->phase, sizeof(row->phase), "rebase");
    (void)snprintf(row->dimension, sizeof(row->dimension), "train");
    (void)snprintf(row->detail, sizeof(row->detail),
                   "train %.900s; seq=%lld proves alone next", why, row->seq);
    row->tree[0] = '\0';
    row->proof_intent[0] = '\0';
    dl_publication_clear(row);
    row->producer_recovered = 0;
    dl_log_path(d, row);
    if (!dl_commit_or_report(d, row, false, reply, "rebased"))
        return;
    dl_step_reply(reply, row, "rebased");
    dl_train_unbind(d, intent, row->seq, true);
}

/* A failed train proof is no verdict on the head alone: it proves alone
 * next, as do the members it carried. */
bool dl_train_fallback(const struct dl_dirs *d, struct dl_row *row,
                       const char *detail, struct zcl_command_reply *reply)
{
    char why[640];
    if (!dl_train_bound(d, row))
        return false;
    (void)snprintf(why, sizeof(why), "proof failed: %.600s", detail);
    dl_train_requeue(d, row, why, reply);
    return true;
}

/* ── stacking ──────────────────────────────────────────────────────────── */

static bool dl_train_checkout(const struct dl_dirs *d, const char *commit)
{
    const char *args[] = { "checkout", "--quiet", "--force", "--detach",
                           commit, NULL };
    return dl_sha_ok(commit) &&
           dl_git(d->wt, args, NULL, 0, DL_GIT_TIMEOUT_MS) == 0;
}

/* Rebase one queued row onto the stacked tip: 1 stacked, 0 skipped (it
 * stays queued, untouched), -1 stop stacking. */
static int dl_train_add(const struct dl_dirs *d, const struct dl_row *head,
                        struct dl_train *t, const struct dl_row *next)
{
    char why[512], note[256], line[800];
    struct dl_row m = *next, range = *head;
    (void)snprintf(m.log_path, sizeof(m.log_path), "%s", head->log_path);
    int rc = dl_rebase(d, &m, t->tip, why, sizeof(why), note, sizeof(note));
    if (rc > 0) {
        (void)snprintf(range.base, sizeof(range.base), "%s", t->tip);
        (void)snprintf(range.local, sizeof(range.local), "%s", m.local);
        if (!dl_push_identity_ok(d, &range)) {
            rc = 0;
            (void)snprintf(why, sizeof(why), "%s",
                           "a commit identity differs from user.email");
        }
    }
    (void)snprintf(line, sizeof(line), "train: seq=%lld %s%.600s\n",
                   next->seq, rc > 0 ? "stacked as " : rc == 0
                       ? "skipped and left queued: " : "stopped the train: ",
                   rc > 0 ? m.local : why);
    dl_log(head, line);
    if (rc <= 0)
        return rc;
    t->m[t->n] = *next;
    (void)snprintf(t->commit[t->n], sizeof(t->commit[0]), "%s", m.local);
    t->n++;
    (void)snprintf(t->tip, sizeof(t->tip), "%s", m.local);
    return 1;
}

/* The joinable row that lands first after `after`, in pick order. */
static const struct dl_row *dl_train_next(const struct dl_row *rows, size_t n,
                                          const struct dl_row *head,
                                          const struct dl_row *after)
{
    const struct dl_row *best = NULL;
    for (size_t i = 0; i < n; i++)
        if (dl_train_joinable(&rows[i], head) &&
            dl_queued_precedes(after, &rows[i]) &&
            dl_queued_precedes(&rows[i], best))
            best = &rows[i];
    return best;
}

/* Stack up to width-1 joinable rows onto the prepared head. Returns true
 * when any rebase ran, i.e. the worktree no longer holds the head. */
static bool dl_train_stack(const struct dl_dirs *d, const struct dl_row *head,
                           struct dl_train *t)
{
    struct dl_row *rows = NULL;
    size_t n = 0, width = dl_train_width();
    char qpath[4096 + 32];
    bool touched = false;
    (void)snprintf(t->tip, sizeof(t->tip), "%s", head->local);
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d->land) >=
        (int)sizeof(qpath))
        return false;
    int lock = dl_rows_lock(d->land);
    if (lock < 0)
        return false;
    bool loaded = dl_load_rows(qpath, &rows, &n, NULL, 0);
    dl_unlock(lock);
    const struct dl_row *after = head, *next;
    while (loaded && t->n + 1 < width &&
           (next = dl_train_next(rows, n, head, after)) != NULL) {
        after = next;
        touched = true;
        if (dl_train_add(d, head, t, next) < 0)
            break;
    }
    free(rows);
    return touched;
}

/* Regen, lint-land and the proof dependencies again, on the stacked tip.
 * A scratch row keeps the head's own detail and dimension untouched. When
 * regen amended the last member's commit, that commit is the amended one. */
static bool dl_train_prepare(const struct dl_dirs *d, const struct dl_row *head,
                             struct dl_train *t)
{
    char regen_head[80] = { 0 }, why[512] = { 0 };
    struct dl_row probe = *head;
    char *log = (char *)zcl_malloc(DL_LOG_CAP, "dev.land.train.regen");
    int rc = log ? zcl_dev_land_regen_phase(d->wt, head->base,
                                            t->m[t->n - 1].tip, regen_head,
                                            sizeof(regen_head), log,
                                            DL_LOG_CAP, why, sizeof(why))
                 : -1;
    if (log) {
        dl_log(head, log);
        free(log);
    }
    if (rc < 0 || !dl_sha_ok(regen_head)) {
        dl_log(head, "train: regen failed on the stacked tip\n");
        return false;
    }
    (void)snprintf(probe.local, sizeof(probe.local), "%s", regen_head);
    if (!dl_stubbed() && dl_lint_candidate(d, &probe) != 0) {
        dl_log(head, "train: lint-land failed on the stacked tip\n");
        return false;
    }
    if (!dl_wt_proof_deps_ensure(d, &probe, dl_stubbed(), why,
                                 sizeof(why))) {
        dl_log(head, "train: proof dependencies failed on the stacked tip\n");
        return false;
    }
    const char *kept[] = { "merge-base", "--is-ancestor", t->tip, regen_head,
                           NULL };
    if (strcmp(regen_head, t->tip) != 0 &&
        dl_git(d->wt, kept, NULL, 0, DL_GIT_TIMEOUT_MS) != 0)
        (void)snprintf(t->commit[t->n - 1], sizeof(t->commit[0]), "%s",
                       regen_head);
    (void)snprintf(t->tip, sizeof(t->tip), "%s", regen_head);
    return true;
}

struct dl_train_bind {
    const struct dl_row *head;
    const struct dl_train *t;
};

/* All or nothing: every member must still be the row that was stacked;
 * its commits are already in the tip, so none can be dropped alone. */
static int dl_train_bind_edit(struct dl_row *rows, size_t n, void *context)
{
    const struct dl_train_bind *b = context;
    size_t bound = 0;
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < b->t->n; j++) {
            if (rows[i].seq != b->t->m[j].seq)
                continue;
            if (!dl_train_joinable(&rows[i], b->head) ||
                strcmp(rows[i].tip, b->t->m[j].tip) != 0)
                return -1;
            (void)snprintf(rows[i].local, sizeof(rows[i].local), "%s",
                           b->head->local);
            (void)snprintf(rows[i].base, sizeof(rows[i].base), "%s",
                           b->head->base);
            (void)snprintf(rows[i].tree, sizeof(rows[i].tree), "%s",
                           b->head->tree);
            (void)snprintf(rows[i].proof_intent, sizeof(rows[i].proof_intent),
                           "%s", b->head->proof_intent);
            (void)snprintf(rows[i].train_commit,
                           sizeof(rows[i].train_commit), "%s",
                           b->t->commit[j]);
            bound++;
        }
    }
    return bound == b->t->n ? 1 : -1;
}

static void dl_train_log_bound(const struct dl_row *row,
                               const struct dl_train *t)
{
    char line[512];
    int used = snprintf(line, sizeof(line), "train: seq=%lld heads %zu rows "
                        "at %.40s:", row->seq, t->n + 1, row->local);
    for (size_t j = 0; j < t->n && used > 0 && (size_t)used < sizeof(line);
         j++)
        used += snprintf(line + used, sizeof(line) - (size_t)used, " %lld",
                         t->m[j].seq);
    dl_log(row, line);
    dl_log(row, "\n");
}

/* Stack, prepare and bind a train on the head's prepared tip. True when the
 * row now carries the stacked pair and every member is bound to it. */
static bool dl_train_form(const struct dl_dirs *d, struct dl_row *row,
                          struct dl_train *t, bool *touched)
{
    *touched = dl_train_stack(d, row, t);
    if (t->n == 0 || !dl_train_checkout(d, t->tip) ||
        !dl_train_prepare(d, row, t))
        return false;
    struct dl_train_bind b = { row, t };
    (void)snprintf(row->local, sizeof(row->local), "%s", t->tip);
    if (!dl_proof_intent_bind(d, row) ||
        !dl_rows_edit(d, dl_train_bind_edit, &b))
        return false;
#if defined(ZCL_TESTING)
    /* Hard death between the members' bind rewrite and the head's own
     * persist: the one window where members hold a pair no durable head
     * holds. */
    if (getenv("ZCL_LAND_TEST_DIE_AFTER_TRAIN_BIND"))
        _exit(83);
#endif
    dl_train_log_bound(row, t);
    return true;
}

/* The head's own commit back in the worktree, with its own proof inputs:
 * the stacked pass re-sealed the restart plan for the stacked tree. */
static bool dl_train_solo(const struct dl_dirs *d, struct dl_row *row,
                          const char *solo)
{
    char why[512] = { 0 };
    (void)snprintf(row->local, sizeof(row->local), "%s", solo);
    dl_log(row, "train: proving the head alone\n");
    if (dl_train_checkout(d, solo) &&
        dl_wt_proof_deps_ensure(d, row, dl_stubbed(), why, sizeof(why)))
        return true;
    dl_log(row, "train: cannot restore the head's own commit: ");
    dl_log(row, why);
    dl_log(row, "\n");
    return false;
}

bool dl_train_intent_bind(const struct dl_dirs *d, struct dl_row *row,
                          size_t *members)
{
    char solo[80];
    bool touched = false, formed;
    *members = 0;
    if (dl_train_width() < 2 || !dl_train_fresh(row))
        return dl_proof_intent_bind(d, row);
    struct dl_train *t = zcl_calloc(1, sizeof(*t), "dev.land.train");
    if (!t)
        return dl_proof_intent_bind(d, row);
    (void)snprintf(solo, sizeof(solo), "%s", row->local);
    formed = dl_train_form(d, row, t, &touched);
    *members = formed ? t->n : 0;
    free(t);
    if (formed) {
        (void)snprintf(row->train_commit, sizeof(row->train_commit), "%s", solo);
        return true;
    }
    if (touched && !dl_train_solo(d, row, solo))
        return false;
    (void)snprintf(row->local, sizeof(row->local), "%s", solo);
    return dl_proof_intent_bind(d, row);
}

/* ── the publication gate ──────────────────────────────────────────────── */

/* A bound member still exactly as the train bound it. */
static bool dl_train_member_intact(const struct dl_row *m,
                                   const struct dl_row *head)
{
    return strcmp(m->state, "queued") == 0 && dl_train_fresh(m) &&
           strcmp(m->local, head->local) == 0 &&
           strcmp(m->base, head->base) == 0 &&
           strcmp(m->tree, head->tree) == 0 && !m->pushed[0] &&
           !m->push_diagnostic_pending && dl_sha_ok(m->train_commit);
}

struct dl_train_view {
    const struct dl_row *head;
    struct dl_train *t;
    bool broken;
};

static int dl_train_view_edit(struct dl_row *rows, size_t n, void *context)
{
    struct dl_train_view *v = context;
    for (size_t i = 0; i < n; i++) {
        if (rows[i].seq == v->head->seq ||
            strcmp(rows[i].proof_intent, v->head->proof_intent) != 0)
            continue;
        if (!dl_train_member_intact(&rows[i], v->head) ||
            v->t->n >= DL_TRAIN_MAX - 1)
            v->broken = true;
        else
            v->t->m[v->t->n++] = rows[i];
    }
    return 0;
}

/* A terminal row of another candidate carrying the head's pair: a member
 * left the train. The same tip settled earlier under another seq (a
 * resubmission whose rebase was a no-op) is the head's own history. */
static bool dl_train_outcome_visit(const struct dl_row *row, void *context)
{
    struct dl_train_view *v = context;
    if (row->seq != v->head->seq && strcmp(row->tip, v->head->tip) != 0 &&
        strcmp(row->proof_intent, v->head->proof_intent) == 0)
        v->broken = true;
    return true;
}

static bool dl_train_view_read(const struct dl_dirs *d,
                               struct dl_train_view *v)
{
    char path[4096 + 32];
    return dl_rows_edit(d, dl_train_view_edit, v) &&
           snprintf(path, sizeof(path), "%s/outcomes.jsonl", d->land) <
               (int)sizeof(path) &&
           dl_history_read(path, dl_train_outcome_visit, v, NULL, 0);
}

static void dl_train_copy_seal(struct dl_row *to, const struct dl_row *from)
{
    (void)snprintf(to->publication_target, sizeof(to->publication_target),
                   "%s", from->publication_target);
    (void)snprintf(to->publication_proof, sizeof(to->publication_proof),
                   "%s", from->publication_proof);
    (void)snprintf(to->publication_bundle, sizeof(to->publication_bundle),
                   "%s", from->publication_bundle);
    (void)snprintf(to->publication_signer, sizeof(to->publication_signer),
                   "%s", from->publication_signer);
    (void)snprintf(to->publication_signature,
                   sizeof(to->publication_signature), "%s",
                   from->publication_signature);
}

/* Persist every member's seal in one rewrite; a member that changed since
 * it was read refuses the whole rewrite. */
static int dl_train_seal_edit(struct dl_row *rows, size_t n, void *context)
{
    const struct dl_train_view *v = context;
    size_t sealed = 0;
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < v->t->n; j++) {
            const struct dl_row *m = &v->t->m[j];
            if (rows[i].seq != m->seq)
                continue;
            if (!dl_train_member_intact(&rows[i], v->head) ||
                strcmp(rows[i].proof_intent, m->proof_intent) != 0 ||
                (rows[i].publication_signature[0] &&
                 strcmp(rows[i].publication_signature,
                        m->publication_signature) != 0))
                return -1;
            dl_train_copy_seal(&rows[i], m);
            sealed++;
        }
    }
    return sealed == v->t->n ? 1 : -1;
}

static bool dl_train_seal(const struct dl_dirs *d, struct dl_train_view *v)
{
    for (size_t j = 0; j < v->t->n; j++)
        if (!dl_train_seal_member(d, v->head, &v->t->m[j]))
            return false;
    return dl_rows_edit(d, dl_train_seal_edit, v);
}

/* A train whose composition changed is never published. Before any send
 * the head is requeued to prove alone; a pair that may already have been
 * sent stays put, fail closed, for the operator. */
static void dl_train_broken(const struct dl_dirs *d, struct dl_row *row,
                            struct zcl_command_reply *reply)
{
    if (strcmp(row->phase, "push") != 0 && !row->push_diagnostic_pending) {
        dl_train_requeue(d, row, "composition changed before publication",
                         reply);
        return;
    }
    dl_fail(reply, "TRAIN_COMPOSITION_BROKEN", "publication",
            "a row bound to this train changed; the pair is never published",
            row->proof_intent);
}

bool dl_train_gate(const struct dl_dirs *d, struct dl_row *row,
                   struct zcl_command_reply *reply)
{
    if (!row->proof_intent[0])
        return true;
    struct dl_train *t = zcl_calloc(1, sizeof(*t), "dev.land.train.gate");
    struct dl_train_view v = { row, t, false };
    bool read = t && dl_train_view_read(d, &v);
    bool ok = read && !v.broken &&
              (!t->n || !row->publication_signature[0] || dl_train_seal(d, &v));
    if (!read)
        dl_fail(reply, "QUEUE_READ_FAILED", "publication",
                "cannot read the rows bound to this pair; publication refused",
                "queue.jsonl or outcomes.jsonl");
    else if (v.broken)
        dl_train_broken(d, row, reply);
    else if (!ok)
        dl_fail(reply, "PUBLICATION_INTENT_INVALID", "push_intent",
                "cannot seal every train member under its own landing intent",
                row->proof_intent);
    free(t);
    return ok;
}

/* ── status ────────────────────────────────────────────────────────────── */

void dl_train_status(struct json_value *inflight, const struct dl_row *rows,
                     size_t n)
{
    const struct dl_row *head = NULL;
    struct json_value members, item;
    for (size_t i = 0; i < n && !head; i++)
        if (strcmp(rows[i].state, "inflight") == 0)
            head = &rows[i];
    if (!head || !head->proof_intent[0])
        return;
    json_init(&members);
    json_set_array(&members);
    for (size_t i = 0; i < n; i++) {
        if (rows[i].seq == head->seq || strcmp(rows[i].state, "queued") != 0 ||
            strcmp(rows[i].proof_intent, head->proof_intent) != 0)
            continue;
        json_init(&item);
        json_set_int(&item, rows[i].seq);
        (void)json_push_back(&members, &item);
        json_free(&item);
    }
    if (members.num_children)
        (void)json_push_kv(inflight, "train_members", &members);
    json_free(&members);
}
