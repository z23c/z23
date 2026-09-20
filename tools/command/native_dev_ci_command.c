/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.ci — one read-only screen over this host's CI and landing
 *          state, composed entirely from the leaves that already own it.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. Answering "what is this box doing, and did my commit pass" costs an
 * operator four different leaves today: dev.land for the landing queue,
 * dev.agent.queue for unit dispatch, dev.proof for a receipt that must be
 * addressed by an exact (local_commit, remote_base) PAIR, and nothing at
 * all for whether a worker is alive. This leaf is the one command that
 * answers all nine operator questions — status, queue, jobs, last pass,
 * last fail, worker, receipt, cancel, retry — over exactly that state.
 *
 * HOW IT COMPOSES. Every fact comes from a sibling leaf called in-process
 * with the caller's own context, exactly as dispatch would after input
 * validation: dev.land (action=status) for the landing queue, the in-flight
 * row and the last outcomes; dev.agent.queue (action=status) for queued and
 * running units, the pool and unit outcomes; dev.proof.status for one exact
 * pair's validated receipt verdict. Each sibling validates its own input and
 * enforces its own permissions. Nothing here re-implements their stores.
 *
 * NO NEW STATE. This leaf creates no file, directory, lock, ledger or cursor
 * anywhere. The only path it reads directly is the proof cache's own receipt
 * directory, <root>/.cache/zcl-dev-proof/receipts, and it reads it solely to
 * DISCOVER which (local_commit, remote_base) pairs exist for a commit —
 * every verdict still comes from dev.proof.status, which validates the seal
 * and the signature. Discovery is not admission.
 *
 * READ-ONLY, INCLUDING THE TWO MUTATING VIEWS. `cancel` and `retry` NAME the
 * exact existing command to run — `dev land cancel --seq=<n>`,
 * `dev agent queue cancel --name=<n>`, `dev proof retry --local_commit=<c>
 * --remote_base=<b>` — and run nothing. There is no second mutation path
 * through this leaf, and no view of it takes a lock.
 *
 * FAIL-CLOSED. Missing evidence is never a pass and never a zero.
 *   - A sibling that did not answer is recorded in sources[] with its reason
 *     and its measured age; the views it fed report "unknown", never empty.
 *   - Worker state uses the queue owner's PID and kernel birth token as
 *     well as claim age and claimant name. A dead owner with an unreaped
 *     claim is blocked; missing owner evidence is unknown; an old claim
 *     is stale. A fresh claim is executing only while its exact owner is
 *     running. Zero claims remain unknown, never assumed idle.
 *   - A commit with no receipt reports verdict "unknown" with reason
 *     "no_receipt_for_commit". It never reports a pass.
 *   - A failing landing outcome whose remote base cannot be resolved from
 *     recorded state reports base "unknown" and emits NO retry command,
 *     rather than guessing a base.
 *
 * INPUT (zcl.dev_ci_input.v1)
 *   topic optional, also the first positional: which of the nine views to
 *         render. One of status (default), queue, jobs, last_pass,
 *         last_fail, worker, receipt, cancel, retry. Hyphens read the same
 *         as underscores. It is named `topic` and not `view` because the
 *         kernel reserves `view` for the projection (summary|normal|full).
 *   sha   receipt view, required: the commit to look a receipt up for. 7 to
 *         40 hex characters; a prefix matches.
 *   root  optional checkout whose proof cache is read. Default: the request
 *         context's source root, else ZCL_DEV_SOURCE_ROOT, else ".".
 *   json  optional bool: drop the human screen.
 *
 * OUTPUT (zcl.dev_ci.v1): leaf, view, sources[], the view's own object, and
 * `screen` unless json=true.
 *
 * PROCESS RULE. No spawn, no shell, no popen()/system(), no sleep, no poll
 * loop, no network. In-process sibling calls and one directory listing.
 */

#include "command/native_command.h"
#include "command/native_dev_proof_command.h"

#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/clock.h"
#include "platform/directory_compat.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DCI_LEAF "dev.ci"
#define DCI_SCHEMA "zcl.dev_ci.v1"
#define DCI_SCREEN_CAP 16384u
#define DCI_VIEW_MAX 32u
#define DCI_SHA_MIN 7u
#define DCI_SHA_MAX 40u
#define DCI_ROOT_MAX 4096u
#define DCI_PATH_MAX (DCI_ROOT_MAX + 128u)
#define DCI_PAIR_CAP 8u
#define DCI_LIST_CAP 32u
#define DCI_CMD_MAX 256u
/* A claim this old is not evidence that a worker is alive. A resident
 * worker's own job cap is far under an hour, so an older claim means the
 * drive died holding it. */
#define DCI_WORKER_STALE_S 3600

/* ── views ───────────────────────────────────────────────────────────────── */

enum dci_view {
    DCI_VIEW_STATUS = 0,
    DCI_VIEW_QUEUE,
    DCI_VIEW_JOBS,
    DCI_VIEW_LAST_PASS,
    DCI_VIEW_LAST_FAIL,
    DCI_VIEW_WORKER,
    DCI_VIEW_RECEIPT,
    DCI_VIEW_CANCEL,
    DCI_VIEW_RETRY,
    DCI_VIEW_UNKNOWN
};

static const char *const dci_view_names[] = {
    "status", "queue", "jobs", "last_pass", "last_fail",
    "worker", "receipt", "cancel", "retry"
};

/* Hyphens read the same as underscores so `--topic=last-fail` is not a
 * refusal an operator has to learn about. */
static void dci_normalize_view(const char *in, char *out, size_t cap)
{
    size_t n = 0;
    out[0] = '\0';
    for (; in && in[n] && n + 1 < cap; n++)
        out[n] = (in[n] == '-') ? '_' : (char)tolower((unsigned char)in[n]);
    if (n + 1 <= cap)
        out[n] = '\0';
}

static enum dci_view dci_view_of(const char *name)
{
    char norm[DCI_VIEW_MAX];
    if (!name || !name[0])
        return DCI_VIEW_STATUS;
    dci_normalize_view(name, norm, sizeof(norm));
    for (size_t i = 0; i < sizeof(dci_view_names) / sizeof(dci_view_names[0]);
         i++) {
        if (strcmp(norm, dci_view_names[i]) == 0)
            return (enum dci_view)i;
    }
    return DCI_VIEW_UNKNOWN;
}

/* ── screen buffer ───────────────────────────────────────────────────────── */

struct dci_screen {
    char *at;
    size_t left;
};

static void dci_say(struct dci_screen *s, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

static void dci_say(struct dci_screen *s, const char *format, ...)
{
    va_list args;
    int n;
    if (!s || s->left <= 1)
        return;
    va_start(args, format);
    n = vsnprintf(s->at, s->left, format, args);
    va_end(args);
    if (n < 0)
        return;
    if ((size_t)n >= s->left)
        n = (int)s->left - 1;
    s->at += n;
    s->left -= (size_t)n;
}

/* ── small JSON readers ──────────────────────────────────────────────────── */

static const char *dci_str(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return (v && v->type == JSON_STR) ? json_get_str(v) : "";
}

static long long dci_int(const struct json_value *obj, const char *key,
                         long long fallback)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return (v && v->type == JSON_INT) ? (long long)json_get_int(v) : fallback;
}

static const struct json_value *dci_arr(const struct json_value *obj,
                                        const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return (v && v->type == JSON_ARR) ? v : NULL;
}

static size_t dci_count(const struct json_value *arr)
{
    return arr ? json_size(arr) : 0;
}

/* ── in-process sibling calls ────────────────────────────────────────────── */

struct dci_sub {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
    bool ran;
    bool valid;
    bool ok;
    char why[48];
    long long age_ms;
};

static void dci_sub_begin(struct dci_sub *s, const char *schema,
                          const struct zcl_command_request *parent,
                          const char *sibling)
{
    memset(s, 0, sizeof(*s));
    json_init(&s->input);
    json_set_object(&s->input);
    s->request.input = &s->input;
    if (parent)
        s->request.context = parent->context;
    s->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), sibling, NULL);
    s->request.view = "normal";
    zcl_command_reply_init(&s->reply, schema);
    s->valid = s->request.spec != NULL;
    (void)snprintf(s->why, sizeof(s->why), "%s", "unknown_sibling");
}

static void dci_sub_end(struct dci_sub *s)
{
    zcl_command_reply_free(&s->reply);
    json_free(&s->input);
    s->ran = false;
}

static bool dci_sub_input(struct dci_sub *s, const char *text)
{
    struct json_value parsed;
    json_init(&parsed);
    if (!json_read(&parsed, text, strlen(text))) {
        json_free(&parsed);
        (void)snprintf(s->why, sizeof(s->why), "%s", "input_encode");
        return false;
    }
    json_free(&s->input);
    s->input = parsed;
    s->request.input = &s->input;
    return true;
}

/* Run one sibling handler and record whether it answered. A refusal is a
 * measured absence, never an error here: the caller reports it. */
static void dci_sub_run(struct dci_sub *s, zcl_command_handler_fn handler)
{
    long long t0, t1;
    if (!s->valid || !handler)
        return;
    t0 = clock_now_wall_ms();
    handler(&s->request, &s->reply);
    t1 = clock_now_wall_ms();
    s->ran = true;
    s->age_ms = t1 - t0;
    if (s->reply.status == ZCL_COMMAND_STATUS_PASSED) {
        s->ok = true;
        s->why[0] = '\0';
    } else {
        (void)snprintf(s->why, sizeof(s->why), "%s", "sibling_refused");
    }
}

static void dci_note_source(struct json_value *sources, const char *name,
                            const struct dci_sub *s)
{
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    if (json_push_kv_str(&item, "leaf", name) &&
        json_push_kv_bool(&item, "answered", s->ok) &&
        json_push_kv_str(&item, "reason", s->ok ? "" : s->why) &&
        json_push_kv_int(&item, "age_ms", s->age_ms))
        (void)json_push_back(sources, &item);
    json_free(&item);
}

/* ── the two composed sources ────────────────────────────────────────────── */

struct dci_state {
    struct dci_sub land;
    struct dci_sub queue;
    char root[DCI_ROOT_MAX];
};

/* Both sources, read once per invocation. The sibling's handler is called by
 * symbol rather than through spec->handler because a dev-only leaf's handler
 * pointer is deliberately NULL in a release-shaped binary; the spec is still
 * what the sibling reads for projection and paging, so it is still attached.
 * A sibling that refuses leaves its view unknown, never empty. */
static void dci_state_load(struct dci_state *st,
                           const struct zcl_command_request *req)
{
    dci_sub_begin(&st->land, "zcl.land.v1", req, "dev.land");
    if (st->land.valid &&
        dci_sub_input(&st->land, "{\"action\":\"status\",\"json\":true}"))
        dci_sub_run(&st->land, zcl_native_handle_dev_land);
    dci_sub_begin(&st->queue, "zcl.agent_queue.v1", req, "dev.agent.queue");
    if (st->queue.valid &&
        dci_sub_input(&st->queue, "{\"action\":\"status\",\"json\":true}"))
        dci_sub_run(&st->queue, zcl_native_handle_dev_agent_queue);
}

static void dci_state_free(struct dci_state *st)
{
    dci_sub_end(&st->land);
    dci_sub_end(&st->queue);
}

static const struct json_value *dci_land(const struct dci_state *st)
{
    return st->land.ok ? &st->land.reply.data : NULL;
}

static const struct json_value *dci_queue(const struct dci_state *st)
{
    return st->queue.ok ? &st->queue.reply.data : NULL;
}

/* ── land outcome classification ─────────────────────────────────────────── */

static bool dci_land_passed(const struct json_value *row)
{
    return strcmp(dci_str(row, "state"), "landed") == 0;
}

static bool dci_land_failed(const struct json_value *row)
{
    const char *state = dci_str(row, "state");
    return state[0] && strcmp(state, "landed") != 0 &&
           strcmp(state, "cancelled") != 0;
}

static bool dci_unit_passed(const struct json_value *row)
{
    const char *verdict = dci_str(row, "verdict");
    if (dci_int(row, "rc", -1) != 0)
        return false;
    return strcmp(verdict, "pass") == 0 || strcmp(verdict, "PASS") == 0;
}

/* Newest matching row, or NULL. dev.land and dev.agent.queue both render
 * their outcome arrays oldest-first, so the newest match is the last. */
static const struct json_value *dci_newest(const struct json_value *arr,
                                           bool (*want)(const struct json_value *))
{
    size_t n = dci_count(arr);
    for (size_t i = n; i > 0; i--) {
        const struct json_value *row = json_at(arr, i - 1);
        if (row && row->type == JSON_OBJ && want(row))
            return row;
    }
    return NULL;
}

/* ── worker health ───────────────────────────────────────────────────────── */

struct dci_worker {
    bool measured;
    long long claims;
    long long named;
    long long stale;
    long long live;
    long long dead;
    long long unverified;
    long long oldest_s;
    char state[16];
    char reason[48];
};

static void dci_worker_tally(const struct json_value *running,
                             struct dci_worker *w)
{
    size_t n = dci_count(running);
    for (size_t i = 0; i < n; i++) {
        const struct json_value *row = json_at(running, i);
        const struct json_value *who = row ? json_get(row, "worker") : NULL;
        const char *owner = dci_str(row, "owner_liveness");
        long long age = dci_int(row, "age_s", -1);
        w->claims++;
        if (who && who->type == JSON_STR && json_get_str(who)[0])
            w->named++;
        if (age > w->oldest_s)
            w->oldest_s = age;
        if (age < 0 || age > DCI_WORKER_STALE_S)
            w->stale++;
        if (strcmp(owner, "running") == 0)
            w->live++;
        else if (strcmp(owner, "dead") == 0)
            w->dead++;
        else
            w->unverified++;
    }
}

/* The verdict over the tally. A claim is the only thing a worker writes that
 * proves it was alive, so absence of one is unknown, never healthy. */
static void dci_worker_verdict(struct dci_worker *w)
{
    if (w->claims == 0) {
        (void)snprintf(w->state, sizeof(w->state), "%s", "unknown");
        (void)snprintf(w->reason, sizeof(w->reason), "%s",
                       "no_worker_claim_observed");
    } else if (w->stale > 0) {
        (void)snprintf(w->state, sizeof(w->state), "%s", "stale");
        (void)snprintf(w->reason, sizeof(w->reason),
                       "claim_older_than_%ds", DCI_WORKER_STALE_S);
    } else if (w->named != w->claims) {
        (void)snprintf(w->state, sizeof(w->state), "%s", "unknown");
        (void)snprintf(w->reason, sizeof(w->reason), "%s",
                       "claim_names_no_worker");
    } else if (w->dead > 0) {
        (void)snprintf(w->state, sizeof(w->state), "%s", "blocked");
        (void)snprintf(w->reason, sizeof(w->reason), "%s",
                       "owner_exited_before_reap");
    } else if (w->unverified > 0) {
        (void)snprintf(w->state, sizeof(w->state), "%s", "unknown");
        (void)snprintf(w->reason, sizeof(w->reason), "%s",
                       "owner_liveness_unverified");
    } else {
        (void)snprintf(w->state, sizeof(w->state), "%s", "executing");
        w->reason[0] = '\0';
    }
}

static void dci_worker_read(const struct dci_state *st, struct dci_worker *w)
{
    const struct json_value *queue = dci_queue(st);
    memset(w, 0, sizeof(*w));
    w->oldest_s = -1;
    if (!queue) {
        (void)snprintf(w->state, sizeof(w->state), "%s", "unknown");
        (void)snprintf(w->reason, sizeof(w->reason), "%s",
                       "dev.agent.queue_unreadable");
        return;
    }
    w->measured = true;
    dci_worker_tally(dci_arr(queue, "running"), w);
    dci_worker_verdict(w);
}

static void dci_worker_emit(struct json_value *out, const struct dci_worker *w)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    (void)json_push_kv_str(&obj, "state", w->state);
    (void)json_push_kv_str(&obj, "reason", w->reason);
    (void)json_push_kv_bool(&obj, "measured", w->measured);
    (void)json_push_kv_int(&obj, "stale_threshold_s", DCI_WORKER_STALE_S);
    /* Counts only when they were measured: an unread queue reports no
     * numbers rather than a zero that reads like an idle host. */
    if (w->measured) {
        (void)json_push_kv_int(&obj, "claims", w->claims);
        (void)json_push_kv_int(&obj, "named_claims", w->named);
        (void)json_push_kv_int(&obj, "stale_claims", w->stale);
        (void)json_push_kv_int(&obj, "live_claims", w->live);
        (void)json_push_kv_int(&obj, "dead_claims", w->dead);
        (void)json_push_kv_int(&obj, "unverified_claims", w->unverified);
        (void)json_push_kv_int(&obj, "oldest_claim_s", w->oldest_s);
    }
    (void)json_push_kv(out, "worker", &obj);
    json_free(&obj);
}

/* ── receipt lookup by commit ────────────────────────────────────────────── */

struct dci_pair {
    char local[DCI_SHA_MAX + 1];
    char base[DCI_SHA_MAX + 1];
    char source[24];
};

static bool dci_hex(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (!isxdigit((unsigned char)s[i]))
            return false;
    }
    return true;
}

/* Lowercase the operator's sha so a prefix compare against the cache's own
 * lowercase file names is exact. Returns false for anything that is not
 * 7..40 hex characters. */
static bool dci_sha_normalize(const char *in, char *out, size_t cap)
{
    size_t n = in ? strlen(in) : 0;
    if (n < DCI_SHA_MIN || n > DCI_SHA_MAX || n + 1 > cap || !dci_hex(in, n))
        return false;
    for (size_t i = 0; i < n; i++)
        out[i] = (char)tolower((unsigned char)in[i]);
    out[n] = '\0';
    return true;
}

/* "<local>-<base>.receipt" -> the pair. Commit ids carry no '-', so the
 * first one separates. False for any other name. */
static bool dci_pair_from_name(const char *name, struct dci_pair *out)
{
    const char *dash = name ? strchr(name, '-') : NULL;
    const char *dot;
    size_t llen, blen;
    if (!dash)
        return false;
    dot = strstr(dash + 1, ".receipt");
    if (!dot || dot[8] != '\0')
        return false;
    llen = (size_t)(dash - name);
    blen = (size_t)(dot - (dash + 1));
    if (llen < DCI_SHA_MIN || llen > DCI_SHA_MAX || !dci_hex(name, llen))
        return false;
    if (blen < DCI_SHA_MIN || blen > DCI_SHA_MAX || !dci_hex(dash + 1, blen))
        return false;
    memcpy(out->local, name, llen);
    out->local[llen] = '\0';
    memcpy(out->base, dash + 1, blen);
    out->base[blen] = '\0';
    (void)snprintf(out->source, sizeof(out->source), "%s", "receipt_cache");
    return true;
}

static bool dci_pair_known(const struct dci_pair *pairs, size_t n,
                           const struct dci_pair *want)
{
    for (size_t i = 0; i < n; i++) {
        if (strcmp(pairs[i].local, want->local) == 0 &&
            strcmp(pairs[i].base, want->base) == 0)
            return true;
    }
    return false;
}

/* Every receipt the proof cache holds for a commit prefix. This only
 * DISCOVERS pairs; the verdict for each still comes from dev.proof.status. */
static size_t dci_pairs_from_cache(const char *root, const char *sha,
                                   struct dci_pair *pairs, size_t cap,
                                   char *why, size_t why_cap)
{
    struct platform_directory_list files = {0};
    char dir[DCI_PATH_MAX];
    size_t found = 0, sha_len = strlen(sha);
    if (snprintf(dir, sizeof(dir), "%s/.cache/zcl-dev-proof/receipts", root) >=
        (int)sizeof(dir)) {
        (void)snprintf(why, why_cap, "%s", "receipt_dir_path_too_long");
        return 0;
    }
    if (!platform_directory_list_regular_sorted(dir, &files)) {
        (void)snprintf(why, why_cap, "%s", "receipt_dir_unreadable");
        return 0;
    }
    for (size_t i = 0; i < files.count && found < cap; i++) {
        struct dci_pair pair;
        const char *name = files.entries[i].name;
        if (!name || strncmp(name, sha, sha_len) != 0)
            continue;
        if (!dci_pair_from_name(name, &pair))
            continue;
        if (!dci_pair_known(pairs, found, &pair))
            pairs[found++] = pair;
    }
    platform_directory_list_free(&files);
    return found;
}

/* The landing queue's in-flight row binds a tip to the base it is being
 * rebased onto, which is the one pair that exists before any receipt file
 * does. */
static size_t dci_pairs_from_land(const struct dci_state *st, const char *sha,
                                  struct dci_pair *pairs, size_t found,
                                  size_t cap)
{
    const struct json_value *land = dci_land(st);
    const struct json_value *row = land ? json_get(land, "in_flight") : NULL;
    struct dci_pair pair;
    const char *tip, *base;
    if (!row || row->type != JSON_OBJ || found >= cap)
        return found;
    tip = dci_str(row, "tip");
    base = dci_str(row, "base");
    if (strncmp(tip, sha, strlen(sha)) != 0 || !base[0])
        return found;
    if (strlen(tip) > DCI_SHA_MAX || strlen(base) > DCI_SHA_MAX)
        return found;
    (void)snprintf(pair.local, sizeof(pair.local), "%s", tip);
    (void)snprintf(pair.base, sizeof(pair.base), "%s", base);
    (void)snprintf(pair.source, sizeof(pair.source), "%s", "land_in_flight");
    if (!dci_pair_known(pairs, found, &pair))
        pairs[found++] = pair;
    return found;
}

/* One pair's validated verdict, asked of dev.proof.status. A sibling that
 * refuses (no dev build, unresolvable root, tampered receipt) yields
 * "unknown" with its reason — never a pass. */
static void dci_pair_verdict(const struct zcl_command_request *req,
                             const char *root, const struct dci_pair *pair,
                             char *verdict, size_t verdict_cap,
                             char *reason, size_t reason_cap)
{
    struct dci_sub sub;
    char input[DCI_PATH_MAX + 256];
    (void)snprintf(verdict, verdict_cap, "%s", "unknown");
    dci_sub_begin(&sub, "zcl.dev_proof_status.v1", req, "dev.proof.status");
    (void)snprintf(reason, reason_cap, "%s", sub.why);
    if (!sub.valid) {
        dci_sub_end(&sub);
        return;
    }
    if (snprintf(input, sizeof(input),
                 "{\"root\":\"%s\",\"local_commit\":\"%s\","
                 "\"remote_base\":\"%s\"}", root, pair->local, pair->base) >=
        (int)sizeof(input)) {
        (void)snprintf(reason, reason_cap, "%s", "input_encode");
        dci_sub_end(&sub);
        return;
    }
    if (dci_sub_input(&sub, input))
        dci_sub_run(&sub, zcl_native_dev_proof_dispatch);
    if (sub.ok) {
        (void)snprintf(verdict, verdict_cap, "%s",
                       dci_str(&sub.reply.data, "status"));
        reason[0] = '\0';
    } else {
        (void)snprintf(reason, reason_cap, "%s", sub.why);
    }
    dci_sub_end(&sub);
}

static void dci_pair_emit(struct json_value *arr,
                          const struct zcl_command_request *req,
                          const char *root, const struct dci_pair *pair)
{
    struct json_value item;
    char verdict[32], reason[48], retry[DCI_CMD_MAX];
    dci_pair_verdict(req, root, pair, verdict, sizeof(verdict), reason,
                     sizeof(reason));
    /* dev.proof.retry refuses a pair that already passed, so a passed pair
     * is offered no command rather than one that would be refused. */
    if (strcmp(verdict, "passed") == 0)
        retry[0] = '\0';
    else
        (void)snprintf(retry, sizeof(retry),
                       "dev proof retry --local_commit=%s --remote_base=%s",
                       pair->local, pair->base);
    json_init(&item);
    json_set_object(&item);
    if (json_push_kv_str(&item, "local_commit", pair->local) &&
        json_push_kv_str(&item, "remote_base", pair->base) &&
        json_push_kv_str(&item, "found_via", pair->source) &&
        json_push_kv_str(&item, "verdict", verdict[0] ? verdict : "unknown") &&
        json_push_kv_str(&item, "reason", reason) &&
        json_push_kv_str(&item, "retry_command", retry))
        (void)json_push_back(arr, &item);
    json_free(&item);
}

/* ── view: receipt ───────────────────────────────────────────────────────── */

static void dci_view_receipt(const struct zcl_command_request *req,
                             const struct dci_state *st,
                             struct zcl_command_reply *reply,
                             struct dci_screen *scr, const char *sha)
{
    struct dci_pair pairs[DCI_PAIR_CAP];
    struct json_value arr;
    char why[48] = {0};
    size_t found;
    found = dci_pairs_from_cache(st->root, sha, pairs, DCI_PAIR_CAP, why,
                                 sizeof(why));
    found = dci_pairs_from_land(st, sha, pairs, found, DCI_PAIR_CAP);
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < found; i++)
        dci_pair_emit(&arr, req, st->root, &pairs[i]);
    (void)json_push_kv_str(&reply->data, "commit", sha);
    (void)json_push_kv_str(&reply->data, "root", st->root);
    (void)json_push_kv_int(&reply->data, "found", (long long)found);
    (void)json_push_kv_str(&reply->data, "reason",
                           found ? "" : (why[0] ? why : "no_receipt_for_commit"));
    (void)json_push_kv(&reply->data, "receipts", &arr);
    dci_say(scr, "receipt for %s (root %s)\n", sha, st->root);
    if (found == 0)
        dci_say(scr, "  UNKNOWN: no receipt for this commit (%s)\n",
                why[0] ? why : "no_receipt_for_commit");
    for (size_t i = 0; i < json_size(&arr); i++) {
        const struct json_value *row = json_at(&arr, i);
        dci_say(scr, "  %.12s onto %.12s: %s%s%s [%s]\n",
                dci_str(row, "local_commit"), dci_str(row, "remote_base"),
                dci_str(row, "verdict"),
                dci_str(row, "reason")[0] ? " " : "", dci_str(row, "reason"),
                dci_str(row, "found_via"));
    }
    json_free(&arr);
}

/* ── view: queue ─────────────────────────────────────────────────────────── */

static void dci_copy_rows(struct json_value *dst, const struct json_value *src,
                          size_t cap)
{
    size_t n = dci_count(src);
    for (size_t i = 0; i < n && i < cap; i++) {
        const struct json_value *row = json_at(src, i);
        if (row)
            (void)json_push_back(dst, row);
    }
}

static void dci_emit_rows(struct zcl_command_reply *reply, const char *key,
                          const struct json_value *src)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    dci_copy_rows(&arr, src, DCI_LIST_CAP);
    (void)json_push_kv(&reply->data, key, &arr);
    json_free(&arr);
}

static void dci_view_queue(const struct dci_state *st,
                           struct zcl_command_reply *reply,
                           struct dci_screen *scr)
{
    const struct json_value *land = dci_land(st), *queue = dci_queue(st);
    const struct json_value *lq = dci_arr(land, "queued");
    const struct json_value *uq = dci_arr(queue, "queued");
    dci_emit_rows(reply, "land_queued", lq);
    dci_emit_rows(reply, "unit_queued", uq);
    if (!land)
        dci_say(scr, "land queue: UNKNOWN (%s)\n", st->land.why);
    else
        dci_say(scr, "land queue: %zu waiting\n", dci_count(lq));
    for (size_t i = 0; i < dci_count(lq) && i < DCI_LIST_CAP; i++) {
        const struct json_value *row = json_at(lq, i);
        dci_say(scr, "  #%lld %.12s %s\n", dci_int(row, "seq", -1),
                dci_str(row, "tip"), dci_str(row, "note"));
    }
    if (!queue)
        dci_say(scr, "unit queue: UNKNOWN (%s)\n", st->queue.why);
    else
        dci_say(scr, "unit queue: %lld waiting (%lld ready)\n",
                dci_int(queue, "queued_total", 0),
                dci_int(queue, "queued_ready", 0));
    for (size_t i = 0; i < dci_count(uq) && i < DCI_LIST_CAP; i++) {
        const struct json_value *row = json_at(uq, i);
        dci_say(scr, "  #%lld %s %s\n", dci_int(row, "seq", -1),
                dci_str(row, "name"), dci_str(row, "kind"));
    }
}

/* ── view: jobs ──────────────────────────────────────────────────────────── */

static void dci_jobs_land(const struct dci_state *st,
                          struct zcl_command_reply *reply,
                          struct dci_screen *scr)
{
    const struct json_value *land = dci_land(st);
    const struct json_value *row = land ? json_get(land, "in_flight") : NULL;
    if (!land) {
        dci_say(scr, "landing: UNKNOWN (%s)\n", st->land.why);
        (void)json_push_kv_str(&reply->data, "land_in_flight", "unknown");
        return;
    }
    if (!row || row->type != JSON_OBJ) {
        dci_say(scr, "landing: nothing in flight\n");
        (void)json_push_kv_str(&reply->data, "land_in_flight", "none");
        return;
    }
    (void)json_push_kv(&reply->data, "land_in_flight", row);
    dci_say(scr, "landing: #%lld %.12s %s attempt %lld, %llds\n",
            dci_int(row, "seq", -1), dci_str(row, "tip"),
            dci_str(row, "phase"), dci_int(row, "attempt", -1),
            dci_int(row, "elapsed_s", -1));
}

static void dci_jobs_units(const struct dci_state *st,
                           struct zcl_command_reply *reply,
                           struct dci_screen *scr)
{
    const struct json_value *queue = dci_queue(st);
    const struct json_value *running = dci_arr(queue, "running");
    dci_emit_rows(reply, "unit_running", running);
    if (!queue) {
        dci_say(scr, "units: UNKNOWN (%s)\n", st->queue.why);
        return;
    }
    dci_say(scr, "units: %zu running\n", dci_count(running));
    for (size_t i = 0; i < dci_count(running) && i < DCI_LIST_CAP; i++) {
        const struct json_value *row = json_at(running, i);
        const struct json_value *who = json_get(row, "worker");
        dci_say(scr, "  #%lld %s a%lld worker %s age %llds\n",
                dci_int(row, "seq", -1), dci_str(row, "name"),
                dci_int(row, "attempt", -1),
                (who && who->type == JSON_STR) ? json_get_str(who) : "unknown",
                dci_int(row, "age_s", -1));
    }
}

static void dci_view_jobs(const struct dci_state *st,
                          struct zcl_command_reply *reply,
                          struct dci_screen *scr)
{
    dci_jobs_land(st, reply, scr);
    dci_jobs_units(st, reply, scr);
}

/* ── views: last pass / last fail ────────────────────────────────────────── */

static void dci_emit_outcome(struct zcl_command_reply *reply, const char *key,
                             const struct json_value *row)
{
    if (row)
        (void)json_push_kv(&reply->data, key, row);
    else
        (void)json_push_kv_str(&reply->data, key, "unknown");
}

static void dci_say_land_outcome(struct dci_screen *scr, const char *label,
                                 const struct json_value *row, bool known,
                                 const char *why)
{
    if (!known) {
        dci_say(scr, "%s: UNKNOWN (%s)\n", label, why);
        return;
    }
    if (!row) {
        dci_say(scr, "%s: UNKNOWN (no matching landing outcome recorded)\n",
                label);
        return;
    }
    dci_say(scr, "%s: #%lld %.12s %s %s%.12s %s\n", label,
            dci_int(row, "seq", -1), dci_str(row, "tip"),
            dci_str(row, "state"),
            dci_str(row, "tip_pushed")[0] ? "-> " : "",
            dci_str(row, "tip_pushed"), dci_str(row, "ts"));
}

static void dci_say_unit_outcome(struct dci_screen *scr, const char *label,
                                 const struct json_value *row, bool known,
                                 const char *why)
{
    if (!known) {
        dci_say(scr, "%s: UNKNOWN (%s)\n", label, why);
        return;
    }
    if (!row) {
        dci_say(scr, "%s: UNKNOWN (no matching unit outcome recorded)\n",
                label);
        return;
    }
    dci_say(scr, "%s: %s a%lld %s rc=%lld %s\n", label, dci_str(row, "name"),
            dci_int(row, "attempt", -1), dci_str(row, "verdict"),
            dci_int(row, "rc", -1), dci_str(row, "ts"));
}

static bool dci_unit_failed(const struct json_value *row)
{
    return dci_str(row, "verdict")[0] && !dci_unit_passed(row);
}

static void dci_view_last(const struct dci_state *st,
                          struct zcl_command_reply *reply,
                          struct dci_screen *scr, bool pass)
{
    const struct json_value *land = dci_land(st), *queue = dci_queue(st);
    const struct json_value *lrow = dci_newest(dci_arr(land, "outcomes"),
        pass ? dci_land_passed : dci_land_failed);
    const struct json_value *urow = dci_newest(dci_arr(queue, "outcomes"),
        pass ? dci_unit_passed : dci_unit_failed);
    dci_emit_outcome(reply, "land", land ? lrow : NULL);
    dci_emit_outcome(reply, "unit", queue ? urow : NULL);
    dci_say_land_outcome(scr, pass ? "last landed" : "last landing failure",
                         lrow, land != NULL, st->land.why);
    dci_say_unit_outcome(scr, pass ? "last unit pass" : "last unit failure",
                         urow, queue != NULL, st->queue.why);
    if (!pass && lrow)
        dci_say(scr, "  dimension %s log %s\n", dci_str(lrow, "dimension"),
                dci_str(lrow, "log_path"));
}

/* ── view: worker ────────────────────────────────────────────────────────── */

static void dci_view_worker(const struct dci_state *st,
                            struct zcl_command_reply *reply,
                            struct dci_screen *scr)
{
    struct dci_worker w;
    dci_worker_read(st, &w);
    dci_worker_emit(&reply->data, &w);
    dci_say(scr, "worker: %s%s%s\n", w.state, w.reason[0] ? " — " : "",
            w.reason);
    if (!w.measured) {
        dci_say(scr, "  no worker evidence was measurable on this host\n");
        return;
    }
    dci_say(scr, "  claims %lld (named %lld, live %lld, dead %lld, "
                 "unverified %lld, stale %lld), oldest %llds, stale over %ds\n",
            w.claims, w.named, w.live, w.dead, w.unverified, w.stale,
            w.oldest_s, DCI_WORKER_STALE_S);
    dci_say(scr, "  derived from dev.agent.queue owner identity and claims; "
                 "dev.agent.worker exposes no status action\n");
}

/* ── view: cancel ────────────────────────────────────────────────────────── */

static void dci_cancel_push(struct json_value *arr, const char *what,
                            const char *target, const char *command,
                            const char *reason)
{
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    if (json_push_kv_str(&item, "what", what) &&
        json_push_kv_str(&item, "target", target) &&
        json_push_kv_str(&item, "command", command) &&
        json_push_kv_str(&item, "reason", reason))
        (void)json_push_back(arr, &item);
    json_free(&item);
}

static void dci_cancel_land(const struct dci_state *st, struct json_value *arr)
{
    const struct json_value *land = dci_land(st);
    const struct json_value *queued = dci_arr(land, "queued");
    const struct json_value *flight = land ? json_get(land, "in_flight") : NULL;
    char cmd[DCI_CMD_MAX], target[64];
    for (size_t i = 0; i < dci_count(queued) && i < DCI_LIST_CAP; i++) {
        const struct json_value *row = json_at(queued, i);
        long long seq = dci_int(row, "seq", -1);
        (void)snprintf(cmd, sizeof(cmd), "dev land cancel --seq=%lld", seq);
        (void)snprintf(target, sizeof(target), "%.12s",
                       dci_str(row, "tip"));
        dci_cancel_push(arr, "land_queued", target, cmd, "");
    }
    if (flight && flight->type == JSON_OBJ) {
        long long seq = dci_int(flight, "seq", -1);
        (void)snprintf(cmd, sizeof(cmd), "dev land cancel --seq=%lld", seq);
        (void)snprintf(target, sizeof(target), "%.12s",
                       dci_str(flight, "tip"));
        dci_cancel_push(arr, "land_in_flight", target, cmd, "");
    }
}

static void dci_cancel_units(const struct dci_state *st, struct json_value *arr)
{
    const struct json_value *queue = dci_queue(st);
    const struct json_value *queued = dci_arr(queue, "queued");
    const struct json_value *running = dci_arr(queue, "running");
    char cmd[DCI_CMD_MAX];
    for (size_t i = 0; i < dci_count(queued) && i < DCI_LIST_CAP; i++) {
        const char *name = dci_str(json_at(queued, i), "name");
        (void)snprintf(cmd, sizeof(cmd), "dev agent queue cancel --name=%s",
                       name);
        dci_cancel_push(arr, "unit_queued", name, cmd, "");
    }
    for (size_t i = 0; i < dci_count(running) && i < DCI_LIST_CAP; i++) {
        const char *name = dci_str(json_at(running, i), "name");
        dci_cancel_push(arr, "unit_running", name, "",
                        "a running unit refuses cancel; it is the worker's "
                        "own shutdown");
    }
}

static void dci_view_cancel(const struct dci_state *st,
                            struct zcl_command_reply *reply,
                            struct dci_screen *scr)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    dci_cancel_land(st, &arr);
    dci_cancel_units(st, &arr);
    (void)json_push_kv_bool(&reply->data, "read_only", true);
    (void)json_push_kv(&reply->data, "cancellable", &arr);
    dci_say(scr, "cancel: this leaf runs nothing; run the command shown\n");
    if (!dci_land(st))
        dci_say(scr, "  land candidates UNKNOWN (%s)\n", st->land.why);
    if (!dci_queue(st))
        dci_say(scr, "  unit candidates UNKNOWN (%s)\n", st->queue.why);
    for (size_t i = 0; i < json_size(&arr); i++) {
        const struct json_value *row = json_at(&arr, i);
        const char *cmd = dci_str(row, "command");
        dci_say(scr, "  %s %s: %s\n", dci_str(row, "what"),
                dci_str(row, "target"),
                cmd[0] ? cmd : dci_str(row, "reason"));
    }
    if (json_size(&arr) == 0 && dci_land(st) && dci_queue(st))
        dci_say(scr, "  nothing is cancellable right now\n");
    json_free(&arr);
}

/* ── view: retry ─────────────────────────────────────────────────────────── */

static void dci_retry_push(struct json_value *arr, const char *tip,
                           const char *base, const char *command,
                           const char *reason)
{
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    if (json_push_kv_str(&item, "tip", tip) &&
        json_push_kv_str(&item, "remote_base", base) &&
        json_push_kv_str(&item, "command", command) &&
        json_push_kv_str(&item, "reason", reason))
        (void)json_push_back(arr, &item);
    json_free(&item);
}

/* One failing landing outcome's retry. The base is never guessed: it comes
 * from the receipt the proof already wrote for this tip, and when no receipt
 * names one the row reports base "unknown" with no command. */
static void dci_retry_row(const struct dci_state *st, struct json_value *arr,
                          const struct json_value *row)
{
    struct dci_pair pairs[DCI_PAIR_CAP];
    char sha[DCI_SHA_MAX + 1], why[48] = {0}, cmd[DCI_CMD_MAX];
    size_t found;
    if (!dci_sha_normalize(dci_str(row, "tip"), sha, sizeof(sha))) {
        dci_retry_push(arr, dci_str(row, "tip"), "unknown", "",
                       "tip_not_a_commit_id");
        return;
    }
    found = dci_pairs_from_cache(st->root, sha, pairs, DCI_PAIR_CAP, why,
                                 sizeof(why));
    if (found == 0) {
        dci_retry_push(arr, sha, "unknown", "",
                       why[0] ? why : "remote_base_unknown");
        return;
    }
    for (size_t i = 0; i < found; i++) {
        (void)snprintf(cmd, sizeof(cmd),
                       "dev proof retry --local_commit=%s --remote_base=%s",
                       pairs[i].local, pairs[i].base);
        dci_retry_push(arr, pairs[i].local, pairs[i].base, cmd, "");
    }
}

static void dci_view_retry(const struct dci_state *st,
                           struct zcl_command_reply *reply,
                           struct dci_screen *scr)
{
    const struct json_value *land = dci_land(st);
    const struct json_value *outcomes = dci_arr(land, "outcomes");
    struct json_value arr;
    size_t n = dci_count(outcomes);
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = n; i > 0 && json_size(&arr) < DCI_LIST_CAP; i--) {
        const struct json_value *row = json_at(outcomes, i - 1);
        if (row && row->type == JSON_OBJ && dci_land_failed(row))
            dci_retry_row(st, &arr, row);
    }
    (void)json_push_kv_bool(&reply->data, "read_only", true);
    (void)json_push_kv(&reply->data, "retryable", &arr);
    dci_say(scr, "retry: this leaf runs nothing; run the command shown\n");
    if (!land)
        dci_say(scr, "  UNKNOWN (%s)\n", st->land.why);
    else if (json_size(&arr) == 0)
        dci_say(scr, "  no failing landing outcome to retry\n");
    for (size_t i = 0; i < json_size(&arr); i++) {
        const struct json_value *row = json_at(&arr, i);
        const char *cmd = dci_str(row, "command");
        dci_say(scr, "  %.12s onto %.12s: %s\n", dci_str(row, "tip"),
                dci_str(row, "remote_base"),
                cmd[0] ? cmd : dci_str(row, "reason"));
    }
    json_free(&arr);
}

/* ── view: status ────────────────────────────────────────────────────────── */

static void dci_status_land(const struct dci_state *st,
                            struct zcl_command_reply *reply,
                            struct dci_screen *scr)
{
    const struct json_value *land = dci_land(st);
    const struct json_value *flight = land ? json_get(land, "in_flight") : NULL;
    const struct json_value *outcomes = dci_arr(land, "outcomes");
    const struct json_value *last;
    if (!land) {
        dci_say(scr, "land: UNKNOWN (%s)\n", st->land.why);
        (void)json_push_kv_str(&reply->data, "land", "unknown");
        return;
    }
    (void)json_push_kv_int(&reply->data, "land_queued",
                           (long long)dci_count(dci_arr(land, "queued")));
    (void)json_push_kv_bool(&reply->data, "land_in_flight",
                            flight && flight->type == JSON_OBJ);
    dci_say(scr, "land: %zu queued, %s\n",
            dci_count(dci_arr(land, "queued")),
            (flight && flight->type == JSON_OBJ) ? "1 in flight"
                                                 : "nothing in flight");
    if (flight && flight->type == JSON_OBJ)
        dci_say(scr, "  #%lld %.12s %s attempt %lld, %llds\n",
                dci_int(flight, "seq", -1), dci_str(flight, "tip"),
                dci_str(flight, "phase"), dci_int(flight, "attempt", -1),
                dci_int(flight, "elapsed_s", -1));
    last = dci_newest(outcomes, dci_land_passed);
    dci_say_land_outcome(scr, "  last landed", last, true, "");
    last = dci_newest(outcomes, dci_land_failed);
    dci_say_land_outcome(scr, "  last failure", last, true, "");
}

static void dci_status_units(const struct dci_state *st,
                             struct zcl_command_reply *reply,
                             struct dci_screen *scr)
{
    const struct json_value *queue = dci_queue(st);
    const struct json_value *pool;
    if (!queue) {
        dci_say(scr, "units: UNKNOWN (%s)\n", st->queue.why);
        (void)json_push_kv_str(&reply->data, "units", "unknown");
        return;
    }
    pool = json_get(queue, "pool");
    (void)json_push_kv_int(&reply->data, "unit_queued",
                           dci_int(queue, "queued_total", 0));
    (void)json_push_kv_int(&reply->data, "unit_running",
                           (long long)dci_count(dci_arr(queue, "running")));
    dci_say(scr, "units: %lld queued (%lld ready), %zu running, "
                 "pool %lld free / %lld total\n",
            dci_int(queue, "queued_total", 0),
            dci_int(queue, "queued_ready", 0),
            dci_count(dci_arr(queue, "running")),
            dci_int(pool, "free", -1), dci_int(pool, "total", -1));
}

static void dci_view_status(const struct dci_state *st,
                            struct zcl_command_reply *reply,
                            struct dci_screen *scr)
{
    struct dci_worker w;
    dci_status_land(st, reply, scr);
    dci_status_units(st, reply, scr);
    dci_worker_read(st, &w);
    dci_worker_emit(&reply->data, &w);
    dci_say(scr, "worker: %s%s%s\n", w.state, w.reason[0] ? " — " : "",
            w.reason);
    dci_say(scr, "views: status queue jobs last_pass last_fail worker "
                 "receipt cancel retry\n");
}

/* ── input ───────────────────────────────────────────────────────────────── */

static const char *dci_input_str(const struct zcl_command_request *req,
                                 const char *key)
{
    const struct json_value *v =
        (req && req->input) ? json_get(req->input, key) : NULL;
    return (v && v->type == JSON_STR) ? json_get_str(v) : "";
}

static bool dci_input_json(const struct zcl_command_request *req)
{
    const struct json_value *v =
        (req && req->input) ? json_get(req->input, "json") : NULL;
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

/* The checkout whose proof cache holds the receipts, resolved exactly the
 * way dev.proof itself resolves it, so both leaves read one cache. */
static void dci_resolve_root(const struct zcl_command_request *req, char *out,
                             size_t cap)
{
    const char *root = dci_input_str(req, "root");
    const char *env;
    if (root[0]) {
        (void)snprintf(out, cap, "%s", root);
        return;
    }
    if (req && req->context && req->context->source_root &&
        req->context->source_root[0]) {
        (void)snprintf(out, cap, "%s", req->context->source_root);
        return;
    }
    env = getenv("ZCL_DEV_SOURCE_ROOT");
    (void)snprintf(out, cap, "%s", (env && env[0]) ? env : ".");
}

static void dci_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, message, evidence);
}

/* ── dispatch ────────────────────────────────────────────────────────────── */

static void dci_render(const struct zcl_command_request *req,
                       const struct dci_state *st,
                       struct zcl_command_reply *reply,
                       struct dci_screen *scr, enum dci_view view,
                       const char *sha)
{
    switch (view) {
    case DCI_VIEW_QUEUE: dci_view_queue(st, reply, scr); return;
    case DCI_VIEW_JOBS: dci_view_jobs(st, reply, scr); return;
    case DCI_VIEW_LAST_PASS: dci_view_last(st, reply, scr, true); return;
    case DCI_VIEW_LAST_FAIL: dci_view_last(st, reply, scr, false); return;
    case DCI_VIEW_WORKER: dci_view_worker(st, reply, scr); return;
    case DCI_VIEW_RECEIPT: dci_view_receipt(req, st, reply, scr, sha); return;
    case DCI_VIEW_CANCEL: dci_view_cancel(st, reply, scr); return;
    case DCI_VIEW_RETRY: dci_view_retry(st, reply, scr); return;
    case DCI_VIEW_STATUS:
    case DCI_VIEW_UNKNOWN:
    default: dci_view_status(st, reply, scr); return;
    }
}

/* The receipt view is the only one that needs an argument, so it is the only
 * one that can refuse before any source is read. */
static bool dci_want_sha(const struct zcl_command_request *req,
                         enum dci_view view, char *sha, size_t cap,
                         struct zcl_command_reply *reply)
{
    const char *raw = dci_input_str(req, "sha");
    sha[0] = '\0';
    if (view != DCI_VIEW_RECEIPT)
        return true;
    if (!raw[0]) {
        dci_fail(reply, "SHA_REQUIRED",
                 "the receipt view needs the commit to look up",
                 "z23-dev dev ci receipt --sha=<commit>");
        return false;
    }
    if (!dci_sha_normalize(raw, sha, cap)) {
        dci_fail(reply, "SHA_INVALID",
                 "a commit is 7 to 40 hexadecimal characters", raw);
        return false;
    }
    return true;
}

void zcl_native_handle_dev_ci(const struct zcl_command_request *request,
                              struct zcl_command_reply *reply)
{
    struct dci_state st;
    struct dci_screen scr;
    struct json_value sources;
    char screen[DCI_SCREEN_CAP], sha[DCI_SHA_MAX + 1];
    const char *raw_view = dci_input_str(request, "topic");
    enum dci_view view = dci_view_of(raw_view);
    if (view == DCI_VIEW_UNKNOWN) {
        dci_fail(reply, "VIEW_UNKNOWN",
                 "topic must be one of status queue jobs last_pass last_fail "
                 "worker receipt cancel retry", raw_view);
        return;
    }
    if (!dci_want_sha(request, view, sha, sizeof(sha), reply))
        return;
    memset(&st, 0, sizeof(st));
    dci_resolve_root(request, st.root, sizeof(st.root));
    dci_state_load(&st, request);
    screen[0] = '\0';
    scr.at = screen;
    scr.left = sizeof(screen);
    (void)json_push_kv_str(&reply->data, "leaf", DCI_LEAF);
    (void)json_push_kv_str(&reply->data, "view", dci_view_names[view]);
    json_init(&sources);
    json_set_array(&sources);
    dci_note_source(&sources, "dev.land", &st.land);
    dci_note_source(&sources, "dev.agent.queue", &st.queue);
    (void)json_push_kv(&reply->data, "sources", &sources);
    json_free(&sources);
    dci_render(request, &st, reply, &scr, view, sha);
    if (!dci_input_json(request))
        (void)json_push_kv_str(&reply->data, "screen", screen);
    dci_state_free(&st);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}
