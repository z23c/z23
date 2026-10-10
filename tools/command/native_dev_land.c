/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.land — submit a tip for proof and push, ask what happened,
 *          drive one scheduler step or one bounded integrator session.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. Landing a commit costs a rebase, a lint pass, an exact proof and a
 * fast-forward push. Today every agent runs that sequence itself and blocks
 * on it for the whole 15-25 minutes, and two agents doing it at once race at
 * the push. The waiting is the cost, not the work. This leaf splits the two:
 * an agent SUBMITS and returns in milliseconds; a resident loop STEPS the
 * queue; the agent PULLS the outcome later. Nothing an agent calls blocks on
 * a proof, a build, or another host.
 *
 * INPUT (zcl.land_input.v1)
 *   action    string, required: submit | attach | attach_publish | status |
 *             step | drive | cancel | fence_replace; also the first positional.
 *   tip       submit only, required: a commit-ish resolved in the submitting
 *             checkout; the row stores the full 40-hex commit id.
 *   worktree  submit only, optional: the checkout that holds the tip.
 *             Default: the checkout root above the current directory.
 *   note      submit only, optional free text carried into the outcome row.
 *   seq       cancel: required. attach and attach_publish: optional; omitted,
 *             they target the ONE
 *             live PASS row lacking intent, else ATTACH_TARGET_NONE|AMBIGUOUS.
 *   base/head attach and attach_publish: optional exact 40-hex pair pins;
 *             supply both to refuse if a reviewed row has changed.
 *   wait_ms   attach_publish only: bounded wait for that explicitly pinned
 *             proof, without holding the landing step lock between polls.
 *   json      status only, optional bool: drop the human screen.
 *
 * STATE. <platform_state_root>/land (0700):
 *   queue.jsonl     one JSON object per line; the live request rows.
 *   outcomes.jsonl  one appended row per terminal outcome, newest last.
 *   queue.lock      the short row-file lock (seq assignment, rewrite).
 *   step.lock       the queue's own step lock: exclusive, NON-BLOCKING,
 *                   taken before step touches anything and held across the
 *                   whole step (rebase, lint, proof request, status read,
 *                   push), released on every exit path. A second `dev land
 *                   step` invocation that cannot take it replies STEP_BUSY
 *                   (ZCL_COMMAND_STATUS_BLOCKED, retryable) without
 *                   touching the queue or the worktree; the caller retries.
 *                   It is never held across separate step calls: a second
 *                   host proving the same tip is not this host's problem.
 *                   Queued exact proofs retain a shared lock from before
 *                   request claim through completion, so preparation and
 *                   proof cannot mutate/read this checkout concurrently.
 *   wt/             the private landing worktree, created once and reused.
 *   logs/           one log per attempt; a failure row names its log.
 *                   logs/precheck.log: one line per queued row the
 *                   queued-row conflict precheck replayed, and its verdict
 *                   or why it has none; bounded per row per observed main.
 * Every outcome also posts a note to the mail leaf (which appends it to
 * <platform_state_root>/mail/outbox.jsonl with the mail seq space) when
 * that directory exists, so an agent learns the result by pulling its mail
 * rather than by waiting on this queue. The row carries ref=<tip> for
 * correlation; the land queue's own seq never enters the mail seq space.
 *
 * OUTPUT (zcl.land.v1) on ok=true: leaf is always "dev.land", plus per
 * action: submit {seq, tip, state:"queued"}; status {queued, in_flight,
 * outcomes, steer, incident} plus screen unless json=true; step {state}
 * where state is one of empty | started | proving | landed | failed |
 * conflict | rebased | queued (a moving-main successor); cancel
 * {seq, state:"cancelled"}.
 * A step that leaves a row in flight also reports queued_prechecked (queued
 * rows replayed onto the main it observed), queued_conflicts (rows it
 * ended as conflict "detected while queued"), queued_uncertain (rows it
 * replayed without a certain answer, left queued and unmarked) and
 * queued_unchecked (rows due a check that the per-beat row cap or deadline
 * left for a later beat); see the precheck section.
 *
 * STEER. status fills one steer object for the row step would pick
 * (the in-flight row, else the oldest queued row, else explicit none):
 * candidate, seq, phase, owner, lease, proof_state, receiver_driver,
 * first_missing_transition, wake_command, remote_state. remote_state is
 * the cached origin/main ref in the submitting checkout, never a fetch.
 * owner is the step.lock holder's pid while a beat holds the lock, and
 * unclaimed when the lock is free. incident is drain_absent when that
 * row is still queued, the lock is observably free, and either the
 * z23-land-step timer is not armed or the row is older than the drain
 * idle bound (ZCL_LAND_DRAIN_IDLE_SEC, default 900s — a healthy timer
 * claims within one 20s period, so 900s is a dead drain, not a gap
 * between beats). The wake command is then `z23-dev dev land step`:
 * another authorized integrator adopts by calling that same step. A
 * held lock is not an incident; a second step returns STEP_BUSY and
 * does not push. status does not create step.lock and does not hold it.
 * It never initializes the state/land/log directories or repairs permissions;
 * an unavailable existing private root is reported instead of created.
 *
 * attach replies {seq, tip, state:"attached", target:explicit|resolved}.
 * attach_publish makes the same explicit signed intent, then runs the
 * existing current-base publication beat before releasing step.lock.
 * A beat blocked on PUBLICATION_INTENT_REQUIRED names seq, tip and base in
 * error.evidence and `z23-dev dev land attach --seq=N` in next_action.
 *
 * step ALSO carries persist:"failed" (plus persist_reason) alongside the
 * `state` it names when the row's own commit to queue.jsonl/outcomes.jsonl
 * did not durably land — queue lock contention or an I/O error rewriting
 * the file. `state` still names what step just did (rebase, proof request,
 * push...) so the transcript reads right, but persist:"failed" is the
 * signal that it was NOT recorded: the row stays at its last-persisted
 * phase and a later step re-drives it. A caller must treat state:"landed"
 * with persist:"failed" as NOT landed from the queue's point of view even
 * though the push already happened — a subsequent step detects that case
 * (the tip is already an ancestor of origin/main) and records it as landed
 * without re-proving, rather than pushing it a second time.
 *
 * PROCESS RULE. `git`, `make` (lint-land, install-hooks), and the existing
 * Linux `devbuild` admission wrapper for watcher creation run through
 * util/spawn.h's zcl_spawn_capture(); popen(), system() and shell command
 * strings are forbidden and gated. The exact proof is requested through the
 * dev.proof machinery (tools/dev/dev_proof.c), never re-implemented. The
 * final push carries no --no-verify: it goes through the installed
 * pre-push hook like any other push to main, and that hook's exact-receipt
 * admission (tools/dev/z23_git_hook.c) is what keeps it fast. One driver
 * steps this queue at a time: `step` holds step.lock for its whole run, and
 * a second driver that finds it held gets STEP_BUSY and retries rather than
 * racing the first driver's rebase/lint against the worktree.
 *
 * submit, status and cancel touch only local files. step returns after
 * requesting proof. drive performs at most four resumable cycles, releasing
 * step.lock before a foreground proof and reclaiming it only for the
 * publication beat. A stopped driver leaves the same durable queue row.
 */

/* realpath() is declared by glibc only through the fortify inline unless a
 * feature-test macro asks for it; without this the file compiles today by
 * accident of -O2 and is a hard C23 error at -O0 or on another libc. Must
 * precede the first #include, which is where <features.h> is read. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_command.h"
#include "command/native_dev_land_regen.h"
#include "command/native_dev_land_attestation.h"
#include "command/native_dev_land_window.h"
#include "util/clientversion.h"
#include "command/native_devagent.h"
#include "command/native_dev_agents.h"
#include "dependency_links.h"

#include "base/safe_alloc.h"
#include "base/hex.h"
#include "config/command_catalog.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "zutf8/zutf8.h"
#include "platform/file_clone.h"
#include "platform/file_metadata.h"
#include "platform/logical_cpu.h"
#include "platform/os_proc.h"
#include "platform/private_file.h"
#include "platform/positioned_file.h"
#include "platform/ram_scratch.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "util/spawn.h"
#include "util/file_tree_ops.h"

#include "command/native_dev_loop_command.h"
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
#include "dev_proof.h"
#include "dev_proof_signer.h"
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <direct.h>
#include <io.h>
#else
#include <sys/file.h>
#endif
#if defined(__linux__)
#include <sys/sysmacros.h>
#endif

/* mingw's <fcntl.h> has no O_CLOEXEC: descriptors on Windows are not
 * inherited unless the handle is explicitly marked inheritable, so the
 * flag is a no-op there rather than a missing guarantee. */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define DL_LEAF "dev.land"

/* Bounded budgets: every file this leaf reads or writes is capped, so a
 * hostile state dir cannot grow the process without bound. */
#define DL_LINE_CAP  32768u
#define DL_FILE_CAP  (1024u * 1024u)
#define DL_GIT_CAP   (256u * 1024u)
#define DL_LOG_CAP   (2u * 1024u * 1024u)
#define DL_NOTE_MAX  512u

/* Attempt ceiling for a host-load retry (a source-identity race or a
 * timeout). A real red dimension is terminal on the first attempt. */
#define DL_ATTEMPT_MAX 3

/* Wall-clock ceilings for the two long git/make actions step performs. */
#define DL_GIT_TIMEOUT_MS  (10 * 60 * 1000)
#define DL_LINT_TIMEOUT_MS (30 * 60 * 1000)

/* ── failure ───────────────────────────────────────────────────────────── */

static void dl_fail(struct zcl_command_reply *reply, const char *code,
                    const char *phase, const char *msg, const char *evidence)
{
    (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, phase, false,
                           false, msg, evidence);
    reply->error.human_action_required = true;
}

/* Another driver already holds step.lock. Nothing has been read or touched
 * yet — the lock is the first thing step takes — so this always fires
 * before any queue or worktree access. Retryable: the caller is expected to
 * step again shortly rather than treat this as a real failure. The lock is
 * a plain open+flock, not a pid-file, so the holder is read from the
 * kernel's /proc/locks (never from the file); the evidence says "unknown"
 * where the kernel does not say, and always names the queue directory. */
static bool dl_lock_holder_pid(const char *path, int *pid_out);

static void dl_step_busy(struct zcl_command_reply *reply, const char *landdir)
{
    char evidence[4096 + 96], path[4096 + 32], holder[24] = "unknown";
    int pid = 0;
    int n = landdir ? snprintf(path, sizeof(path), "%s/step.lock", landdir)
                    : -1;
    if (n > 0 && (size_t)n < sizeof(path) &&
        dl_lock_holder_pid(path, &pid))
        (void)snprintf(holder, sizeof(holder), "%d", pid);
    (void)snprintf(evidence, sizeof(evidence), "holder_pid=%s queue=%s",
                   holder, landdir ? landdir : "");
    (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED, "STEP_BUSY", "step",
                           true, false,
                           "another driver is already stepping this queue; "
                           "retry",
                           evidence);
}

/* ── input accessors ───────────────────────────────────────────────────── */

static const char *dl_str(const struct zcl_command_request *req,
                          const char *key)
{
    const struct json_value *v;
    if (!req || !req->input)
        return NULL;
    v = json_get(req->input, key);
    if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
        return json_get_str(v);
    return NULL;
}

static bool dl_seq_in(const struct zcl_command_request *req, long long *out)
{
    const struct json_value *v;
    if (!req || !req->input || !out)
        return false;
    v = json_get(req->input, "seq");
    if (v && v->type == JSON_INT && json_get_int(v) >= 1) {
        *out = json_get_int(v);
        return true;
    }
    return false;
}

/* ── validators ────────────────────────────────────────────────────────── */

/* A commit-ish this leaf will hand to git: hex only, 7..64 characters. A
 * branch name or a ref expression is deliberately refused — the queue row is
 * evidence about ONE commit, and a name is a moving answer to that. */
static bool dl_tipish_ok(const char *s)
{
    size_t n;
    if (!s || !s[0])
        return false;
    n = strlen(s);
    if (n < 7 || n > 64)
        return false;
    for (const char *p = s; *p; p++) {
        if (!isxdigit((unsigned char)*p))
            return false;
    }
    return true;
}

static bool dl_sha_ok(const char *s)
{
    return s && strlen(s) == 40 && dl_tipish_ok(s);
}

/* ── state dirs ────────────────────────────────────────────────────────── */

struct dl_dirs {
    char root[4096];
    char land[4096];
    char logs[4096];
    char wt[4096];
};

static bool dl_mkdir_one(const char *path)
{
    struct stat st;
#if defined(_WIN32)
    if (_mkdir(path) == 0)
        return true;
#else
    if (mkdir(path, 0700) == 0)
        return true;
#endif
    if (errno != EEXIST)
        return false;
    return stat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR;
}

static bool dl_dirs_resolve(struct dl_dirs *d, bool create)
{
    int n;
    if (!d || !(create ? platform_state_root(d->root, sizeof(d->root))
                       : platform_state_root_existing(d->root, sizeof(d->root))))
        return false;
    n = snprintf(d->land, sizeof(d->land), "%s/land", d->root);
    if (n <= 0 || (size_t)n >= sizeof(d->land))
        return false;
    n = snprintf(d->logs, sizeof(d->logs), "%s/land/logs", d->root);
    if (n <= 0 || (size_t)n >= sizeof(d->logs))
        return false;
    n = snprintf(d->wt, sizeof(d->wt), "%s/land/wt", d->root);
    if (n <= 0 || (size_t)n >= sizeof(d->wt))
        return false;
    return !create || (dl_mkdir_one(d->land) && dl_mkdir_one(d->logs));
}

static bool dl_dirs_make(struct dl_dirs *d)
{
    return dl_dirs_resolve(d, true);
}

/* ── time ──────────────────────────────────────────────────────────────── */

static void dl_now_iso(char out[64])
{
    time_t now = platform_time_wall_time_t();
    struct tm tm_utc;
    memset(&tm_utc, 0, sizeof(tm_utc));
#if defined(_WIN32)
    (void)gmtime_s(&tm_utc, &now);
#else
    (void)gmtime_r(&now, &tm_utc);
#endif
    (void)strftime(out, 64, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

/* ── JSON string escaping (rows are machine-written, never trusted) ────── */

static const char *dl_escape_short(unsigned char c)
{
    switch (c) {
    case '"': return "\\\"";
    case '\\': return "\\\\";
    case '\n': return "\\n";
    case '\r': return "\\r";
    case '\t': return "\\t";
    default: return NULL;
    }
}

static bool dl_escape(const char *in, char *out, size_t cap)
{
    size_t used = 0;
    if (out && cap) out[0] = '\0';
    if (!in || !out || cap == 0)
        return false;
    if (!zutf8_validate_n(in, strlen(in)))
        return false;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        const char *rep = dl_escape_short(*p);
        char tmp[8];
        /* used < cap; subtraction avoids overflowing capacity arithmetic. */
        if (rep) {
            if (cap - used <= 2)
                return false;
            out[used++] = rep[0];
            out[used++] = rep[1];
        } else if (*p < 0x20) {
            int w = snprintf(tmp, sizeof(tmp), "\\u%04x", *p);
            if (w != 6 || cap - used <= 6)
                return false;
            memcpy(out + used, tmp, 6);
            used += 6;
        } else {
            if (cap - used <= 1)
                return false;
            out[used++] = (char)*p;
        }
    }
    out[used] = '\0';
    return true;
}

/* ── minimal per-line field extraction ─────────────────────────────────── */

static bool dl_line_int(const char *line, const char *key, long long *out)
{
    char pat[64];
    const char *p;
    char *end;
    long long n;
    (void)snprintf(pat, sizeof(pat), "\"%s\":", key);
    p = strstr(line, pat);
    if (!p)
        return false;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t')
        p++;
    errno = 0;
    n = strtoll(p, &end, 10);
    if (errno != 0 || end == p)
        return false;
    *out = n;
    return true;
}

enum dl_string_state { DL_STRING_INVALID, DL_STRING_ABSENT, DL_STRING_FOUND };
struct dl_string_result {
    enum dl_string_state state;
    const char *value;
    size_t length;
};

/* Value is copied into caller-owned storage; no JSON allocation is borrowed.
 * ABSENT has no value, unlike FOUND with an empty string. INVALID never
 * masquerades as optional absence. Every caller must choose its policy. */
[[nodiscard]] static struct dl_string_result dl_line_string(
    const char *line, const char *key, char *out, size_t cap)
{
    struct dl_string_result result = { .state = DL_STRING_INVALID };
    if (out && cap) out[0] = '\0';
    if (!line || !key || !out || cap == 0)
        return result;
    struct json_value doc;
    json_init(&doc);
    if (json_read(&doc, line, strlen(line)) && doc.type == JSON_OBJ) {
        const struct json_value *value = json_get(&doc, key);
        if (!value) result.state = DL_STRING_ABSENT;
        else if (value->type == JSON_STR && value->val.s) {
            size_t length = strlen(value->val.s);
            if (length < cap) {
                memcpy(out, value->val.s, length + 1);
                result = (struct dl_string_result){ DL_STRING_FOUND, out, length };
            }
        }
    }
    json_free(&doc);
    return result;
}

/* Successful native serialization emits 35 unique scalar members. Reject
 * foreign ambiguity and displacement; cap extensions before O(n^2) work. */
static bool dl_row_members_ok(const struct json_value *doc)
{
    enum { DL_ROW_MEMBER_MAX = 64 };
    if (!doc || doc->type != JSON_OBJ || doc->num_children > DL_ROW_MEMBER_MAX)
        return false;
    for (size_t i = 0; i < doc->num_children; i++) {
        if (doc->children[i].type == JSON_OBJ || doc->children[i].type == JSON_ARR)
            return false;
        for (size_t j = 0; j < i; j++)
            if (strcmp(doc->keys[i], doc->keys[j]) == 0) return false;
    }
    return true;
}

/* ── bounded file IO ───────────────────────────────────────────────────── */

/* Callers (dl_load_rows) read errno right after a false return to tell
 * "the file does not exist yet" (ENOENT: an empty queue, nothing wrong)
 * from every other failure (a real read error, or the file simply being
 * over budget), which must NOT be treated as empty — treating an oversize
 * queue as empty would let the next rewrite erase every row it holds. So
 * every failure path here sets its own distinct errno rather than leaving
 * whatever a prior, unrelated syscall happened to set. */
static bool dl_read_file(const char *path, char *out, size_t cap,
                         size_t *len_out)
{
    FILE *f;
    size_t n;
    if (!path || !out || cap == 0) {
        errno = EINVAL;
        return false;
    }
    f = fopen(path, "rb");
    if (!f)
        return false; /* errno is fopen's own: ENOENT means "no file yet" */
    n = fread(out, 1, cap - 1, f);
    if (ferror(f)) {
        int saved = errno;
        (void)fclose(f);
        errno = saved ? saved : EIO;
        return false;
    }
    /* A file over the budget is refused, never truncated: half a row is not
     * a smaller row, it is a different one. */
    if (!feof(f)) {
        (void)fclose(f);
        errno = EFBIG;
        return false;
    }
    out[n] = '\0';
    (void)fclose(f);
    if (len_out)
        *len_out = n;
    return true;
}

/* With O_APPEND, concurrent submitters never interleave bytes as long as
 * each row is completed by the writer that started it. A single write()
 * is not that guarantee on its own: it can return early (EINTR, or a
 * short write under memory pressure) after only some of the row landed,
 * and the next line written — by this row or another submitter's row —
 * would fuse onto those leftover bytes into one unparseable line. Loop
 * until every byte is written or a real error (not EINTR) stops us. */
static bool dl_append_row(const char *path, const char *line, size_t len)
{
    int fd;
    size_t off = 0;
    if (!path || !line || len == 0)
        return false;
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    while (off < len) {
        ssize_t w = write(fd, line + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            (void)close(fd);
            return false;
        }
        if (w == 0) {
            (void)close(fd);
            return false;
        }
        off += (size_t)w;
    }
    (void)close(fd);
    return true;
}

static bool dl_append_text(const char *path, const char *text)
{
    size_t len;
    if (!text)
        return false;
    len = strlen(text);
    return len == 0 ? true : dl_append_row(path, text, len);
}

/* Sweep this leaf's own proof generation pools (disk beside the landing
 * worktree, and this host's RAM root when it offers one) for generations
 * whose attempt already finished, and log what came off disk. Called at
 * the start of every submit (sweep stale ones at the next submit) and at
 * the start of every step (which is what runs again right after an
 * attempt lands, fails, or is superseded, so a pool left behind by one
 * attempt is cleared before the next one asks for a generation). Advisory
 * only, like the reap it wraps: finding nothing to remove is success,
 * never a step or submit failure. */
static void dl_pool_sweep_and_log(const struct dl_dirs *d)
{
#ifdef ZCL_DEV_BUILD
    size_t removed = 0;
    uint64_t bytes = 0;
    char why[160] = {0}, line[256], path[4096 + 32];
    bool ok = zcl_dev_proof_generation_pool_sweep(d->wt, &removed, &bytes,
                                                  why, sizeof(why));
    if (ok && !removed)
        return;
    if (snprintf(path, sizeof(path), "%s/pool-sweep.log", d->logs) >=
            (int)sizeof(path))
        return;
    if (!ok)
        (void)snprintf(line, sizeof(line),
                       "pool_sweep: could not compute a pool path: %s\n",
                       why);
    else
        (void)snprintf(line, sizeof(line),
                       "pool_sweep: removed=%zu bytes=%llu\n", removed,
                       (unsigned long long)bytes);
    (void)dl_append_text(path, line);
#else
    /* No real dev_proof.c pool to sweep outside the dev binary (a hermetic
     * land test stubs the proof itself, and never creates one). */
    (void)d;
#endif
}

/* ── rows ──────────────────────────────────────────────────────────────── */

/* dl_rebase() and dl_already_landed() hand row->worktree to `git fetch` as
 * the repository argument, a POSITIONAL slot git itself parses for leading
 * "-" options ("--upload-pack=..." reaches arbitrary exec). dl_load_rows's
 * own doc comment says the queue "survives a foreign write" — queue.jsonl
 * is exactly the kind of file a crafted row can appear in without ever
 * going through dl_submit's own checkout-root resolution — so the row
 * parser rejects non-path shapes without consulting mutable filesystem
 * state. Before use, the locator must also be an existing directory under
 * the user's home or beside the checkout doing the landing. */
static bool dl_worktree_shape_ok(const char *wt)
{
    if (!wt || !wt[0])
        return true; /* absent: dl_rebase falls back to origin only */
    if (wt[0] != '/')
        return false;
    for (const char *p = wt; *p; p++) {
        if (*p == '/' && p[1] == '-')
            return false;
    }
    return true;
}

/* Availability and local path authority are execution preconditions, not
 * reasons to forget an admitted request when another checkout reads it. */
static bool dl_worktree_ok(const char *wt)
{
    struct stat st;
    const char *home;
    char checkout[4096], *slash;
    if (!dl_worktree_shape_ok(wt))
        return false;
    if (!wt || !wt[0])
        return true;
    if (stat(wt, &st) != 0 || !S_ISDIR(st.st_mode))
        return false;
    home = getenv("HOME");
    if (home && home[0]) {
        size_t hlen = strlen(home);
        if (strncmp(wt, home, hlen) == 0 &&
            (wt[hlen] == '/' || wt[hlen] == '\0'))
            return true;
    }
    if (zcl_devagent_checkout_root(NULL, checkout, sizeof(checkout)) &&
        (slash = strrchr(checkout, '/')) != NULL && slash != checkout) {
        size_t plen = (size_t)(slash - checkout);
        if (strncmp(wt, checkout, plen) == 0 &&
            (wt[plen] == '/' || wt[plen] == '\0'))
            return true;
    }
    return false;
}

static bool dl_worktree_present(const char *wt)
{
    return wt && wt[0] && dl_worktree_ok(wt);
}

static bool dl_worktree_file(const char *wt, const char *relative,
                             char *out, size_t cap)
{
    if (!dl_worktree_present(wt))
        return false;
    int n = snprintf(out, cap, "%s/%s", wt, relative);
    return n >= 0 && (size_t)n < cap;
}

static bool dl_tor_source_config(const char *wt, char *out, size_t cap)
{
    if (!dl_worktree_present(wt))
        return false;
    int n = snprintf(out, cap, "submodule.vendor/tor.url=%s/vendor/tor", wt);
    return n >= 0 && (size_t)n < cap;
}

/* state:   queued | inflight | landed | failed | conflict | cancelled
 * phase:   "" | rebase | regen | prebuild | prove | push  (meaningful when
 *          inflight). "regen" is native_dev_land_regen.c's unconditional
 *          post-rebase pass over the generated-doc targets (capability
 *          inventory, executor routing, doc-counts) — separate from the
 *          rebase's own conflict-only auto-resolve of the same artifacts
 *          (see "rebase conflicts on the artifacts every train
 *          regenerates" below), which fires only when a rebase conflicts
 *          on them. Both AMEND their regenerated docs into the rebased
 *          tip, and the amended id replaces `local`: this row schema gains
 *          no separate field for it, because `local` is already "the tip
 *          everything downstream proves and pushes". */
struct dl_row {
    long long seq;
    long long priority_seq;
    char ts[64];
    char tip[80];
    char worktree[4096];
    char note[DL_NOTE_MAX + 1];
    char state[16];
    char phase[16];
    long long attempt;
    long long started;
    char base[80];
    char local[80];
    char tree[80];
    char proof_intent[176];
    long long predecessor_seq;
    char predecessor_local[80], predecessor_base[80], predecessor_tree[80];
    char predecessor_intent[176];
    /* Signed Git landing intent, bound to the exact proven pair. The bundle
     * lives under land/ and its digest is checked again before dispatch. */
    char publication_target[65];
    char publication_proof[65];
    char publication_bundle[65];
    char publication_signer[65];
    char publication_signature[129];
    char remote_tip[65];
    char remote_source[65];
    char remote_signer[65];
    char remote_signature[129];
    char pushed[80];
    char dimension[48];
    char log_path[4096];
    /* Keep the complete bounded worktree-dependency refusal, including its
     * repair command, rather than truncating the upstream 1024-byte text. */
    char detail[1024];
    /* A possible send without durable diagnostics forbids another send.
     * Remote observation remains authoritative, including after a crash. */
    bool push_diagnostic_pending;
    long long fence_peer;
    bool publication_hold;
    /* The origin main this queued row was last replayed onto by the
     * queued-row conflict precheck, so a fresh step process does not
     * replay it again until main moves. A cache, never authority: absence, empty or a fitting
     * non-SHA string only means "not checked yet". */
    char prechecked[80];
    /* Uncertain precheck answers against `uncertain_main`; at
     * DL_PRECHECK_TRIES the check leaves the row alone until main moves.
     * Also a cache: absence, empty or a fitting non-SHA string
     * means "no answers yet". */
    char uncertain_main[80];
    long long uncertain_tries;
    /* Set once the producer-stale recovery has been spent for this row until
     * main moves. Written before the recovery runs; independent of dimension.
     * Optional on disk: an older row loads as "not tried". */
    long long producer_recovered;
    /* Digest of the last phase mail posted for this row (state, phase,
     * attempt, tip, dimension, note, detail, log); 0 means nothing posted.
     * Optional on disk: an older row loads as 0, an older binary ignores
     * the key. A cache that only decides whether a repeat row is mailed. */
    long long phase_mail;
};

static bool dl_hold_field(const struct json_value *doc, bool *hold)
{
    size_t found = 0;
    *hold = false;
    for (size_t i = 0; i < doc->num_children; i++) {
        if (strcmp(doc->keys[i], "publication_hold") != 0)
            continue;
        if (++found != 1 || doc->children[i].type != JSON_BOOL)
            return false;
        *hold = json_get_bool(&doc->children[i]);
    }
    return true;
}

static bool dl_row_json_ok(const char *line, long long *priority,
                           bool *has_priority, bool *hold)
{
    struct json_value doc;
    const struct json_value *field;
    json_init(&doc);
    bool ok = json_read(&doc, line, strlen(line)) && doc.type == JSON_OBJ &&
              dl_row_members_ok(&doc);
    field = ok ? json_get(&doc, "priority_seq") : NULL;
    *has_priority = field != NULL;
    if (field) {
        ok = field->type == JSON_INT;
        if (ok)
            *priority = json_get_int(field);
    }
    field = ok ? json_get(&doc, "push_diagnostic_pending") : NULL;
    if (field)
        ok = field->type == JSON_INT && json_get_int(field) >= 0 && json_get_int(field) <= 1;
    field = ok ? json_get(&doc, "fence_peer") : NULL;
    if (field) ok = field->type == JSON_INT && json_get_int(field) >= 0;
    if (ok) ok = dl_hold_field(&doc, hold);
    json_free(&doc);
    return ok;
}

static bool dl_row_state_ok(const struct dl_row *r)
{
    return strcmp(r->state, "queued") == 0 ||
           strcmp(r->state, "inflight") == 0 ||
           strcmp(r->state, "landed") == 0 ||
           strcmp(r->state, "failed") == 0 ||
           strcmp(r->state, "conflict") == 0 ||
           strcmp(r->state, "fenced") == 0 ||
           strcmp(r->state, "cancelled") == 0;
}

static bool dl_row_phase_ok(const struct dl_row *r)
{
    return !r->phase[0] || strcmp(r->phase, "rebase") == 0 ||
           strcmp(r->phase, "regen") == 0 ||
           strcmp(r->phase, "prebuild") == 0 ||
           strcmp(r->phase, "prove") == 0 ||
           strcmp(r->phase, "push") == 0;
}

static bool dl_row_pair_ok(const struct dl_row *r)
{
    if ((r->base[0] && !dl_sha_ok(r->base)) ||
        (r->local[0] && !dl_sha_ok(r->local)))
        return false;
    if (strcmp(r->state, "inflight") == 0 &&
        (strcmp(r->phase, "prove") == 0 ||
         strcmp(r->phase, "push") == 0))
        return dl_sha_ok(r->base) && dl_sha_ok(r->local);
    return true;
}

static bool dl_hex_ok(const char *s, size_t length)
{
    if (!s || strlen(s) != length)
        return false;
    for (size_t i = 0; i < length; i++)
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

/* Dependency fields are authority: inspect only unique, typed top-level keys.
 * Absence (or a complete empty tuple) preserves legacy independent rows. */
static bool dl_chain_shape_ok(const struct dl_row *r)
{
    char intent[176];
    if (!r->predecessor_seq)
        return !r->predecessor_local[0] && !r->predecessor_base[0] &&
            !r->predecessor_tree[0] && !r->predecessor_intent[0];
    (void)snprintf(intent, sizeof(intent), "%s@%s", r->predecessor_local, r->predecessor_base);
    return r->predecessor_seq > 0 && r->predecessor_seq < r->seq &&
        dl_hex_ok(r->predecessor_local, 40) && dl_hex_ok(r->predecessor_base, 40) &&
        dl_hex_ok(r->predecessor_tree, 40) && strcmp(intent, r->predecessor_intent) == 0;
}

static bool dl_chain_fields_parse(const char *line, struct dl_row *r)
{
    static const char *const names[] = { "predecessor_seq", "predecessor_local",
        "predecessor_base", "predecessor_tree", "predecessor_intent" };
    char *targets[] = { NULL, r->predecessor_local, r->predecessor_base,
        r->predecessor_tree, r->predecessor_intent };
    const size_t caps[] = { 0, sizeof(r->predecessor_local), sizeof(r->predecessor_base),
        sizeof(r->predecessor_tree), sizeof(r->predecessor_intent) };
    struct json_value doc; json_init(&doc);
    unsigned seen = 0;
    bool ok = json_read(&doc, line, strlen(line)) && doc.type == JSON_OBJ;
    for (size_t i = 0; ok && i < doc.num_children; ++i) {
        for (size_t j = 0; ok && j < 5; ++j) {
            if (strcmp(doc.keys[i], names[j]) != 0) continue;
            const struct json_value *v = &doc.children[i];
            ok = !(seen & (1u << j)) && v->type == (j ? JSON_STR : JSON_INT);
            seen |= 1u << j;
            if (!ok) break;
            if (!j) r->predecessor_seq = json_get_int(v);
            else {
                const char *value = json_get_str(v);
                ok = strlen(value) < caps[j];
                if (ok) (void)snprintf(targets[j], caps[j], "%s", value);
            }
        }
    }
    json_free(&doc);
    return ok && (seen == 0 || seen == 31) && dl_chain_shape_ok(r);
}

static bool dl_publication_shape_ok(const struct dl_row *r)
{
    bool present = r->publication_target[0] || r->publication_proof[0] ||
        r->publication_bundle[0] || r->publication_signer[0] ||
        r->publication_signature[0];
    if (!present)
        return true;
    return dl_hex_ok(r->publication_target, 64) &&
        dl_hex_ok(r->publication_proof, 64) &&
        dl_hex_ok(r->publication_bundle, 64) &&
        dl_hex_ok(r->publication_signer, 64) &&
        dl_hex_ok(r->publication_signature, 128);
}

static bool dl_remote_receipt_shape_ok(const struct dl_row *r)
{
    bool present = r->remote_tip[0] || r->remote_source[0] ||
        r->remote_signer[0] || r->remote_signature[0];
    if (!present) return true;
    return dl_sha_ok(r->remote_tip) && dl_sha_ok(r->remote_source) &&
        dl_hex_ok(r->remote_signer, 64) &&
        dl_hex_ok(r->remote_signature, 128);
}

static void dl_publication_clear(struct dl_row *r)
{
    r->publication_target[0] = '\0';
    r->publication_proof[0] = '\0';
    r->publication_bundle[0] = '\0';
    r->publication_signer[0] = '\0';
    r->publication_signature[0] = '\0';
    r->remote_tip[0] = '\0';
    r->remote_source[0] = '\0';
    r->remote_signer[0] = '\0';
    r->remote_signature[0] = '\0';
}

static bool dl_hold_row_ok(const struct dl_row *r)
{
    return !r->publication_hold || (!r->publication_signature[0] &&
        !r->pushed[0] && !r->push_diagnostic_pending && !r->fence_peer &&
        strcmp(r->phase, "push") != 0);
}

static bool dl_row_semantics_ok(const struct dl_row *r)
{
    if (strcmp(r->state, "fenced") == 0 && (!r->publication_signature[0] ||
        !dl_sha_ok(r->base) || !dl_sha_ok(r->local) || !dl_sha_ok(r->tree)))
        return false;
    return dl_row_state_ok(r) && dl_row_phase_ok(r) && dl_row_pair_ok(r) &&
           dl_publication_shape_ok(r) && dl_remote_receipt_shape_ok(r) && dl_hold_row_ok(r);
}

static bool dl_priority_parse(struct dl_row *r, long long priority,
                              bool has_priority)
{
    if (has_priority && (priority < 1 || priority > r->seq))
        return false;
    r->priority_seq = has_priority ? priority : r->seq;
    return true;
}

/* Optional replay caches: invalid field representations obstruct the row.
 * A fitting string that is not a commit id still invalidates only the cache;
 * it never grants authority and costs at most another replay. */
static bool dl_prechecked_parse(const char *line, struct dl_row *r)
{
    struct dl_string_result checked = dl_line_string(line, "prechecked_main",
        r->prechecked, sizeof(r->prechecked));
    struct dl_string_result uncertain = dl_line_string(line, "precheck_uncertain_main",
        r->uncertain_main, sizeof(r->uncertain_main));
    if (checked.state == DL_STRING_INVALID || uncertain.state == DL_STRING_INVALID)
        return false;
    if (checked.state != DL_STRING_FOUND || !dl_sha_ok(r->prechecked))
        r->prechecked[0] = '\0';
    if (uncertain.state != DL_STRING_FOUND ||
        !dl_sha_ok(r->uncertain_main) ||
        !dl_line_int(line, "precheck_uncertain", &r->uncertain_tries) ||
        r->uncertain_tries < 0) {
        r->uncertain_main[0] = '\0';
        r->uncertain_tries = 0;
    }
    return true;
}

static bool dl_optional_row_strings(const char *line, struct dl_row *r)
{
    const struct { const char *key; char *out; size_t cap; } fields[] = {
        { "ts", r->ts, sizeof(r->ts) },
        { "worktree", r->worktree, sizeof(r->worktree) },
        { "note", r->note, sizeof(r->note) },
        { "phase", r->phase, sizeof(r->phase) },
        { "base", r->base, sizeof(r->base) },
        { "local", r->local, sizeof(r->local) },
        { "tree", r->tree, sizeof(r->tree) },
        { "proof_intent", r->proof_intent, sizeof(r->proof_intent) },
        { "publication_target", r->publication_target, sizeof(r->publication_target) },
        { "publication_proof", r->publication_proof, sizeof(r->publication_proof) },
        { "publication_bundle", r->publication_bundle, sizeof(r->publication_bundle) },
        { "publication_signer", r->publication_signer, sizeof(r->publication_signer) },
        { "publication_signature", r->publication_signature, sizeof(r->publication_signature) },
        { "remote_tip", r->remote_tip, sizeof(r->remote_tip) },
        { "remote_source", r->remote_source, sizeof(r->remote_source) },
        { "remote_signer", r->remote_signer, sizeof(r->remote_signer) },
        { "remote_signature", r->remote_signature, sizeof(r->remote_signature) },
        { "tip_pushed", r->pushed, sizeof(r->pushed) },
        { "dimension", r->dimension, sizeof(r->dimension) },
        { "log_path", r->log_path, sizeof(r->log_path) },
        { "detail", r->detail, sizeof(r->detail) }
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        struct dl_string_result value = dl_line_string(line, fields[i].key,
            fields[i].out, fields[i].cap);
        if (value.state == DL_STRING_INVALID) return false;
    }
    return true;
}

static bool dl_parse_dispatch_fields(const char *line, struct dl_row *r)
{
    long long pending = 0;
    (void)dl_line_int(line, "push_diagnostic_pending", &pending);
    r->push_diagnostic_pending = pending != 0;
    (void)dl_line_int(line, "fence_peer", &r->fence_peer);
    (void)dl_line_int(line, "producer_recovered", &r->producer_recovered);
    /* Absent, non-integer or out-of-range (ERANGE) text stays 0; any other non-zero integer (or "1x") is spent. */
    r->producer_recovered = r->producer_recovered != 0;
    (void)dl_line_int(line, "phase_mail", &r->phase_mail);
    if (r->phase_mail < 0)
        r->phase_mail = 0;
    return dl_chain_fields_parse(line, r) && r->fence_peer >= 0 &&
        (strcmp(r->state, "fenced") != 0 || r->fence_peer > 0);
}

static bool dl_required_row_strings(const char *line, struct dl_row *r)
{
    return dl_line_string(line, "tip", r->tip, sizeof(r->tip)).state == DL_STRING_FOUND &&
        dl_sha_ok(r->tip) &&
        dl_line_string(line, "state", r->state, sizeof(r->state)).state == DL_STRING_FOUND;
}

static bool dl_parse_row(const char *line, struct dl_row *r)
{
    long long priority = 0;
    bool has_priority = false;
    bool hold = false;
    if (!line || !line[0] || !r)
        return false;
    if (!dl_row_json_ok(line, &priority, &has_priority, &hold))
        return false;
    memset(r, 0, sizeof(*r));
    r->publication_hold = hold;
    if (!dl_line_int(line, "seq", &r->seq) || r->seq < 1)
        return false;
    if (!dl_priority_parse(r, priority, has_priority))
        return false;
    if (!dl_required_row_strings(line, r))
        return false;
    if (!dl_optional_row_strings(line, r)) return false;
    if (!dl_worktree_shape_ok(r->worktree))
        return false;
    if (!dl_line_int(line, "attempt", &r->attempt) || r->attempt < 1)
        return false;
    (void)dl_line_int(line, "started", &r->started);
    return dl_prechecked_parse(line, r) && dl_parse_dispatch_fields(line, r) &&
           dl_row_semantics_ok(r);
}

static bool dl_escape_proof_fields(const struct dl_row *r,
                                    char base[160], char local[160],
                                    char tree[160], char intent[352], char dependency[512])
{
    if (!dl_chain_shape_ok(r)) return false;
    if (r->predecessor_seq && snprintf(dependency, 512,
        ",\"predecessor_seq\":%lld,\"predecessor_local\":\"%s\",\"predecessor_base\":\"%s\","
        "\"predecessor_tree\":\"%s\",\"predecessor_intent\":\"%s\"",
        r->predecessor_seq, r->predecessor_local, r->predecessor_base,
        r->predecessor_tree, r->predecessor_intent) >= 512) return false;
    return dl_escape(r->base, base, 160) &&
           dl_escape(r->local, local, 160) &&
           dl_escape(r->tree, tree, 160) &&
           dl_escape(r->proof_intent, intent, 352);
}

struct dl_publication_escapes {
    char target[130], proof[130], bundle[130], signer[130];
    char signature[258], remote_tip[130], remote_source[130];
    char remote_signer[130], remote_signature[258];
};

static bool dl_escape_start_fields(const struct dl_row *r, char ts[128],
                                    char tip[160], char wt[8192],
                                    char note[2048], char state[64],
                                    char phase[64])
{
    return dl_escape(r->ts, ts, 128) && dl_escape(r->tip, tip, 160) &&
        dl_escape(r->worktree, wt, 8192) &&
        dl_escape(r->note, note, 2048) &&
        dl_escape(r->state, state, 64) &&
        dl_escape(r->phase, phase, 64);
}

static bool dl_escape_publication_fields(const struct dl_row *r,
                                          struct dl_publication_escapes *e)
{
    return dl_escape(r->publication_target, e->target, sizeof(e->target)) &&
        dl_escape(r->publication_proof, e->proof, sizeof(e->proof)) &&
        dl_escape(r->publication_bundle, e->bundle, sizeof(e->bundle)) &&
        dl_escape(r->publication_signer, e->signer, sizeof(e->signer)) &&
        dl_escape(r->publication_signature, e->signature,
                  sizeof(e->signature)) &&
        dl_escape(r->remote_tip, e->remote_tip, sizeof(e->remote_tip)) &&
        dl_escape(r->remote_source, e->remote_source,
                  sizeof(e->remote_source)) &&
        dl_escape(r->remote_signer, e->remote_signer,
                  sizeof(e->remote_signer)) &&
        dl_escape(r->remote_signature, e->remote_signature,
                  sizeof(e->remote_signature));
}

static const char *dl_hold_literal(bool hold)
{
    return hold ? "true" : "false";
}

static bool dl_encode_row(const struct dl_row *r, char *out, size_t cap,
                          size_t *len_out)
{
    char e_ts[128], e_tip[160], e_wt[8192], e_note[2048], e_state[64];
    char e_phase[64], e_base[160], e_local[160], e_tree[160];
    char e_intent[352], e_pushed[160];
    char dependency[512] = "";
    struct dl_publication_escapes p;
    /* r->detail is char[1024]; dl_escape() can expand a raw control byte
     * (anything but \n/\r/\t) into a 6-byte "\u00XX" sequence, so an
     * ALL-control-byte detail needs up to 1023*6=6138 bytes to escape
     * cleanly. dl_first_actionable() already sanitises what it copies into
     * detail, but detail has other writers too (the proof stub's raw
     * value among them in tests) — sized here for the true worst case of
     * its source field rather than for the sanitised common case, so a
     * valid UTF-8 detail cannot overflow its escaped buffer. */
    char e_dim[128], e_log[8192], e_detail[1024 * 6 + 16];
    int w;
    if (!r || !out || cap == 0)
        return false;
    if (!dl_escape_start_fields(r, e_ts, e_tip, e_wt, e_note, e_state,
                                e_phase) ||
        !dl_escape_proof_fields(r, e_base, e_local, e_tree, e_intent, dependency) ||
        !dl_escape_publication_fields(r, &p) ||
        !dl_escape(r->pushed, e_pushed, sizeof(e_pushed)) ||
        !dl_escape(r->dimension, e_dim, sizeof(e_dim)) ||
        !dl_escape(r->log_path, e_log, sizeof(e_log)) ||
        !dl_escape(r->detail, e_detail, sizeof(e_detail)))
        return false;
    w = snprintf(out, cap,
                 "{\"seq\":%lld,\"priority_seq\":%lld,\"ts\":\"%s\",\"tip\":\"%s\","
                 "\"worktree\":\"%s\",\"note\":\"%s\",\"state\":\"%s\","
                 "\"phase\":\"%s\",\"attempt\":%lld,\"started\":%lld,"
                 "\"base\":\"%s\",\"local\":\"%s\",\"tree\":\"%s\","
                 "\"proof_intent\":\"%s\",\"tip_pushed\":\"%s\","
                 "\"publication_target\":\"%s\",\"publication_proof\":\"%s\","
                 "\"publication_bundle\":\"%s\",\"publication_signer\":\"%s\","
                 "\"publication_signature\":\"%s\","
                 "\"remote_tip\":\"%s\",\"remote_source\":\"%s\","
                 "\"remote_signer\":\"%s\",\"remote_signature\":\"%s\","
                 "\"dimension\":\"%s\",\"log_path\":\"%s\","
                 "\"prechecked_main\":\"%s\","
                 "\"precheck_uncertain_main\":\"%s\","
                 "\"precheck_uncertain\":%lld,\"producer_recovered\":%lld,"
                 "\"phase_mail\":%lld,\"detail\":\"%s\","
                 "\"push_diagnostic_pending\":%d,\"fence_peer\":%lld,"
                 "\"publication_hold\":%s%s}\n",
                 r->seq, r->priority_seq, e_ts, e_tip, e_wt, e_note, e_state, e_phase,
                 r->attempt, r->started, e_base, e_local, e_tree, e_intent,
                 e_pushed, p.target, p.proof, p.bundle, p.signer, p.signature,
                 p.remote_tip, p.remote_source, p.remote_signer,
                 p.remote_signature,
                 /* Unescaped on purpose: dl_prechecked_parse() and the
                  * precheck admit only a 40-hex commit id or "". */
                 e_dim, e_log, r->prechecked, r->uncertain_main,
                 r->uncertain_tries, r->producer_recovered, r->phase_mail, e_detail,
                 r->push_diagnostic_pending ? 1 : 0,
                 r->fence_peer, dl_hold_literal(r->publication_hold), dependency);
    if (w <= 0 || (size_t)w >= cap)
        return false;
    if (len_out)
        *len_out = (size_t)w;
    return true;
}

#if defined(ZCL_TESTING)
/* Exercise the production row encoder with deterministic, bounded strings. */
bool zcl_native_dev_land_test_encode_text(const char *text, bool detail,
                                         char *out, size_t cap,
                                         size_t *len_out)
{
    struct dl_row row = {0};
    if (!text)
        return false;
    size_t len = strlen(text);
    char *field = detail ? row.detail : row.note;
    size_t field_cap = detail ? sizeof(row.detail) : sizeof(row.note);
    if (len >= field_cap)
        return false;
    memcpy(field, text, len + 1);
    return dl_encode_row(&row, out, cap, len_out);
}
#endif

#if defined(ZCL_TESTING)
/* Fixture-only composition of the real serializer and row reader. The queue
 * status projection omits detail; this checks decoded bytes before file IO. */
bool zcl_native_dev_land_test_encode_detail(const char *detail, bool terminal,
                                           char *out, size_t cap)
{
    struct dl_row row = { .seq = 1, .priority_seq = 1, .attempt = 1 };
    struct dl_row decoded;
    if (!detail || strlen(detail) >= sizeof(row.detail)) return false;
    memcpy(row.detail, detail, strlen(detail) + 1);
    memcpy(row.tip, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 41);
    (void)snprintf(row.state, sizeof(row.state), "%s", terminal ? "failed" : "queued");
    return dl_encode_row(&row, out, cap, NULL) && dl_parse_row(out, &decoded) &&
           strcmp(decoded.detail, detail) == 0;
}
#endif

static bool dl_queue_row_ok(const char *line, struct dl_row *r,
                            long long last_seq)
{
    return dl_parse_row(line, r) &&
           (strcmp(r->state, "queued") == 0 ||
            strcmp(r->state, "inflight") == 0) &&
           r->seq > last_seq;
}

#if defined(ZCL_TESTING)
bool zcl_native_dev_land_test_chain_codec(const char *line, char *out, size_t cap)
{
    struct dl_row row;
    return dl_parse_row(line, &row) && dl_encode_row(&row, out, cap, NULL);
}

#endif

static bool dl_rows_reserve(struct dl_row **rows, size_t *cap, size_t n,
                             char *why, size_t why_cap)
{
    if (n < *cap)
        return true;
    size_t next = *cap == 0 ? 16 : *cap * 2;
    if (next > 65536) {
        if (why && why_cap)
            (void)snprintf(why, why_cap, "queue_row_capacity_exceeded");
        errno = EOVERFLOW;
        return false;
    }
    struct dl_row *grow = (struct dl_row *)zcl_realloc(
        *rows, next * sizeof(**rows), "dev.land.rows");
    if (!grow) {
        if (why && why_cap)
            (void)snprintf(why, why_cap, "queue_row_allocation_failed");
        errno = ENOMEM;
        return false;
    }
    *rows = grow;
    *cap = next;
    return true;
}

/* A malformed or legacy queue row is an obstruction, never permission to
 * forget that work. Preserve the file byte-for-byte and name the offending
 * record so another worker can diagnose it. A missing file is empty. */
static bool dl_load_rows(const char *qpath, struct dl_row **rows_out,
                         size_t *n_out, char *why, size_t why_cap)
{
    char *text;
    struct dl_row *rows = NULL;
    size_t n = 0, cap = 0;
    char *save = NULL, *line;
    int read_errno = 0;
    size_t record = 0;
    long long last_seq = 0;
    if (!qpath || !rows_out || !n_out)
        return false;
    *rows_out = NULL;
    *n_out = 0;
    text = (char *)zcl_malloc(DL_FILE_CAP, "dev.land.file");
    if (!text)
        return false;
    if (!dl_read_file(qpath, text, DL_FILE_CAP, NULL)) {
        read_errno = errno;
        free(text);
        if (read_errno != ENOENT && why && why_cap)
            (void)snprintf(why, why_cap, "queue_read_failed_errno_%d",
                           read_errno);
        return read_errno == ENOENT;
    }
    for (line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        struct dl_row r;
        record++;
        if (!dl_queue_row_ok(line, &r, last_seq)) {
            if (why && why_cap)
                (void)snprintf(why, why_cap,
                               "malformed_queue_record_%zu", record);
            free(rows);
            free(text);
            errno = EINVAL;
            return false;
        }
        last_seq = r.seq;
        if (!dl_rows_reserve(&rows, &cap, n, why, why_cap)) {
            free(rows);
            free(text);
            return false;
        }
        rows[n++] = r;
    }
    free(text);
    *rows_out = rows;
    *n_out = n;
    return true;
}

static const char *dl_reason_or_path(const char *why, const char *path)
{
    return why && why[0] ? why : path;
}

static bool dl_queue_file_flush(FILE *f)
{
    if (fflush(f) != 0)
        return false;
#if defined(_WIN32)
    return _commit(_fileno(f)) == 0;
#else
    return fsync(fileno(f)) == 0;
#endif
}

static bool dl_queue_parent_flush(const char *landdir)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    if (getenv("ZCL_LAND_TEST_DIR_SYNC_FAIL"))
        return false;
#endif
    return platform_private_parent_flush(landdir);
}

/* Whole-file rewrite under the row lock: flush the file before rename and
 * the parent after rename, so a pre-push checkpoint survives a restart. */
static bool dl_rewrite_rows(const char *landdir, const char *qpath,
                            const struct dl_row *rows, size_t n)
{
    char tmp[4096 + 32];
    FILE *f;
    char *line;
    size_t len = 0;
    if (!landdir || !qpath || (!rows && n > 0))
        return false;
    if (snprintf(tmp, sizeof(tmp), "%s/queue.jsonl.tmp", landdir) >=
        (int)sizeof(tmp))
        return false;
    line = (char *)zcl_malloc(DL_LINE_CAP, "dev.land.line");
    if (!line)
        return false;
    f = fopen(tmp, "wb");
    if (!f) {
        free(line);
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (!dl_encode_row(&rows[i], line, DL_LINE_CAP, &len) ||
            (len > 0 && fwrite(line, 1, len, f) != len)) {
            (void)fclose(f);
            free(line);
            (void)unlink(tmp);
            return false;
        }
    }
    free(line);
    if (!dl_queue_file_flush(f)) {
        (void)fclose(f);
        (void)unlink(tmp);
        return false;
    }
    if (fclose(f) != 0) {
        (void)unlink(tmp);
        return false;
    }
    /* dl_rewrite_rows always runs under dl_rows_lock, so queue.jsonl.tmp
     * has exactly one writer at a time: a failed rename leaves a stale
     * temp file behind for the next rewrite to overwrite, but leaving it
     * after a failure that stops here (rather than at rename) is pure
     * litter — clean it up rather than leaving proof of a failed rewrite
     * on disk indefinitely. */
    if (rename(tmp, qpath) != 0) {
        (void)unlink(tmp);
        return false;
    }
    return dl_queue_parent_flush(landdir);
}

/* ── locks ─────────────────────────────────────────────────────────────── */

static int dl_lock_path(const char *path, bool nonblocking)
{
    int fd;
    if (!path)
        return -1;
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
#if !defined(_WIN32)
    if (flock(fd, nonblocking ? (LOCK_EX | LOCK_NB) : LOCK_EX) != 0) {
        (void)close(fd);
        return -1;
    }
#else
    (void)nonblocking;
#endif
    return fd;
}

static int dl_rows_lock(const char *landdir)
{
    char path[4096 + 32];
    if (!landdir ||
        snprintf(path, sizeof(path), "%s/queue.lock", landdir) >=
            (int)sizeof(path))
        return -1;
    return dl_lock_path(path, false);
}

/* The queue's step lock. Non-blocking on purpose: a step that cannot have
 * it says so and returns, because a step that waited would be exactly the
 * blocking this leaf exists to remove. Reuses dl_lock_path(), the same
 * open+flock(LOCK_EX|LOCK_NB) helper queue.lock uses, rather than a second
 * raw lock primitive. Windows refuses step before this POSIX helper is used. */
[[maybe_unused]] static int dl_step_lock(const char *landdir)
{
    char path[4096 + 32];
    if (!landdir ||
        snprintf(path, sizeof(path), "%s/step.lock", landdir) >=
            (int)sizeof(path))
        return -1;
    return dl_lock_path(path, true);
}

static void dl_unlock(int fd)
{
    if (fd < 0)
        return;
#if !defined(_WIN32)
    (void)flock(fd, LOCK_UN);
#endif
    (void)close(fd);
}

/* ── git, and only git ─────────────────────────────────────────────────── */

/* Run one git command in `dir` and capture its stdout. No shell is ever
 * involved: argv goes straight to execvp through util/spawn.h. Returns the
 * child's exit status, or -1 when the launch itself failed. */
static int dl_git(const char *dir, const char *const *args, char *out,
                  size_t cap, int timeout_ms)
{
    const char *argv[24];
    size_t n = 0;
    if (out && cap)
        out[0] = '\0';
    if (!dir || !args)
        return -1;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = dir;
    for (size_t i = 0; args[i]; i++) {
        if (n + 2 > sizeof(argv) / sizeof(argv[0]))
            return -1;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    {
        char sink[2];
        return zcl_spawn_capture(argv, out ? out : sink,
                                 out ? cap : sizeof(sink), timeout_ms);
    }
}

static void dl_trim(char *s)
{
    size_t n;
    if (!s)
        return;
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
                     s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = '\0';
}

/* Resolve a commit-ish to its full commit id in `dir`. */
static bool dl_rev_parse(const char *dir, const char *what, char out[80])
{
    char spec[160], buf[256];
    const char *args[] = { "rev-parse", "--verify", "--quiet", spec, NULL };
    if (!dir || !what || !out)
        return false;
    if (snprintf(spec, sizeof(spec), "%s^{commit}", what) >=
        (int)sizeof(spec))
        return false;
    if (dl_git(dir, args, buf, sizeof(buf), DL_GIT_TIMEOUT_MS) != 0)
        return false;
    dl_trim(buf);
    if (!dl_sha_ok(buf))
        return false;
    (void)snprintf(out, 80, "%s", buf);
    return true;
}

/* ── the mail outbox (agents learn by pulling, never by waiting) ───────── */

/* Sibling sub-dispatch into dev.agent.mail: the land leaf never appends to
 * the mail store directly. A raw row cannot carry the mail leaf's
 * sequencing (the land queue's own seq would collide with the outbox's seq
 * space) and rows without to/body, or with a kind outside the mail set,
 * never parse back — every such outcome was skipped by every pull while
 * the global cursor stood still. Posting through the owning leaf keeps one
 * writer, one seq space, and rows every reader parses. Same in-process
 * shape the worker leaf uses for its result mail. */
struct dl_msub {
    struct json_value payload;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
    bool ran;
    bool valid;
};

static void dl_msub_begin(struct dl_msub *s)
{
    json_init(&s->payload);
    json_set_object(&s->payload);
    memset(&s->request, 0, sizeof(s->request));
    s->request.input = &s->payload;
    s->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), "dev.agent.mail",
                                  NULL);
    s->request.view = "normal";
    zcl_command_reply_init(&s->reply, "zcl.agent_mail.v1");
    s->ran = false;
    s->valid = s->request.spec != NULL;
}

static void dl_msub_end(struct dl_msub *s)
{
    zcl_command_reply_free(&s->reply);
    json_free(&s->payload);
    s->ran = false;
}

static bool dl_msub_ok(const struct dl_msub *s)
{
    return s && s->ran && s->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

/* The log file's own name: the mail leaf refuses absolute paths anywhere
 * in a body, and the full path is local-only evidence that never crosses
 * hosts. */
static const char *dl_log_base(const char *path)
{
    const char *slash = path ? strrchr(path, '/') : NULL;
    const char *back = path ? strrchr(path, '\\') : NULL;
    const char *base = slash && back ? (slash > back ? slash : back)
                                     : (slash ? slash : back);
    if (base)
        return base + 1;
    return path ? path : "";
}

/* Full outcome text. False when it does not fit: the caller falls back to
 * the reduced row rather than truncating evidence mid-field. */
static bool dl_outbox_body(const struct dl_row *r, const char *event,
                           char *out, size_t cap)
{
    int w = snprintf(out, cap,
                     "land=%s\nstate=%s\ntip=%s\nattempt=%lld\n"
                     "dimension=%s\nnote=%s\ndetail=%s\nlog=%s\n",
                     event, r->state, r->tip, r->attempt, r->dimension,
                     r->note, r->detail, dl_log_base(r->log_path));
    return w > 0 && (size_t)w < cap;
}

/* The row that always fits: alphabet-constrained fields only, so a body
 * that somehow will not compose never cancels the outcome. Same fail-safe
 * shape as the worker leaf's reduced result mail. */
static void dl_outbox_body_reduced(const struct dl_row *r, const char *event,
                                   char *out, size_t cap)
{
    (void)snprintf(out, cap,
                   "land=%s\nstate=%s\ntip=%s\nattempt=%lld\nreduced=1\n",
                   event, r->state, r->tip, r->attempt);
}

static bool dl_mail_post(const char *body, const char *ref)
{
    struct dl_msub sub;
    bool posted;
    dl_msub_begin(&sub);
    if (!sub.valid) {
        dl_msub_end(&sub);
        return false;
    }
    posted = json_push_kv_str(&sub.payload, "action", "post") &&
             json_push_kv_str(&sub.payload, "to", "*") &&
             json_push_kv_str(&sub.payload, "kind", "note") &&
             json_push_kv_str(&sub.payload, "body", body) &&
             json_push_kv_str(&sub.payload, "ref", ref ? ref : "") &&
             json_push_kv_str(&sub.payload, "from", DL_LEAF);
    if (posted) {
        zcl_command_handler_fn mail_handler = zcl_native_handle_dev_agent_mail;
        mail_handler(&sub.request, &sub.reply);
        /* Ran means the sibling handler was invoked, never that it
         * accepted: acceptance is the reply's own status. */
        sub.ran = true;
        posted = dl_msub_ok(&sub);
    }
    dl_msub_end(&sub);
    return posted;
}

static bool dl_outbox(const struct dl_dirs *d, const struct dl_row *r,
                      const char *event)
{
    /* Bodies stay below the mail leaf's own cap; the full text worst case
     * (note 512 + detail 255 + headers) fits with room to spare. */
    char dir[4096 + 16], full[2048];
    struct stat st;
    if (!d || !r || !event)
        return false;
    if (snprintf(dir, sizeof(dir), "%s/mail", d->root) >= (int)sizeof(dir))
        return false;
    /* Only when the mail leaf's directory already exists: this leaf creates
     * no mailbox of its own and never guesses at another leaf's layout. */
    if (stat(dir, &st) != 0)
        return errno == ENOENT;
    if ((st.st_mode & S_IFMT) != S_IFDIR)
        return false;
    if (dl_outbox_body(r, event, full, sizeof(full)) &&
        dl_mail_post(full, r->tip))
        return true;
    dl_outbox_body_reduced(r, event, full, sizeof(full));
    return dl_mail_post(full, r->tip);
}

/* ── outcomes ──────────────────────────────────────────────────────────── */

/* Encode and append in one call so the encoded length never has to live
 * past a single, self-contained function: dl_record_outcome is a common
 * inline target (dl_cancel calls it too), and a `size_t len` whose address
 * is taken in the caller and used after dl_encode_row returns is exactly
 * the shape GCC's -Wdangling-pointer flags once two inlined copies of that
 * caller share the analysis (false positive here — len is never read past
 * its owning statement). Keeping both the address-of and the use inside
 * one small function removes the ambiguity instead of arguing with it. */
static bool dl_write_row(const char *path, const struct dl_row *r)
{
    char line[DL_LINE_CAP];
    size_t len = 0;
    return dl_encode_row(r, line, sizeof(line), &len) &&
           dl_append_row(path, line, len);
}

static bool dl_outcome_request_matches(const struct dl_row *row,
                                       const struct dl_row *want)
{
    return row->seq == want->seq &&
           strcmp(row->tip, want->tip) == 0 &&
           strcmp(row->ts, want->ts) == 0 &&
           strcmp(row->worktree, want->worktree) == 0;
}

static bool dl_outcome_inputs_match(const struct dl_row *row,
                                    const struct dl_row *want)
{
    return strcmp(row->note, want->note) == 0 &&
           row->predecessor_seq == want->predecessor_seq &&
           strcmp(row->predecessor_local, want->predecessor_local) == 0 &&
           strcmp(row->predecessor_base, want->predecessor_base) == 0 &&
           strcmp(row->predecessor_tree, want->predecessor_tree) == 0 &&
           strcmp(row->predecessor_intent, want->predecessor_intent) == 0 &&
           (!want->base[0] || strcmp(row->base, want->base) == 0) &&
           (!want->local[0] || strcmp(row->local, want->local) == 0);
}

static bool dl_scan_outcome_line(const char *line, const struct dl_row *want,
                                 struct dl_row *found, bool *present,
                                 long long *high_water)
{
    struct dl_row row;
    if (!dl_parse_row(line, &row) ||
        strcmp(row.state, "queued") == 0 ||
        strcmp(row.state, "inflight") == 0)
        return false;
    if (row.seq > *high_water) *high_water = row.seq;
    if (!want || !dl_outcome_request_matches(&row, want)) return true;
    if (!dl_outcome_inputs_match(&row, want)) return false;
    if (*present) return false; /* conflicting terminal observations */
    *present = true;
    if (found) *found = row;
    return true;
}

/* An outcome may have been appended before a crash left its queue row in
 * place. Match the request identity during replay and find the sequence
 * high-water mark for new submissions. Malformed history refuses repair. */
static bool dl_scan_outcomes(const struct dl_dirs *d, const struct dl_row *want,
                             struct dl_row *found, bool *present,
                             long long *high_water)
{
    char path[4096 + 32];
    char *data, *line, *save = NULL;
    size_t len = 0;
    if (!d || !present || !high_water)
        return false;
    *present = false;
    *high_water = 0;
    if (snprintf(path, sizeof(path), "%s/outcomes.jsonl", d->land) >=
        (int)sizeof(path))
        return false;
    data = (char *)zcl_malloc(DL_FILE_CAP, "dev.land.outcome.scan");
    if (!data)
        return false;
    if (!dl_read_file(path, data, DL_FILE_CAP, &len)) {
        int read_errno = errno;
        free(data);
        return read_errno == ENOENT;
    }
    if (memchr(data, '\0', len) || (len && data[len - 1] != '\n')) {
        free(data);
        return false;
    }
    for (line = strtok_r(data, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        if (!dl_scan_outcome_line(line, want, found, present, high_water)) {
            free(data);
            return false;
        }
    }
    free(data);
    return true;
}

static bool dl_record_outcome(const struct dl_dirs *d, struct dl_row *r)
{
    char path[4096 + 32];
    struct dl_row prior;
    bool present = false;
    long long high_water = 0;
    if (!d || !r ||
        !dl_scan_outcomes(d, r, &prior, &present, &high_water) ||
        snprintf(path, sizeof(path), "%s/outcomes.jsonl", d->land) >=
            (int)sizeof(path))
        return false;
    if (present)
        *r = prior;
    else if (
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
        (getenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND") &&
         getenv("ZCL_DEVLOOP_TEST_PROCESS")) ||
#endif
        !dl_write_row(path, r))
        return false;
    return dl_outbox(d, r, "outcome");
}

/* ── commuting tickets: the named call site node2's leaf plugs into ─────
 *
 * A landing does not invalidate what commutes with it. node2 owns
 * dev.proof.tickets: a per-group ticket set saying which groups a proof may
 * legitimately skip because the change under test cannot affect them. This
 * is the ONE place that admission belongs — between "the base is fixed" and
 * "ask for the proof" — and it is deliberately a named function rather than
 * a comment, so the ticket leaf has an exact seam to land in and nothing
 * else in this file has to move.
 *
 * Until that leaf exists there is no ticket set on this host, so the answer
 * is "admit nothing", the proof runs whole, and the queue is merely slower
 * than it will be. Fail-closed: a missing ticket service must never be read
 * as a ticket that admits everything. */
static bool dl_tickets_admit(const struct dl_row *row, const char *base,
                             char *groups, size_t cap)
{
    (void)row;
    (void)base;
    if (groups && cap)
        groups[0] = '\0';
    return false;
}

/* ── the private landing worktree ──────────────────────────────────────── */

static bool dl_wt_ready(const char *wt)
{
    char marker[4096 + 16];
    struct stat st;
    if (!wt ||
        snprintf(marker, sizeof(marker), "%s/.git", wt) >=
            (int)sizeof(marker))
        return false;
    return stat(marker, &st) == 0;
}

/* Whether THIS worktree's own git config already points at an installed
 * hook set. Worktree config (`git config --worktree`) is per-worktree, not
 * shared with the checkout that spawned it, so `git worktree add` alone
 * leaves a brand-new worktree naked even when the source checkout has hooks
 * armed — the landing loop must arm this one itself.
 *
 * A nonempty core.hooksPath is not proof of anything: it can point at a
 * directory that was never populated (a stale config, a test rig, an
 * operator typo), and git silently treats a missing or non-executable
 * pre-push as "no hook" rather than an error — the exact failure mode this
 * leaf's whole contract forbids ("no --no-verify: it goes through the
 * installed pre-push hook like any other push"). So this checks the actual
 * file, not just the setting that names it. */
static bool dl_wt_hooks_ready(const char *wt)
{
    char out[DL_GIT_CAP], hook[4096 + 16];
    const char *args[] = { "config", "--worktree", "--get",
                           "core.hooksPath", NULL };
    struct stat st;
    if (dl_git(wt, args, out, sizeof(out), DL_GIT_TIMEOUT_MS) != 0)
        return false;
    dl_trim(out);
    if (out[0] == '\0')
        return false;
    if (out[0] == '/') {
        if (snprintf(hook, sizeof(hook), "%s/pre-push", out) >=
            (int)sizeof(hook))
            return false;
    } else {
        if (!wt ||
            snprintf(hook, sizeof(hook), "%s/%s/pre-push", wt, out) >=
                (int)sizeof(hook))
            return false;
    }
    return stat(hook, &st) == 0 && S_ISREG(st.st_mode) &&
          access(hook, X_OK) == 0;
}

/* Test-only escape hatch: a throwaway git rig (bare origin + clone, no
 * checkout of this repository) carries no Makefile to run `make
 * install-hooks` in. Tests point this at a fixture hooks directory holding
 * a real executable `pre-push` instead of invoking `make`. Never read
 * outside a test process — dlx_isolate()/dlx_restore() in test_dev_land.c
 * set and clear it the same way they do ZCL_LAND_PROOF_STUB. */
static const char *dl_hooks_stub_dir(void)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    const char *s = getenv("ZCL_LAND_HOOKS_STUB_DIR");
    return s && s[0] ? s : NULL;
#else
    /* A leaked test env var must never turn an operator's production
     * binary's push into a fixture hook that admits anything. */
    return NULL;
#endif
}

/* Byte-for-byte equality of two existing regular files, so a refresh only
 * rewrites when the installed copy really drifted. Any read or size
 * mismatch is simply "not identical"; callers treat that as repair work,
 * never as a hard failure of its own. */
static bool dl_bytes_identical(const char *a, const char *b)
{
#if defined(_WIN32)
    (void)a; (void)b;
    return false;
#else
    FILE *fa = a ? fopen(a, "rb") : NULL;
    FILE *fb = b ? fopen(b, "rb") : NULL;
    char ba[65536], bb[65536];
    bool same = fa && fb;
    while (same) {
        size_t na = fread(ba, 1, sizeof ba, fa);
        size_t nb = fread(bb, 1, sizeof bb, fb);
        same = na == nb && memcmp(ba, bb, na) == 0;
        if (na < sizeof ba || nb < sizeof bb)
            break; /* EOF on at least one side; lengths already compared */
    }
    if (fa) {
        if (ferror(fa))
            same = false;
        (void)fclose(fa);
    }
    if (fb) {
        if (ferror(fb))
            same = false;
        (void)fclose(fb);
    }
    return same;
#endif
}

/* True when the installed hook copy matches the binary the worktree's own
 * build produced — the exact byte equality check-git-hooks-installed
 * demands of a proof generation. A worktree with no built binary yet
 * (a fixture, or a fresh clone before its first lint pass) has nothing
 * to drift from and counts as fresh. */
static bool dl_wt_hooks_fresh(const char *wt)
{
    char out[DL_GIT_CAP], bin[4096 + 96], installed[4096 + 16];
    const char *args[] = { "config", "--worktree", "--get",
                           "core.hooksPath", NULL };
    struct stat st;
    if (dl_git(wt, args, out, sizeof(out), DL_GIT_TIMEOUT_MS) != 0)
        return false;
    dl_trim(out);
    if (!out[0])
        return false;
    if (snprintf(bin, sizeof(bin), "%s/build/bin/z23-git-hook", wt) >=
            (int)sizeof(bin) ||
        stat(bin, &st) != 0 || !S_ISREG(st.st_mode))
        return true;
    if (out[0] == '/') {
        if (snprintf(installed, sizeof(installed), "%s/z23-git-hook",
                     out) >= (int)sizeof(installed))
            return false;
    } else {
        if (snprintf(installed, sizeof(installed), "%s/%s/z23-git-hook",
                     wt, out) >= (int)sizeof(installed))
            return false;
    }
    return dl_bytes_identical(bin, installed);
}

/* Arm this worktree's own pre-push hook so the push below is admitted, or
 * refused, the same way an operator's checkout would be: `make
 * install-hooks` writes a --worktree-scoped core.hooksPath, which `git
 * worktree add` never inherits on its own. This is not best-effort — an
 * unarmed worktree would make every push here silently equivalent to
 * `--no-verify`, which is exactly the fleet rule this leaf must not break. */
static bool dl_wt_hooks_ensure(const char *wt, char *why, size_t why_cap)
{
    const char *stub_dir = dl_hooks_stub_dir();
    char buf[DL_GIT_CAP];
    if (dl_wt_hooks_ready(wt) &&
        (stub_dir || dl_wt_hooks_fresh(wt)))
        return true;
    if (stub_dir) {
        const char *ext_args[] = { "config", "extensions.worktreeConfig",
                                   "true", NULL };
        const char *hook_args[] = { "config", "--worktree",
                                    "core.hooksPath", stub_dir, NULL };
        if (dl_git(wt, ext_args, NULL, 0, DL_GIT_TIMEOUT_MS) != 0 ||
            dl_git(wt, hook_args, NULL, 0, DL_GIT_TIMEOUT_MS) != 0) {
            (void)snprintf(why, why_cap, "%s",
                           "cannot arm the test hook stub");
            return false;
        }
        return true;
    }
    {
        const char *argv[] = { "make", "-C", wt, "install-hooks", NULL };
        int rc = zcl_spawn_capture(argv, buf, sizeof(buf),
                                   DL_LINT_TIMEOUT_MS);
        if (rc != 0 || !dl_wt_hooks_ready(wt)) {
            (void)snprintf(why, why_cap,
                           "make install-hooks failed in the landing "
                           "worktree: %.400s",
                           buf);
            return false;
        }
    }
    return true;
}

/* Create the landing worktree once from the submitting checkout, and reuse
 * it forever after. It is a git worktree, not a clone: it shares the object
 * database, so making one costs a checkout and no fetch. Every return that
 * hands back an existing or freshly created worktree also arms its hooks,
 * so the push phase always goes through the same pre-push admission an
 * operator's own checkout uses. */
static bool dl_wt_ensure(const struct dl_dirs *d, const struct dl_row *r,
                         char *why, size_t why_cap)
{
    const char *base_args[] = { "worktree", "add", "--detach", d->wt,
                                "origin/main", NULL };
    const char *head_args[] = { "worktree", "add", "--detach", d->wt,
                                "HEAD", NULL };
    if (!d || !r)
        return false;
    if (dl_wt_ready(d->wt))
        return dl_wt_hooks_ensure(d->wt, why, why_cap);
    if (!r->worktree[0] || !dl_worktree_ok(r->worktree)) {
        (void)snprintf(why, why_cap, "%s",
                       "source checkout unavailable or outside receiver policy; admission retained in outcomes");
        return false;
    }
    if (dl_git(r->worktree, base_args, NULL, 0, DL_GIT_TIMEOUT_MS) == 0 &&
        dl_wt_ready(d->wt))
        return dl_wt_hooks_ensure(d->wt, why, why_cap);
    if (dl_git(r->worktree, head_args, NULL, 0, DL_GIT_TIMEOUT_MS) == 0 &&
        dl_wt_ready(d->wt))
        return dl_wt_hooks_ensure(d->wt, why, why_cap);
    (void)snprintf(why, why_cap, "git worktree add %s failed", d->wt);
    return false;
}

/* ── failure triage ────────────────────────────────────────────────────── */

/* Host-load failures: the source-identity capture race and the timeouts.
 * These say nothing about the change under test, so they earn a retry; a
 * red dimension does not. */
static bool dl_host_load_failure(const char *text)
{
    static const char *const marks[] = {
        "exact source capture failed",
        "source identity",
        "PROOF_WAIT_TIMEOUT",
        "proof_wait_timeout",
        "Resource temporarily unavailable",
        "Cannot allocate memory",
        "timed out",
    };
    if (!text)
        return false;
    for (size_t i = 0; i < sizeof(marks) / sizeof(marks[0]); i++) {
        if (strstr(text, marks[i]))
            return true;
    }
    return false;
}

/* Copy `line` into `out` (cap bytes, NUL-terminated), replacing every
 * control byte (and DEL) with a space and truncating rather than growing.
 * dl_escape() expands a raw control byte other than \n/\r/\t into a 6-byte
 * "\u00XX" sequence, so a `detail` field dense with control bytes can grow
 * past e_detail's cap in dl_encode_row and make the whole row unpersistable.
 * Replacing them here — before they ever reach row->detail — keeps the
 * worst-case expansion in dl_escape to the 2x of a quote or backslash,
 * which always fits. */
static void dl_sanitize_copy(const char *line, char *out, size_t cap)
{
    size_t used = 0;
    if (!out || cap == 0)
        return;
    if (!line) {
        out[0] = '\0';
        return;
    }
    for (const unsigned char *p = (const unsigned char *)line;
         *p && used + 1 < cap; p++)
        out[used++] = (*p < 0x20 || *p == 0x7f) ? ' ' : (char)*p;
    out[used] = '\0';
}

/* The first line a person can act on: the earliest line naming an error, a
 * failure, or a refusal. A tail is not an answer; this is. */
static void dl_first_actionable(const char *text, char *out, size_t cap)
{
    static const char *const needles[] = {
        "FAIL", "fail", "error:", "Error", "ERROR", "undefined reference",
        "refused", "assert",
    };
    char *copy, *save = NULL, *line;
    size_t len;
    if (out && cap)
        out[0] = '\0';
    if (!text || !out || cap == 0)
        return;
    len = strlen(text) + 1;
    copy = (char *)zcl_malloc(len, "dev.land.triage");
    if (!copy)
        return;
    memcpy(copy, text, len);
    for (line = strtok_r(copy, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        /* Gate names can contain "fail" (check-pipefail-status-pipe).
         * A passing result is not the failure that stopped the candidate. */
        const char *result = line + strspn(line, " \t\r");
        if (strncmp(result, "PASS", 4) == 0 &&
            (result[4] == '\0' || strchr(" \t\r", result[4])))
            continue;
        for (size_t i = 0; i < sizeof(needles) / sizeof(needles[0]); i++) {
            if (strstr(line, needles[i])) {
                dl_sanitize_copy(line, out, cap);
                free(copy);
                return;
            }
        }
    }
    free(copy);
}

/* ── the proof, through the existing dev.proof machinery ───────────────── */

enum dl_proof {
    DL_PROOF_MISSING = -3,
    DL_PROOF_UNAVAILABLE = -2,
    DL_PROOF_FAILED = -1,
    DL_PROOF_PENDING = 0,
    DL_PROOF_PASSED = 1,
};

/* The test-only proof stub. A test that ran a REAL 15-minute proof would not
 * be a test of this queue, so the stub replaces the proof and nothing else:
 * every rebase, push, row and lock below is the production path. */
static const char *dl_stub(void)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    const char *s = getenv("ZCL_LAND_PROOF_STUB");
    return s && s[0] ? s : NULL;
#else
    /* A leaked test env var must never turn an operator's production
     * binary's step into an evidence-free "pass" pushed to main. */
    return NULL;
#endif
}

/* The queued pair is already durable. Any worker with this checkout can run
 * the existing one-pair foreground proof, then a later land step consumes
 * its signed receipt. Keep the exact input in the row detail so losing the
 * originating process does not lose the next action. */
static void dl_proof_step_detail(const char *wt, const char *local,
                                 const char *base, char *detail, size_t cap)
{
    (void)wt;
    int n = snprintf(detail, cap,
        "dev proof step --local_commit=%s --remote_base=%s; "
        "root=dev land status in_flight.proof_step.root",
        local, base);
    if (n < 0 || (size_t)n >= cap)
        (void)snprintf(detail, cap,
                       "proof pending; exact step exceeds row detail budget");
}

#ifdef ZCL_DEV_BUILD
static void dl_proof_status_detail(const struct zcl_dev_proof_status *status,
                                   const char *wt, const char *local,
                                   const char *base, char *detail, size_t cap)
{
    const char *arm = getenv("ZCL_LAND_START_PROOF_WATCHER");
    if ((status->state == ZCL_DEV_PROOF_STATE_MISSING ||
         (status->state == ZCL_DEV_PROOF_STATE_RUNNING &&
          status->worker_id == 0)) &&
        !zcl_native_dev_loop_proof_queue_ready(wt) &&
        !(arm && strcmp(arm, "1") == 0)) {
        dl_proof_step_detail(wt, local, base, detail, cap);
        return;
    }
    (void)snprintf(detail, cap, "%s",
                   status->detail[0] ? status->detail
                                     : zcl_dev_proof_state_name(status->state));
}
#endif

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
/* A one-shot service owns its cgroup only until the step returns. Launch
 * the existing watcher through host admission so its verification lifetime
 * belongs to the development scope, not that completed service beat.
 * Preparation stays in its original containment. A bounded admission wait
 * or unknown readiness leaves the same exact proof request pending. */
#if defined(__linux__)
static void dl_watcher_launch_scheduled(const char *wt, const char *scheduler,
    bool (*is_ready)(const char *), char *detail, size_t cap)
{
    char image[PATH_MAX], input[PATH_MAX * 2 + 128];
    char output[4096];
    if (!os_proc_exe_path(image, sizeof(image))) {
        (void)snprintf(detail, cap, "proof_watcher_admission_unavailable: paths");
        return;
    }
    struct json_value request;
    json_init(&request); json_set_object(&request);
    bool ok = json_push_kv_str(&request, "root", wt) &&
        json_push_kv_str(&request, "mode", "verify");
    size_t len = ok ? json_write(&request, NULL, 0) : 0;
    ok = ok && len > 0 && len < sizeof(input) - 8;
    if (ok) {
        memcpy(input, "--input=", 8);
        ok = json_write(&request, input + 8, sizeof(input) - 8) == len;
    }
    json_free(&request);
    if (!ok) {
        (void)snprintf(detail, cap, "proof_watcher_admission_unavailable: input");
        return;
    }
    const char *argv[] = { scheduler, "--wait", "--project", "z23", image,
        "dev", "loop", "ensure", input, NULL };
    int rc = zcl_spawn_capture(argv, output, sizeof(output), 10000);
    /* Exit success alone is not evidence that the singleton is ready.
     * Conversely, an observer timeout does not prove that launch failed. */
    if (is_ready && is_ready(wt))
        (void)snprintf(detail, cap, "resident_proof_watcher_ready");
    else
        (void)snprintf(detail, cap,
            "proof_watcher_admission_deferred: exit=%d; readiness_unconfirmed", rc);
}
#if defined(ZCL_TESTING)
void zcl_native_dev_land_test_watcher_launch(const char *wt,
    const char *scheduler, char *detail, size_t cap)
{
    dl_watcher_launch_scheduled(wt, scheduler, NULL, detail, cap);
}
#endif
#if defined(ZCL_DEV_BUILD)
static void dl_watcher_kick_scheduled(const char *wt, char *detail, size_t cap)
{
    char scheduler[PATH_MAX];
    const char *home = getenv("HOME");
    int n = home ? snprintf(scheduler, sizeof(scheduler), "%s/bin/devbuild",
                            home) : -1;
    if (n <= 0 || (size_t)n >= sizeof(scheduler)) {
        (void)snprintf(detail, cap, "proof_watcher_admission_unavailable: paths");
        return;
    }
    dl_watcher_launch_scheduled(wt, scheduler,
        zcl_native_dev_loop_proof_queue_ready, detail, cap);
}
#endif
#endif
#endif

#ifdef ZCL_DEV_BUILD
/* A proof request is durable before a worker claims it. An unarmed landing
 * names the exact dev.proof.step input so another worker can take it. Only an
 * operator's explicit ZCL_LAND_START_PROOF_WATCHER=1 choice starts the
 * resident verify watcher here.
 *
 * The non-Linux path reaches dev.loop's internal async-start entry point THROUGH a local
 * function-pointer variable, never by calling it by name, for the same
 * reason native_vault_command.c's vault_dispatch() calls target->handler(...)
 * instead of naming the routed leaf's handler directly: a literal
 * `zcl_native_handle_dev_loop_start_async(&req, &reply)` call site here
 * makes tools/lint/check_command_input_keys.sh's call-graph closure walk
 * INTO that function's real callee, dev_loop_ensure() (native_dev_command.c),
 * which genuinely reads "root"/"mode" off ITS OWN request — and the closure
 * has no notion of which struct instance a callee reads, only that the
 * call graph reaches it, so it folds those reads up into whichever leaf's
 * handler reached them by name. That handler here is
 * zcl_native_handle_dev_land, so a named call previously made "root"/"mode"
 * look like part of dev.land's real, caller-facing input contract, when no
 * caller of `dev land` ever supplies either: kick_input is built entirely
 * from `wt` (this function's own parameter) and the literal "verify", never
 * from dev.land's own request. Routing through a function pointer breaks
 * that false edge exactly like vault_dispatch's target->handler(...) does,
 * without needing dev.loop.start.async to be its own registered leaf (it
 * isn't one — it is an internal, unregistered wrapper around the real
 * dev.loop.ensure handler, used only by in-process callers that want the
 * non-blocking, wait_ready=false variant). */
#if defined(__linux__)
static void dl_watcher_kick(const char *wt, char *detail, size_t cap)
{
    if (wt && wt[0] && !zcl_native_dev_loop_proof_queue_ready(wt))
        dl_watcher_kick_scheduled(wt, detail, cap);
}
#else
static void dl_watcher_kick(const char *wt, char *detail, size_t cap)
{
    struct json_value kick_input;
    struct zcl_command_request req;
    struct zcl_command_reply reply;
    const char *err, *mode;
    const struct json_value *mode_v;
    zcl_command_handler_fn start_watcher = zcl_native_handle_dev_loop_start_async;

    if (!wt || !wt[0] || zcl_native_dev_loop_proof_queue_ready(wt))
        return;
    json_init(&kick_input);
    json_set_object(&kick_input);
    memset(&req, 0, sizeof(req));
    zcl_command_reply_init(&reply, "zcl.dev_loop_status.v1");
    if (json_push_kv_str(&kick_input, "root", wt) &&
        json_push_kv_str(&kick_input, "mode", "verify")) {
        req.input = &kick_input;
        start_watcher(&req, &reply);
        if (reply.exit_code == ZCL_COMMAND_EXIT_OK) {
            (void)snprintf(detail, cap, "%s",
                           "resident_proof_watcher_started");
        } else if (strcmp(reply.error.code, "WATCHER_MODE_MISMATCH") == 0) {
            mode_v = json_get(&reply.data, "mode");
            mode = (mode_v && mode_v->type == JSON_STR)
                       ? json_get_str(mode_v) : "";
            (void)snprintf(detail, cap,
                           "resident_proof_watcher_mode_mismatch: %s",
                           mode && mode[0] ? mode : "unknown");
        } else {
            err = reply.error.message[0] ? reply.error.message
                : (reply.error.evidence[0] ? reply.error.evidence
                                           : "start_failed");
            (void)snprintf(detail, cap,
                           "resident_proof_watcher_absent: %s", err);
        }
    } else {
        (void)snprintf(detail, cap, "%s",
                       "resident_proof_watcher_absent: request_alloc");
    }
    zcl_command_reply_free(&reply);
    json_free(&kick_input);
}
#endif
#endif

static enum dl_proof dl_proof_request(const char *wt, const char *local,
                                      const char *base, char *detail,
                                      size_t cap)
{
    const char *stub = dl_stub();
    if (detail && cap)
        detail[0] = '\0';
    if (stub) {
        if (strcmp(stub, "watcher_absent") == 0)
            (void)snprintf(detail, cap, "%s",
                           "resident_proof_watcher_absent");
        else if (strcmp(stub, "manual") == 0)
            dl_proof_step_detail(wt, local, base, detail, cap);
        else
            (void)snprintf(detail, cap, "proof stub: %s", stub);
        return DL_PROOF_PENDING;
    }
#ifdef ZCL_DEV_BUILD
    {
        struct zcl_dev_proof_status status = {0};
        if (!zcl_dev_proof_ensure(wt, local, base, &status)) {
            (void)snprintf(detail, cap, "%s",
                           status.detail[0] ? status.detail
                                            : "proof_ensure_failed");
            return DL_PROOF_FAILED;
        }
        (void)snprintf(detail, cap, "%s",
                       status.detail[0] ? status.detail : "proof requested");
        if (status.state == ZCL_DEV_PROOF_STATE_PASSED)
            return DL_PROOF_PASSED;
        if (status.state == ZCL_DEV_PROOF_STATE_FAILED)
            return DL_PROOF_FAILED;
        if (!zcl_native_dev_loop_proof_queue_ready(wt)) {
            const char *arm = getenv("ZCL_LAND_START_PROOF_WATCHER");
            if (arm && strcmp(arm, "1") == 0)
                dl_watcher_kick(wt, detail, cap);
            else
                dl_proof_step_detail(wt, local, base, detail, cap);
        }
        return DL_PROOF_PENDING;
    }
#else
    (void)wt;
    (void)local;
    (void)base;
    (void)snprintf(detail, cap, "%s",
                   "exact proofs need the dev binary (make dev-bin)");
    return DL_PROOF_UNAVAILABLE;
#endif
}

/* How long a queued, never-claimed proof request may read as an ordinary
 * pending state before the land status names its idleness. Default 15
 * minutes (a claim follows a healthy resident within seconds); tests lower
 * it through the environment the same way other bounds are forced. */
static int64_t dl_proof_idle_bound_s(void)
{
    const char *forced = getenv("ZCL_LAND_PROOF_IDLE_SEC");
    if (forced && forced[0]) {
        long parsed = strtol(forced, NULL, 10);
        if (parsed >= 0)
            return (int64_t)parsed;
    }
    return 900;
}

/* Append the named-idleness note to a pending detail when the unclaimed
 * request's age crosses the idle bound. Split out so the land-side unit
 * seam can exercise exactly this judgment hermetically. */
[[maybe_unused]] static void dl_proof_idle_note_append(int64_t age_s, char *detail, size_t cap)
{
    if (age_s < dl_proof_idle_bound_s())
        return;
    char idle[96];
    int wrote = snprintf(idle, sizeof(idle),
                         "; proof_request_idle_age_s=%lld "
                         "(no worker has claimed the queued request)",
                         (long long)age_s);
    if (wrote <= 0 || detail == NULL || detail[0] == '\0')
        return;
    size_t used = strlen(detail);
    if (used + 1 >= cap)
        return;
    size_t room = cap - used - 1;
    size_t add = (size_t)wrote < room ? (size_t)wrote : room;
    memcpy(detail + used, idle, add);
    detail[used + add] = '\0';
}

#if defined(ZCL_TESTING)
/* Hermetic seam for test_dev_land: the same judgment dl_proof_read applies
 * to a real status, without needing a resident watcher in a fixture rig. */
bool zcl_native_dev_land_test_idle_note(int64_t age_s, char *detail,
                                        size_t cap)
{
    size_t before = detail ? strlen(detail) : 0;
    dl_proof_idle_note_append(age_s, detail, cap);
    return detail ? strlen(detail) > before : false;
}

int64_t zcl_native_dev_land_test_idle_bound(void)
{
    return dl_proof_idle_bound_s();
}
#endif

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
/* The land verdict a settled proof status maps to. A failure names its
 * settled reason as the dimension, exactly as it always has. */
static enum dl_proof dl_proof_status_map(
    const struct zcl_dev_proof_status *status, char *dimension,
    size_t dim_cap)
{
    switch (status->state) {
    case ZCL_DEV_PROOF_STATE_PASSED:
        return DL_PROOF_PASSED;
    case ZCL_DEV_PROOF_STATE_FAILED:
        (void)snprintf(dimension, dim_cap, "%s",
                       status->detail[0] ? status->detail : "proof");
        return DL_PROOF_FAILED;
    case ZCL_DEV_PROOF_STATE_INVALID:
        return DL_PROOF_UNAVAILABLE;
    case ZCL_DEV_PROOF_STATE_NO_VERDICT:
        (void)snprintf(dimension, dim_cap, "%s", "proof_no_verdict");
        return DL_PROOF_PENDING;
    case ZCL_DEV_PROOF_STATE_MISSING:
        return DL_PROOF_MISSING;
    default:
        return DL_PROOF_PENDING;
    }
}
#endif

/* Stub "status": the proof itself is not run, but its settled state is
 * read through the production status reader, so a test can plant a real
 * attempt's failure record and watch the queue consume it. */
static enum dl_proof dl_proof_stub_status(const char *wt, const char *local,
                                          const char *base, char *dimension,
                                          size_t dim_cap, char *detail,
                                          size_t cap)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    struct zcl_dev_proof_status status = {0};
    if (!zcl_dev_proof_status_read(wt, local, base, &status)) {
        (void)snprintf(detail, cap, "%s",
                       status.detail[0] ? status.detail
                                        : "proof_status_unreadable");
        return DL_PROOF_FAILED;
    }
    (void)snprintf(detail, cap, "%s",
                   status.detail[0] ? status.detail
                                    : zcl_dev_proof_state_name(status.state));
    return dl_proof_status_map(&status, dimension, dim_cap);
#else
    (void)wt;
    (void)local;
    (void)base;
    (void)dimension;
    (void)dim_cap;
    (void)snprintf(detail, cap, "%s", "proof stub: status unavailable");
    return DL_PROOF_UNAVAILABLE;
#endif
}

#if defined(ZCL_TESTING)
/* Test seam for the producer recovery: the stand-in "rebuild" appends one
 * byte to a counter under the isolated state root, and the stubs below read
 * it. Production never compiles this. */
static bool dl_producer_stub_path(char *path, size_t cap)
{
    const char *state = getenv("XDG_STATE_HOME");
    return state && state[0] &&
           snprintf(path, cap, "%s/producer-recovery-count", state) <
               (int)cap;
}

static long dl_producer_stub_runs(void)
{
    char path[PATH_MAX];
    struct stat st;
    if (!dl_producer_stub_path(path, sizeof(path)) || stat(path, &st) != 0)
        return 0;
    return (long)st.st_size;
}

static bool dl_producer_stub_record(void)
{
    char path[PATH_MAX];
    FILE *f = dl_producer_stub_path(path, sizeof(path))
                  ? fopen(path, "ab") : NULL;
    if (!f)
        return false;
    bool ok = fputc('x', f) != EOF;
    return fclose(f) == 0 && ok;
}

/* Only the testing-only producer stubs skip the rebuild. */
static bool dl_producer_stub_active(void)
{
    const char *stub = dl_stub();
    return stub && strncmp(stub, "producer_stale", 14) == 0;
}

/* "producer_stale" always refuses with the producer-source detail;
 * "producer_stale_once" refuses until one recovery has run, then passes.
 * The "_nv" forms present the same refusal as a NO_VERDICT (pending) status,
 * the way the proof status reader classifies an exact-match record.
 * "producer_stale_text" is a RUNNING (pending) status whose detail merely
 * contains the producer-stale text. "no_verdict_other" is a NO_VERDICT whose
 * detail is not producer-stale. "producer_host_load" is a host-load failure. */
static bool dl_proof_stub_producer(const char *stub, enum dl_proof *out,
                                   char *dimension, size_t dim_cap,
                                   char *detail, size_t cap)
{
    bool nv = strncmp(stub, "producer_stale_nv", 17) == 0;
    bool once = strstr(stub, "_once") != NULL;
    bool other = strcmp(stub, "no_verdict_other") == 0;
    if (strcmp(stub, "producer_host_load") == 0) {
        (void)snprintf(dimension, dim_cap, "test");
        (void)snprintf(detail, cap, "proof stub: timed out");
        *out = DL_PROOF_FAILED;
        return true;
    }
    if (strcmp(stub, "producer_stale_text") == 0) {
        (void)snprintf(detail, cap, "%s",
                       "background_verification_running: "
                       "proof_producer_source_mismatch");
        *out = DL_PROOF_PENDING;
        return true;
    }
    if (!nv && !other && strncmp(stub, "producer_stale", 14) != 0)
        return false;
    if (once && dl_producer_stub_runs() > 0) {
        (void)snprintf(detail, cap, "proof stub: pass");
        *out = DL_PROOF_PASSED;
        return true;
    }
    (void)snprintf(detail, cap, "%s", other
                   ? "proof_producer_source_id_unavailable"
                   : "proof_producer_source_mismatch");
    (void)snprintf(dimension, dim_cap, "%s",
                   nv || other ? "proof_no_verdict" : detail);
    *out = nv || other ? DL_PROOF_PENDING : DL_PROOF_FAILED;
    return true;
}
#endif

static enum dl_proof dl_proof_stub_read(const char *stub, const char *wt,
                                        const char *local, const char *base,
                                        char *dimension, size_t dim_cap,
                                        char *detail, size_t cap)
{
#if defined(ZCL_TESTING)
    enum dl_proof produced;
    if (dl_proof_stub_producer(stub, &produced, dimension, dim_cap, detail,
                               cap))
        return produced;
#endif
    if (strcmp(stub, "status") == 0)
        return dl_proof_stub_status(wt, local, base, dimension, dim_cap,
                                    detail, cap);
    if (strcmp(stub, "pass") == 0) {
        (void)snprintf(detail, cap, "proof stub: pass");
        return DL_PROOF_PASSED;
    }
    if (strcmp(stub, "fail") == 0) {
        (void)snprintf(dimension, dim_cap, "lint");
        (void)snprintf(detail, cap, "proof stub: fail");
        return DL_PROOF_FAILED;
    }
    if (strcmp(stub, "missing") == 0) {
        (void)snprintf(detail, cap, "%s", "proof worker lost its request");
        return DL_PROOF_MISSING;
    }
    if (strcmp(stub, "cancelled") == 0) {
        /* The settled text a requester signal leaves (seq 48's shape). */
        (void)snprintf(dimension, dim_cap, "test");
        (void)snprintf(detail, cap, "%s",
                       "child_proof_cancelled_test_budget_ms_3600000_"
                       "elapsed_ms_215489_idle_ms_213923");
        return DL_PROOF_FAILED;
    }
    if (strcmp(stub, "watcher_absent") == 0)
        (void)snprintf(detail, cap, "%s", "resident_proof_watcher_absent");
    else if (strcmp(stub, "manual") == 0)
        dl_proof_step_detail(wt, local, base, detail, cap);
    else
        (void)snprintf(detail, cap, "proof stub: %s", stub);
    return DL_PROOF_PENDING;
}

static enum dl_proof dl_proof_read(const char *wt, const char *local,
                                   const char *base, char *dimension,
                                   size_t dim_cap, char *detail, size_t cap)
{
    const char *stub = dl_stub();
    if (detail && cap)
        detail[0] = '\0';
    if (dimension && dim_cap)
        dimension[0] = '\0';
    if (stub)
        return dl_proof_stub_read(stub, wt, local, base, dimension,
                                  dim_cap, detail, cap);
#ifdef ZCL_DEV_BUILD
    {
        struct zcl_dev_proof_status status = {0};
        if (!zcl_dev_proof_status_read(wt, local, base, &status)) {
            (void)snprintf(detail, cap, "%s",
                           status.detail[0] ? status.detail
                                            : "proof_status_unreadable");
            return DL_PROOF_FAILED;
        }
        dl_proof_status_detail(&status, wt, local, base, detail, cap);
        /* An unclaimed request that has sat past the idle bound is named,
         * not left as a bare "queued": a driver reading this status must
         * be able to tell "a worker is coming" from "nothing has consumed
         * this request for N seconds" — the difference between waiting
         * and investigating the resident. Observed live 2026-09-09/10: a
         * request sat 36 hours behind an alive-but-silent watcher while
         * every consumer read an ordinary "proving" state. */
        dl_proof_idle_note_append(status.request_age_s, detail, cap);
        return dl_proof_status_map(&status, dimension, dim_cap);
    }
#else
    (void)wt;
    (void)local;
    (void)base;
    (void)snprintf(detail, cap, "%s",
                   "exact proofs need the dev binary (make dev-bin)");
    return DL_PROOF_UNAVAILABLE;
#endif
}

/* Test-only escape hatch for the signature check below: a fixture repo may
 * carry no signing key. Same build-mode guard as dl_stub() and
 * dl_hooks_stub_dir() — a leaked env var must never let a production
 * binary queue an unsigned tip for push. */
static const char *dl_allow_unsigned(void)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    return getenv("ZCL_LAND_ALLOW_UNSIGNED");
#else
    return NULL;
#endif
}

/* ── submit ────────────────────────────────────────────────────────────── */

static bool dl_fence_reserve(const struct dl_dirs *d, long long *seq);
static bool dl_fence_blocks(const struct dl_dirs *d, long long seq);
static bool dl_cancel_fence_guard(const struct dl_dirs *d, long long seq,
                                  struct zcl_command_reply *reply)
{
    if (!dl_fence_blocks(d, seq)) return false;
    dl_fail(reply, "FENCE_ACTIVE", "cancel",
             "a paired fence must be reconciled without ordinary cancellation", d->land);
    return true;
}

static bool dl_submit_next_seq(const struct dl_dirs *d,
                               const struct dl_row *rows, size_t nrows,
                               long long *seq, const char **why)
{
    bool unused_present = false;
    long long high_water = 0;
    if (!dl_scan_outcomes(d, NULL, NULL, &unused_present, &high_water) ||
        high_water == LLONG_MAX) {
        *why = "outcomes.jsonl unreadable, malformed, or exhausted";
        return false;
    }
    if (*seq <= high_water) *seq = high_water + 1;
    for (size_t i = 0; i < nrows; i++) {
        if (rows[i].seq == LLONG_MAX) {
            *why = "queue sequence exhausted";
            return false;
        }
        if (rows[i].seq >= *seq) *seq = rows[i].seq + 1;
    }
    if (!dl_fence_reserve(d, seq)) {
        *why = "fenced replacement journal malformed or sequence exhausted";
        return false;
    }
    return true;
}

/* Called with the queue lock held. A duplicate is either answered here or
 * refused until a durable terminal outcome has been replayed. */
static bool dl_submit_live_duplicate(const struct dl_dirs *d,
                                     const struct dl_row *rows, size_t nrows,
                                     const char *tip, const char *worktree,
                                     struct zcl_command_reply *reply)
{
    for (size_t i = 0; i < nrows; ++i) {
        if (strcmp(rows[i].tip, tip) != 0 ||
            strcmp(rows[i].worktree, worktree) != 0)
            continue;
        struct dl_row terminal;
        bool terminal_seen = false;
        long long high_water = 0;
        if (!dl_scan_outcomes(d, &rows[i], &terminal, &terminal_seen,
                              &high_water)) {
            dl_fail(reply, "QUEUE_READ_FAILED", "submit",
                    "cannot compare the live row with terminal history",
                    "outcomes.jsonl unreadable or malformed");
            return true;
        }
        if (terminal_seen) {
            dl_fail(reply, "TERMINAL_REPLAY_PENDING", "submit",
                    "the matching row has a durable terminal outcome awaiting queue replay",
                    "run dev land step, then resubmit if current-base work is still needed");
            return true;
        }
        (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
        (void)json_push_kv_int(&reply->data, "seq", rows[i].seq);
        (void)json_push_kv_str(&reply->data, "tip", rows[i].tip);
        (void)json_push_kv_str(&reply->data, "state", rows[i].state);
        (void)json_push_kv_str(&reply->data, "phase", rows[i].phase);
        (void)json_push_kv_bool(&reply->data, "deduplicated", true);
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = 0;
        return true;
    }
    return false;
}

/* Finish admission under the same lock that loaded rows. Owns rows and lock
 * on every path so duplicate retries cannot race sequence assignment. */
static void dl_submit_loaded(const struct dl_dirs *d, struct dl_row *r,
                             struct dl_row *rows, size_t nrows, int lock,
                             const char *qpath, const char *tip,
                             const char *worktree,
                             struct zcl_command_reply *reply)
{
    char line[DL_LINE_CAP];
    size_t len = 0;
    long long seq = 1;
    const char *seq_why = NULL;
    if (dl_submit_live_duplicate(d, rows, nrows, tip, worktree, reply)) {
        free(rows);
        dl_unlock(lock);
        return;
    }
    if (!dl_submit_next_seq(d, rows, nrows, &seq, &seq_why)) {
        free(rows);
        dl_unlock(lock);
        dl_fail(reply, "QUEUE_READ_FAILED", "submit",
                "cannot assign a unique sequence while outcomes are unreadable",
                seq_why);
        return;
    }
    free(rows);
    r->seq = seq;
    r->priority_seq = seq;
    if (!dl_encode_row(r, line, sizeof(line), &len) ||
        !dl_append_row(qpath, line, len)) {
        dl_unlock(lock);
        dl_fail(reply, "QUEUE_WRITE_FAILED", "submit",
                "cannot append the request row", qpath);
        return;
    }
    dl_unlock(lock);
    dl_outbox(d, r, "queued");
    (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
    (void)json_push_kv_int(&reply->data, "seq", r->seq);
    (void)json_push_kv_str(&reply->data, "tip", r->tip);
    (void)json_push_kv_str(&reply->data, "state", "queued");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* Admit the candidate only after verifying this worktree has no unfinished
 * Git operation. Worktrees share objects, but --git-path resolves each marker
 * in the submitting worktree's own Git directory. Unreadable state refuses. */
static bool dl_submit_tip_resolve(const char *root, const char *tip,
                                  char full[80],
                                  struct zcl_command_reply *reply)
{
    static const char *const marks[] = { "rebase-merge", "rebase-apply",
        "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "sequencer" };
    if (!dl_rev_parse(root, tip, full)) {
        dl_fail(reply, "TIP_UNKNOWN", "submit",
                "that commit does not exist in the checkout",
                "git rev-parse --verify refused the tip");
        return false;
    }
    for (size_t i = 0; i < sizeof(marks) / sizeof(marks[0]); i++) {
        char rel[4096], path[8192];
        const char *args[] = { "rev-parse", "--git-path", marks[i], NULL };
        if (dl_git(root, args, rel, sizeof(rel), DL_GIT_TIMEOUT_MS) != 0) {
            dl_fail(reply, "WORKTREE_STATE_UNAVAILABLE", "submit",
                    "cannot inspect the submitting worktree's Git state",
                    marks[i]);
            return false;
        }
        dl_trim(rel);
        int n = rel[0] == '/' ? snprintf(path, sizeof(path), "%s", rel)
                             : snprintf(path, sizeof(path), "%s/%s", root, rel);
        if (!rel[0] || n < 0 || (size_t)n >= sizeof(path)) {
            dl_fail(reply, "WORKTREE_STATE_UNAVAILABLE", "submit",
                    "Git operation state path is empty or exceeds its bound",
                    marks[i]);
            return false;
        }
        struct stat st;
        if (lstat(path, &st) == 0) {
            dl_fail(reply, "WORKTREE_BUSY", "submit",
                    "finish or abort the unfinished Git operation, then resubmit",
                    marks[i]);
            return false;
        }
        if (errno != ENOENT) {
            dl_fail(reply, "WORKTREE_STATE_UNAVAILABLE", "submit",
                    "cannot inspect the submitting worktree's Git state",
                    marks[i]);
            return false;
        }
    }
    return true;
}

static void dl_submit(const struct zcl_command_request *req,
                      struct zcl_command_reply *reply)
{
    struct dl_dirs d;
    struct dl_row r;
    struct dl_row *rows = NULL;
    size_t nrows = 0;
    char qpath[4096 + 32];
    char root[4096], sig[64], full[80], ts[64];
    const char *tip, *worktree, *note;
    const char *allow_unsigned = dl_allow_unsigned();
    int lock = -1;

    tip = dl_str(req, "tip");
    if (!tip || !dl_tipish_ok(tip)) {
        dl_fail(reply, "BAD_INPUT", "submit",
                "tip is a 7-64 character hex commit id",
                "input.tip missing or not a commit id");
        return;
    }
    if (!dl_dirs_make(&d)) {
        dl_fail(reply, "STATE_DIR_FAILED", "submit",
                "cannot resolve the owner-private state root",
                "platform_state_root");
        return;
    }
    dl_pool_sweep_and_log(&d);
    worktree = dl_str(req, "worktree");
    root[0] = '\0';
    if (worktree) {
        (void)snprintf(root, sizeof(root), "%s", worktree);
    } else if (!zcl_devagent_checkout_root(".", root, sizeof(root))) {
        dl_fail(reply, "NO_CHECKOUT", "submit",
                "run this inside a Z23 checkout or pass --worktree",
                "no checkout root above the current directory");
        return;
    }
    /* The tip has to be a commit THIS checkout can name. A tip nobody can
     * resolve is not a landing request, it is a typo. */
    if (!dl_submit_tip_resolve(root, tip, full, reply)) {
        return;
    }
    /* Signature. main rejects an unsigned commit, so a queue that accepted
     * one would be queueing a push that cannot succeed. */
    {
        const char *args[] = { "log", "-1", "--format=%G?", full, NULL };
        sig[0] = '\0';
        (void)dl_git(root, args, sig, sizeof(sig), DL_GIT_TIMEOUT_MS);
        dl_trim(sig);
    }
    if (sig[0] != 'G') {
        /* The test-only bypass. It is admitted ONLY alongside the proof
         * stub, which no production caller sets: a signing key is not always
         * available to a test process, but a real submission that skipped
         * both the signature and the proof would be a landing with no
         * evidence at all. */
        if (!(allow_unsigned && strcmp(allow_unsigned, "1") == 0 &&
              dl_stub() != NULL)) {
            dl_fail(reply, "TIP_UNSIGNED", "submit",
                    "main takes signed commits only; sign the tip and "
                    "resubmit",
                    sig[0] ? sig : "git log -1 --format=%G? said nothing");
            return;
        }
    }
    /* Shared history with the branch it is going onto. A tip with no merge
     * base is not something a rebase can fix. */
    {
        const char *args[] = { "merge-base", full, "origin/main", NULL };
        char buf[256];
        if (dl_git(root, args, buf, sizeof(buf), DL_GIT_TIMEOUT_MS) != 0) {
            dl_fail(reply, "TIP_UNRELATED", "submit",
                    "that commit shares no history with origin/main",
                    "git merge-base found no common ancestor");
            return;
        }
    }
    note = dl_str(req, "note");
    if (note && strlen(note) > DL_NOTE_MAX) {
        dl_fail(reply, "BAD_INPUT", "submit",
                "note is at most 512 characters",
                "input.note over the row budget");
        return;
    }
    memset(&r, 0, sizeof(r));
    r.attempt = 1;
    (void)snprintf(r.tip, sizeof(r.tip), "%s", full);
    (void)snprintf(r.worktree, sizeof(r.worktree), "%s", root);
    if (note)
        (void)snprintf(r.note, sizeof(r.note), "%s", note);
    (void)snprintf(r.state, sizeof(r.state), "queued");
    dl_now_iso(ts);
    (void)snprintf(r.ts, sizeof(r.ts), "%s", ts);
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d.land) >=
        (int)sizeof(qpath)) {
        dl_fail(reply, "QUEUE_WRITE_FAILED", "submit",
                "the queue path does not fit its buffer",
                "platform_state_root too long");
        return;
    }
    /* The lock covers seq assignment plus the append, so a step rewriting
     * the file cannot drop this row. The critical section is local file IO
     * only — never a git call, never a proof. */
    lock = dl_rows_lock(d.land);
    if (lock < 0) {
        dl_fail(reply, "QUEUE_WRITE_FAILED", "submit",
                "cannot take the queue lock", qpath);
        return;
    }
    char queue_why[128] = {0};
    if (!dl_load_rows(qpath, &rows, &nrows, queue_why,
                      sizeof(queue_why))) {
        dl_unlock(lock);
        dl_fail(reply, "QUEUE_READ_FAILED", "submit",
                "cannot append while the queue cannot be read",
                dl_reason_or_path(queue_why, qpath));
        return;
    }
    /* A retry of the same immutable tip from the same checkout attaches to
     * its live queue row. Keep the original age and proof pair: appending a
     * second row would schedule a second full proof of identical work. The
     * checkout is part of this local lookup because a different locator may
     * be needed to recover a vanished submitter. Terminal outcomes remain
     * separate: a later submission may need a new current-base proof. */
    dl_submit_loaded(&d, &r, rows, nrows, lock, qpath, full, root, reply);
}

static bool dl_cancel_push_settled(const struct dl_dirs *d, const char *qpath,
                                   long long seq, struct dl_row *settled);
static bool dl_push_pair_same(const struct dl_row *a, const struct dl_row *b);

/* ── cancel ────────────────────────────────────────────────────────────── */

static int dl_cancel_acquire(const struct dl_dirs *d, const char *qpath,
                              long long seq, struct dl_row *settled,
                              bool *push_settled, struct zcl_command_reply *reply)
{
    memset(settled, 0, sizeof(*settled));
    if (dl_cancel_fence_guard(d, seq, reply)) return -1;
    *push_settled = dl_cancel_push_settled(d, qpath, seq, settled);
    int lock = dl_rows_lock(d->land);
    if (lock < 0) {
        dl_fail(reply, "QUEUE_READ_FAILED", "cancel", "cannot take the queue lock", qpath);
        return -1;
    }
    if (dl_cancel_fence_guard(d, seq, reply)) { dl_unlock(lock); return -1; }
    return lock;
}

static void dl_cancel(const struct zcl_command_request *req,
                      struct zcl_command_reply *reply)
{
    struct dl_dirs d;
    struct dl_row *rows = NULL;
    size_t nrows = 0, kept = 0;
    char qpath[4096 + 32];
    long long seq = 0;
    bool found = false;
    struct dl_row hit;
    int lock;
    if (!dl_seq_in(req, &seq)) {
        dl_fail(reply, "BAD_INPUT", "cancel",
                "cancel needs the request sequence number, 1 or more",
                "input.seq missing or not a positive integer");
        return;
    }
    if (!dl_dirs_make(&d)) {
        dl_fail(reply, "STATE_DIR_FAILED", "cancel",
                "cannot resolve the owner-private state root",
                "platform_state_root");
        return;
    }
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d.land) >=
        (int)sizeof(qpath)) {
        dl_fail(reply, "QUEUE_READ_FAILED", "cancel",
                "the queue path does not fit its buffer",
                "platform_state_root too long");
        return;
    }
    struct dl_row settled;
    bool push_settled = false;
    lock = dl_cancel_acquire(&d, qpath, seq, &settled, &push_settled, reply);
    if (lock < 0) return;
    char queue_why[128] = {0};
    if (!dl_load_rows(qpath, &rows, &nrows, queue_why,
                      sizeof(queue_why))) {
        dl_unlock(lock);
        dl_fail(reply, "QUEUE_READ_FAILED", "cancel",
                "cannot read the queue file",
                dl_reason_or_path(queue_why, qpath));
        return;
    }
    memset(&hit, 0, sizeof(hit));
    for (size_t i = 0; i < nrows; i++) {
        if (rows[i].seq == seq && !found) {
            /* The durable push checkpoint means the remote may already
             * have moved even if this process has not heard back. Preserve
             * the row for reconciliation unless the same pair was just
             * observed settled as refused. */
            if (strcmp(rows[i].phase, "push") == 0 &&
                !(push_settled && dl_push_pair_same(&rows[i], &settled))) {
                free(rows);
                dl_unlock(lock);
                dl_fail(reply, "PUSH_OUTCOME_UNKNOWN", "cancel",
                        "a push checkpoint must be reconciled before cancellation",
                        "run dev land step to observe the exact remote");
                return;
            }
            found = true;
            hit = rows[i];
            continue;               /* dropped from the live queue */
        }
        rows[kept++] = rows[i];
    }
    if (!found) {
        free(rows);
        dl_unlock(lock);
        dl_fail(reply, "SEQ_UNKNOWN", "cancel",
                "no live request carries that sequence number",
                "run `dev land status` for the live sequence numbers");
        return;
    }
    (void)snprintf(hit.state, sizeof(hit.state), "cancelled");
    hit.phase[0] = '\0';
    (void)snprintf(hit.detail, sizeof(hit.detail), "%s",
                   "cancelled by the operator");
    if (!dl_record_outcome(&d, &hit)) {
        free(rows);
        dl_unlock(lock);
        dl_fail(reply, "OUTCOME_WRITE_FAILED", "cancel",
                "cannot record the terminal outcome; request remains live",
                "outcomes.jsonl or mail/outbox.jsonl");
        return;
    }
    if (!dl_rewrite_rows(d.land, qpath, rows, kept)) {
        free(rows);
        dl_unlock(lock);
        dl_fail(reply, "QUEUE_WRITE_FAILED", "cancel",
                "cannot rewrite the queue file", qpath);
        return;
    }
    free(rows);
    dl_unlock(lock);
    (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
    (void)json_push_kv_int(&reply->data, "seq", seq);
    (void)json_push_kv_str(&reply->data, "tip", hit.tip);
    (void)json_push_kv_str(&reply->data, "state", hit.state);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* ── steer: one re-readable projection of the row step would pick ──────── */

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const char DL_WAKE_STEP[] = "z23-dev dev land step";
static const char DL_WAKE_BUSY[] =
    "none (step.lock held; z23-dev dev land step returns STEP_BUSY and does not push)";

enum dl_beat {
    DL_BEAT_FREE = 0,
    DL_BEAT_HELD = 1,
    DL_BEAT_UNKNOWN = 2
};

enum dl_timer_unit {
    DL_TIMER_ABSENT = 0,
    DL_TIMER_ARMED = 1,
    DL_TIMER_UNKNOWN = 2
};

struct dl_steer_view {
    char candidate[80];
    long long seq;
    char phase[24];
    char owner[32];
    char lease[24];
    char proof_state[128];
    char receiver_driver[96];
    char missing[24];
    char wake[180];
    char remote_state[96];
    char incident[24];
};

static int64_t dl_drain_idle_bound_s(void)
{
    const char *forced = getenv("ZCL_LAND_DRAIN_IDLE_SEC");
    long parsed;
    if (!forced || !forced[0])
        return 900;
    parsed = strtol(forced, NULL, 10);
    if (parsed < 0)
        return 900;
    return (int64_t)parsed;
}

/* Howard Hinnant's civil-from-days inverse, days since 1970-01-01 UTC. */
static int64_t dl_civil_days(int year, int month, int day)
{
    int64_t y = year;
    int m = month;
    int64_t era;
    unsigned yoe, doy, doe;
    y -= m <= 2;
    m += m > 2 ? -3 : 9;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (unsigned)(y - era * 400);
    doy = (153u * (unsigned)m + 2u) / 5u + (unsigned)day - 1u;
    doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static bool dl_iso_unix(const char *ts, int64_t *out)
{
    int y, mo, d, h, mi, s;
    if (!ts || sscanf(ts, "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &s) != 6)
        return false;
    if (mo < 1 || mo > 12 || d < 1 || d > 31)
        return false;
    if (h < 0 || h > 23 || mi < 0 || mi > 59 || s < 0 || s > 60)
        return false;
    *out = dl_civil_days(y, mo, d) * 86400 +
           (int64_t)h * 3600 + (int64_t)mi * 60 + s;
    return true;
}

static int64_t dl_row_age(const struct dl_row *row, int64_t now, int64_t bound)
{
    int64_t then = 0;
    int64_t age;
    if (!row || !dl_iso_unix(row->ts, &then))
        return bound;
    age = now - then;
    if (age < 0)
        return 0;
    return age;
}

static bool dl_lock_holder_pid(const char *path, int *pid_out)
{
#if !defined(__linux__)
    (void)path;
    (void)pid_out;
    return false;
#else
    struct stat st;
    FILE *f;
    char line[256];
    unsigned maj, min;
    unsigned long ino;
    if (!path || !pid_out || stat(path, &st) != 0)
        return false;
    maj = major(st.st_dev);
    min = minor(st.st_dev);
    ino = (unsigned long)st.st_ino;
    f = fopen("/proc/locks", "re");
    if (!f)
        return false;
    while (fgets(line, sizeof(line), f)) {
        int pid = 0;
        unsigned lm = 0, ln = 0;
        unsigned long lino = 0;
        if (sscanf(line, "%*d: FLOCK ADVISORY WRITE %d %x:%x:%lu",
                   &pid, &lm, &ln, &lino) != 4)
            continue;
        if (lm == maj && ln == min && lino == ino && pid > 0) {
            *pid_out = pid;
            (void)fclose(f);
            return true;
        }
    }
    (void)fclose(f);
    return false;
#endif
}

#if defined(_WIN32)
static enum dl_beat dl_beat_state(const char *landdir, int *pid_out)
{
    (void)landdir;
    if (pid_out)
        *pid_out = 0;
    return DL_BEAT_UNKNOWN;
}
#else
/* Observes step.lock. Does not create it and does not keep it: status is
 * not a beat. LOCK_EX|LOCK_NB fails while a step holds the lock. */
static enum dl_beat dl_beat_state(const char *landdir, int *pid_out)
{
    char path[4096 + 32];
    int fd;
    int err;
    if (pid_out)
        *pid_out = 0;
    if (!landdir ||
        snprintf(path, sizeof(path), "%s/step.lock", landdir) >=
            (int)sizeof(path))
        return DL_BEAT_UNKNOWN;
    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT)
            return DL_BEAT_FREE;
        return DL_BEAT_UNKNOWN;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
        (void)flock(fd, LOCK_UN);
        (void)close(fd);
        return DL_BEAT_FREE;
    }
    err = errno;
    (void)close(fd);
    if (err == EWOULDBLOCK || err == EAGAIN) {
        if (pid_out)
            (void)dl_lock_holder_pid(path, pid_out);
        return DL_BEAT_HELD;
    }
    return DL_BEAT_UNKNOWN;
}
#endif

static enum dl_timer_unit dl_timer_unit_state(void)
{
#if defined(_WIN32)
    return DL_TIMER_ABSENT;
#else
    const char *home = getenv("HOME");
    char path[4096];
    struct stat st;
    int n;
    if (!home || !home[0])
        return DL_TIMER_UNKNOWN;
    n = snprintf(path, sizeof(path),
                 "%s/.config/systemd/user/timers.target.wants/"
                 "z23-land-step.timer",
                 home);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return DL_TIMER_UNKNOWN;
    if (lstat(path, &st) == 0)
        return DL_TIMER_ARMED;
    return DL_TIMER_ABSENT;
#endif
}

static const char *dl_timer_word(enum dl_timer_unit timer)
{
    if (timer == DL_TIMER_ARMED)
        return "timer_unit=armed";
    if (timer == DL_TIMER_ABSENT)
        return "timer_unit=absent";
    return "timer_unit=unknown";
}

static bool dl_queued_precedes(const struct dl_row *row,
                               const struct dl_row *best)
{
    return !best || row->priority_seq < best->priority_seq ||
           (row->priority_seq == best->priority_seq && row->seq < best->seq);
}

static const struct dl_row *dl_pick_steer(const struct dl_row *rows, size_t n)
{
    size_t i;
    const struct dl_row *best = NULL;
    if (!rows)
        return NULL;
    for (i = 0; i < n; i++) {
        if (strcmp(rows[i].state, "inflight") == 0)
            return &rows[i];
    }
    for (i = 0; i < n; i++)
        if (strcmp(rows[i].state, "queued") == 0 &&
            dl_queued_precedes(&rows[i], best))
            best = &rows[i];
    return best;
}

static const char *dl_missing_of(const struct dl_row *row)
{
    if (!row)
        return "none";
    if (strcmp(row->state, "queued") == 0)
        return "claim";
    if (strcmp(row->state, "inflight") != 0)
        return "none";
    if (row->phase[0] == '\0' || strcmp(row->phase, "rebase") == 0 ||
        strcmp(row->phase, "regen") == 0)
        return "rebase";
    if (strcmp(row->phase, "prebuild") == 0)
        return "lint";
    if (strcmp(row->phase, "prove") == 0)
        return "proof";
    if (strcmp(row->phase, "push") == 0)
        return row->publication_signature[0] ? "remote_receipt" : "push";
    return "other";
}

static void dl_one_line(const char *in, char *out, size_t cap)
{
    size_t j = 0;
    if (!out || cap == 0)
        return;
    if (!in)
        in = "";
    while (in[0] && j + 1 < cap) {
        char c = in[0];
        if (c == '\n' || c == '\r' || c == '\t')
            c = ' ';
        out[j++] = c;
        in++;
    }
    out[j] = '\0';
}

static void dl_steer_phase(const struct dl_row *row, char *out, size_t cap)
{
    if (strcmp(row->state, "queued") == 0) {
        (void)snprintf(out, cap, "queued");
        return;
    }
    if (row->phase[0])
        (void)snprintf(out, cap, "%s", row->phase);
    else
        (void)snprintf(out, cap, "inflight");
}

static void dl_steer_proof(const struct dl_row *row, char *out, size_t cap)
{
    if (strcmp(row->phase, "prove") == 0) {
        if (row->detail[0])
            dl_one_line(row->detail, out, cap);
        else
            (void)snprintf(out, cap, "pending");
        return;
    }
    if (strcmp(row->phase, "push") == 0) {
        (void)snprintf(out, cap, "passed");
        return;
    }
    (void)snprintf(out, cap, "not_requested");
}

static bool dl_drain_absent(const struct dl_row *row, enum dl_beat beat,
                            enum dl_timer_unit timer, int64_t age,
                            int64_t bound)
{
    if (!row)
        return false;
    if (strcmp(row->state, "queued") != 0)
        return false;
    if (beat != DL_BEAT_FREE)
        return false;
    if (timer == DL_TIMER_ABSENT)
        return true;
    return age >= bound;
}

static bool dl_copy_path(const char *src, char *out, size_t cap)
{
    size_t n;
    if (!src || !out || cap == 0)
        return false;
    n = strlen(src);
    if (n + 1 > cap)
        return false;
    memcpy(out, src, n + 1);
    return true;
}

static bool dl_join_realpath(const char *base, const char *rel,
                             char *out, size_t cap)
{
#if defined(_WIN32)
    (void)base;
    (void)rel;
    (void)out;
    (void)cap;
    return false;
#else
    char joined[PATH_MAX];
    char resolved[PATH_MAX];
    if (!base || !rel || !rel[0])
        return false;
    if (snprintf(joined, sizeof(joined), "%s/%s", base, rel) >=
        (int)sizeof(joined))
        return false;
    if (!realpath(joined, resolved))
        return false;
    return dl_copy_path(resolved, out, cap);
#endif
}

static bool dl_gitdir_file(const char *wt, const char *git_file,
                           char *out, size_t cap)
{
    char buf[512];
    char *p;
    if (!dl_read_file(git_file, buf, sizeof(buf), NULL))
        return false;
    if (strncmp(buf, "gitdir: ", 8) != 0)
        return false;
    p = buf + 8;
    dl_trim(p);
    while (*p == ' ')
        p++;
    if (p[0] == '/')
        return dl_copy_path(p, out, cap);
    return dl_join_realpath(wt, p, out, cap);
}

static bool dl_resolve_gitdir(const char *wt, char *out, size_t cap)
{
    char path[4096];
    struct stat st;
    if (!wt ||
        snprintf(path, sizeof(path), "%s/.git", wt) >= (int)sizeof(path))
        return false;
    if (stat(path, &st) != 0)
        return false;
    if (S_ISDIR(st.st_mode))
        return dl_copy_path(path, out, cap);
    return dl_gitdir_file(wt, path, out, cap);
}

static bool dl_loose_sha(const char *gitdir, const char *ref, char out[80])
{
    char path[4096];
    char buf[80];
    if (!gitdir || !ref ||
        snprintf(path, sizeof(path), "%s/%s", gitdir, ref) >= (int)sizeof(path))
        return false;
    if (!dl_read_file(path, buf, sizeof(buf), NULL))
        return false;
    dl_trim(buf);
    if (!dl_sha_ok(buf))
        return false;
    memcpy(out, buf, 41);
    return true;
}

static bool dl_sha_from_packed(char *text, const char *ref, char out[80])
{
    char *save = NULL;
    char *line;
    if (!text || !ref)
        return false;
    for (line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char *sp;
        if (line[0] == '#' || line[0] == '^' || line[0] == '\0')
            continue;
        sp = strchr(line, ' ');
        if (!sp)
            continue;
        *sp = '\0';
        if (strcmp(sp + 1, ref) != 0)
            continue;
        if (!dl_sha_ok(line))
            return false;
        memcpy(out, line, 40);
        out[40] = '\0';
        return true;
    }
    return false;
}

static bool dl_packed_sha(const char *gitdir, const char *ref, char out[80])
{
    char path[4096];
    char *text;
    bool ok;
    if (!gitdir ||
        snprintf(path, sizeof(path), "%s/packed-refs", gitdir) >=
            (int)sizeof(path))
        return false;
    text = (char *)zcl_malloc(DL_FILE_CAP, "dev.land.packed-refs");
    if (!text)
        return false;
    ok = dl_read_file(path, text, DL_FILE_CAP, NULL) &&
         dl_sha_from_packed(text, ref, out);
    free(text);
    return ok;
}

static bool dl_ref_sha(const char *gitdir, char out[80])
{
    static const char ref[] = "refs/remotes/origin/main";
    if (dl_loose_sha(gitdir, ref, out))
        return true;
    return dl_packed_sha(gitdir, ref, out);
}

static bool dl_common_gitdir(const char *gitdir, char *out, size_t cap)
{
    char path[4096];
    char buf[512];
    if (!gitdir ||
        snprintf(path, sizeof(path), "%s/commondir", gitdir) >=
            (int)sizeof(path))
        return false;
    if (!dl_read_file(path, buf, sizeof(buf), NULL))
        return false;
    dl_trim(buf);
    if (!buf[0])
        return false;
    if (buf[0] == '/')
        return dl_copy_path(buf, out, cap);
    return dl_join_realpath(gitdir, buf, out, cap);
}

static void dl_cached_remote(const char *wt, char *out, size_t cap)
{
    char gitdir[PATH_MAX];
    char common[PATH_MAX];
    char sha[80];
    if (!wt || !wt[0]) {
        (void)snprintf(out, cap, "unknown: no submitter worktree");
        return;
    }
    if (!dl_resolve_gitdir(wt, gitdir, sizeof(gitdir))) {
        (void)snprintf(out, cap, "unknown: gitdir unreadable");
        return;
    }
    if (dl_ref_sha(gitdir, sha) ||
        (dl_common_gitdir(gitdir, common, sizeof(common)) &&
         dl_ref_sha(common, sha))) {
        (void)snprintf(out, cap, "cached:%s", sha);
        return;
    }
    (void)snprintf(out, cap, "unknown: cached origin/main ref missing");
}

static void dl_driver_idle(enum dl_beat beat, enum dl_timer_unit timer,
                           char *out, size_t cap)
{
    if (beat == DL_BEAT_HELD) {
        (void)snprintf(out, cap, "beat_active");
        return;
    }
    if (beat == DL_BEAT_FREE)
        (void)snprintf(out, cap, "idle %s", dl_timer_word(timer));
    else
        (void)snprintf(out, cap, "unknown: step.lock unreadable %s",
                       dl_timer_word(timer));
}

static void dl_steer_compose(const struct dl_dirs *d, const struct dl_row *rows,
                             size_t nrows, int64_t now, struct dl_steer_view *s)
{
    const struct dl_row *row;
    enum dl_beat beat;
    enum dl_timer_unit timer;
    int pid = 0;
    int64_t bound = dl_drain_idle_bound_s();
    int64_t age;

    memset(s, 0, sizeof(*s));
    (void)snprintf(s->candidate, sizeof(s->candidate), "none");
    (void)snprintf(s->phase, sizeof(s->phase), "none");
    (void)snprintf(s->owner, sizeof(s->owner), "none");
    (void)snprintf(s->lease, sizeof(s->lease), "none");
    (void)snprintf(s->proof_state, sizeof(s->proof_state), "none");
    (void)snprintf(s->missing, sizeof(s->missing), "none");
    (void)snprintf(s->wake, sizeof(s->wake), "none");
    (void)snprintf(s->remote_state, sizeof(s->remote_state),
                   "unknown: no eligible row");
    (void)snprintf(s->incident, sizeof(s->incident), "none");
    timer = dl_timer_unit_state();
    beat = dl_beat_state(d ? d->land : NULL, &pid);
    dl_driver_idle(beat, timer, s->receiver_driver, sizeof(s->receiver_driver));
    row = dl_pick_steer(rows, nrows);
    if (!row)
        return;
    (void)snprintf(s->candidate, sizeof(s->candidate), "%s", row->tip);
    s->seq = row->seq;
    dl_steer_phase(row, s->phase, sizeof(s->phase));
    dl_steer_proof(row, s->proof_state, sizeof(s->proof_state));
    (void)snprintf(s->missing, sizeof(s->missing), "%s", dl_missing_of(row));
    dl_cached_remote(row->worktree, s->remote_state, sizeof(s->remote_state));
    age = dl_row_age(row, now, bound);
    if (beat == DL_BEAT_HELD) {
        if (pid > 0)
            (void)snprintf(s->owner, sizeof(s->owner), "pid:%d", pid);
        else
            (void)snprintf(s->owner, sizeof(s->owner), "pid:unknown");
        (void)snprintf(s->lease, sizeof(s->lease), "step.lock:held");
        (void)snprintf(s->wake, sizeof(s->wake), "%s", DL_WAKE_BUSY);
        (void)snprintf(s->receiver_driver, sizeof(s->receiver_driver),
                       "beat_active");
        return;
    }
    (void)snprintf(s->owner, sizeof(s->owner), "unclaimed");
    (void)snprintf(s->lease, sizeof(s->lease), "none");
    (void)snprintf(s->wake, sizeof(s->wake), "%s", DL_WAKE_STEP);
    if (beat == DL_BEAT_FREE)
        (void)snprintf(s->receiver_driver, sizeof(s->receiver_driver),
                       "no_active_drain %s", dl_timer_word(timer));
    else
        (void)snprintf(s->receiver_driver, sizeof(s->receiver_driver),
                       "unknown: step.lock unreadable %s",
                       dl_timer_word(timer));
    if (dl_drain_absent(row, beat, timer, age, bound))
        (void)snprintf(s->incident, sizeof(s->incident), "drain_absent");
}

static void dl_steer_append_screen(char *screen, size_t cap, size_t *used,
                                   const struct dl_steer_view *s)
{
    int w;
    if (!screen || !used || !s || *used >= cap)
        return;
    w = snprintf(screen + *used, cap - *used,
                 "steer.candidate: %s\n"
                 "steer.seq: %lld\n"
                 "steer.phase: %s\n"
                 "steer.owner: %s\n"
                 "steer.lease: %s\n"
                 "steer.proof_state: %s\n"
                 "steer.receiver_driver: %s\n"
                 "steer.first_missing_transition: %s\n"
                 "steer.wake_command: %s\n"
                 "steer.remote_state: %s\n"
                 "incident: %s\n",
                 s->candidate, s->seq, s->phase, s->owner, s->lease,
                 s->proof_state, s->receiver_driver, s->missing, s->wake,
                 s->remote_state, s->incident);
    if (w > 0 && (size_t)w < cap - *used)
        *used += (size_t)w;
}

static void dl_steer_push(struct zcl_command_reply *reply,
                          const struct dl_steer_view *s)
{
    struct json_value obj;
    if (!reply || !s)
        return;
    json_init(&obj);
    json_set_object(&obj);
    (void)json_push_kv_str(&obj, "candidate", s->candidate);
    (void)json_push_kv_int(&obj, "seq", s->seq);
    (void)json_push_kv_str(&obj, "phase", s->phase);
    (void)json_push_kv_str(&obj, "owner", s->owner);
    (void)json_push_kv_str(&obj, "lease", s->lease);
    (void)json_push_kv_str(&obj, "proof_state", s->proof_state);
    (void)json_push_kv_str(&obj, "receiver_driver", s->receiver_driver);
    (void)json_push_kv_str(&obj, "first_missing_transition", s->missing);
    (void)json_push_kv_str(&obj, "wake_command", s->wake);
    (void)json_push_kv_str(&obj, "remote_state", s->remote_state);
    (void)json_push_kv(&reply->data, "steer", &obj);
    (void)json_push_kv_str(&reply->data, "incident", s->incident);
    json_free(&obj);
}

static void dl_status_attach_steer(struct zcl_command_reply *reply,
                                   const struct dl_dirs *d,
                                   const struct dl_row *rows, size_t nrows,
                                   int64_t now, char *screen, size_t screen_cap,
                                   size_t *used, bool want_json)
{
    struct dl_steer_view sv;
    dl_steer_compose(d, rows, nrows, now, &sv);
    if (!want_json)
        dl_steer_append_screen(screen, screen_cap, used, &sv);
    dl_steer_push(reply, &sv);
}

/* ── status ────────────────────────────────────────────────────────────── */

static const char *dl_hold_display(const struct dl_row *r)
{
    return r->publication_hold ? " publication HELD" : "";
}

static bool dl_push_queued(struct json_value *arr, const struct dl_row *r)
{
    struct json_value item;
    bool ok;
    json_init(&item);
    json_set_object(&item);
    ok = json_push_kv_int(&item, "seq", r->seq) &&
         json_push_kv_int(&item, "priority_seq", r->priority_seq) &&
         json_push_kv_bool(&item, "publication_hold", r->publication_hold) &&
         json_push_kv_str(&item, "tip", r->tip) &&
         json_push_kv_str(&item, "ts", r->ts) &&
         json_push_kv_int(&item, "attempt", r->attempt) &&
         json_push_kv_str(&item, "note", r->note) &&
         json_push_back(arr, &item);
    json_free(&item);
    return ok;
}

static bool dl_push_proof_action(struct json_value *obj,
                                  const struct dl_row *r,
                                  const char *proof_root)
{
    if (strcmp(r->phase, "prove") != 0 ||
        !dl_sha_ok(r->local) || !dl_sha_ok(r->base))
        return true;
    struct json_value step;
    json_init(&step);
    json_set_object(&step);
    bool ok = json_push_kv_str(&step, "command", "dev.proof.step") &&
         json_push_kv_str(&step, "root", proof_root) &&
         json_push_kv_str(&step, "local_commit", r->local) &&
         json_push_kv_str(&step, "remote_base", r->base) &&
         json_push_kv(obj, "proof_step", &step);
    json_free(&step);
    return ok;
}

static bool dl_push_publication_fields(struct json_value *obj,
                                        const struct dl_row *r)
{
    return json_push_kv_str(obj, "publication_target",
                            r->publication_target) &&
           json_push_kv_str(obj, "publication_proof",
                            r->publication_proof) &&
           json_push_kv_str(obj, "publication_bundle",
                            r->publication_bundle) &&
           json_push_kv_str(obj, "publication_signer",
                            r->publication_signer) &&
           json_push_kv_str(obj, "remote_tip", r->remote_tip) &&
           json_push_kv_str(obj, "remote_source", r->remote_source) &&
           json_push_kv_str(obj, "remote_signer", r->remote_signer);
}

static bool dl_push_inflight_evidence(struct json_value *obj,
                                       const struct dl_row *r)
{
    return json_push_kv_str(obj, "detail", r->detail) &&
           json_push_kv_bool(obj, "publication_hold", r->publication_hold) &&
           json_push_kv_str(obj, "dispatch_state",
                            strcmp(r->phase, "push") == 0 ? "unknown" :
                            "not_attempted") &&
           /* The queue has no canonical publication or receipt roots. */
           json_push_kv_str(obj, "acceptance_state", "unknown");
}

static bool dl_push_inflight(struct json_value *obj, const struct dl_row *r,
                             const char *proof_root, long long now)
{
    long long elapsed = now - r->started;
    if (elapsed < 0)
        elapsed = 0;
    return json_push_kv_int(obj, "seq", r->seq) &&
           json_push_kv_str(obj, "tip", r->tip) &&
           json_push_kv_str(obj, "phase", r->phase) &&
           json_push_kv_int(obj, "attempt", r->attempt) &&
           json_push_kv_int(obj, "elapsed_s", elapsed) &&
           json_push_kv_str(obj, "base", r->base) &&
           json_push_kv_str(obj, "local", r->local) &&
           json_push_kv_str(obj, "tree", r->tree) &&
           json_push_kv_str(obj, "proof_intent", r->proof_intent) &&
           dl_push_inflight_evidence(obj, r) &&
           dl_push_publication_fields(obj, r) &&
           dl_push_proof_action(obj, r, proof_root);
}

static bool dl_push_fence_disposition(struct json_value *item, const struct dl_row *r)
{
    return json_push_kv_str(item, "acceptance_state", "unknown") &&
        json_push_kv_int(item, "fence_peer", r->fence_peer) &&
        json_push_kv_str(item, "historical_git_acceptance",
                         strcmp(r->state, "landed") == 0 ? "verified" : "unknown") &&
        json_push_kv_str(item, "future_dispatch",
                         strcmp(r->state, "fenced") == 0 ? "fenced" : "complete");
}

static bool dl_push_outcome_row(struct json_value *arr,
                                const struct dl_row *r)
{
    struct json_value item;
    bool ok;
    json_init(&item);
    json_set_object(&item);
    ok = json_push_kv_int(&item, "seq", r->seq) &&
         json_push_kv_str(&item, "ts", r->ts) &&
         json_push_kv_str(&item, "tip", r->tip) &&
         json_push_kv_str(&item, "state", r->state) &&
         dl_push_fence_disposition(&item, r) &&
         json_push_kv_int(&item, "attempt", r->attempt) &&
         json_push_kv_str(&item, "tip_pushed", r->pushed) &&
         json_push_kv_str(&item, "remote_tip", r->remote_tip) &&
         json_push_kv_str(&item, "remote_source", r->remote_source) &&
         json_push_kv_str(&item, "remote_signer", r->remote_signer) &&
         json_push_kv_str(&item, "remote_signature",
                          r->remote_signature) &&
         json_push_kv_str(&item, "dimension", r->dimension) &&
         json_push_kv_str(&item, "log_path", r->log_path) &&
         json_push_kv_str(&item, "detail", r->detail) &&
         json_push_back(arr, &item);
    json_free(&item);
    return ok;
}

static bool dl_outcomes_tail(const char *path, struct dl_row last[10],
                             size_t *count, char *why, size_t why_cap)
{
    char *text = (char *)zcl_malloc(DL_FILE_CAP, "dev.land.outcomes");
    if (!text)
        return false;
    if (!dl_read_file(path, text, DL_FILE_CAP, NULL)) {
        int read_errno = errno;
        free(text);
        if (read_errno == ENOENT)
            return true;
        if (why && why_cap)
            (void)snprintf(why, why_cap,
                           "outcomes_read_failed_errno_%d", read_errno);
        return false;
    }
    char *save = NULL, *line;
    size_t record = 0;
    for (line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        struct dl_row row;
        record++;
        if (!dl_parse_row(line, &row) ||
            strcmp(row.state, "queued") == 0 ||
            strcmp(row.state, "inflight") == 0) {
            if (why && why_cap)
                (void)snprintf(why, why_cap,
                               "malformed_outcome_record_%zu", record);
            free(text);
            return false;
        }
        if (*count == 10) {
            for (size_t k = 1; k < *count; k++)
                last[k - 1] = last[k];
            (*count)--;
        }
        last[(*count)++] = row;
    }
    free(text);
    return true;
}

static void dl_status(const struct zcl_command_request *req,
                      struct zcl_command_reply *reply)
{
    struct dl_dirs d;
    struct dl_row *rows = NULL;
    struct dl_row last[10];
    size_t nrows = 0, nlast = 0;
    char qpath[4096 + 32], opath[4096 + 32], screen[16384];
    char read_why[128] = {0};
    struct json_value queued, inflight, outcomes;
    long long now = (long long)platform_time_wall_unix();
    bool want_json = false, have_inflight = false;
    size_t used = 0;
    int w;
    if (req && req->input) {
        const struct json_value *jv = json_get(req->input, "json");
        want_json = jv && jv->type == JSON_BOOL && json_get_bool(jv);
    }
    if (!dl_dirs_resolve(&d, false)) {
        dl_fail(reply, "STATE_DIR_FAILED", "status",
                "the existing owner-private state root is unavailable",
                "platform_state_root_existing");
        return;
    }
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d.land) >=
            (int)sizeof(qpath) ||
        snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", d.land) >=
            (int)sizeof(opath)) {
        dl_fail(reply, "QUEUE_READ_FAILED", "status",
                "the queue paths do not fit their buffers",
                "platform_state_root too long");
        return;
    }
    char queue_why[128] = {0};
    if (!dl_load_rows(qpath, &rows, &nrows, queue_why,
                      sizeof(queue_why))) {
        dl_fail(reply, "QUEUE_READ_FAILED", "status",
                "cannot read the queue file",
                dl_reason_or_path(queue_why, qpath));
        return;
    }
    json_init(&queued);
    json_set_array(&queued);
    json_init(&inflight);
    json_set_object(&inflight);
    json_init(&outcomes);
    json_set_array(&outcomes);
    for (size_t i = 0; i < nrows; i++) {
        if (strcmp(rows[i].state, "queued") == 0) {
            if (!dl_push_queued(&queued, &rows[i]))
                goto fail;
        } else if (strcmp(rows[i].state, "inflight") == 0 && !have_inflight) {
            if (!dl_push_inflight(&inflight, &rows[i], d.wt, now))
                goto fail;
            have_inflight = true;
        }
    }
    /* The last ten outcomes, oldest first. */
    if (!dl_outcomes_tail(opath, last, &nlast, read_why, sizeof(read_why)))
        goto fail;
    for (size_t k = 0; k < nlast; k++) {
        if (!dl_push_outcome_row(&outcomes, &last[k]))
            goto fail;
    }
    if (!want_json) {
        w = snprintf(screen, sizeof(screen),
                     "land: %llu queued, %s\n",
                     (unsigned long long)queued.num_children,
                     have_inflight ? "1 in flight" : "nothing in flight");
        if (w <= 0 || (size_t)w >= sizeof(screen))
            goto fail;
        used = (size_t)w;
        for (size_t i = 0; i < nrows; i++) {
            long long elapsed;
            if (strcmp(rows[i].state, "inflight") != 0)
                continue;
            elapsed = now - rows[i].started;
            if (elapsed < 0)
                elapsed = 0;
            w = snprintf(screen + used, sizeof(screen) - used,
                         "  #%lld %.12s %-8s attempt %lld, %llds%s\n",
                         rows[i].seq, rows[i].tip, rows[i].phase,
                         rows[i].attempt, elapsed, dl_hold_display(&rows[i]));
            if (w <= 0 || (size_t)w >= sizeof(screen) - used)
                goto render_done;
            used += (size_t)w;
        }
        for (size_t i = 0; i < nrows; i++) {
            if (strcmp(rows[i].state, "queued") != 0)
                continue;
            w = snprintf(screen + used, sizeof(screen) - used,
                         "  #%lld %.12s queued priority #%lld%s\n",
                         rows[i].seq, rows[i].tip, rows[i].priority_seq, dl_hold_display(&rows[i]));
            if (w <= 0 || (size_t)w >= sizeof(screen) - used)
                goto render_done;
            used += (size_t)w;
        }
        for (size_t k = 0; k < nlast; k++) {
            if (strcmp(last[k].state, "landed") == 0)
                w = snprintf(screen + used, sizeof(screen) - used,
                             "  #%lld %.12s landed as %.12s\n", last[k].seq,
                             last[k].tip, last[k].pushed);
            else
                w = snprintf(screen + used, sizeof(screen) - used,
                             "  #%lld %.12s %s %s%s%s\n", last[k].seq,
                             last[k].tip, last[k].state,
                             last[k].dimension[0] ? last[k].dimension : "",
                             last[k].log_path[0] ? " " : "",
                             last[k].log_path);
            if (w <= 0 || (size_t)w >= sizeof(screen) - used)
                goto render_done;
            used += (size_t)w;
        }
    }
render_done:
    dl_status_attach_steer(reply, &d, rows, nrows, now, screen, sizeof(screen),
                           &used, want_json);
    free(rows);
    (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
    (void)json_push_kv(&reply->data, "queued", &queued);
    if (have_inflight)
        (void)json_push_kv(&reply->data, "in_flight", &inflight);
    (void)json_push_kv(&reply->data, "outcomes", &outcomes);
    json_free(&queued);
    json_free(&inflight);
    json_free(&outcomes);
    if (!want_json)
        (void)json_push_kv_str(&reply->data, "screen", screen);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
    return;
fail:
    json_free(&queued);
    json_free(&inflight);
    json_free(&outcomes);
    free(rows);
    dl_fail(reply, "QUEUE_READ_FAILED", "status",
            read_why[0] ? "cannot read the outcomes file"
                        : "cannot encode the status reply",
            dl_reason_or_path(read_why, qpath));
}

/* ── step: one scheduler beat, and it never waits ──────────────────────── */

static bool dl_terminal_checkpoint(const struct dl_dirs *d,
                                    struct dl_row *row)
{
    if (!dl_record_outcome(d, row)) return false;
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    if (getenv("ZCL_LAND_TEST_DIE_AFTER_OUTCOME") &&
        getenv("ZCL_DEVLOOP_TEST_PROCESS"))
        _exit(81);
#endif
    return true;
}

/* FNV-1a over one string and its terminator, so field borders count. */
static uint64_t dl_fnv_str(uint64_t h, const char *s)
{
    do {
        h ^= (unsigned char)*s;
        h *= 1099511628211ULL;
    } while (*s++);
    return h;
}

/* As dl_fnv_str, but the digits right after the idle note's age key are not
 * hashed: the age grows every step, and that growth alone must not post the
 * same idleness again. The key text and the terminator are hashed. */
static uint64_t dl_fnv_detail(uint64_t h, const char *s)
{
    static const char key[] = "proof_request_idle_age_s=";
    const size_t klen = sizeof(key) - 1;
    for (;;) {
        if (strncmp(s, key, klen) == 0) {
            for (size_t i = 0; i < klen; i++) {
                h ^= (unsigned char)s[i];
                h *= 1099511628211ULL;
            }
            s += klen;
            while (*s >= '0' && *s <= '9')
                s++;
            continue;
        }
        h ^= (unsigned char)*s;
        h *= 1099511628211ULL;
        if (*s == '\0')
            return h;
        s++;
    }
}

static const char *dl_or_empty(const char *s)
{
    return s ? s : "";
}

/* Digest of what a phase row says: pure, NULL fields read as empty, never 0. */
long long zcl_dev_land_phase_digest(const char *state, const char *phase,
                                    long long attempt, const char *dimension,
                                    const char *note, const char *detail,
                                    const char *log_base, const char *tip)
{
    char attempt_text[32];
    uint64_t h = 14695981039346656037ULL;
    (void)snprintf(attempt_text, sizeof(attempt_text), "%lld", attempt);
    h = dl_fnv_str(h, dl_or_empty(state));
    h = dl_fnv_str(h, dl_or_empty(phase));
    h = dl_fnv_str(h, attempt_text);
    h = dl_fnv_str(h, dl_or_empty(tip));
    h = dl_fnv_str(h, dl_or_empty(dimension));
    h = dl_fnv_str(h, dl_or_empty(note));
    h = dl_fnv_detail(h, dl_or_empty(detail));
    h = dl_fnv_str(h, dl_or_empty(log_base));
    return (long long)((h & 0x3fffffffffffffffULL) | 1);
}

/* Digest of what a phase row says. Never 0 (0 means "nothing posted"). */
static long long dl_phase_digest(const struct dl_row *r)
{
    return zcl_dev_land_phase_digest(r->state, r->phase, r->attempt,
                                     r->dimension, r->note, r->detail,
                                     dl_log_base(r->log_path), r->tip);
}

/* Record on `row` what this phase row says and report whether it differs
 * from `posted`, the digest the stored row carries. Only the mail depends
 * on the answer; the row is written either way. */
static bool dl_phase_stamp(struct dl_row *row, long long posted)
{
    row->phase_mail = dl_phase_digest(row);
    return row->phase_mail != posted;
}

/* Persist one row back into the queue file, or drop it and record it as an
 * outcome when its state is terminal. */
static bool dl_commit_row(const struct dl_dirs *d, struct dl_row *row,
                          bool terminal)
{
    struct dl_row *rows = NULL;
    size_t nrows = 0, kept = 0;
    char qpath[4096 + 32];
    bool ok, found = false, post = false;
    int lock;
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d->land) >=
        (int)sizeof(qpath))
        return false;
    lock = dl_rows_lock(d->land);
    if (lock < 0)
        return false;
    if (!dl_load_rows(qpath, &rows, &nrows, NULL, 0)) {
        dl_unlock(lock);
        return false;
    }
    for (size_t i = 0; i < nrows; i++) {
        if (rows[i].seq == row->seq) {
            found = true;
            if (terminal)
                continue;
            post = dl_phase_stamp(row, rows[i].phase_mail);
            rows[kept++] = *row;
            continue;
        }
        rows[kept++] = rows[i];
    }
    /* The row was picked (under the step lock) before this commit takes
     * the row lock. If `cancel` removed it from queue.jsonl in between,
     * `row->seq` is no longer present here: there is nothing left to keep
     * "inflight" and no cancelled row should ever get a second, later
     * outcome appended on top of cancel's own. Refuse instead of silently
     * treating an unmatched rewrite as success. */
    if (!found) {
        free(rows);
        dl_unlock(lock);
        return false;
    }
    /* The terminal observation is the checkpoint. If append or mail
     * delivery fails, keep the live row so another step can retry. If the
     * process dies after append but before this rewrite, replay recognizes
     * the exact outcome and removes the row without running work again. */
    ok = !terminal || dl_terminal_checkpoint(d, row);
    if (ok)
        ok = dl_rewrite_rows(d->land, qpath, rows, kept);
    free(rows);
    dl_unlock(lock);
    /* The digest was stamped into the row before this post and is written
     * with it. A phase row whose post fails is therefore not resent until
     * the row changes. Accepted: the post was already best-effort and the
     * board is advisory. Terminal outcome rows do not use this path. */
    if (ok && post)
        (void)dl_outbox(d, row, "phase");
    return ok;
}

static size_t dl_successor_index(const struct dl_row *rows, size_t nrows,
                                 const struct dl_row *row)
{
    for (size_t i = 0; i < nrows; i++)
        if (rows[i].seq == row->seq &&
            strcmp(rows[i].tip, row->tip) == 0 &&
            strcmp(rows[i].state, "inflight") == 0)
            return i;
    return SIZE_MAX;
}

static void dl_log(const struct dl_row *row, const char *text);

/* Append the higher-sequence successor while keeping its original claim
 * priority. The original tip stays byte-identical; a crash sees either
 * the old row or its successor, never both or neither. The drive loop
 * bounds work per call while a later caller can retry. */
static bool dl_requeue_successor(const struct dl_dirs *d, struct dl_row *row,
                                 long long *predecessor)
{
    struct dl_row *rows = NULL;
    size_t nrows = 0, at = SIZE_MAX;
    char qpath[4096 + 32];
    const char *why = NULL;
    long long next_seq = 1;
    int lock;
    bool ok = false;
    if (!d || !row || !predecessor ||
        snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d->land) >=
            (int)sizeof(qpath))
        return false;
    lock = dl_rows_lock(d->land);
    if (lock < 0) return false;
    if (!dl_load_rows(qpath, &rows, &nrows, NULL, 0) || nrows == 0)
        goto done;
    at = dl_successor_index(rows, nrows, row);
    if (at == SIZE_MAX) goto done; /* cancel won the row lock */
    if (!dl_submit_next_seq(d, rows, nrows, &next_seq, &why)) {
        dl_log(row, why);
        dl_log(row, "\n");
        goto done;
    }
    struct dl_row successor = *row;
    successor.seq = next_seq;
    (void)snprintf(successor.state, sizeof(successor.state), "queued");
    (void)snprintf(successor.phase, sizeof(successor.phase), "rebase");
    successor.attempt = 1;
    successor.started = 0;
    successor.local[0] = '\0';
    successor.base[0] = '\0';
    successor.tree[0] = '\0';
    successor.proof_intent[0] = '\0';
    dl_publication_clear(&successor);
    successor.dimension[0] = '\0';
    successor.producer_recovered = 0;
    /* Belt-and-braces: the digest already differs for a successor because
     * `attempt` is hashed; no test discriminates this reset. */
    successor.phase_mail = 0;
    for (size_t i = at + 1; i < nrows; i++) rows[i - 1] = rows[i];
    rows[nrows - 1] = successor;
    ok = dl_rewrite_rows(d->land, qpath, rows, nrows);
    if (ok) {
        *predecessor = row->seq;
        *row = successor;
    }
done:
    free(rows);
    dl_unlock(lock);
    if (ok) dl_outbox(d, row, "queued");
    return ok;
}

static void dl_step_reply(struct zcl_command_reply *reply,
                          const struct dl_row *row, const char *state)
{
    (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
    (void)json_push_kv_str(&reply->data, "state", state);
    if (row) {
        (void)json_push_kv_int(&reply->data, "seq", row->seq);
        (void)json_push_kv_bool(&reply->data, "publication_hold", row->publication_hold);
        (void)json_push_kv_str(&reply->data, "tip", row->tip);
        (void)json_push_kv_str(&reply->data, "phase", row->phase);
        (void)json_push_kv_int(&reply->data, "attempt", row->attempt);
        if (row->pushed[0])
            (void)json_push_kv_str(&reply->data, "tip_pushed", row->pushed);
        if (row->remote_signature[0]) {
            (void)json_push_kv_str(&reply->data, "remote_tip",
                                   row->remote_tip);
            (void)json_push_kv_str(&reply->data, "remote_source",
                                   row->remote_source);
            (void)json_push_kv_str(&reply->data, "remote_signer",
                                   row->remote_signer);
            (void)json_push_kv_str(&reply->data, "remote_signature",
                                   row->remote_signature);
        }
        if (row->dimension[0])
            (void)json_push_kv_str(&reply->data, "dimension",
                                   row->dimension);
        if (row->log_path[0])
            (void)json_push_kv_str(&reply->data, "log_path", row->log_path);
        if (row->detail[0])
            (void)json_push_kv_str(&reply->data, "detail", row->detail);
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* Commit the row and say so honestly either way. A commit failure here
 * (queue lock contention, an I/O error rewriting queue.jsonl) means the
 * state `intended_state` names was NEVER durably recorded: a terminal
 * commit leaves the row inflight and off outcomes.jsonl and mail/outbox,
 * a phase commit leaves the row at its last-persisted phase. Either way
 * the caller must not claim `intended_state` happened — it reports
 * persist:"failed" plus the reason instead, so an agent pulling status
 * sees the truth and a later step re-drives the row rather than treating
 * it as done. Returns true when the commit landed (caller proceeds to
 * build its normal reply via dl_step_reply); false when it already wrote
 * the persist-failure reply itself. */
static bool dl_commit_or_report(const struct dl_dirs *d, struct dl_row *row,
                                bool terminal,
                                struct zcl_command_reply *reply,
                                const char *intended_state)
{
    if (dl_commit_row(d, row, terminal))
        return true;
    dl_step_reply(reply, row, intended_state);
    (void)json_push_kv_str(&reply->data, "persist", "failed");
    (void)json_push_kv_str(
        &reply->data, "persist_reason",
        terminal ? "outcome not recorded in queue.jsonl/outcomes.jsonl; "
                   "the row remains inflight and will be re-driven"
                 : "phase update not recorded in queue.jsonl; the row "
                   "remains at its last-persisted phase and will be "
                   "re-driven");
    return false;
}

static void dl_log_path(const struct dl_dirs *d, struct dl_row *row)
{
    (void)snprintf(row->log_path, sizeof(row->log_path),
                   "%s/land-%lld-a%lld.log", d->logs, row->seq,
                   row->attempt);
}

static void dl_log(const struct dl_row *row, const char *text)
{
    if (row->log_path[0] && text)
        (void)dl_append_text(row->log_path, text);
}

bool zcl_dev_land_beat_format(const struct zcl_land_beat *b, char *out, size_t cap)
{
    char duration[32] = "unknown";
    if (out && cap) out[0] = '\0';
    if (!b || !out || !cap) return false;
    if (!b->beat || !b->base || !b->local || !b->tree) return false;
    if (b->started_us >= 0 && b->finished_us >= b->started_us)
        (void)snprintf(duration, sizeof(duration), "%lld",
                      (long long)(b->finished_us - b->started_us));
    int n = snprintf(out, cap,
        "zcl.dev_land.beat.v1 seq=%lld attempt=%lld base=%s local=%s tree=%s beat=%s elapsed_us=%s\n",
        b->seq, b->attempt, b->base, b->local, b->tree, b->beat, duration);
    if (n <= 0 || (size_t)n >= cap) { out[0] = '\0'; return false; }
    return true;
}

static void dl_beat(const struct dl_row *row, const char *beat, int64_t started)
{
    char wire[768];
    struct zcl_land_beat b = { beat, row->base, row->local, row->tree,
        row->seq, row->attempt, started, platform_time_monotonic_us() };
    if (zcl_dev_land_beat_format(&b, wire, sizeof(wire))) dl_log(row, wire);
}

/* ── rebase conflicts on the artifacts every train regenerates ──────────
 *
 * docs/CAPABILITY_INVENTORY.jsonl, docs/API_REFERENCE.md and the
 * <!-- DOC-COUNTS --> block of docs/CODEBASE_MAP.md are GENERATED from the
 * code, and a train that lands regenerates them. Two tips landing in the
 * same window therefore collide on those files by construction, and a
 * textual merge of two generated files settles nothing: neither side is
 * authoritative, the CODE is. Refusing the whole tip for that is the queue
 * stalling on a conflict whose resolution is mechanical — take the
 * upstream side, re-run the generator that owns the file, then GATE the
 * result and commit what the code actually says.
 *
 * The table is CLOSED, and deliberately: it names the only artifact paths
 * with a regeneration target this file can name. CODEBASE_MAP also carries
 * authored prose, which must merge cleanly before regeneration. A conflict
 * touching anything else — even alongside these — is
 * still a conflict and is reported exactly as it is today, because nothing
 * mechanical can settle it. */
struct dl_regen_artifact {
    const char *path;
    const char *make_target;
    const char *label; /* how the commit subject names it, in English */
};

static const struct dl_regen_artifact DL_REGEN_ARTIFACTS[] = {
    { "docs/CAPABILITY_INVENTORY.jsonl", "docs-capability-inventory",
      "capability inventory" },
    { "docs/API_REFERENCE.md", "docs-api-reference", "API reference" },
    /* No target regenerates this page's body; `fix-doc-counts` (Makefile,
     * next to check-doc-counts) rewrites the machine-readable DOC-COUNTS
     * block from the code-measured values. Recovery normalizes that block
     * to upstream before merging the three stages' authored prose; an
     * authored conflict refuses recovery before regeneration or gates. */
    { "docs/CODEBASE_MAP.md", "fix-doc-counts", "codebase map" },
};

/* Regenerating is only half of it: an artifact rewritten from THIS tree
 * still has to agree with the other generated artifacts and with the
 * code's own counts. These two gates are what says so. They run after the
 * generators and before anything is committed — and they run even when
 * the generators changed nothing, because "clean" is a claim about the
 * merged tree, not about the generator. */
static const char *const DL_REGEN_GATES[] = {
    "check-generated-artifact-contradictions",
    "check-doc-counts",
};

#define DL_REGEN_N \
    (sizeof(DL_REGEN_ARTIFACTS) / sizeof(DL_REGEN_ARTIFACTS[0]))
#define DL_REGEN_GATE_N \
    (sizeof(DL_REGEN_GATES) / sizeof(DL_REGEN_GATES[0]))
/* An unmerged-path list about these files alone cannot be long. Making the
 * classify buffer the same size as the capture that feeds it means a
 * TRUNCATED capture is refused rather than mistaken for a short,
 * all-regenerated list — the one way this classification could fail open. */
#define DL_REGEN_PATHS_CAP 1024u
/* One `rebase --continue` per replayed commit. A rebase still conflicting
 * past this is not making progress; that is a setup failure, never a loop. */
#define DL_REGEN_ROUNDS 20

/* Test-only escape hatch for the generator and gate invocations below. The
 * rigs test_dev_land.c builds are throwaway git repos, not checkouts of
 * this repository: they carry no Makefile, so `make docs-capability-
 * inventory` there would fail for a reason that has nothing to do with the
 * classify / resolve / regenerate / gate / commit sequence under test. With
 * this set the make invocations are replaced by an in-process append to the
 * artifact — enough to dirty the tree so the regen commit is exercised for
 * real. Never read outside a test process, the same build-mode guard and
 * the same reasoning as dl_stub() and dl_hooks_stub_dir() above. */
static bool dl_regen_stub(void)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    const char *s = getenv("ZCL_LAND_REGEN_MAKE_STUB");
    return s && s[0];
#else
    /* A leaked test env var must never let an operator's production
     * binary commit a hand-appended line in place of a real generator's
     * output, nor skip the gates that check it. */
    return false;
#endif
}

/* The stubbed gate's verdict, so the refusal path — not just the happy
 * one — is exercised by a real case. Only ever consulted when
 * dl_regen_stub() already said this is a test process. */
static bool dl_regen_gate_stub_fails(void)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    const char *s = getenv("ZCL_LAND_REGEN_GATE_STUB_FAIL");
    return s && s[0];
#else
    return false;
#endif
}

/* The table index of `path`, or -1 when nothing in the closed table
 * matches it. */
static int dl_regen_index(const char *path)
{
    for (size_t i = 0; i < DL_REGEN_N; i++) {
        if (strcmp(path, DL_REGEN_ARTIFACTS[i].path) == 0)
            return (int)i;
    }
    return -1;
}

/* True only when `paths` (git's newline-separated unmerged list) is
 * NONEMPTY and every entry is a regenerated artifact; `seen[i]` is raised
 * for each artifact that appeared, accumulating across rounds. An empty
 * list — which is what a failed `diff --diff-filter=U` also looks like —
 * is never "all resolved". */
static bool dl_regen_only(const char *paths, bool *seen)
{
    char work[DL_REGEN_PATHS_CAP];
    char *line, *save = NULL;
    bool any = false;
    if (!paths || !paths[0] || strlen(paths) >= sizeof(work))
        return false;
    (void)snprintf(work, sizeof(work), "%s", paths);
    for (line = strtok_r(work, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        size_t n = strlen(line);
        int idx;
        while (n > 0 && (line[n - 1] == '\r' || line[n - 1] == ' '))
            line[--n] = '\0';
        if (!line[0])
            continue;
        idx = dl_regen_index(line);
        if (idx < 0)
            return false;
        seen[idx] = true;
        any = true;
    }
    return any;
}

/* Merge count-page prose; take upstream for fully generated artifacts.
 * During `git rebase <upstream>` "ours" IS the upstream being rebased
 * onto — the side whose generated content already agrees with the code
 * that is on main. A path with no stage-2 entry (a delete/modify
 * conflict) makes `checkout --ours` fail, and that refuses the whole
 * auto-resolve rather than guessing. */
static inline bool dl_counts_span(char *text, char **begin, char **end)
{
    const char *b = "<!-- DOC-COUNTS-BEGIN -->\n";
    const char *e = "<!-- DOC-COUNTS-END -->\n";
    *begin = strstr(text, b);
    *end = strstr(text, e);
    if (!*begin || !*end || *end < *begin ||
        strstr(text, "<!-- DOC-COUNTS-BEGIN -->") != *begin ||
        strstr(text, "<!-- DOC-COUNTS-END -->") != *end ||
        (*begin != text && (*begin)[-1] != '\n') ||
        (*end != text && (*end)[-1] != '\n') ||
        strstr(*begin + strlen(b), "<!-- DOC-COUNTS-BEGIN -->") ||
        strstr(*end + strlen(e), "<!-- DOC-COUNTS-END -->"))
        return false;
    *end += strlen(e);
    return true;
}
/* Largest codebase-map stage the merge reads; a bigger one is refused, never
 * truncated. */
#define DL_COUNTS_MAX_BYTES ((size_t)8 << 20)

/* Read one index stage of docs/CODEBASE_MAP.md into an exact-size heap
 * buffer (NUL-terminated). The size comes first so the capture cap is the
 * real length rather than a guess. */
static bool dl_counts_stage(const struct dl_dirs *d, int stage, char **text,
                            size_t *len)
{
    char spec[64], size_text[32], *endp = NULL;
    struct zcl_spawn_binary_observation capture;
    unsigned long long size;
    (void)snprintf(spec, sizeof(spec), ":%d:docs/CODEBASE_MAP.md", stage);
    const char *cat[] = { "git", "-C", d->wt, "cat-file", "-s", spec, NULL };
    if (!zcl_spawn_capture_binary(cat, size_text, sizeof(size_text) - 1,
                                  DL_GIT_TIMEOUT_MS, &capture).ok) return false;
    size_text[capture.output_len] = '\0';
    size = strtoull(size_text, &endp, 10);
    if (endp == size_text || size == 0) return false;
    if (size > DL_COUNTS_MAX_BYTES) {
        (void)fprintf(stderr, "dl_counts_merge: %s is %llu bytes, over the "
                      "%zu byte ceiling\n", spec, size, DL_COUNTS_MAX_BYTES);
        return false;
    }
    *text = zcl_malloc((size_t)size + 1, "dev.land.counts.stage");
    if (!*text) return false;
    const char *show[] = { "git", "-C", d->wt, "show", spec, NULL };
    if (!zcl_spawn_capture_binary(show, *text, (size_t)size, DL_GIT_TIMEOUT_MS,
                                  &capture).ok || capture.output_len != size)
        return false;
    (*text)[size] = '\0';
    *len = (size_t)size;
    return strlen(*text) == *len;
}

/* Rebuild each stage with stage 2's count block and write the three-way
 * merge of the results to the working tree. */
static bool dl_counts_combine(const struct dl_dirs *d, const char *scratch,
                              char *const text[3], const size_t len[3],
                              char *const begin[3], char *const end[3])
{
    char file[3][4220], path[4220], *merged;
    struct zcl_spawn_binary_observation capture;
    size_t cap = len[0] + len[1] + len[2] + 16384;
    bool ok = false;
    for (int i = 0; i < 3; i++) {
        (void)snprintf(file[i], sizeof(file[i]), "%s/%d", scratch, i);
        if ((begin[i] != text[i] &&
             !dl_append_row(file[i], text[i], (size_t)(begin[i] - text[i]))) ||
            !dl_append_row(file[i], begin[1], (size_t)(end[1] - begin[1])) ||
            !dl_append_text(file[i], end[i])) return false;
    }
    merged = zcl_malloc(cap, "dev.land.counts.merged");
    if (!merged) return false;
    const char *merge[] = { "git", "-C", d->wt, "merge-file", "-p", "--",
                            file[1], file[0], file[2], NULL };
    if (zcl_spawn_capture_binary(merge, merged, cap - 1, DL_GIT_TIMEOUT_MS,
                                 &capture).ok) {
        merged[capture.output_len] = '\0';
        (void)snprintf(path, sizeof(path), "%s/merged", scratch);
        (void)snprintf(file[1], sizeof(file[1]), "%s/docs/CODEBASE_MAP.md",
                       d->wt);
        ok = dl_append_text(path, merged) && rename(path, file[1]) == 0;
    }
    free(merged);
    return ok;
}

static bool dl_counts_merge(const struct dl_dirs *d)
{
#if defined(_WIN32)
    (void)d;
    return false;
#else
    char scratch[4200], *text[3] = { NULL, NULL, NULL };
    char *begin[3], *end[3];
    size_t len[3] = { 0, 0, 0 };
    bool ok = false;
    if (snprintf(scratch, sizeof(scratch), "%s/counts.XXXXXX", d->land) >=
        (int)sizeof(scratch) || !mkdtemp(scratch)) return false;
    for (int i = 0; i < 3; i++)
        if (!dl_counts_stage(d, i + 1, &text[i], &len[i]) ||
            !dl_counts_span(text[i], &begin[i], &end[i])) goto done;
    ok = dl_counts_combine(d, scratch, text, len, begin, end);
done:
    for (int i = 0; i < 3; i++) free(text[i]);
    if (!zcl_tree_remove(scratch).ok) ok = false;
    return ok;
#endif
}
static bool dl_regen_resolve(const struct dl_dirs *d, const char *paths)
{
    char work[DL_REGEN_PATHS_CAP];
    char *line, *save = NULL;
    if (!paths || !paths[0] || strlen(paths) >= sizeof(work))
        return false;
    (void)snprintf(work, sizeof(work), "%s", paths);
    for (line = strtok_r(work, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        const char *ours[] = { "checkout", "--ours", "--", line, NULL };
        const char *add[] = { "add", "--", line, NULL };
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\r' || line[n - 1] == ' '))
            line[--n] = '\0';
        if (!line[0])
            continue;
        bool resolved = strcmp(line, "docs/CODEBASE_MAP.md") == 0
            ? dl_counts_merge(d) : dl_git(d->wt, ours, NULL, 0, DL_GIT_TIMEOUT_MS) == 0;
        if (!resolved ||
            dl_git(d->wt, add, NULL, 0, DL_GIT_TIMEOUT_MS) != 0)
            return false;
    }
    return true;
}

/* The test stub's stand-in for a generator: dirty the artifact in place.
 * No process is spawned — a stub that spawned one would be testing the
 * spawn seam rather than the commit path it exists to reach. */
static bool dl_regen_stub_write(const char *wt, const char *rel)
{
    char path[4096 + 96];
    FILE *f;
    if (snprintf(path, sizeof(path), "%s/%s", wt, rel) >= (int)sizeof(path))
        return false;
    f = fopen(path, "ab");
    if (!f)
        return false;
    if (fputs("regenerated by dev.land\n", f) == EOF) {
        (void)fclose(f);
        return false;
    }
    return fclose(f) == 0;
}

/* One make target in the landing worktree — a generator or a gate. Same
 * spawn seam, same transcript handling and same actionable-line triage as
 * dl_lint_fast() below: generation uses the same `make` execution path.
 * Trust: the targets are the CANDIDATE's own Makefile recipes, run in the
 * private landing worktree -- the tree whose tools the lint and prebuild
 * below already build and execute -- so this adds no execution exposure
 * the landing did not already have. `line` receives the first
 * line a person can act on when the target failed. */
static int dl_regen_make(const struct dl_dirs *d, struct dl_row *row,
                         const char *target, char *line, size_t line_cap)
{
    /* Was a bare "-j8". These are the same make targets the proof just ran,
     * in the same grant, so the two disagreeing about the job count meant one
     * of them was wrong about the same machine. N now comes from the one
     * repository-wide derivation (platform/logical_cpu.h) -- 28 inside this
     * host's build grant, where the old literal spent 8. `jobs` must outlive
     * argv. */
    char jobs[16];
    if (!platform_build_jobs_arg(jobs)) return -1;
    const char *argv[] = { "make", jobs, "-C", d->wt, target, NULL };
    char *buf;
    int rc;
    if (line && line_cap)
        line[0] = '\0';
    buf = (char *)zcl_malloc(DL_LOG_CAP, "dev.land.regen");
    if (!buf)
        return -1;
    rc = zcl_spawn_capture(argv, buf, DL_LOG_CAP, DL_LINT_TIMEOUT_MS);
    dl_log(row, buf);
    if (rc != 0 && line && line_cap) {
        dl_first_actionable(buf, line, line_cap);
        if (!line[0]) {
            /* dl_first_actionable's needles do not include the doc-count
             * gate's own MISMATCH wording, and `make`'s "*** Error" goes
             * to stderr, which this capture does not hold. Look for the
             * gate's word before giving up on naming a line at all. */
            const char *m = strstr(buf, "MISMATCH");
            if (m) {
                const char *start = m;
                while (start > buf && start[-1] != '\n')
                    start--;
                (void)snprintf(line, line_cap, "%.*s",
                               (int)strcspn(start, "\n"), start);
            }
        }
    }
    free(buf);
    return rc;
}

/* "rebase: regenerated <a>,<b>" — the artifacts that ACTUALLY conflicted,
 * in table order, by their raw paths, so the row says what landing added
 * to the tip rather than presenting a silently rewritten tree as an
 * ordinary rebase. Machine-facing on purpose; the commit subject below is
 * the English one. */
static void dl_regen_note(const bool *seen, char *out, size_t cap)
{
    size_t used;
    bool first = true;
    int w;
    if (!out || cap == 0)
        return;
    out[0] = '\0';
    w = snprintf(out, cap, "rebase: regenerated");
    if (w < 0 || (size_t)w >= cap) {
        out[0] = '\0';
        return;
    }
    used = (size_t)w;
    for (size_t i = 0; i < DL_REGEN_N; i++) {
        if (!seen[i])
            continue;
        w = snprintf(out + used, cap - used, "%s%s", first ? " " : ",",
                     DL_REGEN_ARTIFACTS[i].path);
        if (w < 0 || (size_t)w >= cap - used) {
            out[0] = '\0';
            return;
        }
        used += (size_t)w;
        first = false;
    }
}

/* "Regenerate the capability inventory, API reference and codebase map
 * after rebasing onto <short base>" — English, listing only what actually
 * conflicted, because this subject is read by people scanning main's
 * history, not by a parser. */
static bool dl_regen_subject(const bool *seen, const char *base, char *out,
                             size_t cap)
{
    size_t used, remaining = 0;
    bool first = true;
    int w;
    if (!out || cap == 0)
        return false;
    out[0] = '\0';
    for (size_t i = 0; i < DL_REGEN_N; i++) {
        if (seen[i])
            remaining++;
    }
    if (remaining == 0)
        return false;
    w = snprintf(out, cap, "Regenerate the");
    if (w < 0 || (size_t)w >= cap)
        return false;
    used = (size_t)w;
    for (size_t i = 0; i < DL_REGEN_N; i++) {
        const char *sep;
        if (!seen[i])
            continue;
        remaining--;
        sep = first ? " " : (remaining == 0 ? " and " : ", ");
        w = snprintf(out + used, cap - used, "%s%s", sep,
                     DL_REGEN_ARTIFACTS[i].label);
        if (w < 0 || (size_t)w >= cap - used)
            return false;
        used += (size_t)w;
        first = false;
    }
    w = snprintf(out + used, cap - used, " after rebasing onto %.9s", base);
    return w >= 0 && (size_t)w < cap - used;
}

/* Record the regenerated artifacts by AMENDING them into the rebased
 * candidate's last commit, never as a follow-up commit on main.
 *
 * WHY THE TIP, NOT THE REPLAYED COMMIT THAT CONFLICTED. The auto-resolve
 * above settles each conflicted replay by taking main's side, so an
 * intermediate replayed commit carries main's copy of the artifact; the
 * generators then run ONCE, on the finished tree, and describe the code of
 * that tree, which is HEAD's. Only HEAD's tree is proved and published.
 * Folding into the commit being replayed would mean running generators
 * mid-rebase for trees nobody proves, for no difference in what lands.
 *
 * `--amend --no-edit` keeps the tip's message, author and parents; `--only`
 * with the explicit closed-table paths records the tip's own tree plus
 * exactly those paths, whatever else the index holds. Signing is the
 * ambient commit.gpgsign configuration -- no -S and no --no-gpg-sign,
 * exactly as native_dev_train_command.c's regenerate-docs commit relies on
 * it; main rejects an unsigned commit, so a flag invented here would be a
 * second, divergent way to state the same policy.
 *
 * The one HEAD that cannot be amended is one main already holds (the
 * rebase skipped every candidate commit): rewriting it would rewrite
 * published history, so that case alone keeps the separate commit. */
static int dl_regen_fold(const struct dl_dirs *d, struct dl_row *row,
                         const bool *seen, char *why, size_t why_cap)
{
    const char *published_args[] = { "--no-replace-objects", "merge-base",
                                     "--is-ancestor", "HEAD", row->base,
                                     NULL };
    const char *args[DL_REGEN_N + 8];
    char subject[512];
    size_t n = 0;
    int ancestor_rc = dl_git(d->wt, published_args, NULL, 0,
                           DL_GIT_TIMEOUT_MS);
    args[n++] = "commit";
    args[n++] = "-q";
    if (ancestor_rc == 1) {       /* HEAD is the candidate's own commit */
        args[n++] = "--amend";
        args[n++] = "--no-edit";
    } else if (ancestor_rc == 0 &&   /* main already holds HEAD */
               dl_regen_subject(seen, row->base, subject, sizeof(subject))) {
        args[n++] = "-m";
        args[n++] = subject;
    } else {
        (void)snprintf(why, why_cap, "%s",
                       "regen commit failed after auto-resolving the "
                       "rebase");
        return -1;
    }
    args[n++] = "--only";
    args[n++] = "--";
    for (size_t i = 0; i < DL_REGEN_N; i++) {
        if (seen[i])
            args[n++] = DL_REGEN_ARTIFACTS[i].path;
    }
    args[n] = NULL;
    if (dl_git(d->wt, args, NULL, 0, DL_GIT_TIMEOUT_MS) != 0) {
        (void)snprintf(why, why_cap, "%s",
                       "regen commit failed after auto-resolving the "
                       "rebase");
        return -1;
    }
    return 1;
}

/* Run the generator of every `run[i]` artifact, deduped by make target. */
static int dl_regen_generate(const struct dl_dirs *d, struct dl_row *row,
                             const bool *run, char *why, size_t why_cap)
{
    char line[256];
    for (size_t i = 0; i < DL_REGEN_N; i++) {
        bool duplicate = false;
        if (!run[i])
            continue;
        if (dl_regen_stub()) {
            if (dl_regen_stub_write(d->wt, DL_REGEN_ARTIFACTS[i].path))
                continue;
            (void)snprintf(why, why_cap,
                           "regenerating %s (%s) failed after "
                           "auto-resolving the rebase",
                           DL_REGEN_ARTIFACTS[i].path,
                           DL_REGEN_ARTIFACTS[i].make_target);
            return -1;
        }
        for (size_t j = 0; j < i; j++) {
            if (run[j] && strcmp(DL_REGEN_ARTIFACTS[j].make_target,
                                 DL_REGEN_ARTIFACTS[i].make_target) == 0)
                duplicate = true;
        }
        if (duplicate)
            continue;
        if (dl_regen_make(d, row, DL_REGEN_ARTIFACTS[i].make_target, line,
                          sizeof(line)) != 0) {
            (void)snprintf(why, why_cap,
                           "regenerating %s (%s) failed after "
                           "auto-resolving the rebase",
                           DL_REGEN_ARTIFACTS[i].path,
                           DL_REGEN_ARTIFACTS[i].make_target);
            return -1;
        }
    }
    return 1;
}

/* The gates run whether or not the generators moved a byte: agreement
 * between the generated artifacts is a property of the MERGED tree,
 * and the merge is what just changed. */
static int dl_regen_gates(const struct dl_dirs *d, struct dl_row *row,
                          char *why, size_t why_cap)
{
    char line[256];
    for (size_t i = 0; i < DL_REGEN_GATE_N; i++) {
        int rc;
        if (dl_regen_stub()) {
            if (!dl_regen_gate_stub_fails())
                continue;
            (void)snprintf(line, sizeof(line), "%s",
                           "FAIL: stub gate refused "
                           "(ZCL_LAND_REGEN_GATE_STUB_FAIL)");
            rc = 1;
        } else {
            rc = dl_regen_make(d, row, DL_REGEN_GATES[i], line,
                               sizeof(line));
        }
        if (rc == 0)
            continue;
        (void)snprintf(why, why_cap,
                       "%s refused after auto-resolving the rebase: %s",
                       DL_REGEN_GATES[i],
                       line[0] ? line : "no actionable line captured");
        return -1;
    }
    return 1;
}

/* `touched` = conflicted artifacts plus any other one a generator moved. */
static void dl_regen_touched(const struct dl_dirs *d, const bool *seen,
                             const bool *run, bool *touched)
{
    for (size_t i = 0; i < DL_REGEN_N; i++) {
        const char *args[] = { "diff", "--quiet", "--",
                               DL_REGEN_ARTIFACTS[i].path, NULL };
        touched[i] = seen[i] ||
            (run[i] && dl_git(d->wt, args, NULL, 0, DL_GIT_TIMEOUT_MS) != 0);
    }
}

/* Run every artifact's generator (all are deterministic, and a count bump
 * can merge cleanly yet stale while another artifact conflicts), then the
 * two gates that say the regenerated tree is self-consistent, then fold
 * whatever the generators actually changed into the tip
 * (dl_regen_fold()). Returns 1 on success,
 * -1 with `why` on a hard failure — a generator that will not run, a gate
 * that still refuses, or a commit that will not be made is not a conflict
 * any more. The stub regenerates only the conflicted artifacts. */
static int dl_regen_run(const struct dl_dirs *d, struct dl_row *row,
                        const bool *seen, char *why, size_t why_cap)
{
    const char *diff_args[DL_REGEN_N + 4];
    bool run[DL_REGEN_N], touched[DL_REGEN_N];
    size_t dn = 0;

    for (size_t i = 0; i < DL_REGEN_N; i++)
        run[i] = dl_regen_stub() ? seen[i] : true;
    if (dl_regen_generate(d, row, run, why, why_cap) < 0 ||
        dl_regen_gates(d, row, why, why_cap) < 0)
        return -1;
    dl_regen_touched(d, seen, run, touched);

    diff_args[dn++] = "diff";
    diff_args[dn++] = "--quiet";
    diff_args[dn++] = "--";
    for (size_t i = 0; i < DL_REGEN_N; i++) {
        if (touched[i])
            diff_args[dn++] = DL_REGEN_ARTIFACTS[i].path;
    }
    diff_args[dn] = NULL;
    /* Exit 0 means the generators reproduced exactly what the upstream
     * side already held. Nothing to record: that is a clean outcome, not
     * a failure. */
    if (dl_git(d->wt, diff_args, NULL, 0, DL_GIT_TIMEOUT_MS) == 0)
        return 1;
    return dl_regen_fold(d, row, touched, why, why_cap);
}

/* Why an auto-resolve that already settled one replayed commit handed a
 * later one back as a conflict. An empty list means `rebase --continue`
 * failed without leaving an unmerged path: the replayed commit itself was
 * refused, the signer included -- no unsigned commit is ever made here. */
static void dl_regen_stop_log(struct dl_row *row, const char *paths)
{
    char note[DL_REGEN_PATHS_CAP + 160];
    if (!paths || !paths[0]) {
        dl_log(row, "rebase auto-resolve stopped: git rebase --continue "
                    "failed with no unmerged path (the replayed commit, or "
                    "its signature, was refused)\n");
        return;
    }
    (void)snprintf(note, sizeof(note),
                   "rebase auto-resolve stopped: a replayed commit "
                   "conflicted outside the regenerated artifacts: %.*s\n",
                   (int)DL_REGEN_PATHS_CAP, paths);
    for (char *p = note; p[0] && p[1]; p++) {
        if (*p == '\n')
            *p = ' ';
    }
    dl_log(row, note);
}

/* Drive a conflicted rebase to completion when — and only when — every
 * conflicted path is a regenerated artifact, on every replayed commit.
 *
 * Returns 1 auto-resolved (the rebase finished, the generators ran, the
 * gates passed, and their output is committed or provably identical), 0
 * not ours to settle (the caller aborts and reports the conflict
 * byte-identically to how it always has), -1 a hard failure with `why`.
 * `why` is written ONLY on -1: the caller has already composed the
 * conflict message from the original unmerged list and must keep it.
 * `paths` is the caller's capture buffer, reused for each round's
 * re-check. */
static int dl_rebase_autoresolve(const struct dl_dirs *d, struct dl_row *row,
                                 char *paths, size_t paths_cap, bool *seen,
                                 char *why, size_t why_cap)
{
    const char *staged_args[] = { "diff", "--cached", "--quiet", NULL };
    const char *cont_args[] = { "-c", "rerere.autoupdate=false", "-c",
                                "core.editor=true", "rebase", "--continue", NULL };
    const char *skip_args[] = { "-c", "rerere.autoupdate=false", "rebase", "--skip", NULL };
    const char *unmerged_args[] = { "diff", "--name-only", "--diff-filter=U",
                                    NULL };
    size_t recheck_cap = paths_cap < DL_REGEN_PATHS_CAP ? paths_cap
                                                        : DL_REGEN_PATHS_CAP;
    if (!dl_regen_only(paths, seen))
        return 0;
    for (int round = 0; round < DL_REGEN_ROUNDS; round++) {
        int rc;
        if (!dl_regen_resolve(d, paths)) {
            dl_log(row, "rebase auto-resolve refused the conflicted "
                        "artifact set\n");
            return 0;
        }
        /* Taking the upstream side can leave the replayed commit with
         * nothing of its own left to record — a commit that only ever
         * regenerated these files. git refuses to continue on an empty
         * commit and asks for --skip by name; skipping is correct there,
         * because the commit contributes nothing the upstream side does
         * not already hold. */
        if (dl_git(d->wt, staged_args, NULL, 0, DL_GIT_TIMEOUT_MS) == 0)
            rc = dl_git(d->wt, skip_args, NULL, 0, DL_GIT_TIMEOUT_MS);
        else
            rc = dl_git(d->wt, cont_args, NULL, 0, DL_GIT_TIMEOUT_MS);
        if (rc == 0)
            return dl_regen_run(d, row, seen, why, why_cap);
        paths[0] = '\0';
        (void)dl_git(d->wt, unmerged_args, paths, recheck_cap,
                     DL_GIT_TIMEOUT_MS);
        dl_trim(paths);
        /* A nonzero continue with no unmerged paths is a rebase failure
         * this cannot name; so is one naming anything outside the table.
         * Both fall back to the caller's ordinary conflict outcome, whose
         * detail names only the FIRST commit's unmerged list -- so the
         * attempt log says what actually stopped the auto-resolve. */
        if (!dl_regen_only(paths, seen)) {
            dl_regen_stop_log(row, paths);
            return 0;
        }
    }
    (void)snprintf(why, why_cap, "%s",
                   "the rebase kept conflicting on regenerated artifacts "
                   "past the auto-resolve bound");
    return -1;
}

/* Preserve the resolved source while giving the integrated proposal a linear
 * publication identity. The queue retains the original submitted tip.
 * `replay` marks a commit dl_rebase() will replay onto a newer main, where
 * its parent and tree both change: its message then records only what stays
 * true after that replay, the submitted tip and the base it was cut from. */
static bool dl_linear_commit(const struct dl_dirs *d, struct dl_row *row,
    const char *base, const char *tree, bool replay, char commit[80])
{
    char message[512];
    if (replay)
        (void)snprintf(message, sizeof(message),
            "Prepare candidate for linear publication\n\n"
            "Original-Candidate: %s\nOriginal-Base: %s", row->tip, base);
    else
        (void)snprintf(message, sizeof(message),
            "Prepare integrated candidate for linear publication\n\n"
            "Original-Candidate: %s\nIntegrated-Base: %s\nSource-Tree: %s",
            row->tip, base, tree);
    const char *allow = dl_allow_unsigned();
    bool fixture = allow && strcmp(allow, "1") == 0 && dl_stub() != NULL;
    const char *args[10];
    size_t n = 0;
    args[n++] = "commit-tree";
    if (!fixture) args[n++] = "-S";
    args[n++] = tree;
    args[n++] = "-p"; args[n++] = base;
    args[n++] = "-m"; args[n++] = message;
    args[n] = NULL;
    if (dl_git(d->wt, args, commit, 80, DL_GIT_TIMEOUT_MS) != 0)
        return false;
    dl_trim(commit);
    char checked[80];
    return dl_rev_parse(d->wt, commit, checked) && strcmp(commit, checked) == 0;
}

static void dl_linear_log(struct dl_row *row, const char *base,
    const char *commit, const char *tree, bool replay)
{
    char note[480];
    if (replay)
        (void)snprintf(note, sizeof(note),
            "linearized merge-bearing candidate %s as %s at merge-base %s "
            "with exact tree %s; replaying it onto current main\n",
            row->tip, commit, base, tree);
    else
        (void)snprintf(note, sizeof(note),
            "prepared linear candidate %s from %s with exact tree %s\n",
            commit, row->tip, tree);
    dl_log(row, note);
}

static bool dl_linearize(const struct dl_dirs *d, struct dl_row *row,
    const char *base, bool replay, char *why, size_t why_cap)
{
    char range[160], merges[80], tree[80], commit[80], checked[80];
    (void)snprintf(range, sizeof(range), "%s..%s", base, row->tip);
    const char *merges_args[] = { "rev-list", "--merges", "--max-count=1", range, NULL };
    const char *tree_args[] = { "rev-parse", "HEAD^{tree}", NULL };
    const char *checkout_args[] = { "checkout", "--quiet", "--detach", commit, NULL };
    (void)snprintf(why, why_cap, "cannot prepare a tree-preserving linear landing candidate");
    if (dl_git(d->wt, merges_args, merges, sizeof(merges), DL_GIT_TIMEOUT_MS) != 0)
        return false;
    dl_trim(merges);
    if (!merges[0]) return true;
    if (dl_git(d->wt, tree_args, tree, sizeof(tree), DL_GIT_TIMEOUT_MS) != 0)
        return false;
    dl_trim(tree);
    if (!dl_linear_commit(d, row, base, tree, replay, commit) ||
        dl_git(d->wt, checkout_args, NULL, 0, DL_GIT_TIMEOUT_MS) != 0 ||
        dl_git(d->wt, tree_args, checked, sizeof(checked), DL_GIT_TIMEOUT_MS) != 0)
        return false;
    dl_trim(checked);
    if (strcmp(tree, checked) != 0) return false;
    dl_linear_log(row, base, commit, tree, replay);
    return true;
}

/* A tip main has moved past is rebased, and a plain `git rebase` replays
 * each non-merge commit one at a time, DISCARDING the conflict resolutions
 * the tip's own merges of main recorded. A long-lived candidate that merged
 * main into itself (resolving the generated inventory and real source by
 * hand) therefore re-conflicts on a later replayed commit, on source it had
 * already resolved; the generated-artifact auto-resolve correctly declines
 * that, and the row ends as a conflict nobody needed (land queue row 30,
 * docs/CAPABILITY_INVENTORY.jsonl). Cut the tip's exact tree as ONE commit
 * on merge-base(main, tip) first -- the same tree-preserving step and the
 * same signer an integrated tip takes above -- so the rebase replays the
 * candidate's net change once and conflicts only where that net change and
 * main's newer work really overlap. A tip with no merges past the merge
 * base is replayed commit by commit exactly as before. */
static bool dl_linearize_for_rebase(const struct dl_dirs *d,
    struct dl_row *row, const char *observed_main, char *why, size_t why_cap)
{
    char mb[80];
    const char *mb_args[] = { "--no-replace-objects", "merge-base",
                              observed_main, row->tip, NULL };
    /* No common ancestor (or none git will name): there is no base to cut
     * against, and the rebase below reports that the way it always has. */
    if (dl_git(d->wt, mb_args, mb, sizeof(mb), DL_GIT_TIMEOUT_MS) != 0)
        return true;
    dl_trim(mb);
    return !mb[0] || dl_linearize(d, row, mb, true, why, why_cap);
}

/* Resolve and check out the exact submitted tip in the private worktree. */
static bool dl_tip_checkout(const struct dl_dirs *d, struct dl_row *row,
                            const char *observed_main, bool *integrated,
                            char *why, size_t why_cap)
{
    char buf[DL_GIT_CAP];
    const char *ancestor_args[] = { "--no-replace-objects", "merge-base",
                                    "--is-ancestor", observed_main, row->tip, NULL };
    const char *checkout_args[] = { "checkout", "--quiet", "--force",
                                    "--detach", row->tip, NULL };
    if (!dl_rev_parse(d->wt, row->tip, row->local)) {
        if (!dl_worktree_ok(row->worktree)) {
            (void)snprintf(why, why_cap, "%s",
                           "source checkout unavailable or outside receiver policy");
            return false;
        }
        /* The tip lives in another checkout: fetch that ONE object rather
         * than every ref the other checkout happens to hold. The locator
         * passed its current receiver policy above, but "--" still
         * goes in front of it: a positional git argument is git's own to
         * parse, and nothing downstream of this call should have to keep
         * proving that guarantee held all the way here. */
        const char *pull_args[] = { "fetch", "--quiet", "--no-tags", "--",
                                    row->worktree, row->tip, NULL };
        (void)dl_git(d->wt, pull_args, buf, sizeof(buf), DL_GIT_TIMEOUT_MS);
        if (!dl_rev_parse(d->wt, row->tip, row->local)) {
            (void)snprintf(why, why_cap,
                           "the landing worktree cannot resolve the tip");
            return false;
        }
    }
    if (dl_git(d->wt, checkout_args, buf, sizeof(buf), DL_GIT_TIMEOUT_MS) !=
        0) {
        (void)snprintf(why, why_cap, "cannot check the tip out for landing");
        return false;
    }
    int ancestor = dl_git(d->wt, ancestor_args, buf, sizeof(buf),
                          DL_GIT_TIMEOUT_MS);
    if (ancestor != 0 && ancestor != 1) {
        (void)snprintf(why, why_cap, "cannot establish landing tip ancestry");
        return false;
    }
    *integrated = ancestor == 0;
    if (*integrated)
        return dl_linearize(d, row, observed_main, false, why, why_cap);
    return dl_linearize_for_rebase(d, row, observed_main, why, why_cap);
}

/* Move the row's base to a newly observed main. The producer-recovery mark
 * is spent only until main moves, so it clears only when the base changes. */
static void dl_row_move_base(struct dl_row *row, const char *observed_main)
{
    if (strcmp(row->base, observed_main) != 0)
        row->producer_recovered = 0;
    (void)snprintf(row->base, sizeof(row->base), "%s", observed_main);
}

/* Rebase the row's tip onto origin/main inside the private landing
 * worktree. Returns 1 prepared, 0 conflict, -1 setup failure.
 *
 * `regen_note` is an OUT parameter, always initialised: it is filled only
 * when a conflict on the regenerated artifacts above was auto-resolved,
 * and stays empty on every other path — so a caller can tell a rebase
 * that amended regenerated docs into the tip from one that did not,
 * without having to re-derive it from git. */
static int dl_rebase(const struct dl_dirs *d, struct dl_row *row,
                     const char *observed_main, char *why, size_t why_cap,
                     char *regen_note, size_t regen_note_cap)
{
    char buf[DL_GIT_CAP];
    bool integrated = false;
    const char *rebase_args[] = { "--no-replace-objects", "-c",
                                  "rerere.autoupdate=false", "rebase", observed_main, NULL };
    const char *unmerged_args[] = { "diff", "--name-only", "--diff-filter=U", NULL };
    const char *abort_args[] = { "rebase", "--abort", NULL };
    if (regen_note && regen_note_cap)
        regen_note[0] = '\0';
    if (!dl_tip_checkout(d, row, observed_main, &integrated, why, why_cap))
        return -1;
    dl_row_move_base(row, observed_main);
    /* Replaying an already-integrated merge discards its resolution and
     * can reintroduce conflicts from previously published work. Skip only
     * that replay; preparation and exact proof below remain mandatory. */
    if (!integrated &&
        dl_git(d->wt, rebase_args, buf, sizeof(buf), DL_GIT_TIMEOUT_MS) !=
        0) {
        char paths[DL_GIT_CAP];
        bool seen[DL_REGEN_N] = { false };
        int resolved;
        (void)dl_git(d->wt, unmerged_args, paths, sizeof(paths),
                     DL_GIT_TIMEOUT_MS);
        dl_trim(paths);
        /* Compose the conflict message FIRST, from the original list, so
         * the auto-resolve below is free to reuse `paths` as scratch and
         * a conflict it declines to settle still reports byte-identically
         * to how it always has. Replacing newlines in `why` rather than
         * in `paths` is a 1:1 substitution, so it truncates identically
         * too. */
        (void)snprintf(why, why_cap, "%s",
                       paths[0] ? paths : "rebase refused the tip");
        for (char *p = why; *p; p++) {
            if (*p == '\n')
                *p = ' ';
        }
        resolved = dl_rebase_autoresolve(d, row, paths, sizeof(paths), seen,
                                         why, why_cap);
        if (resolved < 0) {
            (void)dl_git(d->wt, abort_args, buf, sizeof(buf),
                         DL_GIT_TIMEOUT_MS);
            return -1;
        }
        if (resolved > 0) {
            dl_regen_note(seen, regen_note, regen_note_cap);
        } else {
            (void)dl_git(d->wt, abort_args, buf, sizeof(buf),
                         DL_GIT_TIMEOUT_MS);
            return 0;
        }
    }
    if (!dl_rev_parse(d->wt, "HEAD", row->local)) {
        (void)snprintf(why, why_cap, "the rebased head cannot be named");
        return -1;
    }
    /* WHY. git worktree add leaves vendor/tor as an empty gitlink. Proof
     * generation then points the submodule url at that empty directory and
     * fails. Seed it from the submitting checkout, which already has the
     * gitlink. Fixture rigs under the proof stub have no submodule, so the
     * live landing is the exercise of this path. */
    if (!dl_stub()) {
        char cfg[4096 + 64];
        const char *gl[] = {
            "-c", "protocol.file.allow=always", "-c", cfg,
            "submodule", "update", "--init", "--no-fetch", "--",
            "vendor/tor", NULL
        };
        if (!dl_tor_source_config(row->worktree, cfg, sizeof(cfg)) ||
            dl_git(d->wt, gl, buf, sizeof(buf), DL_GIT_TIMEOUT_MS) != 0) {
            (void)snprintf(why, why_cap, "%s",
                           "landing_worktree_gitlink_failed");
            return -1;
        }
    }
    return 1;
}

/* make lint-land (lint-fast plus cheap gates that failed in proof lint) in the
 * landing worktree. Returns the child status; the transcript is appended to
 * the attempt log either way. */
static int dl_lint_run(struct dl_row *row, const char *const argv[]);

static int dl_lint_fast(const struct dl_dirs *d, struct dl_row *row)
{
    const char *argv[] = { "make", "-C", d->wt, "lint-land", NULL };
    return dl_lint_run(row, argv);
}

/* Does the candidate range add a compiled source file? 1 yes, 0 no, -1 when
 * git could not answer. */
static int dl_range_adds_source(const char *wt, const char *base,
                                const char *local)
{
    char out[4096];
    const char *args[] = { "diff", "--no-renames", "--diff-filter=A",
                           "--name-only", base, local, "--", "*.c", NULL };
    if (!dl_sha_ok(base) || !dl_sha_ok(local) ||
        dl_git(wt, args, out, sizeof(out), DL_GIT_TIMEOUT_MS) != 0)
        return -1;
    return out[0] != '\0' ? 1 : 0;
}

#if defined(ZCL_TESTING)
int zcl_native_dev_land_test_range_adds_source(const char *wt,
                                               const char *base,
                                               const char *local)
{
    return dl_range_adds_source(wt, base, local);
}
#endif

/* A new compiled source is what the full-lint-only gates in `make
 * lint-preflight` exist for — capability closure above all: a source with
 * no module_capabilities.def row passes lint-land and then fails the
 * proof's lint dimension, a whole proof spent on a gate that answers in
 * under a minute. Those gates read built objects, so they are too dear for
 * every landing and are run only when the range adds a `.c` file. A range
 * git cannot classify runs them: the cost of a needless minute is smaller
 * than the cost of the proof they would have saved. */
static int dl_lint_new_source(const struct dl_dirs *d, struct dl_row *row)
{
    char jobs[16];
    if (dl_range_adds_source(d->wt, row->base, row->local) == 0)
        return 0;
    if (!platform_build_jobs_arg(jobs))
        return -1;
    const char *argv[] = { "make", jobs, "-C", d->wt, "lint-preflight",
                           NULL };
    return dl_lint_run(row, argv);
}

/* Everything the landing lints before it asks for a proof. */
static int dl_lint_candidate(const struct dl_dirs *d, struct dl_row *row)
{
    int rc = dl_lint_fast(d, row);
    return rc != 0 ? rc : dl_lint_new_source(d, row);
}

static int dl_lint_run(struct dl_row *row, const char *const argv[])
{
    char *buf;
    int rc;
    buf = (char *)zcl_malloc(DL_LOG_CAP, "dev.land.lint");
    if (!buf)
        return -1;
    rc = zcl_spawn_capture(argv, buf, DL_LOG_CAP, DL_LINT_TIMEOUT_MS);
    dl_log(row, buf);
    if (rc != 0) {
        dl_first_actionable(buf, row->detail, sizeof(row->detail));
        if (dl_host_load_failure(buf))
            (void)snprintf(row->dimension, sizeof(row->dimension),
                           "host_load");
        else
            (void)snprintf(row->dimension, sizeof(row->dimension), "lint");
    }
    free(buf);
    return rc;
}

/* ── proof-generation dependencies the landing worktree must hold ───────
 *
 * dev_proof.c's prepare_generation() only ever COPIES the entries in its
 * `dependencies[]` array (vendor/lib, vendor/include, the four vendor/tor
 * archives, build/githooks and, on Linux, the two hotswap rollback fixture
 * images) out of paths->root — this worktree — into the proof's private
 * generation; it never builds any of them itself. Separately, the receipt's
 * build-identity capture reads build/dev-loop/restart.env straight from
 * paths->root. A bare `git worktree add` inherits none of this: vendored
 * archives are gitignored, the Tor submodule is not checked out into a
 * fresh worktree, and nothing has ever linked a test binary here — so
 * every one of them is missing the first time a fresh landing worktree
 * reaches this point, and the proof refuses by name
 * (`proof_generation_dependency_unavailable:<dep> (<fix>)` for the copied
 * set; `proof_toolchain_or_policy_unavailable` for the restart plan).
 * build/githooks is already handled: dl_wt_hooks_ensure() above arms it
 * unconditionally via `make install-hooks`, which every push needs
 * regardless of the proof. What is left is primed here, once per worktree
 * lifetime, so the proof always finds the rest already in place. */

/* Landing dependencies own independent inodes: a new hardlink changes the
 * donor's ctime and can invalidate another sealed proof generation. The
 * platform clone seam is available in every build profile; unsupported
 * cloning falls back to bytes copied into the same exclusive temporary file.
 * Preserve mode and mtime before publication, as the old hardlink did. */
static bool dl_same_inode(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static bool dl_same_copy_metadata(const struct stat *a, const struct stat *b)
{
    if (a->st_mode != b->st_mode || a->st_size != b->st_size)
        return false;
#if defined(__APPLE__)
    return a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec &&
           a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec;
#elif defined(_WIN32)
    return a->st_mtime == b->st_mtime;
#else
    return a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
#endif
}

static bool dl_same_file_snapshot(const struct stat *a, const struct stat *b)
{
    if (!dl_same_inode(a, b) || !dl_same_copy_metadata(a, b) ||
        a->st_nlink != b->st_nlink)
        return false;
#if defined(__APPLE__)
    return a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec &&
           a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#elif defined(_WIN32)
    return a->st_ctime == b->st_ctime;
#else
    return a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
}

#if !defined(_WIN32)
static int dl_materialize_tmp_open(const char *target, char *tmp,
                                   size_t tmp_size)
{
    int n = snprintf(tmp, tmp_size, "%s.tmp.XXXXXX", target);
    if (n <= 0 || (size_t)n >= tmp_size) return -1;
    int fd = mkstemp(tmp);
    if (fd < 0) return -1;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == 0) return fd;
    (void)close(fd);
    (void)unlink(tmp);
    return -1;
}

static bool dl_materialize_parent_flush(const char *target)
{
    char parent[4096 + 96];
    size_t target_len = strlen(target);
    if (target_len >= sizeof(parent)) return false;
    memcpy(parent, target, target_len + 1);
    char *slash = strrchr(parent, '/');
    if (!slash || slash == parent) return false;
    *slash = '\0';
    return platform_private_parent_flush(parent);
}

static bool dl_materialize_published(const char *target,
                                     const struct stat *completed,
                                     bool repair)
{
    struct stat observed;
    bool ok = lstat(target, &observed) == 0 && observed.st_nlink == 1 &&
              dl_same_inode(completed, &observed) &&
              dl_same_copy_metadata(completed, &observed);
    if (ok && repair) ok = dl_materialize_parent_flush(target);
    return ok;
}
#endif

static bool dl_materialize_file(const char *source, const char *target,
                                const struct stat *source_st,
                                const char *explained_alias)
{
#if defined(_WIN32)
    /* dev land step already refuses with STEP_WINDOWS_UNAVAILABLE before
     * any caller reaches dl_materialize()/dl_materialize_file() (see
     * dl_step below) -- POSIX hardlink/permission-bit semantics below have
     * no portable Windows equivalent worth building for a path that never
     * runs there, so this arm keeps the refusal instead of the body. */
    (void)source; (void)target; (void)source_st;
    return false;
#else
    int input, output;
    char tmp[4096 + 96];
    bool ok;
    struct stat observed, completed;
    int flags = O_RDONLY | O_CLOEXEC;
#if !defined(_WIN32)
    flags |= O_NOFOLLOW;
#endif
    input = open(source, flags);
    if (input < 0)
        return false;
    if (source_st->st_size < 0 || fstat(input, &observed) != 0 ||
        !S_ISREG(observed.st_mode) ||
        !dl_same_file_snapshot(source_st, &observed)) {
        (void)close(input);
        return false;
    }
    /* A crash before rename can leave a staged copy. A PID-only name could
     * collide after PID reuse and hold every later repair of nlink==2.
     * mkstemp gives each attempt a distinct exclusive name; old staging
     * debris cannot prevent recovery of the actual target inode. */
    output = dl_materialize_tmp_open(target, tmp, sizeof(tmp));
    if (output < 0) {
        (void)close(input);
        return false;
    }
    enum platform_file_clone_result cloned =
        platform_file_clone_fd(input, output);
    ok = cloned != PLATFORM_FILE_CLONE_REFUSED;
    uint64_t remaining = (uint64_t)source_st->st_size;
    while (ok && cloned == PLATFORM_FILE_CLONE_UNAVAILABLE && remaining) {
        unsigned char buf[65536];
        size_t want = remaining < sizeof(buf) ? (size_t)remaining : sizeof(buf);
        ssize_t got = read(input, buf, want);
        ssize_t off = 0;
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            ok = false;
            break;
        }
        remaining -= (uint64_t)got;
        while (ok && off < got) {
            ssize_t wrote = write(output, buf + off, (size_t)(got - off));
            if (wrote < 0 && errno == EINTR)
                continue;
            if (wrote <= 0)
                ok = false;
            else
                off += wrote;
        }
    }
    if (ok)
        ok = fchmod(output, source_st->st_mode & 07777) == 0;
#if !defined(_WIN32)
    /* Landing steps refuse on Windows; POSIX hosts preserve nanoseconds. */
    const struct timespec times[2] = {
#if defined(__APPLE__)
        source_st->st_atimespec, source_st->st_mtimespec,
#else
        source_st->st_atim, source_st->st_mtim,
#endif
    };
    if (ok)
        ok = futimens(output, times) == 0;
    if (ok && explained_alias)
        ok = fsync(output) == 0;
#endif
    if (ok)
        ok = fstat(input, &observed) == 0 &&
             dl_same_file_snapshot(source_st, &observed);
    /* A repair may replace only the exact two names checked by preflight.
     * Recheck after the bounded copy, before publishing a replacement. */
    if (ok && explained_alias)
        ok = lstat(target, &observed) == 0 &&
             dl_same_file_snapshot(source_st, &observed) &&
             lstat(explained_alias, &observed) == 0 &&
             dl_same_file_snapshot(source_st, &observed);
    if (ok)
        ok = fstat(output, &completed) == 0 &&
             S_ISREG(completed.st_mode) && completed.st_nlink == 1 &&
             !dl_same_inode(source_st, &completed) &&
             dl_same_copy_metadata(source_st, &completed) &&
             lstat(tmp, &observed) == 0 &&
             dl_same_file_snapshot(&completed, &observed);
    if (close(input) != 0)
        ok = false;
    if (close(output) != 0)
        ok = false;
    if (ok && rename(tmp, target) != 0)
        ok = false;
    if (ok)
        ok = dl_materialize_published(target, &completed,
                                      explained_alias != NULL);
    if (!ok)
        (void)unlink(tmp);
    return ok;
#endif
}

static bool dl_materialize(const char *source, const char *target)
{
#if defined(_WIN32)
    (void)source; (void)target;
    return false;
#else
    struct stat source_st, target_st;
    DIR *dir;
    struct dirent *entry;
    bool ok;
    if (lstat(source, &source_st) != 0)
        return false;
    if (lstat(target, &target_st) == 0)
        return true; /* the caller already checked readiness */
    if (S_ISREG(source_st.st_mode))
        return dl_materialize_file(source, target, &source_st, NULL);
    if (!S_ISDIR(source_st.st_mode))
        return false; /* fail closed: only plain files and directories */
    dir = opendir(source);
    if (!dir)
        return false;
    if (!dl_mkdir_one(target)) {
        (void)closedir(dir);
        return false;
    }
    ok = true;
    while (ok && (entry = readdir(dir)) != NULL) {
        char child_source[4096 + 96], child_target[4096 + 96];
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (snprintf(child_source, sizeof(child_source), "%s/%s", source,
                     entry->d_name) >= (int)sizeof(child_source) ||
            snprintf(child_target, sizeof(child_target), "%s/%s", target,
                     entry->d_name) >= (int)sizeof(child_target) ||
            !dl_materialize(child_source, child_target))
            ok = false;
    }
    return closedir(dir) == 0 && ok;
#endif
}

/* A local mkdir -p for a dependency's target directory. dev_proof.c has its
 * own private version of this (dependency_parent_ensure); it is not
 * exported, so this is the smallest reimplementation rather than a second
 * layering violation to reach it. */
static bool dl_mkdir_parents(const char *path)
{
    char buf[4096 + 96];
    char *slash;
    if (!path || snprintf(buf, sizeof(buf), "%s", path) >= (int)sizeof(buf))
        return false;
    slash = strrchr(buf, '/');
    if (!slash || slash == buf)
        return true;
    *slash = '\0';
    for (char *p = buf + 1;; p++) {
        if (*p != '/' && *p != '\0')
            continue;
        char saved = *p;
        *p = '\0';
        if (!dl_mkdir_one(buf))
            return false;
        *p = saved;
        if (!saved)
            break;
    }
    return true;
}

/* vendor/lib, vendor/include and the four vendor/tor archives: expensive to
 * build (minutes of `make vendor`) but cheap to copy from an already-primed
 * submitting checkout. This is exactly the set `make worktree-prime`
 * copies (minus its Tor submodule `git` init, which a proof reading these
 * exact paths by `lstat` does not need); rather than shell out to that
 * make target — which would require this worktree, and every hermetic test
 * rig exercising this path, to carry its own Makefile — this uses the
 * dl_materialize() clone-or-copy primitive above, which mirrors the
 * proof's own generation-prep copier without depending on it (see that
 * function's comment for why). Each entry is checked and refused by name,
 * matching dev_proof.c's own vocabulary, so a dependency missing from the
 * submitting checkout too is never silently skipped. */
static const char *const DL_VENDOR_DEPS[] = {
    "vendor/lib",
    "vendor/include",
    "vendor/sqlite3.c",
    "vendor/tor/libtor.a",
    "vendor/tor/.provenance",
    "vendor/tor/Makefile",
    "vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
    "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
    "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
};

/* .git marks a submodule as actually checked out in this worktree; the
 * gitlink entry every `git worktree add` carries is metadata alone and
 * never populates the working tree the way an init/checkout does. */
static bool dl_wt_submodule_ready(const char *wt, const char *subpath)
{
    char marker[4096 + 16];
    struct stat st;
    if (!wt || !subpath ||
        snprintf(marker, sizeof(marker), "%s/%s/.git", wt, subpath) >=
            (int)sizeof(marker))
        return false;
    return stat(marker, &st) == 0;
}

/* `make worktree-prime` (Makefile:2400) initialises this submodule BEFORE
 * copying any vendor/tor archive into a fresh worktree; a bare `git
 * worktree add` never checks a submodule out on its own, so the first time
 * a landing worktree reaches here vendor/tor is a nonempty-once-copied-into,
 * uninitialised directory and tools/dev/source-identity.sh refuses outright
 * ("nonempty uninitialised gitlink would omit bytes: vendor/tor") the very
 * next time this worktree's own build/dev-loop/restart.env is captured.
 * This has to run, and succeed, before any vendor/tor entry below is
 * materialized — mirroring worktree-prime's ordering instead of inventing
 * a second one. It goes through dl_git(), the one git spawn seam this
 * whole file uses: no second way to launch git. */
static bool dl_wt_submodule_ensure(const struct dl_dirs *d,
                                   const char *subpath, char *why,
                                   size_t why_cap)
{
    char buf[DL_GIT_CAP];
    const char *argv[] = { "submodule", "update", "--init", "--", subpath,
                           NULL };
    if (dl_wt_submodule_ready(d->wt, subpath))
        return true;
    if (dl_git(d->wt, argv, buf, sizeof(buf), DL_GIT_TIMEOUT_MS) != 0 ||
        !dl_wt_submodule_ready(d->wt, subpath)) {
        (void)snprintf(why, why_cap,
                       "proof_generation_dependency_unavailable:%s "
                       "(submodule init failed)",
                       subpath);
        return false;
    }
    return true;
}

/* Whether the tip's own tree names vendor/tor as a real submodule (a
 * 160000/commit gitlink entry) rather than a plain directory of tracked
 * files. Every hermetic test rig in this file is a throwaway git repo with
 * no .gitmodules, where vendor/tor is fixture files committed as ordinary
 * blobs — there is no submodule to init or pin there, and treating it as
 * one would refuse those rigs for a condition that does not apply to them.
 * Only a real gitlink entry triggers the init-then-pin-check sequence
 * below; anything else (a normal tree, or the path missing outright) is
 * left to the existing lstat-and-copy path unchanged. */
static bool dl_wt_vendor_tor_is_submodule(const struct dl_dirs *d,
                                          const struct dl_row *r)
{
    char out[512];
    const char *args[] = { "ls-tree", r->tip, "--", "vendor/tor", NULL };
    if (dl_git(d->wt, args, out, sizeof(out), DL_GIT_TIMEOUT_MS) != 0)
        return false;
    return strncmp(out, "160000 commit ", 14) == 0;
}

/* The vendor/tor archives dl_materialize() is about to reuse were built by
 * the SUBMITTING checkout, against whatever commit that checkout's own
 * vendor/tor working tree happened to be at — not necessarily the commit
 * the tip being proven actually pins. Nothing before this compared the
 * two, so a submitting checkout sitting on a stale or ahead vendor/tor
 * would hand the proof a libtor.a built from source that does not match
 * what the tip's gitlink names, and the proof would never know. This
 * checks the landing worktree's own pinned gitlink for the tip
 * (`<tip>:vendor/tor`, resolved through the worktree's shared object
 * database regardless of which worktree the blob table lives under)
 * against the submitting checkout's checked-out submodule HEAD, and
 * refuses by name on any mismatch or unresolved side rather than reusing
 * an archive that was never proven to belong to this tip. */
static bool dl_wt_vendor_tor_pin_matches(const struct dl_dirs *d,
                                         const struct dl_row *r, char *why,
                                         size_t why_cap)
{
    char spec[128], tip_pin[80], src_pin[80], src_dir[4096 + 96];
    const char *tip_args[] = { "rev-parse", "--verify", "--quiet", spec,
                               NULL };
    const char *src_args[] = { "rev-parse", "--verify", "--quiet", "HEAD",
                               NULL };
    if (snprintf(spec, sizeof(spec), "%s:vendor/tor", r->tip) >=
        (int)sizeof(spec)) {
        (void)snprintf(why, why_cap, "%s",
                       "proof_generation_dependency_unavailable:vendor/tor "
                       "(tip commit too long)");
        return false;
    }
    if (dl_git(d->wt, tip_args, tip_pin, sizeof(tip_pin),
              DL_GIT_TIMEOUT_MS) != 0) {
        (void)snprintf(why, why_cap, "%s",
                       "proof_generation_dependency_unavailable:vendor/tor "
                       "(tip carries no vendor/tor gitlink)");
        return false;
    }
    dl_trim(tip_pin);
    if (!dl_sha_ok(tip_pin)) {
        (void)snprintf(why, why_cap, "%s",
                       "proof_generation_dependency_unavailable:vendor/tor "
                       "(tip carries no vendor/tor gitlink)");
        return false;
    }
    /* FAST ACCEPT, before the submitting checkout is consulted at all.
     * dl_wt_vendor_ensure() has already run dl_wt_submodule_ensure() on
     * THIS worktree, so d->wt's own vendor/tor is initialised or the
     * caller already refused; and the archive it materialized survives in
     * the landing worktree across trains. When that worktree is already
     * standing on the very commit the tip pins AND still holds the
     * archive built for it, the submitting checkout has nothing left to
     * prove — re-deriving the pin from a fresh checkout every train is
     * what makes an uninitialised submodule over there refuse a tip that
     * is fine. Accept-or-fall-through only: nothing here ever refuses. */
    if (dl_wt_submodule_ready(d->wt, "vendor/tor")) {
        char wt_dir[4096 + 96], wt_pin[80], archive[4096 + 96];
        struct platform_file_metadata metadata;
        if (snprintf(wt_dir, sizeof(wt_dir), "%s/vendor/tor", d->wt) <
                (int)sizeof(wt_dir) &&
            snprintf(archive, sizeof(archive), "%s/vendor/tor/libtor.a",
                     d->wt) < (int)sizeof(archive) &&
            dl_git(wt_dir, src_args, wt_pin, sizeof(wt_pin),
                   DL_GIT_TIMEOUT_MS) == 0) {
            dl_trim(wt_pin);
            if (dl_sha_ok(wt_pin) && strcmp(wt_pin, tip_pin) == 0 &&
                platform_file_metadata_read(archive, &metadata) ==
                    PLATFORM_FILE_METADATA_OK)
                return true;
        }
    }
    if (!dl_worktree_present(r->worktree) ||
        snprintf(src_dir, sizeof(src_dir), "%s/vendor/tor", r->worktree) >=
            (int)sizeof(src_dir)) {
        (void)snprintf(why, why_cap, "%s",
                       "proof_generation_dependency_unavailable:"
                       "vendor/tor/libtor.a (no source checkout)");
        return false;
    }
    /* An UNINITIALISED vendor/tor over there is not a mismatch, and must
     * not be reported as one. `git -C <checkout>/vendor/tor rev-parse
     * HEAD` on a bare gitlink directory walks up to the ENCLOSING
     * superproject's .git and answers with the superproject's own HEAD —
     * a commit that is not a submodule commit at all — so the comparison
     * below would refuse naming a sha that means nothing. Name the real
     * condition, and the one command that fixes it, instead. */
    if (!dl_wt_submodule_ready(r->worktree, "vendor/tor")) {
        (void)snprintf(why, why_cap,
                       "proof_generation_dependency_unavailable:vendor/tor "
                       "(submodule uninitialised in %s; run git submodule "
                       "update --init vendor/tor)",
                       r->worktree);
        return false;
    }
    if (dl_git(src_dir, src_args, src_pin, sizeof(src_pin),
              DL_GIT_TIMEOUT_MS) != 0) {
        (void)snprintf(why, why_cap, "%s",
                       "proof_generation_dependency_unavailable:"
                       "vendor/tor/libtor.a (submitting checkout's "
                       "vendor/tor is not checked out)");
        return false;
    }
    dl_trim(src_pin);
    if (!dl_sha_ok(src_pin)) {
        (void)snprintf(why, why_cap, "%s",
                       "proof_generation_dependency_unavailable:"
                       "vendor/tor/libtor.a (submitting checkout's "
                       "vendor/tor is not checked out)");
        return false;
    }
    if (strcmp(tip_pin, src_pin) != 0) {
        (void)snprintf(why, why_cap,
                       "proof_generation_dependency_unavailable:"
                       "vendor/tor/libtor.a (submodule commit %s != tip "
                       "%s)",
                       src_pin, tip_pin);
        return false;
    }
    return true;
}

static bool dl_wt_vendor_ensure(const struct dl_dirs *d,
                                const struct dl_row *r, char *why,
                                size_t why_cap)
{
#if defined(_WIN32)
    /* dev land step already refuses with STEP_WINDOWS_UNAVAILABLE before
     * any caller reaches here (see dl_step below); mirror that refusal
     * instead of building a portable lstat/hardlink dependency check for
     * a path Windows never runs. */
    (void)d; (void)r;
    (void)snprintf(why, why_cap,
                   "proof_generation_dependency_check_unavailable:windows");
    return false;
#else
    bool tor_pin_checked = false;
    for (size_t i = 0;
        i < sizeof(DL_VENDOR_DEPS) / sizeof(DL_VENDOR_DEPS[0]); i++) {
        char source[4096 + 96], target[4096 + 96];
        struct stat st;
        if (snprintf(target, sizeof(target), "%s/%s", d->wt,
                     DL_VENDOR_DEPS[i]) >= (int)sizeof(target) ||
            snprintf(source, sizeof(source), "%s/%s", r->worktree,
                     DL_VENDOR_DEPS[i]) >= (int)sizeof(source)) {
            (void)snprintf(why, why_cap,
                           "proof_generation_dependency_path_too_long:%s",
                           DL_VENDOR_DEPS[i]);
            return false;
        }
        if (strncmp(DL_VENDOR_DEPS[i], "vendor/tor/", 11) == 0 &&
            dl_wt_vendor_tor_is_submodule(d, r)) {
            if (!dl_wt_submodule_ensure(d, "vendor/tor", why, why_cap))
                return false;
            if (!tor_pin_checked) {
                if (!dl_wt_vendor_tor_pin_matches(d, r, why, why_cap))
                    return false;
                tor_pin_checked = true;
            }
        }
        if (lstat(target, &st) == 0)
            continue; /* already materialized in this worktree */
        if (!r->worktree[0] || !dl_worktree_ok(r->worktree) || lstat(source, &st) != 0) {
            (void)snprintf(why, why_cap,
                           "proof_generation_dependency_unavailable:%s "
                           "(make vendor)",
                           DL_VENDOR_DEPS[i]);
            return false;
        }
        if (!dl_mkdir_parents(target) ||
            !dl_materialize(source, target)) {
            (void)snprintf(why, why_cap,
                           "proof_generation_dependency_copy_failed:%s",
                           DL_VENDOR_DEPS[i]);
            return false;
        }
    }
    return true;
#endif
}

#if !defined(_WIN32)
/* The rollback test group dlopens these two fixture images by name on
 * Linux; the proof's own dependency check names `make test_parallel` as
 * their fix and lists them only on Linux. Copying is still a POSIX file
 * materialize, and Darwin tests force it via ZCL_LAND_DEPS_TEST_FORCE so
 * a planted fixture is not left behind. Production Darwin land still
 * skips the call (see dl_wt_proof_deps_ensure). */
static const char *const DL_HOTSWAP_DEPS[] = {
    "build/hotswap/zcl_rollback_fixture_a.so",
    "build/hotswap/zcl_rollback_fixture_b.so",
};

static bool dl_wt_hotswap_ensure(const struct dl_dirs *d,
                                 const struct dl_row *r, char *why,
                                 size_t why_cap)
{
    for (size_t i = 0;
        i < sizeof(DL_HOTSWAP_DEPS) / sizeof(DL_HOTSWAP_DEPS[0]); i++) {
        char source[4096 + 96], target[4096 + 96];
        struct stat st;
        if (snprintf(target, sizeof(target), "%s/%s", d->wt,
                     DL_HOTSWAP_DEPS[i]) >= (int)sizeof(target) ||
            snprintf(source, sizeof(source), "%s/%s", r->worktree,
                     DL_HOTSWAP_DEPS[i]) >= (int)sizeof(source)) {
            (void)snprintf(why, why_cap,
                           "proof_generation_dependency_path_too_long:%s",
                           DL_HOTSWAP_DEPS[i]);
            return false;
        }
        if (stat(target, &st) == 0)
            continue;
        if (!r->worktree[0] || !dl_worktree_ok(r->worktree) || stat(source, &st) != 0) {
            (void)snprintf(why, why_cap,
                           "proof_generation_dependency_unavailable:%s "
                           "(make test_parallel)",
                           DL_HOTSWAP_DEPS[i]);
            return false;
        }
        if (!dl_mkdir_parents(target) ||
            !dl_materialize(source, target)) {
            (void)snprintf(why, why_cap,
                           "proof_generation_dependency_copy_failed:%s",
                           DL_HOTSWAP_DEPS[i]);
            return false;
        }
    }
    return true;
}
#endif

/* Test-only escape hatch: exercises the copy-based priming above (vendor
 * archives, hotswap fixtures) against a fixture checkout even though
 * ZCL_LAND_PROOF_STUB also skips lint and the proof itself in the same
 * step. Never read outside a test process, the same guard and reasoning as
 * dl_hooks_stub_dir() above. build/dev-loop/restart.env is not covered:
 * building it needs a real Makefile, which the throwaway git rigs this
 * unlocks for have none of. */
static bool dl_deps_test_force(void)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    const char *s = getenv("ZCL_LAND_DEPS_TEST_FORCE");
    return s && s[0];
#else
    return false;
#endif
}

/* Bound on how many extra names one dependency's inode may carry into the
 * leaf's own generation pools before this refuses instead of repairing. A
 * legitimate proof pool holds a handful of generations at once; anything
 * past this is either a runaway pool (item C's sweep failed to run) or not
 * this code's link to explain. */
#define DL_DEPENDENCY_POOL_PARTNER_MAX 15

struct dl_dependency_repair {
    const struct dl_dirs *dirs;
    const struct dl_row *row;
    char *why;
    size_t why_cap;
    size_t repaired;
    bool apply;
    bool require_single;
    /* The leaf's own generation roots (dev_proof.c's `.z23p` disk pool
     * beside the landing worktree, and the RAM root's `z23p` pool when this
     * host offers one). A link into either is this code's own doing, not a
     * foreign alias, so it is explained and repaired rather than refused. */
    char disk_gen_parent[4096];
    char ram_gen_parent[4096];
    bool has_ram_gen_parent;
};

static void dl_generation_roots_compute(const struct dl_dirs *d,
                                        struct dl_dependency_repair *repair)
{
    (void)snprintf(repair->disk_gen_parent, sizeof(repair->disk_gen_parent),
                   "%s/.z23p", d->land);
    char ram_root[PATH_MAX];
    repair->has_ram_gen_parent = false;
    if (platform_ram_scratch_root(ram_root, sizeof(ram_root), 0) &&
        snprintf(repair->ram_gen_parent, sizeof(repair->ram_gen_parent),
                 "%s/z23p", ram_root) < (int)sizeof(repair->ram_gen_parent))
        repair->has_ram_gen_parent = true;
}

#if !defined(_WIN32)
/* The 32-character lowercase hex tag dev_proof.c's generation_prepare()
 * derives -- the only shape of entry either generation pool ever holds. */
static bool dl_generation_tag_name(const char *name)
{
    size_t len = name ? strlen(name) : 0;
    if (len != 32) return false;
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

/* Look for other names of the same inode as `before` under every generation
 * directory inside `pool_parent`. Each match is a proof generation's own
 * private materialised copy sharing an inode with the worktree file because
 * an older binary linked it instead of copying -- exactly the legacy state
 * item A's fix leaves behind. Every match found is appended to `partners`
 * (bounded by DL_DEPENDENCY_POOL_PARTNER_MAX); returns false only when that
 * bound overflows, never for an absent or otherwise-unreadable pool root. */
static bool dl_generation_pool_scan(
    const char *pool_parent, const char *relative, const struct stat *before,
    const char *target_real, char partners[][4096 + 96],
    size_t *partner_count)
{
    if (!pool_parent || !pool_parent[0]) return true;
    DIR *dir = opendir(pool_parent);
    if (!dir) return true;
    struct dirent *entry;
    bool ok = true;
    while (ok && (entry = readdir(dir)) != NULL) {
        if (!dl_generation_tag_name(entry->d_name)) continue;
        char candidate[4096 + 96], candidate_real[PATH_MAX];
        struct stat candidate_st;
        if (snprintf(candidate, sizeof(candidate), "%s/%s/%s", pool_parent,
                     entry->d_name, relative) >= (int)sizeof(candidate))
            continue;
        if (!realpath(candidate, candidate_real) ||
            strcmp(candidate_real, target_real) == 0)
            continue;
        if (lstat(candidate, &candidate_st) != 0 ||
            !S_ISREG(candidate_st.st_mode) ||
            !dl_same_inode(before, &candidate_st))
            continue;
        if (*partner_count >= DL_DEPENDENCY_POOL_PARTNER_MAX) {
            ok = false;
            break;
        }
        (void)snprintf(partners[*partner_count], sizeof(partners[0]), "%s",
                       candidate);
        (*partner_count)++;
    }
    (void)closedir(dir);
    return ok;
}
#endif

/* A link count is explainable only when every extra name is either the
 * submitting train's own checkout (the donor case dev land priming used
 * before this repair existed) or one of the leaf's own generation pools
 * (the case item A's fix could still leave behind from an older binary, or
 * from a race with a proof generation still materialising this same file).
 * Any name outside those roots is not this code's link, so it still
 * refuses -- fail closed, same reason string as before. */
static bool dl_dependency_repair_one(const char *relative, uint64_t links,
                                     void *opaque)
{
    struct dl_dependency_repair *repair = opaque;
    if (repair->require_single) {
        (void)snprintf(repair->why, repair->why_cap,
                       "proof_generation_dependency_links_changed:%s",
                       relative);
        return false;
    }
#if !defined(_WIN32)
    char target[4096 + 96], donor[4096 + 96];
    char target_real[PATH_MAX], donor_real[PATH_MAX];
    struct stat before, donor_st, after;
    bool have_train_donor = false;
    if (links < 2 ||
        snprintf(target, sizeof(target), "%s/%s", repair->dirs->wt,
                 relative) >= (int)sizeof(target) ||
        !dl_worktree_file(repair->row->worktree, relative, donor, sizeof(donor)) ||
        !realpath(target, target_real) ||
        lstat(target, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_nlink != links) {
        (void)snprintf(repair->why, repair->why_cap,
                       "proof_generation_dependency_unexplained_links:%s",
                       relative);
        return false;
    }
    if (realpath(donor, donor_real) &&
        strcmp(target_real, donor_real) != 0 &&
        lstat(donor, &donor_st) == 0 &&
        dl_same_file_snapshot(&before, &donor_st))
        have_train_donor = true;

    char partners[DL_DEPENDENCY_POOL_PARTNER_MAX][4096 + 96];
    size_t partner_count = 0;
    bool scan_ok =
        dl_generation_pool_scan(repair->disk_gen_parent, relative, &before,
                                target_real, partners, &partner_count) &&
        (!repair->has_ram_gen_parent ||
         dl_generation_pool_scan(repair->ram_gen_parent, relative, &before,
                                 target_real, partners, &partner_count));

    size_t accounted = (have_train_donor ? (size_t)1 : (size_t)0) +
                       partner_count;
    if (!scan_ok || accounted + 1 != links) {
        (void)snprintf(repair->why, repair->why_cap,
                       "proof_generation_dependency_unexplained_links:%s",
                       relative);
        return false;
    }
    if (!repair->apply)
        return true;
    const char *alias =
        have_train_donor ? donor : (partner_count > 0 ? partners[0] : NULL);
    if (!alias ||
        !dl_materialize_file(target, target, &before, alias) ||
        lstat(target, &after) != 0 || !S_ISREG(after.st_mode) ||
        after.st_nlink != 1 || dl_same_inode(&before, &after) ||
        !dl_same_copy_metadata(&before, &after)) {
        (void)snprintf(repair->why, repair->why_cap,
                       "proof_generation_dependency_repair_failed:%s",
                       relative);
        return false;
    }
    /* Every name that explained this link must still be exactly the
     * pre-repair inode, now missing only the name just replaced. */
    uint64_t expected_remaining = links - 1;
    if (have_train_donor) {
        struct stat recheck;
        if (lstat(donor, &recheck) != 0 ||
            (uint64_t)recheck.st_nlink != expected_remaining ||
            !dl_same_inode(&before, &recheck)) {
            (void)snprintf(repair->why, repair->why_cap,
                           "proof_generation_dependency_repair_failed:%s",
                           relative);
            return false;
        }
    }
    for (size_t i = 0; i < partner_count; i++) {
        struct stat recheck;
        if (lstat(partners[i], &recheck) != 0 ||
            (uint64_t)recheck.st_nlink != expected_remaining ||
            !dl_same_inode(&before, &recheck)) {
            (void)snprintf(repair->why, repair->why_cap,
                           "proof_generation_dependency_repair_failed:%s",
                           relative);
            return false;
        }
    }
    repair->repaired++;
    return true;
#else
    (void)links;
    (void)snprintf(repair->why, repair->why_cap,
                   "proof_generation_dependency_repair_unavailable:%s",
                   relative);
    return false;
#endif
}

static bool dl_wt_dependency_links_repair(const struct dl_dirs *d,
                                          const struct dl_row *r,
                                          bool stubbed, char *why,
                                          size_t why_cap)
{
    struct dl_dependency_repair repair = {
        .dirs = d, .row = r, .why = why, .why_cap = why_cap,
    };
    dl_generation_roots_compute(d, &repair);
    struct zcl_dependency_link_stats stats;
    char scan_why[4096];
    why[0] = '\0';
    /* Preflight the complete bounded set before changing any name. */
    if (!zcl_dependency_links_scan(d->wt, dl_dependency_repair_one, &repair,
                                   &stats, scan_why, sizeof(scan_why)))
        goto scan_failed;
    if (!stats.linked)
        return true;
#if !defined(ZCL_DEV_PROOF_MATERIALIZER_CLONES) || \
    ZCL_DEV_PROOF_MATERIALIZER_CLONES != 1
    if (!stubbed) {
        (void)snprintf(why, why_cap, "%s",
                       "proof_generation_dependency_materializer_unqualified");
        return false;
    }
#else
    (void)stubbed;
#endif
    repair.apply = true;
    if (!zcl_dependency_links_scan(d->wt, dl_dependency_repair_one, &repair,
                                   &stats, scan_why, sizeof(scan_why)))
        goto scan_failed;
    /* Any new unexplained link observed after repair still prevents proof
     * admission. These pathname checks are not a cross-process lock. */
    repair.require_single = true;
    if (!zcl_dependency_links_scan(d->wt, dl_dependency_repair_one, &repair,
                                   &stats, scan_why, sizeof(scan_why)))
        goto scan_failed;
    char note[160];
    (void)snprintf(note, sizeof(note),
                   "dependency_repair: files=%zu links=2->1 remaining_linked=0\n",
                   repair.repaired);
    dl_log(r, note);
    return true;

scan_failed:
    if (!why[0])
        (void)snprintf(why, why_cap,
                       "proof_generation_dependency_scan_failed:%.4000s",
                       scan_why);
    return false;
}

/* The copy-based dependencies (vendor archives, hotswap fixtures) run
 * whenever a real proof is about to be requested, or when a test forces
 * them on despite the proof stub. The restart plan always needs a real
 * `make` invocation against a real Makefile, so it stays gated on the
 * proof stub alone: no hermetic test rig here carries one. Any failure
 * refuses with the failing dependency's own typed reason; none of them
 * silently continues past a missing one. */

/* Keep the landing worktree's installed native hooks byte-identical to the
 * binary its own lint prerequisites just rebuilt. The proof generation
 * copies build/githooks into its private generation, and
 * check-git-hooks-installed compares that copy against the generation's
 * freshly built binary: a stale installed copy fails a whole proof cycle
 * at the lint dimension even though nothing in the candidate is wrong —
 * observed 2026-09-10, when a landing worktree created 2026-09-08 held a
 * hook binary two days older than the one its own `make lint-land` just
 * linked. This is the same repair `make install-hooks` performs, scoped
 * to the one file that can drift between a worktree's creation and its
 * nth rebase, plus the four symlinks that name it. */
/* The four installed hook names are symlinks to the one native binary;
 * recreate any that went missing rather than failing a whole proof over a
 * name. */
static bool dl_wt_hook_links_ensure(const struct dl_dirs *d, char *why,
                                     size_t why_cap, bool *repaired)
{
    static const char *const k_links[] = {
        "pre-push", "post-commit", "post-merge", "post-checkout"
    };
    char link[4096 + 96];
    for (size_t i = 0; i < sizeof(k_links) / sizeof(k_links[0]); i++) {
        struct stat st;
        if (snprintf(link, sizeof(link), "%s/build/githooks/%s", d->wt,
                     k_links[i]) >= (int)sizeof(link)) {
            (void)snprintf(why, why_cap,
                           "landing_worktree_hooks_path_too_long:%s",
                           k_links[i]);
            return false;
        }
#if defined(_WIN32)
        if (stat(link, &st) == 0)
            continue;
        (void)snprintf(why, why_cap,
                       "landing_worktree_hook_links_posix_only:%s",
                       k_links[i]);
        return false;
#else
        if (lstat(link, &st) == 0)
            continue;
        if (symlink("z23-git-hook", link) != 0) {
            (void)snprintf(why, why_cap,
                           "landing_worktree_hook_link_failed:%s", k_links[i]);
            return false;
        }
        *repaired = true;
#endif
    }
    return true;
}

/* True when the installed hook copy already matches `bin` byte for byte;
 * a missing, non-regular, or drifted copy is repair work, not a failure. */
static bool dl_wt_hooks_installed_matches(const char *bin,
                                           const char *installed)
{
    struct stat installed_st;
    return stat(installed, &installed_st) == 0 &&
           S_ISREG(installed_st.st_mode) &&
           dl_bytes_identical(bin, installed);
}

static bool dl_wt_hooks_refresh(const struct dl_dirs *d,
                                const struct dl_row *row,
                                char *why, size_t why_cap)
{
#if defined(_WIN32)
    (void)d; (void)row;
    (void)snprintf(why, why_cap, "%s",
                   "STEP_WINDOWS_UNAVAILABLE: POSIX landing hooks");
    return false;
#else
    char bin[4096 + 96], submitter[4096 + 96], installed[4096 + 96];
    struct stat bin_st;
    bool repaired = false;
    if (snprintf(bin, sizeof(bin), "%s/build/bin/z23-git-hook", d->wt) >=
            (int)sizeof(bin) ||
        snprintf(installed, sizeof(installed),
                 "%s/build/githooks/z23-git-hook", d->wt) >=
            (int)sizeof(installed)) {
        (void)snprintf(why, why_cap, "%s",
                       "landing_worktree_hooks_path_too_long");
        return false;
    }
    if (stat(bin, &bin_st) != 0 || !S_ISREG(bin_st.st_mode)) {
        /* The lint pass normally links the binary itself. When it did not
         * (a stubbed step, or a worktree whose build was cleaned), the
         * submitting checkout's own build of the same source is the same
         * deterministic bytes the proof generation will build, so it is
         * an honest source for the installed copy — never a silent pass:
         * if neither tree holds a binary, the named refusal below stands. */
        if (!row->worktree[0] || !dl_worktree_ok(row->worktree) ||
            snprintf(submitter, sizeof(submitter),
                     "%s/build/bin/z23-git-hook", row->worktree) >=
                (int)sizeof(submitter) ||
            stat(submitter, &bin_st) != 0 || !S_ISREG(bin_st.st_mode)) {
            (void)snprintf(why, why_cap, "%s",
                           "landing_worktree_hook_binary_missing "
                           "(lint-fast prerequisites should have built it)");
            return false;
        }
        (void)snprintf(bin, sizeof(bin), "%s", submitter);
    }
    if (!dl_wt_hooks_installed_matches(bin, installed)) {
        if (!dl_mkdir_parents(installed) ||
            !dl_materialize_file(bin, installed, &bin_st, NULL)) {
            (void)snprintf(why, why_cap,
                           "landing_worktree_hook_refresh_failed:%.80s",
                           installed);
            return false;
        }
        repaired = true;
    }
    if (!dl_wt_hook_links_ensure(d, why, why_cap, &repaired))
        return false;
    if (repaired) {
        char note[96];
        (void)snprintf(note, sizeof(note),
                       "hooks: refreshed the installed native hooks from "
                       "the rebuilt binary\n");
        dl_log(row, note);
    }
    return true;
#endif
}

static bool dl_wt_proof_deps_ensure(const struct dl_dirs *d,
                                    const struct dl_row *r, bool stubbed,
                                    char *why, size_t why_cap)
{
#if defined(_WIN32)
    (void)d;
    (void)r;
    (void)stubbed;
    (void)snprintf(why, why_cap, "%s",
                   "STEP_WINDOWS_UNAVAILABLE: POSIX landing dependencies");
    return false;
#else
    if (!stubbed || dl_deps_test_force()) {
        /* The installed native hooks must match the binary the lint pass
         * just rebuilt, or the proof's own generation fails its hook gate
         * on a drift this worktree acquired by aging. First prerequisite,
         * so a hooks miss refuses before any vendor copy runs. */
        if (!dl_wt_hooks_refresh(d, r, why, why_cap))
            return false;
        if (!dl_wt_vendor_ensure(d, r, why, why_cap))
            return false;
#if defined(__linux__)
        if (!dl_wt_hotswap_ensure(d, r, why, why_cap))
            return false;
#elif !defined(_WIN32)
        /* Production Darwin proofs do not require the Linux-only rollback
         * fixtures. Tests that plant them still force the copy. */
        if (dl_deps_test_force() &&
            !dl_wt_hotswap_ensure(d, r, why, why_cap))
            return false;
#endif
        if (!dl_wt_dependency_links_repair(d, r, stubbed, why, why_cap))
            return false;
    }
    if (!stubbed && !zcl_dev_land_proof_tools_prepare(d->wt, why, why_cap))
        return false;
    if (!stubbed && !zcl_dev_land_restart_plan_prepare(d->wt, why, why_cap))
        return false;
    return true;
#endif
}

/* Observe the remote before deciding whether a request landed or needs
 * rebase/proof. An unavailable observation preserves the existing request
 * and proof for retry; it is neither a negative result nor a cached pass. */
static bool dl_fetch_remote_main(const char *wt, char observed_main[80])
{
    char buf[DL_GIT_CAP];
    const char *fetch_args[] = {
        "fetch", "--quiet", "--no-tags", "--refmap=", "origin",
        "+refs/heads/main:refs/remotes/origin/main", NULL
    };
    observed_main[0] = '\0';
    /* Request main explicitly: configured fetch mappings may omit it.
     * Refresh only the local tracking cache even after a remote rewind;
     * publication still requires ancestry against this actual observation.
     * Capture the exact fetched commit before any candidate-object fetch
     * can replace FETCH_HEAD. No cached tracking ref is a fallback. */
    if (dl_git(wt, fetch_args, buf, sizeof(buf), DL_GIT_TIMEOUT_MS) == 0 &&
        dl_rev_parse(wt, "FETCH_HEAD", observed_main) &&
        dl_sha_ok(observed_main))
        return true;
    observed_main[0] = '\0';
    return false;
}

static bool dl_observe_remote_main(const struct dl_dirs *d,
                                   const struct dl_row *row,
                                   char observed_main[80], bool mutated,
                                   struct zcl_command_reply *reply)
{
    if (dl_fetch_remote_main(d->wt, observed_main))
        return true;
    dl_log(row, "remote observation unavailable: cannot fetch and resolve "
                "origin refs/heads/main; retaining request for retry\n");
    (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED,
                           "REMOTE_OBSERVATION_UNAVAILABLE", "observe_remote",
                           true, mutated,
                           "cannot freshly observe origin main; retry this step",
                           "origin refs/heads/main fetch or commit resolution failed");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", "z23-dev dev land step");
    return false;
}

/* A push can succeed before its landed outcome is persisted. Reconcile
 * that row against the freshly observed commit without another proof/push. */
static bool dl_already_landed(const struct dl_dirs *d, struct dl_row *row,
                              const char *observed_main)
{
    char buf[DL_GIT_CAP], commit[80];
    const char *ancestor_args[] = { "--no-replace-objects", "merge-base",
                                    "--is-ancestor", commit, observed_main, NULL };
    if (row->local[0] && dl_sha_ok(row->local)) {
        (void)snprintf(commit, sizeof(commit), "%s", row->local);
    } else if (!dl_rev_parse(d->wt, row->tip, commit)) {
        if (!row->worktree[0] || !dl_worktree_ok(row->worktree))
            return false;
        {
            /* Same "--" before the row-supplied path as dl_rebase(): see
             * that call site's comment. */
            const char *pull_args[] = { "fetch", "--quiet", "--no-tags",
                                        "--", row->worktree, row->tip,
                                        NULL };
            (void)dl_git(d->wt, pull_args, buf, sizeof(buf),
                         DL_GIT_TIMEOUT_MS);
        }
        if (!dl_rev_parse(d->wt, row->tip, commit))
            return false;
    }
    if (dl_git(d->wt, ancestor_args, buf, sizeof(buf), DL_GIT_TIMEOUT_MS) !=
        0)
        return false;
    (void)snprintf(row->local, sizeof(row->local), "%s", commit);
    (void)snprintf(row->pushed, sizeof(row->pushed), "%s", commit);
    (void)snprintf(row->state, sizeof(row->state), "landed");
    row->phase[0] = '\0';
    (void)snprintf(row->detail, sizeof(row->detail), "%s",
                   "already an ancestor of origin/main; recorded as landed "
                   "without re-proving");
    return true;
}

/* Run the unconditional post-rebase regen phase (native_dev_land_regen.c)
 * and fold its outcome into `row`. Returns true when step should continue
 * to prebuild; false when this already recorded and replied a terminal
 * "failed" outcome, mirroring every other phase's failure arm in
 * dl_step_start() below. */
static bool dl_step_regen(const struct dl_dirs *d, struct dl_row *row,
                          struct zcl_command_reply *reply)
{
    char regen_head[80] = { 0 }, regen_why[512] = { 0 };
    char *log;
    int rc;
    (void)snprintf(row->phase, sizeof(row->phase), "regen");
    log = (char *)zcl_malloc(DL_LOG_CAP, "dev.land.regen.log");
    rc = log ? zcl_dev_land_regen_phase(d->wt, row->base, row->tip,
                                        regen_head, sizeof(regen_head), log,
                                        DL_LOG_CAP, regen_why,
                                        sizeof(regen_why))
             : -1;
    /* A success that cannot name HEAD would leave row->local on the
     * pre-amend id, and the proof would then prove a tree nobody pushes. */
    if (rc >= 0 && !dl_sha_ok(regen_head)) {
        rc = -1;
        (void)snprintf(regen_why, sizeof(regen_why), "%s",
                       "regen could not name the tip it left behind");
    }
    if (log) {
        dl_log(row, log);
        free(log);
    } else if (!regen_why[0]) {
        (void)snprintf(regen_why, sizeof(regen_why), "%s",
                      "out of memory preparing the regen transcript");
    }
    if (rc < 0) {
        (void)snprintf(row->state, sizeof(row->state), "failed");
        (void)snprintf(row->dimension, sizeof(row->dimension), "regen");
        (void)snprintf(row->detail, sizeof(row->detail), "%s", regen_why);
        dl_log(row, regen_why);
        dl_log(row, "\n");
        if (dl_commit_or_report(d, row, true, reply, "failed"))
            dl_step_reply(reply, row, "failed");
        return false;
    }
    /* The amended tip replaces the rebased one everywhere downstream: proof
     * intent (local@base and tree), publication intent, receipts and the
     * push all read row->local, and none of them has run yet. */
    (void)snprintf(row->local, sizeof(row->local), "%s", regen_head);
    return true;
}

/* After a successful rebase, log any regeneration note next to the attempt
 * log and run the unconditional post-rebase regen phase. Returns true when
 * dl_step_start() should continue on to prebuild; false when the regen phase
 * itself already recorded and replied a terminal "failed" outcome. */
static bool dl_step_after_rebase(const struct dl_dirs *d, struct dl_row *row,
                                 struct zcl_command_reply *reply,
                                 const char *regen_note)
{
    /* The rebase settled a conflict on the generated artifacts by
     * regenerating them, which amended content into the tip that the
     * submitter never wrote. Say so -- in the row and in the attempt log -- rather
     * than presenting a rewritten tree as an ordinary rebase. */
    if (regen_note[0]) {
        (void)snprintf(row->detail, sizeof(row->detail), "%s", regen_note);
        dl_log(row, regen_note);
        dl_log(row, "\n");
    }
    return dl_step_regen(d, row, reply);
}

/* A missing observation and a reconciled landing both finish this step.
 * Only a fresh remote that does not contain the candidate permits proof. */
static bool dl_publication_verify(const struct dl_dirs *d,
                                   const struct dl_row *row);
static bool dl_publication_remote_observe(const struct dl_dirs *d,
                                           const struct dl_row *row,
                                           char tip[65], char source[65]);
static bool dl_publication_receipt_seal(struct dl_row *row);
static bool dl_publication_receipt_verify(const struct dl_row *row);

static bool dl_reconcile_signed_landing(const struct dl_dirs *d,
                                        struct dl_row *row,
                                        const char *observed_main,
                                        struct zcl_command_reply *reply)
{
        char output[512];
        const char *ancestor[] = { "--no-replace-objects", "merge-base",
            "--is-ancestor", row->local, observed_main, NULL };
        if (dl_git(d->wt, ancestor, output, sizeof(output),
                   DL_GIT_TIMEOUT_MS) != 0)
            return false;
        if (!dl_publication_verify(d, row)) {
            dl_fail(reply, "PUBLICATION_INTENT_INVALID", "observe_remote",
                    "stored Git landing intent no longer verifies", d->land);
            return true;
        }
        if (!row->remote_signature[0]) {
            if (!dl_publication_remote_observe(d, row, row->remote_tip,
                                                row->remote_source) ||
                !dl_publication_receipt_seal(row) ||
                !dl_commit_row(d, row, false)) {
                dl_fail(reply, "REMOTE_RECEIPT_UNAVAILABLE", "observe_remote",
                        "independent fetch or signed receipt persistence failed",
                        d->land);
                return true;
            }
        }
        if (!dl_publication_receipt_verify(row)) {
            dl_fail(reply, "REMOTE_RECEIPT_INVALID", "observe_remote",
                    "persisted independent remote receipt is invalid",
                    d->land);
            return true;
        }
        (void)snprintf(row->pushed, sizeof(row->pushed), "%s", row->local);
        (void)snprintf(row->state, sizeof(row->state), "landed");
        row->phase[0] = '\0';
        (void)snprintf(row->detail, sizeof(row->detail), "%s",
                       "independent fetch, source and ancestry receipt verified");
        if (dl_commit_or_report(d, row, true, reply, "landed"))
            dl_step_reply(reply, row, "landed");
        return true;
}

static bool dl_reconcile_landing(const struct dl_dirs *d, struct dl_row *row,
                                  char observed_main[80], bool mutated,
                                  struct zcl_command_reply *reply)
{
    if (!dl_observe_remote_main(d, row, observed_main, mutated, reply))
        return true;
    if (row->publication_signature[0])
        return dl_reconcile_signed_landing(d, row, observed_main, reply);
    const char *allow_unsigned = dl_allow_unsigned();
    if (!(allow_unsigned && strcmp(allow_unsigned, "1") == 0 && dl_stub()))
        return false;
    if (!dl_already_landed(d, row, observed_main))
        return false;
    if (dl_commit_or_report(d, row, true, reply, "landed"))
        dl_step_reply(reply, row, "landed");
    return true;
}

/* Seal the prepared tree and exact proof pair in the row before asking a
 * worker to prove it. A replacement driver can recover the same request
 * after the initiating process dies. */
/* ── LAND-WINDOW: the two-lander proving window ────────────────────────────
 * Before a fresh row is prepared, a foreign host's open window on the base
 * this row would prove on defers the step (STEP_DEFERRED, retryable). A
 * started proof announces this host's window with an estimate measured from
 * the landing worktree's proof attempts; a proof still pending past it is
 * re-announced; every other settled step closes it, LANDED when the row
 * landed and RELEASED otherwise. ZCL_LAND_WINDOW=0 turns all of it off
 * (test builds: off unless ZCL_LAND_WINDOW=1); ZCL_LAND_WINDOW_HOST names
 * this host, else the host name. Mail trouble is logged, never fatal. */

struct dl_window {
    char host[ZCL_LAND_WINDOW_HOST_MAX + 1];
    char sidecar[4096 + 32];
    struct zcl_land_window_self self;
};

static bool dl_window_host(char host[ZCL_LAND_WINDOW_HOST_MAX + 1])
{
    const char *named = getenv("ZCL_LAND_WINDOW_HOST");
    if (named && named[0])
        (void)snprintf(host, ZCL_LAND_WINDOW_HOST_MAX + 1, "%s", named);
    else
        zcl_agents_host_name(host, ZCL_LAND_WINDOW_HOST_MAX + 1);
    return zcl_land_window_host_ok(host);
}

static bool dl_window_on(const struct dl_dirs *d, struct dl_window *w)
{
    const char *on = getenv("ZCL_LAND_WINDOW");
#if defined(ZCL_TESTING)
    if (!on || strcmp(on, "1") != 0)
        return false;
#else
    if (on && strcmp(on, "0") == 0)
        return false;
#endif
    if (!d || !dl_window_host(w->host) ||
        snprintf(w->sidecar, sizeof(w->sidecar), "%s/window.state",
                 d->land) >= (int)sizeof(w->sidecar))
        return false;
    w->self = (struct zcl_land_window_self){ w->sidecar, w->host, DL_LEAF };
    return true;
}

static void dl_window_log(const struct dl_row *row, const char *note)
{
    if (!row || !note || !note[0])
        return;
    dl_log(row, "land window: ");
    dl_log(row, note);
    dl_log(row, "\n");
}

static void dl_step_deferred(struct zcl_command_reply *reply,
                             const struct zcl_land_window_hit *hit)
{
    char evidence[256];
    (void)snprintf(evidence, sizeof(evidence),
                   "host=%s candidate=%s base=%s seconds_left=%lld",
                   hit->host, hit->candidate, hit->base,
                   (long long)hit->seconds_left);
    (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
    (void)json_push_kv_str(&reply->data, "window_host", hit->host);
    (void)json_push_kv_str(&reply->data, "window_candidate", hit->candidate);
    (void)json_push_kv_str(&reply->data, "window_base", hit->base);
    (void)json_push_kv_int(&reply->data, "window_seconds_left",
                           hit->seconds_left);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED, "STEP_DEFERRED", "window",
                           true, false,
                           "another host is proving on this base; step again "
                           "after its window closes",
                           evidence);
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", "z23-dev dev land step");
}

/* True when the step deferred (reply written). Fail-open: no window, a
 * failed scan, a worktree or fetch problem all proceed to the normal step,
 * which reports its own failures. */
static bool dl_window_defer(const struct dl_dirs *d, const struct dl_row *row,
                            struct zcl_command_reply *reply)
{
    struct dl_window w;
    struct zcl_land_window_hit hit;
    char main_now[80], why[1024] = "", note[160];
    int64_t now = platform_time_wall_unix();
    if (!dl_window_on(d, &w) ||
        !zcl_land_window_foreign(w.host, NULL, now, ZCL_LAND_WINDOW_GRACE_S,
                                 &hit))
        return false;
    if (hit.stale > 0) {
        (void)snprintf(note, sizeof(note),
                       "ignored %lld stale foreign window(s) past "
                       "expected-done + %d min",
                       (long long)hit.stale, ZCL_LAND_WINDOW_GRACE_S / 60);
        dl_window_log(row, note);
    }
    if (!hit.open || !dl_wt_ensure(d, row, why, sizeof(why)) ||
        !dl_fetch_remote_main(d->wt, main_now) ||
        !zcl_land_window_foreign(w.host, main_now, now,
                                 ZCL_LAND_WINDOW_GRACE_S, &hit) ||
        !hit.open)
        return false;
    dl_step_deferred(reply, &hit);
    return true;
}

static void dl_window_begin(const struct dl_dirs *d, const struct dl_row *row)
{
    struct dl_window w;
    struct zcl_land_window_estimate e;
    char note[256];
    if (!dl_window_on(d, &w))
        return;
    zcl_land_window_estimate(d->wt, NULL, &e);
    (void)zcl_land_window_begin(&w.self, row->local, row->base,
                                platform_time_wall_unix(), &e, note,
                                sizeof(note));
    dl_window_log(row, note);
}

static void dl_window_tick(const struct dl_dirs *d, const struct dl_row *row)
{
    struct dl_window w;
    char note[256];
    if (!dl_window_on(d, &w))
        return;
    (void)zcl_land_window_tick(&w.self, d->wt, platform_time_wall_unix(),
                               note, sizeof(note));
    dl_window_log(row, note);
}

/* After a step: keep the window of a proof that is still running, close
 * any other (LANDED for the row that just landed). */
[[maybe_unused]] static void dl_window_settle(const struct dl_dirs *d,
                                              const struct dl_row *row,
                                              const struct zcl_command_reply *reply)
{
    struct dl_window w;
    const char *state;
    char note[256];
    bool proving, landed;
    if (reply->status != ZCL_COMMAND_STATUS_PASSED || !dl_window_on(d, &w))
        return;
    state = json_get_str(json_get(&reply->data, "state"));
    if (!state)
        return;
    proving = row && (strcmp(state, "started") == 0 ||
                      strcmp(state, "proving") == 0);
    landed = row && strcmp(state, "landed") == 0;
    (void)zcl_land_window_close(&w.self, proving ? row->local : NULL,
                                proving ? row->base : NULL,
                                landed ? row->local : NULL, note,
                                sizeof(note));
    dl_window_log(row, note);
}

static bool dl_proof_intent_bind(const struct dl_dirs *d, struct dl_row *row)
{
    char rev[96];
    char tree[256];
    const char *args[] = { "rev-parse", "--verify", "--quiet", rev, NULL };
    int n;
    if (!dl_sha_ok(row->local) || !dl_sha_ok(row->base))
        return false;
    n = snprintf(rev, sizeof(rev), "%s^{tree}", row->local);
    if (n <= 0 || (size_t)n >= sizeof(rev) ||
        dl_git(d->wt, args, tree, sizeof(tree), DL_GIT_TIMEOUT_MS) != 0)
        return false;
    dl_trim(tree);
    if (!dl_sha_ok(tree))
        return false;
    (void)snprintf(row->tree, sizeof(row->tree), "%s", tree);
    dl_publication_clear(row);
    n = snprintf(row->proof_intent, sizeof(row->proof_intent), "%s@%s",
                 row->local, row->base);
    return n > 0 && (size_t)n < sizeof(row->proof_intent);
}

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
/* The settled failure's evidence digest, read through the same status
 * reader the verdict came from. Empty when the record carries none. */
static void dl_proof_evidence_read(const char *wt, const char *local,
                                   const char *base, char *out, size_t cap)
{
    const char *stub = dl_stub();
    out[0] = '\0';
#if defined(ZCL_DEV_BUILD)
    if (stub && strcmp(stub, "status") != 0) return;
#else
    if (!stub || strcmp(stub, "status") != 0) return;
#endif
    struct zcl_dev_proof_status status = {0};
    if (zcl_dev_proof_status_read(wt, local, base, &status) &&
        status.state == ZCL_DEV_PROOF_STATE_FAILED)
        (void)snprintf(out, cap, "%s", status.evidence);
}

/* Name what failed on the settled row. The digest's first line leads the
 * detail with the settled token kept after it, its first word becomes the
 * dimension, and the whole digest is written beside the attempt's land log
 * (land-N-aK.evidence) so it outlives the proof's attempt directory. The
 * failure was already classified on the bare token; nothing here feeds
 * back into a retry or a verdict. */
static void dl_failed_proof_evidence(const struct dl_dirs *d,
                                     struct dl_row *row, const char *token)
{
    char evidence[1280], first[256], path[sizeof(row->log_path) + 16];
    dl_proof_evidence_read(d->wt, row->local, row->base, evidence,
                           sizeof(evidence));
    if (!evidence[0]) return;
    size_t n = strcspn(evidence, "\n");
    char line[1280];
    (void)snprintf(line, sizeof(line), "%.*s", (int)n, evidence);
    dl_sanitize_copy(line, first, sizeof(first));
    size_t word = strcspn(first, " :");
    if (word > 0 && word < sizeof(row->dimension))
        (void)snprintf(row->dimension, sizeof(row->dimension), "%.*s",
                       (int)word, first);
    size_t tlen = strlen(token) < 96 ? strlen(token) : 96;
    size_t room = sizeof(row->detail) - tlen - 4;
    size_t cut = strlen(first) < room ? strlen(first) : room;
    while (cut > 0 && ((unsigned char)first[cut] & 0xC0) == 0x80) cut--;
    (void)snprintf(row->detail, sizeof(row->detail), "%.*s [%.*s]",
                   (int)cut, first, (int)tlen, token);
    dl_log(row, "proof evidence:\n");
    dl_log(row, evidence);
    dl_log(row, "\n");
    size_t len = strlen(row->log_path);
    if (len < 4 || strcmp(row->log_path + len - 4, ".log") != 0) return;
    (void)snprintf(path, sizeof(path), "%.*s.evidence", (int)(len - 4),
                   row->log_path);
    (void)remove(path);
    (void)dl_append_text(path, token);
    (void)dl_append_text(path, "\n");
    (void)dl_append_text(path, evidence);
    (void)dl_append_text(path, "\n");
}
#endif

static void dl_start_proof(const struct dl_dirs *d, struct dl_row *row,
                            const char *regen_note,
                            struct zcl_command_reply *reply)
{
    char detail[512];
    enum dl_proof p;
    (void)snprintf(row->phase, sizeof(row->phase), "prove");
    if (!dl_proof_intent_bind(d, row)) {
        (void)snprintf(row->state, sizeof(row->state), "failed");
        (void)snprintf(row->dimension, sizeof(row->dimension),
                       "proof_intent");
        (void)snprintf(row->detail, sizeof(row->detail), "%s",
                       "cannot bind the prepared tree to the exact proof pair");
        if (dl_commit_or_report(d, row, true, reply, "failed"))
            dl_step_reply(reply, row, "failed");
        return;
    }
    if (!dl_commit_row(d, row, false)) {
        dl_fail(reply, "QUEUE_WRITE_FAILED", "proof_intent",
                "cannot persist the prepared tree and proof pair", d->land);
        return;
    }
    p = dl_proof_request(d->wt, row->local, row->base, detail,
                         sizeof(detail));
    (void)snprintf(row->detail, sizeof(row->detail), "%s%s%s", regen_note,
                   regen_note[0] ? "; " : "", detail);
    dl_log(row, detail);
    dl_log(row, "\n");
    if (p == DL_PROOF_UNAVAILABLE || p == DL_PROOF_FAILED) {
        (void)snprintf(row->state, sizeof(row->state), "failed");
        (void)snprintf(row->dimension, sizeof(row->dimension), "proof");
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
        if (p == DL_PROOF_FAILED)
            dl_failed_proof_evidence(d, row, detail);
#endif
        if (dl_commit_or_report(d, row, true, reply, "failed"))
            dl_step_reply(reply, row, "failed");
        return;
    }
    if (dl_commit_or_report(d, row, false, reply, "started")) {
        dl_step_reply(reply, row, "started");
        dl_window_begin(d, row);
    }
}

static void dl_step_start(const struct dl_dirs *d, struct dl_row *row,
                          struct zcl_command_reply *reply,
                          char observed_main[80])
{
    char why[1024], tickets[512], regen_note[256];
    int rebased;

    (void)snprintf(row->state, sizeof(row->state), "inflight");
    (void)snprintf(row->phase, sizeof(row->phase), "rebase");
    row->started = (long long)platform_time_wall_unix();
    dl_log_path(d, row);
    if (!dl_commit_row(d, row, false)) {
        dl_fail(reply, "QUEUE_WRITE_FAILED", "start",
                "cannot mark the request in flight", d->land);
        return;
    }
    why[0] = '\0';
    if (!dl_wt_ensure(d, row, why, sizeof(why))) {
        (void)snprintf(row->state, sizeof(row->state), "failed");
        (void)snprintf(row->dimension, sizeof(row->dimension), "worktree");
        (void)snprintf(row->detail, sizeof(row->detail), "%s", why);
        dl_log(row, why);
        dl_log(row, "\n");
        if (dl_commit_or_report(d, row, true, reply, "failed"))
            dl_step_reply(reply, row, "failed");
        return;
    }
    if (dl_reconcile_landing(d, row, observed_main, true, reply))
        return;
    rebased = dl_rebase(d, row, observed_main, why, sizeof(why), regen_note,
                        sizeof(regen_note));
    if (rebased == 0) {
        (void)snprintf(row->state, sizeof(row->state), "conflict");
        (void)snprintf(row->dimension, sizeof(row->dimension), "rebase");
        (void)snprintf(row->detail, sizeof(row->detail), "%s", why);
        dl_log(row, "rebase conflict: ");
        dl_log(row, why);
        dl_log(row, "\n");
        if (dl_commit_or_report(d, row, true, reply, "conflict"))
            dl_step_reply(reply, row, "conflict");
        return;
    }
    if (rebased < 0) {
        (void)snprintf(row->state, sizeof(row->state), "failed");
        (void)snprintf(row->dimension, sizeof(row->dimension), "rebase");
        (void)snprintf(row->detail, sizeof(row->detail), "%s", why);
        dl_log(row, why);
        dl_log(row, "\n");
        if (dl_commit_or_report(d, row, true, reply, "failed"))
            dl_step_reply(reply, row, "failed");
        return;
    }
    if (!dl_step_after_rebase(d, row, reply, regen_note))
        return;
    /* The lint pass is what the proof would discover last and cheapest to
     * discover first. The proof stub skips it: a test of this queue is not
     * a test of the lint suite. */
    (void)snprintf(row->phase, sizeof(row->phase), "prebuild");
    if (!dl_stub() && dl_lint_candidate(d, row) != 0) {
        bool retry = strcmp(row->dimension, "host_load") == 0 &&
                     row->attempt < DL_ATTEMPT_MAX;
        if (retry) {
            row->attempt++;
            (void)snprintf(row->phase, sizeof(row->phase), "rebase");
            (void)snprintf(row->state, sizeof(row->state), "queued");
            if (dl_commit_or_report(d, row, false, reply, "rebased"))
                dl_step_reply(reply, row, "rebased");
            return;
        }
        (void)snprintf(row->state, sizeof(row->state), "failed");
        if (dl_commit_or_report(d, row, true, reply, "failed"))
            dl_step_reply(reply, row, "failed");
        return;
    }
    /* Where node2's commuting tickets plug in: with a ticket set installed,
     * the groups it names are admitted here and the proof asks for less. */
    if (dl_tickets_admit(row, row->base, tickets, sizeof(tickets)))
        dl_log(row, tickets);
    /* The exact proof's own private generation only ever COPIES its
     * dependencies out of this worktree, and reads the restart plan
     * straight from it; it never builds any of them. The stub skips the
     * make-based restart plan for the same reason it skips lint: it
     * replaces the proof, not the worktree the proof would have used. */
    (void)snprintf(row->phase, sizeof(row->phase), "prebuild");
    if (!dl_wt_proof_deps_ensure(d, row, dl_stub() != NULL, why,
                                 sizeof(why))) {
        (void)snprintf(row->state, sizeof(row->state), "failed");
        (void)snprintf(row->dimension, sizeof(row->dimension),
                       "worktree_deps");
        (void)snprintf(row->detail, sizeof(row->detail), "%s", why);
        dl_log(row, why);
        dl_log(row, "\n");
        if (dl_commit_or_report(d, row, true, reply, "failed"))
            dl_step_reply(reply, row, "failed");
        return;
    }
    dl_start_proof(d, row, regen_note, reply);
}

static void dl_prepare(const struct dl_dirs *d, struct dl_row *row,
                         struct zcl_command_reply *reply, char observed_main[80])
{
    int64_t started = platform_time_monotonic_us();
    if (dl_window_defer(d, row, reply))
        return;
    dl_step_start(d, row, reply, observed_main);
    dl_beat(row, "prepare", started);
}

/* The lease adds an expected-old-value comparison; it never grants history
 * replacement. Verify the exact proven pair's fast-forward ancestry first. */
/* Publication diagnostics are evidence, never acceptance authority. Binary
 * merged capture preserves exit/EOF/overflow separately; protocol Git reads
 * continue through dl_git's stdout-only seam. An incomplete diagnostic leaves
 * the durable pending checkpoint armed and forbids another unrecorded send. */
static bool dl_push_diagnostic(const struct dl_dirs *d, const struct dl_row *row,
                               const struct zcl_spawn_binary_observation *o,
                               char *output)
{
#if defined(_WIN32)
    (void)d; (void)row; (void)o; (void)output;
    return false; /* Native landing mutations require POSIX private-file semantics. */
#else
    char path[4096 + 96];
    if (snprintf(path, sizeof(path), "%s/push-%lld-a%lld.diagnostic",
                 d->logs, row->seq, row->attempt) >= (int)sizeof(path))
        return false;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                   0600);
    if (fd < 0) return false;
    FILE *f = fdopen(fd, "wb");
    if (!f) { (void)close(fd); return false; }
    for (size_t i = 0; i < o->output_len; ++i) {
        unsigned char byte = (unsigned char)output[i];
        if (byte != '\n' && byte != '\t' && (byte < 32 || byte > 126))
            output[i] = '?';
    }
    bool ok = fprintf(f,
        "publication diagnostic v1\nseq=%lld attempt=%lld target=%s\n"
        "base=%s head=%s\nargv=git -C <owned-worktree> push "
        "--force-with-lease=refs/heads/main:%s origin %s:refs/heads/main\n"
        "exit_observed=%d exit_code=%d timed_out=%d eof=%d overflow=%d bytes=%zu\n",
        row->seq, row->attempt, row->publication_target, row->base, row->local,
        row->base, row->local, o->exit_observed, o->exit_code, o->timed_out,
        o->eof, o->overflow, o->output_len) > 0 &&
        fwrite(output, 1, o->output_len, f) == o->output_len &&
        fputs("\nEND publication diagnostic\n", f) >= 0 &&
        dl_queue_file_flush(f);
    if (fclose(f) != 0) ok = false;
    return ok && dl_queue_parent_flush(d->logs);
#endif
}

static bool dl_publication_target(const struct dl_dirs *d, char out[65]);

static bool dl_push_receiver_bound(const struct dl_dirs *d, const struct dl_row *row)
{
    char target[65];
    return !row->publication_signature[0] ||
        (dl_publication_target(d, target) && strcmp(target, row->publication_target) == 0);
}

static bool dl_push_proven_pair(const struct dl_dirs *d,
                                const struct dl_row *row,
                                char *out, size_t out_cap, bool *recorded)
{
    *recorded = false;
    if (row->publication_hold) {
        (void)snprintf(out, out_cap, "%s", "publication refused: candidate publication hold");
        return false;
    }
    const char *ancestry[] = { "--no-replace-objects", "merge-base",
        "--is-ancestor", row->base, row->local, NULL };
    int rc = dl_git(d->wt, ancestry, out, out_cap, DL_GIT_TIMEOUT_MS);
    if (rc != 0) {
        if (rc == 1 || !out[0])
            (void)snprintf(out, out_cap, "%s", rc == 1
                ? "publication refused: proven base is not an ancestor of candidate"
                : "publication refused: cannot establish proven-pair ancestry");
        return false;
    }
    char lease[128], refspec[128];
    int n = snprintf(lease, sizeof(lease), "--force-with-lease=refs/heads/main:%s",
                     row->base);
    int m = snprintf(refspec, sizeof(refspec), "%s:refs/heads/main", row->local);
    if (n <= 0 || (size_t)n >= sizeof(lease) ||
        m <= 0 || (size_t)m >= sizeof(refspec)) {
        (void)snprintf(out, out_cap, "%s",
            "publication refused: exact ref arguments exceed bounded capacity");
        return false;
    }
    /* Re-read the complete expanded receiver set immediately before dispatch,
     * after checkpoint/barrier work; a changed receiver never gets a send. */
    if (!dl_push_receiver_bound(d, row)) {
        (void)snprintf(out, out_cap, "%s", "publication refused: signed receiver changed before dispatch");
        return false;
    }
    const char *push[] = { "git", "-C", d->wt, "push", lease, "origin",
                           refspec, NULL };
    struct zcl_spawn_binary_observation observation = {0};
    int64_t started = platform_time_monotonic_us();
    (void)zcl_spawn_capture_binary_merged(push, out, out_cap - 1,
                                         DL_GIT_TIMEOUT_MS, &observation);
    dl_beat(row, "push", started);
    out[observation.output_len] = '\0';
    *recorded = dl_push_diagnostic(d, row, &observation, out);
    return observation.exit_observed && observation.exit_code == 0 &&
           !observation.timed_out;
}

/* Git landing has its own local publication intent. It binds the existing
 * exact proof and configured origin, not a Commons package publication. */
static bool dl_publication_file_sha256(const char *path, uint64_t max_bytes,
                                        char out[65])
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    struct sha256_ctx hash;
    uint8_t bytes[65536], digest[32];
    uint64_t offset = 0;
    bool ok;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false;
    ok = platform_positioned_file_snapshot(&file, &before) &&
         before.size > 0 && before.size <= max_bytes;
    sha256_init(&hash);
    while (ok && offset < before.size) {
        size_t want = before.size - offset > sizeof(bytes) ? sizeof(bytes) :
                      (size_t)(before.size - offset);
        int64_t got = platform_positioned_file_read(&file, bytes, want, offset);
        if (got <= 0) { ok = false; break; }
        sha256_write(&hash, bytes, (size_t)got);
        offset += (uint64_t)got;
    }
    ok = ok && platform_positioned_file_snapshot(&file, &after) &&
         platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (!ok) return false;
    sha256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

static bool dl_single_url_line(char *out, size_t length)
{
    if (!length || memchr(out, '\0', length)) return false;
    /* Remove one protocol terminator only. A second empty URL is still a
     * second receiver entry and must not disappear through whitespace trim. */
    if (out[length - 1] == '\n') --length;
    out[length] = '\0';
    return length > 0 && !memchr(out, '\n', length) && !memchr(out, '\r', length);
}

static bool dl_single_origin_url(const char *wt, bool push, char *out, size_t cap)
{
    const char *fetch[] = { "git", "-C", wt, "remote", "get-url", "--all", "origin", NULL };
    const char *send[] = { "git", "-C", wt, "remote", "get-url", "--all", "--push", "origin", NULL };
    struct zcl_spawn_binary_observation o = {0};
    if (cap < 2) return false;
    (void)zcl_spawn_capture_binary(push ? send : fetch, out, cap - 1,
                                   DL_GIT_TIMEOUT_MS, &o);
    return o.exit_observed && o.exit_code == 0 && !o.overflow && o.eof && !o.timed_out &&
        dl_single_url_line(out, o.output_len);
}

static bool dl_publication_target(const struct dl_dirs *d, char out[65])
{
    char fetch[4096], push[4096];
    static const char domain[] = "zcl.dev_land.git_target.v1\nrefs/heads/main\n";
    struct sha256_ctx hash;
    uint8_t digest[32];
    if (!dl_single_origin_url(d->wt, false, fetch, sizeof(fetch)) ||
        !dl_single_origin_url(d->wt, true, push, sizeof(push)))
        return false;
    if (!fetch[0] || strcmp(fetch, push) != 0 ||
        strchr(fetch, '\n') || strchr(fetch, '\r'))
        return false;
    sha256_init(&hash);
    sha256_write(&hash, (const uint8_t *)domain, sizeof(domain) - 1);
    sha256_write(&hash, (const uint8_t *)fetch, strlen(fetch));
    sha256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

static bool dl_publication_bundle_path(const struct dl_dirs *d,
                                        const struct dl_row *row,
                                        char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/publication.%lld.%.40s.bundle",
                     d->land, row->seq, row->local);
    return dl_sha_ok(row->local) && n > 0 && (size_t)n < cap;
}

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
static bool dl_publication_tree_check(const struct dl_dirs *d,
                                       const struct dl_row *row)
{
    char rev[96], observed[128], pair[176];
    if (snprintf(rev, sizeof(rev), "%s^{tree}", row->local) >=
            (int)sizeof(rev) ||
        snprintf(pair, sizeof(pair), "%s@%s", row->local, row->base) >=
            (int)sizeof(pair) || strcmp(pair, row->proof_intent) != 0)
        return false;
    const char *args[] = { "rev-parse", "--verify", "--quiet", rev, NULL };
    if (dl_git(d->wt, args, observed, sizeof(observed), DL_GIT_TIMEOUT_MS) != 0)
        return false;
    dl_trim(observed);
    return strcmp(observed, row->tree) == 0;
}
#endif

static bool dl_publication_message(const struct dl_row *row,
                                    char *out, size_t cap)
{
    static const char domain[] = "zcl.dev_land.publication_intent.v1";
    int n;
    if (!row || !dl_hex_ok(row->publication_target, 64) ||
        !dl_hex_ok(row->publication_proof, 64) ||
        !dl_hex_ok(row->publication_bundle, 64) ||
        !dl_sha_ok(row->base) || !dl_sha_ok(row->local) ||
        !dl_sha_ok(row->tree) || !row->proof_intent[0])
        return false;
    n = snprintf(out, cap,
        "%s\noperator\nrefs/heads/main\n%lld\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
        domain, row->seq, row->publication_target, row->base, row->local,
        row->tree, row->publication_proof, row->publication_bundle,
        row->proof_intent);
    return n > 0 && (size_t)n < cap;
}

static bool dl_publication_proof_digest(const struct dl_dirs *d,
                                         const struct dl_row *row,
                                         char digest[65]);

static bool dl_publication_verify(const struct dl_dirs *d,
                                   const struct dl_row *row)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    char message[1024], target[65], bundle_path[4096 + 128];
    char bundle[65], proof[65];
    uint8_t signer[32], signature[64];
    const char *why = NULL;
    if (!dl_publication_shape_ok(row) ||
        !row->publication_signature[0] ||
        !dl_publication_message(row, message, sizeof(message)) ||
        !zcl_hex_decode_lower(row->publication_signer, signer, sizeof(signer)) ||
        !zcl_hex_decode_lower(row->publication_signature, signature,
                              sizeof(signature)) ||
        !zcl_dev_proof_signer_verify((const uint8_t *)message, strlen(message),
            signer, signature, &why) ||
        !dl_publication_tree_check(d, row) ||
        !dl_publication_target(d, target) ||
        strcmp(target, row->publication_target) != 0 ||
        !dl_publication_bundle_path(d, row, bundle_path,
                                    sizeof(bundle_path)) ||
        !dl_publication_file_sha256(bundle_path, 512u * 1024u * 1024u,
                                    bundle) ||
        strcmp(bundle, row->publication_bundle) != 0 ||
        !dl_publication_proof_digest(d, row, proof) ||
        strcmp(proof, row->publication_proof) != 0)
        return false;
    return true;
#else
    (void)d; (void)row;
    return false;
#endif
}

static bool dl_publication_bundle_make(const struct dl_dirs *d,
                                        const struct dl_row *row,
                                        char digest[65])
{
#if defined(_WIN32)
    (void)d; (void)row; (void)digest;
    return false;
#else
    char path[4096 + 128], tmp[4096 + 160], excluded[80];
    char head[128], output[2048];
    int fd;
    if (!dl_publication_bundle_path(d, row, path, sizeof(path)) ||
        snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >=
            (int)sizeof(tmp) ||
        snprintf(excluded, sizeof(excluded), "^%s", row->base) >=
            (int)sizeof(excluded))
        return false;
    const char *head_args[] = { "rev-parse", "HEAD", NULL };
    if (dl_git(d->wt, head_args, head, sizeof(head), DL_GIT_TIMEOUT_MS) != 0)
        return false;
    dl_trim(head);
    if (strcmp(head, row->local) != 0)
        return false;
    const char *create[] = { "bundle", "create", tmp, "HEAD", excluded, NULL };
    const char *verify[] = { "bundle", "verify", tmp, NULL };
    bool ok = dl_git(d->wt, create, output, sizeof(output), DL_GIT_TIMEOUT_MS) == 0 &&
              dl_git(d->wt, verify, output, sizeof(output), DL_GIT_TIMEOUT_MS) == 0;
    if (ok) {
        fd = open(tmp, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        ok = fd >= 0 && fsync(fd) == 0;
        if (fd >= 0) (void)close(fd);
    }
    if (ok)
        ok = rename(tmp, path) == 0 && dl_queue_parent_flush(d->land);
    if (!ok) {
        (void)unlink(tmp);
        return false;
    }
    return dl_publication_file_sha256(path, 512u * 1024u * 1024u, digest);
#endif
}

static bool dl_publication_proof_digest(const struct dl_dirs *d,
                                         const struct dl_row *row,
                                         char digest[65])
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
#if defined(ZCL_TESTING)
    if (dl_stub() && strcmp(dl_stub(), "pass") == 0) {
        struct sha256_ctx hash;
        uint8_t bytes[32];
        static const char domain[] = "zcl.dev_land.test_proof_stub.v1";
        sha256_init(&hash);
        sha256_write(&hash, (const uint8_t *)domain, sizeof(domain) - 1);
        sha256_write(&hash, (const uint8_t *)row->proof_intent,
                     strlen(row->proof_intent));
        sha256_finalize(&hash, bytes);
        zcl_hex_encode(bytes, sizeof(bytes), digest);
        return true;
    }
#endif
    struct zcl_dev_proof_status status = {0};
    return !dl_stub() &&
        zcl_dev_proof_status_read(d->wt, row->local, row->base, &status) &&
        status.state == ZCL_DEV_PROOF_STATE_PASSED &&
        dl_publication_file_sha256(status.receipt_path, 1024u * 1024u,
                                   digest);
#else
    (void)d; (void)row; (void)digest;
    return false;
#endif
}

static bool dl_publication_sign(struct dl_row *row)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    char message[1024];
    uint8_t signer[32], signature[64];
    const char *why = NULL;
    if (!dl_publication_message(row, message, sizeof(message)) ||
        !zcl_dev_proof_signer_sign((const uint8_t *)message, strlen(message),
                                   signer, signature, &why))
        return false;
    zcl_hex_encode(signer, sizeof(signer), row->publication_signer);
    zcl_hex_encode(signature, sizeof(signature), row->publication_signature);
    return true;
#else
    (void)row;
    return false;
#endif
}

static bool dl_publication_fetched_objects_check(const char *scratch,
                                                  const struct dl_row *row,
                                                  const char *tip,
                                                  char source[65])
{
    char output[2048], head_tree_rev[96], tip_tree_rev[96];
    char head_tree[128], tip_tree[128];
    const char *base_head[] = { "--no-replace-objects", "merge-base",
        "--is-ancestor", row->base, row->local, NULL };
    const char *head_tip[] = { "--no-replace-objects", "merge-base",
        "--is-ancestor", row->local, tip, NULL };
    if (dl_git(scratch, base_head, output, sizeof(output), DL_GIT_TIMEOUT_MS) != 0 ||
        dl_git(scratch, head_tip, output, sizeof(output), DL_GIT_TIMEOUT_MS) != 0 ||
        snprintf(head_tree_rev, sizeof(head_tree_rev), "%s^{tree}",
                 row->local) >= (int)sizeof(head_tree_rev) ||
        snprintf(tip_tree_rev, sizeof(tip_tree_rev), "%s^{tree}", tip) >=
            (int)sizeof(tip_tree_rev))
        return false;
    const char *head_tree_args[] = { "rev-parse", "--verify", head_tree_rev,
                                    NULL };
    const char *tip_tree_args[] = { "rev-parse", "--verify", tip_tree_rev,
                                   NULL };
    const char *fsck[] = { "fsck", "--strict", "--no-reflogs", NULL };
    if (dl_git(scratch, head_tree_args, head_tree, sizeof(head_tree),
               DL_GIT_TIMEOUT_MS) != 0 ||
        dl_git(scratch, tip_tree_args, tip_tree, sizeof(tip_tree),
               DL_GIT_TIMEOUT_MS) != 0 ||
        dl_git(scratch, fsck, output, sizeof(output), DL_GIT_TIMEOUT_MS) != 0)
        return false;
    dl_trim(head_tree);
    dl_trim(tip_tree);
    if (!dl_sha_ok(tip_tree) || strcmp(head_tree, row->tree) != 0)
        return false;
    (void)snprintf(source, 65, "%s", tip_tree);
    return true;
}

/* Fetch into a new object store: neither the lander's tracking ref nor its
 * local object database is evidence that the remote contains these bytes. */
[[maybe_unused]] static bool dl_observer_receiver_same(const char *scratch, const char *locator)
{
    char effective[4096], output[2048];
    const char *add[] = { "remote", "add", "origin", locator, NULL };
    if (dl_git(scratch, add, output, sizeof(output), DL_GIT_TIMEOUT_MS) != 0)
        return false;
    return dl_single_origin_url(scratch, false, effective, sizeof(effective)) &&
        strcmp(effective, locator) == 0;
}

static bool dl_publication_remote_observe(const struct dl_dirs *d,
                                           const struct dl_row *row,
                                           char tip[65], char source[65])
{
#if defined(_WIN32)
    (void)d; (void)row; (void)tip; (void)source;
    return false;
#else
    char scratch[4096 + 96], locator[4096], output[2048];
    char target[65];
    bool ok = false;
    int64_t started = platform_time_monotonic_us();
    tip[0] = '\0';
    source[0] = '\0';
    if (!dl_publication_target(d, target) ||
        strcmp(target, row->publication_target) != 0 ||
        snprintf(scratch, sizeof(scratch), "%s/observe.%lld.XXXXXX",
                 d->land, row->seq) >= (int)sizeof(scratch) ||
        !mkdtemp(scratch))
        return false;
    const char *init[] = { "init", "--bare", "--quiet", NULL };
    if (!dl_single_origin_url(d->wt, false, locator, sizeof(locator)))
        goto done;
    if (locator[0] == '-')
        goto done;
    const char *fetch[] = { "fetch", "--quiet", "--no-tags", "--refmap=",
                           "--", locator, "refs/heads/main", NULL };
    const char *fetched[] = { "rev-parse", "--verify", "FETCH_HEAD", NULL };
    if (dl_git(scratch, init, output, sizeof(output), DL_GIT_TIMEOUT_MS) != 0 ||
        !dl_observer_receiver_same(scratch, locator) ||
        dl_git(scratch, fetch, output, sizeof(output), DL_GIT_TIMEOUT_MS) != 0 ||
        dl_git(scratch, fetched, output, sizeof(output), DL_GIT_TIMEOUT_MS) != 0)
        goto done;
    dl_trim(output);
    if (!dl_sha_ok(output)) goto done;
    (void)snprintf(tip, 65, "%s", output);
    ok = dl_publication_fetched_objects_check(scratch, row, tip, source);
done:
    if (!zcl_tree_remove(scratch).ok) ok = false;
    dl_beat(row, "fresh_observation", started);
    if (!ok) { tip[0] = '\0'; source[0] = '\0'; }
    return ok;
#endif
}

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
static bool dl_publication_receipt_message(const struct dl_row *row,
                                             char *out, size_t cap)
{
    int n;
    if (!dl_publication_shape_ok(row) ||
        !row->publication_signature[0] ||
        !dl_sha_ok(row->remote_tip) || !dl_sha_ok(row->remote_source))
        return false;
    n = snprintf(out, cap,
        "zcl.dev_land.remote_receipt.v1\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
        row->publication_target, row->publication_signature,
        row->base, row->local, row->tree, row->remote_tip,
        row->remote_source);
    return n > 0 && (size_t)n < cap;
}
#endif

static bool dl_publication_receipt_seal(struct dl_row *row)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    char message[1024];
    uint8_t signer[32], signature[64];
    const char *why = NULL;
    if (!dl_publication_receipt_message(row, message, sizeof(message)) ||
        !zcl_dev_proof_signer_sign((const uint8_t *)message, strlen(message),
                                   signer, signature, &why))
        return false;
    zcl_hex_encode(signer, sizeof(signer), row->remote_signer);
    zcl_hex_encode(signature, sizeof(signature), row->remote_signature);
    return true;
#else
    (void)row;
    return false;
#endif
}

static bool dl_publication_receipt_verify(const struct dl_row *row)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    char message[1024];
    uint8_t signer[32], signature[64];
    const char *why = NULL;
    return dl_remote_receipt_shape_ok(row) &&
        row->remote_signature[0] &&
        dl_publication_receipt_message(row, message, sizeof(message)) &&
        zcl_hex_decode_lower(row->remote_signer, signer, sizeof(signer)) &&
        zcl_hex_decode_lower(row->remote_signature, signature,
                             sizeof(signature)) &&
        zcl_dev_proof_signer_verify((const uint8_t *)message, strlen(message),
                                    signer, signature, &why);
#else
    (void)row;
    return false;
#endif
}

static bool dl_chain_pair_bound(const struct dl_row *r)
{
    char intent[176];
    (void)snprintf(intent, sizeof(intent), "%s@%s", r->local, r->base);
    return dl_hex_ok(r->local, 40) && dl_hex_ok(r->base, 40) &&
        dl_hex_ok(r->tree, 40) && strcmp(intent, r->proof_intent) == 0;
}

static bool dl_chain_git(const struct dl_dirs *d, const char *const *args,
    char *out, size_t cap, int64_t deadline)
{
    int64_t left = deadline - platform_time_monotonic_ms();
    return left > 0 && dl_git(d->wt, args, out, cap,
        left > INT_MAX ? INT_MAX : (int)left) == 0;
}
enum dl_chain_relation {
    DL_CHAIN_CURRENT, DL_CHAIN_PENDING, DL_CHAIN_DIVERGED,
    DL_CHAIN_UNKNOWN, DL_CHAIN_INVALID
};

static bool dl_chain_identity_equal(const struct dl_row *r, const struct dl_row *p)
{
    return r->predecessor_seq == p->seq &&
        strcmp(r->predecessor_local, p->local) == 0 &&
        strcmp(r->predecessor_base, p->base) == 0 &&
        strcmp(r->predecessor_tree, p->tree) == 0 &&
        strcmp(r->predecessor_intent, p->proof_intent) == 0;
}

/* Revalidate queue admission against immutable Git objects, never cache labels. */
static bool dl_chain_prepared(const struct dl_dirs *d, const struct dl_row *p, int64_t deadline)
{
    char signature[64] = {0}, tree[80];
    const char *sig[] = { "--no-replace-objects", "log", "-1", "--format=%G?", p->local, NULL };
    const char *object[] = { "--no-replace-objects", "show", "-s", "--format=%T", p->local, NULL };
    const char *ancestry[] = { "--no-replace-objects", "merge-base", "--is-ancestor", p->base, p->local, NULL };
    if (!dl_chain_pair_bound(p) || p->fence_peer)
        return false;
    return dl_chain_git(d, sig, signature, sizeof(signature), deadline) && signature[0] == 'G' &&
        dl_chain_git(d, object, tree, sizeof(tree), deadline) &&
        (dl_trim(tree), strcmp(tree, p->tree) == 0) &&
        dl_chain_git(d, ancestry, tree, sizeof(tree), deadline);
}

/* Read the existing terminal authority by sequence; duplicate or malformed
 * observations refuse. No state=landed shortcut can replace the signed receipt. */
static bool dl_chain_outcome(const struct dl_dirs *d, long long seq,
    struct dl_row *out, bool *present)
{
    char path[4192]; size_t len = 0, count = 0;
    *present = false;
    if (snprintf(path, sizeof(path), "%s/outcomes.jsonl", d->land) >= (int)sizeof(path)) return false;
    char *data = zcl_malloc(DL_FILE_CAP, "dev.land.chain.history");
    if (!data) return false;
    if (!dl_read_file(path, data, DL_FILE_CAP, &len)) {
        int saved = errno; free(data); return saved == ENOENT;
    }
    bool ok = memchr(data, '\0', len) == NULL &&
        (!len || data[len - 1] == '\n');
    char *save = NULL;
    for (char *line = strtok_r(data, "\n", &save); ok && line; line = strtok_r(NULL, "\n", &save)) {
        struct dl_row row;
        ok = ++count <= 65536 && dl_parse_row(line, &row) &&
            strcmp(row.state, "queued") != 0 && strcmp(row.state, "inflight") != 0;
        if (ok && row.seq == seq) {
            ok = !*present; *present = true; *out = row;
        }
    }
    free(data); return ok;
}

static bool dl_chain_find(const struct dl_row *rows, size_t count, long long seq, const struct dl_row **found)
{
    *found = NULL;
    for (size_t i = 0; i < count; ++i) {
        if (rows[i].seq != seq) continue;
        if (*found) return false;
        *found = &rows[i];
    }
    return true;
}

static bool dl_chain_predecessor(const struct dl_dirs *d, const struct dl_row *r,
    const struct dl_row *rows, size_t nrows, struct dl_row *out, int64_t deadline)
{
    const struct dl_row *p = NULL;
    struct dl_row terminal;
    bool present = false;
    if (!dl_chain_shape_ok(r) || !dl_chain_pair_bound(r) || strcmp(r->base, r->predecessor_local) != 0) return false;
    if (!dl_chain_find(rows, nrows, r->predecessor_seq, &p)) return false;
    if (!dl_chain_outcome(d, r->predecessor_seq, &terminal, &present)) return false;
    if (present) {
        if (p && !dl_chain_identity_equal(r, p)) return false;
        p = &terminal;
    }
    if (!p || !dl_chain_identity_equal(r, p) || !dl_chain_prepared(d, p, deadline)) return false;
    *out = *p;
    return strcmp(p->state, "inflight") == 0 || strcmp(p->state, "queued") == 0 ||
        (strcmp(p->state, "landed") == 0 && dl_publication_receipt_verify(p));
}

/* Consume a fresh observation supplied by the caller. Equality is checked only
 * AFTER every pinned dependency qualifies. Exact anchors wait, ancestry does not.
 * B1 has no submit producer or scheduler integration: B2 enables those together. */
[[maybe_unused]] static enum dl_chain_relation dl_chain_relation(const struct dl_dirs *d,
    const struct dl_row *r, const struct dl_row *rows, size_t nrows,
    const char *main, long long *waiting_seq, char *why, size_t why_len)
{
    bool pending = false;
    *waiting_seq = 0;
    if (why_len) why[0] = '\0';
    if (!dl_sha_ok(main)) return DL_CHAIN_UNKNOWN;
    int64_t deadline = platform_time_monotonic_ms() + 5000;
    struct dl_row dependency = *r;
    for (size_t hop = 0; dependency.predecessor_seq; ++hop) {
        struct dl_row predecessor;
        if (hop >= 65536 || !dl_chain_predecessor(d, &dependency, rows, nrows, &predecessor, deadline)) {
            (void)snprintf(why, why_len, "chain_dependency_invalid_seq_%lld", dependency.predecessor_seq);
            fprintf(stderr, "[dev.land] %s\n", why);
            *waiting_seq = 0; return DL_CHAIN_INVALID;
        }
        if (strcmp(predecessor.state, "landed") != 0 && strcmp(main, predecessor.base) == 0) {
            pending = true; *waiting_seq = predecessor.seq;
        }
        if (strcmp(predecessor.state, "landed") == 0) break;
        dependency = predecessor;
    }
    if (strcmp(main, r->base) == 0) { *waiting_seq = 0; return DL_CHAIN_CURRENT; }
    return pending ? DL_CHAIN_PENDING : DL_CHAIN_DIVERGED;
}

#if defined(ZCL_TESTING)
int zcl_native_dev_land_test_chain_relation(const char *line,
    const char *const *lines, size_t count, const char *main, long long *waiting)
{
    struct dl_dirs d;
    struct dl_row row;
    char why[128];
    if (!dl_parse_row(line, &row) || count > 65536 || !dl_dirs_make(&d)) return DL_CHAIN_INVALID;
    struct dl_row *rows = zcl_calloc(count ? count : 1, sizeof(*rows), "dev.land.chain.fixture");
    if (!rows) return DL_CHAIN_INVALID;
    for (size_t i = 0; i < count; ++i) {
        if (!dl_parse_row(lines[i], &rows[i])) { free(rows); return DL_CHAIN_INVALID; }
    }
    (void)snprintf(d.wt, sizeof(d.wt), "%s", count ? rows[0].worktree : row.worktree);
    enum dl_chain_relation relation = dl_chain_relation(&d, &row, rows, count, main, waiting, why, sizeof(why));
    free(rows); return relation;
}
#endif

static bool dl_resume_phase_ready(const char *phase)
{
    return strcmp(phase, "prove") == 0 || strcmp(phase, "push") == 0;
}

/* A changed base invalidates only this exact proof pair. Keep the submitted
 * time and queue position through bounded retries, then yield to other queued
 * work. The old pair stays in the attempt log and proof store, never as
 * authority for the successor. */
static void dl_step_successor(const struct dl_dirs *d, struct dl_row *row,
                              const char *observed_main,
                              struct zcl_command_reply *reply)
{
    char prior[256];
    (void)snprintf(prior, sizeof(prior),
                   "superseded proof local=%.64s base=%.64s tree=%.64s\n",
                   row->local, row->base, row->tree);
    dl_log(row, prior);
    if (row->publication_signature[0]) {
        char signed_prior[512];
        (void)snprintf(signed_prior, sizeof(signed_prior),
            "stale signed intent target=%.64s proof=%.64s bundle=%.64s "
            "signer=%.64s signature=%.128s\n",
            row->publication_target, row->publication_proof,
            row->publication_bundle, row->publication_signer,
            row->publication_signature);
        dl_log(row, signed_prior);
    }
    row->attempt++;
    if (row->publication_signature[0] || row->attempt > DL_ATTEMPT_MAX) {
        long long predecessor = row->seq;
        (void)snprintf(row->detail, sizeof(row->detail),
                       "main moved to %.12s; successor of seq=%lld",
                       observed_main, predecessor);
        if (dl_requeue_successor(d, row, &predecessor)) {
            dl_step_reply(reply, row, "queued");
            (void)json_push_kv_int(&reply->data, "predecessor_seq",
                                   predecessor);
        } else {
            dl_step_reply(reply, row, "rebased");
            (void)json_push_kv_str(&reply->data, "persist", "failed");
        }
        return;
    }
    (void)snprintf(row->state, sizeof(row->state), "queued");
    (void)snprintf(row->phase, sizeof(row->phase), "rebase");
    row->dimension[0] = '\0';
    row->producer_recovered = 0;
    /* Belt-and-braces: the digest already differs for a successor because
     * `attempt` is hashed; no test discriminates this reset. */
    row->phase_mail = 0;
    row->proof_intent[0] = '\0';
    dl_publication_clear(row);
    (void)snprintf(row->detail, sizeof(row->detail),
                   "origin/main moved to %.64s; successor queued",
                   observed_main);
    dl_log(row, row->detail);
    dl_log(row, "\n");
    if (dl_commit_or_report(d, row, false, reply, "rebased"))
        dl_step_reply(reply, row, "rebased");
}

static void dl_push_intent_blocked(const struct dl_row *row, bool required,
                                   struct zcl_command_reply *reply);

/* Signed intent gates every production push; only the isolated test
 * fixture may publish unsigned. A refusal names its exact row and pair plus
 * the one command that clears it (dl_push_intent_blocked, near attach),
 * because a driver that cannot tell which row to attach otherwise loops on
 * `attach --seq=` with nothing to target. */
static bool dl_push_intent_ready(const struct dl_dirs *d,
                                 const struct dl_row *row,
                                 struct zcl_command_reply *reply)
{
    const char *allow_unsigned = dl_allow_unsigned();
    bool fixture_unsigned = allow_unsigned && strcmp(allow_unsigned, "1") == 0 &&
                            dl_stub() != NULL;
    if (!fixture_unsigned && !row->publication_signature[0]) {
        dl_push_intent_blocked(row, true, reply);
        return false;
    }
    if (row->publication_signature[0] && !dl_publication_verify(d, row)) {
        dl_push_intent_blocked(row, false, reply);
        return false;
    }
    return true;
}

/* A durable push checkpoint says dispatch MAY have happened. If its reply was
 * lost and an independent fetch does not yet contain the head, the receiver
 * cannot distinguish a rejected mutation from an unsettled one. Keep the
 * exact intent; this step dispatches nothing further. */
static void dl_push_outcome_unknown(const struct dl_dirs *d,
                                    struct dl_row *row,
                                    const char *observed_main,
                                    struct zcl_command_reply *reply)
{
    static const char detail[] =
        "signed push outcome unknown; await independent remote receipt";
    if (strcmp(row->detail, detail) != 0) {
        (void)snprintf(row->detail, sizeof(row->detail), "%s", detail);
        if (!dl_commit_row(d, row, false)) {
            dl_fail(reply, "PUSH_OUTCOME_PERSIST_FAILED", "observe_remote",
                    "cannot retain the unresolved signed push checkpoint", d->land);
            return;
        }
    }
    (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
    (void)json_push_kv_str(&reply->data, "expected_base", row->base);
    (void)json_push_kv_str(&reply->data, "head_commit", row->local);
    (void)json_push_kv_str(&reply->data, "publication_target",
                           row->publication_target);
    (void)json_push_kv_str(&reply->data, "observed_remote_tip",
                           observed_main ? observed_main : "");
    (void)json_push_kv_str(&reply->data, "dispatch_state", "unknown");
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED,
                           "PUSH_OUTCOME_UNKNOWN", "observe_remote",
                           true, false,
                           "signed push outcome is unresolved; observe the exact remote before a successor",
                           observed_main ? observed_main : "remote observation unavailable");
    (void)snprintf(reply->error.next_action,
                   sizeof(reply->error.next_action), "%s",
                   "z23-dev dev land step");
}

/* dl_push_proven_pair is a compare-and-swap of refs/heads/main from base to
 * local. Once an independent fetch shows main at another commit that
 * provably does not contain local, that dispatch can never apply: its
 * outcome is settled as refused. Anything short of that proof (same base,
 * missing objects, git failure) leaves the outcome unknown. */
static bool dl_push_settled_refused(const struct dl_dirs *d,
                                    const struct dl_row *row,
                                    const char *observed_main)
{
    char out[512];
    const char *ancestor[] = { "--no-replace-objects", "merge-base",
        "--is-ancestor", row->local, observed_main, NULL };
    if (!observed_main || !dl_sha_ok(observed_main) ||
        !dl_sha_ok(row->base) || !dl_sha_ok(row->local) ||
        strcmp(observed_main, row->base) == 0 ||
        strcmp(observed_main, row->local) == 0)
        return false;
    return dl_git(d->wt, ancestor, out, sizeof(out), DL_GIT_TIMEOUT_MS) == 1;
}

static void dl_push_refused_log(const struct dl_row *row, const char *next,
                                const char *observed_main)
{
    char line[512];
    (void)snprintf(line, sizeof(line),
                   "signed push refused: main moved to %.64s without head; %s "
                   "seq=%lld base=%.64s local=%.64s "
                   "observed_main=%.64s\n",
                   observed_main, next, row->seq, row->base, row->local,
                   observed_main);
    dl_log(row, line);
}

/* May a later step send the same signed compare-and-swap again? Only when a
 * fresh independent observation shows main still at the signed base: the
 * head is absent, so the earlier dispatch did not apply, and the push is
 * `--force-with-lease=main:<base> <local>:main`, so sending it again can
 * reach no state the first dispatch could not — it lands this exact signed
 * pair or is refused. Each send consumes one of the row's attempts, so a
 * remote that keeps refusing stops being asked after DL_ATTEMPT_MAX and the
 * row reads as an unresolved checkpoint, exactly as a single lost dispatch
 * did before. Without this a dispatch lost on a quiet main waited for a
 * remote change that nothing was going to make, holding the single-flight
 * queue behind it (observed: nine hours, 2026-10-01). */
static bool dl_push_redispatch_allowed(const struct dl_row *row,
                                       const char *observed_main)
{
    return row->publication_signature[0] && observed_main &&
           !row->push_diagnostic_pending &&
           dl_sha_ok(observed_main) && dl_sha_ok(row->base) &&
           strcmp(observed_main, row->base) == 0 &&
           row->attempt < DL_ATTEMPT_MAX;
}

/* A signed push checkpoint settles as refused (successor, which clears the
 * publication so the new pair needs a new signature) once main has moved
 * without the head. On an unmoved main it stays unknown for this step; see
 * dl_push_redispatch_allowed() for what the next step may do. */
static void dl_push_checkpoint_settle(const struct dl_dirs *d,
                                      struct dl_row *row,
                                      const char *observed_main,
                                      struct zcl_command_reply *reply)
{
    if (!dl_push_settled_refused(d, row, observed_main)) {
        dl_push_outcome_unknown(d, row, observed_main, reply);
        return;
    }
    dl_push_refused_log(row, "successor", observed_main);
    dl_step_successor(d, row, observed_main, reply);
}

/* Cancel may drop a push checkpoint only once it is settled as refused.
 * Observe outside the queue lock; the caller re-reads the row under the
 * lock and requires the identical signed pair. */
static bool dl_cancel_push_settled(const struct dl_dirs *d, const char *qpath,
                                   long long seq, struct dl_row *settled)
{
    struct dl_row *rows = NULL;
    size_t nrows = 0;
    bool found = false;
    char observed[80];
    int lock = dl_rows_lock(d->land);
    if (lock < 0)
        return false;
    if (dl_load_rows(qpath, &rows, &nrows, NULL, 0)) {
        for (size_t i = 0; i < nrows && !found; i++) {
            if (rows[i].seq == seq && strcmp(rows[i].phase, "push") == 0) {
                *settled = rows[i];
                found = true;
            }
        }
    }
    free(rows);
    dl_unlock(lock);
    if (!found || !dl_wt_ready(d->wt) ||
        !dl_fetch_remote_main(d->wt, observed) ||
        !dl_push_settled_refused(d, settled, observed))
        return false;
    dl_push_refused_log(settled, "cancel", observed);
    return true;
}

static bool dl_push_pair_same(const struct dl_row *a, const struct dl_row *b)
{
    return strcmp(a->local, b->local) == 0 &&
           strcmp(a->base, b->base) == 0 &&
           strcmp(a->publication_signature, b->publication_signature) == 0;
}

static bool dl_publication_held(const struct dl_row *row,
                                 struct zcl_command_reply *reply)
{
    if (!row->publication_hold) return false;
    dl_fail(reply, "PUBLICATION_HELD", "publication",
            "candidate may be proven but cannot be sealed or published until released",
            "retained publication hold");
    (void)json_push_kv_int(&reply->data, "seq", row->seq);
    (void)json_push_kv_bool(&reply->data, "publication_hold", true);
    return true;
}

static bool dl_push_allowed(const struct dl_dirs *d, const struct dl_row *row,
                              struct zcl_command_reply *reply)
{
    return !dl_publication_held(row, reply) && dl_push_intent_ready(d, row, reply);
}

static void dl_step_push(const struct dl_dirs *d, struct dl_row *row,
                          struct zcl_command_reply *reply)
{
    char buf[DL_GIT_CAP], observed_main[80];
    /* The legacy pair receipt is proof of a build, not publication authority.
     * Keep unsigned landing confined to the existing isolated test fixture;
     * production must wait for a verified, durable canonical intent. */
    if (!dl_push_allowed(d, row, reply))
        return;
    if (!dl_observe_remote_main(d, row, observed_main, false, reply))
        return;
    if (strcmp(observed_main, row->base) != 0) {
        dl_step_successor(d, row, observed_main, reply);
        return;
    }
    /* A restart must be able to distinguish an unattempted proven pair from
     * a push whose result was lost. Commit the exact pair and transition
     * before Git can mutate the remote; failed persistence forbids dispatch. */
    /* Reflush even when a prior attempt left phase=push: a failed directory
     * sync can leave the renamed row visible without proving its durability. */
    (void)snprintf(row->phase, sizeof(row->phase), "push");
    row->push_diagnostic_pending = true;
    if (!dl_commit_row(d, row, false)) {
        dl_log(row, "pre-push checkpoint failed; remote untouched\n");
        (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED,
                               "PUSH_INTENT_PERSIST_FAILED", "push_intent",
                               true, false,
                               "cannot persist the exact push pair; retry before dispatch",
                               d->land);
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action), "%s",
                       "z23-dev dev land step");
        return;
    }
    {
        /* No --no-verify: this pushes through the installed pre-push hook
         * like everyone else. dl_wt_ensure() already armed d->wt's own
         * hooks, and the exact-receipt admission the hook performs
         * (tools/dev/z23_git_hook.c) finds the very receipt this step just
         * obtained for (local, base) at
         * .cache/zcl-dev-proof/receipts/<local>-<base>.receipt, so the hook
         * admits in seconds instead of re-running the proof. */
        bool recorded = false;
        bool acknowledged = dl_push_proven_pair(d, row, buf, sizeof(buf),
                                                 &recorded);
        if (recorded) {
            row->push_diagnostic_pending = false;
            if (!dl_commit_row(d, row, false)) {
                /* The previous durable checkpoint still forbids redispatch.
                 * Continue independent observation: a real landing must keep
                 * the established landed-with-persist-failed recovery path. */
                (void)json_push_kv_str(&reply->data,
                                       "push_diagnostic_checkpoint", "pending");
            }
        }
        if (!acknowledged) {
            /* A failed client acknowledgement does not prove rejection.
             * Reconcile before consuming the final attempt or discarding
             * the durable request. An unavailable remote leaves it intact. */
            dl_log(row, buf);
            dl_log(row, "\n");
            if (dl_reconcile_landing(d, row, observed_main, true, reply))
                return;
            if (row->publication_signature[0]) {
                dl_push_checkpoint_settle(d, row, observed_main, reply);
                return;
            }
            if (strcmp(observed_main, row->base) != 0) {
                dl_step_successor(d, row, observed_main, reply);
                return;
            }
            row->attempt++;
            (void)snprintf(row->phase, sizeof(row->phase), "rebase");
            (void)snprintf(row->detail, sizeof(row->detail), "%s",
                           "the fast-forward push was refused; rebasing");
            dl_log_path(d, row);
            dl_log(row, row->detail);
            dl_log(row, "\n");
            if (row->attempt > DL_ATTEMPT_MAX) {
                (void)snprintf(row->state, sizeof(row->state), "failed");
                (void)snprintf(row->dimension, sizeof(row->dimension),
                               "push");
                if (dl_commit_or_report(d, row, true, reply, "failed"))
                    dl_step_reply(reply, row, "failed");
                return;
            }
            if (dl_commit_or_report(d, row, false, reply, "rebased"))
                dl_step_reply(reply, row, "rebased");
            return;
        }
    }
    /* A successful push acknowledgement is not a fresh remote observation.
     * Keep the inflight request until the remote independently confirms it. */
    if (!dl_reconcile_landing(d, row, observed_main, true, reply)) {
        dl_log(row, "post-push remote main does not confirm the candidate; "
                    "retaining request for retry\n");
        (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED,
                               "REMOTE_RESULT_UNCONFIRMED", "observe_remote",
                               true, true,
                               "remote main does not confirm this candidate; retry observation",
                               observed_main);
        (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                       "%s", "z23-dev dev land step");
        return;
    }
}

static bool dl_resume_proof_read(const struct dl_dirs *d, struct dl_row *row,
                                  const char *observed_main,
                                  char dimension[48], char detail[512],
                                  enum dl_proof *p,
                                  struct zcl_command_reply *reply)
{
    if (strcmp(observed_main, row->base) != 0) {
        dl_step_successor(d, row, observed_main, reply);
        return false;
    }
    if ((!dl_sha_ok(row->tree) || !row->proof_intent[0]) &&
        (!dl_proof_intent_bind(d, row) || !dl_commit_row(d, row, false))) {
        dl_fail(reply, "PROOF_INTENT_UNAVAILABLE", "prove",
                "cannot recover the prepared tree and exact proof pair",
                d->land);
        return false;
    }
    int64_t started = platform_time_monotonic_us();
    *p = dl_proof_read(d->wt, row->local, row->base, dimension,
                       48, detail, 512);
    dl_beat(row, "proof_status", started);
    if (*p == DL_PROOF_MISSING) {
        dl_log(row, "proof worker missing; requeueing the persisted pair\n");
        *p = dl_proof_request(d->wt, row->local, row->base, detail, 512);
    }
    (void)snprintf(row->detail, sizeof(row->detail), "%s", detail);
    return true;
}

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
enum dl_recover {
    DL_RECOVER_OK = 0,
    DL_RECOVER_RETRY_REFUSED = -1,
    DL_RECOVER_UNAVAILABLE = -2,
};
static bool dl_producer_stale(const char *detail);
static int dl_producer_recover(const char *root, const char *local,
                               const char *base, char *why, size_t why_cap);

/* A producer-stale refusal is a verdict on the proof binary, not on the
 * candidate: do what `dev land drive` does — rebuild the producer in the
 * landing worktree and prove again — once per row until main moves. Returns true when
 * the step is answered; false leaves the failure to settle as before, with
 * the recovery noted in the row detail when one was tried. */
static bool dl_resume_producer_stale(const struct dl_dirs *d,
                                     struct dl_row *row,
                                     const char detail[512],
                                     struct zcl_command_reply *reply)
{
    char why[256];
    int rc;
    if (!dl_producer_stale(detail))
        return false;
    if (row->producer_recovered) {
        (void)snprintf(row->detail, sizeof(row->detail),
                       "%.500s; producer recovery tried once", detail);
        return false;
    }
    row->producer_recovered = 1;
    (void)snprintf(row->detail, sizeof(row->detail),
                   "producer recovery started: %.400s", detail);
    if (!dl_commit_row(d, row, false)) {
        dl_fail(reply, "QUEUE_WRITE_FAILED", "prove",
                "cannot persist the producer recovery mark", d->land);
        return true;
    }
    dl_log(row, "producer source mismatch; rebuilding the producer from the "
                "candidate and proving again\n");
    rc = dl_producer_recover(d->wt, row->local, row->base, why, sizeof(why));
    if (rc != DL_RECOVER_OK) {
        (void)snprintf(row->detail, sizeof(row->detail),
                       "%.400s; producer recovery tried once and failed: %.64s",
                       detail, why);
        dl_log(row, row->detail);
        dl_log(row, "\n");
        return false;
    }
    (void)snprintf(row->detail, sizeof(row->detail),
                   "producer rebuilt from the candidate; proof re-run: %.400s",
                   detail);
    if (dl_commit_or_report(d, row, false, reply, "proving"))
        dl_step_reply(reply, row, "proving");
    return true;
}

/* An interrupted run (a requester signal, an outer timeout, the base probe)
 * is not a verdict on the candidate: re-run the same exact pair rather than
 * settle the request as failed, bounded by DL_ATTEMPT_MAX so a candidate
 * that interrupts its own proof still ends. Returns false when the bound is
 * spent and the caller should settle the failure as before. Never PASS. */
static bool dl_resume_interrupted_proof(const struct dl_dirs *d,
                                        struct dl_row *row,
                                        const char detail[512],
                                        struct zcl_command_reply *reply)
{
    if (row->attempt >= DL_ATTEMPT_MAX)
        return false;
    dl_log(row, "interrupted exact proof; re-running the same pair\n");
#ifdef ZCL_DEV_BUILD
    if (!dl_stub()) {
        struct zcl_dev_proof_status status = {0};
        if (!zcl_dev_proof_retry(d->wt, row->local, row->base, &status)) {
            /* Nothing mutated: the row stays in flight for the next step. */
            (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                                   ZCL_COMMAND_EXIT_BLOCKED,
                                   "PROOF_RETRY_REFUSED", "prove", true, false,
                                   "the interrupted pair could not be re-queued yet; retry this step",
                                   status.detail[0] ? status.detail
                                                    : "proof_retry_refused");
            return true;
        }
    }
#endif
    row->attempt++;
    (void)snprintf(row->detail, sizeof(row->detail),
                   "interrupted proof re-queued: %.400s", detail);
    if (dl_commit_or_report(d, row, false, reply, "proving"))
        dl_step_reply(reply, row, "proving");
    return true;
}
#endif

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
/* The proof status reader classifies a producer-source refusal as NO_VERDICT,
 * which dl_proof_status_map reads as pending. Left pending, a step that
 * cannot rebuild the producer would hold the row in flight forever, so the
 * step treats it as the failure it is: one bounded recovery, then settled. */
static void dl_resume_stale_no_verdict(enum dl_proof *p, char dimension[48],
                                       const char detail[512])
{
    if (*p != DL_PROOF_PENDING ||
        strcmp(dimension, "proof_no_verdict") != 0 ||
        !dl_producer_stale(detail))
        return;
    *p = DL_PROOF_FAILED;
    (void)snprintf(dimension, 48, "%s", "proof_producer_source_mismatch");
}
#endif

static void dl_resume_failed_proof(const struct dl_dirs *d,
                                    struct dl_row *row,
                                    const char dimension[48],
                                    const char detail[512],
                                    struct zcl_command_reply *reply)
{
    char base_now[80];
    dl_log(row, "failed exact proof: ");
    dl_log(row, detail);
    dl_log(row, "\n");
    if (!dl_observe_remote_main(d, row, base_now, false, reply))
        return;
    if (strcmp(base_now, row->base) != 0) {
        dl_step_successor(d, row, base_now, reply);
        return;
    }
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    if (dl_resume_producer_stale(d, row, detail, reply))
        return;
    if (zcl_dev_proof_failure_interrupted(detail) &&
        dl_resume_interrupted_proof(d, row, detail, reply))
        return;
#endif
    bool host_load = dl_host_load_failure(detail);
    dl_log(row, detail);
    dl_log(row, "\n");
    if (host_load && row->attempt < DL_ATTEMPT_MAX) {
        row->attempt++;
        (void)snprintf(row->phase, sizeof(row->phase), "rebase");
        (void)snprintf(row->dimension, sizeof(row->dimension), "host_load");
        dl_log_path(d, row);
        if (dl_commit_or_report(d, row, false, reply, "rebased"))
            dl_step_reply(reply, row, "rebased");
        return;
    }
    (void)snprintf(row->state, sizeof(row->state), "failed");
    (void)snprintf(row->dimension, sizeof(row->dimension), "%s",
                   dimension[0] ? dimension : "proof");
    if (!row->detail[0])
        (void)snprintf(row->detail, sizeof(row->detail), "%s", detail);
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    dl_failed_proof_evidence(d, row, detail);
#endif
    if (dl_commit_or_report(d, row, true, reply, "failed"))
        dl_step_reply(reply, row, "failed");
}
#if defined(ZCL_TESTING)
static void dl_test_die_after_proof(void)
{
    /* Hard death before any landing transition is persisted. */
    if (getenv("ZCL_LAND_TEST_DIE_AFTER_PROOF")) _exit(82);
}
#endif

#ifdef ZCL_DEV_BUILD
/* The resident proof watcher is armed only on explicit request; a pending
 * proof with the arm set but no watcher names its absence instead of
 * waiting quietly. */
static void dl_resume_pending_watcher_kick(const struct dl_dirs *d,
                                           struct dl_row *row)
{
    const char *arm = getenv("ZCL_LAND_START_PROOF_WATCHER");
    if (!dl_stub() && arm && strcmp(arm, "1") == 0 &&
        !zcl_native_dev_loop_proof_queue_ready(d->wt)) {
        (void)snprintf(row->detail, sizeof(row->detail), "%s",
                       "resident_proof_watcher_absent");
        dl_watcher_kick(d->wt, row->detail, sizeof(row->detail));
    }
}
#endif

/* Read the proof's own state for the in-flight request and act once.
 * Windows refuses step before entering this POSIX-only call graph. */
[[maybe_unused]] static void dl_step_resume(const struct dl_dirs *d, struct dl_row *row,
                           struct zcl_command_reply *reply,
                           char observed_main[80])
{
    char detail[512], dimension[48];
    enum dl_proof p;

    /* A prior step can have pushed for real and then failed to persist
     * "landed" (a queue-commit failure after the fact — see
     * dl_commit_or_report). That leaves the row inflight with a STALE
     * phase="prove" pointing at a (local, base) pair that already landed:
     * dl_proof_read would report PASSED again, and the "base moved" check
     * below would misread the row's own successful push as a stranger's
     * commit and spend a whole extra rebase/proof cycle on it. Check
     * first, the same way dl_step_start does before ever starting one. */
    if (dl_reconcile_landing(d, row, observed_main, false, reply))
        return;
    if (strcmp(row->phase, "push") == 0 &&
        row->publication_signature[0]) {
        /* The reconcile above just fetched and found the head absent.  When
         * main has ALSO moved off the signed base, that exact pair can never
         * fast-forward — no in-flight or retried dispatch of it can land
         * later — so awaiting its remote receipt wedges the row (and the
         * single-flight queue behind it) forever.  Take the ordinary
         * successor path: the stale signed intent is logged, the exact pair
         * is never redispatched, and the requeued row re-proves and re-signs
         * a fresh pair on the new base.  Base unmoved sends the same signed
         * compare-and-swap again while the row has attempts left. */
        if (dl_push_redispatch_allowed(row, observed_main)) {
            row->attempt++;
            dl_log(row, "signed push did not apply and main is unmoved; "
                        "sending the same compare-and-swap again\n");
            dl_step_push(d, row, reply);
            return;
        }
        dl_push_checkpoint_settle(d, row, observed_main, reply);
        return;
    }
    if (!dl_resume_phase_ready(row->phase)) {
        /* A step died between phases. Re-drive from the rebase rather than
         * guessing what the dead step had already done. */
        (void)snprintf(row->phase, sizeof(row->phase), "rebase");
        dl_prepare(d, row, reply, observed_main);
        return;
    }
    if (!dl_resume_proof_read(d, row, observed_main, dimension, detail, &p, reply))
        return;
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    dl_resume_stale_no_verdict(&p, dimension, detail);
#endif
    if (p == DL_PROOF_PENDING) {
#ifdef ZCL_DEV_BUILD
        dl_resume_pending_watcher_kick(d, row);
#endif
        dl_window_tick(d, row);
        if (dl_commit_or_report(d, row, false, reply, "proving"))
            dl_step_reply(reply, row, "proving");
        return;
    }
    if (p != DL_PROOF_PASSED) {
        dl_resume_failed_proof(d, row, dimension, detail, reply);
        return;
    }
#if defined(ZCL_TESTING)
    dl_test_die_after_proof();
#endif
    /* The proof passed for THIS (local, base) pair. If main moved while it
     * ran, the receipt is about a base nobody is on any more: rebase again
     * and prove again rather than pushing evidence that no longer applies. */
    {
        char base_now[80];
        if (!dl_observe_remote_main(d, row, base_now, false, reply))
            return;
        if (strcmp(base_now, row->base) != 0) {
            dl_step_successor(d, row, base_now, reply);
            return;
        }
    }
    dl_step_push(d, row, reply);
}

/* ── queued-row conflict precheck ─────────────────────────────────────────
 *
 * WHY. One exact proof runs at a time, so a row queued behind it waits the
 * whole proof out and only then, in the first seconds of dl_rebase(),
 * learns that main moved into a conflicting state while it waited (land
 * seqs 102/103: ~69 minutes queued, then conflict/rebase in under 5 s).
 * Every beat that drives the in-flight row already holds a fresh
 * observation of origin main. After that beat, while a row is still in
 * flight, each queued row is replayed onto that observation IN THE OBJECT
 * STORE ONLY, and a row that certainly cannot rebase ends as the same
 * `conflict` outcome dl_rebase() would record — one beat after main moved
 * instead of one proof later.
 *
 * SEMANTICS. The replay is the one dl_rebase() performs: nothing when the
 * observed main is already an ancestor of the tip (the integrated path);
 * otherwise the tip's net change as ONE commit on merge-base(main, tip)
 * when merges lie past that base (dl_linearize_for_rebase()), else the
 * tip's own commits; minus every commit whose patch main already carries
 * (exactly the set `git rebase` drops); each replayed with its parent as
 * the merge base onto the previous result by `git merge-tree
 * --write-tree`, the same ort merge a rebase pick runs.
 *
 * VERDICTS. Only CERTAINTY ends a row. CONFLICT: the first conflicting
 * replay names a path outside the regenerated-artifact table — dl_rebase()
 * stops on that same commit, dl_rebase_autoresolve() declines it, and the
 * rebase aborts as a conflict. CLEAN: every replay merged. DEFERRED: a
 * settled answer that is not a conflict — the first conflicting replay
 * touches only regenerated artifacts (dl_rebase() settles those and
 * replays on, past what this check follows), or the replay is longer than
 * DL_PRECHECK_COMMITS. CLEAN and DEFERRED rows are marked as checked for
 * this main. UNCERTAIN: anything else — git failing, crashing or timing
 * out, a missing object or unresolvable ref, a capture that may be
 * truncated, an empty or unparseable conflict list. The row is left
 * exactly as it was, unmarked, so the next beat asks again; the reason is
 * logged. In every non-CONFLICT case the real rebase, the exact proof and
 * the expected-base publication decide, unchanged. The verdict is about
 * the main observed now; the in-flight row may still change main before
 * the queued row's turn, exactly as for any rebase that ran now.
 *
 * BOUNDS. Rows are taken in the order dl_step_pick_row() will start them
 * (priority, then seq), at most DL_PRECHECK_ROWS per beat, and the whole
 * check stops at a DL_PRECHECK_BUDGET_MS wall-clock deadline that every
 * git spawn inside it is also held to: a row not reached is left exactly
 * as it is, and a replay the deadline cut short is uncertain (one of the
 * row's tries below, so no replay too slow for any beat holds every
 * beat). A row is replayed at most once per observed main once it has a
 * settled verdict, and at most DL_PRECHECK_TRIES times per observed main
 * while it stays uncertain, after which one log line says it is left to
 * its real rebase until main moves: every beat is a fresh process, so
 * both are kept in the row (`prechecked_main`, `precheck_uncertain_main`
 * and `precheck_uncertain`), and precheck.log grows by a bounded number
 * of lines per row per main. MERGE ATTRIBUTES come from the commit each
 * replay merges onto, as they do for the rebase pick (see
 * dl_precheck_merge()), never from the landing checkout. Nothing is
 * fetched, nothing is pushed, and the landing worktree's index and
 * checkout — which a running proof may be reading — are never touched:
 * merge-tree and commit-tree only add objects, and a multi-commit replay
 * leaves its intermediate commits unreferenced for git's own garbage
 * collection. The in-flight row is never rewritten by this check and no
 * queued row is reordered. */

#define DL_PRECHECK_ROWS 4
#define DL_PRECHECK_COMMITS 64
/* One beat's whole precheck, every git spawn inside it included, ends by
 * this wall-clock budget, so step.lock is never held for minutes on the
 * check's account. */
#define DL_PRECHECK_BUDGET_MS 20000
/* Uncertain answers a row may give against one observed main before the
 * check leaves it alone until main moves. */
#define DL_PRECHECK_TRIES 3

enum dl_precheck {
    DL_PRECHECK_UNCERTAIN = 0, /* unmarked; the next beat asks again */
    DL_PRECHECK_CLEAN,
    DL_PRECHECK_DEFERRED,      /* settled, not a conflict: real rebase */
    DL_PRECHECK_CONFLICT,
};

/* One beat's check: where it runs, the main it replays onto, the deadline
 * every spawn is held to, the shared git capture and the current row's
 * verdict reason. */
struct dl_pc {
    const struct dl_dirs *d;
    const char *main;
    int64_t deadline;
    bool expired;
    char *buf;
    size_t cap;
    char why[DL_REGEN_PATHS_CAP + 128];
};

static const char *dl_precheck_word(enum dl_precheck v)
{
    switch (v) {
    case DL_PRECHECK_CLEAN: return "clean";
    case DL_PRECHECK_DEFERRED: return "deferred";
    case DL_PRECHECK_CONFLICT: return "conflict";
    case DL_PRECHECK_UNCERTAIN: break;
    }
    return "uncertain";
}

/* Test-only: make the merge step itself fail the way a crashed or refused
 * git does (a usage error, exit 129), so the uncertain path is exercised
 * through the real spawn rather than a hand-set verdict. Never read
 * outside a test or dev build, the same guard as dl_stub(). */
static bool dl_precheck_tool_fail(void)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    const char *s = getenv("ZCL_LAND_TEST_PRECHECK_TOOL_FAIL");
    return s && s[0];
#else
    return false;
#endif
}

/* The beat's budget. A test or dev build may only shorten it, down to
 * zero, to reach the deadline path without waiting it out. */
static int64_t dl_precheck_budget_ms(void)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    const char *s = getenv("ZCL_LAND_TEST_PRECHECK_BUDGET_MS");
    char *end = NULL;
    long long v = s && s[0] ? strtoll(s, &end, 10) : -1;
    if (end && *end == '\0' && v >= 0 && v < DL_PRECHECK_BUDGET_MS)
        return v;
#endif
    return DL_PRECHECK_BUDGET_MS;
}

static void dl_precheck_log(const struct dl_dirs *d, const char *line)
{
    char path[4096 + 32];
    if (snprintf(path, sizeof(path), "%s/precheck.log", d->logs) >=
        (int)sizeof(path))
        return;
    (void)dl_append_text(path, line);
}

/* One line per replayed row in logs/precheck.log: what was checked,
 * against which main, and what the check concluded or why it could not. */
static void dl_precheck_note(const struct dl_dirs *d, const struct dl_row *row,
                             const char *observed_main, const char *verdict,
                             const char *why)
{
    char line[1536], ts[64];
    dl_now_iso(ts);
    (void)snprintf(line, sizeof(line), "%s seq=%lld tip=%s main=%s %s%s%s\n",
                   ts, row->seq, row->tip, observed_main, verdict,
                   why && why[0] ? ": " : "", why ? why : "");
    dl_precheck_log(d, line);
}

static enum dl_precheck dl_precheck_uncertain(struct dl_pc *pc,
                                              const char *reason)
{
    (void)snprintf(pc->why, sizeof(pc->why), "%s", reason);
    return DL_PRECHECK_UNCERTAIN;
}

static bool dl_pc_expired(struct dl_pc *pc)
{
    if (!pc->expired && platform_time_monotonic_ms() >= pc->deadline)
        pc->expired = true;
    return pc->expired;
}

/* dl_git() held to the beat's deadline. A spawn that runs into it may have
 * been killed mid-output, so its answer is never read: -1, as for a launch
 * that failed. */
static int dl_pc_git(struct dl_pc *pc, const char *const *args, char *out,
                     size_t cap)
{
    if (out && cap)
        out[0] = '\0';
    if (dl_pc_expired(pc))
        return -1;
    int64_t left = pc->deadline - platform_time_monotonic_ms();
    int rc = dl_git(pc->d->wt, args, out, cap, left > 0 ? (int)left : 1);
    return dl_pc_expired(pc) ? -1 : rc;
}

/* dl_rev_parse() held to the beat's deadline. */
static bool dl_pc_rev(struct dl_pc *pc, const char *what, char out[80])
{
    char spec[160], got[96];
    const char *args[] = { "rev-parse", "--verify", "--quiet", spec, NULL };
    if (snprintf(spec, sizeof(spec), "%s^{commit}", what) >=
            (int)sizeof(spec) ||
        dl_pc_git(pc, args, got, sizeof(got)) != 0)
        return false;
    dl_trim(got);
    if (!dl_sha_ok(got))
        return false;
    (void)snprintf(out, 80, "%s", got);
    return true;
}

/* A commit object for `tree` on `parent`, written to the object store and
 * referenced by nothing. Unsigned on purpose: it is never published, only
 * named as the next replay's upstream side. */
static bool dl_precheck_commit(struct dl_pc *pc, const char *tree,
                               const char *parent, char out[80])
{
    const char *args[] = { "--no-replace-objects", "-c", "user.name=dev.land",
                           "-c", "user.email=dev.land@localhost",
                           "commit-tree", "--no-gpg-sign", tree, "-p", parent,
                           "-m", "dev.land queued-row precheck (never published)",
                           NULL };
    if (dl_pc_git(pc, args, out, 80) != 0)
        return false;
    dl_trim(out);
    return dl_sha_ok(out);
}

/* merge-base(main, tip) and whether merges lie past it: the two facts
 * dl_linearize_for_rebase() shapes the replay from. */
static bool dl_precheck_base(struct dl_pc *pc, const char *tip, char mb[80],
                             bool *merges)
{
    char range[176], found[80];
    const char *mb_args[] = { "--no-replace-objects", "merge-base", pc->main,
                              tip, NULL };
    const char *merges_args[] = { "rev-list", "--merges", "--max-count=1",
                                  range, NULL };
    if (dl_pc_git(pc, mb_args, mb, 80) != 0)
        return false;
    dl_trim(mb);
    (void)snprintf(range, sizeof(range), "%s..%s", mb, tip);
    if (!dl_sha_ok(mb) ||
        dl_pc_git(pc, merges_args, found, sizeof(found)) != 0)
        return false;
    dl_trim(found);
    *merges = found[0] != '\0';
    return true;
}

/* The commit whose replay set `git rebase` would walk, shaped the way
 * dl_tip_checkout() shapes it. CLEAN with `*replay` false when dl_rebase()
 * would replay nothing (main already an ancestor of the tip), CLEAN with
 * `*replay` true and `head` set when there is a replay to run, UNCERTAIN
 * with the reason otherwise. */
static enum dl_precheck dl_precheck_head(struct dl_pc *pc,
                                         const struct dl_row *row,
                                         char head[80], bool *replay)
{
    char tip[80], mb[80], tree[96];
    bool merges = false;
    const char *anc_args[] = { "--no-replace-objects", "merge-base",
                               "--is-ancestor", pc->main, tip, NULL };
    if (!dl_pc_rev(pc, row->tip, tip))
        return dl_precheck_uncertain(pc, "tip not in the landing object "
                                         "store");
    int rc = dl_pc_git(pc, anc_args, NULL, 0);
    if (rc == 0)
        return DL_PRECHECK_CLEAN;
    if (rc != 1)
        return dl_precheck_uncertain(pc, "cannot establish tip ancestry");
    if (!dl_precheck_base(pc, tip, mb, &merges))
        return dl_precheck_uncertain(pc, "no merge base or merge list with "
                                         "main");
    (void)snprintf(head, 80, "%s", tip);
    (void)snprintf(tree, sizeof(tree), "%s^{tree}", tip);
    if (merges && !dl_precheck_commit(pc, tree, mb, head))
        return dl_precheck_uncertain(pc, "cannot cut the linear candidate "
                                         "commit");
    *replay = true;
    return DL_PRECHECK_CLEAN;
}

/* The commits `git rebase <main>` would pick, oldest first: right-side,
 * non-merge, and not patch-equivalent to anything main already carries.
 * Returns their count, or -1 when git fails or the capture may be
 * truncated. */
static int dl_precheck_list(struct dl_pc *pc, const char *head)
{
    char range[176];
    int n = 0;
    const char *args[] = { "--no-replace-objects", "rev-list",
                           "--cherry-pick", "--right-only", "--no-merges",
                           "--topo-order", "--reverse", range, NULL };
    (void)snprintf(range, sizeof(range), "%s...%s", pc->main, head);
    if (dl_pc_git(pc, args, pc->buf, pc->cap) != 0 ||
        strlen(pc->buf) + 1 >= pc->cap)
        return -1;
    for (const char *p = pc->buf; *p; p++) {
        if (*p == '\n' && n < INT_MAX)
            n++;
    }
    return n;
}

/* One rebase pick as an in-core merge: `theirs` onto `ours` with `base`
 * (its parent) as the merge base. CLEAN fills `tree`; CONFLICT points
 * `paths` at git's newline-separated conflicted-path list inside the
 * capture. Exit 1 is also how merge-tree reports a refused argument, so a
 * conflict needs a tree id first and at least one path after it.
 *
 * Merge attributes (a `merge=union` driver, say) come from `ours`, never
 * from the landing checkout: a rebase pick runs with the checkout at the
 * commit it picks onto, so that is the .gitattributes it merges under,
 * while this checkout holds whatever row is in flight. `ours` is always a
 * commit already in the store (the observed main or a replay this check
 * wrote), which matters: git 2.43 reads an --attr-source it cannot find
 * as no attributes at all rather than refusing. */
static enum dl_precheck dl_precheck_merge(struct dl_pc *pc, const char *base,
                                          const char *ours,
                                          const char *theirs, char tree[80],
                                          char **paths)
{
    char mb[96], attr[96];
    const char *args[] = { "--no-replace-objects", attr, "merge-tree",
                           "--write-tree", "--name-only", "--no-messages", mb,
                           ours, theirs, NULL };
    (void)snprintf(mb, sizeof(mb), "--merge-base=%s", base);
    (void)snprintf(attr, sizeof(attr), "--attr-source=%s", ours);
    if (dl_precheck_tool_fail())
        args[3] = "--precheck-test-tool-failure";
    int rc = dl_pc_git(pc, args, pc->buf, pc->cap);
    char *nl = strchr(pc->buf, '\n');
    if ((rc != 0 && rc != 1) || strlen(pc->buf) + 1 >= pc->cap || !nl)
        return DL_PRECHECK_UNCERTAIN;
    *nl = '\0';
    if (!dl_sha_ok(pc->buf))
        return DL_PRECHECK_UNCERTAIN;
    (void)snprintf(tree, 80, "%s", pc->buf);
    *paths = nl + 1;
    dl_trim(*paths);
    if (rc == 0)
        return (*paths)[0] ? DL_PRECHECK_UNCERTAIN : DL_PRECHECK_CLEAN;
    return (*paths)[0] ? DL_PRECHECK_CONFLICT : DL_PRECHECK_UNCERTAIN;
}

/* A conflicted-path list dl_rebase() could not settle is a conflict, named
 * the way dl_rebase() names it (newlines as spaces). A list of regenerated
 * artifacts alone is not: dl_rebase_autoresolve() settles it and the
 * rebase replays on past what this check can follow. The list is known
 * complete here (dl_precheck_merge() refuses a capture that may be
 * truncated), and a list too long for dl_regen_only() to hold cannot be
 * the three artifacts alone: git names each path once. */
static enum dl_precheck dl_precheck_classify(struct dl_pc *pc,
                                             const char *paths)
{
    bool seen[DL_REGEN_N] = { false };
    if (dl_regen_only(paths, seen)) {
        (void)snprintf(pc->why, sizeof(pc->why), "%s",
                       "conflicts only on regenerated artifacts");
        return DL_PRECHECK_DEFERRED;
    }
    (void)snprintf(pc->why, sizeof(pc->why), "%s", paths);
    for (char *p = pc->why; *p; p++) {
        if (*p == '\n')
            *p = ' ';
    }
    return DL_PRECHECK_CONFLICT;
}

/* The upstream side for the replay after `at`, when there is one. dl_git()
 * clears its output before it runs, so the next side is built in its own
 * buffer rather than over the parent it names. */
static bool dl_precheck_advance(struct dl_pc *pc, const char *tree,
                                char ours[80])
{
    char next[80];
    if (!dl_precheck_commit(pc, tree, ours, next))
        return false;
    (void)snprintf(ours, 80, "%s", next);
    return true;
}

/* Replay each listed commit in order; see the SEMANTICS note above. */
static enum dl_precheck dl_precheck_replay(struct dl_pc *pc, char *list,
                                           int count)
{
    char ours[80], parent[80], tree[80], spec[96];
    char *save = NULL, *paths = NULL;
    int at = 0;
    (void)snprintf(ours, sizeof(ours), "%s", pc->main);
    for (char *c = strtok_r(list, "\n", &save); c;
         c = strtok_r(NULL, "\n", &save), at++) {
        (void)snprintf(spec, sizeof(spec), "%s^", c);
        if (!dl_sha_ok(c) || !dl_pc_rev(pc, spec, parent))
            return dl_precheck_uncertain(pc, "a replayed commit's parent is "
                                             "missing");
        enum dl_precheck v = dl_precheck_merge(pc, parent, ours, c, tree,
                                               &paths);
        if (v == DL_PRECHECK_CONFLICT)
            return dl_precheck_classify(pc, paths);
        if (v != DL_PRECHECK_CLEAN)
            return dl_precheck_uncertain(pc, "merge-tree failed, timed out "
                                             "or gave no complete verdict");
        if (at + 1 < count && !dl_precheck_advance(pc, tree, ours))
            return dl_precheck_uncertain(pc, "cannot record an intermediate "
                                             "replay");
    }
    return DL_PRECHECK_CLEAN;
}

static enum dl_precheck dl_precheck_row(struct dl_pc *pc,
                                        const struct dl_row *row)
{
    char head[80];
    bool replay = false;
    enum dl_precheck shape = dl_precheck_head(pc, row, head, &replay);
    if (shape != DL_PRECHECK_CLEAN || !replay)
        return shape;
    int count = dl_precheck_list(pc, head);
    if (count < 0)
        return dl_precheck_uncertain(pc, "the replay list is unavailable");
    if (count > DL_PRECHECK_COMMITS) {
        (void)snprintf(pc->why, sizeof(pc->why),
                       "%d commits to replay, over the bound", count);
        return DL_PRECHECK_DEFERRED;
    }
    if (count == 0)
        return DL_PRECHECK_CLEAN;
    /* The list moves out of the capture, which each merge below reuses. */
    char list[(DL_PRECHECK_COMMITS + 1) * 41];
    (void)snprintf(list, sizeof(list), "%s", pc->buf);
    return dl_precheck_replay(pc, list, count);
}

/* End a queued row the way dl_step_start() ends a rebase conflict: the
 * terminal outcome row and its mail note through dl_commit_row(). */
static bool dl_precheck_end(const struct dl_dirs *d, struct dl_row *row,
                            const char *observed_main, const char *paths)
{
    (void)snprintf(row->state, sizeof(row->state), "conflict");
    (void)snprintf(row->dimension, sizeof(row->dimension), "rebase");
    dl_row_move_base(row, observed_main);
    (void)snprintf(row->detail, sizeof(row->detail),
                   "detected while queued on main %s: %s", observed_main,
                   paths);
    dl_log_path(d, row);
    dl_log(row, "rebase conflict: ");
    dl_log(row, row->detail);
    dl_log(row, "\n");
    return dl_commit_row(d, row, true);
}

/* A row this beat replayed, and whether its verdict settled. */
struct dl_precheck_seen {
    long long seq;
    char tip[80];
    bool settled;
};

/* Fold one verdict into the row as it now stands: a settled verdict marks
 * the row checked for this main; an uncertain one counts against this main
 * only, and the attempt that reaches DL_PRECHECK_TRIES is logged once, as
 * the last word on this row until main moves. */
static void dl_precheck_record(const struct dl_dirs *d, struct dl_row *row,
                               const struct dl_precheck_seen *s,
                               const char *observed_main)
{
    char why[160];
    if (s->settled) {
        (void)snprintf(row->prechecked, sizeof(row->prechecked), "%s",
                       observed_main);
        row->uncertain_main[0] = '\0';
        row->uncertain_tries = 0;
        return;
    }
    if (strcmp(row->uncertain_main, observed_main) != 0) {
        (void)snprintf(row->uncertain_main, sizeof(row->uncertain_main), "%s",
                       observed_main);
        row->uncertain_tries = 0;
    }
    if (row->uncertain_tries >= DL_PRECHECK_TRIES)
        return;
    if (++row->uncertain_tries < DL_PRECHECK_TRIES)
        return;
    (void)snprintf(why, sizeof(why),
                   "uncertain %d times on this main; not rechecked until "
                   "main moves, the real rebase decides",
                   DL_PRECHECK_TRIES);
    dl_precheck_note(d, row, observed_main, "left", why);
}

/* Record, under the row lock, what this beat learned about the rows in
 * `seen`. A row cancelled, started or rewritten since it was read is left
 * exactly as it now is. No mail: nothing about the request moved. */
static bool dl_precheck_mark(const struct dl_dirs *d, const char *observed_main,
                             const struct dl_precheck_seen *seen, size_t n)
{
    struct dl_row *rows = NULL;
    size_t nrows = 0;
    char qpath[4096 + 32];
    bool changed = false, ok = true;
    if (n == 0)
        return true;
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d->land) >=
        (int)sizeof(qpath))
        return false;
    int lock = dl_rows_lock(d->land);
    if (lock < 0)
        return false;
    if (!dl_load_rows(qpath, &rows, &nrows, NULL, 0)) {
        dl_unlock(lock);
        return false;
    }
    for (size_t i = 0; i < nrows; i++) {
        for (size_t k = 0; k < n; k++) {
            if (rows[i].seq != seen[k].seq ||
                strcmp(rows[i].tip, seen[k].tip) != 0 ||
                strcmp(rows[i].state, "queued") != 0)
                continue;
            dl_precheck_record(d, &rows[i], &seen[k], observed_main);
            changed = true;
        }
    }
    if (changed)
        ok = dl_rewrite_rows(d->land, qpath, rows, nrows);
    free(rows);
    dl_unlock(lock);
    return ok;
}

struct dl_precheck_tally {
    struct dl_precheck_seen seen[DL_PRECHECK_ROWS];
    size_t nseen;
    size_t replayed;
    size_t conflicts;
    size_t uncertain;
    size_t unchecked;
};

/* Queued, not yet settled for this main, and not already left alone on
 * it after DL_PRECHECK_TRIES uncertain answers. */
static bool dl_precheck_due(const struct dl_row *row, const char *observed_main)
{
    if (strcmp(row->state, "queued") != 0 ||
        strcmp(row->prechecked, observed_main) == 0)
        return false;
    return strcmp(row->uncertain_main, observed_main) != 0 ||
           row->uncertain_tries < DL_PRECHECK_TRIES;
}

/* The due row that lands first after `after` (NULL: the first of all), in
 * the order dl_step_pick_row() picks queued rows. */
static struct dl_row *dl_precheck_next(struct dl_row *rows, size_t n,
                                       const char *observed_main,
                                       const struct dl_row *after)
{
    struct dl_row *best = NULL;
    for (size_t i = 0; i < n; i++) {
        if (!dl_precheck_due(&rows[i], observed_main) ||
            (after && !dl_queued_precedes(after, &rows[i])))
            continue;
        if (dl_queued_precedes(&rows[i], best))
            best = &rows[i];
    }
    return best;
}

static void dl_precheck_see(struct dl_precheck_tally *t,
                            const struct dl_row *row, bool settled)
{
    struct dl_precheck_seen *s = &t->seen[t->nseen++];
    s->seq = row->seq;
    (void)snprintf(s->tip, sizeof(s->tip), "%s", row->tip);
    s->settled = settled;
}

static void dl_precheck_one(struct dl_pc *pc, struct dl_row *row,
                            struct dl_precheck_tally *t)
{
    pc->why[0] = '\0';
    enum dl_precheck v = dl_precheck_row(pc, row);
    if (v == DL_PRECHECK_UNCERTAIN && pc->expired)
        (void)dl_precheck_uncertain(pc, "the beat's precheck deadline "
                                        "passed mid-replay");
    dl_precheck_note(pc->d, row, pc->main, dl_precheck_word(v), pc->why);
    if (v == DL_PRECHECK_UNCERTAIN) {
        t->uncertain++;
        dl_precheck_see(t, row, false);
        return;
    }
    if (v != DL_PRECHECK_CONFLICT) {
        dl_precheck_see(t, row, true);
        return;
    }
    if (dl_precheck_end(pc->d, row, pc->main, pc->why)) {
        t->conflicts++;
        return;
    }
    /* Not durably ended: stay unmarked so the next beat retries. */
    dl_precheck_note(pc->d, row, pc->main, "conflict not recorded",
                     "queue or outcome write failed; retrying next beat");
}

/* Replay due rows in landing order until the per-beat row cap or the
 * deadline; rows not reached stay exactly as they are. */
static void dl_precheck_walk(struct dl_pc *pc, struct dl_row *rows,
                             size_t nrows, struct dl_precheck_tally *t)
{
    const struct dl_row *after = NULL;
    size_t due = 0;
    char line[256];
    for (size_t i = 0; i < nrows; i++)
        due += dl_precheck_due(&rows[i], pc->main);
    while (t->replayed < DL_PRECHECK_ROWS) {
        struct dl_row *row = dl_precheck_next(rows, nrows, pc->main, after);
        if (!row || dl_pc_expired(pc))
            break;
        t->replayed++;
        dl_precheck_one(pc, row, t);
        after = row;
    }
    t->unchecked = due - t->replayed;
    if (!pc->expired || t->unchecked == 0)
        return;
    (void)snprintf(line, sizeof(line),
                   "precheck stopped at the beat deadline: %zu due row(s) "
                   "left for the next beat\n", t->unchecked);
    dl_precheck_log(pc->d, line);
}

static bool dl_precheck_inflight(const struct dl_row *rows, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(rows[i].state, "inflight") == 0)
            return true;
    return false;
}

static void dl_precheck_reply(struct zcl_command_reply *reply,
                              const struct dl_precheck_tally *t)
{
    (void)json_push_kv_int(&reply->data, "queued_prechecked",
                           (long long)t->replayed);
    (void)json_push_kv_int(&reply->data, "queued_conflicts",
                           (long long)t->conflicts);
    (void)json_push_kv_int(&reply->data, "queued_uncertain",
                           (long long)t->uncertain);
    (void)json_push_kv_int(&reply->data, "queued_unchecked",
                           (long long)t->unchecked);
}

/* The queue, when there is anything to check: a fresh observation of
 * main, a landing object store, and a row in flight. */
static bool dl_precheck_load(const struct dl_dirs *d, const char *observed_main,
                             struct dl_row **rows, size_t *nrows)
{
    char qpath[4096 + 32];
    /* No fresh observation (the beat already replied why) or no landing
     * object store: there is nothing to replay onto. */
    if (!dl_sha_ok(observed_main) || !dl_wt_ready(d->wt))
        return false;
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d->land) >=
            (int)sizeof(qpath) ||
        !dl_load_rows(qpath, rows, nrows, NULL, 0)) {
        dl_precheck_log(d, "precheck skipped: cannot read queue.jsonl\n");
        return false;
    }
    if (dl_precheck_inflight(*rows, *nrows))
        return true;
    free(*rows);
    *rows = NULL;
    return false;
}

/* The beat's last act: replay the queued rows due a check onto the main
 * this beat observed, while a row is in flight. Reports what it did in
 * the step reply beside the in-flight row's own state. */
[[maybe_unused]] static void dl_precheck_queued(const struct dl_dirs *d,
                                                const char *observed_main,
                                                struct zcl_command_reply *reply)
{
    struct dl_row *rows = NULL;
    size_t nrows = 0;
    struct dl_precheck_tally t = { .nseen = 0 };
    if (!dl_precheck_load(d, observed_main, &rows, &nrows))
        return;
    struct dl_pc *pc = (struct dl_pc *)zcl_malloc(sizeof(*pc),
                                                  "dev.land.precheck");
    char *buf = (char *)zcl_malloc(DL_GIT_CAP, "dev.land.precheck");
    if (!pc || !buf) {
        dl_precheck_log(d, "precheck skipped: out of memory for the "
                           "git capture\n");
        free(pc);
        free(buf);
        free(rows);
        return;
    }
    *pc = (struct dl_pc){ .d = d, .main = observed_main, .buf = buf,
                          .cap = DL_GIT_CAP,
                          .deadline = platform_time_monotonic_ms() +
                                      dl_precheck_budget_ms() };
    dl_precheck_walk(pc, rows, nrows, &t);
    free(buf);
    free(pc);
    if (!dl_precheck_mark(d, observed_main, t.seen, t.nseen)) {
        for (size_t k = 0; k < t.nseen; k++) {
            char line[320];
            (void)snprintf(line, sizeof(line),
                           "seq=%lld tip=%s main=%s result not recorded: "
                           "queue rewrite failed; rechecking next beat\n",
                           t.seen[k].seq, t.seen[k].tip, observed_main);
            dl_precheck_log(d, line);
        }
    }
    dl_precheck_reply(reply, &t);
    free(rows);
}

/* Return 1 after a durable terminal observation has been replayed, -1 on
 * malformed history, and 0 when this picked row still needs work. */
[[maybe_unused]] static int dl_step_terminal_replay(const struct dl_dirs *d,
                                   const struct dl_row *pick,
                                   struct zcl_command_reply *reply)
{
    struct dl_row prior;
    bool terminal_seen = false;
    long long high_water = 0;
    if (!dl_scan_outcomes(d, pick, &prior, &terminal_seen, &high_water)) {
        dl_fail(reply, "QUEUE_READ_FAILED", "slot",
                "cannot reconcile a terminal outcome",
                "outcomes.jsonl unreadable or malformed");
        return -1;
    }
    if (!terminal_seen) return 0;
    if (dl_commit_or_report(d, &prior, true, reply, prior.state))
        dl_step_reply(reply, &prior, prior.state);
    /* The step that wrote this outcome may have died, or failed to post
     * its close, before it could settle: close this host's window for the
     * row whose terminal state was just replayed (the caller unlocks). */
    dl_window_settle(d, &prior, reply);
    return 1;
}

[[maybe_unused]] static bool dl_step_pick_row(const struct dl_row *rows,
                                             size_t nrows,
                                             struct dl_row *pick,
                                             bool *inflight)
{
    const struct dl_row *best = NULL;
    for (size_t i = 0; i < nrows; i++) {
        if (strcmp(rows[i].state, "inflight") == 0) {
            *pick = rows[i];
            *inflight = true;
            return true;
        }
    }
    for (size_t i = 0; i < nrows; i++)
        if (strcmp(rows[i].state, "queued") == 0 &&
            dl_queued_precedes(&rows[i], best))
            best = &rows[i];
    if (!best)
        return false;
    *pick = *best;
    return true;
}

#if defined(ZCL_TESTING) && !defined(_WIN32)
static int g_dl_pick_ready_fd = -1;
static int g_dl_pick_release_fd = -1;

void zcl_native_dev_land_test_pick_barrier(int ready_fd, int release_fd)
{
    g_dl_pick_ready_fd = ready_fd;
    g_dl_pick_release_fd = release_fd;
}

static bool dl_test_pick_barrier(void)
{
    if (g_dl_pick_ready_fd < 0 || g_dl_pick_release_fd < 0)
        return true;
    char marker = 'R';
    ssize_t n;
    do n = write(g_dl_pick_ready_fd, &marker, 1);
    while (n < 0 && errno == EINTR);
    if (n != 1) return false;
    do n = read(g_dl_pick_release_fd, &marker, 1);
    while (n < 0 && errno == EINTR);
    return n == 1 && marker == 'G';
}
#endif

/* A compound fence owns singleflight until BOTH outcomes are durably sealed.
 * The immutable anchor retains the old attempt history. A fenced disposition
 * says only that future base-CAS sends are disabled; historical acceptance
 * remains unknown. No ordinary refused/cancelled/successor path is involved. */
struct dl_fence {
    struct dl_row anchor, old, next;
    long long stage; /* 0: live, 1: paired settlement, 2: projected */
    bool dispatched;
    char observed[80], policy[65];
};

static bool dl_fence_anchor_same(const struct dl_row *a, const struct dl_row *b);

#define DL_FENCE_CAP (4u * DL_LINE_CAP)

static bool dl_fence_path(const struct dl_dirs *d, char path[4192])
{
    return snprintf(path, 4192, "%s/fence.jsonl", d->land) < 4192;
}

[[maybe_unused]] static bool dl_fence_prefix(const struct dl_fence *f, char *text, size_t *len)
{
    int written = snprintf(text, DL_FENCE_CAP,
        "{\"kind\":\"zcl.land.fence.v1\",\"stage\":%lld,\"dispatched\":%d,"
        "\"observed\":\"%s\",\"policy\":\"%s\"}\n",
        f->stage, f->dispatched ? 1 : 0, f->observed, f->policy);
    if (written <= 0 || written >= (int)DL_LINE_CAP) return false;
    *len = (size_t)written;
    const struct dl_row *rows[] = { &f->anchor, &f->old, &f->next };
    for (size_t i = 0; i < 3; ++i) {
        size_t n = 0;
        if (!dl_encode_row(rows[i], text + *len, DL_FENCE_CAP - *len, &n))
            return false;
        *len += n;
    }
    return true;
}

static bool dl_fence_write(const struct dl_dirs *d, const struct dl_fence *f)
{
#if (defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)) && !defined(_WIN32)
    char path[4192], tmp[4192 + 8], signer_hex[65], signature_hex[129];
    char *text = zcl_malloc(DL_FENCE_CAP, "dev.land.fence");
    uint8_t signer[32], signature[64];
    const char *why = NULL;
    size_t len = 0;
    bool ok = text && dl_fence_path(d, path) &&
        snprintf(tmp, sizeof(tmp), "%s.tmp", path) < (int)sizeof(tmp) &&
        dl_fence_prefix(f, text, &len) &&
        zcl_dev_proof_signer_sign((const uint8_t *)text, len, signer,
                                   signature, &why);
    if (!ok) { free(text); return false; }
    zcl_hex_encode(signer, sizeof(signer), signer_hex);
    zcl_hex_encode(signature, sizeof(signature), signature_hex);
    int n = snprintf(text + len, DL_FENCE_CAP - len,
                      "{\"signer\":\"%s\",\"signature\":\"%s\"}\n",
                      signer_hex, signature_hex);
    if (n <= 0 || (size_t)n >= DL_FENCE_CAP - len) {
        free(text); return false;
    }
    len += (size_t)n;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                   0600);
    FILE *stream = fd < 0 ? NULL : fdopen(fd, "wb");
    if (!stream) { if (fd >= 0) (void)close(fd); free(text); return false; }
    ok = fwrite(text, 1, len, stream) == len && dl_queue_file_flush(stream);
    if (fclose(stream) != 0) ok = false;
    free(text);
    return ok && rename(tmp, path) == 0 && dl_queue_parent_flush(d->land);
#else
    (void)d; (void)f;
    return false;
#endif
}

[[maybe_unused]] static bool dl_fence_header_decode(const char *line, struct dl_fence *f)
{
    char kind[64]; long long dispatched = 0;
    bool ok = dl_line_string(line, "kind", kind, sizeof(kind)).state == DL_STRING_FOUND &&
        strcmp(kind, "zcl.land.fence.v1") == 0 &&
        dl_line_int(line, "stage", &f->stage) && f->stage >= 0 && f->stage <= 2 &&
        dl_line_int(line, "dispatched", &dispatched) && (dispatched == 0 || dispatched == 1) &&
        dl_line_string(line, "observed", f->observed, sizeof(f->observed)).state == DL_STRING_FOUND && dl_sha_ok(f->observed) &&
        dl_line_string(line, "policy", f->policy, sizeof(f->policy)).state == DL_STRING_FOUND && dl_hex_ok(f->policy, 64);
    f->dispatched = dispatched != 0;
    return ok;
}

[[maybe_unused]] static bool dl_fence_rows_decode(char *const lines[5], struct dl_fence *f,
                                                   char signer[65], char signature[129])
{
    return dl_parse_row(lines[1], &f->anchor) && dl_parse_row(lines[2], &f->old) &&
        dl_parse_row(lines[3], &f->next) && dl_line_string(lines[4], "signer", signer, 65).state == DL_STRING_FOUND &&
        dl_line_string(lines[4], "signature", signature, 129).state == DL_STRING_FOUND;
}

[[maybe_unused]] static bool dl_fence_geometry_ok(const struct dl_fence *f)
{
    return f->old.seq == f->anchor.seq && f->next.seq > f->old.seq &&
        dl_fence_anchor_same(&f->old, &f->anchor) &&
        strcmp(f->anchor.state, "inflight") == 0 && strcmp(f->anchor.phase, "push") == 0 &&
        strcmp(f->old.base, f->next.base) == 0 && strcmp(f->old.tree, f->next.tree) == 0 &&
        strcmp(f->old.local, f->next.local) != 0 &&
        strcmp(f->old.publication_target, f->next.publication_target) == 0 &&
        f->next.fence_peer == f->old.seq;
}

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
static bool dl_fence_seal_ok(const char *text, size_t len,
                              const char *signer_hex, const char *signature_hex)
{
    uint8_t signer[32], signature[64]; const char *why = NULL;
    return zcl_hex_decode_lower(signer_hex, signer, sizeof(signer)) &&
        zcl_hex_decode_lower(signature_hex, signature, sizeof(signature)) &&
        zcl_dev_proof_signer_verify((const uint8_t *)text, len, signer, signature, &why);
}
#endif

/* 0 absent, 1 verified, -1 corrupt/unavailable. A torn record is a block. */
static int dl_fence_read(const struct dl_dirs *d, struct dl_fence *f)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    char path[4192], signer_hex[65], signature_hex[129];
    char *text = zcl_malloc(DL_FENCE_CAP, "dev.land.fence.read");
    size_t len = 0;
    if (!text || !dl_fence_path(d, path)) { free(text); return -1; }
    if (!dl_read_file(path, text, DL_FENCE_CAP, &len)) {
        int rc = errno == ENOENT ? 0 : -1; free(text); return rc;
    }
    char *lines[5], *cursor = text; size_t signed_len = 0; bool ok = true;
    for (size_t i = 0; i < 5; ++i) {
        lines[i] = cursor;
        char *end = strchr(cursor, '\n');
        if (!end) { ok = false; break; }
        if (i == 4) signed_len = (size_t)(cursor - text);
        *end = '\0'; cursor = end + 1;
    }
    memset(f, 0, sizeof(*f));
    ok = ok && *cursor == '\0' && dl_fence_header_decode(lines[0], f) &&
        dl_fence_rows_decode(lines, f, signer_hex, signature_hex) && dl_fence_geometry_ok(f);
    if (ok) {
        /* Restore the exact sealed bytes, never a re-encoding. */
        for (size_t i = 0; i < 4; ++i) lines[i][strlen(lines[i])] = '\n';
        ok = dl_fence_seal_ok(text, signed_len, signer_hex, signature_hex);
    }
    free(text); return ok ? 1 : -1;
#else
    (void)d; (void)f; return 0;
#endif
}

static bool dl_fence_reserve(const struct dl_dirs *d, long long *seq)
{
    struct dl_fence *f = zcl_malloc(sizeof(*f), "dev.land.fence.reserve");
    if (!f) return false;
    int rc = dl_fence_read(d, f);
    bool ok = rc >= 0 && (rc == 0 || f->next.seq < LLONG_MAX);
    if (ok && rc == 1 && *seq <= f->next.seq) *seq = f->next.seq + 1;
    free(f);
    return ok;
}

static bool dl_fence_blocks(const struct dl_dirs *d, long long seq)
{
    struct dl_fence *f = zcl_malloc(sizeof(*f), "dev.land.fence.block");
    if (!f) return true;
    int rc = dl_fence_read(d, f);
    bool blocked = rc < 0 || (rc == 1 && f->stage < 2 &&
        (seq == 0 || seq == f->old.seq || seq == f->next.seq));
    free(f);
    return blocked;
}

static bool dl_fence_repo_byte(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
}

static bool dl_fence_repo_name_ok(const char *name)
{
    size_t length = strlen(name); unsigned slashes = 0;
    for (size_t i = 0; i < length; ++i) {
        if (name[i] == '/') {
            ++slashes;
            if (i == 0 || i + 1 == length) return false;
        } else if (!dl_fence_repo_byte(name[i])) return false;
    }
    return slashes == 1;
}

static bool dl_fence_origin_repo(const char *origin, char name[256])
{
    const char *repository = NULL;
    if (strncmp(origin, "git@github.com:", 15) == 0) repository = origin + 15;
    if (strncmp(origin, "https://github.com/", 19) == 0) repository = origin + 19;
    if (!repository || strlen(repository) >= 256) return false;
    (void)snprintf(name, 256, "%s", repository);
    size_t length = strlen(name);
    if (length > 4 && strcmp(name + length - 4, ".git") == 0) name[length - 4] = '\0';
    return dl_fence_repo_name_ok(name);
}

static bool dl_fence_policy_json(const char *bytes, size_t len, char digest[65])
{
    struct json_value policy; json_init(&policy);
    bool ok = json_read(&policy, bytes, len) && policy.type == JSON_OBJ;
    const char *keys[] = { "allow_force_pushes", "allow_deletions", "enforce_admins" };
    for (size_t i = 0; ok && i < 3; ++i) {
        const struct json_value *object = json_get(&policy, keys[i]);
        const struct json_value *enabled = object ? json_get(object, "enabled") : NULL;
        ok = enabled && enabled->type == JSON_BOOL && json_get_bool(enabled) == (i == 2);
    }
    if (ok) {
        struct sha256_ctx hash; uint8_t raw[32];
        sha256_init(&hash); sha256_write(&hash, (const uint8_t *)bytes, len);
        sha256_finalize(&hash, raw); zcl_hex_encode(raw, sizeof(raw), digest);
    }
    json_free(&policy); return ok;
}

static bool dl_fence_policy_fetch(const char *endpoint, char digest[65])
{
    char bytes[32768];
    const char *argv[] = { "gh", "api", "--hostname", "github.com", endpoint, NULL };
    struct zcl_spawn_binary_observation o = {0};
    (void)zcl_spawn_capture_binary(argv, bytes, sizeof(bytes), 10000, &o);
    return o.exit_observed && o.exit_code == 0 && o.eof && !o.overflow && !o.timed_out &&
        dl_fence_policy_json(bytes, o.output_len, digest);
}

/* Current enforced-admin main protection grants prospective fencing only;
 * multiple effective receivers and unsupported servers are refused. */
static bool dl_fence_policy(const struct dl_dirs *d, char digest[65])
{
#if defined(ZCL_TESTING)
    const char *fixture = getenv("ZCL_LAND_TEST_FENCE_POLICY");
    if (fixture && getenv("ZCL_DEVLOOP_TEST_PROCESS")) {
        if (strcmp(fixture, "monotonic") != 0) return false;
        memset(digest, 'a', 64); digest[64] = '\0'; return true;
    }
#endif
    char origin[4096], name[256], endpoint[512];
    if (!dl_single_origin_url(d->wt, true, origin, sizeof(origin)) ||
        !dl_fence_origin_repo(origin, name) || snprintf(endpoint, sizeof(endpoint),
            "repos/%s/branches/main/protection", name) >= (int)sizeof(endpoint)) return false;
    return dl_fence_policy_fetch(endpoint, digest);
}

static int dl_fence_ancestor(const struct dl_dirs *d, const char *head,
                              const char *remote)
{
    char output[512];
    const char *args[] = { "--no-replace-objects", "merge-base", "--is-ancestor",
                           head, remote, NULL };
    return dl_git(d->wt, args, output, sizeof(output), DL_GIT_TIMEOUT_MS);
}

static bool dl_fence_linear_range(const struct dl_dirs *d, const char *range)
{
    const char *argv[] = { "git", "-C", d->wt, "--no-replace-objects", "rev-list",
                           "--min-parents=2", range, NULL };
    char merges[256]; struct zcl_spawn_binary_observation o = {0};
    (void)zcl_spawn_capture_binary(argv, merges, sizeof(merges), DL_GIT_TIMEOUT_MS, &o);
    return o.exit_observed && o.exit_code == 0 && !o.overflow && o.eof &&
        !o.timed_out && o.output_len == 0;
}

static bool dl_fence_all_signed(const struct dl_dirs *d, const struct dl_row *row)
{
    char range[176], signatures[65536];
    if (snprintf(range, sizeof(range), "%s..%s", row->base, row->local) >=
        (int)sizeof(range)) return false;
    if (!dl_fence_linear_range(d, range)) return false;
    const char *argv[] = { "git", "-C", d->wt, "--no-replace-objects", "log",
                           "--format=%G?", range, NULL };
    struct zcl_spawn_binary_observation o = {0};
    (void)zcl_spawn_capture_binary(argv, signatures, sizeof(signatures),
                                   DL_GIT_TIMEOUT_MS, &o);
    if (!o.exit_observed || o.exit_code != 0 || o.overflow || !o.eof ||
        o.timed_out || !o.output_len || o.output_len % 2) return false;
    for (size_t i = 0; i < o.output_len; i += 2)
        if (signatures[i] != 'G' || signatures[i + 1] != '\n') return false;
    return true;
}

static bool dl_fence_publication_same(const struct dl_row *a, const struct dl_row *b)
{
    return strcmp(a->publication_target, b->publication_target) == 0 &&
        strcmp(a->publication_proof, b->publication_proof) == 0 &&
        strcmp(a->publication_bundle, b->publication_bundle) == 0 &&
        strcmp(a->publication_signer, b->publication_signer) == 0;
}

static bool dl_fence_anchor_same(const struct dl_row *a, const struct dl_row *b)
{
    return dl_push_pair_same(a, b) && a->attempt == b->attempt &&
        a->seq == b->seq && a->priority_seq == b->priority_seq && a->started == b->started &&
        a->push_diagnostic_pending == b->push_diagnostic_pending &&
        strcmp(a->ts, b->ts) == 0 && strcmp(a->worktree, b->worktree) == 0 &&
        strcmp(a->tip, b->tip) == 0 && strcmp(a->tree, b->tree) == 0 &&
        strcmp(a->note, b->note) == 0 &&
        dl_fence_publication_same(a, b) &&
        strcmp(a->proof_intent, b->proof_intent) == 0;
}

static bool dl_fence_current_anchor(const struct dl_dirs *d, const struct dl_fence *f)
{
    char path[4192];
    struct dl_row *rows = NULL;
    size_t count = 0;
    if (snprintf(path, sizeof(path), "%s/queue.jsonl", d->land) >= (int)sizeof(path))
        return false;
    int lock = dl_rows_lock(d->land);
    if (lock < 0) return false;
    bool ok = dl_load_rows(path, &rows, &count, NULL, 0), found = false;
    for (size_t i = 0; ok && i < count; ++i) {
        if (rows[i].seq == f->anchor.seq) {
            found = true; ok = dl_fence_anchor_same(&rows[i], &f->anchor);
        }
        if (rows[i].seq == f->next.seq) ok = false;
    }
    if (ok && !found && f->stage == 1) {
        bool old_seen = false, new_seen = false; long long high_water = 0;
        ok = dl_scan_outcomes(d, &f->old, NULL, &old_seen, &high_water) &&
            dl_scan_outcomes(d, &f->next, NULL, &new_seen, &high_water) && old_seen && new_seen;
    } else if (!found) ok = false;
    free(rows); dl_unlock(lock);
    return ok;
}

static void dl_fence_test_crash(const char *point)
{
#if defined(ZCL_TESTING) && !defined(_WIN32)
    const char *wanted = getenv("ZCL_LAND_TEST_FENCE_CRASH");
    if (wanted && getenv("ZCL_DEVLOOP_TEST_PROCESS") && strcmp(wanted, point) == 0)
        _exit(87);
#else
    (void)point;
#endif
}

static bool dl_fence_row_equal(const struct dl_row *a, const struct dl_row *b)
{
    char *left = zcl_malloc(DL_LINE_CAP, "dev.land.fence.equal.left");
    char *right = zcl_malloc(DL_LINE_CAP, "dev.land.fence.equal.right");
    size_t left_len = 0, right_len = 0;
    bool equal = left && right && dl_encode_row(a, left, DL_LINE_CAP, &left_len) &&
        dl_encode_row(b, right, DL_LINE_CAP, &right_len) && left_len == right_len &&
        memcmp(left, right, left_len) == 0;
    free(left); free(right); return equal;
}

/* Unlike ordinary historical lookup, paired replay must never substitute a
 * loosely matching terminal row for the sealed journal's intended outcome. */
static bool dl_fence_record_outcome(const struct dl_dirs *d, struct dl_row *row)
{
    struct dl_row prior; bool present = false; long long high_water = 0;
    if (!dl_scan_outcomes(d, row, &prior, &present, &high_water)) return false;
    if (present) return dl_fence_row_equal(row, &prior) && dl_outbox(d, row, "outcome");
    return dl_record_outcome(d, row);
}

static bool dl_fence_outcomes_project(const struct dl_dirs *d, struct dl_fence *f)
{
    struct dl_row *winner = strcmp(f->old.state, "landed") == 0 ? &f->old : &f->next;
    struct dl_row *loser = winner == &f->old ? &f->next : &f->old;
    if (strcmp(winner->state, "landed") || strcmp(loser->state, "fenced") ||
        !dl_publication_receipt_verify(winner) || !dl_fence_record_outcome(d, &f->old))
        return false;
    dl_fence_test_crash("old_projection");
    return dl_fence_record_outcome(d, &f->next);
}

/* Paired sealed journal precedes any terminal projection. Both outcome appends
 * and the single whole-queue rewrite are replayable while step.lock stays held.
 * A failed/one-sided projection cannot release singleflight. */
static bool dl_fence_project(const struct dl_dirs *d, struct dl_fence *f)
{
    char qpath[4192];
    struct dl_row *rows = NULL;
    size_t count = 0, kept = 0;
    if (f->stage != 1 || snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d->land) >=
        (int)sizeof(qpath)) return false;
    int lock = dl_rows_lock(d->land);
    if (lock < 0) return false;
    bool ok = dl_load_rows(qpath, &rows, &count, NULL, 0);
    for (size_t i = 0; ok && i < count; ++i) {
        if (rows[i].seq == f->anchor.seq) {
            ok = dl_fence_anchor_same(&rows[i], &f->anchor);
            continue;
        }
        if (rows[i].seq == f->next.seq) { ok = false; break; }
        rows[kept++] = rows[i];
    }
    ok = ok && dl_fence_outcomes_project(d, f) &&
        dl_rewrite_rows(d->land, qpath, rows, kept);
    free(rows);
    if (ok) { f->stage = 2; ok = dl_fence_write(d, f); }
    dl_unlock(lock);
    return ok;
}

static void dl_fence_blocked(struct zcl_command_reply *reply, const char *code,
                              const struct dl_fence *f)
{
    dl_fail(reply, code, "fence_replace",
             "paired fence retained; no ordinary settlement or queue advancement",
             f ? f->observed : "fence.jsonl unavailable");
    if (f) {
        (void)json_push_kv_int(&reply->data, "old_seq", f->anchor.seq);
        (void)json_push_kv_int(&reply->data, "replacement_seq", f->next.seq);
        (void)json_push_kv_str(&reply->data, "historical_git_acceptance", "unknown");
    }
}

static bool dl_fence_hooks_admitted(const char *wt)
{
    if (!dl_wt_hooks_ready(wt) || !dl_wt_hooks_fresh(wt)) return false;
#if defined(ZCL_TESTING)
    const char *fixture = dl_hooks_stub_dir();
    if (fixture && getenv("ZCL_DEVLOOP_TEST_PROCESS") && dl_stub()) {
        char configured[4096];
        const char *get[] = { "config", "--worktree", "--get", "core.hooksPath", NULL };
        if (dl_git(wt, get, configured, sizeof(configured), 10000) != 0) return false;
        dl_trim(configured);
        return strcmp(configured, fixture) == 0;
    }
#endif
    /* The normal canonical gate validates hook identity, scripts and freshness.
     * No installation/repair is authorized by this check-only fence route. */
    const char *argv[] = { "make", "-C", wt, "check-git-hooks-installed", NULL };
    char output[8192]; bool timeout = false;
    return zcl_spawn_capture_merged_observed(argv, output, sizeof(output),
                                             DL_GIT_TIMEOUT_MS, &timeout) == 0 && !timeout;
}

static bool dl_fence_identity_ok(const struct dl_dirs *d,
                                  const struct dl_dirs *next_dirs, const struct dl_fence *f)
{
    return dl_fence_current_anchor(d, f) && dl_publication_verify(d, &f->anchor) &&
        dl_publication_verify(next_dirs, &f->next) && dl_fence_all_signed(next_dirs, &f->next) &&
        dl_fence_hooks_admitted(next_dirs->wt);
}

static bool dl_fence_observation_ok(const struct dl_dirs *next_dirs, const struct dl_fence *f,
                                     const char *observed, int old_contains, int new_contains)
{
    return (old_contains == 0 || old_contains == 1) &&
        (new_contains == 0 || new_contains == 1) &&
        !(old_contains == 0 && new_contains == 0) &&
        dl_fence_ancestor(next_dirs, f->observed, observed) == 0;
}

static void dl_fence_replay(const struct dl_dirs *d, struct dl_fence *f,
                             int old_contains, int new_contains, struct zcl_command_reply *reply)
{
    bool matches = (old_contains == 0 && strcmp(f->old.state, "landed") == 0) ||
        (new_contains == 0 && strcmp(f->next.state, "landed") == 0);
    if (!matches) dl_fence_blocked(reply, "FENCE_OBSERVATION_INCONSISTENT", f);
    else if (!dl_fence_project(d, f)) dl_fence_blocked(reply, "FENCE_PROJECT_PENDING", f);
    else dl_step_reply(reply, &f->next, f->next.state);
}

static void dl_fence_settle(const struct dl_dirs *d, const struct dl_dirs *next_dirs,
                             struct dl_fence *f, int old_contains, struct zcl_command_reply *reply)
{
    char policy[65];
        struct dl_row *winner = old_contains == 0 ? &f->old : &f->next;
        struct dl_row *loser = old_contains == 0 ? &f->next : &f->old;
        const struct dl_dirs *winner_dirs = old_contains == 0 ? d : next_dirs;
        if (!dl_publication_remote_observe(winner_dirs, winner,
                winner->remote_tip, winner->remote_source) ||
            strcmp(winner->remote_tip, f->observed) != 0 ||
            !dl_publication_receipt_seal(winner) ||
            !dl_publication_receipt_verify(winner) ||
            !dl_fence_policy(next_dirs, policy)) {
            dl_fence_blocked(reply, "FENCE_WINNER_RECEIPT_UNAVAILABLE", f); return;
        }
        (void)snprintf(winner->state, sizeof(winner->state), "landed");
        (void)snprintf(winner->pushed, sizeof(winner->pushed), "%s", winner->local);
        winner->phase[0] = '\0';
        (void)snprintf(loser->state, sizeof(loser->state), "fenced");
        /* Retain phase, attempts, pair and intent on the losing checkpoint. */
        loser->fence_peer = winner->seq;
        winner->fence_peer = loser->seq;
        f->stage = 1;
        if (!dl_fence_write(d, f)) {
            dl_fence_blocked(reply, "FENCE_PROJECT_PENDING", f); return;
        }
        dl_fence_test_crash("paired");
        if (!dl_fence_project(d, f)) {
            dl_fence_blocked(reply, "FENCE_PROJECT_PENDING", f); return;
        }
        dl_step_reply(reply, &f->next, f->next.state);
        return;
}

static bool dl_fence_checkout_send_ok(const struct dl_dirs *d, const struct dl_dirs *next_dirs,
                                      struct dl_fence *f, struct zcl_command_reply *reply)
{
    char current[80], output[1024];
    const char *clean[] = { "status", "--porcelain", "--untracked-files=no", NULL };
    if (dl_submit_tip_resolve(next_dirs->wt, "HEAD", current, reply) &&
        strcmp(current, f->next.local) == 0 &&
        dl_git(next_dirs->wt, clean, output, sizeof(output), 10000) == 0 && !output[0] &&
        dl_fence_hooks_admitted(next_dirs->wt)) return true;
    /* No Git send occurred. Retain the fence for independent reconciliation. */
    f->next.push_diagnostic_pending = false;
    if (!dl_fence_write(d, f)) {
        dl_fence_blocked(reply, "FENCE_DISPATCH_PERSIST_FAILED", f); return false;
    }
    dl_fence_blocked(reply, "FENCE_WORKTREE_INVALID", f);
    return false;
}

static void dl_fence_send(const struct dl_dirs *d, const struct dl_dirs *next_dirs,
                           struct dl_fence *f, struct zcl_command_reply *reply)
{
    if (f->next.push_diagnostic_pending ||
        (f->dispatched && f->next.attempt >= DL_ATTEMPT_MAX)) {
        dl_fence_blocked(reply, "FENCE_PUSH_OUTCOME_UNKNOWN", f); return;
    }
    if (f->dispatched) ++f->next.attempt;
    f->dispatched = true;
    f->next.push_diagnostic_pending = true;
    if (!dl_fence_write(d, f)) {
        dl_fence_blocked(reply, "FENCE_DISPATCH_PERSIST_FAILED", f); return;
    }
    dl_fence_test_crash("before_dispatch");
#if defined(ZCL_TESTING) && !defined(_WIN32)
    if (!dl_test_pick_barrier()) {
        dl_fence_blocked(reply, "FENCE_PUSH_OUTCOME_UNKNOWN", f); return;
    }
#endif
    if (!dl_fence_checkout_send_ok(d, next_dirs, f, reply)) return;
    char *output = zcl_malloc(DL_GIT_CAP, "dev.land.fence.push");
    if (!output) { dl_fence_blocked(reply, "FENCE_PUSH_OUTCOME_UNKNOWN", f); return; }
    bool recorded = false;
    (void)dl_push_proven_pair(next_dirs, &f->next, output, DL_GIT_CAP, &recorded);
    free(output);
    dl_fence_test_crash("after_dispatch");
    if (recorded) {
        f->next.push_diagnostic_pending = false;
        if (!dl_fence_write(d, f)) {
            dl_fence_blocked(reply, "FENCE_DIAGNOSTIC_PERSIST_FAILED", f); return;
        }
    }
    /* One send per call, even with missing diagnostics. Next beat observes. */
    dl_fence_blocked(reply, "FENCE_PUSH_OUTCOME_UNKNOWN", f);
}

/* Caller holds step.lock. Definitive answers for both heads precede settlement. */
static void dl_fence_drive(const struct dl_dirs *d, struct dl_fence *f,
                            struct zcl_command_reply *reply)
{
    struct dl_dirs next_dirs = *d;
    (void)snprintf(next_dirs.wt, sizeof(next_dirs.wt), "%s", f->next.worktree);
    char policy[65], observed[80];
    if (!dl_fence_identity_ok(d, &next_dirs, f)) {
        dl_fence_blocked(reply, "FENCE_IDENTITY_INVALID", f); return;
    }
    if (!dl_fence_policy(&next_dirs, policy) || !dl_fetch_remote_main(next_dirs.wt, observed)) {
        dl_fence_blocked(reply, "FENCE_EVIDENCE_UNAVAILABLE", f); return;
    }
    int old_contains = dl_fence_ancestor(&next_dirs, f->anchor.local, observed);
    int new_contains = dl_fence_ancestor(&next_dirs, f->next.local, observed);
    if (!dl_fence_observation_ok(&next_dirs, f, observed, old_contains, new_contains)) {
        dl_fence_blocked(reply, "FENCE_OBSERVATION_INCONSISTENT", f); return;
    }
    if (f->stage == 1) {
        dl_fence_replay(d, f, old_contains, new_contains, reply); return;
    }
    (void)snprintf(f->observed, sizeof(f->observed), "%s", observed);
    (void)snprintf(f->policy, sizeof(f->policy), "%s", policy);
    if (old_contains == 0 || new_contains == 0) {
        dl_fence_settle(d, &next_dirs, f, old_contains, reply); return;
    }
    if (strcmp(observed, f->anchor.base) != 0) {
        (void)dl_fence_write(d, f);
        dl_fence_blocked(reply, "FENCE_NO_VERIFIED_WINNER", f); return;
    }
    dl_fence_send(d, &next_dirs, f, reply);
}

static bool dl_fence_step(const struct dl_dirs *d, struct zcl_command_reply *reply)
{
    struct dl_fence *f = zcl_malloc(sizeof(*f), "dev.land.fence.step");
    if (!f) { dl_fence_blocked(reply, "FENCE_READ_FAILED", NULL); return true; }
    int rc = dl_fence_read(d, f);
    bool handled = rc < 0 || (rc == 1 && f->stage < 2);
    if (rc < 0) dl_fence_blocked(reply, "FENCE_READ_FAILED", NULL);
    else if (rc == 1 && f->stage < 2) dl_fence_drive(d, f, reply);
    free(f);
    return handled;
}

static void dl_step(const struct zcl_command_request *req,
                    struct zcl_command_reply *reply)
{
    (void)req;
#if defined(_WIN32)
    dl_fail(reply, "STEP_WINDOWS_UNAVAILABLE", "slot",
            "dev land step needs POSIX advisory locks",
            "run the landing loop on a POSIX host");
    return;
#else
    struct dl_dirs d;
    struct dl_row *rows = NULL;
    struct dl_row pick;
    size_t nrows = 0;
    char qpath[4096 + 32];
    bool have_inflight = false, have_row = false;
    int slot;
    if (!dl_dirs_make(&d)) {
        dl_fail(reply, "STATE_DIR_FAILED", "slot",
                "cannot resolve the owner-private state root",
                "platform_state_root");
        return;
    }
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d.land) >=
        (int)sizeof(qpath)) {
        dl_fail(reply, "QUEUE_READ_FAILED", "slot",
                "the queue path does not fit its buffer",
                "platform_state_root too long");
        return;
    }
    /* The queue's step lock, taken without blocking, before anything else
     * is read or touched, and held for the whole step below (rebase, lint,
     * proof request, status read, push) — never just the request. Released
     * on every exit path via dl_unlock(), including every early return
     * this function takes. */
    /* Every git checkout and rebase below fires the landing worktree's
     * armed post-* hooks. Their proof scheduling is for developer
     * checkouts whose HEAD is a person's commit; this step's transient
     * HEAD would enqueue doomed pairs (see notify_proof's comment), so
     * this one-shot process quiets them for its whole lifetime. The env
     * dies with the process; a developer's own hooks are unaffected. */
    (void)setenv("ZCL_LAND_HOOK_QUIET", "1", 1);
    slot = dl_step_lock(d.land);
    if (slot < 0) {
        dl_step_busy(reply, d.land);
        return;
    }
    if (dl_fence_step(&d, reply)) {
        dl_unlock(slot);
        return;
    }
    /* A finished attempt's generation is swept here, once the lock proves
     * this step actually runs -- never before the busy check, which the
     * lock-contention test proves touches nothing. */
    dl_pool_sweep_and_log(&d);
    char queue_why[128] = {0};
    if (!dl_load_rows(qpath, &rows, &nrows, queue_why,
                      sizeof(queue_why))) {
        dl_unlock(slot);
        dl_fail(reply, "QUEUE_READ_FAILED", "slot",
                "cannot read the queue file",
                dl_reason_or_path(queue_why, qpath));
        return;
    }
    memset(&pick, 0, sizeof(pick));
    have_row = dl_step_pick_row(rows, nrows, &pick, &have_inflight);
    free(rows);
    if (!have_row) {
        dl_step_reply(reply, NULL, "empty");
        dl_window_settle(&d, NULL, reply);
        dl_unlock(slot);
        return;
    }
    if (dl_step_terminal_replay(&d, &pick, reply) != 0) {
        dl_unlock(slot);
        return;
    }
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    /* Test-only: a fixed, tiny window between picking a row here and
     * driving it below, so a test can race a concurrent cancel (which
     * takes the row lock, not this step lock) against this exact gap
     * deterministically instead of depending on process-scheduling luck.
     * Never read outside a test process. */
    {
        const char *ms = getenv("ZCL_LAND_TEST_PICK_DELAY_MS");
        if (ms && ms[0]) {
            long v = strtol(ms, NULL, 10);
            if (v > 0 && v < 5000) {
                struct timespec ts;
                ts.tv_sec = v / 1000;
                ts.tv_nsec = (v % 1000) * 1000000L;
                (void)nanosleep(&ts, NULL);
            }
        }
    }
#endif
#if defined(ZCL_TESTING) && !defined(_WIN32)
    if (!dl_test_pick_barrier()) {
        dl_unlock(slot);
        dl_fail(reply, "TEST_PICK_BARRIER_FAILED", "step",
                "the test integrator barrier did not complete", d.land);
        return;
    }
#endif
    char observed_main[80] = { 0 };
    if (have_inflight)
        dl_step_resume(&d, &pick, reply, observed_main);
    else
        dl_prepare(&d, &pick, reply, observed_main);
    dl_window_settle(&d, &pick, reply);
    /* Still under step.lock, after the driven row's own work: rows queued
     * behind a row in flight learn now whether this main left them
     * mergeable, not when they reach the head of the queue. */
    dl_precheck_queued(&d, observed_main, reply);
    dl_unlock(slot);
#endif
}

/* Read the durable pair after a step has released step.lock. No process
 * owns this intent: another authorized integrator can read the same row. */
#ifdef ZCL_DEV_BUILD
static bool dl_drive_pair(char local[80], char base[80], char root[4096])
{
    struct dl_dirs d;
    struct dl_row *rows = NULL;
    size_t count = 0;
    char path[4096 + 32];
    bool found = false;
    if (!dl_dirs_make(&d) ||
        snprintf(path, sizeof(path), "%s/queue.jsonl", d.land) >=
            (int)sizeof(path) ||
        !dl_load_rows(path, &rows, &count, NULL, 0))
        return false;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rows[i].state, "inflight") != 0 ||
            strcmp(rows[i].phase, "prove") != 0)
            continue;
        if (dl_sha_ok(rows[i].local) && dl_sha_ok(rows[i].base)) {
            (void)snprintf(local, 80, "%s", rows[i].local);
            (void)snprintf(base, 80, "%s", rows[i].base);
            (void)snprintf(root, 4096, "%s", d.wt);
            found = true;
        }
        break;
    }
    free(rows);
    return found;
}
#endif

/* The probe a proving drive runs every ZCL_DEV_PROOF_BASE_PROBE_MS: one
 * bounded, read-only `ls-remote` of origin main from the landing worktree.
 * Only a well-formed answer naming a different commit says SUPERSEDED; a
 * timeout, a launch failure or unreadable output says UNKNOWN, which never
 * cancels. Publication does not trust this answer either way: attach and
 * push still take their own fresh fetch of the remote tip. */
#define DL_BASE_PROBE_TIMEOUT_MS (10 * 1000)
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
struct dl_base_probe_ctx {
    const char *wt;
    const char *base;
};

static enum zcl_dev_proof_base_observation dl_base_observe(void *opaque)
{
    const struct dl_base_probe_ctx *ctx = opaque;
    const char *args[] = { "ls-remote", "--quiet", "origin",
                           "refs/heads/main", NULL };
    char out[512], tip[80];
    struct dl_dirs dirs;
    /* The proof's only periodic beat: re-announce an overrun window. */
    if (dl_dirs_resolve(&dirs, false))
        dl_window_tick(&dirs, NULL);
    if (!ctx || !ctx->wt || !ctx->base ||
        dl_git(ctx->wt, args, out, sizeof(out), DL_BASE_PROBE_TIMEOUT_MS) != 0)
        return ZCL_DEV_PROOF_BASE_UNKNOWN;
    size_t n = strcspn(out, " \t\r\n");
    if (n >= sizeof(tip) || strcmp(out + n, "\trefs/heads/main\n") != 0)
        return ZCL_DEV_PROOF_BASE_UNKNOWN;
    memcpy(tip, out, n);
    tip[n] = '\0';
    if (!dl_sha_ok(tip))
        return ZCL_DEV_PROOF_BASE_UNKNOWN;
    return strcmp(tip, ctx->base) == 0 ? ZCL_DEV_PROOF_BASE_CURRENT
                                       : ZCL_DEV_PROOF_BASE_SUPERSEDED;
}
#endif

#if defined(ZCL_TESTING)
int zcl_native_dev_land_test_base_observe(const char *wt, const char *base)
{
    struct dl_base_probe_ctx ctx = { .wt = wt, .base = base };
    return (int)dl_base_observe(&ctx);
}
#endif

/* The watched wait a proving drive hands the proof step: this leaf's own
 * observer over `wt`'s origin, asked every `interval_ms` (<= 0 selects
 * ZCL_DEV_PROOF_BASE_PROBE_MS). One constructor, so the test seam below
 * watches a worker exactly the way dl_drive_proof() does. */
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
[[maybe_unused]] static struct zcl_dev_proof_base_probe dl_base_probe(
    struct dl_base_probe_ctx *ctx, const char *wt, const char *base,
    int interval_ms)
{
    ctx->wt = wt;
    ctx->base = base;
    return (struct zcl_dev_proof_base_probe){
        .observe = dl_base_observe, .ctx = ctx, .interval_ms = interval_ms };
}
#endif

#if defined(ZCL_TESTING) && !defined(_WIN32)
/* The drive's watch over an already-forked proof worker: dl_base_probe()
 * against `wt`'s origin, through the proof's own requester wait loop.
 * Returns what that loop returns; `*superseded` says the probe cancelled. */
int zcl_native_dev_land_test_watch_worker(const char *wt, const char *base,
                                          int worker_pid, int interval_ms,
                                          bool *superseded)
{
    struct dl_base_probe_ctx ctx;
    const struct zcl_dev_proof_base_probe probe =
        dl_base_probe(&ctx, wt, base, interval_ms);
    return zcl_dev_proof_test_foreground_wait(worker_pid, &probe, superseded);
}
#endif

/* The exact proof refuses a producer whose own source identity is not the
 * candidate's: the binary that selects tests and applies impact policy must
 * be built from the bytes it proves. A drive runs the proof in its own
 * process, and its binary is whatever was last built where it was started —
 * almost never the candidate the queue just checked out, and never one the
 * lander rebased. That refusal used to fail the row; every landing then
 * needed someone to build the producer and run the step by hand. */
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
#define DL_PRODUCER_BUILD_TIMEOUT_MS (30 * 60 * 1000)
#define DL_PRODUCER_PROOF_TIMEOUT_MS (2 * 60 * 60 * 1000)

[[maybe_unused]] static bool dl_producer_stale(const char *detail)
{
    return detail && strstr(detail, "proof_producer_source_mismatch") != NULL;
}

/* Build the development binary in the landing worktree — the candidate's
 * own Makefile target, in the tree whose lint and regeneration recipes the
 * landing already runs — and prove the pair with that binary as a child.
 * Returns 1 once the child proof has exited (its verdict is the pair's
 * settled proof state, read by the step that follows), -1 with `why` when
 * no candidate-built producer could be run. */
[[maybe_unused]] static int dl_producer_reproof(const char *root,
                                                const char *local,
                                                const char *base,
                                                const char *make_program,
                                                char *why, size_t why_cap)
{
    char jobs[16], bin[4096], root_arg[4200], local_arg[128], base_arg[128];
    char *buf;
    int rc;
    if (!platform_build_jobs_arg(jobs) ||
        snprintf(bin, sizeof(bin), "%s/build/bin/z23-dev", root) >=
            (int)sizeof(bin) ||
        snprintf(root_arg, sizeof(root_arg), "--root=%s", root) >=
            (int)sizeof(root_arg) ||
        snprintf(local_arg, sizeof(local_arg), "--local_commit=%s", local) >=
            (int)sizeof(local_arg) ||
        snprintf(base_arg, sizeof(base_arg), "--remote_base=%s", base) >=
            (int)sizeof(base_arg)) {
        (void)snprintf(why, why_cap, "%s", "producer_arguments_invalid");
        return -1;
    }
    buf = (char *)zcl_malloc(DL_LOG_CAP, "dev.land.producer");
    if (!buf) {
        (void)snprintf(why, why_cap, "%s", "producer_log_unavailable");
        return -1;
    }
    const char *build[] = { make_program, jobs, "-C", root, "dev-bin", NULL };
    rc = zcl_spawn_capture(build, buf, DL_LOG_CAP,
                           DL_PRODUCER_BUILD_TIMEOUT_MS);
    if (rc != 0 || access(bin, X_OK) != 0) {
        dl_first_actionable(buf, why, why_cap);
        if (!why[0])
            (void)snprintf(why, why_cap, "%s", "producer_build_failed");
        free(buf);
        return -1;
    }
    const char *prove[] = { bin, "dev", "proof", "step", root_arg, local_arg,
                            base_arg, NULL };
    rc = zcl_spawn_capture(prove, buf, DL_LOG_CAP,
                           DL_PRODUCER_PROOF_TIMEOUT_MS);
    free(buf);
    if (rc < 0) {
        (void)snprintf(why, why_cap, "%s", "producer_launch_failed");
        return -1;
    }
    return 1;
}

/* The one recovery both `dev land drive` and `dev land step` run for a
 * producer-stale refusal: clear the sticky verdict so the pair queues again,
 * then build the producer in `root` and prove with it (dl_producer_reproof,
 * unchanged). Returns DL_RECOVER_OK once the child proof has exited,
 * DL_RECOVER_RETRY_REFUSED when the pair could not be queued again, and
 * DL_RECOVER_UNAVAILABLE when no candidate-built producer could be run; `why`
 * carries the reason for either failure. Only the testing-only producer stubs
 * skip the rebuild: a test build then only counts the call. */
static int dl_producer_recover(const char *root, const char *local,
                               const char *base, char *why, size_t why_cap)
{
    why[0] = '\0';
#if defined(ZCL_TESTING)
    if (dl_producer_stub_active()) {
        if (dl_producer_stub_record())
            return DL_RECOVER_OK;
        (void)snprintf(why, why_cap, "%s", "producer_stub_unrecorded");
        return DL_RECOVER_UNAVAILABLE;
    }
#endif
#ifdef ZCL_DEV_BUILD
    struct zcl_dev_proof_status again = {0};
    if (!zcl_dev_proof_retry(root, local, base, &again)) {
        (void)snprintf(why, why_cap, "%s", again.detail);
        return DL_RECOVER_RETRY_REFUSED;
    }
    if (dl_producer_reproof(root, local, base, "make", why, why_cap) < 0)
        return DL_RECOVER_UNAVAILABLE;
    return DL_RECOVER_OK;
#else
    (void)root;
    (void)local;
    (void)base;
    (void)snprintf(why, why_cap, "%s", "producer recovery needs the dev binary");
    return DL_RECOVER_UNAVAILABLE;
#endif
}
#endif

#if defined(ZCL_TESTING)
bool zcl_native_dev_land_test_producer_stale(const char *detail)
{
    return dl_producer_stale(detail);
}

int zcl_native_dev_land_test_producer_reproof(const char *root,
                                              const char *local,
                                              const char *base,
                                              const char *make_program,
                                              char *why, size_t why_cap)
{
    return dl_producer_reproof(root, local, base, make_program, why, why_cap);
}
#endif

/* Return 1 after this pair settles, 0 when a worker owns it, -1 on refusal. */
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
static int dl_drive_proof(struct zcl_command_reply *reply)
{
#ifdef ZCL_DEV_BUILD
    char local[80], base[80], root[4096];
    struct zcl_dev_proof_status proof = {0};
    int result;
    if (dl_stub())
        return 1;
    if (!dl_drive_pair(local, base, root)) {
        dl_fail(reply, "PROOF_INTENT_UNAVAILABLE", "drive",
                "the exact in-flight proof pair is unavailable",
                "retry dev land drive after inspecting dev land status");
        return -1;
    }
    struct dl_base_probe_ctx probe_ctx;
    const struct zcl_dev_proof_base_probe probe =
        dl_base_probe(&probe_ctx, root, base, 0);
    bool superseded = false;
    result = zcl_dev_proof_step_watched(root, local, base, &probe, &proof,
                                        &superseded);
    /* A superseded run settles as a cancelled failure; the step that
     * follows re-observes main and cuts the successor. */
    if (superseded)
        (void)json_push_kv_bool(&reply->data, "proof_superseded", true);
    if (result < 0) {
        dl_fail(reply, "PROOF_STEP_REFUSED", "drive",
                "the exact proof worker refused this pair", proof.detail);
        return -1;
    }
    if (result == 0)
        (void)json_push_kv_str(&reply->data, "proof_worker", proof.detail);
    if (result == 1 && dl_producer_stale(proof.detail)) {
        /* Settled as a refusal of this binary, not of the candidate. Queue
         * the pair again and prove it with a producer built from it. */
        char why[256] = "";
        int recovered = dl_producer_recover(root, local, base, why,
                                            sizeof(why));
        if (recovered == DL_RECOVER_RETRY_REFUSED) {
            dl_fail(reply, "PROOF_PRODUCER_RETRY_REFUSED", "drive",
                    "cannot queue the pair again for a candidate-built producer",
                    why);
            return -1;
        }
        if (recovered != DL_RECOVER_OK) {
            dl_fail(reply, "PROOF_PRODUCER_UNAVAILABLE", "drive",
                    "cannot build and run a producer from the candidate",
                    why);
            return -1;
        }
    }
    return result;
#else
    if (!dl_stub()) {
        dl_fail(reply, "DEV_BUILD_REQUIRED", "drive",
                "exact proof driving requires the development binary",
                "make dev-bin");
        return -1;
    }
    return 1;
#endif
}
#endif

/* The dispatcher owns an initialized reply. Between drive cycles, release
 * its prior data before writing the next step's result. */
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
static void dl_drive_reply_reset(struct zcl_command_reply *reply)
{
    zcl_command_reply_free(reply);
    zcl_command_reply_init(reply, "zcl.land.v1");
}
#endif

/* One bounded integrator session. Proof holds the shared step guard rather
 * than the exclusive preparation slot. A PASS is followed immediately by a
 * step that checks the remote base before publication. A lost CAS leaves the
 * same aged row queued for this or any later driver. */
static void dl_drive(const struct zcl_command_request *req,
                     struct zcl_command_reply *reply)
{
#if !defined(ZCL_DEV_BUILD) && !defined(ZCL_TESTING)
    (void)req;
    dl_fail(reply, "DEV_BUILD_REQUIRED", "drive",
            "exact proof driving requires the development binary",
            "make dev-bin");
#else
    for (int cycle = 0; cycle < 4; cycle++) {
        const char *state;
        dl_step(req, reply);
        if (reply->status != ZCL_COMMAND_STATUS_PASSED)
            return;
        state = json_get_str(json_get(&reply->data, "state"));
        if (state && strcmp(state, "rebased") == 0) {
            dl_drive_reply_reset(reply);
            continue;
        }
        if (!state || (strcmp(state, "started") != 0 &&
                       strcmp(state, "proving") != 0))
            return;
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
        if (dl_drive_proof(reply) <= 0)
            return;
#endif
        dl_drive_reply_reset(reply);
        dl_step(req, reply);
        if (reply->status != ZCL_COMMAND_STATUS_PASSED)
            return;
        state = json_get_str(json_get(&reply->data, "state"));
        if (!state || strcmp(state, "rebased") != 0)
            return;
        dl_drive_reply_reset(reply);
    }
    dl_fail(reply, "DRIVE_BUDGET_EXHAUSTED", "drive",
            "four proof cycles ended with a newer main tip; the aged row remains queued",
            "run dev land drive again from a current authorized checkout");
#endif
}

/* Dedicated self observation: no control helper is reachable from this path. */
static const char dl_attest_head[] = "db648476e77c14308d77501ad85655e2444043b3";
static const char dl_attest_base[] = "3a93e60ebf922af3d119b9facc1d95803f42844b";
static const char dl_attest_tree[] = "4514cfd63acc408be3d37023656a8e88bc1be2c6";

static bool dl_attest_string(const struct json_value *j, const char *key,
                            const char *expected)
{
    const char *s = json_get_str(json_get(j, key));
    return s && expected && strcmp(s, expected) == 0;
}

static bool dl_attest_binding(const struct json_value *j,
                             const char *image, const char *source)
{
    return j->type == JSON_OBJ && j->num_children == 13 &&
        dl_attest_string(j, "schema", ZCL_LAND_ATTEST_SCHEMA) &&
        dl_attest_string(j, "candidate", dl_attest_head) &&
        dl_attest_string(j, "base", dl_attest_base) &&
        dl_attest_string(j, "tree", dl_attest_tree) &&
        dl_attest_string(j, "executable_sha256", image) &&
        dl_attest_string(j, "compiled_source_sha256", source) &&
        dl_attest_string(j, "service_origin", "UNKNOWN");
}

static bool dl_attest_clock(const struct json_value *j, int64_t now)
{
    const struct json_value *seq = json_get(j, "seq");
    const struct json_value *clock = json_get(j, "observed_at_ms");
    return seq && seq->type == JSON_INT && seq->val.i == 410 &&
        clock && clock->type == JSON_INT && clock->val.i > 0 &&
        now >= clock->val.i && now - clock->val.i <= 5000;
}

static bool dl_attest_flags(const struct json_value *j, bool *enabled)
{
    const struct json_value *unsealed = json_get(j, "unsealed");
    const struct json_value *a = json_get(j, "allow_unsigned_is_one");
    const struct json_value *b = json_get(j, "proof_stub_nonempty");
    const struct json_value *both = json_get(j, "fixture_exception_enabled");
    bool ok = unsealed && unsealed->type == JSON_BOOL && unsealed->val.b &&
        a && a->type == JSON_BOOL && b && b->type == JSON_BOOL &&
        both && both->type == JSON_BOOL && both->val.b == (a->val.b && b->val.b);
    if (ok) *enabled = both->val.b;
    return ok;
}

/* Exact producer record: refuse alternate encodings and embedded-NUL loss. */
static bool dl_attest_wire(const struct json_value *j, const char *wire, size_t length)
{
    char canonical[ZCL_LAND_ATTEST_CAP];
    size_t n = json_write(j, canonical, sizeof(canonical));
    return n == length && n < sizeof(canonical) && memcmp(canonical, wire, n) == 0;
}

/* Canonical fields contain printable ASCII without escapes. Check only the
 * declared span before the legacy reader can advance over Unicode escapes. */
static bool dl_attest_plain_wire(const char *wire, size_t length)
{
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)wire[i];
        if (c < 0x20 || c > 0x7e || c == '\\') return false;
    }
    return true;
}

bool zcl_dev_land_attestation_decode(const char *wire, size_t length,
    const char *image, const char *source, int64_t now, bool *fixture_enabled)
{
    struct json_value j = {0};
    if (fixture_enabled) *fixture_enabled = false;
    if (!wire || !length || length >= ZCL_LAND_ATTEST_CAP || !fixture_enabled ||
        !dl_hex_ok(image, 64) || !dl_hex_ok(source, 64) || now <= 0) {
        fprintf(stderr, "land attestation: invalid consumer binding\n");
        return false;
    }
    if (!dl_attest_plain_wire(wire, length)) {
        fprintf(stderr, "land attestation: noncanonical wire byte\n");
        return false;
    }
    bool ok = json_read(&j, wire, length) && dl_attest_binding(&j, image, source) &&
        dl_attest_clock(&j, now) && dl_attest_wire(&j, wire, length) &&
        dl_attest_flags(&j, fixture_enabled);
    if (!ok) fprintf(stderr, "land attestation: malformed, stale or foreign self observation\n");
    json_free(&j);
    return ok;
}
static bool dl_join_age(int64_t observed, int64_t now)
{
    return observed > 0 && now >= observed && now - observed <= 5000;
}

static bool dl_join_equal(const char *a, const char *b)
{
    return a && b && *a && strcmp(a, b) == 0;
}

static bool dl_join_identity(const struct zcl_land_launcher_identity *a,
                             const struct zcl_land_launcher_identity *b)
{
    return dl_join_equal(a->unit, b->unit) &&
        dl_join_equal(a->descriptor_sha256, b->descriptor_sha256) &&
        dl_join_equal(a->invocation_id, b->invocation_id) &&
        dl_join_equal(a->boot_id, b->boot_id) &&
        a->manager_uid == b->manager_uid && a->pid == b->pid;
}

static bool dl_join_expected(const struct zcl_land_launcher_identity *expected)
{
    return expected && expected->pid && expected->unit && *expected->unit &&
        dl_hex_ok(expected->descriptor_sha256, 64) &&
        dl_hex_ok(expected->invocation_id, 32) && dl_hex_ok(expected->boot_id, 32);
}

static bool dl_join_matches(const struct zcl_land_launcher_identity *expected,
                            const struct zcl_land_launcher_capture *capture)
{
    const struct zcl_land_launcher_frame *frame = capture->frames;
    return dl_join_identity(expected, &capture->before) &&
        dl_join_identity(expected, &capture->after) &&
        dl_join_identity(expected, &frame->identity) &&
        frame->uid == expected->manager_uid &&
        dl_join_equal(frame->transport, "stdout") && frame->cursor && *frame->cursor;
}

static bool dl_join_fresh(const struct zcl_land_launcher_capture *capture, int64_t now)
{
    const struct zcl_land_launcher_frame *frame = capture->frames;
    return dl_join_age(capture->before.captured_at_ms, now) &&
        dl_join_age(capture->after.captured_at_ms, now) &&
        dl_join_age(frame->identity.captured_at_ms, now) &&
        dl_join_age(frame->journal_at_ms, now) &&
        capture->before.captured_at_ms <= frame->identity.captured_at_ms &&
        frame->journal_at_ms <= frame->identity.captured_at_ms &&
        frame->identity.captured_at_ms <= capture->after.captured_at_ms;
}

bool zcl_dev_land_launcher_join(
    const struct zcl_land_launcher_identity *expected,
    const struct zcl_land_launcher_capture *capture, int64_t now,
    bool *fixture_enabled)
{
    static const char image[] = "d6810cf72e0c0ea08c05e89cb5cd20f37c9d8ecb6f069fc3c38f909bf26af564";
    static const char source[] = "6f0feb89be24e387e3b9cc67074c95172ddb78d9af093dda11dcf3e135bb5248";
    if (fixture_enabled) *fixture_enabled = false;
    if (!dl_join_expected(expected) || !capture || !fixture_enabled ||
        !capture->complete || !capture->frames || capture->frame_count != 1) {
        fprintf(stderr, "land launcher join: missing or ambiguous capture\n");
        return false;
    }
    const struct zcl_land_launcher_frame *frame = capture->frames;
    if (!dl_join_matches(expected, capture) || !dl_join_fresh(capture, now)) {
        fprintf(stderr, "land launcher join: stale or mismatched invocation\n");
        return false;
    }
    if (!zcl_dev_land_attestation_decode(frame->wire, frame->length,
        image, source, now, fixture_enabled)) return false;
    /* The producer's timestamp cannot postdate the journal receipt. Keep the
     * receiver-now check too: an older journal clock must not relax freshness. */
    return zcl_dev_land_attestation_decode(frame->wire, frame->length,
        image, source, frame->journal_at_ms, fixture_enabled);
}

static bool dl_attest_image(char out[65])
{
    if (os_proc_self_exe_identity() != OS_PROC_IMAGE_IDENTITY_RUNNING_IMAGE)
        return false;
    FILE *file = os_proc_open_self_exe();
    if (!file) return false;
    struct sha256_ctx hash;
    uint8_t bytes[8192], digest[32];
    size_t total = 0, n;
    sha256_init(&hash);
    while ((n = fread(bytes, 1, sizeof(bytes), file)) != 0) {
        total += n;
        if (total > 512u * 1024u * 1024u) break;
        sha256_write(&hash, bytes, n);
    }
    bool ok = total > 0 && total <= 512u * 1024u * 1024u &&
        !ferror(file) && feof(file);
    if (fclose(file) != 0) ok = false;
    if (!ok) return false;
    sha256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

static bool dl_attest_row(const struct dl_row *row)
{
    return row && strcmp(row->state, "inflight") == 0 &&
        strcmp(row->local, dl_attest_head) == 0 &&
        strcmp(row->tip, dl_attest_head) == 0 &&
        strcmp(row->base, dl_attest_base) == 0 &&
        strcmp(row->tree, dl_attest_tree) == 0 &&
        strcmp(row->phase, "prove") == 0 && !row->publication_signature[0] &&
        !row->publication_target[0] && !row->publication_proof[0] &&
        !row->publication_bundle[0] && !row->publication_signer[0];
}

static bool dl_attest_load(struct dl_row *out)
{
    struct dl_dirs d;
    struct dl_row *rows = NULL;
    size_t count = 0, found = 0;
    char path[4096 + 32];
    if (!dl_dirs_resolve(&d, false)) return false;
    int n = snprintf(path, sizeof(path), "%s/queue.jsonl", d.land);
    bool ok = n > 0 && (size_t)n < sizeof(path) &&
        dl_load_rows(path, &rows, &count, NULL, 0);
    for (size_t i = 0; ok && i < count; ++i) {
        if (rows[i].seq != 410) continue;
        *out = rows[i];
        ++found;
    }
    ok = ok && found == 1 && dl_attest_row(out);
    free(rows);
    return ok;
}

static bool dl_attest_encode_flags(struct json_value *j)
{
    const char *allow = dl_allow_unsigned();
    bool a = allow && strcmp(allow, "1") == 0;
    bool b = dl_stub() != NULL;
    return json_push_kv_bool(j, "allow_unsigned_is_one", a) &&
        json_push_kv_bool(j, "proof_stub_nonempty", b) &&
        json_push_kv_bool(j, "fixture_exception_enabled", a && b) &&
        json_push_kv_str(j, "service_origin", "UNKNOWN");
}

static bool dl_attest_encode(struct json_value *j, const struct dl_row *row,
                            const char *image, const char *source, int64_t now)
{
    json_set_object(j);
    return json_push_kv_str(j, "schema", ZCL_LAND_ATTEST_SCHEMA) &&
        json_push_kv_int(j, "seq", 410) &&
        json_push_kv_str(j, "candidate", row->local) &&
        json_push_kv_str(j, "base", row->base) &&
        json_push_kv_str(j, "tree", row->tree) &&
        json_push_kv_bool(j, "unsealed", true) &&
        json_push_kv_str(j, "executable_sha256", image) &&
        json_push_kv_str(j, "compiled_source_sha256", source) &&
        json_push_kv_int(j, "observed_at_ms", now) && dl_attest_encode_flags(j);
}

static void dl_attest_only(struct zcl_command_reply *reply)
{
    struct dl_row row = {0};
    char image[65], wire[ZCL_LAND_ATTEST_CAP];
    const char *source = zcl_build_source_id_sha256();
    int64_t now = (int64_t)platform_time_wall_unix() * 1000;
    struct json_value j = {0};
    bool ok = now > 0 && dl_hex_ok(source, 64) && dl_attest_image(image) &&
        dl_attest_load(&row) && dl_attest_encode(&j, &row, image, source, now);
    size_t length = ok ? json_write(&j, wire, sizeof(wire)) : 0;
    bool enabled;
    ok = length && length < sizeof(wire) &&
        zcl_dev_land_attestation_decode(wire, length, image, source, now, &enabled);
    if (!ok) {
        json_free(&j);
        dl_fail(reply, "ATTESTATION_UNKNOWN", "attest_only",
            "self image/source, clock or exact unsealed row unavailable",
            "no service-origin or publication authority inferred");
        return;
    }
    json_free(&reply->data);
    reply->data = j;
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* ── dispatcher ────────────────────────────────────────────────────────── */

/* A publication beat blocked on the operator's signed intent. A failed
 * envelope carries no data on the wire, so the exact row, pair and next
 * command also ride in error.evidence and error.next_action; next[] repeats
 * the command in its reason because a leaf may not name itself there. A
 * stored intent that stopped verifying cannot be re-attached (attach
 * refuses it), so that case points at status and names the cancel. */
static void dl_push_intent_blocked(const struct dl_row *row, bool required,
                                   struct zcl_command_reply *reply)
{
    char evidence[256], command[96], reason[160];
    (void)snprintf(evidence, sizeof(evidence),
                   "seq=%lld tip=%.40s base=%.40s head=%.40s",
                   row->seq, row->tip, row->base, row->local);
    if (required) {
        (void)snprintf(command, sizeof(command),
                       "z23-dev dev land attach --seq=%lld", row->seq);
        (void)snprintf(reason, sizeof(reason),
                       "sign the proven pair, then step: %s", command);
    } else {
        (void)snprintf(command, sizeof(command), "z23-dev dev land status");
        (void)snprintf(reason, sizeof(reason),
                       "stored intent for seq=%lld no longer verifies; if it "
                       "persists: z23-dev dev land cancel --seq=%lld",
                       row->seq, row->seq);
    }
    (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
    (void)json_push_kv_int(&reply->data, "seq", row->seq);
    (void)json_push_kv_str(&reply->data, "tip", row->tip);
    (void)json_push_kv_str(&reply->data, "base", row->base);
    (void)json_push_kv_str(&reply->data, "head_commit", row->local);
    (void)json_push_kv_str(&reply->data, "next_command", command);
    if (required) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED,
                               "PUBLICATION_INTENT_REQUIRED", "push_intent",
                               true, false,
                               "canonical signed publication intent is required before push",
                               evidence);
    } else {
        dl_fail(reply, "PUBLICATION_INTENT_INVALID", "push_intent",
                "signed Git landing intent or attached bundle changed",
                evidence);
    }
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", command);
    (void)zcl_command_reply_add_next(reply, "discover.describe",
                                     "{\"path\":\"dev.land\"}", reason);
}

/* attach's one target shape: a live row at a resumable phase holding an
 * exact pair, a PASS proof for that pair, and no signed intent yet. */
static bool dl_attach_candidate(const struct dl_dirs *d,
                                const struct dl_row *row)
{
    char proof[65];
    return strcmp(row->state, "inflight") == 0 &&
           dl_resume_phase_ready(row->phase) &&
           dl_sha_ok(row->base) && dl_sha_ok(row->local) &&
           !row->publication_signature[0] &&
           dl_publication_proof_digest(d, row, proof);
}

static void dl_attach_append(char *out, size_t cap, const char *sep,
                             const char *text)
{
    size_t used = strlen(out);
    if (used + 1 < cap)
        (void)snprintf(out + used, cap - used, "%s%s", used ? sep : "", text);
}

/* attach without seq never guesses: exactly one candidate is the target;
 * none or several refuse by name, listing the candidates and live rows. */
static bool dl_attach_resolve(const struct dl_dirs *d,
                              const struct dl_row *rows, size_t count,
                              long long *seq, struct zcl_command_reply *reply)
{
    struct json_value list, item;
    char named[160] = "", live[160] = "", one[96], evidence[256];
    size_t found = 0;
    json_init(&list);
    json_set_array(&list);
    for (size_t i = 0; i < count; i++) {
        (void)snprintf(one, sizeof(one), "seq=%lld:%s/%s", rows[i].seq,
                       rows[i].state, rows[i].phase);
        dl_attach_append(live, sizeof(live), " ", one);
        if (!dl_attach_candidate(d, &rows[i]))
            continue;
        (void)snprintf(one, sizeof(one), "%lld", rows[i].seq);
        dl_attach_append(named, sizeof(named), ",", one);
        json_init(&item);
        if (json_read(&item, one, strlen(one)))
            (void)json_push_back(&list, &item);
        json_free(&item);
        *seq = rows[i].seq;
        found++;
    }
    if (found == 1) {
        json_free(&list);
        return true;
    }
    (void)snprintf(evidence, sizeof(evidence), "candidates=%s live=%s",
                   found ? named : "none", live[0] ? live : "none");
    if (found == 0)
        dl_fail(reply, "ATTACH_TARGET_NONE", "attach",
                "no live row holds a PASS exact proof without a signed intent",
                evidence);
    else
        dl_fail(reply, "ATTACH_TARGET_AMBIGUOUS", "attach",
                "several proven rows lack a signed intent; name one with --seq",
                evidence);
    (void)json_push_kv(&reply->data, "candidates", &list);
    json_free(&list);
    if (found == 0)
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action), "%s",
                       "z23-dev dev land status");
    else
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action),
                       "z23-dev dev land attach --seq=<one of %s>", named);
    return false;
}

/* An explicit seq is validated, never widened: a row that is not a live
 * exact pair refuses with its own state. */
static bool dl_attach_pick(const struct dl_row *rows, size_t count,
                           long long seq, bool publish, struct dl_row *row,
                           struct zcl_command_reply *reply)
{
    const struct dl_row *hit = NULL;
    char evidence[160];
    for (size_t i = 0; i < count && !hit; i++)
        if (rows[i].seq == seq) hit = &rows[i];
    if (hit && strcmp(hit->state, "inflight") == 0 &&
        dl_resume_phase_ready(hit->phase) &&
        dl_sha_ok(hit->base) && dl_sha_ok(hit->local)) {
        /* A prior push may have reached the remote despite a lost reply.
         * Only the ordinary step may reconcile that durable checkpoint. */
        if (publish && strcmp(hit->phase, "push") == 0) {
            dl_fail(reply, "PUSH_OUTCOME_UNKNOWN", "attach_publish",
                    "a prior push checkpoint needs independent reconciliation",
                    hit->proof_intent);
            return false;
        }
        *row = *hit;
        return true;
    }
    if (hit)
        (void)snprintf(evidence, sizeof(evidence), "seq=%lld state=%s phase=%s",
                       seq, hit->state, hit->phase);
    else
        (void)snprintf(evidence, sizeof(evidence),
                       "seq=%lld not in the live queue", seq);
    dl_fail(reply, "PUBLICATION_PAIR_UNAVAILABLE", "attach",
            "attach requires one live exact proven pair", evidence);
    (void)json_push_kv_int(&reply->data, "seq", seq);
    if (hit) {
        (void)json_push_kv_str(&reply->data, "state", hit->state);
        (void)json_push_kv_str(&reply->data, "phase", hit->phase);
    }
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", "z23-dev dev land status");
    return false;
}

static void dl_attach_proof_missing(const struct dl_dirs *d,
                                    const struct dl_row *row,
                                    struct zcl_command_reply *reply,
                                    bool waiting)
{
    if (waiting) {
        char dimension[48], detail[512];
        int64_t started = platform_time_monotonic_us();
        enum dl_proof proof = dl_proof_read(d->wt, row->local, row->base,
                                            dimension, sizeof(dimension),
                                            detail, sizeof(detail));
        dl_beat(row, "proof_status", started);
        if (proof == DL_PROOF_PENDING) {
            dl_fail(reply, "PUBLICATION_PROOF_PENDING", "attach",
                    "the reviewed pair is still proving", detail);
            return;
        }
        if (proof == DL_PROOF_FAILED) {
            dl_fail(reply, "PUBLICATION_PROOF_FAILED", "attach",
                    "the reviewed pair's proof failed", detail);
            return;
        }
    }
    dl_fail(reply, "PUBLICATION_PROOF_REQUIRED", "attach",
            "exact signed proof receipt is not PASS", row->proof_intent);
}

static void dl_attach_seal_unheld(const struct dl_dirs *d, struct dl_row *row,
                            const char *qpath,
                            struct zcl_command_reply *reply, bool publish,
                            bool waiting)
{
    char observed[80], output[512], message[1024];
    if (row->publication_signature[0]) {
        if (!dl_publication_verify(d, row))
            dl_fail(reply, "PUBLICATION_INTENT_INVALID", "attach",
                    "stored signed intent or attachment is invalid", qpath);
        else if (publish)
            dl_step_push(d, row, reply);
        else
            dl_step_reply(reply, row, "attached");
        return;
    }
    if (!dl_publication_proof_digest(d, row, row->publication_proof)) {
        dl_attach_proof_missing(d, row, reply, waiting);
        return;
    }
    if (!dl_observe_remote_main(d, row, observed, false, reply))
        return;
    if (strcmp(observed, row->base) != 0) {
        dl_fail(reply, "EXPECTED_BASE_MISMATCH", "attach",
                "remote main moved; preserve this pair and cut a successor",
                observed);
        return;
    }
    const char *ancestry[] = { "--no-replace-objects", "merge-base",
        "--is-ancestor", row->base, row->local, NULL };
    if (dl_git(d->wt, ancestry, output, sizeof(output), DL_GIT_TIMEOUT_MS) != 0 ||
        !dl_publication_target(d, row->publication_target) ||
        !dl_publication_bundle_make(d, row, row->publication_bundle) ||
        !dl_publication_sign(row) ||
        !dl_publication_message(row, message, sizeof(message)) ||
        !dl_publication_verify(d, row)) {
        dl_fail(reply, "PUBLICATION_INTENT_INVALID", "attach",
                "cannot seal exact target, proof, base, head and bundle",
                d->land);
        return;
    }
    if (!dl_commit_row(d, row, false)) {
        dl_fail(reply, "PUBLICATION_INTENT_PERSIST_FAILED", "attach",
                "signed landing intent was not durable; push remains blocked",
                qpath);
        return;
    }
    if (publish)
        dl_step_push(d, row, reply);
    else
        dl_step_reply(reply, row, "attached");
}

static void dl_attach_seal(const struct dl_dirs *d, struct dl_row *row,
                            const char *qpath, struct zcl_command_reply *reply,
                            bool publish, bool waiting)
{
    if (!dl_publication_held(row, reply))
        dl_attach_seal_unheld(d, row, qpath, reply, publish, waiting);
}

struct dl_attach_target {
    long long seq;
    bool explicit_seq;
    const char *base;
    const char *head;
};

static bool dl_attach_target_parse(const struct zcl_command_request *req,
                                   struct dl_attach_target *target,
                                   struct zcl_command_reply *reply)
{
    target->explicit_seq = req && req->input && json_get(req->input, "seq");
    bool base_present = req && req->input && json_get(req->input, "base");
    bool head_present = req && req->input && json_get(req->input, "head");
    target->base = dl_str(req, "base");
    target->head = dl_str(req, "head");
    if ((base_present || head_present) &&
        (!target->base || !target->head || !dl_sha_ok(target->base) ||
         !dl_sha_ok(target->head))) {
        dl_fail(reply, "BAD_INPUT", "attach",
                "base and head must be supplied together as exact commit IDs",
                "input.base/input.head");
        return false;
    }
    if (target->explicit_seq && !dl_seq_in(req, &target->seq)) {
        dl_fail(reply, "BAD_INPUT", "attach",
                "seq must be a live request sequence (1 or more); omit it to "
                "attach the one proven row", "input.seq");
        return false;
    }
    return true;
}

static bool dl_attach_target_pick(const struct dl_dirs *d,
                                  const struct dl_row *rows, size_t count,
                                  struct dl_attach_target *target,
                                  bool publish, struct dl_row *row,
                                  struct zcl_command_reply *reply)
{
    if (!target->explicit_seq &&
        !dl_attach_resolve(d, rows, count, &target->seq, reply))
        return false;
    if (!dl_attach_pick(rows, count, target->seq, publish, row, reply))
        return false;
    if (target->base && (strcmp(row->base, target->base) != 0 ||
                         strcmp(row->local, target->head) != 0)) {
        char evidence[256];
        (void)snprintf(evidence, sizeof(evidence),
                       "seq=%lld expected_base=%s expected_head=%s actual_base=%s actual_head=%s",
                       target->seq, target->base, target->head,
                       row->base, row->local);
        dl_fail(reply, "PUBLICATION_PAIR_CHANGED", "attach",
                "reviewed exact base/head no longer names this row", evidence);
        return false;
    }
    return true;
}

static void dl_attach_once(const struct zcl_command_request *req,
                           struct zcl_command_reply *reply, bool publish,
                           bool waiting)
{
    struct dl_dirs d;
    struct dl_row *rows = NULL, row = {0};
    struct dl_attach_target target = {0};
    size_t count = 0;
    char qpath[4096 + 32];
    int slot;
    /* A present seq is the operator's explicit target and wins; an absent
     * one resolves under the step lock to the single proven row. */
    if (!dl_attach_target_parse(req, &target, reply))
        return;
    if (!dl_dirs_make(&d) ||
        snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d.land) >=
            (int)sizeof(qpath)) {
        dl_fail(reply, "STATE_DIR_FAILED", "attach",
                "cannot resolve the existing landing queue", "platform_state_root");
        return;
    }
    slot = dl_step_lock(d.land);
    if (slot < 0) { dl_step_busy(reply, d.land); return; }
    if (dl_fence_blocks(&d, target.explicit_seq ? target.seq : 0)) {
        dl_fail(reply, "FENCE_ACTIVE", "attach",
                "paired fence owns publication until paired settlement", d.land);
        goto done;
    }
    if (!dl_load_rows(qpath, &rows, &count, NULL, 0)) {
        dl_fail(reply, "QUEUE_READ_FAILED", "attach",
                "cannot read the existing landing queue", qpath);
        goto done;
    }
    if (!dl_attach_target_pick(&d, rows, count, &target, publish, &row, reply))
        goto done;
    dl_attach_seal(&d, &row, qpath, reply, publish, waiting);
    if (reply->status == ZCL_COMMAND_STATUS_PASSED)
        (void)json_push_kv_str(&reply->data, "target",
                               target.explicit_seq ? "explicit" : "resolved");
done:
    free(rows);
    dl_unlock(slot);
}

/* Explicit review may start while an exact proof is still running. Poll its
 * immutable pair, dropping step.lock after every read; a new row, successor,
 * failure, or absent signed PASS returns by name. Only the final successful
 * poll seals and pushes under the lock. */
static bool dl_attach_wait_input(const struct zcl_command_request *req,
                                 bool publish, int64_t *wait_ms,
                                 struct zcl_command_reply *reply)
{
    const struct json_value *value = req && req->input
        ? json_get(req->input, "wait_ms") : NULL;
    *wait_ms = value ? json_get_int(value) : 0;
    if (value && (!publish || value->type != JSON_INT ||
                  *wait_ms < 1 || *wait_ms > 900000 ||
                  !json_get(req->input, "seq") || !dl_str(req, "base") ||
                  !dl_str(req, "head"))) {
        dl_fail(reply, "BAD_INPUT", "attach",
                "wait_ms needs attach_publish, seq, base and head; maximum 900000 ms",
                "input.wait_ms");
        return false;
    }
    return true;
}

static void dl_attach_reply_reset(struct zcl_command_reply *reply)
{
    zcl_command_reply_free(reply);
    zcl_command_reply_init(reply, "zcl.land.v1");
}

static void dl_attach_wait_expired(const struct zcl_command_request *req,
                                   struct zcl_command_reply *reply,
                                   int64_t wait_ms, bool step_busy)
{
    char evidence[192];
    (void)snprintf(evidence, sizeof(evidence),
                   "seq=%lld base=%s head=%s wait_ms=%lld",
                   (long long)json_get_int(json_get(req->input, "seq")),
                   dl_str(req, "base"), dl_str(req, "head"),
                   (long long)wait_ms);
    dl_attach_reply_reset(reply);
    dl_fail(reply, step_busy ? "PUBLICATION_STEP_WAIT_EXPIRED"
                             : "PUBLICATION_PROOF_WAIT_EXPIRED",
            "attach",
            step_busy ? "landing step lock stayed busy through the wait budget"
                      : "reviewed exact proof stayed pending through the wait budget",
            evidence);
}

static void dl_attach(const struct zcl_command_request *req,
                      struct zcl_command_reply *reply, bool publish)
{
    int64_t wait_ms = 0;
    if (!dl_attach_wait_input(req, publish, &wait_ms, reply))
        return;
    int64_t deadline = platform_time_monotonic_ms() + wait_ms;
    for (;;) {
        dl_attach_once(req, reply, publish, wait_ms > 0);
        bool proof_pending = strcmp(reply->error.code,
                                    "PUBLICATION_PROOF_PENDING") == 0;
        bool step_busy = strcmp(reply->error.code, "STEP_BUSY") == 0;
        if (wait_ms == 0 || (!proof_pending && !step_busy))
            return;
        if (platform_time_monotonic_ms() >= deadline) {
            dl_attach_wait_expired(req, reply, wait_ms, step_busy);
            return;
        }
        dl_attach_reply_reset(reply);
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 100000000L };
        (void)nanosleep(&pause, NULL);
    }
}

static void dl_fence_status(struct zcl_command_reply *reply)
{
    struct dl_dirs d;
    if (!dl_dirs_resolve(&d, false)) return;
    struct dl_fence *f = zcl_malloc(sizeof(*f), "dev.land.fence.status");
    if (!f) return;
    int rc = dl_fence_read(&d, f);
    if (rc != 0) {
        struct json_value info;
        json_init(&info); json_set_object(&info);
        (void)json_push_kv_str(&info, "state", rc < 0 ? "unavailable" :
            f->stage == 2 ? "projected" : f->stage == 1 ? "settlement_pending" : "unknown");
        if (rc == 1) {
            (void)json_push_kv_int(&info, "old_seq", f->anchor.seq);
            (void)json_push_kv_int(&info, "replacement_seq", f->next.seq);
            (void)json_push_kv_str(&info, "old_head", f->anchor.local);
            (void)json_push_kv_str(&info, "replacement_head", f->next.local);
            (void)json_push_kv_str(&info, "historical_git_acceptance",
                                   strcmp(f->old.state, "landed") == 0 ? "verified" : "unknown");
            (void)json_push_kv_str(&info, "future_dispatch",
                                   strcmp(f->old.state, "fenced") == 0 ? "fenced" : "unknown");
            (void)json_push_kv_str(&info, "observed_main", f->observed);
            (void)json_push_kv_str(&info, "policy_digest", f->policy);
        }
        (void)json_push_kv(&reply->data, "fence", &info);
        json_free(&info);
    }
    free(f);
}

#if !defined(_WIN32)
static bool dl_fence_archive(const struct dl_dirs *d, const struct dl_fence *f, struct zcl_command_reply *reply)
{
    {
        char path[4192], archive[4192];
        if (!dl_fence_path(d, path) || snprintf(archive, sizeof(archive),
                "%s/fence-%lld.jsonl", d->land, f->anchor.seq) >= (int)sizeof(archive)) {
            dl_fence_blocked(reply, "FENCE_ARCHIVE_FAILED", f); return false;
        }
        bool archived = link(path, archive) == 0;
        if (!archived && errno == EEXIST) {
            char current_hash[65], archive_hash[65];
            archived = dl_publication_file_sha256(path, DL_FENCE_CAP, current_hash) &&
                dl_publication_file_sha256(archive, DL_FENCE_CAP, archive_hash) &&
                strcmp(current_hash, archive_hash) == 0;
        }
        if (!archived || !dl_queue_parent_flush(d->land)) {
            dl_fence_blocked(reply, "FENCE_ARCHIVE_FAILED", f); return false;
        }
    }
    return true;
}

static bool dl_fence_workspace(const struct dl_dirs *d, struct dl_dirs *next_dirs, const char *worktree, const char *tip, struct zcl_command_reply *reply)
{
    char current[80];
    *next_dirs = *d;
    if (!realpath(worktree, next_dirs->wt) || strcmp(next_dirs->wt, d->wt) == 0 ||
        !dl_submit_tip_resolve(next_dirs->wt, tip, current, reply) ||
        strcmp(current, tip) != 0 || !dl_rev_parse(next_dirs->wt, "HEAD", current) ||
        strcmp(current, tip) != 0 || !dl_fence_hooks_admitted(next_dirs->wt)) {
        dl_fail(reply, "FENCE_WORKTREE_INVALID", "fence_replace",
                 "replacement must be an isolated prepared checkout at its exact tip",
                 worktree); return false;
    }
    return true;
}

static bool dl_fence_old_load(const struct dl_dirs *d, struct dl_row *rows, size_t count, long long seq, const char *base, const char *head, struct dl_row **found, struct zcl_command_reply *reply)
{
    struct dl_row *old = NULL;
    for (size_t i = 0; i < count; ++i) {
        if (rows[i].seq == seq) old = &rows[i];
        else if (strcmp(rows[i].state, "inflight") == 0) return false;
    }
    if (!old || old->publication_hold || strcmp(old->state, "inflight") || strcmp(old->phase, "push") ||
        strcmp(old->base, base) || strcmp(old->local, head) ||
        !dl_publication_verify(d, old)) {
        dl_fail(reply, "FENCE_OLD_INTENT_CHANGED", "fence_replace",
                 "old sequence, pair and signed intent must match under native locks",
                 "locked queue identity");
        return false;
    }
    *found = old;
    return true;
}

static bool dl_fence_new_qualify(const struct dl_dirs *next_dirs, struct dl_row *next, const struct dl_row *old, const char *base, const char *tip, struct zcl_command_reply *reply)
{
    if (!dl_proof_intent_bind(next_dirs, next) || strcmp(next->tree, old->tree) ||
        dl_fence_ancestor(next_dirs, base, tip) != 0 ||
        !dl_fence_all_signed(next_dirs, next) ||
        !dl_publication_proof_digest(next_dirs, next, next->publication_proof) ||
        !dl_publication_target(next_dirs, next->publication_target) ||
        strcmp(next->publication_target, old->publication_target) ||
        !dl_publication_bundle_make(next_dirs, next, next->publication_bundle) ||
        !dl_publication_sign(next) || !dl_publication_verify(next_dirs, next)) {
        dl_fail(reply, "FENCE_NEW_PAIR_UNQUALIFIED", "fence_replace",
                 "same tree still requires all-signed range and its own exact proof/intent",
                 tip); return false;
    }
    return true;
}

static bool dl_fence_contract(const struct dl_dirs *next_dirs, struct dl_fence *f, const char *base, const char *tip, struct zcl_command_reply *reply)
{
    char output[1024];
    const char *clean[] = { "status", "--porcelain", "--untracked-files=no", NULL };
    if (dl_git(next_dirs->wt, clean, output, sizeof(output), 10000) != 0 || output[0] ||
        !dl_fence_policy(next_dirs, f->policy) ||
        !dl_fetch_remote_main(next_dirs->wt, f->observed) ||
        strcmp(f->observed, base)) {
        dl_fail(reply, "FENCE_CONTRACT_UNAVAILABLE", "fence_replace",
                 "clean exact checkout, current enforced no-rewind policy and unchanged base required",
                 tip); return false;
    }
    return true;
}

static bool dl_fence_input(const struct zcl_command_request *req, long long *seq,
                            const char *base, const char *head, const char *tip,
                            const char *worktree, struct zcl_command_reply *reply)
{
    if (!dl_seq_in(req, seq) || !dl_sha_ok(base) || !dl_sha_ok(head) ||
        !dl_sha_ok(tip) || strcmp(head, tip) == 0 || !worktree ||
        !dl_worktree_shape_ok(worktree)) {
        dl_fail(reply, "BAD_INPUT", "fence_replace",
                 "seq/base/head pins, distinct exact tip and isolated worktree required",
                 "input.seq/base/head/tip/worktree"); return false;
    }
    return true;
}

static bool dl_fence_existing(int existing, const struct dl_fence *f, long long seq,
                               const char *base, const char *head, const char *tip,
                               const char *worktree, struct zcl_command_reply *reply)
{
    if (existing < 0) { dl_fence_blocked(reply, "FENCE_READ_FAILED", NULL); return true; }
    if (existing == 1 && f->anchor.seq == seq) {
        if (strcmp(f->anchor.base, base) || strcmp(f->anchor.local, head) ||
            strcmp(f->next.local, tip) || strcmp(f->next.worktree, worktree)) {
            dl_fence_blocked(reply, "FENCE_IDENTITY_FROZEN", f); return true;
        }
        (void)json_push_kv_int(&reply->data, "replacement_seq", f->next.seq);
        dl_step_reply(reply, &f->next, f->stage == 2 ? f->next.state : "fence_armed");
        return true; /* Idempotent attachment is never an implicit dispatch. */
    }
    if (existing == 1 && f->stage != 2) {
        dl_fence_blocked(reply, "FENCE_ACTIVE", f); return true;
    }
    return false;
}

static bool dl_fence_locked_queue(const struct dl_dirs *d, char qpath[4192],
                                   int *lock, struct dl_row **rows, size_t *count)
{
    if (snprintf(qpath, 4192, "%s/queue.jsonl", d->land) >= 4192) return false;
    *lock = dl_rows_lock(d->land);
    return *lock >= 0 && dl_load_rows(qpath, rows, count, NULL, 0);
}

static bool dl_fence_initialize(const struct dl_dirs *d, const struct dl_dirs *next_dirs,
                                  struct dl_fence *f, const struct dl_row *old,
                                  struct dl_row *rows, size_t count, const char *base, const char *tip)
{
    f->anchor = *old;
    f->old = *old;
    struct dl_row *next = &f->next;
    next->seq = 1;
    const char *why = NULL;
    if (!dl_submit_next_seq(d, rows, count, &next->seq, &why)) return false;
    next->priority_seq = next->seq; next->attempt = 1;
    next->fence_peer = old->seq;
    dl_now_iso(next->ts);
    (void)snprintf(next->state, sizeof(next->state), "inflight");
    (void)snprintf(next->phase, sizeof(next->phase), "push");
    (void)snprintf(next->base, sizeof(next->base), "%s", base);
    (void)snprintf(next->tip, sizeof(next->tip), "%s", tip);
    (void)snprintf(next->local, sizeof(next->local), "%s", tip);
    (void)snprintf(next->worktree, sizeof(next->worktree), "%s", next_dirs->wt);
    return true;
}

#endif

static void dl_fence_replace(const struct zcl_command_request *req,
                              struct zcl_command_reply *reply)
{
#if defined(_WIN32)
    (void)req;
    dl_fail(reply, "FENCE_WINDOWS_UNAVAILABLE", "fence_replace",
             "paired fencing requires POSIX native locks", "step.lock");
#else
    long long seq = 0;
    const char *base = dl_str(req, "base"), *head = dl_str(req, "head");
    const char *tip = dl_str(req, "tip"), *worktree = dl_str(req, "worktree");
    if (!dl_fence_input(req, &seq, base, head, tip, worktree, reply)) return;
    struct dl_dirs d, next_dirs;
    if (!dl_dirs_make(&d)) {
        dl_fail(reply, "STATE_DIR_FAILED", "fence_replace",
                 "private landing root unavailable", "platform_state_root"); return;
    }
    int slot = dl_step_lock(d.land);
    if (slot < 0) { dl_step_busy(reply, d.land); return; }
    struct dl_fence *f = zcl_malloc(sizeof(*f), "dev.land.fence.create");
    struct dl_row *rows = NULL;
    size_t count = 0;
    int lock = -1;
    char qpath[4192];
    if (!f) { dl_fence_blocked(reply, "FENCE_READ_FAILED", NULL); goto done; }
    int existing = dl_fence_read(&d, f);
    if (dl_fence_existing(existing, f, seq, base, head, tip, worktree, reply)) goto done;
    if (existing == 1 && !dl_fence_archive(&d, f, reply)) goto done;
    memset(f, 0, sizeof(*f));
    if (!dl_fence_workspace(&d, &next_dirs, worktree, tip, reply)) goto done;
    if (!dl_fence_locked_queue(&d, qpath, &lock, &rows, &count)) goto unavailable;
    struct dl_row *old = NULL;
    if (!dl_fence_old_load(&d, rows, count, seq, base, head, &old, reply)) goto done;
    if (!dl_fence_initialize(&d, &next_dirs, f, old, rows, count, base, tip)) goto unavailable;
    struct dl_row *next = &f->next;
    if (!dl_fence_new_qualify(&next_dirs, next, old, base, tip, reply)) goto done;
    if (!dl_fence_contract(&next_dirs, f, base, tip, reply)) goto done;
    dl_log_path(&next_dirs, next);
    if (!dl_fence_write(&d, f)) goto unavailable;
    dl_fence_test_crash("after_record");
    (void)json_push_kv_int(&reply->data, "replacement_seq", next->seq);
    dl_step_reply(reply, next, "fence_armed");
    goto done;
unavailable:
    dl_fence_blocked(reply, "FENCE_PERSIST_FAILED", NULL);
done:
    free(rows); free(f); dl_unlock(lock); dl_unlock(slot);
#endif
}

[[maybe_unused]] static struct dl_row *dl_hold_pick(struct dl_row *rows, size_t count,
                                   long long seq, struct zcl_command_reply *reply)
{
    struct dl_row *hit = NULL;
    for (size_t i = 0; i < count; i++) {
        if (rows[i].seq != seq) continue;
        if (hit) {
            dl_fail(reply, "QUEUE_READ_FAILED", "hold", "duplicate sequence", "locked queue");
            return NULL;
        }
        hit = &rows[i];
    }
    if (!hit) {
        dl_fail(reply, "UNKNOWN_SEQUENCE", "hold", "sequence is not in the active queue", "input.seq");
        return NULL;
    }
    if (hit->publication_signature[0] || hit->publication_bundle[0] ||
        hit->pushed[0] || hit->push_diagnostic_pending || hit->fence_peer ||
        strcmp(hit->phase, "push") == 0) {
        dl_fail(reply, "PUBLICATION_ALREADY_SEALED", "hold",
                "hold and release refuse sealed or dispatch-checkpoint rows", "locked queue");
        return NULL;
    }
    return hit;
}

[[maybe_unused]] static void dl_hold_locked(const struct dl_dirs *d, long long seq, bool hold,
                            struct zcl_command_reply *reply)
{
    char path[4192], why[128] = {0};
    struct dl_row *rows = NULL;
    size_t count = 0;
    if (snprintf(path, sizeof(path), "%s/queue.jsonl", d->land) >= (int)sizeof(path)) {
        dl_fail(reply, "QUEUE_READ_FAILED", "hold", "queue path exceeds capacity", "state root");
        return;
    }
    int lock = dl_rows_lock(d->land);
    if (lock < 0) {
        dl_fail(reply, "QUEUE_LOCK_FAILED", "hold", "cannot lock queue", path);
        return;
    }
    if (!dl_load_rows(path, &rows, &count, why, sizeof(why))) {
        dl_fail(reply, "QUEUE_READ_FAILED", "hold", "cannot read queue", why);
        goto done;
    }
    struct dl_row *hit = dl_hold_pick(rows, count, seq, reply);
    if (!hit) goto done;
    hit->publication_hold = hold;
    if (!dl_rewrite_rows(d->land, path, rows, count)) {
        dl_fail(reply, "QUEUE_WRITE_FAILED", "hold", "cannot durably retain publication hold", path);
        goto done;
    }
    dl_step_reply(reply, hit, hold ? "held" : "released");
done:
    free(rows);
    dl_unlock(lock);
}

static void dl_hold(const struct zcl_command_request *request,
                     struct zcl_command_reply *reply, bool hold)
{
#if defined(_WIN32)
    (void)request; (void)hold;
    dl_fail(reply, "UNAVAILABLE", "hold", "native queue locks unavailable on this platform", "POSIX flock required");
#else
    struct dl_dirs d;
    long long seq = 0;
    if (!dl_seq_in(request, &seq)) {
        dl_fail(reply, "BAD_INPUT", "hold", "hold/release requires a positive sequence", "input.seq");
        return;
    }
    if (!dl_dirs_make(&d)) {
        dl_fail(reply, "STATE_DIR_FAILED", "hold", "private state root unavailable", "state root");
        return;
    }
    int slot = dl_step_lock(d.land);
    if (slot < 0) { dl_step_busy(reply, d.land); return; }
    if (dl_fence_blocks(&d, seq))
        dl_fail(reply, "PUBLICATION_FENCED", "hold", "sequence is owned by a retained fence", "input.seq");
    else
        dl_hold_locked(&d, seq, hold, reply);
    dl_unlock(slot);
#endif
}

static bool dl_hold_action(const char *action,
                            const struct zcl_command_request *request,
                            struct zcl_command_reply *reply)
{
    if (strcmp(action, "hold") == 0) { dl_hold(request, reply, true); return true; }
    if (strcmp(action, "release") == 0) { dl_hold(request, reply, false); return true; }
    return false;
}

void zcl_native_handle_dev_land(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    const char *action;
    if (!reply)
        return;
    if (!request || !request->input) {
        dl_fail(reply, "BAD_INPUT", "route",
                "dev land needs an action: submit|attach|attach_publish|status|step|drive|hold|release|cancel|fence_replace",
                "request.input was missing");
        return;
    }
    action = dl_str(request, "action");
    if (!action) {
        dl_fail(reply, "BAD_INPUT", "route",
                "dev land needs an action: submit|attach|attach_publish|status|step|drive|hold|release|cancel|fence_replace",
                "input.action missing or empty");
        return;
    }
    if (strcmp(action, "attest_only") == 0) {
        dl_attest_only(reply);
        return;
    }
    if (dl_hold_action(action, request, reply)) return;
    if (strcmp(action, "submit") == 0) {
        dl_submit(request, reply);
        return;
    }
    if (strcmp(action, "fence_replace") == 0) {
        dl_fence_replace(request, reply);
        return;
    }
    if (strcmp(action, "attach") == 0) {
        dl_attach(request, reply, false);
        return;
    }
    if (strcmp(action, "attach_publish") == 0) {
        dl_attach(request, reply, true);
        return;
    }
    if (strcmp(action, "status") == 0) {
        dl_status(request, reply);
        dl_fence_status(reply);
        return;
    }
    if (strcmp(action, "step") == 0) {
        dl_step(request, reply);
        return;
    }
    if (strcmp(action, "drive") == 0) {
        dl_drive(request, reply);
        return;
    }
    if (strcmp(action, "cancel") == 0) {
        dl_cancel(request, reply);
        return;
    }
    dl_fail(reply, "UNKNOWN_ACTION", "route",
            "action is one of submit|attach|attach_publish|status|step|drive|hold|release|cancel|fence_replace",
            "input.action unknown");
}
