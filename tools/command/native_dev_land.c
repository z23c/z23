/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.land — submit a tip for proof and push, ask what happened,
 *          and drive one scheduler step, so no agent ever waits on a proof
 *          or a push.
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
 *   action    string, required: submit | status | step | cancel. Also the
 *             first positional, so `z23-dev dev land submit ...` works.
 *   tip       submit only, required: a commit-ish resolved in the submitting
 *             checkout; the row stores the full 40-hex commit id.
 *   worktree  submit only, optional: the checkout that holds the tip.
 *             Default: the checkout root above the current directory.
 *   note      submit only, optional free text carried into the outcome row.
 *   seq       cancel only, required: the request sequence number.
 *   json      status only, optional bool: drop the human screen.
 *
 * STATE. <platform_state_root>/land (0700):
 *   queue.jsonl     one JSON object per line; the live request rows.
 *   outcomes.jsonl  one appended row per terminal outcome, newest last.
 *   queue.lock      the short row-file lock (seq assignment, rewrite).
 *   slot.lock       the HOST-WIDE landing slot, taken NON-BLOCKING inside
 *                   step and released before step returns. It is never held
 *                   across steps: a second host proving the same tip is not
 *                   this host's problem.
 *   wt/             the private landing worktree, created once and reused.
 *   logs/           one log per attempt; a failure row names its log.
 * Every outcome also appends to <platform_state_root>/mail/outbox.jsonl when
 * that directory exists, so an agent learns the result by pulling its mail
 * rather than by waiting on this queue.
 *
 * OUTPUT (zcl.land.v1) on ok=true: leaf is always "dev.land", plus per
 * action: submit {seq, tip, state:"queued"}; status {queued, in_flight,
 * outcomes} plus screen unless json=true; step {state} where state is one of
 * empty | busy | started | proving | landed | failed | conflict | rebased;
 * cancel {seq, state:"cancelled"}.
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
 * PROCESS RULE. `git` and `make` (lint-fast, install-hooks) are the only
 * programs this leaf runs, always through util/spawn.h's
 * zcl_spawn_capture(); popen(), system(), and a shell command string are
 * forbidden and gated. The exact proof is requested through the existing
 * dev.proof machinery (tools/dev/dev_proof.c), never re-implemented. The
 * final push carries no --no-verify: it goes through the installed
 * pre-push hook like any other push to main, and that hook's exact-receipt
 * admission (tools/dev/z23_git_hook.c) is what keeps it fast.
 *
 * NOTHING WAITS. submit, status and cancel touch only local files. step does
 * the rebase and the lint pass it was called to do and then RETURNS on the
 * proof request; a later step reads the proof's own state. No call here ever
 * sleeps, polls, or waits for a proof to finish.
 */

#include "command/native_command.h"
#include "command/native_devagent.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "util/spawn.h"

#ifdef ZCL_DEV_BUILD
#include "command/native_dev_loop_command.h"
#include "dev_proof.h"
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

static bool dl_dirs_make(struct dl_dirs *d)
{
    int n;
    if (!d || !platform_state_root(d->root, sizeof(d->root)))
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
    return dl_mkdir_one(d->land) && dl_mkdir_one(d->logs);
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

static bool dl_escape(const char *in, char *out, size_t cap)
{
    size_t used = 0;
    if (!in || !out || cap == 0)
        return false;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        const char *rep = NULL;
        char tmp[8];
        switch (*p) {
        case '"': rep = "\\\""; break;
        case '\\': rep = "\\\\"; break;
        case '\n': rep = "\\n"; break;
        case '\r': rep = "\\r"; break;
        case '\t': rep = "\\t"; break;
        default: break;
        }
        if (rep) {
            if (used + 2 >= cap)
                return false;
            out[used++] = rep[0];
            out[used++] = rep[1];
        } else if (*p < 0x20) {
            int w = snprintf(tmp, sizeof(tmp), "\\u%04x", *p);
            if (w != 6 || used + 6 >= cap)
                return false;
            memcpy(out + used, tmp, 6);
            used += 6;
        } else {
            if (used + 1 >= cap)
                return false;
            out[used++] = (char)*p;
        }
    }
    if (used >= cap)
        return false;
    out[used] = '\0';
    return true;
}

/* ── minimal per-line field extraction (a malformed row is skipped) ────── */

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

static bool dl_line_str(const char *line, const char *key, char *out,
                        size_t cap)
{
    char pat[64];
    const char *p;
    size_t used = 0;
    (void)snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    p = strstr(line, pat);
    if (!p || !out || cap == 0)
        return false;
    p += strlen(pat);
    while (*p && *p != '"') {
        if (used + 2 > cap)
            return false;
        if (*p == '\\' && p[1]) {
            if (p[1] == 'u' && isxdigit((unsigned char)p[2]) &&
                isxdigit((unsigned char)p[3]) &&
                isxdigit((unsigned char)p[4]) &&
                isxdigit((unsigned char)p[5])) {
                out[used++] = '?';
                p += 6;
            } else {
                out[used++] = p[1];
                p += 2;
            }
        } else {
            out[used++] = *p++;
        }
    }
    if (*p != '"')
        return false;
    out[used] = '\0';
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

/* ── rows ──────────────────────────────────────────────────────────────── */

/* dl_rebase() and dl_already_landed() hand row->worktree to `git fetch` as
 * the repository argument, a POSITIONAL slot git itself parses for leading
 * "-" options ("--upload-pack=..." reaches arbitrary exec). dl_load_rows's
 * own doc comment says the queue "survives a foreign write" — queue.jsonl
 * is exactly the kind of file a crafted row can appear in without ever
 * going through dl_submit's own checkout-root resolution — so the row
 * parser, not the caller, is the trust boundary. Refuse anything that
 * isn't a real, existing directory named by an absolute path with no "-"
 * segment, sitting somewhere a landing worktree could legitimately live:
 * under the user's home, or beside the checkout doing the landing. */
static bool dl_worktree_ok(const char *wt)
{
    struct stat st;
    const char *home;
    char checkout[4096], *slash;
    if (!wt || !wt[0])
        return true; /* absent: dl_rebase falls back to origin only */
    if (wt[0] != '/')
        return false;
    for (const char *p = wt; *p; p++) {
        if (*p == '/' && p[1] == '-')
            return false;
    }
    if (stat(wt, &st) != 0 || !S_ISDIR(st.st_mode))
        return false;
    home = getenv("HOME");
    if (home && home[0]) {
        size_t hlen = strlen(home);
        if (strncmp(wt, home, hlen) == 0 &&
            (wt[hlen] == '/' || wt[hlen] == '\0'))
            return true;
    }
    if (zcl_devagent_checkout_root(".", checkout, sizeof(checkout)) &&
        (slash = strrchr(checkout, '/')) != NULL && slash != checkout) {
        size_t plen = (size_t)(slash - checkout);
        if (strncmp(wt, checkout, plen) == 0 &&
            (wt[plen] == '/' || wt[plen] == '\0'))
            return true;
    }
    return false;
}

/* state:   queued | inflight | landed | failed | conflict | cancelled
 * phase:   "" | rebase | prebuild | prove | push  (meaningful when inflight) */
struct dl_row {
    long long seq;
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
    char pushed[80];
    char dimension[48];
    char log_path[4096];
    char detail[256];
};

static bool dl_parse_row(const char *line, struct dl_row *r)
{
    if (!line || !line[0] || !r)
        return false;
    memset(r, 0, sizeof(*r));
    if (!dl_line_int(line, "seq", &r->seq) || r->seq < 1)
        return false;
    if (!dl_line_str(line, "tip", r->tip, sizeof(r->tip)) ||
        !dl_sha_ok(r->tip))
        return false;
    if (!dl_line_str(line, "state", r->state, sizeof(r->state)))
        return false;
    (void)dl_line_str(line, "ts", r->ts, sizeof(r->ts));
    (void)dl_line_str(line, "worktree", r->worktree, sizeof(r->worktree));
    if (!dl_worktree_ok(r->worktree))
        return false;
    (void)dl_line_str(line, "note", r->note, sizeof(r->note));
    (void)dl_line_str(line, "phase", r->phase, sizeof(r->phase));
    if (!dl_line_int(line, "attempt", &r->attempt) || r->attempt < 1)
        return false;
    (void)dl_line_int(line, "started", &r->started);
    (void)dl_line_str(line, "base", r->base, sizeof(r->base));
    (void)dl_line_str(line, "local", r->local, sizeof(r->local));
    (void)dl_line_str(line, "tip_pushed", r->pushed, sizeof(r->pushed));
    (void)dl_line_str(line, "dimension", r->dimension, sizeof(r->dimension));
    (void)dl_line_str(line, "log_path", r->log_path, sizeof(r->log_path));
    (void)dl_line_str(line, "detail", r->detail, sizeof(r->detail));
    return true;
}

static bool dl_encode_row(const struct dl_row *r, char *out, size_t cap,
                          size_t *len_out)
{
    char e_ts[128], e_tip[160], e_wt[8192], e_note[2048], e_state[64];
    char e_phase[64], e_base[160], e_local[160], e_pushed[160];
    /* r->detail is char[256]; dl_escape() can expand a raw control byte
     * (anything but \n/\r/\t) into a 6-byte "\u00XX" sequence, so an
     * ALL-control-byte detail needs up to 255*6=1530 bytes to escape
     * cleanly. dl_first_actionable() already sanitises what it copies into
     * detail, but detail has other writers too (the proof stub's raw
     * value among them in tests) — sized here for the true worst case of
     * its source field rather than for the sanitised common case, so a
     * source this leaf does not control can never make dl_escape refuse
     * and the whole row un-persistable. */
    char e_dim[128], e_log[8192], e_detail[256 * 6 + 16];
    int w;
    if (!r || !out || cap == 0)
        return false;
    if (!dl_escape(r->ts, e_ts, sizeof(e_ts)) ||
        !dl_escape(r->tip, e_tip, sizeof(e_tip)) ||
        !dl_escape(r->worktree, e_wt, sizeof(e_wt)) ||
        !dl_escape(r->note, e_note, sizeof(e_note)) ||
        !dl_escape(r->state, e_state, sizeof(e_state)) ||
        !dl_escape(r->phase, e_phase, sizeof(e_phase)) ||
        !dl_escape(r->base, e_base, sizeof(e_base)) ||
        !dl_escape(r->local, e_local, sizeof(e_local)) ||
        !dl_escape(r->pushed, e_pushed, sizeof(e_pushed)) ||
        !dl_escape(r->dimension, e_dim, sizeof(e_dim)) ||
        !dl_escape(r->log_path, e_log, sizeof(e_log)) ||
        !dl_escape(r->detail, e_detail, sizeof(e_detail)))
        return false;
    w = snprintf(out, cap,
                 "{\"seq\":%lld,\"ts\":\"%s\",\"tip\":\"%s\","
                 "\"worktree\":\"%s\",\"note\":\"%s\",\"state\":\"%s\","
                 "\"phase\":\"%s\",\"attempt\":%lld,\"started\":%lld,"
                 "\"base\":\"%s\",\"local\":\"%s\",\"tip_pushed\":\"%s\","
                 "\"dimension\":\"%s\",\"log_path\":\"%s\","
                 "\"detail\":\"%s\"}\n",
                 r->seq, e_ts, e_tip, e_wt, e_note, e_state, e_phase,
                 r->attempt, r->started, e_base, e_local, e_pushed, e_dim,
                 e_log, e_detail);
    if (w <= 0 || (size_t)w >= cap)
        return false;
    if (len_out)
        *len_out = (size_t)w;
    return true;
}

/* Load every parseable row. A malformed line is skipped, never fatal: the
 * queue survives a foreign write. A missing file is an empty queue. */
static bool dl_load_rows(const char *qpath, struct dl_row **rows_out,
                         size_t *n_out)
{
    char *text;
    struct dl_row *rows = NULL;
    size_t n = 0, cap = 0;
    char *save = NULL, *line;
    int read_errno = 0;
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
        return read_errno == ENOENT;
    }
    for (line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        struct dl_row r;
        struct dl_row *grow;
        if (!dl_parse_row(line, &r))
            continue;
        if (n == cap) {
            size_t ncap = cap == 0 ? 16 : cap * 2;
            if (ncap > 65536)
                break;
            grow = (struct dl_row *)zcl_realloc(rows, ncap * sizeof(*rows),
                                                "dev.land.rows");
            if (!grow)
                break;
            rows = grow;
            cap = ncap;
        }
        rows[n++] = r;
    }
    free(text);
    *rows_out = rows;
    *n_out = n;
    return true;
}

/* Whole-file rewrite under the row lock: temp file plus rename, so a
 * concurrent reader never sees a half-written queue. */
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
    return true;
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

/* The HOST-WIDE landing slot. Non-blocking on purpose: a step that cannot
 * have the slot says so and returns, because a step that waited would be
 * exactly the blocking this leaf exists to remove. */
static int dl_slot_lock(const char *landdir)
{
    char path[4096 + 32];
    if (!landdir ||
        snprintf(path, sizeof(path), "%s/slot.lock", landdir) >=
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

static void dl_outbox(const struct dl_dirs *d, const struct dl_row *r,
                      const char *event)
{
    char dir[4096 + 16], path[4096 + 32], line[DL_LINE_CAP];
    /* Same worst-case sizing as dl_encode_row's e_detail: see its comment. */
    char e_note[2048], e_detail[256 * 6 + 16], ts[64];
    struct stat st;
    int w;
    if (!d || !r || !event)
        return;
    if (snprintf(dir, sizeof(dir), "%s/mail", d->root) >= (int)sizeof(dir))
        return;
    /* Only when the mail leaf's directory already exists: this leaf creates
     * no mailbox of its own and never guesses at another leaf's layout. */
    if (stat(dir, &st) != 0 || (st.st_mode & S_IFMT) != S_IFDIR)
        return;
    if (snprintf(path, sizeof(path), "%s/outbox.jsonl", dir) >=
        (int)sizeof(path))
        return;
    if (!dl_escape(r->note, e_note, sizeof(e_note)) ||
        !dl_escape(r->detail, e_detail, sizeof(e_detail)))
        return;
    dl_now_iso(ts);
    w = snprintf(line, sizeof(line),
                 "{\"ts\":\"%s\",\"from\":\"dev.land\",\"kind\":\"land\","
                 "\"seq\":%lld,\"tip\":\"%s\",\"state\":\"%s\","
                 "\"event\":\"%s\",\"attempt\":%lld,\"dimension\":\"%s\","
                 "\"log_path\":\"%s\",\"note\":\"%s\","
                 "\"detail\":\"%s\"}\n",
                 ts, r->seq, r->tip, r->state, event, r->attempt,
                 r->dimension, r->log_path, e_note, e_detail);
    if (w > 0 && (size_t)w < sizeof(line))
        (void)dl_append_row(path, line, (size_t)w);
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

static void dl_record_outcome(const struct dl_dirs *d, struct dl_row *r)
{
    char path[4096 + 32];
    if (!d || !r)
        return;
    if (snprintf(path, sizeof(path), "%s/outcomes.jsonl", d->land) >=
        (int)sizeof(path))
        return;
    (void)dl_write_row(path, r);
    dl_outbox(d, r, "outcome");
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
    if (dl_wt_hooks_ready(wt))
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
    if (!r->worktree[0]) {
        (void)snprintf(why, why_cap, "%s",
                       "the request carries no source checkout");
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

#ifdef ZCL_DEV_BUILD
/* WHY. A proof request is only a file; the resident watcher consumes it.
 * Landing starts that watcher in verify mode, or names why it is absent,
 * rather than sitting in proving with nobody draining the queue. */
static void dl_watcher_kick(const char *wt, char *detail, size_t cap)
{
    struct json_value input;
    struct zcl_command_request req;
    struct zcl_command_reply reply;
    const char *err, *mode;
    const struct json_value *mode_v;

    if (!wt || !wt[0] || zcl_native_dev_loop_proof_queue_ready(wt))
        return;
    json_init(&input);
    json_set_object(&input);
    memset(&req, 0, sizeof(req));
    zcl_command_reply_init(&reply, "zcl.dev_loop_status.v1");
    if (json_push_kv_str(&input, "root", wt) &&
        json_push_kv_str(&input, "mode", "verify")) {
        req.input = &input;
        zcl_native_handle_dev_loop_start_async(&req, &reply);
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
    json_free(&input);
}
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
        if (!zcl_native_dev_loop_proof_queue_ready(wt))
            dl_watcher_kick(wt, detail, cap);
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

static enum dl_proof dl_proof_read(const char *wt, const char *local,
                                   const char *base, char *dimension,
                                   size_t dim_cap, char *detail, size_t cap)
{
    const char *stub = dl_stub();
    if (detail && cap)
        detail[0] = '\0';
    if (dimension && dim_cap)
        dimension[0] = '\0';
    if (stub) {
        if (strcmp(stub, "pass") == 0) {
            (void)snprintf(detail, cap, "proof stub: pass");
            return DL_PROOF_PASSED;
        }
        if (strcmp(stub, "fail") == 0) {
            (void)snprintf(dimension, dim_cap, "lint");
            (void)snprintf(detail, cap, "proof stub: fail");
            return DL_PROOF_FAILED;
        }
        if (strcmp(stub, "watcher_absent") == 0)
            (void)snprintf(detail, cap, "%s",
                           "resident_proof_watcher_absent");
        else
            (void)snprintf(detail, cap, "proof stub: %s", stub);
        return DL_PROOF_PENDING;
    }
#ifdef ZCL_DEV_BUILD
    {
        struct zcl_dev_proof_status status = {0};
        if (!zcl_dev_proof_status_read(wt, local, base, &status)) {
            (void)snprintf(detail, cap, "%s",
                           status.detail[0] ? status.detail
                                            : "proof_status_unreadable");
            return DL_PROOF_FAILED;
        }
        (void)snprintf(detail, cap, "%s",
                       status.detail[0] ? status.detail
                                        : zcl_dev_proof_state_name(
                                              status.state));
        switch (status.state) {
        case ZCL_DEV_PROOF_STATE_PASSED:
            return DL_PROOF_PASSED;
        case ZCL_DEV_PROOF_STATE_FAILED:
            (void)snprintf(dimension, dim_cap, "%s",
                           status.detail[0] ? status.detail : "proof");
            return DL_PROOF_FAILED;
        case ZCL_DEV_PROOF_STATE_INVALID:
            return DL_PROOF_UNAVAILABLE;
        default:
            return DL_PROOF_PENDING;
        }
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

static void dl_submit(const struct zcl_command_request *req,
                      struct zcl_command_reply *reply)
{
    struct dl_dirs d;
    struct dl_row r;
    struct dl_row *rows = NULL;
    size_t nrows = 0;
    char qpath[4096 + 32], line[DL_LINE_CAP];
    char root[4096], sig[64], full[80], ts[64];
    const char *tip, *worktree, *note;
    const char *allow_unsigned = dl_allow_unsigned();
    size_t len = 0;
    int lock = -1;
    long long seq = 1;

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
    if (!dl_rev_parse(root, tip, full)) {
        dl_fail(reply, "TIP_UNKNOWN", "submit",
                "that commit does not exist in the checkout",
                "git rev-parse --verify refused the tip");
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
    if (dl_load_rows(qpath, &rows, &nrows)) {
        for (size_t i = 0; i < nrows; i++) {
            if (rows[i].seq >= seq)
                seq = rows[i].seq + 1;
        }
    }
    free(rows);
    r.seq = seq;
    if (!dl_encode_row(&r, line, sizeof(line), &len) ||
        !dl_append_row(qpath, line, len)) {
        dl_unlock(lock);
        dl_fail(reply, "QUEUE_WRITE_FAILED", "submit",
                "cannot append the request row", qpath);
        return;
    }
    dl_unlock(lock);
    dl_outbox(&d, &r, "queued");
    (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
    (void)json_push_kv_int(&reply->data, "seq", r.seq);
    (void)json_push_kv_str(&reply->data, "tip", r.tip);
    (void)json_push_kv_str(&reply->data, "state", "queued");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* ── cancel ────────────────────────────────────────────────────────────── */

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
    lock = dl_rows_lock(d.land);
    if (lock < 0) {
        dl_fail(reply, "QUEUE_READ_FAILED", "cancel",
                "cannot take the queue lock", qpath);
        return;
    }
    if (!dl_load_rows(qpath, &rows, &nrows)) {
        dl_unlock(lock);
        dl_fail(reply, "QUEUE_READ_FAILED", "cancel",
                "cannot read the queue file", qpath);
        return;
    }
    memset(&hit, 0, sizeof(hit));
    for (size_t i = 0; i < nrows; i++) {
        if (rows[i].seq == seq && !found) {
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
    if (!dl_rewrite_rows(d.land, qpath, rows, kept)) {
        free(rows);
        dl_unlock(lock);
        dl_fail(reply, "QUEUE_WRITE_FAILED", "cancel",
                "cannot rewrite the queue file", qpath);
        return;
    }
    free(rows);
    dl_unlock(lock);
    (void)snprintf(hit.state, sizeof(hit.state), "cancelled");
    hit.phase[0] = '\0';
    (void)snprintf(hit.detail, sizeof(hit.detail), "%s",
                   "cancelled by the operator");
    dl_record_outcome(&d, &hit);
    (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
    (void)json_push_kv_int(&reply->data, "seq", seq);
    (void)json_push_kv_str(&reply->data, "tip", hit.tip);
    (void)json_push_kv_str(&reply->data, "state", "cancelled");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* ── status ────────────────────────────────────────────────────────────── */

static bool dl_push_queued(struct json_value *arr, const struct dl_row *r)
{
    struct json_value item;
    bool ok;
    json_init(&item);
    json_set_object(&item);
    ok = json_push_kv_int(&item, "seq", r->seq) &&
         json_push_kv_str(&item, "tip", r->tip) &&
         json_push_kv_str(&item, "ts", r->ts) &&
         json_push_kv_int(&item, "attempt", r->attempt) &&
         json_push_kv_str(&item, "note", r->note) &&
         json_push_back(arr, &item);
    json_free(&item);
    return ok;
}

static bool dl_push_inflight(struct json_value *obj, const struct dl_row *r,
                             long long now)
{
    long long elapsed = now - r->started;
    if (elapsed < 0)
        elapsed = 0;
    return json_push_kv_int(obj, "seq", r->seq) &&
           json_push_kv_str(obj, "tip", r->tip) &&
           json_push_kv_str(obj, "phase", r->phase) &&
           json_push_kv_int(obj, "attempt", r->attempt) &&
           json_push_kv_int(obj, "elapsed_s", elapsed) &&
           json_push_kv_str(obj, "base", r->base);
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
         json_push_kv_int(&item, "attempt", r->attempt) &&
         json_push_kv_str(&item, "tip_pushed", r->pushed) &&
         json_push_kv_str(&item, "dimension", r->dimension) &&
         json_push_kv_str(&item, "log_path", r->log_path) &&
         json_push_kv_str(&item, "detail", r->detail) &&
         json_push_back(arr, &item);
    json_free(&item);
    return ok;
}

static void dl_status(const struct zcl_command_request *req,
                      struct zcl_command_reply *reply)
{
    struct dl_dirs d;
    struct dl_row *rows = NULL;
    struct dl_row last[10];
    size_t nrows = 0, nlast = 0;
    char qpath[4096 + 32], opath[4096 + 32], screen[16384];
    struct json_value queued, inflight, outcomes;
    long long now = (long long)platform_time_wall_unix();
    bool want_json = false, have_inflight = false;
    size_t used = 0;
    int w;
    if (req && req->input) {
        const struct json_value *jv = json_get(req->input, "json");
        want_json = jv && jv->type == JSON_BOOL && json_get_bool(jv);
    }
    if (!dl_dirs_make(&d)) {
        dl_fail(reply, "STATE_DIR_FAILED", "status",
                "cannot resolve the owner-private state root",
                "platform_state_root");
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
    if (!dl_load_rows(qpath, &rows, &nrows)) {
        dl_fail(reply, "QUEUE_READ_FAILED", "status",
                "cannot read the queue file", qpath);
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
            if (!dl_push_inflight(&inflight, &rows[i], now))
                goto fail;
            have_inflight = true;
        }
    }
    /* The last ten outcomes, oldest first. */
    {
        char *text = (char *)zcl_malloc(DL_FILE_CAP, "dev.land.outcomes");
        if (!text)
            goto fail;
        if (dl_read_file(opath, text, DL_FILE_CAP, NULL)) {
            char *save = NULL, *line;
            for (line = strtok_r(text, "\n", &save); line;
                 line = strtok_r(NULL, "\n", &save)) {
                struct dl_row o;
                if (!dl_parse_row(line, &o))
                    continue;
                if (nlast == sizeof(last) / sizeof(last[0])) {
                    for (size_t k = 1; k < nlast; k++)
                        last[k - 1] = last[k];
                    nlast--;
                }
                last[nlast++] = o;
            }
        }
        free(text);
        for (size_t k = 0; k < nlast; k++) {
            if (!dl_push_outcome_row(&outcomes, &last[k]))
                goto fail;
        }
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
                         "  #%lld %.12s %-8s attempt %lld, %llds\n",
                         rows[i].seq, rows[i].tip, rows[i].phase,
                         rows[i].attempt, elapsed);
            if (w <= 0 || (size_t)w >= sizeof(screen) - used)
                goto render_done;
            used += (size_t)w;
        }
        for (size_t i = 0; i < nrows; i++) {
            if (strcmp(rows[i].state, "queued") != 0)
                continue;
            w = snprintf(screen + used, sizeof(screen) - used,
                         "  #%lld %.12s queued\n", rows[i].seq, rows[i].tip);
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
            "cannot encode the status reply", qpath);
}

/* ── step: one scheduler beat, and it never waits ──────────────────────── */

/* Persist one row back into the queue file, or drop it and record it as an
 * outcome when its state is terminal. */
static bool dl_commit_row(const struct dl_dirs *d, struct dl_row *row,
                          bool terminal)
{
    struct dl_row *rows = NULL;
    size_t nrows = 0, kept = 0;
    char qpath[4096 + 32];
    bool ok, found = false;
    int lock;
    if (snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", d->land) >=
        (int)sizeof(qpath))
        return false;
    lock = dl_rows_lock(d->land);
    if (lock < 0)
        return false;
    if (!dl_load_rows(qpath, &rows, &nrows)) {
        dl_unlock(lock);
        return false;
    }
    for (size_t i = 0; i < nrows; i++) {
        if (rows[i].seq == row->seq) {
            found = true;
            if (terminal)
                continue;
            rows[kept++] = *row;
            continue;
        }
        rows[kept++] = rows[i];
    }
    /* The row was picked (under the slot lock) before this commit takes
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
    ok = dl_rewrite_rows(d->land, qpath, rows, kept);
    free(rows);
    dl_unlock(lock);
    if (ok && terminal)
        dl_record_outcome(d, row);
    else if (ok)
        dl_outbox(d, row, "phase");
    return ok;
}

static void dl_step_reply(struct zcl_command_reply *reply,
                          const struct dl_row *row, const char *state)
{
    (void)json_push_kv_str(&reply->data, "leaf", DL_LEAF);
    (void)json_push_kv_str(&reply->data, "state", state);
    if (row) {
        (void)json_push_kv_int(&reply->data, "seq", row->seq);
        (void)json_push_kv_str(&reply->data, "tip", row->tip);
        (void)json_push_kv_str(&reply->data, "phase", row->phase);
        (void)json_push_kv_int(&reply->data, "attempt", row->attempt);
        if (row->pushed[0])
            (void)json_push_kv_str(&reply->data, "tip_pushed", row->pushed);
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

static void dl_log(struct dl_row *row, const char *text)
{
    if (row->log_path[0] && text)
        (void)dl_append_text(row->log_path, text);
}

/* Rebase the row's tip onto origin/main inside the private landing
 * worktree. Returns 1 rebased, 0 conflict, -1 setup failure. */
static int dl_rebase(const struct dl_dirs *d, struct dl_row *row,
                     char *why, size_t why_cap)
{
    char buf[DL_GIT_CAP];
    const char *fetch_args[] = { "fetch", "--quiet", "origin", NULL };
    const char *checkout_args[] = { "checkout", "--quiet", "--force",
                                    "--detach", row->tip, NULL };
    const char *rebase_args[] = { "rebase", "origin/main", NULL };
    const char *unmerged_args[] = { "diff", "--name-only", "--diff-filter=U",
                                    NULL };
    const char *abort_args[] = { "rebase", "--abort", NULL };
    (void)dl_git(d->wt, fetch_args, buf, sizeof(buf), DL_GIT_TIMEOUT_MS);
    if (!dl_rev_parse(d->wt, row->tip, row->local)) {
        /* The tip lives in another checkout: fetch that ONE object rather
         * than every ref the other checkout happens to hold. dl_parse_row
         * already refused a worktree it could not validate, but "--" still
         * goes in front of it: a positional git argument is git's own to
         * parse, and nothing downstream of this call should have to keep
         * proving that guarantee held all the way here. */
        const char *pull_args[] = { "fetch", "--quiet", "--no-tags", "--",
                                    row->worktree, row->tip, NULL };
        (void)dl_git(d->wt, pull_args, buf, sizeof(buf), DL_GIT_TIMEOUT_MS);
        if (!dl_rev_parse(d->wt, row->tip, row->local)) {
            (void)snprintf(why, why_cap,
                           "the landing worktree cannot resolve the tip");
            return -1;
        }
    }
    if (!dl_rev_parse(d->wt, "origin/main", row->base)) {
        (void)snprintf(why, why_cap, "origin/main is unknown here");
        return -1;
    }
    if (dl_git(d->wt, checkout_args, buf, sizeof(buf), DL_GIT_TIMEOUT_MS) !=
        0) {
        (void)snprintf(why, why_cap, "cannot check the tip out for landing");
        return -1;
    }
    if (dl_git(d->wt, rebase_args, buf, sizeof(buf), DL_GIT_TIMEOUT_MS) !=
        0) {
        char paths[DL_GIT_CAP];
        (void)dl_git(d->wt, unmerged_args, paths, sizeof(paths),
                     DL_GIT_TIMEOUT_MS);
        dl_trim(paths);
        for (char *p = paths; *p; p++) {
            if (*p == '\n')
                *p = ' ';
        }
        (void)snprintf(why, why_cap, "%s",
                       paths[0] ? paths : "rebase refused the tip");
        (void)dl_git(d->wt, abort_args, buf, sizeof(buf), DL_GIT_TIMEOUT_MS);
        return 0;
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
        if (snprintf(cfg, sizeof(cfg),
                     "submodule.vendor/tor.url=%s/vendor/tor",
                     row->worktree) >= (int)sizeof(cfg) ||
            dl_git(d->wt, gl, buf, sizeof(buf), DL_GIT_TIMEOUT_MS) != 0) {
            (void)snprintf(why, why_cap, "%s",
                           "landing_worktree_gitlink_failed");
            return -1;
        }
    }
    return 1;
}

/* make lint-fast in the landing worktree. Returns the child's status; the
 * transcript is appended to the attempt log either way. */
static int dl_lint_fast(const struct dl_dirs *d, struct dl_row *row)
{
    const char *argv[] = { "make", "-C", d->wt, "lint-fast", NULL };
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

/* A local link-then-copy primitive, deliberately not the shared
 * zcl_dev_proof_dependency_materialize() (tools/dev/dev_proof.c): that
 * function is real dev.proof machinery, and this file's own `#include
 * "dev_proof.h"` above is itself gated on ZCL_DEV_BUILD, so calling it here
 * would fail to even declare in the plain node build, and — because
 * dev_proof.c is only ever compiled into the dev/test build, never the
 * plain node's object set — would fail to LINK in a release build even if
 * the declaration were forced visible. That is the layering violation
 * DEVELOPING.md warns about, one build-profile boundary wide rather than a
 * namespace one, so this is the smallest shared helper instead: the same
 * link-with-copy-fallback shape, without the symlink case neither vendor
 * archives nor hotswap fixture images ever need (fail closed on anything
 * that is not a plain file or a directory). Unlike its sibling, this one
 * compiles into every profile — including the plain test harness that
 * exercises `test_dev_land` — so the priming below is exercised for real
 * rather than only ever seen by production. */
static bool dl_materialize_file(const char *source, const char *target,
                                const struct stat *source_st)
{
    int input, output;
    char tmp[4096 + 96];
    bool ok;
    if (link(source, target) == 0)
        return true;
    if (errno != EXDEV && errno != EPERM && errno != EMLINK)
        return false;
    input = open(source, O_RDONLY | O_CLOEXEC);
    if (input < 0)
        return false;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", target, (long)getpid()) >=
        (int)sizeof(tmp)) {
        (void)close(input);
        return false;
    }
    output = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (output < 0) {
        (void)close(input);
        return false;
    }
    ok = true;
    while (ok) {
        unsigned char buf[65536];
        ssize_t got = read(input, buf, sizeof(buf));
        ssize_t off = 0;
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0) {
            ok = false;
            break;
        }
        if (got == 0)
            break;
        while (ok && off < got) {
            ssize_t wrote = write(output, buf + off, (size_t)(got - off));
            if (wrote < 0 && errno == EINTR)
                continue;
            if (wrote < 0)
                ok = false;
            else
                off += wrote;
        }
    }
    if (ok)
        ok = fchmod(output, source_st->st_mode & 07777) == 0;
    if (close(input) != 0)
        ok = false;
    if (close(output) != 0)
        ok = false;
    if (ok && rename(tmp, target) != 0)
        ok = false;
    if (!ok)
        (void)unlink(tmp);
    return ok;
}

static bool dl_materialize(const char *source, const char *target)
{
    struct stat source_st, target_st;
    DIR *dir;
    struct dirent *entry;
    bool ok;
    if (lstat(source, &source_st) != 0)
        return false;
    if (lstat(target, &target_st) == 0)
        return true; /* the caller already checked readiness */
    if (S_ISREG(source_st.st_mode))
        return dl_materialize_file(source, target, &source_st);
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
 * dl_materialize() link-then-copy primitive above, which mirrors the
 * proof's own generation-prep copier without depending on it (see that
 * function's comment for why). Each entry is checked and refused by name,
 * matching dev_proof.c's own vocabulary, so a dependency missing from the
 * submitting checkout too is never silently skipped. */
static const char *const DL_VENDOR_DEPS[] = {
    "vendor/lib",
    "vendor/include",
    "vendor/tor/libtor.a",
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
    if (!r->worktree[0] ||
        snprintf(src_dir, sizeof(src_dir), "%s/vendor/tor", r->worktree) >=
            (int)sizeof(src_dir)) {
        (void)snprintf(why, why_cap, "%s",
                       "proof_generation_dependency_unavailable:"
                       "vendor/tor/libtor.a (no source checkout)");
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
        if (!r->worktree[0] || lstat(source, &st) != 0) {
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
}

#if defined(__linux__)
/* The rollback test group dlopens these two fixture images by name; the
 * proof's own dependency check names `make test_parallel` as their fix.
 * Since the landing worktree carries the same source revision the
 * submitting checkout does (after the rebase two steps up), copying an
 * already-built image from there is both cheap and no less faithful than
 * one built here would be, and avoids running a multi-minute full test
 * link inside a landing step just to obtain two small fixture images. */
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
        if (!r->worktree[0] || stat(source, &st) != 0) {
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

/* build/dev-loop/restart.env bakes this worktree's own absolute paths
 * (DEV_OBJ_DIR, DEV_LINK_RSP, ...), so unlike the vendored archives it
 * cannot be copied from the submitting checkout: a copy would hand the
 * proof another worktree's paths and every restart plan built into it
 * would name files that do not exist here. It has to be built, once, in
 * this worktree, through the same make target the Makefile itself builds
 * it with. */
static bool dl_wt_restart_env_ready(const char *wt)
{
    char path[4096 + 32];
    struct stat st;
    if (!wt || snprintf(path, sizeof(path),
                        "%s/build/dev-loop/restart.env", wt) >=
                   (int)sizeof(path))
        return false;
    return stat(path, &st) == 0;
}

static bool dl_wt_restart_env_ensure(const struct dl_dirs *d, char *why,
                                     size_t why_cap)
{
    char *buf;
    int rc;
    if (dl_wt_restart_env_ready(d->wt))
        return true;
    buf = (char *)zcl_malloc(DL_LOG_CAP, "dev.land.restartenv");
    if (!buf) {
        (void)snprintf(why, why_cap, "%s",
                       "out of memory building the dev-loop restart plan");
        return false;
    }
    {
        const char *argv[] = { "make", "-C", d->wt,
                               "build/dev-loop/restart.env", NULL };
        rc = zcl_spawn_capture(argv, buf, DL_LOG_CAP, DL_LINT_TIMEOUT_MS);
    }
    if (rc != 0 || !dl_wt_restart_env_ready(d->wt)) {
        (void)snprintf(why, why_cap,
                       "building build/dev-loop/restart.env failed in the "
                       "landing worktree (the proof's receipt identity "
                       "capture reads it from this worktree and cannot "
                       "use a copy from elsewhere): %.300s",
                       buf);
        free(buf);
        return false;
    }
    free(buf);
    return true;
}

/* The copy-based dependencies (vendor archives, hotswap fixtures) run
 * whenever a real proof is about to be requested, or when a test forces
 * them on despite the proof stub. The restart plan always needs a real
 * `make` invocation against a real Makefile, so it stays gated on the
 * proof stub alone: no hermetic test rig here carries one. Any failure
 * refuses with the failing dependency's own typed reason; none of them
 * silently continues past a missing one. */
static bool dl_wt_proof_deps_ensure(const struct dl_dirs *d,
                                    const struct dl_row *r, bool stubbed,
                                    char *why, size_t why_cap)
{
    if (!stubbed || dl_deps_test_force()) {
        if (!dl_wt_vendor_ensure(d, r, why, why_cap))
            return false;
#if defined(__linux__)
        if (!dl_wt_hotswap_ensure(d, r, why, why_cap))
            return false;
#endif
    }
    if (!stubbed && !dl_wt_restart_env_ensure(d, why, why_cap))
        return false;
    return true;
}

/* Take the oldest queued request and drive it to the point where the proof
 * has been ASKED FOR. Then return: the answer arrives on a later step. */
/* A row can be re-driven from "inflight" after a step that already pushed
 * successfully but then failed to persist the "landed" outcome (queue lock
 * contention, an I/O error on the rewrite). Re-proving that tip would waste
 * the proof and, worse, a second push attempt races a commit that is
 * already the tip of origin/main. Before spending a rebase/lint/proof
 * cycle, check whether the tip is already an ancestor of origin/main and,
 * if so, record it as landed directly. */
static bool dl_already_landed(const struct dl_dirs *d, struct dl_row *row)
{
    char buf[DL_GIT_CAP], commit[80];
    const char *fetch_args[] = { "fetch", "--quiet", "origin", NULL };
    const char *ancestor_args[] = { "merge-base", "--is-ancestor", commit,
                                    "origin/main", NULL };
    (void)dl_git(d->wt, fetch_args, buf, sizeof(buf), DL_GIT_TIMEOUT_MS);
    if (row->local[0] && dl_sha_ok(row->local)) {
        (void)snprintf(commit, sizeof(commit), "%s", row->local);
    } else if (!dl_rev_parse(d->wt, row->tip, commit)) {
        if (!row->worktree[0])
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

static void dl_step_start(const struct dl_dirs *d, struct dl_row *row,
                          struct zcl_command_reply *reply)
{
    char why[1024], detail[512], tickets[512];
    int rebased;
    enum dl_proof p;

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
    if (dl_already_landed(d, row)) {
        if (dl_commit_or_report(d, row, true, reply, "landed"))
            dl_step_reply(reply, row, "landed");
        return;
    }
    rebased = dl_rebase(d, row, why, sizeof(why));
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
    /* The lint pass is what the proof would discover last and cheapest to
     * discover first. The proof stub skips it: a test of this queue is not
     * a test of the lint suite. */
    (void)snprintf(row->phase, sizeof(row->phase), "prebuild");
    if (!dl_stub() && dl_lint_fast(d, row) != 0) {
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
    (void)snprintf(row->phase, sizeof(row->phase), "prove");
    p = dl_proof_request(d->wt, row->local, row->base, detail,
                         sizeof(detail));
    (void)snprintf(row->detail, sizeof(row->detail), "%s", detail);
    dl_log(row, detail);
    dl_log(row, "\n");
    if (p == DL_PROOF_UNAVAILABLE || p == DL_PROOF_FAILED) {
        (void)snprintf(row->state, sizeof(row->state), "failed");
        (void)snprintf(row->dimension, sizeof(row->dimension), "proof");
        if (dl_commit_or_report(d, row, true, reply, "failed"))
            dl_step_reply(reply, row, "failed");
        return;
    }
    /* Asked for. Nothing here waits on the answer. */
    if (dl_commit_or_report(d, row, false, reply, "started"))
        dl_step_reply(reply, row, "started");
}

/* Read the proof's own state for the in-flight request and act once. */
static void dl_step_resume(const struct dl_dirs *d, struct dl_row *row,
                           struct zcl_command_reply *reply)
{
    char detail[512], dimension[48], buf[DL_GIT_CAP];
    enum dl_proof p;

    /* A prior step can have pushed for real and then failed to persist
     * "landed" (a queue-commit failure after the fact — see
     * dl_commit_or_report). That leaves the row inflight with a STALE
     * phase="prove" pointing at a (local, base) pair that already landed:
     * dl_proof_read would report PASSED again, and the "base moved" check
     * below would misread the row's own successful push as a stranger's
     * commit and spend a whole extra rebase/proof cycle on it. Check
     * first, the same way dl_step_start does before ever starting one. */
    if (dl_already_landed(d, row)) {
        if (dl_commit_or_report(d, row, true, reply, "landed"))
            dl_step_reply(reply, row, "landed");
        return;
    }
    if (strcmp(row->phase, "prove") != 0) {
        /* A step died between phases. Re-drive from the rebase rather than
         * guessing what the dead step had already done. */
        (void)snprintf(row->phase, sizeof(row->phase), "rebase");
        dl_step_start(d, row, reply);
        return;
    }
    p = dl_proof_read(d->wt, row->local, row->base, dimension,
                      sizeof(dimension), detail, sizeof(detail));
    (void)snprintf(row->detail, sizeof(row->detail), "%s", detail);
    if (p == DL_PROOF_PENDING) {
#ifdef ZCL_DEV_BUILD
        /* WHY. Resume used to keep proving with a stale queued detail
         * while no watcher existed for the landing worktree. */
        if (!dl_stub() && !zcl_native_dev_loop_proof_queue_ready(d->wt)) {
            (void)snprintf(row->detail, sizeof(row->detail), "%s",
                           "resident_proof_watcher_absent");
            dl_watcher_kick(d->wt, row->detail, sizeof(row->detail));
        }
#endif
        if (dl_commit_or_report(d, row, false, reply, "proving"))
            dl_step_reply(reply, row, "proving");
        return;
    }
    if (p != DL_PROOF_PASSED) {
        bool host_load = dl_host_load_failure(detail);
        dl_log(row, detail);
        dl_log(row, "\n");
        if (host_load && row->attempt < DL_ATTEMPT_MAX) {
            row->attempt++;
            (void)snprintf(row->phase, sizeof(row->phase), "rebase");
            (void)snprintf(row->dimension, sizeof(row->dimension),
                           "host_load");
            dl_log_path(d, row);
            if (dl_commit_or_report(d, row, false, reply, "rebased"))
                dl_step_reply(reply, row, "rebased");
            return;
        }
        (void)snprintf(row->state, sizeof(row->state), "failed");
        (void)snprintf(row->dimension, sizeof(row->dimension), "%s",
                       dimension[0] ? dimension : "proof");
        {
            char *log = (char *)zcl_malloc(DL_LOG_CAP, "dev.land.logread");
            if (log) {
                if (dl_read_file(row->log_path, log, DL_LOG_CAP, NULL))
                    dl_first_actionable(log, row->detail,
                                        sizeof(row->detail));
                free(log);
            }
        }
        if (!row->detail[0])
            (void)snprintf(row->detail, sizeof(row->detail), "%s", detail);
        if (dl_commit_or_report(d, row, true, reply, "failed"))
            dl_step_reply(reply, row, "failed");
        return;
    }
    /* The proof passed for THIS (local, base) pair. If main moved while it
     * ran, the receipt is about a base nobody is on any more: rebase again
     * and prove again rather than pushing evidence that no longer applies. */
    {
        const char *fetch_args[] = { "fetch", "--quiet", "origin", NULL };
        char base_now[80];
        (void)dl_git(d->wt, fetch_args, buf, sizeof(buf), DL_GIT_TIMEOUT_MS);
        if (dl_rev_parse(d->wt, "origin/main", base_now) &&
            strcmp(base_now, row->base) != 0) {
            row->attempt++;
            (void)snprintf(row->detail, sizeof(row->detail),
                           "origin/main moved to %.12s while proving",
                           base_now);
            dl_log_path(d, row);
            dl_log(row, row->detail);
            dl_log(row, "\n");
            /* A base that keeps moving under a legitimately-passing proof
             * is not this row's fault, but it is still bounded: an
             * inflight row is always preferred over a queued one (dl_step
             * picks it first), so an uncapped retry here would starve
             * every other request behind a repo where main advances every
             * cycle. Fail it like any other exhausted attempt budget
             * rather than loop forever. */
            if (row->attempt > DL_ATTEMPT_MAX) {
                (void)snprintf(row->state, sizeof(row->state), "failed");
                (void)snprintf(row->dimension, sizeof(row->dimension),
                               "rebase");
                if (dl_commit_or_report(d, row, true, reply, "failed"))
                    dl_step_reply(reply, row, "failed");
                return;
            }
            (void)snprintf(row->phase, sizeof(row->phase), "rebase");
            if (dl_commit_or_report(d, row, false, reply, "rebased"))
                dl_step_reply(reply, row, "rebased");
            return;
        }
    }
    (void)snprintf(row->phase, sizeof(row->phase), "push");
    {
        /* No --no-verify: this pushes through the installed pre-push hook
         * like everyone else. dl_wt_ensure() already armed d->wt's own
         * hooks, and the exact-receipt admission the hook performs
         * (tools/dev/z23_git_hook.c) finds the very receipt this step just
         * obtained for (local, base) at
         * .cache/zcl-dev-proof/receipts/<local>-<base>.receipt, so the hook
         * admits in seconds instead of re-running the proof. */
        const char *push_args[] = { "push", "origin", "HEAD:main", NULL };
        if (dl_git(d->wt, push_args, buf, sizeof(buf), DL_GIT_TIMEOUT_MS) !=
            0) {
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
    (void)snprintf(row->pushed, sizeof(row->pushed), "%s", row->local);
    (void)snprintf(row->state, sizeof(row->state), "landed");
    row->phase[0] = '\0';
    (void)snprintf(row->detail, sizeof(row->detail), "%s",
                   "fast-forwarded origin/main");
    if (dl_commit_or_report(d, row, true, reply, "landed"))
        dl_step_reply(reply, row, "landed");
}

static void dl_step(const struct zcl_command_request *req,
                    struct zcl_command_reply *reply)
{
    struct dl_dirs d;
    struct dl_row *rows = NULL;
    struct dl_row pick;
    size_t nrows = 0;
    char qpath[4096 + 32];
    bool have_inflight = false, have_queued = false;
    int slot;
    (void)req;
#if defined(_WIN32)
    dl_fail(reply, "STEP_WINDOWS_UNAVAILABLE", "slot",
            "dev land step needs POSIX advisory locks",
            "run the landing loop on a POSIX host");
    return;
#else
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
    /* The host-wide landing slot, taken without blocking and released
     * before this call returns. It is never held across steps. */
    slot = dl_slot_lock(d.land);
    if (slot < 0) {
        dl_step_reply(reply, NULL, "busy");
        return;
    }
    if (!dl_load_rows(qpath, &rows, &nrows)) {
        dl_unlock(slot);
        dl_fail(reply, "QUEUE_READ_FAILED", "slot",
                "cannot read the queue file", qpath);
        return;
    }
    memset(&pick, 0, sizeof(pick));
    for (size_t i = 0; i < nrows; i++) {
        if (strcmp(rows[i].state, "inflight") == 0) {
            pick = rows[i];
            have_inflight = true;
            break;
        }
    }
    if (!have_inflight) {
        for (size_t i = 0; i < nrows; i++) {
            if (strcmp(rows[i].state, "queued") == 0) {
                pick = rows[i];
                have_queued = true;
                break;
            }
        }
    }
    free(rows);
    if (!have_inflight && !have_queued) {
        dl_unlock(slot);
        dl_step_reply(reply, NULL, "empty");
        return;
    }
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    /* Test-only: a fixed, tiny window between picking a row here and
     * driving it below, so a test can race a concurrent cancel (which
     * takes the row lock, not this slot lock) against this exact gap
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
    if (have_inflight)
        dl_step_resume(&d, &pick, reply);
    else
        dl_step_start(&d, &pick, reply);
    dl_unlock(slot);
#endif
}

/* ── dispatcher ────────────────────────────────────────────────────────── */

void zcl_native_handle_dev_land(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    const char *action;
    if (!reply)
        return;
    if (!request || !request->input) {
        dl_fail(reply, "BAD_INPUT", "route",
                "dev land needs an action: submit|status|step|cancel",
                "request.input was missing");
        return;
    }
    action = dl_str(request, "action");
    if (!action) {
        dl_fail(reply, "BAD_INPUT", "route",
                "dev land needs an action: submit|status|step|cancel",
                "input.action missing or empty");
        return;
    }
    if (strcmp(action, "submit") == 0) {
        dl_submit(request, reply);
        return;
    }
    if (strcmp(action, "status") == 0) {
        dl_status(request, reply);
        return;
    }
    if (strcmp(action, "step") == 0) {
        dl_step(request, reply);
        return;
    }
    if (strcmp(action, "cancel") == 0) {
        dl_cancel(request, reply);
        return;
    }
    dl_fail(reply, "UNKNOWN_ACTION", "route",
            "action is one of submit|status|step|cancel",
            "input.action unknown");
}
