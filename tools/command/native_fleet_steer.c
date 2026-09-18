/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: fleet.steer — the thin remote-STEER adapter over the existing
 *          authenticated fleet mail, queue, board and receipt leaves.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. ChatGPT (or any remote steering client) must steer the fleet
 * without a
 * human relaying chat messages. This file is the smallest surface that
 * proves the connection: fleet.steer.brief (one call: who is working on
 * what, blockers, capacity, candidates, evidence refs, changes since a
 * cursor) plus fleet.steer.send (one bounded batch of directives to named
 * agents with per-item acceptance). fleet.steer.evidence returns one
 * bounded object by exact reference, never a log; fleet.steer.grant mints
 * and revokes the adapter's scoped bearer grants. No new scheduler, no
 * new ledger, no parallel workflow: composition only.
 *
 * HOW IT COMPOSES. Every fact comes from a sibling leaf called in-process
 * with the caller's context, exactly as the CLI would after input
 * validation: dev.agent.mail (post/pull/ack files), dev.agent.queue
 * (status), fleet.board.list/show (node RPC, fail-closed without a node),
 * fleet.ledger.status (local chains). Each sibling validates its own inputs
 * and enforces its own permissions; nothing here re-implements their
 * stores. A sibling that fails (no node, no delegation, empty state) is
 * reported in `missing[]` with its age — an unreachable source never reads
 * as an idle fleet.
 *
 * AUTHORIZATION. Two paths, never mixed:
 *   - Local operator: no `grant` key. Dispatch already gated on
 *     AUTH_OPERATOR (brief/send/evidence) or AUTH_OWNER (grant mint/revoke).
 *   - Remote bearer: a `grant` key naming one row in <state>/steer/grants.jsonl
 *     minted by the operator. The row carries a scope subset of
 *     brief|send|evidence, created/expires unix times (expires 0 = never),
 *     a revoked flag and a label. Expired, revoked, unknown or
 *     insufficient-scope grants fail closed with STEER_GRANT_* — writes are
 *     never disguised as reads, and no credential is ever echoed back.
 *
 * SENDER IDENTITY. `from` is not caller authority. On the bearer path the
 * sender IS the grant's label: `from` must be stated and must agree
 * (STEER_SENDER_UNSTATED / STEER_SENDER_MISMATCH), and an unlabelled grant
 * names no sender (STEER_GRANT_UNLABELLED). The check runs once for the
 * whole batch BEFORE idempotency, so no reconcile can hand one party
 * another party's row. Each posted row carries the grant's binding beside
 * the name, and the receiver admits on that binding rather than on the
 * name, so holding one send-capable grant no longer lets anyone speak as
 * anyone. On the operator path the sender is the local operator and the
 * row carries no binding.
 * This adapter is NOT wallet authority (see agent_session for spend grants)
 * and NOT fleet key roles (see fleet.roles grant/revoke/check, which govern
 * fleet leaves by key fingerprint and need node delegation to mint). It
 * governs only fleet.steer verbs; minting needs no delegation, only the
 * owner. Bearer ids are 128-bit CSPRNG hex via zcl_random_secret_bytes.
 *
 * IDEMPOTENCY. send items carry a caller-chosen idempotency_key. The first
 * accept appends the mail row and records key->seq plus a payload digest,
 * the ref, and the grant in <state>/steer/sent.jsonl; a retry with the
 * same key AND the same payload returns the recorded accept with
 * duplicate:true and appends nothing. Retries reconcile; they never
 * duplicate work. A different payload under an already-recorded key is
 * refused per-item as IDEMPOTENCY_CONFLICT: the key names one exact
 * delivery, never two. The recorded ref+grant let revoke cancel exactly
 * the queued work its grant sent. The reply's top-level `accepted` counts
 * only items whose result state is not "refused" (a reconciled duplicate
 * counts, a fresh IDEMPOTENCY_CONFLICT/BAD_INPUT/mail refusal does not) —
 * it is never just the item-result count.
 *
 * STATES. queued, delivered, acknowledged, completed — four different
 * facts; absence of evidence is reported as the earlier state, never
 * skipped ahead. The closed vocabulary never grows.
 *
 * The sender's own outbox is ALWAYS inside the sender's own pull, so
 * "visible in pull" is no evidence at all that a directive this host sent
 * ever left this machine. So the rule splits on who wrote the row:
 *   - A row THIS host sent through steer — its seq and recipient are
 *     recorded in <state>/steer/sent.jsonl — is "queued" until there is
 *     RECEIVER evidence, and never "delivered". Either of two facts
 *     promotes it straight to "acknowledged": (a) a mail row whose `from`
 *     is the sent row's `to` carrying the SAME ref, which is what a
 *     transport brings back into an inbox.<peer>.jsonl file, or (b) the
 *     local ack cursor <state>/mail/cursor.<to> covering its seq, which is
 *     how a receiver on THIS host acks. Both are the receiver's own
 *     writing; the sender can forge neither by posting.
 *   - Every other row — an inbound row a transport delivered here, an
 *     ordinary local post — reads as before: "delivered", because it
 *     really is visible where its reader reads, and "acknowledged" once
 *     the ack cursor covers it.
 * "completed" is resolved for either kind from a retained queue outcome
 * naming the ref with an explicit pass verdict and rc 0. A change row
 * still "queued" carries queued_age_s, and a directive this host sent
 * with no receiver evidence past FMC_QUEUED_STALE_S (120 s) becomes the
 * blocker "directive <ref> to <to>: no receiver evidence after N s" — the
 * visible form of "send said QUEUED but the target never read it". The
 * newest FMC_STALE_BLOCKER_CAP (8) are spelled out and one more line
 * counts the rest, so they never crowd every other blocker out.
 *
 * REPLIES. Each directive change row also carries `reply`, correlating
 * the rows already pulled by ref (+ attempt when both state one):
 * answered (a later `result` under the ref, from the addressee or
 * addressed back to the origin by anyone but the origin), else acked (the
 * receiver's ack cursor only; a reply is never an ack), else queued; with
 * the directive's own sent_ts/sent_age_s apart from answer_ts/answer_age_s.
 * An answered directive is never a "no receiver evidence" blocker.
 *
 * WORKERS. `agents` is only the names seen in mail and on the board. The
 * `workers` array is evidence: an identity appears only after it answered
 * as a receiver (a body carrying receiver=) or a worker (worker=), or as
 * this host's resident (a queue row or a receiver/worker lock file).
 * Remote fields are the worker's own newest words and are marked
 * self_reported; this host's load, available memory and state-root disk
 * are measured now. state is one of
 *   working  a running queue row, or a ref claimed (stage running|engine)
 *            with no terminal outcome (result row or queue outcome);
 *   blocked  the newest answer is a refusal, queued local work has no
 *            resident worker to claim it, or the local receiver's intake
 *            (the same mail pull) failed in this brief; the cumulative
 *            count in receive/intake.state is named in the reason as
 *            history, never taken as a current block;
 *   idle     evidence newer than FMC_ALIVE_WINDOW_S and nothing open;
 *   unknown  everything else,
 * always with a reason. A lock held or a name seen is liveness at most,
 * never work. Unknown numbers are JSON null, never 0: capacity reports
 * known:false and all-null numbers when the queue did not answer, the
 * worktree pool reads pool_known:false and "UNKNOWN" sizes when this host
 * has no queue/pool.txt (only a measured empty pool reads 0), and
 * token usage comes from run receipts (queue outcomes locally, result
 * rows remotely) or stays null.
 *
 * SESSIONS. `sessions` lists each coding-agent session (roles A, B, C, D
 * always, plus any other presence-<ROLE> seen), apart from the resident
 * Muse `workers`. Mail `from` is the box's Unix user, so a session is
 * known only from its own `note` row under ref presence-<ROLE> carrying
 * the strict presence.v1 line documented at the sessions section below.
 * state is live within FMC_ALIVE_WINDOW_S of that row's ts, stale past it
 * (with age_s), and UNKNOWN when no row exists; a missing or refused
 * field is the string "UNKNOWN". Linked workers are named, never copied;
 * `muse_spend` sums the workers' receipt tokens, and reservations stay
 * UNKNOWN because no existing source records them. No body text reaches
 * the brief except through the parsed, credential-screened whitelist.
 *
 * STATE. <platform_state_root()>/steer (0700): grants.jsonl, sent.jsonl.
 * Single O_APPEND writes; revoke appends a superseding revoked row like
 * the mail ack cursor. Nothing here blocks on a peer or a model.
 *
 * REVOCATION. Revoking a grant kills the credential AND cancels the
 * queued work it sent: each accepted send row records its ref and grant,
 * and revoke best-effort cancels the queue row under each ref sent with
 * that grant (queued-only; running rows refuse and need the worker's own
 * explicit authority, completed history is never rewritten). Later steer
 * verbs on the revoked grant fail closed; completed evidence stays
 * readable under a fresh grant.
 *
 * BOUNDS. brief changes[] default 25, max 100; agents/work/candidates 32;
 * blockers 16; workers 16 emitted of 64 tracked; sessions 12 emitted of
 * 16 tracked; the whole reply data is
 * trimmed (changes first) under FMC_REPLY_SOFT_BUDGET and budget_truncated
 * names every array that was cut; body leads 160 chars; send at most 8
 * items, body at most 2048 bytes each (under mail's own 4096 ceiling and
 * refusal scanners, which still apply). Mail bodies over-long or tripping
 * refusal rules come back per-item as refused, never as a crash.
 *
 * PROCESS RULE. No spawn, no shell, no popen()/system(), no sleep, no poll
 * loop. Only in-process sibling calls and local filesystem operations.
 */

#include "command/native_command.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "command/native_devagent.h"
#include "command/native_fleet.h"
#include "config/command_catalog.h"
#include "crypto/random_secret.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/clock.h"
#include "platform/directory_compat.h"
#include "platform/os_proc.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "services/disk_monitor.h"
#include "sha3/sha3.h"
#include "util/log_macros.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#if !defined(_WIN32)
#include <sys/file.h>
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define FMC_LEAF "fleet.steer"
#define FMC_GRANT_LEAF "fleet.steer.grant"
#define FMC_LOG "fleet.steer"
#define FMC_DIR_MODE 0700

#define FMC_SEND_MAX 8u
#define FMC_BODY_MAX 2048u
#define FMC_KEY_MAX 128u
#define FMC_NAME_MAX 64u
#define FMC_REF_MAX 128u
#define FMC_LEAD_MAX 160u
#define FMC_LIST_CAP 32u
#define FMC_BLOCKER_CAP 16u
#define FMC_CHANGES_DEFAULT 25
#define FMC_CHANGES_MAX 100
#define FMC_LINE_CAP 8192
#define FMC_INPUT_CAP 65536
#define FMC_GRANT_TTL_MAX (30LL * 24 * 60 * 60)

/* Worker roster: at most FMC_WORKER_TRACK distinct identities are tracked
 * per brief and FMC_WORKER_CAP are emitted, newest first; the rest are
 * counted in workers_total. Evidence newer than FMC_ALIVE_WINDOW_S counts
 * as alive; a directive this host sent that is still queued with no
 * receiver evidence after FMC_QUEUED_STALE_S becomes a blocker. The reply
 * data is held under FMC_REPLY_SOFT_BUDGET so the leaf's 64 KiB response
 * budget (envelope included) can never refuse the whole brief. */
#define FMC_WORKER_CAP 16u
#define FMC_WORKER_TRACK 64u
#define FMC_DONE_TRACK 256u
#define FMC_DIRECTIVE_SCAN 64
#define FMC_STALE_BLOCKER_CAP 8
#define FMC_ALIVE_WINDOW_S 900LL
#define FMC_QUEUED_STALE_S 120LL
#define FMC_REPLY_SOFT_BUDGET 49152u
/* Sessions: A, B, C, D always, plus other presence-<label> roles, at most
 * FMC_SESSION_TRACK tracked and FMC_SESSION_CAP emitted. */
#define FMC_SESSION_TRACK 16u
#define FMC_SESSION_CAP 12u

/* ── failure (every error return logs context) ─────────────────────────── */

static void fmc_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message, const char *evidence)
{
    LOG_ERROR(FMC_LOG, "%s: %s (%s)", code, message,
              evidence ? evidence : FMC_LEAF);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "execute", false,
                           false, message, evidence ? evidence : FMC_LEAF);
}

/* ── input getters ─────────────────────────────────────────────────────── */

static const char *fmc_str(const struct zcl_command_request *req,
                           const char *key)
{
    const struct json_value *v;
    if (!req || !req->input || !key)
        return NULL;
    v = json_get(req->input, key);
    if (!v || v->type != JSON_STR)
        return NULL;
    return json_get_str(v);
}

static bool fmc_int(const struct zcl_command_request *req, const char *key,
                    long long *out)
{
    const struct json_value *v;
    if (!req || !req->input || !key || !out)
        return false;
    v = json_get(req->input, key);
    if (!v)
        return false;
    if (v->type == JSON_INT) {
        *out = (long long)json_get_int(v);
        return true;
    }
    return false;
}

/* ── small string helpers (no locale, no allocation) ───────────────────── */

static bool fmc_is_token_char(char c)
{
    return isalnum((unsigned char)c) != 0 || c == '.' || c == '_' ||
           c == '-' || c == '*';
}

/* Caller tokens: agent names, idempotency keys, refs. Empty, over-long or
 * off-alphabet input is rejected so it can never become a filename or a
 * cursor path. `*` is allowed only when star_ok (broadcast recipients). */
static bool fmc_is_token(const char *s, size_t max, bool star_ok)
{
    size_t i;
    if (!s || s[0] == '\0' || strlen(s) > max)
        return false;
    for (i = 0; s[i]; i++) {
        if (s[i] == '*') {
            if (!star_ok)
                return false;
        } else if (!fmc_is_token_char(s[i])) {
            return false;
        }
    }
    return true;
}

/* JSON string escape into a bounded buffer. False when the budget runs out. */
/* One lowercase hex digit by arithmetic: the repo's single hex codec owns
 * digit tables, so this escaper must not carry one (hex-codec-single). */
static char fmc_hex_digit(unsigned v)
{
    return (char)(v <= 9 ? ('0' + v) : ('a' + v - 10));
}

static bool fmc_escape(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    if (!in || !out || cap == 0)
        return false;
    for (; *in; in++) {
        unsigned char c = (unsigned char)*in;
        if (c == '"' || c == '\\') {
            if (o + 2 >= cap)
                return false;
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c == '\n') {
            if (o + 2 >= cap)
                return false;
            out[o++] = '\\';
            out[o++] = 'n';
        } else if (c < 0x20) {
            if (o + 6 >= cap)
                return false;
            out[o++] = '\\';
            out[o++] = 'u';
            out[o++] = '0';
            out[o++] = '0';
            out[o++] = fmc_hex_digit((unsigned)((c >> 4) & 0xf));
            out[o++] = fmc_hex_digit((unsigned)(c & 0xf));
        } else {
            if (o + 1 >= cap)
                return false;
            out[o++] = (char)c;
        }
    }
    if (o >= cap)
        return false;
    out[o] = '\0';
    return true;
}

/* Lead: first FMC_LEAD_MAX bytes, cut at a newline, for change lists. The
 * full body is always one evidence call away; the brief never carries it. */
static void fmc_lead(const char *body, char *out, size_t cap)
{
    size_t i = 0;
    if (!body || !out || cap == 0)
        return;
    while (body[i] && i + 1 < cap && i < FMC_LEAD_MAX) {
        if (body[i] == '\n' || body[i] == '\r')
            break;
        out[i] = body[i];
        i++;
    }
    out[i] = '\0';
}

/* ── owner-private steer dir ─────────────────────────────────────────────── */

static bool fmc_dirs(char *steerdir, size_t cap)
{
    char root[4096];
    int n;
    if (!steerdir || cap == 0)
        return false;
    if (!platform_state_root(root, sizeof(root)))
        return false;
    n = snprintf(steerdir, cap, "%s/steer", root);
    if (n <= 0 || (size_t)n >= cap)
        return false;
    if (!platform_private_directory_ensure(steerdir))
        return false;
    return true;
}

static bool fmc_append_line(const char *path, const char *line, size_t len)
{
    int fd;
    ssize_t w;
    if (!path || !line || len == 0)
        return false;
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    w = write(fd, line, len);
    (void)close(fd);
    return w == (ssize_t)len;
}

/* ── grant store ───────────────────────────────────────────────────────── */

struct fmc_grant {
    char id[33];
    char scopes[64];
    char label[FMC_NAME_MAX + 1];
    long long created;
    long long expires;
    int revoked;
};

/* True when the comma-token scope list names want as a whole token. */
static bool fmc_scope_has(const char *scopes, const char *want)
{
    size_t wn;
    const char *p;
    if (!scopes || !want || !want[0])
        return false;
    wn = strlen(want);
    for (p = scopes; *p;) {
        while (*p == ',' || *p == ' ')
            p++;
        if (*p == '\0')
            break;
        if (strncmp(p, want, wn) == 0 && (p[wn] == '\0' || p[wn] == ',' ||
                                          p[wn] == ' ')) {
            return true;
        }
        while (*p && *p != ',')
            p++;
    }
    return false;
}

static bool fmc_grant_line_str(const char *line, const char *key, char *out,
                               size_t cap)
{
    /* Minimal flat-JSON string/int extractor for our own grant rows.
     * Rows are machine-written by mint below, so "key":"value" and
     * "key":number shapes are exact; anything else fails closed. */
    char pat[64];
    const char *p, *q;
    size_t n;
    int r;
    if (!line || !key || !out || cap == 0)
        return false;
    r = snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    if (r <= 0 || (size_t)r >= sizeof(pat))
        return false;
    p = strstr(line, pat);
    if (!p)
        return false;
    p += strlen(pat);
    q = strchr(p, '"');
    if (!q)
        return false;
    n = (size_t)(q - p);
    if (n == 0 || n >= cap)
        return false;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static bool fmc_grant_line_int(const char *line, const char *key,
                               long long *out)
{
    char pat[64];
    const char *p;
    char *end = NULL;
    long long v;
    int r;
    if (!line || !key || !out)
        return false;
    r = snprintf(pat, sizeof(pat), "\"%s\":", key);
    if (r <= 0 || (size_t)r >= sizeof(pat))
        return false;
    p = strstr(line, pat);
    if (!p)
        return false;
    p += strlen(pat);
    if (*p == '"')
        return false;
    v = strtoll(p, &end, 10);
    if (end == p || v < 0)
        return false;
    *out = v;
    return true;
}

static bool fmc_grant_parse(const char *line, struct fmc_grant *g)
{
    char revoked[16];
    if (!line || !g)
        return false;
    memset(g, 0, sizeof(*g));
    if (!fmc_grant_line_str(line, "id", g->id, sizeof(g->id)))
        return false;
    if (!fmc_grant_line_str(line, "scopes", g->scopes, sizeof(g->scopes)))
        return false;
    if (!fmc_grant_line_int(line, "created", &g->created))
        return false;
    if (!fmc_grant_line_int(line, "expires", &g->expires))
        return false;
    g->revoked = 0;
    if (fmc_grant_line_str(line, "revoked", revoked, sizeof(revoked)))
        g->revoked = strcmp(revoked, "1") == 0 ? 1 : 0;
    /* Optional: a row minted without a label keeps the empty name, which
     * no label lookup can ever match. */
    (void)fmc_grant_line_str(line, "label", g->label, sizeof(g->label));
    if (strlen(g->id) != 32)
        return false;
    return true;
}

/* Find the LAST row naming id (later rows supersede). False when absent. */
static bool fmc_grant_find(const char *path, const char *id,
                           struct fmc_grant *out)
{
    FILE *f;
    char line[FMC_LINE_CAP];
    bool found = false;
    struct fmc_grant g;
    if (!path || !id || !out)
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    while (fgets(line, sizeof(line), f)) {
        if (!fmc_grant_parse(line, &g))
            continue;
        if (strcmp(g.id, id) == 0) {
            *out = g;
            found = true;
        }
    }
    (void)fclose(f);
    return found;
}

/* Validate a presented bearer for one verb scope and hand back the row it
 * named. NULL/empty grant means the local operator path, which dispatch
 * already authorized; `row` is then left zeroed and the caller reads the
 * operator identity, never a grant. */
static const char *fmc_grant_check_row(const char *grant, const char *scope,
                                       struct fmc_grant *row)
{
    char steerdir[4096], path[4096 + 32];
    struct fmc_grant g;
    time_t now;
    int n;
    memset(row, 0, sizeof(*row));
    if (!grant || !grant[0])
        return NULL;
    if (!scope || !scope[0])
        return "STEER_GRANT_SCOPE";
    if (strlen(grant) != 32)
        return "STEER_GRANT_UNKNOWN";
    if (!fmc_dirs(steerdir, sizeof(steerdir)))
        return "STEER_GRANT_STORE";
    n = snprintf(path, sizeof(path), "%s/grants.jsonl", steerdir);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return "STEER_GRANT_STORE";
    if (!fmc_grant_find(path, grant, &g))
        return "STEER_GRANT_UNKNOWN";
    if (g.revoked)
        return "STEER_GRANT_REVOKED";
    now = platform_time_wall_time_t();
    if (g.expires != 0 && (long long)now >= g.expires)
        return "STEER_GRANT_EXPIRED";
    if (!fmc_scope_has(g.scopes, scope))
        return "STEER_GRANT_SCOPE";
    *row = g;
    return NULL;
}

/* The same check when the caller needs only the verdict. */
static const char *fmc_grant_check(const char *grant, const char *scope)
{
    struct fmc_grant g;
    return fmc_grant_check_row(grant, scope, &g);
}

/* ── live grant lookup BY BINDING (shared admission helper) ──────────────
 *
 * The resident mail receiver (tools/command/native_devagent_receive.c) has
 * to decide whether a directive row really came from the sender it names.
 * That is this store's question, so it is answered here rather than
 * duplicated there: no second permission system, no second credential file,
 * no second store.
 *
 * WHY A BINDING AND NOT A LABEL. A label is the human name the owner minted
 * a grant under, and a label inside a row is only a claim: anything that can
 * write a row can write any name into it. Asking "does SOME live grant carry
 * this label" therefore admitted any sender who held any send-capable grant
 * to speak as any other — proven live on 2026-09-17, where one probe grant
 * successfully claimed four different senders. The question asked here is
 * the binding one: "did the grant that carries this label stamp this exact
 * row", which only a holder of that grant's id can answer.
 *
 * grants.jsonl is re-read on every call, so a revoke takes effect on the
 * next check. Fail-closed: the reason of the closest matching row is
 * returned when nothing admits, and an unreadable or absent store reads as
 * "no grant names this sender". */

#define FMC_LABEL_IDS 64u

struct fmc_grant_set {
    struct fmc_grant g[FMC_LABEL_IDS];
    size_t n;
};

/* Keep the LAST row per id (later rows supersede, as fmc_grant_find does),
 * bounded by FMC_LABEL_IDS distinct ids of ONE label. The store is
 * append-only, so the newest ids are the ones still able to be live: when
 * the bound is full the OLDEST id is evicted, never the newcomer. Keeping
 * the first ids instead once let a store of 64 dead test grants hide every
 * later grant, so a live sender read as STEER_GRANT_UNKNOWN. */
static void fmc_grant_set_put(struct fmc_grant_set *s,
                              const struct fmc_grant *g)
{
    size_t i;
    for (i = 0; i < s->n; i++) {
        if (strcmp(s->g[i].id, g->id) == 0) {
            s->g[i] = *g;
            return;
        }
    }
    if (s->n == FMC_LABEL_IDS) {
        memmove(&s->g[0], &s->g[1], (FMC_LABEL_IDS - 1) * sizeof(s->g[0]));
        s->n--;
    }
    s->g[s->n++] = *g;
}

/* Load only the rows about `label`: the admission question is about one
 * sender, so another label's grants must not spend its bound. */
static bool fmc_grant_set_load(const char *path, const char *label,
                               struct fmc_grant_set *s)
{
    FILE *f;
    char line[FMC_LINE_CAP];
    struct fmc_grant g;
    s->n = 0;
    f = fopen(path, "rb");
    if (!f)
        return false;
    while (fgets(line, sizeof(line), f)) {
        if (fmc_grant_parse(line, &g) && strcmp(g.label, label) == 0)
            fmc_grant_set_put(s, &g);
    }
    (void)fclose(f);
    return true;
}

/* One row's verdict for a label admission. NULL admits. */
static const char *fmc_grant_row_verdict(const struct fmc_grant *g,
                                         const char *scope, long long now)
{
    if (g->revoked)
        return "STEER_GRANT_REVOKED";
    if (g->expires != 0 && now >= g->expires)
        return "STEER_GRANT_EXPIRED";
    if (!fmc_scope_has(g->scopes, scope))
        return "STEER_GRANT_SCOPE";
    return NULL;
}

/* The stamp one grant writes on the rows it sends: SHA3-256 over the grant
 * id and the label it speaks under, printed as the first 32 hex digits.
 *
 * It is derived from the id and is NEVER the id: the id is the bearer
 * secret, and a mail row crosses hosts, is pulled by every reader of the
 * maildir, and is quoted in evidence. A digest lets a receiver holding the
 * store recompute the same value and compare, while a reader of the row
 * learns nothing that lets it send. The label is folded in so one grant's
 * stamp cannot be lifted onto a different name. */
bool zcl_fleet_steer_sender_binding(const char *grant_id, const char *label,
                                    char *out, size_t cap)
{
    struct sha3_256_ctx ctx;
    unsigned char sum[SHA3_256_OUTPUT_SIZE];
    size_t i;
    if (!grant_id || !grant_id[0] || !label || !label[0] || !out ||
        cap <= ZCL_FLEET_STEER_BINDING_HEX)
        return false;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)"z23.steer.sender.v1", 19u);
    sha3_256_write(&ctx, (const unsigned char *)grant_id,
                   strlen(grant_id) + 1u);
    sha3_256_write(&ctx, (const unsigned char *)label, strlen(label) + 1u);
    sha3_256_finalize(&ctx, sum);
    for (i = 0; i < (size_t)ZCL_FLEET_STEER_BINDING_HEX / 2u; i++)
        (void)snprintf(out + i * 2u, 3u, "%02x", sum[i]);
    out[ZCL_FLEET_STEER_BINDING_HEX] = '\0';
    return true;
}

/* True when this row's stamp is the one this grant writes. Compared over
 * the full fixed width so a truncated or padded stamp can never match. */
static bool fmc_binding_is(const struct fmc_grant *g, const char *label,
                           const char *binding)
{
    char want[ZCL_FLEET_STEER_BINDING_HEX + 1];
    if (!zcl_fleet_steer_sender_binding(g->id, label, want, sizeof(want)))
        return false;
    return strcmp(want, binding) == 0;
}

/* Read the owner-private grant store for a read-only admission question.
 * Deliberately NOT fmc_dirs(): a caller answering a status question must
 * not create the steer directory as a side effect. Returns the refusal
 * that stopped it, or NULL with *set loaded. */
static const char *fmc_grant_set_read(const char *label,
                                      struct fmc_grant_set *set)
{
    char root[4096], path[4096 + 32];
    int n;
    if (!platform_state_root(root, sizeof(root)))
        return "STEER_GRANT_STORE";
    n = snprintf(path, sizeof(path), "%s/steer/grants.jsonl", root);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return "STEER_GRANT_STORE";
    if (!fmc_grant_set_load(path, label, set))
        return "STEER_GRANT_UNKNOWN";
    return NULL;
}

/* The verdict the loaded store gives one (label, binding, scope) triple:
 * NULL when some live grant of that label carries the scope AND is the
 * grant that wrote this stamp, otherwise the most specific reason any row
 * about that label gave. A label nobody holds stays UNKNOWN. */
static const char *fmc_grant_binding_scan(const struct fmc_grant_set *set,
                                          const char *label,
                                          const char *binding,
                                          const char *scope, long long now)
{
    const char *why = "STEER_GRANT_UNKNOWN";
    size_t i;
    for (i = 0; i < set->n; i++) {
        const char *row;
        if (strcmp(set->g[i].label, label) != 0)
            continue;
        /* The label matched, so this row is at least ABOUT the claimed
         * sender: report its liveness reason rather than a bare unknown,
         * and only then ask whether it is the grant that stamped this row. */
        row = fmc_grant_row_verdict(&set->g[i], scope, now);
        if (!row && !fmc_binding_is(&set->g[i], label, binding))
            row = "STEER_GRANT_BINDING";
        if (!row)
            return NULL;
        why = row;
    }
    return why;
}

const char *zcl_fleet_steer_grant_binding_live(const char *label,
                                               const char *binding,
                                               const char *scope)
{
    struct fmc_grant_set set;
    const char *store;
    if (!label || !label[0] || !scope || !scope[0])
        return "STEER_GRANT_SCOPE";
    /* An unattributable row is refused, never admitted: without a stamp
     * there is nothing here to check the claimed name against. */
    if (!binding || strlen(binding) != ZCL_FLEET_STEER_BINDING_HEX)
        return "STEER_GRANT_BINDING";
    store = fmc_grant_set_read(label, &set);
    if (store)
        return store;
    return fmc_grant_binding_scan(&set, label, binding, scope,
                                  (long long)platform_time_wall_time_t());
}

/* ── idempotency store ─────────────────────────────────────────────────── */

/* Payload digest: FNV-1a/64 over to, body, ref, from with NUL separators.
 * An equality check for reconcile and nothing more; fixed-size hex keeps
 * sent.jsonl lines flat and greppable. It is NOT what keeps one sender out
 * of another's rows — the digest is reached only after the sender has been
 * bound to its credential, and `from` is by then the grant's own label
 * rather than a caller's claim. Folding a claim into a digest was never a
 * boundary: two parties presenting one key simply disagreed about who they
 * were, and the reconcile handed the second one the first one's row. */
static void fmc_payload_sum(const char *to, const char *body,
                            const char *ref, const char *from,
                            char out[17])
{
    uint64_t h = 1469598103934665603ULL;
    const char *parts[4];
    size_t i;
    parts[0] = to ? to : "";
    parts[1] = body ? body : "";
    parts[2] = ref ? ref : "";
    parts[3] = from ? from : "";
    for (i = 0; i < 4; i++) {
        const unsigned char *p = (const unsigned char *)parts[i];
        while (*p) {
            h ^= (uint64_t)*p++;
            h *= 1099511628211ULL;
        }
        h ^= 0ULL;
        h *= 1099511628211ULL;
    }
    snprintf(out, 17, "%016llx", (unsigned long long)h);
}

/* Find the recorded accept for key. On hit, seq takes the delivery identity
 * and sum takes the recorded payload digest ("" when the row predates
 * digests, which the caller treats as unverifiable, never as a match). */
static bool fmc_sent_find(const char *path, const char *key, long long *seq,
                          char sum[17])
{
    FILE *f;
    char line[FMC_LINE_CAP];
    long long s = -1;
    bool found = false;
    const char *p;
    char *end = NULL;
    if (!path || !key || !seq || !sum)
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    while (fgets(line, sizeof(line), f)) {
        char pat[256];
        int r = snprintf(pat, sizeof(pat), "\"key\":\"%s\"", key);
        if (r <= 0 || (size_t)r >= sizeof(pat))
            continue;
        if (!strstr(line, pat))
            continue;
        p = strstr(line, "\"seq\":");
        if (!p)
            continue;
        s = strtoll(p + 6, &end, 10);
        if (end == p + 6 || s < 0)
            continue;
        p = strstr(line, "\"sum\":\"");
        if (p && strlen(p + 7) >= 16) {
            memcpy(sum, p + 7, 16);
            sum[16] = '\0';
        } else {
            sum[0] = '\0';
        }
        *seq = s;
        found = true;
    }
    (void)fclose(f);
    return found;
}

/* Read-only path of this host's send receipts. Unlike fmc_dirs this creates
 * nothing: the brief and evidence are reads, and an absent file simply
 * means this host has sent nothing through steer. */
static bool fmc_sent_path_read(char *out, size_t cap)
{
    char root[4096];
    int n;
    if (!out || cap == 0)
        return false;
    if (!platform_state_root(root, sizeof(root)))
        return false;
    n = snprintf(out, cap, "%s/steer/sent.jsonl", root);
    return n > 0 && (size_t)n < cap;
}

/* True when THIS host sent that exact mail row through steer: one
 * sent.jsonl receipt recording the same seq and the same recipient. The
 * recipient is compared too because inbox.<peer>.jsonl rows carry the
 * peer's own seq numbering, so seq alone could collide with ours. Such a
 * row is never reported "delivered" on the strength of our own outbox. */
static bool fmc_sent_by_us(const char *path, long long seq, const char *to)
{
    FILE *f;
    char line[FMC_LINE_CAP];
    char rto[FMC_NAME_MAX + 1];
    long long rseq = -1;
    bool ours = false;
    if (!path || !path[0] || seq < 0 || !to || !to[0])
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    while (!ours && fgets(line, sizeof(line), f)) {
        if (!fmc_grant_line_int(line, "seq", &rseq) || rseq != seq)
            continue;
        if (!fmc_grant_line_str(line, "to", rto, sizeof(rto)))
            continue;
        ours = strcmp(rto, to) == 0;
    }
    (void)fclose(f);
    return ours;
}

/* ── in-process sibling calls ────────────────────────────────────────────
 *
 * Each sibling validates its own input and enforces its own permissions.
 * A sibling that fails (no node, no delegation, empty state) is not an
 * error here: the caller records it in missing[] with its age. */

struct fmc_sub {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
    bool ran;
    /* False when the sibling path does not resolve: siblings (notably the
     * board list's projection helper) dereference request->spec, so a call
     * without one would crash instead of failing. Callers treat this as a
     * missing source, never as a dispatch. */
    bool valid;
};

static void fmc_sub_begin(struct fmc_sub *s, const char *schema,
                          const struct zcl_command_request *parent,
                          const char *sib_path)
{
    json_init(&s->input);
    json_set_object(&s->input);
    memset(&s->request, 0, sizeof(s->request));
    s->request.input = &s->input;
    if (parent)
        s->request.context = parent->context;
    /* Exactly what dispatch supplies: the sibling's own spec (projection
     * and paging read it) and a normal view. */
    s->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), sib_path, NULL);
    s->request.view = "normal";
    zcl_command_reply_init(&s->reply, schema);
    s->ran = false;
    s->valid = s->request.spec != NULL;
}

static void fmc_sub_end(struct fmc_sub *s)
{
    zcl_command_reply_free(&s->reply);
    json_free(&s->input);
    s->ran = false;
}

/* Build the sub-input object from one JSON text. False when it does not
 * parse (caller fails closed with BAD_INPUT, never dispatches garbage). */
static bool fmc_sub_input(struct fmc_sub *s, const char *text)
{
    struct json_value tmp;
    if (!s || !text)
        return false;
    json_init(&tmp);
    if (!json_read(&tmp, text, strlen(text))) {
        json_free(&tmp);
        return false;
    }
    json_free(&s->input);
    s->input = tmp;
    s->request.input = &s->input;
    return true;
}

static bool fmc_sub_ok(const struct fmc_sub *s)
{
    return s && s->ran && s->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static long long fmc_sub_int(const struct fmc_sub *s, const char *key,
                             long long dflt)
{
    const struct json_value *v;
    if (!s || !key)
        return dflt;
    v = json_get(&s->reply.data, key);
    if (!v || v->type != JSON_INT)
        return dflt;
    return (long long)json_get_int(v);
}

/* Push one {source, reason} row onto missing[] and note the observation age
 * of the attempt in ms. Small and single-purpose for the complexity gate. */
static void fmc_note_missing(struct json_value *missing, const char *source,
                             const char *reason, long long age_ms)
{
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    if (json_push_kv_str(&item, "source", source) &&
        json_push_kv_str(&item, "reason", reason) &&
        json_push_kv_int(&item, "age_ms", age_ms))
        (void)json_push_back(missing, &item);
    json_free(&item);
}

/* Push one distinct string onto a capped array. Returns true when the value
 * is now represented (already present or appended). */
static bool fmc_push_distinct(struct json_value *arr, const char *s,
                              size_t cap)
{
    size_t n, i;
    struct json_value item;
    if (!arr || !s || !s[0])
        return false;
    n = json_size(arr);
    for (i = 0; i < n; i++) {
        const struct json_value *e = json_at(arr, i);
        const char *es;
        if (!e || e->type != JSON_STR)
            continue;
        es = json_get_str(e);
        if (es && strcmp(es, s) == 0)
            return true;
    }
    if (n >= cap)
        return true;
    json_init(&item);
    json_set_str(&item, s);
    (void)json_push_back(arr, &item);
    json_free(&item);
    return true;
}

/* Keep only the mail leaf's cursor alphabet so a `to` name can never
 * escape the mail dir. False when nothing survives. */
static bool fmc_clean_agent(const char *agent, char *out, size_t cap)
{
    size_t i, o = 0;
    if (!agent || !out || cap == 0)
        return false;
    for (i = 0; agent[i] && o + 1 < cap; i++) {
        char c = agent[i];
        if (isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-')
            out[o++] = c;
    }
    out[o] = '\0';
    return o > 0;
}

/* Receiver ack cursor from the mail leaf's cursor.<agent> file. Returns -1
 * when the receiver never acked (nothing acknowledged). */
static long long fmc_ack_cursor(const char *agent)
{
    char root[4096], path[4096 + 64];
    char clean[FMC_NAME_MAX + 1];
    FILE *f;
    char buf[32];
    char *end = NULL;
    long long v;
    int n;
    if (!fmc_clean_agent(agent, clean, sizeof(clean)))
        return -1;
    if (!platform_state_root(root, sizeof(root)))
        return -1;
    n = snprintf(path, sizeof(path), "%s/mail/cursor.%s", root, clean);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return -1;
    f = fopen(path, "rb");
    if (!f)
        return -1;
    buf[0] = '\0';
    (void)fgets(buf, sizeof(buf), f);
    (void)fclose(f);
    v = strtoll(buf, &end, 10);
    if (end == buf || v < 0)
        return -1;
    return v;
}

/* Closed completion vocabulary. Only an explicit pass verdict with a
 * clean exit completes a directive: "pass" is the long-standing explicit
 * allowlist entry and "PASS" is what the tree's own receipt producers
 * emit. Anything else — fail words, unknown or arbitrary strings, case
 * variants, a missing verdict — stays incomplete no matter what rc says,
 * and a pass claim contradicted by a nonzero exit does not complete
 * either. rc == 0 alone is never completion evidence. The outcome row is
 * always cited in evidence so the caller verifies. */
static bool fmc_verdict_pass(const char *verdict, long long rc)
{
    if (!verdict || rc != 0)
        return false;
    return strcmp(verdict, "pass") == 0 || strcmp(verdict, "PASS") == 0;
}

/* ── brief: mail section ─────────────────────────────────────────────────
 *
 * Pulls mail (since=0; filters locally so multi-inbox ambiguity never
 * refuses), collects agents, directives-as-work and bounded changes with
 * per-row lifecycle states. Returns the pull cursor, or -1 with a missing[]
 * note when the sibling failed. */

struct fmc_mail_view {
    long long cursor;
    long long count;
    bool ok;
};

/* One parsed mail row. String pointers borrow the sibling reply and are
 * valid until the sub call ends. */
struct fmc_row {
    long long seq;
    const char *ts;
    const char *from;
    const char *to;
    const char *kind;
    const char *body;
    const char *ref;
};

static const char *fmc_row_field(const struct json_value *r, const char *key)
{
    const struct json_value *v = json_get(r, key);
    if (!v || v->type != JSON_STR)
        return "";
    return json_get_str(v) ? json_get_str(v) : "";
}

static bool fmc_row_parse(const struct json_value *r, struct fmc_row *v)
{
    const struct json_value *s;
    if (!r || r->type != JSON_OBJ || !v)
        return false;
    s = json_get(r, "seq");
    if (!s || s->type != JSON_INT)
        return false;
    v->seq = (long long)json_get_int(s);
    v->ts = fmc_row_field(r, "ts");
    v->from = fmc_row_field(r, "from");
    v->to = fmc_row_field(r, "to");
    v->kind = fmc_row_field(r, "kind");
    v->body = fmc_row_field(r, "body");
    v->ref = fmc_row_field(r, "ref");
    return true;
}

/* Roster plus directives-as-work. */
static void fmc_row_tally(struct json_value *agents, struct json_value *work,
                          const struct fmc_row *v)
{
    if (v->from[0])
        (void)fmc_push_distinct(agents, v->from, FMC_LIST_CAP);
    if (v->to[0] && strcmp(v->to, "*") != 0)
        (void)fmc_push_distinct(agents, v->to, FMC_LIST_CAP);
    if (strcmp(v->kind, "directive") == 0 && v->body[0]) {
        char w[128];
        int wlen = snprintf(w, sizeof(w), "directive %s->%s %.64s", v->from,
                            v->to, v->ref);
        if (wlen > 0 && (size_t)wlen < sizeof(w))
            (void)fmc_push_distinct(work, w, FMC_LIST_CAP);
    }
}

/* True when the pulled rows carry a reply from this row's recipient under
 * the same ref: the row a transport brings back into inbox.<peer>.jsonl,
 * and the only proof available here that the directive left this host. A
 * row whose `from` is our own sender name is our side of the thread, never
 * receiver evidence — so a directive addressed to its own sender cannot
 * promote itself. Bounded by the pull the brief already holds; nothing is
 * accumulated. */
static bool fmc_rows_reply_from(const struct json_value *rows,
                                const struct fmc_row *v)
{
    size_t n, i;
    if (!rows || rows->type != JSON_ARR || !v || !v->ref[0] || !v->to[0])
        return false;
    n = json_size(rows);
    for (i = 0; i < n; i++) {
        struct fmc_row r;
        if (!fmc_row_parse(json_at(rows, i), &r))
            continue;
        if (strcmp(r.from, v->from) == 0)
            continue;
        if (strcmp(r.from, v->to) == 0 && strcmp(r.ref, v->ref) == 0)
            return true;
    }
    return false;
}

/* One row's lifecycle state, per the STATES rule at the top of this file.
 *
 * A row this host sent through steer is "queued" until the RECEIVER has
 * written something: its reply under the same ref, or the local ack cursor.
 * It is never "delivered", because the sender's own outbox is always in the
 * sender's own pull — reporting delivery from it would claim a transport
 * that may never have run. Any other row (inbound from a transport, an
 * ordinary local post) is genuinely visible where its reader reads, so it
 * stays "delivered" and upgrades on the cursor. "completed" is resolved
 * later against queue outcomes. */
static const char *fmc_row_state(const struct fmc_row *v,
                                 const struct json_value *rows,
                                 const char *sent_path)
{
    long long ack = fmc_ack_cursor(v->to);
    bool acked = ack >= 0 && v->seq <= ack;
    if (!fmc_sent_by_us(sent_path, v->seq, v->to))
        return acked ? "acknowledged" : "delivered";
    if (acked || fmc_rows_reply_from(rows, v))
        return "acknowledged";
    return "queued";
}

/* ── brief: time and body fields ─────────────────────────────────────────
 *
 * Mail rows carry an RFC 3339 UTC `ts` ("YYYY-MM-DDTHH:MM:SSZ"), and
 * receiver/worker answers carry flat `key=value` lines. Both are parsed
 * here without libc timegm and without trusting a value's shape: anything
 * that does not parse is UNKNOWN (-1 / false), never zero. */

static long long fmc_days_from_civil(long long y, long long m, long long d)
{
    long long era, yoe, doy, doe;
    y -= m <= 2 ? 1 : 0;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static bool fmc_digits(const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
    }
    return true;
}

static long long fmc_num(const char *s, size_t n)
{
    long long v = 0;
    size_t i;
    for (i = 0; i < n; i++)
        v = v * 10 + (s[i] - '0');
    return v;
}

/* True when ts has exactly the "YYYY-MM-DDTHH:MM:SSZ" shape. */
static bool fmc_ts_shape_ok(const char *ts)
{
    static const char pat[] = "dddd-dd-ddTdd:dd:ddZ";
    size_t i;
    if (!ts || strlen(ts) != sizeof(pat) - 1)
        return false;
    for (i = 0; pat[i]; i++) {
        bool ok = pat[i] == 'd' ? (ts[i] >= '0' && ts[i] <= '9')
                                : ts[i] == pat[i];
        if (!ok)
            return false;
    }
    return true;
}

/* Unix seconds of one "YYYY-MM-DDTHH:MM:SSZ" stamp, or -1. */
static long long fmc_ts_unix(const char *ts)
{
    long long mo, d, h, mi, s;
    if (!fmc_ts_shape_ok(ts))
        return -1;
    mo = fmc_num(ts + 5, 2);
    d = fmc_num(ts + 8, 2);
    h = fmc_num(ts + 11, 2);
    mi = fmc_num(ts + 14, 2);
    s = fmc_num(ts + 17, 2);
    if (mo < 1 || mo > 12 || d < 1 || d > 31)
        return -1;
    if (h > 23 || mi > 59 || s > 59)
        return -1;
    return fmc_days_from_civil(fmc_num(ts, 4), mo, d) * 86400 + h * 3600 +
           mi * 60 + s;
}

/* Seconds between a stamp and now, or -1 when the stamp does not parse.
 * A stamp from the future (clock skew) reads as age 0, not negative. */
static long long fmc_age_s(long long now, const char *ts)
{
    long long t = fmc_ts_unix(ts);
    if (t < 0)
        return -1;
    return now > t ? now - t : 0;
}

/* The value of one `key=value` line in a body, bounded to cap. */
static bool fmc_body_kv(const char *body, const char *key, char *out,
                        size_t cap)
{
    size_t klen, n;
    const char *p = body;
    if (!body || !key || !out || cap == 0)
        return false;
    klen = strlen(key);
    while (p && *p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            n = strcspn(p + klen + 1, "\r\n");
            if (n >= cap)
                n = cap - 1;
            memcpy(out, p + klen + 1, n);
            out[n] = '\0';
            return true;
        }
        p = strchr(p, '\n');
        if (p)
            p++;
    }
    return false;
}

/* A non-negative decimal `key=` value, or -1 when absent or malformed. */
static long long fmc_body_int(const char *body, const char *key)
{
    char buf[24];
    size_t n;
    if (!fmc_body_kv(body, key, buf, sizeof(buf)))
        return -1;
    n = strlen(buf);
    if (n == 0 || n > 18 || !fmc_digits(buf, n))
        return -1;
    return fmc_num(buf, n);
}

/* heartbeat_ts= as unix seconds or as an RFC 3339 UTC stamp; -1 when
 * absent or neither. */
static long long fmc_body_stamp(const char *body, const char *key)
{
    char buf[40];
    size_t n;
    if (!fmc_body_kv(body, key, buf, sizeof(buf)))
        return -1;
    n = strlen(buf);
    if (n > 0 && n <= 18 && fmc_digits(buf, n))
        return fmc_num(buf, n);
    return fmc_ts_unix(buf);
}

/* ── brief: workers ──────────────────────────────────────────────────────
 *
 * A worker is an identity that has SPOKEN as one: a mail row whose body
 * carries `receiver=` (the receiver's accept/refuse answer) or `worker=`
 * (the resident worker's result row), or this host's own resident
 * receiver/worker observed through the queue and its lock files. A name
 * that only appears in from/to is a correspondent, not a worker, and stays
 * in agents[]. Remote values are the worker's own words (self_reported);
 * local resources are measured now. A process or a lock existing is
 * liveness evidence only — "working" needs a running queue row or a
 * claimed ref with no terminal outcome. */

struct fmc_worker {
    char name[FMC_NAME_MAX + 1];
    char host[FMC_NAME_MAX + 1];
    char ts[40];
    char ref[FMC_REF_MAX + 1];
    char state[24];
    char stage[24];
    char reason[96];
    char ws_ts[40];
    char host_ts[40];
    char ws_selector[FMC_NAME_MAX + 1];
    char ws_head[72];
    char tok_ts[40];
    long long load1;
    long long mem_kib;
    long long disk_kib;
    long long heartbeat;
    long long tok_last;
    long long tok_total;
    bool local;
};

struct fmc_roster {
    struct fmc_worker *w;
    size_t n;
    size_t untracked;
    char (*done)[FMC_REF_MAX + 1];
    size_t ndone;
    struct fmc_session *ss;
    size_t nss;
    size_t ss_untracked;
};

static void fmc_sessions_seed(struct fmc_roster *ro);
static size_t fmc_session_size(void);

static bool fmc_roster_init(struct fmc_roster *ro)
{
    memset(ro, 0, sizeof(*ro));
    ro->w = (struct fmc_worker *)zcl_calloc(FMC_WORKER_TRACK, sizeof(*ro->w),
                                            "fleet_steer.workers");
    ro->done = (char (*)[FMC_REF_MAX + 1])zcl_calloc(
        FMC_DONE_TRACK, FMC_REF_MAX + 1, "fleet_steer.done_refs");
    ro->ss = (struct fmc_session *)zcl_calloc(
        FMC_SESSION_TRACK, fmc_session_size(), "fleet_steer.sessions");
    fmc_sessions_seed(ro);
    return ro->w && ro->done && ro->ss;
}

static void fmc_roster_free(struct fmc_roster *ro)
{
    free(ro->w);
    free(ro->done);
    free(ro->ss);
    memset(ro, 0, sizeof(*ro));
}

/* A ref some worker posted a result under: its terminal outcome. */
static void fmc_roster_done(struct fmc_roster *ro, const char *ref)
{
    size_t i;
    if (!ro->done || !ref || !ref[0])
        return;
    for (i = 0; i < ro->ndone; i++) {
        if (strcmp(ro->done[i], ref) == 0)
            return;
    }
    if (ro->ndone < FMC_DONE_TRACK)
        (void)snprintf(ro->done[ro->ndone++], FMC_REF_MAX + 1, "%s", ref);
}

static bool fmc_roster_is_done(const struct fmc_roster *ro, const char *ref)
{
    size_t i;
    for (i = 0; ro->done && ref && ref[0] && i < ro->ndone; i++) {
        if (strcmp(ro->done[i], ref) == 0)
            return true;
    }
    return false;
}

/* The entry for name, created fresh (every number unknown) when absent.
 * NULL once FMC_WORKER_TRACK identities are held: the row is counted in
 * `untracked`, and workers_total_exact turns false. */
static struct fmc_worker *fmc_roster_entry(struct fmc_roster *ro,
                                           const char *name)
{
    size_t i;
    struct fmc_worker *e;
    for (i = 0; ro->w && i < ro->n; i++) {
        if (strcmp(ro->w[i].name, name) == 0)
            return &ro->w[i];
    }
    if (!ro->w || ro->n >= FMC_WORKER_TRACK) {
        ro->untracked++;
        return NULL;
    }
    e = &ro->w[ro->n++];
    memset(e, 0, sizeof(*e));
    (void)snprintf(e->name, sizeof(e->name), "%s", name);
    e->load1 = e->mem_kib = e->disk_kib = e->heartbeat = -1;
    e->tok_last = e->tok_total = -1;
    return e;
}

/* Workspace evidence from the newest row that states it. */
static void fmc_worker_ws(struct fmc_worker *e, const struct fmc_row *v)
{
    char head[72], sel[FMC_NAME_MAX + 1];
    if (!fmc_body_kv(v->body, "workspace_head", head, sizeof(head)))
        return;
    if (e->ws_ts[0] && strcmp(v->ts, e->ws_ts) <= 0)
        return;
    if (!fmc_body_kv(v->body, "workspace_selector", sel, sizeof(sel)))
        sel[0] = '\0';
    (void)snprintf(e->ws_head, sizeof(e->ws_head), "%s", head);
    (void)snprintf(e->ws_selector, sizeof(e->ws_selector), "%s", sel);
    (void)snprintf(e->ws_ts, sizeof(e->ws_ts), "%.39s", v->ts);
}

/* Host from the newest row that states it. A result row names no host, so
 * the identity keeps the host its newest answer stated; sessions[] links
 * workers to a session by it. */
static void fmc_worker_host(struct fmc_worker *e, const struct fmc_row *v)
{
    char host[FMC_NAME_MAX + 1];
    if (!fmc_body_kv(v->body, "host", host, sizeof(host)))
        return;
    if (e->host_ts[0] && strcmp(v->ts, e->host_ts) <= 0)
        return;
    (void)snprintf(e->host, sizeof(e->host), "%s", host);
    (void)snprintf(e->host_ts, sizeof(e->host_ts), "%.39s", v->ts);
}

/* Token usage from one result row. A "no-receipt" row states tokens=0 as
 * a placeholder (the run never produced a receipt), so it is not a known
 * cost and is skipped rather than summed as zero. */
static void fmc_worker_tokens(struct fmc_worker *e, const struct fmc_row *v)
{
    char gate[32];
    long long t = fmc_body_int(v->body, "tokens");
    if (t < 0)
        return;
    if (fmc_body_kv(v->body, "gate", gate, sizeof(gate)) &&
        strcmp(gate, "no-receipt") == 0)
        return;
    e->tok_total = (e->tok_total < 0 ? 0 : e->tok_total) + t;
    if (!e->tok_ts[0] || strcmp(v->ts, e->tok_ts) > 0) {
        e->tok_last = t;
        (void)snprintf(e->tok_ts, sizeof(e->tok_ts), "%.39s", v->ts);
    }
}

/* The newest row this worker authored decides its current fields. */
static void fmc_worker_newest(struct fmc_worker *e, const struct fmc_row *v)
{
    (void)snprintf(e->ts, sizeof(e->ts), "%.39s", v->ts);
    (void)snprintf(e->ref, sizeof(e->ref), "%s", v->ref);
    if (!fmc_body_kv(v->body, "state", e->state, sizeof(e->state)))
        (void)snprintf(e->state, sizeof(e->state), "%s",
                       strcmp(v->kind, "result") == 0 ? "result" : "");
    if (!fmc_body_kv(v->body, "stage", e->stage, sizeof(e->stage)))
        e->stage[0] = '\0';
    if (!fmc_body_kv(v->body, "reason", e->reason, sizeof(e->reason)))
        e->reason[0] = '\0';
    e->load1 = fmc_body_int(v->body, "load1_centi");
    e->mem_kib = fmc_body_int(v->body, "mem_avail_kib");
    e->disk_kib = fmc_body_int(v->body, "disk_free_kib");
    e->heartbeat = fmc_body_stamp(v->body, "heartbeat_ts");
}

/* Fold one pulled row into the roster. */
static void fmc_roster_note(struct fmc_roster *ro, const struct fmc_row *v)
{
    char name[FMC_NAME_MAX + 2];
    struct fmc_worker *e;
    if (strcmp(v->kind, "result") == 0)
        fmc_roster_done(ro, v->ref);
    if (!fmc_body_kv(v->body, "receiver", name, sizeof(name)) &&
        !fmc_body_kv(v->body, "worker", name, sizeof(name)))
        return;
    if (!fmc_is_token(name, 48, false))
        return;
    e = fmc_roster_entry(ro, name);
    if (!e)
        return;
    fmc_worker_ws(e, v);
    fmc_worker_host(e, v);
    fmc_worker_tokens(e, v);
    if (e->ts[0] && strcmp(v->ts, e->ts) <= 0)
        return;
    fmc_worker_newest(e, v);
}

/* What the queue sibling said, with `known` false whenever it did not
 * answer: every number is then unknown, never an idle zero. */
struct fmc_queue_view {
    bool known;
    char reason[48];
    long long queued;
    long long running;
    long long pool_total;
    long long pool_free;
    bool pool_known;
    char pool_reason[160];
    char run_ref[FMC_REF_MAX + 1];
    char run_worker[FMC_NAME_MAX + 1];
    long long tok_last;
    long long tok_total;
    char outcome_ts[40];
};

/* This host's resident locks, probed without creating anything. "held"
 * means some process holds it — liveness, never work. */
static const char *fmc_lock_state(const char *sub, const char *file)
{
    char root[4096], path[4096 + 64];
    const char *state = "unavailable";
    int fd;
    if (!platform_state_root(root, sizeof(root)) ||
        snprintf(path, sizeof(path), "%s/%s/%s", root, sub, file) >=
            (int)sizeof(path))
        return "unknown";
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return "never-run";
#if !defined(_WIN32)
    state = flock(fd, LOCK_EX | LOCK_NB) == 0 ? "free" : "held";
    if (strcmp(state, "free") == 0)
        (void)flock(fd, LOCK_UN);
#endif
    (void)close(fd);
    return state;
}

struct fmc_local {
    const char *worker_lock;
    const char *receive_lock;
    bool mail_ok;
    long long intake_failures;
    char intake_error[64];
};

/* The local receiver's own intake record (<state>/receive/intake.state:
 * failures= and last_error=). The count is cumulative and never cleared,
 * so it is reported in the reason as history, not taken as a current
 * block; the current block is this brief's own failed pull of the same
 * mail. -1 when the receiver never wrote one. */
static void fmc_intake_read(struct fmc_local *lo)
{
    char root[4096], path[4096 + 64], text[1024];
    FILE *f;
    size_t n;
    lo->intake_failures = -1;
    lo->intake_error[0] = '\0';
    if (!platform_state_root(root, sizeof(root)) ||
        snprintf(path, sizeof(path), "%s/receive/intake.state", root) >=
            (int)sizeof(path))
        return;
    f = fopen(path, "rb");
    if (!f)
        return;
    n = fread(text, 1, sizeof(text) - 1, f);
    (void)fclose(f);
    text[n] = '\0';
    lo->intake_failures = fmc_body_int(text, "failures");
    if (!fmc_body_kv(text, "last_error", lo->intake_error,
                     sizeof(lo->intake_error)))
        lo->intake_error[0] = '\0';
}

static bool fmc_lock_seen(const char *s)
{
    return strcmp(s, "held") == 0 || strcmp(s, "free") == 0;
}

static bool fmc_lock_held(const char *s)
{
    return strcmp(s, "held") == 0;
}

/* The local resident, when any local evidence exists: a queue row, or a
 * receiver/worker lock file. Named after the claimant of the running row
 * when there is one, else "local". Merges into a mail entry of the same
 * name, so one identity is one entry. */
static void fmc_roster_local(struct fmc_roster *ro,
                             const struct fmc_queue_view *qv,
                             const struct fmc_local *lo)
{
    struct fmc_worker *e;
    bool rows = qv->known && (qv->queued > 0 || qv->running > 0);
    if (!rows && !fmc_lock_seen(lo->worker_lock) &&
        !fmc_lock_seen(lo->receive_lock))
        return;
    e = fmc_roster_entry(ro, qv->run_worker[0] ? qv->run_worker : "local");
    if (e)
        e->local = true;
}

/* Local state, per the rules in the file header. */
static const char *fmc_local_state(const struct fmc_queue_view *qv,
                                   const struct fmc_local *lo, char *why,
                                   size_t cap)
{
    if (qv->known && qv->running > 0) {
        (void)snprintf(why, cap, "queue row %s is running (claimant %s)",
                       qv->run_ref, qv->run_worker[0] ? qv->run_worker
                                                      : "not recorded");
        return "working";
    }
    if (!lo->mail_ok && fmc_lock_held(lo->receive_lock)) {
        (void)snprintf(why, cap, "%s",
                       "local receiver intake failed: the dev.agent.mail "
                       "pull it reads refused in this brief");
        return "blocked";
    }
    if (qv->known && qv->queued > 0 && !fmc_lock_held(lo->worker_lock)) {
        (void)snprintf(why, cap,
                       "%lld queued row(s) and no resident worker holds "
                       "worker.lock (%s) to claim them",
                       qv->queued, lo->worker_lock);
        return "blocked";
    }
    if (qv->known && qv->queued > 0) {
        (void)snprintf(why, cap,
                       "%lld queued row(s) not yet claimed; worker.lock held",
                       qv->queued);
        return "unknown";
    }
    if (!qv->known) {
        (void)snprintf(why, cap, "queue status unavailable (%s)",
                       qv->reason);
        return "unknown";
    }
    if (fmc_lock_held(lo->worker_lock) || fmc_lock_held(lo->receive_lock)) {
        (void)snprintf(why, cap, "%s",
                       "a resident lock is held now; nothing queued or "
                       "running");
        return "idle";
    }
    (void)snprintf(why, cap, "%s",
                   "no resident lock held and nothing running");
    return "unknown";
}

static bool fmc_stage_claimed(const char *stage)
{
    return strcmp(stage, "running") == 0 || strcmp(stage, "engine") == 0;
}

/* Remote state from the worker's own newest words. */
static const char *fmc_remote_state(const struct fmc_worker *e,
                                    bool terminal, long long alive,
                                    char *why, size_t cap)
{
    if (strcmp(e->state, "refused") == 0) {
        (void)snprintf(why, cap, "newest answer refused ref %s: %s", e->ref,
                       e->reason[0] ? e->reason : "no reason stated");
        return "blocked";
    }
    if (!terminal && fmc_stage_claimed(e->stage)) {
        (void)snprintf(why, cap,
                       "claimed ref %s at stage %s; no terminal result yet",
                       e->ref, e->stage);
        return "working";
    }
    if (!terminal && strcmp(e->state, "accepted") == 0) {
        (void)snprintf(why, cap,
                       "ref %s accepted at stage %s; no claim or result "
                       "evidence yet",
                       e->ref, e->stage[0] ? e->stage : "unstated");
        return "unknown";
    }
    if (alive >= 0 && alive <= FMC_ALIVE_WINDOW_S) {
        (void)snprintf(why, cap,
                       "last evidence %llds ago, within the %llds window; "
                       "no open claim",
                       alive, FMC_ALIVE_WINDOW_S);
        return "idle";
    }
    if (alive < 0) {
        (void)snprintf(why, cap, "%s",
                       "newest row carries no parseable timestamp");
        return "unknown";
    }
    (void)snprintf(why, cap, "last evidence %llds ago, older than the %llds "
                   "window", alive, FMC_ALIVE_WINDOW_S);
    return "unknown";
}

/* A string field, or JSON null when unknown. */
static void fmc_put_str(struct json_value *o, const char *key, const char *s)
{
    struct json_value nv;
    if (s && s[0]) {
        (void)json_push_kv_str(o, key, s);
        return;
    }
    json_init(&nv);
    json_set_null(&nv);
    (void)json_push_kv(o, key, &nv);
    json_free(&nv);
}

/* A number field, or JSON null when unknown (-1). */
static void fmc_put_int(struct json_value *o, const char *key, long long v)
{
    struct json_value nv;
    if (v >= 0) {
        (void)json_push_kv_int(o, key, v);
        return;
    }
    json_init(&nv);
    json_set_null(&nv);
    (void)json_push_kv(o, key, &nv);
    json_free(&nv);
}

/* Local resources, measured now through the platform seams. */
static void fmc_local_resources(struct fmc_worker *e, char *why, size_t cap)
{
    char root[4096];
    struct os_proc_mem mem;
    int64_t disk = -1;
    e->load1 = os_proc_load1_centi();
    e->mem_kib = -1;
    if (os_proc_mem_read(&mem) && mem.sys_avail_bytes >= 0)
        e->mem_kib = mem.sys_avail_bytes / 1024;
    if (platform_state_root(root, sizeof(root)))
        disk = disk_monitor_free_bytes(root);
    e->disk_kib = disk >= 0 ? disk / 1024 : -1;
    (void)snprintf(why, cap, "%s",
                   e->load1 >= 0 && e->mem_kib >= 0 && e->disk_kib >= 0
                       ? "measured on this host now"
                       : "measured on this host now; null = this host "
                         "could not read it");
}

static void fmc_remote_resources(const struct fmc_worker *e, char *why,
                                 size_t cap)
{
    bool any = e->load1 >= 0 || e->mem_kib >= 0 || e->disk_kib >= 0;
    (void)snprintf(why, cap, "%s",
                   any ? "self-reported in its newest answer; null = not "
                         "reported"
                       : "not reported");
}

struct fmc_emit_ctx {
    long long now;
    const struct fmc_roster *ro;
    const struct json_value *outcomes;
    const struct fmc_queue_view *qv;
    const struct fmc_local *lo;
};

/* True when a retained queue outcome or a result row names ref. */
static bool fmc_ref_terminal(const struct fmc_emit_ctx *c, const char *ref)
{
    size_t n, i;
    if (!ref || !ref[0])
        return false;
    if (fmc_roster_is_done(c->ro, ref))
        return true;
    n = c->outcomes ? json_size(c->outcomes) : 0;
    for (i = 0; i < n; i++) {
        const struct json_value *r = json_at(c->outcomes, i);
        if (strcmp(fmc_row_field(r, "name"), ref) == 0)
            return true;
    }
    return false;
}

/* Alive age: the newest of the row stamp and a self-reported heartbeat. */
static long long fmc_alive_age(const struct fmc_worker *e, long long now)
{
    long long age = fmc_age_s(now, e->ts);
    long long hb = e->heartbeat >= 0 ? (now > e->heartbeat
                                            ? now - e->heartbeat
                                            : 0)
                                     : -1;
    if (hb >= 0 && (age < 0 || hb < age))
        return hb;
    return age;
}

static void fmc_now_iso(long long now, char *out, size_t cap)
{
    struct tm tm_utc;
    out[0] = '\0';
    if (!platform_time_utc_tm((time_t)now, &tm_utc) ||
        strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0)
        out[0] = '\0';
}

/* The local entry's view: queue claim, resources, token usage, stamp. */
static const char *fmc_local_fill(struct fmc_worker *e,
                                  const struct fmc_emit_ctx *c,
                                  char *why, size_t cap, char *res_why,
                                  size_t res_cap)
{
    const char *state = fmc_local_state(c->qv, c->lo, why, cap);
    fmc_local_resources(e, res_why, res_cap);
    if (c->lo->intake_failures > 0) {
        size_t used = strlen(why);
        (void)snprintf(why + used, cap - used,
                       "; receiver intake.state records %lld past intake "
                       "failure(s), last_error=%.48s",
                       c->lo->intake_failures,
                       c->lo->intake_error[0] ? c->lo->intake_error
                                              : "unstated");
    }
    if (c->qv->known && c->qv->running > 0) {
        (void)snprintf(e->ref, sizeof(e->ref), "%s", c->qv->run_ref);
        (void)snprintf(e->stage, sizeof(e->stage), "%s", "running");
    }
    e->tok_last = c->qv->tok_last;
    e->tok_total = c->qv->tok_total;
    if (fmc_lock_held(c->lo->worker_lock) ||
        fmc_lock_held(c->lo->receive_lock))
        fmc_now_iso(c->now, e->ts, sizeof(e->ts));
    else if (!e->ts[0])
        (void)snprintf(e->ts, sizeof(e->ts), "%s", c->qv->outcome_ts);
    return state;
}

/* One worker as its JSON entry. */
static void fmc_worker_emit(struct json_value *arr, struct fmc_worker *e,
                            const struct fmc_emit_ctx *c)
{
    struct json_value o;
    char why[384], res_why[96];
    const char *state;
    long long age;
    if (e->local) {
        state = fmc_local_fill(e, c, why, sizeof(why), res_why,
                               sizeof(res_why));
    } else {
        state = fmc_remote_state(e, fmc_ref_terminal(c, e->ref),
                                 fmc_alive_age(e, c->now), why, sizeof(why));
        fmc_remote_resources(e, res_why, sizeof(res_why));
    }
    age = fmc_age_s(c->now, e->ts);
    json_init(&o);
    json_set_object(&o);
    (void)json_push_kv_str(&o, "name", e->name);
    fmc_put_str(&o, "host", e->host);
    (void)json_push_kv_str(&o, "source", e->local ? "local" : "mail");
    (void)json_push_kv_bool(&o, "self_reported", !e->local);
    fmc_put_str(&o, "workspace_selector", e->ws_selector);
    fmc_put_str(&o, "workspace_head", e->ws_head);
    fmc_put_str(&o, "current_ref", e->ref);
    fmc_put_str(&o, "stage", e->stage);
    fmc_put_str(&o, "last_seen_ts", age >= 0 ? e->ts : "");
    fmc_put_int(&o, "age_s", age);
    fmc_put_int(&o, "tokens_last_run", e->tok_last);
    fmc_put_int(&o, "tokens_total", e->tok_total);
    fmc_put_int(&o, "load1_centi", e->load1);
    fmc_put_int(&o, "mem_avail_kib", e->mem_kib);
    fmc_put_int(&o, "disk_free_kib", e->disk_kib);
    (void)json_push_kv_str(&o, "resources_reason", res_why);
    (void)json_push_kv_str(&o, "state", state);
    (void)json_push_kv_str(&o, "reason", why);
    (void)json_push_back(arr, &o);
    json_free(&o);
}

/* Local first, then newest evidence first. */
static int fmc_worker_cmp(const void *a, const void *b)
{
    const struct fmc_worker *x = (const struct fmc_worker *)a;
    const struct fmc_worker *y = (const struct fmc_worker *)b;
    if (x->local != y->local)
        return x->local ? -1 : 1;
    return strcmp(y->ts, x->ts);
}

/* workers[] plus its bound: at most FMC_WORKER_CAP entries, with the true
 * total and a truncated flag beside them. */
static void fmc_workers_emit(struct json_value *data, struct fmc_roster *ro,
                             const struct fmc_emit_ctx *c)
{
    struct json_value arr;
    size_t i, total = ro->n;
    json_init(&arr);
    json_set_array(&arr);
    if (ro->w && ro->n > 1)
        qsort(ro->w, ro->n, sizeof(*ro->w), fmc_worker_cmp);
    for (i = 0; ro->w && i < ro->n && i < FMC_WORKER_CAP; i++)
        fmc_worker_emit(&arr, &ro->w[i], c);
    (void)json_push_kv(data, "workers", &arr);
    (void)json_push_kv_int(data, "workers_total", (long long)total);
    (void)json_push_kv_bool(data, "workers_total_exact", ro->untracked == 0);
    (void)json_push_kv_bool(data, "workers_truncated",
                            total > json_size(&arr) || ro->untracked > 0);
    (void)json_push_kv_int(data, "alive_window_s", FMC_ALIVE_WINDOW_S);
    json_free(&arr);
}

/* ── brief: agent sessions ───────────────────────────────────────────────
 *
 * workers[] is the resident Muse executors; sessions[] is the coding-agent
 * SESSIONS (roles A, B, C, D, plus any other label seen) that steer them.
 * Every box posts mail as its Unix user, so `from` names no role: a session
 * is known ONLY from its own presence row, a `note` under ref
 * presence-<ROLE> whose body is the strict presence.v1 line
 *
 *   presence.v1; host=H; session=S; pid=N; started=TS; role=R; observed=TS;
 *   task=T; phase=P; source=SRC; binary_sha256=HEX64; workers=W1,W2;
 *   spend=N
 *
 * Only that line is parsed; free text, unknown keys and values that fail
 * their key's shape are ignored, and a value that looks like a credential
 * (a bearer, an API-key prefix, a password or secret word, or any unbroken
 * alphanumeric run of FMC_SECRET_RUN or more) is dropped and named in
 * refused_fields, never echoed. The change lead of a presence row is
 * replaced for the same reason: the body leaves this leaf only through
 * the parsed whitelist. The newest row per role decides; state is live
 * within FMC_ALIVE_WINDOW_S of that row's own ts, stale past it (with the
 * age), and UNKNOWN with no row at all. Every missing field is the string
 * "UNKNOWN", never empty and never 0. Linked workers are the workers[]
 * names whose self-reported host equals the session's host, referenced by
 * name only, and a session's resource headroom is the first such worker's
 * reported load/memory/disk. */

#define FMC_PRESENCE_REF "presence-"
#define FMC_PRESENCE_TAG "presence.v1"
#define FMC_ROLE_MAX 32u
#define FMC_SESSION_VAL 97u
#define FMC_SECRET_RUN 24u
#define FMC_SESSION_LINKS 8u

enum fmc_pv { FMC_PV_WORD, FMC_PV_TEXT, FMC_PV_INT, FMC_PV_TS,
              FMC_PV_SHA256, FMC_PV_LIST };

struct fmc_pkey {
    const char *key;
    const char *out;
    enum fmc_pv kind;
    size_t max;
};

static const struct fmc_pkey fmc_pkeys[] = {
    {"host", "host", FMC_PV_WORD, 64},
    {"session", "session", FMC_PV_WORD, 64},
    {"pid", "pid", FMC_PV_INT, 10},
    {"started", "started", FMC_PV_TS, 20},
    {"role", "role_reported", FMC_PV_WORD, FMC_ROLE_MAX},
    {"observed", "observed", FMC_PV_TS, 20},
    {"task", "task", FMC_PV_TEXT, 96},
    {"phase", "phase", FMC_PV_WORD, 32},
    {"source", "source", FMC_PV_TEXT, 96},
    {"binary_sha256", "binary_sha256", FMC_PV_SHA256, 64},
    {"workers", "workers_reported", FMC_PV_LIST, 96},
    {"spend", "spend_tokens", FMC_PV_INT, 18},
};
#define FMC_PKEYS (sizeof(fmc_pkeys) / sizeof(fmc_pkeys[0]))
#define FMC_PKEY_HOST 0u

struct fmc_session {
    char role[FMC_ROLE_MAX + 1];
    char ts[40];
    char val[FMC_PKEYS][FMC_SESSION_VAL];
    bool refused[FMC_PKEYS];
    long long seq;
    bool seen;
    bool parsed;
};

static const char *const fmc_expected_roles[] = {"A", "B", "C", "D"};

/* A presence row's role, or NULL when the row is not one. */
static const char *fmc_presence_role(const struct fmc_row *v)
{
    size_t plen = sizeof(FMC_PRESENCE_REF) - 1;
    if (strcmp(v->kind, "note") != 0 ||
        strncmp(v->ref, FMC_PRESENCE_REF, plen) != 0)
        return NULL;
    return fmc_is_token(v->ref + plen, FMC_ROLE_MAX, false) ? v->ref + plen
                                                            : NULL;
}

/* The session entry for role, created when absent (NULL once the table
 * is full; the overflow is counted so sessions_total stays honest). */
static struct fmc_session *fmc_session_entry(struct fmc_roster *ro,
                                             const char *role)
{
    size_t i;
    for (i = 0; ro->ss && i < ro->nss; i++) {
        if (strcmp(ro->ss[i].role, role) == 0)
            return &ro->ss[i];
    }
    if (!ro->ss || ro->nss >= FMC_SESSION_TRACK) {
        ro->ss_untracked++;
        return NULL;
    }
    memset(&ro->ss[ro->nss], 0, sizeof(ro->ss[0]));
    (void)snprintf(ro->ss[ro->nss].role, FMC_ROLE_MAX + 1, "%s", role);
    ro->ss[ro->nss].seq = -1;
    return &ro->ss[ro->nss++];
}

static size_t fmc_session_size(void)
{
    return sizeof(struct fmc_session);
}

static void fmc_sessions_seed(struct fmc_roster *ro)
{
    size_t i;
    for (i = 0; i < sizeof(fmc_expected_roles) / sizeof(fmc_expected_roles[0]);
         i++)
        (void)fmc_session_entry(ro, fmc_expected_roles[i]);
}

static bool fmc_pv_char_ok(char ch, enum fmc_pv kind)
{
    if (isalnum((unsigned char)ch) || strchr("._:@+-", ch))
        return true;
    if (kind == FMC_PV_LIST && ch == ',')
        return true;
    return kind == FMC_PV_TEXT && strchr(" /,#", ch) != NULL;
}

static bool fmc_all_hex(const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (!isxdigit((unsigned char)s[i]) || isupper((unsigned char)s[i]))
            return false;
    }
    return true;
}

/* True when some unbroken alphanumeric run is long enough to be a key or
 * a bearer. A 40-hex git commit id is the one exemption, and only where
 * hex40_ok says the field names a source revision. */
static bool fmc_has_secret_run(const char *s, bool hex40_ok)
{
    size_t i = 0, run;
    while (s[i]) {
        for (run = 0; isalnum((unsigned char)s[i + run]); run++)
            ;
        if (run >= FMC_SECRET_RUN &&
            !(hex40_ok && run == 40 && fmc_all_hex(s + i, run)))
            return true;
        i += run ? run : 1;
    }
    return false;
}

/* True when s names a credential: a secret word anywhere, or a vendor
 * key prefix at the start of a word. Case-insensitive. */
static bool fmc_has_secret_word(const char *s)
{
    static const char *const words[] = {
        "bearer", "password", "passwd", "secret", "apikey", "api_key",
        "api-key", "authorization", "private_key", "privkey",
    };
    static const char *const prefixes[] = {
        "sk-", "xai-", "gsk_", "ghp_", "gho_", "ghs_", "github_pat_",
        "glpat-", "akia",
    };
    char low[FMC_SESSION_VAL];
    size_t i, j;
    for (i = 0; s[i] && i + 1 < sizeof(low); i++)
        low[i] = (char)tolower((unsigned char)s[i]);
    low[i] = '\0';
    for (j = 0; j < sizeof(words) / sizeof(words[0]); j++) {
        if (strstr(low, words[j]))
            return true;
    }
    for (i = 0; low[i]; i++) {
        if (i > 0 && isalnum((unsigned char)low[i - 1]))
            continue;
        for (j = 0; j < sizeof(prefixes) / sizeof(prefixes[0]); j++) {
            if (strncmp(low + i, prefixes[j], strlen(prefixes[j])) == 0)
                return true;
        }
    }
    return false;
}

/* One value against its key's shape. */
static bool fmc_pv_ok(const struct fmc_pkey *k, const char *val, size_t n)
{
    size_t i;
    if (n == 0 || n > k->max)
        return false;
    if (k->kind == FMC_PV_INT)
        return fmc_digits(val, n);
    if (k->kind == FMC_PV_TS)
        return fmc_ts_shape_ok(val);
    if (k->kind == FMC_PV_SHA256)
        return n == 64 && fmc_all_hex(val, n);
    for (i = 0; i < n; i++) {
        if (!fmc_pv_char_ok(val[i], k->kind))
            return false;
    }
    return !fmc_has_secret_word(val) &&
           !fmc_has_secret_run(val, strcmp(k->key, "source") == 0);
}

/* One `key=value` segment. Unknown keys are ignored; the first stated
 * value of a key wins; a value failing its shape is refused by name. */
static void fmc_presence_pair(struct fmc_session *s, const char *seg,
                              size_t len)
{
    char val[FMC_SESSION_VAL + 1];
    const char *eq = memchr(seg, '=', len);
    size_t klen, vlen, i;
    if (!eq)
        return;
    klen = (size_t)(eq - seg);
    vlen = len - klen - 1;
    while (vlen > 0 && eq[vlen] == ' ')
        vlen--;
    for (i = 0; i < FMC_PKEYS; i++) {
        if (strlen(fmc_pkeys[i].key) == klen &&
            strncmp(seg, fmc_pkeys[i].key, klen) == 0)
            break;
    }
    if (i == FMC_PKEYS || s->val[i][0] || s->refused[i])
        return;
    if (vlen >= sizeof(val)) {
        s->refused[i] = true;
        return;
    }
    memcpy(val, eq + 1, vlen);
    val[vlen] = '\0';
    if (fmc_pv_ok(&fmc_pkeys[i], val, vlen))
        (void)snprintf(s->val[i], FMC_SESSION_VAL, "%s", val);
    else
        s->refused[i] = true;
}

/* Parse one body as presence.v1: the tag, then `; key=value` segments to
 * the end of the first line. Anything else leaves every field UNKNOWN. */
static void fmc_presence_parse(struct fmc_session *s, const char *body)
{
    size_t tlen = sizeof(FMC_PRESENCE_TAG) - 1;
    const char *p = body + tlen;
    memset(s->val, 0, sizeof(s->val));
    memset(s->refused, 0, sizeof(s->refused));
    s->parsed = strncmp(body, FMC_PRESENCE_TAG, tlen) == 0 &&
                (body[tlen] == '\0' || body[tlen] == ';');
    if (!s->parsed)
        return;
    while (*p == ';') {
        size_t n;
        p++;
        while (*p == ' ')
            p++;
        n = strcspn(p, ";\r\n");
        fmc_presence_pair(s, p, n);
        p += n;
    }
}

/* Fold one pulled row into the session table: the newest presence row
 * per role decides (ties keep the first seen). */
static void fmc_sessions_note(struct fmc_roster *ro, const struct fmc_row *v)
{
    const char *role = fmc_presence_role(v);
    struct fmc_session *s;
    if (!role)
        return;
    s = fmc_session_entry(ro, role);
    if (!s || (s->seen && strcmp(v->ts, s->ts) <= 0))
        return;
    s->seen = true;
    s->seq = v->seq;
    (void)snprintf(s->ts, sizeof(s->ts), "%.39s", v->ts);
    fmc_presence_parse(s, v->body);
}

/* A string, or "UNKNOWN" when empty. */
static void fmc_put_known(struct json_value *o, const char *key,
                          const char *s)
{
    (void)json_push_kv_str(o, key, s && s[0] ? s : "UNKNOWN");
}

/* A number, or "UNKNOWN" when negative (unknown). */
static void fmc_put_known_int(struct json_value *o, const char *key,
                              long long v)
{
    if (v >= 0)
        (void)json_push_kv_int(o, key, v);
    else
        (void)json_push_kv_str(o, key, "UNKNOWN");
}

static const char *fmc_session_state(const struct fmc_session *s,
                                     long long age, char *why, size_t cap)
{
    const char *state = "UNKNOWN";
    if (!s->seen)
        (void)snprintf(why, cap, "no note row under ref presence-%s in the "
                       "mail this host pulls", s->role);
    else if (age < 0)
        (void)snprintf(why, cap, "%s",
                       "presence row carries no parseable ts");
    else if (age <= FMC_ALIVE_WINDOW_S)
        (void)snprintf(why, cap, "presence row %llds old, within the "
                       "%llds window", age, FMC_ALIVE_WINDOW_S);
    else
        (void)snprintf(why, cap, "presence row %llds old, older than the "
                       "%llds window", age, FMC_ALIVE_WINDOW_S);
    if (s->seen && age >= 0)
        state = age <= FMC_ALIVE_WINDOW_S ? "live" : "stale";
    if (s->seen && !s->parsed) {
        size_t used = strlen(why);
        (void)snprintf(why + used, cap - used, "%s",
                       "; body is not a presence.v1 line, fields UNKNOWN");
    }
    return state;
}

/* The parsed whitelist, each field its value or "UNKNOWN". */
static void fmc_session_fields(struct json_value *o,
                               const struct fmc_session *s)
{
    struct json_value refused;
    size_t i;
    json_init(&refused);
    json_set_array(&refused);
    for (i = 0; i < FMC_PKEYS; i++) {
        if (fmc_pkeys[i].kind == FMC_PV_INT)
            fmc_put_known_int(o, fmc_pkeys[i].out,
                              s->val[i][0] ? fmc_num(s->val[i],
                                                     strlen(s->val[i]))
                                           : -1);
        else
            fmc_put_known(o, fmc_pkeys[i].out, s->val[i]);
        if (s->refused[i])
            (void)fmc_push_distinct(&refused, fmc_pkeys[i].key, FMC_PKEYS);
    }
    (void)json_push_kv(o, "refused_fields", &refused);
    json_free(&refused);
}

/* Workers on the session's host, by name only, and the first one's
 * reported resource headroom; UNKNOWN when none reports it. */
static void fmc_session_links(struct json_value *o,
                              const struct fmc_session *s,
                              const struct fmc_roster *ro)
{
    const char *host = s->val[FMC_PKEY_HOST];
    const struct fmc_worker *res = NULL;
    struct json_value names;
    size_t i;
    json_init(&names);
    json_set_array(&names);
    for (i = 0; host[0] && ro->w && i < ro->n; i++) {
        const struct fmc_worker *e = &ro->w[i];
        if (strcmp(e->host, host) != 0)
            continue;
        (void)fmc_push_distinct(&names, e->name, FMC_SESSION_LINKS);
        if (!res && (e->load1 >= 0 || e->mem_kib >= 0 || e->disk_kib >= 0))
            res = e;
    }
    (void)json_push_kv(o, "workers", &names);
    json_free(&names);
    fmc_put_known_int(o, "load1_centi", res ? res->load1 : -1);
    fmc_put_known_int(o, "mem_avail_kib", res ? res->mem_kib : -1);
    fmc_put_known_int(o, "disk_free_kib", res ? res->disk_kib : -1);
    fmc_put_known(o, "resources_from", res ? res->name : "");
}

static void fmc_session_emit(struct json_value *arr,
                             const struct fmc_session *s,
                             const struct fmc_roster *ro, long long now)
{
    struct json_value o;
    char why[160];
    long long age = s->seen ? fmc_age_s(now, s->ts) : -1;
    const char *state = fmc_session_state(s, age, why, sizeof(why));
    json_init(&o);
    json_set_object(&o);
    (void)json_push_kv_str(&o, "role", s->role);
    (void)json_push_kv_str(&o, "state", state);
    (void)json_push_kv_str(&o, "reason", why);
    fmc_put_known(&o, "format", s->seen ? (s->parsed ? FMC_PRESENCE_TAG
                                                     : "unparsed")
                                        : "");
    fmc_session_fields(&o, s);
    fmc_put_known(&o, "last_observed_ts", age >= 0 ? s->ts : "");
    fmc_put_known_int(&o, "age_s", age);
    fmc_put_known(&o, "observed_via", s->seen ? "dev.agent.mail pull" : "");
    /* The pull merges the outbox and every inbox.<peer>.jsonl without
     * naming a row's stream, so the file a row came from is not known
     * here; the seq is the exact handle for fleet.steer.evidence. */
    (void)json_push_kv_str(&o, "observed_stream", "UNKNOWN");
    fmc_put_known_int(&o, "mail_seq", s->seq);
    fmc_session_links(&o, s, ro);
    (void)json_push_back(arr, &o);
    json_free(&o);
}

/* Fleet Muse spend: the tokens the workers already report from their run
 * receipts. No existing source records reservations, so they are
 * UNKNOWN rather than a guessed zero. */
static void fmc_spend_emit(struct json_value *data,
                           const struct fmc_roster *ro)
{
    struct json_value o;
    long long sum = 0, counted = 0, unknown = 0;
    size_t i;
    for (i = 0; ro->w && i < ro->n; i++) {
        if (ro->w[i].tok_total < 0) {
            unknown++;
            continue;
        }
        sum += ro->w[i].tok_total;
        counted++;
    }
    json_init(&o);
    json_set_object(&o);
    fmc_put_known_int(&o, "tokens_total", counted > 0 ? sum : -1);
    (void)json_push_kv_bool(&o, "tokens_total_exact",
                            unknown == 0 && ro->untracked == 0);
    (void)json_push_kv_int(&o, "workers_counted", counted);
    (void)json_push_kv_int(&o, "workers_without_receipt", unknown);
    (void)json_push_kv_str(&o, "reservations", "UNKNOWN");
    (void)json_push_kv_str(&o, "reason",
                           "sum of workers[] tokens_total from run receipts; "
                           "no existing source records Muse reservations");
    (void)json_push_kv(data, "muse_spend", &o);
    json_free(&o);
}

/* sessions[] plus its bound, after workers[] so the local worker's
 * receipt tokens are filled before they are summed. */
static void fmc_sessions_emit(struct json_value *data,
                              const struct fmc_roster *ro, long long now)
{
    struct json_value arr;
    size_t i;
    json_init(&arr);
    json_set_array(&arr);
    for (i = 0; ro->ss && i < ro->nss && i < FMC_SESSION_CAP; i++)
        fmc_session_emit(&arr, &ro->ss[i], ro, now);
    (void)json_push_kv(data, "sessions", &arr);
    (void)json_push_kv_int(data, "sessions_total",
                           (long long)(ro->nss + ro->ss_untracked));
    (void)json_push_kv_bool(data, "sessions_truncated",
                            ro->nss + ro->ss_untracked > json_size(&arr));
    (void)json_push_kv_str(data, "presence_format", FMC_PRESENCE_TAG);
    json_free(&arr);
    fmc_spend_emit(data, ro);
}

/* Push one bounded blocker string. */
static void fmc_push_blocker(struct json_value *blockers, const char *b)
{
    struct json_value item;
    if (json_size(blockers) >= FMC_BLOCKER_CAP)
        return;
    json_init(&item);
    json_set_str(&item, b);
    (void)json_push_back(blockers, &item);
    json_free(&item);
}

/* A directive this host sent that is still "queued" (no receiver evidence
 * at all) past FMC_QUEUED_STALE_S: exactly "steer send said QUEUED but
 * the target never read it". True when the row is stale; only the first
 * FMC_STALE_BLOCKER_CAP are spelled out, so they cannot crowd every other
 * blocker out, and fmc_stale_summary counts the rest. */
static bool fmc_stale_blocker(struct json_value *blockers,
                              const struct fmc_row *v, long long age,
                              bool spell)
{
    char b[256];
    int wlen;
    if (age <= FMC_QUEUED_STALE_S)
        return false;
    if (!spell)
        return true;
    wlen = snprintf(b, sizeof(b),
                    "directive %.64s to %.48s: no receiver evidence after "
                    "%lld s (threshold %lld s)",
                    v->ref, v->to, age, FMC_QUEUED_STALE_S);
    if (wlen > 0 && (size_t)wlen < sizeof(b))
        fmc_push_blocker(blockers, b);
    return true;
}

/* One line for the stale directives not spelled out. */
static void fmc_stale_summary(struct json_value *blockers, int stale)
{
    char b[192];
    if (stale <= FMC_STALE_BLOCKER_CAP)
        return;
    (void)snprintf(b, sizeof(b),
                   "%d more directives sent from here have no receiver "
                   "evidence after %lld s (among the newest %d directives)",
                   stale - FMC_STALE_BLOCKER_CAP, FMC_QUEUED_STALE_S,
                   FMC_DIRECTIVE_SCAN);
    fmc_push_blocker(blockers, b);
}

/* ── brief: request/result correlation ───────────────────────────────────
 *
 * A directive change row carries `reply`, three facts kept apart:
 *   acked     the receiver's own ack cursor covers the row (never a reply);
 *   answered  a later `result` row under the same ref from the other side:
 *             written by the addressee (answer_match "addressee"), or
 *             addressed back to the origin by anyone but the origin itself
 *             (answer_match "reply_to_origin" — every box posts as its Unix
 *             user, so the reply's author need not carry the role name);
 *             an attempt= stated on both sides must agree;
 *   state     answered, else acked, else queued.
 * sent_ts/sent_age_s are the directive's own time; answer_ts/answer_age_s
 * the reply's. The lifecycle `state` beside it keeps its closed
 * vocabulary; a reply never becomes an ack there either unless it came
 * from the addressee by name, as before. */

struct fmc_answer {
    const struct fmc_row *row;
    struct fmc_row keep;
    const char *match;
};

static bool fmc_attempt_agrees(const char *a, const char *b)
{
    long long x = fmc_body_int(a, "attempt");
    long long y = fmc_body_int(b, "attempt");
    return x < 0 || y < 0 || x == y;
}

/* How r answers directive d, or NULL when it does not. */
static const char *fmc_answer_match(const struct fmc_row *d,
                                    const struct fmc_row *r)
{
    long long dt = fmc_ts_unix(d->ts), rt = fmc_ts_unix(r->ts);
    if (strcmp(r->kind, "result") != 0 || strcmp(r->ref, d->ref) != 0 ||
        strcmp(r->from, d->from) == 0)
        return NULL;
    if ((dt >= 0 && rt >= 0 && rt < dt) ||
        !fmc_attempt_agrees(d->body, r->body))
        return NULL;
    if (strcmp(r->from, d->to) == 0)
        return "addressee";
    return strcmp(r->to, d->from) == 0 ? "reply_to_origin" : NULL;
}

/* The newest answer to d among the pulled rows. */
static bool fmc_answer_find(const struct json_value *rows,
                            const struct fmc_row *d, struct fmc_answer *a)
{
    size_t n = rows && rows->type == JSON_ARR ? json_size(rows) : 0u, i;
    a->row = NULL;
    a->match = NULL;
    for (i = 0; d->ref[0] && i < n; i++) {
        struct fmc_row r;
        const char *m;
        if (!fmc_row_parse(json_at(rows, i), &r))
            continue;
        m = fmc_answer_match(d, &r);
        if (!m || (a->row && strcmp(r.ts, a->keep.ts) <= 0))
            continue;
        a->keep = r;
        a->row = &a->keep;
        a->match = m;
    }
    return a->row != NULL;
}

/* The reply object for one directive change row. */
static void fmc_reply_emit(struct json_value *item, const struct fmc_row *v,
                           const struct json_value *rows, long long now)
{
    struct json_value o;
    struct fmc_answer a;
    long long ack = fmc_ack_cursor(v->to);
    bool acked = ack >= 0 && v->seq <= ack;
    bool answered = fmc_answer_find(rows, v, &a);
    json_init(&o);
    json_set_object(&o);
    (void)json_push_kv_str(&o, "state", answered ? "answered"
                                         : acked ? "acked" : "queued");
    (void)json_push_kv_bool(&o, "acked", acked);
    fmc_put_known(&o, "sent_ts", fmc_ts_unix(v->ts) >= 0 ? v->ts : "");
    fmc_put_known_int(&o, "sent_age_s", fmc_age_s(now, v->ts));
    fmc_put_known_int(&o, "answer_seq", answered ? a.row->seq : -1);
    fmc_put_known(&o, "answer_ts", answered ? a.row->ts : "");
    fmc_put_known_int(&o, "answer_age_s",
                      answered ? fmc_age_s(now, a.row->ts) : -1);
    fmc_put_known(&o, "answered_by", answered ? a.row->from : "");
    fmc_put_known(&o, "answer_match", answered ? a.match : "");
    (void)json_push_kv(item, "reply", &o);
    json_free(&o);
}

/* One bounded change row, carrying the state fmc_row_state resolves from
 * receiver evidence; completed is resolved later against queue outcomes
 * and board results. queued_age_s is how long a row has sat "queued"
 * (null for every other state, and when its stamp does not parse). */
static void fmc_row_change(struct json_value *changes, const struct fmc_row *v,
                           const struct json_value *rows,
                           const char *sent_path, long long now)
{
    struct json_value item;
    char lead[FMC_LEAD_MAX + 1];
    const char *state = fmc_row_state(v, rows, sent_path);
    bool queued = strcmp(state, "queued") == 0;
    json_init(&item);
    json_set_object(&item);
    /* A presence body leaves the brief only through sessions[]' parsed
     * whitelist, so its raw lead is never echoed here. */
    if (fmc_presence_role(v))
        (void)snprintf(lead, sizeof(lead), "%s",
                       "presence row; parsed fields in sessions[]");
    else
        fmc_lead(v->body, lead, sizeof(lead));
    if (json_push_kv_int(&item, "seq", v->seq) &&
        json_push_kv_str(&item, "from", v->from) &&
        json_push_kv_str(&item, "to", v->to) &&
        json_push_kv_str(&item, "kind", v->kind) &&
        json_push_kv_str(&item, "ref", v->ref) &&
        json_push_kv_str(&item, "lead", lead) &&
        json_push_kv_str(&item, "state", state)) {
        fmc_put_int(&item, "queued_age_s",
                    queued ? fmc_age_s(now, v->ts) : -1);
        if (strcmp(v->kind, "directive") == 0)
            fmc_reply_emit(&item, v, rows, now);
        (void)json_push_back(changes, &item);
    }
    json_free(&item);
}

/* dev.agent.mail answers in bounded pages, and every mail reader in this
 * file needs the whole history: follow next_since until a page says it was
 * the last, appending each page's rows to *rows (an initialized array).
 * FMC_MAIL_PAGES_MAX bounds the walk so a runaway history is an explicit
 * failure, never a silently partial view. NULL on success with *cursor set
 * to the mail leaf's cursor, else the missing[] reason. */
#define FMC_MAIL_PAGES_MAX 4096
#define FMC_MAIL_SINCE_CAP 4096

/* One page after `since` ("" = from the start) onto *rows. NULL on success,
 * with *more saying whether another page follows and `since` advanced. */
static const char *fmc_mail_page(const struct zcl_command_request *req,
                                 struct json_value *rows, long long *cursor,
                                 char *since, bool *more)
{
    struct fmc_sub sub;
    const struct json_value *arr, *tok, *tr;
    const char *next;
    size_t n, i;
    fmc_sub_begin(&sub, "zcl.agent_mail.v1", req, "dev.agent.mail");
    if (!sub.valid) {
        fmc_sub_end(&sub);
        return "unknown_sibling";
    }
    (void)json_push_kv_str(&sub.input, "action", "pull");
    if (since[0])
        (void)json_push_kv_str(&sub.input, "since", since);
    else
        (void)json_push_kv_int(&sub.input, "since", 0);
    zcl_native_handle_dev_agent_mail(&sub.request, &sub.reply);
    sub.ran = true;
    tok = json_get(&sub.reply.data, "next_since");
    next = (tok && tok->type == JSON_STR) ? json_get_str(tok) : NULL;
    if (!fmc_sub_ok(&sub) || !next || strlen(next) >= FMC_MAIL_SINCE_CAP) {
        fmc_sub_end(&sub);
        return "sibling_refused";
    }
    *cursor = fmc_sub_int(&sub, "cursor", -1);
    arr = json_get(&sub.reply.data, "rows");
    n = (arr && arr->type == JSON_ARR) ? json_size(arr) : 0u;
    for (i = 0; i < n; i++)
        (void)json_push_back(rows, json_at(arr, i));
    tr = json_get(&sub.reply.data, "truncated");
    *more = tr && tr->type == JSON_BOOL && json_get_bool(tr);
    (void)snprintf(since, FMC_MAIL_SINCE_CAP, "%s", next);
    fmc_sub_end(&sub);
    return NULL;
}

static const char *fmc_mail_drain(const struct zcl_command_request *req,
                                  struct json_value *rows, long long *cursor)
{
    char since[FMC_MAIL_SINCE_CAP] = "";
    bool more = true;
    for (int page = 0; page < FMC_MAIL_PAGES_MAX && more; page++) {
        const char *why = fmc_mail_page(req, rows, cursor, since, &more);
        if (why)
            return why;
    }
    return more ? "page_limit" : NULL;
}

/* Everything the mail walk writes into, so each row is one call. */
struct fmc_mail_ctx {
    struct json_value *agents;
    struct json_value *work;
    struct json_value *changes;
    struct json_value *blockers;
    struct fmc_roster *ro;
    long long since;
    long long changes_cap;
    long long now;
    long long shown;
    int scanned;
    int stale;
    char sent_path[4096 + 32];
};

/* One pulled row: roster, tallies, the stale-directive check (bounded to
 * the newest FMC_DIRECTIVE_SCAN directives), and — above `since`, under
 * the cap — one change row. */
static void fmc_mail_row(struct fmc_mail_ctx *c, const struct fmc_row *v,
                         const struct json_value *rows)
{
    struct fmc_answer a;
    fmc_row_tally(c->agents, c->work, v);
    fmc_roster_note(c->ro, v);
    fmc_sessions_note(c->ro, v);
    if (strcmp(v->kind, "directive") == 0 &&
        c->scanned < FMC_DIRECTIVE_SCAN) {
        c->scanned++;
        if (strcmp(fmc_row_state(v, rows, c->sent_path), "queued") == 0 &&
            !fmc_answer_find(rows, v, &a) &&
            fmc_stale_blocker(c->blockers, v, fmc_age_s(c->now, v->ts),
                              c->stale < FMC_STALE_BLOCKER_CAP))
            c->stale++;
    }
    if (v->seq <= c->since || c->shown >= c->changes_cap)
        return;
    fmc_row_change(c->changes, v, rows, c->sent_path, c->now);
    c->shown++;
}

static long long fmc_brief_mail(const struct zcl_command_request *req,
                                struct fmc_mail_ctx *c,
                                struct json_value *missing,
                                struct fmc_mail_view *view)
{
    struct json_value rows;
    const char *why;
    size_t n, i;
    int64_t t0, t1;
    view->cursor = -1;
    view->count = 0;
    view->ok = false;
    if (!fmc_sent_path_read(c->sent_path, sizeof(c->sent_path)))
        c->sent_path[0] = '\0';
    json_init(&rows);
    json_set_array(&rows);
    t0 = clock_now_wall_ms();
    why = fmc_mail_drain(req, &rows, &view->cursor);
    t1 = clock_now_wall_ms();
    if (why) {
        fmc_note_missing(missing, "dev.agent.mail", why, t1 - t0);
        json_free(&rows);
        view->cursor = -1;
        return -1;
    }
    view->ok = true;
    n = json_size(&rows);
    view->count = (long long)n;
    /* Newest-first walk from the tail: changes[] carries the latest rows
     * above `since`, each with its lifecycle state. */
    for (i = n; i > 0; i--) {
        struct fmc_row v;
        if (fmc_row_parse(json_at(&rows, i - 1), &v))
            fmc_mail_row(c, &v, &rows);
    }
    fmc_stale_summary(c->blockers, c->stale);
    json_free(&rows);
    return view->cursor;
}

/* One queue row name into a capped list. Split out so the queue walker
 * stays under the complexity gate. */
static void fmc_queue_row_name(const struct json_value *r,
                               struct json_value *list)
{
    const struct json_value *v;
    const char *name;
    if (!r || r->type != JSON_OBJ || !list)
        return;
    v = json_get(r, "name");
    if (!v || v->type != JSON_STR)
        return;
    name = json_get_str(v);
    if (name && name[0])
        (void)fmc_push_distinct(list, name, FMC_LIST_CAP);
}

/* One non-pass outcome row as a bounded blocker string. Pass-like rows
 * are not blockers and stay silent here. */
static void fmc_queue_outcome_row(const struct json_value *r,
                                  struct json_value *blockers)
{
    const struct json_value *v;
    const char *verdict, *name;
    long long rc;
    char b[160];
    int wlen;
    struct json_value item;
    if (!r || r->type != JSON_OBJ || !blockers)
        return;
    v = json_get(r, "verdict");
    verdict = (v && v->type == JSON_STR) ? json_get_str(v) : "";
    v = json_get(r, "rc");
    rc = (v && v->type == JSON_INT) ? (long long)json_get_int(v) : -1;
    if (!verdict[0] || fmc_verdict_pass(verdict, rc))
        return;
    v = json_get(r, "name");
    name = (v && v->type == JSON_STR) ? json_get_str(v) : "?";
    wlen = snprintf(b, sizeof(b), "outcome %s %s rc=%lld", name, verdict,
                    rc);
    if (wlen <= 0 || (size_t)wlen >= sizeof(b))
        return;
    if (json_size(blockers) >= FMC_BLOCKER_CAP)
        return;
    json_init(&item);
    json_set_str(&item, b);
    (void)json_push_back(blockers, &item);
    json_free(&item);
}

/* One outcome's receipt-stated token cost into the local usage totals.
 * The status projection is oldest first, so the last known one is the
 * last run. A null (no receipt) is skipped, never summed as zero. */
static void fmc_queue_outcome_usage(const struct json_value *r,
                                    struct fmc_queue_view *view)
{
    const struct json_value *v = json_get(r, "tokens_used");
    const char *ts = fmc_row_field(r, "ts");
    if (ts[0])
        (void)snprintf(view->outcome_ts, sizeof(view->outcome_ts), "%.39s",
                       ts);
    if (!v || v->type != JSON_INT || json_get_int(v) < 0)
        return;
    view->tok_last = (long long)json_get_int(v);
    view->tok_total =
        (view->tok_total < 0 ? 0 : view->tok_total) + view->tok_last;
}

/* Non-pass outcomes become blockers; the whole array is retained for
 * completed-by-ref matching after the sub reply is freed. */
static void fmc_queue_outcomes(struct fmc_sub *sub,
                               struct json_value *blockers,
                               struct json_value *outcomes_keep,
                               struct fmc_queue_view *view)
{
    const struct json_value *arr;
    size_t n, i;
    if (!sub || !blockers || !outcomes_keep)
        return;
    arr = json_get(&sub->reply.data, "outcomes");
    if (!arr || arr->type != JSON_ARR)
        return;
    /* Bounded by the sibling's own cap. */
    json_copy(outcomes_keep, arr);
    n = json_size(arr);
    for (i = 0; i < n && i < FMC_BLOCKER_CAP * 4; i++) {
        fmc_queue_outcome_row(json_at(arr, i), blockers);
        fmc_queue_outcome_usage(json_at(arr, i), view);
    }
}

/* True when <state>/queue/pool.txt exists as a regular file. The queue
 * status reports total 0 both for an empty pool file and for none at all,
 * so only this probe tells a measured empty pool from an unmeasured one. */
static bool fmc_pool_file_present(void)
{
    char root[4096], path[4096 + 32];
    struct stat st;
    if (!platform_state_root(root, sizeof(root)) ||
        snprintf(path, sizeof(path), "%s/queue/pool.txt", root) >=
            (int)sizeof(path))
        return false;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Pool numbers become capacity, but only when the pool is measured: a
 * host with no pool.txt has an unmeasured pool, never an empty one. */
static void fmc_queue_pool(struct fmc_sub *sub, struct fmc_queue_view *view)
{
    const struct json_value *pool, *t, *f;
    if (!sub || !view)
        return;
    pool = json_get(&sub->reply.data, "pool");
    t = pool && pool->type == JSON_OBJ ? json_get(pool, "total") : NULL;
    f = pool && pool->type == JSON_OBJ ? json_get(pool, "free") : NULL;
    if (!t || t->type != JSON_INT || !f || f->type != JSON_INT) {
        (void)snprintf(view->pool_reason, sizeof(view->pool_reason), "%s",
                       "dev.agent.queue status carried no pool numbers");
        return;
    }
    if (!fmc_pool_file_present()) {
        (void)snprintf(view->pool_reason, sizeof(view->pool_reason), "%s",
                       "no queue/pool.txt on this host: the worktree pool "
                       "is not measured here, so its size is unknown");
        return;
    }
    view->pool_known = true;
    view->pool_total = (long long)json_get_int(t);
    view->pool_free = (long long)json_get_int(f);
    if (view->running > view->pool_total)
        (void)snprintf(view->pool_reason, sizeof(view->pool_reason),
                       "%lld running row(s) exceed the %lld-entry worktree "
                       "pool: running work does not draw from pool.txt",
                       view->running, view->pool_total);
}

/* Running/queued names become work + candidates; the first running row
 * names the local claim (its ref and, when claim.json recorded one, its
 * claimant). */
static void fmc_queue_rows(struct fmc_sub *sub, struct json_value *work,
                           struct json_value *candidates,
                           struct fmc_queue_view *view)
{
    const struct json_value *q = json_get(&sub->reply.data, "queued");
    const struct json_value *r = json_get(&sub->reply.data, "running");
    size_t nq = (q && q->type == JSON_ARR) ? json_size(q) : 0u;
    size_t nr = (r && r->type == JSON_ARR) ? json_size(r) : 0u;
    size_t i;
    view->queued = (long long)nq;
    view->running = (long long)nr;
    for (i = 0; i < nq; i++) {
        fmc_queue_row_name(json_at(q, i), candidates);
        fmc_queue_row_name(json_at(q, i), work);
    }
    for (i = 0; i < nr; i++) {
        fmc_queue_row_name(json_at(r, i), candidates);
        fmc_queue_row_name(json_at(r, i), work);
    }
    if (nr == 0)
        return;
    (void)snprintf(view->run_ref, sizeof(view->run_ref), "%.128s",
                   fmc_row_field(json_at(r, 0), "name"));
    (void)snprintf(view->run_worker, sizeof(view->run_worker), "%.64s",
                   fmc_row_field(json_at(r, 0), "worker"));
}

/* ── brief: queue section ────────────────────────────────────────────────
 *
 * Running/queued names become work + candidates; non-pass outcomes become
 * blockers; pool numbers become capacity. Completed-by-ref matching reads
 * the outcomes array for name==ref with an explicit pass verdict. A
 * sibling that did not answer leaves view->known false with the reason,
 * so capacity reports unknown instead of an idle zero. */

static void fmc_brief_queue(const struct zcl_command_request *req,
                            struct json_value *work,
                            struct json_value *candidates,
                            struct json_value *blockers,
                            struct json_value *missing,
                            struct fmc_queue_view *view,
                            struct json_value *outcomes_keep)
{
    struct fmc_sub sub;
    int64_t t0, t1;
    memset(view, 0, sizeof(*view));
    view->tok_last = view->tok_total = -1;
    view->pool_total = view->pool_free = -1;
    (void)snprintf(view->reason, sizeof(view->reason), "%s",
                   "unknown_sibling");
    fmc_sub_begin(&sub, "zcl.agent_queue.v1", req, "dev.agent.queue");
    if (!sub.valid) {
        fmc_note_missing(missing, "dev.agent.queue", view->reason, 0);
        fmc_sub_end(&sub);
        return;
    }
    if (!fmc_sub_input(&sub,
                       "{\"action\":\"status\",\"json\":true}")) {
        (void)snprintf(view->reason, sizeof(view->reason), "%s",
                       "input_encode");
        fmc_note_missing(missing, "dev.agent.queue", view->reason, 0);
        fmc_sub_end(&sub);
        return;
    }
    t0 = clock_now_wall_ms();
    zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
    t1 = clock_now_wall_ms();
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        (void)snprintf(view->reason, sizeof(view->reason), "%s",
                       "sibling_refused");
        fmc_note_missing(missing, "dev.agent.queue", view->reason, t1 - t0);
        fmc_sub_end(&sub);
        return;
    }
    view->known = true;
    view->reason[0] = '\0';
    fmc_queue_rows(&sub, work, candidates, view);
    fmc_queue_outcomes(&sub, blockers, outcomes_keep, view);
    fmc_queue_pool(&sub, view);
    fmc_sub_end(&sub);
}

/* One retained outcome row: true when it names ref with an explicit
 * pass verdict and a clean exit. */
static bool fmc_outcome_row_matches(const struct json_value *r,
                                    const char *ref)
{
    const struct json_value *v;
    const char *name, *verdict;
    long long rc;
    if (!r || r->type != JSON_OBJ || !ref || !ref[0])
        return false;
    v = json_get(r, "name");
    name = (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
    if (!name || strcmp(name, ref) != 0)
        return false;
    v = json_get(r, "verdict");
    verdict = (v && v->type == JSON_STR) ? json_get_str(v) : "";
    v = json_get(r, "rc");
    rc = (v && v->type == JSON_INT) ? (long long)json_get_int(v) : -1;
    return fmc_verdict_pass(verdict, rc);
}

/* True when a retained queue outcome completes ref (name match, explicit
 * pass verdict, clean exit) for the changes[] upgrade. */
static bool fmc_outcome_completes(const struct json_value *outcomes,
                                  const char *ref)
{
    size_t n, i;
    if (!outcomes || outcomes->type != JSON_ARR || !ref || !ref[0])
        return false;
    n = json_size(outcomes);
    for (i = 0; i < n; i++) {
        if (fmc_outcome_row_matches(json_at(outcomes, i), ref))
            return true;
    }
    return false;
}

/* One open problem/need as a bounded blocker string. */
static void fmc_board_blocker(struct json_value *blockers, const char *kind,
                              const char *text, const char *ref)
{
    char b[192];
    char lead[FMC_LEAD_MAX + 1];
    int wlen;
    struct json_value item;
    if (!blockers || !kind)
        return;
    fmc_lead(text ? text : "", lead, sizeof(lead));
    wlen = snprintf(b, sizeof(b), "board %s %.96s %.64s", kind, lead,
                    ref ? ref : "");
    if (wlen <= 0 || (size_t)wlen >= sizeof(b))
        return;
    if (json_size(blockers) >= FMC_BLOCKER_CAP)
        return;
    json_init(&item);
    json_set_str(&item, b);
    (void)json_push_back(blockers, &item);
    json_free(&item);
}

/* One board post's agent/kind/text/ref into the brief lists. Open problems
 * and needs are blockers; claims and results are candidates; every agent
 * name joins the roster. Bounded text only — the full post stays behind
 * fleet.board.show. */
static void fmc_board_post_lists(const struct json_value *post,
                                 struct json_value *agents,
                                 struct json_value *blockers,
                                 struct json_value *candidates)
{
    const char *agent, *kind, *ref;
    if (!post || post->type != JSON_OBJ)
        return;
    agent = fmc_row_field(post, "agent");
    if (agent[0])
        (void)fmc_push_distinct(agents, agent, FMC_LIST_CAP);
    kind = fmc_row_field(post, "kind");
    ref = fmc_row_field(post, "ref");
    if (!kind[0])
        return;
    if (strcmp(kind, "problem") == 0 || strcmp(kind, "need") == 0)
        fmc_board_blocker(blockers, kind, fmc_row_field(post, "text"),
                          ref);
    else if (strcmp(kind, "claim") == 0 || strcmp(kind, "result") == 0) {
        if (ref[0])
            (void)fmc_push_distinct(candidates, ref, FMC_LIST_CAP);
    }
}

/* Name a board sibling refusal in missing[] terms. A node that answered
 * with method-not-found predates the board RPC (generation skew, never an
 * unreachable node); anything else is the sibling's own refusal. */
static const char *fmc_board_refusal(const struct fmc_sub *sub)
{
    if (!sub)
        return "sibling_refused";
    if (sub->reply.error.code[0] &&
        strstr(sub->reply.error.code, "NODE_UNAVAILABLE"))
        return "node_unavailable";
    if (sub->reply.error.code[0] &&
        strstr(sub->reply.error.code, "METHOD_NOT_FOUND"))
        return "node_predates_board_rpc";
    return "sibling_refused";
}

/* Walk open posts into the brief lists, collecting post ids as evidence
 * references. */
static void fmc_board_posts_walk(const struct json_value *posts,
                                 struct json_value *agents,
                                 struct json_value *blockers,
                                 struct json_value *candidates,
                                 struct json_value *post_ids)
{
    size_t n, i;
    if (!posts || posts->type != JSON_ARR)
        return;
    n = json_size(posts);
    for (i = 0; i < n; i++) {
        const struct json_value *post = json_at(posts, i);
        const struct json_value *v;
        const char *id;
        fmc_board_post_lists(post, agents, blockers, candidates);
        if (!post || post->type != JSON_OBJ)
            continue;
        v = json_get(post, "id");
        id = (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
        if (id && id[0])
            (void)fmc_push_distinct(post_ids, id, FMC_LIST_CAP);
    }
}

/* ── brief: board section ────────────────────────────────────────────────
 *
 * Open board posts via node RPC. No node (or an old binary) fails closed
 * inside the sibling; here that becomes a missing[] entry, never an empty
 * board masquerading as good news. */

static void fmc_brief_board(const struct zcl_command_request *req,
                            struct json_value *agents,
                            struct json_value *blockers,
                            struct json_value *candidates,
                            struct json_value *missing,
                            struct json_value *post_ids)
{
    struct fmc_sub sub;
    const struct json_value *posts;
    int64_t t0, t1;
    fmc_sub_begin(&sub, "zcl.fleet_board_list.v1", req, "fleet.board.list");
    if (!sub.valid) {
        fmc_note_missing(missing, "fleet.board", "unknown_sibling", 0);
        fmc_sub_end(&sub);
        return;
    }
    if (!fmc_sub_input(&sub, "{\"open\":true,\"limit\":20}")) {
        fmc_note_missing(missing, "fleet.board", "input_encode", 0);
        fmc_sub_end(&sub);
        return;
    }
    t0 = clock_now_wall_ms();
    zcl_native_handle_fleet_board_list(&sub.request, &sub.reply);
    t1 = clock_now_wall_ms();
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        fmc_note_missing(missing, "fleet.board",
                         fmc_board_refusal(&sub), t1 - t0);
        fmc_sub_end(&sub);
        return;
    }
    posts = json_get(&sub.reply.data, "posts");
    fmc_board_posts_walk(posts, agents, blockers, candidates, post_ids);
    fmc_sub_end(&sub);
}

/* ── brief: ledger section ───────────────────────────────────────────────
 *
 * Chain counts and replica staleness only — row contents never leave the
 * ledger leaf, and they do not leave through this one either. */

static void fmc_brief_ledger(const struct zcl_command_request *req,
                             struct json_value *missing,
                             long long *boxes, long long *rows)
{
    struct fmc_sub sub;
    int64_t t0, t1;
    *boxes = -1;
    *rows = -1;
    fmc_sub_begin(&sub, "zcl.fleet_ledger_status.v1", req, "fleet.ledger.status");
    if (!sub.valid) {
        fmc_note_missing(missing, "fleet.ledger", "unknown_sibling", 0);
        fmc_sub_end(&sub);
        return;
    }
    if (!fmc_sub_input(&sub, "{}")) {
        fmc_note_missing(missing, "fleet.ledger", "input_encode", 0);
        fmc_sub_end(&sub);
        return;
    }
    t0 = clock_now_wall_ms();
    zcl_native_handle_fleet_ledger_status(&sub.request, &sub.reply);
    t1 = clock_now_wall_ms();
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        fmc_note_missing(missing, "fleet.ledger", "sibling_refused",
                         t1 - t0);
        fmc_sub_end(&sub);
        return;
    }
    *boxes = fmc_sub_int(&sub, "boxes", -1);
    *rows = fmc_sub_int(&sub, "rows_loaded", -1);
    fmc_sub_end(&sub);
}

/* Replace a string member in place (json_push_kv appends, so an upgrade
 * must overwrite the existing slot or the old value stays visible). */
static void fmc_replace_str(struct json_value *obj, const char *key,
                            const char *s)
{
    size_t i;
    struct json_value nv;
    if (!obj || obj->type != JSON_OBJ || !key || !s)
        return;
    json_init(&nv);
    json_set_str(&nv, s);
    for (i = 0; i < obj->num_children; i++) {
        if (obj->keys[i] && strcmp(obj->keys[i], key) == 0) {
            json_free(&obj->children[i]);
            obj->children[i] = nv;
            return;
        }
    }
    (void)json_push_kv(obj, key, &nv);
    json_free(&nv);
}

/* Upgrade delivered change rows to completed when a retained queue outcome
 * completes their ref. Single-purpose loop for the complexity gate. */
static void fmc_apply_completed(struct json_value *changes,
                                const struct json_value *outcomes)
{
    size_t n, i;
    if (!changes || changes->type != JSON_ARR)
        return;
    n = json_size(changes);
    for (i = 0; i < n; i++) {
        struct json_value *item = (struct json_value *)json_at(changes, i);
        const struct json_value *v;
        const char *ref, *state;
        if (!item || item->type != JSON_OBJ)
            continue;
        v = json_get(item, "state");
        state = (v && v->type == JSON_STR) ? json_get_str(v) : "";
        if (!state || strcmp(state, "completed") == 0)
            continue;
        v = json_get(item, "ref");
        ref = (v && v->type == JSON_STR) ? json_get_str(v) : "";
        if (ref && ref[0] && fmc_outcome_completes(outcomes, ref))
            fmc_replace_str(item, "state", "completed");
    }
}

/* ── brief entry ───────────────────────────────────────────────────────── */

/* capacity: real numbers only when the queue sibling answered. Otherwise
 * every number is null beside known:false and the reason, because a queue
 * nobody could read is not an idle queue. */
static void fmc_capacity_emit(struct json_value *cap,
                              const struct fmc_queue_view *qv)
{
    char why[96];
    (void)json_push_kv_bool(cap, "known", qv->known);
    if (qv->known && !qv->pool_known) {
        (void)json_push_kv_str(cap, "pool_total", "UNKNOWN");
        (void)json_push_kv_str(cap, "pool_free", "UNKNOWN");
    } else {
        fmc_put_int(cap, "pool_total", qv->known ? qv->pool_total : -1);
        fmc_put_int(cap, "pool_free", qv->known ? qv->pool_free : -1);
    }
    (void)json_push_kv_bool(cap, "pool_known", qv->known && qv->pool_known);
    fmc_put_str(cap, "pool_reason", qv->known ? qv->pool_reason : "");
    fmc_put_int(cap, "queued", qv->known ? qv->queued : -1);
    fmc_put_int(cap, "running", qv->known ? qv->running : -1);
    why[0] = '\0';
    if (!qv->known)
        (void)snprintf(why, sizeof(why), "dev.agent.queue did not answer: %s",
                       qv->reason);
    fmc_put_str(cap, "reason", why);
}

/* Drop the tail of one array member until the data fits the budget.
 * Returns how many entries were dropped. */
static long long fmc_trim_member(struct json_value *data, const char *key)
{
    struct json_value *arr = (struct json_value *)json_get(data, key);
    long long dropped = 0;
    if (!arr || arr->type != JSON_ARR)
        return 0;
    while (arr->num_children > 0 &&
           json_write(data, NULL, 0) > FMC_REPLY_SOFT_BUDGET) {
        json_free(&arr->children[arr->num_children - 1]);
        arr->num_children--;
        dropped++;
    }
    return dropped;
}

/* Hold the reply data under FMC_REPLY_SOFT_BUDGET so the leaf's response
 * budget can never refuse the whole brief: the least essential arrays
 * lose their tail first, and budget_truncated names every array that was
 * cut and by how many entries (empty when nothing was). */
static void fmc_fit_budget(struct json_value *data)
{
    static const char *const order[] = {
        "changes", "workers", "candidates", "work", "agents", "sessions",
        "blockers",
    };
    struct json_value trunc;
    size_t i;
    json_init(&trunc);
    json_set_object(&trunc);
    for (i = 0; i < sizeof(order) / sizeof(order[0]); i++) {
        long long d = fmc_trim_member(data, order[i]);
        if (d > 0)
            (void)json_push_kv_int(&trunc, order[i], d);
    }
    (void)json_push_kv(data, "budget_truncated", &trunc);
    json_free(&trunc);
}

struct fmc_brief_lists {
    struct json_value agents, work, blockers, candidates, changes, missing;
    struct json_value capacity, evidence, post_ids, outcomes;
};

static void fmc_lists_init(struct fmc_brief_lists *l)
{
    struct json_value *arrs[] = {&l->agents,   &l->work,    &l->blockers,
                                 &l->candidates, &l->changes, &l->missing,
                                 &l->post_ids, &l->outcomes};
    size_t i;
    for (i = 0; i < sizeof(arrs) / sizeof(arrs[0]); i++) {
        json_init(arrs[i]);
        json_set_array(arrs[i]);
    }
    json_init(&l->capacity);
    json_set_object(&l->capacity);
    json_init(&l->evidence);
    json_set_object(&l->evidence);
}

static void fmc_lists_free(struct fmc_brief_lists *l)
{
    struct json_value *all[] = {&l->agents,   &l->work,     &l->blockers,
                                &l->candidates, &l->changes, &l->missing,
                                &l->capacity, &l->evidence, &l->post_ids,
                                &l->outcomes};
    size_t i;
    for (i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        json_free(all[i]);
}

static void fmc_brief_evidence(struct fmc_brief_lists *l,
                               const struct fmc_mail_view *mv,
                               long long mail_cursor, long long boxes,
                               long long rows, long long now)
{
    char ts[32];
    (void)json_push_kv_int(&l->evidence, "mail_cursor", mail_cursor);
    (void)json_push_kv_int(&l->evidence, "mail_count", mv->count);
    (void)json_push_kv_int(&l->evidence, "ledger_boxes", boxes);
    (void)json_push_kv_int(&l->evidence, "ledger_rows", rows);
    (void)json_push_kv(&l->evidence, "post_ids", &l->post_ids);
    (void)json_push_kv_int(&l->evidence, "queued_stale_after_s",
                           FMC_QUEUED_STALE_S);
    fmc_now_iso(now, ts, sizeof(ts));
    if (ts[0])
        (void)json_push_kv_str(&l->evidence, "observed_at", ts);
}

static void fmc_brief_reply(struct zcl_command_reply *reply,
                            struct fmc_brief_lists *l,
                            struct fmc_roster *ro,
                            const struct fmc_emit_ctx *ec,
                            long long mail_cursor)
{
    (void)json_push_kv_str(&reply->data, "leaf", FMC_LEAF);
    (void)json_push_kv(&reply->data, "agents", &l->agents);
    fmc_workers_emit(&reply->data, ro, ec);
    fmc_sessions_emit(&reply->data, ro, ec->now);
    (void)json_push_kv(&reply->data, "work", &l->work);
    (void)json_push_kv(&reply->data, "blockers", &l->blockers);
    (void)json_push_kv(&reply->data, "capacity", &l->capacity);
    (void)json_push_kv(&reply->data, "candidates", &l->candidates);
    (void)json_push_kv(&reply->data, "evidence", &l->evidence);
    (void)json_push_kv(&reply->data, "changes", &l->changes);
    (void)json_push_kv(&reply->data, "missing", &l->missing);
    (void)json_push_kv_int(&reply->data, "cursor", mail_cursor);
    fmc_fit_budget(&reply->data);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static void fmc_do_brief(const struct zcl_command_request *req,
                         struct zcl_command_reply *reply)
{
    struct fmc_brief_lists l;
    struct fmc_mail_ctx mc;
    struct fmc_mail_view mv;
    struct fmc_queue_view qv;
    struct fmc_roster ro;
    struct fmc_local lo;
    struct fmc_emit_ctx ec;
    long long mail_cursor, boxes, rows, tmp;
    if (!fmc_roster_init(&ro)) {
        fmc_roster_free(&ro);
        fmc_fail(reply, "STEER_BRIEF_ALLOC", "cannot allocate the worker "
                 "roster", "fleet.steer.brief");
        return;
    }
    fmc_lists_init(&l);
    memset(&mc, 0, sizeof(mc));
    mc.agents = &l.agents;
    mc.work = &l.work;
    mc.changes = &l.changes;
    mc.blockers = &l.blockers;
    mc.ro = &ro;
    mc.changes_cap = FMC_CHANGES_DEFAULT;
    mc.now = (long long)platform_time_wall_unix();
    if (fmc_int(req, "since", &tmp) && tmp >= 0)
        mc.since = tmp;
    if (fmc_int(req, "limit", &tmp) && tmp > 0)
        mc.changes_cap = tmp > FMC_CHANGES_MAX ? FMC_CHANGES_MAX : tmp;
    mail_cursor = fmc_brief_mail(req, &mc, &l.missing, &mv);
    fmc_brief_queue(req, &l.work, &l.candidates, &l.blockers, &l.missing,
                    &qv, &l.outcomes);
    fmc_brief_board(req, &l.agents, &l.blockers, &l.candidates, &l.missing,
                    &l.post_ids);
    fmc_brief_ledger(req, &l.missing, &boxes, &rows);
    fmc_apply_completed(&l.changes, &l.outcomes);
    fmc_capacity_emit(&l.capacity, &qv);
    fmc_brief_evidence(&l, &mv, mail_cursor, boxes, rows, mc.now);
    lo.worker_lock = fmc_lock_state("queue", "worker.lock");
    lo.receive_lock = fmc_lock_state("receive", "receive.lock");
    lo.mail_ok = mv.ok;
    fmc_intake_read(&lo);
    fmc_roster_local(&ro, &qv, &lo);
    ec.now = mc.now;
    ec.ro = &ro;
    ec.outcomes = &l.outcomes;
    ec.qv = &qv;
    ec.lo = &lo;
    fmc_brief_reply(reply, &l, &ro, &ec, mail_cursor);
    fmc_lists_free(&l);
    fmc_roster_free(&ro);
}

/* ── send ────────────────────────────────────────────────────────────────
 *
 * One bounded batch of directives to named agents. Each item carries a
 * caller idempotency key: the first accept posts one mail row and records
 * key->seq; a retry returns the recorded accept with duplicate:true and
 * posts nothing. Per-item outcomes; the batch fails outright only on bad
 * batch input or a bad grant. */

/* ── who this call is ────────────────────────────────────────────────────
 *
 * The sender identity is decided by the credential that carried the
 * request, never by a field inside it. Before 2026-09-17 `from` was taken
 * at its word: one grant could claim any name, and the receiver admitted on
 * that name alone. The two paths now are:
 *
 *   Remote bearer. The sender IS the label the owner minted the grant
 *   under. `from` must be stated and must agree with it, and a
 *   disagreement is REFUSED (STEER_SENDER_MISMATCH) rather than quietly
 *   rewritten: silently correcting the claim would hide an impersonation
 *   attempt in progress, and the caller is entitled to know its claim was
 *   rejected. An omitted `from` is refused too (STEER_SENDER_UNSTATED) and
 *   never defaulted — a default would attribute work to whatever name the
 *   box happens to answer to. A grant minted without a label names no
 *   sender at all and cannot send (STEER_GRANT_UNLABELLED).
 *
 *   Local operator. No `grant` key; dispatch already gated the leaf on
 *   AUTH_OPERATOR. The identity is the operator's own — the name it gave,
 *   or the one dev.agent.mail resolves for this box — and the row carries
 *   no grant binding, because no grant carried the request. A receiver
 *   that requires a binding therefore refuses it: to steer a receiver the
 *   operator mints a grant like every other sender, which is what the
 *   receiver has always required of a named sender anyway.
 *
 * Either way the shape of a caller-supplied name is checked first, so
 * garbage stays BAD_INPUT instead of being reported as an impersonation. */

struct fmc_sender {
    /* The name the row is stamped with. Empty only on the operator path
     * with no name given, where the mail sibling resolves this box's own. */
    char from[FMC_NAME_MAX + 1];
    /* The grant's stamp, or "" on the operator path. */
    char binding[ZCL_FLEET_STEER_BINDING_HEX + 1];
};

/* The name to hand the mail sibling: NULL keeps its own default, which is
 * the operator identity and is reachable only on the operator path. */
static const char *fmc_sender_name(const struct fmc_sender *s)
{
    return s->from[0] ? s->from : NULL;
}

/* Resolve the sender from the credential. NULL admits; otherwise the typed
 * refusal code for the whole batch — an identity is a property of the call,
 * not of one item. */
static const char *fmc_sender_resolve(const struct zcl_command_request *req,
                                      struct fmc_sender *s)
{
    const char *claimed = fmc_str(req, "from");
    const char *grant = fmc_str(req, "grant");
    struct fmc_grant g;
    memset(s, 0, sizeof(*s));
    if (claimed && claimed[0] && !fmc_is_token(claimed, FMC_NAME_MAX, false))
        return "BAD_INPUT";
    if (claimed)
        (void)snprintf(s->from, sizeof(s->from), "%s", claimed);
    if (!grant || !grant[0])
        return NULL; /* the operator, speaking as itself */
    /* fmc_enter already admitted this grant for the send scope; this
     * re-read only asks the store who the holder is. */
    if (fmc_grant_check_row(grant, "send", &g))
        return "STEER_GRANT_UNKNOWN";
    if (!g.label[0])
        return "STEER_GRANT_UNLABELLED";
    if (!s->from[0])
        return "STEER_SENDER_UNSTATED";
    if (strcmp(s->from, g.label) != 0)
        return "STEER_SENDER_MISMATCH";
    (void)snprintf(s->from, sizeof(s->from), "%s", g.label);
    if (!zcl_fleet_steer_sender_binding(g.id, g.label, s->binding,
                                        sizeof(s->binding)))
        return "STEER_SENDER_UNBINDABLE";
    return NULL;
}

/* Encode one mail-post input object. Escaped fields keep caller quotes
 * from breaking the JSON seam; the mail sibling still runs its own
 * refusal scanners. The binding rides the row beside the name so the
 * receiver can check who actually sent it. False when any budget runs
 * out. */
static bool fmc_post_input(char *input, size_t cap, const char *to,
                           const char *body, const char *ref,
                           const struct fmc_sender *s)
{
    char eto[128], ebody[4096], eref[256], efrom[128];
    const char *from = fmc_sender_name(s);
    int n;
    if (!input || cap == 0 || !to || !body)
        return false;
    if (!fmc_escape(to, eto, sizeof(eto)))
        return false;
    if (!fmc_escape(body, ebody, sizeof(ebody)))
        return false;
    if (!fmc_escape(ref ? ref : "", eref, sizeof(eref)))
        return false;
    if (from) {
        if (!fmc_escape(from, efrom, sizeof(efrom)))
            return false;
        n = snprintf(input, cap,
                     "{\"action\":\"post\",\"to\":\"%s\",\"kind\":\"directive\","
                     "\"body\":\"%s\",\"ref\":\"%s\",\"from\":\"%s\","
                     "\"sender_binding\":\"%s\"}",
                     eto, ebody, eref, efrom, s->binding);
    } else {
        n = snprintf(input, cap,
                     "{\"action\":\"post\",\"to\":\"%s\",\"kind\":\"directive\","
                     "\"body\":\"%s\",\"ref\":\"%s\"}",
                     eto, ebody, eref);
    }
    return n > 0 && (size_t)n < cap;
}

/* Post one directive through the mail sibling. Returns the accepted seq,
 * or -1 with `why` (caller buffer) naming the sibling's refusal. The code
 * is copied out before the sub reply is freed: it never points at it. */
static long long fmc_post_directive(const struct zcl_command_request *req,
                                    const char *to, const char *body,
                                    const char *ref,
                                    const struct fmc_sender *s,
                                    char *why, size_t why_cap)
{
    struct fmc_sub sub;
    char input[FMC_INPUT_CAP];
    long long seq;
    if (why && why_cap > 0)
        (void)snprintf(why, why_cap, "sibling_refused");
    if (!fmc_post_input(input, sizeof(input), to, body, ref, s))
        return -1;
    fmc_sub_begin(&sub, "zcl.agent_mail.v1", req, "dev.agent.mail");
    if (!sub.valid) {
        fmc_sub_end(&sub);
        return -1;
    }
    if (!fmc_sub_input(&sub, input)) {
        fmc_sub_end(&sub);
        return -1;
    }
    zcl_native_handle_dev_agent_mail(&sub.request, &sub.reply);
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        if (why && why_cap > 0) {
            if (sub.reply.error.code[0])
                (void)snprintf(why, why_cap, "%s",
                               sub.reply.error.code);
            else
                (void)snprintf(why, why_cap, "sibling_refused");
        }
        fmc_sub_end(&sub);
        return -1;
    }
    seq = fmc_sub_int(&sub, "seq", -1);
    fmc_sub_end(&sub);
    return seq;
}

/* One item's fields with bounds and alphabets checked. The mail sibling
 * re-scans the body for secrets and paths; this gate only bounds shape. */
struct fmc_item_fields {
    const char *to;
    const char *body;
    const char *ref;
    const char *key;
};

static const char *fmc_item_str(const struct json_value *it, const char *k)
{
    const struct json_value *v = json_get(it, k);
    if (!v || v->type != JSON_STR)
        return NULL;
    return json_get_str(v);
}

/* `error` always receives the code the caller should report, so a refusal
 * names which field was wrong instead of collapsing to one opaque code. */
static bool fmc_item_shape_ok(const struct fmc_item_fields *f,
                              const char *from, const char **error)
{
    if (error)
        *error = "BAD_INPUT";
    if (!fmc_is_token(f->to, FMC_NAME_MAX, true))
        return false;
    if (!f->body || !f->body[0] || strlen(f->body) > FMC_BODY_MAX)
        return false;
    if (!fmc_is_token(f->key, FMC_KEY_MAX, false))
        return false;
    /* The ref names the queue row this directive is meant to become, so it
     * must satisfy the queue's own grammar here, before any mail is
     * written. Accepting a ref the queue would refuse used to produce a
     * delivered directive that could never be dispatched — mail describing
     * work with nowhere to go. Refused without normalizing: a ref is what
     * the caller said it was, or it is refused. */
    if (!zcl_devagent_name_ok(f->ref)) {
        if (error)
            *error = "BAD_REF";
        return false;
    }
    if (from && (strlen(from) > FMC_NAME_MAX ||
                 !fmc_is_token(from, FMC_NAME_MAX, false)))
        return false;
    return true;
}

static bool fmc_send_item_fields(const struct json_value *it,
                                 const char *from,
                                 struct fmc_item_fields *f,
                                 const char **error)
{
    const char *ref;
    if (error)
        *error = "BAD_INPUT";
    if (!it || it->type != JSON_OBJ || !f)
        return false;
    f->to = fmc_item_str(it, "to");
    f->body = fmc_item_str(it, "body");
    f->key = fmc_item_str(it, "idempotency_key");
    /* A missing ref stays the empty string and is refused by the grammar:
     * every directive is traceable by the ref it names, and "" names
     * nothing. */
    ref = fmc_item_str(it, "ref");
    f->ref = ref ? ref : "";
    return fmc_item_shape_ok(f, from, error);
}

/* One refused item result. */
static void fmc_send_item_refused(struct json_value *items, size_t index,
                                  const char *to, const char *error)
{
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    (void)json_push_kv_int(&item, "index", (long long)index);
    (void)json_push_kv_str(&item, "state", "refused");
    (void)json_push_kv_str(&item, "error", error ? error : "BAD_INPUT");
    (void)json_push_kv_str(&item, "to", to ? to : "");
    (void)json_push_back(items, &item);
    json_free(&item);
}

/* One accepted item result, after recording key->seq plus the payload
 * digest, the ref, and the grant for reconcile and revoke-cancel. */
static void fmc_send_item_accept(struct json_value *items, size_t index,
                                 const struct fmc_item_fields *f,
                                 long long seq, bool duplicate,
                                 const char *sent_path, const char *from,
                                 const char *grant)
{
    /* `from` here is the resolved sender, never the caller's claim. */
    struct json_value item;
    char sent_line[4096];
    char sum[17];
    char eref[512];
    int n;
    json_init(&item);
    json_set_object(&item);
    (void)json_push_kv_int(&item, "index", (long long)index);
    (void)json_push_kv_str(&item, "to", f->to);
    fmc_payload_sum(f->to, f->body, f->ref, from, sum);
    if (!fmc_escape(f->ref ? f->ref : "", eref, sizeof(eref)))
        eref[0] = '\0';
    n = snprintf(sent_line, sizeof(sent_line),
                 "{\"key\":\"%s\",\"to\":\"%s\",\"seq\":%lld,\"state\":"
                 "\"queued\",\"sum\":\"%s\",\"ref\":\"%s\",\"grant\":\"%s\"}\n",
                 f->key, f->to, seq, sum, eref, grant ? grant : "");
    if (!duplicate && (n <= 0 || (size_t)n >= sizeof(sent_line) ||
                       !fmc_append_line(sent_path, sent_line, (size_t)n))) {
        /* The mail row exists but the receipt did not persist: report the
         * seq honestly and let the caller's retry reconcile by key on a
         * best-effort basis. Never claim a duplicate that is not one. */
        LOG_ERROR(FMC_LOG, "send: sent.jsonl append failed (to=%s seq=%lld)",
                  f->to, seq);
        (void)json_push_kv_str(&item, "state", "queued");
        (void)json_push_kv_int(&item, "seq", seq);
        (void)json_push_kv_bool(&item, "duplicate", false);
        (void)json_push_kv_str(&item, "warning", "SENT_RECORD_LOST");
    } else {
        (void)json_push_kv_str(&item, "state", "queued");
        (void)json_push_kv_int(&item, "seq", seq);
        (void)json_push_kv_bool(&item, "duplicate", duplicate);
    }
    (void)json_push_back(items, &item);
    json_free(&item);
}

/* One send item: validate, reconcile idempotency, post, record. Emits its
 * result object onto items[]. Returns true iff the item's state is an
 * accept (fresh or duplicate), false for every refused state — the
 * caller sums this to report `accepted` honestly. */
static bool fmc_send_item(const struct zcl_command_request *req,
                          const struct json_value *it, size_t index,
                          const struct fmc_sender *s, const char *sent_path,
                          const char *grant, struct json_value *items)
{
    struct fmc_item_fields f;
    long long seq;
    char why[64];
    const char *from = fmc_sender_name(s);
    const char *shape_error = "BAD_INPUT";
    if (!fmc_send_item_fields(it, from, &f, &shape_error)) {
        const char *to =
            (it && it->type == JSON_OBJ) ? fmc_item_str(it, "to") : NULL;
        fmc_send_item_refused(items, index, to, shape_error);
        return false;
    }
    /* Reconcile: same key AND same payload returns the recorded accept
     * with no second row. A different payload under a recorded key is
     * refused: the key names one exact delivery. A row without a digest
     * predates digests and is unverifiable, never a match.
     *
     * Every sender reaching this point has already been bound to its
     * credential by fmc_sender_resolve(), which runs once for the whole
     * batch before any of this. That order is deliberate: reconcile
     * answers with somebody else's recorded row, so a second party
     * presenting the same key under a different claimed name must be
     * refused BEFORE it is consulted, or the reconcile path becomes the
     * bypass the binding closed. */
    {
        char recorded[17], presented[17];
        if (fmc_sent_find(sent_path, f.key, &seq, recorded)) {
            fmc_payload_sum(f.to, f.body, f.ref, from, presented);
            if (recorded[0] && strcmp(recorded, presented) == 0) {
                fmc_send_item_accept(items, index, &f, seq, true, sent_path,
                                     from, grant);
                return true;
            }
            LOG_ERROR(FMC_LOG,
                      "send: payload conflict under key (to=%s seq=%lld)",
                      f.to, seq);
            fmc_send_item_refused(items, index, f.to,
                                  "IDEMPOTENCY_CONFLICT");
            return false;
        }
    }
    why[0] = '\0';
    seq = fmc_post_directive(req, f.to, f.body, f.ref, s, why, sizeof(why));
    if (seq < 0) {
        fmc_send_item_refused(items, index, f.to,
                              why[0] ? why : "POST_FAILED");
        return false;
    }
    fmc_send_item_accept(items, index, &f, seq, false, sent_path, from,
                         grant);
    return true;
}

static void fmc_do_send(const struct zcl_command_request *req,
                        struct zcl_command_reply *reply)
{
    const struct json_value *v;
    const struct json_value *arr;
    const char *refused;
    const char *grant;
    struct fmc_sender sender;
    char steerdir[4096], sent_path[4096 + 32];
    struct json_value items;
    size_t n, i;
    int n2;
    v = json_get(req->input, "items");
    if (!v || v->type != JSON_ARR) {
        fmc_fail(reply, "BAD_INPUT", "send needs items[]",
                 "missing items array");
        return;
    }
    arr = v;
    n = json_size(arr);
    if (n == 0 || n > FMC_SEND_MAX) {
        fmc_fail(reply, "BAD_INPUT", "send takes 1..8 items",
                 "batch bound");
        return;
    }
    /* Identity first, before a single item is read: it decides who this
     * call is, and every per-item answer below — including the recorded
     * accept a reconcile would return — is attributed to the name it
     * resolves. */
    refused = fmc_sender_resolve(req, &sender);
    if (refused) {
        fmc_fail(reply, refused,
                 "the sender is the grant's own label, stated and matching",
                 "input.from against the presented grant");
        return;
    }
    grant = fmc_str(req, "grant");
    if (!fmc_dirs(steerdir, sizeof(steerdir))) {
        fmc_fail(reply, "STATE_DIR_FAILED",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    n2 = snprintf(sent_path, sizeof(sent_path), "%s/sent.jsonl", steerdir);
    if (n2 <= 0 || (size_t)n2 >= sizeof(sent_path)) {
        fmc_fail(reply, "STATE_DIR_FAILED", "sent path exceeds its bound",
                 steerdir);
        return;
    }
    {
        long long accepted = 0;
        json_init(&items);
        json_set_array(&items);
        for (i = 0; i < n; i++) {
            if (fmc_send_item(req, json_at(arr, i), i, &sender, sent_path,
                              grant, &items))
                accepted++;
        }
        (void)json_push_kv_str(&reply->data, "leaf", FMC_LEAF);
        (void)json_push_kv(&reply->data, "items", &items);
        /* `accepted` counts only items whose result state is not
         * "refused" (a reconciled duplicate counts: it is the recorded
         * accept, not a new one) — never the item-result count, which a
         * remote client would otherwise mistake for delivery. */
        (void)json_push_kv_int(&reply->data, "accepted", accepted);
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
    json_free(&items);
}

/* ── evidence ────────────────────────────────────────────────────────────
 *
 * One bounded object by exact reference, never a log: a mail row with
 * ref==ref, a queue row/outcome with name==ref, or one board post by id. */

/* Lifecycle state for one mail row, resolved by exactly the rule the
 * brief's changes[] uses (fmc_row_state), so the two never disagree about
 * the same row: a row this host sent through steer reads "queued" until
 * the recipient replies under the same ref or the local ack cursor covers
 * it, and is never called "delivered" from the sender's own outbox; any
 * other row reads "delivered", or "acknowledged" on the cursor.
 * `ack_cursor` still reports the receiver cursor itself so the caller can
 * check the promotion, and an unparseable row reports the earliest state
 * rather than guessing. `rows` is the pull this lookup already holds. */
static void fmc_evidence_mail_ack(struct zcl_command_reply *reply,
                                  const struct json_value *r,
                                  const struct json_value *rows)
{
    struct fmc_row v;
    char sent_path[4096 + 32];
    if (!fmc_row_parse(r, &v)) {
        (void)json_push_kv_int(&reply->data, "ack_cursor", -1);
        (void)json_push_kv_str(&reply->data, "state", "queued");
        return;
    }
    if (!fmc_sent_path_read(sent_path, sizeof(sent_path)))
        sent_path[0] = '\0';
    (void)json_push_kv_int(&reply->data, "ack_cursor", fmc_ack_cursor(v.to));
    (void)json_push_kv_str(&reply->data, "state",
                           fmc_row_state(&v, rows, sent_path));
}

/* Copy one whole JSON value onto the reply under "object". The sources are
 * already bounded by their own leaves (mail bodies <= 4KiB, one post). */
static void fmc_emit_object(struct zcl_command_reply *reply,
                            const char *type, const struct json_value *obj)
{
    (void)json_push_kv_str(&reply->data, "leaf", FMC_LEAF);
    (void)json_push_kv_str(&reply->data, "type", type);
    (void)json_push_kv(&reply->data, "object", obj);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static void fmc_evidence_mail(const struct zcl_command_request *req,
                              struct zcl_command_reply *reply,
                              const char *ref)
{
    struct json_value rows;
    const struct json_value *hit = NULL;
    long long cursor = -1;
    const char *why;
    size_t n, i;
    json_init(&rows);
    json_set_array(&rows);
    why = fmc_mail_drain(req, &rows, &cursor);
    if (why) {
        fmc_fail(reply, "EVIDENCE_UNAVAILABLE",
                 strcmp(why, "unknown_sibling") == 0
                     ? "the mail sibling is unknown"
                     : "the mail store did not answer",
                 "dev.agent.mail");
        json_free(&rows);
        return;
    }
    /* A ref may own a thread (directive, then worker result rows). The
     * latest entry is the exact result, matching the queue rule that the
     * last terminal outcome wins; single-row threads read unchanged. */
    n = json_size(&rows);
    for (i = 0; i < n; i++) {
        const struct json_value *r = json_at(&rows, i);
        const struct json_value *v;
        const char *rref;
        if (!r || r->type != JSON_OBJ)
            continue;
        v = json_get(r, "ref");
        rref = (v && v->type == JSON_STR) ? json_get_str(v) : "";
        if (rref && strcmp(rref, ref) == 0)
            hit = r;
    }
    if (hit) {
        fmc_emit_object(reply, "mail", hit);
        fmc_evidence_mail_ack(reply, hit, &rows);
        json_free(&rows);
        return;
    }
    fmc_fail(reply, "EVIDENCE_NOT_FOUND", "no mail row carries that ref",
             ref);
    json_free(&rows);
}

/* One queue row by name: terminal-section matches overwrite *term so the
 * last retained outcome wins; live rows set *live once. */
static void fmc_evidence_queue_row(const struct json_value *r,
                                   const char *ref, bool terminal,
                                   const struct json_value **live,
                                   const struct json_value **term)
{
    const struct json_value *v;
    const char *name;
    if (!r || r->type != JSON_OBJ)
        return;
    v = json_get(r, "name");
    name = (v && v->type == JSON_STR) ? json_get_str(v) : "";
    if (!name || strcmp(name, ref) != 0)
        return;
    if (terminal)
        *term = r;
    else if (!*live)
        *live = r;
}

static void fmc_evidence_queue(const struct zcl_command_request *req,
                               struct zcl_command_reply *reply,
                               const char *ref)
{
    struct fmc_sub sub;
    static const char *const sections[] = {"queued", "running", "outcomes"};
    const struct json_value *live = NULL, *term = NULL;
    size_t s;
    fmc_sub_begin(&sub, "zcl.agent_queue.v1", req, "dev.agent.queue");
    if (!sub.valid) {
        fmc_fail(reply, "EVIDENCE_UNAVAILABLE", "the queue sibling is unknown", "dev.agent.queue");
        fmc_sub_end(&sub);
        return;
    }
    if (!fmc_sub_input(&sub, "{\"action\":\"status\",\"json\":true}")) {
        fmc_fail(reply, "BAD_INPUT", "cannot encode the queue lookup",
                 "input_encode");
        fmc_sub_end(&sub);
        return;
    }
    zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        fmc_fail(reply, "EVIDENCE_UNAVAILABLE",
                 "the queue did not answer", "dev.agent.queue");
        fmc_sub_end(&sub);
        return;
    }
    /* A ref may own several rows across attempts (resume re-posts the
     * same name). The latest terminal outcome is the exact result; a
     * live queued or running row carries no result yet, so terminal
     * history wins and, within it, the last retained row wins. */
    for (s = 0; s < sizeof(sections) / sizeof(sections[0]); s++) {
        const struct json_value *arr = json_get(&sub.reply.data,
                                                sections[s]);
        size_t n, i;
        if (!arr || arr->type != JSON_ARR)
            continue;
        n = json_size(arr);
        for (i = 0; i < n; i++)
            fmc_evidence_queue_row(json_at(arr, i), ref,
                                   s == sizeof(sections) /
                                   sizeof(sections[0]) - 1, &live, &term);
    }
    if (term) {
        fmc_emit_object(reply, "queue", term);
        fmc_sub_end(&sub);
        return;
    }
    if (live) {
        fmc_emit_object(reply, "queue", live);
        fmc_sub_end(&sub);
        return;
    }
    fmc_fail(reply, "EVIDENCE_NOT_FOUND",
             "no queue row or outcome carries that name", ref);
    fmc_sub_end(&sub);
}

static void fmc_evidence_board(const struct zcl_command_request *req,
                               struct zcl_command_reply *reply,
                               const char *ref)
{
    struct fmc_sub sub;
    char input[512];
    char eref[256];
    int n;
    const struct json_value *post;
    if (!fmc_escape(ref, eref, sizeof(eref))) {
        fmc_fail(reply, "BAD_INPUT", "ref too large to encode",
                 "escape budget");
        return;
    }
    n = snprintf(input, sizeof(input), "{\"id\":\"%s\"}", eref);
    if (n <= 0 || (size_t)n >= sizeof(input)) {
        fmc_fail(reply, "BAD_INPUT", "ref too large to encode",
                 "input bound");
        return;
    }
    fmc_sub_begin(&sub, "zcl.fleet_board_post.v1", req, "fleet.board.show");
    if (!sub.valid) {
        fmc_fail(reply, "EVIDENCE_UNAVAILABLE", "the board sibling is unknown", "fleet.board.show");
        fmc_sub_end(&sub);
        return;
    }
    if (!fmc_sub_input(&sub, input)) {
        fmc_fail(reply, "BAD_INPUT", "cannot encode the board lookup",
                 "input_encode");
        fmc_sub_end(&sub);
        return;
    }
    zcl_native_handle_fleet_board_show(&sub.request, &sub.reply);
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        if (sub.reply.error.code[0] &&
            strstr(sub.reply.error.code, "NODE_UNAVAILABLE"))
            fmc_fail(reply, "EVIDENCE_UNAVAILABLE",
                     "no local node answered the board call",
                     "fleet.board.show");
        else
            fmc_fail(reply, "EVIDENCE_NOT_FOUND",
                     "this node holds no post with that id",
                     "fleet.board.show");
        fmc_sub_end(&sub);
        return;
    }
    post = json_get(&sub.reply.data, "post");
    if (!post || post->type != JSON_OBJ)
        post = &sub.reply.data;
    fmc_emit_object(reply, "board", post);
    fmc_sub_end(&sub);
}

static void fmc_do_evidence(const struct zcl_command_request *req,
                            struct zcl_command_reply *reply)
{
    const char *type;
    const char *ref;
    type = fmc_str(req, "type");
    ref = fmc_str(req, "ref");
    if (!type || !ref || !ref[0] || strlen(ref) > FMC_REF_MAX) {
        fmc_fail(reply, "BAD_INPUT", "evidence needs type and ref",
                 "type in {mail,queue,board}, ref exact");
        return;
    }
    if (strcmp(type, "mail") == 0)
        fmc_evidence_mail(req, reply, ref);
    else if (strcmp(type, "queue") == 0)
        fmc_evidence_queue(req, reply, ref);
    else if (strcmp(type, "board") == 0)
        fmc_evidence_board(req, reply, ref);
    else
        fmc_fail(reply, "BAD_INPUT", "unknown evidence type",
                 "type in {mail,queue,board}");
}

/* ── grants ──────────────────────────────────────────────────────────────
 *
 * Mint and revoke the adapter's own bearer grants. Mint draws 128 CSPRNG
 * bits per id and appends one row; revoke appends a superseding revoked
 * row (the store is append-only; the last row for an id wins). The id is
 * returned exactly once at mint and never echoed by any other verb. */

/* One closed-vocabulary scope word. Table-driven so adding a verb cannot
 * widen the set by accident. */
static bool fmc_scope_word_ok(const char *word, size_t len)
{
    static const char *const names[] = {"brief", "send", "evidence"};
    size_t i;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (strlen(names[i]) == len && strncmp(names[i], word, len) == 0)
            return true;
    }
    return false;
}

static bool fmc_scopes_valid(const char *scopes)
{
    const char *p;
    if (!scopes || !scopes[0] || strlen(scopes) >= 64)
        return false;
    for (p = scopes; *p;) {
        const char *w;
        size_t len = 0;
        while (*p == ',' || *p == ' ')
            p++;
        if (*p == '\0')
            break;
        w = p;
        while (*p && *p != ',' && *p != ' ') {
            p++;
            len++;
        }
        if (len == 0 || !fmc_scope_word_ok(w, len))
            return false;
    }
    return true;
}

/* Mint inputs with bounds checked. Fills scopes/label/ttl; fails the
 * reply on the first bad field. */
struct fmc_mint_in {
    const char *scopes;
    const char *label;
    long long ttl;
};

static bool fmc_grant_inputs(const struct zcl_command_request *req,
                             struct zcl_command_reply *reply,
                             struct fmc_mint_in *in)
{
    long long tmp;
    in->scopes = fmc_str(req, "scopes");
    if (!in->scopes || !fmc_scopes_valid(in->scopes)) {
        fmc_fail(reply, "BAD_INPUT",
                 "scopes is a subset of brief,send,evidence",
                 "closed scope vocabulary");
        return false;
    }
    in->ttl = 0;
    if (fmc_int(req, "ttl_seconds", &tmp)) {
        if (tmp < 0 || tmp > FMC_GRANT_TTL_MAX) {
            fmc_fail(reply, "BAD_INPUT", "ttl_seconds is 0..2592000",
                     "grant lifetime bound");
            return false;
        }
        in->ttl = tmp;
    }
    in->label = fmc_str(req, "label");
    if (in->label && (strlen(in->label) > FMC_NAME_MAX ||
                      !fmc_is_token(in->label, FMC_NAME_MAX, false))) {
        fmc_fail(reply, "BAD_INPUT", "label is a short token",
                 "label bound");
        return false;
    }
    return true;
}

static void fmc_grant_mint(const struct zcl_command_request *req,
                           struct zcl_command_reply *reply)
{
    struct fmc_mint_in in;
    time_t now;
    long long expires;
    uint8_t raw[16];
    char id[33];
    char steerdir[4096], path[4096 + 32];
    char line[512];
    int n;
    if (!fmc_grant_inputs(req, reply, &in))
        return;
    if (!zcl_random_secret_bytes(raw, sizeof(raw), "fleet.steer.grant")) {
        fmc_fail(reply, "GRANT_MINT_FAILED",
                 "the CSPRNG did not yield grant material",
                 "zcl_random_secret_bytes");
        return;
    }
    zcl_hex_encode(raw, sizeof(raw), id);
    if (!fmc_dirs(steerdir, sizeof(steerdir))) {
        fmc_fail(reply, "STATE_DIR_FAILED",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    n = snprintf(path, sizeof(path), "%s/grants.jsonl", steerdir);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        fmc_fail(reply, "STATE_DIR_FAILED", "grant path exceeds its bound",
                 steerdir);
        return;
    }
    now = platform_time_wall_time_t();
    expires = in.ttl == 0 ? 0 : (long long)now + in.ttl;
    n = snprintf(line, sizeof(line),
                 "{\"id\":\"%s\",\"scopes\":\"%s\",\"created\":%lld,"
                 "\"expires\":%lld,\"revoked\":\"0\",\"label\":\"%s\"}\n",
                 id, in.scopes, (long long)now, expires,
                 in.label ? in.label : "");
    if (n <= 0 || (size_t)n >= sizeof(line)) {
        fmc_fail(reply, "GRANT_MINT_FAILED", "grant row exceeds its bound",
                 "row budget");
        return;
    }
    if (!fmc_append_line(path, line, (size_t)n)) {
        fmc_fail(reply, "GRANT_MINT_FAILED",
                 "cannot append the owner-private grant store", path);
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", FMC_GRANT_LEAF);
    (void)json_push_kv_str(&reply->data, "id", id);
    (void)json_push_kv_str(&reply->data, "scopes", in.scopes);
    (void)json_push_kv_int(&reply->data, "expires", expires);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* True when ref already sits in the collected set. */
static bool fmc_ref_seen(char refs[][FMC_REF_MAX + 1], size_t nrefs,
                         const char *ref)
{
    size_t i;
    for (i = 0; i < nrefs; i++) {
        if (strcmp(refs[i], ref) == 0)
            return true;
    }
    return false;
}

/* Collect the distinct non-empty refs sent under one grant. Old rows
 * without a grant never match; rows without a ref carry nothing to
 * cancel. Returns the ref count (0 when the store is absent). */
static size_t fmc_revoke_refs(const char *sent_path, const char *grant_id,
                              char refs[][FMC_REF_MAX + 1], size_t cap)
{
    FILE *f;
    char line[FMC_LINE_CAP];
    char grant[64], ref[FMC_REF_MAX + 1];
    size_t nrefs = 0;
    if (!sent_path || !grant_id || !refs || cap == 0)
        return 0;
    f = fopen(sent_path, "rb");
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f)) {
        if (!fmc_grant_line_str(line, "grant", grant, sizeof(grant)))
            continue;
        if (strcmp(grant, grant_id) != 0)
            continue;
        if (!fmc_grant_line_str(line, "ref", ref, sizeof(ref)))
            continue;
        if (fmc_ref_seen(refs, nrefs, ref))
            continue;
        if (nrefs >= cap)
            break;
        (void)snprintf(refs[nrefs], sizeof(refs[nrefs]), "%s", ref);
        nrefs++;
    }
    (void)fclose(f);
    return nrefs;
}

/* Cancel one queue row by ref through the queue sibling. Returns 1 when
 * a queued row dropped, 0 when there was nothing queued to stop
 * (not-found, running, or a sibling refusal). Running rows belong to
 * their worker; completed history is never rewritten. */
static long long fmc_revoke_cancel_one(const struct zcl_command_request *req,
                                       const char *ref)
{
    struct fmc_sub sub;
    char input[512];
    const struct json_value *v;
    long long cancelled = 0;
    int n;
    n = snprintf(input, sizeof(input),
                 "{\"action\":\"cancel\",\"name\":\"%s\"}", ref);
    if (n <= 0 || (size_t)n >= sizeof(input))
        return 0;
    fmc_sub_begin(&sub, "zcl.agent_queue.v1", req, "dev.agent.queue");
    if (!sub.valid) {
        fmc_sub_end(&sub);
        return 0;
    }
    if (!fmc_sub_input(&sub, input)) {
        fmc_sub_end(&sub);
        return 0;
    }
    zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
    sub.ran = true;
    if (fmc_sub_ok(&sub)) {
        v = json_get(&sub.reply.data, "cancelled");
        if (v && v->type == JSON_INT)
            cancelled = (long long)json_get_int(v);
    } else if (sub.reply.error.code[0] &&
               strcmp(sub.reply.error.code, "CANCEL_RUNNING") != 0 &&
               strcmp(sub.reply.error.code, "CANCEL_NOT_FOUND") != 0) {
        LOG_ERROR(FMC_LOG, "revoke: queue cancel refused (ref=%s code=%s)",
                  ref, sub.reply.error.code);
    }
    fmc_sub_end(&sub);
    return cancelled > 0 ? 1 : 0;
}

/* Best-effort revoke-cancel: drop every queued queue row whose ref was
 * sent under the revoked grant. Returns rows dropped. */
static long long fmc_revoke_cancel_queued(
    const struct zcl_command_request *req, const char *sent_path,
    const char *grant_id)
{
    char refs[64][FMC_REF_MAX + 1];
    size_t nrefs, i;
    long long cancelled = 0;
    nrefs = fmc_revoke_refs(sent_path, grant_id, refs, 64);
    for (i = 0; i < nrefs; i++)
        cancelled += fmc_revoke_cancel_one(req, refs[i]);
    return cancelled;
}

static void fmc_grant_revoke(const struct zcl_command_request *req,
                             struct zcl_command_reply *reply)
{
    const char *id;
    char steerdir[4096], path[4096 + 32];
    struct fmc_grant g;
    char line[512];
    time_t now;
    int n, m;
    id = fmc_str(req, "id");
    if (!id || strlen(id) != 32) {
        fmc_fail(reply, "BAD_INPUT", "revoke needs the 32-hex grant id",
                 "id bound");
        return;
    }
    if (!fmc_dirs(steerdir, sizeof(steerdir))) {
        fmc_fail(reply, "STATE_DIR_FAILED",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    n = snprintf(path, sizeof(path), "%s/grants.jsonl", steerdir);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        fmc_fail(reply, "STATE_DIR_FAILED", "grant path exceeds its bound",
                 steerdir);
        return;
    }
    /* Revoking an unknown id is refused, not silently accepted: the caller
     * must know which credential they just killed. */
    if (!fmc_grant_find(path, id, &g)) {
        fmc_fail(reply, "STEER_GRANT_UNKNOWN", "no grant carries that id",
                 "revoke exact id");
        return;
    }
    now = platform_time_wall_time_t();
    /* The superseding row keeps the ORIGINAL label. Overwriting it made a
     * revoked grant unfindable by name, so a label lookup reported the
     * credential as unknown instead of revoked — fail-closed either way,
     * but the caller could not tell "never granted" from "taken away". */
    m = snprintf(line, sizeof(line),
                 "{\"id\":\"%s\",\"scopes\":\"%s\",\"created\":%lld,"
                 "\"expires\":%lld,\"revoked\":\"1\",\"label\":\"%s\"}\n",
                 id, g.scopes, (long long)now, g.expires, g.label);
    if (m <= 0 || (size_t)m >= sizeof(line)) {
        fmc_fail(reply, "GRANT_MINT_FAILED", "grant row exceeds its bound",
                 "row budget");
        return;
    }
    if (!fmc_append_line(path, line, (size_t)m)) {
        fmc_fail(reply, "GRANT_MINT_FAILED",
                 "cannot append the owner-private grant store", path);
        return;
    }
    /* The credential is dead from this append onward. Best-effort cancel
     * the queued work it sent: queued rows drop so later stages have
     * nothing to claim; running rows refuse here and stay the worker's
     * own explicit-authority business; completed history is untouched. */
    {
        char sent_path[4096 + 32];
        long long cancelled = 0;
        int s;
        s = snprintf(sent_path, sizeof(sent_path), "%s/sent.jsonl",
                     steerdir);
        if (s > 0 && (size_t)s < sizeof(sent_path))
            cancelled = fmc_revoke_cancel_queued(req, sent_path, id);
        (void)json_push_kv_str(&reply->data, "leaf", FMC_GRANT_LEAF);
        (void)json_push_kv_str(&reply->data, "id", id);
        (void)json_push_kv_bool(&reply->data, "revoked", true);
        (void)json_push_kv_int(&reply->data, "cancelled", cancelled);
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* ── public entry points ─────────────────────────────────────────────────
 *
 * One thin wrapper per leaf: check the verb's grant scope, then run. The
 * grant key is optional; without one the call is the local operator's own,
 * which dispatch already authorized per leaf. */

static void fmc_enter(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply, const char *scope,
                      const char *need,
                      void (*run)(const struct zcl_command_request *,
                                  struct zcl_command_reply *))
{
    const char *grant;
    const char *refused;
    if (!request || !request->input) {
        fmc_fail(reply, "BAD_INPUT", need, "request.input was missing");
        return;
    }
    grant = fmc_str(request, "grant");
    refused = fmc_grant_check(grant, scope);
    if (refused) {
        fmc_fail(reply, refused, "the grant does not allow this verb",
                 "grant scope/expiry/revocation");
        return;
    }
    run(request, reply);
}

void zcl_native_handle_fleet_steer_brief(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    fmc_enter(request, reply, "brief", "fleet.steer.brief takes grant,since,limit",
              fmc_do_brief);
}

void zcl_native_handle_fleet_steer_send(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    fmc_enter(request, reply, "send", "fleet.steer.send takes grant,items,from",
              fmc_do_send);
}

void zcl_native_handle_fleet_steer_evidence(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    fmc_enter(request, reply, "evidence",
              "fleet.steer.evidence takes grant,type,ref", fmc_do_evidence);
}

void zcl_native_handle_fleet_steer_grant(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *action;
    if (!request || !request->input) {
        fmc_fail(reply, "BAD_INPUT", "fleet.steer.grant needs action",
                 "request.input was missing");
        return;
    }
    action = fmc_str(request, "action");
    if (!action) {
        fmc_fail(reply, "BAD_INPUT",
                 "fleet.steer.grant needs action mint|revoke",
                 "missing action");
        return;
    }
    if (strcmp(action, "mint") == 0)
        fmc_grant_mint(request, reply);
    else if (strcmp(action, "revoke") == 0)
        fmc_grant_revoke(request, reply);
    else
        fmc_fail(reply, "BAD_INPUT", "unknown action (mint|revoke)",
                 "action");
}
