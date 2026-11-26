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
 * STATES. queued, read, acknowledged, completed — four different facts.
 * Absence of evidence stays at the earlier state. On a mail pass that was
 * cut the absence itself is not known, and a directive that would read
 * queued or recipient_gone by that absence reads "unresolved" instead
 * (MAIL WINDOW, below). "read" is only the
 * receiver's mail/read.<to> file covering the row. It is not an
 * acknowledgement and it is not execution. "completed" stays a retained
 * queue outcome with an explicit pass verdict and rc 0.
 *
 * The sender's own outbox is ALWAYS inside the sender's own pull, so
 * "visible in pull" is no evidence at all that a directive this host sent
 * ever left this machine. So the rule splits on who wrote the row:
 *   - A row THIS host sent through steer — its seq and recipient are
 *     recorded in <state>/steer/sent.jsonl — is "queued" until there is
 *     RECEIVER evidence, and never "delivered". "acknowledged" is either
 *     (a) a mail row whose `from` is the sent row's `to` carrying the SAME
 *     ref (any other party when `to` is `*`), which is what a transport
 *     brings back, or (b) <state>/mail/cursor.<to> covering the row. A
 *     scalar cursor covers seq <= floor. A next_since token also covers
 *     when its stream offset is at or past that row's end, even if the
 *     token's integer floor is 0. mail/alias.<stale> is one live label,
 *     followed once, and only when that recipient has neither a read nor
 *     a cursor file. An alias copies nothing and grants no send authority.
 *     Named replies still have to be later, address the sender, and agree
 *     on attempt; the sender cannot forge that by posting.
 *   - Every other row — an inbound row a transport delivered here, an
 *     ordinary local post — reads as before: "delivered", because it
 *     really is visible where its reader reads, and "acknowledged" once
 *     the ack cursor covers it. A reply does not promote an inbound row,
 *     and an inbound row is never "read".
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
 * addressed back to the origin by anyone but the origin), else closed (a
 * later `note` or `result` under the same ref from the origin itself, or
 * from an owner name, whose body starts with "closed by sender:"; the
 * words after it name superseded, recipient gone, withdrawn or other),
 * else ambiguous, else recipient_gone (a worker directive with no ack,
 * typed read or read file covering it, whose recipient has posted a
 * presence-<name> session note here, including one within a window of
 * bytes before a cut stream's start, and whose newest row, presence or
 * mail, is older than FMC_RECIPIENT_GONE_S, 24 h; a name with no presence
 * row is never gone, it stays open), else acked (the
 * receiver's ack cursor covers the row, including a string next_since
 * token; a reply is never an ack and a read file is never an ack), else
 * queued; with
 * the directive's own sent_ts/sent_age_s apart from answer_ts/answer_age_s.
 * A closure is a new row and rewrites nothing; a real answer still wins
 * over it. `class` sorts every directive: broadcast (to `*`), owner (to a
 * name in ZCL_FLEET_OWNER_NAMES, comma-separated, default the host $USER), else
 * worker. An answered, closed, recipient_gone or unresolved directive, a
 * broadcast and an owner-addressed row are never "no receiver evidence"
 * blockers (unresolved exists only on a cut pass).
 *
 * DIRECTIVE BACKLOG. Over the newest FMC_DIRECTIVE_SCAN (64) directives,
 * open_worker_directives counts worker directives that are not answered,
 * closed or recipient_gone; overdue_worker_directives counts the open ones
 * this host sent that have no receiver evidence (no ack, read or reply)
 * after FMC_QUEUED_STALE_S, exactly the stale blockers. No deadline is
 * invented. directive_queue[] groups the open ones by recipient (count,
 * oldest age), at most FMC_DQ_CAP (16) recipients; directive_counts holds
 * the other classes and the definition the output states.
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
 *   idle     evidence newer than FMC_WORKER_ALIVE_WINDOW_S and nothing open;
 *   unknown  everything else,
 * always with a reason. A lock held or a name seen is liveness at most,
 * never work. A receive.lock file that exists and is not held means the
 * resident receiver has stopped: the brief names that as the blocker
 * "local receiver down: receive.lock free" and does not change any worker
 * that still holds worker.lock (that worker stays idle or working).
 * Unknown numbers are JSON null, never 0: capacity reports
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
 * state is presence freshness: live within FMC_SESSION_ALIVE_WINDOW_S of that row's ts, stale past it
 * (with age_s), and UNKNOWN when no row exists; a missing or refused
 * field is the string "UNKNOWN". Linked workers are named, never copied;
 * `muse_spend` sums the workers' receipt tokens, and reservations stay
 * UNKNOWN because no existing source records them. No body text reaches
 * the brief except through the parsed, credential-screened whitelist.
 *
 * STATE. <platform_state_root()>/steer (0700): grants.jsonl, sent.jsonl.
 * PEER GRANTS. A grant minted with peer=<roster name> is an ADMISSION
 * record, not a bearer: it lets dev.agent.receive admit a directive that
 * came over the signed fleet board from that enrolled box under that label
 * (zcl_fleet_steer_grant_peer_live), and nothing else. It is never
 * accepted as a `grant` on any steer verb (STEER_GRANT_PEER_ONLY), and it
 * never admits a row by sender binding: an unsigned row cannot borrow a
 * peer grant, and a board row cannot borrow a local one.
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
 * MAIL WINDOW. Every brief that is not compact makes one pass over mail,
 * for agents, work, candidates, workers (a worker is known only by a
 * receiver= or worker= row), sessions and the directive tallies, and for
 * the rows a change's state resolves against. That pass starts each stream
 * at its newest ZCL_DEVAGENT_MAIL_WINDOW_BYTES of whole rows and never
 * past a position the caller's own `since` token names. The pages it
 * follows are that window's, not the history's; the leaf still lists
 * every stream to place the start, and the last page replays through the
 * public pull, which reads every stream once more for its newest seq (the
 * scan that keeps cursor exact).
 * When older rows were left unread, evidence.mail_window_cut is true, and
 * once the pass read the first row of every cut stream,
 * evidence.mail_window_reach_ts is the newest stamp any cut stream began
 * at. The first key is present only when rows were cut and the pass
 * succeeded; the second only when it is known. With the keys absent,
 * either the whole history was read, the pass failed (missing[] names
 * dev.agent.mail) or the brief is compact. Every list above then means
 * "seen back to that stamp", never "ever": a directive whose row stands
 * before it is not tallied, a worker whose last row stands before it is
 * not listed, candidates_total is unknown (candidates_complete false, and
 * missing[] names candidates.mail), tokens_total_exact is false,
 * workers_total_exact is false, a remote worker's tokens_total sums only
 * the receipts inside the window (a floor with no flag of its own), and
 * a session whose presence note is outside the window reads UNKNOWN with
 * a reason that says the pass was cut.
 * What such a pass fails to find for a row it did read is not evidence.
 * A directive, whoever sent it, stamped at or before the reach, that
 * would read "queued" or "recipient_gone" from that absence reads
 * "unresolved" instead: what would show it received or answered, or the
 * recipient gone, may stand in the rows not read. A directive reads so in
 * reply.state too, is counted in directive_counts.unresolved (present
 * only when nonzero), is in neither open number, is never a stale
 * blocker, and carries a next_action naming the exact read by ref. An
 * unknown reach reads every such row that way. A presence note within
 * one window before a cut stream's start is kept for that verdict only,
 * so a directive stamped after the reach can still read recipient_gone.
 * The note is not a row the pass counts, and a worker who never posted
 * one stays open. A stream appended out of stamp order can still read
 * queued where the truth is answered. That errs towards alarm.
 * changes stay exact for a token-resumed brief: they are the rows after
 * its token, in order and under the changes cap as before, each resolved
 * against the rows this pass read. A brief without a token shows the
 * newest rows of the window.
 * A window the leaf cannot hand out, or a cut start that fails, is the
 * walk from the start as before (the cut start's reason is logged), so
 * history past FMC_MAIL_PAGES_MAX pages without a window is still an
 * explicit failure.
 *
 * TASKS. tasks[] is an additive, bounded LOCAL snapshot over agent queue
 * and landing status; it never joins names to canonical work. Exact seq +
 * attempt + ref detail selectors cannot select old-attempt queue outcomes.
 * A fresh observation and a live exact consumer are required for executing;
 * resident_proof_request_queued stays queued despite proof status running.
 * Receipt admission, independent review and remote publication stay separate.
 * tasks_inventory_complete is always false: canonical and remote inventories
 * are not enumerated; queue parsing and recent landing history are bounded.
 * Observation age describes this status read, never the age of a receipt or
 * source row. source_ts/attempt_age_s remain separate, nullable provenance.
 *
 * PROCESS RULE. No spawn, no shell, no popen()/system(), no sleep, no poll
 * loop. Only in-process sibling calls and local filesystem operations.
 */

#include "command/native_command.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "command/native_devagent.h"
#include "command/native_fleet.h"
#include "session/fleet_wiki_entry.h"
#include "command/native_fleet_steer_compact.h"
#include "command/native_fleet_steer_tasks.h"
#include "command/native_fleet_typed_index.h"
#include "command/native_devagent_mail_projection.h"
#include "command/native_dev_proof_command.h"
#include "config/command_catalog.h"
#include "crypto/random_secret.h"
#include "fleet_enrol.h"
#include "json/json.h"
#include "zutf8/zutf8.h"
#include "kernel/command_registry.h"
#include "platform/clock.h"
#include "platform/directory_compat.h"
#include "platform/os_proc.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "services/disk_monitor.h"
#include "sha3/sha3.h"
#include "session/fleet_board_proto.h"
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
/* A fleet roster name: 2..24 of [a-z0-9-] (tools/dev/fleet_enrol.h). */
#define FMC_PEER_MAX 24u
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
 * counted in workers_total. Evidence newer than FMC_WORKER_ALIVE_WINDOW_S counts
 * as alive; a directive this host sent that is still queued with no
 * receiver evidence after FMC_QUEUED_STALE_S becomes a blocker. The reply
 * data is held under FMC_REPLY_SOFT_BUDGET so the leaf's 64 KiB response
 * budget (envelope included) can never refuse the whole brief. */
#define FMC_WORKER_CAP 16u
#define FMC_WORKER_TRACK 64u
#define FMC_DONE_TRACK 256u
#define FMC_DIRECTIVE_SCAN 64
#define FMC_STALE_BLOCKER_CAP 8
#define FMC_WORKER_ALIVE_WINDOW_S 900LL
#define FMC_SESSION_ALIVE_WINDOW_S 60LL
#define FMC_QUEUED_STALE_S 120LL
/* Directive backlog: a seen recipient silent this long is gone; at most
 * FMC_DQ_CAP recipients are grouped in directive_queue[]. */
#define FMC_RECIPIENT_GONE_S (24LL * 60 * 60)
#define FMC_DQ_CAP 16u
#define FMC_CLOSE_PREFIX "closed by sender:"
#define FMC_OWNER_ENV "ZCL_FLEET_OWNER_NAMES"
#define FMC_REPLY_SOFT_BUDGET 49152u
/* Leave time after board observation for local projection/serialization. */
#define FMC_BRIEF_FINISH_RESERVE_MS 50
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
    if (!in || !out || cap == 0 || !zutf8_validate(in))
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

/* Admission reads existing authenticated state. Never initialize or repair
 * it, even for a refused credential. Preserve the directory policy used by
 * the mutating path; unavailable or non-private state fails closed. */
static bool fmc_dirs_read(char *steerdir, size_t cap)
{
    char root[4096];
    uintptr_t retained = 0;
    if (!platform_state_root_existing(root, sizeof(root)))
        return false;
    int n = snprintf(steerdir, cap, "%s/steer", root);
    if (n <= 0 || (size_t)n >= cap ||
        !platform_private_directory_open_validated_traverse(steerdir, &retained))
        return false;
    platform_private_directory_close(retained);
    return true;
}

static bool fmc_admission_dirs(const char *scope, char *steerdir, size_t cap)
{
    bool observe = strcmp(scope, "brief") == 0 || strcmp(scope, "evidence") == 0 ||
                   strcmp(scope, "deliver") == 0;
    return observe ? fmc_dirs_read(steerdir, cap) : fmc_dirs(steerdir, cap);
}

/* Status leaves may legitimately render an absent store as empty for their
 * own CLI. A fleet snapshot must retain that absence instead of qualifying
 * it as an observation of an idle fleet. This check never opens for write. */
static const char *fmc_snapshot_source(const char *relative, bool directory)
{
    char root[4096], path[4096 + 64];
    struct stat st;
    if (!platform_state_root_existing(root, sizeof(root)))
        return "existing_state_unavailable";
    int n = snprintf(path, sizeof(path), "%s/%s", root, relative);
    if (n <= 0 || (size_t)n >= sizeof(path)) return "source_path_too_long";
#if defined(_WIN32)
    int result = stat(path, &st);
#else
    int result = lstat(path, &st);
#endif
    if (result != 0) {
        if (errno == ENOENT) return "source_missing";
        if (errno == ENOTDIR) return "source_parent_not_directory";
        return "source_unavailable";
    }
    if (directory ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode))
        return "sibling_refused";
    return NULL;
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
    /* "" for a local bearer grant; a roster box name for a peer grant. */
    char peer[FMC_PEER_MAX + 1];
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
    /* Optional: absent on every local grant. */
    (void)fmc_grant_line_str(line, "peer", g->peer, sizeof(g->peer));
    if (strlen(g->id) != 32)
        return false;
    return true;
}

/* Constant-time equality over a grant id's exact 32 hex bytes.
 *
 * The presented bearer IS the credential, so strcmp against every stored id
 * leaked how many leading characters a guess shared with a real grant: the
 * comparison stopped at the first difference, and the store is walked for
 * every call. Both sides are known to be 32 bytes here (fmc_grant_parse
 * refuses any other length, and the caller checks the presented one), so a
 * fixed-length compare is exact as well as constant-time. */
#define FMC_GRANT_ID_LEN 32u

static bool fmc_grant_id_eq(const char *a, const char *b)
{
    unsigned diff = 0;
    size_t i;
    if (!a || !b)
        return false;
    if (strlen(a) != FMC_GRANT_ID_LEN || strlen(b) != FMC_GRANT_ID_LEN)
        return false;
    for (i = 0; i < FMC_GRANT_ID_LEN; i++)
        diff |= (unsigned)((unsigned char)a[i] ^ (unsigned char)b[i]);
    return diff == 0;
}

static int fmc_grant_line_read(FILE *f, char line[FMC_LINE_CAP])
{
    size_t n = 0;
    struct fmc_grant g;
    int ch;
    while ((ch = fgetc(f)) != EOF && ch != '\n') {
        if (ch == 0 || n == FMC_LINE_CAP - 1) {
            LOG_ERROR(FMC_LOG, "grant record contains NUL or exceeds its bound");
            return -1;
        }
        line[n++] = (char)ch;
    }
    line[n] = '\0';
    if (ferror(f)) {
        LOG_ERROR(FMC_LOG, "grant store read failed");
        return -1;
    }
    if (n == 0 && ch == EOF) return 0;
    if (line[strspn(line, " \t\r")] != '{' || !json_valid(line, n) ||
        !fmc_grant_parse(line, &g)) {
        LOG_ERROR(FMC_LOG, "grant record is not one complete JSON object");
        return -1;
    }
    return 1;
}

static bool fmc_grant_scan_end(FILE *f, int status)
{
    bool complete = fclose(f) == 0 && status == 0;
    if (!complete)
        LOG_ERROR(FMC_LOG, "grant store scan incomplete or close failed");
    return complete;
}

/* Find the LAST row naming id (later rows supersede). False when absent. */
static bool fmc_grant_find(const char *path, const char *id,
                           struct fmc_grant *out)
{
    FILE *f;
    char line[FMC_LINE_CAP];
    bool found = false;
    struct fmc_grant g;
    int status;
    if (!path || !id || !out)
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    while ((status = fmc_grant_line_read(f, line)) > 0) {
        if (!fmc_grant_parse(line, &g))
            continue;
        if (fmc_grant_id_eq(g.id, id)) {
            *out = g;
            found = true;
        }
    }
    if (!fmc_grant_scan_end(f, status)) found = false;
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
    if (!fmc_admission_dirs(scope, steerdir, sizeof(steerdir)))
        return "STEER_GRANT_STORE";
    n = snprintf(path, sizeof(path), "%s/grants.jsonl", steerdir);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return "STEER_GRANT_STORE";
    if (!fmc_grant_find(path, grant, &g))
        return "STEER_GRANT_UNKNOWN";
    if (g.revoked)
        return "STEER_GRANT_REVOKED";
    /* A peer grant admits board-carried rows only; presenting its id as a
     * bearer would turn an admission record into a local credential. */
    if (g.peer[0])
        return "STEER_GRANT_PEER_ONLY";
    now = platform_time_wall_time_t();
    if (g.expires != 0 && (long long)now >= g.expires)
        return "STEER_GRANT_EXPIRED";
    if (!fmc_scope_has(g.scopes, scope))
        return "STEER_GRANT_SCOPE";
    *row = g;
    return NULL;
}

/* Admit one credential for `scope` as the sender `claimed` and hand back the
 * label and the sender binding of the grant row that was validated. NULL
 * admits; otherwise the typed refusal. The grant id is consumed, never
 * returned. Used by the deliver leaf to bind uploads to the credential. */
const char *zcl_fleet_steer_grant_sender(const char *grant, const char *scope,
                                         const char *claimed, char *label,
                                         size_t lcap, char *binding,
                                         size_t bcap)
{
    struct fmc_grant g;
    const char *refused;
    if (!grant || !grant[0])
        return "STEER_GRANT_UNKNOWN";
    refused = fmc_grant_check_row(grant, scope, &g);
    if (refused)
        return refused;
    if (!g.label[0])
        return "STEER_GRANT_UNLABELLED";
    if (!claimed || !claimed[0])
        return "STEER_SENDER_UNSTATED";
    if (strcmp(claimed, g.label) != 0)
        return "STEER_SENDER_MISMATCH";
    if (snprintf(label, lcap, "%s", g.label) >= (int)lcap ||
        !zcl_fleet_steer_sender_binding(g.id, g.label, binding, bcap))
        return "STEER_SENDER_UNBINDABLE";
    return NULL;
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
    int status;
    s->n = 0;
    f = fopen(path, "rb");
    if (!f)
        return false;
    while ((status = fmc_grant_line_read(f, line)) > 0) {
        if (fmc_grant_parse(line, &g) && strcmp(g.label, label) == 0)
            fmc_grant_set_put(s, &g);
    }
    if (fmc_grant_scan_end(f, status)) return true;
    s->n = 0;
    return false;
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
    if (!platform_state_root_existing(root, sizeof(root)))
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
        /* A peer grant never admits a row by binding: it names a board
         * signer, and a row that came any other way has none. */
        if (strcmp(set->g[i].label, label) != 0 || set->g[i].peer[0])
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

/* The verdict the loaded store gives one (label, peer, scope) triple: NULL
 * when a live peer grant of that label names exactly that peer and carries
 * the scope, otherwise the most specific reason a row about that label
 * gave. A label held only by local grants reads STEER_GRANT_PEER: somebody
 * may send under that name from THIS box, but no enrolled box may. */
static const char *fmc_grant_peer_scan(const struct fmc_grant_set *set,
                                       const char *peer, const char *scope,
                                       long long now)
{
    const char *why = "STEER_GRANT_UNKNOWN";
    size_t i;
    for (i = 0; i < set->n; i++) {
        const char *row;
        if (strcmp(set->g[i].peer, peer) != 0) {
            why = "STEER_GRANT_PEER";
            continue;
        }
        row = fmc_grant_row_verdict(&set->g[i], scope, now);
        if (!row)
            return NULL;
        why = row;
    }
    return why;
}

const char *zcl_fleet_steer_grant_peer_live(const char *label,
                                            const char *peer,
                                            const char *scope)
{
    struct fmc_grant_set set;
    const char *store;
    if (!label || !label[0] || !scope || !scope[0])
        return "STEER_GRANT_SCOPE";
    if (!peer || !peer[0] || strlen(peer) > FMC_PEER_MAX)
        return "STEER_GRANT_PEER";
    store = fmc_grant_set_read(label, &set);
    if (store)
        return store;
    return fmc_grant_peer_scan(&set, peer, scope,
                               (long long)platform_time_wall_time_t());
}

/* The expiry timestamp behind a preflight's grant_expiry field: the SAME
 * grants.jsonl store, the SAME label set, the SAME liveness rule
 * (fmc_grant_row_verdict) as the binding admission above — no new format,
 * no new scope, no second permission system. One label may hold several
 * live ids (an older grant still unexpired beside its replacement); the
 * longest authority is what a sender acts under, so the maximum is
 * reported, and a grant that never expires (expires 0) reports 0, which
 * dominates every finite timestamp. False when no live grant carries the
 * label with the scope — including peer-only rows, which never admit a
 * local binding — so a caller that just proved liveness and then reads
 * false has raced a revoke, and refuses. */
bool zcl_fleet_steer_grant_expiry(const char *label, const char *scope,
                                  long long *out)
{
    struct fmc_grant_set set;
    const char *store;
    long long now, best = -1;
    size_t i;
    bool any = false;
    if (!label || !label[0] || !scope || !scope[0] || !out)
        return false;
    store = fmc_grant_set_read(label, &set);
    if (store)
        return false;
    now = (long long)platform_time_wall_time_t();
    for (i = 0; i < set.n; i++) {
        if (strcmp(set.g[i].label, label) != 0 || set.g[i].peer[0])
            continue;
        if (fmc_grant_row_verdict(&set.g[i], scope, now))
            continue;
        if (set.g[i].expires == 0) {
            *out = 0;
            return true;
        }
        if (!any || set.g[i].expires > best)
            best = set.g[i].expires;
        any = true;
    }
    if (!any)
        return false;
    *out = best;
    return true;
}

/* ── idempotency store ─────────────────────────────────────────────────── */

/* Payload digest: FNV-1a/64 over to, body, ref, from (and kind, for a
 * result only) with NUL separators.
 * An equality check for reconcile and nothing more; fixed-size hex keeps
 * sent.jsonl lines flat and greppable. It is NOT what keeps one sender out
 * of another's rows — the digest is reached only after the sender has been
 * bound to its credential, and `from` is by then the grant's own label
 * rather than a caller's claim. Folding a claim into a digest was never a
 * boundary: two parties presenting one key simply disagreed about who they
 * were, and the reconcile handed the second one the first one's row. */
static void fmc_payload_sum(const char *to, const char *body,
                            const char *ref, const char *from,
                            const char *kind, char out[17])
{
    uint64_t h = 1469598103934665603ULL;
    const char *parts[5];
    size_t i, nparts = 4;
    parts[0] = to ? to : "";
    parts[1] = body ? body : "";
    parts[2] = ref ? ref : "";
    parts[3] = from ? from : "";
    /* A result folds its kind in; a directive digests exactly as it did
     * before kinds existed, so recorded receipts still reconcile. */
    if (kind && strcmp(kind, "directive") != 0)
        parts[nparts++] = kind;
    for (i = 0; i < nparts; i++) {
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
static int fmc_revoke_read_line(FILE *f, char line[FMC_LINE_CAP]);
static bool fmc_sent_match(const char *line, const char *key, long long *seq,
                           char sum[17])
{
    char pat[256], *end = NULL; const char *p; long long s;
    *seq = -1; sum[0] = '\0';
    int r = snprintf(pat, sizeof(pat), "\"key\":\"%s\"", key);
    if (r <= 0 || (size_t)r >= sizeof(pat) || !strstr(line, pat)) return false;
    p = strstr(line, "\"seq\":");
    if (!p) return false;
    s = strtoll(p + 6, &end, 10);
    if (end == p + 6 || s < 0) return false;
    p = strstr(line, "\"sum\":\"");
    if (p && strlen(p + 7) >= 16) {
        memcpy(sum, p + 7, 16); sum[16] = '\0';
    }
    *seq = s; return true;
}
static bool fmc_sent_owner(const char *line, const char *grant,
                           char sum[17], bool *keyed)
{
    struct json_value obj;
    json_init(&obj);
    if (!json_read(&obj, line, strlen(line)) || obj.type != JSON_OBJ) {
        json_free(&obj); return false;
    }
    const struct json_value *g = json_get(&obj, "grant");
    const char *owner = g && g->type == JSON_STR ? json_get_str(g) : "";
    const struct json_value *src = json_get(&obj, "source");
    *keyed = src && src->type == JSON_STR &&
        strcmp(json_get_str(src), "keyed") == 0;
    if (!owner || strcmp(owner, grant ? grant : "") != 0) sum[0] = 0;
    json_free(&obj);
    return true;
}

static int fmc_sent_find(const char *path, const char *key, long long *seq,
                          char sum[17], const char *grant, bool *keyed)
{
    FILE *f;
    char line[FMC_LINE_CAP];
    bool found = false; int read_rc;
    if (seq) *seq = -1;
    if (sum) sum[0] = '\0';
    if (!path || !key || !seq || !sum)
        return false;
    f = fopen(path, "rb");
    if (!f)
        return errno == ENOENT ? 0 : -1;
    while ((read_rc = fmc_revoke_read_line(f, line)) > 0) {
        long long candidate; char digest[17] = {0};
        if (fmc_sent_match(line, key, &candidate, digest)) {
            if (!fmc_sent_owner(line, grant, digest, keyed)) {
                read_rc = -1; break;
            }
            *seq = candidate; memcpy(sum, digest, sizeof(digest));
            found = true;
        }
    }
    bool failed = read_rc < 0 || ferror(f) != 0;
    failed |= fclose(f) != 0;
    if (failed) {
        *seq = -1; sum[0] = '\0';
        LOG_ERROR(FMC_LOG, "send: receipt store unreadable (%s)", path);
        return -1;
    }
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
    if (!platform_state_root_existing(root, sizeof(root)))
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
    int read_rc;
    if (!path || !path[0] || seq < 0 || !to || !to[0])
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    while ((read_rc = fmc_revoke_read_line(f, line)) > 0) {
        if (!fmc_grant_line_int(line, "seq", &rseq) || rseq != seq)
            continue;
        if (!fmc_grant_line_str(line, "to", rto, sizeof(rto)))
            continue;
        ours |= strcmp(rto, to) == 0;
    }
    bool failed = read_rc < 0 || ferror(f) != 0;
    failed |= fclose(f) != 0;
    return !failed && ours;
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
static void fmc_note_missing_next(struct json_value *missing,
                                  const char *source, const char *reason,
                                  long long age_ms, const char *next,
                                  long long dropped)
{
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    bool ok = json_push_kv_str(&item, "source", source) &&
              json_push_kv_str(&item, "reason", reason) &&
              json_push_kv_int(&item, "age_ms", age_ms);
    if (ok && next && next[0])
        ok = json_push_kv_str(&item, "next", next);
    if (ok && dropped > 0)
        ok = json_push_kv_int(&item, "dropped", dropped);
    if (ok)
        (void)json_push_back(missing, &item);
    json_free(&item);
}

static void fmc_note_missing(struct json_value *missing, const char *source,
                             const char *reason, long long age_ms)
{
    fmc_note_missing_next(missing, source, reason, age_ms, NULL, 0);
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

/* Use the mail cursor alphabet without changing the recipient identity. */
static bool fmc_clean_agent(const char *agent, char *out, size_t cap)
{
    if (!agent || !agent[0] || strlen(agent) > 128 || strlen(agent) >= cap)
        return false;
    for (const char *p = agent; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '_' && *p != '-')
            return false;
    memcpy(out, agent, strlen(agent) + 1);
    return true;
}

/* Receiver ack cursor from the mail leaf's cursor.<agent> file. Returns -1
 * when the receiver never acked (nothing acknowledged). */
/* Matches DVM_TOKEN_CAP in native_devagent_mail.c, including seq.max. */
#define FMC_ACK_TOKEN_CAP (16u * (128u + 24u) + 64u)

static bool fmc_ack_token_ok(const char *token)
{
    for (const char *p = token; *p; p++) {
        if (!isalnum((unsigned char)*p) && !strchr("._-:,|", *p))
            return false;
    }
    return true;
}

static long long fmc_ack_parse(char *buf, size_t len)
{
    char *end = NULL;
    if (len == 0 || memchr(buf, '\0', len)) return -1;
    if (buf[len - 1] == '\n') len--;
    if (len == 0 || len >= FMC_ACK_TOKEN_CAP || !isdigit((unsigned char)buf[0])) return -1;
    buf[len] = '\0';
    errno = 0;
    long long v = strtoll(buf, &end, 10);
    if (errno == ERANGE || v < 0) return -1;
    if (*end && (*end != '|' || !fmc_ack_token_ok(end + 1))) return -1;
    return v;
}

static size_t fmc_ack_read(const char *agent, char *buf, size_t cap)
{
    char root[4096], path[4096 + 130];
    char clean[129];
    FILE *f;
    int n;
    if (cap <= FMC_ACK_TOKEN_CAP ||
        !fmc_clean_agent(agent, clean, sizeof(clean)) ||
        !platform_state_root_existing(root, sizeof(root)))
        return 0;
    n = snprintf(path, sizeof(path), "%s/mail/cursor.%s", root, clean);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return 0;
    f = fopen(path, "rb");
    if (!f)
        return 0;
    size_t len = fread(buf, 1, cap, f);
    bool failed = ferror(f) != 0 || len == cap;
    failed |= fclose(f) != 0;
    return failed ? 0 : len;
}

static long long fmc_ack_cursor(const char *agent)
{
    char buf[FMC_ACK_TOKEN_CAP + 1];
    size_t len = fmc_ack_read(agent, buf, sizeof(buf));
    long long cursor = fmc_ack_parse(buf, len);
    if (cursor >= 0 && strchr(buf, '|') &&
        !zcl_devagent_mail_cursor_valid(buf)) return -1;
    return cursor;
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

/* Resume-token bound: the leaf's token caps at DVM_TOKEN_CAP (under 3 KiB
 * for 16 streams), so 4 KiB carries any watermark with room to spare. */
#define FMC_MAIL_SINCE_CAP 4096

struct fmc_mail_view {
    bool forward;
    bool projection_failed;
    char start_token[FMC_MAIL_SINCE_CAP];
    long long cursor;
    long long count;
    bool ok;
    /* Composite per-stream watermark: the next_since token at the end of
     * the drain the caller passes back as `since` to resume exactly where
     * this brief stopped. "" when mail did not answer. */
    char cursor_token[FMC_MAIL_SINCE_CAP];
    /* The changes cap cut the feed: truncated rows were seen but not shown
     * (dropped counts them). Re-poll with the PREVIOUS token and dedupe to
     * recover them; the advanced token moves past. */
    bool truncated;
    long long dropped;
    /* The pass over mail began inside the history, at each stream's newest
     * window: cut says older rows exist that this brief did not read, and
     * window_reach_ts is the newest stamp at which any cut stream began,
     * once the pass read that row of every cut stream ("" when it did not,
     * and when nothing was cut). Every compact path reads no window and
     * stays exact. */
    bool window_cut;
    char window_reach_ts[32];
};

/* One parsed mail row. String pointers borrow the sibling reply and are
 * valid until the sub call ends. */
struct fmc_row {
    long long seq;
    long long row_offset;
    long long row_end;
    const char *stream;
    const char *row_sha3;
    const char *ts;
    const char *from;
    const char *to;
    const char *kind;
    const char *body;
    const char *ref;
    const char *observed_disposition, *observed_stream, *observed_sha3, *sender_binding;
    long long observed_offset, observed_seq;
};

static const char *fmc_row_field(const struct json_value *r, const char *key)
{
    const struct json_value *v = json_get(r, key);
    if (!v || v->type != JSON_STR)
        return "";
    return json_get_str(v) ? json_get_str(v) : "";
}

#ifdef ZCL_TESTING
static unsigned long long s_fmc_row_parses;
unsigned long long zcl_fleet_steer_test_row_parses(void);
unsigned long long zcl_fleet_steer_test_row_parses(void) { return s_fmc_row_parses; }
#endif

static bool fmc_row_parse(const struct json_value *r, struct fmc_row *v)
{
    const struct json_value *s;
#ifdef ZCL_TESTING
    s_fmc_row_parses++;
#endif
    if (!r || r->type != JSON_OBJ || !v)
        return false;
    s = json_get(r, "seq");
    if (!s || s->type != JSON_INT)
        return false;
    v->seq = (long long)json_get_int(s);
    v->stream = fmc_row_field(r, "stream");
    v->row_sha3 = fmc_row_field(r, "row_sha3");
    const struct json_value *offset = json_get(r, "row_offset");
    v->row_offset = offset && offset->type == JSON_INT ? json_get_int(offset) : -1;
    const struct json_value *end = json_get(r, "row_end");
    v->row_end = end && end->type == JSON_INT ? json_get_int(end) : -1;
    v->ts = fmc_row_field(r, "ts");
    v->from = fmc_row_field(r, "from");
    v->to = fmc_row_field(r, "to");
    v->kind = fmc_row_field(r, "kind");
    v->body = fmc_row_field(r, "body");
    v->ref = fmc_row_field(r, "ref");
    v->observed_disposition = fmc_row_field(r, "observed_disposition");
    v->observed_stream = fmc_row_field(r, "observed_stream");
    v->observed_sha3 = fmc_row_field(r, "observed_sha3");
    v->sender_binding = fmc_row_field(r, "sender_binding");
    const struct json_value *oo = json_get(r, "observed_offset");
    const struct json_value *os = json_get(r, "observed_seq");
    v->observed_offset = oo && oo->type == JSON_INT ? json_get_int(oo) : -1;
    v->observed_seq = os && os->type == JSON_INT ? json_get_int(os) : -1;
    return true;
}

/* The pass's rows parsed once. Each directive's answer, conflict, closure
 * and reply scans walk every row, and parsing a row is seventeen linear
 * key lookups, so re-parsing per scan made a brief O(directives * rows *
 * keys). The table is bound to one exact rows array (its address, child
 * storage and length); any other array, or a failed allocation, parses
 * as before. The borrowed strings live as long as that array. */
static thread_local struct fmc_parsed {
    const struct json_value *rows, *children;
    size_t n;
    struct fmc_row *v;
    bool *ok;
} s_fmc_parsed;

static void fmc_parsed_end(void)
{
    free(s_fmc_parsed.v);
    free(s_fmc_parsed.ok);
    memset(&s_fmc_parsed, 0, sizeof(s_fmc_parsed));
}

static void fmc_parsed_begin(const struct json_value *rows)
{
    size_t n = rows && rows->type == JSON_ARR ? json_size(rows) : 0u;
    fmc_parsed_end();
    if (n == 0)
        return;
    s_fmc_parsed.v = zcl_calloc(n, sizeof(*s_fmc_parsed.v), "fleet_steer.parsed_rows");
    s_fmc_parsed.ok = zcl_calloc(n, sizeof(*s_fmc_parsed.ok), "fleet_steer.parsed_ok");
    if (!s_fmc_parsed.v || !s_fmc_parsed.ok) {
        fmc_parsed_end();
        return;
    }
    for (size_t i = 0; i < n; i++)
        s_fmc_parsed.ok[i] = fmc_row_parse(json_at(rows, i), &s_fmc_parsed.v[i]);
    s_fmc_parsed.rows = rows;
    s_fmc_parsed.children = rows->children;
    s_fmc_parsed.n = n;
}

/* Row i of rows, from the table when it is bound to this exact array. */
static bool fmc_rows_at(const struct json_value *rows, size_t i, struct fmc_row *v)
{
    const struct fmc_parsed *p = &s_fmc_parsed;
    if (p->v && p->rows == rows && p->children == rows->children &&
        p->n == json_size(rows) && i < p->n) {
        if (p->ok[i])
            *v = p->v[i];
        return p->ok[i];
    }
    return fmc_row_parse(json_at(rows, i), v);
}

static bool fmc_row_acked(const struct fmc_row *v)
{
    char buf[FMC_ACK_TOKEN_CAP + 1];
    size_t len = fmc_ack_read(v->to, buf, sizeof(buf));
    long long cursor = fmc_ack_parse(buf, len);
    if (cursor < 0)
        return false;
    char *bar = strchr(buf, '|');
    return bar ? zcl_devagent_mail_cursor_covers(buf, v->stream, v->row_end, v->seq)
               : v->seq <= cursor;
}

/* Local private source rows are minted only after full typed validation.
 * Imported hints do not establish a read or acknowledge another row. */
static bool fmc_typed_read_matches(const struct fmc_row *d,
                                   const struct fmc_row *r)
{
    if (strcmp(d->kind, "directive") || strcmp(r->kind, "result") ||
        strcmp(r->stream, "outbox.jsonl") || !r->observed_disposition[0] ||
        !strcmp(r->observed_disposition, "UNVERIFIED")) return false;
    if (strcmp(r->from, d->to) || strcmp(r->to, d->from) || strcmp(r->ref, d->ref) ||
        strcmp(r->observed_stream, d->stream) || strcmp(r->observed_sha3, d->row_sha3) ||
        r->observed_offset != d->row_offset || r->observed_seq != d->seq) return false;
    return r->sender_binding[0] &&
        !zcl_fleet_steer_grant_binding_live(r->from, r->sender_binding, "send");
}

static const char *fmc_typed_read(const struct json_value *rows, const struct fmc_row *d)
{
    if (strcmp(d->kind, "directive") || !rows || rows->type != JSON_ARR) return NULL;
    const char *latest = NULL;
    long long latest_offset = -1;
    for (size_t i = 0; i < json_size(rows); i++) {
        struct fmc_row r;
        if (fmc_rows_at(rows, i, &r) && r.observed_disposition[0] &&
            r.row_offset > latest_offset && fmc_typed_read_matches(d, &r)) {
            latest = r.observed_disposition;
            latest_offset = r.row_offset;
        }
    }
    return latest;
}

struct fmc_typed_match {
    const struct fmc_row *directive;
    const char *disposition;
};

static bool fmc_typed_candidate(const struct json_value *row, void *opaque)
{
    struct fmc_typed_match *match = opaque;
    struct fmc_row candidate;
    if (!fmc_row_parse(row, &candidate) ||
        !fmc_typed_read_matches(match->directive, &candidate)) return false;
    match->disposition = candidate.observed_disposition;
    return true;
}

/* The index is scoped to this exact rows array and never caches grant checks. */
static const char *fmc_typed_read_indexed(const struct json_value *rows,
    const struct fmc_row *d, struct zcl_fleet_typed_index *index)
{
    if (!index) return fmc_typed_read(rows, d);
    struct zcl_fleet_typed_locator key = {
        d->from, d->to, d->ref, d->stream, d->row_sha3,
        d->row_offset, d->seq, d->kind
    };
    struct fmc_typed_match match = {.directive = d};
    if (!zcl_fleet_typed_index_visit_key(index, &key, fmc_typed_candidate, &match))
        return fmc_typed_read(rows, d);
    return match.disposition;
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

/* One "<stream>:<offset>" entry of a next_since token. The integer floor
 * can be 0 for every pull that started at 0; the offset is the position
 * that actually passed this row. */
static bool fmc_ack_entry_covers(const char *entry, const struct fmc_row *v)
{
    const char *colon;
    char *end = NULL;
    long long off;
    size_t nlen;
    if (!entry || !v || !v->stream || !v->stream[0] || v->row_end < 0)
        return false;
    colon = strchr(entry, ':');
    if (!colon || colon == entry)
        return false;
    nlen = (size_t)(colon - entry);
    if (nlen != strlen(v->stream) || strncmp(entry, v->stream, nlen) != 0)
        return false;
    errno = 0;
    off = strtoll(colon + 1, &end, 10);
    if (errno == ERANGE || !end || *end != '\0' || off < 0)
        return false;
    return off >= v->row_end;
}

static bool fmc_token_covers_row(const char *token, const struct fmc_row *v)
{
    const char *bar;
    char entry[160];
    if (!token)
        return false;
    bar = strchr(token, '|');
    if (!bar || bar[1] == '\0')
        return false;
    for (bar = bar + 1; *bar;) {
        const char *comma = strchr(bar, ',');
        size_t n = comma ? (size_t)(comma - bar) : strlen(bar);
        if (n == 0 || n >= sizeof(entry))
            return false;
        memcpy(entry, bar, n);
        entry[n] = '\0';
        if (fmc_ack_entry_covers(entry, v))
            return true;
        if (!comma)
            break;
        bar = comma + 1;
    }
    return false;
}

/* A scalar cursor covers by sequence. A composite token covers only when
 * its stream offset has passed the row: the floor is a pull bound, and a
 * row that offset missed stays uncovered. An invalid token covers nothing. */
static bool fmc_text_covers(char *buf, size_t len, const struct fmc_row *v)
{
    long long floor;
    if (!v || len == 0)
        return false;
    floor = fmc_ack_parse(buf, len);
    if (floor < 0)
        return false;
    if (!strchr(buf, '|'))
        return v->seq <= floor;
    return fmc_token_covers_row(buf, v);
}

static bool fmc_mail_leaf_ok(const char *leaf)
{
    return leaf && (strcmp(leaf, "cursor") == 0 || strcmp(leaf, "read") == 0 ||
                    strcmp(leaf, "alias") == 0);
}

static bool fmc_agent_exact(const char *agent, char *clean, size_t cap)
{
    if (!fmc_clean_agent(agent, clean, cap))
        return false;
    return strcmp(agent, clean) == 0;
}

static bool fmc_read_capped(FILE *f, char *buf, size_t cap, size_t *out_len)
{
    size_t len = fread(buf, 1, cap, f);
    bool failed = ferror(f) != 0 || len == cap || fclose(f) != 0;
    if (failed)
        return false;
    *out_len = len;
    return true;
}

/* Bytes of mail/<leaf>.<agent>. The agent must already be a cursor name:
 * a stripped spelling must not open a different file. A full buffer is
 * not a cursor. */
static bool fmc_mail_text(const char *leaf, const char *agent, char *buf,
                          size_t cap, size_t *out_len)
{
    char root[4096], path[4096 + 96];
    char clean[FMC_NAME_MAX + 1];
    FILE *f;
    int n;
    if (!fmc_mail_leaf_ok(leaf) || !buf || cap < 2 || !out_len)
        return false;
    if (!fmc_agent_exact(agent, clean, sizeof(clean)))
        return false;
    if (!platform_state_root_existing(root, sizeof(root)))
        return false;
    n = snprintf(path, sizeof(path), "%s/mail/%s.%s", root, leaf, clean);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    return fmc_read_capped(f, buf, cap, out_len);
}

/* mail/alias.<stale> holds one live agent name. No chain, no self-alias. */
static bool fmc_alias_target(const char *agent, char *live, size_t cap)
{
    char buf[FMC_NAME_MAX + 2];
    char clean[FMC_NAME_MAX + 1];
    size_t n = 0;
    if (!live || cap <= FMC_NAME_MAX)
        return false;
    if (!fmc_mail_text("alias", agent, buf, sizeof(buf), &n))
        return false;
    if (n == 0 || memchr(buf, '\0', n))
        return false;
    if (buf[n - 1] == '\n')
        n--;
    if (n > 0 && buf[n - 1] == '\r')
        n--;
    if (n == 0 || n > FMC_NAME_MAX)
        return false;
    memcpy(live, buf, n);
    live[n] = '\0';
    if (!fmc_clean_agent(live, clean, sizeof(clean)) ||
        strcmp(live, clean) != 0)
        return false;
    return strcmp(live, agent) != 0;
}

/* True when mail/<leaf>.<agent> exists. A present file blocks an alias
 * even when its bytes do not cover the row. */
static bool fmc_mail_present(const char *leaf, const char *agent)
{
    char root[4096], path[4096 + 96];
    char clean[FMC_NAME_MAX + 1];
    FILE *f;
    int n;
    if (!fmc_mail_leaf_ok(leaf) || !fmc_agent_exact(agent, clean, sizeof(clean)))
        return false;
    if (!platform_state_root_existing(root, sizeof(root)))
        return false;
    n = snprintf(path, sizeof(path), "%s/mail/%s.%s", root, leaf, clean);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    (void)fclose(f);
    return true;
}

/* An alias is one hop, and only for a label that has no position file. */
static bool fmc_alias_allowed(const char *agent, const char *leaf)
{
    const char *other = strcmp(leaf, "cursor") == 0 ? "read" : "cursor";
    return !fmc_mail_present(leaf, agent) && !fmc_mail_present(other, agent);
}

static bool fmc_pos_covers(const char *agent, const struct fmc_row *v,
                           const char *leaf, bool alias_ok)
{
    char buf[FMC_ACK_TOKEN_CAP + 1];
    char live[FMC_NAME_MAX + 1];
    size_t n = 0;
    if (!v)
        return false;
    if (!fmc_mail_text(leaf, agent, buf, sizeof(buf), &n)) {
        if (!alias_ok || !fmc_alias_allowed(agent, leaf) ||
            !fmc_alias_target(agent, live, sizeof(live)))
            return false;
        return fmc_pos_covers(live, v, leaf, false);
    }
    return fmc_text_covers(buf, n, v);
}

/* One hop, and only when this recipient has neither a read nor a cursor
 * file. The target's own cursor is not followed further. */
static bool fmc_alias_ack(const struct fmc_row *v)
{
    char live[FMC_NAME_MAX + 1];
    if (!v || !fmc_alias_allowed(v->to, "cursor") ||
        !fmc_alias_target(v->to, live, sizeof(live)))
        return false;
    return fmc_pos_covers(live, v, "cursor", false);
}

static bool fmc_read_covers(const struct fmc_row *v)
{
    return v && fmc_pos_covers(v->to, v, "read", true);
}

static bool fmc_reply_compatible(const struct fmc_row *directive, const struct fmc_row *reply);

static bool fmc_reply_addressed(const struct fmc_row *d, const struct fmc_row *r)
{
    return !strcmp(r->to, d->from) || !strcmp(r->to, "*");
}

struct fmc_reply_conflicts { bool any, target, attempt_any, attempt_target; };
static struct fmc_reply_conflicts fmc_reply_conflicts(const struct json_value *, const struct fmc_row *);
static bool fmc_reply_conflicting(const struct fmc_reply_conflicts *, const struct fmc_row *, const struct fmc_row *, bool);

/* True when the pulled rows carry a reply from this row's recipient under
 * the same ref: the row a transport brings back into inbox.<peer>.jsonl,
 * and the only proof available here that the directive left this host. A
 * row whose `from` is our own sender name is our side of the thread, never
 * receiver evidence — so a directive addressed to its own sender cannot
 * promote itself. Bounded by the pull the brief already holds; nothing is
 * accumulated. Only strictly later valid timestamps establish ordering;
 * equal seconds are ambiguous, and stream sequence numbers are not comparable. */
static bool fmc_direct_reply(const struct fmc_row *v, const struct fmc_row *r,
                             const struct fmc_reply_conflicts *conflicts)
{
    return !strcmp(r->from, v->to) && !strcmp(r->ref, v->ref) &&
        fmc_reply_addressed(v, r) && fmc_reply_compatible(v, r) &&
        !fmc_reply_conflicting(conflicts, v, r, true);
}

static bool fmc_rows_reply_from(const struct json_value *rows,
                                const struct fmc_row *v)
{
    size_t n, i;
    if (!rows || rows->type != JSON_ARR || !v || !v->ref[0] || !v->to[0])
        return false;
    struct fmc_reply_conflicts conflicts = {0};
    if (!strcmp(v->kind, "directive"))
        conflicts = fmc_reply_conflicts(rows, v);
    n = json_size(rows);
    for (i = 0; i < n; i++) {
        struct fmc_row r;
        if (!fmc_rows_at(rows, i, &r))
            continue;
        if (r.observed_disposition[0]) continue;
        if (strcmp(r.from, v->from) == 0)
            continue;
        /* `to` of `*` names no cursor file. A note from anyone but the
         * sender is that broadcast's receiver evidence. A named recipient
         * still has to be later, addressed back, and attempt-compatible. */
        if (strcmp(v->to, "*") == 0) {
            if (strcmp(r.ref, v->ref) == 0 && r.from[0])
                return true;
            continue;
        }
        if (fmc_direct_reply(v, &r, &conflicts))
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
static const char *fmc_row_state_with_read(const struct fmc_row *v,
    const struct json_value *rows, const char *sent_path, const char *typed)
{
    bool acked = fmc_row_acked(v) || typed || fmc_alias_ack(v);
    if (!fmc_sent_by_us(sent_path, v->seq, v->to))
        return acked ? "acknowledged" : "delivered";
    if (acked || fmc_rows_reply_from(rows, v))
        return "acknowledged";
    if (fmc_read_covers(v))
        return "read";
    return "queued";
}

static const char *fmc_row_state(const struct fmc_row *v,
    const struct json_value *rows, const char *sent_path)
{
    return fmc_row_state_with_read(v, rows, sent_path, fmc_typed_read(rows, v));
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

/* Directive backlog over the newest FMC_DIRECTIVE_SCAN directives (see
 * DIRECTIVE BACKLOG at the top of this file). */
struct fmc_dq_entry {
    char to[FMC_NAME_MAX + 1];
    long long open;
    long long oldest_age_s;
};

struct fmc_directive_tally {
    long long scanned, open_worker, overdue_worker;
    long long answered, closed, gone, unresolved;
    long long broadcast, broadcast_open, owner, owner_open;
    struct fmc_dq_entry q[FMC_DQ_CAP];
    size_t nq;
    long long q_untracked;
    bool forward_page;
};

/* True when name is one comma-separated entry of list. */
static bool fmc_name_listed(const char *list, const char *name)
{
    size_t len = name ? strlen(name) : 0u;
    for (const char *p = list; len && p && *p; ) {
        const char *end = strchr(p, ',');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (n == len && strncmp(p, name, len) == 0)
            return true;
        p = end ? end + 1 : NULL;
    }
    return false;
}

/* The configured human owner names (comma-separated), else none. Never the
 * host user: every box posts as its Unix user, so that name is shared by
 * every agent on the host and would make each of them an owner. */
static const char *fmc_owner_names(void)
{
    const char *env = getenv(FMC_OWNER_ENV);
    return env ? env : "";
}

static bool fmc_owner_name(const char *name)
{
    return fmc_name_listed(fmc_owner_names(), name);
}

/* broadcast (to `*`), owner (a configured human name), else worker. */
static const char *fmc_directive_class(const struct fmc_row *d)
{
    if (strcmp(d->to, "*") == 0)
        return "broadcast";
    return fmc_owner_name(d->to) ? "owner" : "worker";
}

struct fmc_roster {
    struct fmc_directive_tally dt;
    struct fmc_worker *w;
    size_t n;
    size_t untracked;
    char (*done)[FMC_REF_MAX + 1];
    size_t ndone;
    struct fmc_session *ss;
    size_t nss;
    size_t ss_untracked;
    /* The brief's mail pass was cut to its newest window: a worker seen
     * only before it is unknown here, so the total is not exact. */
    bool window_cut;
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
    if (v->observed_disposition[0]) return;
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
    if (!platform_state_root_existing(root, sizeof(root)) ||
        snprintf(path, sizeof(path), "%s/%s/%s", root, sub, file) >=
            (int)sizeof(path))
        return "unknown";
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return errno == ENOENT ? "never-run" : "unknown";
#if !defined(_WIN32)
    state = flock(fd, LOCK_EX | LOCK_NB) == 0 ? "free" :
            (errno == EAGAIN || errno == EWOULDBLOCK) ? "held" : "unknown";
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
/* Complete intake extent; unavailable output is never a measured prefix. */
bool fleet_steer_intake_stream(FILE *f, long long *count, char error[64]);
static bool fmc_intake_extent(FILE *f, char text[1024], size_t *n)
{
    *n = fread(text, 1, 1024, f);
    if (ferror(f) || !feof(f) || *n == 1024 || memchr(text, 0, *n)) return false;
    text[*n] = '\0'; return true;
}
bool fleet_steer_intake_stream(FILE *f, long long *count, char error[64])
{
    char text[1024]; size_t n, len; char *p, *end;
    *count = -1; (void)snprintf(error, 64, "INTAKE_UNAVAILABLE");
    if (!fmc_intake_extent(f, text, &n)) return false;
    p = text;
    if (strncmp(p, "position=", 9) == 0) {
        p = strchr(p, '\n'); if (!p) return false; ++p;
    }
    if (strncmp(p, "failures=", 9) != 0) return false;
    p += 9; end = strchr(p, '\n'); if (!end) return false;
    len = (size_t)(end - p);
    if (!len || len > 18u || !fmc_digits(p, len)) return false;
    long long value = fmc_num(p, len);
    p = end + 1;
    if (strncmp(p, "last_error=", 11) != 0) return false;
    p += 11; len = n - (size_t)(p - text);
    if (len && p[len - 1u] == '\n') --len;
    if (len >= 64u || memchr(p, '\n', len) || memchr(p, '\r', len)) return false;
    memcpy(error, p, len); error[len] = '\0'; *count = value;
    return true;
}
static void fmc_intake_read(struct fmc_local *lo)
{
    char root[4096], path[4096 + 64];
    FILE *f;
    lo->intake_failures = -1;
    lo->intake_error[0] = '\0';
    if (!platform_state_root_existing(root, sizeof(root)) ||
        snprintf(path, sizeof(path), "%s/receive/intake.state", root) >=
            (int)sizeof(path))
        return;
    f = fopen(path, "rb");
    if (!f)
        return;
    bool ok = fleet_steer_intake_stream(f, &lo->intake_failures, lo->intake_error);
    if (fclose(f) != 0) {
        ok = false; lo->intake_failures = -1;
        (void)snprintf(lo->intake_error, sizeof(lo->intake_error), "INTAKE_UNAVAILABLE");
    }
    if (!ok) LOG_WARN(FMC_LOG, "receiver intake.state unavailable: incomplete or malformed record");
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
                       "running in dev.agent.queue");
        return "idle";
    }
    (void)snprintf(why, cap, "%s",
                   "no resident lock held and nothing running in "
                   "dev.agent.queue");
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
    if (alive >= 0 && alive <= FMC_WORKER_ALIVE_WINDOW_S) {
        (void)snprintf(why, cap,
                       "last evidence %llds ago, within the %llds window; "
                       "no open claim",
                       alive, FMC_WORKER_ALIVE_WINDOW_S);
        return "idle";
    }
    if (alive < 0) {
        (void)snprintf(why, cap, "%s",
                       "newest row carries no parseable timestamp");
        return "unknown";
    }
    (void)snprintf(why, cap, "last evidence %llds ago, older than the %llds "
                   "window", alive, FMC_WORKER_ALIVE_WINDOW_S);
    return "unknown";
}

static bool fmc_put_null(struct json_value *o, const char *key)
{
    struct json_value nv;
    json_init(&nv);
    json_set_null(&nv);
    bool ok = json_push_kv(o, key, &nv);
    json_free(&nv);
    return ok;
}

/* A string field, or JSON null when unknown. */
static bool fmc_put_str(struct json_value *o, const char *key, const char *s)
{
    return s && s[0] ? json_push_kv_str(o, key, s) : fmc_put_null(o, key);
}

/* A number field, or JSON null when unknown (-1). */
static bool fmc_put_int(struct json_value *o, const char *key, long long v)
{
    return v >= 0 ? json_push_kv_int(o, key, v) : fmc_put_null(o, key);
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
    if (platform_state_root_existing(root, sizeof(root)))
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

/* Who the presented credential says the caller is: a whitelisted copy of the
 * validated grant row, never its id or token. */
struct fmc_caller {
    bool grant;
    char label[FMC_NAME_MAX + 1];
    char binding[ZCL_FLEET_STEER_BINDING_HEX + 1];
    char scopes[64];
    long long expires;
};

struct fmc_emit_ctx {
    const struct fmc_caller *caller;
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
    (void)json_push_kv_bool(data, "workers_total_exact",
                            ro->untracked == 0 && !ro->window_cut);
    (void)json_push_kv_bool(data, "workers_truncated",
                            total > json_size(&arr) || ro->untracked > 0);
    (void)json_push_kv_int(data, "alive_window_s", FMC_WORKER_ALIVE_WINDOW_S);
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
 * within FMC_SESSION_ALIVE_WINDOW_S of that row's own ts, stale past it (with the
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
    {"head", "head", FMC_PV_WORD, 40},
    {"progress", "progress", FMC_PV_TEXT, 96},
    {"blockers", "blockers", FMC_PV_TEXT, 96},
    {"binary_sha256", "binary_sha256", FMC_PV_SHA256, 64},
    {"workers", "workers_reported", FMC_PV_LIST, 96},
    {"spend", "spend_tokens", FMC_PV_INT, 18},
};
#define FMC_PKEYS (sizeof(fmc_pkeys) / sizeof(fmc_pkeys[0]))
#define FMC_PKEY_HOST 0u

struct fmc_session {
    char stream[129];
    char row_sha3[65];
    long long row_offset;
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
           !fmc_has_secret_run(val, (strcmp(k->key, "source") == 0 || strcmp(k->key, "head") == 0));
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
    s->row_offset = v->row_offset;
    (void)snprintf(s->stream, sizeof(s->stream), "%s", v->stream);
    (void)snprintf(s->row_sha3, sizeof(s->row_sha3), "%s", v->row_sha3);
    (void)snprintf(s->ts, sizeof(s->ts), "%.39s", v->ts);
    fmc_presence_parse(s, v->body);
}

/* A string, or "UNKNOWN" when empty. */
static bool fmc_put_known(struct json_value *o, const char *key,
                          const char *s)
{
    return json_push_kv_str(o, key, s && s[0] ? s : "UNKNOWN");
}

/* A number, or "UNKNOWN" when negative (unknown). */
static bool fmc_put_known_int(struct json_value *o, const char *key,
                              long long v)
{
    if (v >= 0)
        return json_push_kv_int(o, key, v);
    else
        return json_push_kv_str(o, key, "UNKNOWN");
}

static const char *fmc_session_state(const struct fmc_session *s,
                                     long long age, bool cut, char *why,
                                     size_t cap)
{
    const char *state = "UNKNOWN";
    if (!s->seen)
        /* On a cut pass the note may stand in the rows not read, so the
         * absence is not of the whole mailbox. */
        (void)snprintf(why, cap, cut
                           ? "no note row under ref presence-%s in the rows "
                             "this pass read (cut: older rows unread)"
                           : "no note row under ref presence-%s in the "
                             "mail this host pulls",
                       s->role);
    else if (age < 0)
        (void)snprintf(why, cap, "%s",
                       "presence row carries no parseable ts");
    else if (age <= FMC_SESSION_ALIVE_WINDOW_S)
        (void)snprintf(why, cap, "presence row %llds old, within the "
                       "%llds window", age, FMC_SESSION_ALIVE_WINDOW_S);
    else
        (void)snprintf(why, cap, "presence row %llds old, older than the "
                       "%llds window", age, FMC_SESSION_ALIVE_WINDOW_S);
    if (s->seen && age >= 0)
        state = age <= FMC_SESSION_ALIVE_WINDOW_S ? "live" : "stale";
    if (s->seen && !s->parsed) {
        size_t used = strlen(why);
        (void)snprintf(why + used, cap - used, "%s",
                       "; body is not a presence.v1 line, fields UNKNOWN");
    }
    return state;
}

/* Presence freshness does not establish an executing turn. Only explicit
 * recognized phases count as reported activity; absent or unfamiliar phases
 * stay unknown. Stale reports cannot establish current activity. */
static const char *fmc_session_activity(const struct fmc_session *s,
                                       long long age)
{
    const char *phase = "";
    size_t i;
    if (!s->seen || !s->parsed || age < 0)
        return "UNKNOWN";
    for (i = 0; i < FMC_PKEYS; i++)
        if (strcmp(fmc_pkeys[i].key, "phase") == 0)
            phase = s->val[i];
    if (strcmp(phase, "completed") == 0)
        return "completed";
    if (age > FMC_SESSION_ALIVE_WINDOW_S)
        return "stale";
    if (strcmp(phase, "blocked") == 0)
        return "blocked";
    if (strcmp(phase, "idle") == 0)
        return "idle";
    if (strcmp(phase, "active") == 0 || strcmp(phase, "running") == 0 ||
        strcmp(phase, "build") == 0 || strcmp(phase, "test") == 0 ||
        strcmp(phase, "busy") == 0)
        return "busy";
    return "UNKNOWN";
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
    const char *state = fmc_session_state(s, age, ro->window_cut, why,
                                          sizeof(why));
    json_init(&o);
    json_set_object(&o);
    (void)json_push_kv_str(&o, "role", s->role);
    (void)json_push_kv_str(&o, "state", state);
    (void)json_push_kv_str(&o, "activity", fmc_session_activity(s, age));
    (void)json_push_kv_str(&o, "reason", why);
    fmc_put_known(&o, "format", s->seen ? (s->parsed ? FMC_PRESENCE_TAG
                                                     : "unparsed")
                                        : "");
    fmc_session_fields(&o, s);
    fmc_put_known(&o, "last_observed_ts", age >= 0 ? s->ts : "");
    fmc_put_known_int(&o, "age_s", age);
    fmc_put_known(&o, "observed_via", s->seen ? "dev.agent.mail pull" : "");
    fmc_put_known(&o, "observed_stream", s->stream);
    if (s->stream[0] && s->row_sha3[0] && s->row_offset >= 0) {
        (void)json_push_kv_str(&o, "stream", s->stream);
        (void)json_push_kv_str(&o, "row_sha3", s->row_sha3);
        (void)json_push_kv_int(&o, "row_offset", s->row_offset);
        (void)json_push_kv_int(&o, "seq", s->seq);
    }
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
    /* Exact only over a whole pass: a worker seen before a cut window is
     * not summed, and one inside it sums only the receipts there. */
    (void)json_push_kv_bool(&o, "tokens_total_exact",
                            unknown == 0 && ro->untracked == 0 &&
                                !ro->window_cut);
    (void)json_push_kv_int(&o, "workers_counted", counted);
    (void)json_push_kv_int(&o, "workers_without_receipt", unknown);
    (void)json_push_kv_str(&o, "reservations", "UNKNOWN");
    (void)json_push_kv_str(&o, "reason",
                           "sum of workers[] tokens_total from run receipts; "
                           "no existing source records Muse reservations");
    (void)json_push_kv(data, "muse_spend", &o);
    json_free(&o);
}

/* Emitted in snapshots only: a forward page's caller-chosen byte budget
 * belongs to its changes, and these fixed scalars cannot be trimmed. */
#define FMC_DIRECTIVE_DEFINITION \
    "open_worker_directives: among the newest 64 directives in the rows " \
    "this brief read of this host's mail, those addressed to a worker " \
    "(not '*', not an owner name) with no " \
    "later result from the addressee or back to the origin, no later " \
    "'closed by sender:' note or result from the origin or an owner, and not " \
    "recipient_gone (no ack or read covers it, the recipient posted a " \
    "presence-<name> note here, and its newest presence note or row whose " \
    "from is that name is older " \
    "than 86400 s). overdue_worker_directives: the open ones this host sent " \
    "with no receiver evidence after 120 s. Directives carry no deadline. " \
    "On a brief whose mail pass was cut (evidence.mail_window_cut), a " \
    "directive stamped at or before evidence.mail_window_reach_ts (any " \
    "such directive, when no reach is known) that nothing read answers, " \
    "closes or acknowledges is unresolved: counted in " \
    "directive_counts.unresolved, in neither open number, never " \
    "overdue; a change row shown for it carries next_action, the latest " \
    "row held under its ref."

static bool fmc_directive_queue_emit(struct json_value *data,
                                     const struct fmc_directive_tally *t)
{
    struct json_value q;
    bool ok = true;
    json_init(&q);
    json_set_array(&q);
    for (size_t i = 0; ok && i < t->nq; i++) {
        struct json_value e;
        json_init(&e);
        json_set_object(&e);
        ok = json_push_kv_str(&e, "to", t->q[i].to) &&
             json_push_kv_int(&e, "open", t->q[i].open) &&
             fmc_put_known_int(&e, "oldest_age_s", t->q[i].oldest_age_s) &&
             json_push_back(&q, &e);
        json_free(&e);
    }
    ok = ok && json_push_kv(data, "directive_queue", &q) &&
         json_push_kv_bool(data, "directive_queue_truncated", t->q_untracked > 0);
    json_free(&q);
    return ok;
}

/* The directive backlog: one defined number a dashboard reads
 * (open_worker_directives), its overdue part, the other classes apart.
 * Snapshots only; a forward page carries changes. */
static void fmc_directives_emit(struct json_value *data,
                                const struct fmc_directive_tally *t)
{
    struct json_value o;
    if (t->forward_page)
        return;
    json_init(&o);
    json_set_object(&o);
    const struct { const char *key; long long v; } n[] = {
        {"scanned", t->scanned}, {"answered", t->answered},
        {"closed", t->closed}, {"recipient_gone", t->gone},
        {"broadcast", t->broadcast}, {"broadcast_open", t->broadcast_open},
        {"owner", t->owner}, {"owner_open", t->owner_open},
        {"scan_window", FMC_DIRECTIVE_SCAN},
        {"recipient_gone_after_s", FMC_RECIPIENT_GONE_S},
        {"overdue_after_s", FMC_QUEUED_STALE_S},
        {"queue_recipients_untracked", t->q_untracked}};
    bool ok = true;
    for (size_t i = 0; i < sizeof(n) / sizeof(n[0]); i++)
        ok &= json_push_kv_int(&o, n[i].key, n[i].v);
    /* Present only when some directive was unresolved (a cut pass). */
    if (t->unresolved > 0)
        ok &= json_push_kv_int(&o, "unresolved", t->unresolved);
    char owners[72];
    (void)snprintf(owners, sizeof(owners), "%.64s", fmc_owner_names());
    ok &= json_push_kv_str(&o, "owner_names", owners);
    ok = ok && json_push_kv_int(data, "open_worker_directives", t->open_worker) &&
         json_push_kv_int(data, "overdue_worker_directives", t->overdue_worker) &&
         json_push_kv_str(data, "directive_definition", FMC_DIRECTIVE_DEFINITION) &&
         json_push_kv(data, "directive_counts", &o) &&
         fmc_directive_queue_emit(data, t);
    json_free(&o);
    if (!ok)
        LOG_ERROR(FMC_LOG, "directive backlog projection incomplete (%s)", FMC_LEAF);
}

/* sessions[] plus its bound, after workers[] so the local worker's
 * receipt tokens are filled before they are summed. */
static void fmc_sessions_emit(struct json_value *data,
                              const struct fmc_roster *ro, long long now)
{
    struct json_value arr;
    size_t i, active = 0;
    json_init(&arr);
    json_set_array(&arr);
    for (i = 0; ro->ss && i < ro->nss && i < FMC_SESSION_CAP; i++) {
        fmc_session_emit(&arr, &ro->ss[i], ro, now);
        if (strcmp(fmc_session_activity(&ro->ss[i],
                       fmc_age_s(now, ro->ss[i].ts)), "busy") == 0)
            active++;
    }
    (void)json_push_kv(data, "sessions", &arr);
    (void)json_push_kv_int(data, "sessions_total",
                           (long long)(ro->nss + ro->ss_untracked));
    (void)json_push_kv_bool(data, "sessions_truncated",
                            ro->nss + ro->ss_untracked > json_size(&arr));
    (void)json_push_kv_str(data, "presence_format", FMC_PRESENCE_TAG);
    (void)json_push_kv_int(data, "sessions_active_reported", (long long)active);
    (void)json_push_kv_str(data, "sessions_active_basis",
                           "first bounded session rows before reply trimming, "
                           "with fresh recognized active phases; self-reports, "
                           "not model-turn proof or a complete fleet count");
    json_free(&arr);
    fmc_spend_emit(data, ro);
    fmc_directives_emit(data, &ro->dt);
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
 *   answered  a later `result` row under the same ref from the other side
 *             (or under that ref with one `-result` token inserted, the
 *             form a directive prescribes for its reply, e.g.
 *             `go-A-20260918-v1` answered by `go-A-result-20260918-v1`):
 *             written by the addressee (answer_match "addressee"), or
 *             addressed back to the origin by anyone but the origin itself
 *             (answer_match "reply_to_origin" — every box posts as its Unix
 *             user, so the reply's author need not carry the role name);
 *             an attempt= stated on both sides must agree;
 *   state     answered, closed, ambiguous, recipient_gone, else acked, else
 *             queued (see fmc_directive_resolve); on a cut pass,
 *             unresolved replaces recipient_gone and queued at or before
 *             the reach (fmc_directive_window).
 *             Unbound reply-to-origin matches are marked as heuristics.
 * sent_ts/sent_age_s are the directive's own time; answer_ts/answer_age_s
 * the reply's. The lifecycle `state` beside it keeps its closed
 * vocabulary; a reply never becomes an ack there either unless it came
 * from the addressee by name, as before. */

struct fmc_answer {
    const char *observed_disposition;
    const struct fmc_row *row;
    struct fmc_row keep;
    const char *match;
    bool ambiguous;
};

static bool fmc_attempt_unique(const char *body)
{
    unsigned count = 0;
    for (const char *p = body; p && *p; ) {
        if (strncmp(p, "attempt=", 8) == 0 && ++count > 1) return false;
        p = strchr(p, '\n');
        if (p) p++;
    }
    return true;
}

static bool fmc_attempt_agrees(const char *a, const char *b)
{
    char buf[24];
    bool has_a = fmc_body_kv(a, "attempt", buf, sizeof(buf));
    bool has_b = fmc_body_kv(b, "attempt", buf, sizeof(buf));
    long long x = fmc_body_int(a, "attempt");
    long long y = fmc_body_int(b, "attempt");
    if (!fmc_attempt_unique(a) || !fmc_attempt_unique(b) ||
        (has_a && x < 0) || (has_b && y < 0)) return false;
    return !has_a || !has_b || x == y;
}

static bool fmc_reply_calendar_valid(const char *ts)
{
    static const int days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    if (!fmc_ts_shape_ok(ts)) return false;
    long long year = fmc_num(ts, 4), month = fmc_num(ts + 5, 2), day = fmc_num(ts + 8, 2);
    if (month < 1 || month > 12 || day < 1) return false;
    bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    return day <= days[month - 1] + (month == 2 && leap);
}

/* Later records can resolve an earlier directive; unknown or equal-second
 * times cannot prove order, irrespective of sequence values from other streams. */
static bool fmc_reply_compatible(const struct fmc_row *directive, const struct fmc_row *reply)
{
    long long dt = fmc_ts_unix(directive->ts), rt = fmc_ts_unix(reply->ts);
    return dt >= 0 && rt >= 0 && rt > dt &&
        fmc_reply_calendar_valid(directive->ts) && fmc_reply_calendar_valid(reply->ts) &&
        fmc_attempt_agrees(directive->body, reply->body);
}

/* True when reply ref rref answers directive ref dref: equal, or dref
 * with one `-result` token inserted at a `-` boundary or at its end. */
static bool fmc_ref_answers(const char *dref, const char *rref)
{
    static const char tag[] = "-result";
    const size_t tl = sizeof(tag) - 1u;
    const char *p;
    if (strcmp(rref, dref) == 0)
        return true;
    for (p = strstr(rref, tag); p; p = strstr(p + 1, tag)) {
        size_t pre = (size_t)(p - rref);
        if (p[tl] != '\0' && p[tl] != '-')
            continue;
        if (strncmp(rref, dref, pre) == 0 && strcmp(p + tl, dref + pre) == 0)
            return true;
    }
    return false;
}

/* How r answers directive d, or NULL when it does not. */
static const char *fmc_answer_match(const struct fmc_row *d,
                                    const struct fmc_row *r)
{
    /* A closure note never answers, even as a result to the origin. */
    if (strcmp(r->kind, "result") != 0 || !fmc_ref_answers(d->ref, r->ref) ||
        strcmp(r->from, d->from) == 0 ||
        strncmp(r->body, FMC_CLOSE_PREFIX, sizeof(FMC_CLOSE_PREFIX) - 1u) == 0)
        return NULL;
    if (!fmc_reply_compatible(d, r))
        return NULL;
    if (strcmp(r->from, d->to) == 0)
        return fmc_reply_addressed(d, r) ? "addressee" : NULL;
    return strcmp(r->to, d->from) == 0 ? "reply_to_origin" : NULL;
}

/* Distinct source rows remain distinct even when their directive text agrees. */
static bool fmc_same_source_row(const struct fmc_row *a, const struct fmc_row *b)
{
    return a->stream[0] && a->row_sha3[0] && a->row_offset >= 0 &&
        a->row_end > a->row_offset && a->seq == b->seq &&
        a->row_offset == b->row_offset && a->row_end == b->row_end &&
        !strcmp(a->stream, b->stream) && !strcmp(a->row_sha3, b->row_sha3);
}

/* One linear pass per directive; same-attempt candidates are tracked apart
 * so a reply with an explicit attempt may disambiguate them. */
static struct fmc_reply_conflicts fmc_reply_conflicts(const struct json_value *rows,
                                                      const struct fmc_row *d)
{
    struct fmc_reply_conflicts c = {0};
    size_t n = rows && rows->type == JSON_ARR ? json_size(rows) : 0u;
    for (size_t i = 0; i < n; i++) {
        struct fmc_row other;
        if (!fmc_rows_at(rows, i, &other) ||
            strcmp(other.kind, "directive") != 0 ||
            strcmp(other.from, d->from) != 0 || strcmp(other.ref, d->ref) != 0 ||
            fmc_same_source_row(d, &other)) continue;
        bool same = strcmp(other.to, d->to) == 0;
        c.any = true;
        if (same) c.target = true;
        if (fmc_attempt_agrees(d->body, other.body)) {
            c.attempt_any = true;
            if (same) c.attempt_target = true;
        }
    }
    return c;
}

static bool fmc_reply_conflicting(const struct fmc_reply_conflicts *c,
                                  const struct fmc_row *d,
                                  const struct fmc_row *r, bool direct)
{
    char a[24], b[24];
    bool bound = fmc_body_kv(d->body, "attempt", a, sizeof(a)) &&
                 fmc_body_kv(r->body, "attempt", b, sizeof(b));
    bool target = bound ? c->attempt_target : c->target;
    bool any = bound ? c->attempt_any : c->any;
    return target || (!direct && any);
}

/* The newest answer to d among the pulled rows. */
static bool fmc_answer_find(const struct json_value *rows,
                            const struct fmc_row *d, struct fmc_answer *a)
{
    size_t n = rows && rows->type == JSON_ARR ? json_size(rows) : 0u, i;
    a->row = NULL;
    a->match = NULL;
    a->observed_disposition = NULL;
    a->ambiguous = false;
    struct fmc_reply_conflicts conflicts = fmc_reply_conflicts(rows, d);
    for (i = 0; d->ref[0] && i < n; i++) {
        struct fmc_row r;
        const char *m;
        if (!fmc_rows_at(rows, i, &r))
            continue;
        m = fmc_answer_match(d, &r);
        if (m && r.observed_disposition[0]) {
            if (!fmc_reply_conflicting(&conflicts, d, &r, !strcmp(m, "addressee")))
                a->observed_disposition = r.observed_disposition;
            continue;
        }
        if (m && fmc_reply_conflicting(&conflicts, d, &r, !strcmp(m, "addressee"))) {
            a->ambiguous = true;
            continue;
        }
        if (!m || (a->row && strcmp(r.ts, a->keep.ts) <= 0))
            continue;
        a->keep = r;
        a->row = &a->keep;
        a->match = m;
    }
    return a->row != NULL;
}

/* ── directive close and expiry ──────────────────────────────────────────
 *
 * A sender (or an owner) closes its own directive with a new row; nothing
 * is rewritten. A recipient that announced itself as a presence session
 * (a presence-<name> note) and then wrote nothing, presence or mail, for
 * FMC_RECIPIENT_GONE_S expires the directive. A name with no presence row
 * has no session liveness to lose, so it never expires. Both read only the rows the
 * brief already pulled, in one pass, and only when no answer exists. */

struct fmc_close {
    struct fmc_row keep;
    bool found;
    long long last_seen;
    long long last_presence;
};

struct fmc_dstatus {
    const char *cls;
    const char *state;
    struct fmc_answer a;
    struct fmc_close c;
};

/* The reason after FMC_CLOSE_PREFIX, as one closed word. */
static const char *fmc_close_reason(const char *body)
{
    const char *p = body + sizeof(FMC_CLOSE_PREFIX) - 1u;
    while (*p == ' ')
        p++;
    if (strncmp(p, "superseded", 10) == 0)
        return "superseded";
    if (strncmp(p, "recipient gone", 14) == 0)
        return "recipient_gone";
    if (strncmp(p, "withdrawn", 9) == 0)
        return "withdrawn";
    return "other";
}

/* Who may close d: an owner name, or the origin by name. A sender binding is
 * a fixed digest the directive row already shows, so it proves nothing and
 * is not required; a closure must not depend on a grant that can expire or
 * live on another host. */
static bool fmc_close_author_ok(const struct fmc_row *d, const struct fmc_row *r)
{
    if (fmc_owner_name(r->from))
        return true;
    if (strcmp(r->from, d->from) != 0)
        return false;
    return true;
}

/* A closure is dated before d, or at the same second but not later in the
 * same stream. ts has one-second resolution, so seq breaks the tie. */
static bool fmc_closure_before(const struct fmc_row *d, const struct fmc_row *r)
{
    long long dt = fmc_ts_unix(d->ts), rt = fmc_ts_unix(r->ts);
    if (dt < 0 || rt < 0 || !fmc_reply_calendar_valid(d->ts) ||
        !fmc_reply_calendar_valid(r->ts))
        return true;
    if (rt != dt)
        return rt < dt;
    return !(d->stream[0] && strcmp(r->stream, d->stream) == 0 && r->seq > d->seq);
}

/* True when r closes d: a later note or result under the same ref, from
 * the origin or an owner, whose body starts with FMC_CLOSE_PREFIX. */
static bool fmc_close_match(const struct fmc_row *d, const struct fmc_row *r)
{
    if (strcmp(r->kind, "note") != 0 && strcmp(r->kind, "result") != 0)
        return false;
    if (!d->ref[0] || r->observed_disposition[0] || strcmp(r->ref, d->ref) != 0 ||
        fmc_closure_before(d, r))
        return false;
    if (!fmc_close_author_ok(d, r))
        return false;
    return strncmp(r->body, FMC_CLOSE_PREFIX, sizeof(FMC_CLOSE_PREFIX) - 1u) == 0 &&
           fmc_attempt_agrees(d->body, r->body);
}

/* Fold r into the recipient's newest presence note and newest own row. */
static void fmc_recipient_seen(const struct fmc_row *d, const struct fmc_row *r,
                               struct fmc_close *c)
{
    const char *role = fmc_presence_role(r);
    bool presence = role && strcmp(role, d->to) == 0;
    if (!presence && strcmp(r->from, d->to) != 0)
        return;
    long long t = fmc_ts_unix(r->ts);
    if (t > c->last_seen)
        c->last_seen = t;
    if (presence && t > c->last_presence)
        c->last_presence = t;
}

/* One pass: d's newest closure and its recipient's newest rows. */
static void fmc_close_find(const struct json_value *rows,
                           const struct fmc_row *d, struct fmc_close *c)
{
    size_t n = rows && rows->type == JSON_ARR ? json_size(rows) : 0u;
    c->found = false;
    c->last_seen = -1;
    c->last_presence = -1;
    for (size_t i = 0; i < n; i++) {
        struct fmc_row r;
        if (!fmc_rows_at(rows, i, &r))
            continue;
        fmc_recipient_seen(d, &r, c);
        if (fmc_close_match(d, &r) && (!c->found || strcmp(r.ts, c->keep.ts) > 0)) {
            c->keep = r;
            c->found = true;
        }
    }
}

/* Receiver evidence with no time on it: an ack, a typed read or a read
 * file covering d. Evaluated only when expiry is otherwise due. */
static bool fmc_dir_covered(const struct json_value *rows,
                            const struct fmc_row *d, bool acked,
                            struct zcl_fleet_typed_index *index)
{
    return acked || fmc_read_covers(d) || fmc_typed_read_indexed(rows, d, index) != NULL;
}

static bool fmc_recipient_gone(const struct json_value *rows,
                               const struct fmc_row *d,
                               const struct fmc_dstatus *st, long long now,
                               bool acked, struct zcl_fleet_typed_index *index)
{
    return strcmp(st->cls, "worker") == 0 && st->c.last_presence >= 0 &&
           now - st->c.last_seen > FMC_RECIPIENT_GONE_S &&
           !fmc_dir_covered(rows, d, acked, index);
}

/* answered, closed, ambiguous, recipient_gone, acked, queued, unresolved:
 * a real answer wins over a closure, a closure over everything else. */
static void fmc_directive_resolve(const struct json_value *rows,
                                  const struct fmc_row *d, long long now,
                                  bool acked, struct fmc_dstatus *st,
                                  struct zcl_fleet_typed_index *index)
{
    st->cls = fmc_directive_class(d);
    st->c.found = false;
    st->c.last_seen = -1;
    st->c.last_presence = -1;
    if (fmc_answer_find(rows, d, &st->a)) {
        st->state = "answered";
        return;
    }
    fmc_close_find(rows, d, &st->c);
    if (st->c.found)
        st->state = "closed";
    else if (st->a.ambiguous)
        st->state = "ambiguous";
    else if (fmc_recipient_gone(rows, d, st, now, acked, index))
        st->state = "recipient_gone";
    else
        st->state = acked ? "acked" : "queued";
}

/* What a cut pass cannot know. A directive at or before the reach that
 * nothing read answers or closes is unresolved, from queued (its answer
 * may stand in the rows not read) and from recipient_gone (the
 * recipient's newer rows may stand there). */
static void fmc_directive_window(struct fmc_dstatus *st, bool past)
{
    if (past && (!strcmp(st->state, "queued") ||
                 !strcmp(st->state, "recipient_gone")))
        st->state = "unresolved";
}

static bool fmc_dstate_open(const char *state)
{
    return strcmp(state, "answered") != 0 && strcmp(state, "closed") != 0 &&
           strcmp(state, "recipient_gone") != 0 &&
           strcmp(state, "unresolved") != 0;
}

/* The closure and expiry facts beside a directive's reply state. */
static bool fmc_reply_close_emit(struct json_value *o,
                                 const struct fmc_dstatus *st, long long now)
{
    bool ok = json_push_kv_str(o, "class", st->cls);
    if (strcmp(st->state, "closed") == 0) {
        ok &= json_push_kv_str(o, "close_reason", fmc_close_reason(st->c.keep.body));
        ok &= fmc_put_known(o, "closed_by", st->c.keep.from);
        ok &= fmc_put_known(o, "close_ts", st->c.keep.ts);
        ok &= fmc_put_known_int(o, "close_age_s", fmc_age_s(now, st->c.keep.ts));
    }
    if (strcmp(st->state, "recipient_gone") == 0)
        ok &= fmc_put_known_int(o, "recipient_silent_s", now - st->c.last_seen);
    return ok;
}

/* The reply object for one directive change row. */
static bool fmc_reply_disposition(struct json_value *out, const char *typed,
                                  const struct fmc_answer *answer)
{
    if (!typed && !answer->observed_disposition) return true;
    return json_push_kv_str(out, "observed_disposition",
                            typed ? typed : answer->observed_disposition) &&
           json_push_kv_bool(out, "disposition_verified", typed != NULL);
}

/* How to settle an unresolved row: the exact read by its ref, spelled out
 * when the ref is a name the queue's grammar admits (safe to paste), else
 * in general terms. */
static const char *fmc_unresolved_action(const struct fmc_row *v, char *buf,
                                         size_t cap)
{
    if (!v->ref[0] || !zcl_devagent_name_ok(v->ref))
        return "fleet steer evidence --type=mail --ref=<the row's ref>";
    (void)snprintf(buf, cap, "fleet steer evidence --type=mail --ref=%s", v->ref);
    return buf;
}

/* An unresolved directive (fmc_directive_window) says so in its reply
 * object and names the read that settles it. */
static bool fmc_reply_emit(struct json_value *item, const struct fmc_row *v,
                           const struct json_value *rows, long long now,
                           const char *typed, bool past,
                           struct zcl_fleet_typed_index *index)
{
    struct json_value o;
    struct fmc_dstatus st;
    char action[FMC_REF_MAX + 64];
    bool acked = fmc_row_acked(v) || typed || fmc_alias_ack(v);
    fmc_directive_resolve(rows, v, now, acked, &st, index);
    fmc_directive_window(&st, past);
    const struct fmc_answer *a = &st.a;
    bool answered = strcmp(st.state, "answered") == 0;
    json_init(&o);
    json_set_object(&o);
    bool ok = json_push_kv_str(&o, "state", st.state);
    ok &= json_push_kv_bool(&o, "acked", acked);
    ok &= fmc_reply_close_emit(&o, &st, now);
    ok &= fmc_reply_disposition(&o, typed, a);
    ok &= fmc_put_known(&o, "sent_ts", fmc_ts_unix(v->ts) >= 0 ? v->ts : "");
    ok &= fmc_put_known_int(&o, "sent_age_s", fmc_age_s(now, v->ts));
    ok &= fmc_put_known_int(&o, "answer_seq", answered ? a->row->seq : -1);
    ok &= fmc_put_known(&o, "answer_ts", answered ? a->row->ts : "");
    ok &= fmc_put_known_int(&o, "answer_age_s",
                      answered ? fmc_age_s(now, a->row->ts) : -1);
    ok &= fmc_put_known(&o, "answered_by", answered ? a->row->from : "");
    ok &= fmc_put_known(&o, "answer_match", answered ? a->match : "");
    if (answered)
        ok &= json_push_kv_bool(&o, "answer_heuristic",
                                !strcmp(a->match, "reply_to_origin"));
    if (strcmp(st.state, "unresolved") == 0)
        ok &= json_push_kv_str(&o, "next_action",
                               fmc_unresolved_action(v, action, sizeof(action)));
    if (ok) ok = json_push_kv(item, "reply", &o);
    json_free(&o);
    return ok;
}

/* The exact-read locator of a mail row, when the native pull supplied one. */
static bool fmc_row_locator(struct json_value *item, const struct fmc_row *row)
{
    if (!row->stream[0] || !row->row_sha3[0] || row->row_offset < 0) return true;
    return json_push_kv_str(item, "stream", row->stream) &&
        json_push_kv_str(item, "row_sha3", row->row_sha3) &&
        json_push_kv_int(item, "row_offset", row->row_offset) &&
        json_push_kv_int(item, "row_end", row->row_end);
}

#ifdef ZCL_TESTING
static void (*s_fmc_before_change_projection)(void);
static void (*s_fmc_before_history_copy)(void);
void zcl_fleet_steer_test_set_before_change_projection(void (*hook)(void))
{
    s_fmc_before_change_projection = hook;
}
void zcl_fleet_steer_test_set_before_history_copy(void (*hook)(void))
{
    s_fmc_before_history_copy = hook;
}
#endif

static bool fmc_change_locator_shape(const struct json_value *item, const struct fmc_row *row)
{
    const char *const keys[] = {"stream", "row_sha3", "row_offset", "row_end"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const struct json_value *value = json_get(item, keys[i]);
        if (!value || value->type != (i < 2 ? JSON_STR : JSON_INT)) return false;
    }
    return !strcmp(json_get_str(json_get(item, "stream")), row->stream) &&
        !strcmp(json_get_str(json_get(item, "row_sha3")), row->row_sha3) &&
        json_get_int(json_get(item, "row_offset")) == row->row_offset &&
        json_get_int(json_get(item, "row_end")) == row->row_end;
}

static bool fmc_change_shape(const struct json_value *item, const struct fmc_row *row)
{
    const char *const strings[] = {"from", "to", "kind", "ref", "lead", "state"};
    if (!item || item->type != JSON_OBJ) return false;
    for (size_t i = 0; i < sizeof(strings) / sizeof(strings[0]); i++) {
        const struct json_value *value = json_get(item, strings[i]);
        if (!value || value->type != JSON_STR) return false;
    }
    const struct json_value *seq = json_get(item, "seq");
    if (!seq || seq->type != JSON_INT || json_get_int(seq) != row->seq) return false;
    const struct json_value *age = json_get(item, "queued_age_s");
    if (!age || (age->type != JSON_INT && age->type != JSON_NULL)) return false;
    return !row->stream[0] || fmc_change_locator_shape(item, row);
}

/* One bounded change row, carrying the state fmc_row_state resolves from
 * receiver evidence; completed is resolved later against queue outcomes
 * and board results. queued_age_s is how long a row has sat "queued"
 * (null for every other state, and when its stamp does not parse). A row
 * at or before a cut pass's reach that would read "queued" reads
 * "unresolved": what would show it received may be in the rows not read. */
static bool fmc_row_change(struct json_value *changes, const struct fmc_row *v,
                           const struct json_value *rows,
                           const char *sent_path, long long now, bool past,
                           struct zcl_fleet_typed_index *index)
{
    struct json_value item;
    char lead[FMC_LEAD_MAX + 1];
    const char *typed = fmc_typed_read_indexed(rows, v, index);
    const char *state = fmc_row_state_with_read(v, rows, sent_path, typed);
    bool queued = strcmp(state, "queued") == 0;
    if (past && queued) {
        state = "unresolved";
        queued = false;
    }
#ifdef ZCL_TESTING
    if (s_fmc_before_change_projection) s_fmc_before_change_projection();
#endif
    json_init(&item);
    json_set_object(&item);
    /* A presence body leaves the brief only through sessions[]' parsed
     * whitelist, so its raw lead is never echoed here. */
    if (fmc_presence_role(v))
        (void)snprintf(lead, sizeof(lead), "%s",
                       "presence row; parsed fields in sessions[]");
    else
        fmc_lead(v->body, lead, sizeof(lead));
    const struct { const char *key; const char *value; } fields[] = {
        {"from", v->from}, {"to", v->to}, {"kind", v->kind}, {"ref", v->ref},
        {"lead", lead}, {"state", state}};
    bool ok = json_push_kv_int(&item, "seq", v->seq);
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        ok &= json_push_kv_str(&item, fields[i].key, fields[i].value);
    ok &= fmc_row_locator(&item, v);
    if (v->observed_disposition[0]) {
        ok &= json_push_kv_str(&item, "observed_disposition", v->observed_disposition);
        ok &= json_push_kv_bool(&item, "disposition_verified", false);
    }
    ok &= fmc_put_int(&item, "queued_age_s", queued ? fmc_age_s(now, v->ts) : -1);
    if (!strcmp(v->kind, "directive"))
        ok &= fmc_reply_emit(&item, v, rows, now, typed, past, index);
    ok = ok && fmc_change_shape(&item, v);
    size_t before = json_size(changes);
    if (ok) ok = json_push_back(changes, &item);
    if (ok) ok = json_size(changes) == before + 1 && fmc_change_shape(json_at(changes, before), v);
    json_free(&item);
    return ok;
}

/* dev.agent.mail answers in bounded pages, and every mail reader in this
 * file reads its walk whole: follow next_since until a page says it was
 * the last, appending each page's rows to *rows (an initialized array).
 * FMC_MAIL_PAGES_MAX bounds the walk so a runaway history is an explicit
 * failure, never a silently partial view. NULL on success with *cursor set
 * to the mail leaf's cursor, else the missing[] reason. */
#define FMC_MAIL_PAGES_MAX 4096

/* Refusal reason for a failed page: the leaf's own error code when it
 * named one (so a stale token reads as MAIL_CURSOR_STALE instead of a
 * generic sibling failure), else "sibling_refused". */
static const char *fmc_mail_page_why(const struct fmc_sub *sub,
                                     char *why_buf, size_t why_cap)
{
    if (why_buf && why_cap > 0) {
        if (!fmc_sub_ok(sub) && sub->reply.error.code[0])
            (void)snprintf(why_buf, why_cap, "%s",
                           sub->reply.error.code);
        else
            (void)snprintf(why_buf, why_cap, "sibling_refused");
        return why_buf;
    }
    return "sibling_refused";
}

/* One page after `since` ("" = from the start, else a next_since token)
 * onto *rows. NULL on success, with *more saying whether another page
 * follows and `since` advanced. */
/* Evidence narrows only by work ref: replies and acknowledgments may reverse
 * endpoints or use another kind. Initial floor zero preserves every stream. */
static bool fmc_mail_page_input(struct fmc_sub *sub, const char *since,
                                 const char *ref)
{
    return json_push_kv_str(&sub->input, "action", "pull") &&
        (since[0] ? json_push_kv_str(&sub->input, "since", since)
                  : json_push_kv_int(&sub->input, "since", 0)) &&
        (!ref || json_push_kv_str(&sub->input, "ref", ref));
}

static bool fmc_mail_sources_valid(const struct json_value *data, bool more)
{
    const struct json_value *sources = json_get(data, "sources");
    if (!sources || sources->type != JSON_ARR) return false;
    for (size_t i = 0; i < json_size(sources); i++) {
        const struct json_value *complete = json_get(json_at(sources, i), "complete");
        if (!complete || complete->type != JSON_BOOL ||
            (!more && !json_get_bool(complete))) return false;
    }
    return true;
}

static bool fmc_mail_page_valid(const struct fmc_sub *sub, const char *next,
    const struct json_value *rows, const struct json_value *truncated)
{
    const struct json_value *cursor = json_get(&sub->reply.data, "cursor");
    return fmc_sub_ok(sub) && next && next[0] && strlen(next) < FMC_MAIL_SINCE_CAP &&
        rows && rows->type == JSON_ARR && truncated && truncated->type == JSON_BOOL &&
        cursor && cursor->type == JSON_INT && json_get_int(cursor) >= 0 &&
        fmc_mail_sources_valid(&sub->reply.data, json_get_bool(truncated));
}

#ifdef ZCL_TESTING
static void (*s_fmc_mail_test_hook)(const struct zcl_command_request *,
                                    struct zcl_command_reply *);
void zcl_fleet_steer_test_set_mail_pull(
    void (*hook)(const struct zcl_command_request *, struct zcl_command_reply *))
{
    s_fmc_mail_test_hook = hook;
}
#endif

static void fmc_mail_invoke(struct fmc_sub *sub, bool brief)
{
#ifdef ZCL_TESTING
    if (s_fmc_mail_test_hook && !brief) {
        s_fmc_mail_test_hook(&sub->request, &sub->reply);
        return;
    }
#endif
    if (brief) zcl_native_handle_dev_agent_mail_brief_drain(&sub->request, &sub->reply);
    else zcl_native_handle_dev_agent_mail(&sub->request, &sub->reply);
}

static const char *fmc_mail_page(const struct zcl_command_request *req,
                                 struct json_value *rows, long long *cursor,
                                 char *since, bool *more,
                                 char *why_buf, size_t why_cap,
                                 bool brief_drain, const char *ref,
                                 zcl_devagent_mail_ref_filter keep, void *ctx)
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
    if (!fmc_mail_page_input(&sub, since, ref)) {
        fmc_sub_end(&sub);
        return "allocation_failed";
    }
    if (keep)
        zcl_native_handle_dev_agent_mail_brief_filtered(&sub.request, &sub.reply, keep, ctx);
    else
        fmc_mail_invoke(&sub, brief_drain);
    sub.ran = true;
    tok = json_get(&sub.reply.data, "next_since");
    next = (tok && tok->type == JSON_STR) ? json_get_str(tok) : NULL;
    arr = json_get(&sub.reply.data, "rows");
    tr = json_get(&sub.reply.data, "truncated");
    if (!fmc_mail_page_valid(&sub, next, arr, tr)) {
        const char *why = fmc_mail_page_why(&sub, why_buf, why_cap);
        fmc_sub_end(&sub);
        return why;
    }
    *cursor = fmc_sub_int(&sub, "cursor", -1);
    n = json_size(arr);
#ifdef ZCL_TESTING
    if (keep && s_fmc_before_history_copy) s_fmc_before_history_copy();
#endif
    for (i = 0; i < n; i++) {
        if (!json_push_back(rows, json_at(arr, i))) {
            fmc_sub_end(&sub);
            return "allocation_failed";
        }
    }
    *more = json_get_bool(tr);
    (void)snprintf(since, FMC_MAIL_SINCE_CAP, "%s", next);
    fmc_sub_end(&sub);
    return NULL;
}

/* Drain from `since_init` ("" = from the start, else a next_since token
 * the leaf resumes past) until a page says it was last. On success the end
 * position lands in end_token (when asked): a composite per-stream watermark
 * the caller passes back as `since` to see exactly what arrived after it. */
static const char *fmc_mail_drain_filtered(const struct zcl_command_request *req,
                                       struct json_value *rows,
                                       long long *cursor,
                                       const char *since_init,
                                       char *end_token, size_t end_cap,
                                       char *why_buf, size_t why_cap,
                                       bool brief_drain, const char *ref,
                                       zcl_devagent_mail_ref_filter keep, void *ctx)
{
    char since[FMC_MAIL_SINCE_CAP] = "";
    bool more = true;
    if (since_init && since_init[0])
        (void)snprintf(since, sizeof(since), "%s", since_init);
    for (int page = 0; page < FMC_MAIL_PAGES_MAX && more; page++) {
        const char *why =
            fmc_mail_page(req, rows, cursor, since, &more, why_buf,
                          why_cap, brief_drain, ref, keep, ctx);
        if (why)
            return why;
    }
    if (end_token && end_cap > 0)
        (void)snprintf(end_token, end_cap, "%s", since);
    return more ? "page_limit" : NULL;
}

static const char *fmc_mail_drain_from(const struct zcl_command_request *req,
                                       struct json_value *rows, long long *cursor,
                                       const char *since_init, char *end_token,
                                       size_t end_cap, char *why_buf, size_t why_cap,
                                       bool brief_drain, const char *ref)
{
    return fmc_mail_drain_filtered(req, rows, cursor, since_init, end_token,
                                   end_cap, why_buf, why_cap, brief_drain, ref,
                                   NULL, NULL);
}

static const char *fmc_mail_drain(const struct zcl_command_request *req,
                                  struct json_value *rows, long long *cursor, const char *ref)
{
    return fmc_mail_drain_from(req, rows, cursor, "", NULL, 0, NULL, 0,
                               false, ref);
}

/* The pass over mail every brief that is not compact makes, for the
 * roster, the work list, the directive tallies and the rows a change's
 * state resolves against. It begins each stream at its newest window and
 * never past a position the caller's own token names
 * (zcl_devagent_mail_brief_window), so the rows it parses follow what is
 * still live and not the history. *cut says whether that left older rows
 * unread; when it did, start keeps the token that pass began at (its
 * entries name each cut stream's first row), else start is "". No window,
 * none that cuts anything, or a cut start that fails is the walk from the
 * start as before: whole, cut false, and on failure no better than it
 * ever was (the cut start's reason is logged, not dropped). */
static const char *fmc_mail_pass(const struct zcl_command_request *req,
                                 struct json_value *rows, long long *cursor,
                                 const char *resume, bool resumed,
                                 char *end_token, size_t end_cap,
                                 char *why_buf, size_t why_cap, bool *cut,
                                 char *start, size_t start_cap)
{
    const char *fail = NULL;
    start[0] = '\0';
    if (zcl_devagent_mail_brief_window(start, start_cap,
                                       ZCL_DEVAGENT_MAIL_WINDOW_BYTES,
                                       resumed ? resume : NULL, cut) && *cut) {
        fail = fmc_mail_drain_from(req, rows, cursor, start, end_token,
                                   end_cap, why_buf, why_cap, true, NULL);
        if (!fail)
            return NULL;
        /* `fail`, not why_buf: only a page the leaf refused writes that
         * buffer; the other failures return a static string of their own. */
        LOG_WARN(FMC_LOG, "brief window start refused (%s); reading from the start",
                 fail);
        json_free(rows);
        json_init(rows);
        json_set_array(rows);
        *cursor = -1;
        end_token[0] = '\0';
    }
    *cut = false;
    start[0] = '\0';
    return fmc_mail_drain_from(req, rows, cursor, "", end_token, end_cap,
                               why_buf, why_cap, true, NULL);
}

/* ── the reach of a cut pass ─────────────────────────────────────────────
 *
 * A pass that began inside the history read each cut stream from one
 * position on. What it did not read cannot settle a row it did read, so
 * "nothing found" for a row old enough to have its answer back there is
 * not a finding. The reach is the newest stamp at which any cut stream
 * began: a row stamped after it was sent after every position the pass
 * started from, so what answers it was read.
 *
 * That rests on stamps ascending in each stream's file order. The pull
 * merges the streams' heads by stamp and reads each stream as its file
 * holds it; the leaf lets a transport append a row stamped older than
 * the row before it. A row appended after an answer and stamped older
 * than it leaves the answer unread when the window starts at that row,
 * while a directive stamped between the two reads past the reach:
 * "queued" where the truth is answered. It errs towards alarm.
 *
 * The reach cannot settle a recipient's absence by itself.
 * recipient_gone needs a presence row and a last-seen stamp. Each cut
 * stream keeps every role's newest presence note, and each sender's
 * newest row, in the one window of bytes before its start
 * (fmc_window_keep_presence). One outbox carries every role. The
 * directive scan resolves against those lines without counting them or
 * moving the reach. A row older than that bound is still unread. A
 * worker who never posted a presence note stays open: reading every
 * unseen recipient as unresolved would silence a real alarm to a new
 * worker. A stream appended out of stamp order can still read queued
 * where the truth is answered. */
#define FMC_WINDOW_STREAMS 16u /* the leaf refuses more */
#define FMC_WINDOW_NAME 160u  /* longer than any name the leaf admits */

struct fmc_window_entry {
    char name[FMC_WINDOW_NAME];
    long long off;
    char ts[32];
    bool seen;
};

struct fmc_window {
    bool cut;
    bool known;         /* the first row of every cut stream was read */
    long long reach;    /* its stamp, in seconds; -1 when unknown */
    char reach_ts[32];  /* "" when unknown, and when nothing was cut */
    struct fmc_window_entry e[FMC_WINDOW_STREAMS];
    size_t n;
};

/* One "<stream>:<offset>" entry of the token a cut pass began at. */
static bool fmc_window_entry(struct fmc_window *w, const char *entry)
{
    const char *colon;
    char *end = NULL;
    struct fmc_window_entry *e;
    size_t nlen;
    long long off;
    colon = entry ? strchr(entry, ':') : NULL;
    if (!colon || colon == entry || w->n == FMC_WINDOW_STREAMS)
        return false;
    nlen = (size_t)(colon - entry);
    if (nlen >= sizeof(w->e[0].name))
        return false;
    errno = 0;
    off = strtoll(colon + 1, &end, 10);
    if (errno == ERANGE || !end || *end != '\0' || off < 0)
        return false;
    e = &w->e[w->n++];
    memcpy(e->name, entry, nlen);
    e->name[nlen] = '\0';
    e->off = off;
    return true;
}

/* Every entry of the token, after its integer floor. False when the token
 * is not that shape: the reach then stays unknown. */
static bool fmc_window_entries(struct fmc_window *w, const char *token)
{
    const char *bar = token ? strchr(token, '|') : NULL;
    char entry[192];
    if (!bar || !bar[1])
        return false;
    for (bar++; *bar;) {
        const char *comma = strchr(bar, ',');
        size_t n = comma ? (size_t)(comma - bar) : strlen(bar);
        if (n == 0 || n >= sizeof(entry))
            return false;
        memcpy(entry, bar, n);
        entry[n] = '\0';
        if (!fmc_window_entry(w, entry))
            return false;
        if (!comma)
            break;
        bar = comma + 1;
    }
    return true;
}

/* The pass began at `token` when it was cut: keep its entries, or none
 * (an unknown reach) when the token is not that shape. */
static void fmc_window_begin(struct fmc_window *w, bool cut, const char *token)
{
    memset(w, 0, sizeof(*w));
    w->cut = cut;
    if (cut && !fmc_window_entries(w, token))
        w->n = 0;
}

/* The cut stream's first row, once that row is among the pass's: the
 * entry it begins (the stream it names, at the position that stream's
 * window began, not noted yet), else NULL. `row` is an object. */
static struct fmc_window_entry *fmc_window_at(struct fmc_window *w,
                                              const struct json_value *row)
{
    const struct json_value *s = json_get(row, "stream");
    const struct json_value *o = json_get(row, "row_offset");
    if (!s || s->type != JSON_STR || !o || o->type != JSON_INT)
        return NULL;
    for (size_t i = 0; i < w->n; i++) {
        struct fmc_window_entry *e = &w->e[i];
        if (e->off > 0 && !e->seen && json_get_int(o) == e->off &&
            strcmp(e->name, json_get_str(s)) == 0)
            return e;
    }
    return NULL;
}

/* One row of the pass: when it begins exactly where a cut stream began it
 * is the oldest row read there, so its stamp is kept. */
static void fmc_window_note(struct fmc_window *w, const struct json_value *row)
{
    struct fmc_window_entry *e;
    const struct json_value *t;
    if (!row || row->type != JSON_OBJ)
        return;
    e = fmc_window_at(w, row);
    if (!e)
        return;
    t = json_get(row, "ts");
    if (!t || t->type != JSON_STR || !json_get_str(t))
        return;
    (void)snprintf(e->ts, sizeof(e->ts), "%s", json_get_str(t));
    e->seen = true;
}

/* The reach, once the pass has read its rows: the newest stamp at which a
 * cut stream began, known only when every cut stream's first row was
 * among them with a stamp that parses. It is the view's window evidence. */
static void fmc_window_finish(struct fmc_window *w, const struct json_value *rows,
                              struct fmc_mail_view *view)
{
    size_t i, n = rows && rows->type == JSON_ARR ? json_size(rows) : 0u;
    w->known = false;
    w->reach = -1;
    w->reach_ts[0] = '\0';
    if (!w->cut)
        return;
    for (i = 0; i < n; i++)
        fmc_window_note(w, json_at(rows, i));
    for (i = 0; i < w->n; i++) {
        long long t = w->e[i].seen ? fmc_ts_unix(w->e[i].ts) : -1;
        if (w->e[i].off <= 0)
            continue;
        if (t < 0) {
            w->reach = -1;
            w->reach_ts[0] = '\0';
            break;
        }
        if (t > w->reach) {
            w->reach = t;
            (void)snprintf(w->reach_ts, sizeof(w->reach_ts), "%s", w->e[i].ts);
        }
    }
    w->known = w->reach >= 0;
    (void)snprintf(view->window_reach_ts, sizeof(view->window_reach_ts),
                   "%s", w->reach_ts);
}

/* Whether a row may have its answer among the rows a cut pass did not
 * read: it is stamped at or before the reach. A reach that is not known,
 * or a stamp that does not parse, reads the same way. False whenever
 * nothing was cut. */
static bool fmc_window_past(const struct fmc_window *w, const struct fmc_row *v)
{
    long long t;
    if (!w->cut)
        return false;
    if (!w->known)
        return true;
    t = fmc_ts_unix(v->ts);
    return t < 0 || t <= w->reach;
}

/* ── landing observations ────────────────────────────────────────────────
 *
 * The host that runs the land queue posts one typed note per landing event
 * to * under the candidate's tip. A host that runs no queue has no status
 * to read, and before this list only a result or claim row's `landed=` line
 * said a landing had happened: a candidate without one read
 * `landing-unattested`. Each typed note
 * the mail pass reads is one observation, newest note per tip, carrying the
 * locator that returns that exact note. A note states what its sender
 * wrote; none of it is a verified landing. */
#define FMC_LANDING_CAP 16u
#define FMC_LANDING_STATE 24u
/* note= with room for one character past the longest name the candidate
 * registry admits, so a value cut by the bound cannot pass as a name. */
#define FMC_LANDING_NOTE (ZCL_FMC_CAND_ID_CAP + 1u)

/* The typed lines of one landing note. */
struct fmc_landing_note {
    char event[8];
    char state[FMC_LANDING_STATE];
    char note[FMC_LANDING_NOTE];
    long long attempt;
};

/* One tip's newest note. The strings are copies: the pull's reply that the
 * parsed row borrows from does not outlive the pass. */
struct fmc_landing {
    char ref[41];
    char event[8];
    char state[FMC_LANDING_STATE];
    char note[FMC_LANDING_NOTE];
    char ts[32];
    char stream[129];
    char row_sha3[65];
    long long row_offset;
    long long seq;
    long long attempt;
    long long age;   /* seconds; -1 when the stamp does not parse */
    unsigned notes;  /* typed notes read for this tip */
};

/* Newest first, in the order the pass read them. */
struct fmc_landings {
    struct fmc_landing row[FMC_LANDING_CAP];
    size_t n;
    bool more; /* typed notes were read for tips the list does not carry */
};

static void fmc_landings_init(struct fmc_landings *l)
{
    memset(l, 0, sizeof(*l));
}

/* An exact copy that fits, or "" when it does not: never a cut value. */
static void fmc_landing_copy(char *dst, size_t cap, const char *src)
{
    if (!src || strlen(src) >= cap) {
        dst[0] = '\0';
        return;
    }
    memcpy(dst, src, strlen(src) + 1);
}

/* The queue's three landing events. */
static bool fmc_landing_event(const char *event)
{
    return strcmp(event, "queued") == 0 || strcmp(event, "phase") == 0 ||
           strcmp(event, "outcome") == 0;
}

/* The sender, the kind and the ref of a landing note: the queue's own
 * sender, a note, and a tip as the ref. Its free-text notes under other
 * refs are not landing events. */
static bool fmc_landing_sender_ok(const struct fmc_row *v)
{
    return strcmp(v->from, "dev.land") == 0 && strcmp(v->kind, "note") == 0 &&
           strlen(v->ref) == 40 && fmc_all_hex(v->ref, 40);
}

/* The typed lines, each present whole where the queue always writes a
 * value: one cut by the bound is no value, as with every other field here.
 * `note=` may be empty. */
static bool fmc_landing_fields(struct fmc_landing_note *n,
                               const struct fmc_row *v)
{
    char event[sizeof(n->event) + 1] = {0}, state[sizeof(n->state) + 1] = {0};
    char tip[48] = {0};
    bool ok = fmc_body_kv(v->body, "land", event, sizeof(event)) &&
              fmc_body_kv(v->body, "state", state, sizeof(state)) &&
              fmc_body_kv(v->body, "tip", tip, sizeof(tip));
    n->attempt = fmc_body_int(v->body, "attempt");
    (void)fmc_body_kv(v->body, "note", n->note, sizeof(n->note));
    fmc_landing_copy(n->event, sizeof(n->event), event);
    fmc_landing_copy(n->state, sizeof(n->state), state);
    /* The note's tip is its row's ref: the queue writes both from one
     * value, so another tip is no observation of this ref. */
    return ok && fmc_landing_event(n->event) && n->state[0] && tip[0] &&
           strcmp(tip, v->ref) == 0 && n->attempt >= 0;
}

/* One mail row as a typed landing note, or false when it is none. The
 * filter is by shape, never by trust in the sender's claim. */
static bool fmc_landing_typed(const struct fmc_row *v,
                              struct fmc_landing_note *n)
{
    if (!v)
        return false;
    memset(n, 0, sizeof(*n));
    return fmc_landing_sender_ok(v) && fmc_landing_fields(n, v);
}

static struct fmc_landing *fmc_landing_find(struct fmc_landings *l,
                                            const char *ref)
{
    for (size_t i = 0; i < l->n; i++)
        if (strcmp(l->row[i].ref, ref) == 0)
            return &l->row[i];
    return NULL;
}

/* One note into its row, with the locator of the mail row that carried
 * it. A note too long to be a name is no note to show either. */
static void fmc_landing_fill(struct fmc_landing *r,
                             const struct fmc_landing_note *n,
                             const struct fmc_row *v, long long now)
{
    memset(r, 0, sizeof(*r));
    fmc_landing_copy(r->ref, sizeof(r->ref), v->ref);
    fmc_landing_copy(r->event, sizeof(r->event), n->event);
    fmc_landing_copy(r->state, sizeof(r->state), n->state);
    if (strlen(n->note) < ZCL_FMC_CAND_ID_CAP)
        fmc_landing_copy(r->note, sizeof(r->note), n->note);
    /* A stamp of another shape is not shown cut: it stays unknown. */
    fmc_landing_copy(r->ts, sizeof(r->ts),
                     fmc_ts_shape_ok(v->ts) ? v->ts : NULL);
    fmc_landing_copy(r->stream, sizeof(r->stream), v->stream);
    fmc_landing_copy(r->row_sha3, sizeof(r->row_sha3), v->row_sha3);
    r->row_offset = v->row_offset;
    r->seq = v->seq;
    r->attempt = n->attempt;
    r->age = fmc_age_s(now, v->ts);
}

/* One typed note. The pass reads newest first, so the first note read for
 * a tip is its newest: it fills the row, and each later note of that tip
 * only counts. The list keeps the newest FMC_LANDING_CAP tips; a note for
 * any other tip only says the list is not all the window holds. */
static void fmc_landing_note(struct fmc_landings *l,
                             const struct fmc_landing_note *n,
                             const struct fmc_row *v, long long now)
{
    struct fmc_landing *row = fmc_landing_find(l, v->ref);
    if (row) {
        row->notes++;
        return;
    }
    if (l->n >= FMC_LANDING_CAP) {
        l->more = true;
        return;
    }
    fmc_landing_fill(&l->row[l->n], n, v, now);
    l->row[l->n].notes = 1;
    l->n++;
}

/* Everything the mail walk writes into, so each row is one call. */
struct fmc_mail_ctx {
    bool projection_failed;
    struct zcl_fleet_typed_index *typed_index;
    struct json_value *agents;
    struct json_value *work;
    struct json_value *changes;
    struct json_value *blockers;
    struct fmc_roster *ro;
    struct zcl_fmc_cand_reg *cand;
    struct fmc_landings *landings;
    long long since;
    long long changes_cap;
    long long now;
    long long shown;
    int scanned;
    int stale;
    /* Where the pass began when it was cut: what makes an absence unknowable. */
    struct fmc_window win;
    char sent_path[4096 + 32];
};

/* An outcome that states `landed` reports publication of the one name its
 * note carries: the token the submitter wrote there, and no other. A note
 * that is empty or more than one token names nothing. It is the queue's
 * sender reporting, as any mail sighting is, so the candidate reads
 * reported_landed and `landed` itself stays null. */
static void fmc_landing_report(struct fmc_mail_ctx *c,
                               const struct fmc_landing_note *n,
                               const struct fmc_row *v)
{
    char name[ZCL_FMC_CAND_ID_CAP];
    long long age;
    if (strcmp(n->event, "outcome") != 0 || strcmp(n->state, "landed") != 0 ||
        !fmc_clean_agent(n->note, name, sizeof(name)))
        return;
    age = fmc_age_s(c->now, v->ts);
    zcl_fmc_cand_note(c->cand, name, ZCL_FMC_CAND_SRC_MAIL, "dev.land", age,
                      age >= 0);
    zcl_fmc_cand_note_landed(c->cand, name, "dev.land", age, age >= 0);
}

/* One mail row as a landing observation when it is a typed landing note.
 * The sighting is exact wherever the pass read it, cut or whole. */
static void fmc_landing_row(struct fmc_mail_ctx *c, const struct fmc_row *v)
{
    struct fmc_landing_note n;
    if (!fmc_landing_typed(v, &n))
        return;
    fmc_landing_note(c->landings, &n, v, c->now);
    fmc_landing_report(c, &n, v);
}

/* This is disposable request-local acceleration, never evidence authority. */
static void fmc_typed_index_begin(struct fmc_mail_ctx *c,
                                  struct zcl_fleet_typed_index *index,
                                  const struct json_value *rows)
{
    zcl_fleet_typed_index_init(index, 4096u, 16u * 1024u * 1024u);
    c->typed_index = zcl_fleet_typed_index_build(index, rows) ? index : NULL;
    fmc_parsed_begin(rows);
}

static void fmc_typed_index_end(struct fmc_mail_ctx *c,
                                struct zcl_fleet_typed_index *index)
{
    c->typed_index = NULL;
    zcl_fleet_typed_index_free(index);
    fmc_parsed_end();
}

/* Mail counts as a read candidates source only when the pass read it
 * whole: a cut pass leaves the total unknown, never a floor for one. */
static void fmc_mail_source_note(const struct fmc_mail_ctx *c,
                                 const struct fmc_mail_view *view)
{
    if (!view->window_cut)
        zcl_fmc_cand_source_ok(c->cand, ZCL_FMC_CAND_SRC_MAIL);
}

/* ── candidates from each source ─────────────────────────────────────────
 *
 * Three small bridges so the walkers stay under the complexity gate and so
 * the identity rule lives in one place: the ref IS the identity, and the
 * same ref from mail, board and queue is one candidate with three sources.
 *
 * An unparsable timestamp is passed through as age_known=false rather than
 * as 0. That distinction is the whole point: 0 reads as "seen just now". */

/* A handover may report landing explicitly with true or a full source SHA. */
static void fmc_cand_from_mail(struct fmc_mail_ctx *c, const struct fmc_row *v)
{
    long long age;
    char landed[80];
    if (!c || !c->cand || !v || !v->ref[0])
        return;
    if (strcmp(v->kind, "result") != 0 && strcmp(v->kind, "claim") != 0)
        return;
    age = fmc_age_s(c->now, v->ts);
    zcl_fmc_cand_note(c->cand, v->ref, ZCL_FMC_CAND_SRC_MAIL, v->from, age,
                      age >= 0);
    if (fmc_body_kv(v->body, "landed", landed, sizeof(landed)) &&
        (strcmp(landed, "true") == 0 ||
         (strlen(landed) == 40 && fmc_all_hex(landed, 40))))
        zcl_fmc_cand_note_landed(c->cand, v->ref, v->from, age, age >= 0);
}

/* A queue row knows a name; that is a sighting, not a handover, so it adds
 * the queue source without on its own reaching `delivered`. */
static void fmc_cand_from_queue(struct zcl_fmc_cand_reg *cand,
                                const struct json_value *r)
{
    const struct json_value *v;
    const char *name;
    if (!cand || !r || r->type != JSON_OBJ)
        return;
    v = json_get(r, "name");
    if (!v || v->type != JSON_STR)
        return;
    name = json_get_str(v);
    if (name && name[0])
        zcl_fmc_cand_note(cand, name, ZCL_FMC_CAND_SRC_QUEUE, NULL, 0,
                          false);
}

static bool fmc_outcome_row_matches(const struct json_value *r, const char *ref);

/* Queue outcomes report tests; they do not establish remote verification. */
static void fmc_cand_from_outcomes(struct zcl_fmc_cand_reg *cand,
                                   const struct json_value *outcomes)
{
    size_t n, i;
    if (!cand || !outcomes || outcomes->type != JSON_ARR)
        return;
    n = json_size(outcomes);
    for (i = 0; i < n; i++) {
        const struct json_value *row = json_at(outcomes, i);
        const char *name = fmc_row_field(row, "name");
        if (fmc_outcome_row_matches(row, name))
            zcl_fmc_cand_note_proven(cand, name, 0, false);
    }
}

/* One open directive into directive_queue[], grouped by recipient. */
static void fmc_dq_note(struct fmc_directive_tally *t, const char *to,
                        long long age)
{
    for (size_t i = 0; i < t->nq; i++) {
        if (strcmp(t->q[i].to, to) != 0)
            continue;
        t->q[i].open++;
        if (age > t->q[i].oldest_age_s)
            t->q[i].oldest_age_s = age;
        return;
    }
    if (t->nq >= FMC_DQ_CAP) {
        t->q_untracked++;
        return;
    }
    struct fmc_dq_entry *e = &t->q[t->nq++];
    (void)snprintf(e->to, sizeof(e->to), "%s", to);
    e->open = 1;
    e->oldest_age_s = age;
}

static void fmc_tally_note(struct fmc_directive_tally *t,
                           const struct fmc_dstatus *st,
                           const struct fmc_row *v, long long age, bool open)
{
    t->scanned++;
    t->answered += strcmp(st->state, "answered") == 0;
    t->closed += strcmp(st->state, "closed") == 0;
    t->gone += strcmp(st->state, "recipient_gone") == 0;
    /* unresolved is in neither open number: a cut pass did not see what
     * would settle it. */
    t->unresolved += strcmp(st->state, "unresolved") == 0;
    if (strcmp(st->cls, "broadcast") == 0) {
        t->broadcast++;
        t->broadcast_open += open;
    } else if (strcmp(st->cls, "owner") == 0) {
        t->owner++;
        t->owner_open += open;
    } else if (open) {
        t->open_worker++;
        fmc_dq_note(t, v->to, age);
    }
}

/* One scanned directive: its class and state into the tally, and — open,
 * a worker's, sent from here with no receiver evidence past
 * FMC_QUEUED_STALE_S — one stale blocker (overdue_worker_directives). */
static void fmc_directive_scan(struct fmc_mail_ctx *c, const struct fmc_row *v,
                               const struct json_value *rows)
{
    struct fmc_dstatus st;
    long long age = fmc_age_s(c->now, v->ts);
    /* At or before a cut pass's reach, a directive nothing read resolves
     * is unresolved: tallied apart, never open, never a blocker. */
    bool past = fmc_window_past(&c->win, v);
    fmc_directive_resolve(rows, v, c->now, fmc_row_acked(v) || fmc_alias_ack(v), &st,
                          c->typed_index);
    fmc_directive_window(&st, past);
    bool open = fmc_dstate_open(st.state);
    if (c->ro)
        fmc_tally_note(&c->ro->dt, &st, v, age, open);
    if (!open || strcmp(st.cls, "worker") != 0 ||
        strcmp(fmc_row_state_with_read(v, rows, c->sent_path,
               fmc_typed_read_indexed(rows, v, c->typed_index)), "queued") != 0 ||
        !fmc_stale_blocker(c->blockers, v, age, c->stale < FMC_STALE_BLOCKER_CAP))
        return;
    c->stale++;
    if (c->ro)
        c->ro->dt.overdue_worker++;
}

/* One pulled row: roster, tallies, a landing observation when it is a typed
 * landing note, the stale-directive check (bounded to the newest
 * FMC_DIRECTIVE_SCAN directives), and above `since`, under the cap, one
 * change row. */
static void fmc_mail_row(struct fmc_mail_ctx *c, const struct fmc_row *v,
                         const struct json_value *rows)
{
    fmc_row_tally(c->agents, c->work, v);
    fmc_roster_note(c->ro, v);
    fmc_sessions_note(c->ro, v);
    fmc_cand_from_mail(c, v);
    fmc_landing_row(c, v);
    if (strcmp(v->kind, "directive") == 0 &&
        c->scanned < FMC_DIRECTIVE_SCAN) {
        c->scanned++;
        fmc_directive_scan(c, v, rows);
    }
    if (c->projection_failed || v->seq <= c->since || c->shown >= c->changes_cap)
        return;
    if (fmc_row_change(c->changes, v, rows, c->sent_path, c->now,
                       fmc_window_past(&c->win, v), c->typed_index)) c->shown++;
    else c->projection_failed = true;
}

/* `since` as a resume token: the composite per-stream watermark a previous
 * brief returned as cursor_token. 1 with the token copied; 0 when since is
 * absent, empty, or an integer (the legacy global floor); -1 when since is
 * a string too long to be a leaf token — malformed input, never silently
 * a full redisplay. Shape is the leaf's call: it refuses what it did not
 * hand out. */
static int fmc_brief_resume(const struct zcl_command_request *req,
                            char *token, size_t cap)
{
    const struct json_value *v;
    const char *s;
    if (!req || !req->input || !token || cap == 0)
        return 0;
    v = json_get(req->input, "since");
    if (!v || v->type != JSON_STR)
        return 0;
    s = json_get_str(v);
    if (!s || !s[0])
        return 0;
    if (strlen(s) >= cap)
        return -1;
    (void)snprintf(token, cap, "%s", s);
    return 1;
}

/* Token changes follow the native forward merge prefix. The opaque cursor
 * is projected later, after row and byte limits, from actual survivors. */
static void fmc_brief_token_changes(struct fmc_mail_ctx *c,
                                    const struct json_value *rows_new,
                                    const struct json_value *rows_full,
                                    struct fmc_mail_view *view)
{
    size_t n =
        rows_new && rows_new->type == JSON_ARR ? json_size(rows_new) : 0u;
    size_t i;
    for (i = 0; i < n && c->shown < c->changes_cap; i++) {
        struct fmc_row v;
        if (!fmc_row_parse(json_at(rows_new, i), &v) ||
            !fmc_row_change(c->changes, &v, rows_full, c->sent_path, c->now,
                            fmc_window_past(&c->win, &v), c->typed_index)) {
            c->projection_failed = true;
            break;
        }
        c->shown++;
    }
    view->projection_failed = c->projection_failed;
    view->dropped = (long long)n - c->shown;
    view->truncated = view->dropped > 0;
}

/* Second drain for a token resume: rows that arrived after the caller's
 * watermark become changes (bounded, counted); tallies already ran over
 * the pass's rows, so this walk is display-only. False when the resume
 * position failed: missing[] names it, nothing is shown, and the token
 * does not advance — the caller replays an older token or the start. */
static bool fmc_brief_resume_changes(const struct zcl_command_request *req,
                                     struct fmc_mail_ctx *c,
                                     struct json_value *missing,
                                     struct fmc_mail_view *view,
                                     const struct json_value *rows_full,
                                     const char *resume)
{
    struct json_value fresh;
    long long fresh_cursor = -1;
    const char *fail;
    char why[128];
    int64_t t0, t1;
    json_init(&fresh);
    json_set_array(&fresh);
    t0 = clock_now_wall_ms();
    fail = fmc_mail_drain_from(req, &fresh, &fresh_cursor, resume,
                               view->cursor_token,
                               sizeof(view->cursor_token), why,
                               sizeof(why), true, NULL);
    t1 = clock_now_wall_ms();
    if (fail) {
        fmc_note_missing(missing, "dev.agent.mail", fail, t1 - t0);
        json_free(&fresh);
        view->cursor_token[0] = '\0';
        return false;
    }
    fmc_brief_token_changes(c, &fresh, rows_full, view);
    view->forward = true;
    (void)snprintf(view->start_token, sizeof(view->start_token), "%s", resume);
    json_free(&fresh);
    return true;
}

static int fmc_brief_compact_probe(const struct zcl_command_request *req,
                                   struct json_value *missing,
                                   struct fmc_mail_view *view,
                                   const char *resume, struct json_value *fresh_out)
{
    long long cursor = -1;
    char token[FMC_MAIL_SINCE_CAP], why[128];
    int64_t t0 = clock_now_wall_ms(), t1;
    json_init(fresh_out);
    json_set_array(fresh_out);
    const char *fail = fmc_mail_drain_from(req, fresh_out, &cursor, resume,
        token, sizeof(token), why, sizeof(why), true, NULL);
    t1 = clock_now_wall_ms();
    if (fail) {
        fmc_note_missing(missing, "dev.agent.mail", fail, t1 - t0);
        view->cursor_token[0] = 0;
        return -1;
    }
    bool empty = json_size(fresh_out) == 0;
    {
        view->cursor = cursor;
        view->ok = true;
        view->forward = true;
        (void)snprintf(view->cursor_token, sizeof(view->cursor_token), "%s", token);
        (void)snprintf(view->start_token, sizeof(view->start_token), "%s", resume);
    }
    return empty ? 1 : 0;
}

struct fmc_compact_refs {
    const char *refs[FMC_CHANGES_MAX];
    size_t count;
};

#define FMC_PROJECTION_REFS_MAX 4096u
struct fmc_projection_refs {
    char values[FMC_PROJECTION_REFS_MAX][DEV_MAIL_REF_MAX + 1];
    const char *ptrs[FMC_PROJECTION_REFS_MAX];
    size_t count;
};

static bool fmc_projection_add_ref(struct fmc_projection_refs *v, const char *ref)
{
    for (size_t i=0;i<v->count;i++) if (!strcmp(v->values[i],ref)) return true;
    if (v->count==FMC_PROJECTION_REFS_MAX) return false;
    int n=snprintf(v->values[v->count],sizeof(v->values[0]),"%s",ref);
    if (n<0 || (size_t)n>=sizeof(v->values[0])) return false;
    v->ptrs[v->count]=v->values[v->count]; v->count++;
    return true;
}

static bool fmc_projection_expand(struct fmc_projection_refs *out, const struct fmc_compact_refs *refs)
{
    for (size_t i=0;i<refs->count;i++) {
        const char *ref=refs->refs[i]; size_t len=strlen(ref);
        if (len+7>DEV_MAIL_REF_MAX || !fmc_projection_add_ref(out,ref)) return false;
        for (size_t p=0;p<=len;p++) {
            if (p<len && ref[p]!='-') continue;
            char variant[DEV_MAIL_REF_MAX+1];
            memcpy(variant,ref,p); memcpy(variant+p,"-result",7);
            memcpy(variant+p+7,ref+p,len-p+1);
            if (!fmc_projection_add_ref(out,variant)) return false;
        }
    }
    return true;
}

#ifdef ZCL_TESTING
bool zcl_fleet_steer_test_projection_ref(const char *directive, const char *candidate,
                                         bool *matches_original, bool *matches_expansion)
{
    if (!directive || !candidate || !matches_original || !matches_expansion) return false;
    struct fmc_projection_refs *v=zcl_calloc(1,sizeof(*v),"fleet_steer.test_projection_refs");
    if (!v) return false;
    struct fmc_compact_refs refs={.refs={directive},.count=1};
    bool ok=fmc_projection_expand(v,&refs);
    *matches_original=fmc_ref_answers(directive,candidate); *matches_expansion=false;
    for (size_t i=0;ok && i<v->count;i++) if (!strcmp(v->values[i],candidate)) *matches_expansion=true;
    free(v); return ok;
}
#endif

/* 0 unavailable (fallback), 1 copied, -1 copy failed (refuse). */
static int fmc_compact_projection(const struct fmc_compact_refs *refs, struct json_value *history)
{
    struct fmc_projection_refs *variants=zcl_calloc(1,sizeof(*variants),"fleet_steer.projection_refs");
    if (!variants) return 0;
    struct json_value result; json_init(&result); json_set_array(&result);
    bool ok=fmc_projection_expand(variants,refs) && dvm_projection_refs(variants->ptrs,variants->count,&result);
    free(variants);
    if (!ok) { json_free(&result); return 0; }
#ifdef ZCL_TESTING
    if (s_fmc_before_history_copy) s_fmc_before_history_copy();
#endif
    for (size_t i=0;i<json_size(&result);i++) {
        if (!json_push_back(history,json_at(&result,i))) { json_free(&result); return -1; }
    }
    json_free(&result);
    return 1;
}

static bool fmc_compact_keep_ref(const char *ref, void *ctx)
{
    const struct fmc_compact_refs *refs = ctx;
    for (size_t i = 0; i < refs->count; i++)
        if (fmc_ref_answers(refs->refs[i], ref)) return true;
    return false;
}

static bool fmc_compact_collect_refs(const struct json_value *fresh,
                                     const struct fmc_mail_ctx *c,
                                     struct fmc_compact_refs *refs)
{
    for (size_t i = 0; i < json_size(fresh) &&
         (long long)i + c->shown < c->changes_cap; i++) {
        struct fmc_row row;
        if (!fmc_row_parse(json_at(fresh, i), &row) ||
            (strcmp(row.kind, "directive") != 0 &&
             !fmc_sent_by_us(c->sent_path, row.seq, row.to)))
            continue;
        if (refs->count == FMC_CHANGES_MAX) return false;
        refs->refs[refs->count++] = row.ref;
    }
    return true;
}

static bool fmc_brief_compact_history(const struct zcl_command_request *req,
                                      struct fmc_mail_ctx *c,
                                      struct json_value *missing,
                                      struct fmc_mail_view *view,
                                      const struct json_value *fresh)
{
    struct fmc_compact_refs refs = {0};
    struct json_value history;
    long long cursor = -1;
    char why[128];
    const char *fail = NULL;
    json_init(&history);
    json_set_array(&history);
    if (!fmc_compact_collect_refs(fresh, c, &refs))
        fail = "history_ref_cap";
    else if (refs.count) {
        int projected=fmc_compact_projection(&refs,&history);
        if (projected<0) fail="allocation_failed";
        else if (!projected)
            fail = fmc_mail_drain_filtered(req, &history, &cursor, "", NULL, 0,
                                           why, sizeof(why), true, NULL,
                                           fmc_compact_keep_ref, &refs);
    }
    if (fail) {
        fmc_note_missing(missing, "dev.agent.mail", fail, 0);
        view->cursor_token[0] = 0;
        view->ok = false;
        view->forward = false;
    } else {
        view->ok = true;
        view->forward = true;
        struct zcl_fleet_typed_index index;
        fmc_typed_index_begin(c, &index, &history);
        fmc_brief_token_changes(c, fresh, &history, view);
        fmc_typed_index_end(c, &index);
    }
    json_free(&history);
    return !fail;
}

/* A presence note keeps its ref. Any other lookbehind row is only
 * evidence of who was seen: a copied ref would answer or close a
 * directive the pass did not read. */
static bool fmc_lookbehind_is_presence(const struct json_value *v)
{
    const char *kind = fmc_row_field(v, "kind");
    const char *ref = fmc_row_field(v, "ref");
    size_t plen = sizeof(FMC_PRESENCE_REF) - 1;
    return strcmp(kind, "note") == 0 &&
           strncmp(ref, FMC_PRESENCE_REF, plen) == 0 &&
           fmc_is_token(ref + plen, FMC_ROLE_MAX, false);
}

static bool fmc_blank_ref(struct json_value *v)
{
    size_t i;
    if (!v || v->type != JSON_OBJ)
        return false;
    for (i = 0; i < v->num_children; i++) {
        if (!v->keys[i] || strcmp(v->keys[i], "ref") != 0)
            continue;
        json_set_str(&v->children[i], "");
        return v->children[i].type == JSON_STR;
    }
    return json_push_kv_str(v, "ref", "");
}

/* One lookbehind line onto the rows the directive scan resolves against.
 * The caller has already stored the pass's own count. */
static bool fmc_keep_presence_line(struct json_value *rows, const char *line)
{
    struct json_value v;
    bool ok;
    json_init(&v);
    ok = line && line[0] && json_read(&v, line, strlen(line)) &&
         v.type == JSON_OBJ &&
         (fmc_lookbehind_is_presence(&v) || fmc_blank_ref(&v)) &&
         json_push_back(rows, &v);
    json_free(&v);
    return ok;
}

static void fmc_window_keep_cb(const char *line, void *ctx)
{
    (void)fmc_keep_presence_line(ctx, line);
}

static void fmc_window_keep_one(struct json_value *rows, const char *name,
                                long long off)
{
    if (off <= 0 || !name || !name[0])
        return;
    (void)zcl_devagent_mail_brief_presence(name, off, fmc_window_keep_cb, rows);
}

/* Presence notes and each sender's newest row before a cut, appended
 * after the pass's own rows. The walk that follows uses the count taken
 * before this call, so those lines are not mail_count and not changes. */
static void fmc_window_keep_presence(struct json_value *rows,
                                    const struct fmc_window *w)
{
    size_t i;
    if (!rows || !w || !w->cut)
        return;
    for (i = 0; i < w->n; i++)
        fmc_window_keep_one(rows, w->e[i].name, w->e[i].off);
}

static long long fmc_brief_mail(const struct zcl_command_request *req,
                                struct fmc_mail_ctx *c,
                                struct json_value *missing,
                                struct fmc_mail_view *view, bool compact)
{
    struct json_value rows;
    char resume[FMC_MAIL_SINCE_CAP];
    char window_start[FMC_MAIL_SINCE_CAP];
    char why[128];
    const char *fail;
    long long saved_cap;
    size_t n, i;
    int64_t t0, t1;
    int resume_state;
    view->cursor = -1;
    view->count = 0;
    view->ok = false;
    view->cursor_token[0] = '\0';
    view->truncated = false;
    view->dropped = 0;
    view->window_cut = false;
    view->window_reach_ts[0] = '\0';
    view->forward = false;
    view->projection_failed = false;
    view->start_token[0] = '\0';
    fail = fmc_snapshot_source("mail", true);
    if (fail) {
        fmc_note_missing(missing, "dev.agent.mail", fail, 0);
        return -1;
    }
    if (!fmc_sent_path_read(c->sent_path, sizeof(c->sent_path)))
        c->sent_path[0] = '\0';
    resume_state = fmc_brief_resume(req, resume, sizeof(resume));
    json_init(&rows);
    json_set_array(&rows);
    if (compact && resume_state > 0) {
        view->count = -1;
        int empty = fmc_brief_compact_probe(req, missing, view, resume, &rows);
        if (empty != 0) {
            json_free(&rows);
            return view->cursor;
        }
        if (!fmc_brief_compact_history(req, c, missing, view, &rows)) {
            json_free(&rows);
            return view->cursor;
        }
        json_free(&rows);
        return view->cursor;
    }
    t0 = clock_now_wall_ms();
    fail = fmc_mail_pass(req, &rows, &view->cursor, resume,
                         resume_state > 0, view->cursor_token,
                         sizeof(view->cursor_token), why, sizeof(why),
                         &view->window_cut, window_start,
                         sizeof(window_start));
    t1 = clock_now_wall_ms();
    if (fail) {
        fmc_note_missing(missing, "dev.agent.mail", fail, t1 - t0);
        json_free(&rows);
        view->cursor = -1;
        view->cursor_token[0] = '\0';
        return -1;
    }
    view->ok = true;
    /* The reach comes from the rows of the pass itself before any row is
     * read against it. */
    fmc_window_begin(&c->win, view->window_cut, window_start);
    fmc_window_finish(&c->win, &rows, view);
    fmc_mail_source_note(c, view);
    n = json_size(&rows);
    view->count = (long long)n;
    fmc_window_keep_presence(&rows, &c->win);
    struct zcl_fleet_typed_index index;
    fmc_typed_index_begin(c, &index, &rows);
    /* The pass feeds roster, tallies, candidates and the
     * stale-directive scan on every path. The changes feed differs: the
     * legacy integer path filters it by the global floor here, while the
     * token path fills it from the resume drain below (and a malformed
     * token fills nothing — replaying everything would duplicate). */
    saved_cap = c->changes_cap;
    if (resume_state != 0)
        c->changes_cap = 0;
    /* Newest-first walk from the tail: changes[] carries the latest rows
     * above `since`, each with its lifecycle state. */
    for (i = n; i > 0; i--) {
        struct fmc_row v;
        if (!fmc_row_parse(json_at(&rows, i - 1), &v))
            continue;
        fmc_mail_row(c, &v, &rows);
    }
    c->changes_cap = saved_cap;
    view->projection_failed = c->projection_failed;
    if (resume_state < 0)
        fmc_note_missing(missing, "dev.agent.mail",
                         "brief_since_token_too_long", 0);
    else if (resume_state > 0)
        fmc_brief_resume_changes(req, c, missing, view, &rows, resume);
    fmc_stale_summary(c->blockers, c->stale);
    fmc_typed_index_end(c, &index);
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

/* Pool numbers become capacity, but only when the pool is measured: a
 * host with no pool.txt has an unmeasured pool, never an empty one.
 *
 * WHO DECIDES THAT. dev.agent.queue does, and it says so in the reply:
 * pool.known plus pool.reason, with total/warm/free null when unmeasured.
 * This function used to stat() pool.txt itself, because that leaf reported
 * total 0 for an absent pool file and for a measured empty one alike and its
 * zero could not be trusted. Two files deciding one thing is one file too
 * many, and the queue's own state is the queue leaf's business, so the probe
 * is gone and the reason is carried through verbatim. */
/* True when the leaf said it measured nothing, in which case view carries
 * the leaf's OWN reason verbatim. Split out so fmc_queue_pool stays under
 * the complexity gate; an unmeasured pool and an empty one are different
 * answers and only this branch can tell them apart. */
static bool fmc_pool_unmeasured(const struct json_value *pool,
                                struct fmc_queue_view *view)
{
    const struct json_value *known = json_get(pool, "known");
    const struct json_value *why = json_get(pool, "reason");
    if (!known || known->type != JSON_BOOL || json_get_bool(known))
        return false;
    (void)snprintf(view->pool_reason, sizeof(view->pool_reason), "%s",
                   why && why->type == JSON_STR && json_get_str(why)[0]
                       ? json_get_str(why)
                       : "dev.agent.queue reported the pool unmeasured");
    return true;
}

static void fmc_queue_pool(struct fmc_sub *sub, struct fmc_queue_view *view)
{
    const struct json_value *pool, *t, *f;
    if (!sub || !view)
        return;
    pool = json_get(&sub->reply.data, "pool");
    if (!pool || pool->type != JSON_OBJ) {
        (void)snprintf(view->pool_reason, sizeof(view->pool_reason), "%s",
                       "dev.agent.queue status carried no pool object");
        return;
    }
    if (fmc_pool_unmeasured(pool, view))
        return;
    t = json_get(pool, "total");
    f = json_get(pool, "free");
    if (!t || t->type != JSON_INT || !f || f->type != JSON_INT) {
        (void)snprintf(view->pool_reason, sizeof(view->pool_reason), "%s",
                       "dev.agent.queue status carried no pool numbers");
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
                           struct zcl_fmc_cand_reg *cand,
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
        fmc_cand_from_queue(cand, json_at(q, i));
        fmc_queue_row_name(json_at(q, i), work);
    }
    for (i = 0; i < nr; i++) {
        fmc_cand_from_queue(cand, json_at(r, i));
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
                            struct zcl_fmc_cand_reg *cand,
                            struct json_value *blockers,
                            struct json_value *missing,
                            struct fmc_queue_view *view,
                            struct json_value *outcomes_keep,
                            struct zcl_fmc_tasks *tasks)
{
    struct fmc_sub sub;
    int64_t t0, t1;
    memset(view, 0, sizeof(*view));
    view->tok_last = view->tok_total = -1;
    view->pool_total = view->pool_free = -1;
    (void)snprintf(view->reason, sizeof(view->reason), "%s",
                   "unknown_sibling");
    const char *unavailable = fmc_snapshot_source("queue/queue.jsonl", false);
    if (unavailable) {
        (void)snprintf(view->reason, sizeof(view->reason), "%s", unavailable);
        fmc_note_missing(missing, "dev.agent.queue", unavailable, 0);
        if (strcmp(unavailable, "source_missing") != 0) return;
    }
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
    view->known = unavailable == NULL;
    if (!unavailable) {
        view->reason[0] = '\0';
        zcl_fmc_cand_source_ok(cand, ZCL_FMC_CAND_SRC_QUEUE);
    }
    fmc_queue_rows(&sub, work, cand, view);
    long long now = (long long)platform_time_wall_unix();
    if (!zcl_fmc_tasks_queue(tasks, &sub.reply.data, now, now))
        fmc_note_missing(missing, "dev.agent.queue", "task_source_malformed", 0);
    if (unavailable) tasks->queue_ok = false;
    fmc_queue_outcomes(&sub, blockers, outcomes_keep, view);
    fmc_cand_from_outcomes(cand, outcomes_keep);
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
static void fmc_board_blocker(struct json_value *blockers, size_t *dropped,
                              const char *kind,
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
    if (json_size(blockers) >= FMC_BLOCKER_CAP) {
        if (dropped)
            (*dropped)++;
        return;
    }
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
                                 struct zcl_fmc_cand_reg *cand,
                                 size_t *dropped)
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
        fmc_board_blocker(blockers, dropped, kind,
                          fmc_row_field(post, "text"), ref);
    else if (strcmp(kind, "claim") == 0 || strcmp(kind, "result") == 0) {
        if (ref[0])
            zcl_fmc_cand_note(cand, ref, ZCL_FMC_CAND_SRC_BOARD, agent,
                              0, false);
    }
}

/* Name a board sibling refusal in missing[] terms. A node that answered
 * with method-not-found predates the board RPC (generation skew, never an
 * unreachable node); anything else is the sibling's own refusal. */
static const char *fmc_board_refusal(const struct fmc_sub *sub)
{
    if (!sub)
        return "sibling_refused";
    if (strcmp(sub->reply.error.code, "BOARD_OBSERVATION_BUDGET_EXHAUSTED") == 0)
        return "observation_budget_exhausted";
    if (strcmp(sub->reply.error.code, "BOARD_PAGE_METADATA_MISSING") == 0)
        return "board_page_metadata_missing";
    if (strcmp(sub->reply.error.code, "BOARD_PAGE_BUDGET") == 0)
        return "board_post_too_large";
    if (sub->reply.error.code[0] &&
        strstr(sub->reply.error.code, "NODE_UNAVAILABLE"))
        return "node_unavailable";
    if (sub->reply.error.code[0] &&
        strstr(sub->reply.error.code, "METHOD_NOT_FOUND"))
        return "node_predates_board_rpc";
    return "sibling_refused";
}

/* Recovery guidance for board refusals: observation-budget exhaustion can
 * be retried as a bounded normal-view page on the same selected endpoint.
 * Keep it contextual and non-pasteable so the response neither discloses a
 * private datadir nor suggests switching nodes. Oversized posts retain their
 * existing summary-view recovery. */
static const char *fmc_board_refusal_next(const struct fmc_sub *sub)
{
    if (sub && strcmp(sub->reply.error.code,
                      "BOARD_OBSERVATION_BUDGET_EXHAUSTED") == 0)
        return "On the same selected node, datadir, and RPC port, inspect "
               "one open board post in normal view (fleet board list, limit 1).";
    if (sub && strcmp(sub->reply.error.code, "BOARD_PAGE_BUDGET") == 0)
        return "z23 fleet board list --open --limit=1 --view=summary";
    return NULL;
}

/* Walk open posts into the brief lists, collecting post ids as evidence
 * references. */
static void fmc_board_posts_walk(const struct json_value *posts,
                                 struct json_value *agents,
                                 struct json_value *blockers,
                                 struct zcl_fmc_cand_reg *cand,
                                 struct json_value *post_ids,
                                 size_t *dropped)
{
    size_t n, i;
    if (!posts || posts->type != JSON_ARR)
        return;
    n = json_size(posts);
    for (i = 0; i < n; i++) {
        const struct json_value *post = json_at(posts, i);
        const struct json_value *v;
        const char *id;
        fmc_board_post_lists(post, agents, blockers, cand, dropped);
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

struct fmc_board_observation {
    struct fmc_sub sub;
    const char *failure;
    int64_t elapsed_ms;
};

static void fmc_board_observe(const struct zcl_command_request *req,
                              int64_t deadline_ms, struct fmc_board_observation *obs)
{
    memset(obs, 0, sizeof(*obs));
    fmc_sub_begin(&obs->sub, "zcl.fleet_board_list.v1", req, "fleet.board.list");
    if (!obs->sub.valid) { obs->failure = "unknown_sibling"; return; }
    if (!fmc_sub_input(&obs->sub, "{\"open\":true,\"limit\":20}")) {
        obs->failure = "input_encode"; return;
    }
    int64_t t0 = platform_time_monotonic_ms();
    zcl_native_fleet_board_list_until(&obs->sub.request, &obs->sub.reply, deadline_ms);
    obs->elapsed_ms = platform_time_monotonic_ms() - t0;
    obs->sub.ran = true;
}

/* Name the unread rest of the open queue: reason more_open_posts, the exact
 * next command with the reply's own cursor, never a page loop in the brief. */
static void fmc_board_note_more(const struct json_value *data,
                                struct json_value *missing, int64_t age_ms)
{
    const struct json_value *more = json_get(data, "has_more");
    const struct json_value *at = json_get(data, "next_created_at");
    const struct json_value *id = json_get(data, "next_id");
    char next[256];
    uint8_t decoded[32];
    if (!more || more->type != JSON_BOOL || !json_get_bool(more))
        return;
    int n = -1;
    if (at && at->type == JSON_INT && json_get_int(at) > 0 &&
        id && id->type == JSON_STR && json_get_str(id) &&
        zcl_hex_decode_lower(json_get_str(id), decoded, sizeof(decoded)))
        n = snprintf(next, sizeof(next),
                     "z23 fleet board list --open --before_created_at=%lld --before_id=%s",
                     (long long)json_get_int(at), json_get_str(id));
    if (n < 0 || (size_t)n >= sizeof(next))
        snprintf(next, sizeof(next), "z23 fleet board list --open");
    fmc_note_missing_next(missing, "fleet.board", "more_open_posts", age_ms,
                          next, 0);
}

/* Blockers the shared cap refused: say how many, and where the rest are. */
static void fmc_board_note_dropped(struct json_value *missing, size_t dropped,
                                   int64_t age_ms)
{
    if (dropped)
        fmc_note_missing_next(missing, "fleet.board", "blockers_capped", age_ms,
                              "z23 fleet board list --open",
                              (long long)dropped);
}

#if defined(ZCL_TESTING)
/* Drive the cursor text from a raw list reply: the leaf only emits valid
 * cursors, so a malformed one can be exercised only here. */
bool zcl_fleet_steer_test_board_more(const char *reply, char *next, size_t cap);
bool zcl_fleet_steer_test_board_more(const char *reply, char *next, size_t cap)
{
    struct json_value data, missing;
    const struct json_value *e;
    const char *text;
    bool ok = false;
    json_init(&data);
    json_init(&missing);
    json_set_array(&missing);
    if (json_read(&data, reply, strlen(reply))) {
        fmc_board_note_more(&data, &missing, 0);
        e = json_size(&missing) ? json_at(&missing, 0) : NULL;
        text = e ? json_get_str(json_get(e, "next")) : NULL;
        ok = text && strlen(text) < cap;
        if (ok)
            memcpy(next, text, strlen(text) + 1);
    }
    json_free(&data);
    json_free(&missing);
    return ok;
}
#endif

static void fmc_brief_board(struct fmc_board_observation *obs,
                            struct json_value *agents,
                            struct json_value *blockers,
                            struct zcl_fmc_cand_reg *cand,
                            struct json_value *missing,
                            struct json_value *post_ids)
{
    if (obs->failure)
        fmc_note_missing(missing, "fleet.board", obs->failure, 0);
    else if (!fmc_sub_ok(&obs->sub))
        fmc_note_missing_next(missing, "fleet.board", fmc_board_refusal(&obs->sub),
                              obs->elapsed_ms, fmc_board_refusal_next(&obs->sub), 0);
    else {
        const struct json_value *data = &obs->sub.reply.data;
        size_t dropped = 0;
        zcl_fmc_cand_source_ok(cand, ZCL_FMC_CAND_SRC_BOARD);
        fmc_board_posts_walk(json_get(data, "posts"), agents, blockers, cand,
                             post_ids, &dropped);
        fmc_board_note_more(data, missing, obs->elapsed_ms);
        fmc_board_note_dropped(missing, dropped, obs->elapsed_ms);
    }
    fmc_sub_end(&obs->sub);
}

/* ── brief: ledger section ───────────────────────────────────────────────
 *
 * Chain counts and replica staleness only — row contents never leave the
 * ledger leaf, and they do not leave through this one either. */

struct fmc_ledger_view {
    long long boxes, rows, max_age, unknown_ages, overflow;
};

static void fmc_ledger_ages(const struct json_value *data,
                           struct fmc_ledger_view *view)
{
    const struct json_value *chains = json_get(data, "chains");
    const struct json_value *overflow = json_get(data, "index_overflow_rows");
    if (overflow && overflow->type == JSON_INT && json_get_int(overflow) >= 0)
        view->overflow = json_get_int(overflow);
    if (!chains || chains->type != JSON_ARR) return;
    view->unknown_ages = 0;
    for (size_t i = 0; i < json_size(chains); i++) {
        const struct json_value *age = json_get(json_at(chains, i), "age_s");
        if (!age || age->type != JSON_INT || json_get_int(age) < 0) {
            view->unknown_ages++;
            continue;
        }
        long long value = json_get_int(age);
        if (value > view->max_age) view->max_age = value;
    }
}

static void fmc_brief_ledger(const struct zcl_command_request *req,
                             struct json_value *missing,
                             struct fmc_ledger_view *view)
{
    struct fmc_sub sub;
    int64_t t0, t1;
    *view = (struct fmc_ledger_view){-1, -1, -1, -1, -1};
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
    view->boxes = fmc_sub_int(&sub, "boxes", -1);
    view->rows = fmc_sub_int(&sub, "rows_loaded", -1);
    fmc_ledger_ages(&sub.reply.data, view);
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

/* Where a host that could not read its land queue status can still see a
 * landing: the typed notes the mail pass kept. Said only when it kept one;
 * a page budget can still cut every row afterwards, which landings_dropped
 * reports. A tip outside the list is one lookup away: a ref alone returns
 * the newest held row under it. */
static const char *fmc_landings_next(const struct fmc_landings *l)
{
    if (!l || !l->n)
        return NULL;
    return "the land queue status was not read here; landings[] in this brief "
           "lists the typed landing notes the mail pass read, landings_dropped "
           "the rows a page budget cut: "
           "fleet steer evidence --type=mail --ref=<ref> --stream=<stream> "
           "--row_offset=<n> --seq=<n> --row_sha3=<hex> returns a row's "
           "exact note; --ref=<tip> alone returns the newest held row under "
           "the tip, of any kind";
}

/* Read the owning status leaves exactly once. Status only: never step,
 * ensure, wait, retry, reap or take a scheduler lock while rendering. A
 * status that could not be read says where a landing is still seen. */
static bool fmc_land_read(const struct zcl_command_request *req,
    struct fmc_sub *sub, struct json_value *missing, bool *complete,
    const struct fmc_landings *landings)
{
    fmc_sub_begin(sub, "zcl.dev_land.v1", req, "dev.land");
    const char *unavailable = fmc_snapshot_source("land/queue.jsonl", false);
    if (complete) *complete = unavailable == NULL;
    if (unavailable) {
        fmc_note_missing_next(missing, "dev.land", unavailable, 0,
                              fmc_landings_next(landings), 0);
        if (strcmp(unavailable, "source_missing") != 0) return false;
    }
    if (sub->valid && fmc_sub_input(sub, "{\"action\":\"status\",\"json\":true}")) {
        zcl_native_handle_dev_land(&sub->request, &sub->reply);
        sub->ran = true;
    }
    if (fmc_sub_ok(sub)) return true;
    fmc_note_missing_next(missing, "dev.land", "status_unavailable", 0,
                          fmc_landings_next(landings), 0);
    return false;
}

static void fmc_land_proof(const struct zcl_command_request *req,
    const struct json_value *flight, struct json_value *proof,
    struct json_value *missing)
{
    const struct json_value *step = json_get(flight, "proof_step");
    if (!step || step->type != JSON_OBJ) {
        if (flight) fmc_note_missing(missing, "dev.proof.status",
            "exact_proof_route_unavailable", 0);
        return;
    }
    struct fmc_sub sub;
    fmc_sub_begin(&sub, "zcl.dev_proof_status.v1", req, "dev.proof.status");
    const char *const fields[] = {"root", "local_commit", "remote_base"};
    bool ready = sub.valid;
    for (size_t i = 0; i < 3; i++) {
        const char *value = fmc_row_field(step, fields[i]);
        ready = ready && value[0] && json_push_kv_str(&sub.input, fields[i], value);
    }
    if (ready) {
        zcl_native_dev_proof_dispatch(&sub.request, &sub.reply);
        sub.ran = true;
    }
    if (fmc_sub_ok(&sub))
        json_copy(proof, &sub.reply.data);
    else
        fmc_note_missing(missing, "dev.proof.status", "exact_status_unavailable", 0);
    fmc_sub_end(&sub);
}

static void fmc_brief_land(const struct zcl_command_request *req,
    struct zcl_fmc_tasks *tasks, struct json_value *missing,
    bool changes_only, const struct fmc_landings *landings)
{
    struct fmc_sub sub;
    struct json_value proof = {0};
    bool complete = false;
    /* A changes-only page lists no landings, so it names none. */
    if (fmc_land_read(req, &sub, missing, &complete,
                      changes_only ? NULL : landings)) {
        fmc_land_proof(req, json_get(&sub.reply.data, "in_flight"), &proof, missing);
        long long now = (long long)platform_time_wall_unix();
        if (!zcl_fmc_tasks_land(tasks, &sub.reply.data, &proof, now, now))
            fmc_note_missing(missing, "dev.land", "task_source_malformed", 0);
        if (!complete) tasks->land_ok = false;
    }
    json_free(&proof);
    fmc_sub_end(&sub);
}

/* ── brief entry ───────────────────────────────────────────────────────── */

/* capacity: real numbers only when the queue sibling answered. Otherwise
 * every number is null beside known:false and the reason, because a queue
 * nobody could read is not an idle queue. */
static void fmc_capacity_emit(struct json_value *cap,
                              const struct fmc_queue_view *qv)
{
    char why[96];
    (void)json_push_kv_str(cap, "source", "dev.agent.queue");
    (void)json_push_kv_str(cap, "domain",
                           "resident-worker-queue-and-worktree-pool");
    (void)json_push_kv_str(cap, "host_builds", "not_measured");
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
static long long fmc_trim_member(struct json_value *data, const char *key, size_t budget)
{
    struct json_value *arr = (struct json_value *)json_get(data, key);
    long long dropped = 0;
    if (!arr || arr->type != JSON_ARR)
        return 0;
    while (arr->num_children > 0 &&
           /* Reserve the bounded truncation object and final task counts
            * that are appended after trimming. */
           json_write(data, NULL, 0) > budget) {
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
static bool fmc_trunc_add(struct json_value *trunc, const char *key, long long count)
{
    struct json_value *value = (struct json_value *)json_get(trunc, key);
    if (!value) return json_push_kv_int(trunc, key, count);
    if (value->type != JSON_INT) return false;
    json_set_int(value, json_get_int(value) + count);
    return true;
}

/* Directory entries are optional presentation, but their loss must be named. */
static bool fmc_directory_fit(struct json_value *data, struct json_value *trunc, size_t budget)
{
    struct json_value *dir = (struct json_value *)json_get(data, "mailbox_directory");
    if (!dir) return true;
    struct json_value *labels = (struct json_value *)json_get(dir, "labels");
    struct json_value *state = (struct json_value *)json_get(dir, "state");
    if (!labels || labels->type != JSON_ARR || !state || state->type != JSON_STR || !json_get_str(state)) return false;
    if (!labels->num_children || json_write(data, NULL, 0) <= budget) return true;
    json_set_str(state, "truncated");
    if (state->type != JSON_STR) return false;
    while (labels->num_children && json_write(data, NULL, 0) > budget) {
        json_free(&labels->children[--labels->num_children]);
        if (!fmc_trunc_add(trunc, "mailbox_directory", 1)) return false;
    }
    return true;
}

static bool fmc_fit_member(struct json_value *data, struct json_value *trunc,
                           const char *key, size_t budget)
{
    long long d;
    do {
        d = fmc_trim_member(data, key, budget);
        if (d > 0 && !fmc_trunc_add(trunc, key, d)) return false;
    } while (d > 0 && json_write(data, NULL, 0) > budget);
    return true;
}

static bool fmc_fit_budget(struct json_value *data, size_t budget, bool forward)
{
    static const char *const order[] = {
        "changes", "workers", "candidates", "landings", "work", "agents",
        "sessions", "blockers", "tasks",
    };
    static const char *const forward_order[] = {
        "workers", "candidates", "landings", "work", "agents", "sessions",
        "blockers", "tasks", "changes"};
    const char *const *keys = forward ? forward_order : order;
    struct json_value empty;
    size_t i;
    json_init(&empty); json_set_object(&empty);
    bool ok = true;
    if (!json_get(data, "budget_truncated")) ok = json_push_kv(data, "budget_truncated", &empty);
    json_free(&empty);
    struct json_value *trunc = (struct json_value *)json_get(data, "budget_truncated");
    if (!ok || !trunc || trunc->type != JSON_OBJ) return false;
    for (i = 0; i < sizeof(order) / sizeof(order[0]); i++) {
        if (forward && !strcmp(keys[i], "changes") &&
            !fmc_directory_fit(data, trunc, budget)) return false;
        if (!fmc_fit_member(data, trunc, keys[i], budget)) return false;
    }
    return ok && (forward || fmc_directory_fit(data, trunc, budget));
}

struct fmc_brief_lists {
    struct json_value agents, work, blockers, candidates, changes, missing;
    struct json_value capacity, evidence, post_ids, outcomes;
    /* candidates[] is emitted FROM this registry; the array above stays
     * only as the buffer zcl_fmc_cand_emit fills. landings is the same
     * kind of store for the typed landing notes the mail pass read. */
    struct zcl_fmc_cand_reg cand;
    struct fmc_landings landings;
    struct zcl_fmc_tasks tasks;
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
    zcl_fmc_cand_init(&l->cand);
    fmc_landings_init(&l->landings);
    zcl_fmc_tasks_init(&l->tasks);
}

static void fmc_lists_free(struct fmc_brief_lists *l)
{
    zcl_fmc_tasks_free(&l->tasks);
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
                               long long mail_cursor,
                               const struct fmc_ledger_view *ledger, long long now)
{
    char ts[32];
    (void)json_push_kv_int(&l->evidence, "mail_cursor", mail_cursor);
    fmc_put_int(&l->evidence, "mail_count", mv->count);
    /* Present only when the pass was cut: a page answer at a tight budget
     * has room for neither key when nothing was cut (the forward budget
     * test stalls one row sooner with 72 bytes more beside its rows). */
    if (mv->window_cut) {
        (void)json_push_kv_bool(&l->evidence, "mail_window_cut", true);
        if (mv->window_reach_ts[0])
            (void)json_push_kv_str(&l->evidence, "mail_window_reach_ts",
                                   mv->window_reach_ts);
    }
    fmc_put_int(&l->evidence, "ledger_boxes", ledger->boxes);
    fmc_put_int(&l->evidence, "ledger_rows", ledger->rows);
    fmc_put_int(&l->evidence, "ledger_max_age_s", ledger->max_age);
    fmc_put_int(&l->evidence, "ledger_age_unknown_boxes", ledger->unknown_ages);
    fmc_put_int(&l->evidence, "ledger_index_overflow_rows", ledger->overflow);
    (void)json_push_kv_str(&l->evidence, "ledger_age_basis",
        "last signed statement; snapshot observed_at is not replica freshness");
    (void)json_push_kv(&l->evidence, "post_ids", &l->post_ids);
    (void)json_push_kv_int(&l->evidence, "queued_stale_after_s",
                           FMC_QUEUED_STALE_S);
    fmc_now_iso(now, ts, sizeof(ts));
    if (ts[0])
        (void)json_push_kv_str(&l->evidence, "observed_at", ts);
}

/* The scope words of a comma/space list, as a JSON array member. */
static bool fmc_caller_scopes(struct json_value *obj, const char *scopes)
{
    struct json_value arr, word;
    char buf[sizeof(((struct fmc_caller *)0)->scopes)];
    size_t n = 0;
    bool ok = true;
    json_init(&arr);
    json_set_array(&arr);
    for (const char *p = scopes; ok; p++) {
        if (*p != '\0' && *p != ',' && *p != ' ') {
            if (n + 1 < sizeof(buf)) buf[n++] = *p;
            continue;
        }
        if (n > 0) {
            buf[n] = '\0';
            json_init(&word);
            json_set_str(&word, buf);
            ok = word.type == JSON_STR && json_push_back(&arr, &word);
            json_free(&word);
            n = 0;
        }
        if (*p == '\0') break;
    }
    if (ok) ok = json_push_kv(obj, "scopes", &arr);
    json_free(&arr);
    return ok;
}

/* Caller is the validated credential's label, scopes and expiry, never its ID. */
static bool fmc_caller_emit(struct json_value *data, const struct fmc_caller *c)
{
    struct json_value o;
    char iso[32] = "";
    json_init(&o);
    json_set_object(&o);
    bool ok = json_push_kv_str(&o, "mode", c->grant ? "grant" : "operator");
    if (ok && c->grant) {
        ok = fmc_put_str(&o, "sender", c->label);
        if (ok && !c->label[0])
            ok = json_push_kv_str(&o, "sender_reason", "STEER_GRANT_UNLABELLED");
        if (ok) ok = fmc_caller_scopes(&o, c->scopes);
        if (c->expires > 0) fmc_now_iso(c->expires, iso, sizeof(iso));
        if (ok) ok = fmc_put_str(&o, "expires", iso);
    }
    if (ok) ok = json_push_kv(data, "caller", &o);
    json_free(&o);
    return ok;
}

/* A verified local roster snapshot is not a receiver-liveness observation.
 * A brief-only grant does not gain the send scope's route-name disclosure. */
static bool fmc_mailbox_directory(struct json_value *data, const struct fmc_caller *caller,
                                  int64_t now)
{
    struct json_value names, directory; json_init(&names); json_init(&directory);
    json_set_array(&names); json_set_object(&directory);
    bool allowed = !caller->grant || fmc_scope_has(caller->scopes, "send");
    bool truncated = false;
    bool known = allowed && zcl_devagent_boardmail_directory(&names, &truncated);
    const char *state = !allowed ? "withheld" : !known ? "unknown" : truncated ? "truncated" : "complete";
    char iso[32] = "";
    if (known && now > 0) fmc_now_iso(now, iso, sizeof(iso));
    bool ok = json_push_kv_str(&directory, "state", state) &&
        json_push_kv_str(&directory, "source", "verified_roster") &&
        json_push_kv_str(&directory, "freshness", known ? "local_snapshot" : "unknown") &&
        json_push_kv_str(&directory, "observed_at", iso) &&
        json_push_kv(&directory, "labels", &names) && json_push_kv(data, "mailbox_directory", &directory);
    json_free(&names); json_free(&directory); return ok;
}

static size_t fmc_brief_data_budget(const struct zcl_command_request *req)
{
    size_t cap = req->budget_bytes ? req->budget_bytes : 65536u;
    size_t data = cap > 1024u ? cap - 1024u : 0u;
    return data < FMC_REPLY_SOFT_BUDGET - 512u ? data : FMC_REPLY_SOFT_BUDGET - 512u;
}

static bool fmc_brief_cursor_set(struct json_value *data, const char *token)
{
    struct json_value *value = (struct json_value *)json_get(data, "cursor_token");
    if (!value || value->type != JSON_STR) return false;
    json_set_str(value, token);
    const char *actual = json_get_str(value);
    return value->type == JSON_STR && actual && !strcmp(actual, token);
}

static bool fmc_brief_changes_set(struct json_value *data, const struct fmc_mail_view *view)
{
    long long cut = json_get_int(json_get(json_get(data, "budget_truncated"), "changes"));
    struct json_value *dropped = (struct json_value *)json_get(data, "changes_dropped");
    struct json_value *truncated = (struct json_value *)json_get(data, "changes_truncated");
    if (!dropped || dropped->type != JSON_INT || !truncated || truncated->type != JSON_BOOL) return false;
    json_set_int(dropped, view->dropped + cut);
    json_set_bool(truncated, view->truncated || cut > 0);
    return true;
}

static bool fmc_brief_tasks_update(struct json_value *data, long long base_dropped)
{
    const struct json_value *tasks = json_get(data, "tasks");
    if (!tasks || tasks->type != JSON_ARR) return false;
    struct json_value *complete = (struct json_value *)json_get(data, "tasks_sources_complete");
    struct json_value *dropped = (struct json_value *)json_get(data, "tasks_dropped");
    struct json_value *shown = (struct json_value *)json_get(data, "tasks_shown");
    if (!complete || complete->type != JSON_BOOL || !dropped || dropped->type != JSON_INT ||
        !shown || shown->type != JSON_INT) return false;
    long long cut = json_get_int(json_get(json_get(data, "budget_truncated"), "tasks"));
    if (cut > 0) json_set_bool(complete, false);
    json_set_int(dropped, base_dropped + cut);
    json_set_int(shown, (long long)json_size(json_get(data, "tasks")));
    return true;
}

/* The same for landings[] after a budget cut: shown is what survived and
 * dropped the rows the cut removed. Nothing else drops a row: a tip past
 * the list's cap is landings_more, not a dropped row. A page that lists
 * no landings has no count to rewrite. */
static bool fmc_brief_landings_update(struct json_value *data)
{
    struct json_value *shown = (struct json_value *)json_get(data, "landings_shown");
    struct json_value *dropped = (struct json_value *)json_get(data, "landings_dropped");
    if (!json_get(data, "landings"))
        return true;
    if (!shown || shown->type != JSON_INT || !dropped || dropped->type != JSON_INT)
        return false;
    long long cut = json_get_int(json_get(json_get(data, "budget_truncated"), "landings"));
    json_set_int(dropped, cut);
    json_set_int(shown, (long long)json_size(json_get(data, "landings")));
    return true;
}

/* The two counts a budget cut rewrites. */
static bool fmc_brief_counts_update(struct json_value *data,
                                    long long base_tasks_dropped)
{
    return fmc_brief_tasks_update(data, base_tasks_dropped) &&
           fmc_brief_landings_update(data);
}

/* 0 closed, 1 cursor projection failed, 2 budget metadata failed, 3 stalled. */
static int fmc_brief_cursor_finish(struct json_value *data,
    const struct fmc_mail_view *view, size_t budget, long long base_tasks_dropped,
    bool include_tasks)
{
    size_t initial = json_size(json_get(data, "changes"));
    for (size_t attempt = 0; attempt <= initial + 1; attempt++) {
        const struct json_value *changes = json_get(data, "changes");
        size_t count = json_size(changes);
        char token[FMC_MAIL_SINCE_CAP];
        if (!zcl_devagent_mail_cursor_prefix(view->start_token, view->cursor_token, changes, token, sizeof(token)) ||
            !fmc_brief_cursor_set(data, token) || !fmc_brief_changes_set(data, view) ||
            (include_tasks && !fmc_brief_counts_update(data, base_tasks_dropped)))
            return 1;
        if (json_write(data, NULL, 0) <= budget) {
            if (json_size(changes) || json_get_int(json_get(data, "changes_dropped")) == 0) return 0;
            break;
        }
        if (!fmc_fit_budget(data, budget, true))
            return 2;
        if (json_write(data, NULL, 0) > budget && json_size(json_get(data, "changes")) == count) break;
    }
    return 3;
}

static bool fmc_brief_cursor_fail(struct zcl_command_reply *reply, int rc)
{
    if (rc == 1) {
        fmc_fail(reply, "BRIEF_CURSOR_PROJECTION", "native mail cursor could not be projected faithfully", "same since token retained by caller");
        return false;
    }
    if (rc == 2) {
        fmc_fail(reply, "BRIEF_PROJECTION_FAILED", "brief budget projection failed", "json");
        return false;
    }
    fmc_fail(reply, "BRIEF_PAGE_STALLED", "no complete forward mail row fits this response budget; cursor is unchanged", "same since token");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
        "retry the same since with a larger permitted budget, or inspect a retained exact-mail locator");
    return false;
}

static bool fmc_brief_changes_copy(struct json_value *data, const struct json_value *changes)
{
    if (!json_push_kv(data, "changes", changes)) return false;
    const struct json_value *copy = json_get(data, "changes");
    if (!copy || copy->type != JSON_ARR || json_size(copy) != json_size(changes)) return false;
    for (size_t i = 0; i < json_size(changes); i++) {
        struct fmc_row row;
        if (!fmc_row_parse(json_at(changes, i), &row) || !fmc_change_shape(json_at(copy, i), &row)) return false;
    }
    return true;
}

static bool fmc_brief_mail_meta(struct json_value *data, const struct fmc_mail_view *view,
    long long cursor)
{
    const char *token = view && view->ok ? (view->forward ? view->start_token : view->cursor_token) : "";
    bool ok = json_push_kv_int(data, "cursor", cursor);
    ok &= json_push_kv_str(data, "cursor_token", token);
    ok &= json_push_kv_bool(data, "changes_truncated", view && view->truncated);
    ok &= json_push_kv_int(data, "changes_dropped", view ? view->dropped : 0);
    const struct json_value *value = json_get(data, "cursor_token");
    return ok && value && value->type == JSON_STR && !strcmp(json_get_str(value), token);
}

/* Refuse a partial task projection before computing any usable cursor. */
static bool fmc_brief_tasks_emit(struct fmc_brief_lists *lists,
                                  struct zcl_command_reply *reply)
{
    if (zcl_fmc_tasks_emit(&lists->tasks, &reply->data))
        return true;
    json_free(&reply->data);
    json_init(&reply->data);
    json_set_object(&reply->data);
    fmc_fail(reply, "STEER_BRIEF_DEGRADED",
             "the task projection could not be copied whole; refusing the brief",
             NULL);
    return false;
}

/* A landing row's fixed keys: the tip, its newest note's typed lines, and
 * how many notes were read for that tip. */
static bool fmc_landing_emit_fields(struct json_value *o,
                                    const struct fmc_landing *r)
{
    return json_push_kv_str(o, "ref", r->ref) &&
           json_push_kv_str(o, "event", r->event) &&
           json_push_kv_str(o, "state", r->state) &&
           json_push_kv_int(o, "attempt", r->attempt) &&
           fmc_put_str(o, "note", r->note) &&
           fmc_put_int(o, "age_s", r->age) &&
           json_push_kv_int(o, "seq", r->seq) &&
           json_push_kv_int(o, "notes", (long long)r->notes);
}

/* The locator of the note's mail row, when the pull supplied one: with
 * seq, the keys fleet steer evidence --type=mail reads an exact line by.
 * None when the pull gave no locator. */
static bool fmc_landing_emit_locator(struct json_value *o,
                                     const struct fmc_landing *r)
{
    if (!r->stream[0] || !r->row_sha3[0] || r->row_offset < 0)
        return true;
    return json_push_kv_str(o, "stream", r->stream) &&
           json_push_kv_int(o, "row_offset", r->row_offset) &&
           json_push_kv_str(o, "row_sha3", r->row_sha3);
}

/* One landing row onto the list. */
static bool fmc_landing_emit_row(struct json_value *arr,
                                 const struct fmc_landing *r)
{
    struct json_value o;
    bool ok;
    json_init(&o);
    json_set_object(&o);
    ok = fmc_landing_emit_fields(&o, r);
    if (ok && r->ts[0])
        ok = json_push_kv_str(&o, "ts", r->ts);
    ok = ok && fmc_landing_emit_locator(&o, r) && json_push_back(arr, &o);
    json_free(&o);
    return ok;
}

/* landings[] and its coverage keys. A budget cut rewrites the two counts
 * afterwards; landings_more is the pass's own and does not change. */
static bool fmc_landings_emit(struct json_value *data,
                              const struct fmc_landings *l)
{
    struct json_value arr;
    bool ok = true;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < l->n; i++)
        ok = ok && fmc_landing_emit_row(&arr, &l->row[i]);
    ok = ok && json_push_kv(data, "landings", &arr) &&
         json_push_kv_int(data, "landings_shown", (long long)l->n) &&
         json_push_kv_int(data, "landings_dropped", 0) &&
         json_push_kv_bool(data, "landings_more", l->more);
    json_free(&arr);
    return ok;
}

static void fmc_brief_observe_if_fits(struct json_value *data, size_t budget);

/* Compact ",\"observation_generation\":\"<16 hex>\",\"not_modified\":false"
 * on a non-empty object. The fit keeps this slack so the fields land inside
 * the budget the page already closed. */
#define FMC_BRIEF_OBS_BYTES 65u

static bool fmc_brief_close_budget(struct zcl_command_reply *reply,
                                   const struct fmc_mail_view *mv, size_t budget,
                                   long long base_tasks_dropped, bool include_tasks,
                                   bool report)
{
    if (!fmc_fit_budget(&reply->data, budget, mv && mv->forward)) {
        if (report)
            fmc_fail(reply, "BRIEF_PROJECTION_FAILED",
                     "brief budget metadata could not be copied", "json");
        return false;
    }
    if (mv && mv->forward) {
        int rc = fmc_brief_cursor_finish(&reply->data, mv, budget, base_tasks_dropped,
                                         include_tasks);
        if (rc != 0) {
            if (report)
                fmc_brief_cursor_fail(reply, rc);
            return false;
        }
    }
    return true;
}

static void fmc_brief_finalize(const struct zcl_command_request *req,
                               struct zcl_command_reply *reply,
                               const struct fmc_mail_view *mv, bool include_tasks)
{
    long long base_tasks_dropped = json_get_int(json_get(&reply->data, "tasks_dropped"));
    size_t budget = fmc_brief_data_budget(req);
    size_t fit = budget > FMC_BRIEF_OBS_BYTES ? budget - FMC_BRIEF_OBS_BYTES : budget;
    struct json_value saved;
    bool held = false;
    bool stamped = false;
    json_init(&saved);
    if (fit < budget && json_copy_checked(&saved, &reply->data))
        held = true;
    if (held &&
        fmc_brief_close_budget(reply, mv, fit, base_tasks_dropped, include_tasks, false))
        stamped = true;
    else {
        if (held) {
            json_free(&reply->data);
            if (!json_copy_checked(&reply->data, &saved)) {
                json_free(&saved);
                fmc_fail(reply, "BRIEF_PROJECTION_FAILED",
                         "brief budget metadata could not be copied", "json");
                return;
            }
        }
        if (!fmc_brief_close_budget(reply, mv, budget, base_tasks_dropped,
                                    include_tasks, true)) {
            json_free(&saved);
            return;
        }
    }
    json_free(&saved);
    if (include_tasks && !fmc_brief_counts_update(&reply->data, base_tasks_dropped)) {
        fmc_fail(reply, "BRIEF_PROJECTION_FAILED",
                 "task or landing count projection is incomplete", "json");
        return;
    }
    /* Reserved slack carries the observation. A row that needed those bytes
     * keeps the page and omits the fields. */
    if (stamped)
        fmc_brief_observe_if_fits(&reply->data, budget);
    if (json_write(&reply->data, NULL, 0) > budget) {
        json_free(&reply->data);
        json_set_object(&reply->data);
        fmc_fail(reply, "BRIEF_BUDGET_EXCEEDED",
                 "required brief metadata exceeds the response budget", "budget_bytes");
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static bool fmc_brief_view(struct zcl_command_reply *reply, struct fmc_brief_lists *l,
                           struct fmc_roster *ro, const struct fmc_emit_ctx *ec,
                           bool changes_only, const struct fmc_mail_view *mv)
{
    if (!changes_only && !fmc_mailbox_directory(&reply->data, ec->caller, ec->now)) {
        fmc_fail(reply, "BRIEF_PROJECTION_FAILED", "mailbox directory could not be copied", "json");
        return false;
    }
    if (changes_only && (!json_push_kv_bool(&reply->data, "snapshot_included", false) ||
                         !json_push_kv_str(&reply->data, "changes_scope", "mail"))) {
        fmc_fail(reply, "BRIEF_PROJECTION_FAILED", "compact metadata could not be copied", "json");
        return false;
    }
    if (!changes_only) {
        (void)json_push_kv(&reply->data, "agents", &l->agents);
        fmc_workers_emit(&reply->data, ro, ec);
        fmc_sessions_emit(&reply->data, ro, ec->now);
        (void)json_push_kv(&reply->data, "work", &l->work);
        (void)json_push_kv(&reply->data, "blockers", &l->blockers);
        (void)json_push_kv(&reply->data, "capacity", &l->capacity);
    }
    if (!changes_only) {
        zcl_fmc_cand_emit(&l->cand, &l->candidates, &reply->data, &l->missing);
        (void)json_push_kv(&reply->data, "candidates", &l->candidates);
        /* The snapshot always lists landings, so an empty list there reads
         * as read and empty. A forward page lists them only when its pass
         * read a typed landing note: its budget is the caller's, and an
         * empty list with three counts would spend seventy-six bytes of
         * it. */
        if ((!mv || !mv->forward || l->landings.n > 0) &&
            !fmc_landings_emit(&reply->data, &l->landings)) {
            fmc_fail(reply, "BRIEF_PROJECTION_FAILED",
                     "landing observations could not be copied", "json");
            return false;
        }
    }
    return true;
}

/* A snapshot's tasks, then its compact form unless all=true; a forward
 * page is the caller's own budgeted feed and stays whole. */
static bool fmc_brief_snapshot_tail(const struct zcl_command_request *req,
                                    struct zcl_command_reply *reply,
                                    struct fmc_brief_lists *l,
                                    const struct fmc_mail_view *mv)
{
    if (!fmc_brief_tasks_emit(l, reply)) return false;
    if (!json_push_kv_int(&reply->data, "tasks_shown", 0)) {
        fmc_fail(reply, "BRIEF_PROJECTION_FAILED", "task count could not be copied", "json");
        return false;
    }
    if ((mv && mv->forward) || json_get_bool(json_get(req->input, "all")) ||
        zcl_fmc_brief_compact(&reply->data))
        return true;
    fmc_fail(reply, "BRIEF_PROJECTION_FAILED", "compact brief could not be copied", "all");
    return false;
}

static void fmc_brief_reply(const struct zcl_command_request *req, struct zcl_command_reply *reply,
                            struct fmc_brief_lists *l,
                            struct fmc_roster *ro,
                            const struct fmc_emit_ctx *ec,
                            const struct fmc_mail_view *mv,
                            long long mail_cursor, bool changes_only)
{
    if (mv && mv->projection_failed) {
        fmc_fail(reply, "BRIEF_PROJECTION_FAILED", "mail change projection failed; cursor is unchanged", "json");
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", FMC_LEAF);
    if (!fmc_caller_emit(&reply->data, ec->caller)) {
        fmc_fail(reply, "BRIEF_PROJECTION_FAILED", "caller could not be copied", "json");
        return;
    }
    if (!fmc_brief_view(reply, l, ro, ec, changes_only, mv)) return;
    if (!json_push_kv(&reply->data, "evidence", &l->evidence) && changes_only) {
        fmc_fail(reply, "BRIEF_PROJECTION_FAILED", "evidence could not be copied", "json");
        return;
    }
    if (!fmc_brief_changes_copy(&reply->data, &l->changes) ||
        !fmc_brief_mail_meta(&reply->data, mv, mail_cursor)) {
        fmc_fail(reply, "BRIEF_PROJECTION_FAILED", "mail changes or cursor metadata could not be copied", "json");
        return;
    }
    if (!json_push_kv(&reply->data, "missing", &l->missing) && changes_only) {
        fmc_fail(reply, "BRIEF_PROJECTION_FAILED", "missing metadata could not be copied", "json");
        return;
    }
    if (!changes_only && !fmc_brief_snapshot_tail(req, reply, l, mv)) return;
    fmc_brief_finalize(req, reply, mv, !changes_only);
}

/* Keep source diagnostics on a failed compact read, never a usable cursor. */
static void fmc_compact_read_failure(struct zcl_command_reply *reply,
                                     struct fmc_brief_lists *l,
                                     const struct fmc_caller *caller)
{
    bool ok = fmc_caller_emit(&reply->data, caller) &&
        json_push_kv_bool(&reply->data, "snapshot_included", false) &&
        json_push_kv_str(&reply->data, "changes_scope", "mail") &&
        json_push_kv(&reply->data, "evidence", &l->evidence) &&
        json_push_kv(&reply->data, "missing", &l->missing);
    const struct json_value *missing = json_get(&reply->data, "missing");
    ok = ok && missing && json_size(missing) == json_size(&l->missing);
    if (!ok) {
        json_free(&reply->data); json_init(&reply->data); json_set_object(&reply->data);
        fmc_fail(reply, "BRIEF_PROJECTION_FAILED", "failure diagnostics could not be copied", "since token unchanged");
        return;
    }
    fmc_fail(reply, "STEER_BRIEF_DEGRADED", "mail cursor could not be observed", "since token unchanged");
}

/* A receiver that has run on this box (the lock file exists) and is not
 * holding that lock now is down. Said once, before the per-directive
 * stale lines, so a full blocker list cannot hide it. A worker that
 * still holds worker.lock is left on its own state: a down receiver
 * does not stop runnable workers. */
static void fmc_receiver_down_incident(struct json_value *blockers,
                                       const char *receive_lock)
{
    if (!receive_lock || strcmp(receive_lock, "free") != 0)
        return;
    fmc_push_blocker(blockers,
                     "local receiver down: receive.lock free");
}

/* A compact view is a mail feed, and must never silently become a snapshot. */
static bool fmc_brief_compact(const struct zcl_command_request *req,
                              bool *compact, struct zcl_command_reply *reply)
{
    const struct json_value *flag = req && req->input ? json_get(req->input, "changes_only") : NULL;
    *compact = false;
    if (!flag) return true;
    if (flag->type != JSON_BOOL) goto invalid;
    if (!json_get_bool(flag)) return true;
    const struct json_value *since = json_get(req->input, "since");
    const char *token = since && since->type == JSON_STR ? json_get_str(since) : NULL;
    if (!token || !strchr(token, '|') || !zcl_devagent_mail_cursor_valid(token)) goto invalid;
    *compact = true;
    return true;
invalid:
    fmc_fail(reply, "BAD_INPUT", "changes_only requires a valid composite since token", "changes_only");
    return false;
}

static void fmc_brief_screen(const struct zcl_command_request *req,
                             struct zcl_command_reply *reply)
{
    char screen[4096]; struct json_value trial;
    size_t budget=fmc_brief_data_budget(req);
    zcl_fmc_tasks_screen(&reply->data,screen,sizeof(screen));
    json_init(&trial);
    bool ok=json_copy_checked(&trial,&reply->data) && json_push_kv_str(&trial,"screen",screen);
    if (!ok) {
        json_free(&trial);
        json_free(&reply->data); json_set_object(&reply->data);
        fmc_fail(reply,"BRIEF_PROJECTION_FAILED","brief screen could not be copied","json");
        return;
    }
    if (json_write(&trial,NULL,0)<=budget) {
        json_free(&reply->data); reply->data=trial; return;
    }
    json_free(&trial);
    if (json_push_kv_bool(&reply->data,"screen_omitted",true) &&
        json_write(&reply->data,NULL,0)<=budget) return;
    json_free(&reply->data); json_set_object(&reply->data);
    fmc_fail(reply,"BRIEF_BUDGET_EXCEEDED","required brief metadata exceeds the response budget","budget_bytes");
}

static void fmc_do_brief(const struct zcl_command_request *req,
                         struct zcl_command_reply *reply,
                         const struct fmc_caller *who)
{
    const int64_t observation_deadline_ms = platform_time_monotonic_ms() +
        ZCL_COMMAND_LATENCY_BUDGET_FAST_MS - FMC_BRIEF_FINISH_RESERVE_MS;
    struct fmc_brief_lists l;
    struct fmc_mail_ctx mc;
    struct fmc_mail_view mv;
    struct fmc_queue_view qv;
    struct fmc_roster ro;
    struct fmc_local lo;
    struct fmc_emit_ctx ec;
    struct fmc_ledger_view ledger;
    struct fmc_board_observation board;
    long long mail_cursor, tmp;
    bool changes_only;
    if (!fmc_brief_compact(req, &changes_only, reply)) return;
    if (!fmc_roster_init(&ro)) {
        fmc_roster_free(&ro);
        fmc_fail(reply, "STEER_BRIEF_ALLOC", "cannot allocate the worker "
                 "roster", "fleet.steer.brief");
        return;
    }
    fmc_lists_init(&l);
    fmc_board_observe(req, observation_deadline_ms, &board);
    memset(&mc, 0, sizeof(mc));
    mc.agents = &l.agents;
    mc.work = &l.work;
    mc.changes = &l.changes;
    mc.blockers = &l.blockers;
    mc.ro = &ro;
    mc.cand = &l.cand;
    mc.landings = &l.landings;
    mc.changes_cap = FMC_CHANGES_DEFAULT;
    mc.now = (long long)platform_time_wall_unix();
    if (fmc_int(req, "since", &tmp) && tmp >= 0)
        mc.since = tmp;
    if (fmc_int(req, "limit", &tmp) && tmp > 0)
        mc.changes_cap = tmp > FMC_CHANGES_MAX ? FMC_CHANGES_MAX : tmp;
    /* Name a stopped receiver before the mail scan fills blockers. */
    memset(&lo, 0, sizeof(lo));
    lo.receive_lock = fmc_lock_state("receive", "receive.lock");
    fmc_receiver_down_incident(&l.blockers, lo.receive_lock);
    mail_cursor = fmc_brief_mail(req, &mc, &l.missing, &mv, changes_only);
    ro.dt.forward_page = mv.forward;
    ro.window_cut = mv.window_cut;
    fmc_brief_queue(req, &l.work, &l.cand, &l.blockers, &l.missing,
                    &qv, &l.outcomes, &l.tasks);
    fmc_brief_land(req, &l.tasks, &l.missing, changes_only, mc.landings);
    fmc_brief_board(&board, &l.agents, &l.blockers, &l.cand, &l.missing,
                    &l.post_ids);
    fmc_brief_ledger(req, &l.missing, &ledger);
    fmc_apply_completed(&l.changes, &l.outcomes);
    fmc_capacity_emit(&l.capacity, &qv);
    fmc_brief_evidence(&l, &mv, mail_cursor, &ledger, mc.now);
    lo.worker_lock = fmc_lock_state("queue", "worker.lock");
    lo.receive_lock = fmc_lock_state("receive", "receive.lock");
    lo.mail_ok = mv.ok;
    fmc_intake_read(&lo);
    fmc_roster_local(&ro, &qv, &lo);
    ec.now = mc.now;
    ec.caller = who;
    ec.ro = &ro;
    ec.outcomes = &l.outcomes;
    ec.qv = &qv;
    ec.lo = &lo;
    if (changes_only && (!mv.ok || !mv.forward))
        fmc_compact_read_failure(reply, &l, who);
    else
        fmc_brief_reply(req, reply, &l, &ro, &ec, &mv, mail_cursor, changes_only);
    if (reply->status == ZCL_COMMAND_STATUS_PASSED && !mv.forward &&
        !json_get_bool(json_get(req->input, "json"))) {
        fmc_brief_screen(req,reply);
    }
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
static bool fmc_board_input(char *input, size_t cap, const char *ref)
{
    char escaped[256];
    if (!fmc_escape(ref, escaped, sizeof(escaped))) return false;
    int n = snprintf(input, cap, "{\"id\":\"%s\"}", escaped);
    return n > 0 && (size_t)n < cap;
}

static bool fmc_post_input(char *input, size_t cap, const char *to,
                           const char *kind, const char *body,
                           const char *ref, const struct fmc_sender *s)
{
    char eto[128], ebody[4096], eref[256], efrom[128];
    const char *from = fmc_sender_name(s);
    int n;
    if (!input || cap == 0 || !to || !kind || !body)
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
                     "{\"action\":\"post\",\"to\":\"%s\",\"kind\":\"%s\","
                     "\"body\":\"%s\",\"ref\":\"%s\",\"from\":\"%s\","
                     "\"sender_binding\":\"%s\"}",
                     eto, kind, ebody, eref, efrom, s->binding);
    } else {
        n = snprintf(input, cap,
                     "{\"action\":\"post\",\"to\":\"%s\",\"kind\":\"%s\","
                     "\"body\":\"%s\",\"ref\":\"%s\"}",
                     eto, kind, ebody, eref);
    }
    return n > 0 && (size_t)n < cap;
}

#if defined(ZCL_TESTING)
bool zcl_fleet_steer_test_input(unsigned mode, const char *body, const char *ref, char *out, size_t cap);
bool zcl_fleet_steer_test_input(unsigned mode, const char *body, const char *ref, char *out, size_t cap)
{
    struct fmc_sender sender = {0};
    if (mode == 2) return fmc_board_input(out, cap, ref);
    if (mode == 1) { memcpy(sender.from, "sender", 7); memset(sender.binding, 'a', sizeof(sender.binding) - 1); }
    return fmc_post_input(out, cap, "receiver", "directive", body, ref, &sender);
}
#endif

/* These mail refusals carry static policy guidance, never submitted body
 * text or host-local evidence. Do not forward arbitrary sibling errors. */
static bool fmc_mail_guidance_code(const char *code)
{
    return strcmp(code, "MAIL_REFUSED_PATH") == 0 ||
           strcmp(code, "MAIL_REFUSED_IP") == 0 ||
           strcmp(code, "MAIL_REFUSED_ONION") == 0 ||
           strcmp(code, "MAIL_REFUSED_KEY") == 0;
}

/* Post one directive through the mail sibling. Returns the accepted seq,
 * or -1 with `why` (caller buffer) naming the sibling's refusal. The code
 * is copied out before the sub reply is freed: it never points at it. */
static long long fmc_post_directive(const struct zcl_command_request *req,
                                    const char *to, const char *kind,
                                    const char *body,
                                    const char *ref,
                                    const struct fmc_sender *s,
                                    const char *key, bool require_existing,
                                    bool *duplicate,
                                    const char *disposition, bool probe,
                                    char *why, size_t why_cap,
                                    char *message, size_t message_cap)
{
    struct fmc_sub sub;
    char input[FMC_INPUT_CAP];
    long long seq;
    message[0] = '\0';
    if (why && why_cap > 0)
        (void)snprintf(why, why_cap, "sibling_refused");
    if (!fmc_post_input(input, sizeof(input), to, kind, body, ref, s))
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
    struct sha3_256_ctx hash;
    uint8_t digest[32];
    char key_digest[65];
    static const char domain[] = "z23.steer.key.v1";
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&hash, (const uint8_t *)key, strlen(key));
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), key_digest);
    zcl_devagent_mail_steer_post(&sub.request, &sub.reply, key_digest, require_existing, disposition, probe);
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        if (fmc_mail_guidance_code(sub.reply.error.code))
            (void)snprintf(message, message_cap, "%s", sub.reply.error.message);
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
    const struct json_value *dv = json_get(&sub.reply.data, "duplicate");
    *duplicate = dv && dv->type == JSON_BOOL && json_get_bool(dv);
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
    const char *kind;           /* "directive" or "result" */
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
    /* A remote agent answers its directive with a `result` under the same
     * ref; this surface is the only path some agents have. Closed set. */
    f->kind = fmc_item_str(it, "kind");
    if (!f->kind)
        f->kind = "directive";
    if (strcmp(f->kind, "directive") != 0 && strcmp(f->kind, "result") != 0)
        return false;
    return fmc_item_shape_ok(f, from, error);
}

/* One refused item result. */
static void fmc_send_item_refused_message(struct json_value *items, size_t index,
                                  const char *to, const char *error,
                                  const char *message)
{
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    (void)json_push_kv_int(&item, "index", (long long)index);
    (void)json_push_kv_str(&item, "state", "refused");
    (void)json_push_kv_str(&item, "error", error ? error : "BAD_INPUT");
    (void)json_push_kv_str(&item, "to", to ? to : "");
    if (message && message[0] && !json_push_kv_str(&item, "message", message))
        LOG_ERROR(FMC_LOG, "send: could not append static refusal guidance");
    (void)json_push_back(items, &item);
    json_free(&item);
}

static void fmc_send_item_refused(struct json_value *items, size_t index,
                                  const char *to, const char *error)
{
    fmc_send_item_refused_message(items, index, to, error, NULL);
}

/* One accepted item result, after recording key->seq plus the payload
 * digest, the ref, and the grant for reconcile and revoke-cancel. */
static void fmc_send_item_accept(struct json_value *items, size_t index,
                                 const struct fmc_item_fields *f,
                                 long long seq, bool duplicate, bool record,
                                 const char *sent_path, const char *from,
                                 const char *grant, const struct json_value *disposition)
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
    fmc_payload_sum(f->to, f->body, f->ref, from, f->kind, sum);
    if (!fmc_escape(f->ref ? f->ref : "", eref, sizeof(eref)))
        eref[0] = '\0';
    n = snprintf(sent_line, sizeof(sent_line),
                 "{\"key\":\"%s\",\"to\":\"%s\",\"seq\":%lld,\"state\":"
                 "\"queued\",\"sum\":\"%s\",\"ref\":\"%s\",\"grant\":\"%s\",\"source\":\"keyed\"}\n",
                 f->key, f->to, seq, sum, eref, grant ? grant : "");
    if (record && (n <= 0 || (size_t)n >= sizeof(sent_line) ||
                       !fmc_append_line(sent_path, sent_line, (size_t)n))) {
        /* The mail row exists but the receipt did not persist: report the
         * seq honestly and let the caller's retry reconcile by key on a
         * best-effort basis. Never claim a duplicate that is not one. */
        LOG_ERROR(FMC_LOG, "send: sent.jsonl append failed (to=%s seq=%lld)",
                  f->to, seq);
        (void)json_push_kv_str(&item, "state", "queued");
        (void)json_push_kv_int(&item, "seq", seq);
        (void)json_push_kv_bool(&item, "duplicate", duplicate);
        (void)json_push_kv_str(&item, "warning", "SENT_RECORD_LOST");
    } else {
        (void)json_push_kv_str(&item, "state", "queued");
        (void)json_push_kv_int(&item, "seq", seq);
        (void)json_push_kv_bool(&item, "duplicate", duplicate);
    }
    if (disposition) {
        (void)json_push_kv_bool(&item, "verified_read", true);
        (void)json_push_kv_str(&item, "disposition", fmc_item_str(disposition, "state"));
    }
    struct zcl_boardmail_delivery route;
    zcl_devagent_boardmail_observe(f->to, f->ref, &route);
    (void)json_push_kv_str(&item, "route_snapshot", route.label);
    if (route.hint[0]) (void)json_push_kv_str(&item, "route_hint", route.hint);
    (void)json_push_back(items, &item);
    json_free(&item);
}

/* Bytes `s` takes once the mail sibling escapes it (dvm_escape's rules:
 * two-character escapes for quote, backslash, newline, carriage return,
 * tab, backspace and form-feed; a six-byte u-escape for any other control
 * byte). */
static size_t fmc_mail_escaped_len(const char *s)
{
    size_t n = 0;
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t' ||
            c == 0x08 || c == 0x0c)
            n += 2;
        else
            n += c < 0x20 ? 6u : 1u;
    }
    return n;
}

/* True when the mail row this item becomes could not ride one board note:
 * the row line the mail sibling writes, with the widest seq (19 digits),
 * its fixed-width ts, and — when the sender name is the sibling's own
 * default — the widest agent name it accepts. Bounded from above, so a row
 * is never accepted here and then stranded by export. */
static bool fmc_remote_row_too_large(const struct fmc_item_fields *f,
                                     const struct fmc_sender *s, size_t extra)
{
    static const char shell[] =
        "{\"seq\":,\"ts\":\"\",\"from\":\"\",\"to\":\"\",\"kind\":\"directive\","
        "\"body\":\"\",\"ref\":\"\"}";
    static const char bind_shell[] = ",\"sender_binding\":\"\"";
    const char *from = fmc_sender_name(s);
    size_t n = sizeof(shell) - 1u + 19u + 20u;
    n += from ? fmc_mail_escaped_len(from) : 128u;
    n += sizeof(",\"steer_key\":\"\"") - 1u + 64u;
    n += fmc_mail_escaped_len(f->to) + fmc_mail_escaped_len(f->body) +
         fmc_mail_escaped_len(f->ref);
    if (from)
        n += sizeof(bind_shell) - 1u + strlen(s->binding);
    return n + extra > ZCL_BOARDMAIL_TEXT_MAX;
}

/* A typed result is an explicit full-body claim against one retained row. */
static const char *const fmc_disposition_keys[] = {"stream", "row_offset", "seq", "row_sha3",
    "read", "read_bytes", "read_sha3", "state", "queue_seq", "queue_attempt", "resolved_sha3"};

static bool fmc_disposition_keys_ok(const struct json_value *d, size_t n)
{
    if (d->num_children != n) return false;
    for (size_t i = 0; i < n; i++) {
        size_t count = 0;
        for (size_t j = 0; j < d->num_children; j++)
            if (d->keys[j] && !strcmp(d->keys[j], fmc_disposition_keys[i])) count++;
        if (count != 1) return false;
    }
    return true;
}

static bool fmc_disposition_read_ok(const struct json_value *d)
{
    const struct json_value *read = json_get(d, "read");
    const struct json_value *bytes = json_get(d, "read_bytes");
    const char *hash = fmc_item_str(d, "read_sha3");
    unsigned char decoded[32];
    return read && read->type == JSON_BOOL && json_get_bool(read) &&
        bytes && bytes->type == JSON_INT && json_get_int(bytes) >= 0 &&
        hash && zcl_hex_decode_lower(hash, decoded, sizeof(decoded));
}

static bool fmc_disposition_admission_ok(const struct json_value *d)
{
    const struct json_value *seq = json_get(d, "queue_seq");
    const struct json_value *attempt = json_get(d, "queue_attempt");
    const char *resolved = fmc_item_str(d, "resolved_sha3");
    unsigned char decoded[32];
    return seq && seq->type == JSON_INT && json_get_int(seq) > 0 &&
        attempt && attempt->type == JSON_INT && json_get_int(attempt) >= 0 &&
        resolved && zcl_hex_decode_lower(resolved, decoded, sizeof(decoded));
}

static bool fmc_disposition_shape(const struct json_value *d)
{
    if (!d || d->type != JSON_OBJ) return false;
    const char *state = fmc_item_str(d, "state");
    if (!state) return false;
    bool accepted = !strcmp(state, "ACCEPTED");
    if (!accepted && strcmp(state, "DEFERRED") && strcmp(state, "BLOCKED")) return false;
    return fmc_disposition_keys_ok(d, accepted ? 11 : 8) &&
        fmc_disposition_read_ok(d) && (!accepted || fmc_disposition_admission_ok(d));
}

static bool fmc_object_unique(const struct json_value *o)
{
    if (!o || o->type != JSON_OBJ) return false;
    for (size_t i = 0; i < o->num_children; i++) {
        if (!o->keys[i]) return false;
        for (size_t j = 0; j < i; j++)
            if (!strcmp(o->keys[i], o->keys[j])) return false;
    }
    return true;
}

static bool fmc_disposition_raw(const struct json_value *raw,
                                const struct json_value *d,
                                const struct fmc_item_fields *f,
                                const char *from)
{
    static const char *const keys[] = {"from", "to", "kind", "ref", "body"};
    if (!fmc_object_unique(raw)) return false;
    for (size_t i = 0; i < 5; i++)
        if (!fmc_item_str(raw, keys[i])) return false;
    const struct json_value *seq = json_get(raw, "seq");
    if (!seq || seq->type != JSON_INT ||
        json_get_int(seq) != json_get_int(json_get(d, "seq"))) return false;
    const char *body = fmc_item_str(raw, "body");
    if (strcmp(fmc_item_str(raw, "to"), from) ||
        strcmp(fmc_item_str(raw, "from"), f->to) ||
        strcmp(fmc_item_str(raw, "kind"), "directive") ||
        strcmp(fmc_item_str(raw, "ref"), f->ref) ||
        (long long)strlen(body) != json_get_int(json_get(d, "read_bytes")))
        return false;
    unsigned char digest[32];
    char hex[65];
    sha3_256((const unsigned char *)body, strlen(body), digest);
    zcl_hex_encode(digest, sizeof(digest), hex);
    return !strcmp(hex, json_get_str(json_get(d, "read_sha3")));
}

static bool fmc_disposition_encode(const struct json_value *d, char *wire,
                                   size_t cap)
{
    size_t nkeys = d->num_children;
    struct json_value ordered;
    json_init(&ordered); json_set_object(&ordered);
    bool ok = true;
    for (size_t i = 0; i < nkeys && ok; i++)
        ok = json_push_kv(&ordered, fmc_disposition_keys[i], json_get(d, fmc_disposition_keys[i]));
    size_t n = ok ? json_write(&ordered, wire, cap) : 0;
    json_free(&ordered);
    return n > 0 && n < cap;
}

static bool fmc_disposition_authorized(const struct json_value *d,
    const struct fmc_item_fields *f, const char *from, const char *grant)
{
    struct fmc_grant g;
    return grant && grant[0] && from && from[0] &&
        !fmc_grant_check_row(grant, "evidence", &g) &&
        !strcmp(g.label, from) && !strcmp(f->kind, "result") &&
        fmc_disposition_shape(d);
}

static bool fmc_disposition_admission(const struct json_value *d,
    const struct fmc_item_fields *f, const struct json_value *raw,
    const char *from, bool required)
{
    if (!required || strcmp(fmc_item_str(d, "state"), "ACCEPTED")) return true;
    return zcl_devagent_receive_admission(f->ref, fmc_item_str(raw, "body"),
        json_get_int(json_get(d, "queue_seq")), json_get_int(json_get(d, "queue_attempt")),
        fmc_item_str(d, "resolved_sha3"), from, fmc_item_str(d, "stream"),
        json_get_int(json_get(d, "row_offset")), fmc_item_str(d, "row_sha3"));
}

static bool fmc_disposition_verify(const struct zcl_command_request *req,
    const struct json_value *d, const struct fmc_item_fields *f,
    const char *from, const char *grant, char *wire, size_t cap, bool require_admission)
{
    struct fmc_sub sub;
    struct json_value raw;
    const char *const keys[] = {"stream", "row_offset", "seq", "row_sha3"};
    bool ok = fmc_disposition_authorized(d, f, from, grant);
    if (!ok) return false;
    fmc_sub_begin(&sub, "zcl.agent_mail.v1", req, "dev.agent.mail");
    ok = sub.valid && json_push_kv_str(&sub.input, "action", "exact") &&
         json_push_kv_str(&sub.input, "ref", f->ref);
    for (size_t i = 0; i < 4 && ok; i++) {
        const struct json_value *v = json_get(d, keys[i]);
        ok = v && json_push_kv(&sub.input, keys[i], v);
    }
    if (ok) fmc_mail_invoke(&sub, false);
    const struct json_value *line = json_get(&sub.reply.data, "raw_line");
    json_init(&raw);
    ok = ok && sub.reply.status == ZCL_COMMAND_STATUS_PASSED && line &&
         line->type == JSON_STR && json_read(&raw, json_get_str(line), strlen(json_get_str(line))) &&
         fmc_disposition_raw(&raw, d, f, from);
    if (ok) ok = fmc_disposition_admission(d, f, &raw, from, require_admission);
    if (ok) ok = fmc_disposition_encode(d, wire, cap);
    json_free(&raw);
    fmc_sub_end(&sub);
    return ok;
}

struct fmc_send_reconcile {
    const struct zcl_command_request *req;
    const struct fmc_item_fields *f;
    const struct fmc_sender *sender;
    const char *sent_path, *grant, *from;
    struct json_value *items;
    const struct json_value *disposition;
    char *wire;
    size_t index;
    long long seq;
    int receipt;
    bool keyed;
};

/* 0 refuses, 1 is an old unkeyed replay, 2 continues to source lookup. */
static int fmc_send_reconcile_receipt(struct fmc_send_reconcile *c)
{
    char recorded[17], presented[17];
    c->receipt = fmc_sent_find(c->sent_path, c->f->key, &c->seq, recorded,
                               c->grant, &c->keyed);
    if (c->receipt < 0) {
        fmc_send_item_refused(c->items, c->index, c->f->to, "SENT_UNAVAILABLE");
        return 0;
    }
    if (!c->receipt) return 2;
    fmc_payload_sum(c->f->to, c->f->body, c->f->ref, c->from, c->f->kind, presented);
    if (!recorded[0] || strcmp(recorded, presented) || (!c->keyed && c->disposition)) {
        fmc_send_item_refused(c->items, c->index, c->f->to, "IDEMPOTENCY_CONFLICT");
        return 0;
    }
    if (c->keyed) return 2;
    fmc_send_item_accept(c->items, c->index, c->f, c->seq, true, false,
                         c->sent_path, c->from, c->grant, NULL);
    return 1;
}

/* 0 refuses, 1 replays, 2 admits a fresh, verified disposition. */
static int fmc_send_reconcile_disposition(struct fmc_send_reconcile *c)
{
    char why[64], message[sizeof(((struct zcl_command_reply *)0)->error.message)];
    bool duplicate = false;
    long long seq = fmc_post_directive(c->req, c->f->to, c->f->kind, c->f->body,
        c->f->ref, c->sender, c->f->key, true, &duplicate, c->wire, true,
        why, sizeof(why), message, sizeof(message));
    if (seq >= 0) {
        if (c->keyed && seq != c->seq) {
            fmc_send_item_refused(c->items, c->index, c->f->to, "SENT_SOURCE_MISMATCH");
            return 0;
        }
        fmc_send_item_accept(c->items, c->index, c->f, seq, true, c->receipt == 0,
                             c->sent_path, c->from, c->grant, c->disposition);
        return 1;
    }
    if (c->receipt > 0 || strcmp(why, "MAIL_SOURCE_NOT_FOUND")) {
        fmc_send_item_refused(c->items, c->index, c->f->to, why);
        return 0;
    }
    if (!fmc_disposition_verify(c->req, c->disposition, c->f, c->from, c->grant,
                                c->wire, 2048, true)) {
        fmc_send_item_refused(c->items, c->index, c->f->to, "BAD_DISPOSITION");
        return 0;
    }
    return 2;
}

static bool fmc_send_preflight(const struct json_value *it,
    struct fmc_send_reconcile *c, struct fmc_item_fields *f,
    const struct fmc_sender *sender)
{
    const char *error = "BAD_INPUT";
    if (!fmc_send_item_fields(it, c->from, f, &error)) {
        const char *to = it && it->type == JSON_OBJ ? fmc_item_str(it, "to") : NULL;
        fmc_send_item_refused(c->items, c->index, to, error);
        return false;
    }
    if (c->disposition && (!fmc_disposition_authorized(c->disposition, f, c->from, c->grant) ||
        !fmc_disposition_encode(c->disposition, c->wire, 2048))) {
        fmc_send_item_refused(c->items, c->index, f->to, "BAD_DISPOSITION");
        return false;
    }
    if (zcl_devagent_boardmail_remote(f->to) &&
        fmc_remote_row_too_large(f, sender, c->disposition ? strlen(c->wire) + 24u : 0)) {
        fmc_send_item_refused(c->items, c->index, f->to, "STEER_REMOTE_BODY_TOO_LARGE");
        return false;
    }
    return true;
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
    long long seq = -1;
    bool keyed = false, duplicate = false;
    int receipt;
    char why[64];
    char message[sizeof(((struct zcl_command_reply *)0)->error.message)];
    const char *from = fmc_sender_name(s);
    const struct json_value *disposition = json_get(it, "disposition");
    char disposition_wire[2048];
    struct fmc_send_reconcile c = {
        .req = req, .f = &f, .sender = s, .sent_path = sent_path,
        .grant = grant, .from = from, .items = items, .disposition = disposition,
        .wire = disposition_wire, .index = index, .seq = -1
    };
    if (!fmc_send_preflight(it, &c, &f, s)) return false;
    int verdict = fmc_send_reconcile_receipt(&c);
    if (verdict != 2) return verdict == 1;
    if (disposition) {
        verdict = fmc_send_reconcile_disposition(&c);
        if (verdict != 2) return verdict == 1;
    }
    seq = c.seq; keyed = c.keyed; receipt = c.receipt;
    why[0] = 0;
    long long recorded_seq = seq;
     seq = fmc_post_directive(req, f.to, f.kind, f.body, f.ref, s, f.key,
                             keyed, &duplicate, disposition ? disposition_wire : NULL, false, why,
                             sizeof(why), message, sizeof(message));
    if (seq < 0) {
        fmc_send_item_refused_message(items, index, f.to,
                              why[0] ? why : "POST_FAILED", message);
        return false;
    }
    if (keyed && seq != recorded_seq) {
        fmc_send_item_refused(items, index, f.to, "SENT_SOURCE_MISMATCH");
        return false;
    }
    fmc_send_item_accept(items, index, &f, seq, duplicate, receipt == 0, sent_path, from,
                         grant, disposition);
    return true;
}

/* Serialize receipt lookup, mail post and receipt repair. Mail takes post.lock
 * inside this region; no mail path acquires this steer lock in reverse. */
static bool fmc_send_item_locked(const struct zcl_command_request *req,
                                 const struct json_value *it, size_t index,
                                 const struct fmc_sender *sender,
                                 const char *sent_path, const char *grant,
                                 struct json_value *items)
{
    char path[4096 + 64];
    int n = snprintf(path, sizeof(path), "%s.lock", sent_path);
    struct platform_private_file lock;
    platform_private_file_init(&lock);
    if (n <= 0 || (size_t)n >= sizeof(path) ||
        !platform_private_file_open_locked_create_wait(path, &lock)) {
        fmc_send_item_refused(items, index, "", "SENT_UNAVAILABLE");
        platform_private_file_close(&lock);
        return false;
    }
    bool ok = fmc_send_item(req, it, index, sender, sent_path, grant, items);
    platform_private_file_close(&lock);
    return ok;
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
            if (fmc_send_item_locked(req, json_at(arr, i), i, &sender, sent_path,
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

/* Same outcome rule brief uses when it upgrades a change to completed.
 * A queue that does not answer leaves the mail state unchanged. */
static bool fmc_mail_outcome_done(const struct zcl_command_request *req,
                                  const char *ref)
{
    struct fmc_sub sub;
    bool done = false;
    fmc_sub_begin(&sub, "zcl.agent_queue.v1", req, "dev.agent.queue");
    if (sub.valid &&
        fmc_sub_input(&sub, "{\"action\":\"status\",\"json\":true}")) {
        zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
        sub.ran = true;
        if (fmc_sub_ok(&sub))
            done = fmc_outcome_completes(
                json_get(&sub.reply.data, "outcomes"), ref);
    }
    fmc_sub_end(&sub);
    return done;
}

/* Lifecycle state for one mail row, resolved by exactly the rule the
 * brief's changes[] uses (fmc_row_state, then a retained pass outcome),
 * so the two never disagree about the same row: a row this host sent
 * through steer reads "queued" until the recipient replies under the same
 * ref or the local ack cursor covers it, and is never called "delivered"
 * from the sender's own outbox. A read file alone is "read". Any other
 * row reads "delivered", or "acknowledged" on the cursor. A pass outcome
 * with rc 0 then reads "completed". `ack_cursor` stays the integer floor.
 * An unparseable row reports the earliest state rather than guessing.
 * `rows` is the pull this lookup already holds. */
static void fmc_evidence_mail_ack(const struct zcl_command_request *req,
                                  struct zcl_command_reply *reply,
                                  const struct json_value *r,
                                  const struct json_value *rows)
{
    struct fmc_row v;
    char sent_path[4096 + 32];
    const char *state;
    if (!fmc_row_parse(r, &v)) {
        (void)json_push_kv_int(&reply->data, "ack_cursor", -1);
        (void)json_push_kv_str(&reply->data, "state", "queued");
        return;
    }
    if (!fmc_sent_path_read(sent_path, sizeof(sent_path)))
        sent_path[0] = '\0';
    state = fmc_row_state(&v, rows, sent_path);
    if (fmc_mail_outcome_done(req, v.ref))
        state = "completed";
    (void)json_push_kv_int(&reply->data, "ack_cursor", fmc_ack_cursor(v.to));
    (void)json_push_kv_str(&reply->data, "state", state);
}

/* Copy one whole JSON value onto the reply under "object". The sources are
 * already bounded by their own leaves (mail bodies <= 4KiB, one post). */
static bool fmc_emit_object(struct zcl_command_reply *reply,
                            const char *type, const struct json_value *obj)
{
    if (!json_push_kv_str(&reply->data, "leaf", FMC_LEAF) ||
        !json_push_kv_str(&reply->data, "type", type) ||
        !json_push_kv(&reply->data, "object", obj)) {
        fmc_fail(reply, "EVIDENCE_UNAVAILABLE", "cannot faithfully copy the evidence object", "allocation");
        return false;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
    return true;
}

/* Only an authenticated local outbox row can project locally verified state.
 * Imported board rows need independent signed-text validation. */
static bool fmc_disposition_project_raw(const struct json_value *object,
                                        struct json_value *raw)
{
    const char *stream = fmc_item_str(object, "stream");
    const char *line = fmc_item_str(object, "raw_line");
    return stream && !strcmp(stream, "outbox.jsonl") && line &&
        json_read(raw, line, strlen(line)) && fmc_object_unique(raw);
}

static bool fmc_disposition_own_source(const struct fmc_grant *g,
    const char *from, const char *stamp)
{
    char binding[ZCL_FLEET_STEER_BINDING_HEX + 1];
    return !strcmp(from, g->label) && stamp &&
        zcl_fleet_steer_sender_binding(g->id, g->label, binding, sizeof(binding)) &&
        !strcmp(stamp, binding);
}

static bool fmc_disposition_recipient(const struct fmc_grant *g,
    const char *from, const char *to, const char *stamp)
{
    return !strcmp(to, g->label) && stamp &&
        !zcl_fleet_steer_grant_binding_live(from, stamp, "send");
}

/* -1 means a typed row is foreign to this grant; 0 is unverified. */
static int fmc_disposition_project_authority(const struct zcl_command_request *req,
                                              const struct json_value *raw)
{
    const struct json_value *d = json_get(raw, "steer_disposition");
    if (!d) return 0;
    const char *from = fmc_item_str(raw, "from"), *to = fmc_item_str(raw, "to");
    const char *stamp = fmc_item_str(raw, "sender_binding");
    const char *key = fmc_item_str(raw, "steer_key");
    const char *grant = fmc_str(req, "grant");
    struct fmc_grant g;
    unsigned char decoded[32];
    if (!grant || fmc_grant_check_row(grant, "evidence", &g) || !g.label[0] ||
        !from || !to || (strcmp(g.label, from) && strcmp(g.label, to))) return -1;
    bool own = fmc_disposition_own_source(&g, from, stamp);
    bool recipient = fmc_disposition_recipient(&g, from, to, stamp);
    return (own || recipient) && key && zcl_hex_decode_lower(key, decoded, sizeof(decoded)) &&
        fmc_disposition_shape(d) ? 1 : 0;
}

static int fmc_disposition_project(const struct zcl_command_request *req,
                                    const struct json_value *object,
                                    struct zcl_command_reply *reply)
{
    struct json_value raw;
    json_init(&raw);
    int authority = fmc_disposition_project_raw(object, &raw)
        ? fmc_disposition_project_authority(req, &raw) : 0;
    bool written = authority >= 0 && json_push_kv_bool(&reply->data, "verified_read", authority == 1);
    if (authority == 1) written = written && json_push_kv(&reply->data, "disposition", json_get(&raw, "steer_disposition"));
    json_free(&raw);
    return authority < 0 ? -1 : written ? 1 : 0;
}

static bool fmc_evidence_kind_match(const struct zcl_command_request *req,
                                    const struct json_value *row)
{
    const char *kind = fmc_str(req, "kind");
    const struct json_value *value;
    if (!kind || !kind[0]) return true;
    value = json_get(row, "kind");
    return value && value->type == JSON_STR &&
           strcmp(json_get_str(value), kind) == 0;
}

static void fmc_evidence_mail_exact(const struct zcl_command_request *req,
    struct zcl_command_reply *reply)
{
    struct fmc_sub sub;
    fmc_sub_begin(&sub, "zcl.agent_mail.v1", req, "dev.agent.mail");
    const char *const keys[] = {"ref", "stream", "row_offset", "seq", "row_sha3"};
    bool ready = sub.valid && json_push_kv_str(&sub.input, "action", "exact");
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        ready = json_push_kv(&sub.input, keys[i], json_get(req->input, keys[i])) && ready;
    if (ready) fmc_mail_invoke(&sub, false);
    if (!ready || sub.reply.status != ZCL_COMMAND_STATUS_PASSED)
        fmc_fail(reply, "EVIDENCE_UNAVAILABLE", "exact retained mail did not match or answer", "dev.agent.mail");
    else if (!fmc_evidence_kind_match(req, &sub.reply.data))
        fmc_fail(reply, "EVIDENCE_NOT_FOUND", "exact retained mail kind did not match", "dev.agent.mail");
    else {
        int projected = fmc_disposition_project(req, &sub.reply.data, reply);
        if (projected < 0)
            fmc_fail(reply, "STEER_EVIDENCE_FOREIGN", "typed receipt belongs to other participants", "recipient");
        else if (!projected)
            fmc_fail(reply, "EVIDENCE_UNAVAILABLE", "cannot project verified disposition", "allocation");
        else (void)fmc_emit_object(reply, "mail", &sub.reply.data);
    }
    fmc_sub_end(&sub);
}

static void fmc_evidence_mail(const struct zcl_command_request *req,
                              struct zcl_command_reply *reply,
                              const char *ref)
{
    if (json_get(req->input, "stream")) {
        fmc_evidence_mail_exact(req, reply);
        return;
    }
    struct json_value rows;
    const struct json_value *hit = NULL;
    long long cursor = -1;
    const char *why;
    size_t n, i;
    json_init(&rows);
    json_set_array(&rows);
    why = fmc_mail_drain(req, &rows, &cursor, ref);
    if (why) {
        fmc_fail(reply, "EVIDENCE_UNAVAILABLE",
                 strcmp(why, "unknown_sibling") == 0
                     ? "the mail sibling is unknown"
                     : "the mail store did not answer",
                 "dev.agent.mail");
        json_free(&rows);
        return;
    }
    /* A ref may own a thread. Return its latest held message; an ACK
     * under the same ref can replace the prior body. Versioned evidence
     * refs keep observations distinct. This is not an immutable version. */
    n = json_size(&rows);
    for (i = 0; i < n; i++) {
        const struct json_value *r = json_at(&rows, i);
        const struct json_value *v;
        const char *rref;
        if (!r || r->type != JSON_OBJ)
            continue;
        v = json_get(r, "ref");
        rref = (v && v->type == JSON_STR) ? json_get_str(v) : "";
        if (rref && strcmp(rref, ref) == 0 &&
            fmc_evidence_kind_match(req, r))
            hit = r;
    }
    if (hit) {
        if (fmc_emit_object(reply, "mail", hit))
            fmc_evidence_mail_ack(req, reply, hit, &rows);
        json_free(&rows);
        return;
    }
    fmc_fail(reply, "EVIDENCE_NOT_FOUND", "no mail row carries that ref",
             ref);
    json_free(&rows);
}

/* New task links bind the queue/landing row AND attempt. Legacy ref-only
 * queue lookups retain their historical preference for terminal outcomes. */
static bool fmc_evidence_exact(const struct zcl_command_request *req,
    const struct json_value *row)
{
    const char *const keys[] = {"seq", "attempt"};
    for (size_t i = 0; i < 2; i++) {
        const struct json_value *want = json_get(req->input, keys[i]);
        const struct json_value *have = json_get(row, keys[i]);
        if (want && (!have || have->type != JSON_INT ||
            json_get_int(want) != json_get_int(have))) return false;
    }
    return true;
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
            if (fmc_evidence_exact(req, json_at(arr, i)))
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
    const struct json_value *post;
    if (!fmc_board_input(input, sizeof(input), ref)) {
        fmc_fail(reply, "BAD_INPUT", "ref cannot be encoded", "text or input bound");
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
        if (strcmp(sub.reply.error.code, "NOT_FOUND") == 0)
            fmc_fail(reply, "EVIDENCE_NOT_FOUND",
                     "this node holds no post with that id",
                     "fleet.board.show");
        else {
            const char *cause = "fleet.board.show";
            const char *code = sub.reply.error.code;
            if (strcmp(code, "NODE_UNAVAILABLE") == 0 ||
                strcmp(code, "BOARD_READ_FAILED") == 0 ||
                strcmp(code, "BOARD_RPC_UNSUPPORTED") == 0)
                cause = code;
            fmc_fail(reply, "EVIDENCE_UNAVAILABLE",
                     "the board lookup could not establish whether the post is held",
                     cause);
            (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                           "inspect the selected node and board storage logs before retrying");
        }
        fmc_sub_end(&sub);
        return;
    }
    post = json_get(&sub.reply.data, "post");
    if (!post || post->type != JSON_OBJ)
        post = &sub.reply.data;
    fmc_emit_object(reply, "board", post);
    fmc_sub_end(&sub);
}

static void fmc_evidence_land(const struct zcl_command_request *req,
    struct zcl_command_reply *reply, const char *ref)
{
    struct fmc_sub sub;
    struct json_value missing = {0}, proof = {0};
    json_set_array(&missing);
    if (!fmc_land_read(req, &sub, &missing, NULL, NULL)) {
        fmc_fail(reply, "EVIDENCE_UNAVAILABLE", "landing status did not answer", "dev.land");
        goto done;
    }
    const struct json_value *hit = NULL;
    const struct json_value *flight = json_get(&sub.reply.data, "in_flight");
    if (strcmp(fmc_row_field(flight, "tip"), ref) == 0 &&
        fmc_evidence_exact(req, flight)) hit = flight;
    const char *const sections[] = {"queued", "outcomes"};
    for (size_t s = 0; s < 2; s++) {
        const struct json_value *arr = json_get(&sub.reply.data, sections[s]);
        if (!arr || arr->type != JSON_ARR) continue;
        for (size_t i = 0; i < json_size(arr); i++) {
            const struct json_value *row = json_at(arr, i);
            if (strcmp(fmc_row_field(row, "tip"), ref) == 0 &&
                fmc_evidence_exact(req, row)) hit = row;
        }
    }
    if (!hit) {
        fmc_fail(reply, "EVIDENCE_NOT_FOUND", "the exact landing attempt was not retained", ref);
        goto done;
    }
    if (hit == flight) fmc_land_proof(req, flight, &proof, &missing);
    fmc_emit_object(reply, "land", hit);
    (void)json_push_kv(&reply->data, "proof_observation", &proof);
    (void)json_push_kv(&reply->data, "missing", &missing);
done:
    json_free(&proof);
    json_free(&missing);
    fmc_sub_end(&sub);
}

static bool fmc_evidence_mail_selectors(const struct json_value *input)
{
    unsigned char decoded[32];
    const struct json_value *stream = json_get(input, "stream");
    const struct json_value *offset = json_get(input, "row_offset");
    const struct json_value *hash = json_get(input, "row_sha3");
    const struct json_value *seq = json_get(input, "seq");
    return stream && stream->type == JSON_STR && json_get_str(stream)[0] &&
        offset && offset->type == JSON_INT && json_get_int(offset) >= 0 &&
        seq && seq->type == JSON_INT && json_get_int(seq) > 0 &&
        hash && hash->type == JSON_STR && zcl_hex_decode_lower(json_get_str(hash), decoded, sizeof(decoded));
}

static bool fmc_evidence_selectors(const struct zcl_command_request *req,
    const char *type)
{
    const struct json_value *seq = json_get(req->input, "seq");
    const struct json_value *attempt = json_get(req->input, "attempt");
    const struct json_value *stream = json_get(req->input, "stream");
    const struct json_value *offset = json_get(req->input, "row_offset");
    const struct json_value *hash = json_get(req->input, "row_sha3");
    if (stream || offset || hash) {
        return !strcmp(type, "mail") && !attempt && fmc_evidence_mail_selectors(req->input);
    }
    if (!seq && !attempt) return strcmp(type, "land") != 0;
    return (strcmp(type, "queue") == 0 || strcmp(type, "land") == 0) &&
        seq && seq->type == JSON_INT && json_get_int(seq) > 0 &&
        attempt && attempt->type == JSON_INT && json_get_int(attempt) > 0;
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
                 "type in {mail,queue,board,land}, ref exact");
        return;
    }
    const struct json_value *kind_value = json_get(req->input, "kind");
    if (kind_value &&
        (kind_value->type != JSON_STR || !json_get_str(kind_value)[0] ||
         strcmp(type, "mail") != 0 ||
         !zcl_devagent_name_ok(json_get_str(kind_value)))) {
        fmc_fail(reply, "BAD_INPUT", "evidence kind must be a mail row kind",
                 "mail: kind is optional and uses the row's exact kind");
        return;
    }
    if (!fmc_evidence_selectors(req, type)) {
        fmc_fail(reply, "BAD_INPUT", "evidence selectors must match the requested type",
            "mail: stream,row_offset,seq,row_sha3 together; queue: seq,attempt together; land requires seq,attempt; board has no selectors");
        return;
    }
    if (strcmp(type, "land") == 0)
        fmc_evidence_land(req, reply, ref);
    else if (strcmp(type, "mail") == 0)
        fmc_evidence_mail(req, reply, ref);
    else if (strcmp(type, "queue") == 0)
        fmc_evidence_queue(req, reply, ref);
    else if (strcmp(type, "board") == 0)
        fmc_evidence_board(req, reply, ref);
    else
        fmc_fail(reply, "BAD_INPUT", "unknown evidence type",
                 "type in {mail,queue,board,land}");
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
    static const char *const names[] = {"brief", "send", "evidence",
                                        "terminate", "deliver", "wiki-write"};
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
    const char *peer; /* "" for a local bearer grant */
    long long ttl;
};

/* A peer grant names one roster box by the roster's own name grammar, and
 * it only means something as "this label may send from that box", so it
 * needs the label and the send scope. False with the reply failed. */
static bool fmc_grant_peer_input(const struct zcl_command_request *req,
                                 struct zcl_command_reply *reply,
                                 struct fmc_mint_in *in)
{
    in->peer = fmc_str(req, "peer");
    if (!in->peer || !in->peer[0]) {
        in->peer = "";
        return true;
    }
    if (!fleet_enrol_name_valid(in->peer) || strlen(in->peer) > FMC_PEER_MAX) {
        fmc_fail(reply, "BAD_INPUT",
                 "peer is a fleet roster name: 2..24 of [a-z0-9-]",
                 "input.peer has an illegal spelling");
        return false;
    }
    if (!in->label || !in->label[0] || !fmc_scope_has(in->scopes, "send")) {
        fmc_fail(reply, "BAD_INPUT",
                 "a peer grant needs a label and the send scope",
                 "input.peer without label or send");
        return false;
    }
    return true;
}

static bool fmc_grant_inputs(const struct zcl_command_request *req,
                             struct zcl_command_reply *reply,
                             struct fmc_mint_in *in)
{
    long long tmp;
    in->scopes = fmc_str(req, "scopes");
    if (!in->scopes || !fmc_scopes_valid(in->scopes)) {
        fmc_fail(reply, "BAD_INPUT",
                 "scopes is a subset of brief,send,evidence,terminate,deliver,wiki-write",
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
    return fmc_grant_peer_input(req, reply, in);
}

/* The optional peer member of a grant row, written only when the grant
 * names one, so every local grant row keeps its exact old shape. Its
 * alphabet was checked at mint, so it needs no escaping. */
static void fmc_grant_peer_part(const char *peer, char *out, size_t cap)
{
    out[0] = '\0';
    if (peer && peer[0])
        (void)snprintf(out, cap, ",\"peer\":\"%s\"", peer);
}

static void fmc_grant_mint(const struct zcl_command_request *req,
                           struct zcl_command_reply *reply)
{
    struct fmc_mint_in in;
    char peer_part[FMC_PEER_MAX + 16];
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
    fmc_grant_peer_part(in.peer, peer_part, sizeof(peer_part));
    n = snprintf(line, sizeof(line),
                 "{\"id\":\"%s\",\"scopes\":\"%s\",\"created\":%lld,"
                 "\"expires\":%lld,\"revoked\":\"0\",\"label\":\"%s\"%s}\n",
                 id, in.scopes, (long long)now, expires,
                 in.label ? in.label : "", peer_part);
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
    if (in.peer[0])
        (void)json_push_kv_str(&reply->data, "peer", in.peer);
    (void)json_push_kv_int(&reply->data, "expires", expires);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* ── grant inventory (action=list) ───────────────────────────────────────
 *
 * Until this existed there was NO way to ask what credentials were live:
 * mint returned an id once and revoke took one away, and anything in
 * between meant reading the JSONL by hand. Eight forgotten full-scope
 * grants is what that costs, and an owner rule that says "revocation is
 * how access ends" only holds if the owner can see what there is to
 * revoke.
 *
 * WHAT IT DOES NOT PRINT: the grant id. A listing that carried whole ids
 * would BE a credential file — anything that could read it could use every
 * grant in it. It prints the first 8 hex characters, which name a row for
 * a human without admitting anyone: every check demands the full 32. */
/* The store keeps every row; the listing HOLDS the newest 1024 distinct ids
 * and serves them in pages of at most FMC_GRANT_PAGE_MAX rows. */
#define FMC_GRANT_LIST_CAP 1024u
#define FMC_GRANT_PAGE_DEFAULT 32u
#define FMC_GRANT_PAGE_MAX 128u
/* Row bytes one page may carry, so it always serializes inside the leaf budget. */
#define FMC_GRANT_PAGE_BYTES 24000u
#define FMC_GRANT_PREFIX 8u

/* Keep the LAST row per id (later rows supersede), bounded, oldest id
 * evicted first so a long store still shows its newest grants.
 * Returns true when `g` is a distinct id the caller has not counted yet. */
static bool fmc_list_put(struct fmc_grant *set, size_t *n,
                         const struct fmc_grant *g)
{
    size_t i;
    for (i = 0; i < *n; i++) {
        if (fmc_grant_id_eq(set[i].id, g->id)) {
            set[i] = *g;
            return false;
        }
    }
    if (*n < FMC_GRANT_LIST_CAP) {
        set[(*n)++] = *g;
        return true;
    }
    memmove(set, set + 1, (FMC_GRANT_LIST_CAP - 1) * sizeof(set[0]));
    set[FMC_GRANT_LIST_CAP - 1] = *g;
    return true;
}

/* The one word that answers "can this credential be used right now". */
static const char *fmc_grant_state(const struct fmc_grant *g, long long now)
{
    if (g->revoked)
        return "revoked";
    if (g->peer[0])
        return "peer";
    if (g->expires != 0 && now >= g->expires)
        return "expired";
    return "live";
}

static void fmc_list_emit(struct json_value *arr, const struct fmc_grant *g,
                          long long now)
{
    struct json_value row;
    char prefix[FMC_GRANT_PREFIX + 1];
    json_init(&row);
    json_set_object(&row);
    memcpy(prefix, g->id, FMC_GRANT_PREFIX);
    prefix[FMC_GRANT_PREFIX] = '\0';
    (void)json_push_kv_str(&row, "id_prefix", prefix);
    (void)json_push_kv_str(&row, "label", g->label);
    (void)json_push_kv_str(&row, "scopes", g->scopes);
    if (g->peer[0])
        (void)json_push_kv_str(&row, "peer", g->peer);
    (void)json_push_kv_int(&row, "created", g->created);
    (void)json_push_kv_int(&row, "expires", g->expires);
    (void)json_push_kv_bool(&row, "revoked", g->revoked != 0);
    (void)json_push_kv_str(&row, "state", fmc_grant_state(g, now));
    (void)json_push_back(arr, &row);
    json_free(&row);
}

/* Collapse the append-only store to its current rows. Returns how many
 * ids the window kept. *total counts an id once while that id stays in
 * the window; a later row for an id still held supersedes it and is not
 * another grant. An id already evicted is no longer recognized. */
static size_t fmc_list_collect(const char *path, struct fmc_grant *set,
                               size_t *total, bool *complete)
{
    FILE *f;
    char line[FMC_LINE_CAP];
    struct fmc_grant g;
    size_t n = 0;
    int status;
    *complete = true;
    *total = 0;
    f = fopen(path, "rb");
    if (!f)
        return 0;
    while ((status = fmc_grant_line_read(f, line)) > 0) {
        if (!fmc_grant_parse(line, &g))
            continue;
        /* A later row for an id already counted supersedes that row. It is
         * not another grant, even when the window is already full. */
        if (fmc_list_put(set, &n, &g))
            (*total)++;
    }
    *complete = fmc_grant_scan_end(f, status);
    if (!*complete) { *total = 0; return 0; }
    return n;
}

/* Page bounds: limit 1..128 (default 32) and before, the ordinal a previous
 * page returned as `next` (default: the newest). False with reply failed. */
static bool fmc_list_page_in(const struct zcl_command_request *req,
                             struct zcl_command_reply *reply,
                             size_t *limit, long long *before)
{
    long long v;
    *limit = FMC_GRANT_PAGE_DEFAULT;
    *before = -1;
    if (fmc_int(req, "limit", &v)) {
        if (v < 1 || v > (long long)FMC_GRANT_PAGE_MAX) {
            fmc_fail(reply, "BAD_INPUT", "limit is 1..128", "grant list page");
            return false;
        }
        *limit = (size_t)v;
    }
    if (fmc_int(req, "before", &v)) {
        if (v < 0) {
            fmc_fail(reply, "BAD_INPUT",
                     "before is the next value of a previous page",
                     "grant list cursor");
            return false;
        }
        *before = v;
    }
    return true;
}

/* Newest-first page of the held ids below ordinal `before`. An id's ordinal
 * is its position in first-seen order, so it never moves when a revoke row
 * supersedes it and a newer mint never shifts an older page. *next is the
 * ordinal to pass back as `before`, or -1 when this page reached the oldest
 * held id. */
static size_t fmc_list_page(const struct fmc_grant *set, size_t n,
                            size_t total, long long before, size_t limit,
                            long long now, struct json_value *arr,
                            long long *next)
{
    size_t floor = total - n, shown = 0, bytes = 0;
    size_t top = (before < 0 || (size_t)before > total) ? total : (size_t)before;
    *next = -1;
    while (top > floor && shown < limit) {
        const struct fmc_grant *g = &set[top - 1 - floor];
        size_t before_n = json_size(arr);
        fmc_list_emit(arr, g, now);
        bytes += json_write(json_at(arr, before_n), NULL, 0) + 1;
        top--;
        shown++;
        if (bytes >= FMC_GRANT_PAGE_BYTES)
            break;
    }
    if (top > floor)
        *next = (long long)top;
    return shown;
}

static void fmc_grant_list(const struct zcl_command_request *req,
                           struct zcl_command_reply *reply)
{
    char steerdir[4096], path[4096 + 32];
    struct fmc_grant *set;
    struct json_value arr;
    size_t n, shown, limit, total = 0, live = 0;
    long long now, before, next = -1;
    int r;
    bool complete;
    if (!fmc_list_page_in(req, reply, &limit, &before))
        return;
    if (!fmc_dirs(steerdir, sizeof(steerdir))) {
        fmc_fail(reply, "STATE_DIR_FAILED",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    r = snprintf(path, sizeof(path), "%s/grants.jsonl", steerdir);
    if (r <= 0 || (size_t)r >= sizeof(path)) {
        fmc_fail(reply, "STATE_DIR_FAILED", "grant path exceeds its bound",
                 steerdir);
        return;
    }
    set = (struct fmc_grant *)zcl_calloc(FMC_GRANT_LIST_CAP, sizeof(*set),
                                         "fleet.steer.grant");
    if (!set) {
        fmc_fail(reply, "GRANT_LIST_FAILED",
                 "cannot hold the grant inventory", "row budget");
        return;
    }
    now = (long long)platform_time_wall_time_t();
    n = fmc_list_collect(path, set, &total, &complete);
    json_init(&arr);
    json_set_array(&arr);
    shown = fmc_list_page(set, n, total, before, limit, now, &arr,
                          &next);
    for (size_t i = 0; i < n; i++)
        if (strcmp(fmc_grant_state(&set[i], now), "live") == 0)
            live++;
    free(set);
    if (!complete) {
        json_free(&arr);
        fmc_fail(reply, "GRANT_LIST_FAILED", "grant store is incomplete", path);
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", FMC_GRANT_LEAF);
    (void)json_push_kv(&reply->data, "grants", &arr);
    (void)json_push_kv_int(&reply->data, "shown", (long long)shown);
    (void)json_push_kv_int(&reply->data, "total", (long long)total);
    (void)json_push_kv_int(&reply->data, "live", (long long)live);
    /* truncated: older held grants remain; pass next back as before. */
    (void)json_push_kv_bool(&reply->data, "truncated", next >= 0);
    if (next >= 0)
        (void)json_push_kv_int(&reply->data, "next", next);
    /* Ids older than the held window cannot be listed; say so. */
    (void)json_push_kv_int(&reply->data, "unlisted",
                           (long long)(total - n));
    /* Say it in the reply, not only in the docs: the ids are cut short on
     * purpose, and revoke still needs the whole one. */
    (void)json_push_kv_str(&reply->data, "id_note",
                           "id_prefix is the first 8 characters; revoke "
                           "needs the full 32-character id from mint");
    json_free(&arr);
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

static int fmc_ref_compare(const void *a, const void *b)
{ return strcmp(a, b); }

/* 1: bounded text row, 0: EOF, -1: NUL, oversized row or read error. */
static int fmc_revoke_read_line(FILE *f, char line[FMC_LINE_CAP])
{
    size_t len = 0;
    int ch;
    while (len + 1 < FMC_LINE_CAP && (ch = fgetc(f)) != EOF) {
        if (ch == '\0') {
            LOG_ERROR(FMC_LOG, "revoke: NUL in sent row");
            return -1;
        }
        line[len++] = (char)ch;
        if (ch == '\n') break;
    }
    if (ferror(f) || (len + 1 == FMC_LINE_CAP && line[len - 1] != '\n' &&
                     (fgetc(f) != EOF || ferror(f)))) {
        LOG_ERROR(FMC_LOG, "revoke: sent row unreadable or exceeds bound");
        return -1;
    }
    line[len] = '\0';
    if (len && !json_valid(line, len)) {
        LOG_ERROR(FMC_LOG, "steer: malformed sent JSON record");
        return -1;
    }
    return len ? 1 : 0;
}

/* Page distinct refs after the previous lexical cursor. Each read has a
 * 4096-row budget; SIZE_MAX refuses coverage. Rows without a grant
 * or ref are skipped; an absent store yields 0. */
static size_t fmc_revoke_refs(const char *sent_path, const char *grant_id,
                              char refs[][FMC_REF_MAX + 1], const char *after)
{
    FILE *f;
    char line[FMC_LINE_CAP];
    char grant[64], ref[FMC_REF_MAX + 1];
    size_t nrefs = 0, rows = 0, cap = 64;
    int read_rc;
    f = fopen(sent_path, "rb");
    if (!f)
        return errno == ENOENT ? 0 : SIZE_MAX;
    while ((read_rc = fmc_revoke_read_line(f, line)) > 0) {
        if (++rows > 4096) { nrefs = SIZE_MAX; break; }
        if (!fmc_grant_line_str(line, "grant", grant, sizeof(grant)))
            continue;
        if (strcmp(grant, grant_id) != 0)
            continue;
        if (!fmc_grant_line_str(line, "ref", ref, sizeof(ref)))
            continue;
        if (strcmp(ref, after) <= 0)
            continue;
        if (fmc_ref_seen(refs, nrefs, ref))
            continue;
        if (nrefs >= cap) {
            if (strcmp(ref, refs[cap - 1]) >= 0) continue;
            nrefs--;
        }
        (void)snprintf(refs[nrefs], sizeof(refs[nrefs]), "%s", ref);
        nrefs++;
        qsort(refs, nrefs, sizeof(refs[0]), fmc_ref_compare);
    }
    bool failed = read_rc < 0 || ferror(f) != 0;
    failed |= fclose(f) != 0;
    return failed ? SIZE_MAX : nrefs;
}

static long long fmc_reply_int(const struct fmc_sub *sub, const char *key)
{
    const struct json_value *v = json_get(&sub->reply.data, key);
    if (!v || v->type != JSON_INT)
        return 0;
    return (long long)json_get_int(v);
}

static bool fmc_reply_bool(const struct fmc_sub *sub, const char *key)
{
    const struct json_value *v = json_get(&sub->reply.data, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

/* Cancel one queue row by ref. `terminate` is the grant's explicit
 * authority to end a running row's claim on later stages. Without it a
 * running row is counted in *continued and left in place. */
static bool fmc_revoke_cancel_one(const struct zcl_command_request *req,
                                  const char *ref, bool terminate,
                                  long long *cancelled, long long *terminated,
                                  long long *continued)
{
    struct fmc_sub sub;
    bool complete = false;
    char input[512];
    int n;
    *cancelled = 0;
    *terminated = 0;
    *continued = 0;
    n = terminate
            ? snprintf(input, sizeof(input),
                       "{\"action\":\"cancel\",\"name\":\"%s\","
                       "\"terminate\":true}",
                       ref)
            : snprintf(input, sizeof(input),
                       "{\"action\":\"cancel\",\"name\":\"%s\"}", ref);
    if (n <= 0 || (size_t)n >= sizeof(input)) {
        LOG_ERROR(FMC_LOG, "revoke: cancel input exceeds bound (ref=%s)", ref);
        return false;
    }
    fmc_sub_begin(&sub, "zcl.agent_queue.v1", req, "dev.agent.queue");
    if (!sub.valid || !fmc_sub_input(&sub, input)) {
        LOG_ERROR(FMC_LOG, "revoke: cannot prepare queue cancel (ref=%s)", ref);
        fmc_sub_end(&sub);
        return false;
    }
    zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
    sub.ran = true;
    if (fmc_sub_ok(&sub)) {
        complete = true;
        *cancelled = fmc_reply_int(&sub, "cancelled");
        *terminated = fmc_reply_int(&sub, "terminated");
        if (fmc_reply_bool(&sub, "running_continues"))
            *continued = 1;
    } else if (strcmp(sub.reply.error.code, "CANCEL_RUNNING") == 0) {
        *continued = 1;
        complete = true;
    } else if (strcmp(sub.reply.error.code, "CANCEL_NOT_FOUND") == 0) {
        complete = true;
    } else {
        LOG_ERROR(FMC_LOG, "revoke: queue cancel refused (ref=%s code=%s)",
                  ref, sub.reply.error.code);
    }
    fmc_sub_end(&sub);
    return complete;
}

/* At most 64 cancellation pages plus one exhaustion read; refuse leftovers. */
static bool fmc_revoke_cancel_queued(const struct zcl_command_request *req,
                                     const char *sent_path,
                                     const char *grant_id, bool terminate,
                                     long long *cancelled,
                                     long long *terminated,
                                     long long *continued)
{
    char refs[64][FMC_REF_MAX + 1] = {{0}}, after[FMC_REF_MAX + 1] = "";
    size_t nrefs, i;
    *cancelled = 0;
    *terminated = 0;
    *continued = 0;
    for (unsigned page = 0; page <= 64; page++) {
        nrefs = fmc_revoke_refs(sent_path, grant_id, refs, after);
        if (nrefs == SIZE_MAX || (page == 64 && nrefs)) break;
        for (i = 0; i < nrefs; i++) {
            long long c = 0, t = 0, k = 0;
            if (!fmc_revoke_cancel_one(req, refs[i], terminate, &c, &t, &k)) return false;
            *cancelled += c;
            *terminated += t;
            *continued += k;
        }
        if (nrefs < 64) return true;
        memcpy(after, refs[nrefs - 1], sizeof(after));
    }
    LOG_ERROR(FMC_LOG, "revoke: incomplete ref coverage (%s)", sent_path);
    return false;
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
    char peer_part[FMC_PEER_MAX + 16];
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
    /* ...and the ORIGINAL peer, so a revoked peer grant still reads as
     * that peer's revoked grant rather than as a local one. */
    fmc_grant_peer_part(g.peer, peer_part, sizeof(peer_part));
    m = snprintf(line, sizeof(line),
                 "{\"id\":\"%s\",\"scopes\":\"%s\",\"created\":%lld,"
                 "\"expires\":%lld,\"revoked\":\"1\",\"label\":\"%s\"%s}\n",
                 id, g.scopes, (long long)now, g.expires, g.label, peer_part);
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
        long long cancelled = 0, terminated = 0, continued = 0;
        bool complete = false;
        int s;
        s = snprintf(sent_path, sizeof(sent_path), "%s/sent.jsonl",
                     steerdir);
        if (s > 0 && (size_t)s < sizeof(sent_path))
            complete = fmc_revoke_cancel_queued(req, sent_path, id,
                                     fmc_scope_has(g.scopes, "terminate"),
                                     &cancelled, &terminated, &continued);
        (void)json_push_kv_str(&reply->data, "leaf", FMC_GRANT_LEAF);
        (void)json_push_kv_str(&reply->data, "id", id);
        (void)json_push_kv_bool(&reply->data, "revoked", true);
        (void)json_push_kv_int(&reply->data, "cancelled", cancelled);
        (void)json_push_kv_int(&reply->data, "terminated", terminated);
        (void)json_push_kv_int(&reply->data, "running_continued", continued);
        if (!complete) {
            fmc_fail(reply, "REVOKE_CANCEL_INCOMPLETE",
                     "grant revoked; queued cancellation coverage is incomplete",
                     "queued ref coverage");
            reply->error.mutated = true;
            return;
        }
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* ── public entry points ─────────────────────────────────────────────────
 *
 * One thin wrapper per leaf: check the verb's grant scope, then run. The
 * grant key is optional; without one the call is the local operator's own,
 * which dispatch already authorized per leaf. */

/* Admit the call for one verb scope. False with the reply failed when the
 * credential is refused; otherwise *who names the caller (operator mode
 * when no grant was presented). */
static bool fmc_admit(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply, const char *scope,
                      const char *need, struct fmc_caller *who)
{
    struct fmc_grant row;
    const char *refused;
    memset(who, 0, sizeof(*who));
    if (!request || !request->input) {
        fmc_fail(reply, "BAD_INPUT", need, "request.input was missing");
        return false;
    }
    refused = fmc_grant_check_row(fmc_str(request, "grant"), scope, &row);
    if (refused) {
        fmc_fail(reply, refused, "the grant does not allow this verb",
                 "grant scope/expiry/revocation");
        return false;
    }
    if (row.id[0]) {
        who->grant = true;
        (void)snprintf(who->label, sizeof(who->label), "%s", row.label);
        (void)snprintf(who->scopes, sizeof(who->scopes), "%s", row.scopes);
        who->expires = row.expires;
        if (!strcmp(scope, "wiki-write") &&
            !zcl_fleet_steer_sender_binding(row.id, row.label,
                who->binding, sizeof(who->binding))) {
            fmc_fail(reply, "GRANT_BINDING", "wiki writes require an attributable grant", "grant label/id");
            return false;
        }
    }
    return true;
}

static void fmc_enter(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply, const char *scope,
                      const char *need,
                      void (*run)(const struct zcl_command_request *,
                                  struct zcl_command_reply *))
{
    struct fmc_caller who;
    if (fmc_admit(request, reply, scope, need, &who))
        run(request, reply);
}

/* Same as fmc_enter for a verb whose run function also reports the caller. */
static void fmc_enter_who(const struct zcl_command_request *request,
                          struct zcl_command_reply *reply, const char *scope,
                          const char *need,
                          void (*run)(const struct zcl_command_request *,
                                      struct zcl_command_reply *,
                                      const struct fmc_caller *))
{
    struct fmc_caller who;
    if (fmc_admit(request, reply, scope, need, &who))
        run(request, reply, &who);
}

static bool fmc_mail_obs_name(const char *name)
{
    size_t n;
    if (!name)
        return false;
    n = strlen(name);
    if (n >= 7 && memcmp(name + (n - 6), ".jsonl", 6) == 0)
        return true;
    if (strncmp(name, "cursor.", 7) == 0)
        return true;
    return strncmp(name, "read.", 5) == 0;
}

static void fmc_fnv_bytes(uint64_t *h, const void *p, size_t n)
{
    const unsigned char *b = p;
    size_t i;
    for (i = 0; i < n; i++) {
        *h ^= b[i];
        *h *= UINT64_C(0x100000001b3);
    }
}

static void fmc_fnv_str(uint64_t *h, const char *s)
{
    if (s)
        fmc_fnv_bytes(h, s, strlen(s));
    fmc_fnv_bytes(h, "\n", 1);
}

static void fmc_gen_hex_out(uint64_t h, char out[17])
{
    snprintf(out, 17, "%016llx", (unsigned long long)h);
}

/* Informational mail generation cannot bind nonmail state or time and must
 * never authorize skipping a fresh brief.
 * Names and sizes of every mail stream and ack file. A later file's size
 * is part of the generation: skipping a tail would hide a new message.
 * Missing mail is a stable empty generation. Bodies and mtimes are not read. */
static void fmc_observation_mix(uint64_t *h,
                                const struct platform_directory_list *files)
{
    size_t i;
    for (i = 0; i < files->count; i++) {
        const struct platform_directory_entry *e = &files->entries[i];
        char size[32];
        int n;
        if (!fmc_mail_obs_name(e->name))
            continue;
        fmc_fnv_str(h, e->name);
        if (!e->snapshot_valid) {
            fmc_fnv_str(h, "nosnap");
            continue;
        }
        n = snprintf(size, sizeof(size), "%llu", (unsigned long long)e->size);
        if (n > 0)
            fmc_fnv_str(h, size);
    }
}

static void fmc_observation_generation(char out[17])
{
    char root[4096], dir[4200];
    struct platform_directory_list files;
    uint64_t h = UINT64_C(0xcbf29ce484222325);
    int n;
    memset(&files, 0, sizeof(files));
    if (!platform_state_root_existing(root, sizeof(root))) {
        fmc_gen_hex_out(h, out);
        return;
    }
    n = snprintf(dir, sizeof(dir), "%s/mail", root);
    if (n <= 0 || (size_t)n >= sizeof(dir) ||
        platform_directory_probe_real(dir) != PLATFORM_DIRECTORY_PROBE_OK ||
        !platform_directory_list_regular_sorted(dir, &files)) {
        fmc_gen_hex_out(h, out);
        return;
    }
    fmc_observation_mix(&h, &files);
    platform_directory_list_free(&files);
    fmc_gen_hex_out(h, out);
}

static void fmc_brief_put_observation(struct json_value *data)
{
    char live[17];
    if (!data || json_get(data, "observation_generation"))
        return;
    fmc_observation_generation(live);
    (void)json_push_kv_str(data, "observation_generation", live);
    (void)json_push_kv_bool(data, "not_modified", false);
}

/* Stamp only when the measured fields fit in the slack the fit held. */
static void fmc_brief_observe_if_fits(struct json_value *data, size_t budget)
{
    size_t used;
    if (!data || budget == 0 || json_get(data, "observation_generation"))
        return;
    used = json_write(data, NULL, 0);
    if (used > budget || budget - used < FMC_BRIEF_OBS_BYTES)
        return;
    fmc_brief_put_observation(data);
}

void zcl_native_handle_fleet_steer_brief(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    fmc_enter_who(request, reply, "brief",
                  "fleet.steer.brief takes grant,since,limit,json,changes_only,generation",
                  fmc_do_brief);
}

void zcl_native_handle_fleet_steer_send(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    fmc_enter(request, reply, "send", "fleet.steer.send takes grant,items,from",
              fmc_do_send);
}

/* ── mailbox ─────────────────────────────────────────────────────────────
 *
 * One recipient's mail, a bounded page at a time. The mail leaf already
 * pages the whole store with an exact `to`/`from` filter and a resume
 * token; this verb adds the ref-prefix filter, the body bound and the
 * authority rule (a grant reads only the inbox whose recipient label it
 * holds), and returns rows newest-last with an opaque `cursor`.
 *
 * CURSOR. "<mail resume token>" or "<token>~<n>": resume at the token and
 * skip its first n matching rows. A page therefore ends exactly at the
 * row limit or the byte bound, and the next call starts on the very next
 * row: no gap, no repeat. Pass the returned cursor back as `since`. */
#define FMC_MBOX_LIMIT_DEFAULT 20
#define FMC_MBOX_LIMIT_MAX 64
#define FMC_MBOX_BODY_MAX 480u
#define FMC_MBOX_ROW_BYTES 40000u
#define FMC_MBOX_PAGES_MAX 64
#define FMC_MBOX_SCREEN_BODY 72u

/* Longest prefix of s within cap bytes that ends on a UTF-8 boundary. */
static size_t fmc_mbox_cut(const char *s, size_t cap)
{
    size_t n = strlen(s);
    if (n <= cap)
        return n;
    while (cap > 0 && ((unsigned char)s[cap] & 0xC0u) == 0x80u)
        cap--;
    return cap;
}

struct fmc_mbox {
    struct json_value rows;
    char screen[8192];
    size_t screen_len;
    size_t screen_dropped;
    size_t bytes;
    size_t emitted;
    size_t limit;
    size_t bodies_truncated;
};

static void fmc_mbox_screen_line(struct fmc_mbox *m, const struct fmc_row *v)
{
    char flat[FMC_MBOX_SCREEN_BODY + 4];
    size_t take = fmc_mbox_cut(v->body, FMC_MBOX_SCREEN_BODY), i;
    bool cut = strlen(v->body) > take;
    int w;
    for (i = 0; i < take; i++) {
        char c = v->body[i];
        flat[i] = (c == '\n' || c == '\r' || c == '\t') ? ' ' : c;
    }
    flat[take] = '\0';
    w = snprintf(m->screen + m->screen_len,
                 sizeof(m->screen) - 128 - m->screen_len,
                 "#%lld %s %s\xe2\x86\x92%s %s %s: %s%s\n", v->seq, v->ts,
                 v->from, v->to, v->kind, v->ref[0] ? v->ref : "-", flat,
                 cut ? "..." : "");
    if (w > 0 && (size_t)w < sizeof(m->screen) - 128 - m->screen_len)
        m->screen_len += (size_t)w;
    else
        m->screen_dropped++;
}

static bool fmc_mbox_locator_valid(const struct fmc_row *v)
{
    unsigned char hash[32];
    size_t n = strlen(v->stream);
    return n >= 7 && fmc_is_token(v->stream, 128, false) &&
        !strcmp(v->stream + n - 6, ".jsonl") && v->seq > 0 && v->row_offset >= 0 &&
        v->row_end > v->row_offset && strlen(v->row_sha3) == 64 &&
        zcl_hex_decode_lower(v->row_sha3, hash, sizeof(hash));
}

static bool fmc_mbox_fields(struct json_value *o, const struct fmc_row *v,
                            const char *body, size_t take, size_t full)
{
    return json_push_kv_int(o, "seq", v->seq) &&
        json_push_kv_str(o, "ts", v->ts) &&
        json_push_kv_str(o, "from", v->from) &&
        json_push_kv_str(o, "to", v->to) &&
        json_push_kv_str(o, "kind", v->kind) &&
        json_push_kv_str(o, "ref", v->ref) &&
        json_push_kv_str(o, "body", body) &&
        json_push_kv_bool(o, "body_truncated", take < full) &&
        json_push_kv_int(o, "body_bytes", (long long)full) &&
        fmc_row_locator(o, v);
}

/* Append one row; false when the row bytes would pass the page bound (the
 * caller stops BEFORE this row so the cursor stays exact). */
static bool fmc_mbox_add(struct fmc_mbox *m, const struct fmc_row *v)
{
    struct json_value o;
    char body[FMC_MBOX_BODY_MAX + 1];
    size_t full = strlen(v->body), take = fmc_mbox_cut(v->body, FMC_MBOX_BODY_MAX);
    size_t size;
    bool ok;
    memcpy(body, v->body, take);
    body[take] = '\0';
    json_init(&o);
    json_set_object(&o);
    ok = fmc_mbox_fields(&o, v, body, take, full);
    size = ok ? json_write(&o, NULL, 0) + 1 : 0;
    if (!ok || (m->emitted > 0 && m->bytes + size > FMC_MBOX_ROW_BYTES) ||
        !json_push_back(&m->rows, &o)) {
        json_free(&o);
        return false;
    }
    json_free(&o);
    m->bytes += size;
    m->emitted++;
    if (take < full)
        m->bodies_truncated++;
    fmc_mbox_screen_line(m, v);
    return true;
}

/* `since` as the (token, skip) pair; a bare integer is a token too. */
static bool fmc_mbox_cursor(const struct zcl_command_request *req, char *tok,
                            size_t cap, size_t *skip)
{
    const char *s = fmc_str(req, "since");
    long long iv;
    char *tilde;
    *skip = 0;
    tok[0] = '\0';
    if (!s && fmc_int(req, "since", &iv) && iv >= 0)
        return snprintf(tok, cap, "%lld", iv) > 0;
    if (!s || !s[0])
        return true;
    if (strlen(s) >= cap)
        return false;
    memcpy(tok, s, strlen(s) + 1);
    tilde = strrchr(tok, '~');
    if (tilde) {
        char *end;
        long long n = strtoll(tilde + 1, &end, 10);
        if (tilde[1] == '\0' || *end != '\0' || n < 0 || n > 1000000)
            return false;
        *skip = (size_t)n;
        *tilde = '\0';
    }
    return tok[0] != '\0';
}

static bool fmc_mbox_inputs(const struct zcl_command_request *req,
                            struct zcl_command_reply *reply,
                            struct fmc_mbox *m, const char **to,
                            const char **from, const char **prefix)
{
    long long lim;
    *to = fmc_str(req, "to");
    *from = fmc_str(req, "from");
    *prefix = fmc_str(req, "ref");
    m->limit = FMC_MBOX_LIMIT_DEFAULT;
    if (!*to || !fmc_is_token(*to, FMC_NAME_MAX, false) ||
        (*from && *from[0] && !fmc_is_token(*from, FMC_NAME_MAX, false)) ||
        (*prefix && strlen(*prefix) > FMC_REF_MAX)) {
        fmc_fail(reply, "BAD_INPUT",
                 "mailbox needs to (a label); from and ref are optional",
                 "to/from short tokens; ref prefix at most 128 bytes");
        return false;
    }
    if (fmc_int(req, "limit", &lim)) {
        if (lim < 1 || lim > FMC_MBOX_LIMIT_MAX) {
            fmc_fail(reply, "BAD_INPUT", "limit is 1..64", "mailbox page");
            return false;
        }
        m->limit = (size_t)lim;
    }
    return true;
}

/* The mail leaf takes a bare integer or a resume token as `since`. */
static bool fmc_mbox_since_push(struct json_value *input, const char *tok)
{
    bool digits = tok[0] != '\0';
    for (const char *p = tok; *p; p++)
        digits = digits && *p >= '0' && *p <= '9';
    if (digits)
        return json_push_kv_int(input, "since", atoll(tok));
    return json_push_kv_str(input, "since", tok);
}

/* One mail-leaf page for (tok, to, from) into sub. NULL on success. */
static const char *fmc_mbox_pull(struct fmc_sub *sub,
                                 const struct zcl_command_request *req,
                                 const char *tok, const char *to,
                                 const char *from)
{
    const struct json_value *next, *arr, *tr;
    fmc_sub_begin(sub, "zcl.agent_mail.v1", req, "dev.agent.mail");
    if (!sub->valid)
        return "unknown_sibling";
    if (!json_push_kv_str(&sub->input, "action", "pull") ||
        !fmc_mbox_since_push(&sub->input, tok) ||
        !json_push_kv_str(&sub->input, "to", to) ||
        (from && from[0] && !json_push_kv_str(&sub->input, "from", from)))
        return "allocation_failed";
    fmc_mail_invoke(sub, false);
    sub->ran = true;
    next = json_get(&sub->reply.data, "next_since");
    arr = json_get(&sub->reply.data, "rows");
    tr = json_get(&sub->reply.data, "truncated");
    if (!fmc_mail_page_valid(sub, next && next->type == JSON_STR
                                      ? json_get_str(next) : NULL, arr, tr))
        return "sibling_refused";
    return NULL;
}

static void fmc_mbox_finish(struct zcl_command_reply *reply, struct fmc_mbox *m,
                            const char *to, const char *cursor, bool more,
                            bool json_only)
{
    bool ok = json_push_kv_str(&reply->data, "leaf", "fleet.steer.mailbox") &&
        json_push_kv_str(&reply->data, "to", to) &&
        json_push_kv(&reply->data, "rows", &m->rows) &&
        json_push_kv_int(&reply->data, "count", (long long)m->emitted) &&
        json_push_kv_str(&reply->data, "cursor", cursor) &&
        json_push_kv_str(&reply->data, "cursor_token", cursor) &&
        json_push_kv_bool(&reply->data, "more", more) &&
        json_push_kv_int(&reply->data, "body_cap_bytes", FMC_MBOX_BODY_MAX) &&
        json_push_kv_int(&reply->data, "bodies_truncated",
                         (long long)m->bodies_truncated);
    if (ok && !json_only) {
        if (m->screen_dropped)
            (void)snprintf(m->screen + m->screen_len,
                           sizeof(m->screen) - m->screen_len,
                           "(+%zu rows not shown here; see rows)\n",
                           m->screen_dropped);
        ok = json_push_kv_str(&reply->data, "screen", m->screen);
    }
    if (!ok) {
        fmc_fail(reply, "MAILBOX_FAILED", "the mailbox page could not be copied",
                 "allocation");
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* The walk's moving position. */
struct fmc_mbox_run {
    const char *to, *from, *prefix;
    char tok[FMC_MAIL_SINCE_CAP];
    char out[FMC_MAIL_SINCE_CAP + 24];
    size_t skip;
    bool more, full;
};

/* Consume one mail page: emit the rows that match the prefix after the
 * skipped ones, stopping at the row limit or byte bound with a cursor that
 * names the row to resume on. NULL on success, else the refusal reason. */
static const char *fmc_mbox_scan(struct fmc_mbox *m,
                                 const struct zcl_command_request *req,
                                 struct fmc_mbox_run *r)
{
    struct fmc_sub sub;
    const struct json_value *arr;
    char next[FMC_MAIL_SINCE_CAP];
    size_t n, i, matched = 0, plen = r->prefix ? strlen(r->prefix) : 0;
    const char *why = fmc_mbox_pull(&sub, req, r->tok, r->to, r->from);
    if (why) {
        fmc_sub_end(&sub);
        return why;
    }
    arr = json_get(&sub.reply.data, "rows");
    (void)snprintf(next, sizeof(next), "%s",
                   json_get_str(json_get(&sub.reply.data, "next_since")));
    r->more = json_get_bool(json_get(&sub.reply.data, "truncated"));
    n = json_size(arr);
    for (i = 0; i < n && !r->full; i++) {
        struct fmc_row v;
        if (!fmc_row_parse(json_at(arr, i), &v) ||
            (plen && strncmp(v.ref, r->prefix, plen) != 0))
            continue;
        if (!fmc_mbox_locator_valid(&v)) {
            fmc_sub_end(&sub);
            return "mail_row_identity_unavailable";
        }
        if (matched >= r->skip &&
            (m->emitted >= m->limit || !fmc_mbox_add(m, &v)))
            r->full = true;
        else
            matched++;
    }
    if (r->full) {
        (void)snprintf(r->out, sizeof(r->out), "%s~%zu", r->tok, matched);
        r->more = true;
    } else {
        (void)snprintf(r->tok, sizeof(r->tok), "%s", next);
        (void)snprintf(r->out, sizeof(r->out), "%s", next);
        r->skip = 0;
        r->full = m->emitted >= m->limit;
    }
    fmc_sub_end(&sub);
    return NULL;
}

static void fmc_do_mailbox(const struct zcl_command_request *req,
                           struct zcl_command_reply *reply,
                           const struct fmc_caller *who)
{
    struct fmc_mbox m;
    struct fmc_mbox_run r = {.more = true};
    const char *why = NULL;
    memset(&m, 0, sizeof(m));
    json_init(&m.rows);
    json_set_array(&m.rows);
    if (!fmc_mbox_inputs(req, reply, &m, &r.to, &r.from, &r.prefix))
        goto done;
    if (who->grant && strcmp(who->label, r.to) != 0) {
        fmc_fail(reply, "STEER_MAILBOX_FOREIGN",
                 "a grant reads only the mailbox of its own label",
                 "grant label differs from to");
        goto done;
    }
    if (!fmc_mbox_cursor(req, r.tok, sizeof(r.tok), &r.skip)) {
        fmc_fail(reply, "BAD_INPUT", "since is a cursor this verb returned",
                 "mailbox cursor");
        goto done;
    }
    if (!r.tok[0])
        (void)snprintf(r.tok, sizeof(r.tok), "0");
    (void)snprintf(r.out, sizeof(r.out), "%s", r.tok);
    for (int page = 0; page < FMC_MBOX_PAGES_MAX && r.more && !r.full && !why;
         page++)
        why = fmc_mbox_scan(&m, req, &r);
    if (why) {
        fmc_fail(reply, "MAILBOX_UNAVAILABLE", "the mail store did not answer",
                 "dev.agent.mail");
        goto done;
    }
    fmc_mbox_finish(reply, &m, r.to, r.out, r.more,
                    json_get_bool(json_get(req->input, "json")));
done:
    json_free(&m.rows);
}
void zcl_native_handle_fleet_steer_mailbox(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    fmc_enter_who(request, reply, "brief",
                  "fleet.steer.mailbox takes grant,to,from,ref,since,limit",
                  fmc_do_mailbox);
}


void zcl_native_handle_fleet_steer_evidence(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    fmc_enter(request, reply, "evidence",
              "fleet.steer.evidence takes grant,type,ref", fmc_do_evidence);
}

static bool fmc_wiki_identity_item(const struct json_value *item)
{
    const char *id = json_get_str(json_get(item, "id"));
    const char *host = json_get_str(json_get(item, "host"));
    const struct json_value *created = json_get(item, "created_at");
    const struct json_value *expires = json_get(item, "expires_at");
    uint8_t decoded[32];
    return zcl_hex_decode_lower(id, decoded, sizeof(decoded)) &&
        zcl_hex_decode_lower(host, decoded, sizeof(decoded)) &&
        created && created->type == JSON_INT && json_get_int(created) > 0 &&
        expires && expires->type == JSON_INT &&
        json_get_int(expires) >= json_get_int(created);
}
static bool fmc_wiki_identity(const struct json_value *discovery)
{
    const char *schema = json_get_str(json_get(discovery, "identity_schema"));
    const struct json_value *entries = json_get(discovery, "entries");
    if (!schema || strcmp(schema, FLEET_WIKI_DISCOVERY_IDENTITY_SCHEMA) ||
        !entries || entries->type != JSON_ARR || json_size(entries) > 8 ||
        json_write(discovery, NULL, 0) > 8192) return false;
    for (size_t i = 0; i < json_size(entries); i++)
        if (!fmc_wiki_identity_item(json_at(entries, i))) return false;
    return true;
}

static bool fmc_wiki_query_prepare(struct fmc_sub *sub,
    const struct zcl_command_request *req, struct zcl_command_reply *reply)
{
    size_t budget = req->budget_bytes ? req->budget_bytes : 4096;
    if (budget > 8192) budget = 8192;
    if (budget < 3072) {
        fmc_fail(reply, "QUERY_BUDGET", "wiki wrapper requires at least 3072 response bytes", "budget_bytes");
        return false;
    }
    sub->request.budget_bytes = budget - 1024;
    const char *const keys[] = {"topic", "applies_to", "after_slug"};
    for (size_t i = 0; i < 3; i++) {
        const struct json_value *v = json_get(req->input, keys[i]);
        if (!v) continue;
        if (v->type != JSON_STR || strlen(json_get_str(v)) > 64) {
            fmc_fail(reply, "BAD_INPUT", "query filters and cursor must be strings of at most 64 bytes", keys[i]);
            return false;
        }
        if (!json_push_kv(&sub->input, keys[i], v)) {
            fmc_fail(reply, "ALLOC_FAILED", "query filters could not be copied", keys[i]);
            return false;
        }
    }
    return true;
}

static void fmc_do_wiki_find(const struct zcl_command_request *req,
                              struct zcl_command_reply *reply)
{
    const char *q = fmc_str(req, "q");
    if (!q || !q[0] || strlen(q) > 128) {
        fmc_fail(reply, "BAD_INPUT", "q must be a nonempty string of at most 128 bytes", "q");
        return;
    }
    struct fmc_sub sub;
    fmc_sub_begin(&sub, "zcl.fleet_wiki_find.v1", req, "fleet.wiki.find");
    if (!sub.valid || !json_push_kv_str(&sub.input, "q", q)) {
        fmc_fail(reply, "WIKI_UNAVAILABLE", "wiki discovery cannot be prepared", "fleet.wiki.find");
        fmc_sub_end(&sub);
        return;
    }
    if (!fmc_wiki_query_prepare(&sub, req, reply)) {
        fmc_sub_end(&sub);
        return;
    }
    zcl_native_handle_fleet_wiki_find(&sub.request, &sub.reply);
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        fmc_fail(reply, "WIKI_UNAVAILABLE", "the local wiki did not answer", sub.reply.error.code);
    } else if (!fmc_wiki_identity(&sub.reply.data)) {
        fmc_fail(reply, "WIKI_CAPABILITY_UNAVAILABLE",
            "the selected node lacks exact wiki revision identity", "fleet.wiki.find identity_schema");
    } else if (json_write(&sub.reply.data, NULL, 0) > sub.request.budget_bytes - 768) {
        fmc_fail(reply, "WIKI_BUDGET_EXCEEDED",
            "the selected node exceeded the bounded nested query budget", "fleet.wiki.find response_budget");
    } else {
        bool ok = json_push_kv(&reply->data, "discovery", &sub.reply.data) &&
            json_push_kv_int(&reply->data, "observed_at", (int64_t)platform_time_wall_time_t()) &&
            json_push_kv_bool(&reply->data, "untrusted", true) &&
            json_push_kv_str(&reply->data, "selection", "latest-held") &&
            json_push_kv_str(&reply->data, "exact_read", "wiki_read(id,offset,bytes)");
        if (!ok) fmc_fail(reply, "ALLOC_FAILED", "wiki discovery projection failed", "json");
        else {
            reply->status = ZCL_COMMAND_STATUS_PASSED;
            reply->exit_code = 0;
        }
    }
    fmc_sub_end(&sub);
}

void zcl_native_handle_fleet_steer_wiki_find(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    fmc_enter(request, reply, "evidence",
              "fleet.steer.wiki-find takes grant,q,topic,applies_to,after_slug", fmc_do_wiki_find);
}

static bool fmc_wiki_read_prepare(struct fmc_sub *sub,
    const struct zcl_command_request *req, struct zcl_command_reply *reply)
{
    uint8_t decoded[32];
    const char *id = fmc_str(req, "id");
    size_t budget = req->budget_bytes ? req->budget_bytes : 4096;
    if (budget > 8192) budget = 8192;
    if (!zcl_hex_decode_lower(id, decoded, sizeof(decoded))) {
        fmc_fail(reply, "BAD_INPUT", "id must be an exact 64-character lowercase revision id", "id");
        return false;
    }
    if (budget < 3072) {
        fmc_fail(reply, "WIKI_BUDGET", "wiki read wrapper requires at least 3072 response bytes", "budget_bytes");
        return false;
    }
    sub->request.budget_bytes = budget - 1024;
    if (!json_push_kv_str(&sub->input, "id", id)) {
        fmc_fail(reply, "ALLOC_FAILED", "wiki revision id could not be copied", "id");
        return false;
    }
    const char *const keys[] = {"offset", "bytes"};
    for (size_t i = 0; i < 2; i++) {
        const struct json_value *v = json_get(req->input, keys[i]);
        if (!v) continue;
        if (v->type != JSON_INT) {
            fmc_fail(reply, "BAD_CHUNK", "offset and bytes must be bounded integers", keys[i]);
            return false;
        }
        if (!json_push_kv(&sub->input, keys[i], v)) {
            fmc_fail(reply, "ALLOC_FAILED", "chunk controls could not be copied", keys[i]);
            return false;
        }
    }
    return true;
}

static bool fmc_wiki_chunk_identity(const struct json_value *chunk,
                                     const char *expected)
{
    const char *mode = json_get_str(json_get(chunk, "representation"));
    const char *id = json_get_str(json_get(chunk, "id"));
    const struct json_value *scope = json_get(chunk, "signed_scope");
    const struct json_value *room = json_get(chunk, "signed_room");
    return mode && !strcmp(mode, "zcl.fleet_wiki_body_chunk.v1") &&
        id && !strcmp(id, expected) && scope && scope->type == JSON_INT &&
        room && room->type == JSON_STR;
}

static void fmc_do_wiki_read(const struct zcl_command_request *req,
                              struct zcl_command_reply *reply)
{
    struct fmc_sub sub;
    fmc_sub_begin(&sub, "zcl.fleet_wiki_read.v1", req, "fleet.wiki.read");
    if (!sub.valid) {
        fmc_fail(reply, "WIKI_UNAVAILABLE", "exact wiki read cannot be prepared", "fleet.wiki.read");
        fmc_sub_end(&sub);
        return;
    }
    if (!fmc_wiki_read_prepare(&sub, req, reply)) {
        fmc_sub_end(&sub);
        return;
    }
    zcl_native_handle_fleet_wiki_read(&sub.request, &sub.reply);
    sub.ran = true;
    if (!fmc_sub_ok(&sub)) {
        fmc_fail(reply, "WIKI_READ_UNAVAILABLE", "the exact retained wiki revision was refused", sub.reply.error.code);
    } else if (!fmc_wiki_chunk_identity(&sub.reply.data, fmc_str(req, "id"))) {
        fmc_fail(reply, "WIKI_CAPABILITY_UNAVAILABLE", "the selected node lacks exact signed wiki chunks", "representation/id/signed_scope/signed_room");
    } else if (json_write(&sub.reply.data, NULL, 0) > sub.request.budget_bytes - 768) {
        fmc_fail(reply, "WIKI_BUDGET_EXCEEDED", "the selected node exceeded the nested read budget", "fleet.wiki.read");
    } else {
        bool ok = json_push_kv(&reply->data, "revision", &sub.reply.data) &&
            json_push_kv_int(&reply->data, "observed_at", (int64_t)platform_time_wall_time_t()) &&
            json_push_kv_bool(&reply->data, "untrusted", true) &&
            json_push_kv_bool(&reply->data, "partial", true);
        if (!ok) fmc_fail(reply, "ALLOC_FAILED", "wiki chunk projection failed", "json");
        else {
            reply->status = ZCL_COMMAND_STATUS_PASSED;
            reply->exit_code = 0;
        }
    }
    fmc_sub_end(&sub);
}

void zcl_native_handle_fleet_steer_wiki_read(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    fmc_enter(request, reply, "evidence",
              "fleet.steer.wiki-read takes grant,id,offset,bytes", fmc_do_wiki_read);
}

static bool fmc_wiki_write_prepare(struct fmc_sub *sub,
    const struct zcl_command_request *req, struct zcl_command_reply *reply,
    const struct fmc_caller *who)
{
    const char *key = fmc_str(req, "request_key");
    if (!who->grant || !who->binding[0]) {
        fmc_fail(reply, "GRANT_REQUIRED", "wiki mutation requires an explicit attributable wiki-write grant", "grant");
        return false;
    }
    if (!fmc_is_token(key, 128, false)) {
        fmc_fail(reply, "BAD_INPUT", "request_key must be a nonempty token of at most 128 bytes", "request_key");
        return false;
    }
    size_t budget = req->budget_bytes ? req->budget_bytes : 4096;
    if (budget > 8192) budget = 8192;
    if (budget < 3072) {
        fmc_fail(reply, "WIKI_BUDGET", "wiki mutation requires at least 3072 response bytes", "budget_bytes");
        return false;
    }
    sub->request.budget_bytes = budget - 1024;
    struct sha3_256_ctx hash;
    unsigned char sum[32];
    char marker[65];
    static const char domain[] = "z23.steer.wiki.request.v1";
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&hash, (const unsigned char *)who->binding, strlen(who->binding) + 1);
    sha3_256_write(&hash, (const unsigned char *)key, strlen(key) + 1);
    sha3_256_finalize(&hash, sum);
    zcl_hex_encode(sum, sizeof(sum), marker);
    bool ok = json_push_kv_str(&sub->input, "marker", marker) &&
        json_push_kv_str(&sub->input, "binding", who->binding);
    static const char *const keys[] = {"expected", "slug", "title", "text"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const struct json_value *value = json_get(req->input, keys[i]);
        if (!value || value->type != JSON_STR) {
            fmc_fail(reply, "BAD_INPUT", "expected, slug, title and inline text are required strings", keys[i]);
            return false;
        }
        if (!strcmp(keys[i], "text") && strlen(json_get_str(value)) > FLEET_BOARD_WIKI_TEXT_MAX) {
            fmc_fail(reply, "BAD_INPUT", "inline text exceeds the signed 16384-byte bound", "text");
            return false;
        }
        ok &= json_push_kv(&sub->input, keys[i], value);
    }
    if (!ok) fmc_fail(reply, "ALLOC_FAILED", "wiki mutation input could not be copied", "json");
    return ok;
}

static bool fmc_wiki_receipt_text_matches(const struct json_value *receipt,
    const struct json_value *input)
{
    const char *text = json_get_str(json_get(input, "text"));
    const struct json_value *size = json_get(receipt, "text_len");
    if (!text || !size || size->type != JSON_INT ||
        json_get_int(size) != (int64_t)strlen(text)) return false;
    struct sha3_256_ctx hash;
    unsigned char sum[32];
    char hex[65];
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const unsigned char *)text, strlen(text));
    sha3_256_finalize(&hash, sum);
    zcl_hex_encode(sum, sizeof(sum), hex);
    const char *actual = json_get_str(json_get(receipt, "body_sha3_256"));
    return actual && !strcmp(actual, hex);
}

static bool fmc_wiki_receipt_fields_match(const struct json_value *receipt,
    const struct json_value *input)
{
    static const char *const keys[] = {"slug", "title"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const char *want = json_get_str(json_get(input, keys[i]));
        const char *actual = json_get_str(json_get(receipt, keys[i]));
        if (!want || !actual || strcmp(want, actual)) return false;
    }
    const char *binding = json_get_str(json_get(input, "binding"));
    const char *agent = json_get_str(json_get(receipt, "agent"));
    const char *marker = json_get_str(json_get(input, "marker"));
    const char *actual_marker = json_get_str(json_get(receipt, "receipt"));
    char expected_marker[80];
    if (!binding || !agent || !marker || !actual_marker) return false;
    (void)snprintf(expected_marker, sizeof(expected_marker), "wiki-write-v1:%s", marker);
    return !strcmp(binding, agent) && !strcmp(expected_marker, actual_marker);
}

static bool fmc_wiki_signed_strings(struct fleet_board_post *post,
    const struct json_value *receipt)
{
    const struct { const char *key; char *target; size_t capacity; } fields[] = {
        {"signed_room", post->room, sizeof(post->room)}, {"agent", post->agent, sizeof(post->agent)},
        {"slug", post->slug, sizeof(post->slug)}, {"title", post->title, sizeof(post->title)},
        {"receipt", post->receipt, sizeof(post->receipt)}};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        const char *s = json_get_str(json_get(receipt, fields[i].key));
        if (!s || strlen(s) >= fields[i].capacity) return false;
        memcpy(fields[i].target, s, strlen(s) + 1);
    }
    return true;
}

static bool fmc_wiki_signed_hex(struct fleet_board_post *post,
    const struct json_value *receipt)
{
    const struct { const char *key; uint8_t *target; size_t length; } fields[] = {
        {"id", post->id, sizeof(post->id)}, {"host", post->host_pubkey, sizeof(post->host_pubkey)},
        {"signature", post->signature, sizeof(post->signature)}, {"ref", post->ref, sizeof(post->ref)},
        {"supersedes", post->supersedes, sizeof(post->supersedes)}};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        if (!zcl_hex_decode_lower(json_get_str(json_get(receipt, fields[i].key)), fields[i].target, fields[i].length)) return false;
    return true;
}

static bool fmc_wiki_signed_numbers(const struct json_value *receipt)
{
    const struct json_value *scope = json_get(receipt, "signed_scope");
    const struct json_value *created = json_get(receipt, "created_at");
    const struct json_value *ttl = json_get(receipt, "ttl");
    return scope && scope->type == JSON_INT && json_get_int(scope) == FLEET_BOARD_SCOPE_PUBLIC &&
        created && created->type == JSON_INT && json_get_int(created) > 0 &&
        ttl && ttl->type == JSON_INT && json_get_int(ttl) == FLEET_BOARD_TTL_DEFAULT;
}

static bool fmc_wiki_signature_matches(const struct json_value *receipt,
    const struct json_value *input)
{
    const struct json_value *created = json_get(receipt, "created_at");
    const char *body = json_get_str(json_get(input, "text"));
    const char *kind = json_get_str(json_get(receipt, "kind"));
    if (!fmc_wiki_signed_numbers(receipt)) return false;
    if (!body || strlen(body) > FLEET_BOARD_WIKI_TEXT_MAX || !kind || strcmp(kind, "wiki")) return false;
    struct fleet_board_post post = {.kind = FLEET_BOARD_KIND_WIKI, .scope = FLEET_BOARD_SCOPE_PUBLIC,
        .created_at = (uint64_t)json_get_int(created), .ttl = FLEET_BOARD_TTL_DEFAULT,
        .text_len = (uint32_t)strlen(body)};
    memcpy(post.text, body, post.text_len + 1);
    if (!fmc_wiki_signed_strings(&post, receipt) || !fmc_wiki_signed_hex(&post, receipt)) return false;
    return !strcmp(post.room, FLEET_BOARD_ROOM_DEFAULT) && fleet_board_post_verify(&post) == FLEET_BOARD_OK;
}

bool zcl_native_fleet_wiki_receipt_matches(const struct json_value *receipt,
    const struct json_value *input, bool *replayed)
{
    uint8_t decoded[32];
    const char *mode = json_get_str(json_get(receipt, "representation"));
    const struct json_value *replay = json_get(receipt, "replayed");
    const char *parent = json_get_str(json_get(input, "expected"));
    const char *actual_parent = json_get_str(json_get(receipt, "supersedes"));
    static const char absent[] = "0000000000000000000000000000000000000000000000000000000000000000";
    if (!parent || !actual_parent) return false;
    const char *want_parent = !strcmp(parent, "absent") ? absent : parent;
    bool matched = mode && !strcmp(mode, "zcl.fleet_wiki_write_receipt.v1") &&
        zcl_hex_decode_lower(json_get_str(json_get(receipt, "id")), decoded, 32) &&
        zcl_hex_decode_lower(json_get_str(json_get(receipt, "body_sha3_256")), decoded, 32) &&
        replay && replay->type == JSON_BOOL && !strcmp(actual_parent, want_parent) &&
        fmc_wiki_receipt_text_matches(receipt, input) &&
        fmc_wiki_receipt_fields_match(receipt, input) && fmc_wiki_signature_matches(receipt, input);
    if (matched && replayed) *replayed = json_get_bool(replay);
    return matched;
}

static void fmc_wiki_outcome_unknown(struct zcl_command_reply *reply,
    const char *message, const char *evidence, bool mutated, bool retained_replay)
{
    fmc_fail(reply, "WIKI_OUTCOME_UNKNOWN", message, evidence);
    reply->error.mutated = mutated;
    (void)snprintf(reply->error.current_state, sizeof(reply->error.current_state), "%s",
        mutated ? "committed_receipt_unavailable" : retained_replay ? "retained_replay_receipt_unavailable" : "outcome_unknown");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
        "reconcile the same request_key; do not issue a new key");
}

static void fmc_do_wiki_write(const struct zcl_command_request *req,
    struct zcl_command_reply *reply, const struct fmc_caller *who)
{
    struct fmc_sub sub;
    fmc_sub_begin(&sub, "zcl.fleet_wiki_write_receipt.v1", req, "fleet.steer.wiki-write");
    if (!sub.valid || !fmc_wiki_write_prepare(&sub, req, reply, who)) {
        if (!sub.valid) fmc_fail(reply, "WIKI_CAPABILITY_UNAVAILABLE", "wiki mutation command is unavailable", "catalog");
        fmc_sub_end(&sub);
        return;
    }
    zcl_native_fleet_wiki_write_rpc(&sub.request, &sub.reply);
    sub.ran = true;
    bool replayed = false;
    if (!fmc_sub_ok(&sub)) {
        const char *code = !strncmp(sub.reply.error.code, "WIKI_", 5)
            ? sub.reply.error.code : "WIKI_OUTCOME_UNKNOWN";
        if (!strcmp(code, "WIKI_OUTCOME_UNKNOWN"))
            fmc_wiki_outcome_unknown(reply, "wiki mutation receipt is unavailable", sub.reply.error.code,
                sub.reply.error.mutated, !strcmp(sub.reply.error.current_state, "retained_replay"));
        else fmc_fail(reply, code, "receiver-local wiki mutation was refused", sub.reply.error.code);
    } else if (!zcl_native_fleet_wiki_receipt_matches(&sub.reply.data, &sub.input, &replayed)) {
        fmc_wiki_outcome_unknown(reply, "selected node returned an unverified or mismatched signed receipt", "signed receipt", false, false);
    } else if (json_write(&sub.reply.data, NULL, 0) > sub.request.budget_bytes) {
        /* This sibling reply is projected directly, without serializing a
         * second command envelope. The reserved 1024 covers the one final
         * envelope and caller/read-next metadata. */
        fmc_wiki_outcome_unknown(reply, "verified receipt exceeded its response budget", "fleet_board", !replayed, replayed);
    } else {
        bool ok = json_push_kv(&reply->data, "revision", &sub.reply.data) &&
            json_push_kv_str(&reply->data, "caller", who->label) &&
            json_push_kv_str(&reply->data, "caller_binding", who->binding) &&
            json_push_kv_str(&reply->data, "exact_read", "wiki_read(id,offset,bytes)");
        if (!ok) fmc_wiki_outcome_unknown(reply, "verified receipt projection failed", "json", !replayed, replayed);
        else {
            reply->status = ZCL_COMMAND_STATUS_PASSED; reply->exit_code = 0;
            reply->error.mutated = !replayed;
            (void)snprintf(reply->error.current_state, sizeof(reply->error.current_state), "%s",
                replayed ? "retained_replay" : "committed");
        }
    }
    fmc_sub_end(&sub);
}

void zcl_native_handle_fleet_steer_wiki_write(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    /* Admission linearizes here: revocation before entry denies even replay;
     * this does not cancel a mutation already admitted and committing. */
    fmc_enter_who(request, reply, "wiki-write",
        "fleet.steer.wiki-write requires grant,request_key,expected,slug,title,inline text",
        fmc_do_wiki_write);
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
                 "fleet.steer.grant needs action mint|list|revoke",
                 "missing action");
        return;
    }
    if (strcmp(action, "list") == 0)
        fmc_grant_list(request, reply);
    else if (strcmp(action, "mint") == 0)
        fmc_grant_mint(request, reply);
    else if (strcmp(action, "revoke") == 0)
        fmc_grant_revoke(request, reply);
    else
        fmc_fail(reply, "BAD_INPUT", "unknown action (mint|list|revoke)",
                 "action");
}
