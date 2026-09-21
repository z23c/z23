/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.receive — the resident RECEIVER loop that turns a
 *          directive arriving in this box's agent mail into real work
 *          without a human typing anything. It composes the EXISTING
 *          leaves only: dev.agent.mail carries directives in and answers
 *          out, dev.agent.queue is the one work ledger, fleet.steer's
 *          owner-minted grant store is the one permission system, and
 *          dev.agent.worker (a separate resident) executes and posts the
 *          result. This file adds no scheduler, no credential, no ledger
 *          and no executor.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. Cross-box work still needed a human to read a message and then run
 * a command. One beat of this loop closes that gap: intake, admission,
 * to-work, answer. The receiver never executes anything, so a long model
 * turn can never block intake, status, or delivery.
 *
 * ONE BEAT.
 *   0. CARRY IN. Rows a paired box posted to the signed FLEET board for
 *      this receiver (or answering a row this box sent) are appended to
 *      inbox.<box>.jsonl with board_post and board_signer, before intake
 *      (native_devagent_boardmail.c). After step 5, CARRY OUT posts this
 *      box's remote-bound rows and its answers to carried directives.
 *   1. INTAKE. dev.agent.mail is called in-process (the same shape
 *      fleet.steer uses) with action=pull, kind=directive, and `since` set
 *      to the durable INTAKE CURSOR: the mail leaf's own next_since token,
 *      stored in <state>/receive/intake.state, or the integer 0 when there
 *      is none yet. Mail answers in bounded pages, so a beat drains at most
 *      RCV_PAGES_PER_BEAT pages and the next beat continues from the
 *      cursor; no row is ever dropped because the history is long. The
 *      cursor is advanced only AFTER every row of a page was handled, so a
 *      crash mid-page replays that page, and the answer markers below make
 *      the replay idempotent. A missing or unreadable cursor starts from
 *      the beginning for the same reason. A failed pull is never silent:
 *      it is logged with its code, counted in intake_failed, and recorded
 *      (intake_failures, intake_last_error) for the status action; a
 *      cursor the mail leaf rejects as stale or malformed is dropped so the
 *      next beat replays instead of failing forever. Pulled rows are never
 *      echoed into this leaf's own reply.
 *   2. ADMISSION, fail-closed, re-derived every beat so a revocation takes
 *      effect on the next one. A row is admitted only when ALL hold:
 *        - `to` names this receiver or is the broadcast "*";
 *        - `ref` is non-empty and matches [A-Za-z0-9_.-]{1,64}. An empty
 *          ref is invalid for coordinated work: one ref names one exact
 *          piece of work, and nothing can be reconciled or answered under
 *          a name that does not exist;
 *        - a row carrying board_post/board_signer is admitted on its board
          instead: this box's node must show that exact unexpired post,
          signed by that signer, whose text is this row; the signer must be
          an enrolled box other than this one; and a live peer grant must
          carry `from` for that box (RECEIVE_PEER_UNSIGNED, _POST_GONE,
          _POST_MISMATCH, _UNENROLLED, _UNGRANTED). A node that does not
          answer (RECEIVE_PEER_POST_MISSING) leaves the row undecided: no
          marker, and the intake cursor stays before it until it is decided;
        - any other row carries a sender binding, and that binding is the stamp
 *          of a LIVE grant in <state>/steer/grants.jsonl that carries the
 *          claimed `from` label with the "send" scope, read through the one
 *          shared helper zcl_fleet_steer_grant_binding_live() so this file
 *          cannot drift from the store's own semantics. `from` alone is a
 *          claim and was believed once: any holder of any send-capable
 *          grant could name any sender and have work dispatched under it.
 *          A row with no binding is unattributable and refused.
 *          BE HONEST ABOUT WHAT THE BINDING BUYS. It is a value the sender
 *          could only have produced by holding its own credential, and it
 *          is therefore unforgeable by someone who has never seen a row
 *          that carries it. It is NOT a signature over this row: it is
 *          fixed per (grant, label), it rides in the clear, and mail rows
 *          are readable by everyone who can read this box's maildir. So
 *          anyone who can both READ one stamped row and WRITE the maildir
 *          can lift that stamp onto a directive of their own and speak as
 *          that label until the grant is revoked. That is a narrower hole
 *          than "any grant may name any sender" and it is still a hole;
 *          closing it needs a per-row signature, which is what routing
 *          directives over the already-signed board is for;
 *        - the body parses as a well-formed Muse task direction (below).
 *      Anything else is refused with a typed reason and executes nothing.
 *   3. TO WORK. The directive body is written verbatim to
 *      <state>/receive/brief/<ref>.brief and posted through dev.agent.queue
 *      with name=<ref>, so the QUEUE ROW is the record. The queue requires
 *      `brief` to be an existing file for kind=doc|file, which is why the
 *      file is written first.
 *   4. IDEMPOTENCE AND CONFLICT, with no work ledger of its own. A ref is
 *      "known" when a queue row, a run directory, or an outcome names it.
 *      For a known ref the stored brief bytes decide: byte-identical body
 *      reconciles (nothing is queued again, nothing executes again, the
 *      existing state is re-answered); a different body is refused as a
 *      CONFLICT, because one ref names one exact piece of work.
 *   5. ANSWER. Only after the queue actually accepted the row (or an
 *      existing one was reconciled) does an accept row go back to the
 *      sender under the SAME ref, carrying the queue seq and the brief
 *      digest. An accept is never posted because bytes arrived. A refusal
 *      answers under the same ref too, with its reason.
 *   6. EXECUTION belongs to dev.agent.worker's own resident loop, which
 *      already gates the run and posts the result mail row under the same
 *      ref through the closed pass predicate. Nothing here reimplements
 *      execution, gating, receipts, retry, or the result mail.
 *
 * DIRECTION FORMAT. The Muse executor's machine header at the top of the
 * body, then a blank line, then the prompt:
 *
 *   muse-workspace: receiver | . | /abs/path  (a selector, or a local path)
 *   muse-scope: src/[,tests/x.c]              (1-4 prefixes, no "..")
 *   muse-gate: group_name                     (a test group name)
 *   muse-model: model-id                      (optional)
 *   muse-kind: file|doc                       (optional, default file)
 *   muse-sha: <7..40 hex>                      (optional HEAD pin)
 *   muse-priority: 0|1|2|3                     (optional, default 3)
 *   muse-depends-on: <ref>                     (optional dependency)
 *
 *   <prompt>
 *
 * A malformed direction is refused here, before any row is queued, so
 * nothing is ever spawned for it. muse-scope becomes the queue row's
 * `path` and muse-gate its `group`.
 *
 * THE WIRE CARRIES A SELECTOR; THE RECEIVER OWNS RESOLUTION. A remote
 * sender cannot name this box's filesystem: it does not know it, and
 * dev.agent.mail refuses a body mentioning an absolute path outside the
 * caller's own checkout — correctly, and that rule is NOT weakened here. So
 * `muse-workspace` carries a LOGICAL selector, the literal word `receiver`
 * (`.` is accepted as the same thing), and this receiver resolves it to the
 * ONE workspace the OPERATOR named when starting the loop. The resolved
 * ABSOLUTE path is written into the brief the queue hands the worker, so
 * the worker and the Muse executor need no change at all, and muse-scope
 * stays relative to that workspace. An absolute `muse-workspace` still
 * works exactly as before for the same-box case.
 *
 * WHAT IS HONOURED FROM THE WIRE, AND NOTHING ELSE. One known selector.
 * Anything else — a path-shaped word, a selector this box does not know, a
 * traversal — is refused with a typed reason, so no sender can steer this
 * receiver at a directory the operator did not configure. With no workspace
 * configured a selector directive is refused, never resolved against a cwd,
 * a $HOME or a discovered checkout. The configured workspace ROOT is
 * canonicalized with realpath and the canonical path is what is recorded,
 * pinned and written into the brief: ".." collapses and every symlinked
 * component is followed, so a workspace below a symlink (a Mac's /tmp is
 * /private/tmp) resolves to the one real directory instead of being
 * refused, and a spelling that would climb out has already become
 * wherever it actually points. A configured path carrying a ".." segment
 * never reaches here: the operator flag refuses it as bad input. A root
 * that will not resolve at all fails closed. It must exist, be a
 * directory, and be a git checkout whose
 * HEAD resolves. An optional `muse-sha` must name that HEAD (full or
 * prefix) or the directive is refused — that is what lets a client pin the
 * exact image it is certifying. And the resolved workspace's pre-state must
 * be clean: tracked paths diverging from its index refuse EARLY, here,
 * before a queue row exists, while muse_run's own `git status` stays the
 * authoritative gate immediately before a turn.
 *
 * EVERY RESOLUTION IS A FILE READ. .git (directory or gitfile), HEAD, the
 * loose ref or packed-refs, and the DIRC index. No git, no spawn, no shell:
 * a beat can never block on a subprocess, which is the whole reason this
 * loop can promise intake never stalls.
 *
 * RECEIVED IS NOT BRIEF. Because the brief is rewritten with a resolved
 * path, the received bytes are stored beside it (<ref>.received) and the
 * duplicate-versus-conflict decision is taken against THOSE. Comparing a
 * replay against the rewritten brief would report a false conflict for a
 * byte-identical retry, which would break at-most-once by refusing honest
 * work. A ref that is already known is answered from its stored record
 * WITHOUT being resolved again, so a receiver restarted against a different
 * workspace can never move decided work into it.
 *
 * SINGLE INSTANCE. <state>/receive/receive.lock (flock, non-blocking, held
 * for the whole drive), the same precedent as the worker's worker.lock. A
 * second drive refuses immediately with RECEIVE_BUSY and never waits.
 *
 * RESTART SAFETY. Nothing is remembered in memory between beats: every
 * decision is re-derived from files — the intake cursor, the mail dir, the
 * grant store, the
 * queue, the run dirs, the outcomes, and the stored brief. A crash between
 * the brief write and the queue post leaves a brief with no row, and the
 * next beat writes the identical brief and posts once. A crash between the
 * queue post and the answer leaves a known ref whose stored brief matches,
 * and the next beat reconciles and answers. Work is therefore executed at
 * most once per ref; an answer may be posted more than once if this process
 * dies mid-answer, which is the honest side to fail on.
 *
 * ANSWER MARKERS. <state>/receive/answered/<row digest> is a zero-length
 * marker meaning "this receiver has already answered this exact directive
 * row". It is de-duplication for MAIL only: it holds no work state, no
 * verdict and no lifecycle, and every idempotence/conflict decision above
 * is taken from the queue, the run dirs, the outcomes and the stored brief
 * rather than from it. It lives under the owner-private state root and not
 * in the mail dir precisely so that a peer able to write an inbox file
 * cannot forge one and suppress an answer.
 *
 * BOUNDED IDLE AND WAKE. The loop waits on <state>/mail through
 * platform_directory_watcher_open/_wait/_close, so a delivered inbox file
 * wakes it immediately, and a wait that times out beats anyway. There is no
 * busy poll, no sleep loop and no timer: the wait is the only place this
 * leaf blocks, and its ceiling is `wait_ms`. The mail directory is created
 * before the watch is armed so a box that has never had mail can still be
 * watched. A watcher that cannot be opened refuses the run, and a watch
 * whose ERROR is observed ends the drive: there is deliberately no fallback
 * path, because any fallback that returned without waiting would be a busy
 * poll. A mailbox directory that is renamed, deleted or recreated reports
 * as CHANGED while the watch keeps pointing at the old inode, so the drive
 * notices the path's (device, inode) identity change after each wait and
 * re-arms by closing and reopening the watch on the configured path,
 * recreating the directory first when it is gone; the durable intake
 * cursor, the queue and the answer markers continue untouched.
 *
 * SIGTERM. The handler sets one flag. The loop stops taking new work at the
 * next check, the watcher wait is interrupted within its 50 ms stop-sample
 * slice, and the drive returns after finishing the beat it is in. A ref's
 * record cannot be corrupted by that: the brief is installed by rename and
 * the queue row is the queue's own single append.
 *
 * WHAT THIS AUTHORITY DOES NOT PROVE — read this before trusting it.
 * An UNSIGNED row's provenance is its FILENAME plus whatever wrote the
 * file, so its admission means exactly "an owner-minted grant names this
 * sender", and NOT "this peer was cryptographically authenticated".
 * Anyone who can write a file into this box's mail directory can claim
 * any `from`. The narrowing that makes that bounded is the grant store —
 * the owner has to have minted a grant under that label with the send
 * scope — plus the queue's own path, name and brief containment rules,
 * plus the worker's gate. A BOARD-CARRIED row is different: its admission
 * binds the grant to the node key that signed the post carrying it, as
 * verified by this box's own node, and to the enrolled box that key
 * belongs to. That authenticates the sending BOX, not the person or agent
 * behind the label there, which is that box's own steer grant check.
 *
 * PROCESS RULE. No spawn, no shell, no popen()/system(), no sleep, no busy
 * poll, no network. Only in-process sibling calls, local filesystem
 * operations, one flock, and one directory watcher wait. Execution is
 * dev.agent.worker's business and happens in its own resident process.
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_command.h"
#include "command/native_devagent.h"
#include "command/native_fleet.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/directory_compat.h"
#include "platform/directory_watcher.h"
#include "platform/file_metadata.h"
#include "platform/os_proc.h"
#include "platform/path_compat.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"
#include "services/muse_run_audit.h"
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
#include <sys/types.h>
#include <unistd.h>
#if !defined(_WIN32)
#include <signal.h>
#include <sys/file.h>
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define RCV_LEAF "dev.agent.receive"
#define RCV_LOG "dev.agent.receive"
#define RCV_LOCK_FILE "receive.lock"
#define RCV_SCOPE "send"
/* Intake pages one beat drains before it lets the loop wait again, and the
 * ceiling a read-only survey walks from the beginning. A backlog larger than
 * one beat continues on the next beat from the persisted intake cursor. */
#define RCV_PAGES_PER_BEAT 4u
#define RCV_SURVEY_PAGES 4096u
#define RCV_POS_MAX 4096u
#define RCV_INTAKE_FILE "intake.state"
#define RCV_BODY_MAX 4097u
/* The resolved brief is the received body with the workspace selector
 * replaced by an absolute path, so it is bounded by the mail body cap plus
 * one path. */
#define RCV_BRIEF_MAX (RCV_BODY_MAX + ZCL_DEVAGENT_WS_PATH_MAX + 32u)
#define RCV_NAME_MAX 48u
#define RCV_INPUT_CAP 16384u

/* ── failure (every error return logs context) ─────────────────────────── */

static void rcv_fail(struct zcl_command_reply *reply, const char *code,
                     const char *phase, const char *msg, const char *evidence)
{
    LOG_ERROR(RCV_LOG, "%s: %s (%s)", code, msg,
              evidence ? evidence : RCV_LEAF);
    (void)json_push_kv_str(&reply->data, "leaf", RCV_LEAF);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, phase, false,
                           false, msg, evidence ? evidence : RCV_LEAF);
}

/* ── input getters ─────────────────────────────────────────────────────── */

static const char *rcv_in_str(const struct zcl_command_request *req,
                              const char *key)
{
    const struct json_value *v;
    if (!req || !req->input || !key)
        return "";
    v = json_get(req->input, key);
    return (v && v->type == JSON_STR && json_get_str(v)) ? json_get_str(v)
                                                         : "";
}

static long long rcv_in_int(const struct zcl_command_request *req,
                            const char *key, long long dflt, long long lo,
                            long long hi)
{
    const struct json_value *v;
    long long n;
    if (!req || !req->input || !key)
        return dflt;
    v = json_get(req->input, key);
    if (!v || v->type != JSON_INT)
        return dflt;
    n = (long long)json_get_int(v);
    if (n < lo)
        return lo;
    return n > hi ? hi : n;
}

/* ── alphabets ─────────────────────────────────────────────────────────── */

/* The queue's own name alphabet, which is also the fleet ref alphabet:
 * [A-Za-z0-9_.-]{1,64}, never "." or "..". An empty ref never passes.
 *
 * The grammar itself is zcl_devagent_name_ok, the one dev.agent.queue
 * judges names by. A second copy here could drift into accepting a ref
 * this receiver would file work under and the queue would then refuse,
 * or into naming a per-ref file outside the run directory. */
static bool rcv_ref_ok(const char *s)
{
    return zcl_devagent_name_ok(s);
}

/* A receiver or agent name: the mail leaf's cursor alphabet, bounded. */
static bool rcv_name_ok(const char *s)
{
    size_t i, n;
    if (!s || !s[0])
        return false;
    n = strlen(s);
    if (n > RCV_NAME_MAX)
        return false;
    for (i = 0; i < n; i++) {
        char c = s[i];
        if (!isalnum((unsigned char)c) && c != '.' && c != '_' && c != '-')
            return false;
    }
    return true;
}

/* A test group name, the queue's own group alphabet. */
static bool rcv_group_ok(const char *s)
{
    size_t i, n;
    if (!s || !s[0])
        return false;
    n = strlen(s);
    if (n >= 64)
        return false;
    for (i = 0; i < n; i++) {
        char c = s[i];
        if (!isalnum((unsigned char)c) && c != '_' && c != '-')
            return false;
    }
    return true;
}

/* A repo-relative scope: never absolute, never carrying a ".." segment. */
/* muse-scope is the executor's own scope grammar: one to four relative
 * prefixes joined by ','. One validator, so intake cannot drift from the
 * run that audits the change set against it. */
static bool rcv_scope_ok(const char *s)
{
    return muse_scope_valid(s);
}

/* ── one pulled directive row ──────────────────────────────────────────── */

/* String members borrow the sibling reply and are valid until the sub call
 * ends; nothing here outlives one beat. */
struct rcv_row {
    long long seq;
    const char *ts;
    const char *from;
    const char *to;
    const char *kind;
    const char *body;
    const char *ref;
    /* The stamp of the credential that sent the row, "" when unstamped.
     * `from` is only a claim — this is what the claim is checked against. */
    const char *sender_binding;
    /* The board post that carried the row and its signer, "" unless a
     * board carrier imported it (native_devagent_boardmail.c). */
    const char *board_post;
    const char *board_signer;
};

/* ── digests ───────────────────────────────────────────────────────────── */

/* Row identity for the answer marker: FNV-1a/64 over
 * ts|seq|from|to|kind|ref|body with NUL separators, printed as 16 hex. The
 * stamp and sequence are IN the identity on purpose. Without them a
 * genuine retry — the sender asking again because the first answer never
 * reached it — would look like the row this receiver already answered and
 * would get silence. With them, re-reading one row every beat answers once
 * and a new row always gets an answer. An equality check for
 * de-duplication, never a security boundary: a forged row is refused by
 * admission, not by this digest. */
static void rcv_row_digest(const struct rcv_row *v, char out[17])
{
    uint64_t h = 1469598103934665603ULL;
    char seq[32];
    const char *parts[7];
    size_t i;
    (void)snprintf(seq, sizeof(seq), "%lld", v->seq);
    parts[0] = v->ts;
    parts[1] = seq;
    parts[2] = v->from;
    parts[3] = v->to;
    parts[4] = v->kind;
    parts[5] = v->ref;
    parts[6] = v->body;
    for (i = 0; i < 7; i++) {
        const unsigned char *p = (const unsigned char *)parts[i];
        while (*p) {
            h ^= (uint64_t)*p++;
            h *= 1099511628211ULL;
        }
        h ^= 0ULL;
        h *= 1099511628211ULL;
    }
    /* A board-carried row is a different row from any unsigned twin: a
     * refused forgery written first must not mark the genuine post as
     * already answered. Rows without the field keep their old identity. */
    for (const unsigned char *p = (const unsigned char *)v->board_post;
         p && *p; p++) {
        h ^= (uint64_t)*p;
        h *= 1099511628211ULL;
    }
    (void)snprintf(out, 17, "%016llx", (unsigned long long)h);
}

/* The brief digest carried in an accept: SHA3-256 of the exact body bytes,
 * so a sender can prove which text this box briefed. */
static void rcv_brief_digest(const char *body, char out[65])
{
    struct sha3_256_ctx ctx;
    unsigned char sum[SHA3_256_OUTPUT_SIZE];
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)(body ? body : ""),
                   body ? strlen(body) : 0u);
    sha3_256_finalize(&ctx, sum);
    zcl_hex_encode(sum, sizeof(sum), out);
}

/* ── state paths ───────────────────────────────────────────────────────── */

struct rcv_paths {
    char root[3072];      /* <state> */
    char dir[3200];       /* <state>/receive */
    char briefdir[3264];  /* <state>/receive/brief */
    char ansdir[3264];    /* <state>/receive/answered */
    char maildir[3200];   /* <state>/mail */
    char enginedir[3200]; /* <state>/engine */
    char outcomes[3264];  /* <state>/queue/outcomes.jsonl */
    char intake[3264];    /* <state>/receive/intake.state */
};

/* Resolve every path this leaf reads or writes. Creates nothing: the
 * writing paths call rcv_dirs_ensure() afterwards, and the read-only
 * status action deliberately never does. */
static bool rcv_paths_resolve(struct rcv_paths *p)
{
    if (!p)
        return false;
    memset(p, 0, sizeof(*p));
    if (!platform_state_root(p->root, sizeof(p->root)))
        return false;
    if (snprintf(p->dir, sizeof(p->dir), "%s/receive", p->root) <= 0)
        return false;
    if (snprintf(p->briefdir, sizeof(p->briefdir), "%s/brief", p->dir) <= 0)
        return false;
    if (snprintf(p->ansdir, sizeof(p->ansdir), "%s/answered", p->dir) <= 0)
        return false;
    if (snprintf(p->maildir, sizeof(p->maildir), "%s/mail", p->root) <= 0)
        return false;
    if (snprintf(p->enginedir, sizeof(p->enginedir), "%s/engine", p->root) <=
        0)
        return false;
    if (snprintf(p->outcomes, sizeof(p->outcomes), "%s/queue/outcomes.jsonl",
                 p->root) <= 0)
        return false;
    if (snprintf(p->intake, sizeof(p->intake), "%s/%s", p->dir,
                 RCV_INTAKE_FILE) <= 0)
        return false;
    return true;
}

/* The mail directory is ensured here as well, with the same owner-only mode
 * the mail leaf uses: a watcher cannot be armed on a directory that does not
 * exist, and this loop refuses to run without a watcher rather than poll. */
static bool rcv_dirs_ensure(const struct rcv_paths *p)
{
    return platform_private_directory_ensure(p->dir) &&
           platform_private_directory_ensure(p->briefdir) &&
           platform_private_directory_ensure(p->ansdir) &&
           platform_private_directory_ensure(p->maildir);
}

static bool rcv_exists(const char *path)
{
    struct stat st;
    return path && path[0] && stat(path, &st) == 0;
}

static bool rcv_is_dir(const char *path)
{
    struct stat st;
    return path && path[0] && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Read a whole small file. False when absent, unreadable, or larger than
 * cap — a truncated brief must never compare equal to a body. */
static bool rcv_read_file(const char *path, char *out, size_t cap)
{
    FILE *f;
    size_t n;
    if (!path || !out || cap == 0)
        return false;
    out[0] = '\0';
    f = fopen(path, "rb");
    if (!f)
        return false;
    n = fread(out, 1, cap - 1, f);
    if (ferror(f) || !feof(f)) {
        (void)fclose(f);
        out[0] = '\0';
        return false;
    }
    out[n] = '\0';
    (void)fclose(f);
    return true;
}

/* Install small file contents by rename, so a crash never leaves a half
 * brief for the queue to hand an executor. */
static bool rcv_write_atomic(const char *path, const char *text, size_t len)
{
    char tmp[4096];
    FILE *f;
    if (!path || !text)
        return false;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
        return false;
    f = fopen(tmp, "wb");
    if (!f)
        return false;
    if (len > 0 && fwrite(text, 1, len, f) != len) {
        (void)fclose(f);
        (void)remove(tmp);
        return false;
    }
    if (fclose(f) != 0) {
        (void)remove(tmp);
        return false;
    }
    if (rename(tmp, path) != 0) {
        (void)remove(tmp);
        return false;
    }
    return true;
}

/* JSON string escape for the small sibling inputs this leaf builds. */
static bool rcv_escape(const char *in, char *out, size_t cap)
{
    size_t used = 0;
    if (!in || !out || cap == 0)
        return false;
    for (; *in; in++) {
        unsigned char c = (unsigned char)*in;
        const char *rep = NULL;
        char tmp[8];
        size_t n;
        if (c == '"')
            rep = "\\\"";
        else if (c == '\\')
            rep = "\\\\";
        else if (c == '\n')
            rep = "\\n";
        else if (c == '\t')
            rep = "\\t";
        else if (c < 0x20) {
            (void)snprintf(tmp, sizeof(tmp), "\\u%04x", c);
            rep = tmp;
        }
        if (!rep) {
            if (used + 1 >= cap)
                return false;
            out[used++] = (char)c;
            continue;
        }
        n = strlen(rep);
        if (used + n >= cap)
            return false;
        memcpy(out + used, rep, n);
        used += n;
    }
    if (used >= cap)
        return false;
    out[used] = '\0';
    return true;
}

/* ── in-process sibling calls (the shape fleet.steer uses) ─────────────── */

struct rcv_sub {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
    bool ran;
    bool valid;
};

static void rcv_sub_begin(struct rcv_sub *s, const char *schema,
                          const char *sib_path)
{
    json_init(&s->input);
    json_set_object(&s->input);
    memset(&s->request, 0, sizeof(s->request));
    s->request.input = &s->input;
    s->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), sib_path, NULL);
    s->request.view = "normal";
    zcl_command_reply_init(&s->reply, schema);
    s->ran = false;
    s->valid = s->request.spec != NULL;
}

static void rcv_sub_end(struct rcv_sub *s)
{
    zcl_command_reply_free(&s->reply);
    json_free(&s->input);
    s->ran = false;
}

static bool rcv_sub_input(struct rcv_sub *s, const char *text)
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

static bool rcv_sub_ok(const struct rcv_sub *s)
{
    return s && s->ran && s->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static long long rcv_sub_int(const struct rcv_sub *s, const char *key,
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

/* ── one workspace, observed from files alone ──────────────────────────────
 * A REMOTE sender never carries a foreign absolute path, so the receiver has
 * to answer three questions about the workspace IT chose: is this really a
 * git checkout, which commit is it on, and was it clean before the turn.
 * All three are answered by reading files — .git (directory or gitfile),
 * HEAD, the loose ref or packed-refs, and the DIRC index — because this leaf
 * spawns nothing and a beat must never wait on a subprocess.
 */

#define RCV_PATH_MAX ZCL_DEVAGENT_WS_PATH_MAX
#define RCV_DIRTY_NAMED 3        /* offending paths carried in the record */
#define RCV_INDEX_BYTES_MAX (64u * 1024u * 1024u)
#define RCV_INDEX_ENTRIES_MAX 1000000u

static bool rcv_copy(char *out, size_t cap, const char *s)
{
    int n = snprintf(out, cap, "%s", s ? s : "");
    return n > 0 && (size_t)n < cap;
}

static bool rcv_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

/* The first line of a small text file, trailing blanks and CR/LF trimmed.
 * False when the file is absent, unreadable, or empty. */
static bool rcv_first_line(const char *path, char *out, size_t cap)
{
    FILE *f;
    size_t n;
    if (!path || !out || cap < 2 || cap > (size_t)INT_MAX)
        return false;
    out[0] = '\0';
    f = fopen(path, "rb");
    if (!f)
        return false;
    if (!fgets(out, (int)cap, f)) {
        (void)fclose(f);
        out[0] = '\0';
        return false;
    }
    (void)fclose(f);
    n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' ||
                     out[n - 1] == ' ' || out[n - 1] == '\t'))
        out[--n] = '\0';
    return out[0] != '\0';
}

/* `want` lowercase hex digits at s. Uppercase is deliberately NOT accepted:
 * git writes object ids lowercase, and accepting both spellings would make
 * two different strings name one commit. */
static bool rcv_hex_n(const char *s, size_t want)
{
    size_t i;
    if (!s)
        return false;
    for (i = 0; i < want; i++) {
        char c = s[i];
        if ((c < '0' || c > '9') && (c < 'a' || c > 'f'))
            return false;
    }
    return true;
}

static bool rcv_hex40(const char *s)
{
    return rcv_hex_n(s, 40) && s[40] == '\0';
}

/* <ws>/.git is either the git directory itself or a "gitdir: <path>" file a
 * linked worktree leaves behind. This answers with the git directory of
 * THIS worktree, never a guess about a sibling. */
static bool rcv_git_dir(const char *ws, char *out, size_t cap)
{
    char dot[RCV_PATH_MAX + 8];
    char line[RCV_PATH_MAX + 16];
    if (!rcv_join(dot, sizeof(dot), ws, ".git"))
        return false;
    if (rcv_is_dir(dot))
        return rcv_copy(out, cap, dot);
    if (!rcv_first_line(dot, line, sizeof(line)) ||
        strncmp(line, "gitdir: ", 8) != 0 || !line[8])
        return false;
    if (line[8] == '/')
        return rcv_copy(out, cap, line + 8);
    return rcv_join(out, cap, ws, line + 8);
}

/* A linked worktree keeps its own HEAD in its admin directory and shares the
 * repository's refs through the common directory that <admin>/commondir
 * names. A main worktree has no commondir file and is its own common dir. */
static bool rcv_common_dir(const char *gitdir, char *out, size_t cap)
{
    char path[RCV_PATH_MAX + 32];
    char line[RCV_PATH_MAX + 16];
    if (!rcv_join(path, sizeof(path), gitdir, "commondir") ||
        !rcv_first_line(path, line, sizeof(line)))
        return rcv_copy(out, cap, gitdir);
    if (line[0] == '/')
        return rcv_copy(out, cap, line);
    return rcv_join(out, cap, gitdir, line);
}

/* "<40 hex> <refname>" rows. A peeled "^<hex>" row names a tag's target,
 * not the ref, so it never matches the refname test above it. */
static bool rcv_packed_head(const char *common, const char *ref, char *out,
                            size_t cap)
{
    char path[RCV_PATH_MAX + 32];
    char line[1024];
    FILE *f;
    bool found = false;
    if (!rcv_join(path, sizeof(path), common, "packed-refs"))
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    while (!found && fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        if (!rcv_hex_n(line, 40) || line[40] != ' ')
            continue;
        if (strcmp(line + 41, ref) != 0)
            continue;
        line[40] = '\0';
        found = rcv_copy(out, cap, line);
    }
    (void)fclose(f);
    return found;
}

/* One ref, from the worktree's own git dir first (a per-worktree ref lives
 * there), then the shared loose ref, then packed-refs. */
static bool rcv_ref_head(const char *gitdir, const char *common,
                         const char *ref, char *out, size_t cap)
{
    char path[RCV_PATH_MAX + 256];
    char line[256];
    if (rcv_join(path, sizeof(path), gitdir, ref) &&
        rcv_first_line(path, line, sizeof(line)) && rcv_hex40(line))
        return rcv_copy(out, cap, line);
    if (rcv_join(path, sizeof(path), common, ref) &&
        rcv_first_line(path, line, sizeof(line)) && rcv_hex40(line))
        return rcv_copy(out, cap, line);
    return rcv_packed_head(common, ref, out, cap);
}

/* The workspace's HEAD commit: a detached HEAD is the 40 hex itself, and a
 * symbolic one is followed into its ref. No spawn, no git, no guess. */
static bool rcv_head_of(const char *gitdir, char *out, size_t cap)
{
    char path[RCV_PATH_MAX + 32];
    char common[RCV_PATH_MAX + 32];
    char line[1024];
    if (!rcv_join(path, sizeof(path), gitdir, "HEAD") ||
        !rcv_first_line(path, line, sizeof(line)))
        return false;
    if (rcv_hex40(line))
        return rcv_copy(out, cap, line);
    if (strncmp(line, "ref: ", 5) != 0 || !line[5])
        return false;
    if (!rcv_common_dir(gitdir, common, sizeof(common)))
        return false;
    return rcv_ref_head(gitdir, common, line + 5, out, cap);
}

/* ── the DIRC index: the tree id and the tracked-path pre-state ────────── */

/* One index entry's fields, already bounds-checked. The index is
 * big-endian throughout and goes through base's one codec. */
struct rcv_idx_row {
    uint32_t mode;
    uint32_t size;
    uint32_t mtime;
    int stage;
    const unsigned char *oid; /* 20 bytes, borrowed from the mapping */
    char name[4096];
    size_t bytes; /* this entry's on-disk size, padded */
};

static int rcv_be16(const unsigned char *p)
{
    return (int)p[0] * 256 + (int)p[1];
}

/* Decode one v2/v3 entry at p with `avail` bytes left. v4's
 * prefix-compressed names are NOT decoded here; the caller refuses that
 * version outright rather than guessing at a partial file list. */
static bool rcv_idx_row(const unsigned char *p, size_t avail, uint32_t ver,
                        struct rcv_idx_row *row)
{
    size_t nlen, fixed;
    int flags, ext;
    if (avail < 64u)
        return false;
    flags = rcv_be16(p + 60);
    ext = (ver >= 3u && (flags & 0x4000) != 0) ? 2 : 0;
    fixed = 62u + (size_t)ext;
    nlen = (size_t)(flags & 0xFFF);
    if (nlen == 0xFFFu) {
        const unsigned char *nul;
        if (avail <= fixed)
            return false;
        nul = memchr(p + fixed, 0, avail - fixed);
        if (!nul)
            return false;
        nlen = (size_t)(nul - (p + fixed));
    }
    if (nlen == 0 || nlen >= sizeof(row->name) || fixed + nlen + 1u > avail)
        return false;
    memcpy(row->name, p + fixed, nlen);
    row->name[nlen] = '\0';
    row->mode = zcl_read_u32_be(p + 24);
    row->size = zcl_read_u32_be(p + 36);
    row->mtime = zcl_read_u32_be(p + 8);
    row->stage = (flags >> 12) & 3;
    row->oid = p + 40;
    row->bytes = (fixed + nlen + 8u) & ~(size_t)7u;
    return row->bytes <= avail;
}

/* True when the worktree file still matches what the index recorded. This is
 * git's own stat shortcut — type, size, exec bit, mtime seconds — and its
 * limits are stated in the struct rcv_workspace contract. */
static bool rcv_entry_clean(const char *ws, const struct rcv_idx_row *row)
{
    char path[RCV_PATH_MAX + sizeof(row->name) + 2u];
    uint32_t kind = row->mode & 0170000u;
    if (row->stage != 0)
        return false; /* an unmerged path is never a clean pre-state */
    if (kind == 0160000u)
        return true; /* a gitlink has no worktree file of its own here */
    if (!rcv_join(path, sizeof(path), ws, row->name))
        return false;
#if defined(_WIN32)
    struct platform_file_metadata metadata;
    /* NTFS has no POSIX executable mode. Reparse points remain unverified;
     * a regular file is compared using handle-observed size and time. */
    return kind == 0100000u &&
           platform_file_metadata_read(path, &metadata) ==
               PLATFORM_FILE_METADATA_OK &&
           metadata.size == row->size &&
           metadata.modified_seconds == row->mtime;
#else
    struct stat st;
    if (lstat(path, &st) != 0)
        return false;
    if (kind == 0120000u)
        return S_ISLNK(st.st_mode) && (uint32_t)st.st_size == row->size;
    if (!S_ISREG(st.st_mode) || (uint32_t)st.st_size != row->size)
        return false;
    if (((st.st_mode & 0111u) != 0u) != ((row->mode & 0111u) != 0u))
        return false;
    return (uint32_t)st.st_mtime == (uint32_t)row->mtime;
#endif
}

/* Fold one entry into the staged tree id: mode, path and object id only, so
 * two boxes holding the same staged content answer the same digest. The
 * index's stat data is deliberately NOT folded in — it differs per box. */
static void rcv_idx_fold(struct sha3_256_ctx *tree,
                         const struct rcv_idx_row *row)
{
    char head[24];
    int n = snprintf(head, sizeof(head), "%06o ", (unsigned)(row->mode &
                                                             0177777u));
    if (n <= 0)
        return;
    sha3_256_write(tree, (const unsigned char *)head, (size_t)n);
    sha3_256_write(tree, (const unsigned char *)row->name,
                   strlen(row->name) + 1u);
    sha3_256_write(tree, row->oid, 20u);
}

/* Record an offending path. Every divergence is counted; the first few are
 * named, because a refusal that says only "dirty" cannot be acted on. */
static void rcv_dirty_name(struct rcv_workspace *w, const char *name)
{
    size_t used = strlen(w->dirty_names);
    size_t room = sizeof(w->dirty_names) - used;
    w->dirty++;
    if (w->dirty > RCV_DIRTY_NAMED || strlen(name) + 2u >= room)
        return;
    (void)snprintf(w->dirty_names + used, room, "%s%s", used ? "," : "",
                   name);
}

/* Walk every entry: fold the tree id and compare the pre-state. False when
 * the file desyncs at any point, which fails closed rather than reporting a
 * clean tree off a partial read. */
static bool rcv_idx_walk(const unsigned char *buf, size_t n, uint32_t ver,
                         const char *ws, struct rcv_workspace *w)
{
    struct sha3_256_ctx tree;
    unsigned char sum[SHA3_256_OUTPUT_SIZE];
    uint32_t count = zcl_read_u32_be(buf + 8), i;
    size_t off = 12u;
    if (count > RCV_INDEX_ENTRIES_MAX)
        return false;
    sha3_256_init(&tree);
    w->dirty = 0;
    for (i = 0; i < count; i++) {
        struct rcv_idx_row row;
        if (off >= n || !rcv_idx_row(buf + off, n - off, ver, &row))
            return false;
        rcv_idx_fold(&tree, &row);
        if (!rcv_entry_clean(ws, &row))
            rcv_dirty_name(w, row.name);
        off += row.bytes;
    }
    sha3_256_finalize(&tree, sum);
    zcl_hex_encode(sum, sizeof(sum), w->tree);
    w->tracked = (long long)count;
    return true;
}

/* Read the whole index once. A v4 index is refused rather than misread: its
 * names are prefix-compressed, and a reader that guessed would report a
 * short file list, which here would mean calling a dirty tree clean. */
static unsigned char *rcv_idx_load(const char *path, size_t *out_n)
{
    unsigned char *buf;
    struct stat st;
    FILE *f;
    *out_n = 0;
    if (stat(path, &st) != 0 || st.st_size <= 0 ||
        (unsigned long long)st.st_size > RCV_INDEX_BYTES_MAX)
        return NULL;
    buf = zcl_malloc((size_t)st.st_size, "devagent_receive.git_index");
    if (!buf)
        return NULL;
    f = fopen(path, "rb");
    if (!f) {
        free(buf);
        return NULL;
    }
    *out_n = fread(buf, 1, (size_t)st.st_size, f);
    (void)fclose(f);
    return buf;
}

static void rcv_idx_scan(const char *gitdir, const char *ws,
                         struct rcv_workspace *w)
{
    char path[RCV_PATH_MAX + 32];
    unsigned char *buf;
    size_t n = 0;
    uint32_t ver;
    if (!rcv_join(path, sizeof(path), gitdir, "index"))
        return;
    buf = rcv_idx_load(path, &n);
    if (!buf)
        return;
    ver = (n >= 32u && memcmp(buf, "DIRC", 4) == 0) ? zcl_read_u32_be(buf + 4)
                                                    : 0u;
    if ((ver == 2u || ver == 3u) && !rcv_idx_walk(buf, n - 20u, ver, ws, w)) {
        w->dirty = -1;
        w->tree[0] = '\0';
    }
    free(buf);
}

bool zcl_devagent_workspace_observe(const char *dir, bool scan_tracked,
                                    struct rcv_workspace *out)
{
    char gitdir[RCV_PATH_MAX + 64];
    char real[PATH_MAX];
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    out->dirty = -1;
    if (!platform_path_is_absolute(dir) || strlen(dir) >= sizeof(out->root))
        return false;
#if defined(_WIN32)
    out->resolved = platform_directory_canonical_real(dir, real, sizeof(real));
    out->directory = out->resolved;
#else
    out->directory = rcv_is_dir(dir);
    /* Canonicalize the ROOT ITSELF and then use the canonical path for
     * everything after this line. Demanding realpath(dir) == dir instead
     * refuses every legitimate workspace that merely sits below a symlinked
     * component — /tmp is /private/tmp on a Mac, and a lane directory can
     * hang off a symlinked home — which is an availability bug, not a
     * safety property. Resolving it keeps the safety: realpath collapses
     * ".." and follows every link, so what is recorded, compared and
     * written into the brief is the one real directory, and a path that
     * would climb out has already become wherever it actually points. */
    out->resolved = out->directory && realpath(dir, real) != NULL;
#endif
    if (!rcv_copy(out->root, sizeof(out->root),
                  out->resolved ? real : dir))
        return false;
    if (!out->resolved)
        return true;
    out->checkout = rcv_git_dir(out->root, gitdir, sizeof(gitdir)) &&
                    rcv_head_of(gitdir, out->head, sizeof(out->head));
    if (out->checkout && scan_tracked)
        rcv_idx_scan(gitdir, out->root, out);
    return true;
}

/* ── the Muse task direction ───────────────────────────────────────────── */

/* The one logical selector a remote sender may put on the wire. "receiver"
 * is the spelling to write; "." is accepted as the same thing, because a
 * sender that means "wherever you are" already spells that "." everywhere
 * else in this tree. Neither names a path, so neither can name a path on
 * this box. */
static bool rcv_ws_selector(const char *v)
{
    return v && (strcmp(v, "receiver") == 0 || strcmp(v, ".") == 0);
}

struct rcv_direction {
    char workspace[1024]; /* exactly what the wire carried */
    char scope[512];
    char gate[64];
    char model[160];
    char kind[8];
    char sha[65];         /* optional muse-sha pin, 7..40 lowercase hex */
    char priority[4];     /* optional queue priority digit, "" = 3 */
    char depends_on[80];  /* optional ref this work waits for */
    bool selector;        /* the workspace value is a logical selector */
    const char *prompt;   /* borrows the pulled row's body */
    char why[64];         /* refusal detail: a bare token, never a path */
    char code[48];        /* the typed refusal code for that detail */
};

/* Copy one header value, trimming trailing blanks and a CR. */
static bool rcv_dir_value(const char *v, size_t len, char *out, size_t cap)
{
    while (len > 0 && (v[0] == ' ' || v[0] == '\t')) {
        v++;
        len--;
    }
    while (len > 0 && (v[len - 1] == ' ' || v[len - 1] == '\t' ||
                       v[len - 1] == '\r'))
        len--;
    if (len == 0 || len >= cap)
        return false;
    memcpy(out, v, len);
    out[len] = '\0';
    return true;
}

/* One "muse-<key>: <value>" header line. False (with d->why set) when the
 * line is not a known header in that exact shape. */
static bool rcv_dir_header(const char *line, size_t len,
                           struct rcv_direction *d)
{
    static const char pre[] = "muse-";
    const char *colon;
    size_t klen;
    if (len <= sizeof(pre) - 1 || memcmp(line, pre, sizeof(pre) - 1) != 0) {
        (void)snprintf(d->why, sizeof(d->why), "not-a-muse-header");
        return false;
    }
    colon = memchr(line, ':', len);
    if (!colon) {
        (void)snprintf(d->why, sizeof(d->why), "header-has-no-colon");
        return false;
    }
    klen = (size_t)(colon - line) - (sizeof(pre) - 1);
    {
        const char *k = line + sizeof(pre) - 1;
        const char *v = colon + 1;
        size_t vlen = len - (size_t)(v - line);
        struct {
            const char *name;
            char *out;
            size_t cap;
        } rows[] = {
            {"workspace", d->workspace, sizeof(d->workspace)},
            {"scope", d->scope, sizeof(d->scope)},
            {"gate", d->gate, sizeof(d->gate)},
            {"model", d->model, sizeof(d->model)},
            {"kind", d->kind, sizeof(d->kind)},
            {"sha", d->sha, sizeof(d->sha)},
            {"priority", d->priority, sizeof(d->priority)},
            {"depends-on", d->depends_on, sizeof(d->depends_on)},
        };
        size_t i;
        for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            if (strlen(rows[i].name) != klen ||
                memcmp(k, rows[i].name, klen) != 0)
                continue;
            if (rcv_dir_value(v, vlen, rows[i].out, rows[i].cap))
                return true;
            (void)snprintf(d->why, sizeof(d->why), "empty-or-long-%s",
                           rows[i].name);
            return false;
        }
    }
    (void)snprintf(d->why, sizeof(d->why), "unknown-muse-header");
    return false;
}

/* The workspace field's SHAPE only. Two spellings reach here and nothing
 * else does: a logical selector, which this receiver resolves for itself
 * once the ref is known to be new work, and an absolute path, which is the
 * same-box case and keeps exactly the rule it always had. Resolution is
 * deliberately NOT done here, so that a ref this receiver has already
 * decided is never re-resolved against a changed configuration. */
static bool rcv_dir_workspace_ok(struct rcv_direction *d)
{
    if (rcv_ws_selector(d->workspace)) {
        d->selector = true;
        return true;
    }
    if (d->workspace[0] == '/' && rcv_is_dir(d->workspace))
        return true;
    (void)snprintf(d->code, sizeof(d->code),
                   "RECEIVE_WORKSPACE_SELECTOR_UNKNOWN");
    (void)snprintf(d->why, sizeof(d->why),
                   "muse-workspace-is-not-a-known-selector");
    return false;
}

/* The optional queue order: one priority digit 0..3 and a dependency ref
 * in the queue's own name grammar. The queue re-checks both. */
static bool rcv_dir_order_ok(struct rcv_direction *d)
{
    if (d->priority[0] && !(d->priority[1] == '\0' &&
                            d->priority[0] >= '0' && d->priority[0] <= '3')) {
        (void)snprintf(d->why, sizeof(d->why), "muse-priority");
        return false;
    }
    if (d->depends_on[0] && !zcl_devagent_name_ok(d->depends_on)) {
        (void)snprintf(d->why, sizeof(d->why), "muse-depends-on");
        return false;
    }
    return true;
}

/* The three required fields plus the optional ones. */
static bool rcv_dir_fields_ok(struct rcv_direction *d)
{
    if (!d->workspace[0]) {
        (void)snprintf(d->why, sizeof(d->why), "muse-workspace");
        return false;
    }
    if (!rcv_dir_workspace_ok(d))
        return false;
    if (d->sha[0] && !(strlen(d->sha) >= 7 && strlen(d->sha) <= 40 &&
                       rcv_hex_n(d->sha, strlen(d->sha)))) {
        (void)snprintf(d->why, sizeof(d->why), "muse-sha");
        return false;
    }
    if (!rcv_scope_ok(d->scope)) {
        (void)snprintf(d->why, sizeof(d->why), "muse-scope");
        return false;
    }
    if (!rcv_group_ok(d->gate)) {
        (void)snprintf(d->why, sizeof(d->why), "muse-gate");
        return false;
    }
    if (d->model[0] && strlen(d->model) > 128) {
        (void)snprintf(d->why, sizeof(d->why), "muse-model");
        return false;
    }
    if (!rcv_dir_order_ok(d))
        return false;
    if (!d->kind[0])
        (void)snprintf(d->kind, sizeof(d->kind), "file");
    if (strcmp(d->kind, "file") != 0 && strcmp(d->kind, "doc") != 0) {
        (void)snprintf(d->why, sizeof(d->why), "muse-kind");
        return false;
    }
    return true;
}

static const char *rcv_skip_blank(const char *p)
{
    while (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t')
        p++;
    return p;
}

/* Parse the machine header, the blank line, and the prompt. False (with
 * d->why naming the field) refuses the directive before anything is
 * written, queued, or spawned. */
static bool rcv_direction_parse(const char *body, struct rcv_direction *d)
{
    const char *p = body;
    if (!d)
        return false;
    memset(d, 0, sizeof(*d));
    (void)snprintf(d->code, sizeof(d->code), "RECEIVE_DIRECTION_MALFORMED");
    (void)snprintf(d->why, sizeof(d->why), "empty-body");
    if (!body || !body[0])
        return false;
    for (;;) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len > 0 && p[len - 1] == '\r')
            len--;
        if (len == 0) {
            p = nl ? nl + 1 : p + strlen(p);
            break;
        }
        if (!rcv_dir_header(p, len, d))
            return false;
        if (!nl) {
            (void)snprintf(d->why, sizeof(d->why), "no-prompt-after-header");
            return false;
        }
        p = nl + 1;
    }
    d->prompt = rcv_skip_blank(p);
    if (!d->prompt[0]) {
        (void)snprintf(d->why, sizeof(d->why), "no-prompt-after-header");
        return false;
    }
    return rcv_dir_fields_ok(d);
}

/* ── reading one pulled directive row ──────────────────────────────────── */

static const char *rcv_field(const struct json_value *r, const char *key)
{
    const struct json_value *v = json_get(r, key);
    if (!v || v->type != JSON_STR || !json_get_str(v))
        return "";
    return json_get_str(v);
}

static bool rcv_row_parse(const struct json_value *r, struct rcv_row *v)
{
    const struct json_value *s;
    if (!r || r->type != JSON_OBJ || !v)
        return false;
    s = json_get(r, "seq");
    if (!s || s->type != JSON_INT)
        return false;
    v->seq = (long long)json_get_int(s);
    v->ts = rcv_field(r, "ts");
    v->from = rcv_field(r, "from");
    v->to = rcv_field(r, "to");
    v->kind = rcv_field(r, "kind");
    v->body = rcv_field(r, "body");
    v->ref = rcv_field(r, "ref");
    v->sender_binding = rcv_field(r, "sender_binding");
    v->board_post = rcv_field(r, "board_post");
    v->board_signer = rcv_field(r, "board_signer");
    return true;
}

/* ── known-ref derivation (the queue is the only work ledger) ──────────── */

struct rcv_known {
    bool known;
    long long seq;
    char stage[16]; /* queued | running | engine | outcome */
};

static void rcv_known_from_array(const struct json_value *arr, const char *ref,
                                 const char *stage, struct rcv_known *k)
{
    size_t n, i;
    if (k->known || !arr || arr->type != JSON_ARR)
        return;
    n = json_size(arr);
    for (i = 0; i < n; i++) {
        const struct json_value *r = json_at(arr, i);
        const struct json_value *v;
        if (!r || r->type != JSON_OBJ)
            continue;
        if (strcmp(rcv_field(r, "name"), ref) != 0)
            continue;
        k->known = true;
        (void)snprintf(k->stage, sizeof(k->stage), "%s", stage);
        v = json_get(r, "seq");
        k->seq = (v && v->type == JSON_INT) ? (long long)json_get_int(v) : -1;
        return;
    }
}

/* True when any outcome row names ref. Read straight from the queue's own
 * outcomes file because the status projection keeps only the newest rows. */
static bool rcv_outcome_names(const char *path, const char *ref)
{
    FILE *f;
    char line[8192];
    char pat[96];
    bool found = false;
    if (snprintf(pat, sizeof(pat), "\"name\":\"%s\"", ref) >= (int)sizeof(pat))
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    while (!found && fgets(line, sizeof(line), f))
        found = strstr(line, pat) != NULL;
    (void)fclose(f);
    return found;
}

/* ── the beat ──────────────────────────────────────────────────────────── */

/* The durable intake cursor and the intake failure record, one small file
 * under this receiver's own state dir. `pos` is the mail leaf's next_since
 * token for the directive stream, "" meaning "from the beginning". */
struct rcv_intake {
    char pos[RCV_POS_MAX];
    long long failures;
    char error[64];
};

struct rcv_ctx {
    struct rcv_paths p;
    char receiver[RCV_NAME_MAX + 1];
    /* The ONE workspace this receiver was started against, named by the
     * operator. Empty means unconfigured, and a selector directive is then
     * refused rather than resolved against a guess. */
    char workspace[ZCL_DEVAGENT_WS_PATH_MAX];
    bool dry; /* status: decide and count, write and post nothing */
    struct rcv_beat_stats *st;
    struct rcv_intake intake;
    /* A board row this beat could not decide (its node did not answer):
     * the intake cursor must not move past it. */
    bool deferred;
};

/* Ask the queue whether it already holds this ref, then the run dirs, then
 * the outcomes. Every source is existing state; nothing is cached. */
static void rcv_ref_known(struct rcv_ctx *c, const char *ref,
                          struct rcv_known *k)
{
    struct rcv_sub sub;
    char dir[4096];
    memset(k, 0, sizeof(*k));
    k->seq = -1;
    rcv_sub_begin(&sub, "zcl.agent_queue.v1", "dev.agent.queue");
    if (sub.valid && rcv_sub_input(&sub, "{\"action\":\"status\","
                                         "\"json\":true}")) {
        zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
        sub.ran = true;
        if (rcv_sub_ok(&sub)) {
            rcv_known_from_array(json_get(&sub.reply.data, "queued"), ref,
                                 "queued", k);
            rcv_known_from_array(json_get(&sub.reply.data, "running"), ref,
                                 "running", k);
        }
    }
    rcv_sub_end(&sub);
    if (k->known)
        return;
    if (snprintf(dir, sizeof(dir), "%s/%s", c->p.enginedir, ref) <
            (int)sizeof(dir) &&
        rcv_is_dir(dir)) {
        k->known = true;
        (void)snprintf(k->stage, sizeof(k->stage), "engine");
        return;
    }
    if (rcv_outcome_names(c->p.outcomes, ref)) {
        k->known = true;
        (void)snprintf(k->stage, sizeof(k->stage), "outcome");
    }
}

/* Post one answer row to the sender under the SAME ref. Flat scanner-safe
 * key=value lines with no path and no slash of any kind: the mail leaf
 * refuses a body carrying a filesystem path, and the brief lives outside
 * the checkout by design. Best-effort — the queue row is the record. */
static void rcv_answer(struct rcv_ctx *c, const struct rcv_row *v,
                       const char *kind, const char *body)
{
    struct rcv_sub sub;
    char ebody[8192], eref[256], eto[128];
    char input[RCV_INPUT_CAP];
    const char *to = (v->from && v->from[0]) ? v->from : "*";
    if (c->dry)
        return;
    if (!rcv_escape(body, ebody, sizeof(ebody)) ||
        !rcv_escape(rcv_ref_ok(v->ref) ? v->ref : "", eref, sizeof(eref)) ||
        !rcv_escape(to, eto, sizeof(eto)))
        return;
    if (snprintf(input, sizeof(input),
                 "{\"action\":\"post\",\"to\":\"%s\",\"kind\":\"%s\","
                 "\"body\":\"%s\",\"ref\":\"%s\",\"from\":\"%s\"}",
                 eto, kind, ebody, eref, c->receiver) >= (int)sizeof(input))
        return;
    rcv_sub_begin(&sub, "zcl.agent_mail.v1", "dev.agent.mail");
    if (sub.valid && rcv_sub_input(&sub, input)) {
        zcl_native_handle_dev_agent_mail(&sub.request, &sub.reply);
        sub.ran = true;
        if (!rcv_sub_ok(&sub))
            LOG_WARN(RCV_LOG, "answer refused by dev.agent.mail for ref %s",
                     rcv_ref_ok(v->ref) ? v->ref : "(invalid)");
    }
    rcv_sub_end(&sub);
}

static void rcv_answer_refuse(struct rcv_ctx *c, const struct rcv_row *v,
                              const char *src, const char *reason,
                              const char *detail)
{
    char body[1024];
    c->st->refused++;
    LOG_WARN(RCV_LOG, "refused directive src=%s: %s (%s)", src, reason,
             detail);
    if (snprintf(body, sizeof(body),
                 "receiver=%s\nstate=refused\nsrc=%s\nreason=%s\n"
                 "detail=%s\n",
                 c->receiver, src, reason, detail) >= (int)sizeof(body))
        return;
    rcv_answer(c, v, "problem", body);
}

/* `evidence` is the scanner-safe workspace record (selector, path digest,
 * HEAD, tree id) — empty for a ref decided before this receiver resolved
 * workspaces. The resolved absolute path itself is deliberately absent: the
 * mail leaf refuses a body naming a filesystem path, that rule is not
 * weakened here, and a peer that never learns this box's paths is the whole
 * point of receiver-side resolution. The digest is what lets a sender prove
 * which workspace answered it. */
static void rcv_answer_accept(struct rcv_ctx *c, const struct rcv_row *v,
                              const char *src, const struct rcv_direction *d,
                              long long seq, const char *stage,
                              const char *evidence)
{
    char body[2048];
    char sha[65];
    rcv_brief_digest(v->body, sha);
    if (snprintf(body, sizeof(body),
                 "receiver=%s\nstate=accepted\nsrc=%s\nqueue_seq=%lld\n"
                 "stage=%s\nkind=%s\ngate=%s\nbrief_sha3=%s\n%s",
                 c->receiver, src, seq, stage, d->kind, d->gate, sha,
                 evidence ? evidence : "") >= (int)sizeof(body))
        return;
    rcv_answer(c, v, "claim", body);
}

/* Post the brief through the EXISTING queue. Returns the accepted seq, or
 * -1 when the queue refused (its own name, path, group, brief containment
 * and model rules all still apply, unchanged). */
static long long rcv_queue_post(const char *ref, const struct rcv_direction *d,
                                const char *briefpath)
{
    struct rcv_sub sub;
    char ebrief[8192];
    char input[RCV_INPUT_CAP];
    long long seq = -1;
    if (!rcv_escape(briefpath, ebrief, sizeof(ebrief)))
        return -1;
    if (snprintf(input, sizeof(input),
                 "{\"action\":\"post\",\"kind\":\"%s\",\"name\":\"%s\","
                 "\"group\":\"%s\",\"path\":\"%s\",\"brief\":\"%s\","
                 "\"model\":\"%s\",\"priority\":%c,\"depends_on\":\"%s\"}",
                 d->kind, ref, d->gate, d->scope, ebrief,
                 d->model[0] ? d->model : "",
                 d->priority[0] ? d->priority[0] : '3', d->depends_on) >=
        (int)sizeof(input))
        return -1;
    rcv_sub_begin(&sub, "zcl.agent_queue.v1", "dev.agent.queue");
    if (sub.valid && rcv_sub_input(&sub, input)) {
        zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
        sub.ran = true;
        if (rcv_sub_ok(&sub))
            seq = rcv_sub_int(&sub, "seq", -1);
    }
    rcv_sub_end(&sub);
    return seq;
}

/* ── resolution: the wire carries a selector, this box owns the path ────── */

/* The optional muse-sha pin. A client that is certifying one exact image
 * says so, and a workspace that is not on that commit is refused rather
 * than quietly worked in. A prefix is admitted only when it actually names
 * the resolved HEAD, which for one workspace is exactly "is a prefix". */
static const char *rcv_ws_pin(const struct rcv_direction *d,
                              const struct rcv_workspace *w, char *detail,
                              size_t cap)
{
    if (!d->sha[0])
        return NULL;
    if (!w->head[0]) {
        (void)snprintf(detail, cap, "workspace-head-unresolvable");
        return "RECEIVE_WORKSPACE_SHA_MISMATCH";
    }
    if (strncmp(w->head, d->sha, strlen(d->sha)) != 0) {
        (void)snprintf(detail, cap, "muse-sha-is-not-the-resolved-head");
        return "RECEIVE_WORKSPACE_SHA_MISMATCH";
    }
    return NULL;
}

/* The pre-state requirement, on the RESOLVED workspace. muse_run runs the
 * authoritative `git status` before it starts a turn; this is the cheap,
 * spawn-free, EARLY refusal so a dirty box never gets as far as a queue row.
 * An unreadable pre-state fails closed. The offending paths are named in
 * the log and in the workspace record, never in the answer: a mail body
 * carrying a path is refused by dev.agent.mail, so an answer naming them
 * would be dropped and the sender would hear nothing at all. */
static const char *rcv_ws_prestate(const struct rcv_workspace *w,
                                   char *detail, size_t cap)
{
    if (w->dirty < 0) {
        (void)snprintf(detail, cap, "workspace-pre-state-unreadable");
        return "RECEIVE_WORKSPACE_DIRTY";
    }
    if (w->dirty == 0)
        return NULL;
    LOG_WARN(RCV_LOG,
             "workspace pre-state is not clean: %lld tracked path(s) "
             "diverge from the index (%s) under %s",
             w->dirty, w->dirty_names, w->root);
    (void)snprintf(detail, cap, "dirty-tracked-paths-%lld", w->dirty);
    return "RECEIVE_WORKSPACE_DIRTY";
}

/* Turn the direction's workspace field into one real absolute path. NULL
 * means admitted and `w` carries the evidence; anything else is the typed
 * refusal code, with `detail` naming the reason in one bare token.
 *
 * This is the ONLY place a selector becomes a path, and it runs ONLY for a
 * ref this receiver has not already decided — which is what keeps a
 * configuration change from re-resolving, or re-running, settled work. */
static const char *rcv_ws_resolve(struct rcv_ctx *c,
                                  const struct rcv_direction *d,
                                  struct rcv_workspace *w, char *detail,
                                  size_t cap)
{
    if (!d->selector) {
        /* The same-box case, unchanged: the sender named the path, so this
         * receiver vouches for nothing it did not already vouch for. HEAD
         * is read anyway — three file reads, no index walk — so that an
         * explicit muse-sha pin still binds. */
        (void)zcl_devagent_workspace_observe(d->workspace, false, w);
        if (!rcv_copy(w->root, sizeof(w->root), d->workspace))
            return "RECEIVE_WORKSPACE_INVALID";
        return rcv_ws_pin(d, w, detail, cap);
    }
    if (!c->workspace[0]) {
        (void)snprintf(detail, cap, "no-workspace-configured");
        return "RECEIVE_WORKSPACE_UNCONFIGURED";
    }
    if (!zcl_devagent_workspace_observe(c->workspace, true, w)) {
        (void)snprintf(detail, cap, "configured-workspace-unusable");
        return "RECEIVE_WORKSPACE_INVALID";
    }
    if (!w->directory) {
        (void)snprintf(detail, cap, "configured-workspace-absent");
        return "RECEIVE_WORKSPACE_MISSING";
    }
    if (!w->resolved) {
        /* The directory stats but realpath() will not resolve it: a symlink
         * loop, or a component this receiver may not traverse. Fail closed
         * rather than working from an unresolved spelling. */
        (void)snprintf(detail, cap, "configured-workspace-unresolvable");
        return "RECEIVE_WORKSPACE_ESCAPE";
    }
    if (!w->checkout) {
        (void)snprintf(detail, cap, "configured-workspace-not-a-checkout");
        return "RECEIVE_WORKSPACE_NOT_A_CHECKOUT";
    }
    {
        const char *why = rcv_ws_pin(d, w, detail, cap);
        return why ? why : rcv_ws_prestate(w, detail, cap);
    }
}

/* The brief the queue hands the worker: the received text with the
 * workspace header replaced by the RESOLVED absolute path and every other
 * byte untouched. The worker, the executor and muse-scope therefore keep
 * seeing exactly what they always saw. */
static bool rcv_brief_render(const char *body, const char *resolved,
                             char *out, size_t cap)
{
    static const char key[] = "muse-workspace:";
    const char *line = body, *tail;
    int n;
    while (strncmp(line, key, sizeof(key) - 1) != 0) {
        const char *nl = strchr(line, '\n');
        if (!nl || nl == line)
            return false; /* no workspace header in the header block */
        line = nl + 1;
    }
    tail = strchr(line, '\n');
    tail = tail ? tail + 1 : line + strlen(line);
    n = snprintf(out, cap, "%.*smuse-workspace: %s\n%s",
                 (int)(line - body), body, resolved, tail);
    return n > 0 && (size_t)n < cap;
}

/* ── the receiver's per-ref record ─────────────────────────────────────── */

/* The three files one ref owns. Splitting RECEIVED from BRIEF is what keeps
 * at-most-once honest: the brief is rewritten with a real absolute path for
 * the executor, so a replay of the SAME row has to be compared against the
 * received bytes or every replay would read as a conflict. */
struct rcv_ref_files {
    char brief[4096];
    char received[4104];
    char evidence[4104];
};

static bool rcv_ref_files_of(const struct rcv_ctx *c, const char *ref,
                             struct rcv_ref_files *f)
{
    int a = snprintf(f->brief, sizeof(f->brief), "%s/%s.brief",
                     c->p.briefdir, ref);
    int b = snprintf(f->received, sizeof(f->received), "%s/%s.received",
                     c->p.briefdir, ref);
    int e = snprintf(f->evidence, sizeof(f->evidence), "%s/%s.evidence",
                     c->p.briefdir, ref);
    return a > 0 && (size_t)a < sizeof(f->brief) && b > 0 &&
           (size_t)b < sizeof(f->received) && e > 0 &&
           (size_t)e < sizeof(f->evidence);
}

/* What this receiver resolved, in its own words. Every line but the last is
 * scanner-safe and is replayed verbatim into the answer; the final
 * `workspace=` line holds the resolved absolute path and stays on this box.
 * The tree id is the index-projected staged tree, NOT
 * tools/dev/source-identity.sh's source_id_sha256 — that one hashes the
 * built source set and cannot be had without a heavy call, and a beat never
 * waits on one.
 *
 * The sender lines are the worker's pre-spend record: the label the row
 * was admitted under, the binding stamp that tied it to the granting
 * credential, and the grant expiry read at install time (or the literal
 * `peer` with the board signer for a board-carried row, whose authority is
 * the peer grant, never a local one). The worker re-verifies all of this
 * against the live store after claim and before forking, so a revoke or
 * expiry that lands between admission and execution spends nothing. Every
 * value is a bare token (label alphabet, lowercase hex, integer, or the
 * `peer` literal), validated below so no row bytes can forge a line. */
static bool rcv_label_token(const char *s, size_t max)
{
    size_t i, n;
    if (!s || s[0] == '\0' || (n = strlen(s)) > max)
        return false;
    for (i = 0; i < n; i++) {
        char c = s[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')
            continue;
        return false;
    }
    return true;
}

static bool rcv_hex_token(const char *s, size_t want)
{
    size_t i;
    if (!s || strlen(s) != want)
        return false;
    for (i = 0; i < want; i++) {
        char c = s[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
            continue;
        return false;
    }
    return true;
}

static bool rcv_evidence_render(const struct rcv_direction *d,
                                const struct rcv_workspace *w,
                                const char *brief, const char *sender,
                                const char *binding, const char *expiry,
                                const char *signer, char *out, size_t cap)
{
    char wsd[65], bd[65];
    char sigline[128];
    int n;
    if (!rcv_label_token(sender, 64) ||
        !rcv_hex_token(binding, ZCL_FLEET_STEER_BINDING_HEX))
        return false;
    if (strcmp(expiry, "peer") == 0) {
        if (!rcv_label_token(signer, 64))
            return false;
        if (snprintf(sigline, sizeof(sigline), "board_signer=%s\n", signer) >=
            (int)sizeof(sigline))
            return false;
    } else {
        char *end = NULL;
        (void)strtoll(expiry, &end, 10);
        if (!expiry[0] || !end || *end != '\0')
            return false;
        sigline[0] = '\0';
    }
    rcv_brief_digest(w->root, wsd);
    rcv_brief_digest(brief, bd);
    n = snprintf(out, cap,
                 "sender=%s\nsender_binding=%s\ngrant_expiry=%s\n%s"
                 "workspace_selector=%s\nworkspace_sha3=%s\n"
                 "workspace_head=%s\nworkspace_tree_sha3=%s\n"
                 "resolved_sha3=%s\nworkspace=%s\n",
                 sender, binding, expiry, sigline,
                 d->selector ? d->workspace : "absolute", wsd,
                 w->head[0] ? w->head : "none", w->tree[0] ? w->tree : "none",
                 bd, w->root);
    return n > 0 && (size_t)n < cap;
}

/* The scanner-safe prefix of that record: every line above `workspace=`.
 * The fresh answer and a replay's answer are both built from it, so a
 * reconciled ref answers the evidence it was actually decided with. */
static void rcv_evidence_fragment(const char *record, char *out, size_t cap)
{
    const char *cut = strstr(record, "\nworkspace=");
    size_t n = cut ? (size_t)(cut - record) + 1u : strlen(record);
    out[0] = '\0';
    if (n >= cap)
        return;
    memcpy(out, record, n);
    out[n] = '\0';
}

static void rcv_evidence_replay(const char *path, char *out, size_t cap)
{
    char record[1024];
    out[0] = '\0';
    if (rcv_read_file(path, record, sizeof(record)))
        rcv_evidence_fragment(record, out, cap);
}

/* ── idempotence and conflict ──────────────────────────────────────────── */

/* The ref is already known to the queue, a run dir, or an outcome. Exactly
 * two answers: the byte-identical RECEIVED body reconciles against the
 * existing record and queues nothing; a different body is a conflict and
 * executes nothing. Nothing here re-resolves a selector and nothing here
 * rewrites a brief, so a receiver restarted against a DIFFERENT workspace
 * cannot move settled work into it — the decided ref keeps the path it was
 * decided with, or it is a conflict.
 *
 * A ref briefed before this receiver kept the received bytes has no
 * .received file; it is compared against the brief, exactly as it always
 * was, so an upgrade mid-flight turns no replay into a false conflict. */
static void rcv_reconcile(struct rcv_ctx *c, const struct rcv_row *v,
                          const char *src, const struct rcv_direction *d,
                          const struct rcv_known *k,
                          const struct rcv_ref_files *f)
{
    char stored[RCV_BRIEF_MAX];
    char evidence[1024];
    const char *path = rcv_exists(f->received) ? f->received : f->brief;
    if (!rcv_read_file(path, stored, sizeof(stored))) {
        rcv_answer_refuse(c, v, src, "RECEIVE_REF_CONFLICT",
                          "ref-claimed-without-a-brief-from-this-receiver");
        return;
    }
    if (strcmp(stored, v->body) != 0) {
        rcv_answer_refuse(c, v, src, "RECEIVE_REF_CONFLICT",
                          "received-body-differs");
        return;
    }
    c->st->reconciled++;
    rcv_evidence_replay(f->evidence, evidence, sizeof(evidence));
    rcv_answer_accept(c, v, src, d, k->seq, k->stage, evidence);
}

/* Write the received bytes, the resolved brief and the record, post the
 * queue row, then answer — in that order, so an accept can never be posted
 * before the queue actually holds the work, and no half state can be
 * mistaken for a decided ref: until the queue row exists the ref is still
 * unknown, and the next beat rewrites all three files identically. */
/* The authority the worker will spend on, read at install rather than
 * trusted from admission: a revoke landing between the two reads refuses
 * instead of queueing. True with the expiry token filled (the integer the
 * store reports, or the `peer` literal for a board-carried row, whose
 * authority is the peer grant the board admission already checked). False
 * answers the refusal, which names the SAME typed reason the worker would
 * refuse with at spend time. */
static bool rcv_install_authority(struct rcv_ctx *c, const struct rcv_row *v,
                                  const char *src, char *expiry, size_t cap,
                                  bool *board)
{
    long long exp = 0;
    *board = (v->board_post && v->board_post[0]) ||
             (v->board_signer && v->board_signer[0]);
    if (*board) {
        (void)snprintf(expiry, cap, "%s", "peer");
        return true;
    }
    if (!zcl_fleet_steer_grant_expiry(v->from, RCV_SCOPE, &exp)) {
        rcv_answer_refuse(c, v, src, "RECEIVE_SENDER_UNGRANTED",
                          "grant-expiry-unreadable");
        return false;
    }
    if (snprintf(expiry, cap, "%lld", exp) >= (int)cap) {
        rcv_answer_refuse(c, v, src, "RECEIVE_STATE_UNWRITABLE",
                          "brief-store");
        return false;
    }
    return true;
}

static void rcv_install(struct rcv_ctx *c, const struct rcv_row *v,
                        const char *src, const struct rcv_direction *d,
                        const struct rcv_workspace *w,
                        const struct rcv_ref_files *f)
{
    char brief[RCV_BRIEF_MAX];
    char record[2048], evidence[1024];
    char expiry[32];
    bool board = false;
    long long seq;
    if (!rcv_install_authority(c, v, src, expiry, sizeof(expiry), &board))
        return;
    if (!rcv_brief_render(v->body, w->root, brief, sizeof(brief)) ||
        !rcv_evidence_render(d, w, brief, v->from, v->sender_binding, expiry,
                             board ? v->board_signer : "", record,
                             sizeof(record))) {
        rcv_answer_refuse(c, v, src, "RECEIVE_WORKSPACE_INVALID",
                          "resolved-brief-too-long");
        return;
    }
    if (!rcv_write_atomic(f->received, v->body, strlen(v->body)) ||
        !rcv_write_atomic(f->brief, brief, strlen(brief)) ||
        !rcv_write_atomic(f->evidence, record, strlen(record))) {
        rcv_answer_refuse(c, v, src, "RECEIVE_STATE_UNWRITABLE",
                          "brief-store");
        return;
    }
    seq = rcv_queue_post(v->ref, d, f->brief);
    if (seq < 0) {
        rcv_answer_refuse(c, v, src, "RECEIVE_QUEUE_REFUSED",
                          "queue-post-refused");
        return;
    }
    c->st->admitted++;
    rcv_evidence_fragment(record, evidence, sizeof(evidence));
    LOG_INFO(RCV_LOG, "ref %s admitted: selector %s resolved to %s at %s",
             v->ref, d->selector ? d->workspace : "absolute", w->root,
             w->head[0] ? w->head : "an unresolved head");
    rcv_answer_accept(c, v, src, d, seq, "queued", evidence);
}

/* Known-ref first, resolution second. That order is the at-most-once
 * guarantee: a settled ref is answered from its stored record without the
 * workspace being looked at, let alone resolved again. */
static void rcv_to_work(struct rcv_ctx *c, const struct rcv_row *v,
                        const char *src, const struct rcv_direction *d)
{
    struct rcv_ref_files f;
    struct rcv_workspace w;
    struct rcv_known k;
    char detail[64];
    const char *why;
    memset(&w, 0, sizeof(w));
    if (!rcv_ref_files_of(c, v->ref, &f)) {
        rcv_answer_refuse(c, v, src, "RECEIVE_STATE_UNWRITABLE",
                          "brief-path-too-long");
        return;
    }
    rcv_ref_known(c, v->ref, &k);
    if (k.known) {
        rcv_reconcile(c, v, src, d, &k, &f);
        return;
    }
    detail[0] = '\0';
    why = rcv_ws_resolve(c, d, &w, detail, sizeof(detail));
    if (why) {
        rcv_answer_refuse(c, v, src, why, detail);
        return;
    }
    if (c->dry) {
        c->st->admitted++;
        return;
    }
    rcv_install(c, v, src, d, &w, &f);
}

/* The sender gate for a row that crossed hosts on the signed fleet board:
 * this box's node must vouch for the exact post and signer, and the owner
 * must have granted the sender's label to that enrolled box. Returns false
 * only when the node did not answer, so the row is left unmarked and is
 * decided on a later beat instead of being refused for an outage. */
static bool rcv_admit_board(struct rcv_ctx *c, const struct rcv_row *v,
                            const char *src, bool *admitted)
{
    struct zcl_boardmail_row row = {
        .seq = v->seq, .ts = v->ts, .from = v->from, .to = v->to,
        .kind = v->kind, .body = v->body, .ref = v->ref,
        .sender_binding = v->sender_binding, .board_post = v->board_post,
        .board_signer = v->board_signer,
    };
    struct zcl_boardmail_decision d;
    *admitted = false;
    zcl_devagent_boardmail_admit(&row, c->receiver, &d);
    if (d.verdict == ZCL_BOARDMAIL_DEFER) {
        c->st->board_deferred++;
        c->deferred = true;
        LOG_WARN(RCV_LOG, "board row src=%s waits: %s (%s)", src, d.code,
                 d.detail);
        return false;
    }
    if (d.verdict == ZCL_BOARDMAIL_REFUSE) {
        rcv_answer_refuse(c, v, src, d.code, d.detail);
        return true;
    }
    *admitted = true;
    return true;
}

/* The sender gate for a row written on this box: the stamp of a live local
 * grant carrying the claimed name. */
static bool rcv_admit_local(struct rcv_ctx *c, const struct rcv_row *v,
                            const char *src)
{
    const char *why;
    /* A row that stamps no credential cannot be attributed to anyone, and
     * work is dispatched on the strength of who asked. Refused, not
     * admitted: this is the fail-closed direction. */
    if (!v->sender_binding || !v->sender_binding[0]) {
        rcv_answer_refuse(c, v, src, "RECEIVE_SENDER_UNBOUND",
                          "row-carries-no-sender-binding");
        return false;
    }
    /* Ask the store whether the grant that stamped this row is the one
     * carrying the name it claims. Asking only whether SOME live grant
     * carried the name admitted any send-capable holder as any sender. */
    why = zcl_fleet_steer_grant_binding_live(v->from, v->sender_binding,
                                             RCV_SCOPE);
    if (why) {
        rcv_answer_refuse(c, v, src, "RECEIVE_SENDER_UNGRANTED", why);
        return false;
    }
    return true;
}

/* The admission tests, in the order that refuses earliest — and all of
 * them before any queue row exists, so nothing this refuses was ever
 * dispatched. Returns false only when the row must stay undecided (its
 * board post could not be checked yet); every other outcome, admitted or
 * refused, is final for this exact row. */
static bool rcv_admit(struct rcv_ctx *c, const struct rcv_row *v,
                      const char *src)
{
    struct rcv_direction d;
    bool board = v->board_post[0] || v->board_signer[0];
    bool sender_ok = false;
    if (!rcv_ref_ok(v->ref)) {
        rcv_answer_refuse(c, v, src, "RECEIVE_REF_INVALID",
                          "ref-must-match-64-name-alphabet");
        return true;
    }
    if (board && !rcv_admit_board(c, v, src, &sender_ok))
        return false;
    if (!board)
        sender_ok = rcv_admit_local(c, v, src);
    if (!sender_ok)
        return true;
    if (!rcv_direction_parse(v->body, &d)) {
        rcv_answer_refuse(c, v, src, d.code, d.why);
        return true;
    }
    rcv_to_work(c, v, src, &d);
    return true;
}

/* Has this receiver already answered this exact row? */
static bool rcv_answered(const struct rcv_ctx *c, const char *src, char *path,
                         size_t cap)
{
    if (snprintf(path, cap, "%s/%s", c->p.ansdir, src) >= (int)cap)
        return true; /* cannot be recorded, so never answer it twice */
    return rcv_exists(path);
}

static void rcv_row_handle(struct rcv_ctx *c, const struct json_value *r)
{
    struct rcv_row v;
    char src[17];
    char marker[4096];
    if (!rcv_row_parse(r, &v))
        return;
    if (strcmp(v.to, c->receiver) != 0 && strcmp(v.to, "*") != 0)
        return;
    c->st->seen++;
    rcv_row_digest(&v, src);
    if (rcv_answered(c, src, marker, sizeof(marker))) {
        c->st->already++;
        return;
    }
    /* The marker is written AFTER the answer: a crash in between costs one
     * duplicate answer on the next beat, never a duplicate queue row. An
     * undecided board row gets no marker, so a later beat decides it. */
    if (rcv_admit(c, &v, src) && !c->dry)
        (void)rcv_write_atomic(marker, "", 0);
}

/* ── the intake cursor ─────────────────────────────────────────────────── */

/* A token is the mail leaf's own spelling: digits, a bar, and
 * "<stream>:<offset>" entries. Anything else in the file is not a token
 * this receiver wrote, and is treated as no cursor (replay from the
 * beginning, which the answer markers make idempotent). */
static bool rcv_pos_ok(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n >= RCV_POS_MAX || !strchr(s, '|'))
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (!isalnum(ch) && !strchr("._-:|,", ch))
            return false;
    }
    return true;
}

/* One "key=value" line of the intake file into *in. */
static void rcv_intake_line(const char *line, struct rcv_intake *in)
{
    if (strncmp(line, "position=", 9) == 0 && rcv_pos_ok(line + 9))
        (void)snprintf(in->pos, sizeof(in->pos), "%s", line + 9);
    else if (strncmp(line, "failures=", 9) == 0)
        in->failures = strtoll(line + 9, NULL, 10);
    else if (strncmp(line, "last_error=", 11) == 0)
        (void)snprintf(in->error, sizeof(in->error), "%.63s", line + 11);
}

/* Read the intake file. Absent or unreadable is the empty record. */
static void rcv_intake_load(const struct rcv_paths *p, struct rcv_intake *in)
{
    char text[RCV_POS_MAX + 256];
    char *line, *nl;
    memset(in, 0, sizeof(*in));
    if (!rcv_read_file(p->intake, text, sizeof(text)))
        return;
    for (line = text; line && *line; line = nl ? nl + 1 : NULL) {
        nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        rcv_intake_line(line, in);
    }
    if (in->failures < 0)
        in->failures = 0;
}

static void rcv_intake_save(const struct rcv_ctx *c)
{
    char text[RCV_POS_MAX + 256];
    int n;
    if (c->dry)
        return;
    n = snprintf(text, sizeof(text),
                 "position=%s\nfailures=%lld\nlast_error=%s\n",
                 c->intake.pos, c->intake.failures, c->intake.error);
    if (n <= 0 || (size_t)n >= sizeof(text) ||
        !rcv_write_atomic(c->p.intake, text, (size_t)n))
        LOG_WARN(RCV_LOG, "cannot record the intake cursor in %s",
                 c->p.intake);
}

/* Never silent: every failed pull is logged with its code, counted in this
 * drive's stats, and recorded for the status action. A cursor the mail
 * leaf rejects (a stream replaced or truncated under it) is dropped, so the
 * next beat replays from the beginning instead of failing forever. */
static void rcv_intake_failed(struct rcv_ctx *c, const char *code,
                              const char *since)
{
    bool reset = since[0] && (strcmp(code, "MAIL_CURSOR_STALE") == 0 ||
                              strcmp(code, "BAD_INPUT") == 0);
    c->st->intake_failed++;
    LOG_WARN(RCV_LOG, "intake pull failed: %s (%s)%s", code,
             since[0] ? "resuming from the intake cursor"
                      : "from the beginning",
             reset ? "; dropping the cursor, next beat replays" : "");
    if (c->dry)
        return;
    c->intake.failures++;
    (void)snprintf(c->intake.error, sizeof(c->intake.error), "%s", code);
    if (reset)
        c->intake.pos[0] = '\0';
    rcv_intake_save(c);
}

/* The page's resume token and whether more rows wait behind it. False
 * when the reply does not carry a token this receiver can store. */
static bool rcv_page_tail(const struct rcv_sub *sub, char *next, size_t cap,
                          bool *more)
{
    const struct json_value *tok = json_get(&sub->reply.data, "next_since");
    const struct json_value *tr = json_get(&sub->reply.data, "truncated");
    const char *s = (tok && tok->type == JSON_STR) ? json_get_str(tok) : NULL;
    if (!s || !rcv_pos_ok(s) || strlen(s) >= cap)
        return false;
    (void)snprintf(next, cap, "%s", s);
    *more = tr && tr->type == JSON_BOOL && json_get_bool(tr);
    return true;
}

/* Pull and handle one page of directives after `since` ("" = from the
 * beginning). Rows are handled in page order before the caller may
 * advance the cursor past them. False with *code set on intake failure. */
static bool rcv_intake_page(struct rcv_ctx *c, const char *since, char *next,
                            size_t cap, bool *more, char *code, size_t ccap)
{
    struct rcv_sub sub;
    const struct json_value *rows;
    char input[RCV_POS_MAX + 96];
    size_t n, i;
    /* The cursor passed rcv_pos_ok (no quote, no backslash), so it is
     * spliced into the fixed pull object verbatim. */
    int w = since[0] ? snprintf(input, sizeof(input),
                                "{\"action\":\"pull\",\"since\":\"%s\","
                                "\"kind\":\"directive\"}", since)
                     : snprintf(input, sizeof(input), "%s",
                                "{\"action\":\"pull\",\"since\":0,"
                                "\"kind\":\"directive\"}");
    rcv_sub_begin(&sub, "zcl.agent_mail.v1", "dev.agent.mail");
    if (sub.valid && w > 0 && (size_t)w < sizeof(input) &&
        rcv_sub_input(&sub, input)) {
        zcl_native_handle_dev_agent_mail(&sub.request, &sub.reply);
        sub.ran = true;
    }
    if (!rcv_sub_ok(&sub) || !rcv_page_tail(&sub, next, cap, more)) {
        (void)snprintf(code, ccap, "%s",
                       !sub.valid ? "MAIL_LEAF_UNAVAILABLE"
                       : sub.reply.error.code[0] ? sub.reply.error.code
                                                 : "MAIL_REPLY_UNREADABLE");
        rcv_sub_end(&sub);
        return false;
    }
    rows = json_get(&sub.reply.data, "rows");
    n = (rows && rows->type == JSON_ARR) ? json_size(rows) : 0u;
    for (i = 0; i < n; i++)
        rcv_row_handle(c, json_at(rows, i));
    rcv_sub_end(&sub);
    return true;
}

/* The carriage view of this receiver's own paths. */
static struct zcl_boardmail_ctx rcv_board_ctx(const struct rcv_ctx *c)
{
    struct zcl_boardmail_ctx b = {
        .receiver = c->receiver, .recvdir = c->p.dir,
        .maildir = c->p.maildir, .dry = c->dry,
    };
    return b;
}

/* Drain up to `cap` intake pages from `since`. The durable cursor follows
 * the pages only until a board row is left undecided: from then on this
 * beat keeps deciding later rows, but the cursor stays where the next beat
 * must replay from, and the answer markers make that replay idempotent. */
static void rcv_intake_drain(struct rcv_ctx *c, char *since, unsigned cap)
{
    char next[RCV_POS_MAX], code[64];
    unsigned pages = 0;
    bool more = true;
    while (more && pages++ < cap) {
        if (!rcv_intake_page(c, since, next, RCV_POS_MAX, &more, code,
                             sizeof(code))) {
            rcv_intake_failed(c, code, since);
            return;
        }
        (void)snprintf(since, RCV_POS_MAX, "%s", next);
        if (!c->dry && !c->deferred && strcmp(since, c->intake.pos) != 0) {
            (void)snprintf(c->intake.pos, sizeof(c->intake.pos), "%s",
                           since);
            rcv_intake_save(c);
        }
    }
}

/* One beat: carry rows in from the fleet board, drain up to
 * RCV_PAGES_PER_BEAT pages from the intake cursor, persisting the cursor
 * after each handled page, deciding each row from files alone, then carry
 * this box's answers and remote-bound rows out. A survey walks from the
 * beginning instead, carries nothing and persists nothing. */
static void rcv_beat(struct rcv_ctx *c)
{
    char since[RCV_POS_MAX];
    struct zcl_boardmail_ctx board = rcv_board_ctx(c);
    c->st->beats++;
    c->deferred = false;
    if (c->dry && !rcv_is_dir(c->p.maildir))
        return;
    zcl_devagent_boardmail_import(&board, c->st);
    (void)snprintf(since, sizeof(since), "%s", c->dry ? "" : c->intake.pos);
    rcv_intake_drain(c, since, c->dry ? RCV_SURVEY_PAGES : RCV_PAGES_PER_BEAT);
    zcl_devagent_boardmail_export(&board, c->st);
}

/* ── the resident drive ────────────────────────────────────────────────── */

#if !defined(_WIN32)

/* SIGTERM asks for shutdown. The flag is checked between beats and sampled
 * by the watcher wait, so a stop is honoured within one wait slice. */
static volatile sig_atomic_t g_rcv_term;

static void rcv_on_term(int sig)
{
    (void)sig;
    g_rcv_term = 1;
}

static bool rcv_stop(void *opaque)
{
    (void)opaque;
    return g_rcv_term != 0;
}

static int rcv_lock_acquire(const char *path)
{
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

/* True when the loop should keep going. */
static bool rcv_loop_live(const struct rcv_drive_opts *opts,
                          const struct rcv_beat_stats *st, long long t0)
{
    if (g_rcv_term)
        return false;
    if (opts->max_beats > 0 && st->beats >= opts->max_beats)
        return false;
    return platform_time_wall_unix() - t0 < opts->deadline_s;
}

#ifdef ZCL_TESTING
static bool g_rcv_test_watch_loss;
static void (*g_rcv_test_before_wait)(void *);
static void *g_rcv_test_wait_arg;
void zcl_devagent_receive_test_before_wait(void (*hook)(void *), void *arg);
void zcl_devagent_receive_test_before_wait(void (*hook)(void *), void *arg)
{
    g_rcv_test_before_wait = hook;
    g_rcv_test_wait_arg = arg;
}
void zcl_devagent_receive_test_watch_loss(bool enabled);
void zcl_devagent_receive_test_watch_loss(bool enabled)
{
    g_rcv_test_watch_loss = enabled;
}
#endif

/* The mailbox pathname identity, sampled on both sides of opening a watch.
 * This detects ordinary replacement, not adversarial pathname ABA changes.
 * Linux reports a renamed or deleted mailbox as CHANGED while the
 * watch keeps pointing at the old inode, so the path and the watch silently
 * disagree from then on. Comparing the identity after every wait notices the
 * replacement using one stat per wait — still bounded waiting, never a poll.
 * The durable intake cursor, the queue and the answer markers are files and
 * survive a re-arm untouched. */
struct rcv_mail_id {
    dev_t dev;
    ino_t ino;
    bool valid;
};

static void rcv_mail_snapshot(const char *maildir, struct rcv_mail_id *id)
{
    struct stat st;
    if (!id)
        return;
    id->valid = false;
    if (!maildir || stat(maildir, &st) != 0 || !S_ISDIR(st.st_mode))
        return;
    id->dev = st.st_dev;
    id->ino = st.st_ino;
    id->valid = true;
}

static bool rcv_mail_same(const char *maildir, const struct rcv_mail_id *was)
{
    struct stat st;
    if (!was || !was->valid || !maildir)
        return false;
    if (stat(maildir, &st) != 0 || !S_ISDIR(st.st_mode))
        return false;
    return st.st_dev == was->dev && st.st_ino == was->ino;
}

/* Close the stale watch, recreate the mailbox when it was deleted, and open
 * a fresh watch on the configured path. False when the path cannot be
 * watched, which ends the drive rather than polling. */
static bool rcv_watch_rearm(struct platform_directory_watcher *w,
                            const struct rcv_ctx *c, struct rcv_mail_id *id)
{
    platform_directory_watcher_close(w);
    platform_directory_watcher_init(w);
    if (!rcv_dirs_ensure(&c->p))
        return false;
    rcv_mail_snapshot(c->p.maildir, id);
    if (!id->valid || !platform_directory_watcher_open(w, c->p.maildir))
        return false;
    if (rcv_mail_same(c->p.maildir, id))
        return true;
    LOG_WARN(RCV_LOG, "mail directory changed while opening watch");
    platform_directory_watcher_close(w);
    return false;
}

/* The one place this loop blocks. It parks in the directory-watcher wait for
 * at most wait_ms; a delivered inbox file wakes it early, a quiet window
 * times out and beats anyway. There is no fallback that returns without
 * waiting, because that fallback would be a busy poll. */
static bool rcv_wait(struct platform_directory_watcher *w,
                     uint32_t wait_ms, bool *watch_lost)
{
    enum platform_directory_watch_result r;
#ifdef ZCL_TESTING
    if (g_rcv_test_before_wait)
        g_rcv_test_before_wait(g_rcv_test_wait_arg);
    /* Exercise error propagation without changing the platform watcher or
     * touching a live receiver. This seam is absent from shipped binaries. */
    if (g_rcv_test_watch_loss)
        r = PLATFORM_DIRECTORY_WATCH_ERROR;
    else
#endif
    r = platform_directory_watcher_wait(w, wait_ms, rcv_stop, NULL);
    if (r == PLATFORM_DIRECTORY_WATCH_STOPPED)
        return false;
    if (r == PLATFORM_DIRECTORY_WATCH_ERROR)
        *watch_lost = true;
    return !g_rcv_term;
}

static long long rcv_drive_posix(const struct rcv_drive_opts *opts,
                                 struct rcv_beat_stats *st)
{
    struct rcv_ctx c;
    struct platform_directory_watcher watcher;
    struct rcv_mail_id mid;
    char lockpath[4096];
    void (*old_term)(int) = SIG_DFL;
    bool watch_lost = false;
    bool watch_dead = false;
    int lockfd;
    long long t0;
    memset(&c, 0, sizeof(c));
    if (!rcv_paths_resolve(&c.p) || !rcv_dirs_ensure(&c.p))
        return -1;
    if (snprintf(lockpath, sizeof(lockpath), "%s/%s", c.p.dir,
                 RCV_LOCK_FILE) >= (int)sizeof(lockpath))
        return -1;
    lockfd = rcv_lock_acquire(lockpath);
    if (lockfd < 0)
        return -1;
    (void)snprintf(c.receiver, sizeof(c.receiver), "%s", opts->receiver);
    (void)snprintf(c.workspace, sizeof(c.workspace), "%s", opts->workspace);
    c.st = st;
    /* Resume where the last drive stopped: the cursor file is the only
     * intake memory that survives a restart. */
    rcv_intake_load(&c.p, &c.intake);
    g_rcv_term = 0;
    old_term = signal(SIGTERM, rcv_on_term);
    t0 = platform_time_wall_unix();
    /* The watcher is armed before the first beat, so a directive that lands
     * while that beat runs still wakes the next wait instead of being missed
     * until the ceiling expires. */
    platform_directory_watcher_init(&watcher);
    if (!rcv_watch_rearm(&watcher, &c, &mid)) {
        LOG_WARN(RCV_LOG, "cannot watch the mail dir; refusing to run rather "
                          "than poll for mail");
        (void)signal(SIGTERM, old_term);
        (void)flock(lockfd, LOCK_UN);
        (void)close(lockfd);
        return -2;
    }
    rcv_beat(&c);
    while (rcv_loop_live(opts, st, t0)) {
        if (!rcv_wait(&watcher, (uint32_t)opts->wait_ms, &watch_lost))
            break;
        if (watch_lost) {
            /* Losing the watch removes the only bounded wait this loop has,
             * so the drive ends here with every ref's record intact; the
             * service unit's Restart=on-failure brings it back. */
            LOG_WARN(RCV_LOG, "mail watch lost; failing this drive for recovery");
            break;
        }
        /* A renamed, deleted or recreated mailbox reports as CHANGED while
         * the watch keeps pointing at the old inode, so an observed ERROR
         * is not the signal — the path's identity is. Re-arm onto the
         * configured path and keep beating: the intake cursor, the queue
         * and the answer markers are files and continue untouched. */
        if (!rcv_mail_same(c.p.maildir, &mid)) {
            LOG_WARN(RCV_LOG, "mail dir replaced; re-arming the mail watch");
            if (!rcv_watch_rearm(&watcher, &c, &mid)) {
                LOG_WARN(RCV_LOG, "cannot re-arm the mail watch; refusing "
                                  "to run rather than poll for mail");
                watch_dead = true;
                break;
            }
        }
        if (!rcv_loop_live(opts, st, t0))
            break;
        rcv_beat(&c);
    }
    platform_directory_watcher_close(&watcher);
    (void)signal(SIGTERM, old_term);
    (void)flock(lockfd, LOCK_UN);
    (void)close(lockfd);
    if (watch_dead)
        return -2;
    return watch_lost ? -3 : st->beats;
}

/* Lock state without creating anything: O_RDONLY and no O_CREAT, so the
 * read-only status action never brings the lock file into existence. */
static const char *rcv_lock_state(const struct rcv_paths *p)
{
    char path[4096];
    const char *state;
    int fd;
    if (snprintf(path, sizeof(path), "%s/%s", p->dir, RCV_LOCK_FILE) >=
        (int)sizeof(path))
        return "unknown";
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return "never-run";
    state = flock(fd, LOCK_EX | LOCK_NB) == 0 ? "free" : "held";
    if (strcmp(state, "free") == 0)
        (void)flock(fd, LOCK_UN);
    (void)close(fd);
    return state;
}

#else /* _WIN32 */

static long long rcv_drive_posix(const struct rcv_drive_opts *opts,
                                 struct rcv_beat_stats *st)
{
    (void)opts;
    (void)st;
    return -1;
}

static const char *rcv_lock_state(const struct rcv_paths *p)
{
    (void)p;
    return "unavailable";
}

#endif /* _WIN32 */

/* ONE definition of the public entry point, above the platform split: the
 * arms differ only in how the singleton and the watch are held, and two
 * non-static bodies for one name is what check-arm-symbol-single refuses. */
/* The operator's workspace flag, checked for SHAPE at the door so a typo is
 * loud at start instead of quietly refusing every selector directive later:
 * absolute, bounded, no ".." segment, no trailing slash. Existence,
 * resolvability and checkout-ness are re-derived per directive instead,
 * because a workspace can be moved out from under a resident. Empty is a
 * legitimate state: a receiver with no workspace refuses selectors.
 *
 * A ".." SEGMENT is refused — ".." bounded by slashes or by the path's own
 * ends — while a directory whose name merely contains dots ("/srv/a..b")
 * is one segment of its own and stays legal. */
static bool rcv_ws_flag_ok(const char *s)
{
    size_t i, n;
    if (!s || !s[0])
        return true;
    n = strlen(s);
    if (s[0] != '/' || n >= ZCL_DEVAGENT_WS_PATH_MAX || s[n - 1] == '/')
        return false;
    for (i = 0; i + 1 < n; i++) {
        if (s[i] != '.' || s[i + 1] != '.')
            continue;
        if ((i == 0 || s[i - 1] == '/') &&
            (s[i + 2] == '\0' || s[i + 2] == '/'))
            return false;
    }
    return true;
}

long long zcl_devagent_receive_drive(const struct rcv_drive_opts *opts,
                                     struct rcv_beat_stats *st)
{
    struct rcv_beat_stats local;
    if (!opts || !rcv_name_ok(opts->receiver) ||
        !rcv_ws_flag_ok(opts->workspace))
        return -1;
    if (!st) {
        memset(&local, 0, sizeof(local));
        st = &local;
    }
    return rcv_drive_posix(opts, st);
}

/* ── status: facts only, writes nothing ────────────────────────────────── */

long long zcl_devagent_receive_survey(const char *receiver,
                                      const char *workspace,
                                      struct rcv_beat_stats *st)
{
    struct rcv_ctx c;
    memset(&c, 0, sizeof(c));
    if (!receiver || !rcv_name_ok(receiver) || !st ||
        !rcv_ws_flag_ok(workspace))
        return -1;
    memset(st, 0, sizeof(*st));
    if (!rcv_paths_resolve(&c.p))
        return -1;
    (void)snprintf(c.receiver, sizeof(c.receiver), "%s", receiver);
    (void)snprintf(c.workspace, sizeof(c.workspace), "%s",
                   workspace ? workspace : "");
    c.dry = true;
    c.st = st;
    rcv_beat(&c);
    return st->beats;
}

/* ── preflight: one directive's admission, decided, never written ──────
 *
 * The run beat's admission pipeline (ref, addressing, sender, direction,
 * known-ref, workspace, queue) with every writing step removed: no mail,
 * no queue row, no brief/received/evidence file, no answer, no marker, no
 * cursor, and rcv_queue_post is never reached, so nothing can be spawned
 * for it. Every check reuses the live path's own predicate, in the live
 * order, so a PREPARED verdict means the next beat would admit this exact
 * row — subject to the one honest gap, stated in the receipt: the executor
 * is wired at worker-run time by the operator, so executor is reported as
 * operator-determined, never as preflight-verified. queue_shape_ok means
 * every queue shape gate this leaf parses (name, kind, group, scope,
 * model, order) passed; it is not a live post verdict, because posting
 * would write. claim_path_clear means the ref is unknown and the queue is
 * not full.
 *
 * The receipt is one typed object in reply->data, PASSED in every case:
 * state PREPARED (admission would succeed), decided (the ref is already
 * known and the bytes match: known, stage, seq), or refused (code and
 * detail name the SAME typed refusal the live beat would have answered
 * with). Refusals are logged like every other error return. */

/* The rung os_proc_open_self_exe() reaches on this build, as a bare
 * token. Never widened here: the label travels from the one ladder in
 * platform/os_proc.h, so it cannot drift from the mechanism. */
static const char *rcv_image_identity_label(void)
{
    switch (os_proc_self_exe_identity()) {
    case OS_PROC_IMAGE_IDENTITY_RUNNING_IMAGE:
        return "running-image";
    case OS_PROC_IMAGE_IDENTITY_RESOLVED_PATH:
        return "resolved-path";
    case OS_PROC_IMAGE_IDENTITY_UNAVAILABLE:
        break;
    }
    return "unavailable";
}

/* SHA3-256 over the running executable image, streamed straight from
 * os_proc_open_self_exe() the way rcv_brief_digest streams the directive
 * bytes. "" when the platform offers no running-image read: no evidence,
 * never a match. */
static void rcv_image_digest(char out[65])
{
    FILE *f = os_proc_open_self_exe();
    struct sha3_256_ctx ctx;
    unsigned char sum[SHA3_256_OUTPUT_SIZE], buf[8192];
    size_t n;
    out[0] = '\0';
    if (!f)
        return;
    sha3_256_init(&ctx);
    for (;;) {
        n = fread(buf, 1, sizeof(buf), f);
        if (n > 0)
            sha3_256_write(&ctx, buf, n);
        if (n < sizeof(buf))
            break;
    }
    if (ferror(f)) {
        (void)fclose(f);
        out[0] = '\0';
        return;
    }
    (void)fclose(f);
    sha3_256_finalize(&ctx, sum);
    zcl_hex_encode(sum, sizeof(sum), out);
}

/* The queue's own numbers without writing: next_seq is one past the
 * highest seq still held (queued or running), depth counts the queued
 * rows, full is the QUEUE_FULL refusal waiting to happen. */
struct rcv_queue_view {
    bool ok;
    long long next_seq;
    long long depth;
    bool full;
};

static void rcv_queue_view_seq(const struct json_value *arr, long long *max)
{
    size_t i, n;
    if (!arr || arr->type != JSON_ARR)
        return;
    n = json_size(arr);
    for (i = 0; i < n; i++) {
        const struct json_value *r = json_at(arr, i);
        const struct json_value *v = r ? json_get(r, "seq") : NULL;
        if (v && v->type == JSON_INT && (long long)json_get_int(v) > *max)
            *max = (long long)json_get_int(v);
    }
}

static void rcv_queue_view(struct rcv_queue_view *q)
{
    struct rcv_sub sub;
    const struct json_value *arr;
    long long max = 0;
    memset(q, 0, sizeof(*q));
    q->next_seq = 1;
    rcv_sub_begin(&sub, "zcl.agent_queue.v1", "dev.agent.queue");
    if (sub.valid && rcv_sub_input(&sub, "{\"action\":\"status\","
                                         "\"json\":true}")) {
        zcl_native_handle_dev_agent_queue(&sub.request, &sub.reply);
        sub.ran = true;
    }
    if (!rcv_sub_ok(&sub)) {
        rcv_sub_end(&sub);
        return;
    }
    arr = json_get(&sub.reply.data, "queued");
    q->depth = (arr && arr->type == JSON_ARR) ? (long long)json_size(arr) : 0;
    rcv_queue_view_seq(arr, &max);
    rcv_queue_view_seq(json_get(&sub.reply.data, "running"), &max);
    rcv_sub_end(&sub);
    q->next_seq = max + 1;
    q->full = q->depth >= (long long)zcl_devagent_queue_queued_max();
    q->ok = true;
}

/* A refused preflight is still a successful call: the receipt carries the
 * SAME typed code the live beat would have answered with, and the log
 * carries the context every error return owes. */
static void rcv_preflight_refuse(struct zcl_command_reply *reply,
                                 const char *receiver, const char *ref,
                                 const char *code, const char *detail)
{
    LOG_WARN(RCV_LOG, "preflight refused ref %s: %s (%s)",
             rcv_ref_ok(ref) ? ref : "(invalid)", code,
             detail ? detail : "");
    (void)json_push_kv_str(&reply->data, "leaf", RCV_LEAF);
    (void)json_push_kv_str(&reply->data, "state", "refused");
    (void)json_push_kv_str(&reply->data, "receiver", receiver);
    (void)json_push_kv_str(&reply->data, "ref",
                           rcv_ref_ok(ref) ? ref : "");
    (void)json_push_kv_str(&reply->data, "code", code);
    (void)json_push_kv_str(&reply->data, "detail", detail ? detail : "");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static void rcv_preflight_decided(struct zcl_command_reply *reply,
                                  const char *receiver, const char *ref,
                                  const char *root,
                                  const struct rcv_known *k)
{
    (void)json_push_kv_str(&reply->data, "leaf", RCV_LEAF);
    (void)json_push_kv_str(&reply->data, "state", "decided");
    (void)json_push_kv_str(&reply->data, "receiver", receiver);
    (void)json_push_kv_str(&reply->data, "ref", ref);
    (void)json_push_kv_str(&reply->data, "directive_root", root);
    (void)json_push_kv_bool(&reply->data, "known", true);
    (void)json_push_kv_str(&reply->data, "stage", k->stage);
    (void)json_push_kv_int(&reply->data, "seq", k->seq);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* One refusal, copied into the caller's struct: codes and details are
 * short static or member strings, so the copy outlives every stage. */
struct rcv_pre_refusal {
    const char *code;
    char detail[64];
};

/* The live beat's first half — ref, addressing, sender, direction — with
 * no write in it. False with *r naming the SAME typed refusal the beat
 * would have answered with. */
static bool rcv_pre_admit(const struct zcl_command_request *request,
                          const char *receiver, const char *ref,
                          struct rcv_direction *d, long long *expiry,
                          struct rcv_pre_refusal *r)
{
    const char *from = rcv_in_str(request, "from");
    const char *binding = rcv_in_str(request, "sender_binding");
    const char *body = rcv_in_str(request, "body");
    const struct json_value *to_v =
        request && request->input ? json_get(request->input, "to") : NULL;
    const char *to = (to_v && to_v->type == JSON_STR && json_get_str(to_v))
                         ? json_get_str(to_v)
                         : "";
    const char *why;
    r->code = "RECEIVE_REF_INVALID";
    (void)snprintf(r->detail, sizeof(r->detail),
                   "ref-must-match-64-name-alphabet");
    if (!rcv_ref_ok(ref))
        return false;
    /* `to` is implicitly this receiver: naming anyone else is not this
     * box's work. */
    r->code = "RECEIVE_NOT_ADDRESSED";
    (void)snprintf(r->detail, sizeof(r->detail),
                   "to-is-not-this-receiver");
    if (to[0] != '\0' && strcmp(to, receiver) != 0)
        return false;
    r->code = "RECEIVE_SENDER_UNBOUND";
    (void)snprintf(r->detail, sizeof(r->detail),
                   "row-carries-no-sender-binding");
    if (!binding[0])
        return false;
    why = zcl_fleet_steer_grant_binding_live(from, binding, RCV_SCOPE);
    r->code = "RECEIVE_SENDER_UNGRANTED";
    (void)snprintf(r->detail, sizeof(r->detail), "%s",
                   why ? why : "grant-expiry-unreadable");
    if (why || !zcl_fleet_steer_grant_expiry(from, RCV_SCOPE, expiry))
        return false;
    if (!rcv_direction_parse(body, d)) {
        r->code = d->code;
        (void)snprintf(r->detail, sizeof(r->detail), "%s", d->why);
        return false;
    }
    return true;
}

/* The live beat's at-most-once order — known-ref first, resolution
 * second — with no write in it. The stored RECEIVED bytes decide, exactly
 * as rcv_reconcile reads them. */
enum rcv_pre_known_out {
    RCV_PRE_NEW,
    RCV_PRE_DECIDED,
    RCV_PRE_REFUSED,
};

static enum rcv_pre_known_out rcv_pre_known(struct rcv_ctx *c,
                                            const char *ref, const char *body,
                                            char root[65],
                                            struct rcv_known *k,
                                            struct rcv_pre_refusal *r)
{
    struct rcv_ref_files f;
    char stored[RCV_BRIEF_MAX];
    const char *path;
    rcv_ref_known(c, ref, k);
    if (!k->known)
        return RCV_PRE_NEW;
    rcv_brief_digest(body, root);
    r->code = "RECEIVE_STATE_UNWRITABLE";
    (void)snprintf(r->detail, sizeof(r->detail), "brief-path-too-long");
    if (!rcv_ref_files_of(c, ref, &f))
        return RCV_PRE_REFUSED;
    path = rcv_exists(f.received) ? f.received : f.brief;
    r->code = "RECEIVE_REF_CONFLICT";
    (void)snprintf(r->detail, sizeof(r->detail),
                   "ref-claimed-without-a-brief-from-this-receiver");
    if (!rcv_read_file(path, stored, sizeof(stored)))
        return RCV_PRE_REFUSED;
    (void)snprintf(r->detail, sizeof(r->detail), "received-body-differs");
    if (strcmp(stored, body) != 0)
        return RCV_PRE_REFUSED;
    return RCV_PRE_DECIDED;
}

static void rcv_preflight(const struct zcl_command_request *request,
                          const char *receiver, const char *workspace,
                          struct zcl_command_reply *reply)
{
    const char *ref = rcv_in_str(request, "ref");
    const char *from = rcv_in_str(request, "from");
    const char *binding = rcv_in_str(request, "sender_binding");
    struct rcv_direction d;
    struct rcv_ctx c;
    struct rcv_workspace w;
    struct rcv_known k;
    struct rcv_queue_view q;
    struct rcv_pre_refusal r;
    char root[65], img[65], imgid[32], detail[64];
    const char *why;
    long long expiry = 0;
    memset(&d, 0, sizeof(d));
    memset(&r, 0, sizeof(r));
    if (!rcv_pre_admit(request, receiver, ref, &d, &expiry, &r)) {
        rcv_preflight_refuse(reply, receiver, ref, r.code, r.detail);
        return;
    }
    memset(&c, 0, sizeof(c));
    if (!rcv_paths_resolve(&c.p)) {
        rcv_preflight_refuse(reply, receiver, ref, "RECEIVE_STATE_UNWRITABLE",
                             "state-root-unresolvable");
        return;
    }
    (void)snprintf(c.workspace, sizeof(c.workspace), "%s", workspace);
    switch (rcv_pre_known(&c, ref, rcv_in_str(request, "body"), root, &k,
                          &r)) {
    case RCV_PRE_DECIDED:
        rcv_preflight_decided(reply, receiver, ref, root, &k);
        return;
    case RCV_PRE_REFUSED:
        rcv_preflight_refuse(reply, receiver, ref, r.code, r.detail);
        return;
    case RCV_PRE_NEW:
        break;
    }
    memset(&w, 0, sizeof(w));
    detail[0] = '\0';
    why = rcv_ws_resolve(&c, &d, &w, detail, sizeof(detail));
    if (why) {
        rcv_preflight_refuse(reply, receiver, ref, why, detail);
        return;
    }
    rcv_queue_view(&q);
    if (!q.ok) {
        rcv_preflight_refuse(reply, receiver, ref, "RECEIVE_QUEUE_REFUSED",
                             "queue-status-unreadable");
        return;
    }
    rcv_brief_digest(rcv_in_str(request, "body"), root);
    rcv_image_digest(img);
    (void)snprintf(imgid, sizeof(imgid), "%s", rcv_image_identity_label());
    (void)json_push_kv_str(&reply->data, "leaf", RCV_LEAF);
    (void)json_push_kv_str(&reply->data, "state", "PREPARED");
    (void)json_push_kv_str(&reply->data, "receiver", receiver);
    (void)json_push_kv_str(&reply->data, "ref", ref);
    (void)json_push_kv_str(&reply->data, "directive_root", root);
    (void)json_push_kv_str(&reply->data, "sender", from);
    (void)json_push_kv_str(&reply->data, "binding", binding);
    (void)json_push_kv_int(&reply->data, "grant_expiry", expiry);
    (void)json_push_kv_str(&reply->data, "workspace_realpath", w.root);
    (void)json_push_kv_str(&reply->data, "workspace_head", w.head);
    (void)json_push_kv_bool(&reply->data, "workspace_clean", w.dirty == 0);
    (void)json_push_kv_str(&reply->data, "gate", d.gate);
    (void)json_push_kv_str(&reply->data, "kind", d.kind);
    (void)json_push_kv_int(&reply->data, "queue_next_seq", q.next_seq);
    (void)json_push_kv_int(&reply->data, "queue_depth", q.depth);
    (void)json_push_kv_bool(&reply->data, "queue_full", q.full);
    (void)json_push_kv_bool(&reply->data, "queue_shape_ok", true);
    (void)json_push_kv_bool(&reply->data, "claim_path_clear", !q.full);
    (void)json_push_kv_str(&reply->data, "executor", "operator-determined");
    (void)json_push_kv_str(&reply->data, "image_sha3", img);
    (void)json_push_kv_str(&reply->data, "image_identity", imgid);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

/* ── leaf ──────────────────────────────────────────────────────────────── */

static void rcv_push_stats(struct zcl_command_reply *reply,
                           const struct rcv_beat_stats *st)
{
    (void)json_push_kv_int(&reply->data, "beats", st->beats);
    (void)json_push_kv_int(&reply->data, "seen", st->seen);
    (void)json_push_kv_int(&reply->data, "admitted", st->admitted);
    (void)json_push_kv_int(&reply->data, "reconciled", st->reconciled);
    (void)json_push_kv_int(&reply->data, "refused", st->refused);
    (void)json_push_kv_int(&reply->data, "already_answered", st->already);
    (void)json_push_kv_int(&reply->data, "intake_failed", st->intake_failed);
    (void)json_push_kv_int(&reply->data, "board_in", st->board_in);
    (void)json_push_kv_int(&reply->data, "board_out", st->board_out);
    (void)json_push_kv_int(&reply->data, "board_deferred", st->board_deferred);
}

/* The resident's durable intake record, read-only: where its cursor
 * stands, how many pulls have failed across its drives, and the last
 * failure code. A survey cannot see these, because it pulls on its own. */
static void rcv_push_intake(struct zcl_command_reply *reply,
                            const struct rcv_paths *p)
{
    struct rcv_intake in;
    rcv_intake_load(p, &in);
    (void)json_push_kv_str(&reply->data, "intake_cursor",
                           in.pos[0] ? in.pos : "");
    (void)json_push_kv_str(&reply->data, "intake_cursor_state",
                           in.pos[0] ? "resuming" : "from-start");
    (void)json_push_kv_int(&reply->data, "intake_failures", in.failures);
    (void)json_push_kv_str(&reply->data, "intake_last_error", in.error);
}

static void rcv_status(const char *receiver, const char *workspace,
                       struct zcl_command_reply *reply)
{
    struct rcv_beat_stats st;
    struct rcv_paths p;
    if (!rcv_paths_resolve(&p)) {
        rcv_fail(reply, "STATE_DIR_FAILED", "status",
                 "cannot resolve the owner-private state root",
                 "platform_state_root");
        return;
    }
    if (zcl_devagent_receive_survey(receiver, workspace, &st) < 0) {
        rcv_fail(reply, "RECEIVE_SURVEY_FAILED", "status",
                 "cannot survey the receiver state", p.dir);
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", RCV_LEAF);
    (void)json_push_kv_str(&reply->data, "state", "surveyed");
    (void)json_push_kv_str(&reply->data, "receiver", receiver);
    (void)json_push_kv_str(&reply->data, "workspace",
                           workspace && workspace[0] ? workspace : "");
    (void)json_push_kv_str(&reply->data, "workspace_state",
                           workspace && workspace[0] ? "configured"
                                                     : "unconfigured");
    (void)json_push_kv_str(&reply->data, "lock", rcv_lock_state(&p));
    (void)json_push_kv_str(&reply->data, "mail",
                           rcv_is_dir(p.maildir) ? "present" : "absent");
    (void)json_push_kv_str(&reply->data, "scope", RCV_SCOPE);
    rcv_push_stats(reply, &st);
    rcv_push_intake(reply, &p);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static void rcv_run(const struct zcl_command_request *request,
                    const char *receiver, const char *workspace,
                    struct zcl_command_reply *reply)
{
    struct rcv_drive_opts opts;
    struct rcv_beat_stats st;
    long long beats;
    memset(&opts, 0, sizeof(opts));
    memset(&st, 0, sizeof(st));
    (void)snprintf(opts.receiver, sizeof(opts.receiver), "%s", receiver);
    (void)snprintf(opts.workspace, sizeof(opts.workspace), "%s", workspace);
    opts.deadline_s = rcv_in_int(request, "deadline_s", 300, 1, 86400);
    opts.wait_ms = rcv_in_int(request, "wait_ms", 1000, 50, 60000);
    opts.max_beats = rcv_in_int(request, "max_beats", 0, 0, 1000000);
    beats = zcl_devagent_receive_drive(&opts, &st);
    if (beats == -3) {
        rcv_fail(reply, "RECEIVE_WATCH_LOST", "run",
                 "mail watch failed; restart the receiver to resume its "
                 "durable intake cursor",
                 "platform_directory_watcher_wait lost the mail watch");
        return;
    }
    if (beats == -2) {
        rcv_fail(reply, "RECEIVE_WATCH_UNAVAILABLE", "run",
                 "this box cannot watch its mail directory, and this loop "
                 "waits on that watch instead of polling",
                 "platform_directory_watcher_open refused the mail dir");
        return;
    }
    if (beats < 0) {
        rcv_fail(reply, "RECEIVE_BUSY", "run",
                 "another receiver holds this loop, or the state root refuses",
                 "receive.lock exclusive");
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", RCV_LEAF);
    (void)json_push_kv_str(&reply->data, "state", "done");
    (void)json_push_kv_str(&reply->data, "receiver", opts.receiver);
    (void)json_push_kv_str(&reply->data, "workspace", opts.workspace);
    rcv_push_stats(reply, &st);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

void zcl_native_handle_dev_agent_receive(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *action, *receiver, *workspace;
    if (!reply)
        return;
    if (!request || !request->input) {
        rcv_fail(reply, "BAD_INPUT", "run",
                 "dev.agent.receive needs an action and a receiver identity",
                 "request.input was missing");
        return;
    }
    action = rcv_in_str(request, "action");
    receiver = rcv_in_str(request, "receiver");
    if (!rcv_name_ok(receiver)) {
        rcv_fail(reply, "BAD_INPUT", "run",
                 "receiver names this box's mail identity, 1-48 of "
                 "[A-Za-z0-9_.-]",
                 "input.receiver missing or misspelled");
        return;
    }
    workspace = rcv_in_str(request, "workspace");
    if (!rcv_ws_flag_ok(workspace)) {
        rcv_fail(reply, "BAD_INPUT", "run",
                 "workspace names the ONE workspace this receiver resolves "
                 "a directive's `muse-workspace: receiver` selector to: an "
                 "absolute path with no \"..\" segment and no trailing slash",
                 "input.workspace is not an absolute canonical-shaped path");
        return;
    }
    if (strcmp(action, "status") == 0) {
        rcv_status(receiver, workspace, reply);
        return;
    }
    if (strcmp(action, "preflight") == 0) {
        rcv_preflight(request, receiver, workspace, reply);
        return;
    }
    if (strcmp(action, "run") != 0) {
        rcv_fail(reply, "BAD_INPUT", "run",
                 "action is one of run|status|preflight",
                 "input.action missing or unknown");
        return;
    }
#if defined(_WIN32)
    rcv_fail(reply, "RECEIVE_WINDOWS_UNAVAILABLE", "run",
             "the resident receiver needs POSIX flock and signals",
             "run the receiver on a POSIX host");
#else
    rcv_run(request, receiver, workspace, reply);
#endif
}
