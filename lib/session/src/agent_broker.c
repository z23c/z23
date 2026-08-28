/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The broker: the privileged side of the confined-agent boundary.
 *
 * The privileged side is three files: this one (peer identity, the request
 * pipeline, and the listening socket), agent_broker_spawn.c (the confined
 * fork/execve), and agent_broker_status.c (the operator-facing report).
 *
 * THE ORDERING THAT MAKES THE BOUNDARY REAL — read this before editing
 * agent_broker_spawn_confined() (agent_broker_spawn.c) or
 * agent_broker_mode_main() (agent_broker_modes.c):
 *
 *   1. The child is confined by the PARENT, before execve. rlimits,
 *      no_new_privs, Landlock and the stage-1 seccomp filter are all applied in
 *      the forked child while it is still our code, and all four survive
 *      execve. A hostile agent therefore cannot decline to be sandboxed: by the
 *      time its own first instruction runs, the kernel is already refusing.
 *      The child narrows itself further (stage-2 seccomp drops execve) but that
 *      is defence in depth, not the boundary.
 *
 *   2. The grant is constructed AFTER the fork. A forked child shares a
 *      copy-on-write image of the parent's address space, so anything the
 *      broker is holding at fork time is readable in the child's memory. The
 *      grant is therefore not built until the child already exists — and
 *      execve then replaces that image entirely, along with the inherited
 *      environment, which is why /proc/<child>/environ is empty rather than a
 *      copy of the operator's session.
 *
 *   3. The grant is never an argument to the child. It is not in argv (mode,
 *      script, scratch dir, and at most a canary path), not in envp (empty),
 *      and not in any file the child's Landlock domain can open. The child
 *      cannot present, forward, or leak an authority it has no way to name.
 *
 * The peer is identified once per connection, before any verb is dispatched,
 * from the kernel's own attribution — so a client that asserts an identity in
 * its own bytes is not merely disbelieved, it is never asked.
 *
 * WHICH kernel attribution is not a detail. SO_PEERCRED names the process that
 * CREATED the socket: for an accept()ed connection that is the peer, but for a
 * socketpair(2) it is the BROKER, on both ends, so it cannot tell the broker
 * apart from the child it handed the other end to. The socketpair posture
 * therefore identifies the peer from SCM_CREDENTIALS on the message it sent,
 * which the kernel stamps per message and the sender cannot forge. See
 * agent_broker_identify_peer().
 */
#define _GNU_SOURCE  /* struct ucred, execvpe — must precede every include */
#include "session/agent_broker.h"
#include "base/format_attribute.h"
#include "session/agent_broker_vocab.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "crypto/sha3.h"
#include "platform/clock.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#define BROKER_TAG "agent.broker"
/* The child receives the connected socket as this descriptor. Fixed, so the
 * child needs no argument naming it — one less thing on a command line. */
#define AGENT_CHILD_SOCKET_FD 3
/* ── fd helpers (EINTR-safe, exact-length) ──────────────────────────────── */

static bool read_full(int fd, uint8_t *buf, size_t n, bool *peer_closed)
{
    size_t got = 0;
    if (peer_closed)
        *peer_closed = false;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r == 0) {
            if (peer_closed)
                *peer_closed = true;
            return false;
        }
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        got += (size_t)r;
    }
    return true;
}
static bool write_full(int fd, const uint8_t *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, buf + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        sent += (size_t)w;
    }
    return true;
}
/* ── SO_PEERCRED ────────────────────────────────────────────────────────── */

bool agent_broker_peercred(int fd, struct agent_peer_cred *out)
{
    if (!out)
        LOG_FAIL(BROKER_TAG, "null out for fd=%d", fd);
    memset(out, 0, sizeof(*out));
    if (fd < 0)
        LOG_FAIL(BROKER_TAG, "bad fd=%d", fd);
#if defined(__APPLE__)
    uid_t uid = 0;
    gid_t gid = 0;
    if (getpeereid(fd, &uid, &gid) != 0)
        LOG_FAIL(BROKER_TAG, "getpeereid on fd=%d failed: %s", fd,
                 strerror(errno));
    out->pid = -1;
    out->uid = uid;
    out->gid = gid;
#else
    struct ucred uc;
    socklen_t len = sizeof(uc);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) != 0 ||
        len != sizeof(uc))
        LOG_FAIL(BROKER_TAG, "SO_PEERCRED on fd=%d failed: %s", fd,
                 strerror(errno));
    out->pid   = uc.pid;
    out->uid   = uc.uid;
    out->gid   = uc.gid;
#endif
    out->valid = true;
    return true;
}
bool agent_broker_sender_cred(int fd, struct agent_peer_cred *out)
{
#if defined(__APPLE__)
    return agent_broker_peercred(fd, out);
#else
    if (!out)
        LOG_FAIL(BROKER_TAG, "null out for fd=%d", fd);
    memset(out, 0, sizeof(*out));
    if (fd < 0)
        LOG_FAIL(BROKER_TAG, "bad fd=%d", fd);
    /* Enabling this on the RECEIVING socket is what makes the kernel attach
     * credentials to messages; a sender cannot opt out of being named. */
    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) != 0)
        LOG_FAIL(BROKER_TAG, "SO_PASSCRED on fd=%d failed: %s", fd,
                 strerror(errno));
    uint8_t peek;
    struct iovec iov = { .iov_base = &peek, .iov_len = 1 };
    union {
        struct cmsghdr align;
        char           bytes[CMSG_SPACE(sizeof(struct ucred))];
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = control.bytes;
    msg.msg_controllen = sizeof(control.bytes);
    ssize_t r;
    do {
        r = recvmsg(fd, &msg, MSG_PEEK);
    } while (r < 0 && errno == EINTR);
    if (r <= 0)
        LOG_FAIL(BROKER_TAG, "nothing to attribute on fd=%d: %s", fd,
                 r == 0 ? "peer closed without sending" : strerror(errno));
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_CREDENTIALS ||
            c->cmsg_len != CMSG_LEN(sizeof(struct ucred)))
            continue;
        struct ucred uc;
        memcpy(&uc, CMSG_DATA(c), sizeof(uc));
        out->pid   = uc.pid;
        out->uid   = uc.uid;
        out->gid   = uc.gid;
        out->valid = true;
        return true;
    }
    LOG_FAIL(BROKER_TAG,
             "the kernel attached no credentials to the message on fd=%d "
             "(SO_PASSCRED must be set before the peer sends)", fd);
#endif
}
bool agent_broker_identify_peer(int fd, struct agent_peer_cred *out)
{
    if (!out)
        LOG_FAIL(BROKER_TAG, "null out for fd=%d", fd);
    if (!agent_broker_peercred(fd, out))
        LOG_FAIL(BROKER_TAG, "no socket credentials on fd=%d", fd);
    /* SO_PEERCRED just named the socket's CREATOR. When that is us, this is a
     * socketpair we made and both ends carry our pid — an answer about the
     * broker, not about the peer. Ask who actually sent instead. */
    if (out->pid == getpid()) {
        struct agent_peer_cred sender;
        if (agent_broker_sender_cred(fd, &sender) && sender.valid)
            *out = sender;
    }
    return true;
}
bool agent_broker_peer_authorized(const struct agent_peer_cred *c,
                                  const struct agent_peer_expectation *e,
                                  char *why, size_t why_cap)
{
    if (why && why_cap)
        why[0] = '\0';
    if (!c || !e) {
        if (why && why_cap)
            snprintf(why, why_cap, "internal: null credential or expectation");
        return false;
    }
    if (!c->valid) {
        if (why && why_cap)
            snprintf(why, why_cap,
                     "kernel did not supply peer credentials for this socket");
        return false;
    }
    /* An expectation that checks nothing would accept every local process.
     * That is a misconfiguration, and it fails closed. */
    if (!e->require_uid && !e->require_gid && !e->require_pid) {
        if (why && why_cap)
            snprintf(why, why_cap,
                     "expectation constrains nothing (no uid/gid/pid required)");
        return false;
    }
    if (e->require_uid && c->uid != e->uid) {
        if (why && why_cap)
            snprintf(why, why_cap, "uid mismatch: peer=%u expected=%u",
                     (unsigned)c->uid, (unsigned)e->uid);
        return false;
    }
    if (e->require_gid && c->gid != e->gid) {
        if (why && why_cap)
            snprintf(why, why_cap, "gid mismatch: peer=%u expected=%u",
                     (unsigned)c->gid, (unsigned)e->gid);
        return false;
    }
    if (e->require_pid && c->pid != e->pid) {
        if (why && why_cap)
            snprintf(why, why_cap, "pid mismatch: peer=%d expected=%d",
                     (int)c->pid, (int)e->pid);
        return false;
    }
    return true;
}

/* ── the real property surface (registered by the composition root) ─────── */

static const struct agent_broker_provider *g_provider;

void agent_broker_provider_install(const struct agent_broker_provider *p)
{
    g_provider = p;
}

const struct agent_broker_provider *agent_broker_provider_get(void)
{
    return g_provider;
}

/* THE ONE PLACE A SESSION ACQUIRES AUTHORITY. It exists so that "bind" is not
 * a recipe each caller retypes: forgetting to record `provider`/`provider_ctx`
 * on the reference would leave a reference that names a grant and cannot reach
 * it, which authorize_live() correctly refuses — silently, and for a reason
 * nobody would guess. Doing it here means no caller can get it half right.
 *
 * A refusal is a STATE, not an error to recover from: the session stays
 * ungranted, `ref->bound` stays false, and every request is refused by name. */
bool agent_broker_session_bind(struct agent_broker_session *s,
                               struct agent_authority_ref *ref, char *why,
                               size_t why_cap)
{
    if (why && why_cap)
        why[0] = '\0';
    if (!s || !ref)
        LOG_FAIL(BROKER_TAG, "bind: null session or authority reference");
    memset(ref, 0, sizeof(*ref));
    s->authority = ref;

    const struct agent_broker_provider *p = g_provider;
    if (!p) {
        if (why && why_cap)
            snprintf(why, why_cap,
                     "no property provider is registered: this broker has no "
                     "authority and no property surface");
        return false;
    }
    if (p->ops)
        s->ops = p->ops(p->ctx);
    if (!p->bind || !p->bind(p->ctx, ref, why, why_cap)) {
        memset(ref, 0, sizeof(*ref));
        if (why && why_cap && !why[0])
            snprintf(why, why_cap, "provider '%s' refused to bind",
                     p->name ? p->name : "(unnamed)");
        return false;
    }
    ref->provider     = p;
    ref->provider_ctx = p->ctx;
    return true;
}

/* ── the request pipeline ───────────────────────────────────────────────── */

static void resp_init(struct mvap_response *r, const struct mvap_request *req,
                      int32_t status)
{
    memset(r, 0, sizeof(*r));
    r->verb       = req ? req->verb : MVAP_VERB_NONE;
    r->request_id = req ? req->request_id : 0;
    /* Reply in the dialect the peer spoke, not the one this build prefers. */
    r->version    = req ? req->version : 0;
    r->status     = status;
}

static void resp_body(struct mvap_response *r, const char *fmt, ...)
    ZCL_PRINTF_LIKE(2, 3);

static void resp_body(struct mvap_response *r, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(r->body, sizeof(r->body), fmt, ap);
    va_end(ap);
    if (n < 0)
        r->body[0] = '\0';
}

/* Replay protection lives in agent_broker_idem.c — the digest, the ring, and
 * the replay label. What is left in this file is WHERE it is consulted, and
 * that is exactly TWO places: a claim before anything is dispatched, and a
 * commit after a mutation has actually happened. Every refusal in between
 * simply returns, leaving the id claimed and nothing cached under it. */

/* ── the live authority ─────────────────────────────────────────────────── */

/* THE ONE PLACE A REQUEST IS AUTHORIZED, and it reads no session state that
 * could be stale: the verdict comes from the provider, which consults the
 * store as it is at this instant, and the session contributes only the
 * narrowing (agent_broker_scope_check, which can refuse and cannot allow).
 *
 * THERE IS NO FALLBACK. An unbound reference, a provider that vanished, or a
 * provider with no authorize entry point all produce DENIED_NO_GRANT. That is
 * the whole reason the session stopped holding a grant: with a copy present,
 * "the authority is unreachable" would silently become "use the copy", which
 * is exactly how a revoked grant keeps working. */
static int32_t authorize_live(const struct agent_broker_session *s,
                              const struct mvap_request *req, int64_t now_ms)
{
    const struct agent_authority_ref *a = s->authority;
    if (!a || !a->bound || !a->provider || !a->provider->authorize)
        return MVAP_ERR_DENIED_NO_GRANT;
    int32_t verdict =
        a->provider->authorize(a->provider_ctx, a, req, now_ms);
    if (verdict != MVAP_OK)
        return verdict;
    return agent_broker_scope_check(&a->scope, req);
}

static const char *session_principal(const struct agent_broker_session *s)
{
    return (s->authority && s->authority->bound) ? s->authority->principal : "";
}

static const char *session_grant_id(const struct agent_broker_session *s)
{
    return (s->authority && s->authority->bound)
               ? s->authority->canonical_grant_id
               : "";
}

/* One confinement receipt. `action_receipt_id` is the canonical metaverse
 * action receipt this row COMMITS TO — passed in from the COMMIT outcome, all
 * zero when the operation minted none (a refusal, or a query, which never
 * reaches here at all). It is inside the row's digest, so a confinement row
 * cannot later be pointed at a different action. */
static void broker_receipt(struct agent_broker_session *s,
                           const struct mvap_request *req,
                           struct mvap_response *resp, const char *detail,
                           const uint8_t action_receipt_id[32])
{
    if (!s->audit || !s->audit->open)
        return;
    struct agent_receipt r = { 0 };
    r.receipt_version = 3;
    snprintf(r.money_snapshot_status, sizeof(r.money_snapshot_status),
             "UNKNOWN");
    r.verb       = req->verb;
    r.request_id = req->request_id;
    r.status     = resp->status;
    r.value_zats = req->value_zats;
    memcpy(r.property_id, req->property_id, MVAP_PROPERTY_ID_LEN);
    if (action_receipt_id)
        memcpy(r.action_receipt_id, action_receipt_id, 32);
    snprintf(r.principal, sizeof(r.principal), "%s", session_principal(s));
    snprintf(r.grant_id, sizeof(r.grant_id), "%s", session_grant_id(s));
    r.peer = s->peer;
    snprintf(r.detail, sizeof(r.detail), "%s", detail ? detail : "");
    if (agent_audit_append(s->audit, &r)) {
        memcpy(resp->receipt_id, r.id, MVAP_RECEIPT_ID_LEN);
        s->receipts_written++;
    }
}

/* The audit row a REPLAY writes.
 *
 * It is its own row, and deliberately so: the agent asked twice, and a log that
 * records only the first ask cannot answer "how many times did this agent
 * present this receipt". It is DISTINGUISHABLE from a first execution on its
 * face — the detail begins with the word REPLAYED and names the receipt of the
 * execution it is replaying, which no first execution's detail can do.
 *
 * It is NOT counted in `receipts_written`, because that counter answers "how
 * much work did this broker commit" and a replay commits none; `replays_served`
 * counts it instead.
 *
 * `resp` is const on purpose. A replay returns the ORIGINAL confinement
 * receipt id, so this row must not stamp its own id over it — otherwise a
 * retry would hand the agent a second receipt for one action, which is the
 * double-count the ring exists to prevent. */
static void broker_replay_receipt(struct agent_broker_session *s,
                                  const struct mvap_request *req,
                                  const struct mvap_response *resp,
                                  const struct agent_idem_slot *slot)
{
    if (!s->audit || !s->audit->open || !slot)
        return;
    struct agent_receipt r = { 0 };
    r.receipt_version = 3;
    snprintf(r.money_snapshot_status, sizeof(r.money_snapshot_status),
             "UNKNOWN");
    r.verb       = req->verb;
    r.request_id = req->request_id;
    r.status     = resp->status;
    r.value_zats = req->value_zats;
    memcpy(r.property_id, req->property_id, MVAP_PROPERTY_ID_LEN);
    memcpy(r.action_receipt_id, slot->action_receipt_id, 32);
    snprintf(r.principal, sizeof(r.principal), "%s", session_principal(s));
    snprintf(r.grant_id, sizeof(r.grant_id), "%s", session_grant_id(s));
    r.peer = s->peer;

    char first[65];
    zcl_hex_encode(slot->resp.receipt_id, MVAP_RECEIPT_ID_LEN, first);
    snprintf(r.detail, sizeof(r.detail),
             "REPLAYED request_id=%u: executed nothing; first_receipt=%s",
             req->request_id, first);
    (void)agent_audit_append(s->audit, &r);
}

void agent_broker_handle(struct agent_broker_session *s,
                         const struct mvap_request *req,
                         struct mvap_response *out)
{
    if (!s || !req || !out)
        return;

    s->requests_served++;

    /* Queries and actions are two different pipelines from here on. A QUERY
     * resolves and answers; it can reach neither PLAN/COMMIT nor a receipt,
     * because those calls are not on its path at all.
     *
     * The class is decided BEFORE the ring is consulted: an unknown verb names
     * no operation, so it has no identity worth remembering and never claims
     * an id. */
    const bool is_action = mvap_verb_is_action(req->verb);
    if (!is_action && !mvap_verb_is_query(req->verb)) {
        resp_init(out, req, MVAP_ERR_UNKNOWN_VERB);
        resp_body(out, "{\"denied\":\"UNKNOWN_VERB\"}");
        s->requests_denied++;
        return;
    }

    /* THE REQUEST'S IDENTITY: every field that can change what it asks for,
     * plus the authority it is asked under — carried as fields, and hashed
     * into the key the ring indexes by. Everything the ring does is a
     * comparison of both, never of the request_id alone and never of the
     * digest alone. */
    struct agent_idem_identity ident;
    mvap_request_identity(req, session_grant_id(s), &ident);
    uint8_t digest[32];
    mvap_identity_digest(&ident, digest);

    const struct agent_idem_slot *slot = NULL;
    enum agent_idem_verdict remembered =
        agent_broker_idem_lookup(s, &ident, digest, &slot);
    if (remembered == AGENT_IDEM_CONFLICT) {
        /* The id already names a different request. The first request's record
         * is left exactly as it was — a second, unrelated ask must not be able
         * to evict or repoint it. */
        resp_init(out, req, MVAP_ERR_REQUEST_ID_REUSED);
        resp_body(out, "{\"denied\":\"REQUEST_ID_REUSED\","
                       "\"stage\":\"idempotency\",\"request_id\":%u,"
                       "\"detail\":\"this id already names a different "
                       "request\"}", req->request_id);
        s->requests_denied++;
        s->idempotency_conflicts++;
        broker_receipt(s, req, out,
                       "refused: request_id already names a different request",
                       NULL);
        return;
    }
    if (remembered == AGENT_IDEM_REPLAY) {
        /* A committed mutation, asked for again. Return the ORIGINAL response
         * and the ORIGINAL receipt, execute nothing, and say so on the wire. */
        *out = slot->resp;
        agent_broker_idem_label_replay(out);
        s->replays_served++;
        broker_replay_receipt(s, req, out, slot);
        return;
    }
    /* FRESH or CLAIMED both proceed. CLAIMED means this exact request was
     * dispatched before and cached nothing — a query, or a mutation that was
     * refused — so there is nothing to return and everything to re-decide
     * against the authority as it stands NOW.
     *
     * The claim is taken HERE, before any authorization or catalog work, so
     * the id is bound to this request no matter which of the outcomes below it
     * reaches. Every refusal from this point simply returns. */
    agent_broker_idem_claim(s, &ident, digest);

    int64_t now = clock_now_wall_ms();
    resp_init(out, req, MVAP_OK);

    /* 1. Authorization, on what the agent CLAIMED. The verdict comes from the
     *    LIVE authority through the provider; the session narrows it. */
    int32_t verdict = authorize_live(s, req, now);
    if (verdict != MVAP_OK) {
        resp_init(out, req, verdict);
        resp_body(out, "{\"denied\":\"%s\",\"stage\":\"authorize\"}",
                  mvap_status_name(verdict));
        s->requests_denied++;
        broker_receipt(s, req, out, "denied at pre-plan authorize", NULL);
        return;
    }

    /* 2. Resolve the property through the node seam — `query` for a query,
     *    `plan` for an action. */
    struct agent_plan plan;
    bool (*resolve)(void *, const struct mvap_request *, struct agent_plan *) =
        is_action ? s->ops.plan
                  : (s->ops.query ? s->ops.query : s->ops.plan);
    if (!resolve || !resolve(s->ops.ctx, req, &plan)) {
        resp_init(out, req, MVAP_ERR_PLAN_FAILED);
        resp_body(out, "{\"denied\":\"PLAN_FAILED\"}");
        s->requests_denied++;
        broker_receipt(s, req, out, "plan refused", NULL);
        return;
    }
    if (!plan.found) {
        resp_init(out, req, MVAP_ERR_NOT_FOUND);
        resp_body(out, "{\"denied\":\"NOT_FOUND\",\"detail\":\"%s\"}",
                  plan.detail);
        s->requests_denied++;
        return;
    }

    /* 3. Re-authorize against the CATALOG's kind, not the agent's claim. A
     *    request that understated its kind to slip past the mask dies here.
     *    Skipped only when the request named no property at all, where there
     *    is no catalog kind to disagree with.
     *
     *    This is a SECOND read of the live authority, not a re-run over the
     *    first verdict: the resolve above did real datadir work, and a revoke
     *    that landed during it must be seen here. */
    if (!mvap_property_id_is_zero(req->property_id)) {
        struct mvap_request authoritative = *req;
        authoritative.kind = plan.kind;
        verdict = authorize_live(s, &authoritative, now);
        if (verdict != MVAP_OK) {
            resp_init(out, req, verdict);
            resp_body(out, "{\"denied\":\"%s\",\"stage\":\"recheck\","
                           "\"actual_kind\":\"%s\"}",
                      mvap_status_name(verdict), mvap_kind_name(plan.kind));
            s->requests_denied++;
            broker_receipt(s, req, out, "denied at post-plan kind recheck",
                           NULL);
            return;
        }
    }

    /* 4. A query answers from what it resolved. It mutates nothing, debits
     *    nothing, and mints no receipt — on either side.
     *
     *    AND IT IS NOT REMEMBERED. A query used to be stored here, which meant
     *    a repeated request_id returned the old OK without consulting the
     *    authority at all: an agent could hold an answer across a revocation
     *    simply by retrying. A query is a read of live authority and live
     *    property state, so the only correct cache lifetime for one is zero. */
    if (!is_action) {
        resp_init(out, req, MVAP_OK);
        resp_body(out,
                  "{\"kind\":\"%s\",\"revision\":%llu,\"owner_matches\":%s,"
                  "\"detail\":\"%s\"}",
                  mvap_kind_name(plan.kind),
                  (unsigned long long)plan.revision,
                  plan.owner_matches ? "true" : "false", plan.detail);
        return;
    }

    /* 5. COMMIT — rechecks ownership and revision inside the seam. */
    struct agent_commit_outcome outcome;
    memset(&outcome, 0, sizeof(outcome));
    if (!plan.owner_matches) {
        resp_init(out, req, MVAP_ERR_DENIED_PROPERTY);
        resp_body(out, "{\"denied\":\"DENIED_PROPERTY\",\"stage\":\"commit\","
                       "\"detail\":\"controller is not the grant principal\"}");
        s->requests_denied++;
        broker_receipt(s, req, out, "commit refused: owner mismatch", NULL);
        return;
    }
    if (!s->ops.commit ||
        !s->ops.commit(s->ops.ctx, req, &plan, &outcome)) {
        resp_init(out, req, MVAP_ERR_COMMIT_FAILED);
        resp_body(out, "{\"denied\":\"COMMIT_FAILED\"}");
        s->requests_denied++;
        broker_receipt(s, req, out, "commit refused by the node seam", NULL);
        return;
    }

    /* The debit lands on the LIVE authority, so a budget spent here is spent
     * for every other reader of that grant — not in a session-local copy that
     * dies with the connection. */
    if (s->authority && s->authority->provider &&
        s->authority->provider->debit &&
        !s->authority->provider->debit(s->authority->provider_ctx,
                                       s->authority, req, now))
        LOG_WARN(BROKER_TAG,
                 "grant %s: the live authority refused a debit that authorize "
                 "had already allowed (verb=%s value=%llu)",
                 session_grant_id(s), mvap_verb_name(req->verb),
                 (unsigned long long)req->value_zats);
    resp_init(out, req, MVAP_OK);
    resp_body(out, "%s", outcome.body);
    /* The confinement envelope commits to the canonical action receipt rather
     * than restating what the action was. */
    char detail[AGENT_RECEIPT_DETAIL_MAX + 1];
    char action_hex[65];
    zcl_hex_encode(outcome.action_receipt_id, 32, action_hex);
    bool have_action_receipt = false;
    for (size_t i = 0; i < 32; i++)
        have_action_receipt |= outcome.action_receipt_id[i] != 0;
    snprintf(detail, sizeof(detail), "%s action_receipt=%s", plan.detail,
             have_action_receipt ? action_hex : "none");
    broker_receipt(s, req, out, detail, outcome.action_receipt_id);
    /* THE ONLY THING THAT PUTS AN ANSWER IN THE RING. A mutation that actually
     * committed: an identical repeat now replays this response and this
     * receipt and executes nothing. Stored with the canonical action receipt
     * it commits to, so the replay's audit row can name it too. */
    agent_broker_idem_commit(s, &ident, digest, out,
                             outcome.action_receipt_id);
}

/* ── serving ────────────────────────────────────────────────────────────── */

int agent_broker_serve_once(struct agent_broker_session *s, int fd)
{
    if (!s || fd < 0)
        LOG_ERR(BROKER_TAG, "bad session=%p fd=%d", (void *)s, fd);

    uint8_t prefix[MVAP_FRAME_PREFIX];
    bool closed = false;
    if (!read_full(fd, prefix, sizeof(prefix), &closed)) {
        if (closed)
            return 0;
        LOG_ERR(BROKER_TAG, "reading frame prefix failed: %s", strerror(errno));
    }
    uint32_t rec = mvap_frame_length(prefix, sizeof(prefix));
    if (rec == 0)
        LOG_ERR(BROKER_TAG, "peer declared an out-of-bounds frame length");

    uint8_t buf[MVAP_MAX_FRAME];
    if (!read_full(fd, buf, rec, &closed))
        LOG_ERR(BROKER_TAG, "short read of a %u-byte frame%s", rec,
                closed ? " (peer closed mid-frame)" : "");

    struct mvap_request req;
    struct mvap_response resp;
    if (!mvap_request_decode(buf, rec, &req)) {
        memset(&req, 0, sizeof(req));
        resp_init(&resp, &req, MVAP_ERR_BAD_REQUEST);
        resp_body(&resp, "{\"denied\":\"BAD_REQUEST\"}");
    } else {
        agent_broker_handle(s, &req, &resp);
    }

    uint8_t out[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
    size_t n = mvap_response_encode(&resp, out, sizeof(out));
    if (n == 0)
        LOG_ERR(BROKER_TAG, "could not encode the response for request_id=%u",
                resp.request_id);
    if (!write_full(fd, out, n))
        LOG_ERR(BROKER_TAG, "writing the response failed: %s", strerror(errno));
    return 1;
}

int agent_broker_serve_fd(struct agent_broker_session *s, int fd,
                          uint64_t max_requests)
{
    if (!s || fd < 0)
        LOG_ERR(BROKER_TAG, "bad session=%p fd=%d", (void *)s, fd);

    /* The credential check happens ONCE, here, before a single verb is
     * dispatched. A peer that fails it never reaches agent_broker_handle. */
    if (!agent_broker_identify_peer(fd, &s->peer))
        LOG_ERR(BROKER_TAG, "no peer credentials on fd=%d", fd);

    char why[160];
    if (!agent_broker_peer_authorized(&s->peer, &s->expect, why, sizeof(why))) {
        struct mvap_request empty = { .verb = MVAP_VERB_INSPECT };
        struct mvap_response resp;
        resp_init(&resp, &empty, MVAP_ERR_DENIED_PEER_IDENTITY);
        resp_body(&resp, "{\"denied\":\"DENIED_PEER_IDENTITY\",\"why\":\"%s\"}",
                  why);
        s->requests_denied++;
        broker_receipt(s, &empty, &resp, why, NULL);
        uint8_t out[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
        size_t n = mvap_response_encode(&resp, out, sizeof(out));
        if (n)
            (void)write_full(fd, out, n);
        LOG_ERR(BROKER_TAG, "peer refused: %s", why);
    }

    uint64_t served = 0;
    for (;;) {
        int r = agent_broker_serve_once(s, fd);
        if (r <= 0)
            return r == 0 ? (int)served : -1;
        served++;
        if (max_requests && served >= max_requests)
            return (int)served;
    }
}

int agent_broker_listen(const char *path)
{
    if (!path || !path[0])
        LOG_ERR(BROKER_TAG, "null socket path");
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (strnlen(path, sizeof(sa.sun_path)) >= sizeof(sa.sun_path))
        LOG_ERR(BROKER_TAG, "socket path too long (%zu >= %zu): %s",
                strnlen(path, 4096), sizeof(sa.sun_path), path);
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);

    int fd = socket(AF_UNIX, SOCK_STREAM
#if defined(SOCK_CLOEXEC)
                    | SOCK_CLOEXEC
#endif
                    , 0);
    if (fd < 0)
        LOG_ERR(BROKER_TAG, "socket(AF_UNIX) failed: %s", strerror(errno));
#if !defined(SOCK_CLOEXEC)
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        (void)close(fd);
        LOG_ERR(BROKER_TAG, "socket CLOEXEC failed: %s", strerror(errno));
    }
#endif
    (void)unlink(path);

    /* 0700 before bind: the filesystem permission is a coarse first gate, and
     * SO_PEERCRED is the exact one. Neither replaces the other. */
    mode_t old = umask(0077);
    bool bound = bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0;
    (void)umask(old);
    if (!bound) {
        (void)close(fd);
        LOG_ERR(BROKER_TAG, "bind %s failed: %s", path, strerror(errno));
    }
    if (listen(fd, 4) != 0) {
        (void)close(fd);
        LOG_ERR(BROKER_TAG, "listen on %s failed: %s", path, strerror(errno));
    }
    return fd;
}

int agent_broker_accept_once(struct agent_broker_session *s, int listen_fd,
                             int timeout_ms)
{
    if (!s || listen_fd < 0)
        LOG_ERR(BROKER_TAG, "bad session=%p listen_fd=%d", (void *)s,
                listen_fd);
    struct pollfd p = { .fd = listen_fd, .events = POLLIN };
    int pr = poll(&p, 1, timeout_ms);
    if (pr == 0)
        return 0;
    if (pr < 0)
        LOG_ERR(BROKER_TAG, "poll on the listener failed: %s", strerror(errno));

    int cfd = accept(listen_fd, NULL, NULL);
    if (cfd < 0)
        LOG_ERR(BROKER_TAG, "accept failed: %s", strerror(errno));
    int served = agent_broker_serve_fd(s, cfd, 0);
    (void)close(cfd);
    return served < 0 ? -1 : 1;
}
