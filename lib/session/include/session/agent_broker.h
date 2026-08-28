/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agent_broker — a REAL confinement boundary for an agent that acts on
 * metaverse properties on the operator's behalf.
 *
 * THE PROBLEM THIS EXISTS TO FIX: an "agent" that is merely a process in the
 * operator's own session is not confined at all. It inherits the environment
 * (every secret in it), can read every file the uid can read, and can exec
 * anything. A grant handed to such a process is a bearer token in a place that
 * leaks — /proc/<pid>/environ and a process listing both publish it.
 *
 * THE SHAPE OF THE FIX — two processes, asymmetric trust:
 *
 *   BROKER (privileged side, run by the operator/node)
 *     - HOLDS the grant. The grant is never written to the child's argv,
 *       environment, or any file the child can open. The child cannot name it,
 *       present it, forward it, or leak it, because it never has it.
 *     - Owns the socket. Validates SO_PEERCRED on EVERY connection: the kernel
 *       tells it the peer's real pid/uid/gid, so a client-asserted identity is
 *       never consulted.
 *     - Runs PLAN -> COMMIT against the node, rechecking the grant at commit.
 *     - Writes one tamper-evident audit receipt per action.
 *
 *   CONFINED AGENT (untrusted side)
 *     - Same binary, `--metaverse-agent-confined` mode.
 *     - Landlock: no datadir, no wallet, no RPC cookie, no $HOME. The only
 *       filesystem grant is its own scratch dir and /proc/self.
 *     - seccomp ALLOW-list (default KILL_PROCESS): no execve, no socket(), no
 *       connect(), no ptrace, no mount/namespace. It cannot open a NEW channel
 *       to anything — it has exactly one pre-opened socket fd from the broker
 *       and no syscall with which to make another.
 *     - rlimits: one process, no core dump, small address space.
 *     - Speaks only session/agent_broker_proto.h, whose wire cannot express a
 *       path, a shell word, or an RPC method.
 *
 * WHAT IS AND IS NOT A UID BOUNDARY (read this before trusting the model):
 * `agent_broker_spawn_confined()` will setgid/setuid to `confined_uid` when the
 * broker holds CAP_SETUID (the production posture: the node runs as a service
 * that can drop to a pre-provisioned unprivileged account). Where it cannot, it
 * records AGENT_CONFINE_SAME_UID in the report and keeps every other layer.
 * Landlock is not a weaker substitute for that: it denies access to the GRANTING
 * uid's own files, which a uid switch alone does not do. The honest summary is
 * that the filesystem boundary here is enforced by Landlock in both postures,
 * and the uid boundary is present only in the first.
 */

#ifndef ZCL_SESSION_AGENT_BROKER_H
#define ZCL_SESSION_AGENT_BROKER_H

#include "session/agent_broker_proto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#if defined(_WIN32)
/* Storage-only placeholders while the agent adapter is hard-disabled on
 * Windows. Authorization must use token SIDs, never these numeric fields;
 * keeping a fixed-width representation lets the node compile without
 * pretending that Unix UID/GID checks provide a Windows security boundary. */
typedef uint32_t uid_t;
typedef uint32_t gid_t;
#endif

/* ── the grant (broker-side only; never crosses to the child) ───────────── */

#define AGENT_GRANT_ID_MAX      32
#define AGENT_PRINCIPAL_MAX     64
#define AGENT_GRANT_MAX_PROPS   8
#define AGENT_ALLOWLIST_MAX     192
#define AGENT_MONEY_BINDINGS_MAX 2
#define AGENT_MONEY_ENDPOINT_MAX 480

/* Owner-created custody binding. Endpoint/datadir are broker-private and are
 * never rendered by metaverse status/money/audit. */
struct agent_money_binding {
    char wallet_scope[5];
    char wallet_instance_id[33];
    char network_genesis[65];
    char node_datadir[AGENT_MONEY_ENDPOINT_MAX];
    int rpc_port;
};

/* One capability grant.
 *
 * `actions_mask` is the CANONICAL metaverse_action_set — the same persisted
 * bit per action the metaverse grants and receipts carry. It used to be
 * `1u << verb` over the wire enum, a third incompatible bit layout that meant
 * a grant minted here and a grant read from the metaverse described different
 * rights with the same number. Set it only through
 * agent_grant_allow_action(), which translates the wire verb to its canonical
 * action.
 *
 * `queries_mask` is separate and keyed by WIRE value, because queries
 * (INSPECT, LIST) are not canonical actions at all and must never occupy a
 * canonical action bit.
 *
 * `kinds_mask` is a bitmask over enum mvap_kind. Scope is the INTERSECTION of
 * every field: the action must be granted AND the property must be in
 * `properties` (or, when n_properties == 0, its kind must be in kinds_mask)
 * AND the value must fit both ceilings AND the window must have room AND the
 * grant must be unexpired and unrevoked. */
struct agent_grant {
    char     grant_id[AGENT_GRANT_ID_MAX + 1];
    char     principal[AGENT_PRINCIPAL_MAX + 1];

    uint8_t  properties[AGENT_GRANT_MAX_PROPS][MVAP_PROPERTY_ID_LEN];
    size_t   n_properties;
    uint32_t kinds_mask;
    uint32_t actions_mask;        /* canonical metaverse_action_set          */
    uint32_t queries_mask;        /* bit N == wire query verb N              */

    uint64_t max_value_zats;      /* per-action ceiling; 0 == no value allowed */
    uint64_t budget_zats;         /* cumulative ceiling                        */
    uint64_t spent_zats;          /* debited at COMMIT                         */

    /* Counterparty allowlist: space-separated safe tokens; "" == any. */
    char     counterparty_allowlist[AGENT_ALLOWLIST_MAX + 1];

    int64_t  expires_unix_ms;     /* 0 == never                                */
    uint32_t rate_limit;          /* max committed actions per window; 0 == off */
    uint32_t window_seconds;
    uint32_t window_used;
    int64_t  window_start_ms;

    bool     may_delegate;
    uint32_t max_delegation_depth;

    uint64_t revocation_generation;
    bool     revoked;
};

/* Add a verb or kind to a grant's masks. `verb` is a WIRE value; the verb's
 * class decides which mask it lands in, so a caller never picks. An
 * unrecognized verb is ignored — it cannot be granted because it names
 * nothing. */
void agent_grant_allow_action(struct agent_grant *g, uint32_t verb);
void agent_grant_allow_kind(struct agent_grant *g, uint16_t kind);
bool agent_grant_add_property(struct agent_grant *g,
                              const uint8_t id[MVAP_PROPERTY_ID_LEN]);

/* SHA3-256 over the grant's canonical scope fields. Published in `metaverse
 * agent status` so an operator can see WHICH grant is live without the broker
 * ever rendering the grant itself. */
void agent_grant_fingerprint(const struct agent_grant *g, uint8_t out[32]);

/* Evaluate `req` against `g` at time `now_ms`. Returns MVAP_OK or the specific
 * refusal. Pure: debits nothing. `agent_grant_commit_debit()` is the mutating
 * half, called only after a successful COMMIT. */
int32_t agent_grant_authorize(const struct agent_grant *g,
                              const struct mvap_request *req, int64_t now_ms);
void agent_grant_commit_debit(struct agent_grant *g,
                              const struct mvap_request *req, int64_t now_ms);

/* ── peer identity (SO_PEERCRED) ────────────────────────────────────────── */

struct agent_peer_cred {
    pid_t pid;
    uid_t uid;
    gid_t gid;
    bool  valid;
};

/* What the broker will accept. Any `require_*` left false is not checked; at
 * least one must be set or agent_broker_peer_authorized() refuses outright —
 * an expectation that checks nothing is a misconfiguration, not a wildcard. */
struct agent_peer_expectation {
    bool  require_uid;  uid_t uid;
    bool  require_gid;  gid_t gid;
    bool  require_pid;  pid_t pid;
};

/* Read the peer's credentials from the kernel via getsockopt(SO_PEERCRED).
 * These are the values the KERNEL attributes to the peer process — nothing the
 * peer sends can influence them. Returns false (and leaves out->valid false)
 * when the socket is not AF_UNIX or the option is unavailable.
 *
 * THE TRAP THIS OPTION CARRIES: SO_PEERCRED reports the process that CREATED
 * the socket. On an accept()ed connection that is the connecting peer, which is
 * the answer we want. On a socketpair(2) it is the process that made the PAIR —
 * the broker itself, on BOTH ends — so it cannot distinguish the broker from
 * the child it handed the other end to. Use agent_broker_identify_peer() unless
 * you specifically want the socket-creation answer. */
bool agent_broker_peercred(int fd, struct agent_peer_cred *out);

/* Read the credentials of whoever SENT the next pending message, from the
 * kernel's SCM_CREDENTIALS on that message. The kernel fills these in itself
 * and refuses a pid/uid the sender does not hold, so they cannot be forged; and
 * because they are per-message they name the process on the other end of a
 * socketpair, which SO_PEERCRED cannot. Requires SO_PASSCRED, which this call
 * enables. The message is PEEKED, not consumed, so the caller still reads it
 * normally. Blocks until the peer sends or closes. */
bool agent_broker_sender_cred(int fd, struct agent_peer_cred *out);

/* The broker's canonical "who is actually on the other end of this fd" answer:
 * SO_PEERCRED when it names some OTHER process (an accept()ed connection), and
 * the per-message credentials when it names us (a socketpair, where the
 * socket-creation answer is about the broker and therefore says nothing about
 * the peer). Every credential check in the broker goes through this. */
bool agent_broker_identify_peer(int fd, struct agent_peer_cred *out);

/* True iff `c` satisfies `e`. On refusal, writes the exact mismatch into `why`
 * (e.g. "uid mismatch: peer=1000 expected=65534"). */
bool agent_broker_peer_authorized(const struct agent_peer_cred *c,
                                  const struct agent_peer_expectation *e,
                                  char *why, size_t why_cap);

/* ── tamper-evident audit receipts ──────────────────────────────────────── */

#define AGENT_RECEIPT_DETAIL_MAX 160

/* One CONFINEMENT receipt: `id` = SHA3-256 over the canonical preimage (which
 * includes `prev`, so the log is a hash chain); `sig` = Ed25519 over `id` under
 * the broker's audit key. A verifier needs only the file and the public key.
 *
 * WHAT THIS IS AND IS NOT. It is evidence about the BOUNDARY — which kernel-
 * attributed peer asked for what, under which grant, and what the broker did
 * about it. It is NOT a second account of what the action meant. The metaverse
 * mints the authoritative action receipt (metaverse/property_receipt.h: a
 * canonical, hash-chained, signed record), and this envelope COMMITS TO it:
 * `action_receipt_id` carries that receipt's chain hash and is inside this
 * row's digest. So a confinement row cannot be pointed at a different action
 * than the one the metaverse recorded, and the two logs are joined by a hash
 * instead of by two independent restatements of the same event.
 *
 * All-zero `action_receipt_id` means the operation minted no canonical
 * receipt — a query, or a refusal that never reached COMMIT. */
struct agent_receipt {
    uint32_t receipt_version;     /* 2 legacy; 3 commits custody snapshot   */
    uint64_t seq;                 /* 1-based; monotonic per log             */
    int64_t  unix_ms;
    uint8_t  prev[32];            /* previous receipt id; zeroes for seq 1  */
    uint8_t  id[32];
    uint8_t  sig[64];

    uint32_t verb;
    uint32_t request_id;
    int32_t  status;
    uint64_t value_zats;
    uint8_t  property_id[MVAP_PROPERTY_ID_LEN];
    uint8_t  action_receipt_id[32];  /* canonical metaverse receipt chain hash */
    char     money_snapshot_status[16]; /* CURRENT/UNKNOWN/STALE/CONFLICTED */
    uint8_t  money_snapshot_root[32];   /* zero iff status is not CURRENT    */

    char     principal[AGENT_PRINCIPAL_MAX + 1];
    char     grant_id[AGENT_GRANT_ID_MAX + 1];
    struct agent_peer_cred peer;
    char     detail[AGENT_RECEIPT_DETAIL_MAX + 1];
};

/* An open append-only audit log plus the broker's signing key. The key is
 * generated on first open and its PUBLIC half written next to the log; the
 * secret half never leaves this struct (and never reaches the confined child,
 * which has no Landlock grant on the broker's directory). */
struct agent_audit_log {
    char     dir[384];
    char     log_path[448];
    char     pub_path[448];
    uint8_t  sk[32];
    uint8_t  pk[32];
    uint64_t seq;
    uint8_t  head[32];
    bool     open;
};

/* Open (creating if absent) `<dir>/audit.log` + `<dir>/audit.pub`. When the log
 * already exists it is REPLAYED to recover seq and head, so an append after a
 * restart continues the same chain rather than starting a second one. */
bool agent_audit_open(struct agent_audit_log *log, const char *dir);

/* Fill r->{seq,unix_ms,prev,id,sig}, append one canonical JSON line, and fsync.
 * The caller fills the descriptive fields. Idempotency is the BROKER's job
 * (see agent_broker_session): this call always appends. */
bool agent_audit_append(struct agent_audit_log *log, struct agent_receipt *r);

struct agent_audit_verdict {
    uint64_t rows;
    uint64_t chain_breaks;   /* prev != previous row's id, or seq out of order */
    uint64_t bad_signatures;
    uint64_t malformed;
    uint8_t  head[32];
    bool     ok;             /* rows > 0 && every counter above == 0           */
};

/* Replay `<dir>/audit.log`, recompute every id from its preimage, check the
 * chain links, and verify every signature against `<dir>/audit.pub`. This is
 * the whole tamper-evidence claim: editing, reordering, or deleting any row
 * breaks either a recomputed id, a chain link, or a signature. */
bool agent_audit_verify_dir(const char *dir, struct agent_audit_verdict *out);

/* Render up to `max` most-recent receipts as JSON text into `out`. Used by
 * `metaverse agent audit`; read-only, creates nothing. */
size_t agent_audit_render_json(const char *dir, size_t max, char *out,
                               size_t out_cap);

/* ── the confinement report ─────────────────────────────────────────────── */

enum agent_confine_uid_posture {
    AGENT_CONFINE_UID_UNKNOWN = 0,
    AGENT_CONFINE_SEPARATE_UID,   /* setuid to a different uid SUCCEEDED     */
    AGENT_CONFINE_SAME_UID,       /* no CAP_SETUID here; other layers stand  */
};

/* What confinement the child ACTUALLY got. Reported to the broker over the
 * socket at handshake and republished by `metaverse agent status`, so the
 * operator reads the achieved posture rather than the requested one. */
struct agent_confine_report {
    enum agent_confine_uid_posture uid_posture;
    uid_t  ran_as_uid;
    gid_t  ran_as_gid;
    int    landlock_abi;
    bool   landlock_applied;
    bool   seccomp_applied;
    bool   rlimits_applied;
    size_t fs_grants;
    char   seccomp_method[16];
};

/* ── the node seam (PLAN -> COMMIT) ─────────────────────────────────────── */

/* What PLAN resolved about the target property. COMMIT rechecks `revision` and
 * `owner_matches`; a move between the two is MVAP_ERR_REVISION_MOVED. */
struct agent_plan {
    bool     found;
    uint16_t kind;
    uint64_t revision;
    bool     owner_matches;
    uint8_t  content_root[32];
    char     detail[AGENT_RECEIPT_DETAIL_MAX + 1];
};

/* What a COMMIT produced. `body` is the bounded JSON the agent gets back;
 * `action_receipt_id` is the canonical metaverse receipt's chain hash, which
 * the broker's confinement envelope then commits to. A seam that mints no
 * canonical receipt leaves it all-zero and says so rather than inventing
 * one. */
struct agent_commit_outcome {
    char    body[MVAP_BODY_MAX + 1];
    uint8_t action_receipt_id[32];
};

/* The seam onto the property catalog and the property grant service.
 *
 * QUERIES AND ACTIONS ARE DIFFERENT ENTRY POINTS, not one entry point with a
 * flag. `query` resolves a read; `plan` + `commit` are the two halves of an
 * action. The property that holds structurally is the one that matters: a
 * QUERY never reaches `commit`, because `commit` is not on its code path at
 * all — not because something remembered to check a flag first.
 *
 * `query` is OPTIONAL. A seam whose resolution is already side-effect-free may
 * leave it NULL and the broker resolves reads through `plan`, which is pure
 * resolution by contract; `commit` is the only call permitted to change
 * anything, and no query ever makes it. */
struct agent_broker_node_ops {
    bool (*query)(void *ctx, const struct mvap_request *req,
                  struct agent_plan *out);
    bool (*plan)(void *ctx, const struct mvap_request *req,
                 struct agent_plan *out);
    bool (*commit)(void *ctx, const struct mvap_request *req,
                   const struct agent_plan *plan,
                   struct agent_commit_outcome *out);
    void *ctx;
};

/* ── the live authority ─────────────────────────────────────────────────── */

/* The narrowing a broker SESSION adds on top of the canonical verdict, and
 * the only thing about authority the session is allowed to hold by value.
 *
 * Every field here can do exactly one thing: REFUSE. There is no field whose
 * value can turn a canonical NO into a YES, which is why copying it into the
 * session is safe while copying a grant is not. It is derived MECHANICALLY
 * from the canonical grant at bind time (agent_broker_scope_from_grant), never
 * hand-authored beside it, so there is no second policy that can drift away
 * from the one the operator actually issued. */
struct agent_broker_scope {
    uint8_t  properties[AGENT_GRANT_MAX_PROPS][MVAP_PROPERTY_ID_LEN];
    size_t   n_properties;
    uint32_t kinds_mask;          /* bit N == enum mvap_kind N               */
    uint64_t max_value_zats;      /* per-action ceiling under the cumulative */
};

/* Derive the session narrowing from the grant the session is bound to. */
void agent_broker_scope_from_grant(const struct agent_grant *g,
                                   struct agent_broker_scope *out);

/* Apply the narrowing to one request. MVAP_OK or a named refusal. Pure, and
 * structurally incapable of widening: every branch returns either OK or a
 * DENIED_*. */
int32_t agent_broker_scope_check(const struct agent_broker_scope *sc,
                                 const struct mvap_request *req);

/* WHAT A BROKER SESSION HOLDS INSTEAD OF A GRANT.
 *
 * It used to hold `struct agent_grant grant` BY VALUE, and every authorize and
 * every debit read and wrote that copy. The consequence was not subtle: an
 * operator revoking the grant, shortening its expiry, or cutting its budget
 * changed the store and changed NOTHING about a broker session already
 * running. The session went on answering out of the snapshot it took when it
 * started, for as long as the agent stayed connected. Revocation was a
 * property of new sessions only.
 *
 * So the session now holds a REFERENCE and no authority at all. There is no
 * grant in `struct agent_broker_session` to go stale, and no fallback path
 * that could read one: when the reference is unbound or the provider cannot
 * answer, the request is REFUSED (MVAP_ERR_DENIED_NO_GRANT). "Could not reach
 * the authority" and "the authority said no" have the same effect, which is
 * the only arrangement in which the first cannot be used to obtain the
 * second.
 *
 * LIFETIME: `provider` and `provider_ctx` are BORROWED. The registry borrows
 * the provider pointer too (agent_broker_provider_install), so both the
 * provider object and its context must have static lifetime. A stack-local
 * provider is a dangling pointer, not a style choice. */
struct agent_authority_ref {
    const struct agent_broker_provider *provider;  /* borrowed, static      */
    void *provider_ctx;                            /* borrowed, static      */
    char  canonical_grant_id[AGENT_GRANT_ID_MAX + 1];
    char  principal[AGENT_PRINCIPAL_MAX + 1];
    struct agent_broker_scope scope;
    bool  bound;                  /* false == UNGRANTED, and it fails closed */
};

/* Operator-facing status about the authority. EXPLICITLY LABELLED as status:
 * nothing on a decision path may read this struct, and nothing in it is
 * consulted by agent_broker_handle(). It exists so `metaverse agent status`
 * can say WHICH authority is live and how durable it is, without the broker
 * keeping a second copy of the grant to render. */
struct agent_authority_status {
    char     authority_source[64];   /* who issued it, e.g. "grant-id"      */
    bool     live_authority;         /* every decision re-reads the store   */
    bool     ephemeral;              /* the store does not survive a restart */
    char     canonical_grant_id[AGENT_GRANT_ID_MAX + 1];
    char     principal[AGENT_PRINCIPAL_MAX + 1];
    bool     revoked;
    uint64_t budget_zat;
    uint64_t spent_zat;
    uint64_t authority_generation;
    uint8_t  fingerprint[32];
};

/* Where the broker gets its REAL authority and its REAL property surface.
 *
 * lib/ sits below app/services, so the property catalog and the property grant
 * service cannot be named from here; the composition root registers them. With
 * nothing registered `agent_broker_mode_main()` REFUSES to run. That is the
 * point: a broker that cannot reach the real catalog must not fall back to a
 * fixture, because a fixture grant that authorizes real-looking actions is
 * exactly the failure this seam exists to make impossible.
 *
 * REGISTRATION GRANTS NOTHING. `bind` is a separate call, made AFTER the
 * confined child has been forked, and a provider that was handed no explicit
 * operator-selected grant source must refuse it. */
struct agent_broker_provider {
    /* Bind this session to an EXISTING canonical grant. Fills the immutable
     * reference — canonical id, principal, and the narrowing derived from
     * that grant. Returns false to refuse the session; `why` (when non-NULL)
     * receives the named reason. Called ONCE, after the fork. */
    bool (*bind)(void *ctx, struct agent_authority_ref *out, char *why,
                 size_t why_cap);

    /* THE LIVE DECISION. Consults the authority AS IT IS NOW — no cached
     * verdict, no session copy. MVAP_OK or the named refusal. Called for
     * every request, twice per action (once on the claimed kind, once on the
     * catalog's). */
    int32_t (*authorize)(void *ctx, const struct agent_authority_ref *ref,
                         const struct mvap_request *req, int64_t now_ms);

    /* Record a committed action against the live authority (budget, rate
     * window). Returns false when the authority refused the debit, which the
     * broker logs — it never silently proceeds. */
    bool (*debit)(void *ctx, const struct agent_authority_ref *ref,
                  const struct mvap_request *req, int64_t now_ms);

    /* Optional. Fill the labelled status snapshot. Never consulted by a
     * decision. */
    bool (*status)(void *ctx, const struct agent_authority_ref *ref,
                   struct agent_authority_status *out);

    /* Optional owner-created custody bindings. These are configuration, not
     * authority: returning them does not permit a spend. The broker persists
     * them in a mode-0600 private file outside the confined child's grants. */
    bool (*money_bindings)(void *ctx, struct agent_money_binding *out,
                           size_t max, size_t *count);

    /* The property surface the grant acts on. */
    struct agent_broker_node_ops (*ops)(void *ctx);
    void *ctx;
    const char *name;             /* named in the refusal and in status      */
};

void agent_broker_provider_install(const struct agent_broker_provider *p);
const struct agent_broker_provider *agent_broker_provider_get(void);

/* Bind `s` to the REGISTERED provider's authority: fills `ref`, points
 * `s->authority` at it, and installs the provider's property surface into
 * `s->ops`. `ref` must OUTLIVE `s` — the session borrows it and never copies
 * it. Call once, AFTER the confined child has been forked.
 *
 * False means UNGRANTED, which is a served state and not a startup failure:
 * the socket still comes up and every request is refused by name, so an
 * operator sees the reason per request instead of a process that vanished.
 * `why` (optional) receives that reason. */
struct agent_broker_session;
bool agent_broker_session_bind(struct agent_broker_session *s,
                               struct agent_authority_ref *ref, char *why,
                               size_t why_cap);

/* The fixture catalog and demo grant exist ONLY in a build compiled with
 * -DZCL_TESTING; in a production binary the symbols below are not declared and
 * not compiled, so no production path can reach them. Read
 * `agent_broker_fixtures_compiled_in` to say which build this is. */
extern const bool agent_broker_fixtures_compiled_in;

/* The deterministic ids of the fixture catalog's properties. Kept outside the
 * test-only guard because the confined-agent demo scripts name a target with
 * it: it derives an identifier and confers no authority and no behaviour. */
void agent_broker_fixture_property_id(size_t index,
                                      uint8_t out[MVAP_PROPERTY_ID_LEN]);
#define AGENT_BROKER_FIXTURE_PROPERTIES 2

#ifdef ZCL_TESTING
/* The fixture catalog: two properties (one content, one zcode). */
struct agent_broker_node_ops agent_broker_fixture_ops(void);

/* The demo grant + fixture ops as a provider, for the adversarial demo that
 * drives `--metaverse-broker --fixture`. The fixture's authority lives in the
 * fixture, not in the session, so the demo's revocation below is a real live
 * revocation and not a poke at a session copy. */
void agent_broker_install_fixture_provider(void);

/* Revoke the fixture provider's live authority. A session already running is
 * affected immediately, because it holds no copy of it. */
void agent_broker_fixture_revoke(void);

/* Move the fixture provider's authority clock, so a test can walk past an
 * expiry without sleeping. `ms` is an offset added to the wall clock. */
void agent_broker_fixture_advance_clock(int64_t ms);

/* Install `g` as the fixture provider's live authority, and bind a session to
 * it. Returns false when the grant cannot be represented. */
void agent_broker_fixture_set_grant(const struct agent_grant *g);

/* The fixture provider's authority as it stands right now, for a test that
 * needs to assert on it. */
void agent_broker_fixture_get_grant(struct agent_grant *out);
#endif

/* ── idempotency: the identity of a request, not just its number ────────── */

#define AGENT_IDEMPOTENCY_SLOTS 32

/* THE CANONICAL REQUEST DIGEST — SHA3-256 over everything that can change what
 * a request ASKS FOR, plus the authority it is asked under.
 *
 * WHY IT EXISTS. The ring used to key a replay on `request_id` alone (with the
 * verb compared at the call site, and nothing else). So request_id=7 INSPECT
 * property A followed by request_id=7 INSPECT property B returned property A's
 * answer to a question about property B — a confused-deputy read, produced by
 * the broker itself, with no refusal anywhere. Comparing the FULL digest is
 * what makes "the same request_id" mean "the same request".
 *
 * THE PREIMAGE, field by field, in this order — every variable-length field is
 * length-prefixed, so no two distinct requests can share a preimage:
 *
 *   19 bytes  "zcl.mvap.request.v1"  domain-separation tag, no NUL
 *    u32 le   protocol version       req->version, with 0 normalized to
 *                                    MVAP_VERSION (0 means "the current one"
 *                                    everywhere else on this wire, so the two
 *                                    spellings must digest alike)
 *    u32 le   verb                   the wire verb value
 *    u32 le   request_id             the key itself, so a slot cannot be read
 *                                    as belonging to another id
 *    u16 le   kind                   the AGENT'S declared kind — the catalog's
 *                                    kind is discovered later and is not part
 *                                    of what was asked
 *    u64 le   value_zats
 *   32 bytes  property_id            raw, including the all-zero sentinel
 *    u16 le   param length           strlen, at most MVAP_PARAM_MAX
 *      n      param bytes            no NUL terminator in the preimage
 *    u16 le   authority id length    at most AGENT_GRANT_ID_MAX
 *      n      authority id bytes     the canonical grant id the session is
 *                                    bound to, "" when ungranted; a request
 *                                    replayed under a DIFFERENT authority is
 *                                    a different request
 *
 * `authority_id` may be NULL, which digests identically to "".
 *
 * THE DIGEST IS A KEY, NOT THE PROOF. Two requests that hash alike must not be
 * treated as one, so the ring stores the preimage FIELDS as well (struct
 * agent_idem_identity below) and a hit is confirmed against them. That leaves
 * the "same id, same request" guarantee resting on a comparison this code
 * performs, rather than on SHA3-256 having no collisions. */
void mvap_request_digest(const struct mvap_request *req,
                         const char *authority_id, uint8_t out[32]);

/* THE PREIMAGE, AS FIELDS. Exactly the values listed above and nothing else —
 * `param` and `authority_id` are stored with explicit lengths and WITHOUT a
 * terminator, the same shape the preimage uses, so comparing two identities is
 * comparing two preimages.
 *
 * WHY IT IS STORED. The ring used to hold the digest alone, so a hit was
 * "these 32 bytes matched" and the entry was then served as a legitimate
 * replay. Finding a second request with the same SHA3-256 is not a practical
 * attack — but the guarantee was INHERITED from SHA3 rather than established
 * here, and establishing it costs one comparison of fields the broker already
 * had in hand. A slot is served only when the digest AND every field match; a
 * digest that matches over different fields is a CONFLICT, which is the same
 * refusal any other reuse of the id gets.
 *
 * The digest is computed FROM this struct (mvap_identity_digest), so the two
 * cannot describe different things: there is no second place that decides what
 * a request's identity is. */
struct agent_idem_identity {
    uint64_t value_zats;
    uint32_t version;                 /* 0 normalized to MVAP_VERSION      */
    uint32_t verb;
    uint32_t request_id;
    uint16_t kind;
    uint16_t param_len;
    uint16_t authority_len;
    uint8_t  property_id[MVAP_PROPERTY_ID_LEN];
    char     param[MVAP_PARAM_MAX];            /* not NUL-terminated       */
    char     authority_id[AGENT_GRANT_ID_MAX]; /* not NUL-terminated       */
};

/* Project a request plus the authority it is asked under into its identity.
 * `authority_id` may be NULL, which is the ungranted session and reads as "".
 * Zeroes `*out` first, so the unused tail of each bounded string is fixed. */
void mvap_request_identity(const struct mvap_request *req,
                           const char *authority_id,
                           struct agent_idem_identity *out);

/* SHA3-256 over the preimage this identity IS. mvap_request_digest() is these
 * two calls composed, which is why the digest can never cover a field the slot
 * does not store. */
void mvap_identity_digest(const struct agent_idem_identity *id,
                          uint8_t out[32]);

/* Field-by-field equality. Not a memcmp: a struct comparison would pass over
 * padding and would keep passing when a field is added and forgotten. The
 * sizeof assertion in agent_broker_idem.c makes that omission a build error. */
bool mvap_identity_equal(const struct agent_idem_identity *a,
                         const struct agent_idem_identity *b);

/* A SLOT HOLDS A NAME; ONLY A COMMITTED MUTATION ALSO HOLDS AN ANSWER.
 *
 * Two different jobs share this ring and must not be confused:
 *
 *   CLAIMED — the id is bound to this exact request and NOTHING is cached
 *   under it. Every dispatched request claims its id: every query (always),
 *   and every mutation until it commits. An identical repeat is re-executed
 *   from scratch against the live authority; a repeat that changed any field
 *   is a conflict. This is the half that catches a reused id, and it caches
 *   nothing, which is why a revoked grant still stops answering reads.
 *
 *   COMMITTED — a mutation completed. Now, and only now, the ring holds the
 *   response and the receipt, and an identical repeat is a REPLAY.
 *
 * The two are separate ENTRY POINTS below, not a flag: agent_broker_idem_claim()
 * takes no response argument, so a query answer has no way into the ring. */
enum agent_idem_outcome {
    AGENT_IDEM_OUTCOME_NONE = 0,
    AGENT_IDEM_OUTCOME_CLAIMED,
    AGENT_IDEM_OUTCOME_COMMITTED,
};

struct agent_idem_slot {
    bool     used;
    uint32_t request_id;
    uint8_t  digest[32];
    /* WHAT THE DIGEST WAS TAKEN OVER. A hit on `digest` is confirmed against
     * this before anything is served, so a collision cannot present one
     * request's answer as another's. `identity.request_id` is the same number
     * as `request_id` above; the duplicate is deliberate, because the digest
     * covers the id and the identity must reproduce the preimage exactly. */
    struct agent_idem_identity identity;
    enum agent_idem_outcome outcome;
    /* Meaningful only when `outcome` is COMMITTED; all-zero while CLAIMED. */
    struct mvap_response resp;             /* the reply as first sent        */
    uint8_t  action_receipt_id[32];        /* canonical receipt it commits to */
};

enum agent_idem_verdict {
    AGENT_IDEM_FRESH = 0,   /* nothing is remembered under this request_id   */
    AGENT_IDEM_REPLAY,      /* same id, same digest, and it COMMITTED        */
    AGENT_IDEM_CLAIMED,     /* same id, same digest, nothing cached          */
    AGENT_IDEM_CONFLICT,    /* same id, DIFFERENT digest                     */
};

/* Ask the ring about the request `id` names, under `digest`. A slot is a hit
 * only when BOTH match; a slot whose digest matches over different fields is a
 * CONFLICT, never a replay. On REPLAY or CLAIMED `*slot_out` (when non-NULL)
 * receives the remembered slot; otherwise it is set to NULL. Pure: it records
 * nothing. */
enum agent_idem_verdict agent_broker_idem_lookup(
    const struct agent_broker_session *s,
    const struct agent_idem_identity *id, const uint8_t digest[32],
    const struct agent_idem_slot **slot_out);

/* Bind the request id to this request and cache NOTHING. Idempotent: claiming
 * an id already claimed by the same request changes nothing. */
void agent_broker_idem_claim(struct agent_broker_session *s,
                             const struct agent_idem_identity *id,
                             const uint8_t digest[32]);

/* Upgrade a claim to a committed mutation, with the response an identical
 * repeat will replay. `action_receipt_id` may be NULL, which stores all-zero —
 * the honest answer when the seam minted no canonical receipt. */
void agent_broker_idem_commit(struct agent_broker_session *s,
                              const struct agent_idem_identity *id,
                              const uint8_t digest[32],
                              const struct mvap_response *resp,
                              const uint8_t action_receipt_id[32]);

/* Label a replayed response IN PLACE: `"replayed":true` becomes the first
 * member of the returned JSON object, ahead of the original answer verbatim.
 * An agent that cannot tell a replay from a first execution will count one
 * event twice, so the label is part of the reply and not a broker-side note. */
void agent_broker_idem_label_replay(struct mvap_response *resp);

/* ── the broker session ─────────────────────────────────────────────────── */

/* One served connection.
 *
 * THERE IS NO GRANT IN HERE. `authority` is a const pointer to an immutable
 * reference (see struct agent_authority_ref for why): the session can name its
 * authority and cannot hold, copy, mutate, or outlive it. Every authorize and
 * every debit goes through `authority->provider`, so an operator's revoke,
 * expiry change, or budget change lands on the very next request of a session
 * that is already running.
 *
 * THE IDEMPOTENCY RING CACHES MUTATIONS AND NOTHING ELSE. A QUERY is a read of
 * live authority and live property state, so a cached query answer is stale by
 * definition: replaying one after a revoke, or after the property moved, would
 * return an answer the authority would no longer give. A query's ANSWER
 * therefore never enters the ring and no query is ever served from it — every
 * query is re-executed, which is the only way a revoked grant stops answering
 * reads. A query's NAME does enter it, so that an id pointed at a second,
 * different question is refused rather than answered about the first.
 *
 * `requests_served` counts every request; `receipts_written` counts audit rows
 * for work the broker actually did; `replays_served` counts requests answered
 * from the ring, which performed no work and therefore mint no receipt (their
 * audit row is a labelled REPLAY row, not a receipt); `idempotency_conflicts`
 * counts ids pointed at a second, different request. */
struct agent_broker_session {
    const struct agent_authority_ref *authority;
    struct agent_peer_expectation expect;
    struct agent_broker_node_ops  ops;
    struct agent_audit_log       *audit;

    struct agent_peer_cred        peer;
    struct agent_confine_report   child;

    uint64_t requests_served;
    uint64_t requests_denied;
    uint64_t receipts_written;
    uint64_t replays_served;
    uint64_t idempotency_conflicts;

    struct agent_idem_slot idem[AGENT_IDEMPOTENCY_SLOTS];
};

/* Handle exactly ONE request frame already read off the wire. Returns the
 * response to send. This is the whole authorization pipeline in one function:
 *   peercred -> grant authorize -> PLAN -> grant recheck -> COMMIT -> receipt.
 * Never trusts a field of `req` beyond what mvap_request_decode() validated. */
void agent_broker_handle(struct agent_broker_session *s,
                         const struct mvap_request *req,
                         struct mvap_response *out);

/* Read one framed request from `fd`, handle it, write the framed response.
 * Returns 1 on a served request, 0 on a clean peer close, -1 on a protocol or
 * IO error (the caller closes the connection). */
int agent_broker_serve_once(struct agent_broker_session *s, int fd);

/* Serve `fd` until the peer closes or `max_requests` is reached (0 == until
 * close). Validates SO_PEERCRED ONCE up front and refuses the whole connection
 * when it does not match — a rejected peer never reaches the verb dispatch. */
int agent_broker_serve_fd(struct agent_broker_session *s, int fd,
                          uint64_t max_requests);

/* Bind + listen an AF_UNIX stream socket at `path` (unlinking a stale node),
 * mode 0700. Returns the listening fd or -1. This is the surface an arbitrary
 * local process can reach, which is exactly why every accept() is peercred
 * checked. */
int agent_broker_listen(const char *path);

/* Accept one connection, peercred-check it, and serve it. Returns 1 when a
 * connection was served, 0 on accept timeout, -1 on error. A peer that fails
 * the credential check is refused with MVAP_ERR_DENIED_PEER_IDENTITY, audited,
 * and disconnected without any verb being dispatched. */
int agent_broker_accept_once(struct agent_broker_session *s, int listen_fd,
                             int timeout_ms);

/* ── spawning the confined child ────────────────────────────────────────── */

struct agent_spawn_request {
    const char *self_exe;      /* path to this binary                        */
    const char *scratch_dir;   /* the ONLY writable Landlock grant the child gets */
    const char *script;        /* safe-token name of the child's built-in script */
    /* One path the BROKER wants the agent to TRY to open, so the refusal is
     * recorded as the kernel's errno in the child's report. It is an
     * instruction, never an authority: naming a path the child may not reach is
     * how the boundary is measured against a real asset instead of against
     * /etc/passwd. NULL or "" means "no canary". */
    const char *canary;
    uid_t       confined_uid;  /* target uid; 0 == "do not attempt a switch"  */
    gid_t       confined_gid;
};

struct agent_spawn_result {
    pid_t pid;
    int   sock;                /* broker end of the socketpair               */
};

/* socketpair() + fork() + exec self in confined-agent mode. The child end of
 * the pair becomes fd 3; argv carries ONLY the mode word, the script name, the
 * scratch dir and (when set) the canary path; the environment is EMPTY. No
 * grant material is placed in either, which is what makes the
 * /proc/<pid>/environ and cmdline assertions in the test hold.
 * Returns false and leaves result->pid <= 0 on failure. */
bool agent_broker_spawn_confined(const struct agent_spawn_request *req,
                                 struct agent_spawn_result *result);

/* ── the two argv modes (dispatched from src/main.c) ────────────────────── */

/* `--metaverse-agent-confined <script> <scratch-dir>` — the confined child.
 * Applies confinement to ITSELF, then speaks the protocol on fd 3. Never
 * returns to any node code path. */
int agent_confined_mode_main(int argc, char **argv);

/* `--metaverse-broker` — run a broker: spawn one confined agent, serve it,
 * write receipts, and exit. Accepts -datadir=, --broker-dir=,
 * --script=, --requests=, --listen (use a listening socket instead of the
 * inherited socketpair), and --expect-uid=.
 *
 * The grant and the property surface come from the registered
 * agent_broker_provider. With none registered this refuses rather than
 * serving; a ZCL_TESTING build additionally accepts --fixture to register the
 * demo provider, which is how the adversarial demo drives it. */
int agent_broker_mode_main(int argc, char **argv);

/* Apply the confined-agent profile to the CALLING process: rlimits ->
 * no_new_privs -> Landlock (scratch dir rw + /proc/self ro) -> seccomp
 * allow-list. ONE-WAY. `out` records what actually landed. Returns false only
 * when a step that MUST hold failed; a missing-Landlock kernel degrades and
 * says so in `out` rather than pretending. */
bool agent_confined_enter(const char *scratch_dir, uid_t want_uid,
                          gid_t want_gid, struct agent_confine_report *out);

/* The confined agent's seccomp ALLOW-list. Deliberately OMITS execve/execveat,
 * the whole socket family (socket/socketpair/connect/bind/accept/sendto/
 * recvfrom/sendmsg/recvmsg), clone/fork/vfork, ptrace/process_vm_*, mount/
 * setns/unshare/pivot_root, bpf/kexec/module ops, keyrings, and
 * open_by_handle_at. It DOES allow openat: the filesystem boundary is
 * Landlock's job, so a forbidden open must fail as EACCES (an operable,
 * attributable denial) rather than as an unattributable SIGSYS. */
const int *agent_confined_allowed_syscalls(size_t *count_out);

/* Write the achieved-confinement report / broker state to `<dir>/broker.json`
 * for `metaverse agent status` to read. Best-effort; a failure is logged and
 * does not stop the broker.
 *
 * The grant is no longer an argument, because the broker no longer holds one.
 * The authority section is pulled from the provider's labelled status
 * snapshot at write time, and a provider that supplies none is reported as
 * ungranted rather than as an empty grant. */
void agent_broker_write_status(const char *dir,
                               const struct agent_broker_session *s,
                               pid_t child_pid, const char *socket_path);

/* Render `<dir>/broker.json` (or a not-running verdict) as JSON text. */
size_t agent_broker_render_status_json(const char *dir, char *out,
                                       size_t out_cap);

#endif /* ZCL_SESSION_AGENT_BROKER_H */
