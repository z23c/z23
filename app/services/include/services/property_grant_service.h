/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Property grant service — the PLAN → COMMIT → RECEIPT state machine for
 * agent rights over metaverse property.
 *
 * The rules live in lib/metaverse (metaverse/property_grant.h, pure, no I/O).
 * This file owns the three things rules cannot own: the STORE (which grants
 * exist, what they have spent, which receipts have been emitted), the CLOCK
 * and HEIGHT, and the RECEIPT SIGNING KEY.
 *
 * ── WHY PLAN AND COMMIT ARE SEPARATE, AND WHY COMMIT RE-CHECKS EVERYTHING ──
 * A plan is a quote, not a permit. Between PLAN and COMMIT the world moves:
 * the grant can be revoked, its parent can be revoked, its budget can be spent
 * by a concurrent action, it can expire, the property can change owner, and the
 * property can be revised. A commit that trusted its plan would be authorizing
 * against facts that are no longer true — which is the exact failure mode a
 * plan/commit split is supposed to prevent. So COMMIT re-runs, from scratch,
 * against CURRENT state:
 *
 *   1. the grant record as the store holds it NOW (not the copy taken at plan),
 *   2. every ancestor's CURRENT revocation generation,
 *   3. the property's CURRENT owner and revision from the catalog,
 *   4. the remaining budget and rate window NOW,
 *   5. expiry against the CURRENT clock and height.
 *
 * The plan contributes exactly two things to the commit: the request it
 * described (so a commit cannot silently substitute a different action), and
 * the property REVISION observed at plan time (so a commit against a property
 * that has since been revised is rejected — optimistic concurrency control).
 *
 * Every rejection is a NAMED reason from the taxonomy below. There is no
 * generic "denied": a denial that does not say which of the twenty-odd
 * conditions fired is unactionable for the operator and unauditable for the
 * agent.
 *
 * ── SCOPE OF THIS STORE ───────────────────────────────────────────────────
 * The store is IN-PROCESS and bounded (fixed capacities, no heap). It is the
 * authority for the running node and nothing else: it is not written to
 * node.db, so it does not survive a restart. That is a deliberate, named
 * limitation of this lane, not an oversight — the receipt chain is designed to
 * be persisted (canonical fixed-width body, hash-chained, signed; see
 * metaverse/property_receipt.h), and wiring it through the AR lifecycle onto a
 * node.db table is a separate, reviewable change. Nothing here claims
 * durability. */

#ifndef ZCL_SERVICES_PROPERTY_GRANT_SERVICE_H
#define ZCL_SERVICES_PROPERTY_GRANT_SERVICE_H

#include "metaverse/property_grant.h"
#include "metaverse/property_id.h"
#include "metaverse/property_receipt.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bounded store capacities. Exceeding one is a named refusal (STORE_FULL). */
#define PROPERTY_GRANT_MAX_GRANTS 64
#define PROPERTY_GRANT_MAX_PLANS 128
#define PROPERTY_GRANT_MAX_RECEIPTS 512

#define PROPERTY_GRANT_PLAN_ID_LEN 32

/* A plan is short-lived on purpose: it is a quote against facts that move, and
 * a quote that outlives its facts is a trap. Two minutes is long enough for an
 * operator to read a plan and confirm it, short enough that the window in which
 * the world can shift under it stays small. Expiry is not the safety property
 * (the commit-time re-check is); it is the bound on how stale a rejected
 * commit's diagnostics can be. */
#define PROPERTY_GRANT_PLAN_TTL_SECONDS 120

/* ── Rejection taxonomy ─────────────────────────────────────────────────────
 * One flat enum covering both stages. Values 1..N mirror
 * enum metaverse_grant_verdict one-for-one (the static-scope rules), then the
 * commit-time re-check reasons follow. Tokens are contract: tests and the CLI
 * assert them exactly. */
enum property_grant_reason {
    PROPERTY_GRANT_OK = 0,

    /* Arguments and store */
    PROPERTY_GRANT_BAD_ARGS,
    PROPERTY_GRANT_STORE_FULL,
    PROPERTY_GRANT_GRANT_UNKNOWN,
    PROPERTY_GRANT_GRANT_EXISTS,

    /* Static scope — from metaverse_grant_check */
    PROPERTY_GRANT_GRANT_MALFORMED,
    PROPERTY_GRANT_GRANT_REVOKED,
    PROPERTY_GRANT_ANCESTOR_REVOKED,
    PROPERTY_GRANT_GRANT_EXPIRED_HEIGHT,
    PROPERTY_GRANT_GRANT_EXPIRED_TIME,
    PROPERTY_GRANT_WRONG_HOLDER,
    PROPERTY_GRANT_ACTION_NOT_GRANTED,
    PROPERTY_GRANT_PROPERTY_OUT_OF_SCOPE,
    PROPERTY_GRANT_KIND_OUT_OF_SCOPE,
    PROPERTY_GRANT_COUNTERPARTY_NOT_ALLOWED,
    PROPERTY_GRANT_VALUE_NEGATIVE,
    PROPERTY_GRANT_VALUE_ON_FREE_ACTION,
    PROPERTY_GRANT_BUDGET_EXCEEDED,
    PROPERTY_GRANT_RATE_LIMITED,
    PROPERTY_GRANT_DELEGATION_NOT_PERMITTED,
    PROPERTY_GRANT_DELEGATION_DEPTH_EXCEEDED,

    /* Commit-time re-checks — none of these can be decided at PLAN time */
    PROPERTY_GRANT_PLAN_UNKNOWN,
    PROPERTY_GRANT_PLAN_EXPIRED,
    PROPERTY_GRANT_PLAN_ALREADY_COMMITTED,
    PROPERTY_GRANT_CATALOG_UNAVAILABLE,
    PROPERTY_GRANT_PROPERTY_UNKNOWN,
    PROPERTY_GRANT_OWNER_MISMATCH,
    PROPERTY_GRANT_STALE_REVISION,
    PROPERTY_GRANT_RECEIPT_SEAL_FAILED,
    PROPERTY_GRANT_SIGNING_KEY_UNAVAILABLE,

    /* The (grant, idempotency_key) pair already names a receipt, but for a
     * DIFFERENT request. An idempotency key identifies one attempt at one
     * operation; matching on the key alone would hand back an unrelated
     * receipt with status OK and `replayed` set, so the caller's actual
     * request would never run and nothing would say so. Neither answer is
     * available here — replaying the stored receipt would answer a question
     * nobody asked, and executing the new request under a key that already
     * has a receipt would break the one guarantee the key exists to give — so
     * the reuse itself is the refusal. */
    PROPERTY_GRANT_IDEMPOTENCY_KEY_REUSED,

    /* The store moved WHILE a decision was being computed over a snapshot of
     * it, and the one permitted retry saw it move again. Neither a grant nor a
     * denial: the service declines to return a verdict it cannot show was made
     * over a coherent state. */
    PROPERTY_GRANT_AUTHORITY_CHANGED,

    PROPERTY_GRANT_REASON_COUNT
};

const char *property_grant_reason_token(enum property_grant_reason r);

/* Map a pure-rules verdict onto the service taxonomy. Total (never returns OK
 * for a non-OK verdict). */
enum property_grant_reason property_grant_reason_from_verdict(
    enum metaverse_grant_verdict v);

/* ── The catalog seam ───────────────────────────────────────────────────────
 * The property catalog is a SEPARATE lane's canonical projection. This service
 * needs exactly four facts from it and nothing else, so the dependency is one
 * function pointer rather than a header include. The catalog lane wires its
 * real lookup in at merge time; nothing about the state machine changes.
 *
 * FAIL CLOSED: with no lookup installed, every COMMIT is refused with
 * CATALOG_UNAVAILABLE. A commit that cannot confirm current ownership must not
 * proceed — "the catalog was not wired" and "the caller does not own this"
 * have to have the same effect, or an unwired build silently authorizes
 * everything. */
struct metaverse_catalog_view {
    struct metaverse_property_id id;
    char controller[METAVERSE_PRINCIPAL_MAX + 1]; /* owning/controlling principal */
    int64_t revision;                             /* monotonic per property */
    int64_t freshness_height;
};

/* Return false when the property is not in the catalog (→ PROPERTY_UNKNOWN).
 *
 * CALLED WITH NO SERVICE LOCK HELD. It used to run inside the store mutex,
 * which made binding the real catalog to it a deadlock-and-latency hazard: the
 * property catalog is a projection that rebuilds every view from authoritative
 * bytes on every call, so it does filesystem and SQLite work, and doing that
 * under the mutex would stall every other grant decision in the process behind
 * a disk read. Both call sites now take a snapshot under the lock, RELEASE it,
 * call this, and re-acquire to confirm the store did not move
 * (property_grant_service_recheck below).
 *
 * WHAT AN IMPLEMENTATION MAY DO. It may block and it may touch the datadir —
 * that is the entire reason the lock is released around it. It may also call
 * back into this service, including entry points that MUTATE the store: no
 * lock of this service is held while it runs, so there is nothing to re-enter.
 * That is not a loophole grudgingly permitted; it is how the lane's own
 * lock-discipline test PROVES the mutex is released, by mutating the store from
 * inside this callback and living.
 *
 * WHAT THAT COSTS, AND IT IS DEFINED BEHAVIOUR RATHER THAN AN ACCIDENT. A
 * callback that mutates the store moves the store-wide authority generation,
 * and the decision currently in flight is exactly the decision that generation
 * exists to invalidate: the caller re-acquires the lock, sees the move, and
 * reports AUTHORITY_CHANGED. PLAN and COMMIT each retry from scratch exactly
 * once and then refuse, rather than answer over a state nobody can show still
 * exists. So a callback that mutates on EVERY call makes every decision through
 * it fail with AUTHORITY_CHANGED — a callback is treated exactly as a
 * concurrent thread would be, because that is what it is. */
typedef bool (*metaverse_catalog_lookup_fn)(
    const struct metaverse_property_id *id,
    struct metaverse_catalog_view *out, void *ctx);

/* Supplies `now_unix` and `height`. The default reads the wall clock and
 * reports height 0; a caller that wants height-based grant expiry enforced
 * must install a provider that returns the active chain tip. Height 0 with a
 * grant that sets expires_height is NOT treated as expired — an unknown height
 * cannot prove expiry — which is why installing a real provider matters and is
 * stated here rather than left implicit. */
typedef void (*metaverse_clock_fn)(int64_t *now_unix, int64_t *height,
                                   void *ctx);

struct property_grant_env {
    metaverse_catalog_lookup_fn catalog_lookup;
    void *catalog_ctx;
    metaverse_clock_fn clock;
    void *clock_ctx;
};

/* Install the environment. NULL resets to defaults (no catalog → fail closed,
 * wall clock, height 0). Call before any plan/commit. */
void property_grant_service_configure(const struct property_grant_env *env);

/* Drop every grant, plan, and receipt and forget the signing key. Exposed for
 * tests and for a clean node shutdown; there is no partial reset. */
void property_grant_service_reset(void);

/* Install the receipt signing seed (32 bytes). Idempotent for the same seed.
 * When no seed is installed, the first commit draws one from the project
 * CSPRNG; a build that wants receipts verifiable across process restarts must
 * install a stable seed. Returns false (logged) on NULL or on an RNG failure. */
bool property_grant_service_set_signing_seed(const uint8_t seed[32]);

/* The public half of the receipt signing key — the `expected_signer` every
 * verification must pin. Returns false when no key has been established yet. */
bool property_grant_service_signer_pubkey(uint8_t out[METAVERSE_PUBKEY_LEN]);

/* ── Grants ─────────────────────────────────────────────────────────────── */

/* Insert a fully-formed ROOT grant (depth 0). `g->grant_id` may be empty, in
 * which case a 128-bit id is drawn and written back into *g. Rejects a
 * malformed grant (GRANT_MALFORMED), a duplicate id (GRANT_EXISTS), and a
 * depth>0 grant (BAD_ARGS — use property_grant_service_delegate). */
enum property_grant_reason property_grant_service_mint(
    struct metaverse_grant *g);

/* Mint a CHILD grant under `parent_grant_id`. Runs
 * metaverse_grant_check_delegation against the parent's current record and its
 * ancestors, then stamps the child's lineage from the live store (so the child
 * records the generations that are current at mint, which is what makes a later
 * parent revocation kill it). `child->depth`, `->lineage*` are set by this
 * function; anything the caller put there is overwritten. */
enum property_grant_reason property_grant_service_delegate(
    const char *parent_grant_id, struct metaverse_grant *child);

/* Copy the stored grant record. GRANT_UNKNOWN when there is no such id. */
enum property_grant_reason property_grant_service_get(
    const char *grant_id, struct metaverse_grant *out);

/* Bump `grant_id`'s revocation generation and set its revoked flag. This is
 * the whole REVOKE mechanism: the bump alone invalidates every grant delegated
 * from it, at any depth, because each child records the generation it was
 * minted under. Idempotent (a second revoke bumps again and still returns OK).
 * Every subsequent plan or commit against the grant or its subtree fails with
 * GRANT_REVOKED / ANCESTOR_REVOKED respectively. */
enum property_grant_reason property_grant_service_revoke(const char *grant_id);

/* Copy up to `max` grant records for `holder` ("" or NULL = every holder).
 * Returns the count written (never negative; 0 is a legitimate empty list). */
size_t property_grant_service_list(const char *holder,
                                   struct metaverse_grant *out, size_t max);

/* ── LIVE AUTHORITY (snapshot → decide → recheck) ────────────────────────────
 *
 * THE PROBLEM THIS SOLVES. A caller that wants to decide something about a
 * grant has three needs that pull against each other: it must read a coherent
 * grant + ancestor set, it must do EXPENSIVE work outside the store mutex (the
 * property catalog is a projection over datadir bytes), and it must not return
 * a verdict computed over state that has since changed. Holding the mutex
 * across the catalog read satisfies the first and third and violates the
 * second. Copying the grant and never looking again satisfies the second and
 * violates the third — and that is the exact shape of a revoke that does not
 * take effect.
 *
 * THE PROTOCOL, and it is not optional:
 *
 *   1. property_grant_service_snapshot()  — takes the mutex, copies the grant,
 *      its ancestors, every relevant revocation generation and the store-wide
 *      authority generation, RELEASES the mutex.
 *   2. the caller does its catalog / datadir work and runs the PURE decision
 *      (metaverse_grant_check / _query_check) against the snapshot. No lock is
 *      held for any of it.
 *   3. property_grant_service_recheck()   — re-takes the mutex briefly and
 *      confirms the authority generation and the grant's own revocation
 *      generation are exactly what the snapshot recorded. Anything else is
 *      AUTHORITY_CHANGED and the caller must retry from step 1 ONCE, then give
 *      up with AUTHORITY_CHANGED rather than answer.
 *
 * A decision returned without step 3 is a decision over a state nobody
 * confirmed still exists. */

struct property_grant_authority_snapshot {
    struct metaverse_grant grant;
    struct metaverse_grant ancestors[METAVERSE_GRANT_MAX_DEPTH];
    size_t ancestor_count;
    /* Each ancestor's revocation generation AS SNAPSHOTTED, in the same
     * root-first order. Re-compared by recheck: a parent revoked during the
     * decision window moves one of these even when the child is untouched. */
    uint32_t ancestor_generations[METAVERSE_GRANT_MAX_DEPTH];
    uint32_t grant_generation;
    uint64_t authority_generation;
    /* The clock the snapshot was taken against, so the caller's pure decision
     * measures expiry against the same instant the recheck will. */
    int64_t now_unix;
    int64_t height;
    bool valid;
};

/* Step 1. GRANT_UNKNOWN when there is no such id, ANCESTOR_REVOKED when an
 * ancestor is missing from the store (fail closed: "could not check the
 * parent" and "the parent said no" must have the same effect). */
enum property_grant_reason property_grant_service_snapshot(
    const char *grant_id, struct property_grant_authority_snapshot *out);

/* Step 3. OK when nothing moved, AUTHORITY_CHANGED when it did, BAD_ARGS on a
 * NULL or invalid snapshot, GRANT_UNKNOWN when the grant is simply gone. */
enum property_grant_reason property_grant_service_recheck(
    const struct property_grant_authority_snapshot *snap);

/* The current store-wide authority generation. Bumped by every mutation of the
 * store. Exposed so an operator status surface can publish WHICH state a
 * decision was made over. */
uint64_t property_grant_service_authority_generation(void);

/* Ancestor array as the pure evaluator wants it (an array of pointers,
 * root-first) over a snapshot's own copies. Returns the count and writes the
 * pointer array; the pointers are into `snap`, so they live exactly as long as
 * it does. */
size_t property_grant_snapshot_ancestors(
    const struct property_grant_authority_snapshot *snap,
    const struct metaverse_grant **out);

/* TEST-ONLY lock-discipline probe. True when the property-grant-store mutex is
 * held right now (by this thread or another). It exists so the lane's lock
 * test can prove from INSIDE a catalog callback that no datadir work runs
 * under the mutex — an assertion no amount of code reading can make. Always
 * false outside a ZCL_TESTING build. */
bool property_grant_service_test_store_lock_busy(void);

/* ── PLAN ───────────────────────────────────────────────────────────────── */

/* What a plan carries. `request` is echoed back exactly as planned, including
 * the resolved `now_unix`/`height`, so a caller can see the facts the quote was
 * made against. */
struct property_grant_plan {
    char plan_id[PROPERTY_GRANT_PLAN_ID_LEN + 1];
    char grant_id[METAVERSE_GRANT_ID_LEN + 1];
    struct metaverse_action_request request;
    int64_t property_revision;                    /* observed at PLAN */
    char controller_at_plan[METAVERSE_PRINCIPAL_MAX + 1];
    bool catalog_seen;                            /* false = catalog absent */
    int64_t created_unix;
    int64_t expires_unix;
    bool committed;
    uint64_t receipt_seq;                         /* set once committed */
};

/* PLAN one action. Fills the request's `now_unix`/`height` from the clock
 * provider (ignoring whatever the caller put there — a caller must not be able
 * to choose the time an expiry is measured against), reads the catalog if one
 * is installed, and runs the full static-scope check.
 *
 * FAILS FAST: an action outside the grant's action set, a property outside its
 * scope, a counterparty outside the allowlist, a budget-exceeding value, an
 * expired or revoked grant — all are refused HERE, before any plan is stored.
 * Nothing is recorded on a refusal.
 *
 * A missing catalog is NOT fatal at plan time (`catalog_seen` is false and the
 * revision is recorded as -1); it is fatal at commit time. Planning is a
 * read-only quote, and refusing to even quote when the catalog is down would
 * hide the far more useful static-scope diagnostics. */
enum property_grant_reason property_grant_service_plan(
    const char *grant_id, const struct metaverse_action_request *req,
    struct property_grant_plan *out);

/* Copy a stored plan. PLAN_UNKNOWN when absent. */
enum property_grant_reason property_grant_service_plan_get(
    const char *plan_id, struct property_grant_plan *out);

/* ── COMMIT ─────────────────────────────────────────────────────────────── */

struct property_grant_commit_result {
    struct metaverse_receipt receipt;
    /* True when this call returned an ALREADY-STORED receipt for the same
     * (grant, idempotency_key). Nothing was charged and nothing was appended:
     * an idempotent retry is a lookup, not a second execution. */
    bool replayed;
    /* What this grant can still actually move: its own remaining cumulative
     * ceiling capped by every ancestor's, because a commit charges the whole
     * lineage. For a root grant the two are the same number; for a child,
     * reporting its own ceiling alone would quote a budget its parent will
     * refuse to fund. */
    int64_t budget_remaining_zat;
};

/* COMMIT the plan named by `plan_id`.
 *
 * `idempotency_key` may be NULL/"" — then the commit is NOT replay-protected
 * and a second call fails with PLAN_ALREADY_COMMITTED. When it is non-empty and
 * a receipt already exists for (this plan's grant, this key) RECORDING THE SAME
 * REQUEST, that receipt is returned verbatim with `replayed` set: same seq,
 * same hashes, no budget debit, no chain append.
 *
 * A key that already names a receipt for a DIFFERENT request (a different
 * action, property, value, counterparty or actor) is IDEMPOTENCY_KEY_REUSED
 * and nothing runs. Matching the key alone would return the earlier,
 * unrelated receipt with status OK, so the caller's actual request would never
 * execute and the answer would not say so.
 *
 * Every re-check listed at the top of this file runs before anything is
 * recorded, and the first one to fail names itself. On success the rate window
 * of the acting grant is updated, the cumulative spend of the acting grant AND
 * OF EVERY ANCESTOR rises by the value that moved, and one sealed receipt is
 * appended to that grant's chain. The lineage charge is all-or-none: an
 * ancestor that cannot pay makes the whole commit BUDGET_EXCEEDED with no
 * record moved and no receipt minted. */
enum property_grant_reason property_grant_service_commit(
    const char *plan_id, const char *idempotency_key,
    struct property_grant_commit_result *out);

/* ── RECEIPTS ───────────────────────────────────────────────────────────── */

/* Copy up to `max` receipts for `grant_id` ("" or NULL = every grant), in
 * ascending (grant, seq) order. Returns the count written. */
size_t property_grant_service_receipts(const char *grant_id,
                                       struct metaverse_receipt *out,
                                       size_t max);

/* Verify one grant's whole receipt chain as the store currently holds it:
 * body hashes, chain links, sequence, pinned signer, signatures. On failure
 * *out_bad_seq (when non-NULL) receives the 1-based seq of the first bad
 * receipt — a tamper report has to say where. */
enum metaverse_receipt_status property_grant_service_verify_chain(
    const char *grant_id, uint64_t *out_bad_seq);

/* TEST-ONLY tamper hook: overwrite the stored receipt at (grant, seq) with
 * `edited`, bypassing every seal. It exists so a test can prove the chain is
 * tamper-EVIDENT — there is no other way to produce a corrupted store without
 * mocking the store away and thereby proving nothing about the real one. It
 * refuses outside a ZCL_TESTING build. */
bool property_grant_service_test_overwrite_receipt(
    const char *grant_id, uint64_t seq,
    const struct metaverse_receipt *edited);

/* TEST-ONLY seal-failure hook. Runs at the ONE instant in a commit where the
 * grant record has already taken the action's effect (spend, rate window) and
 * no receipt exists yet — the window whose only exit is an exact restore.
 * Returning false makes the seal fail, which is otherwise unreachable: the real
 * sealer only fails on a NULL argument or a zero seq, neither of which a commit
 * can produce. Without it the rollback path is untestable, and an untestable
 * money path is where R2's two arithmetic defects lived unseen.
 *
 * The hook runs WITH the store mutex held (that is the invariant it exists to
 * probe — see property_grant_service_test_store_lock_busy), so it must not call
 * any entry point of this service that takes the lock. Cleared by
 * property_grant_service_reset(). Refuses outside a ZCL_TESTING build. */
typedef bool (*property_grant_test_seal_hook_fn)(void *ctx);
bool property_grant_service_test_set_seal_hook(
    property_grant_test_seal_hook_fn fn, void *ctx);

#endif /* ZCL_SERVICES_PROPERTY_GRANT_SERVICE_H */
