/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Property grant service, COMMIT half — the commit-time re-check, the receipt
 * chain append, and chain verification. Shares one lock and one store with
 * property_grant_service.c (property_grant_store.h).
 *
 * THE POINT OF THIS FILE: a commit trusts NOTHING from its plan except the
 * request it described and the property revision it observed. Ownership,
 * revocation (own and ancestral), budget, rate window, and expiry are all
 * re-read and re-decided here against current state, because every one of them
 * can change between plan and commit. See the public header.
 *
 * It is also where the CUMULATIVE ceiling stops being a per-grant number. The
 * pure rules hold one grant at a time and cannot see a parent's spending; this
 * file holds the store, so the charge that a committed action puts on the
 * whole lineage is applied here, all ancestors or none. */

// one-result-type-ok:grant-decision — the COMMIT half of the same service; see
// the same marker on property_grant_service.c. COMMIT returns
// `enum property_grant_reason` and chain verification returns
// `enum metaverse_receipt_status`; both are closed taxonomies whose tokens the
// tests assert exactly. The two bool exports are the ZCL_TESTING-only tamper
// hook and the ZCL_TESTING-only seal-failure hook, neither of which has an
// operator-facing failure to report.

#include "services/property_grant_service.h"

#include "base/log_macros.h"
#include "property_grant_store.h"

#include <stdio.h>
#include <string.h>

#define PGC_LOG "metaverse.grant_commit"

/* Lock held. The last receipt in `grant_id`'s chain, or NULL for an empty
 * chain. Scans backwards because the common case is "the newest one". */
static const struct metaverse_receipt *last_receipt(const char *grant_id)
{
    for (size_t i = g_pg_store.receipt_count; i > 0; i--) {
        const struct metaverse_receipt *r = &g_pg_store.receipts[i - 1];
        if (strcmp(r->grant_id, grant_id) == 0) return r;
    }
    return NULL;
}

/* True when a stored receipt records the SAME REQUEST the caller is making
 * now. These five fields are what make two calls one operation; the clock, the
 * height and the property revision are deliberately not compared, because
 * those are facts the earlier commit OBSERVED rather than anything the caller
 * asked for, and a retry one second later must still be a retry. */
static bool receipt_matches_request(const struct metaverse_receipt *r,
                                    const struct metaverse_action_request *req)
{
    return r->action == req->action && r->value_zat == req->value_zat &&
           metaverse_property_id_equal(&r->property, &req->property) &&
           strcmp(r->actor, req->actor) == 0 &&
           strcmp(r->counterparty, req->counterparty) == 0;
}

/* What a (grant, idempotency_key) lookup found. A key that matches a receipt
 * for a DIFFERENT request is its own answer and not a replay: handing back the
 * stored receipt would report OK for a request that never ran, and running the
 * new request would put two receipts under one key and destroy the only
 * guarantee the key exists to give. */
enum pg_replay_match {
    PG_REPLAY_NONE = 0,
    PG_REPLAY_SAME,
    PG_REPLAY_DIFFERENT,
};

/* Lock held. Find the stored receipt for (grant, idempotency_key) and say
 * whether it answers THIS request. An EMPTY key never matches: collapsing
 * every un-keyed commit onto one empty key would make the first un-keyed
 * action of a grant permanently replay the same receipt for every later one. */
static enum pg_replay_match receipt_by_key(
    const char *grant_id, const char *key,
    const struct metaverse_action_request *req,
    const struct metaverse_receipt **out)
{
    *out = NULL;
    if (!key || key[0] == '\0') return PG_REPLAY_NONE;
    for (size_t i = 0; i < g_pg_store.receipt_count; i++) {
        const struct metaverse_receipt *r = &g_pg_store.receipts[i];
        if (strcmp(r->grant_id, grant_id) != 0) continue;
        if (strcmp(r->idempotency_key, key) != 0) continue;
        *out = r;
        return receipt_matches_request(r, req) ? PG_REPLAY_SAME
                                               : PG_REPLAY_DIFFERENT;
    }
    return PG_REPLAY_NONE;
}

/* Lock held. What this grant can still actually move: its own remaining
 * ceiling capped by every ancestor's, because a commit charges the whole
 * lineage. Publishing the grant's own number alone would quote a child a
 * budget its parent will refuse to fund. A missing ancestor is not a budget
 * question — every decision path refuses on it first — but the number still
 * has to be safe to publish, and 0 is the only safe one. */
static int64_t effective_budget_remaining(const struct metaverse_grant *g)
{
    int64_t remaining = metaverse_grant_budget_remaining(g);
    for (size_t i = 0; i < g->lineage_count; i++) {
        const struct metaverse_grant *a = pg_find_grant(g->lineage[i].grant_id);
        if (!a) return 0;
        int64_t ancestor_remaining = metaverse_grant_budget_remaining(a);
        if (ancestor_remaining < remaining) remaining = ancestor_remaining;
    }
    return remaining;
}

/* Lock held. Number of receipts already in this grant's chain. */
static uint64_t chain_len(const char *grant_id)
{
    uint64_t n = 0;
    for (size_t i = 0; i < g_pg_store.receipt_count; i++) {
        if (strcmp(g_pg_store.receipts[i].grant_id, grant_id) == 0) n++;
    }
    return n;
}

/* One COMMIT attempt. Returns AUTHORITY_CHANGED when the store moved while the
 * catalog was being read outside the lock; property_grant_service_commit()
 * retries exactly once and then gives up rather than committing over a state
 * it cannot show was coherent. */
static enum property_grant_reason commit_attempt(
    const char *plan_id, const char *idempotency_key,
    struct property_grant_commit_result *out)
{
    int64_t now = 0, height = 0;
    pg_now(&now, &height);

    pthread_mutex_lock(&g_pg_store.lock);

    struct property_grant_plan *plan = pg_find_plan_locked(plan_id);
    if (!plan) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PGC_LOG, "commit: no plan %s", plan_id);
        return PROPERTY_GRANT_PLAN_UNKNOWN;
    }

    /* IDEMPOTENCY FIRST. A retry of an already-committed (grant, key) is a
     * LOOKUP, not a second execution: it must succeed, return the identical
     * receipt, and charge nothing. Checking this before the
     * already-committed/expired guards is what makes a retry after a lost
     * response work at all. */
    const struct metaverse_receipt *replay = NULL;
    enum pg_replay_match replay_match = receipt_by_key(
        plan->grant_id, idempotency_key, &plan->request, &replay);
    if (replay_match == PG_REPLAY_DIFFERENT) {
        /* Copied out: everything the message names lives in the store, and the
         * message is written after the unlock. */
        uint64_t seq = replay->seq;
        char reused_grant[METAVERSE_GRANT_ID_LEN + 1];
        snprintf(reused_grant, sizeof(reused_grant), "%s", plan->grant_id);
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PGC_LOG,
                 "commit: idempotency key on plan %s already names receipt %llu "
                 "of grant %s, and that receipt records a different request — "
                 "replaying it would report success for an action nobody "
                 "asked for, and running this one would put two receipts under "
                 "one key",
                 plan_id, (unsigned long long)seq, reused_grant);
        return PROPERTY_GRANT_IDEMPOTENCY_KEY_REUSED;
    }
    if (replay_match == PG_REPLAY_SAME) {
        out->receipt = *replay;
        out->replayed = true;
        const struct metaverse_grant *g = pg_find_grant(plan->grant_id);
        out->budget_remaining_zat = g ? effective_budget_remaining(g) : 0;
        pthread_mutex_unlock(&g_pg_store.lock);
        return PROPERTY_GRANT_OK;
    }

    if (plan->committed) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PGC_LOG, "commit: plan %s already committed (seq %llu)",
                 plan_id, (unsigned long long)plan->receipt_seq);
        return PROPERTY_GRANT_PLAN_ALREADY_COMMITTED;
    }
    if (now >= plan->expires_unix) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PGC_LOG, "commit: plan %s expired at %lld, now %lld", plan_id,
                 (long long)plan->expires_unix, (long long)now);
        return PROPERTY_GRANT_PLAN_EXPIRED;
    }

    /* ── Re-check 1: the grant record AS IT IS NOW ──────────────────────── */
    struct metaverse_grant *g = pg_find_grant(plan->grant_id);
    if (!g) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PGC_LOG, "commit: grant %s no longer in the store",
                 plan->grant_id);
        return PROPERTY_GRANT_GRANT_UNKNOWN;
    }

    /* ── Re-check 2: current ownership and revision from the catalog ──────
     *
     * THE LOOKUP RUNS WITH NO LOCK HELD. The real catalog rebuilds every view
     * from datadir bytes on every call, and doing that inside the store mutex
     * would stall every other grant decision in the process behind a disk
     * read. So: copy what the lookup needs, RELEASE, look up, RE-ACQUIRE, and
     * confirm the store-wide authority generation did not move. Everything
     * after the re-acquire re-reads the store fresh, exactly as before. */
    metaverse_catalog_lookup_fn lookup = g_pg_store.env.catalog_lookup;
    void *lookup_ctx = g_pg_store.env.catalog_ctx;
    if (!lookup) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PGC_LOG,
                 "commit: no property catalog installed — refusing to commit "
                 "an action whose current ownership cannot be confirmed");
        return PROPERTY_GRANT_CATALOG_UNAVAILABLE;
    }
    struct metaverse_property_id target = plan->request.property;
    uint64_t seen_generation = g_pg_store.authority_generation;
    pthread_mutex_unlock(&g_pg_store.lock);

    struct metaverse_catalog_view view;
    memset(&view, 0, sizeof(view));
    bool found = lookup(&target, &view, lookup_ctx);

    pthread_mutex_lock(&g_pg_store.lock);
    if (g_pg_store.authority_generation != seen_generation) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PGC_LOG,
                 "commit: the store moved while reading the catalog for plan "
                 "%s — retrying", plan_id);
        return PROPERTY_GRANT_AUTHORITY_CHANGED;
    }
    /* The generation is unchanged, so nothing was minted, delegated, revoked,
     * debited or reset; plan and grant are the same records. Re-resolve the
     * pointers anyway — the arrays are addressed by index and a pointer held
     * across an unlock is a habit worth not having. */
    plan = pg_find_plan_locked(plan_id);
    g = plan ? pg_find_grant(plan->grant_id) : NULL;
    if (!plan || !g) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_ERROR(PGC_LOG,
                  "commit: plan or grant vanished at an unchanged authority "
                  "generation (plan %s)", plan_id);
        return PROPERTY_GRANT_AUTHORITY_CHANGED;
    }
    if (!found) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PGC_LOG, "commit: property not in the catalog (plan %s)",
                 plan_id);
        return PROPERTY_GRANT_PROPERTY_UNKNOWN;
    }
    /* The controlling principal must be the one the plan was quoted against.
     * A property that changed hands between plan and commit is a different
     * authority situation, and silently committing under the new owner is
     * exactly the confused-deputy the re-check exists to stop. */
    if (plan->catalog_seen &&
        strcmp(view.controller, plan->controller_at_plan) != 0) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PGC_LOG, "commit: controller changed since plan %s", plan_id);
        return PROPERTY_GRANT_OWNER_MISMATCH;
    }
    /* ── Re-check 3: OPTIMISTIC CONCURRENCY on the property revision ────── */
    if (!plan->catalog_seen || view.revision != plan->property_revision) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PGC_LOG,
                 "commit: stale revision — plan %s saw %lld, catalog now %lld",
                 plan_id, (long long)plan->property_revision,
                 (long long)view.revision);
        return PROPERTY_GRANT_STALE_REVISION;
    }

    /* ── Re-check 4: the FULL capability check, run fresh ───────────────── */
    struct metaverse_action_request req = plan->request;
    req.now_unix = now;
    req.height = height;

    const struct metaverse_grant *anc[METAVERSE_GRANT_MAX_DEPTH];
    size_t anc_count = 0;
    const struct metaverse_grant *const *anc_arg = NULL;
    if (g->lineage_count > 0) {
        if (!pg_collect_ancestors(g, anc, &anc_count)) {
            pthread_mutex_unlock(&g_pg_store.lock);
            LOG_WARN(PGC_LOG, "commit: grant %s has a missing ancestor",
                     g->grant_id);
            return PROPERTY_GRANT_ANCESTOR_REVOKED;
        }
        anc_arg = anc;
    }

    enum metaverse_grant_verdict v =
        metaverse_grant_check(g, anc_arg, anc_count, &req);
    if (v != METAVERSE_GRANT_OK) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PGC_LOG, "commit: grant %s refused at commit time (%s)",
                 g->grant_id, metaverse_grant_verdict_token(v));
        return property_grant_reason_from_verdict(v);
    }

    /* ── Everything passed. Record the effect, then seal a receipt. ─────── */
    if (g_pg_store.receipt_count >= PROPERTY_GRANT_MAX_RECEIPTS) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_ERROR(PGC_LOG, "commit: receipt store full (cap %d)",
                  PROPERTY_GRANT_MAX_RECEIPTS);
        return PROPERTY_GRANT_STORE_FULL;
    }
    if (!pg_ensure_key()) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_ERROR(PGC_LOG, "commit: no receipt signing key available");
        return PROPERTY_GRANT_SIGNING_KEY_UNAVAILABLE;
    }

    /* ── THE LINEAGE, RESOLVED AND COPIED BEFORE ANYTHING MOVES ─────────────
     *
     * max_value_zat is a ceiling on everything that moves BENEATH a grant, and
     * a delegated child is beneath its parent, so this commit charges every
     * ancestor as well and is refused unless all of them can pay. Attenuation
     * at delegation time cannot supply that bound — two children each declaring
     * the parent's full remaining budget are each a legal attenuation, and
     * twice the ceiling then moves — and reserving a child's DECLARED maximum
     * at delegation time would be the opposite defect, charging the operator
     * for money the child may never spend and making the revocation of an
     * unused child a refund.
     *
     * DELIBERATELY ABOVE the mutate-and-restore window that begins on the next
     * statement: resolving and copying the ancestors moves nothing, so the one
     * refusal here needs no restore and must not sit inside a region whose
     * every exit is required to have one. The lineage is at most
     * METAVERSE_GRANT_MAX_DEPTH long, so this is a bounded copy under a lock
     * that is already held.
     *
     * The records are re-resolved rather than reusing `anc`, whose element type
     * is const: pg_collect_ancestors above has already proven every one of them
     * is present, so the refusal here is a fail-closed backstop, not an
     * expected path. */
    struct metaverse_grant *lineage[METAVERSE_GRANT_MAX_DEPTH];
    struct metaverse_grant lineage_before[METAVERSE_GRANT_MAX_DEPTH];
    for (size_t i = 0; i < anc_count; i++) {
        lineage[i] = pg_find_grant(g->lineage[i].grant_id);
        if (!lineage[i]) {
            char missing[METAVERSE_GRANT_ID_LEN + 1];
            char acting[METAVERSE_GRANT_ID_LEN + 1];
            snprintf(missing, sizeof(missing), "%s", g->lineage[i].grant_id);
            snprintf(acting, sizeof(acting), "%s", g->grant_id);
            pthread_mutex_unlock(&g_pg_store.lock);
            LOG_ERROR(PGC_LOG,
                      "commit: ancestor %s of grant %s vanished between the "
                      "capability check and the debit",
                      missing, acting);
            return PROPERTY_GRANT_ANCESTOR_REVOKED;
        }
        lineage_before[i] = *lineage[i];
    }

    /* ── THE WHOLE RECORD, BEFORE THE EFFECT ────────────────────────────────
     *
     * Everything from here to the receipt append either produces evidence or
     * puts this record back exactly as it was. The restore is a whole-record
     * copy and NOT a hand-written "give the debit back", because the charge
     * rule does not live here: metaverse_grant_record_commit() bills only a
     * value that MOVES (a quoted asking price is not exposure) and may roll the
     * rate window forward before it counts. A compensating action written out
     * by hand is a second copy of that rule that has to be kept in step with
     * it, and it was not — it credited value that had never been charged, which
     * drove spent_zat negative and WIDENED the operator's ceiling on a failed
     * commit, and it never put back a rolled window_start_unix. A whole-record
     * restore is the exact inverse of any effect record_commit can have, this
     * one and every one added later, and cannot drift from the charge rule
     * because it does not restate it.
     *
     * The same is true one record over: once the lineage charge below has run,
     * every ancestor has moved too, and each of them is restored from its own
     * whole-record copy on every exit that mints no receipt.
     *
     * LOCK INVARIANT, and the whole-record restore depends on it: the mutation
     * and the restore are both inside ONE contiguous hold of g_pg_store.lock —
     * taken at the catalog re-acquire above and released only by a return path
     * below. In between the record HAS moved, so a snapshot taken inside that
     * window and rechecked after the restore would see an unchanged generation
     * and revalidate over values it never observed. No such snapshot can be
     * taken: property_grant_service_snapshot() takes the same mutex. */
    const struct metaverse_grant grant_before_effect = *g;

    if (!metaverse_grant_record_commit(g, &req)) {
        /* It can refuse AFTER having already rolled the rate window, so the
         * restore is not optional on this path either. */
        *g = grant_before_effect;
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_ERROR(PGC_LOG,
                  "commit: grant %s passed the check but rejected the debit",
                  g->grant_id);
        return PROPERTY_GRANT_BUDGET_EXCEEDED;
    }

    for (size_t i = 0; i < anc_count; i++) {
        if (metaverse_grant_record_descendant_charge(lineage[i], &req))
            continue;
        for (size_t j = 0; j < i; j++) *lineage[j] = lineage_before[j];
        *g = grant_before_effect;
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PGC_LOG,
                 "commit: grant %s may spend this, but its ancestor %s cannot "
                 "— the cumulative ceiling binds the whole delegation subtree",
                 grant_before_effect.grant_id, lineage_before[i].grant_id);
        return PROPERTY_GRANT_BUDGET_EXCEEDED;
    }

    struct metaverse_receipt r;
    memset(&r, 0, sizeof(r));
    r.seq = chain_len(g->grant_id) + 1u;
    snprintf(r.grant_id, sizeof(r.grant_id), "%s", g->grant_id);
    snprintf(r.actor, sizeof(r.actor), "%s", req.actor);
    snprintf(r.counterparty, sizeof(r.counterparty), "%s", req.counterparty);
    if (idempotency_key)
        snprintf(r.idempotency_key, sizeof(r.idempotency_key), "%s",
                 idempotency_key);
    r.property = req.property;
    r.action = req.action;
    r.value_zat = req.value_zat;
    r.property_revision = view.revision;
    r.height = height;
    r.unix_time = now;
    r.grant_spent_after_zat = g->spent_zat;

    const struct metaverse_receipt *prev = last_receipt(g->grant_id);
    bool sealed = metaverse_receipt_seal(&r, prev ? prev->chain_hash : NULL,
                                         g_pg_store.sk, g_pg_store.pk);
#ifdef ZCL_TESTING
    /* The one point where a test can make the seal fail. See the hook's
     * declaration: the real sealer cannot fail here, so without this the
     * restore below has no test and the arithmetic that used to live in it went
     * two defects deep before anyone looked. */
    if (sealed && g_pg_store.seal_hook)
        sealed = g_pg_store.seal_hook(g_pg_store.seal_hook_ctx);
#endif
    if (!sealed) {
        /* No evidence, so no effect. The restore is byte-exact, which is why
         * this path does NOT bump the authority generation: the record is
         * genuinely unmutated, the receipt array is untouched, and the plan is
         * still uncommitted, so there is nothing for a reader to have missed.
         * A bump here would be the opposite defect — telling every in-flight
         * decision the world moved when it did not.
         *
         * The lineage is restored with it: by here every ancestor has taken
         * this action's charge, and leaving any of them debited for a commit
         * that minted no receipt is the same defect one record over. */
        *g = grant_before_effect;
        for (size_t i = 0; i < anc_count; i++) *lineage[i] = lineage_before[i];
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_ERROR(PGC_LOG, "commit: could not seal receipt for grant %s",
                  g->grant_id);
        return PROPERTY_GRANT_RECEIPT_SEAL_FAILED;
    }

    g_pg_store.receipts[g_pg_store.receipt_count++] = r;
    plan->committed = true;
    plan->receipt_seq = r.seq;

    out->receipt = r;
    out->replayed = false;
    out->budget_remaining_zat = effective_budget_remaining(g);
    /* The budget debit above is a mutation of the authority, so it moves the
     * store-wide generation: a decision computed over the pre-debit budget is
     * no longer a decision over current state. */
    pg_bump_authority();
    pthread_mutex_unlock(&g_pg_store.lock);
    return PROPERTY_GRANT_OK;
}

enum property_grant_reason property_grant_service_commit(
    const char *plan_id, const char *idempotency_key,
    struct property_grant_commit_result *out)
{
    if (!plan_id || !out) {
        LOG_ERROR(PGC_LOG, "commit: NULL plan id or output");
        return PROPERTY_GRANT_BAD_ARGS;
    }
    memset(out, 0, sizeof(*out));
    enum property_grant_reason r =
        commit_attempt(plan_id, idempotency_key, out);
    if (r == PROPERTY_GRANT_AUTHORITY_CHANGED) {
        memset(out, 0, sizeof(*out));
        r = commit_attempt(plan_id, idempotency_key, out);  /* ONE retry */
    }
    return r;
}

size_t property_grant_service_receipts(const char *grant_id,
                                       struct metaverse_receipt *out,
                                       size_t max)
{
    if (!out || max == 0) return 0;
    bool all = (!grant_id || grant_id[0] == '\0');
    size_t n = 0;
    pthread_mutex_lock(&g_pg_store.lock);
    for (size_t i = 0; i < g_pg_store.receipt_count && n < max; i++) {
        if (!all && strcmp(g_pg_store.receipts[i].grant_id, grant_id) != 0)
            continue;
        out[n++] = g_pg_store.receipts[i];
    }
    pthread_mutex_unlock(&g_pg_store.lock);
    return n;
}

enum metaverse_receipt_status property_grant_service_verify_chain(
    const char *grant_id, uint64_t *out_bad_seq)
{
    if (out_bad_seq) *out_bad_seq = 0;
    if (!grant_id || grant_id[0] == '\0') return METAVERSE_RECEIPT_BAD_ARGS;

    /* Walked IN PLACE under the lock. Copying the chain out first would put
     * ~350 KB on the stack and would verify a snapshot rather than the store. */
    pthread_mutex_lock(&g_pg_store.lock);

    uint8_t prev[METAVERSE_HASH_LEN];
    memset(prev, 0, sizeof(prev));
    uint64_t expect_seq = 1;
    enum metaverse_receipt_status status = METAVERSE_RECEIPT_OK;
    uint64_t bad_seq = 0;

    for (size_t i = 0; i < g_pg_store.receipt_count; i++) {
        const struct metaverse_receipt *r = &g_pg_store.receipts[i];
        if (strcmp(r->grant_id, grant_id) != 0) continue;

        if (!g_pg_store.key_set) {
            status = METAVERSE_RECEIPT_SIGNER_UNEXPECTED;
            bad_seq = r->seq;
            break;
        }
        if (r->seq != expect_seq) {
            status = METAVERSE_RECEIPT_SEQ_OUT_OF_ORDER;
            bad_seq = expect_seq;
            break;
        }
        if (memcmp(r->prev_chain_hash, prev, METAVERSE_HASH_LEN) != 0) {
            status = METAVERSE_RECEIPT_CHAIN_BROKEN;
            bad_seq = r->seq;
            break;
        }
        status = metaverse_receipt_verify(r, g_pg_store.pk);
        if (status != METAVERSE_RECEIPT_OK) {
            bad_seq = r->seq;
            break;
        }
        memcpy(prev, r->chain_hash, METAVERSE_HASH_LEN);
        expect_seq++;
    }

    pthread_mutex_unlock(&g_pg_store.lock);
    if (status != METAVERSE_RECEIPT_OK && out_bad_seq) *out_bad_seq = bad_seq;
    return status;
}

bool property_grant_service_test_set_seal_hook(
    property_grant_test_seal_hook_fn fn, void *ctx)
{
#ifndef ZCL_TESTING
    (void)fn; (void)ctx;
    LOG_FAIL(PGC_LOG, "the seal-failure hook is a test-only hook and this is "
                      "not a ZCL_TESTING build");
#else
    pthread_mutex_lock(&g_pg_store.lock);
    g_pg_store.seal_hook = fn;
    g_pg_store.seal_hook_ctx = ctx;
    pthread_mutex_unlock(&g_pg_store.lock);
    return true;
#endif
}

bool property_grant_service_test_overwrite_receipt(
    const char *grant_id, uint64_t seq, const struct metaverse_receipt *edited)
{
#ifndef ZCL_TESTING
    (void)grant_id; (void)seq; (void)edited;
    LOG_FAIL(PGC_LOG, "receipt overwrite is a test-only hook and this is not a "
                      "ZCL_TESTING build");
#else
    if (!grant_id || !edited || seq == 0)
        LOG_FAIL(PGC_LOG, "receipt overwrite: bad arguments");
    /* DELIBERATELY NO AUTHORITY BUMP. This hook exists to forge a store that
     * looks untouched, so announcing the edit would defeat the tamper-evidence
     * proof: the chain verifier has to catch it from the hashes alone. */
    bool found = false;
    pthread_mutex_lock(&g_pg_store.lock);
    for (size_t i = 0; i < g_pg_store.receipt_count; i++) {
        struct metaverse_receipt *r = &g_pg_store.receipts[i];
        if (strcmp(r->grant_id, grant_id) != 0 || r->seq != seq) continue;
        *r = *edited;
        found = true;
        break;
    }
    pthread_mutex_unlock(&g_pg_store.lock);
    if (!found)
        LOG_FAIL(PGC_LOG, "receipt overwrite: no receipt %s seq %llu", grant_id,
                 (unsigned long long)seq);
    return true;
#endif
}
