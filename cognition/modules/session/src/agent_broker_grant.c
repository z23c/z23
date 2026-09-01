/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The broker's grant evaluator — a TRANSLATOR, not an authority.
 *
 * WHAT THIS FILE USED TO DO AND NO LONGER DOES. It kept three local tables:
 * verb_has_counterparty(), verb_carries_value(), and an actions_mask built as
 * `1u << verb` over the wire enum. Those were private answers to questions the
 * metaverse already answers — which actions move value, which name a
 * counterparty, what an action's persisted bit is — and the two answers had
 * drifted: TRANSFER moved value on the metaverse side and was free here, so
 * the same transfer debited the operator's cumulative budget or did not,
 * depending on which side you asked. All three are DELETED. The mask is now
 * the canonical metaverse_action_set, and every predicate over an action is
 * asked of metaverse_grant_check().
 *
 * WHAT REMAINS HERE, AND WHY IT IS NOT A SECOND AUTHORITY. The broker still
 * enforces confinement rules that are about THIS SESSION rather than about the
 * action vocabulary:
 *
 *   - property-id ∩ kind scope. A broker grant is scoped to an explicit set of
 *     32-byte ids AND a kind mask, intersected. A canonical grant is scoped to
 *     ids OR kinds, never both (metaverse/property_grant.h explains why the
 *     "both" shape is dangerous for an operator writing one). An intersection
 *     cannot be expressed in that form, so the broker evaluates it and the
 *     canonical grant is projected with a wildcard kind scope. This is a
 *     NARROWING the broker adds on top of the canonical verdict, never a
 *     widening: nothing here can allow what the metaverse refused.
 *   - the per-action value ceiling. Canonical `max_value_zat` is CUMULATIVE by
 *     design; `max_value_zats` here is a per-action cap the confinement layer
 *     adds beneath it. Both are enforced, and the cumulative one is the
 *     metaverse's.
 *   - delegation permission, which needs a child grant the wire cannot carry.
 *
 * agent_grant_authorize() is still PURE — it debits nothing — so the broker can
 * call it twice (once on the agent's claimed kind, once on the catalog's
 * authoritative kind) and get the same answer for the same inputs.
 */

#include "session/agent_broker.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "session/agent_broker_vocab.h"

#include <stdio.h>
#include <string.h>

#define GRANT_TAG "agent.grant"

/* ── building a grant ───────────────────────────────────────────────────── */

void agent_grant_allow_action(struct agent_grant *g, uint32_t verb)
{
    if (!g)
        return;
    const struct mvap_verb_row *row = mvap_verb_row(verb);
    if (!row)
        return;
    /* A query left the canonical action space, so it cannot occupy a canonical
     * action bit; it gets its own mask keyed by wire value. An action takes the
     * canonical bit and nothing else — no `1u << verb`. The accessor refuses a
     * query row outright, so the two masks cannot be filled from one another. */
    enum metaverse_action action;
    if (mvap_verb_row_action(row, &action))
        g->actions_mask |= metaverse_action_bit(action);
    else if (row->verb_class == MVAP_VERB_CLASS_QUERY)
        g->queries_mask |= (uint32_t)1u << verb;
}

void agent_grant_allow_kind(struct agent_grant *g, uint16_t kind)
{
    if (!g || kind >= MVAP_KIND__COUNT)
        return;
    g->kinds_mask |= (uint32_t)1u << kind;
}

bool agent_grant_add_property(struct agent_grant *g,
                              const uint8_t id[MVAP_PROPERTY_ID_LEN])
{
    if (!g || !id)
        LOG_FAIL(GRANT_TAG, "null argument g=%p id=%p", (void *)g,
                 (const void *)id);
    if (g->n_properties >= AGENT_GRANT_MAX_PROPS)
        LOG_FAIL(GRANT_TAG, "grant %s already holds the maximum %d properties",
                 g->grant_id, AGENT_GRANT_MAX_PROPS);
    memcpy(g->properties[g->n_properties], id, MVAP_PROPERTY_ID_LEN);
    g->n_properties++;
    return true;
}

/* ── the session narrowing ──────────────────────────────────────────────── */

void agent_broker_scope_from_grant(const struct agent_grant *g,
                                   struct agent_broker_scope *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!g)
        return;
    /* Copied, not re-derived. The narrowing a session enforces is exactly the
     * one the bound grant carries; there is no second place where an operator
     * could write a different answer and no arithmetic in between. */
    size_t n = g->n_properties > AGENT_GRANT_MAX_PROPS ? AGENT_GRANT_MAX_PROPS
                                                       : g->n_properties;
    for (size_t i = 0; i < n; i++)
        memcpy(out->properties[i], g->properties[i], MVAP_PROPERTY_ID_LEN);
    out->n_properties   = n;
    out->kinds_mask     = g->kinds_mask;
    out->max_value_zats = g->max_value_zats;
}

int32_t agent_broker_scope_check(const struct agent_broker_scope *sc,
                                 const struct mvap_request *req)
{
    if (!sc || !req)
        return MVAP_ERR_INTERNAL;
    const struct mvap_verb_row *row = mvap_verb_row(req->verb);
    if (!row)
        return MVAP_ERR_UNKNOWN_VERB;

    if (mvap_property_id_is_zero(req->property_id)) {
        if (!row->allows_zero_property_id)
            return MVAP_ERR_DENIED_PROPERTY;
    } else if (sc->n_properties > 0) {
        bool hit = false;
        for (size_t i = 0; i < sc->n_properties && !hit; i++)
            hit = memcmp(sc->properties[i], req->property_id,
                         MVAP_PROPERTY_ID_LEN) == 0;
        if (!hit)
            return MVAP_ERR_DENIED_PROPERTY;
    }

    /* Kind scope. Checked whenever the request names a kind; the broker calls
     * this a second time with the catalog's authoritative kind so a request
     * that understated its kind is caught before COMMIT. */
    if (req->kind != MVAP_KIND_ANY &&
        (sc->kinds_mask & ((uint32_t)1u << req->kind)) == 0)
        return MVAP_ERR_DENIED_KIND;

    /* The per-action ceiling beneath the canonical cumulative budget. */
    if (req->value_zats > 0 && req->value_zats > sc->max_value_zats)
        return MVAP_ERR_DENIED_VALUE;

    return MVAP_OK;
}

/* Canonical scope digest. Deliberately EXCLUDES the mutable counters
 * (spent_zats, window_used, window_start_ms) so the fingerprint identifies the
 * grant's AUTHORITY, not its usage — an operator comparing two status dumps
 * wants "same grant" to survive normal spending. */
void agent_grant_fingerprint(const struct agent_grant *g, uint8_t out[32])
{
    if (!out)
        return;
    memset(out, 0, 32);
    if (!g)
        return;

    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)"zcl.agent_grant.v1", 18);
    sha3_256_write(&c, (const unsigned char *)g->grant_id,
                   strnlen(g->grant_id, AGENT_GRANT_ID_MAX));
    sha3_256_write(&c, (const unsigned char *)g->principal,
                   strnlen(g->principal, AGENT_PRINCIPAL_MAX));
    for (size_t i = 0; i < g->n_properties; i++)
        sha3_256_write(&c, g->properties[i], MVAP_PROPERTY_ID_LEN);

    uint8_t nums[9][8];
    uint64_t vals[9] = {
        (uint64_t)g->kinds_mask, (uint64_t)g->actions_mask,
        (uint64_t)g->queries_mask,
        g->max_value_zats, g->budget_zats,
        (uint64_t)g->expires_unix_ms, (uint64_t)g->rate_limit,
        (uint64_t)g->window_seconds, g->revocation_generation,
    };
    for (size_t i = 0; i < 9; i++)
        zcl_write_u64_le(nums[i], vals[i]);
    sha3_256_write(&c, (const unsigned char *)nums, sizeof(nums));

    sha3_256_write(&c, (const unsigned char *)g->counterparty_allowlist,
                   strnlen(g->counterparty_allowlist, AGENT_ALLOWLIST_MAX));
    unsigned char flags[3] = { (unsigned char)g->may_delegate,
                               (unsigned char)g->max_delegation_depth,
                               (unsigned char)g->revoked };
    sha3_256_write(&c, flags, sizeof(flags));
    sha3_256_finalize(&c, out);
}

/* ── projection onto the canonical grant record ─────────────────────────── */

/* A canonical grant id is exactly METAVERSE_GRANT_ID_LEN hex chars. A broker
 * grant id is an operator-chosen label of any length, so the projection
 * derives a stable canonical id from it rather than truncating or padding —
 * two different broker grants must never project onto one canonical id. */
_Static_assert(METAVERSE_GRANT_ID_LEN % 2 == 0 &&
                   METAVERSE_GRANT_ID_LEN / 2 <= 32,
               "the canonical grant id must be an even number of hex chars "
               "that a SHA3-256 digest can fill");
static void project_grant_id(const struct agent_grant *g,
                             char out[METAVERSE_GRANT_ID_LEN + 1])
{
    struct sha3_256_ctx c;
    uint8_t d[32];
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)"zcl.agent_grant.canonical_id",
                   28);
    sha3_256_write(&c, (const unsigned char *)g->grant_id,
                   strnlen(g->grant_id, AGENT_GRANT_ID_MAX));
    sha3_256_write(&c, (const unsigned char *)g->principal,
                   strnlen(g->principal, AGENT_PRINCIPAL_MAX));
    sha3_256_finalize(&c, d);
    zcl_hex_encode(d, METAVERSE_GRANT_ID_LEN / 2, out);
}

/* Split the broker's space-separated allowlist into the canonical array.
 * Returns false when the list holds more entries than a canonical grant can
 * carry — refusing is the fail-closed answer, because keeping the first eight
 * would silently narrow an allowlist the operator believed they had written
 * (and a caller that treated that as "allowed" would be widening it). */
static bool project_counterparties(const char *list, struct metaverse_grant *mg)
{
    mg->counterparty_count = 0;
    if (!list || !list[0])
        return true;                    /* empty list == any counterparty */
    const char *p = list;
    while (*p) {
        while (*p == ' ')
            p++;
        if (!*p)
            break;
        const char *start = p;
        while (*p && *p != ' ')
            p++;
        size_t len = (size_t)(p - start);
        if (mg->counterparty_count >= METAVERSE_GRANT_COUNTERPARTIES_MAX)
            return false;
        if (len > METAVERSE_PRINCIPAL_MAX)
            return false;
        memcpy(mg->counterparties[mg->counterparty_count], start, len);
        mg->counterparties[mg->counterparty_count][len] = '\0';
        mg->counterparty_count++;
    }
    return true;
}

/* Every kind, so the canonical scope check never fires. The broker evaluates
 * the id ∩ kind intersection itself (see the header note) and adds it to the
 * canonical verdict; a wildcard here means the canonical answer covers
 * everything EXCEPT scope, with no overlap and no second opinion. */
static metaverse_kind_set all_real_kinds(void)
{
    metaverse_kind_set s = 0;
    for (int k = METAVERSE_KIND_UNKNOWN + 1; k < METAVERSE_KIND_COUNT; k++)
        s |= metaverse_kind_bit((enum metaverse_kind)k);
    return s;
}

/* Project the broker's session grant onto the canonical record.
 *
 * TIME IS IN MILLISECONDS ON BOTH SIDES. The canonical record's time fields
 * are plain int64 quantities compared against each other (`now - window_start
 * >= window`, `now >= expires`), so the projection carries the broker's
 * millisecond clock through consistently rather than rounding to seconds and
 * moving an expiry by up to a second.
 *
 * Returns false only when the grant cannot be represented at all; the caller
 * turns that into a named refusal. */
static bool project_grant(const struct agent_grant *g,
                          const struct mvap_verb_row *row,
                          struct metaverse_grant *mg)
{
    memset(mg, 0, sizeof(*mg));
    project_grant_id(g, mg->grant_id);
    snprintf(mg->holder, sizeof(mg->holder), "%s", g->principal);
    snprintf(mg->issuer, sizeof(mg->issuer), "%s", g->principal);

    mg->depth = 0;
    mg->lineage_count = 0;
    mg->delegation_allowed = g->may_delegate;
    mg->max_delegation_depth =
        g->max_delegation_depth > METAVERSE_GRANT_MAX_DEPTH
            ? (uint32_t)METAVERSE_GRANT_MAX_DEPTH
            : g->max_delegation_depth;

    mg->scope_form = METAVERSE_SCOPE_KINDS;
    mg->kinds = all_real_kinds();

    /* Read rights and act rights are two separate closed sets on a canonical
     * grant, never one word. A query is ruled on by metaverse_grant_query_check
     * against `queries`; an action by metaverse_grant_check against `actions`.
     * Projecting a query onto the reserved INSPECT bit would not work even if
     * it were tempting: that bit is not a member of METAVERSE_ACTION_ALL, so
     * metaverse_grant_well_formed() rejects the whole record as MALFORMED. */
    if (row->verb_class == MVAP_VERB_CLASS_QUERY) {
        mg->actions = 0u;
        mg->queries = 0u;
        for (uint32_t w = 0; w < 32u; w++) {
            if ((g->queries_mask & ((uint32_t)1u << w)) == 0u)
                continue;
            /* Through the join, so a wire value that is not a QUERY verb
             * contributes no read right however the mask came to hold it. */
            enum metaverse_query q;
            if (mvap_verb_to_query(w, &q) && q != METAVERSE_QUERY_NONE)
                mg->queries |= (metaverse_query_set)q;
        }
    } else {
        mg->actions = g->actions_mask;
        mg->queries = 0u;
    }

    if (g->budget_zats > (uint64_t)INT64_MAX ||
        g->spent_zats > (uint64_t)INT64_MAX)
        return false;
    mg->max_value_zat = (int64_t)g->budget_zats;
    mg->spent_zat     = (int64_t)g->spent_zats;
    if (mg->spent_zat > mg->max_value_zat)
        return false;

    /* An allowlist constrains WHO the counterparty may be. An action that has
     * no counterparty is not constrained by it — projecting the list onto a
     * HOST would refuse it for naming nobody, which is not what an operator
     * writing "sell only to buyer-one" meant. Whether the action has one is
     * the canonical column, asked once here and once in the request
     * projection, never decided locally.
     *
     * A QUERY names no counterparty at all, so the accessor refuses and the
     * question is never asked. It used to be asked with the reserved INSPECT
     * bit standing in for a query's "action". */
    enum metaverse_action action;
    if (mvap_verb_row_action(row, &action) &&
        metaverse_action_uses_counterparty(action) &&
        !project_counterparties(g->counterparty_allowlist, mg))
        return false;

    /* A query is not an action and does not consume the action rate window. */
    if (row->verb_class == MVAP_VERB_CLASS_ACTION && g->rate_limit > 0 &&
        g->window_seconds > 0) {
        mg->rate_limit = g->rate_limit;
        mg->rate_window_seconds = (int64_t)g->window_seconds * 1000;
        mg->window_start_unix = g->window_start_ms;
        mg->window_used = g->window_used;
    }

    mg->expires_unix = g->expires_unix_ms > 0 ? g->expires_unix_ms : 0;
    mg->expires_height = 0;
    mg->revocation_generation = (uint32_t)g->revocation_generation;
    mg->revoked = g->revoked;
    return true;
}

/* ── the decision ───────────────────────────────────────────────────────── */

int32_t agent_grant_authorize(const struct agent_grant *g,
                              const struct mvap_request *req, int64_t now_ms)
{
    if (!g || !req)
        return MVAP_ERR_INTERNAL;
    /* "No grant installed" and "a grant with nobody to act for" are session
     * facts, not vocabulary: a canonical grant cannot even be built without
     * them, so they fail closed here. */
    if (!g->grant_id[0] || !g->principal[0])
        return MVAP_ERR_DENIED_NO_GRANT;

    const struct mvap_verb_row *row = mvap_verb_row(req->verb);
    if (!row)
        return MVAP_ERR_UNKNOWN_VERB;

    struct metaverse_grant mg;
    if (!project_grant(g, row, &mg))
        return MVAP_ERR_INTERNAL;

    /* 1. THE CANONICAL VERDICT. Revocation, expiry, holder, whether the
     *    operation is granted, whether the counterparty is allowed, whether it
     *    may carry value at all, the cumulative budget, and the rate window —
     *    all of it decided by the metaverse, none of it restated here.
     *
     *    A QUERY and an ACTION are two different questions and go to two
     *    different canonical evaluators. Routing a query through the action
     *    evaluator is not merely untidy: a query names no action, so the
     *    action evaluator can only answer BAD_ARGS, and every read would be
     *    refused. */
    enum metaverse_grant_verdict verdict;
    if (row->verb_class == MVAP_VERB_CLASS_QUERY) {
        /* A query has no value column at all, so a canonical query request has
         * nowhere to carry one and the evaluator can never see it. Refusing
         * here is reading the canonical class, not inventing a local policy:
         * silently dropping the amount would let a caller believe it had paid
         * for a read. */
        if (req->value_zats != 0)
            return MVAP_ERR_BAD_REQUEST;
        struct metaverse_query_request qreq;
        if (!mvap_request_to_query_request(req, g->principal, now_ms, 0, &qreq))
            return MVAP_ERR_BAD_REQUEST;
        verdict = metaverse_grant_query_check(&mg, NULL, 0, &qreq);
    } else {
        struct metaverse_action_request mreq;
        if (!mvap_request_to_action_request(req, g->principal, now_ms, 0,
                                            &mreq))
            return MVAP_ERR_BAD_REQUEST;
        verdict = metaverse_grant_check(&mg, NULL, 0, &mreq);
    }
    if (verdict != METAVERSE_GRANT_OK)
        return mvap_status_from_grant_verdict(verdict);

    /* 2. CONFINEMENT NARROWING. Everything below can only refuse. It runs
     *    through agent_broker_scope_check(), the SAME function a broker
     *    session applies to a live-authority verdict, so the confinement layer
     *    has one implementation and not two that can disagree. */
    struct agent_broker_scope sc;
    agent_broker_scope_from_grant(g, &sc);
    int32_t narrowed = agent_broker_scope_check(&sc, req);
    if (narrowed != MVAP_OK)
        return narrowed;

    /* Delegation needs a child grant, which the wire cannot carry, so
     * metaverse_grant_check_delegation() cannot be reached from here. What the
     * broker can still refuse is a DELEGATE attempted under a grant that
     * forbids delegating at all. */
    enum metaverse_action action;
    if (mvap_verb_row_action(row, &action) &&
        action == METAVERSE_ACTION_DELEGATE &&
        (!g->may_delegate || g->max_delegation_depth == 0))
        return MVAP_ERR_DENIED_DELEGATION;

    return MVAP_OK;
}

void agent_grant_commit_debit(struct agent_grant *g,
                              const struct mvap_request *req, int64_t now_ms)
{
    if (!g || !req)
        return;
    const struct mvap_verb_row *row = mvap_verb_row(req->verb);
    if (!row)
        return;

    struct metaverse_grant mg;
    struct metaverse_action_request mreq;
    if (!project_grant(g, row, &mg) ||
        !mvap_request_to_action_request(req, g->principal, now_ms, 0, &mreq))
        return;

    /* The canonical record decides what a commit COSTS — the spend against the
     * cumulative budget and the rate window roll. authorize() already proved
     * both fit, so a refusal here is an internal inconsistency and is logged
     * rather than silently swallowed. */
    if (!metaverse_grant_record_commit(&mg, &mreq)) {
        LOG_WARN(GRANT_TAG,
                 "grant %s: the canonical record refused a commit that "
                 "authorize() had already allowed (verb=%s value=%llu)",
                 g->grant_id, mvap_verb_name(req->verb),
                 (unsigned long long)req->value_zats);
        return;
    }

    g->spent_zats = (uint64_t)mg.spent_zat;
    if (mg.rate_limit > 0) {
        g->window_start_ms = mg.window_start_unix;
        g->window_used     = mg.window_used;
    }
}
