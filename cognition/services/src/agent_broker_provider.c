/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The real broker provider: configuration, binding, and the LIVE authority
 * decision. See services/agent_broker_provider.h for the ordering contract and
 * why registration grants nothing.
 *
 * ── HOW A DECISION IS MADE, AND WHY IT CANNOT BE STALE ───────────────────
 * provider_authorize() holds no grant. It runs the three-step live-authority
 * protocol on every single call:
 *
 *   1. property_grant_service_snapshot()  — brief mutex, copy the grant, its
 *      ancestors, their revocation generations and the store-wide authority
 *      generation, release.
 *   2. the PURE canonical evaluator (metaverse_grant_check /
 *      metaverse_grant_query_check) over that snapshot, with NO lock held.
 *   3. property_grant_service_recheck() — brief mutex, confirm nothing moved.
 *      If it did, retry the whole thing ONCE, then answer AUTHORITY_CHANGED
 *      rather than return a verdict over a state that no longer exists.
 *
 * There is no branch in this file that answers from a remembered verdict, a
 * cached grant, or a session copy — the broker session has none to offer, and
 * the only thing it hands in is `ref`, which names WHICH grant and carries a
 * narrowing that can refuse and cannot allow.
 */

// one-result-type-ok:broker-provider — this file speaks two closed taxonomies
// that already carry their own refusals and cannot be merged into
// struct zcl_result without losing them: enum mvap_status on the wire (the
// agent reads the named refusal) and enum property_grant_reason from the grant
// service. The bool exports are the provider seam's own signatures
// (session/agent_broker.h), which cognition/modules/session declares and this file
// implements.

#include "services/agent_broker_provider.h"
#include "base/format_attribute.h"

#include "agent_broker_provider_internal.h"

#include "base/log_macros.h"
#include "json/json.h"
#include "metaverse/property_grant.h"
#include "metaverse/property_id.h"
#include "session/agent_broker_vocab.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BP_LOG "metaverse.broker_provider"

/* STATIC LIFETIME. The registry and every authority reference borrow pointers
 * into this object; see the internal header. */
static struct broker_provider_ctx g_ctx;

const char *agent_broker_provider_last_refusal(void)
{
    return g_ctx.refusal;
}

static void refuse(char *why, size_t why_cap, const char *fmt, ...)
    ZCL_PRINTF_LIKE(3, 4);

static void refuse(char *why, size_t why_cap, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(g_ctx.refusal, sizeof(g_ctx.refusal), fmt, ap);
    va_end(ap);
    if (why && why_cap)
        snprintf(why, why_cap, "%s", g_ctx.refusal);
}

/* ── binding ────────────────────────────────────────────────────────────── */

/* Derive the broker's confinement narrowing from the CANONICAL grant, and
 * from nothing else.
 *
 * This is the whole of A6: the operator writes one policy, the canonical
 * grant. What the broker enforces on top of the canonical verdict is computed
 * from that record here, once, at bind. There is no second place where a
 * property id, a kind, or a ceiling is chosen, so there is nothing that can
 * drift away from the grant the operator actually issued.
 *
 * The two scope forms map differently and both map to a NARROWING:
 *   SCOPE_IDS   — the exact roots, plus the kinds those ids carry, so a wire
 *                 request that names a granted root under a different kind is
 *                 refused before the catalog is even asked.
 *   SCOPE_KINDS — no id list (the canonical evaluator enforces the kind set),
 *                 and the same kind mask mirrored here.
 *
 * `max_value_zats` is the canonical CUMULATIVE ceiling used as a per-action
 * one. That is deliberately conservative: no single action may exceed what the
 * grant may ever spend in total. It can only refuse more, never less. */
static bool scope_from_canonical(const struct metaverse_grant *g,
                                 struct agent_broker_scope *out, char *why,
                                 size_t why_cap)
{
    memset(out, 0, sizeof(*out));

    if (g->scope_form == METAVERSE_SCOPE_IDS) {
        if (g->id_count == 0) {
            refuse(why, why_cap,
                   "grant %s is id-scoped and names no property: it authorizes "
                   "nothing and the broker will not widen it", g->grant_id);
            return false;
        }
        if (g->id_count > AGENT_GRANT_MAX_PROPS) {
            /* Keeping the first eight would silently narrow a list the
             * operator believes they wrote, and a caller reading the result as
             * "allowed" would then be acting outside it. */
            refuse(why, why_cap,
                   "grant %s names %zu properties and a broker session can "
                   "carry at most %d", g->grant_id, g->id_count,
                   AGENT_GRANT_MAX_PROPS);
            return false;
        }
        for (size_t i = 0; i < g->id_count; i++) {
            memcpy(out->properties[i], g->ids[i].root, MVAP_PROPERTY_ID_LEN);
            out->kinds_mask |= (uint32_t)1u
                               << (unsigned)mvap_kind_from_metaverse(
                                      g->ids[i].kind);
        }
        out->n_properties = g->id_count;
    } else {
        out->n_properties = 0;
        out->kinds_mask = (uint32_t)g->kinds;
    }

    out->max_value_zats =
        g->max_value_zat > 0 ? (uint64_t)g->max_value_zat : 0u;
    return true;
}

static bool provider_bind(void *ctx, struct agent_authority_ref *out,
                          char *why, size_t why_cap)
{
    struct broker_provider_ctx *c = ctx;
    if (!c || !out)
        LOG_FAIL(BP_LOG, "bind: null context or output");
    memset(out, 0, sizeof(*out));
    c->bound = false;
    c->refusal[0] = '\0';

    if (!c->composed) {
        refuse(why, why_cap,
               "the broker provider was never composed: no configuration and "
               "therefore no authority");
        return false;
    }
    if (c->grant_id[0] && c->grant_spec[0]) {
        refuse(why, why_cap,
               "--grant-id= and --grant-spec= were both given; the operator "
               "must name ONE authority, not two");
        return false;
    }
    if (!c->grant_id[0] && !c->grant_spec[0]) {
        /* THE FAIL-CLOSED DEFAULT. Registration by itself is not
         * provisioning: with no operator-selected grant source there is no
         * authority, and the broker serves named refusals rather than
         * inventing a default grant nobody issued. */
        refuse(why, why_cap,
               "no --grant-id= and no --grant-spec=: this broker is UNGRANTED "
               "(registering a provider grants nothing)");
        return false;
    }
    if (!c->datadir[0]) {
        refuse(why, why_cap,
               "no -datadir=DIR: the broker will not guess a datadir, because "
               "the guess would be the operator's live node");
        return false;
    }

    char id[METAVERSE_GRANT_ID_LEN + 1];
    if (c->grant_spec[0]) {
        /* MINTED HERE AND NOWHERE EARLIER. bind runs after the confined child
         * has been forked, so the grant this creates was never in the child's
         * copy-on-write image. */
        if (!broker_provider_mint_from_spec(c->grant_spec, id, sizeof(id), why,
                                            why_cap)) {
            snprintf(c->refusal, sizeof(c->refusal), "%s",
                     why && why[0] ? why : "the grant specification was "
                                           "refused");
            return false;
        }
        snprintf(c->source, sizeof(c->source), "grant-spec");
        if (!broker_provider_money_from_spec(
                c->grant_spec, c->money, AGENT_MONEY_BINDINGS_MAX,
                &c->money_count, why, why_cap)) {
            snprintf(c->refusal, sizeof(c->refusal), "%s",
                     why && why[0] ? why : "custody bindings were refused");
            return false;
        }
    } else {
        snprintf(id, sizeof(id), "%s", c->grant_id);
        snprintf(c->source, sizeof(c->source), "grant-id");
    }

    struct metaverse_grant g;
    enum property_grant_reason r = property_grant_service_get(id, &g);
    if (r != PROPERTY_GRANT_OK) {
        refuse(why, why_cap,
               "the property grant store holds no grant '%s' (%s); the store "
               "is in-process and EPHEMERAL, so a restart leaves it empty "
               "until the operator reprovisions", id,
               property_grant_reason_token(r));
        return false;
    }
    if (!scope_from_canonical(&g, &out->scope, why, why_cap))
        LOG_FAIL(BP_LOG, "bind refused: %s", c->refusal);

    size_t holder_len = strlen(g.holder);
    if (holder_len >= sizeof(out->principal) ||
        holder_len >= sizeof(c->principal)) {
        refuse(why, why_cap, "grant holder identity exceeds the broker limit");
        return false;
    }

    snprintf(out->canonical_grant_id, sizeof(out->canonical_grant_id), "%s",
             g.grant_id);
    memcpy(out->principal, g.holder, holder_len + 1);
    snprintf(c->bound_grant_id, sizeof(c->bound_grant_id), "%s", g.grant_id);
    memcpy(c->principal, g.holder, holder_len + 1);
    out->bound = true;
    c->bound = true;
    return true;
}

static bool provider_money_bindings(void *ctx,
                                    struct agent_money_binding *out,
                                    size_t max, size_t *count)
{
    const struct broker_provider_ctx *c = ctx;
    if (!c || !out || !count || max < c->money_count)
        return false;
    if (c->money_count)
        memcpy(out, c->money, c->money_count * sizeof(*out));
    *count = c->money_count;
    return true;
}

/* ── the live authority decision ────────────────────────────────────────── */

/* Map a store refusal onto the wire's named refusals. Total: every reason has
 * exactly one status and none falls through to a generic denial. */
static int32_t status_from_reason(enum property_grant_reason r)
{
    switch (r) {
    case PROPERTY_GRANT_OK:                 return MVAP_OK;
    case PROPERTY_GRANT_GRANT_UNKNOWN:      return MVAP_ERR_DENIED_NO_GRANT;
    case PROPERTY_GRANT_ANCESTOR_REVOKED:
    case PROPERTY_GRANT_GRANT_REVOKED:      return MVAP_ERR_DENIED_REVOKED;
    case PROPERTY_GRANT_AUTHORITY_CHANGED:  return MVAP_ERR_AUTHORITY_CHANGED;
    case PROPERTY_GRANT_BAD_ARGS:           return MVAP_ERR_BAD_REQUEST;
    default:                                return MVAP_ERR_INTERNAL;
    }
}

/* One authorize attempt over one snapshot. `*moved` is set when the store
 * changed under the decision, which is the caller's cue to retry once. */
static int32_t authorize_attempt(const struct broker_provider_ctx *c,
                                 const struct agent_authority_ref *ref,
                                 const struct mvap_verb_row *row,
                                 const struct mvap_request *req, bool *moved)
{
    (void)c;
    *moved = false;

    struct property_grant_authority_snapshot snap;
    enum property_grant_reason r =
        property_grant_service_snapshot(ref->canonical_grant_id, &snap);
    if (r != PROPERTY_GRANT_OK)
        return status_from_reason(r);

    const struct metaverse_grant *anc[METAVERSE_GRANT_MAX_DEPTH];
    size_t anc_count = property_grant_snapshot_ancestors(&snap, anc);

    /* The PURE decision, with no lock held. The clock comes from the snapshot,
     * so expiry is measured against the same instant the recheck validates —
     * not against a second reading that could straddle it. */
    enum metaverse_grant_verdict verdict;
    if (row->verb_class == MVAP_VERB_CLASS_QUERY) {
        /* A canonical query request has no value column, so an amount on a
         * read cannot be silently dropped: it is a bad request. */
        if (req->value_zats != 0)
            return MVAP_ERR_BAD_REQUEST;
        struct metaverse_query_request qreq;
        if (!mvap_request_to_query_request(req, ref->principal, snap.now_unix,
                                           snap.height, &qreq))
            return MVAP_ERR_BAD_REQUEST;
        verdict = metaverse_grant_query_check(&snap.grant,
                                              anc_count ? anc : NULL,
                                              anc_count, &qreq);
    } else {
        struct metaverse_action_request areq;
        if (!mvap_request_to_action_request(req, ref->principal, snap.now_unix,
                                            snap.height, &areq))
            return MVAP_ERR_BAD_REQUEST;
        verdict = metaverse_grant_check(&snap.grant, anc_count ? anc : NULL,
                                        anc_count, &areq);
    }

    /* CONFIRM THE STATE HELD. Before this line the verdict is a computation
     * over a copy; after it, and only if it passed, the verdict is a statement
     * about the store. */
    r = property_grant_service_recheck(&snap);
    if (r == PROPERTY_GRANT_AUTHORITY_CHANGED) {
        *moved = true;
        return MVAP_ERR_AUTHORITY_CHANGED;
    }
    if (r != PROPERTY_GRANT_OK)
        return status_from_reason(r);

    if (verdict != METAVERSE_GRANT_OK)
        return mvap_status_from_grant_verdict(verdict);

    /* Delegation needs a child grant the wire cannot carry, so the canonical
     * delegation check is unreachable from here. What IS checkable is whether
     * the live grant permits delegating at all. Read from the snapshot that
     * the recheck just validated, never from a session copy. */
    enum metaverse_action action;
    if (mvap_verb_row_action(row, &action) &&
        action == METAVERSE_ACTION_DELEGATE &&
        (!snap.grant.delegation_allowed ||
         snap.grant.max_delegation_depth == 0))
        return MVAP_ERR_DENIED_DELEGATION;

    /* A verb that does not accept the all-zero "no specific property" id is
     * refused by name, from the join table's own column. The session's
     * confinement check (agent_broker_scope_check) says the same thing a step
     * later; saying it here too means the provider's verdict is complete on its
     * own, which is what a test that calls authorize() directly is entitled to.
     * It can only refuse. */
    if (mvap_property_id_is_zero(req->property_id) &&
        !row->allows_zero_property_id)
        return MVAP_ERR_DENIED_PROPERTY;

    /* ── CAPABILITY, checked LAST so an unauthorized request still reports the
     *    authorization refusal rather than an availability one.
     *
     *    Nothing in this tree EXECUTES a property mutation.
     *    property_grant_service_commit() authorizes, debits and seals a
     *    receipt; it does not host a file, move a title, or transfer value.
     *    Answering OK here would produce a receipt for an event that did not
     *    happen, which is the worst outcome this seam can produce — worse than
     *    any refusal. So every action-class verb is refused by name and the
     *    broker never reaches PLAN, COMMIT, or a canonical receipt. */
    if (row->verb_class == MVAP_VERB_CLASS_ACTION)
        return MVAP_ERR_ACTION_EXECUTOR_UNAVAILABLE;

    /* ENUMERATE_PROPERTIES has no bounded result type on this seam. The wire's
     * only carrier would be agent_plan.detail, a 160-byte human string, and a
     * list truncated into a diagnostic field is a list an agent will act on
     * wrongly. Named unavailable instead.
     *
     * KEYED ON WHICH QUERY WAS ASKED, not on whether the request carried a
     * property id. Those are different questions, and the second one used to
     * stand in for the first: both query verbs projected onto the reserved
     * INSPECT action bit, so this was the only distinguishing fact left, and it
     * is the WRONG fact — an ENUMERATE naming a real property id sailed past
     * and was served as though it were an INSPECT of that property. A request
     * to list is never answered as a request to look. */
    enum metaverse_query query;
    if (mvap_verb_row_query(row, &query) &&
        query == METAVERSE_QUERY_ENUMERATE_PROPERTIES)
        return MVAP_ERR_QUERY_UNAVAILABLE;

    return MVAP_OK;
}

static int32_t provider_authorize(void *ctx,
                                  const struct agent_authority_ref *ref,
                                  const struct mvap_request *req,
                                  int64_t now_ms)
{
    (void)now_ms;   /* the authority's clock is the store's, not the wire's */
    const struct broker_provider_ctx *c = ctx;
    if (!c || !ref || !req)
        return MVAP_ERR_INTERNAL;
    if (!ref->bound || !ref->canonical_grant_id[0])
        return MVAP_ERR_DENIED_NO_GRANT;

    const struct mvap_verb_row *row = mvap_verb_row(req->verb);
    if (!row)
        return MVAP_ERR_UNKNOWN_VERB;

    bool moved = false;
    int32_t status = authorize_attempt(c, ref, row, req, &moved);
    if (moved)
        status = authorize_attempt(c, ref, row, req, &moved);   /* ONE retry */
    return status;
}

static bool provider_debit(void *ctx, const struct agent_authority_ref *ref,
                           const struct mvap_request *req, int64_t now_ms)
{
    (void)ctx; (void)ref; (void)now_ms;
    /* UNREACHABLE BY CONSTRUCTION and stated rather than assumed: the broker
     * only debits after a successful COMMIT, and provider_authorize refuses
     * every action-class verb before PLAN. If this ever fires, an action was
     * executed that this seam declared it could not execute. */
    LOG_FAIL(BP_LOG,
             "debit reached for verb %s: this seam executes no mutations, so a "
             "commit should have been impossible",
             req ? mvap_verb_name(req->verb) : "(null)");
}

static bool provider_status(void *ctx, const struct agent_authority_ref *ref,
                            struct agent_authority_status *out)
{
    const struct broker_provider_ctx *c = ctx;
    if (!c || !ref || !out)
        return false;
    memset(out, 0, sizeof(*out));
    snprintf(out->authority_source, sizeof(out->authority_source), "%s",
             c->source[0] ? c->source : "none");
    snprintf(out->canonical_grant_id, sizeof(out->canonical_grant_id), "%s",
             ref->canonical_grant_id);
    snprintf(out->principal, sizeof(out->principal), "%s", ref->principal);
    /* Every decision re-reads the store; nothing here is served from a copy. */
    out->live_authority = true;
    /* The property grant store is IN-PROCESS and is not written to node.db.
     * Saying so in the status document is what stops an operator reading a
     * revocation here as durable. */
    out->ephemeral = true;
    out->authority_generation = property_grant_service_authority_generation();

    struct metaverse_grant g;
    if (property_grant_service_get(ref->canonical_grant_id, &g) ==
        PROPERTY_GRANT_OK) {
        out->revoked = g.revoked;
        out->budget_zat = g.max_value_zat > 0 ? (uint64_t)g.max_value_zat : 0u;
        out->spent_zat = g.spent_zat > 0 ? (uint64_t)g.spent_zat : 0u;
    }
    return true;
}

/* ── composition ────────────────────────────────────────────────────────── */

static const char *arg_value(int argc, char **argv, const char *prefix)
{
    size_t n = strlen(prefix);
    for (int i = 1; i < argc; i++)
        if (strncmp(argv[i], prefix, n) == 0)
            return argv[i] + n;
    return NULL;
}

/* STATIC LIFETIME, borrowed by the registry. */
static const struct agent_broker_provider k_provider = {
    .bind      = provider_bind,
    .authorize = provider_authorize,
    .debit     = provider_debit,
    .status    = provider_status,
    .money_bindings = provider_money_bindings,
    .ops       = broker_provider_ops,
    .ctx       = &g_ctx,
    .name      = "property_catalog + property_grant_service",
};

void agent_broker_provider_compose_explicit(const char *datadir,
                                            const char *grant_id,
                                            const char *grant_spec)
{
    /* INERT. Copies three non-secret strings and installs static pointers.
     * Nothing is opened, read, minted or drawn — see the ordering contract in
     * services/agent_broker_provider.h. */
    memset(&g_ctx, 0, sizeof(g_ctx));
    if (datadir)
        snprintf(g_ctx.datadir, sizeof(g_ctx.datadir), "%s", datadir);
    if (grant_id)
        snprintf(g_ctx.grant_id, sizeof(g_ctx.grant_id), "%s", grant_id);
    if (grant_spec)
        snprintf(g_ctx.grant_spec, sizeof(g_ctx.grant_spec), "%s", grant_spec);
    g_ctx.composed = true;
    agent_broker_provider_install(&k_provider);
}

void agent_broker_provider_compose(int argc, char **argv)
{
    agent_broker_provider_compose_explicit(arg_value(argc, argv, "-datadir="),
                                           arg_value(argc, argv, "--grant-id="),
                                           arg_value(argc, argv,
                                                     "--grant-spec="));
}
