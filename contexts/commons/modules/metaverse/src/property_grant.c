/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Property grants — the pure rule evaluator. Every fact arrives as an
 * argument; nothing here reads a clock, a database, or the network, and
 * nothing allocates. See the header for the budget and revocation rationale. */

#include "metaverse/property_grant.h"

#include "base/log_macros.h"

#include <stdio.h>
#include <string.h>

#define GRANT_LOG "metaverse.grant"

/* The action token table that used to live here — thirteen names indexed by a
 * bit POSITION — was the second half of the duplication this file no longer
 * carries. Names come from metaverse/property_action.h's one table now. */

static const char *const k_verdict_tokens[METAVERSE_GRANT_VERDICT_COUNT] = {
    "OK",
    "BAD_ARGS",
    "GRANT_MALFORMED",
    "GRANT_REVOKED",
    "ANCESTOR_REVOKED",
    "GRANT_EXPIRED_HEIGHT",
    "GRANT_EXPIRED_TIME",
    "WRONG_HOLDER",
    "ACTION_NOT_GRANTED",
    "PROPERTY_OUT_OF_SCOPE",
    "KIND_OUT_OF_SCOPE",
    "COUNTERPARTY_NOT_ALLOWED",
    "VALUE_NEGATIVE",
    "VALUE_ON_FREE_ACTION",
    "BUDGET_EXCEEDED",
    "RATE_LIMITED",
    "DELEGATION_NOT_PERMITTED",
    "DELEGATION_DEPTH_EXCEEDED",
};

const char *metaverse_grant_verdict_token(enum metaverse_grant_verdict v)
{
    if (v < 0 || v >= METAVERSE_GRANT_VERDICT_COUNT) return "UNKNOWN_VERDICT";
    return k_verdict_tokens[v];
}

/* ── Well-formedness ────────────────────────────────────────────────────── */

bool metaverse_grant_well_formed(const struct metaverse_grant *g)
{
    if (!g) return false;
    if (g->grant_id[0] == '\0') return false;
    if (strlen(g->grant_id) != METAVERSE_GRANT_ID_LEN) return false;
    if (g->holder[0] == '\0') return false;

    if (g->depth > METAVERSE_GRANT_MAX_DEPTH) return false;
    if (g->lineage_count != (size_t)g->depth) return false;
    for (size_t i = 0; i < g->lineage_count; i++) {
        if (g->lineage[i].grant_id[0] == '\0') return false;
    }

    if (g->scope_form == METAVERSE_SCOPE_IDS) {
        if (g->id_count == 0 || g->id_count > METAVERSE_GRANT_IDS_MAX)
            return false;
        for (size_t i = 0; i < g->id_count; i++) {
            if (!metaverse_property_id_valid(&g->ids[i])) return false;
        }
    } else if (g->scope_form == METAVERSE_SCOPE_KINDS) {
        if (g->kinds == 0u) return false;
        /* Bit 0 is UNKNOWN and can never be a legitimate scope member. */
        if (g->kinds & 1u) return false;
    } else {
        return false;
    }

    /* Neither right set may carry a bit that names nothing. A grant holding
     * an unnameable bit is not "a grant with a future right"; it is a grant
     * nobody can audit, and the reserved bit 0x1 (once INSPECT) lands here. */
    if (!metaverse_action_mask_valid(g->actions)) return false;
    if (!metaverse_query_mask_valid(g->queries)) return false;

    if (g->max_value_zat < 0 || g->spent_zat < 0) return false;
    if (g->spent_zat > g->max_value_zat) return false;
    if (g->counterparty_count > METAVERSE_GRANT_COUNTERPARTIES_MAX) return false;
    if (g->rate_limit > 0 && g->rate_window_seconds <= 0) return false;
    if (g->max_delegation_depth > METAVERSE_GRANT_MAX_DEPTH) return false;
    if (g->expires_height < 0 || g->expires_unix < 0) return false;
    return true;
}

int64_t metaverse_grant_budget_remaining(const struct metaverse_grant *g)
{
    if (!g) return 0;
    if (g->spent_zat >= g->max_value_zat) return 0;
    return g->max_value_zat - g->spent_zat;
}

uint32_t metaverse_grant_rate_remaining(const struct metaverse_grant *g,
                                       int64_t now_unix)
{
    if (!g) return 0;
    if (g->rate_limit == 0) return UINT32_MAX;
    /* A window that has elapsed is already rolled for decision purposes; the
     * counter is only physically reset when a commit is recorded. */
    if (now_unix - g->window_start_unix >= g->rate_window_seconds)
        return g->rate_limit;
    if (g->window_used >= g->rate_limit) return 0;
    return g->rate_limit - g->window_used;
}

bool metaverse_grant_in_scope(const struct metaverse_grant *g,
                             const struct metaverse_property_id *id)
{
    if (!g || !metaverse_property_id_valid(id)) return false;
    if (g->scope_form == METAVERSE_SCOPE_KINDS)
        return (g->kinds & metaverse_kind_bit(id->kind)) != 0u;
    for (size_t i = 0; i < g->id_count; i++) {
        if (metaverse_property_id_equal(&g->ids[i], id)) return true;
    }
    return false;
}

static bool counterparty_allowed(const struct metaverse_grant *g,
                                 const char *counterparty)
{
    if (g->counterparty_count == 0) return true;  /* wildcard */
    if (!counterparty || counterparty[0] == '\0') return false;
    for (size_t i = 0; i < g->counterparty_count; i++) {
        if (strcmp(g->counterparties[i], counterparty) == 0) return true;
    }
    return false;
}

/* Revocation over the whole lineage. `ancestors` is the store's CURRENT view,
 * root-first, parallel to g->lineage. Missing/short/mismatched input is
 * ANCESTOR_REVOKED: "cannot check the parent" and "parent said no" must have
 * the same effect, or a store outage becomes a privilege escalation. */
static enum metaverse_grant_verdict lineage_verdict(
    const struct metaverse_grant *g,
    const struct metaverse_grant *const *ancestors, size_t ancestor_count)
{
    if (g->revoked) return METAVERSE_GRANT_REVOKED;
    if (g->lineage_count == 0) return METAVERSE_GRANT_OK;
    if (!ancestors || ancestor_count != g->lineage_count)
        return METAVERSE_GRANT_ANCESTOR_REVOKED;

    for (size_t i = 0; i < g->lineage_count; i++) {
        const struct metaverse_grant *a = ancestors[i];
        if (!a) return METAVERSE_GRANT_ANCESTOR_REVOKED;
        if (strcmp(a->grant_id, g->lineage[i].grant_id) != 0)
            return METAVERSE_GRANT_ANCESTOR_REVOKED;
        if (a->revoked) return METAVERSE_GRANT_ANCESTOR_REVOKED;
        if (a->revocation_generation != g->lineage[i].revocation_generation)
            return METAVERSE_GRANT_ANCESTOR_REVOKED;
    }
    return METAVERSE_GRANT_OK;
}

enum metaverse_grant_verdict metaverse_grant_check(
    const struct metaverse_grant *g,
    const struct metaverse_grant *const *ancestors, size_t ancestor_count,
    const struct metaverse_action_request *req)
{
    if (!g || !req) return METAVERSE_GRANT_BAD_ARGS;
    if (!metaverse_grant_well_formed(g)) return METAVERSE_GRANT_MALFORMED;
    if (!metaverse_action_valid(req->action))
        return METAVERSE_GRANT_BAD_ARGS;

    /* An absent property is legal ONLY for an action whose row says so
     * (REVOKE names a grant, not a property). For every other action a
     * missing id is a malformed request, never a wildcard. */
    bool named_property = metaverse_property_id_valid(&req->property);
    if (!named_property &&
        !metaverse_action_allows_zero_property_id(req->action))
        return METAVERSE_GRANT_BAD_ARGS;

    /* Revocation and expiry first: a dead grant must not leak scope. */
    enum metaverse_grant_verdict lv =
        lineage_verdict(g, ancestors, ancestor_count);
    if (lv != METAVERSE_GRANT_OK) return lv;

    if (g->expires_height > 0 && req->height >= g->expires_height)
        return METAVERSE_GRANT_EXPIRED_HEIGHT;
    if (g->expires_unix > 0 && req->now_unix >= g->expires_unix)
        return METAVERSE_GRANT_EXPIRED_TIME;

    if (req->actor[0] == '\0' || strcmp(req->actor, g->holder) != 0)
        return METAVERSE_GRANT_WRONG_HOLDER;

    if (!(g->actions & metaverse_action_bit(req->action)))
        return METAVERSE_GRANT_ACTION_NOT_GRANTED;

    if (named_property && !metaverse_grant_in_scope(g, &req->property)) {
        return g->scope_form == METAVERSE_SCOPE_KINDS
                   ? METAVERSE_GRANT_KIND_OUT_OF_SCOPE
                   : METAVERSE_GRANT_PROPERTY_OUT_OF_SCOPE;
    }

    /* Only the actions whose row names a counterparty are held to the
     * allowlist. Applying it to the rest would make an operator who narrowed
     * WHO they trade with also unable to HOST their own property. */
    if (metaverse_action_uses_counterparty(req->action) &&
        !counterparty_allowed(g, req->counterparty))
        return METAVERSE_GRANT_COUNTERPARTY_NOT_ALLOWED;

    /* Columns 8 and 9 are asked separately. An action may legitimately NAME a
     * value it does not MOVE (LIST_FOR_SALE quotes an asking price), and
     * charging that against the cumulative ceiling would bill the operator
     * for an advertisement. */
    if (req->value_zat < 0) return METAVERSE_GRANT_VALUE_NEGATIVE;
    if (req->value_zat > 0 && !metaverse_action_accepts_value(req->action))
        return METAVERSE_GRANT_VALUE_ON_FREE_ACTION;
    if (metaverse_action_moves_value(req->action) &&
        req->value_zat > metaverse_grant_budget_remaining(g))
        return METAVERSE_GRANT_BUDGET_EXCEEDED;

    if (metaverse_grant_rate_remaining(g, req->now_unix) == 0)
        return METAVERSE_GRANT_RATE_LIMITED;

    return METAVERSE_GRANT_OK;
}

enum metaverse_grant_verdict metaverse_grant_query_check(
    const struct metaverse_grant *g,
    const struct metaverse_grant *const *ancestors, size_t ancestor_count,
    const struct metaverse_query_request *req)
{
    if (!g || !req) return METAVERSE_GRANT_BAD_ARGS;
    if (!metaverse_grant_well_formed(g)) return METAVERSE_GRANT_MALFORMED;
    if (!metaverse_query_valid(req->query))
        return METAVERSE_GRANT_BAD_ARGS;

    bool named_property = metaverse_property_id_valid(&req->property);
    if (!named_property &&
        !metaverse_query_allows_zero_property_id(req->query))
        return METAVERSE_GRANT_BAD_ARGS;

    enum metaverse_grant_verdict lv =
        lineage_verdict(g, ancestors, ancestor_count);
    if (lv != METAVERSE_GRANT_OK) return lv;

    if (g->expires_height > 0 && req->height >= g->expires_height)
        return METAVERSE_GRANT_EXPIRED_HEIGHT;
    if (g->expires_unix > 0 && req->now_unix >= g->expires_unix)
        return METAVERSE_GRANT_EXPIRED_TIME;

    if (req->actor[0] == '\0' || strcmp(req->actor, g->holder) != 0)
        return METAVERSE_GRANT_WRONG_HOLDER;

    if (!(g->queries & metaverse_query_bit(req->query)))
        return METAVERSE_GRANT_ACTION_NOT_GRANTED;

    if (named_property && !metaverse_grant_in_scope(g, &req->property)) {
        return g->scope_form == METAVERSE_SCOPE_KINDS
                   ? METAVERSE_GRANT_KIND_OUT_OF_SCOPE
                   : METAVERSE_GRANT_PROPERTY_OUT_OF_SCOPE;
    }

    /* No value, no counterparty, no rate window. A read consumes none of the
     * three, and spending an action budget on a look would make an agent's
     * ability to act depend on how often it checked. */
    return METAVERSE_GRANT_OK;
}

/* ── Delegation ─────────────────────────────────────────────────────────── */

enum metaverse_grant_verdict metaverse_grant_check_delegation(
    const struct metaverse_grant *g,
    const struct metaverse_grant *const *ancestors, size_t ancestor_count,
    const struct metaverse_grant *child,
    int64_t now_unix, int64_t height)
{
    if (!g || !child) return METAVERSE_GRANT_BAD_ARGS;
    if (!metaverse_grant_well_formed(g)) return METAVERSE_GRANT_MALFORMED;

    enum metaverse_grant_verdict lv =
        lineage_verdict(g, ancestors, ancestor_count);
    if (lv != METAVERSE_GRANT_OK) return lv;

    if (g->expires_height > 0 && height >= g->expires_height)
        return METAVERSE_GRANT_EXPIRED_HEIGHT;
    if (g->expires_unix > 0 && now_unix >= g->expires_unix)
        return METAVERSE_GRANT_EXPIRED_TIME;

    if (!(g->actions & metaverse_action_bit(METAVERSE_ACTION_DELEGATE)) ||
        !g->delegation_allowed)
        return METAVERSE_GRANT_DELEGATION_NOT_PERMITTED;

    if (child->depth != g->depth + 1u ||
        child->depth > g->max_delegation_depth ||
        child->depth > METAVERSE_GRANT_MAX_DEPTH)
        return METAVERSE_GRANT_DELEGATION_DEPTH_EXCEEDED;

    /* ATTENUATION. A child may only ever be narrower than its parent. */
    if (child->actions & ~g->actions)
        return METAVERSE_GRANT_ACTION_NOT_GRANTED;
    /* Reads attenuate exactly like writes: a child that could look at more
     * than its parent is a widening, and a widening by delegation is how a
     * bounded grant becomes an unbounded one. */
    if (child->queries & ~g->queries)
        return METAVERSE_GRANT_ACTION_NOT_GRANTED;
    if (child->max_value_zat > metaverse_grant_budget_remaining(g))
        return METAVERSE_GRANT_BUDGET_EXCEEDED;
    if (child->max_delegation_depth > g->max_delegation_depth)
        return METAVERSE_GRANT_DELEGATION_DEPTH_EXCEEDED;

    if (child->scope_form == METAVERSE_SCOPE_KINDS) {
        /* A kind-scoped child under an id-scoped parent is a WIDENING (the
         * child would reach every property of that kind, present and future),
         * so it is refused outright. */
        if (g->scope_form != METAVERSE_SCOPE_KINDS)
            return METAVERSE_GRANT_KIND_OUT_OF_SCOPE;
        if (child->kinds & ~g->kinds)
            return METAVERSE_GRANT_KIND_OUT_OF_SCOPE;
    } else {
        for (size_t i = 0; i < child->id_count; i++) {
            if (!metaverse_grant_in_scope(g, &child->ids[i]))
                return g->scope_form == METAVERSE_SCOPE_KINDS
                           ? METAVERSE_GRANT_KIND_OUT_OF_SCOPE
                           : METAVERSE_GRANT_PROPERTY_OUT_OF_SCOPE;
        }
    }

    /* A child may not outlive its parent. */
    if (g->expires_unix > 0 &&
        (child->expires_unix == 0 || child->expires_unix > g->expires_unix))
        return METAVERSE_GRANT_EXPIRED_TIME;
    if (g->expires_height > 0 &&
        (child->expires_height == 0 || child->expires_height > g->expires_height))
        return METAVERSE_GRANT_EXPIRED_HEIGHT;

    if (!metaverse_grant_well_formed(child)) return METAVERSE_GRANT_MALFORMED;
    return METAVERSE_GRANT_OK;
}

/* ── Commit effect ──────────────────────────────────────────────────────── */

/* THE CHARGE RULE, stated once. Only a value that actually MOVES is charged: a
 * quoted asking price is not exposure and must not consume the operator's
 * ceiling. Both the acting grant's debit and the lineage debit below read it
 * from here, so neither can drift from the other. */
static int64_t charge_for(const struct metaverse_action_request *req)
{
    return metaverse_action_moves_value(req->action) ? req->value_zat : 0;
}

bool metaverse_grant_record_commit(struct metaverse_grant *g,
                                  const struct metaverse_action_request *req)
{
    if (!g || !req)
        LOG_FAIL(GRANT_LOG, "record commit: NULL grant or request");
    if (!metaverse_action_valid(req->action))
        LOG_FAIL(GRANT_LOG, "record commit: request names no action");
    if (req->value_zat < 0)
        LOG_FAIL(GRANT_LOG, "record commit: negative value %lld",
                 (long long)req->value_zat);
    int64_t charge = charge_for(req);
    if (charge > metaverse_grant_budget_remaining(g))
        LOG_FAIL(GRANT_LOG,
                 "record commit: value %lld over remaining budget %lld "
                 "(grant %s)",
                 (long long)req->value_zat,
                 (long long)metaverse_grant_budget_remaining(g), g->grant_id);

    if (g->rate_limit > 0) {
        if (req->now_unix - g->window_start_unix >= g->rate_window_seconds) {
            g->window_start_unix = req->now_unix;
            g->window_used = 0;
        }
        if (g->window_used >= g->rate_limit)
            LOG_FAIL(GRANT_LOG, "record commit: rate window full (grant %s)",
                     g->grant_id);
        g->window_used++;
    }

    g->spent_zat += charge;
    return true;
}

bool metaverse_grant_record_descendant_charge(
    struct metaverse_grant *ancestor,
    const struct metaverse_action_request *req)
{
    if (!ancestor || !req)
        LOG_FAIL(GRANT_LOG, "lineage charge: NULL grant or request");
    if (!metaverse_action_valid(req->action))
        LOG_FAIL(GRANT_LOG, "lineage charge: request names no action");
    if (req->value_zat < 0)
        LOG_FAIL(GRANT_LOG, "lineage charge: negative value %lld",
                 (long long)req->value_zat);

    int64_t charge = charge_for(req);
    if (charge > metaverse_grant_budget_remaining(ancestor))
        LOG_FAIL(GRANT_LOG,
                 "lineage charge: value %lld over ancestor %s remaining budget "
                 "%lld",
                 (long long)req->value_zat, ancestor->grant_id,
                 (long long)metaverse_grant_budget_remaining(ancestor));

    /* ONLY the budget. The rate window bounds how often THIS grant's holder
     * may act, and a descendant's action is not this grant's action; charging
     * it here would let a child's traffic exhaust its parent's liveness bound
     * as a side effect of spending money. */
    ancestor->spent_zat += charge;
    return true;
}
