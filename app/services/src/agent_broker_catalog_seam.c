/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The property surface the real broker provider hands to a confined agent: a
 * READ against the real property catalog, and a named refusal for everything
 * this tree cannot execute.
 *
 * ── THE READ IS THE REAL PROJECTION, NOT A COPY OF ONE ───────────────────
 * resolve() calls property_catalog_show() against the operator's datadir. That
 * function has no cache and no catalog table: it rebuilds the view from the
 * authoritative model's own bytes on every call and throws it away. So an
 * agent's INSPECT answer is as current as the datadir, and there is nothing
 * here that could disagree with the store.
 *
 * IT RUNS WITH NO GRANT-STORE LOCK HELD. The property grant service takes its
 * mutex only to copy a snapshot and to re-confirm a generation; the datadir
 * work happens between those two, from the provider's authorize path, and the
 * catalog read below happens from the broker's resolve path, which never
 * touches the grant store at all.
 *
 * ── THERE IS NO WRITE PATH, AND THAT IS STATED, NOT IMPLIED ──────────────
 * commit() refuses. Not "is unimplemented" — refuses, by name, every time. The
 * grant service's COMMIT authorizes, debits a budget and seals a receipt; it
 * hosts nothing, transfers nothing and moves no value. A seam that answered OK
 * would be minting evidence for an event that did not occur.
 */

// one-result-type-ok:broker-catalog-seam — the entry points here are the
// broker's node-ops function pointers (session/agent_broker.h), whose bool
// signature lib/session declares; the catalog call inside already returns
// struct zcl_result and its message is carried into the agent's reply.

#include "agent_broker_provider_internal.h"

#include "base/log_macros.h"
#include "base/text_fit.h"
#include "base/result.h"
#include "base/hex.h"
#include "json/json.h"
#include "metaverse/property_grant.h"
#include "metaverse/property_id.h"
#include "metaverse/property_view.h"
#include "services/property_catalog.h"
#include "session/agent_broker_vocab.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BS_LOG "metaverse.broker_seam"

/* ── the read ───────────────────────────────────────────────────────────── */

/* Ask the catalog about one (kind, root). Returns true when the catalog
 * ANSWERED — including when its answer is "the authority holds nothing here",
 * which is a fact and not a failure. */
static bool show_one(const char *datadir, enum metaverse_kind kind,
                     const uint8_t root[MVAP_PROPERTY_ID_LEN],
                     struct metaverse_property_view *view, char *why,
                     size_t why_cap)
{
    struct metaverse_property_id id;
    memset(&id, 0, sizeof(id));
    id.kind = kind;
    memcpy(id.root, root, METAVERSE_ROOT_BYTES);

    struct zcl_result r = property_catalog_show(datadir, &id, view);
    if (!r.ok) {
        if (why && why_cap) {
            size_t message_len = strlen(r.message);
            if (message_len >= why_cap)
                message_len = why_cap - 1;
            memcpy(why, r.message, message_len);
            why[message_len] = '\0';
        }
        return false; /* raw-return-ok:caller receives the named open error */
    }
    return true;
}

/* Resolve the request's property through the REAL catalog.
 *
 * A wire request may decline to name a kind (MVAP_KIND_ANY), and a canonical
 * id is always (kind, root), so this walks the kind table in order and takes
 * the first kind whose authority actually holds that root. The walk is bounded
 * by METAVERSE_KIND_COUNT and each step is one read of a projection that
 * caches nothing, so the cost is the same as the agent naming the kind itself
 * — it just does not require the agent to know. */
static bool resolve(void *ctx, const struct mvap_request *req,
                    struct agent_plan *out)
{
    const struct broker_provider_ctx *c = ctx;
    if (!c || !req || !out)
        LOG_FAIL(BS_LOG, "resolve: null context, request or output");
    memset(out, 0, sizeof(*out));

    if (mvap_property_id_is_zero(req->property_id)) {
        /* ENUMERATE is refused by name in the provider's authorize, so this is
         * only reachable if that refusal is ever removed. Say what happened
         * rather than resolve a property nobody named. */
        snprintf(out->detail, sizeof(out->detail),
                 "no property named: this seam answers no catalog-wide query");
        return true;                              /* resolved: not found */
    }
    if (!c->datadir[0])
        LOG_FAIL(BS_LOG, "resolve: no datadir was composed");

    struct metaverse_property_view view;
    char why[192];
    why[0] = '\0';
    enum metaverse_kind found_kind = METAVERSE_KIND_UNKNOWN;

    if (req->kind != MVAP_KIND_ANY) {
        enum metaverse_kind k = mvap_kind_to_metaverse(req->kind);
        if (show_one(c->datadir, k, req->property_id, &view, why, sizeof(why)))
            found_kind = k;
    } else {
        for (int k = METAVERSE_KIND_UNKNOWN + 1;
             k < METAVERSE_KIND_COUNT && found_kind == METAVERSE_KIND_UNKNOWN;
             k++) {
            if (!show_one(c->datadir, (enum metaverse_kind)k, req->property_id,
                          &view, why, sizeof(why)))
                continue;
            if (view.status == METAVERSE_STATUS_PRESENT ||
                view.status == METAVERSE_STATUS_INCOMPLETE)
                found_kind = (enum metaverse_kind)k;
        }
    }

    if (found_kind == METAVERSE_KIND_UNKNOWN) {
        snprintf(out->detail, sizeof(out->detail), "catalog: %s",
                 why[0] ? why : "no authority holds this root");
        return true;                              /* resolved: not found */
    }
    if (view.status != METAVERSE_STATUS_PRESENT &&
        view.status != METAVERSE_STATUS_INCOMPLETE) {
        snprintf(out->detail, sizeof(out->detail),
                 "catalog: %s reports this property %s",
                 metaverse_kind_authority(found_kind),
                 metaverse_property_status_name(view.status));
        return true;                              /* resolved: not found */
    }

    out->found    = true;
    out->kind     = mvap_kind_from_metaverse(found_kind);
    out->revision = view.has_revision ? view.revision : 0u;
    /* An authority that records NO owner (a content blob proves bytes, never
     * authorship) cannot disagree with the grant principal, so ownership is
     * vacuously satisfied and says so in `detail`. An authority that DOES
     * record one must match the principal the grant names exactly. This field
     * gates COMMIT only, and no action reaches COMMIT through this seam; for a
     * query it is reported, never enforced. */
    out->owner_matches =
        view.owner_principal[0] == '\0'
            ? true
            : strcmp(view.owner_principal, c->principal) == 0;
    memcpy(out->content_root,
           view.has_content_root ? view.content_root : view.immutable_root,
           32);
    /* Four of these five values are CLOSED-SET identifiers declared in one
     * table each -- authority sources in metaverse/property_id.h, status and
     * evidence grades in metaverse/property_view.c, settlement classes in
     * metaverse/property_id.c -- and most of them are longer than 12 bytes
     * (`chain_indexed_unvalidated` is 25, `chain_anchored_incomplete` is 25).
     * A fixed `%.12s` therefore printed `settlement=content_addr`, a token
     * that matches no member of the enum it names, with bytes still free in
     * the field. They all carry their FULL width here: their combined worst
     * case is 77 bytes, which with the literals and a 20-digit revision puts
     * the head at 154 of the 160-byte detail field.
     *
     * The owner principal is the ONE free-form value (up to
     * METAVERSE_VIEW_TEXT_MAX-1 = 127 bytes), so it is the field that spends
     * whatever is left, and zcl_text_fit() cuts it VISIBLY -- a "...[cut n/m]"
     * marker in the field plus a WARN carrying the whole principal -- instead
     * of the silent prefix a `%.20s` stored. Note the field size is NOT
     * negotiable: detail[] sits inside the receipt preimage that the SHA3
     * digest and the Ed25519 audit signature cover (lib/session/src/
     * agent_audit.c), so the content is made to fit, never the buffer. */
    int head = snprintf(out->detail, sizeof(out->detail),
             "authority=%s status=%s evidence=%s settlement=%s "
             "revision=%llu owner=",
             view.authority_source ? view.authority_source : "unknown",
             metaverse_property_status_name(view.status),
             metaverse_evidence_name(view.evidence),
             metaverse_settlement_name(view.settlement),
             (unsigned long long)out->revision);
    if (head > 0 && (size_t)head < sizeof(out->detail))
        (void)zcl_text_fit(out->detail + head,
                           sizeof(out->detail) - (size_t)head,
                           view.owner_principal[0] ? view.owner_principal
                                                   : "(none recorded)",
                           "agent_broker", "receipt.detail.owner");
    return true;
}

static bool seam_commit(void *ctx, const struct mvap_request *req,
                        const struct agent_plan *plan,
                        struct agent_commit_outcome *out)
{
    (void)ctx; (void)plan;
    if (out)
        memset(out, 0, sizeof(*out));
    /* The refusal is the answer. It mints no canonical receipt, leaves
     * `action_receipt_id` zero, and returns false so the broker replies with a
     * refusal instead of a body describing a change that did not happen. */
    LOG_FAIL(BS_LOG,
             "commit refused for %s: nothing in this tree executes a property "
             "mutation (the grant service authorizes, debits and seals a "
             "receipt; it hosts, transfers and pays nothing)",
             req ? mvap_verb_name(req->verb) : "(null)");
}

struct agent_broker_node_ops broker_provider_ops(void *ctx)
{
    return (struct agent_broker_node_ops){
        .query  = resolve,
        .plan   = resolve,
        .commit = seam_commit,
        .ctx    = ctx,
    };
}

/* ── the bounded grant specification ────────────────────────────────────── */

/* Read at most this many bytes of specification. A grant is a small fixed
 * record; anything larger is a mistake or an attack, and truncating one
 * silently would mint an authority the operator did not write. */
#define BROKER_SPEC_MAX 8192u

static bool spec_slurp(const char *path, char *buf, size_t cap, size_t *out_len,
                       char *why, size_t why_cap)
{
    FILE *f = fopen(path, "re");
    if (!f) {
        snprintf(why, why_cap, "cannot open the grant specification %s", path);
        LOG_FAIL(BS_LOG, "%s", why);
    }
    size_t got = fread(buf, 1, cap - 1, f);
    bool overflowed = !feof(f);
    (void)fclose(f);
    if (overflowed) {
        snprintf(why, why_cap,
                 "the grant specification %s is larger than %u bytes; refusing "
                 "to mint an authority from a truncated document",
                 path, (unsigned)BROKER_SPEC_MAX);
        LOG_FAIL(BS_LOG, "%s", why);
    }
    buf[got] = '\0';
    *out_len = got;
    return true;
}

static bool spec_scope(const struct json_value *doc, struct metaverse_grant *g,
                       char *why, size_t why_cap)
{
    const char *form = json_get_str(json_get(doc, "scope"));
    if (form && strcmp(form, "kinds") == 0) {
        g->scope_form = METAVERSE_SCOPE_KINDS;
        const char *csv = json_get_str(json_get(doc, "kinds"));
        metaverse_kind_set kinds = 0;
        for (const char *p = csv ? csv : ""; *p;) {
            char name[64];
            size_t n = 0;
            while (*p == ' ' || *p == ',') p++;
            while (*p && *p != ',' && n + 1 < sizeof(name)) name[n++] = *p++;
            name[n] = '\0';
            if (!n) continue;
            enum metaverse_kind k = metaverse_kind_from_name(name);
            if (k == METAVERSE_KIND_UNKNOWN) {
                snprintf(why, why_cap, "'%s' names no property kind", name);
                return false;
            }
            kinds |= metaverse_kind_bit(k);
        }
        if (!kinds) {
            snprintf(why, why_cap,
                     "scope is \"kinds\" and the kind list is empty: that "
                     "grant authorizes nothing");
            return false;
        }
        g->kinds = kinds;
        return true;
    }

    g->scope_form = METAVERSE_SCOPE_IDS;
    const struct json_value *ids = json_get(doc, "ids");
    size_t n = ids ? json_size(ids) : 0;
    if (n == 0) {
        snprintf(why, why_cap,
                 "scope is \"ids\" and no property id was listed: name at "
                 "least one, or use scope \"kinds\"");
        return false;
    }
    if (n > METAVERSE_GRANT_IDS_MAX) {
        snprintf(why, why_cap, "%zu property ids listed; a grant carries at "
                               "most %d", n, METAVERSE_GRANT_IDS_MAX);
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        const char *text = json_get_str(json_at(ids, i));
        if (!text || !metaverse_property_id_parse(text, &g->ids[i])) {
            snprintf(why, why_cap, "ids[%zu] is not a property id "
                                   "(\"<kind>:<64 hex>\")", i);
            return false;
        }
    }
    g->id_count = n;
    return true;
}

static bool spec_hex(const char *s, size_t n)
{
    if (!s || strlen(s) != n)
        return false; /* raw-return-ok:closed input predicate */
    uint8_t decoded[32];
    return n <= sizeof(decoded) * 2 && zcl_hex_decode(s, decoded, n / 2);
}

bool broker_provider_money_from_spec(
    const char *path, struct agent_money_binding *out, size_t max,
    size_t *count, char *why, size_t why_cap)
{
    if (!path || !out || max == 0 || !count || !why || why_cap == 0)
        LOG_FAIL(BS_LOG, "money grant spec: null argument");
    *count = 0;
    char raw[BROKER_SPEC_MAX];
    size_t len = 0;
    if (!spec_slurp(path, raw, sizeof(raw), &len, why, why_cap)) {
        LOG_WARN(BS_LOG, "custody grant specification read failed: %s", why);
        return false;
    }
    struct json_value doc;
    json_init(&doc);
    if (!json_read(&doc, raw, len)) {
        json_free(&doc);
        (void)snprintf(why, why_cap, "grant specification is not valid JSON");
        return false;
    }
    const struct json_value *wallets = json_get(&doc, "wallets");
    size_t n = wallets ? json_size(wallets) : 0;
    /* Old property-only grants remain valid and explicitly have no custody
     * binding; every money snapshot then reports UNKNOWN rather than zero. */
    if (!wallets) {
        json_free(&doc);
        return true;
    }
    if (wallets->type != JSON_ARR || n == 0 || n > max) {
        json_free(&doc);
        (void)snprintf(why, why_cap,
                       "grant must contain 1..%zu custody wallet bindings", max);
        return false;
    }
    memset(out, 0, max * sizeof(*out));
    bool ok = true;
    for (size_t i = 0; i < n && ok; i++) {
        const struct json_value *w = json_at(wallets, i);
        const char *scope = w ? json_get_str(json_get(w, "scope")) : NULL;
        const char *wid = w ? json_get_str(json_get(w, "wallet_instance_id")) : NULL;
        const char *gen = w ? json_get_str(json_get(w, "network_genesis")) : NULL;
        const char *datadir = w ? json_get_str(json_get(w, "node_datadir")) : NULL;
        int64_t port = w ? json_get_int(json_get(w, "rpc_port")) : 0;
        if (!w || w->type != JSON_OBJ ||
            (!scope || (strcmp(scope, "dev") != 0 &&
                        strcmp(scope, "prod") != 0)) ||
            !spec_hex(wid, 32) || !spec_hex(gen, 64) ||
            !datadir || datadir[0] != '/' ||
            strnlen(datadir, AGENT_MONEY_ENDPOINT_MAX) >=
                AGENT_MONEY_ENDPOINT_MAX || port <= 0 || port > 65535) {
            (void)snprintf(why, why_cap,
                           "wallets[%zu] needs scope dev|prod, expected id/"
                           "genesis, absolute node_datadir, and rpc_port", i);
            ok = false;
            break;
        }
        for (size_t j = 0; j < i; j++) {
            if (strcmp(out[j].wallet_scope, scope) == 0) {
                (void)snprintf(why, why_cap,
                               "wallet scope %s appears more than once", scope);
                ok = false;
                break;
            }
        }
        if (!ok)
            break;
        (void)snprintf(out[i].wallet_scope, sizeof(out[i].wallet_scope),
                       "%s", scope);
        (void)snprintf(out[i].wallet_instance_id,
                       sizeof(out[i].wallet_instance_id), "%s", wid);
        (void)snprintf(out[i].network_genesis,
                       sizeof(out[i].network_genesis), "%s", gen);
        (void)snprintf(out[i].node_datadir, sizeof(out[i].node_datadir),
                       "%s", datadir);
        out[i].rpc_port = (int)port;
    }
    json_free(&doc);
    if (!ok)
        return false;
    *count = n;
    return true;
}

bool broker_provider_mint_from_spec(const char *path, char *out_id,
                                    size_t out_id_cap, char *why,
                                    size_t why_cap)
{
    if (!path || !out_id || !why || why_cap == 0)
        LOG_FAIL(BS_LOG, "grant spec: null argument");
    why[0] = '\0';

    char raw[BROKER_SPEC_MAX];
    size_t len = 0;
    if (!spec_slurp(path, raw, sizeof(raw), &len, why, why_cap))
        LOG_FAIL(BS_LOG, "grant specification refused: %s", why);

    struct json_value doc;
    json_init(&doc);
    if (!json_read(&doc, raw, len)) {
        json_free(&doc);
        snprintf(why, why_cap, "the grant specification %s is not valid JSON",
                 path);
        return false;
    }

    struct metaverse_grant g;
    memset(&g, 0, sizeof(g));
    const char *holder = json_get_str(json_get(&doc, "holder"));
    const char *issuer = json_get_str(json_get(&doc, "issuer"));
    if (!holder || !holder[0]) {
        json_free(&doc);
        snprintf(why, why_cap,
                 "the grant specification names no \"holder\": a grant with no "
                 "principal authorizes nobody");
        return false;
    }
    snprintf(g.holder, sizeof(g.holder), "%s", holder);
    snprintf(g.issuer, sizeof(g.issuer), "%s", issuer && issuer[0] ? issuer
                                                                   : holder);

    bool ok = spec_scope(&doc, &g, why, why_cap);
    if (ok) {
        const char *queries = json_get_str(json_get(&doc, "queries"));
        const char *actions = json_get_str(json_get(&doc, "actions"));
        if (queries && queries[0] &&
            !metaverse_query_set_parse(queries, &g.queries)) {
            snprintf(why, why_cap, "\"queries\" is not a query list: %s",
                     queries);
            ok = false;
        } else if (actions && actions[0] &&
                   !metaverse_action_set_parse(actions, &g.actions)) {
            snprintf(why, why_cap, "\"actions\" is not an action list: %s",
                     actions);
            ok = false;
        } else if (!g.queries && !g.actions) {
            snprintf(why, why_cap,
                     "the grant specification lists neither a query nor an "
                     "action: it would authorize nothing");
            ok = false;
        }
    }
    if (ok) {
        g.max_value_zat = json_get_int(json_get(&doc, "max_value_zat"));
        g.expires_unix  = json_get_int(json_get(&doc, "expires_unix"));
        g.expires_height = json_get_int(json_get(&doc, "expires_height"));
        g.rate_limit = (uint32_t)json_get_int(json_get(&doc, "rate_limit"));
        g.rate_window_seconds =
            json_get_int(json_get(&doc, "rate_window_seconds"));
        if (g.rate_limit > 0 && g.rate_window_seconds <= 0)
            g.rate_window_seconds = 60;
        if (g.max_value_zat < 0) {
            snprintf(why, why_cap, "\"max_value_zat\" is negative");
            ok = false;
        }
    }
    json_free(&doc);
    if (!ok)
        return false;

    enum property_grant_reason r = property_grant_service_mint(&g);
    if (r != PROPERTY_GRANT_OK) {
        snprintf(why, why_cap, "the property grant store refused the minted "
                               "grant (%s)", property_grant_reason_token(r));
        return false;
    }
    snprintf(out_id, out_id_cap, "%s", g.grant_id);
    return true;
}
