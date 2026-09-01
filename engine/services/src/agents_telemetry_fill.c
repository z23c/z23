/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `agents` telemetry collector. Contract, data sources and the reason it
 * returns void: services/agents_telemetry.h.
 *
 * one-result-type-ok:telemetry-fill-provider — the whole
 * point of this shape is that a read it could not perform becomes a leaf
 * presence (TELEMETRY_UNAVAILABLE + a static reason token) rather than a
 * return value. There is no fallible surface here for a struct zcl_result to
 * carry: a caller cannot act on "the collector failed" differently from "the
 * grant store was unreadable", and the snapshot already says the second in
 * machine-readable form.
 *
 * Read this file as three passes: gather (bounded RPC reads into plain C
 * values), derive (one scan over the grant page), publish (one fill function
 * per group, each of which sets EVERY leaf of its group on EVERY path). The
 * third property is the one that matters — TELEMETRY_UNSET is a counted
 * provider defect, so a group filler that returns early has shipped a bug. */

#include "services/agents_telemetry.h"

/* Both upward includes exist for the same reason vault.session.* has them
 * (cognition/services/src/agent_spend_policy.c): the grant store and the identity
 * registry live in the NODE's node.db, a native command runs in a CLI process
 * that has none, and the loopback RPC client is owned by the controller shape.
 * Reaching down for a socket instead would put transport under the model. */
#include "controllers/agent_session_client.h"  // shape-layer-ok:agents-telemetry-reads-node-over-rpc
#include "controllers/rpc_client.h"  // shape-layer-ok:agents-telemetry-reads-node-over-rpc

#include "json/json.h"
#include "models/agent_session.h"
#include "services/agent_session_service.h"
#include "util/log_macros.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"
#include "util/telemetry_render.h"

#include <stdlib.h>
#include <string.h>

#define AT_TAG "agents_telemetry"

/* Short, explicit deadlines. The generic defaults are 2 s connect / 10 s total
 * (controllers/rpc_client.h); four of those against a stopped node would make
 * a leaf declared LATENCY_FAST take most of a minute. The probe below also
 * short-circuits the remaining reads, so a stopped node costs ONE connect
 * timeout, not four. */
#define AT_CONNECT_MS 500L
#define AT_TOTAL_MS 1500L

/* The whole collection's own wall budget, checked before each remaining read.
 * The leaves are declared LATENCY_FOREGROUND (a 750 ms dispatch bucket) and
 * on a healthy local node the five loopback reads land in single-digit
 * milliseconds, so this never fires in normal operation — it exists so that a
 * SLOW node degrades into partial-but-labelled data inside the declared
 * bucket instead of serially paying every deadline above. Leaves skipped this
 * way are unavailable with AT_WHY_BUDGET, never absent and never zero.
 *
 * Honest limit: the one grant-page read goes through agent_session_client,
 * which uses the RPC client's generic 10 s total deadline and takes no
 * per-call override, so a node that accepts a connection and then stalls
 * mid-page can still exceed this. This guard bounds everything before and
 * after that call, not that call itself. */
#define AT_WALL_BUDGET_MS 700

/* Static reason tokens. Greppable, never formatted, never prose — the render
 * layer treats a non-present leaf with an empty reason as a provider defect. */
#define AT_WHY_NODE_DOWN "node_unreachable"
#define AT_WHY_DB_CLOSED "node_db_closed"
#define AT_WHY_STORE "grant_store_unreadable"
#define AT_WHY_ALLOC "row_buffer_alloc_failed"
#define AT_WHY_CLOCK "wall_clock_unavailable"
#define AT_WHY_PRINCIPALS "principal_registry_unreadable"
#define AT_WHY_AUTH "auth_challenge_store_unreadable"
#define AT_WHY_BACKTRACE "backtrace_state_unreadable"
#define AT_WHY_BUDGET "collection_budget_exhausted"
#define AT_NA_NO_USABLE "no_usable_grant"
#define AT_NA_NO_EXPIRY "no_expiring_usable_grant"
#define AT_NA_NO_CAP "no_usable_grant_with_a_window_cap"
#define AT_NA_NO_LOGIN "no_principal_has_logged_in"

/* ── gather: one bounded read-only dumpstate call ─────────────────────────
 * On success *body_out holds the whole reply object and the caller must
 * json_free() it; `state` is borrowed from inside it.
 *
 * The "did it work" test is `state` being an object, and that is deliberate
 * rather than lazy. node_rpc_call never returns NULL: a transport or cookie
 * failure comes back as {"error":{...}}, an RPC-level failure as a bare
 * string, and an unknown subsystem as an object with no `state`. None of the
 * three carries a state object, so ONE condition rejects all of them, and
 * there is no shape this function could mistake for a successful dump. Every
 * such failure is the same fact to the leaves below — reported as unavailable
 * with a static token, never swallowed. */
/* NULL while the collection may keep reading; AT_WHY_BUDGET once it may not.
 * Threaded through as a `skip` argument rather than consulted inside each
 * gatherer so that the skip is visible at the call site. */
static const char *at_skip_reason(int64_t started_ms)
{
    int64_t elapsed = platform_time_monotonic_ms() - started_ms;
    if (elapsed < 0 || elapsed < AT_WALL_BUDGET_MS)
        return NULL;
    return AT_WHY_BUDGET;
}

static bool at_dump_state(const char *params_json, struct json_value *body_out)
{
    json_init(body_out);
    char *raw = node_rpc_call_deadline("dumpstate", params_json,
                                       AT_CONNECT_MS, AT_TOTAL_MS);
    if (!raw)
        return false;
    bool ok = json_read(body_out, raw, strlen(raw)) &&
              body_out->type == JSON_OBJ;
    free(raw);
    if (ok) {
        const struct json_value *st = json_get(body_out, "state");
        ok = st && st->type == JSON_OBJ;
    }
    if (!ok)
        json_free(body_out);
    return ok;
}

/* ── derive: the grant-page aggregate ─────────────────────────────────────
 * Every figure the three groups publish, computed in one pass over one
 * bounded page of grant rows. Nothing here is a JSON key; the field table
 * owns the names. */
struct at_grants {
    bool store_ok;      /* the node answered AND its node.db is open */
    bool node_down;     /* the probe itself did not complete — a flag, not a
                         * `why == AT_WHY_NODE_DOWN` test, because comparing
                         * string literals by address is unspecified */
    const char *why;    /* static token when !store_ok */
    bool enumerated;    /* the grant page itself came back */
    const char *list_why;
    bool clock_ok;

    int64_t total;      /* the node's own agent_sessions row count */
    int64_t seen;       /* rows this call actually enumerated */
    bool truncated;

    int64_t usable, revoked, expired, holders, malformed;
    int64_t any_recipient, never_expire;
    int64_t max_tx, max_window;
    int64_t spent_total, with_spend;

    bool have_oldest;
    int64_t oldest_age;
    bool have_soonest;
    int64_t soonest;
    bool have_permille;
    int64_t permille;
};

/* A row the agent_sessions CHECK constraints and agent_session_validate say
 * cannot exist. session_id is NOT checked: the node redacts it before this
 * process ever sees it, so its length here means nothing. */
static bool at_row_malformed(const struct db_agent_session *r)
{
    if (r->account[0] == '\0')
        return true;
    if (r->window_seconds <= 0 ||
        r->window_seconds > AGENT_SESSION_WINDOW_SECONDS_MAX)
        return true;
    if (r->max_per_tx_zat < 0 || r->max_per_tx_zat > AGENT_SESSION_MAX_ZAT)
        return true;
    if (r->max_per_window_zat < 0 ||
        r->max_per_window_zat > AGENT_SESSION_MAX_ZAT)
        return true;
    if (r->reserve_floor_zat < 0 ||
        r->reserve_floor_zat > AGENT_SESSION_MAX_ZAT)
        return true;
    if (r->spent_in_window_zat < 0 ||
        r->spent_in_window_zat > AGENT_SESSION_MAX_ZAT)
        return true;
    if (r->expires_at < 0)
        return true;
    return r->revoked != 0 && r->revoked != 1;
}

/* Mirrors agent_session_is_usable exactly (models/agent_session.h): revoked
 * loses, expires_at==0 never expires, and expiry is `now >= expires_at`. */
static bool at_row_usable(const struct db_agent_session *r, int64_t now)
{
    if (r->revoked)
        return false;
    return r->expires_at == 0 || now < r->expires_at;
}

/* What the NEXT authorize would see as already spent in the current window.
 * agent_session_authorize rolls the window when
 * `now - window_start >= window_seconds` and zeroes the debit as it does, so
 * a stale row past its roll has effectively spent nothing. Subtraction, never
 * a sum — the same overflow-free comparison the model uses. */
static int64_t at_effective_spend(const struct db_agent_session *r, int64_t now)
{
    if (r->window_seconds > 0 && now - r->window_start_epoch >= r->window_seconds)
        return 0;
    return r->spent_in_window_zat;
}

/* Distinct-account test over the usable rows seen SO FAR. O(n^2) over a page
 * capped at AGENT_SESSION_LIST_MAX (64), so ~4k string compares worst case —
 * bounded by construction, which is why no set structure is warranted. */
static bool at_first_sighting(const struct db_agent_session *rows, int upto,
                              int64_t now, const char *account)
{
    for (int j = 0; j < upto; j++) {
        if (!at_row_usable(&rows[j], now))
            continue;
        if (strcmp(rows[j].account, account) == 0)
            return false;
    }
    return true;
}

static void at_scan(const struct db_agent_session *rows, int n, int64_t now,
                    struct at_grants *g)
{
    for (int i = 0; i < n; i++) {
        const struct db_agent_session *r = &rows[i];
        if (at_row_malformed(r))
            g->malformed++;
        if (r->revoked) {
            g->revoked++;
            continue;
        }
        if (r->expires_at != 0 && now >= r->expires_at) {
            g->expired++;
            continue;
        }
        g->usable++;
        if (at_first_sighting(rows, i, now, r->account))
            g->holders++;
        if (r->recipient_allowlist[0] == '\0')
            g->any_recipient++;
        if (r->expires_at == 0) {
            g->never_expire++;
        } else {
            int64_t left = r->expires_at - now;
            if (left < 0)
                left = 0;
            if (!g->have_soonest || left < g->soonest) {
                g->have_soonest = true;
                g->soonest = left;
            }
        }
        if (r->max_per_tx_zat > g->max_tx)
            g->max_tx = r->max_per_tx_zat;
        if (r->max_per_window_zat > g->max_window)
            g->max_window = r->max_per_window_zat;
        if (r->created_at > 0) {
            int64_t age = now - r->created_at;
            if (age < 0)
                age = 0;
            if (!g->have_oldest || age > g->oldest_age) {
                g->have_oldest = true;
                g->oldest_age = age;
            }
        }
        int64_t spent = at_effective_spend(r, now);
        g->spent_total += spent;
        if (spent > 0)
            g->with_spend++;
        if (r->max_per_window_zat > 0) {
            int64_t pm = (spent / r->max_per_window_zat) * 1000 +
                         ((spent % r->max_per_window_zat) * 1000) /
                             r->max_per_window_zat;
            if (pm > 1000)
                pm = 1000;
            if (!g->have_permille || pm > g->permille) {
                g->have_permille = true;
                g->permille = pm;
            }
        }
    }
}

/* ── gather: the grant page ───────────────────────────────────────────── */

static void at_gather_grants(struct at_grants *g, int64_t now,
                             int64_t started_ms)
{
    struct json_value body;
    if (!at_dump_state("[\"agent_sessions\"]", &body)) {
        g->node_down = true;
        g->why = AT_WHY_NODE_DOWN;
        g->list_why = AT_WHY_NODE_DOWN;
        return;
    }
    const struct json_value *st = json_get(&body, "state");
    bool db_open = json_get_bool(json_get(st, "db_open"));
    g->total = json_get_int(json_get(st, "count"));
    json_free(&body);
    if (!db_open) {
        g->why = AT_WHY_DB_CLOSED;
        g->list_why = AT_WHY_DB_CLOSED;
        g->total = 0;
        return;
    }
    g->store_ok = true;

    const char *skip = at_skip_reason(started_ms);
    if (skip) {
        g->list_why = skip;
        return;
    }

    struct db_agent_session *rows =
        zcl_malloc(sizeof(*rows) * AGENT_SESSION_LIST_MAX,
                   "agents telemetry grant page");
    if (!rows) {
        g->list_why = AT_WHY_ALLOC;
        LOG_ERROR(AT_TAG, "grant page allocation failed (%d rows)",
                  AGENT_SESSION_LIST_MAX);
        return;
    }
    char why[64] = { 0 };
    int n = agent_session_client_list(NULL, rows, AGENT_SESSION_LIST_MAX, why,
                                      sizeof(why));
    if (n < 0) {
        free(rows);
        g->list_why = AT_WHY_STORE;
        LOG_ERROR(AT_TAG, "grant enumeration refused: %s",
                  why[0] ? why : "(no token)");
        return;
    }
    g->enumerated = true;
    g->seen = n;
    /* The page cap and the node's own count are two different numbers; when
     * they disagree every derived figure below is a floor, and scan_truncated
     * is what says so rather than the reply quietly understating. */
    g->truncated = g->total > (int64_t)n;
    if (g->clock_ok)
        at_scan(rows, n, now, g);
    free(rows);
}

/* ── publish: sessions ────────────────────────────────────────────────── */

/* A count that is real but computed over a PREFIX of its table is TRUNCATED,
 * not PRESENT: the bytes are honest, the total is not, and a reader deciding
 * whether a cap is the widest one on the node needs to know which it got.
 * `trunc_why` NULL means the figure is whole. There is no TELEMETRY_SET_
 * macro for this because the contract's setters only mint PRESENT. */
#define AT_TRUNC_GRANTS "grant_page_capped"
#define AT_TRUNC_PRINCIPALS "principal_page_capped"

static void at_set_count(int64_t *slot, struct telemetry_leaf_meta *meta,
                         int64_t value, const char *trunc_why)
{
    *slot = value;
    *meta = (struct telemetry_leaf_meta){
        .presence = trunc_why ? TELEMETRY_TRUNCATED : TELEMETRY_PRESENT,
        .source = TELEMETRY_SRC_DURABLE_STORE,
        .observed_unix = telemetry_now_unix(),
        .age_ms = 0,
        .reason = trunc_why ? trunc_why : "" };
}

#define AT_COUNT(snap_, m_, v_, trunc_why_) \
    at_set_count(&(snap_)->m_, &(snap_)->m_##_meta, (int64_t)(v_), \
                 (trunc_why_))

static void at_fill_sessions(struct agents_snapshot *snap,
                             const struct at_grants *g)
{
    TELEMETRY_SET_BOOL(snap, store_readable, g->store_ok,
                       TELEMETRY_SRC_DERIVED);

    const char *tg = g->truncated ? AT_TRUNC_GRANTS : NULL;

    if (!g->store_ok) {
        const char *why = g->why ? g->why : AT_WHY_STORE;
        TELEMETRY_UNAVAILABLE_LEAF(snap, sessions_total, why);
    } else {
        /* The node counted its own table, so this one figure is whole even
         * when the page below it was capped. */
        AT_COUNT(snap, sessions_total, g->total, NULL);
    }

    if (!g->enumerated) {
        const char *why = g->list_why ? g->list_why : AT_WHY_STORE;
        TELEMETRY_UNAVAILABLE_LEAF(snap, sessions_usable, why);
        TELEMETRY_UNAVAILABLE_LEAF(snap, sessions_revoked, why);
        TELEMETRY_UNAVAILABLE_LEAF(snap, sessions_expired, why);
        TELEMETRY_UNAVAILABLE_LEAF(snap, session_holders, why);
        TELEMETRY_UNAVAILABLE_LEAF(snap, oldest_session_age_seconds, why);
        TELEMETRY_UNAVAILABLE_LEAF(snap, scan_truncated, why);
        TELEMETRY_UNAVAILABLE_LEAF(snap, malformed_rows, why);
        return;
    }
    if (!g->clock_ok) {
        /* Without a wall clock, "revoked" is still readable but every
         * expiry-dependent classification is a guess. Say so per leaf. */
        TELEMETRY_UNAVAILABLE_LEAF(snap, sessions_usable, AT_WHY_CLOCK);
        AT_COUNT(snap, sessions_revoked, g->revoked, tg);
        TELEMETRY_UNAVAILABLE_LEAF(snap, sessions_expired, AT_WHY_CLOCK);
        TELEMETRY_UNAVAILABLE_LEAF(snap, session_holders, AT_WHY_CLOCK);
        TELEMETRY_UNAVAILABLE_LEAF(snap, oldest_session_age_seconds,
                                   AT_WHY_CLOCK);
        TELEMETRY_SET_BOOL(snap, scan_truncated, g->truncated,
                           TELEMETRY_SRC_DERIVED);
        AT_COUNT(snap, malformed_rows, g->malformed, tg);
        return;
    }
    AT_COUNT(snap, sessions_usable, g->usable, tg);
    AT_COUNT(snap, sessions_revoked, g->revoked, tg);
    AT_COUNT(snap, sessions_expired, g->expired, tg);
    AT_COUNT(snap, session_holders, g->holders, tg);
    AT_COUNT(snap, malformed_rows, g->malformed, tg);
    TELEMETRY_SET_BOOL(snap, scan_truncated, g->truncated,
                       TELEMETRY_SRC_DERIVED);
    if (g->have_oldest)
        AT_COUNT(snap, oldest_session_age_seconds, g->oldest_age, tg);
    else
        TELEMETRY_NOT_APPLICABLE_LEAF(snap, oldest_session_age_seconds,
                                      AT_NA_NO_USABLE);
}

/* ── publish: grants ──────────────────────────────────────────────────── */

static void at_fill_grants(struct agents_snapshot *snap,
                           const struct at_grants *g)
{
    if (!g->enumerated || !g->clock_ok) {
        const char *why = !g->enumerated
                              ? (g->list_why ? g->list_why : AT_WHY_STORE)
                              : AT_WHY_CLOCK;
        TELEMETRY_UNAVAILABLE_LEAF(snap, grants_any_recipient, why);
        TELEMETRY_UNAVAILABLE_LEAF(snap, grants_never_expire, why);
        TELEMETRY_UNAVAILABLE_LEAF(snap, max_per_tx_zat_highest, why);
        TELEMETRY_UNAVAILABLE_LEAF(snap, max_per_window_zat_highest, why);
        TELEMETRY_UNAVAILABLE_LEAF(snap, soonest_expiry_seconds, why);
        return;
    }
    const char *tg = g->truncated ? AT_TRUNC_GRANTS : NULL;
    AT_COUNT(snap, grants_any_recipient, g->any_recipient, tg);
    AT_COUNT(snap, grants_never_expire, g->never_expire, tg);
    if (g->usable > 0) {
        AT_COUNT(snap, max_per_tx_zat_highest, g->max_tx, tg);
        AT_COUNT(snap, max_per_window_zat_highest, g->max_window, tg);
    } else {
        TELEMETRY_NOT_APPLICABLE_LEAF(snap, max_per_tx_zat_highest,
                                      AT_NA_NO_USABLE);
        TELEMETRY_NOT_APPLICABLE_LEAF(snap, max_per_window_zat_highest,
                                      AT_NA_NO_USABLE);
    }
    if (g->have_soonest)
        AT_COUNT(snap, soonest_expiry_seconds, g->soonest, tg);
    else
        TELEMETRY_NOT_APPLICABLE_LEAF(snap, soonest_expiry_seconds,
                                      AT_NA_NO_EXPIRY);
}

/* ── publish: activity ────────────────────────────────────────────────── */

/* The identity half of the activity picture. The principals dumper returns a
 * true `count` alongside a page of at most 50 rows, so the two login figures
 * are marked TRUNCATED whenever the count exceeds the page. */
struct at_people {
    bool ok;
    bool paged;
    int64_t total;
    int64_t ever_logged_in;
    bool have_last;
    int64_t last_login;
};

static void at_gather_people(struct at_people *p, const char *skip)
{
    if (skip)
        return;
    struct json_value body;
    if (!at_dump_state("[\"principals\"]", &body))
        return;
    const struct json_value *st = json_get(&body, "state");
    if (!json_get_bool(json_get(st, "db_open"))) {
        json_free(&body);
        return;
    }
    p->ok = true;
    p->total = json_get_int(json_get(st, "count"));
    const struct json_value *arr = json_get(st, "principals");
    size_t n = (arr && arr->type == JSON_ARR) ? arr->num_children : 0;
    p->paged = p->total > (int64_t)n;
    for (size_t i = 0; i < n; i++) {
        int64_t last = json_get_int(json_get(json_at(arr, i), "last_login"));
        if (last <= 0)
            continue;
        p->ever_logged_in++;
        if (!p->have_last || last > p->last_login) {
            p->have_last = true;
            p->last_login = last;
        }
    }
    json_free(&body);
}

static void at_fill_people(struct agents_snapshot *snap,
                           const struct at_people *p, int64_t now,
                           bool clock_ok, const char *skip)
{
    if (!p->ok) {
        const char *why = skip ? skip : AT_WHY_PRINCIPALS;
        TELEMETRY_UNAVAILABLE_LEAF(snap, principals_total, why);
        TELEMETRY_UNAVAILABLE_LEAF(snap, principals_ever_logged_in, why);
        TELEMETRY_UNAVAILABLE_LEAF(snap, last_login_age_seconds, why);
        return;
    }
    const char *tp = p->paged ? AT_TRUNC_PRINCIPALS : NULL;
    /* The registry's own count is whole; the two login figures are derived
     * from the ≤50-row page the dumper returns, so they are floors. */
    AT_COUNT(snap, principals_total, p->total, NULL);
    AT_COUNT(snap, principals_ever_logged_in, p->ever_logged_in, tp);
    if (!p->have_last) {
        TELEMETRY_NOT_APPLICABLE_LEAF(snap, last_login_age_seconds,
                                      AT_NA_NO_LOGIN);
    } else if (!clock_ok) {
        TELEMETRY_UNAVAILABLE_LEAF(snap, last_login_age_seconds, AT_WHY_CLOCK);
    } else {
        int64_t age = now - p->last_login;
        if (age < 0)
            age = 0;
        AT_COUNT(snap, last_login_age_seconds, age, tp);
    }
}

static void at_fill_spend(struct agents_snapshot *snap,
                          const struct at_grants *g)
{
    if (!g->enumerated || !g->clock_ok) {
        const char *why = !g->enumerated
                              ? (g->list_why ? g->list_why : AT_WHY_STORE)
                              : AT_WHY_CLOCK;
        TELEMETRY_UNAVAILABLE_LEAF(snap, window_spent_zat_total, why);
        TELEMETRY_UNAVAILABLE_LEAF(snap, grants_with_spend, why);
        TELEMETRY_UNAVAILABLE_LEAF(snap, window_used_permille_worst, why);
        return;
    }
    const char *tg = g->truncated ? AT_TRUNC_GRANTS : NULL;
    AT_COUNT(snap, window_spent_zat_total, g->spent_total, tg);
    AT_COUNT(snap, grants_with_spend, g->with_spend, tg);
    if (g->have_permille)
        AT_COUNT(snap, window_used_permille_worst, g->permille, tg);
    else
        TELEMETRY_NOT_APPLICABLE_LEAF(snap, window_used_permille_worst,
                                      AT_NA_NO_CAP);
}

static void at_fill_auth(struct agents_snapshot *snap, const char *skip)
{
    if (skip) {
        TELEMETRY_UNAVAILABLE_LEAF(snap, auth_challenges_pending, skip);
        return;
    }
    struct json_value body;
    if (!at_dump_state("[\"auth\"]", &body)) {
        TELEMETRY_UNAVAILABLE_LEAF(snap, auth_challenges_pending, AT_WHY_AUTH);
        return;
    }
    const struct json_value *st = json_get(&body, "state");
    if (!json_get_bool(json_get(st, "db_open"))) {
        json_free(&body);
        TELEMETRY_UNAVAILABLE_LEAF(snap, auth_challenges_pending,
                                   AT_WHY_DB_CLOSED);
        return;
    }
    /* The auth dumper publishes only db_open and an unconsumed-nonce count —
     * no nonce, no address. Nothing more from this subsystem may be copied
     * into a leaf; it is one read away from login material. */
    AT_COUNT(snap, auth_challenges_pending,
             json_get_int(json_get(st, "pending")), NULL);
    json_free(&body);
}

static void at_fill_backtrace(struct agents_snapshot *snap, const char *skip)
{
    if (skip) {
        TELEMETRY_UNAVAILABLE_LEAF(snap, backtrace_handler_armed, skip);
        TELEMETRY_UNAVAILABLE_LEAF(snap, backtrace_dumps_total, skip);
        return;
    }
    struct json_value body;
    if (!at_dump_state("[\"self_backtrace\"]", &body)) {
        TELEMETRY_UNAVAILABLE_LEAF(snap, backtrace_handler_armed,
                                   AT_WHY_BACKTRACE);
        TELEMETRY_UNAVAILABLE_LEAF(snap, backtrace_dumps_total,
                                   AT_WHY_BACKTRACE);
        return;
    }
    const struct json_value *st = json_get(&body, "state");
    TELEMETRY_SET_BOOL(snap, backtrace_handler_armed,
                       json_get_bool(json_get(st, "installed")),
                       TELEMETRY_SRC_IN_PROCESS);
    AT_COUNT(snap, backtrace_dumps_total,
             json_get_int(json_get(st, "dump_count")), NULL);
    json_free(&body);
}

/* ── the collector ────────────────────────────────────────────────────── */

void agents_dump_state_fill(struct agents_snapshot *snap)
{
    if (!snap) {
        LOG_ERROR(AT_TAG, "fill: snapshot is NULL");
        return;
    }

    int64_t started_ms = platform_time_monotonic_ms();
    int64_t now = telemetry_now_unix();
    bool clock_ok = now > 0;
    if (clock_ok)
        TELEMETRY_SET_I64(snap, collected_unix, now, TELEMETRY_SRC_DERIVED);
    else
        TELEMETRY_UNAVAILABLE_LEAF(snap, collected_unix, AT_WHY_CLOCK);

    struct at_grants g;
    memset(&g, 0, sizeof(g));
    g.clock_ok = clock_ok;
    at_gather_grants(&g, now, started_ms);

    at_fill_sessions(snap, &g);
    at_fill_grants(snap, &g);
    at_fill_spend(snap, &g);

    /* Two reasons to stop reading, both of which still REPORT every remaining
     * leaf rather than leaving it unset. If the first probe could not reach
     * the node, the next three reads would each pay the same connect timeout
     * to learn the same fact. If the wall budget is gone, continuing would
     * push a leaf declared FOREGROUND past its bucket for data the caller can
     * re-ask for. */
    const char *skip = g.node_down ? AT_WHY_NODE_DOWN
                                   : at_skip_reason(started_ms);

    struct at_people people;
    memset(&people, 0, sizeof(people));
    at_gather_people(&people, skip);
    at_fill_people(snap, &people, now, clock_ok, skip);
    at_fill_auth(snap, skip ? skip : at_skip_reason(started_ms));
    at_fill_backtrace(snap, skip ? skip : at_skip_reason(started_ms));
}
