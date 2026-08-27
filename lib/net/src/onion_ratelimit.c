/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Onion-service request admission — see net/onion_ratelimit.h for the
 * design rationale and the threat it closes. This file owns:
 *   1. onion_route_classify() — the audited STATIC/CHEAP/EXPENSIVE table
 *   2. three independent per-second budgets
 *   3. sustained-pressure escalation on the EXPENSIVE budget
 *   4. the route-bound client puzzle (net/puzzle.h) applied only while
 *      escalated
 *   5. dumpstate telemetry
 *
 * All state here is transient / process-local, exactly like the global
 * rate-limit counter it replaces — never written to progress.kv, never a
 * consensus predicate. */

#include "platform/time_compat.h"
#include "net/onion_ratelimit.h"
#include "net/site_routes.h"
#include "net/puzzle.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "util/log_json.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Route classification table ───────────────────────────────────────
 *
 * The app MVC mounts classify from the rows of net/site_routes.def — the
 * single inventory the onion dispatch chain, the HTTPS dispatch chain,
 * both site navs, AND this classifier all expand. Every new app route
 * MUST be a row there; never add a parallel route table here.
 *
 * The hand-written remainder below is what a per-row class cannot
 * express — exact-match STATIC assets, the method-sensitive store POST
 * special, and the free-text search prefixes — audited against
 * onion_service_handle_request() (lib/net/src/onion_service.c) and the
 * controllers it delegates to. A trailing "..." means "any suffix".
 *
 *   PATH                              TIER       WHY
 *   ────────────────────────────────  ─────────  ──────────────────────
 *   /                                 STATIC     landing page; one
 *                                                 bounded SELECT for the
 *                                                 header stats
 *   /status                           STATIC     JSON, bounded SELECTs
 *   /favicon.ico,                     STATIC     fixed asset, no DB
 *   /explorer/style.css,
 *   /explorer/favicon.png
 *   /search...                        EXPENSIVE  free-text scan over the
 *                                                 peer directory
 *   /explorer/search...               EXPENSIVE  free-text scan across
 *                                                 blocks/tx/address/token
 *   /store/orders (POST),             EXPENSIVE  MINTS a Sapling
 *   /store/buy/...                               z-address + writes an
 *                                                 `orders` row
 *   /n/...                            EXPENSIVE  (def row names_gateway)
 *                                                 the ZCL Names gateway:
 *                                                 with the operator opt-in
 *                                                 ZCL_NAMES_ONION_GATEWAY
 *                                                 on, this DIALS a
 *                                                 third-party onion on an
 *                                                 anonymous visitor's
 *                                                 behalf and blocks the
 *                                                 serving thread for up to
 *                                                 NAME_GATEWAY_TIMEOUT_SECS.
 *                                                 Classified EXPENSIVE
 *                                                 unconditionally rather
 *                                                 than "only when the flag
 *                                                 is set": this file is
 *                                                 lib/, it must not read
 *                                                 app/ policy (gate #14
 *                                                 layering), and
 *                                                 over-limiting is the
 *                                                 fail-safe direction for
 *                                                 a DoS guard. With the
 *                                                 gateway off the cost is
 *                                                 a name redirect served
 *                                                 from the 20/s budget
 *                                                 instead of the 100/s
 *                                                 one. /names (the browse
 *                                                 and profile pages) is
 *                                                 NOT this prefix and
 *                                                 stays CHEAP (def row
 *                                                 names).
 *   /directory.json, /directory       CHEAP      bounded SELECT, LIMIT
 *   /explorer/..., shortcuts          CHEAP      dashboards, listings,
 *   (/stats,/tokens,/hodl,/events,               and single-key indexed
 *   /factoids,/market,/swaps,                    lookups (chrome)
 *   /messages), /wallet
 *   every other def row               CHEAP      /blog..., /store...
 *                                                 (GET), /names...,
 *                                                 /zcode...,
 *                                                 /metaverse...,
 *                                                 /yardsale...: bounded
 *                                                 listings and single-key
 *                                                 indexed lookups
 *   the REST API prefix               UNREACHABLE onion dispatch only
 *                                                 forwards "/explorer" or
 *                                                 a canonical shortcut to
 *                                                 explorer_handle_request,
 *                                                 neither of which
 *                                                 produces the REST
 *                                                 prefix.
 *
 * Anything not positively matched defaults CHEAP. A new route that mints,
 * writes, or scans must be classified EXPENSIVE — by its def row's cost
 * column when the whole prefix is expensive, or by a hand-written special
 * below when the trigger is method- or sub-path-sensitive. That is
 * fail-open toward review, not a silent hole: an unclassified expensive
 * route still degrades behind the CHEAP budget, it is just not eligible
 * for puzzle escalation until it is classified. */

static bool path_prefix(const char *path, const char *prefix, size_t plen)
{
    return path && strncmp(path, prefix, plen) == 0;
}

enum onion_route_class onion_route_classify(const char *method,
                                            const char *path,
                                            char route_key_out[32])
{
    if (route_key_out) route_key_out[0] = '\0';
    if (!path) return ONION_ROUTE_STATIC; /* NULL becomes "/" downstream */

    /* EXPENSIVE: free-text hostname search. Prefix-matches exactly the way
     * onion_service_handle_request() itself dispatches "/search", so
     * classification can never disagree with routing. */
    if (path_prefix(path, "/search", 7)) {
        if (route_key_out) snprintf(route_key_out, 32, "search-hostname");
        return ONION_ROUTE_EXPENSIVE;
    }

    /* EXPENSIVE: free-text block/tx/address/token search. */
    if (path_prefix(path, "/explorer/search", 16)) {
        if (route_key_out) snprintf(route_key_out, 32, "search-explorer");
        return ONION_ROUTE_EXPENSIVE;
    }

    /* EXPENSIVE: order creation — mints a z-address and writes a row.
     * store_controller.c ALSO runs its own unconditional product-bound
     * gate on this path (store_controller_pow.c). The two are
     * complementary: that one prices the mint per product whatever the
     * load, this one protects the shared listener budget under flood. */
    if (method && strcmp(method, "POST") == 0 &&
        (strcmp(path, "/store/orders") == 0 ||
         strcmp(path, "/store/orders/") == 0 ||
         path_prefix(path, "/store/buy/", 11))) {
        if (route_key_out) snprintf(route_key_out, 32, "store-order");
        return ONION_ROUTE_EXPENSIVE;
    }

    /* STATIC: the pages and assets that must stay reachable no matter what
     * the other tiers are doing — including the node's own error pages. */
    if (strcmp(path, "/") == 0 ||
        strcmp(path, "/status") == 0 ||
        strcmp(path, "/favicon.ico") == 0 ||
        strcmp(path, "/explorer/style.css") == 0 ||
        strcmp(path, "/explorer/favicon.png") == 0)
        return ONION_ROUTE_STATIC;

    /* App MVC mounts — the rows of net/site_routes.def, prefix-matched in
     * dispatch order, exactly the way onion_service_handle_request()
     * dispatches them, so classification can never disagree with routing.
     * Only an EXPENSIVE row carries a route key (names_gateway today). */
#define SITE_ROUTE(id, prefix, handler, flavor, methods, cost, rkey, \
                   nav_app, nav_onion, grid, nav_label, nav_href, nav_id, \
                   grid_desc, fail_body, app_id) \
    if (path_prefix(path, prefix, sizeof(prefix) - 1)) { \
        if (route_key_out && (rkey)[0]) \
            snprintf(route_key_out, 32, "%s", rkey); \
        return cost; \
    }
#include "net/site_routes.def"
#undef SITE_ROUTE

    return ONION_ROUTE_CHEAP;
}

/* ── Per-tier budgets ──────────────────────────────────────────────────
 *
 * Same per-second-window counter shape as the global limiter this
 * replaces: a fresh window seeds the counter at 1 and the fetch_add below
 * also increments, so a budget trips one request early. That conservative
 * bias is intentional — over-limiting is the fail-safe direction for a
 * DoS guard. Do not "fix" it toward exact-N without re-reading that
 * history. */

/* STATIC: deliberately far above the legacy global cap. These responses
 * are a snprintf into a stack buffer; the budget exists to bound absurd
 * volume, not to ration honest browsing. */
#define ONION_STATIC_MAX_REQUESTS_PER_SECOND 400

/* CHEAP: matches the legacy global cap, so honest browsing pays nothing
 * extra versus the single-bucket limiter. */
#define ONION_CHEAP_MAX_REQUESTS_PER_SECOND 100

/* EXPENSIVE: a fifth of CHEAP. Mint/write/scan paths cost real CPU and
 * disk per admitted request; a tighter cap bounds the worst case while
 * still leaving a handful of concurrent honest searches or orders before
 * either the budget or the puzzle engages. */
#define ONION_EXPENSIVE_MAX_REQUESTS_PER_SECOND 20

/* Escalate once the EXPENSIVE budget has been fully spent for this many
 * CONSECUTIVE one-second windows — i.e. a sustained flood, not one burst. */
#define ONION_ESCALATE_SUSTAIN_SECS 5

/* De-escalate only after this many consecutive windows come in under half
 * the cap. Longer than the escalate threshold on purpose: hysteresis, so
 * an attacker alternating flood and pause cannot cheaply toggle the
 * puzzle requirement off and time its bursts to the free windows. */
#define ONION_DEESCALATE_CLEAR_SECS 15

struct onion_budget {
    _Atomic int64_t count;
    _Atomic int64_t window_start;
    _Atomic int64_t admitted_total;
    _Atomic int64_t denied_total;
    _Atomic int32_t saturated_streak; /* consecutive whole seconds at cap  */
    _Atomic int32_t clear_streak;     /* consecutive whole seconds < cap/2 */
};

static struct onion_budget g_static_budget = {0};
static struct onion_budget g_cheap_budget = {0};
static struct onion_budget g_expensive_budget = {0};

static _Atomic bool g_expensive_escalated = false;
static _Atomic int64_t g_escalate_total = 0;
static _Atomic int64_t g_deescalate_total = 0;
static _Atomic int64_t g_puzzle_required_total = 0;
static _Atomic int64_t g_puzzle_passed_total = 0;
static _Atomic int64_t g_puzzle_failed_total = 0;

/* The EXPENSIVE tier's puzzle gate. One instance, route-bound per
 * request via the peer token, so difficulty responds to total expensive
 * pressure rather than per-route pressure — an attacker cannot dodge the
 * ramp by spreading a flood across route classes.
 *
 * Policy notes, all in the "never lock out a slow honest operator"
 * direction:
 *   - the floor is the default 12 bits (~4k hashes, sub-millisecond even
 *     in browser JS);
 *   - the ceiling is lowered from the primitive's 26 to 22 (~4M hashes,
 *     a few seconds in JS) because a human with a browser is the client
 *     here, not a sync peer with a C solver;
 *   - the seed epoch is widened from 45s to 120s, so with the primitive's
 *     one-epoch grace a challenge stays solvable for up to four minutes —
 *     comfortably longer than a slow Tor round trip plus a slow solve. */
static struct puzzle_gate g_onion_puzzle_gate;

static const struct puzzle_policy g_onion_puzzle_policy = {
    .max_bits = 22,
    .seed_rotate_secs = 120,
};

static pthread_once_t g_onion_puzzle_once = PTHREAD_ONCE_INIT;

static void onion_puzzle_gate_init_once(void)
{
    puzzle_gate_init(&g_onion_puzzle_gate, &g_onion_puzzle_policy);
}

static void onion_puzzle_gate_ready(void)
{
    /* puzzle_gate_* self-initialize on first use, but that default init
     * would install the default policy. Install ours exactly once.
     *
     * pthread_once, not a compare-exchange flag: the flag version published
     * "initialized" BEFORE puzzle_gate_init() had run, so a second thread
     * arriving in that window fell through to the gate's own lazy
     * ensure_init and raced puzzle_gate_init() on the same mutex — two
     * pthread_mutex_init() calls on one mutex, and the default policy
     * possibly winning over ours. pthread_once blocks the second thread
     * until the initializer has completed. */
    pthread_once(&g_onion_puzzle_once, onion_puzzle_gate_init_once);
}

/* Called once per completed one-second window on the EXPENSIVE budget,
 * with the count that window finished at. Drives the escalate /
 * de-escalate state machine and logs every transition — escalation is
 * never silent. */
static void onion_pressure_update(int64_t prev_window_count)
{
    const int cap = ONION_EXPENSIVE_MAX_REQUESTS_PER_SECOND;
    bool prev_saturated = prev_window_count >= cap;
    bool prev_clear = prev_window_count < (cap / 2);

    if (prev_saturated) {
        atomic_fetch_add(&g_expensive_budget.saturated_streak, 1);
        atomic_store(&g_expensive_budget.clear_streak, 0);
    } else {
        atomic_store(&g_expensive_budget.saturated_streak, 0);
        if (prev_clear)
            atomic_fetch_add(&g_expensive_budget.clear_streak, 1);
        else
            atomic_store(&g_expensive_budget.clear_streak, 0);
    }

    bool escalated = atomic_load(&g_expensive_escalated);
    if (!escalated &&
        atomic_load(&g_expensive_budget.saturated_streak) >=
            ONION_ESCALATE_SUSTAIN_SECS) {
        atomic_store(&g_expensive_escalated, true);
        atomic_fetch_add(&g_escalate_total, 1);
        atomic_store(&g_expensive_budget.saturated_streak, 0);
        /* Hold the gate's concurrency term for the whole escalated period.
         * The gate's own EWMA prices repeat solvers — it only counts
         * requests that got through — so without this the very first
         * escalated challenge would still be issued at the idle floor.
         * The escalated flag makes begin/end strictly alternating. */
        onion_puzzle_gate_ready();
        puzzle_gate_serve_begin(&g_onion_puzzle_gate);
        log_jsonf(LOG_JSON_WARN, "onion_puzzle_escalate",
                  "\"reason\":\"expensive budget saturated\","
                  "\"cap_per_sec\":%d,\"sustain_secs\":%d",
                  cap, ONION_ESCALATE_SUSTAIN_SECS);
    } else if (escalated &&
               atomic_load(&g_expensive_budget.clear_streak) >=
                   ONION_DEESCALATE_CLEAR_SECS) {
        atomic_store(&g_expensive_escalated, false);
        atomic_fetch_add(&g_deescalate_total, 1);
        atomic_store(&g_expensive_budget.clear_streak, 0);
        onion_puzzle_gate_ready();
        puzzle_gate_serve_end(&g_onion_puzzle_gate);
        log_jsonf(LOG_JSON_INFO, "onion_puzzle_deescalate",
                  "\"reason\":\"expensive budget clear\",\"clear_secs\":%d",
                  ONION_DEESCALATE_CLEAR_SECS);
    }
}

static bool budget_check(struct onion_budget *b, int cap, bool track_pressure)
{
    int64_t now = (int64_t)platform_time_wall_time_t();
    int64_t window = atomic_load(&b->window_start);
    if (now != window) {
        if (atomic_compare_exchange_strong(&b->window_start, &window, now)) {
            int64_t prev_count = atomic_exchange(&b->count, 1);
            if (track_pressure)
                onion_pressure_update(prev_count);
            atomic_fetch_add(&b->admitted_total, 1);
            return true;
        }
    }
    int64_t count = atomic_fetch_add(&b->count, 1);
    bool admitted = count < cap;
    atomic_fetch_add(admitted ? &b->admitted_total : &b->denied_total, 1);
    return admitted;
}

/* ── Route-bound puzzle (escalated state only) ────────────────────────
 *
 * The peer token binds a solution to one route class, so a puzzle solved
 * for /search cannot be presented on a store order. Everything else —
 * the rotating server-issued seed, the adaptive difficulty, the
 * single-use ring, the timestamp skew — belongs to struct puzzle_gate. */

static void onion_route_token(const char *route_key, uint8_t out[32])
{
    char ctx[64];
    snprintf(ctx, sizeof(ctx), "onion:expensive:pow:%s",
             (route_key && route_key[0]) ? route_key : "unknown");
    sha3_256((const unsigned char *)ctx, strlen(ctx), out);
}

static void hex32(const uint8_t in[32], char out[65])
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        out[i * 2]     = hex[(in[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[in[i] & 0x0f];
    }
    out[64] = '\0';
}

static void onion_fill_challenge(const char *route_key,
                                 struct onion_pow_challenge *out)
{
    uint8_t seed[32], token[32];
    int bits = 0;
    int64_t server_time = 0;

    onion_puzzle_gate_ready();
    puzzle_gate_challenge(&g_onion_puzzle_gate, seed, &bits, &server_time);
    onion_route_token(route_key, token);
    hex32(seed, out->seed_hex);
    hex32(token, out->token_hex);
    out->bits = bits;
    out->server_time = server_time;
}

/* Scan `hay[0..hay_len)` for a `key=value` field delimited by `&`, `?`,
 * space, or the buffer boundary — the same shape store_controller.c uses
 * for query/form fields, kept local so lib/net has no dependency on
 * app/controllers. pow_ts/pow_nonce are always plain decimal digits, so
 * no percent or `+` decoding is needed. */
static bool extract_param(const char *hay, size_t hay_len, const char *key,
                          char *out, size_t out_max)
{
    if (!hay || !hay_len || !key || !out || !out_max)
        return false; // raw-return-ok:absent-input-not-a-server-error
    size_t klen = strlen(key);
    if (klen == 0 || klen + 1 > hay_len)
        return false; // raw-return-ok:key-cannot-fit-not-a-server-error

    for (size_t i = 0; i + klen < hay_len; i++) {
        bool at_boundary = (i == 0 || hay[i - 1] == '&' || hay[i - 1] == '?');
        if (!at_boundary) continue;
        if (memcmp(hay + i, key, klen) != 0) continue;
        if (hay[i + klen] != '=') continue;

        size_t vstart = i + klen + 1;
        size_t vlen = 0;
        while (vstart + vlen < hay_len && hay[vstart + vlen] != '&' &&
               hay[vstart + vlen] != ' ' && hay[vstart + vlen] != '\0')
            vlen++;
        if (vlen == 0 || vlen >= out_max)
            return false; // raw-return-ok:empty-or-oversized-value-not-a-server-error
        memcpy(out, hay + vstart, vlen);
        out[vlen] = '\0';
        return true;
    }
    return false; // raw-return-ok:field-absent-not-a-server-error
}

static bool onion_puzzle_present(const char *route_key,
                                 const char *pow_ts_str,
                                 const char *pow_nonce_str)
{
    uint8_t token[32];
    char *end = NULL;
    long long ts;
    unsigned long long nonce;

    if (!pow_ts_str || !pow_ts_str[0] || !pow_nonce_str || !pow_nonce_str[0])
        return false; // raw-return-ok:missing-puzzle-fields-refused-not-a-server-error

    ts = strtoll(pow_ts_str, &end, 10);
    if (!end || *end != '\0')
        return false; // raw-return-ok:malformed-client-field-not-a-server-error
    end = NULL;
    nonce = strtoull(pow_nonce_str, &end, 10);
    if (!end || *end != '\0')
        return false; // raw-return-ok:malformed-client-field-not-a-server-error

    onion_puzzle_gate_ready();
    onion_route_token(route_key, token);
    return puzzle_gate_verify(&g_onion_puzzle_gate, token, (int64_t)ts,
                              (uint64_t)nonce);
}

enum onion_admit_result onion_ratelimit_admit(
    const char *method, const char *path,
    const uint8_t *body, size_t body_len,
    struct onion_pow_challenge *challenge_out)
{
    char route_key[32] = "";
    enum onion_route_class cls = onion_route_classify(method, path, route_key);

    if (cls == ONION_ROUTE_STATIC) {
        return budget_check(&g_static_budget,
                            ONION_STATIC_MAX_REQUESTS_PER_SECOND, false)
                   ? ONION_ADMIT_OK : ONION_ADMIT_RATE_LIMITED;
    }

    if (cls == ONION_ROUTE_CHEAP) {
        return budget_check(&g_cheap_budget,
                            ONION_CHEAP_MAX_REQUESTS_PER_SECOND, false)
                   ? ONION_ADMIT_OK : ONION_ADMIT_RATE_LIMITED;
    }

    bool budget_admitted = budget_check(&g_expensive_budget,
                                        ONION_EXPENSIVE_MAX_REQUESTS_PER_SECOND,
                                        true);

    if (!atomic_load(&g_expensive_escalated))
        return budget_admitted ? ONION_ADMIT_OK : ONION_ADMIT_RATE_LIMITED;

    /* Escalated: the budget's rejection is not binding — this route is
     * gated by a solved, route-bound, single-use puzzle instead. Two
     * lockout traps this ordering avoids, both structural:
     *   - rejecting on the budget before the puzzle check would let a
     *     flood eat every per-second slot and turn honest solvers away
     *     with a bare 429 before they ever see the challenge that would
     *     admit them;
     *   - skipping the budget for puzzle-less requests would let that
     *     same flood read as quiet and flap the hysteresis. Feeding the
     *     budget on every escalated attempt keeps the saturation windows
     *     honest. */
    atomic_fetch_add(&g_puzzle_required_total, 1);

    char ts_str[32] = "", nonce_str[32] = "";
    size_t path_len = path ? strlen(path) : 0;
    bool have = extract_param(path, path_len, "pow_ts", ts_str, sizeof(ts_str)) &&
                extract_param(path, path_len, "pow_nonce", nonce_str,
                              sizeof(nonce_str));
    if (!have && body && body_len) {
        have = extract_param((const char *)body, body_len, "pow_ts",
                             ts_str, sizeof(ts_str)) &&
               extract_param((const char *)body, body_len, "pow_nonce",
                             nonce_str, sizeof(nonce_str));
    }

    if (!have || !onion_puzzle_present(route_key, ts_str, nonce_str)) {
        atomic_fetch_add(&g_puzzle_failed_total, 1);
        if (challenge_out)
            onion_fill_challenge(route_key, challenge_out);
        return ONION_ADMIT_POW_REQUIRED;
    }
    atomic_fetch_add(&g_puzzle_passed_total, 1);
    return ONION_ADMIT_OK;
}

/* ── Telemetry ─────────────────────────────────────────────────────── */

static void push_budget_json(struct json_value *out, const char *key,
                             struct onion_budget *b, int cap)
{
    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_int(&obj, "cap_per_sec", (int64_t)cap);
    json_push_kv_int(&obj, "spent_this_window", atomic_load(&b->count));
    json_push_kv_int(&obj, "admitted_total", atomic_load(&b->admitted_total));
    json_push_kv_int(&obj, "denied_total", atomic_load(&b->denied_total));
    json_push_kv_int(&obj, "saturated_streak_secs",
                     (int64_t)atomic_load(&b->saturated_streak));
    json_push_kv_int(&obj, "clear_streak_secs",
                     (int64_t)atomic_load(&b->clear_streak));
    json_push_kv(out, key, &obj);
    json_free(&obj);
}

bool onion_ratelimit_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false; // raw-return-ok:absent-output-buffer-not-a-server-error
    json_set_object(out);

    push_budget_json(out, "static", &g_static_budget,
                     ONION_STATIC_MAX_REQUESTS_PER_SECOND);
    push_budget_json(out, "cheap", &g_cheap_budget,
                     ONION_CHEAP_MAX_REQUESTS_PER_SECOND);
    push_budget_json(out, "expensive", &g_expensive_budget,
                     ONION_EXPENSIVE_MAX_REQUESTS_PER_SECOND);

    json_push_kv_bool(out, "expensive_escalated",
                      atomic_load(&g_expensive_escalated));
    json_push_kv_int(out, "escalate_total", atomic_load(&g_escalate_total));
    json_push_kv_int(out, "deescalate_total", atomic_load(&g_deescalate_total));
    json_push_kv_int(out, "escalate_sustain_secs", ONION_ESCALATE_SUSTAIN_SECS);
    json_push_kv_int(out, "deescalate_clear_secs", ONION_DEESCALATE_CLEAR_SECS);

    onion_puzzle_gate_ready();
    json_push_kv_int(out, "puzzle_bits_now",
                     (int64_t)puzzle_gate_current_bits(&g_onion_puzzle_gate));
    json_push_kv_int(out, "puzzle_rate_ewma_milli",
                     puzzle_gate_rate_ewma_milli(&g_onion_puzzle_gate));
    json_push_kv_int(out, "puzzle_required_total",
                     atomic_load(&g_puzzle_required_total));
    json_push_kv_int(out, "puzzle_passed_total",
                     atomic_load(&g_puzzle_passed_total));
    json_push_kv_int(out, "puzzle_failed_total",
                     atomic_load(&g_puzzle_failed_total));
    return true;
}

void onion_ratelimit_test_reset(void)
{
    memset(&g_static_budget, 0, sizeof(g_static_budget));
    memset(&g_cheap_budget, 0, sizeof(g_cheap_budget));
    memset(&g_expensive_budget, 0, sizeof(g_expensive_budget));
    atomic_store(&g_expensive_escalated, false);
    atomic_store(&g_escalate_total, 0);
    atomic_store(&g_deescalate_total, 0);
    atomic_store(&g_puzzle_required_total, 0);
    atomic_store(&g_puzzle_passed_total, 0);
    atomic_store(&g_puzzle_failed_total, 0);
    onion_puzzle_gate_ready();
    puzzle_gate_init(&g_onion_puzzle_gate, &g_onion_puzzle_policy);
}

int onion_ratelimit_test_cap(enum onion_route_class cls)
{
    switch (cls) {
    case ONION_ROUTE_STATIC:    return ONION_STATIC_MAX_REQUESTS_PER_SECOND;
    case ONION_ROUTE_CHEAP:     return ONION_CHEAP_MAX_REQUESTS_PER_SECOND;
    case ONION_ROUTE_EXPENSIVE: return ONION_EXPENSIVE_MAX_REQUESTS_PER_SECOND;
    }
    return 0;
}

void onion_ratelimit_test_force_escalated(bool escalated)
{
    atomic_store(&g_expensive_escalated, escalated);
}
