/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Onion-service request admission: cost-tiered rate limiting + an
 * adaptive client puzzle on expensive routes under sustained pressure.
 *
 * The dynhost bridge (core/modules/net/src/onion_service.c) carries only
 * method/path/body across the Tor circuit boundary — no circuit or IP
 * identity reaches the app layer by design. There is therefore no
 * per-client axis to rate-limit on, and a single flat request budget
 * (the global counter this module replaces) let one flooding client
 * exhaust the same budget every honest client shares, on every path.
 *
 * Admission is split into three independent per-second budgets,
 * classified per route (onion_route_classify(), table in
 * onion_ratelimit.c):
 *
 *   STATIC    fixed assets, the landing page, and /status. Generous cap,
 *             never puzzle-gated: the node must always be able to serve
 *             its own front page and its own error pages, whatever is
 *             happening on the other tiers.
 *   CHEAP     bounded single-key DB reads — explorer block/tx/address
 *             pages, the peer directory, store listings, the blog.
 *   EXPENSIVE work that mints keys, writes rows, or runs a free-text
 *             scan. Tightest cap, and the only tier that can escalate.
 *
 * When the EXPENSIVE budget stays saturated for a sustained window, that
 * tier additionally requires a solved client puzzle (net/puzzle.h — the
 * same primitive the file service and snapshot serve use) until pressure
 * clears. The puzzle is route-bound, so a solution for one route class
 * cannot be presented on another, and single-use, so one solution admits
 * one request. Under no pressure there is no puzzle at all: honest UX on
 * expensive paths is unchanged.
 *
 * See docs/DEFENSIVE_CODING.md before touching this file. */

#ifndef ZCL_NET_ONION_RATELIMIT_H
#define ZCL_NET_ONION_RATELIMIT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Cost tier a request path/method classifies into. */
enum onion_route_class {
    ONION_ROUTE_STATIC = 0,
    ONION_ROUTE_CHEAP = 1,
    ONION_ROUTE_EXPENSIVE = 2,
};

/* Admission verdict for one request. RATE_LIMITED is the unescalated
 * budget verdict; while escalated the puzzle gate owns admission and a
 * bare 429 is never emitted on an expensive route. */
enum onion_admit_result {
    ONION_ADMIT_OK = 0,           /* proceed to normal routing            */
    ONION_ADMIT_RATE_LIMITED = 1, /* 429 — this tier's budget is spent    */
    ONION_ADMIT_POW_REQUIRED = 2, /* 402 — escalated, no valid solution   */
};

/* The challenge a 402 response hands back, everything a client needs to
 * solve the puzzle and retry. Filled by onion_ratelimit_admit() on
 * ONION_ADMIT_POW_REQUIRED. */
struct onion_pow_challenge {
    char    seed_hex[65];   /* server-issued rotating challenge seed     */
    char    token_hex[65];  /* route-bound peer token                    */
    int     bits;           /* required leading zero bits                */
    int64_t server_time;    /* server's wall clock, for the ts field     */
};

/* Classify `path` (+ `method`, needed to tell GET from POST on
 * /store/orders) into a cost tier. For EXPENSIVE routes, writes a short
 * stable route key (<=31 chars + NUL) into route_key_out (may be NULL) —
 * the puzzle-binding identity. Other tiers set it to the empty string. */
enum onion_route_class onion_route_classify(const char *method,
                                            const char *path,
                                            char route_key_out[32]);

/* Full admission check for one request: tiered budget check, and — only
 * while the EXPENSIVE tier is escalated — a route-bound puzzle check.
 * `path` (GET query strings) and `body`/`body_len` (POST form bodies) are
 * scanned for `pow_ts=`/`pow_nonce=` (the field names store_controller.c
 * already uses). On ONION_ADMIT_POW_REQUIRED, `challenge_out` (may be
 * NULL) receives the live challenge to render. Never allocates. */
enum onion_admit_result onion_ratelimit_admit(
    const char *method, const char *path,
    const uint8_t *body, size_t body_len,
    struct onion_pow_challenge *challenge_out);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. Reports
 * per-tier budgets/admitted/denied, escalation state + transitions, and
 * puzzle required/passed/failed counters. */
struct json_value;
bool onion_ratelimit_dump_state_json(struct json_value *out, const char *key);

/* Test-only: reset every budget, the escalation state machine, and the
 * puzzle gate to a fresh-process baseline. Never called from production
 * code — declared here (not behind an #ifdef) to match the existing
 * msgprocessor_test_reset_recent_blocks() precedent. */
void onion_ratelimit_test_reset(void);

/* Test-only: the per-tier caps, so a test drives the real thresholds
 * rather than a copied constant that can drift. */
int onion_ratelimit_test_cap(enum onion_route_class cls);

/* Test-only: force the EXPENSIVE tier into its escalated state, so the
 * puzzle path is reachable without spending real seconds saturating a
 * budget. */
void onion_ratelimit_test_force_escalated(bool escalated);

#endif
