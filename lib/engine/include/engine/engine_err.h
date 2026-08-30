/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_err — classify a dispatch failure, because retry policy differs by
 * class, and hold the breaker that stops a retry loop turning one outage into
 * a bill.
 *
 * ── WHY A CLASS AND NOT A BOOLEAN ────────────────────────────────────────
 * "It failed" throws away the only information that says what to do next.
 * Retrying a 401 burns wall clock and will never succeed; retrying a 529 is
 * exactly right and usually works on the second attempt. The owner's own C
 * client (RhettCreighton/VibePoint, src/llm/llm.c:398 classify_http_error,
 * :410 should_retry) draws the same line, and the mapping below is its
 * mapping — 429 rate-limited, 529 overloaded, 401/403 auth, 400 bad request,
 * 5xx server — because it was derived from real vendor behaviour rather than
 * from the RFC.
 *
 * ── WHY A BREAKER AND NOT JUST RETRIES ───────────────────────────────────
 * Retries alone are a way to spend money faster on an endpoint that is
 * already broken. Three consecutive failures open the circuit for a cooling
 * period, and a caller that asks to dispatch while it is open is refused
 * without a request being made.
 *
 * Everything here is a pure function of its arguments, INCLUDING time: the
 * breaker is driven by a `now_ms` the caller passes in. That is not
 * fastidiousness — a module that reads its own clock cannot be tested for the
 * behaviour that matters (does the circuit actually reopen?) without sleeping,
 * and it would also violate the tree's single-clock rule.
 *
 * NONE OF THIS IS A VERDICT. A successful dispatch with zero retries says
 * nothing about whether the work is any good. The gate decides that; see
 * engine/engine_verdict.h.
 */

#ifndef ZCL_ENGINE_ERR_H
#define ZCL_ENGINE_ERR_H

#include <stdbool.h>
#include <stdint.h>

enum engine_err {
    ENGINE_OK = 0,
    ENGINE_ERR_RATE_LIMIT,   /* 429 */
    ENGINE_ERR_OVERLOADED,   /* 529 */
    ENGINE_ERR_AUTH,         /* 401, 403 */
    ENGINE_ERR_BAD_REQUEST,  /* 400 */
    ENGINE_ERR_SERVER,       /* 5xx */
    ENGINE_ERR_TIMEOUT,
    ENGINE_ERR_NETWORK,
    ENGINE_ERR_PARSE,        /* the response was refused by engine_wire */
    ENGINE_ERR_REFUSED       /* this harness declined before sending */
};

const char *engine_err_name(enum engine_err e);

/* Map an HTTP status to a class. A 2xx maps to ENGINE_OK. */
enum engine_err engine_err_of_status(int http_status);

/* Only these classes are worth another attempt. AUTH, BAD_REQUEST, PARSE and
 * REFUSED are not: they will fail identically forever, and retrying them is
 * how a harness spends an hour proving that a key is still wrong. */
bool engine_err_should_retry(enum engine_err e);

/* Exponential backoff with a hard ceiling, in milliseconds. attempt is
 * 0-based. Deterministic, so the test can assert on it. */
int engine_err_backoff_ms(int attempt);

/* ── the circuit breaker ─────────────────────────────────────────────── */

#define ENGINE_BREAKER_THRESHOLD 3
#define ENGINE_BREAKER_COOLDOWN_MS 60000

struct engine_breaker {
    int     consecutive_failures;
    int64_t open_until_ms;   /* 0 means closed */
};

/* Record one outcome. A success closes the circuit and clears the count; a
 * retryable failure counts toward the threshold. A NON-retryable failure also
 * counts: an endpoint answering 401 to everything is just as broken from this
 * harness's point of view as one answering 503, and hammering it is just as
 * pointless. */
void engine_breaker_record(struct engine_breaker *b, enum engine_err e,
                           int64_t now_ms);

/* True when a dispatch must be refused without sending anything. */
bool engine_breaker_is_open(const struct engine_breaker *b, int64_t now_ms);

#endif /* ZCL_ENGINE_ERR_H */
