/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Failure classification, the retry rule, and the circuit breaker. See
 * engine/engine_err.h for why each of the three exists.
 */

#include "engine/engine_err.h"

#include <stddef.h>

const char *engine_err_name(enum engine_err e)
{
    switch (e) {
    case ENGINE_OK:              return "ok";
    case ENGINE_ERR_RATE_LIMIT:  return "rate_limited(429)";
    case ENGINE_ERR_OVERLOADED:  return "overloaded(529)";
    case ENGINE_ERR_AUTH:        return "auth_failed(401/403)";
    case ENGINE_ERR_BAD_REQUEST: return "bad_request(400)";
    case ENGINE_ERR_SERVER:      return "server_error(5xx)";
    case ENGINE_ERR_TIMEOUT:     return "timeout";
    case ENGINE_ERR_NETWORK:     return "network_error";
    case ENGINE_ERR_PARSE:       return "response_refused";
    case ENGINE_ERR_REFUSED:     return "refused_before_sending";
    }
    return "unknown";
}

enum engine_err engine_err_of_status(int http_status)
{
    if (http_status >= 200 && http_status < 300)
        return ENGINE_OK;
    switch (http_status) {
    case 429: return ENGINE_ERR_RATE_LIMIT;
    case 529: return ENGINE_ERR_OVERLOADED;
    case 401:
    case 403: return ENGINE_ERR_AUTH;
    case 400: return ENGINE_ERR_BAD_REQUEST;
    default:  break;
    }
    if (http_status >= 500)
        return ENGINE_ERR_SERVER;
    return ENGINE_ERR_NETWORK;
}

bool engine_err_should_retry(enum engine_err e)
{
    switch (e) {
    case ENGINE_ERR_RATE_LIMIT:
    case ENGINE_ERR_OVERLOADED:
    case ENGINE_ERR_SERVER:
    case ENGINE_ERR_TIMEOUT:
    case ENGINE_ERR_NETWORK:
        return true;
    case ENGINE_OK:
    case ENGINE_ERR_AUTH:
    case ENGINE_ERR_BAD_REQUEST:
    case ENGINE_ERR_PARSE:
    case ENGINE_ERR_REFUSED:
        return false;
    }
    return false;
}

int engine_err_backoff_ms(int attempt)
{
    if (attempt < 0)
        attempt = 0;
    if (attempt > 6)
        attempt = 6;                     /* 2000 << 6 already exceeds the cap */
    long ms = 2000L << attempt;
    if (ms > 60000L)
        ms = 60000L;
    return (int)ms;
}

void engine_breaker_record(struct engine_breaker *b, enum engine_err e,
                           int64_t now_ms)
{
    if (!b)
        return;
    if (e == ENGINE_OK) {
        b->consecutive_failures = 0;
        b->open_until_ms = 0;
        return;
    }
    if (b->consecutive_failures < ENGINE_BREAKER_THRESHOLD)
        b->consecutive_failures++;
    if (b->consecutive_failures >= ENGINE_BREAKER_THRESHOLD)
        b->open_until_ms = now_ms + ENGINE_BREAKER_COOLDOWN_MS;
}

bool engine_breaker_is_open(const struct engine_breaker *b, int64_t now_ms)
{
    return b != NULL && b->open_until_ms != 0 && now_ms < b->open_until_ms;
}
