/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Strong Parameters — Rails-style input validation for RPC handlers.
 *
 * Pattern:
 *   struct rpc_params p;
 *   rpc_params_init(&p, params);
 *   const char *addr = rpc_require_str(&p, 0, "address");
 *   int64_t amt = rpc_require_amount(&p, 1, "amount");
 *   int confs = rpc_permit_int(&p, 2, "minconf", 1);  // default=1
 *   if (rpc_params_invalid(&p)) {
 *       rpc_params_error(&p, result);
 *       return false;
 *   }
 *
 * Benefits:
 *   - Declarative param extraction (self-documenting)
 *   - Automatic type checking with clear error messages
 *   - Default values for optional params
 *   - Prevents accessing unpermitted params
 */

#ifndef ZCL_CONTROLLERS_STRONG_PARAMS_H
#define ZCL_CONTROLLERS_STRONG_PARAMS_H

#include "json/json.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RPC_PARAM_ERROR_MAX 256

struct rpc_params {
    const struct json_value *raw;
    char error[RPC_PARAM_ERROR_MAX];
    bool valid;
};

static inline void rpc_params_init(struct rpc_params *p,
                                    const struct json_value *params)
{
    p->raw = params;
    p->error[0] = '\0';
    p->valid = true;
}

static inline bool rpc_params_invalid(const struct rpc_params *p)
{
    return !p->valid;
}

static inline void rpc_params_set_error(struct rpc_params *p,
                                         const char *msg)
{
    if (p->valid) {
        snprintf(p->error, RPC_PARAM_ERROR_MAX, "%s", msg);
        p->valid = false;
    }
}

static inline void rpc_params_error(const struct rpc_params *p,
                                     struct json_value *result)
{
    json_set_str(result, p->error);
}

/* ── Required Parameters ──────────────────────────────────────── */

/* Require a string at position idx. Returns NULL on error. */
static inline const char *rpc_require_str(struct rpc_params *p,
                                           size_t idx,
                                           const char *name)
{
    if (!p->valid) return NULL;
    if (json_size(p->raw) <= idx) {
        char buf[RPC_PARAM_ERROR_MAX];
        snprintf(buf, sizeof(buf), "Missing required parameter: %s", name);
        rpc_params_set_error(p, buf);
        return NULL;
    }
    const struct json_value *v = json_at(p->raw, idx);
    if (v->type != JSON_STR) {
        char buf[RPC_PARAM_ERROR_MAX];
        snprintf(buf, sizeof(buf), "Parameter %s must be a string", name);
        rpc_params_set_error(p, buf);
        return NULL;
    }
    return json_get_str(v);
}

/* Require an integer at position idx. Returns 0 on error. */
static inline int64_t rpc_require_int(struct rpc_params *p,
                                       size_t idx,
                                       const char *name)
{
    if (!p->valid) return 0;
    if (json_size(p->raw) <= idx) {
        char buf[RPC_PARAM_ERROR_MAX];
        snprintf(buf, sizeof(buf), "Missing required parameter: %s", name);
        rpc_params_set_error(p, buf);
        return 0;
    }
    const struct json_value *v = json_at(p->raw, idx);
    if (v->type == JSON_INT) return json_get_int(v);
    if (v->type == JSON_REAL) return (int64_t)json_get_real(v);
    if (v->type == JSON_STR) return strtoll(json_get_str(v), NULL, 10);
    char buf[RPC_PARAM_ERROR_MAX];
    snprintf(buf, sizeof(buf), "Parameter %s must be numeric", name);
    rpc_params_set_error(p, buf);
    return 0;
}

/* Require a boolean at position idx. Returns false on error. */
static inline bool rpc_require_bool(struct rpc_params *p,
                                     size_t idx,
                                     const char *name)
{
    if (!p->valid) return false;
    if (json_size(p->raw) <= idx) {
        char buf[RPC_PARAM_ERROR_MAX];
        snprintf(buf, sizeof(buf), "Missing required parameter: %s", name);
        rpc_params_set_error(p, buf);
        return false;
    }
    const struct json_value *v = json_at(p->raw, idx);
    if (v->type == JSON_BOOL) return json_get_bool(v);
    if (v->type == JSON_INT) return json_get_int(v) != 0;
    char buf[RPC_PARAM_ERROR_MAX];
    snprintf(buf, sizeof(buf), "Parameter %s must be boolean", name);
    rpc_params_set_error(p, buf);
    return false;
}

/* ── Optional Parameters (with defaults) ──────────────────────── */

static inline const char *rpc_permit_str(struct rpc_params *p,
                                          size_t idx,
                                          const char *name,
                                          const char *default_val)
{
    if (!p->valid) return default_val;
    if (json_size(p->raw) <= idx) return default_val;
    const struct json_value *v = json_at(p->raw, idx);
    if (v->type == JSON_NULL) return default_val;
    if (v->type != JSON_STR) {
        char buf[RPC_PARAM_ERROR_MAX];
        snprintf(buf, sizeof(buf), "Parameter %s must be a string", name);
        rpc_params_set_error(p, buf);
        return default_val;
    }
    return json_get_str(v);
}

static inline int64_t rpc_permit_int(struct rpc_params *p,
                                      size_t idx,
                                      const char *name,
                                      int64_t default_val)
{
    if (!p->valid) return default_val;
    if (json_size(p->raw) <= idx) return default_val;
    const struct json_value *v = json_at(p->raw, idx);
    if (v->type == JSON_NULL) return default_val;
    if (v->type == JSON_INT) return json_get_int(v);
    if (v->type == JSON_REAL) return (int64_t)json_get_real(v);
    if (v->type == JSON_STR) return strtoll(json_get_str(v), NULL, 10);
    char buf[RPC_PARAM_ERROR_MAX];
    snprintf(buf, sizeof(buf), "Parameter %s must be numeric", name);
    rpc_params_set_error(p, buf);
    return default_val;
}

static inline bool rpc_permit_bool(struct rpc_params *p,
                                    size_t idx,
                                    const char *name,
                                    bool default_val)
{
    if (!p->valid) return default_val;
    if (json_size(p->raw) <= idx) return default_val;
    const struct json_value *v = json_at(p->raw, idx);
    if (v->type == JSON_NULL) return default_val;
    if (v->type == JSON_BOOL) return json_get_bool(v);
    if (v->type == JSON_INT) return json_get_int(v) != 0;
    char buf[RPC_PARAM_ERROR_MAX];
    snprintf(buf, sizeof(buf), "Parameter %s must be boolean", name);
    rpc_params_set_error(p, buf);
    return default_val;
}

/* ── Amount Parsing (satoshi-safe) ────────────────────────────── */

/* Parse a ZCL amount from string or number, returning satoshis.
 * Handles both "0.001" (string) and 0.001 (number) forms. */
static inline int64_t rpc_require_amount(struct rpc_params *p,
                                          size_t idx,
                                          const char *name)
{
    if (!p->valid) return 0;
    if (json_size(p->raw) <= idx) {
        char buf[RPC_PARAM_ERROR_MAX];
        snprintf(buf, sizeof(buf), "Missing required parameter: %s", name);
        rpc_params_set_error(p, buf);
        return 0;
    }
    const struct json_value *v = json_at(p->raw, idx);
    int64_t satoshis = 0;
    if (v->type == JSON_INT) {
        satoshis = json_get_int(v) * 100000000LL;
    } else if (v->type == JSON_REAL) {
        double d = json_get_real(v);
        satoshis = (int64_t)(d * 100000000.0 + 0.5);
    } else if (v->type == JSON_STR) {
        const char *s = json_get_str(v);
        /* Capture the sign explicitly: strtoll applies it to the integer part,
         * but "-0.5" has an integer part of 0, so the sign would be lost and a
         * negative amount silently become a positive send. Detect a leading '-'
         * and negate the full result so negatives reach the rejection below. */
        const char *t = s;
        while (*t == ' ' || *t == '\t') t++;
        bool negative = (*t == '-');
        const char *dot = strchr(s, '.');
        if (dot) {
            int64_t whole = strtoll(s, NULL, 10);
            if (whole < 0) whole = -whole; /* magnitude; sign applied below */
            int64_t frac = 0;
            int digits = 0;
            for (const char *c = dot + 1; *c >= '0' && *c <= '9' && digits < 8; c++, digits++)
                frac = frac * 10 + (*c - '0');
            for (int i = digits; i < 8; i++)
                frac *= 10;
            satoshis = whole * 100000000LL + frac;
        } else {
            satoshis = strtoll(s, NULL, 10) * 100000000LL;
            if (satoshis < 0) satoshis = -satoshis; /* magnitude */
        }
        if (negative)
            satoshis = -satoshis;
    } else {
        char buf[RPC_PARAM_ERROR_MAX];
        snprintf(buf, sizeof(buf), "Parameter %s must be a valid amount", name);
        rpc_params_set_error(p, buf);
        return 0;
    }
    if (satoshis < 0) {
        char buf[RPC_PARAM_ERROR_MAX];
        snprintf(buf, sizeof(buf), "Parameter %s: amount must be non-negative", name);
        rpc_params_set_error(p, buf);
        return 0;
    }
    return satoshis;
}

/* ── Param Count Validation ───────────────────────────────────── */

static inline void rpc_params_expect(struct rpc_params *p,
                                      size_t min_params,
                                      size_t max_params)
{
    if (!p->valid) return;
    size_t n = json_size(p->raw);
    if (n < min_params) {
        char buf[RPC_PARAM_ERROR_MAX];
        snprintf(buf, sizeof(buf),
                 "Expected at least %zu parameter(s), got %zu",
                 min_params, n);
        rpc_params_set_error(p, buf);
    } else if (n > max_params) {
        char buf[RPC_PARAM_ERROR_MAX];
        snprintf(buf, sizeof(buf),
                 "Expected at most %zu parameter(s), got %zu",
                 max_params, n);
        rpc_params_set_error(p, buf);
    }
}

/* ── Help Check Macro ─────────────────────────────────────────── */

/* Standard help dispatch — use at the top of every RPC handler.
 * Emits help text and returns true if help is requested. */
#define RPC_HELP(help, result, text) do { \
    if (help) { \
        json_set_str(result, text); \
        return true; \
    } \
} while (0)

#endif
