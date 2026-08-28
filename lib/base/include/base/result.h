/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcl_result — rich error type for service-layer functions.
 *
 * Per DEFENSIVE_CODING.md §2. Replaces bare `bool` returns on functions
 * that can fail for more than one reason. A function returning
 * `struct zcl_result` forces the author to populate a failure message,
 * a numeric code, and the source file:line where the failure was
 * produced — so every `return !r.ok` leaves a paper trail in the log.
 *
 * A bare `false` return with no log line — e.g. from
 * wallet_sqlite_open() — can make an unspendable-funds bug undiagnosable.
 * That bug class is what this type is designed to eliminate. A zcl_result
 * literal carries enough context that silence is no longer an option.
 *
 * Usage:
 *
 *   struct zcl_result do_thing(void) {
 *       if (bad) return ZCL_ERR(-42, "reason: %s", detail);
 *       return ZCL_OK;
 *   }
 *
 *   struct zcl_result caller(void) {
 *       ZCL_CHECK(do_thing());   // logs + returns on failure
 *       return ZCL_OK;
 *   }
 */

#ifndef ZCL_UTIL_RESULT_H
#define ZCL_UTIL_RESULT_H

#include <stdarg.h>
#include <stdbool.h>

#define ZCL_RESULT_MSG_MAX 256

/* [[nodiscard]] on the TYPE, so every function returning it inherits the
 * requirement without touching 343 declarations. Note the two compilers
 * report it differently: gcc under -Wunused-result, clang under
 * -Wunused-value. Note also that C23 lets a `(void)` cast suppress it —
 * so this attribute is a fence against NEW silent discards, not a way to
 * excavate the existing cast-discard population. That population is what
 * tools/lint/check_result_discard.sh ratchets down. */
struct [[nodiscard]] zcl_result {
    bool        ok;
    int         code;                         /* 0 on success */
    char        message[ZCL_RESULT_MSG_MAX];  /* always NUL terminated */
    const char *source_file;                  /* __FILE__ */
    int         source_line;                  /* __LINE__ */
};

/* Success literal. Zero-initialises message and source fields. */
#define ZCL_OK ((struct zcl_result){ .ok = true, .code = 0 })

/* Build a non-ok result with a printf-style message. Captures
 * __FILE__ and __LINE__ automatically. */
#define ZCL_ERR(err_code, ...) \
    zcl_result_make((err_code), __FILE__, __LINE__, __VA_ARGS__)

/* Short-circuit: evaluate a zcl_result expression; if it is non-ok,
 * LOG_FAIL-style print it and return it from the enclosing function
 * (which must also return struct zcl_result). */
#define ZCL_CHECK(res_expr) do {                                     \
    struct zcl_result _zr_chk = (res_expr);                          \
    if (!_zr_chk.ok) {                                               \
        fprintf(stderr, "[zcl_check] %s:%d %s(): code=%d %s\n",      \
                _zr_chk.source_file, _zr_chk.source_line, __func__,  \
                _zr_chk.code, _zr_chk.message);                      \
        return _zr_chk;                                              \
    }                                                                \
} while (0)

/* Deliberately discard a zcl_result, with a stated reason.
 *
 * A bare `(void)call();` also silences [[nodiscard]] under C23, but says
 * nothing about why the failure is safe to drop. This macro makes the
 * discard expressible rather than merely tolerated: `reason` must be a
 * non-empty string literal, enforced at compile time, and the lint gate
 * tools/lint/check_result_discard.sh counts every remaining bare
 * `(void)` discard as debt that may only shrink.
 *
 *   ZCL_IGNORE_RESULT(flush_cache(db), "best-effort; tip refold re-derives it");
 */
#define ZCL_IGNORE_RESULT(res_expr, reason)                              \
    do {                                                                 \
        static_assert(sizeof("" reason) > 1,                             \
                      "ZCL_IGNORE_RESULT requires a non-empty reason");  \
        (void)(res_expr);                                                \
    } while (0)

/* Build a zcl_result from a format string. Defined in result.c.
 * NULL fmt is accepted defensively and becomes an explicit diagnostic
 * marker; use "" for an intentionally empty message. */
struct zcl_result zcl_result_make(int code, const char *file, int line,
                                   const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

/* Convenience: convert a zcl_result to bool, for callers still on
 * the bool API. Returns r.ok directly — does NOT log. Use the
 * bool-returning wrapper that called this to emit the LOG_FAIL. */
static inline bool zcl_result_is_ok(struct zcl_result r) { return r.ok; }

#endif /* ZCL_UTIL_RESULT_H */
