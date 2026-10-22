/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Line-level JSON field readers and report-text helpers shared by
 *          the soak and stopwatch judges. */

#ifndef ZCL_NATIVE_EVIDENCE_JUDGE_UTIL_H
#define ZCL_NATIVE_EVIDENCE_JUDGE_UTIL_H

#include "native_evidence_judge.h"

enum ej_kind { EJ_MISSING, EJ_NULL, EJ_NUM };

struct ej_num {
    enum ej_kind kind;
    int64_t n;
};

/* First `"key":<integer>` of a single-line JSON object; with allow_null a
 * `"key":null` also matches. Occurrences that match neither are skipped. */
struct ej_num ej_field_num(const char *line, const char *key, bool allow_null);

/* First `"key":"<text>"`; the text excludes quotes. False when absent. */
bool ej_field_str(const char *line, const char *key, char *out, size_t cap);

/* Appends one formatted fragment to out->text, truncating at the bound. */
void ej_cat(struct zcl_judge_result *out, const char *fmt, ...)
    __attribute__((format(gnu_printf, 2, 3)));

void ej_verdict(struct zcl_judge_result *out, int exit_code, const char *verdict,
                const char *reason);

int64_t ej_now(int64_t given);

/* Parses the value of environment variable `name` (as returned by getenv)
 * as a non-negative integer. 1 = set and valid,
 * 0 = unset or empty, -1 = malformed (err names the variable). */
int ej_env_int(const char *name, const char *text, int64_t *value, char *err,
               size_t err_cap);

/* Whole file in a NUL-terminated heap buffer; NULL when absent, empty or
 * larger than `max`. The caller frees. */
char *ej_slurp(const char *path, size_t max, size_t *len);

#endif /* ZCL_NATIVE_EVIDENCE_JUDGE_UTIL_H */
