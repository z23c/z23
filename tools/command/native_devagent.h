/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Pure, testable primitives behind the dev.agent.* command surface —
 *          checkout-root resolution, SUITE VERDICT parsing, and the
 *          deterministic single-line source mutation used by
 *          dev.agent.mutate. Kept separate from the handlers so a registered
 *          test group can prove them without spawning a build. */

#ifndef ZCL_NATIVE_DEVAGENT_H
#define ZCL_NATIVE_DEVAGENT_H

#include <stdbool.h>
#include <stddef.h>

/* ── SUITE VERDICT ────────────────────────────────────────────────────────
 * test_parallel prints exactly one machine-greppable verdict line:
 *
 *   SUITE VERDICT mode=cold groups_total=N groups_ran=N groups_cached=N
 *     groups_gated=N groups_failed=N self_skips=N env_unobserved=N toolkey=..
 *
 * `groups_ran` is the field that separates "the group passed" from "nothing
 * executed and the runner still printed ALL TESTS PASSED". Every consumer of
 * a test run must read it, so it is parsed once, here. */
#define ZCL_DEVAGENT_MODE_MAX    16
#define ZCL_DEVAGENT_TOOLKEY_MAX 32

struct zcl_devagent_verdict {
    bool present;               /* a SUITE VERDICT line was found at all */
    char mode[ZCL_DEVAGENT_MODE_MAX];       /* "cold" | "cached" */
    char toolkey[ZCL_DEVAGENT_TOOLKEY_MAX];
    long long groups_total;
    long long groups_ran;
    long long groups_cached;
    long long groups_gated;
    long long groups_failed;
    long long self_skips;
    long long env_unobserved;
    bool hotswap;               /* the run executed a hot-swapped module */
};

/* Parse the LAST `SUITE VERDICT` line in `text`. `out` is always initialized;
 * returns out->present. Missing numeric fields stay -1 so an absent field can
 * never be mistaken for a zero. */
bool zcl_devagent_verdict_parse(const char *text,
                                struct zcl_devagent_verdict *out);

/* ── single-line source mutation ──────────────────────────────────────────
 * One deterministic edit to one line, chosen by the first applicable rule in
 * a left-to-right scan of the line's CODE regions (string literals, character
 * literals and trailing `//` comments are skipped). A line whose first
 * non-blank character starts a comment is refused outright: from one line
 * alone a block-comment interior is indistinguishable from code. */
#define ZCL_DEVAGENT_RULE_MAX  24
#define ZCL_DEVAGENT_TOKEN_MAX 24

struct zcl_devagent_mutation {
    char rule[ZCL_DEVAGENT_RULE_MAX];   /* e.g. "eq_to_ne" */
    char before[ZCL_DEVAGENT_TOKEN_MAX];
    char after[ZCL_DEVAGENT_TOKEN_MAX];
    size_t column;                      /* 1-based column of the edit */
};

/* Write the mutated form of `line` (which must NOT contain a newline) into
 * `out`. Returns false and leaves `out`/`m` zeroed when no rule applies —
 * that is a refusal the caller must report, never a silent no-op. */
bool zcl_devagent_mutate_line(const char *line, struct zcl_devagent_mutation *m,
                              char *out, size_t out_cap);

/* ── checkout root ────────────────────────────────────────────────────────
 * Walk up from `start` (NULL = current directory) until a directory carries
 * all three checkout markers. Returns false when none does — the caller must
 * then say so rather than guessing a root and writing somewhere else. */
bool zcl_devagent_checkout_root(const char *start, char *out, size_t out_cap);

/* ── bounded process helpers ──────────────────────────────────────────────
 * Not pure: these spawn (never through a shell) and are shared by the
 * dev.agent.* handlers. Both run from `root` and restore the caller's
 * directory before returning. A negative return is a launch failure. */
int zcl_devagent_run_make(const char *root, const char *target, int timeout_ms);

/* Run build/bin/test_parallel with one already-formed selector
 * ("--exact=x" / "--only=x") and --no-cache. `out` is always initialized; a
 * run whose transcript overflowed the capture buffer sets *truncated and
 * leaves out->present false rather than parsing a partial transcript. */
int zcl_devagent_run_group(const char *root, const char *selector,
                           int timeout_ms, struct zcl_devagent_verdict *out,
                           bool *truncated);

#endif /* ZCL_NATIVE_DEVAGENT_H */
