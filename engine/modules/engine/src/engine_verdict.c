/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Reading the gate, and judging the unit by what it said. See
 * engine/engine_verdict.h for the law and for the four ways a unit looks
 * green without being green.
 *
 * The reader takes the LAST verdict line in the log, not the first. A gate
 * run can legitimately print more than one (a rebuild that runs a sub-suite,
 * a retry), and the last one is the one that describes the run that finished.
 */

#include "engine/engine_verdict.h"

#include "base/log_macros.h"

#include <stdlib.h>
#include <string.h>

const char *engine_verdict_name(enum engine_verdict v)
{
    switch (v) {
    case ENGINE_VERDICT_PASS:       return "PASS";
    case ENGINE_VERDICT_FAIL:       return "FAIL";
    case ENGINE_VERDICT_HOLLOW:     return "FAIL(HOLLOW)";
    case ENGINE_VERDICT_NO_CHANGE:  return "FAIL(NO-CHANGE)";
    case ENGINE_VERDICT_TIMEOUT:    return "TIMEOUT";
    case ENGINE_VERDICT_REFUSED:    return "REFUSED";
    case ENGINE_VERDICT_UNVERIFIED: return "UNVERIFIED";
    }
    return "UNKNOWN";
}

bool engine_verdict_is_pass(enum engine_verdict v)
{
    return v == ENGINE_VERDICT_PASS;
}

/* Read `key=<number>` out of one line. Absent leaves *out untouched. */
static void field(const char *line, const char *key, long *out)
{
    const char *at = strstr(line, key);
    if (!at)
        return;
    *out = strtol(at + strlen(key), NULL, 10);
}

/* Is `hay[0..n)` a whole-token occurrence of `needle` that is NOT immediately
 * followed by the (CACHED) qualifier? The qualifier is the whole reason this
 * is not a substring search: "ALL TESTS PASSED (CACHED)" contains "ALL TESTS
 * PASSED", and a grep for the token matches a run that executed nothing. */
static bool has_cold_pass_token(const char *hay, size_t n)
{
    static const char tok[] = "ALL TESTS PASSED";
    const size_t tl = sizeof(tok) - 1;
    for (size_t i = 0; i + tl <= n; i++) {
        if (memcmp(hay + i, tok, tl) != 0)
            continue;
        const char *rest = hay + i + tl;
        const size_t left = n - i - tl;
        if (left >= 9 && memcmp(rest, " (CACHED)", 9) == 0)
            continue;
        return true;
    }
    return false;
}

static bool contains(const char *hay, size_t n, const char *needle)
{
    const size_t nl = strlen(needle);
    if (nl > n)
        return false;
    for (size_t i = 0; i + nl <= n; i++) {
        if (memcmp(hay + i, needle, nl) == 0)
            return true;
    }
    return false;
}

bool engine_gate_read(const char *log, size_t len,
                      struct engine_gate_reading *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!log)
        LOG_FAIL("engine", "refusing to read a null gate log");

    /* Walk every line; keep the last SUITE VERDICT. The line is bounded, so a
     * pathological log cannot make this allocate. */
    const char *cur = log;
    const char *end = log + len;
    char keep[512];
    keep[0] = '\0';
    while (cur < end) {
        const char *nl = memchr(cur, '\n', (size_t)(end - cur));
        const char *line_end = nl ? nl : end;
        const size_t n = (size_t)(line_end - cur);
        if (n >= 13 && n < sizeof(keep) && memcmp(cur, "SUITE VERDICT", 13) == 0) {
            memcpy(keep, cur, n);
            keep[n] = '\0';
        }
        cur = nl ? nl + 1 : end;
    }

    if (keep[0]) {
        out->saw_verdict_line = true;
        out->cached_mode = strstr(keep, "mode=cached") != NULL;
        field(keep, "groups_total=", &out->groups_total);
        field(keep, "groups_ran=", &out->groups_ran);
        field(keep, "groups_cached=", &out->groups_cached);
        field(keep, "groups_failed=", &out->groups_failed);
        field(keep, "self_skips=", &out->self_skips);
        field(keep, "env_unobserved=", &out->env_unobserved);
    }
    out->saw_pass_token = has_cold_pass_token(log, len);
    out->saw_fail_token = contains(log, len, "SOME TESTS FAILED");
    return true;
}

enum engine_verdict engine_verdict_of(const struct engine_gate_reading *gate,
                                      size_t files_changed,
                                      bool timed_out,
                                      bool have_group)
{
    /* Order matters, and this order is the argument of the whole module.
     *
     * The timeout is first because a unit cut off mid-thought has an
     * unknowable relationship to whatever the gate then said — the gate might
     * have run against half a change. Reporting that as PASS or as FAIL both
     * throw away the fact an operator needs. */
    if (timed_out)
        return ENGINE_VERDICT_TIMEOUT;

    /* Second: nothing changed. This is checked BEFORE the gate is consulted,
     * on purpose. When the diff is empty the gate is measuring the tree as it
     * was before the unit ran, so a green gate is evidence about the baseline
     * and says nothing whatever about the unit. An engine that reports success
     * having written nothing is the single most common failure this harness
     * exists to catch, and it is a FAILURE. */
    if (files_changed == 0)
        return ENGINE_VERDICT_NO_CHANGE;

    /* A unit dispatched without a group proved nothing. It is not a pass. */
    if (!have_group)
        return ENGINE_VERDICT_UNVERIFIED;

    if (!gate || !gate->saw_verdict_line)
        return ENGINE_VERDICT_REFUSED;

    /* The hollow green: a selector that matched nothing, or a run served
     * entirely from cache. Both print a zero and exit 0. */
    if (gate->groups_ran <= 0)
        return ENGINE_VERDICT_HOLLOW;
    if (gate->cached_mode && gate->groups_cached >= gate->groups_ran)
        return ENGINE_VERDICT_HOLLOW;

    if (gate->groups_failed != 0 || gate->saw_fail_token)
        return ENGINE_VERDICT_FAIL;

    /* Fail-closed tail: a run that neither failed nor printed the cold pass
     * token is not a pass. Silence is not consent. */
    if (!gate->saw_pass_token)
        return ENGINE_VERDICT_REFUSED;
    return ENGINE_VERDICT_PASS;
}
