/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — hosted-suite cold-verdict verification
 * (check-hosted-suite-verdict), the C23 port of
 * tools/lint/lintc/gate_hosted_suite_verdict.c. Holds the hosted test job to one
 * non-vacuous cold-suite verdict: exactly one SUITE VERDICT line whose fields
 * are well-formed, complete, non-duplicated and numerically coherent, plus
 * exactly one cold ALL TESTS PASSED headline and no cached or failure
 * headline. A substring grep is insufficient: "ALL TESTS PASSED (CACHED)"
 * deliberately contains the old pass token and can describe a run that
 * executed zero groups.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "base/safe_alloc.h"
#include "gate_hosted_suite_verdict_priv.h"
#include "lintc.h"
#include "lintc_text.h"

/* Every static name carries the hsv_ prefix: the code index links test
 * closures by symbol name. */

static const char *const k_hsv_fields[] = {
    "mode", "groups_total", "groups_ran", "groups_cached", "groups_gated",
    "groups_failed", "self_skips", "env_unobserved", "toolkey", "load_flaky"
};
enum { HSV_FIELDS = sizeof k_hsv_fields / sizeof k_hsv_fields[0] };
enum { HSV_MODE = 0, HSV_TOTAL = 1, HSV_RAN = 2, HSV_CACHED = 3,
       HSV_GATED = 4, HSV_FAILED = 5, HSV_SKIPS = 6, HSV_UNOBS = 7,
       HSV_TOOLKEY = 8, HSV_LOAD_FLAKY = 9 };

static const char k_hsv_verdict_prefix[] = "SUITE VERDICT ";
static const char k_hsv_pass_prefix[] = "ALL TESTS PASSED \xE2\x80\x94 ";
static const char k_hsv_cached_prefix[] = "ALL TESTS PASSED (CACHED)";
static const char k_hsv_failed_prefix[] = "SOME TESTS FAILED";

/* fail() sink: stderr normally; the self-test redirects both streams for
 * its rejecting-mutation runs, exactly as the script's 2>&1 did. */
FILE *g_hsv_err = NULL;

void hsv_fail(const char *fmt, ...)
{
    va_list ap;
    if (!g_hsv_err)
        return;
    fputs("hosted-suite-verdict: FAIL: ", g_hsv_err);
    va_start(ap, fmt);
    vfprintf(g_hsv_err, fmt, ap);
    va_end(ap);
    fputc('\n', g_hsv_err);
}

static bool hsv_prefix_at(const char *line, size_t len, const char *pre)
{
    size_t n = strlen(pre);
    return len >= n && memcmp(line, pre, n) == 0;
}

/* Keep only verdict/headline lines: suite output can be arbitrarily large.
 * Candidate lines must be complete and bounded; unrelated long lines are
 * discarded without affecting their interpretation. */
static bool hsv_candidate(const char *line)
{
    return strncmp(line, k_hsv_verdict_prefix, strlen(k_hsv_verdict_prefix)) == 0 ||
           strncmp(line, k_hsv_pass_prefix, strlen(k_hsv_pass_prefix)) == 0 ||
           strncmp(line, k_hsv_cached_prefix, strlen(k_hsv_cached_prefix)) == 0 ||
           strncmp(line, k_hsv_failed_prefix, strlen(k_hsv_failed_prefix)) == 0;
}

static bool hsv_record_line(char *out, size_t cap, size_t *used,
                            char *line, size_t len, bool complete)
{
    line[len] = '\0';
    if (!hsv_candidate(line)) return true;
    if (!complete || len + 1 >= cap - *used) return false;
    memcpy(out + *used, line, len);
    *used += len;
    out[(*used)++] = '\n';
    return true;
}

static char *hsv_read_file(const char *path, size_t *out_size)
{
    enum { HSV_LINE_CAP = 4096, HSV_OUTPUT_CAP = 65536 };
    char line[HSV_LINE_CAP];
    size_t len = 0, used = 0;
    bool overflow = false, ok = true;
    FILE *f = fopen(path, "rb");
    char *out = zcl_malloc(HSV_OUTPUT_CAP, "hsv_log_buffer");
    *out_size = 0;
    if (!f || !out) goto fail;
    int c;
    while ((c = fgetc(f)) != EOF) {
        if (c == 0) { ok = false; break; }
        if (c == '\n') {
            if (!hsv_record_line(out, HSV_OUTPUT_CAP, &used, line, len, !overflow)) {
                ok = false; break;
            }
            len = 0; overflow = false;
        } else if (len < sizeof(line) - 1) line[len++] = (char)c;
        else overflow = true;
    }
    if (ferror(f) || (len && !hsv_record_line(out, HSV_OUTPUT_CAP, &used, line, len, false)))
        ok = false;
    if (fclose(f) != 0) ok = false;
    if (!ok) { free(out); hsv_fail("suite log has invalid or incomplete candidate line"); return NULL; }
    out[used] = '\0'; *out_size = used;
    return out;
fail:
    if (f) fclose(f);
    free(out);
    hsv_fail("suite log is not readable: %s", path);
    return NULL;
}

/* Parse a digits-only string with the same 64-bit wrap arithmetic bash used
 * (`$((10#...))` evaluates in intmax_t): accumulate in unsigned 64-bit and
 * compare through signed 64-bit, so absurdly long digit strings behave
 * exactly as the script's arithmetic did instead of clamping. */
static long long hsv_parse_wrapped(const char *s)
{
    unsigned long long v = 0;
    for (; *s; s++)
        v = v * 10u + (unsigned long long)(*s - '0');
    return (long long)v;
}

static bool hsv_is_lower_hex12(const char *s)
{
    size_t i;
    if (strlen(s) != 12)
        return false;
    for (i = 0; i < 12; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

struct hsv_values {
    char *v[HSV_FIELDS];      /* pointers into the verdict-line copy */
    bool present[HSV_FIELDS];
};

/* Walk the whitespace-split tokens of the remainder, mirroring the script's
 * `for token in ${verdict#SUITE VERDICT }` word splitting. */
static void hsv_parse_tokens(char *rest, struct hsv_values *vals, int *bad)
{
    char *p = rest;
    while (*p) {
        char *tok, *eq, *datum;
        const char *key;
        int idx = -1;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        tok = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        if (*p)
            *p++ = '\0';
        eq = strchr(tok, '=');
        if (!eq) {
            hsv_fail("suite verdict token is not key=value: %s", tok);
            *bad = 1;
            continue;
        }
        *eq = '\0';
        key = tok;
        datum = eq + 1;
        for (int i = 0; i < (int)HSV_FIELDS; i++)
            if (strcmp(key, k_hsv_fields[i]) == 0)
                idx = i;
        if (idx < 0) {
            hsv_fail("unknown suite verdict field: %s", key);
            *bad = 1;
            continue;
        }
        if (vals->present[idx]) {
            hsv_fail("duplicate suite verdict field: %s", key);
            *bad = 1;
            continue;
        }
        vals->present[idx] = true;
        vals->v[idx] = datum;
    }
}

/* The value to show in diagnostics: the stored value, or "missing" when the
 * field never landed — the script's `${value[$key]-missing}`. */
static const char *hsv_show(const struct hsv_values *vals, int idx)
{
    return vals->present[idx] ? vals->v[idx] : "missing";
}

/* One log-line scan: counts the verdict and headline shapes exactly as the
 * script's three greps did (a trailing chunk without a newline still counts
 * as a line). Only the first verdict line is kept for token parsing — with
 * more than one the script never parsed tokens at all. */
struct hsv_scan {
    size_t verdict_count;
    char *verdict_line;        /* owned copy of the first verdict line */
    size_t pass_headlines;
    bool cached_headline, failed_headline, filtered_headline;
};

static bool hsv_suffix_at(const char *line, size_t len, const char *suffix)
{
    size_t n = strlen(suffix);
    while (len && (line[len - 1] == ' ' || line[len - 1] == '\t' || line[len - 1] == '\r')) len--;
    return len >= n && memcmp(line + len - n, suffix, n) == 0;
}

static void hsv_scan_lines(char *buf, size_t size, struct hsv_scan *sc)
{
    size_t i = 0;
    memset(sc, 0, sizeof *sc);
    while (i < size) {
        size_t end = i, len;
        char *line;
        while (end < size && buf[end] != '\n')
            end++;
        len = end - i;            /* provably <= size: keeps the copy's
                                   * bounds visible to the compiler */
        line = buf + i;
        if (hsv_prefix_at(line, len, k_hsv_verdict_prefix)) {
            sc->verdict_count++;
            if (!sc->verdict_line) {
                /* Terminate the line in place: end<size means that byte
                 * was the '\n' this scanner owns; end==size means the
                 * buffer already ends NUL. No copy is needed. */
                buf[end] = '\0';
                sc->verdict_line = line;
            }
        }
        if (hsv_prefix_at(line, len, k_hsv_pass_prefix)) {
            sc->pass_headlines++;
            sc->filtered_headline = hsv_suffix_at(line, len, " [--exact filtered]") ||
                                    hsv_suffix_at(line, len, " [--only filtered]");
        }
        if (hsv_prefix_at(line, len, k_hsv_cached_prefix))
            sc->cached_headline = true;
        if (hsv_prefix_at(line, len, k_hsv_failed_prefix))
            sc->failed_headline = true;
        if (end == size)
            break;
        i = end + 1;
    }
}

/* Missing-field, mode, numeric-format and toolkey diagnostics, in the
 * script's exact order. */
static void hsv_validate_fields(const struct hsv_values *vals, int *bad)
{
    for (int i = 0; i < (int)HSV_FIELDS; i++)
        if (i != HSV_LOAD_FLAKY && !vals->present[i]) {
            hsv_fail("suite verdict is missing field: %s", k_hsv_fields[i]);
            *bad = 1;
        }
    if (strcmp(hsv_show(vals, HSV_MODE), "cold") != 0) {
        hsv_fail("suite mode is '%s', expected cold",
                 hsv_show(vals, HSV_MODE));
        *bad = 1;
    }
    for (int i = HSV_TOTAL; i <= HSV_UNOBS; i++) {
        const char *s = hsv_show(vals, i);
        if (!lct_is_digits(s)) {
            hsv_fail("suite field %s is not a non-negative integer: %s",
                     k_hsv_fields[i], s);
            *bad = 1;
        }
    }
    if (vals->present[HSV_LOAD_FLAKY] && !lct_is_digits(vals->v[HSV_LOAD_FLAKY])) {
        hsv_fail("suite load_flaky is not a non-negative integer");
        *bad = 1;
    }
    if (!hsv_is_lower_hex12(hsv_show(vals, HSV_TOOLKEY))) {
        hsv_fail("suite toolkey is not 12 lowercase hex characters: %s",
                 hsv_show(vals, HSV_TOOLKEY));
        *bad = 1;
    }
}

/* The arithmetic coherence block, only reached when nothing earlier failed,
 * in the script's exact order. */
static void hsv_validate_counts(const struct hsv_values *vals, int *bad)
{
    long long total_n = hsv_parse_wrapped(vals->v[HSV_TOTAL]);
    long long ran_n = hsv_parse_wrapped(vals->v[HSV_RAN]);
    long long cached_n = hsv_parse_wrapped(vals->v[HSV_CACHED]);
    long long gated_n = hsv_parse_wrapped(vals->v[HSV_GATED]);
    long long failed_n = hsv_parse_wrapped(vals->v[HSV_FAILED]);
    long long skips_n = hsv_parse_wrapped(vals->v[HSV_SKIPS]);
    long long unobserved_n = hsv_parse_wrapped(vals->v[HSV_UNOBS]);
    /* Bash `$((ran + gated))` wraps in 64-bit; reproduce that wrap. */
    long long sum_n = (long long)((unsigned long long)ran_n
        + (unsigned long long)gated_n);
    if (total_n == 0 || ran_n == 0) {
        hsv_fail("suite executed no groups (total=%lld ran=%lld)",
                 total_n, ran_n);
        *bad = 1;
    }
    if (cached_n != 0) {
        hsv_fail("suite reused %lld cached group(s); hosted proof must "
                 "be cold", cached_n);
        *bad = 1;
    }
    if (failed_n != 0) {
        hsv_fail("suite reports %lld failed group(s)", failed_n);
        *bad = 1;
    }
    if (unobserved_n != 0) {
        hsv_fail("suite reports %lld environment-unobserved group(s)",
                 unobserved_n);
        *bad = 1;
    }
    if (sum_n != total_n) {
        hsv_fail("suite accounting is incomplete: ran=%lld gated=%lld "
                 "total=%lld", ran_n, gated_n, total_n);
        *bad = 1;
    }
    if (skips_n > ran_n) {
        hsv_fail("suite self-skips exceed executed groups: skips=%lld "
                 "ran=%lld", skips_n, ran_n);
        *bad = 1;
    }
}

/* Ship never permits wraparound to turn an invalid count into zero. */
static bool hsv_ship_number(const char *s, uint64_t *out)
{
    if (!s || !lct_is_digits(s)) return false;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(s, &end, 10);
    if (errno == ERANGE || !end || *end || value > UINT64_MAX) return false;
    *out = (uint64_t)value;
    return true;
}

static void hsv_ship_counts(const struct hsv_values *vals, int *bad)
{
    uint64_t counts[HSV_FIELDS] = {0};
    for (int i = HSV_TOTAL; i <= HSV_UNOBS; i++) {
        if (!hsv_ship_number(vals->v[i], &counts[i])) {
            hsv_fail("invalid ship count: %s", k_hsv_fields[i]);
            *bad = 1; return;
        }
    }
    if (!vals->present[HSV_LOAD_FLAKY] ||
        !hsv_ship_number(vals->v[HSV_LOAD_FLAKY], &counts[HSV_LOAD_FLAKY])) {
        hsv_fail("missing or invalid ship load_flaky"); *bad = 1; return;
    }
    uint64_t ran = counts[HSV_RAN], gated = counts[HSV_GATED];
    if (!counts[HSV_TOTAL] || !ran || counts[HSV_CACHED] || counts[HSV_FAILED] ||
        ran > UINT64_MAX - gated || ran + gated != counts[HSV_TOTAL] ||
        counts[HSV_SKIPS] > ran) {
        hsv_fail("ship suite counts are incomplete or failed"); *bad = 1;
    }
}

static void hsv_check_headlines(const struct hsv_scan *sc, bool ship, int *bad)
{
    if (sc->pass_headlines != 1) {
        hsv_fail("expected exactly one cold ALL TESTS PASSED headline");
        *bad = 1;
    }
    if (ship && sc->filtered_headline) {
        hsv_fail("filtered suite is not full-suite evidence");
        *bad = 1;
    }
    if (sc->cached_headline) {
        hsv_fail("cached pass headline is not hosted cold-suite evidence");
        *bad = 1;
    }
    if (sc->failed_headline) {
        hsv_fail("failure headline is present");
        *bad = 1;
    }
}

static int hsv_check_log_mode(const char *path, FILE *out, bool ship)
{
    size_t size;
    char *buf = hsv_read_file(path, &size);
    struct hsv_scan sc;
    struct hsv_values vals;
    int bad = 0;
    if (!buf)
        return 1;
    hsv_scan_lines(buf, size, &sc);
    memset(&vals, 0, sizeof vals);
    if (sc.verdict_count != 1) {
        hsv_fail("expected exactly one SUITE VERDICT line, found %zu",
                 sc.verdict_count);
        bad = 1;
    } else if (sc.verdict_line) {
        /* The grep prefix guarantees the first two words are SUITE and
         * VERDICT, so like the script's read, that check cannot fail here;
         * tokenize the remainder after the prefix. */
        hsv_parse_tokens(sc.verdict_line + strlen(k_hsv_verdict_prefix),
                         &vals, &bad);
    }
    hsv_validate_fields(&vals, &bad);
    if (!bad && ship) hsv_ship_counts(&vals, &bad);
    if (!bad && !ship) hsv_validate_counts(&vals, &bad);
    hsv_check_headlines(&sc, ship, &bad);
    if (!bad && out && ship)
        fprintf(out, "ship-suite-verdict: PASS: groups_total=%s groups_ran=%s "
                "groups_gated=%s self_skips=%s env_unobserved=%s load_flaky=%s\n",
                vals.v[HSV_TOTAL], vals.v[HSV_RAN], vals.v[HSV_GATED],
                vals.v[HSV_SKIPS], vals.v[HSV_UNOBS], vals.v[HSV_LOAD_FLAKY]);
    if (!bad && out && !ship)
        fprintf(out,
            "hosted-suite-verdict: PASS: cold groups_total=%s groups_ran=%s "
            "groups_gated=%s self_skips=%s\n",
            vals.v[HSV_TOTAL], vals.v[HSV_RAN], vals.v[HSV_GATED],
            vals.v[HSV_SKIPS]);
    free(buf);
    return bad ? 1 : 0;
}

int hsv_check_log(const char *path, FILE *out)
{
    return hsv_check_log_mode(path, out, false);
}

static int hsv_check_ship_log(const char *path, FILE *out)
{
    return hsv_check_log_mode(path, out, true);
}

int check_hosted_suite_verdict_run(int argc, char **argv)
{
    g_hsv_err = stderr;
    if (argc == 1 && strcmp(argv[0], "--self-test") == 0)
        return check_hosted_suite_verdict_selftest();
    if (argc == 2 && strcmp(argv[0], "--ship") == 0 && argv[1][0])
        return hsv_check_ship_log(argv[1], stdout);
    if (argc == 1 && argv[0][0])
        return hsv_check_log(argv[0], stdout);
    hsv_fail("usage: z23-lint check-hosted-suite-verdict --self-test | [--ship] LOG");
    return 2;
}
