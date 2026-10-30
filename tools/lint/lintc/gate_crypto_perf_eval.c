/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the verdict arithmetic of check-crypto-perf. The shell script
 * compared bench and baseline fields with awk: a field counts as a number only
 * when the whole field looks like one (otherwise the comparison is textual),
 * and arithmetic reads the leading decimal number. Only decimal spans are
 * converted, so hex, inf and nan never reach strtod. These rules are kept so
 * every verdict matches the script's.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_crypto_perf_priv.h"

static int ccp_blank(char c)
{
    return c == ' ' || c == '\t' || c == '\n';
}

/* End of the decimal number starting at p, or NULL when there is none. */
static const char *ccp_span(const char *p)
{
    const char *q = p;
    int digits = 0;
    if (*q == '+' || *q == '-')
        q++;
    while (isdigit((unsigned char)*q)) {
        q++;
        digits++;
    }
    if (*q == '.') {
        q++;
        while (isdigit((unsigned char)*q)) {
            q++;
            digits++;
        }
    }
    if (digits == 0)
        return NULL;
    if (*q == 'e' || *q == 'E') {
        const char *r = q + 1;
        if (*r == '+' || *r == '-')
            r++;
        if (isdigit((unsigned char)*r)) {
            while (isdigit((unsigned char)*r))
                r++;
            q = r;
        }
    }
    return q;
}

/* Value of the decimal number at the start of s (after blanks). Returns 1 when
 * there is one (*v set, *end past it), 0 when there is none (*v is 0, *end is
 * the first non-blank byte), -1 when the span is too long to convert. Only the
 * validated span is copied out, so strtod never reads hex, inf or nan. */
static int ccp_decimal(const char *s, double *v, const char **end)
{
    char buf[CCP_NUM];
    const char *p = s;
    while (ccp_blank(*p))
        p++;
    const char *q = ccp_span(p);
    *v = 0.0;
    *end = p;
    if (!q)
        return 0;
    if ((size_t)(q - p) >= sizeof buf)
        return -1;
    memcpy(buf, p, (size_t)(q - p));
    buf[q - p] = '\0';
    *v = strtod(buf, NULL);
    *end = q;
    return 1;
}

/* awk's numeric value of a string: its leading decimal number, or 0. */
static int ccp_num(const char *s, double *v)
{
    const char *end;
    return ccp_decimal(s, v, &end) < 0 ? 2 : 0;
}

/* awk's numeric-string test: the whole field is one decimal number. */
static int ccp_strnum(const char *s, double *v)
{
    const char *end;
    if (ccp_decimal(s, v, &end) != 1)
        return 0;
    while (ccp_blank(*end))
        end++;
    return *end == '\0';
}

int ccp_is_number(const char *s)
{
    double v;
    return ccp_strnum(s, &v);
}

/* awk comparison: numeric when both sides are numeric strings, else textual. */
static int ccp_cmp(const char *a, const char *b)
{
    double x, y;
    if (ccp_strnum(a, &x) && ccp_strnum(b, &y))
        return (x > y) - (x < y);
    int r = strcmp(a, b);
    return (r > 0) - (r < 0);
}

static int ccp_fmt4(double v, char *out, size_t cap)
{
    return ovf(snprintf(out, cap, "%.4f", v), cap);
}

/* The script's fdiv: (b==0)?0:a/b printed with %.4f. A non-numeric rust field
 * made awk divide by zero, which left the ratio empty. */
static int ccp_ratio(const char *meas, const char *rust, char *out, size_t cap)
{
    double b, a;
    if (!ccp_strnum(rust, &b)) {
        out[0] = '\0';
        return 0;
    }
    if (ccp_num(meas, &a))
        return 2;
    return ccp_fmt4(b == 0 ? 0.0 : a / b, out, cap);
}

/* The script's fmul: cbase * (1 + margin), each factor rounded to %.4f. */
static int ccp_ceiling(const char *cbase, const char *margin, char *out,
                       size_t cap)
{
    char mult[CCP_NUM];
    double m, c;
    if (ccp_num(margin, &m) || ccp_num(cbase, &c))
        return 2;
    if (ccp_fmt4(1.0 + m, mult, sizeof mult))
        return 2;
    double k;
    if (ccp_num(mult, &k))
        return 2;
    return ccp_fmt4(c * k, out, cap);
}

int ccp_eval_row(const char *meas, const char *cbase, const char *rust,
                 const char *mode, const char *margin, char *ratio,
                 size_t rcap)
{
    char ceil[CCP_NUM];
    int beat = strcmp(mode, "beat") == 0;
    if (ccp_ratio(meas, rust, ratio, rcap)
        || ccp_ceiling(cbase, margin, ceil, sizeof ceil))
        return -1;
    if (beat && ccp_cmp(meas, rust) >= 0)
        return CCP_FAIL_BEAT;
    if (ccp_cmp(meas, ceil) > 0)
        return CCP_FAIL_RATCHET;
    if (!beat)
        return CCP_OK_BEHIND;
    if (ccp_cmp(ceil, rust) > 0)
        return CCP_FAIL_CONFIG;
    return CCP_OK_BEAT;
}

const char *ccp_verdict_name(int v)
{
    switch (v) {
    case CCP_OK_BEAT: return "OK_BEAT";
    case CCP_OK_BEHIND: return "OK_BEHIND";
    case CCP_FAIL_RATCHET: return "FAIL_RATCHET";
    case CCP_FAIL_BEAT: return "FAIL_BEAT";
    default: return "FAIL_CONFIG";
    }
}

const char *ccp_verdict_tag(int v)
{
    switch (v) {
    case CCP_OK_BEAT: return "BEAT (ahead of rust)";
    case CCP_OK_BEHIND: return "behind — ratchet holds";
    case CCP_FAIL_RATCHET: return "*** FAIL: self-regression > margin ***";
    case CCP_FAIL_BEAT: return "*** FAIL: lost lead vs rust (ratio>=1) ***";
    default: return "*** FAIL: beat row mis-pinned (no ratchet headroom vs rust) ***";
    }
}
