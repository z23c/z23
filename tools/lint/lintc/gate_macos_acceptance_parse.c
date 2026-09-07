/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-macos-acceptance
 * Third file of the check-macos-acceptance family (the 700-line family
 * ceiling split): the matrix/catalog text parser — row and registry
 * loading (matrix_rows(), required_groups(), registered_groups(), and
 * their shared "PREFIX(<ident>)$" line matcher), plus the small sort/join
 * helpers validate() uses to build its exact-set comparison strings.
 * gate_macos_acceptance.c holds the die/slurp entry points, validate()'s
 * own row/contract checks, the Makefile/ACCEPT-script wiring checks, and
 * the gate entry; gate_macos_acceptance_selftest.c holds --selftest.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_macos_acceptance_priv.h"

int mac_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 1;
    size_t n = fread(buf, 1, cap - 1, f);
    int err = ferror(f);
    buf[n] = '\0';
    fclose(f);
    return err ? 1 : 0;
}

void mac_strip_ws(const char *in, char *out, size_t cap)
{
    size_t oi = 0;
    for (const char *p = in; *p && oi + 1 < cap; p++)
        if (!isspace((unsigned char)*p))
            out[oi++] = *p;
    out[oi] = '\0';
}

/* ── matrix_rows(): "^ZCL_MACOS_CAPABILITY\(" lines, content between the
 * opening "(" and a trailing ")" (optional trailing whitespace). ────────── */

int mac_load_rows(const char *matrix_text, struct mac_rows *out)
{
    out->n = 0;
    const char *p = matrix_text;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t linelen = eol ? (size_t)(eol - p) : strlen(p);
        static const char pfx[] = "ZCL_MACOS_CAPABILITY(";
        size_t pfxlen = sizeof pfx - 1;
        if (linelen >= pfxlen && strncmp(p, pfx, pfxlen) == 0) {
            size_t e = linelen;
            while (e > pfxlen && isspace((unsigned char)p[e - 1]))
                e--;
            if (e > pfxlen && p[e - 1] == ')') {
                size_t n = e - 1 - pfxlen;
                if (out->n >= MAC_MAXROWS || n >= MAC_GROUPS)
                    return die("z23-lint: derived buffer overflow\n", "");
                memcpy(out->r[out->n].groups, p + pfxlen, n);
                out->r[out->n].groups[n] = '\0';
                out->n++;
            }
        }
        p = eol ? eol + 1 : p + linelen;
    }
    return 0;
}

/* Split one raw row body "id,state,reason,groups..." into 4 fields, the
 * last holding everything from the 3rd comma onward (bash `read`'s
 * remainder-in-last-var behavior), then strip ALL whitespace from each. */
void mac_split_row(const char *raw, struct mac_row *out)
{
    const char *c1 = strchr(raw, ',');
    const char *c2 = c1 ? strchr(c1 + 1, ',') : NULL;
    const char *c3 = c2 ? strchr(c2 + 1, ',') : NULL;
    char tmp[MAC_GROUPS];
    if (!c1) { mac_strip_ws(raw, out->id, MAC_ID); out->state[0] = out->reason[0] = out->groups[0] = '\0'; return; }
    size_t n = (size_t)(c1 - raw);
    if (n >= sizeof tmp) n = sizeof tmp - 1;
    memcpy(tmp, raw, n); tmp[n] = '\0';
    mac_strip_ws(tmp, out->id, MAC_ID);
    if (!c2) { mac_strip_ws(c1 + 1, out->state, MAC_STATE); out->reason[0] = out->groups[0] = '\0'; return; }
    n = (size_t)(c2 - (c1 + 1));
    if (n >= sizeof tmp) n = sizeof tmp - 1;
    memcpy(tmp, c1 + 1, n); tmp[n] = '\0';
    mac_strip_ws(tmp, out->state, MAC_STATE);
    if (!c3) { mac_strip_ws(c2 + 1, out->reason, MAC_REASON); out->groups[0] = '\0'; return; }
    n = (size_t)(c3 - (c2 + 1));
    if (n >= sizeof tmp) n = sizeof tmp - 1;
    memcpy(tmp, c2 + 1, n); tmp[n] = '\0';
    mac_strip_ws(tmp, out->reason, MAC_REASON);
    mac_strip_ws(c3 + 1, out->groups, MAC_GROUPS);
}

/* required_groups(): "^ZCL_MACOS_REQUIRED_TEST\([A-Za-z_0-9]+\)[[:space:]]*$" */

/* Shared "PREFIX(<ident>)<trailing ws>$" line matcher for both the
 * required-groups and registered-groups parsers below: finds pfx starting
 * at line[i], then a trailing ')' after optional whitespace, anchored at
 * end of line. On match, out_start/out_len bound the identifier body. */
static int mac_extract_paren_ident(const char *line, size_t i, size_t linelen,
                                   const char *pfx, size_t pfxlen,
                                   size_t *out_start, size_t *out_len)
{
    if (linelen - i < pfxlen || strncmp(line + i, pfx, pfxlen) != 0)
        return 0;
    size_t s = i + pfxlen;
    size_t e = linelen;
    while (e > s && isspace((unsigned char)line[e - 1]))
        e--;
    if (e <= s || line[e - 1] != ')')
        return 0;
    e--;
    *out_start = s;
    *out_len = e - s;
    return 1;
}

/* Identifier body must be non-empty and all [A-Za-z0-9_]. */
static int mac_ident_ok(const char *s, size_t n)
{
    if (n == 0)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (!(isalnum(ch) || ch == '_'))
            return 0;
    }
    return 1;
}

static int mac_load_required_line(const char *p, size_t linelen,
                                  struct mac_names *out)
{
    static const char pfx[] = "ZCL_MACOS_REQUIRED_TEST(";
    size_t pfxlen = sizeof pfx - 1;
    size_t s, n;
    if (!mac_extract_paren_ident(p, 0, linelen, pfx, pfxlen, &s, &n))
        return 0;
    if (!mac_ident_ok(p + s, n))
        return 0;
    if (out->n_used >= MAC_MAXREQ || n >= MAC_ID)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(out->n[out->n_used], p + s, n);
    out->n[out->n_used][n] = '\0';
    out->n_used++;
    return 0;
}

int mac_load_required(const char *matrix_text, struct mac_names *out)
{
    out->n_used = 0;
    const char *p = matrix_text;
    int rc = 0;
    while (rc == 0 && *p) {
        const char *eol = strchr(p, '\n');
        size_t linelen = eol ? (size_t)(eol - p) : strlen(p);
        rc = mac_load_required_line(p, linelen, out);
        p = eol ? eol + 1 : p + linelen;
    }
    return rc;
}

/* registered_groups(): ZCL_TEST_GROUP(x)->test_x, ZCL_SPEC_GROUP(x)->spec_x,
 * leading whitespace allowed, whole-line anchored. */

static int mac_reg_line(const char *line, size_t linelen, const char *pfx,
                        const char *out_prefix, struct mac_reg *out)
{
    size_t i = 0;
    while (i < linelen && isspace((unsigned char)line[i]))
        i++;
    size_t pfxlen = strlen(pfx);
    size_t s, n;
    if (!mac_extract_paren_ident(line, i, linelen, pfx, pfxlen, &s, &n))
        return 0;
    if (!mac_ident_ok(line + s, n))
        return 0;
    if (out->n_used >= MAC_MAXREG)
        return die("z23-lint: derived buffer overflow\n", "");
    int k = snprintf(out->n[out->n_used], MAC_REG, "%s%.*s", out_prefix,
                     (int)n, line + s);
    if (k < 0 || (size_t)k >= MAC_REG)
        return die("z23-lint: derived buffer overflow\n", "");
    out->n_used++;
    return 0;
}

int mac_load_registered(const char *catalog_text, struct mac_reg *out)
{
    out->n_used = 0;
    const char *p = catalog_text;
    int rc = 0;
    while (rc == 0 && *p) {
        const char *eol = strchr(p, '\n');
        size_t linelen = eol ? (size_t)(eol - p) : strlen(p);
        rc = mac_reg_line(p, linelen, "ZCL_TEST_GROUP(", "test_", out);
        if (rc == 0)
            rc = mac_reg_line(p, linelen, "ZCL_SPEC_GROUP(", "spec_", out);
        p = eol ? eol + 1 : p + linelen;
    }
    return rc;
}

int mac_reg_has(const struct mac_reg *reg, const char *name)
{
    for (int i = 0; i < reg->n_used; i++)
        if (strcmp(reg->n[i], name) == 0)
            return 1;
    return 0;
}

static int mac_str_cmp(const void *a, const void *b)
{ return strcmp((const char *)a, (const char *)b); }

/* sorted(-dedup optional) space-join of a name list, into out. */
void mac_join_sorted(const char names[][MAC_ID], int n, int dedup,
                            char *out, size_t cap, const char *sep)
{
    static char tmp[MAC_MAXREG][MAC_ID];
    int m = n < MAC_MAXREG ? n : MAC_MAXREG;
    for (int i = 0; i < m; i++)
        snprintf(tmp[i], MAC_ID, "%s", names[i]);
    qsort(tmp, (size_t)m, MAC_ID, mac_str_cmp);
    size_t used = 0;
    out[0] = '\0';
    for (int i = 0; i < m; i++) {
        if (dedup && i > 0 && strcmp(tmp[i], tmp[i - 1]) == 0)
            continue;
        int k = snprintf(out + used, cap - used, "%s%s", used ? sep : "",
                         tmp[i]);
        if (k < 0 || (size_t)k >= cap - used)
            return;
        used += (size_t)k;
    }
}

void mac_union_add(struct mac_union *u, const char *name)
{
    if (u->n_used >= MAC_MAXUNION)
        return;
    snprintf(u->n[u->n_used], MAC_ID, "%s", name);
    u->n_used++;
}
