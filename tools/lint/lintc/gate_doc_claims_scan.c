/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: document scanning for check-doc-claims (gate_doc_claims.c).
 * dc_scan_claim_file parses "<!-- claim: ... -->" annotations line by
 * line, skipping fenced code blocks, accumulating the prose run above
 * each annotation for context, and evaluating every owned claim.
 * dc_scan_positive_reliance rejects the narrow positive-reliance phrase
 * set in entry documents. dc_doc_has_claim is the literal grep -lF used
 * to select annotation-bearing documents for the --global part.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "gate_doc_claims_priv.h"

struct dc_sf {
    const char *disp;
    long lineno;
    int fenced;
    char prev[DC_CTX];
    size_t prev_n;
};

static const char *dc_claim_body(const char *line)
{
    const char *c = strstr(line, "<!--");
    if (!c)
        return NULL;
    const char *k = strstr(c, "claim:");
    if (!k)
        return NULL;
    const char *b = k + 6;
    if (!strstr(b, "-->"))
        return NULL;
    return b;
}

static int dc_fence(int *fenced, const char *line)
{
    if ((line[0] == '`' && line[1] == '`' && line[2] == '`') ||
        (line[0] == '~' && line[1] == '~' && line[2] == '~')) {
        *fenced ^= 1;
        return 1;
    }
    return *fenced;
}

static void dc_prev_note(struct dc_sf *s, const char *line)
{
    const char *t = dc_ltrim(line);
    if (!*t) {
        s->prev[0] = '\0';
        s->prev_n = 0;
        return;
    }
    if (s->prev_n >= sizeof s->prev - 1)
        return;
    if (s->prev_n)
        s->prev[s->prev_n++] = ' ';
    size_t n = strlen(t);
    if (n > sizeof s->prev - 1 - s->prev_n)
        n = sizeof s->prev - 1 - s->prev_n;
    memcpy(s->prev + s->prev_n, t, n);
    s->prev_n += n;
    s->prev[s->prev_n] = '\0';
}

/* Byte length of the first `max` UTF-8 characters of t; *more is set when
 * t holds further characters (bash ${#ctx} / ${ctx:0:110} count characters). */
static size_t dc_utf8_prefix(const char *t, size_t max, int *more)
{
    size_t i = 0, chars = 0;
    while (t[i]) {
        if (((unsigned char)t[i] & 0xC0) != 0x80) {
            if (chars == max) {
                *more = 1;
                return i;
            }
            chars++;
        }
        i++;
    }
    *more = 0;
    return i;
}

static void dc_ctx_of(struct dc_sf *s, char *ctx, size_t cap)
{
    const char *t = dc_ltrim(s->prev);
    int more = 0;
    size_t n = dc_utf8_prefix(t, 110, &more);
    if (n + 4 > cap)
        n = cap - 4;
    memcpy(ctx, t, n);
    if (more) {
        memcpy(ctx + n, "\xe2\x80\xa6", 3);
        n += 3;
    }
    ctx[n] = '\0';
    if (!n)
        memcpy(ctx, "(no prose line above the annotation)", 37);
}

static int dc_sf_claim(struct dc_sf *s, const char *b)
{
    char body[DC_LINE], reason[DC_REASON], ctx[480];
    const char *e = strstr(b, "-->");
    size_t n = e ? (size_t)(e - b) : strlen(b);
    if (n >= sizeof body)
        n = sizeof body - 1;
    memcpy(body, b, n);
    body[n] = '\0';
    dc_claims_parsed++;
    if (!dc_claim_owned(body)) {
        dc_claims_left++;
        return 0;
    }
    int rc = dc_eval_claim(body, reason, sizeof reason);
    if (rc == 0)
        return 0;
    dc_ctx_of(s, ctx, sizeof ctx);
    if (rc == 2)
        return dc_viol_add("%s:%ld: MALFORMED claim — %s\n      annotation:"
                           " <!-- claim:%s-->", s->disp, s->lineno, reason,
                           body);
    return dc_viol_add("%s:%ld: STALE claim — the document says one thing,"
                       " the tree says another.\n      claim text: %s\n"
                       "      bound predicate:<!-- claim:%s-->\n"
                       "      reality:    %s", s->disp, s->lineno, ctx, body,
                       reason);
}

static int dc_sf_line(void *v, const char *line, size_t len)
{
    struct dc_sf *s = v;
    char raw[DC_LINE];
    size_t n = len;
    s->lineno++;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    if (n >= sizeof raw) {
        fprintf(stderr, "check_doc_claims: line %ld of %s exceeds %d bytes\n",
                s->lineno, s->disp, DC_LINE);
        return 2;
    }
    memcpy(raw, line, n);
    raw[n] = '\0';
    if (dc_fence(&s->fenced, raw))
        return 0;
    const char *b = dc_claim_body(raw);
    if (!b) {
        dc_prev_note(s, raw);
        return 0;
    }
    return dc_sf_claim(s, b);
}

int dc_scan_claim_file(const char *path, const char *disp)
{
    struct dc_sf s;
    s.disp = disp;
    s.lineno = 0;
    s.fenced = 0;
    s.prev_n = 0;
    s.prev[0] = '\0';
    int rc = lc_each_line(path, dc_sf_line, &s, 1);
    if (rc == 1) {
        fprintf(stderr, "check_doc_claims: cannot read document: %s\n", path);
        return 2;
    }
    return rc ? 2 : 0;
}

/* ── positive reliance ─────────────────────────────────────────────── */

static regex_t dc_rel_re[6];
static int dc_rel_ready = 0;

static int dc_rel_init(void)
{
    static const char *pats[6] = {
        "trustworthy[[:space:]-]+(package|build|worker|artifact|node|"
        "evidence)",
        "trusted[[:space:]-]+(package|build|worker)",
        "trust[[:space:]]+us",
        "proven[[:space:]-]+safe",
        "guaranteed[[:space:]-]+secure",
        "proof[[:space:]]+that[[:space:]]+(this|the|our)[[:space:]]+code"
        "[[:space:]]+is[[:space:]]+safe",
    };
    for (int i = 0; i < 6; i++)
        if (regcomp(&dc_rel_re[i], pats[i],
                    REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0)
            return 2;
    dc_rel_ready = 1;
    return 0;
}

struct dc_pr {
    const char *disp;
    long lineno;
    int fenced;
};

static int dc_pr_line(void *v, const char *line, size_t len)
{
    struct dc_pr *s = v;
    char raw[DC_LINE];
    size_t n = len;
    s->lineno++;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    if (n >= sizeof raw) {
        fprintf(stderr, "check_doc_claims: line %ld of %s exceeds %d bytes\n",
                s->lineno, s->disp, DC_LINE);
        return 2;
    }
    memcpy(raw, line, n);
    raw[n] = '\0';
    if (dc_fence(&s->fenced, raw))
        return 0;
    for (int i = 0; i < 6; i++)
        if (regexec(&dc_rel_re[i], raw, 0, NULL, 0) == 0)
            return dc_viol_add("%s:%ld: POSITIVE RELIANCE claim — entry "
                               "documents must describe independently "
                               "verifiable evidence and local policy, not a "
                               "producer or artifact readers should trust."
                               "\n      text: %s", s->disp, s->lineno, raw);
    return 0;
}

int dc_scan_positive_reliance(const char *path, const char *disp)
{
    if (!dc_rel_ready && dc_rel_init())
        return 2;
    dc_reliance_scanned++;
    struct dc_pr s;
    s.disp = disp;
    s.lineno = 0;
    s.fenced = 0;
    int rc = lc_each_line(path, dc_pr_line, &s, 1);
    if (rc == 1) {
        fprintf(stderr, "check_doc_claims: cannot read document: %s\n", path);
        return 2;
    }
    return rc ? 2 : 0;
}

/* ── literal "claim:" selection (grep -lF) ─────────────────────────── */

int dc_doc_has_claim(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[DC_LINE];
    int found = 0;
    while (!found && fgets(line, sizeof line, f))
        if (strstr(line, "claim:"))
            found = 1;
    fclose(f);
    return found;
}

/* ── --list mode ───────────────────────────────────────────────────── */

struct dc_ls {
    const char *path;
    long lineno;
    int fenced;
};

static int dc_ls_line(void *v, const char *line, size_t len)
{
    struct dc_ls *s = v;
    char raw[DC_LINE];
    size_t n = len;
    s->lineno++;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    if (n >= sizeof raw)
        return 2;
    memcpy(raw, line, n);
    raw[n] = '\0';
    if (dc_fence(&s->fenced, raw))
        return 0;
    static regex_t re;
    static int ready;
    if (!ready) {
        if (regcomp(&re, "<!--[[:space:]]*claim:", REG_EXTENDED) != 0)
            return 2;
        ready = 1;
    }
    if (regexec(&re, raw, 0, NULL, 0) == 0)
        printf("%s:%ld: %s\n", s->path, s->lineno, raw);
    return 0;
}

int dc_list_mode(void)
{
    for (int i = 0; i < dc_scan_n; i++) {
        struct dc_ls s;
        s.path = dc_scan_files[i];
        s.lineno = 0;
        s.fenced = 0;
        int rc = lc_each_line(dc_scan_files[i], dc_ls_line, &s, 1);
        if (rc)
            return rc;
    }
    printf("check_doc_claims: %d bound claim(s) across %d document(s)\n",
           dc_claims_parsed, dc_scan_n);
    return 0;
}
