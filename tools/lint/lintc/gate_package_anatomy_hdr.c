/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: check_package_anatomy R4-R6, the public-header scan (guard, macro
 * and inline checks). Shared declarations live in gate_package_anatomy_priv.h.
 */
#include "gate_package_anatomy_priv.h"

/* ---------- public header: R4 guard, R5 macro, R6 inline ---------- */

struct pka_hdr_scan {
    struct cstrip cs;
    char guard[300];
    char exp_if[320], exp_def[320];
    char macro_hit[600], inline_hit[600];
    long lineno;
    int g_if, g_def, g_end, macro, inl;
};

static int pka_macro_match(const char *s)
{
    size_t i = pka_ws(s, 0);
    if (s[i] != '#')
        return 0;
    i = pka_ws(s, i + 1);
    if (strncmp(s + i, "define", 6) != 0)
        return 0;
    i += 6;
    size_t j = pka_ws(s, i);
    if (j == i)
        return 0;
    if (!(isalpha((unsigned char)s[j]) || s[j] == '_'))
        return 0;
    j++;
    while (pka_idch(s[j]))
        j++;
    return s[j] == '(';
}

static int pka_bok(const char *s, size_t i, size_t len, size_t w)
{
    if (i && pka_idch(s[i - 1]))
        return 0;
    if (i + w < len && pka_idch(s[i + w]))
        return 0;
    return 1;
}

static int pka_inline_match(const char *s)
{
    size_t len = strlen(s);
    for (size_t i = 0; s[i]; i++) {
        if (strncmp(s + i, "__inline", 8) == 0 && pka_bok(s, i, len, 8))
            return 1;
        if (strncmp(s + i, "inline", 6) == 0 && pka_bok(s, i, len, 6))
            return 1;
    }
    return 0;
}

static void pka_hdr_guards(struct pka_hdr_scan *s, const char *raw)
{
    if (!s->g_if && strcmp(raw, s->exp_if) == 0)
        s->g_if = 1;
    if (!s->g_def && strcmp(raw, s->exp_def) == 0)
        s->g_def = 1;
    if (!s->g_end && strncmp(raw, "#endif", 6) == 0)
        s->g_end = 1;
}

static int pka_hdr_record(char *dst, size_t cap, long lineno, const char *code)
{
    int w = snprintf(dst, cap, "%ld:%.380s", lineno, code);
    return ovf(w, cap) ? 2 : 0;
}

static int pka_hdr_line(void *v, const char *line, size_t len)
{
    struct pka_hdr_scan *s = v;
    char raw[PKA_LINE], code[PKA_LINE];
    size_t n = len;
    s->lineno++;
    if (n && line[n - 1] == '\n')
        n--;
    if (n >= sizeof raw) {
        fprintf(stderr, "%s: line %ld of header exceeds %d bytes\n",
                k_pka_gate, s->lineno, PKA_LINE);
        return 2;
    }
    memcpy(raw, line, n);
    raw[n] = '\0';
    pka_hdr_guards(s, raw);
    if (s->macro && s->inl)
        return 0;
    cstrip_line(&s->cs, raw, n, code, sizeof code);
    if (!s->macro && pka_macro_match(code)) {
        s->macro = 1;
        if (pka_hdr_record(s->macro_hit, sizeof s->macro_hit, s->lineno, code))
            return 2;
    }
    if (!s->inl && pka_inline_match(code)) {
        s->inl = 1;
        if (pka_hdr_record(s->inline_hit, sizeof s->inline_hit, s->lineno,
                           code))
            return 2;
    }
    return 0;
}

static int pka_r456(const char *hdr, const char *pkg, struct pka_ctx *cf)
{
    struct pka_hdr_scan s;
    memset(&s, 0, sizeof s);
    pka_upper(pkg, s.guard, sizeof s.guard);
    if (ovf(snprintf(s.exp_if, sizeof s.exp_if, "#ifndef %s_H", s.guard),
            sizeof s.exp_if))
        return 2;
    if (ovf(snprintf(s.exp_def, sizeof s.exp_def, "#define %s_H", s.guard),
            sizeof s.exp_def))
        return 2;
    int rc = lc_each_line(hdr, pka_hdr_line, &s, 1);
    if (rc) {
        fprintf(stderr, "%s: FATAL — cannot strip comments from %s\n",
                k_pka_gate, hdr);
        return 2;
    }
    if (!s.g_if)
        PKA_FAIL("%s: public header missing #ifndef %s_H", pkg, s.guard);
    if (!s.g_def)
        PKA_FAIL("%s: public header missing #define %s_H", pkg, s.guard);
    if (!s.g_end)
        PKA_FAIL("%s: public header missing #endif guard close", pkg);
    if (s.macro)
        PKA_FAIL("%s: function-like macro in public header: %s "
                 "(use enum/constexpr/_Generic)", pkg, s.macro_hit);
    if (s.inl)
        PKA_FAIL("%s: inline function in public header: %s "
                 "(the archive owns definitions)", pkg, s.inline_hit);
    return 0;
}

int pka_r4(const char *dir, const char *pkg, struct pka_ctx *cf)
{
    char incpfx[PKA_PATH], want[PKA_PATH];
    if (ovf(snprintf(incpfx, sizeof incpfx, "%s/include/", dir), sizeof incpfx))
        return 2;
    if (ovf(snprintf(want, sizeof want, "%s/include/%s/%s.h", dir, pkg, pkg),
            sizeof want))
        return 2;
    size_t pl = strlen(incpfx), hi = 0;
    int cnt = 0;
    for (int i = 0; i < g_pka_fl.n; i++) {
        size_t len = strlen(g_pka_fl.p[i]);
        if (len >= pl + 2 && strncmp(g_pka_fl.p[i], incpfx, pl) == 0
            && strcmp(g_pka_fl.p[i] + len - 2, ".h") == 0) {
            cnt++;
            hi = (size_t)i;
        }
    }
    if (cnt != 1)
        PKA_FAIL("%s: expected exactly 1 public header, found %d", pkg, cnt);
    else if (strcmp(g_pka_fl.p[hi], want) != 0)
        PKA_FAIL("%s: public header is %s, want include/%s/%s.h", pkg,
                 g_pka_fl.p[hi] + strlen(dir) + 1, pkg, pkg);
    else
        return pka_r456(g_pka_fl.p[hi], pkg, cf);
    return 0;
}

