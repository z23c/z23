/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: gate — check-no-uncited-victory (replaces
 * tools/scripts/check_no_uncited_victory.sh). Guards the one live-state
 * page, docs/HANDOFF.md (ZCL_LINT_MODE override), against uncited
 * "cured / at tip / fully synced" claims in prose — this repo shipped 9+
 * such claims in six weeks, every one later false (~103 wedge-FIXED-then-
 * re-wedge cycles). Per-paragraph: any victory phrase with no citation
 * token (or historical <!-- victory-ok: ... --> override) in the same
 * paragraph is a violation. HARD gate, no baseline. Split 2026-09-07 out
 * of gate_narrative_integrity_fences.c (pure move, no code change) — see
 * check-no-dev-history-in-contracts in the sibling file
 * gate_no_dev_history_in_contracts.c for the paired narrative-integrity
 * gate this file used to share a translation unit with.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
enum { NI_PATH = 512, NUV_DOC = 65536, NUV_HIT = 16, NUV_HLEN = 64 };
static const char k_nuv_cite[] =
    "uptime-ledger|slo-summary:|verdict=pass|wall_clock_seconds|"
    "gap_vs_oracle|(ts=|\"ts\"[[:space:]]*:[[:space:]]*)[0-9]|victory-ok:";
static const char *const k_nuv_v[] = {
    "at tip", "at-tip", "reaches tip", "holds tip", "fully synced", "cured",
    "unwedged", "wedge cleared", "wedge closed", "wedge fixed",
    "soak window open", "soak window running", "proven live", "live-proven",
    "stable at tip"
};
enum { NUV_NV = (int)(sizeof k_nuv_v / sizeof k_nuv_v[0]) };
static int ni_ws(unsigned char c)
{ return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'; }
static int ni_wc(unsigned char c)
{ return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'; }
static char ni_foldc(char c)
{ return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c; }
static int ni_row_cmp(const void *a, const void *b)
{ return strcmp(a, b); }
static const char *ni_base(const char *p)
{ const char *s = strrchr(p, '/'); return s ? s + 1 : p; }
static int ni_quiet(int (*fn)(void), int *code)
{
    FILE *t = tmpfile();
    if (!t) return die("z23-lint: tmpfile failed\n", "");
    fflush(stdout); fflush(stderr);
    int fd = fileno(t);
    int ou = dup(STDOUT_FILENO), eu = dup(STDERR_FILENO);
    if (ou < 0 || eu < 0 || dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
        return die("z23-lint: dup2 failed\n", "");
    *code = fn();
    fflush(stdout); fflush(stderr);
    if (dup2(ou, STDOUT_FILENO) < 0 || dup2(eu, STDERR_FILENO) < 0)
        return die("z23-lint: dup2 failed\n", "");
    close(ou); close(eu); fclose(t);
    return 0;
}
static int nuv_find(const char *fold, size_t from, size_t n, const char *pat,
                    size_t plen, size_t *at)
{
    if (plen == 0 || from + plen > n) return 0;
    for (size_t i = from; i + plen <= n; i++) {
        if (memcmp(fold + i, pat, plen) != 0) continue;
        if (i > 0 && ni_wc((unsigned char)fold[i - 1])) continue;
        if (i + plen < n && ni_wc((unsigned char)fold[i + plen])) continue;
        *at = i;
        return 1;
    }
    return 0;
}
static int nuv_next(const char *fold, size_t from, size_t n, size_t *at,
                    size_t *plen, int *pi)
{
    size_t best = n + 1, bl = 0;
    int bp = -1;
    for (int p = 0; p < NUV_NV; p++) {
        size_t pl = strlen(k_nuv_v[p]), pos = 0;
        if (nuv_find(fold, from, n, k_nuv_v[p], pl, &pos) && pos < best) {
            best = pos; bp = p; bl = pl;
        }
    }
    if (bp < 0) return 0;
    *at = best; *plen = bl; *pi = bp;
    return 1;
}
static int nuv_check_para(const char *doc, int s, int e, const char *text,
                          size_t n, regex_t *cite, int *found)
{
    char fold[NUV_DOC];
    if (n >= sizeof fold) return die("z23-lint: derived buffer overflow\n", "");
    for (size_t i = 0; i < n; i++) fold[i] = ni_foldc(text[i]);
    fold[n] = '\0';
    char hits[NUV_HIT][NUV_HLEN];
    int nh = 0;
    size_t from = 0, at = 0, plen = 0;
    int pi = 0;
    while (nuv_next(fold, from, n, &at, &plen, &pi)) {
        if (nh >= NUV_HIT) return die("z23-lint: scan-set overflow\n", "");
        if (ovf(snprintf(hits[nh], NUV_HLEN, "%.*s", (int)plen, text + at), NUV_HLEN))
            return 2;
        nh++;
        from = at + plen;
    }
    if (nh == 0 || regexec(cite, fold, 0, NULL, 0) == 0) return 0;
    qsort(hits, (size_t)nh, NUV_HLEN, ni_row_cmp);
    int w = 1;
    for (int i = 1; i < nh; i++)
        if (strcmp(hits[i], hits[w - 1]) != 0) {
            if (w != i) memcpy(hits[w], hits[i], NUV_HLEN);
            w++;
        }
    char joined[512];
    size_t used = 0;
    joined[0] = '\0';
    for (int i = 0; i < w; i++) {
        int k = snprintf(joined + used, sizeof joined - used, "%s%s", i ? "," : "", hits[i]);
        if (ovf(k, sizeof joined - used)) return 2;
        used += (size_t)k;
    }
    (*found)++;
    printf("  %s:%d-%d: uncited victory phrase(s): %s\n", ni_base(doc), s, e, joined);
    return 0;
}
static int nuv_append(char *para, size_t *plen, const char *ls, const char *p, int nl)
{
    size_t add = (size_t)(p - ls);
    if (*plen + (nl ? 1 : 0) + add >= NUV_DOC)
        return die("z23-lint: derived buffer overflow\n", "");
    if (nl) para[(*plen)++] = '\n';
    memcpy(para + *plen, ls, add);
    *plen += add;
    return 0;
}
static int nuv_blank(const char *ls, const char *p)
{ for (; ls < p; ls++) if (!ni_ws((unsigned char)*ls)) return 0; return 1; }
static int nuv_paras(const char *doc, const char *buf, size_t n, regex_t *cite)
{
    int found = 0, lineno = 1, pstart = 0, active = 0, rc = 0;
    const char *ls = buf, *p = buf, *end = buf + n;
    char para[NUV_DOC];
    size_t plen = 0;
    while (rc == 0 && p <= end) {
        int at_eof = (p == end), is_nl = (!at_eof && *p == '\n');
        if (!at_eof && !is_nl) { p++; continue; }
        int blank = nuv_blank(ls, p);
        if (blank) {
            if (active) {
                para[plen] = '\0';
                rc = nuv_check_para(doc, pstart, lineno - 1, para, plen, cite, &found);
                active = 0; plen = 0;
            }
        } else if (!active) {
            pstart = lineno; plen = 0;
            rc = nuv_append(para, &plen, ls, p, 0);
            active = 1;
        } else {
            rc = nuv_append(para, &plen, ls, p, 1);
        }
        if (at_eof) break;
        lineno++; p++; ls = p;
    }
    if (rc == 0 && active) {
        para[plen] = '\0';
        rc = nuv_check_para(doc, pstart, lineno, para, plen, cite, &found);
    }
    if (rc) return rc;
    if (!found) return 0;
    printf("\nFAIL: %d uncited victory claim(s) in %s.\n", found, doc);
    fputs("  This repo shipped 9+ false 'cured / at tip' claims (~103 wedge-\n"
          "  FIXED -> re-wedge cycles). Cite a real proof in the SAME paragraph\n"
          "  (VERDICT=PASS, gap_vs_oracle, uptime-ledger, a ts= stamp, slo-summary:,\n"
          "  WALL_CLOCK_SECONDS) or, for HISTORICAL narration only, add\n"
          "  <!-- victory-ok: <reason> -->. Never override a current-state claim.\n",
          stdout);
    return 1;
}
static int nuv_scan_doc(const char *doc)
{
    struct stat st;
    if (stat(doc, &st) != 0 || !S_ISREG(st.st_mode)) {
        printf("FAIL: %s is missing — the victory-claim scan set is empty.\n", doc);
        fputs("      This is the one live-state page; it must exist and carry\n"
              "      current node state, or an uncited claim could hide here.\n", stdout);
        return 2;
    }
    FILE *f = fopen(doc, "r");
    if (!f) return die("z23-lint: cannot open %s\n", doc);
    char buf[NUV_DOC];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    int err = ferror(f);
    fclose(f);
    if (err) return die("z23-lint: cannot open %s\n", doc);
    if (n == sizeof buf - 1) return die("z23-lint: derived buffer overflow\n", "");
    buf[n] = '\0';
    int nlines = 0;
    for (size_t i = 0; i < n; i++) if (buf[i] == '\n') nlines++;
    if (nlines < 10) {
        printf("FAIL: %s has %d lines (< 10) — hollow scan set.\n", doc, nlines);
        fputs("      The live-state page must carry real current state, not a\n"
              "      stub; a near-empty file would pass this gate vacuously.\n", stdout);
        return 2;
    }
    regex_t cite;
    int rc = reg_fail(&cite, regcomp(&cite, k_nuv_cite, REG_EXTENDED | REG_NOSUB));
    if (rc) return rc;
    rc = nuv_paras(doc, buf, n, &cite);
    regfree(&cite);
    return rc;
}
static const char *nuv_doc(void)
{
    const char *mode = getenv("ZCL_LINT_MODE");
    struct stat st;
    if (mode && mode[0] && stat(mode, &st) == 0 && S_ISREG(st.st_mode)) return mode;
    return "docs/HANDOFF.md";
}
int check_no_uncited_victory_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    const char *doc = nuv_doc();
    int rc = nuv_scan_doc(doc);
    if (rc == 0) printf("  OK: no uncited victory claim in %s\n", doc);
    return rc;
}
#define NUV_FILL \
    "Filler line one to clear the hollow-gate line floor.\n" \
    "Filler line two to clear the hollow-gate line floor.\n" \
    "Filler line three to clear the hollow-gate line floor.\n" \
    "Filler line four to clear the hollow-gate line floor.\n" \
    "Filler line five to clear the hollow-gate line floor.\n"
static const char k_nuv_clean[] =
    "# HANDOFF — current state\n\n"
    "The canonical node is blocked. H* has not advanced for 13 days.\n"
    "Primary blocker: catchup_stalled, a downstream symptom of the fold blocker.\n\n"
    "The wedge root cause is closed in code; the live apply is pending the owner\n"
    "gate. The tip_finalize rate bug is still open and gates any catch-up.\n\n"
    "Read the live node before trusting this file.\n"
    "Verify with typed status commands.\nDo not deploy on unit-test green alone.\n";
static const char k_nuv_uncited[] =
    "# HANDOFF — current state\n\n"
    "The node is at tip and holding. Everything is fine now.\n"
    "No further action is required and we can move on.\n\n" NUV_FILL;
static const char k_nuv_cited[] =
    "# HANDOFF — current state\n\n"
    "The soak run reached tip and held: VERDICT=PASS, gap_vs_oracle=0,\n"
    "WALL_CLOCK_SECONDS=54, ts=1690000000. This is a ledgered proof.\n\n" NUV_FILL;
static const char k_nuv_over[] =
    "# HANDOFF — current state\n\n"
    "The old July claim that the wedge was cured is historical, not current.\n"
    "<!-- victory-ok: narrating a superseded false-victory, not a live claim -->\n\n"
    NUV_FILL;
static char g_nuv_path[NI_PATH];
static int nuv_scan_g(void) { return nuv_scan_doc(g_nuv_path); }
static int nuv_st_case(const char *root, const char *name, const char *body, int want)
{ int got = 0, rc;
    if (ovf(snprintf(g_nuv_path, sizeof g_nuv_path, "%s/%s", root, name), sizeof g_nuv_path))
        return 2;
    if (body && (rc = csr_write(g_nuv_path, body)) != 0) return rc;
    rc = ni_quiet(nuv_scan_g, &got);
    if (rc) return rc;
    if (got != want) {
        fprintf(stderr, "  FAIL: %s expected rc=%d got rc=%d\n", name, want, got);
        return 1;
    }
    printf("  ok: %s (rc=%d)\n", name, got);
    return 0;
}
int check_no_uncited_victory_selftest(void)
{
    if (csr_mkdirs("test-tmp")) return 2;
    char tmpl[] = "test-tmp/nuv_st.XXXXXX";
    char *tmp = mkdtemp(tmpl);
    if (!tmp) return die("z23-lint: mkdir failed: %s\n", "test-tmp");
    int bad = nuv_st_case(tmp, "clean.md", k_nuv_clean, 0); // error-doc-ref-ok: planted selftest fixture
    bad |= nuv_st_case(tmp, "uncited.md", k_nuv_uncited, 1); // error-doc-ref-ok: planted selftest fixture
    bad |= nuv_st_case(tmp, "cited.md", k_nuv_cited, 0); // error-doc-ref-ok: planted selftest fixture
    bad |= nuv_st_case(tmp, "override.md", k_nuv_over, 0); // error-doc-ref-ok: planted selftest fixture
    bad |= nuv_st_case(tmp, "short.md", "too short\n", 2); // error-doc-ref-ok: planted selftest fixture
    bad |= nuv_st_case(tmp, "does-not-exist", NULL, 2);
    (void)rap_rm_rf(tmp);
    if (bad) { fputs("selftest: FAIL\n", stdout); return 1; }
    fputs("selftest: PASS\n", stdout);
    return 0;
}
