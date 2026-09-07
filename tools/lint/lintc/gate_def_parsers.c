/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gates that parse one or two .def manifests and check a closed
 * vocabulary.
 *
 * Gates: check-persona-resolves, check-prompt-templates
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum {
    DEF_SLURP = 65536, DEF_CALLS = 48, DEF_LITS = 16, DEF_LIT_W = 2048,
    DEF_RAW = 8192, DEF_STANCE = 4096, DEF_LS = 262144, PRT_ROWS = 48,
    PRT_KINDS = 24, PRT_ALWAYS = 16, PRT_FIELD = 96, PR_STANCE_MIN = 40,
    PR_STANCE_MAX = 700, PRT_SEC_FLOOR = 3
};

struct def_call { char raw[DEF_RAW]; char lit[DEF_LITS][DEF_LIT_W]; int n_lit; };
struct def_calls { struct def_call row[DEF_CALLS]; int n; };

static int env_int_or(const char *name, int fallback)
{
    const char *e = getenv(name);
    return (e && e[0]) ? atoi(e) : fallback;
}

static void crush_ht(char *s)
{
    char *d = s;
    for (; *s; s++)
        if (*s != ' ' && *s != '\t') *d++ = *s;
    *d = '\0';
}

static int def_take_lit(const char **rest, char *dst, size_t cap)
{
    const char *p = *rest;
    while (*p && *p != '"') p++;
    if (*p != '"') return 0;
    p++;
    size_t n = 0;
    while (*p) {
        if (*p == '\\' && p[1]) {
            if (n + 2 >= cap) return die("z23-lint: derived buffer overflow\n", "");
            dst[n++] = *p++;
            dst[n++] = *p++;
            continue;
        }
        if (*p == '"') { dst[n] = '\0'; *rest = p + 1; return 1; }
        if (n + 1 >= cap) return die("z23-lint: derived buffer overflow\n", "");
        dst[n++] = *p++;
    }
    *rest = p;
    return 0;
}

static const char *def_line_end(const char *p)
{
    const char *eol = p;
    while (*eol && *eol != '\n') eol++;
    return eol;
}

static int def_line_closes(const char *p, size_t linelen)
{
    size_t trim = linelen;
    while (trim && isspace((unsigned char)p[trim - 1])) trim--;
    return trim && p[trim - 1] == ')';
}

static int def_call_starts(int collecting, const char *p, size_t linelen,
                           const char *prefix, size_t plen)
{
    return !collecting && linelen >= plen && memcmp(p, prefix, plen) == 0;
}

static int def_finish_call(struct def_calls *out, const char *call, size_t used)
{
    if (out->n >= DEF_CALLS)
        return die("z23-lint: derived buffer overflow\n", "");
    struct def_call *c = &out->row[out->n];
    memcpy(c->raw, call, used + 1);
    const char *r = c->raw;
    c->n_lit = 0;
    for (;;) {
        if (c->n_lit >= DEF_LITS)
            return die("z23-lint: derived buffer overflow\n", "");
        int k = def_take_lit(&r, c->lit[c->n_lit], DEF_LIT_W);
        if (k == 0) break;
        if (k != 1) return 2;
        c->n_lit++;
    }
    out->n++;
    return 0;
}

static int def_parse_calls(const char *text, const char *prefix, struct def_calls *out)
{
    out->n = 0;
    int collecting = 0;
    char call[DEF_RAW];
    size_t used = 0, plen = strlen(prefix);
    const char *p = text;
    while (*p) {
        const char *eol = def_line_end(p);
        size_t linelen = (size_t)(eol - p);
        int closes = def_line_closes(p, linelen);
        if (def_call_starts(collecting, p, linelen, prefix, plen)) {
            collecting = 1;
            used = 0;
        }
        if (collecting) {
            if (used + linelen >= sizeof call)
                return die("z23-lint: derived buffer overflow\n", "");
            memcpy(call + used, p, linelen);
            used += linelen;
            call[used] = '\0';
            if (closes) {
                collecting = 0;
                if (def_finish_call(out, call, used)) return 2;
            }
        }
        p = *eol == '\n' ? eol + 1 : eol;
    }
    return 0;
}

static int def_missing(const char *path)
{
    struct stat st;
    return stat(path, &st) != 0 || !S_ISREG(st.st_mode);
}

static int def_load(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f) return die("z23-lint: cannot open %s\n", path);
    struct stat st;
    if (fstat(fileno(f), &st) != 0) {
        fclose(f);
        return die("z23-lint: cannot open %s\n", path);
    }
    if ((size_t)st.st_size >= cap) {
        fclose(f);
        return die("z23-lint: derived buffer overflow\n", "");
    }
    int rc = csr_slurp(f, buf, cap);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int add_fault(char *faults, size_t cap, size_t *used, int *n, const char *line)
{
    int k = snprintf(faults + *used, cap - *used, "%s%s", *used ? "\n" : "", line);
    if (ovf(k, cap - *used)) return 2;
    *used += (size_t)k;
    (*n)++;
    return 0;
}

static int pr_git_ls(const char *fmt, const char *a, const char *b, char *out, size_t cap, int *code)
{
    char qa[RS_PATH * 2], qb[RS_PATH * 2], cmd[4096];
    if (sh_single_quote(a, qa, sizeof qa) || (b && sh_single_quote(b, qb, sizeof qb))
        || ovf(snprintf(cmd, sizeof cmd, fmt, qa, qb), sizeof cmd))
        return 2;
    return capture_cmd(cmd, out, cap, code);
}

static int pr_territory_resolves(const char *t)
{
    struct stat st;
    if (stat(t, &st) != 0 || !S_ISDIR(st.st_mode)) return 0;
    char spec_c[RS_PATH], spec_h[RS_PATH];
    static char lsbuf[DEF_LS];
    int code = 0;
    if (ovf(snprintf(spec_c, sizeof spec_c, "%s/*.c", t), sizeof spec_c)
        || ovf(snprintf(spec_h, sizeof spec_h, "%s/*.h", t), sizeof spec_h)
        || pr_git_ls("git ls-files -- %s %s 2>/dev/null", spec_c, spec_h,
                     lsbuf, sizeof lsbuf, &code))
        return -1;
    return lsbuf[0] != '\0';
}

static int pr_evidence_tracked(const char *ev)
{
    char dump[RS_PATH];
    int code = 0;
    if (pr_git_ls("git ls-files --error-unmatch -- %s 2>/dev/null", ev, "",
                  dump, sizeof dump, &code))
        return -1;
    return code == 0;
}

static int pr_join_stance(const struct def_call *c, char *stance, size_t cap)
{
    stance[0] = '\0';
    for (int j = 1; j < c->n_lit - 1; j++) {
        size_t have = strlen(stance), add = strlen(c->lit[j]);
        if (have + add >= cap)
            return die("z23-lint: derived buffer overflow\n", "");
        memcpy(stance + have, c->lit[j], add + 1);
    }
    return 0;
}

static int pr_fault_dup_territory(struct sr_set *seen, const char *t,
                                  char *faults, size_t cap, size_t *used, int *nf)
{
    char line[512];
    if (sr_has(seen, t)
        && (ovf(snprintf(line, sizeof line,
                         "  %s: a second stance for a territory that already has one", t),
                sizeof line)
            || add_fault(faults, cap, used, nf, line)))
        return 2;
    if (sr_add(seen, t)) return 2;
    return 0;
}

static int pr_fault_not_territory(const char *t, char *faults, size_t cap,
                                  size_t *used, int *nf)
{
    char line[512];
    int ok = pr_territory_resolves(t);
    if (ok < 0) return 2;
    if (!ok && (ovf(snprintf(line, sizeof line,
                             "  %s: not a territory — no tracked .c or .h under that path", t),
                    sizeof line)
                || add_fault(faults, cap, used, nf, line)))
        return 2;
    return 0;
}

static int pr_fault_evidence_untracked(const char *t, const char *ev,
                                       char *faults, size_t cap, size_t *used, int *nf)
{
    char line[512];
    int ok = pr_evidence_tracked(ev);
    if (ok < 0) return 2;
    if (!ok && (ovf(snprintf(line, sizeof line,
                             "  %s: evidence '%s' is not a tracked file", t, ev),
                    sizeof line)
                || add_fault(faults, cap, used, nf, line)))
        return 2;
    return 0;
}

static int pr_fault_stance_bounds(const char *t, int len, char *faults, size_t cap,
                                  size_t *used, int *nf)
{
    char line[512];
    if (len < PR_STANCE_MIN) {
        if (ovf(snprintf(line, sizeof line,
                         "  %s: stance is %d characters; a refusal a reader can act on is longer",
                         t, len), sizeof line)
            || add_fault(faults, cap, used, nf, line))
            return 2;
    } else if (len > PR_STANCE_MAX
               && (ovf(snprintf(line, sizeof line,
                                "  %s: stance is %d characters; that is a summary, not a refusal",
                                t, len), sizeof line)
                   || add_fault(faults, cap, used, nf, line)))
        return 2;
    return 0;
}

static int pr_scan(const char *text, char *faults, size_t cap, int *nrows, int *nf)
{
    static struct def_calls calls;
    *nrows = 0;
    *nf = 0;
    faults[0] = '\0';
    size_t used = 0;
    if (def_parse_calls(text, "PERSONA(", &calls)) return 2;
    *nrows = calls.n;
    struct sr_set seen = {0};
    for (int i = 0; i < calls.n; i++) {
        struct def_call *c = &calls.row[i];
        if (c->n_lit < 3) {
            if (add_fault(faults, cap, &used, nf,
                          "  a PERSONA row does not carry three strings "
                          "(territory, stance, evidence)"))
                return 2;
            continue;
        }
        const char *t = c->lit[0], *ev = c->lit[c->n_lit - 1];
        if (!t[0]) continue;
        char stance[DEF_STANCE];
        if (pr_join_stance(c, stance, sizeof stance)) return 2;
        if (pr_fault_dup_territory(&seen, t, faults, cap, &used, nf)) return 2;
        if (pr_fault_not_territory(t, faults, cap, &used, nf)) return 2;
        if (pr_fault_evidence_untracked(t, ev, faults, cap, &used, nf)) return 2;
        if (pr_fault_stance_bounds(t, (int)strlen(stance), faults, cap, &used, nf))
            return 2;
    }
    return 0;
}

static int pr_run_at(const char *def, int floor)
{
    if (def_missing(def)) {
        fprintf(stderr, "[check_persona_resolves] FATAL — %s is missing; "
                        "refusing to report a clean scan\n", def);
        return 2;
    }
    static char text[DEF_SLURP], faults[8192];
    int nrows = 0, nf = 0;
    if (def_load(def, text, sizeof text)
        || pr_scan(text, faults, sizeof faults, &nrows, &nf))
        return 2;
    char hint[256];
    if (ovf(snprintf(hint, sizeof hint,
                     "personas.def parsed %d row(s); the PERSONA( parser or the file changed shape",
                     nrows), sizeof hint))
        return 2;
    int rc = gate_require_scanned(nrows, floor, "check_persona_resolves", hint);
    if (rc) return rc;
    if (nf) {
        if (puts("") == EOF
            || puts("[check_persona_resolves] a persona names something that is no longer there:") == EOF
            || puts(faults) == EOF || puts("") == EOF
            || puts("  A stance is the one thing about a territory this project writes") == EOF
            || puts("  down, and the deal is that it stays true. Correct the row or") == EOF
            || puts("  delete it — there is no baseline to add it to.") == EOF)
            return die("z23-lint: write failed\n", "");
        return 1;
    }
    if (printf("[check_persona_resolves] PASS (%d persona(s); every territory holds tracked C and every evidence file is tracked)\n",
               nrows) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

int check_persona_resolves_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    return pr_run_at(env_or("ZCL_PERSONA_DEF",
                            "engine/modules/engine/include/engine/personas.def"),
                     env_int_or("ZCL_PERSONA_ROW_FLOOR", 3));
}

static int hush_run(int (*fn)(int, char **))
{
    int n = open("/dev/null", O_WRONLY), o = dup(1), e = dup(2);
    if (n < 0 || o < 0 || e < 0) return die("z23-lint: tmpfile failed\n", "");
    int rc = 2;
    if (dup2(n, 1) >= 0 && dup2(n, 2) >= 0) rc = fn(0, NULL);
    (void)dup2(o, 1); (void)dup2(e, 2);
    close(n); close(o); close(e);
    return rc;
}

static int empty_run_is_2(const char *env, int (*fn)(int, char **))
{
    char tmpl[] = "/tmp/z23-lint-def-XXXXXX";
    char *tmp = mkdtemp(tmpl), empty[256];
    int bad = 0;
    if (!tmp) return die("z23-lint: mkdir failed: %s\n", "/tmp");
    if (ovf(snprintf(empty, sizeof empty, "%s/empty.def", tmp), sizeof empty)
        || csr_write(empty, "") || setenv(env, empty, 1) != 0
        || hush_run(fn) != 2)
        bad = 1;
    (void)unsetenv(env);
    (void)rap_rm_rf(tmp);
    return bad;
}

static const char k_pr_good[] =
    "PERSONA(\"platform/modules/base\",\n"
    "    \"LOG_FAIL, LOG_ERR and LOG_NULL RETURN; they are not print statements.\",\n"
    "    \"platform/modules/base/include/base/log_macros.h\")\n";
static const char k_pr_stance[] =
    "    \"LOG_FAIL, LOG_ERR and LOG_NULL RETURN; they are not print statements.\",\n"
    "    \"platform/modules/base/include/base/log_macros.h\")\n";

int check_persona_resolves_selftest(void)
{
    static char faults[4096], buf[1024];
    int nrows = 0, nf = 0, bad = 0;
    const char *dirty[] = {
        "PERSONA(\"lib/nope\",\n",
        "PERSONA(\".github\",\n",
        "PERSONA(\"platform/modules/base\",\n"
        "    \"LOG_FAIL, LOG_ERR and LOG_NULL RETURN; they are not print statements.\",\n"
        "    \"platform/modules/base/include/base/deleted_yesterday.h\")\n",
        ("PERSONA(\"platform/modules/base\",\n    \"be careful\",\n"
        "    \"platform/modules/base/include/base/log_macros.h\")\n")
    };
    if (pr_scan(k_pr_good, faults, sizeof faults, &nrows, &nf) || nf) bad = 1;
    for (size_t i = 0; i < 2; i++) {
        if (ovf(snprintf(buf, sizeof buf, "%s%s", dirty[i], k_pr_stance), sizeof buf)
            || pr_scan(buf, faults, sizeof faults, &nrows, &nf) || !nf)
            bad = 1;
    }
    if (pr_scan(dirty[2], faults, sizeof faults, &nrows, &nf) || !nf) bad = 1;
    if (ovf(snprintf(buf, sizeof buf, "%s%s", k_pr_good, k_pr_good), sizeof buf)
        || pr_scan(buf, faults, sizeof faults, &nrows, &nf) || !nf)
        bad = 1;
    if (pr_scan(dirty[3], faults, sizeof faults, &nrows, &nf) || !nf) bad = 1;
    bad |= empty_run_is_2("ZCL_PERSONA_DEF", check_persona_resolves_run);
    return st_ok(bad, "check_persona_resolves selftest: OK\n");
}

static int cmpstr(const void *a, const void *b) { return strcmp(a, b); }

static int kinds_add(char k[][PRT_FIELD], int *n, const char *kind)
{
    for (int i = 0; i < *n; i++)
        if (!strcmp(k[i], kind)) return 0;
    if (*n >= PRT_KINDS || strlen(kind) >= PRT_FIELD)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(k[(*n)++], kind, strlen(kind) + 1);
    return 0;
}

static int prt_split3(const char *raw, const char *prefix,
                      char *a, size_t ac, char *b, size_t bc, char *c, size_t cc)
{
    size_t pl = strlen(prefix);
    if (strncmp(raw, prefix, pl) != 0) return 1;
    const char *p = raw + pl, *c1 = strchr(p, ',');
    if (!c1) return 1;
    size_t an = (size_t)(c1 - p);
    if (an >= ac) return die("z23-lint: derived buffer overflow\n", "");
    memcpy(a, p, an); a[an] = '\0';
    const char *rest = c1 + 1, *c2 = strchr(rest, ',');
    if (!c2) return 1;
    size_t bn = (size_t)(c2 - rest);
    if (bn >= bc) return die("z23-lint: derived buffer overflow\n", "");
    memcpy(b, rest, bn); b[bn] = '\0';
    if (strlen(c2 + 1) >= cc) return die("z23-lint: derived buffer overflow\n", "");
    memcpy(c, c2 + 1, strlen(c2 + 1) + 1);
    crush_ht(a); crush_ht(b); crush_ht(c);
    return 0;
}

static int prt_collect_sections(struct def_calls *scalls, struct sr_set *declared,
                                char always[][PRT_FIELD], int *n_always, int *nsec)
{
    for (int i = 0; i < scalls->n; i++) {
        char id[PRT_FIELD], need[PRT_FIELD], unused[DEF_RAW];
        int skip = prt_split3(scalls->row[i].raw, "ENGINE_PROMPT_SECTION(",
                              id, sizeof id, need, sizeof need, unused, sizeof unused);
        if (skip < 0) return 2;
        if (skip || !id[0]) continue;
        (*nsec)++;
        if (sr_add(declared, id)) return 2;
        if (!strcmp(need, "ENGINE_PROMPT_NEED_ALWAYS")) {
            if (*n_always >= PRT_ALWAYS || strlen(id) >= PRT_FIELD)
                return die("z23-lint: derived buffer overflow\n", "");
            memcpy(always[(*n_always)++], id, strlen(id) + 1);
        }
    }
    return 0;
}

static int prt_collect_templates(struct def_calls *tcalls,
                                 char kind[][PRT_FIELD], char section[][PRT_FIELD],
                                 char kinds[][PRT_FIELD], int *nkind, int *nrows)
{
    for (int i = 0; i < tcalls->n; i++) {
        char k[PRT_FIELD], s[PRT_FIELD], body[DEF_RAW];
        int skip = prt_split3(tcalls->row[i].raw, "ENGINE_PROMPT_TEMPLATE(",
                              k, sizeof k, s, sizeof s, body, sizeof body);
        if (skip < 0) return 2;
        if (skip || !strcmp(body, "\"\")") || !k[0] || !s[0]) continue;
        if (*nrows >= PRT_ROWS) return die("z23-lint: derived buffer overflow\n", "");
        memcpy(kind[*nrows], k, strlen(k) + 1);
        memcpy(section[*nrows], s, strlen(s) + 1);
        if (kinds_add(kinds, nkind, k)) return 2;
        (*nrows)++;
    }
    return 0;
}

static int prt_fault_undeclared_section(char kind[][PRT_FIELD],
                                        char section[][PRT_FIELD], int nrows,
                                        struct sr_set *declared, char *faults,
                                        size_t cap, size_t *used, int *nf)
{
    for (int i = 0; i < nrows; i++) {
        if (sr_has(declared, section[i])) continue;
        char line[256];
        if (ovf(snprintf(line, sizeof line,
                         "  %s: names the section '%s', which prompt_sections.def does not declare",
                         kind[i], section[i]), sizeof line)
            || add_fault(faults, cap, used, nf, line))
            return 2;
    }
    return 0;
}

static int prt_fault_missing_always(char kind[][PRT_FIELD], char section[][PRT_FIELD],
                                    int nrows, char kinds[][PRT_FIELD], int nkind,
                                    char always[][PRT_FIELD], int n_always,
                                    char *faults, size_t cap, size_t *used, int *nf)
{
    for (int i = 0; i < nkind; i++) {
        for (int j = 0; j < n_always; j++) {
            int found = 0;
            for (int r = 0; r < nrows; r++)
                if (!strcmp(kind[r], kinds[i]) && !strcmp(section[r], always[j])) {
                    found = 1; break;
                }
            if (found) continue;
            char line[256];
            if (ovf(snprintf(line, sizeof line,
                             "  %s: supplies no body for the always-required '%s' section, so nobody can select this kind",
                             kinds[i], always[j]), sizeof line)
                || add_fault(faults, cap, used, nf, line))
                return 2;
        }
    }
    return 0;
}

static int prt_scan(const char *tmpl, const char *secs, char *faults, size_t cap,
                    int *nrows, int *nsec, int *nkinds, int *nf)
{
    static struct def_calls scalls, tcalls;
    *nrows = 0; *nsec = 0; *nkinds = 0; *nf = 0; faults[0] = '\0';
    size_t used = 0;
    if (def_parse_calls(secs, "ENGINE_PROMPT_SECTION(", &scalls)
        || def_parse_calls(tmpl, "ENGINE_PROMPT_TEMPLATE(", &tcalls))
        return 2;
    struct sr_set declared = {0};
    char always[PRT_ALWAYS][PRT_FIELD];
    int n_always = 0;
    if (prt_collect_sections(&scalls, &declared, always, &n_always, nsec))
        return 2;
    char kind[PRT_ROWS][PRT_FIELD], section[PRT_ROWS][PRT_FIELD];
    char kinds[PRT_KINDS][PRT_FIELD];
    int nkind = 0;
    if (prt_collect_templates(&tcalls, kind, section, kinds, &nkind, nrows))
        return 2;
    *nkinds = nkind;
    if (prt_fault_undeclared_section(kind, section, *nrows, &declared, faults,
                                     cap, &used, nf))
        return 2;
    qsort(kinds, (size_t)nkind, sizeof kinds[0], cmpstr);
    if (prt_fault_missing_always(kind, section, *nrows, kinds, nkind,
                                 always, n_always, faults, cap, &used, nf))
        return 2;
    return 0;
}

static int prt_load_scan(const char *tmpl, const char *secs,
                         char *ttext, size_t tcap, char *stext, size_t scap,
                         char *faults, size_t fcap,
                         int *nrows, int *nsec, int *nkinds, int *nf)
{
    if (def_load(tmpl, ttext, tcap) || def_load(secs, stext, scap)
        || prt_scan(ttext, stext, faults, fcap, nrows, nsec, nkinds, nf))
        return 2;
    return 0;
}

static int prt_require_counts(int nrows, int nsec, int floor)
{
    char hint[256];
    if (ovf(snprintf(hint, sizeof hint,
                     "prompt_templates.def parsed %d row(s); the ENGINE_PROMPT_TEMPLATE( parser or the file changed shape",
                     nrows), sizeof hint))
        return 2;
    int rc = gate_require_scanned(nrows, floor, "check_prompt_templates", hint);
    if (rc) return rc;
    if (ovf(snprintf(hint, sizeof hint,
                     "prompt_sections.def parsed %d row(s); the ENGINE_PROMPT_SECTION( parser or the file changed shape",
                     nsec), sizeof hint))
        return 2;
    return gate_require_scanned(nsec, PRT_SEC_FLOOR, "check_prompt_templates", hint);
}

static int prt_print_disagree(const char *faults)
{
    if (puts("") == EOF
        || puts("[check_prompt_templates] a prompt template and the declared prompt shape disagree:") == EOF
        || puts(faults) == EOF || puts("") == EOF
        || puts("  A body under a section nobody emits is never delivered, and a") == EOF
        || puts("  kind missing a required body is an option nobody can choose.") == EOF
        || puts("  Neither shows up at run time. Fix the row or the section.") == EOF)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int prt_run_at(const char *tmpl, const char *secs, int floor)
{
    if (def_missing(tmpl)) {
        fprintf(stderr, "[check_prompt_templates] FATAL — %s is missing; "
                        "refusing to report a clean scan\n", tmpl);
        return 2;
    }
    if (def_missing(secs)) {
        fprintf(stderr, "[check_prompt_templates] FATAL — %s is missing; "
                        "refusing to report a clean scan\n", secs);
        return 2;
    }
    static char ttext[DEF_SLURP], stext[DEF_SLURP], faults[8192];
    int nrows = 0, nsec = 0, nkinds = 0, nf = 0;
    if (prt_load_scan(tmpl, secs, ttext, sizeof ttext, stext, sizeof stext,
                      faults, sizeof faults, &nrows, &nsec, &nkinds, &nf))
        return 2;
    int rc = prt_require_counts(nrows, nsec, floor);
    if (rc) return rc;
    if (nf) return prt_print_disagree(faults);
    if (printf("[check_prompt_templates] PASS (%d row(s), %d kind(s); every section is declared and every kind fills each always-required section)\n",
               nrows, nkinds) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

int check_prompt_templates_run(int argc, char **argv)
{
    (void)argc; (void)argv;
    return prt_run_at(env_or("ZCL_PROMPT_TEMPLATES_DEF",
                             "engine/composition/prompt_templates.def"),
                      env_or("ZCL_PROMPT_SECTIONS_DEF",
                             "engine/modules/engine/include/engine/prompt_sections.def"),
                      env_int_or("ZCL_PROMPT_TEMPLATE_ROW_FLOOR", 8));
}

static const char k_prt_secs[] =
    "ENGINE_PROMPT_SECTION(rules, ENGINE_PROMPT_NEED_NO_SYSTEM_CHANNEL, \"R\")\n"
    "ENGINE_PROMPT_SECTION(task, ENGINE_PROMPT_NEED_ALWAYS, \"T\")\n"
    "ENGINE_PROMPT_SECTION(protocol, ENGINE_PROMPT_NEED_ALWAYS, \"P\")\n";
static const char k_prt_good[] =
    "ENGINE_PROMPT_TEMPLATE(fix-gate, task, \"do the thing\")\n"
    "ENGINE_PROMPT_TEMPLATE(fix-gate, protocol, \"write files\")\n";

int check_prompt_templates_selftest(void)
{
    static char faults[4096], buf[1024];
    int nrows = 0, nsec = 0, nkinds = 0, nf = 0, bad = 0;
    if (prt_scan(k_prt_good, k_prt_secs, faults, sizeof faults,
                 &nrows, &nsec, &nkinds, &nf) || nf)
        bad = 1;
    const char *dirty[] = {
        "ENGINE_PROMPT_TEMPLATE(fix-gate, epilogue, \"and finally\")\n",
        "ENGINE_PROMPT_TEMPLATE(half-done, task, \"only half\")\n",
        ("ENGINE_PROMPT_TEMPLATE(fix-gate, task, \"\")\n"
        "ENGINE_PROMPT_TEMPLATE(fix-gate, protocol, \"write files\")\n")
    };
    if (ovf(snprintf(buf, sizeof buf, "%s%s", k_prt_good, dirty[0]), sizeof buf)
        || prt_scan(buf, k_prt_secs, faults, sizeof faults, &nrows, &nsec, &nkinds, &nf)
        || !nf)
        bad = 1;
    if (ovf(snprintf(buf, sizeof buf, "%s%s", k_prt_good, dirty[1]), sizeof buf)
        || prt_scan(buf, k_prt_secs, faults, sizeof faults, &nrows, &nsec, &nkinds, &nf)
        || !nf)
        bad = 1;
    if (prt_scan(dirty[2], k_prt_secs, faults, sizeof faults,
                 &nrows, &nsec, &nkinds, &nf) || !nf)
        bad = 1;
    bad |= empty_run_is_2("ZCL_PROMPT_TEMPLATES_DEF", check_prompt_templates_run);
    return st_ok(bad, "check_prompt_templates selftest: OK\n");
}
